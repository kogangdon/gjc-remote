import { existsSync, realpathSync } from "node:fs";
import { IDLE_TIMEOUT_MS } from "@gjc-remote/shared";
import { createSdkSession } from "./sdk-session.js";
import { validateNativeWorkDir } from "./work-dir.js";

const SESSION_DISPOSE_TIMEOUT_MS = 5_000;
// Session creation activates the host's model profile, which can touch the
// credential store and model registry (potentially a network token exchange),
// so it needs a far larger bound than teardown. Sharing the 5s dispose bound
// made cold-host creations spuriously "time out" and churn create/dispose.
const SESSION_CREATE_TIMEOUT_MS = 60_000;

function normalizeCanonicalWorkDir(workDir, platform) {
  if (platform !== "win32") return workDir;
  return workDir
    .replace(/^\\\\\?\\UNC\\/i, "\\\\")
    .replace(/^\\\\\?\\/, "");
}

/** Per-workDir pool of embedded GJC SDK sessions. */
export class SessionPool {
  constructor({
    sessionFactory = createSdkSession,
    existsSyncFn = existsSync,
    realpathSyncFn = realpathSync.native ?? realpathSync,
    platform = process.platform,
    sessionDisposeTimeoutMs = SESSION_DISPOSE_TIMEOUT_MS,
    sessionCreateTimeoutMs = SESSION_CREATE_TIMEOUT_MS,
  } = {}) {
    /** @type {Map<string, { session?: object, creation?: Promise<object>, lastUsed: number }>} */
    this.sessions = new Map();
    this.sessionFactory = sessionFactory;
    this.existsSyncFn = existsSyncFn;
    this.realpathSyncFn = realpathSyncFn;
    this.platform = platform;
    this.sessionCreateTimeoutMs = sessionCreateTimeoutMs;
    this.sessionDisposeTimeoutMs = sessionDisposeTimeoutMs;
    this.closed = false;
    this.reapTimer = setInterval(() => {
      void this.#reapIdle().catch((error) =>
        console.error("SessionPool: idle reap failed:", error)
      );
    }, 5 * 60 * 1000);
    this.reapTimer.unref?.();
  }

  async #reapIdle() {
    const now = Date.now();
    const disposals = [];
    for (const [workDir, entry] of this.sessions) {
      if (entry.session && now - entry.lastUsed > IDLE_TIMEOUT_MS) {
        console.log(`SessionPool: reaping idle session for ${workDir}`);
        this.sessions.delete(workDir);
        disposals.push(this.#disposeIgnoringFailure(entry.session, workDir, "idle"));
      }
    }
    await Promise.all(disposals);
  }
  async #settleBounded(operation, timeoutMs) {
    let timer;
    const settlement = Promise.resolve(operation).then(
      (value) => ({ status: "fulfilled", value }),
      (reason) => ({ status: "rejected", reason })
    );
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve({ status: "timed_out" }), timeoutMs);
    });

    const result = await Promise.race([settlement, timeout]);
    clearTimeout(timer);
    return result;
  }

  #disposeBounded(session) {
    return this.#settleBounded(
      Promise.resolve().then(() => session.dispose()),
      this.sessionDisposeTimeoutMs
    );
  }

  async #disposeIgnoringFailure(session, workDir, context) {
    const result = await this.#disposeBounded(session);
    if (result.status === "rejected") {
      console.error(
        `SessionPool: failed to dispose ${context} session for ${workDir}:`,
        result.reason
      );
    } else if (result.status === "timed_out") {
      console.error(`SessionPool: ${context} session disposal timed out for ${workDir}`);
    }
  }

  async #createSessionBounded(workDir) {
    const pending = Promise.resolve().then(() => this.sessionFactory(workDir));
    const result = await this.#settleBounded(pending, this.sessionCreateTimeoutMs);
    if (result.status === "fulfilled") return result.value;
    if (result.status === "rejected") throw result.reason;

    void pending.then(
      (session) => this.#disposeIgnoringFailure(session, workDir, "late-created"),
      () => {}
    );
    throw new Error(`GJC SDK session creation timed out for ${workDir}`);
  }

  async ensureSession(workDir) {
    if (this.closed) throw new Error("SessionPool is shut down");

    const requestedWorkDir = validateNativeWorkDir(workDir, this.platform);

    if (!this.existsSyncFn(requestedWorkDir)) {
      throw new Error(`workDir does not exist on this host: ${requestedWorkDir}`);
    }

    let canonicalWorkDir;
    try {
      canonicalWorkDir = normalizeCanonicalWorkDir(
        this.realpathSyncFn(requestedWorkDir),
        this.platform
      );
      canonicalWorkDir = validateNativeWorkDir(canonicalWorkDir, this.platform);
    } catch (error) {
      throw new Error(`workDir cannot be resolved on this host: ${requestedWorkDir}`, {
        cause: error,
      });
    }

    const existing = this.sessions.get(canonicalWorkDir);
    if (existing?.session && !existing.session.closed) {
      existing.lastUsed = Date.now();
      return existing.session;
    }
    if (existing?.creation) {
      existing.lastUsed = Date.now();
      return await existing.creation;
    }

    const entry = { lastUsed: Date.now(), session: undefined, creation: undefined };
    const creation = (async () => {
      if (existing?.session) {
        await this.#disposeIgnoringFailure(existing.session, canonicalWorkDir, "replacement");
      }

      const session = await this.#createSessionBounded(canonicalWorkDir);
      if (this.closed) {
        await this.#disposeIgnoringFailure(session, canonicalWorkDir, "late-created");
        throw new Error("SessionPool was shut down during session creation");
      }
      entry.session = session;
      entry.creation = undefined;
      return session;
    })();
    entry.creation = creation;
    this.sessions.set(canonicalWorkDir, entry);

    try {
      return await creation;
    } catch (error) {
      if (this.sessions.get(canonicalWorkDir) === entry) {
        this.sessions.delete(canonicalWorkDir);
      }
      throw error;
    }
  }

  async shutdown() {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.reapTimer);

    const entries = [...this.sessions.entries()];
    this.sessions.clear();
    const results = await Promise.allSettled(
      entries.map(async ([workDir, entry]) => {
        const session = entry.session;
        if (!session && entry.creation) {
          const creationResult = await this.#settleBounded(
            entry.creation,
            this.sessionDisposeTimeoutMs
          );
          if (creationResult.status === "timed_out") {
            console.error(`SessionPool: session creation wait timed out for ${workDir}`);
          }
          return;
        }
        if (!session) return;

        const result = await this.#disposeBounded(session);
        if (result.status === "rejected") throw result.reason;
        if (result.status === "timed_out") {
          console.error(`SessionPool: shutdown session disposal timed out for ${workDir}`);
        }
      })
    );
    const errors = results
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason);
    if (errors.length > 0) throw new AggregateError(errors, "Failed to dispose GJC SDK sessions");
  }
}
