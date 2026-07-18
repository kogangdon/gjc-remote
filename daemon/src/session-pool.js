import { existsSync, realpathSync } from "node:fs";
import { IDLE_TIMEOUT_MS } from "@gjc-remote/shared";
import { createSdkSession } from "./sdk-session.js";
import { validateNativeWorkDir } from "./work-dir.js";

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
  } = {}) {
    /** @type {Map<string, { session?: object, creation?: Promise<object>, lastUsed: number }>} */
    this.sessions = new Map();
    this.aliases = new Map();
    this.sessionFactory = sessionFactory;
    this.existsSyncFn = existsSyncFn;
    this.realpathSyncFn = realpathSyncFn;
    this.platform = platform;
    this.closed = false;
    this.reapTimer = setInterval(() => {
      void this.#reapIdle().catch((error) =>
        console.error("SessionPool: idle reap failed:", error)
      );
    }, 5 * 60 * 1000);
    this.reapTimer.unref?.();
  }

  #aliasKey(workDir) {
    return this.platform === "win32" ? workDir.toLowerCase() : workDir;
  }

  #entryForRequestedWorkDir(workDir) {
    const canonical = this.aliases.get(this.#aliasKey(workDir));
    return canonical === undefined ? undefined : this.sessions.get(canonical);
  }

  async #reapIdle() {
    const now = Date.now();
    const disposals = [];
    for (const [workDir, entry] of this.sessions) {
      if (entry.session && now - entry.lastUsed > IDLE_TIMEOUT_MS) {
        console.log(`SessionPool: reaping idle session for ${workDir}`);
        this.sessions.delete(workDir);
        this.#deleteAliasesFor(workDir);
        disposals.push(
          entry.session.dispose().catch((error) =>
            console.error(`SessionPool: failed to dispose idle session for ${workDir}:`, error)
          )
        );
      }
    }
    await Promise.all(disposals);
  }

  #deleteAliasesFor(canonicalWorkDir) {
    for (const [alias, canonical] of this.aliases) {
      if (canonical === canonicalWorkDir) this.aliases.delete(alias);
    }
  }

  async ensureSession(workDir) {
    if (this.closed) throw new Error("SessionPool is shut down");

    const requestedWorkDir = validateNativeWorkDir(workDir, this.platform);
    const exact = this.#entryForRequestedWorkDir(requestedWorkDir);
    if (exact?.session && !exact.session.closed) {
      exact.lastUsed = Date.now();
      return exact.session;
    }
    if (exact?.creation) {
      exact.lastUsed = Date.now();
      return await exact.creation;
    }

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

    this.aliases.set(this.#aliasKey(requestedWorkDir), canonicalWorkDir);
    this.aliases.set(this.#aliasKey(canonicalWorkDir), canonicalWorkDir);

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
        try {
          await existing.session.dispose();
        } catch (error) {
          console.error(`SessionPool: failed to dispose replaced session for ${canonicalWorkDir}:`, error);
        }
      }

      const session = await this.sessionFactory(canonicalWorkDir);
      if (this.closed) {
        await session.dispose();
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
        this.#deleteAliasesFor(canonicalWorkDir);
      }
      throw error;
    }
  }

  async shutdown() {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.reapTimer);

    const entries = [...this.sessions.values()];
    this.sessions.clear();
    this.aliases.clear();
    const results = await Promise.allSettled(
      entries.map(async (entry) => {
        const session = entry.session ?? (await entry.creation?.catch(() => undefined));
        if (session) await session.dispose();
      })
    );
    const errors = results
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason);
    if (errors.length > 0) throw new AggregateError(errors, "Failed to dispose GJC SDK sessions");
  }
}
