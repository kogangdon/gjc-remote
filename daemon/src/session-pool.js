import { realpathSync, statSync } from "node:fs";
import { IDLE_TIMEOUT_MS } from "@gjc-remote/shared";
import { createSdkSession } from "./sdk-session.js";
import { validateNativeWorkDir } from "./work-dir.js";
import { sanitizeErrorMessage } from "./reconnect.js";

const SESSION_DISPOSE_TIMEOUT_MS = 5_000;
export const DEFAULT_MAX_SESSIONS = 8;
// Session creation activates the host's model profile, which can touch the
// credential store and model registry (potentially a network token exchange),
// so it needs a far larger bound than teardown. Sharing the 5s dispose bound
// made cold-host creations spuriously "time out" and churn create/dispose.
const SESSION_CREATE_TIMEOUT_MS = 60_000;

function leaseConflict() {
  const error = new Error("managed session transition is already in progress");
  error.code = "LEASE_CONFLICT";
  return error;
}

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
    statSyncFn = statSync,
    realpathSyncFn = realpathSync.native ?? realpathSync,
    platform = process.platform,
    sessionDisposeTimeoutMs = SESSION_DISPOSE_TIMEOUT_MS,
    sessionCreateTimeoutMs = SESSION_CREATE_TIMEOUT_MS,
    idleTimeoutMs = IDLE_TIMEOUT_MS,
    reapIntervalMs = 5 * 60 * 1000,
    setIntervalFn = setInterval,
    clearIntervalFn = clearInterval,
    nowFn = Date.now,
    sensitiveValues = [],
    maxSessions = DEFAULT_MAX_SESSIONS,
  } = {}) {
    if (!Number.isSafeInteger(maxSessions) || maxSessions < 1) {
      throw new TypeError("maxSessions must be a positive safe integer");
    }
    /** @type {Map<string, { session?: object, creation?: Promise<object>, lastUsed: number }>} */
    this.sessions = new Map();
    this.sessionFactory = sessionFactory;
    this.statSyncFn = statSyncFn;
    this.realpathSyncFn = realpathSyncFn;
    this.platform = platform;
    this.sessionCreateTimeoutMs = sessionCreateTimeoutMs;
    this.sessionDisposeTimeoutMs = sessionDisposeTimeoutMs;
    this.idleTimeoutMs = idleTimeoutMs;
    this.setIntervalFn = setIntervalFn;
    this.clearIntervalFn = clearIntervalFn;
    this.nowFn = nowFn;
    this.closed = false;
    this.sensitiveValues = [...sensitiveValues];
    this.maxSessions = maxSessions;
    this.pendingOperations = new Map();
    this.sessionTransitions = new Map();
    this.reapTimer = this.setIntervalFn(() => {
      void this.#reapIdle().catch((error) =>
        console.error(`SessionPool: idle reap failed: ${this.#sanitize(error)}`)
      );
    }, reapIntervalMs);
    this.reapTimer.unref?.();
  }
  #sanitize(value) {
    return sanitizeErrorMessage(value, this.sensitiveValues);
  }

  async #reapIdle() {
    const now = this.nowFn();
    const disposals = [];
    for (const [workDir, entry] of this.sessions) {
      if (!entry.session) continue;
      if (typeof entry.session.isBusy === "function" && entry.session.isBusy()) {
        entry.lastUsed = now;
        continue;
      }
      if (now - entry.lastUsed > this.idleTimeoutMs) {
        console.log(`SessionPool: reaping idle session for ${this.#sanitize(workDir)}`);
        this.sessions.delete(workDir);
        disposals.push(this.#disposeIgnoringFailure(entry.session, workDir, "idle"));
      }
    }
    await Promise.all(disposals);
  }
  async #settleBounded(operation, timeoutMs) {
    if (typeof timeoutMs !== "number") {
      throw new TypeError("#settleBounded requires a numeric timeoutMs");
    }
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
  #trackPending(workDir, operation, callback) {
    const token = Symbol(operation);
    this.pendingOperations.set(token, { workDir, operation });
    return Promise.resolve()
      .then(callback)
      .finally(() => this.pendingOperations.delete(token));
  }

  getPendingShutdownOperations() {
    return [...this.pendingOperations.values()].map(({ workDir, operation }) => ({
      workDir,
      operation,
    }));
  }

  getAdmissionSnapshot() {
    let activeSessions = 0;
    let pendingSessions = 0;
    for (const entry of this.sessions.values()) {
      if (entry.session && !entry.session.closed) activeSessions += 1;
      if (entry.creation) pendingSessions += 1;
    }
    return Object.freeze({
      activeSessions,
      pendingSessions,
      admittedWorkspaces: this.sessions.size,
      maxSessions: this.maxSessions,
    });
  }

  #startDispose(session, workDir, context) {
    const operation = Promise.resolve().then(() => session.dispose());
    const settlement = operation.then(
      (value) => ({ status: "fulfilled", value }),
      (reason) => ({ status: "rejected", reason })
    );
    const token = Symbol(`${context} session disposal`);
    this.pendingOperations.set(token, {
      workDir,
      operation: `${context} session disposal`,
    });
    void settlement.then(() => this.pendingOperations.delete(token));
    const bounded = this.#settleBounded(
      operation,
      this.sessionDisposeTimeoutMs
    );
    return { bounded, settlement };
  }

  #disposeBounded(session, workDir, context) {
    return this.#startDispose(session, workDir, context).bounded;
  }

  async #disposeIgnoringFailure(session, workDir, context) {
    const result = await this.#disposeBounded(session, workDir, context);
    if (result.status === "rejected") {
      console.error(
        `SessionPool: failed to dispose ${context} session for ${this.#sanitize(
          workDir
        )}: ` + this.#sanitize(result.reason)
      );
    } else if (result.status === "timed_out") {
      console.error(
        `SessionPool: ${context} session disposal timed out for ${this.#sanitize(
          workDir
        )}`
      );
    }
  }

  async #disposeForReplacement(session, workDir) {
    const disposal = this.#startDispose(session, workDir, "replacement");
    const result = await disposal.bounded;
    if (result.status === "fulfilled") return;
    console.error(
      result.status === "timed_out"
        ? "SessionPool: managed replacement session disposal timed out"
        : "SessionPool: managed replacement session disposal failed"
    );
    const error = new Error("prior managed session could not be fenced");
    error.code = "LEASE_CONFLICT";
    if (result.status === "timed_out") {
      error.pendingCleanup = disposal.settlement;
    }
    throw error;
  }

  async #createSessionBounded(workDir) {
    const pending = Promise.resolve().then(() => this.sessionFactory(workDir));
    const result = await this.#settleBounded(pending, this.sessionCreateTimeoutMs);
    if (result.status === "fulfilled") return result.value;
    if (result.status === "rejected") throw result.reason;

    const error = new Error(`GJC SDK session creation timed out for ${workDir}`);
    error.pendingCleanup = pending.then(
      async (session) => {
        const disposal = this.#startDispose(session, workDir, "late-created");
        const result = await disposal.bounded;
        if (result.status === "rejected") {
          console.error(
            `SessionPool: failed to dispose late-created session for ${this.#sanitize(
              workDir
            )}: ` + this.#sanitize(result.reason)
          );
        } else if (result.status === "timed_out") {
          console.error(
            `SessionPool: late-created session disposal timed out for ${this.#sanitize(
              workDir
            )}`
          );
          await disposal.settlement;
        }
      },
      () => {}
    );
    throw error;
  }

  async #ensureCanonicalSession(canonicalWorkDir, managedIdentity) {
    let existing = this.sessions.get(canonicalWorkDir);
    const identityMatches = existing?.managedIdentity === managedIdentity;
    if (identityMatches && existing?.session && !existing.session.closed) {
      existing.lastUsed = this.nowFn();
      return existing.session;
    }
    if (identityMatches && existing?.creation) {
      existing.lastUsed = this.nowFn();
      return await existing.creation;
    }
    if (!existing && this.sessions.size >= this.maxSessions) {
      const error = new Error("SDK session admission limit reached");
      error.code = "SESSION_LIMIT";
      throw error;
    }

    const entry = {
      lastUsed: this.nowFn(),
      session: undefined,
      creation: undefined,
      managedIdentity,
    };
    const creation = (async () => {
      let priorSession = existing?.session;
      if (!priorSession && existing?.creation) {
        try {
          priorSession = await existing.creation;
        } catch {
          existing = undefined;
          priorSession = undefined;
        }
      }
      if (priorSession) {
        if (existing?.managedIdentity !== managedIdentity) {
          await this.#disposeForReplacement(priorSession, canonicalWorkDir);
        } else {
          await this.#disposeIgnoringFailure(
            priorSession,
            canonicalWorkDir,
            "replacement"
          );
        }
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
        if (existing) {
          this.sessions.set(canonicalWorkDir, existing);
        } else {
          this.sessions.delete(canonicalWorkDir);
        }
      }
      throw error;
    }
  }

  async ensureSession(workDir, { managedIdentity } = {}) {
    if (this.closed) throw new Error("SessionPool is shut down");
    if (
      managedIdentity !== undefined &&
      (typeof managedIdentity !== "string" || managedIdentity.length === 0)
    ) {
      throw new TypeError("managedIdentity must be a non-empty string");
    }

    const requestedWorkDir = validateNativeWorkDir(workDir, this.platform);

    let stat;
    try {
      stat = this.statSyncFn(requestedWorkDir);
    } catch {
      throw new Error(`workDir does not exist on this host: ${requestedWorkDir}`);
    }
    if (!stat.isDirectory()) {
      throw new Error(`workDir is not a directory on this host: ${requestedWorkDir}`);
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

    const active = this.sessionTransitions.get(canonicalWorkDir);
    if (active) {
      if (
        active.managedIdentity === undefined &&
        managedIdentity === undefined
      ) {
        return await this.#ensureCanonicalSession(canonicalWorkDir, managedIdentity);
      }
      if (active.managedIdentity === managedIdentity) {
        return await active.operation;
      }
      throw leaseConflict();
    }

    const rawOperation = this.#ensureCanonicalSession(
      canonicalWorkDir,
      managedIdentity
    );
    const transition = { managedIdentity, operation: undefined };
    const clearTransition = () => {
      if (this.sessionTransitions.get(canonicalWorkDir) === transition) {
        this.sessionTransitions.delete(canonicalWorkDir);
      }
    };
    const operation = rawOperation.then(
      (session) => {
        clearTransition();
        return session;
      },
      (error) => {
        if (error?.pendingCleanup) {
          void error.pendingCleanup.then(clearTransition);
        } else {
          clearTransition();
        }
        throw error;
      }
    );
    transition.operation = operation;
    this.sessionTransitions.set(canonicalWorkDir, transition);
    return await operation;
  }

  async shutdown() {
    if (this.closed) return;
    this.closed = true;
    this.clearIntervalFn(this.reapTimer);

    const entries = [...this.sessions.entries()];
    this.sessions.clear();
    const results = await Promise.allSettled(
      entries.map(async ([workDir, entry]) => {
        const session = entry.session;
        if (!session && entry.creation) {
          const creationResult = await this.#trackPending(
            workDir,
            "session creation wait",
            () =>
              this.#settleBounded(
                entry.creation,
                this.sessionDisposeTimeoutMs
              )
          );
          if (creationResult.status === "timed_out") {
            console.error(
              `SessionPool: session creation wait timed out for ${this.#sanitize(
                workDir
              )}`
            );
          }
          return;
        }
        if (!session) return;

        const result = await this.#disposeBounded(session, workDir, "shutdown");
        if (result.status === "rejected") throw result.reason;
        if (result.status === "timed_out") {
          console.error(
            `SessionPool: shutdown session disposal timed out for ${this.#sanitize(
              workDir
            )}`
          );
        }
      })
    );
    const errors = results
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason);
    if (errors.length > 0) throw new AggregateError(errors, "Failed to dispose GJC SDK sessions");
  }
}
