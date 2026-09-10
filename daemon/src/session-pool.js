import { realpathSync, statSync } from "node:fs";
import { IDLE_TIMEOUT_MS } from "@gjc-remote/shared";
import { createSdkSession } from "./sdk-session.js";
import { validateNativeWorkDir } from "./work-dir.js";
import { sanitizeErrorMessage } from "./reconnect.js";
import { emitOwnerEvent, validateOwnerObserver } from "./daemon-observability.js";

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

function normalizeReceiptIdentity(receiptIdentity) {
  if (
    !receiptIdentity ||
    typeof receiptIdentity !== "object" ||
    !Number.isSafeInteger(receiptIdentity.socketGeneration) ||
    receiptIdentity.socketGeneration < 1 ||
    typeof receiptIdentity.bindingId !== "string" ||
    receiptIdentity.bindingId.length === 0 ||
    !/^[0-9a-f]{64}$/.test(receiptIdentity.bindingFingerprint)
  ) {
    throw new TypeError("receiptIdentity is invalid");
  }
  return Object.freeze({
    socketGeneration: receiptIdentity.socketGeneration,
    bindingId: receiptIdentity.bindingId,
    bindingFingerprint: receiptIdentity.bindingFingerprint,
  });
}

function receiptIdentityKey(receiptIdentity) {
  // JSON array preserves field boundaries, so A/B/C cannot concatenate into
  // the same managed identity.
  return `receipt:${JSON.stringify([
    receiptIdentity.socketGeneration,
    receiptIdentity.bindingId,
    receiptIdentity.bindingFingerprint,
  ])}`;
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
    monotonicNowFn = () => performance.now(),
    observer,
    sensitiveValues = [],
    maxSessions = DEFAULT_MAX_SESSIONS,
  } = {}) {
    if (!Number.isSafeInteger(maxSessions) || maxSessions < 1) {
      throw new TypeError("maxSessions must be a positive safe integer");
    }
    const validatedObserver = validateOwnerObserver(observer);
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
    this.monotonicNowFn = monotonicNowFn;
    this.observer = validatedObserver;
    this.closed = false;
    this.sensitiveValues = [...sensitiveValues];
    this.maxSessions = maxSessions;
    this.pendingOperations = new Map();
    this.sessionTransitions = new Map();
    /** @type {Map<string, { session: object, generation: number, managedIdentity?: string, settlement: Promise<{ status: string }>, state: "pending" | "retired" | "failed" }>} */
    this.retirements = new Map();
    this.receiptRetirements = new Map();
    this.creationHolds = new Map();
    this.nextRetirementGeneration = 1;
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
  #durationSince(start) {
    const duration = Math.floor(this.monotonicNowFn() - start);
    return Number.isSafeInteger(duration) && duration >= 0 ? duration : null;
  }
  #emit(event) {
    emitOwnerEvent(this.observer, event);
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
        const disposal = this.#retireIgnoringFailure(
          entry.session,
          workDir,
          "idle",
          entry.managedIdentity
        );
        disposals.push(disposal);
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
    const pendingWorkspaces = new Set(this.creationHolds.keys());
    for (const [workDir, entry] of this.sessions) {
      if (entry.session && !entry.session.closed) activeSessions += 1;
      if (entry.creation) pendingWorkspaces.add(workDir);
    }
    const admittedWorkspaces = new Set([
      ...this.sessions.keys(),
      ...this.retirements.keys(),
      ...this.creationHolds.keys(),
    ]).size;
    return Object.freeze({
      activeSessions,
      pendingSessions: pendingWorkspaces.size,
      admittedWorkspaces,
      maxSessions: this.maxSessions,
    });
  }

  getObservabilitySnapshot() {
    const admission = this.getAdmissionSnapshot();
    return Object.freeze({
      activeSessions: admission.activeSessions,
      pendingSessions: admission.pendingSessions,
      admittedSessionWorkspaces: admission.admittedWorkspaces,
      maxSessions: admission.maxSessions,
      pendingSessionRetirements: [...this.retirements.values()].filter(
        (retirement) => retirement.state === "pending"
      ).length,
      failedSessionRetirements: [...this.retirements.values()].filter(
        (retirement) => retirement.state === "failed"
      ).length,
    });
  }

  #startDispose(session, workDir, context) {
    const startedAt = this.monotonicNowFn();
    const observesReceiptRetirement = context === "receipt retirement";
    if (observesReceiptRetirement) {
      this.#emit({
        name: "session_pool",
        action: "managed_cleanup",
        outcome: "started",
        cleanupState: "started",
      });
    }
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
    if (observesReceiptRetirement) {
      void bounded.then((result) => {
        this.#emit({
          name: "session_pool",
          action: "managed_cleanup",
          outcome: "settled",
          cleanupState: result.status,
          durationMs: this.#durationSince(startedAt),
        });
      });
    }
    return { bounded, settlement };
  }

  #addRetirementHolds(retirement, holds) {
    if (holds === undefined) return;
    if (!Array.isArray(holds) || holds.some((hold) => typeof hold !== "function")) {
      throw new TypeError("holds must be an array of release callbacks");
    }
    for (const hold of holds) {
      if (retirement.releasedHolds.has(hold)) continue;
      if (retirement.state === "retired") {
        retirement.releasedHolds.add(hold);
        try {
          hold();
        } catch {
          console.error("SessionPool: containment hold release failed");
        }
      } else {
        retirement.holds.add(hold);
      }
    }
  }

  #releaseRetirementHolds(retirement) {
    retirement.state = "retired";
    this.#addRetirementHolds(retirement, [...retirement.holds]);
    retirement.holds.clear();
  }

  #transferRetirementHolds(source, retirement) {
    this.#addRetirementHolds(retirement, [...source.holds]);
    source.holds.clear();
  }

  #retire(session, workDir, context, managedIdentity, holds) {
    const existing = this.retirements.get(workDir);
    if (existing) {
      if (existing.session !== session) {
        const error = new Error("SDK session retirement identity mismatch");
        error.code = "SESSION_RETIREMENT_FAILED";
        throw error;
      }
      if (
        existing.managedIdentity !== undefined &&
        managedIdentity !== undefined &&
        existing.managedIdentity !== managedIdentity
      ) {
        const error = new Error("SDK session retirement identity mismatch");
        error.code = "SESSION_RETIREMENT_FAILED";
        throw error;
      }
      this.#addRetirementHolds(existing, holds);
      return existing;
    }

    const disposal = this.#startDispose(session, workDir, context);
    const retirement = {
      session,
      generation: this.nextRetirementGeneration++,
      managedIdentity,
      holds: new Set(),
      releasedHolds: new Set(),
      settlement: undefined,
      state: "pending",
      bounded: disposal.bounded,
    };
    this.#addRetirementHolds(retirement, holds);
    this.retirements.set(workDir, retirement);
    if (this.sessions.get(workDir)?.session === session) {
      this.sessions.delete(workDir);
    }
    retirement.settlement = disposal.settlement.then((result) => {
      if (result.status === "fulfilled") {
        if (this.retirements.get(workDir) === retirement) {
          this.retirements.delete(workDir);
        }
        this.#releaseRetirementHolds(retirement);
      } else {
        retirement.state = "failed";
      }
      return result;
    });
    return retirement;
  }

  async #retireIgnoringFailure(session, workDir, context, managedIdentity) {
    const result = await this.#retire(session, workDir, context, managedIdentity).bounded;
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

  async #retireForReplacement(session, workDir, managedIdentity) {
    const retirement = this.#retire(session, workDir, "replacement", managedIdentity);
    const result = await retirement.bounded;
    if (result.status === "fulfilled") return;
    console.error(
      result.status === "timed_out"
        ? "SessionPool: managed replacement session disposal timed out"
        : "SessionPool: managed replacement session disposal failed"
    );
    const error = result.status === "rejected"
      ? this.#retirementError({ state: "failed" })
      : this.#retirementError(retirement);
    if (result.status === "timed_out") {
      error.pendingCleanup = retirement.settlement.then((settlement) => {
        if (settlement.status === "rejected") {
          throw this.#retirementError({ state: "failed" });
        }
        return settlement;
      });
    }
    throw error;
  }

  #retirementError(retirement) {
    const error = new Error("prior SDK session retirement has not completed");
    error.code = retirement.state === "failed"
      ? "SESSION_RETIREMENT_FAILED"
      : "SESSION_RETIREMENT_PENDING";
    return error;
  }

  async #createSessionBounded(workDir, managedIdentity) {
    const hold = Symbol("session creation");
    this.creationHolds.set(workDir, hold);
    const pending = Promise.resolve().then(() => this.sessionFactory(workDir));
    const result = await this.#settleBounded(pending, this.sessionCreateTimeoutMs);
    if (result.status === "fulfilled") {
      if (this.creationHolds.get(workDir) === hold) this.creationHolds.delete(workDir);
      return result.value;
    }
    if (result.status === "rejected") {
      if (this.creationHolds.get(workDir) === hold) this.creationHolds.delete(workDir);
      throw result.reason;
    }

    const error = new Error("GJC SDK session creation timed out");
    error.code = "SESSION_CREATE_TIMEOUT";
    error.pendingCleanup = pending.then(
      async (session) => {
        const retirement = this.#retire(
          session,
          workDir,
          "late-created",
          managedIdentity
        );
        const result = await retirement.bounded;
        if (result.status === "rejected") {
          console.error(
            `SessionPool: failed to dispose late-created session for ${this.#sanitize(
              workDir
            )}: ` + this.#sanitize(result.reason)
          );
          if (managedIdentity !== undefined) throw this.#retirementError(retirement);
        } else if (result.status === "timed_out") {
          console.error(
            `SessionPool: late-created session disposal timed out for ${this.#sanitize(
              workDir
            )}`
          );
          const settlement = await retirement.settlement;
          if (managedIdentity !== undefined && settlement.status === "rejected") {
            throw this.#retirementError(retirement);
          }
        }
      },
      () => {}
    );
    void error.pendingCleanup.then(
      () => {
        if (this.creationHolds.get(workDir) === hold) this.creationHolds.delete(workDir);
      },
      () => {
        if (this.creationHolds.get(workDir) === hold) this.creationHolds.delete(workDir);
      }
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
    const admittedWorkspaces = new Set([
      ...this.sessions.keys(),
      ...this.retirements.keys(),
      ...this.creationHolds.keys(),
    ]).size;
    if (!existing && admittedWorkspaces >= this.maxSessions) {
      this.#emit({
        name: "session_pool",
        action: "create",
        outcome: "denied",
        code: "SESSION_LIMIT",
      });
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
    const creationStartedAt = this.monotonicNowFn();
    this.#emit({
      name: "session_pool",
      action: "create",
      outcome: "started",
    });
    let priorRetired = false;
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
        priorRetired = true;
        await this.#retireForReplacement(
          priorSession,
          canonicalWorkDir,
          existing?.managedIdentity
        );
      }

      const session = await this.#createSessionBounded(
        canonicalWorkDir,
        managedIdentity
      );
      if (this.closed) {
        await this.#retireIgnoringFailure(
          session,
          canonicalWorkDir,
          "late-created",
          managedIdentity
        );
        throw new Error("SessionPool was shut down during session creation");
      }
      entry.session = session;
      entry.creation = undefined;
      this.#emit({
        name: "session_pool",
        action: "create",
        outcome: "settled",
        durationMs: this.#durationSince(creationStartedAt),
      });
      return session;
    })();
    void creation.then(undefined, () => {
      this.#emit({
        name: "session_pool",
        action: "create",
        outcome: "settled",
        durationMs: this.#durationSince(creationStartedAt),
      });
    });
    entry.creation = creation;
    this.sessions.set(canonicalWorkDir, entry);

    try {
      return await creation;
    } catch (error) {
      if (this.sessions.get(canonicalWorkDir) === entry) {
        if (existing && !priorRetired) {
          this.sessions.set(canonicalWorkDir, existing);
        } else {
          this.sessions.delete(canonicalWorkDir);
        }
      }
      throw error;
    }
  }

  async ensureSession(workDir, { managedIdentity, receiptIdentity } = {}) {
    if (this.closed) throw new Error("SessionPool is shut down");
    if (managedIdentity !== undefined && receiptIdentity !== undefined) {
      throw new TypeError("managedIdentity and receiptIdentity are mutually exclusive");
    }
    if (
      managedIdentity !== undefined &&
      (typeof managedIdentity !== "string" || managedIdentity.length === 0)
    ) {
      throw new TypeError("managedIdentity must be a non-empty string");
    }
    const normalizedReceiptIdentity = receiptIdentity === undefined
      ? undefined
      : normalizeReceiptIdentity(receiptIdentity);
    const effectiveManagedIdentity = normalizedReceiptIdentity === undefined
      ? managedIdentity
      : receiptIdentityKey(normalizedReceiptIdentity);
    const receiptRetirement = effectiveManagedIdentity === undefined
      ? undefined
      : this.receiptRetirements.get(effectiveManagedIdentity);
    if (receiptRetirement) {
      throw this.#retirementError(receiptRetirement);
    }

    const requestedWorkDir = validateNativeWorkDir(workDir, this.platform);

    let stat;
    try {
      stat = this.statSyncFn(requestedWorkDir);
    } catch {
      throw new Error("workDir does not exist on this host");
    }
    if (!stat.isDirectory()) {
      throw new Error("workDir is not a directory on this host");
    }

    let canonicalWorkDir;
    try {
      canonicalWorkDir = normalizeCanonicalWorkDir(
        this.realpathSyncFn(requestedWorkDir),
        this.platform
      );
      canonicalWorkDir = validateNativeWorkDir(canonicalWorkDir, this.platform);
    } catch (error) {
      throw new Error("workDir cannot be resolved on this host", {
        cause: error,
      });
    }

    const active = this.sessionTransitions.get(canonicalWorkDir);
    const retirement = this.retirements.get(canonicalWorkDir);
    if (retirement) {
      throw this.#retirementError(retirement);
    }
    if (active) {
      if (active.cleanupPending) {
        throw leaseConflict();
      }
      if (active.managedIdentity === effectiveManagedIdentity) {
        return await active.operation;
      }
      throw leaseConflict();
    }

    const rawOperation = this.#ensureCanonicalSession(
      canonicalWorkDir,
      effectiveManagedIdentity
    );
    const transition = {
      managedIdentity: effectiveManagedIdentity,
      operation: undefined,
      cleanupPending: false,
    };
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
          transition.cleanupPending = true;
          void error.pendingCleanup.then(clearTransition, clearTransition);
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

  async retireManagedReceipt(workDir, receiptIdentity, { holds } = {}) {
    if (this.closed) return;
    const identity = receiptIdentityKey(normalizeReceiptIdentity(receiptIdentity));
    const existing = this.receiptRetirements.get(identity);
    if (existing) {
      this.#addRetirementHolds(existing, holds);
      if (existing.retirement) {
        this.#transferRetirementHolds(existing, existing.retirement);
      }
      if (existing.state === "failed") {
        throw this.#retirementError(existing.retirement ?? existing);
      }
      return await existing.operation;
    }
    const receiptRetirement = {
      state: "pending",
      operation: undefined,
      retirement: undefined,
      holds: new Set(),
      releasedHolds: new Set(),
    };
    this.#addRetirementHolds(receiptRetirement, holds);
    this.receiptRetirements.set(identity, receiptRetirement);
    const operation = this.#retireManagedReceipt(identity, receiptRetirement);
    receiptRetirement.operation = operation.then(
      (result) => {
        if (!receiptRetirement.retirement) {
          this.#releaseRetirementHolds(receiptRetirement);
        }
        if (this.receiptRetirements.get(identity) === receiptRetirement) {
          this.receiptRetirements.delete(identity);
        }
        return result;
      },
      (error) => {
        if (error?.pendingCleanup) {
          void error.pendingCleanup.then(
            () => {
              if (this.receiptRetirements.get(identity) === receiptRetirement) {
                this.receiptRetirements.delete(identity);
              }
            },
            () => {
              receiptRetirement.state = "failed";
            }
          );
        } else {
          receiptRetirement.state = "failed";
        }
        throw error;
      }
    );
    return await receiptRetirement.operation;
  }

  async #retireManagedReceipt(identity, receiptRetirement) {
    const transitionMatch = [...this.sessionTransitions.entries()].find(
      ([, transition]) => transition.managedIdentity === identity
    );
    const transition = transitionMatch?.[1];
    if (transition) {
      try {
        await transition.operation;
      } catch (error) {
        if (error?.pendingCleanup) {
          try {
            await error.pendingCleanup;
          } catch (cleanupError) {
            if (
              cleanupError?.code === "SESSION_RETIREMENT_PENDING" ||
              cleanupError?.code === "SESSION_RETIREMENT_FAILED"
            ) {
              throw cleanupError;
            }
            throw this.#retirementError({ state: "failed" });
          }
        }
      }
    }
    const canonicalRetirement = [...this.retirements.values()].find(
      (retirement) => retirement.managedIdentity === identity
    );
    if (canonicalRetirement) {
      receiptRetirement.retirement = canonicalRetirement;
      this.#transferRetirementHolds(receiptRetirement, canonicalRetirement);
      const result = await canonicalRetirement.bounded;
      if (result.status === "fulfilled") return;
      const error = result.status === "rejected"
        ? this.#retirementError({ state: "failed" })
        : this.#retirementError(canonicalRetirement);
      if (result.status === "timed_out") {
        error.pendingCleanup = canonicalRetirement.settlement.then((settlement) => {
          if (settlement.status === "rejected") {
            throw this.#retirementError(canonicalRetirement);
          }
        });
      }
      throw error;
    }
    const sessionMatch = [...this.sessions.entries()].find(
      ([, entry]) => entry.managedIdentity === identity
    );
    if (!sessionMatch) {
      return;
    }
    const [canonicalWorkDir, entry] = sessionMatch;
    const session = entry.session ?? await entry.creation;
    const retirement = this.#retire(
      session,
      canonicalWorkDir,
      "receipt retirement",
      identity,
      [...receiptRetirement.holds]
    );
    receiptRetirement.retirement = retirement;
    receiptRetirement.holds.clear();
    const result = await retirement.bounded;
    if (result.status === "fulfilled") {
      return;
    }
    const error = result.status === "rejected"
      ? this.#retirementError({ state: "failed" })
      : this.#retirementError(retirement);
    if (result.status === "timed_out") {
      error.pendingCleanup = retirement.settlement.then((settlement) => {
        if (settlement.status === "rejected") throw this.#retirementError(retirement);
      });
    }
    throw error;
  }

  async shutdown() {
    if (this.closed) return;
    this.closed = true;
    this.clearIntervalFn(this.reapTimer);

    const entries = [...this.sessions.entries()];
    const shutdownRetirements = new Map(
      entries.flatMap(([workDir, entry]) =>
        entry.session
          ? [[workDir, this.#retire(
            entry.session,
            workDir,
            "shutdown",
            entry.managedIdentity
          )]]
          : []
      )
    );
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

        const result = await shutdownRetirements.get(workDir).bounded;
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
