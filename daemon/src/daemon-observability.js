import {
  PROTOCOL_ERROR_CODES,
  WORKSPACE_LIFECYCLE_OPERATIONS,
} from "@gjc-remote/shared";

const EVENT_FIELDS = [
  "name",
  "action",
  "outcome",
  "code",
  "cleanupState",
  "mappingId",
  "workspaceId",
  "transactionId",
  "fenceSequence",
  "durationMs",
  "socketGeneration",
  "readinessRevision",
  "mappingGeneration",
  "workspaceGeneration",
];
const REQUIRED_EVENT_FIELDS = ["name", "action", "outcome"];
const CLOSED_NAMES = new Set([
  "admission_budget",
  "session_pool",
  "workspace_lease_registry",
  "daemon",
]);
const CLOSED_ACTIONS = new Set([
  "invoke_capacity",
  "create",
  "managed_cleanup",
  "adopt",
  "acquire",
  "release",
  "invalidate",
  "retire",
  "invoke",
  ...Object.values(WORKSPACE_LIFECYCLE_OPERATIONS).flatMap((operations) => [
    ...operations,
  ]),
  "manual_cleanup",
]);
const CLOSED_OUTCOMES = new Set([
  "started",
  "succeeded",
  "denied",
  "settled",
  "refused",
  "failed",
  "committed",
  "required",
]);
const CLOSED_CODES = new Set([
  ...Object.values(PROTOCOL_ERROR_CODES),
  "MANUAL_CLEANUP_REQUIRED",
]);
const CLOSED_CLEANUP_STATES = new Set([
  "started",
  "fulfilled",
  "rejected",
  "timed_out",
  "not_applicable",
  "not_required",
  "manual_required",
  "indeterminate",
]);
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SNAPSHOT_KEY_CONFIGURATION_ERROR =
  "observability owner snapshots contain duplicate keys";

export function isOpaqueId(value) {
  return typeof value === "string" && OPAQUE_ID.test(value);
}

export function validateOwnerObserver(observer) {
  if (observer === undefined || observer === null || typeof observer === "function") {
    return observer;
  }
  if (
    typeof observer === "object" &&
    typeof observer.emitOwnerEvent === "function"
  ) {
    return observer;
  }
  throw new TypeError("owner observer must be a function or event emitter");
}

function requiredString(value, field, allowed) {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new TypeError(`owner event ${field} is invalid`);
  }
  return value;
}

function optionalOpaqueId(value, field) {
  if (value === undefined || value === null) return null;
  if (!isOpaqueId(value)) {
    throw new TypeError(`owner event ${field} is invalid`);
  }
  return value;
}

function optionalSafeInteger(value, field) {
  if (value === undefined || value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`owner event ${field} is invalid`);
  }
  return value;
}

/** Emits process-local, privacy-bounded facts from daemon resource owners. */
export class DaemonObservability {
  constructor({ now = () => performance.now() } = {}) {
    if (typeof now !== "function") {
      throw new TypeError("observability clock must be a function");
    }
    this.listeners = new Set();
    this.snapshotReaders = undefined;
    this.now = now;
    this.invokeTransactionsByConnection = new Map();
    this.workspaceLifecycleTransactionsByConnection = new Map();
  }

  subscribe(listener) {
    if (typeof listener !== "function") {
      throw new TypeError("observability subscriber must be a function");
    }
    this.listeners.add(listener);
    return () => this.unsubscribe(listener);
  }

  unsubscribe(listener) {
    return this.listeners.delete(listener);
  }

  emitOwnerEvent(candidate) {
    const event = normalizeOwnerEvent(candidate);
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Telemetry consumers are never allowed to affect resource ownership.
      }
    }
    return event;
  }

  attachOwners({ admissionBudget, sessionPool, workspaceLeaseRegistry } = {}) {
    if (this.snapshotReaders) {
      throw new Error("observability owners are already attached");
    }
    if (
      !admissionBudget || typeof admissionBudget.snapshot !== "function" ||
      !sessionPool || typeof sessionPool.getObservabilitySnapshot !== "function" ||
      !workspaceLeaseRegistry ||
        typeof workspaceLeaseRegistry.getAdmissionSnapshot !== "function"
    ) {
      throw new TypeError("observability requires exactly three owner snapshot readers");
    }
    this.snapshotReaders = Object.freeze({
      admissionBudget: () => admissionBudget.snapshot(),
      sessionPool: () => sessionPool.getObservabilitySnapshot(),
      workspaceLeaseRegistry: () => workspaceLeaseRegistry.getAdmissionSnapshot(),
    });
    return this;
  }

  getSnapshot() {
    if (!this.snapshotReaders) {
      throw new Error("observability owners are not attached");
    }
    const snapshots = [
      this.snapshotReaders.admissionBudget(),
      this.snapshotReaders.sessionPool(),
      this.snapshotReaders.workspaceLeaseRegistry(),
    ];
    const keys = new Set(["schemaVersion"]);
    for (const snapshot of snapshots) {
      for (const key of Object.keys(snapshot)) {
        if (keys.has(key)) throw new Error(SNAPSHOT_KEY_CONFIGURATION_ERROR);
        keys.add(key);
      }
    }
    return Object.freeze({
      schemaVersion: 1,
      ...snapshots[0],
      ...snapshots[1],
      ...snapshots[2],
    });
  }

  createInvokeTransaction(connection, requestId) {
    if (typeof requestId !== "string") {
      throw new TypeError("invoke transaction requires a validated request id");
    }
    const startedAt = this.now();
    const tracked = this.invokeTransactionsByConnection.get(connection) ?? new Set();
    this.invokeTransactionsByConnection.set(connection, tracked);
    let completed = false;
    let dispatchContext;
    const transaction = Object.freeze({
      admit: (candidate) => {
        assertInvokeDispatchShape(candidate);
        if (completed) return undefined;
        if (dispatchContext) return dispatchContext;
        try {
          dispatchContext = projectInvokeDispatchContext(candidate);
        } catch {
          dispatchContext = EMPTY_INVOKE_DISPATCH_CONTEXT;
        }
        return dispatchContext;
      },
      finish: (outcome, code = null) => {
        if (completed) return undefined;
        completed = true;
        tracked.delete(transaction);
        if (tracked.size === 0) this.invokeTransactionsByConnection.delete(connection);
        try {
          return this.emitOwnerEvent({
            name: "daemon",
            action: "invoke",
            outcome,
            code,
            transactionId: isOpaqueId(requestId) ? requestId : null,
            durationMs: boundedMonotonicDuration(this.now(), startedAt),
            ...(dispatchContext ?? EMPTY_INVOKE_DISPATCH_CONTEXT),
          });
        } catch {
          // Local telemetry must not alter daemon invoke behavior.
          return undefined;
        }
      },
    });
    tracked.add(transaction);
    return transaction;
  }

  finishInvokeTransactionsForConnection(connection, outcome, code = null) {
    for (const transaction of [
      ...(this.invokeTransactionsByConnection.get(connection) ?? []),
    ]) {
      transaction.finish(outcome, code);
    }
  }

  createWorkspaceLifecycleTransaction(connection, operation, transactionId) {
    if (!WORKSPACE_LIFECYCLE_ACTIONS.has(operation)) {
      throw new TypeError("workspace lifecycle transaction requires a validated operation");
    }
    if (typeof transactionId !== "string") {
      throw new TypeError("workspace lifecycle transaction requires a validated idempotency fingerprint");
    }
    const startedAt = this.now();
    const tracked =
      this.workspaceLifecycleTransactionsByConnection.get(connection) ?? new Set();
    this.workspaceLifecycleTransactionsByConnection.set(connection, tracked);
    let completed = false;
    let manualCleanupEmitted = false;
    let dispatchContext;
    const transaction = Object.freeze({
      admit: (candidate) => {
        assertWorkspaceLifecycleDispatchShape(candidate);
        if (completed) return undefined;
        if (dispatchContext) return dispatchContext;
        try {
          dispatchContext = projectWorkspaceLifecycleDispatchContext(candidate);
        } catch {
          dispatchContext = EMPTY_WORKSPACE_LIFECYCLE_DISPATCH_CONTEXT;
        }
        return dispatchContext;
      },
      finish: (
        outcome,
        code = null,
        cleanupState = defaultLifecycleCleanupState(operation, outcome),
      ) => {
        if (completed) return undefined;
        completed = true;
        tracked.delete(transaction);
        if (tracked.size === 0) {
          this.workspaceLifecycleTransactionsByConnection.delete(connection);
        }
        try {
          return this.emitOwnerEvent({
            name: "daemon",
            action: operation,
            outcome,
            code,
            cleanupState,
            transactionId: isOpaqueId(transactionId) ? transactionId : null,
            durationMs: boundedMonotonicDuration(this.now(), startedAt),
            ...(dispatchContext ?? EMPTY_WORKSPACE_LIFECYCLE_DISPATCH_CONTEXT),
          });
        } catch {
          return undefined;
        }
      },
      emitManualCleanupRequired: () => {
        if (manualCleanupEmitted) return undefined;
        manualCleanupEmitted = true;
        try {
          return this.emitOwnerEvent({
            name: "daemon",
            action: "manual_cleanup",
            outcome: "required",
            code: "MANUAL_CLEANUP_REQUIRED",
            cleanupState: "manual_required",
            transactionId: isOpaqueId(transactionId) ? transactionId : null,
            durationMs: boundedMonotonicDuration(this.now(), startedAt),
            ...(dispatchContext ?? EMPTY_WORKSPACE_LIFECYCLE_DISPATCH_CONTEXT),
          });
        } catch {
          return undefined;
        }
      },
    });
    tracked.add(transaction);
    return transaction;
  }

  finishWorkspaceLifecycleTransactionsForConnection(connection, outcome, code = null) {
    for (const transaction of [
      ...(this.workspaceLifecycleTransactionsByConnection.get(connection) ?? []),
    ]) {
      transaction.finish(outcome, code);
    }
  }
}

const EMPTY_INVOKE_DISPATCH_CONTEXT = Object.freeze({
  socketGeneration: null,
  readinessRevision: null,
  mappingGeneration: null,
  workspaceGeneration: null,
  mappingId: null,
  workspaceId: null,
  fenceSequence: null,
});
const INVOKE_DISPATCH_FIELDS = new Set(Object.keys(
  EMPTY_INVOKE_DISPATCH_CONTEXT,
));
const EMPTY_WORKSPACE_LIFECYCLE_DISPATCH_CONTEXT = EMPTY_INVOKE_DISPATCH_CONTEXT;
const WORKSPACE_LIFECYCLE_DISPATCH_FIELDS = INVOKE_DISPATCH_FIELDS;
const WORKSPACE_LIFECYCLE_ACTIONS = new Set(
  Object.values(WORKSPACE_LIFECYCLE_OPERATIONS).flatMap((operations) => [
    ...operations,
  ]),
);
const DESTRUCTIVE_LIFECYCLE_ACTIONS = new Set([
  "reset",
  "delete",
  "restore",
  "migration",
]);

export function isDestructiveLifecycleAction(operation) {
  return DESTRUCTIVE_LIFECYCLE_ACTIONS.has(operation);
}

function defaultLifecycleCleanupState(operation, outcome) {
  return isDestructiveLifecycleAction(operation) &&
    outcome !== "committed"
    ? "indeterminate"
    : "not_applicable";
}

function projectInvokeDispatchContext(candidate) {
  assertInvokeDispatchShape(candidate);
  const {
    socketGeneration,
    readinessRevision,
    mappingGeneration,
    workspaceGeneration,
    mappingId,
    workspaceId,
    fenceSequence,
  } = candidate;
  const projected = projectOwnerEvent({
    name: "daemon",
    action: "invoke",
    outcome: "started",
    code: null,
    durationMs: 0,
    socketGeneration,
    readinessRevision,
    mappingGeneration,
    workspaceGeneration,
    mappingId,
    workspaceId,
    fenceSequence,
  });
  return Object.freeze({
    socketGeneration: projected.socketGeneration,
    readinessRevision: projected.readinessRevision,
    mappingGeneration: projected.mappingGeneration,
    workspaceGeneration: projected.workspaceGeneration,
    mappingId: projected.mappingId,
    workspaceId: projected.workspaceId,
    fenceSequence: projected.fenceSequence,
  });
}

function assertInvokeDispatchShape(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new TypeError("invoke dispatch context must be an object");
  }
  if (
    Object.keys(candidate).length !== INVOKE_DISPATCH_FIELDS.size ||
    Object.keys(candidate).some((key) => !INVOKE_DISPATCH_FIELDS.has(key))
  ) {
    throw new TypeError("invoke dispatch context has invalid fields");
  }
}

function projectWorkspaceLifecycleDispatchContext(candidate) {
  assertWorkspaceLifecycleDispatchShape(candidate);
  const projected = projectOwnerEvent({
    name: "daemon",
    action: "create",
    outcome: "committed",
    code: null,
    cleanupState: "not_applicable",
    durationMs: 0,
    ...candidate,
  });
  return Object.freeze({
    socketGeneration: projected.socketGeneration,
    readinessRevision: projected.readinessRevision,
    mappingGeneration: projected.mappingGeneration,
    workspaceGeneration: projected.workspaceGeneration,
    mappingId: projected.mappingId,
    workspaceId: projected.workspaceId,
    fenceSequence: projected.fenceSequence,
  });
}

function assertWorkspaceLifecycleDispatchShape(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new TypeError("workspace lifecycle dispatch context must be an object");
  }
  if (
    Object.keys(candidate).length !== WORKSPACE_LIFECYCLE_DISPATCH_FIELDS.size ||
    Object.keys(candidate).some(
      (key) => !WORKSPACE_LIFECYCLE_DISPATCH_FIELDS.has(key),
    )
  ) {
    throw new TypeError("workspace lifecycle dispatch context has invalid fields");
  }
}

function boundedMonotonicDuration(now, startedAt) {
  const duration = Math.floor(now - startedAt);
  if (!Number.isFinite(duration) || duration <= 0) return 0;
  return Math.min(duration, Number.MAX_SAFE_INTEGER);
}

export function projectOwnerEvent(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new TypeError("owner event must be a flat object");
  }
  for (const key of Object.keys(candidate)) {
    if (!EVENT_FIELDS.includes(key)) throw new TypeError("owner event has an unknown field");
    if (candidate[key] && typeof candidate[key] === "object") {
      throw new TypeError("owner event must be flat");
    }
  }
  for (const field of REQUIRED_EVENT_FIELDS) {
    if (candidate[field] === undefined) throw new TypeError(`owner event ${field} is required`);
  }
  const event = {
    schemaVersion: 1,
    name: requiredString(candidate.name, "name", CLOSED_NAMES),
    action: requiredString(candidate.action, "action", CLOSED_ACTIONS),
    outcome: requiredString(candidate.outcome, "outcome", CLOSED_OUTCOMES),
    code: candidate.code === undefined || candidate.code === null
      ? null
      : requiredString(candidate.code, "code", CLOSED_CODES),
    cleanupState: candidate.cleanupState === undefined || candidate.cleanupState === null
      ? null
      : requiredString(candidate.cleanupState, "cleanupState", CLOSED_CLEANUP_STATES),
    mappingId: optionalOpaqueId(candidate.mappingId, "mappingId"),
    workspaceId: optionalOpaqueId(candidate.workspaceId, "workspaceId"),
    transactionId: optionalOpaqueId(candidate.transactionId, "transactionId"),
    fenceSequence: optionalSafeInteger(
      candidate.fenceSequence,
      "fenceSequence",
    ),
    durationMs: optionalSafeInteger(candidate.durationMs, "durationMs"),
    socketGeneration: optionalSafeInteger(
      candidate.socketGeneration,
      "socketGeneration",
    ),
    readinessRevision: optionalSafeInteger(
      candidate.readinessRevision,
      "readinessRevision",
    ),
    mappingGeneration: optionalSafeInteger(
      candidate.mappingGeneration,
      "mappingGeneration",
    ),
    workspaceGeneration: optionalSafeInteger(
      candidate.workspaceGeneration,
      "workspaceGeneration",
    ),
  };
  return Object.freeze(event);
}

function normalizeOwnerEvent(candidate) {
  if (candidate?.schemaVersion !== 1) return projectOwnerEvent(candidate);
  const raw = {};
  for (const field of EVENT_FIELDS) raw[field] = candidate[field];
  const projected = projectOwnerEvent(raw);
  if (
    Object.keys(candidate).length !== Object.keys(projected).length ||
    Object.keys(projected).some(
      (key) => !Object.hasOwn(candidate, key) ||
        !Object.is(candidate[key], projected[key]),
    )
  ) {
    throw new TypeError("projected owner event is invalid");
  }
  return projected;
}

export function emitOwnerEvent(observer, event) {
  const validatedObserver = validateOwnerObserver(observer);
  if (validatedObserver === undefined || validatedObserver === null) return undefined;
  try {
    const projected = projectOwnerEvent(event);
    if (typeof validatedObserver === "function") {
      return validatedObserver(projected);
    }
    return validatedObserver.emitOwnerEvent(projected);
  } catch {
    return undefined;
  }
}
