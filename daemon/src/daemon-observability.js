import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

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
]);
const CLOSED_OUTCOMES = new Set([
  "started",
  "succeeded",
  "denied",
  "settled",
  "refused",
  "failed",
]);
const CLOSED_CODES = new Set(Object.values(PROTOCOL_ERROR_CODES));
const CLOSED_CLEANUP_STATES = new Set(["started", "fulfilled", "rejected", "timed_out"]);
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
  constructor() {
    this.listeners = new Set();
    this.snapshotReaders = undefined;
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
