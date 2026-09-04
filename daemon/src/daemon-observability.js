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
];
const REQUIRED_EVENT_FIELDS = ["name", "action", "outcome"];
const CLOSED_NAMES = new Set([
  "admission_budget",
  "session_pool",
  "workspace_lease_registry",
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
]);
const CLOSED_OUTCOMES = new Set(["started", "succeeded", "denied", "settled"]);
const CLOSED_CODES = new Set([
  "RESOURCE_EXHAUSTED",
  "SESSION_LIMIT",
  "LEASE_CONFLICT",
  "WORKSPACE_ADMISSION_EXCEEDED",
  "WORKSPACE_BUSY",
]);
const CLOSED_CLEANUP_STATES = new Set(["started", "fulfilled", "rejected", "timed_out"]);
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function requiredString(value, field, allowed) {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new TypeError(`owner event ${field} is invalid`);
  }
  return value;
}

function optionalOpaqueId(value, field) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !OPAQUE_ID.test(value)) {
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
    const event = projectOwnerEvent(candidate);
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
    return Object.freeze({
      schemaVersion: 1,
      ...this.snapshotReaders.admissionBudget(),
      ...this.snapshotReaders.sessionPool(),
      ...this.snapshotReaders.workspaceLeaseRegistry(),
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
  };
  return Object.freeze(event);
}

export function emitOwnerEvent(observer, event) {
  if (!observer) return undefined;
  try {
    if (typeof observer === "function") return observer(projectOwnerEvent(event));
    if (typeof observer.emitOwnerEvent === "function") return observer.emitOwnerEvent(event);
  } catch {
    return undefined;
  }
  throw new TypeError("owner observer must be a function or event emitter");
}
