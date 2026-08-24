// Shared WS message shapes between bot/ and daemon/.
// Kept dependency-free and framework-agnostic so both sides can import it
// directly (Node ESM) without a build step.
import { isWorkspaceAuthorityDescriptor } from "./workspace-binding.js";

export const MAX_WS_PAYLOAD_BYTES = 8 * 1024 * 1024;

export const V0_LIMITS = Object.freeze({
  HOST_ID: 128,
  TOKEN: 4096,
  LABEL: 256,
  REQUEST_ID: 128,
  WORK_DIR: 4096,
  // Leaves headroom for worst-case JSON escaping plus invoke metadata.
  MESSAGE: 1024 * 1024,
  MODEL_NAME: 512,
  ERROR: 4096,
  DENIAL_REASON: 1024,
  // Bounds concurrent in-flight invokes per host so a single daemon cannot
  // grow the bot's pending-request map without limit. Excess invokes are
  // rejected locally (fail-closed) rather than queued or dropped silently.
  MAX_PENDING_PER_HOST: 64,
  // Bounds on the additive v1 protocol negotiation fields (see PROTOCOL_VERSION).
  CAPABILITY: 64,
  MAX_CAPABILITIES: 32,
  // Bounds on the additive #35 ask/gate answer channel. gateId mirrors a UUID;
  // prompt/choice labels are rendered to a Discord channel; answer reuses the
  // MESSAGE bound since it is user chat text routed back as a gate answer.
  GATE_ID: 128,
  GATE_PROMPT: 16 * 1024,
  CHOICE_LABEL: 1024,
  MAX_CHOICES: 64,
  PROTOCOL_VERSION_MAX: 1_000_000,
});
export const WORKSPACE_READINESS_CAPABILITY = "workspace_readiness_v2";
export const WORKSPACE_READINESS_V2_CAPABILITY = WORKSPACE_READINESS_CAPABILITY;
export const PROTOCOL_VERSION_V2 = 2;
export const PROTOCOL_VERSION_V3 = 3;
export const WORKSPACE_INVENTORY_RECEIPT_CAPABILITY = "workspace_inventory_receipt_v2";
export const INVENTORY_RECEIPT_TTL_MS = 10_000;
export const WORKSPACE_READINESS_V2 = WORKSPACE_READINESS_CAPABILITY;

/**
 * Bounded v2 workspace/readiness fields. These limits are intentionally
 * independent from the legacy v0 limits so adding v2 fields cannot change
 * validation of existing frames.
 */
export const V2_LIMITS = Object.freeze({
  WORKSPACE_ID: 128,
  MAPPING_ID: 128,
  SOCKET_GENERATION: Number.MAX_SAFE_INTEGER,
  WORKSPACE_GENERATION: Number.MAX_SAFE_INTEGER,
  MAPPING_GENERATION: Number.MAX_SAFE_INTEGER,
  MAPPING_VERSION: Number.MAX_SAFE_INTEGER,
  READINESS_REVISION: Number.MAX_SAFE_INTEGER,
  READINESS_ERROR_CODE: 64,
  READINESS_REMEDIATION_CODE: 64,
  READINESS_REMEDIATION_ACTION: 32,
});

/** Readiness TTL is receiver-clamped; sender values outside this range fail closed. */
export const READINESS_MIN_TTL_MS = 1_000;
export const READINESS_MAX_TTL_MS = 60_000;
export const READINESS_DEFAULT_TTL_MS = READINESS_MAX_TTL_MS;
export const READINESS_MAX_SKEW_MS = 5 * 60 * 1_000;

/**
 * The opaque workspace identifier is deliberately narrower than a path or
 * URL. It is safe to log and to use as a lookup key, but is never a path.
 */
export const WORKSPACE_ID_MAX_LENGTH = V2_LIMITS.WORKSPACE_ID;
export const WORKSPACE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Stable readiness dimensions and their complete wire-level value sets. */
export const READINESS_DIMENSIONS = Object.freeze([
  "connection",
  "runtime",
  "providerAuth",
  "modelProfile",
  "workspace",
]);
export const READINESS_STATUS_VALUES = Object.freeze({
  connection: Object.freeze(["online", "offline"]),
  runtime: Object.freeze(["ready", "incompatible", "error"]),
  providerAuth: Object.freeze(["configured", "missing", "invalid", "unknown"]),
  modelProfile: Object.freeze(["ready", "missing", "invalid", "unknown"]),
  workspace: Object.freeze(["ready", "unavailable", "unknown"]),
});
export const READINESS_DIMENSION_VALUES = READINESS_STATUS_VALUES;
export const READINESS_STATUSES = READINESS_STATUS_VALUES;
export const READINESS_AGGREGATE_STATUSES = Object.freeze([
  "online",
  "offline",
  "incompatible",
  "degraded",
  "connected-not-ready",
  "ready",
]);
export const READINESS_CONNECTION_STATUS = Object.freeze({
  ONLINE: "online",
  OFFLINE: "offline",
});
export const READINESS_RUNTIME_STATUS = Object.freeze({
  READY: "ready",
  INCOMPATIBLE: "incompatible",
  ERROR: "error",
});
export const READINESS_PROVIDER_AUTH_STATUS = Object.freeze({
  CONFIGURED: "configured",
  MISSING: "missing",
  INVALID: "invalid",
  UNKNOWN: "unknown",
});
export const READINESS_MODEL_PROFILE_STATUS = Object.freeze({
  READY: "ready",
  MISSING: "missing",
  INVALID: "invalid",
  UNKNOWN: "unknown",
});
export const READINESS_WORKSPACE_STATUS = Object.freeze({
  READY: "ready",
  UNAVAILABLE: "unavailable",
  UNKNOWN: "unknown",
});

/** Stable remediation actions exposed to readiness consumers. */
export const READINESS_REMEDIATION_ACTIONS = Object.freeze([
  "login",
  "repair_profile",
  "retry_later",
  "refresh_workspace",
  "contact_admin",
]);

/**
 * Stable public error taxonomy. Keep values wire-compatible and path-free.
 * Category-specific views below make it possible for consumers to avoid
 * duplicating string literals while retaining one canonical taxonomy.
 */
export const PROTOCOL_ERROR_CODES = Object.freeze({
  AUTH_REJECTED: "AUTH_REJECTED",
  PROTOCOL_INCOMPATIBLE: "PROTOCOL_INCOMPATIBLE",
  CONNECTION_LOST: "CONNECTION_LOST",
  HEARTBEAT_TIMEOUT: "HEARTBEAT_TIMEOUT",
  PROVIDER_MISSING: "PROVIDER_MISSING",
  PROVIDER_INVALID: "PROVIDER_INVALID",
  PROVIDER_EXPIRED: "PROVIDER_EXPIRED",
  PROVIDER_UNAVAILABLE: "PROVIDER_UNAVAILABLE",
  MODEL_PROFILE_MISSING: "MODEL_PROFILE_MISSING",
  MODEL_PROFILE_INVALID: "MODEL_PROFILE_INVALID",
  RUNTIME_INCOMPATIBLE: "RUNTIME_INCOMPATIBLE",
  CONFIG_INVALID: "CONFIG_INVALID",
  UNKNOWN_RUNTIME: "UNKNOWN_RUNTIME",
  INVENTORY_PENDING: "INVENTORY_PENDING",
  INVENTORY_INVALID: "INVENTORY_INVALID",
  INVENTORY_ACCESS_DENIED: "INVENTORY_ACCESS_DENIED",
  INVENTORY_STALE: "INVENTORY_STALE",
  INVENTORY_MANUAL_CLEANUP: "INVENTORY_MANUAL_CLEANUP",
  INVENTORY_IO_FAILED: "INVENTORY_IO_FAILED",
  WORKSPACE_NOT_FOUND: "WORKSPACE_NOT_FOUND",
  WORKSPACE_ROOT_ESCAPE: "WORKSPACE_ROOT_ESCAPE",
  CONTAINMENT_UNSUPPORTED: "CONTAINMENT_UNSUPPORTED",
  MAPPING_ID_REQUIRED: "MAPPING_ID_REQUIRED",
  WORKSPACE_MAPPING_CHANGED: "WORKSPACE_MAPPING_CHANGED",
  MAPPING_GENERATION_STALE: "MAPPING_GENERATION_STALE",
  WORKSPACE_BUSY: "WORKSPACE_BUSY",
  WORKSPACE_GENERATION_STALE: "WORKSPACE_GENERATION_STALE",
  LEASE_CONFLICT: "LEASE_CONFLICT",
  GIT_GRAPH_INCOMPLETE: "GIT_GRAPH_INCOMPLETE",
  GIT_AUTH_FAILED: "GIT_AUTH_FAILED",
  GIT_NETWORK_FAILED: "GIT_NETWORK_FAILED",
  READINESS_TIMESTAMP_INVALID: "READINESS_TIMESTAMP_INVALID",
  READINESS_REPLAYED: "READINESS_REPLAYED",
  READINESS_EXPIRED: "READINESS_EXPIRED",
  RESOURCE_EXHAUSTED: "RESOURCE_EXHAUSTED",
  SESSION_LIMIT: "SESSION_LIMIT",
  WORKSPACE_ADMISSION_EXCEEDED: "WORKSPACE_ADMISSION_EXCEEDED",
  SESSION_CREATE_TIMEOUT: "SESSION_CREATE_TIMEOUT",
  SHUTDOWN_TIMEOUT: "SHUTDOWN_TIMEOUT",
  DAEMON_FATAL: "DAEMON_FATAL",
  UNHANDLED_REJECTION: "UNHANDLED_REJECTION",
  UNCAUGHT_EXCEPTION: "UNCAUGHT_EXCEPTION",
});
export const READINESS_ERROR_CODES = PROTOCOL_ERROR_CODES;
export const READINESS_ERROR_TAXONOMY = Object.freeze({
  transport: Object.freeze([
    PROTOCOL_ERROR_CODES.AUTH_REJECTED,
    PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
    PROTOCOL_ERROR_CODES.CONNECTION_LOST,
    PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT,
  ]),
  providerProfile: Object.freeze([
    PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
    PROTOCOL_ERROR_CODES.PROVIDER_INVALID,
    PROTOCOL_ERROR_CODES.PROVIDER_EXPIRED,
    PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE,
    PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING,
    PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID,
  ]),
  runtimeConfig: Object.freeze([
    PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
    PROTOCOL_ERROR_CODES.CONFIG_INVALID,
    PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
  ]),
  workspaceMappingLease: Object.freeze([
    PROTOCOL_ERROR_CODES.INVENTORY_PENDING,
    PROTOCOL_ERROR_CODES.INVENTORY_INVALID,
    PROTOCOL_ERROR_CODES.INVENTORY_ACCESS_DENIED,
    PROTOCOL_ERROR_CODES.INVENTORY_STALE,
    PROTOCOL_ERROR_CODES.INVENTORY_MANUAL_CLEANUP,
    PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED,
    PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
    PROTOCOL_ERROR_CODES.WORKSPACE_ROOT_ESCAPE,
    PROTOCOL_ERROR_CODES.CONTAINMENT_UNSUPPORTED,
    PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED,
    PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
    PROTOCOL_ERROR_CODES.MAPPING_GENERATION_STALE,
    PROTOCOL_ERROR_CODES.WORKSPACE_BUSY,
    PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
    PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
  ]),
  git: Object.freeze([
    PROTOCOL_ERROR_CODES.GIT_GRAPH_INCOMPLETE,
    PROTOCOL_ERROR_CODES.GIT_AUTH_FAILED,
    PROTOCOL_ERROR_CODES.GIT_NETWORK_FAILED,
  ]),
  readiness: Object.freeze([
    PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID,
    PROTOCOL_ERROR_CODES.READINESS_REPLAYED,
    PROTOCOL_ERROR_CODES.READINESS_EXPIRED,
  ]),
  resourceSession: Object.freeze([
    PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED,
    PROTOCOL_ERROR_CODES.SESSION_LIMIT,
    PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED,
    PROTOCOL_ERROR_CODES.SESSION_CREATE_TIMEOUT,
    PROTOCOL_ERROR_CODES.SHUTDOWN_TIMEOUT,
  ]),
  fatal: Object.freeze([
    PROTOCOL_ERROR_CODES.DAEMON_FATAL,
    PROTOCOL_ERROR_CODES.UNHANDLED_REJECTION,
    PROTOCOL_ERROR_CODES.UNCAUGHT_EXCEPTION,
  ]),
});
export const ERROR_CODES = PROTOCOL_ERROR_CODES;
/**
 * Canonical remediation tuples for all public protocol/readiness errors.
 * Consumers MUST copy a tuple before adding local diagnostic fields.
 */
const remediationTuple = (code, retryable, action) =>
  Object.freeze({ code, retryable, action });

export const READINESS_REMEDIATIONS = Object.freeze({
  [PROTOCOL_ERROR_CODES.AUTH_REJECTED]: remediationTuple(
    PROTOCOL_ERROR_CODES.AUTH_REJECTED,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE]: remediationTuple(
    PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.CONNECTION_LOST]: remediationTuple(
    PROTOCOL_ERROR_CODES.CONNECTION_LOST,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT]: remediationTuple(
    PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.PROVIDER_MISSING]: remediationTuple(
    PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
    true,
    "login"
  ),
  [PROTOCOL_ERROR_CODES.PROVIDER_INVALID]: remediationTuple(
    PROTOCOL_ERROR_CODES.PROVIDER_INVALID,
    false,
    "repair_profile"
  ),
  [PROTOCOL_ERROR_CODES.PROVIDER_EXPIRED]: remediationTuple(
    PROTOCOL_ERROR_CODES.PROVIDER_EXPIRED,
    true,
    "login"
  ),
  [PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE]: remediationTuple(
    PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING]: remediationTuple(
    PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING,
    false,
    "repair_profile"
  ),
  [PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID]: remediationTuple(
    PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID,
    false,
    "repair_profile"
  ),
  [PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE]: remediationTuple(
    PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.CONFIG_INVALID]: remediationTuple(
    PROTOCOL_ERROR_CODES.CONFIG_INVALID,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME]: remediationTuple(
    PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.INVENTORY_PENDING]: remediationTuple(
    PROTOCOL_ERROR_CODES.INVENTORY_PENDING,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.INVENTORY_INVALID]: remediationTuple(
    PROTOCOL_ERROR_CODES.INVENTORY_INVALID,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.INVENTORY_ACCESS_DENIED]: remediationTuple(
    PROTOCOL_ERROR_CODES.INVENTORY_ACCESS_DENIED,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.INVENTORY_STALE]: remediationTuple(
    PROTOCOL_ERROR_CODES.INVENTORY_STALE,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.INVENTORY_MANUAL_CLEANUP]: remediationTuple(
    PROTOCOL_ERROR_CODES.INVENTORY_MANUAL_CLEANUP,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED]: remediationTuple(
    PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND]: remediationTuple(
    PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
    false,
    "refresh_workspace"
  ),
  [PROTOCOL_ERROR_CODES.WORKSPACE_ROOT_ESCAPE]: remediationTuple(
    PROTOCOL_ERROR_CODES.WORKSPACE_ROOT_ESCAPE,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.CONTAINMENT_UNSUPPORTED]: remediationTuple(
    PROTOCOL_ERROR_CODES.CONTAINMENT_UNSUPPORTED,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED]: remediationTuple(
    PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED]: remediationTuple(
    PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
    false,
    "refresh_workspace"
  ),
  [PROTOCOL_ERROR_CODES.MAPPING_GENERATION_STALE]: remediationTuple(
    PROTOCOL_ERROR_CODES.MAPPING_GENERATION_STALE,
    false,
    "refresh_workspace"
  ),
  [PROTOCOL_ERROR_CODES.WORKSPACE_BUSY]: remediationTuple(
    PROTOCOL_ERROR_CODES.WORKSPACE_BUSY,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE]: remediationTuple(
    PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
    false,
    "refresh_workspace"
  ),
  [PROTOCOL_ERROR_CODES.LEASE_CONFLICT]: remediationTuple(
    PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.GIT_GRAPH_INCOMPLETE]: remediationTuple(
    PROTOCOL_ERROR_CODES.GIT_GRAPH_INCOMPLETE,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.GIT_AUTH_FAILED]: remediationTuple(
    PROTOCOL_ERROR_CODES.GIT_AUTH_FAILED,
    false,
    "login"
  ),
  [PROTOCOL_ERROR_CODES.GIT_NETWORK_FAILED]: remediationTuple(
    PROTOCOL_ERROR_CODES.GIT_NETWORK_FAILED,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID]: remediationTuple(
    PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.READINESS_REPLAYED]: remediationTuple(
    PROTOCOL_ERROR_CODES.READINESS_REPLAYED,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.READINESS_EXPIRED]: remediationTuple(
    PROTOCOL_ERROR_CODES.READINESS_EXPIRED,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED]: remediationTuple(
    PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.SESSION_LIMIT]: remediationTuple(
    PROTOCOL_ERROR_CODES.SESSION_LIMIT,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED]: remediationTuple(
    PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.SESSION_CREATE_TIMEOUT]: remediationTuple(
    PROTOCOL_ERROR_CODES.SESSION_CREATE_TIMEOUT,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.SHUTDOWN_TIMEOUT]: remediationTuple(
    PROTOCOL_ERROR_CODES.SHUTDOWN_TIMEOUT,
    true,
    "retry_later"
  ),
  [PROTOCOL_ERROR_CODES.DAEMON_FATAL]: remediationTuple(
    PROTOCOL_ERROR_CODES.DAEMON_FATAL,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.UNHANDLED_REJECTION]: remediationTuple(
    PROTOCOL_ERROR_CODES.UNHANDLED_REJECTION,
    false,
    "contact_admin"
  ),
  [PROTOCOL_ERROR_CODES.UNCAUGHT_EXCEPTION]: remediationTuple(
    PROTOCOL_ERROR_CODES.UNCAUGHT_EXCEPTION,
    false,
    "contact_admin"
  ),
});
/** Aliases retain one canonical mapping for consumers using map terminology. */
export const READINESS_REMEDIATION_MAP = READINESS_REMEDIATIONS;
export const READINESS_REMEDIATION_BY_CODE = READINESS_REMEDIATIONS;

/**
 * Wire protocol version this build speaks. v0 (legacy) daemons omit
 * `protocolVersion`/`capabilities` entirely; both sides MUST keep treating a
 * missing version as 0 so the handshake stays backward compatible.
 */
export const PROTOCOL_VERSION = 1;

/** Capabilities this build advertises during the register handshake. */
export const CAPABILITIES = Object.freeze(["invoke", "set_model", "heartbeat"]);

/**
 * host -> bot, sent immediately after the daemon opens its WS connection.
 * `protocolVersion` and `capabilities` are additive v1 fields; legacy v0
 * daemons omit them.
 * @typedef {{ type: "register", hostId: string, token: string, label?: string,
 *   protocolVersion?: number, capabilities?: string[] }} RegisterMessage
 */

/**
 * bot -> host, one GJC invocation request routed to a specific working directory.
 * @typedef {{
 *   type: "invoke",
 *   requestId: string,
 *   workDir?: string,
 *   bindingId?: string,
 *   mappingId?: string,
 *   mappingGeneration?: number,
 *   mappingVersion?: number,
 *   workspaceId?: string,
 *   workspaceGeneration?: number,
 *   command: { kind: "prompt" | "steer" | "follow_up", message: string }
 *     | { kind: "set_model", modelName: string },
 * }} InvokeMessage
 *
 * `set_model.modelName` is a unique name/id query or exact `provider:modelId`.
 */

/**
 * host -> bot, streamed GJC RPC events for a given requestId until `done: true`.
 * @typedef {{ type: "event", requestId: string, event: object, done?: boolean, error?: string }} EventMessage
 */

/** bot -> host, health check. */
export const PING = { type: "ping" };

/** host -> bot, health check reply. */
export const PONG = { type: "pong" };

export const MSG_TYPES = Object.freeze({
  REGISTER: "register",
  REGISTER_OK: "register_ok",
  REGISTER_DENIED: "register_denied",
  BIND_WORKSPACE: "bind_workspace",
  BIND_OK: "bind_ok",
  UNBIND_WORKSPACE: "unbind_workspace",
  UNBIND_OK: "unbind_ok",
  INVOKE: "invoke",
  EVENT: "event",
  PING: "ping",
  PONG: "pong",
  // #35: additive ask/gate answer channel. ANSWER is a top-level bot->host
  // message; GATE_REQUEST is an event *subtype* that rides an EventMessage's
  // `event` payload (daemon->bot). v0 peers that don't know these simply never
  // emit ANSWER and treat an unrecognized event subtype as an ignorable event.
  ANSWER: "answer",
  GATE_REQUEST: "gate_request",
  READINESS: "readiness",
});
function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactFields(value, fields) {
  return isObject(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => hasOwn(value, field));
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isBoundedString(value, maxLength, allowEmpty = false) {
  return (
    typeof value === "string" &&
    value.length <= maxLength &&
    (allowEmpty || value.length > 0)
  );
}

export function isModelName(value) {
  return isBoundedString(value, V0_LIMITS.MODEL_NAME);
}

/**
 * Additive v1 negotiation field: a non-negative, bounded integer version.
 * Absence is treated as v0 by callers, so this only validates present values.
 */
export function isProtocolVersion(value) {
  return (
    Number.isInteger(value) &&
    value >= 0 &&
    value <= PROTOCOL_VERSION_V3
  );
}

/** Additive v1 negotiation field: a bounded array of bounded capability tags. */
export function isCapabilityList(value) {
  return (
    Array.isArray(value) &&
    value.length <= V0_LIMITS.MAX_CAPABILITIES &&
    value.every((cap) => isBoundedString(cap, V0_LIMITS.CAPABILITY))
  );
}
/**
 * Validate the opaque workspace lookup key used by v2 frames. Path separators,
 * whitespace, control characters, and URL punctuation are intentionally not
 * part of the safe alphabet.
 */
export function isWorkspaceId(value) {
  return (
    isBoundedString(value, WORKSPACE_ID_MAX_LENGTH) &&
    WORKSPACE_ID_PATTERN.test(value)
  );
}
export function isMappingId(value) {
  return (
    isBoundedString(value, V2_LIMITS.MAPPING_ID) &&
    WORKSPACE_ID_PATTERN.test(value)
  );
}

export function isMappingGeneration(value) {
  return isBoundedSafeInteger(value, 1, V2_LIMITS.MAPPING_GENERATION);
}

export function isMappingVersion(value) {
  return isBoundedSafeInteger(value, 1, V2_LIMITS.MAPPING_VERSION);
}

function isBoundedSafeInteger(value, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

export function isReadinessRevision(value) {
  return isBoundedSafeInteger(value, 1, V2_LIMITS.READINESS_REVISION);
}

export function isReadinessSocketGeneration(value) {
  return isBoundedSafeInteger(value, 1, V2_LIMITS.SOCKET_GENERATION);
}

export function isReadinessWorkspaceGeneration(value) {
  return isBoundedSafeInteger(value, 1, V2_LIMITS.WORKSPACE_GENERATION);
}

export function isReadinessTtl(value) {
  return (
    Number.isSafeInteger(value) &&
    value >= READINESS_MIN_TTL_MS &&
    value <= READINESS_MAX_TTL_MS
  );
}

export function normalizeReadinessTtl(value) {
  return value === undefined ? READINESS_DEFAULT_TTL_MS : value;
}

function isReadinessTimestamp(value) {
  return isBoundedSafeInteger(value, 0);
}

function isKnownErrorCode(value) {
  return (
    isBoundedString(value, V2_LIMITS.READINESS_ERROR_CODE) &&
    Object.values(PROTOCOL_ERROR_CODES).includes(value)
  );
}

function isReadinessRemediation(value) {
  if (!isObject(value)) return false;
  if (
    !hasOwn(value, "code") ||
    !hasOwn(value, "retryable") ||
    !hasOwn(value, "action") ||
    !isKnownErrorCode(value.code) ||
    typeof value.retryable !== "boolean" ||
    !READINESS_REMEDIATION_ACTIONS.includes(value.action)
  ) {
    return false;
  }
  return Object.keys(value).every(
    (key) => key === "code" || key === "retryable" || key === "action"
  );
}

export function isReadinessError(value) {
  if (
    !isObject(value) ||
    !hasOwn(value, "code") ||
    !hasOwn(value, "at") ||
    !hasOwn(value, "remediation") ||
    !isKnownErrorCode(value.code) ||
    !isReadinessTimestamp(value.at) ||
    !isReadinessRemediation(value.remediation)
  ) {
    return false;
  }
  const expectedRemediation = READINESS_REMEDIATIONS[value.code];
  if (
    !expectedRemediation ||
    value.remediation.code !== expectedRemediation.code ||
    value.remediation.retryable !== expectedRemediation.retryable ||
    value.remediation.action !== expectedRemediation.action
  ) {
    return false;
  }
  return Object.keys(value).every(
    (key) => key === "code" || key === "at" || key === "remediation"
  );
}

export function isReadinessStatus(value) {
  if (!isObject(value) || Object.keys(value).length !== READINESS_DIMENSIONS.length) {
    return false;
  }
  return READINESS_DIMENSIONS.every(
    (dimension) =>
      hasOwn(value, dimension) &&
      typeof value[dimension] === "string" &&
      READINESS_STATUS_VALUES[dimension].includes(value[dimension])
  );
}

function isReadinessFrameShape(value) {
  if (
    !isObject(value) ||
    value.type !== MSG_TYPES.READINESS ||
    !isReadinessSocketGeneration(value.socketGeneration) ||
    !isReadinessRevision(value.revision) ||
    !isReadinessTimestamp(value.observedAt) ||
    !isReadinessStatus(value.status)
  ) {
    return false;
  }

  const allowedFields = new Set([
    "type",
    "socketGeneration",
    "revision",
    "observedAt",
    "ttlMs",
    "workspaceId",
    "workspaceGeneration",
    "bindingId",
    "status",
    "lastError",
    "expiresAt",
  ]);
  if (!Object.keys(value).every((key) => allowedFields.has(key))) return false;

  if (hasOwn(value, "ttlMs") && !isReadinessTtl(value.ttlMs)) return false;
  if (hasOwn(value, "expiresAt") && !isReadinessTimestamp(value.expiresAt)) return false;
  if (hasOwn(value, "lastError") && !isReadinessError(value.lastError)) return false;

  const hasWorkspaceId = hasOwn(value, "workspaceId");
  const hasWorkspaceGeneration = hasOwn(value, "workspaceGeneration");
  if (hasWorkspaceId !== hasWorkspaceGeneration) return false;
  if (hasWorkspaceId) {
    return (
      isWorkspaceId(value.workspaceId) &&
      isReadinessWorkspaceGeneration(value.workspaceGeneration) &&
      (!hasOwn(value, "bindingId") || isMappingId(value.bindingId))
    );
  }
  if (hasOwn(value, "bindingId") && !isMappingId(value.bindingId)) return false;
  return true;
}

/**
 * Validate a v2 readiness frame. The optional `context` argument lets a
 * receiver apply its current socket/revision fence without moving that state
 * into this dependency-free shared module.
 */
export function isReadinessMessage(value, context = undefined) {
  if (!isReadinessFrameShape(value)) return false;
  return isReadinessContextValid(value, context);
}

function isReadinessContextValid(value, context) {
  if (!isObject(context)) return true;

  const currentSocketGeneration =
    context.currentSocketGeneration ?? context.socketGeneration;
  if (
    currentSocketGeneration !== undefined &&
    value.socketGeneration !== currentSocketGeneration
  ) {
    return false;
  }

  const previous =
    context.previous ??
    context.previousFrame ??
    (context.type === MSG_TYPES.READINESS ? context : undefined);
  if (isObject(previous)) {
    if (
      previous.socketGeneration === value.socketGeneration &&
      isReadinessRevision(previous.revision) &&
      value.revision <= previous.revision
    ) {
      return false;
    }
    if (
      isReadinessTimestamp(previous.observedAt) &&
      value.observedAt < previous.observedAt
    ) {
      return false;
    }
  }

  const receivedAt = context.receivedAt;
  if (receivedAt !== undefined && isReadinessTimestamp(receivedAt)) {
    if (Math.abs(value.observedAt - receivedAt) > READINESS_MAX_SKEW_MS) {
      return false;
    }
  }
  return true;
}

export const isWorkspaceReadinessMessage = isReadinessMessage;

const INVENTORY_RECEIPT_READINESS_ERRORS = new Set([
  PROTOCOL_ERROR_CODES.INVENTORY_PENDING,
  PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
  PROTOCOL_ERROR_CODES.INVENTORY_INVALID,
  PROTOCOL_ERROR_CODES.INVENTORY_ACCESS_DENIED,
  PROTOCOL_ERROR_CODES.INVENTORY_STALE,
  PROTOCOL_ERROR_CODES.INVENTORY_MANUAL_CLEANUP,
  PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED,
  PROTOCOL_ERROR_CODES.WORKSPACE_ROOT_ESCAPE,
  PROTOCOL_ERROR_CODES.CONTAINMENT_UNSUPPORTED,
  PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
]);
const INVENTORY_RECEIPT_READINESS_FIELDS = new Set([
  "type",
  "socketGeneration",
  "revision",
  "observedAt",
  "ttlMs",
  "bindingId",
  "workspaceId",
  "workspaceGeneration",
  "status",
  "lastError",
  "inventoryGeneration",
  "inventoryFingerprint",
  "bindingFingerprint",
  "expiresAt",
]);
const RECEIPT_IDENTITY_FIELDS = [
  "bindingId",
  "workspaceId",
  "workspaceGeneration",
];
const RECEIPT_PROOF_FIELDS = [
  "inventoryGeneration",
  "inventoryFingerprint",
  "bindingFingerprint",
];

function isInventoryReceiptReadinessShape(value) {
  if (!isObject(value) || value.type !== MSG_TYPES.READINESS) return false;
  const hasBindingState = [...RECEIPT_IDENTITY_FIELDS, ...RECEIPT_PROOF_FIELDS]
    .some((field) => hasOwn(value, field));
  if (!hasBindingState) {
    return isReadinessFrameShape(value) &&
      !hasOwn(value, "workspaceId") &&
      !hasOwn(value, "workspaceGeneration") &&
      !hasOwn(value, "bindingId");
  }
  if (
    !Object.keys(value).every((key) => INVENTORY_RECEIPT_READINESS_FIELDS.has(key)) ||
    !isReadinessSocketGeneration(value.socketGeneration) ||
    !isReadinessRevision(value.revision) ||
    !isReadinessTimestamp(value.observedAt) ||
    value.ttlMs !== INVENTORY_RECEIPT_TTL_MS ||
    !isMappingId(value.bindingId) ||
    !isWorkspaceId(value.workspaceId) ||
    !isReadinessWorkspaceGeneration(value.workspaceGeneration) ||
    !isReadinessStatus(value.status) ||
    (hasOwn(value, "expiresAt") && !isReadinessTimestamp(value.expiresAt))
  ) {
    return false;
  }

  const hasLastError = hasOwn(value, "lastError");
  const proofCount = RECEIPT_PROOF_FIELDS.filter((field) => hasOwn(value, field)).length;
  if (hasLastError) {
    return proofCount === 0 &&
      value.status.workspace === READINESS_WORKSPACE_STATUS.UNKNOWN &&
      isReadinessError(value.lastError) &&
      INVENTORY_RECEIPT_READINESS_ERRORS.has(value.lastError.code);
  }
  if (
    proofCount !== RECEIPT_PROOF_FIELDS.length ||
    !isReadinessWorkspaceGeneration(value.inventoryGeneration) ||
    !isHex64(value.inventoryFingerprint) ||
    !isHex64(value.bindingFingerprint) ||
    ![READINESS_WORKSPACE_STATUS.UNKNOWN, READINESS_WORKSPACE_STATUS.READY]
      .includes(value.status.workspace)
  ) {
    return false;
  }
  return value.status.workspace !== READINESS_WORKSPACE_STATUS.READY ||
    READINESS_DIMENSIONS.every((dimension) =>
      value.status[dimension] === READINESS_STATUS_VALUES[dimension][0]
    );
}

export function isInventoryReceiptReadinessMessage(value, context = undefined) {
  return isInventoryReceiptReadinessShape(value) &&
    isReadinessContextValid(value, context);
}

/**
 * Atomically enable the v2 workspace/readiness extension only when both
 * sides advertised and accepted protocol v2 and the capability. Missing
 * negotiation fields are therefore treated as legacy, not as an implicit
 * opt-in.
 */
export function isReadinessCapabilityGate(register, registerOk) {
  if (
    arguments.length === 1 &&
    isObject(register) &&
    isObject(register.register) &&
    (isObject(register.registerOk) || isObject(register.response))
  ) {
    registerOk = register.registerOk ?? register.response;
    register = register.register;
  }
  if (
    arguments.length === 1 &&
    isObject(register) &&
    Number.isSafeInteger(register.negotiatedVersion)
  ) {
    return (
      register.negotiatedVersion === PROTOCOL_VERSION_V2 &&
      isCapabilityList(register.localCapabilities) &&
      isCapabilityList(register.remoteCapabilities) &&
      register.localCapabilities.includes(WORKSPACE_READINESS_CAPABILITY) &&
      register.remoteCapabilities.includes(WORKSPACE_READINESS_CAPABILITY)
    );
  }
  if (!isRegisterMessage(register) || !isRegisterOkMessage(registerOk)) return false;
  if (
    !hasOwn(register, "protocolVersion") ||
    !hasOwn(register, "capabilities") ||
    !hasOwn(registerOk, "protocolVersion") ||
    !hasOwn(registerOk, "capabilities")
  ) {
    return false;
  }
  return (
    register.protocolVersion === PROTOCOL_VERSION_V2 &&
    registerOk.protocolVersion === PROTOCOL_VERSION_V2 &&
    register.capabilities.includes(WORKSPACE_READINESS_CAPABILITY) &&
    registerOk.capabilities.includes(WORKSPACE_READINESS_CAPABILITY)
  );
}

/**
 * Atomically enable inventory receipt frames only when both peers negotiated
 * protocol v3 and advertised both the retained readiness capability and the
 * distinct receipt capability.
 */
export function isInventoryReceiptCapabilityGate(register, registerOk) {
  if (
    arguments.length === 1 &&
    isObject(register) &&
    isObject(register.register) &&
    (isObject(register.registerOk) || isObject(register.response))
  ) {
    registerOk = register.registerOk ?? register.response;
    register = register.register;
  }
  if (
    arguments.length === 1 &&
    isObject(register) &&
    Number.isSafeInteger(register.negotiatedVersion)
  ) {
    return (
      register.negotiatedVersion === PROTOCOL_VERSION_V3 &&
      isCapabilityList(register.localCapabilities) &&
      isCapabilityList(register.remoteCapabilities) &&
      [WORKSPACE_READINESS_CAPABILITY, WORKSPACE_INVENTORY_RECEIPT_CAPABILITY]
        .every((capability) =>
          register.localCapabilities.includes(capability) &&
          register.remoteCapabilities.includes(capability)
        )
    );
  }
  if (!isRegisterMessage(register) || !isRegisterOkMessage(registerOk)) return false;
  if (
    !hasOwn(register, "protocolVersion") ||
    !hasOwn(register, "capabilities") ||
    !hasOwn(registerOk, "protocolVersion") ||
    !hasOwn(registerOk, "capabilities")
  ) {
    return false;
  }
  return (
    register.protocolVersion === PROTOCOL_VERSION_V3 &&
    registerOk.protocolVersion === PROTOCOL_VERSION_V3 &&
    [WORKSPACE_READINESS_CAPABILITY, WORKSPACE_INVENTORY_RECEIPT_CAPABILITY]
      .every((capability) =>
        register.capabilities.includes(capability) &&
        registerOk.capabilities.includes(capability)
      )
  );
}

/** Intersects a local capability list with a remote peer's advertised set. */
export function negotiateCapabilities(local, remote) {
  const advertised = new Set(isCapabilityList(remote) ? remote : []);
  return local.filter((cap) => advertised.has(cap));
}

export function isRegisterMessage(value) {
  return (
    isObject(value) &&
    value.type === MSG_TYPES.REGISTER &&
    isBoundedString(value.hostId, V0_LIMITS.HOST_ID) &&
    isBoundedString(value.token, V0_LIMITS.TOKEN) &&
    (value.label === undefined ||
      isBoundedString(value.label, V0_LIMITS.LABEL, true)) &&
    (value.protocolVersion === undefined ||
      isProtocolVersion(value.protocolVersion)) &&
    (value.capabilities === undefined || isCapabilityList(value.capabilities))
  );
}

export function isEventMessage(value) {
  if (
    !isObject(value) ||
    value.type !== MSG_TYPES.EVENT ||
    !isBoundedString(value.requestId, V0_LIMITS.REQUEST_ID)
  ) {
    return false;
  }

  const hasEvent = hasOwn(value, "event");
  const hasDone = hasOwn(value, "done");
  const hasError = hasOwn(value, "error");
  if (!hasEvent && !hasDone && !hasError) return false;

  return (
    (!hasEvent || isObject(value.event)) &&
    (!hasDone || typeof value.done === "boolean") &&
    (!hasError || isBoundedString(value.error, V0_LIMITS.ERROR))
  );
}

export function isRegisterOkMessage(value) {
  return (
    isObject(value) &&
    value.type === MSG_TYPES.REGISTER_OK &&
    (value.protocolVersion === undefined ||
      isProtocolVersion(value.protocolVersion)) &&
    (value.capabilities === undefined || isCapabilityList(value.capabilities))
  );
}

export function isRegisterDeniedMessage(value) {
  return (
    isObject(value) &&
    value.type === MSG_TYPES.REGISTER_DENIED &&
    isBoundedString(value.reason, V0_LIMITS.DENIAL_REASON, true)
  );
}

const HEX64_PATTERN = /^[0-9a-f]{64}$/;
const BINDING_SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);

function isHex64(value) {
  return typeof value === "string" && HEX64_PATTERN.test(value);
}

function isBindingIdentity(value) {
  return (
    isObject(value) &&
    isMappingId(value.bindingId) &&
    isBoundedString(value.hostId, V0_LIMITS.HOST_ID) &&
    isMappingId(value.mappingId) &&
    isMappingGeneration(value.mappingGeneration) &&
    isMappingVersion(value.mappingVersion) &&
    isWorkspaceId(value.workspaceId) &&
    isReadinessWorkspaceGeneration(value.workspaceGeneration) &&
    BINDING_SOURCE_PLATFORMS.has(value.sourcePlatform) &&
    isHex64(value.routeFingerprint) &&
    isHex64(value.authorityFingerprint) &&
    isReadinessWorkspaceGeneration(value.inventoryGeneration)
  );
}

/**
 * The management authority sends this path-free binding after registration.
 * It is deliberately only an identity/proof tuple: the daemon must resolve
 * the workspace from its own verified local inventory before serving it.
 */
export function isBindWorkspaceMessage(value) {
  if (!isBindingIdentity(value) || value.type !== MSG_TYPES.BIND_WORKSPACE) return false;
  return Object.keys(value).every((key) => [
    "type",
    "bindingId",
    "hostId",
    "mappingId",
    "mappingGeneration",
    "mappingVersion",
    "workspaceId",
    "workspaceGeneration",
    "sourcePlatform",
    "routeFingerprint",
    "authorityFingerprint",
    "inventoryGeneration",
  ].includes(key));
}

export function isBindOkMessage(value) {
  if (
    !isObject(value) ||
    value.type !== MSG_TYPES.BIND_OK ||
    !isBoundedString(value.bindingId, V2_LIMITS.MAPPING_ID) ||
    !isHex64(value.bindingFingerprint)
  ) {
    return false;
  }
  return Object.keys(value).every((key) =>
    ["type", "bindingId", "bindingFingerprint"].includes(key)
  );
}

const RECEIPT_BIND_KEYS = Object.freeze([
  "type",
  "bindingId",
  "authorityEpoch",
  "fenceGeneration",
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "authorityFingerprint",
]);
const RECEIPT_BIND_OK_KEYS = Object.freeze([
  "type",
  "bindingId",
  "inventoryGeneration",
  "inventoryFingerprint",
  "bindingFingerprint",
]);
const RECEIPT_UNBIND_KEYS = Object.freeze(["type", "bindingId"]);

function receiptAuthorityDescriptor(value) {
  return {
    authorityEpoch: value.authorityEpoch,
    fenceGeneration: value.fenceGeneration,
    hostId: value.hostId,
    mappingId: value.mappingId,
    mappingGeneration: value.mappingGeneration,
    workspaceGeneration: value.workspaceGeneration,
    mappingVersion: value.mappingVersion,
    sourcePlatform: value.sourcePlatform,
    workspaceId: value.workspaceId,
    authorityFingerprint: value.authorityFingerprint,
  };
}

export function isInventoryReceiptBindWorkspaceMessage(value) {
  return hasExactFields(value, RECEIPT_BIND_KEYS) &&
    value.type === MSG_TYPES.BIND_WORKSPACE &&
    isMappingId(value.bindingId) &&
    isWorkspaceAuthorityDescriptor(receiptAuthorityDescriptor(value));
}

export function isInventoryReceiptBindOkMessage(value) {
  return hasExactFields(value, RECEIPT_BIND_OK_KEYS) &&
    value.type === MSG_TYPES.BIND_OK &&
    isMappingId(value.bindingId) &&
    isReadinessWorkspaceGeneration(value.inventoryGeneration) &&
    isHex64(value.inventoryFingerprint) &&
    isHex64(value.bindingFingerprint);
}

export function isUnbindWorkspaceMessage(value) {
  return hasExactFields(value, RECEIPT_UNBIND_KEYS) &&
    value.type === MSG_TYPES.UNBIND_WORKSPACE &&
    isMappingId(value.bindingId);
}

export function isUnbindOkMessage(value) {
  return hasExactFields(value, RECEIPT_UNBIND_KEYS) &&
    value.type === MSG_TYPES.UNBIND_OK &&
    isMappingId(value.bindingId);
}

export function isInvokeMessage(value, context = undefined) {
  if (
    !isObject(value) ||
    value.type !== MSG_TYPES.INVOKE ||
    !isBoundedString(value.requestId, V0_LIMITS.REQUEST_ID) ||
    !isObject(value.command)
  ) {
    return false;
  }

  const isV2 = isObject(context) && context.v2 === true;
  const v2Fields = [
    "bindingId",
    "mappingId",
    "mappingGeneration",
    "mappingVersion",
    "workspaceId",
    "workspaceGeneration",
  ];
  const hasV2Field = v2Fields.some((field) => hasOwn(value, field));
  // A legacy socket must never carry v2 identity, even if the fields happen
  // to have valid values. This keeps the capability gate atomic.
  if (!isV2 && hasV2Field) return false;

  if (isV2) {
    const allowedFields = new Set([
      "type",
      "requestId",
      "bindingId",
      "mappingId",
      "mappingGeneration",
      "mappingVersion",
      "workspaceId",
      "workspaceGeneration",
      "command",
    ]);
    if (!Object.keys(value).every((key) => allowedFields.has(key))) return false;
    if (
      !isMappingId(value.mappingId) ||
      !isMappingGeneration(value.mappingGeneration) ||
      !isMappingVersion(value.mappingVersion)
    ) {
      return false;
    }
    if (hasOwn(value, "bindingId") && !isMappingId(value.bindingId)) return false;
    if (hasOwn(value, "workspaceId") && !isWorkspaceId(value.workspaceId)) {
      return false;
    }
    if (hasOwn(value, "workspaceGeneration") && !isReadinessWorkspaceGeneration(value.workspaceGeneration)) {
      return false;
    }
  } else if (!isBoundedString(value.workDir, V0_LIMITS.WORK_DIR)) {
    return false;
  }

  const { command } = value;
  if (command.kind === "set_model") {
    return isModelName(command.modelName);
  }
  if (
    command.kind === "prompt" ||
    command.kind === "steer" ||
    command.kind === "follow_up"
  ) {
    return isBoundedString(command.message, V0_LIMITS.MESSAGE, true);
  }
  return false;
}

/**
 * bot -> host, a user's answer to a pending workflow gate (#35). Additive: v0
 * hosts never receive one because they never emit a `gate_request`.
 * @typedef {{ type: "answer", requestId: string, gateId: string, answer: string }} AnswerMessage
 */
export function isAnswerMessage(value) {
  return (
    isObject(value) &&
    value.type === MSG_TYPES.ANSWER &&
    isBoundedString(value.requestId, V0_LIMITS.REQUEST_ID) &&
    isBoundedString(value.gateId, V0_LIMITS.GATE_ID) &&
    isBoundedString(value.answer, V0_LIMITS.MESSAGE, true)
  );
}

/**
 * A `gate_request` event subtype (#35). This validates the inner `event`
 * payload carried by an EventMessage (daemon -> bot), NOT a top-level WS frame:
 * a pending workflow gate the bot must render and collect an answer for.
 * `choices` is present only for choice-style gates; `kind` mirrors the SDK
 * WorkflowGateKind. Unknown/legacy event payloads fail this check and are
 * treated as ordinary (ignorable) events by v0-aware peers.
 * @typedef {{ type: "gate_request", requestId?: string, gateId: string, prompt: string, kind: string, choices?: Array<{ value: unknown, label: string }> }} GateRequestEvent
 */
export function isGateRequestEvent(value) {
  if (
    !isObject(value) ||
    value.type !== MSG_TYPES.GATE_REQUEST ||
    !isBoundedString(value.gateId, V0_LIMITS.GATE_ID) ||
    !isBoundedString(value.prompt, V0_LIMITS.GATE_PROMPT) ||
    (value.kind !== "question" &&
      value.kind !== "approval" &&
      value.kind !== "execution")
  ) {
    return false;
  }
  if (hasOwn(value, "requestId") && !isBoundedString(value.requestId, V0_LIMITS.REQUEST_ID)) {
    return false;
  }
  if (hasOwn(value, "choices")) {
    if (!Array.isArray(value.choices) || value.choices.length > V0_LIMITS.MAX_CHOICES) {
      return false;
    }
    for (const choice of value.choices) {
      if (
        !isObject(choice) ||
        !hasOwn(choice, "value") ||
        !isBoundedString(choice.label, V0_LIMITS.CHOICE_LABEL)
      ) {
        return false;
      }
    }
  }
  return true;
}

export function normalizeProtocolError(value) {
  let message = value;
  try {
    if (value instanceof Error) message = value.message;
  } catch {
    message = "";
  }

  if (typeof message !== "string") {
    try {
      message = String(message);
    } catch {
      message = "";
    }
  }
  if (message.length === 0) message = "Unknown daemon error";
  return message.slice(0, V0_LIMITS.ERROR);
}

export function isPingMessage(value) {
  return isObject(value) && value.type === MSG_TYPES.PING;
}

export function isPongMessage(value) {
  return isObject(value) && value.type === MSG_TYPES.PONG;
}

/** 1 hour, matches the daemon's idle GJC-RPC-process reap timeout. */
export const IDLE_TIMEOUT_MS = 60 * 60 * 1000;
