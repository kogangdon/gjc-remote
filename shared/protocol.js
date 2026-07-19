// Shared WS message shapes between bot/ and daemon/.
// Kept dependency-free and framework-agnostic so both sides can import it
// directly (Node ESM) without a build step.
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
  PROTOCOL_VERSION_MAX: 1_000_000,
});

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
 * @typedef {{ type: "register", hostId: string, token: string, label?: string }} RegisterMessage
 */

/**
 * bot -> host, one GJC invocation request routed to a specific working directory.
 * @typedef {{
 *   type: "invoke",
 *   requestId: string,
 *   workDir: string,
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
  INVOKE: "invoke",
  EVENT: "event",
  PING: "ping",
  PONG: "pong",
});
function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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
    value <= V0_LIMITS.PROTOCOL_VERSION_MAX
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

export function isInvokeMessage(value) {
  if (
    !isObject(value) ||
    value.type !== MSG_TYPES.INVOKE ||
    !isBoundedString(value.requestId, V0_LIMITS.REQUEST_ID) ||
    !isBoundedString(value.workDir, V0_LIMITS.WORK_DIR) ||
    !isObject(value.command)
  ) {
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
