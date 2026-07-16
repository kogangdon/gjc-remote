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
  MESSAGE: MAX_WS_PAYLOAD_BYTES,
  MODEL_NAME: 512,
  ERROR: 4096,
  DENIAL_REASON: 1024,
});

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

function isBoundedString(value, maxLength, allowEmpty = false) {
  return (
    typeof value === "string" &&
    value.length <= maxLength &&
    (allowEmpty || value.length > 0)
  );
}

export function isRegisterMessage(value) {
  return (
    isObject(value) &&
    value.type === MSG_TYPES.REGISTER &&
    isBoundedString(value.hostId, V0_LIMITS.HOST_ID) &&
    isBoundedString(value.token, V0_LIMITS.TOKEN) &&
    (value.label === undefined ||
      isBoundedString(value.label, V0_LIMITS.LABEL, true))
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

  const hasEvent = Object.hasOwn(value, "event");
  const hasDone = Object.hasOwn(value, "done");
  const hasError = Object.hasOwn(value, "error");
  if (!hasEvent && !hasDone && !hasError) return false;

  return (
    (!hasEvent || isObject(value.event)) &&
    (!hasDone || typeof value.done === "boolean") &&
    (!hasError || isBoundedString(value.error, V0_LIMITS.ERROR))
  );
}

export function isRegisterOkMessage(value) {
  return isObject(value) && value.type === MSG_TYPES.REGISTER_OK;
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
    return isBoundedString(command.modelName, V0_LIMITS.MODEL_NAME);
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
  let message;
  if (value instanceof Error) {
    message = value.message;
  } else if (typeof value === "string") {
    message = value;
  } else {
    message = value;
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
