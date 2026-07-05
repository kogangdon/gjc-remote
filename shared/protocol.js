// Shared WS message shapes between bot/ and daemon/.
// Kept dependency-free and framework-agnostic so both sides can import it
// directly (Node ESM) without a build step.

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
 *   command: { kind: "prompt" | "steer" | "follow_up", message: string } | { kind: "set_model", provider: string, modelId: string },
 * }} InvokeMessage
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

/** 1 hour, matches the daemon's idle GJC-RPC-process reap timeout. */
export const IDLE_TIMEOUT_MS = 60 * 60 * 1000;
