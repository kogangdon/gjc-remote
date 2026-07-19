import { WebSocket, WebSocketServer } from "ws";
import { randomUUID } from "node:crypto";
import {
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PING,
  isEventMessage,
  isInvokeMessage,
  isPongMessage,
  isRegisterMessage,
} from "@gjc-remote/shared";

const HEARTBEAT_INTERVAL_MS = 30_000;
const HEARTBEAT_TIMEOUT_MS = 10_000;
const PING_PAYLOAD = JSON.stringify(PING);
const SYSTEM_TIMERS = {
  setInterval: (callback, delay) => setInterval(callback, delay),
  clearInterval: (timer) => clearInterval(timer),
  setTimeout: (callback, delay) => setTimeout(callback, delay),
  clearTimeout: (timer) => clearTimeout(timer),
};

function isPositiveDuration(value) {
  return Number.isFinite(value) && value > 0;
}

/**
 * WS server that host daemons connect to (outbound from the daemon's side).
 * Tracks live connections by hostId and routes invoke/event frames between
 * the Discord layer and whichever daemon owns the target host.
 */
export class HostRegistry {
  /**
   * @param {{
   *   port: number,
   *   tokensByHostId: Map<string, string>,
   *   heartbeatIntervalMs?: number,
   *   heartbeatTimeoutMs?: number,
   *   timers?: typeof SYSTEM_TIMERS,
   * }} opts
   */
  constructor({
    port,
    tokensByHostId,
    heartbeatIntervalMs = HEARTBEAT_INTERVAL_MS,
    heartbeatTimeoutMs = HEARTBEAT_TIMEOUT_MS,
    timers = SYSTEM_TIMERS,
  }) {
    if (!isPositiveDuration(heartbeatIntervalMs)) {
      throw new Error("heartbeatIntervalMs must be a positive duration");
    }
    if (!isPositiveDuration(heartbeatTimeoutMs)) {
      throw new Error("heartbeatTimeoutMs must be a positive duration");
    }

    this.tokensByHostId = tokensByHostId;
    this.heartbeatTimeoutMs = heartbeatTimeoutMs;
    this.timers = timers;
    /** @type {Map<string, import("ws").WebSocket>} */
    this.connections = new Map();
    /** @type {Map<import("ws").WebSocket, { hostId: string, timeout?: object }>} */
    this.heartbeatStates = new Map();
    /** @type {Map<string, { socket: import("ws").WebSocket, resolve: (v: any) => void, onEvent: (e: object) => void, text?: string }>} */
    this.pendingRequests = new Map();
    this.closed = false;
    this.closePromise = undefined;

    this.wss = new WebSocketServer({ port, maxPayload: MAX_WS_PAYLOAD_BYTES });
    this.wss.on("connection", (socket) => this.#handleConnection(socket));
    this.heartbeatTimer = this.timers.setInterval(
      () => this.#sendHeartbeats(),
      heartbeatIntervalMs
    );
    this.heartbeatTimer.unref?.();
    console.log(`HostRegistry: WS server listening on :${port}`);
  }

  #handleConnection(socket) {
    let hostId;

    socket.once("message", (raw, isBinary) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        socket.close(1008, "invalid json");
        return;
      }
      if (isBinary || !isRegisterMessage(msg)) {
        socket.close(1008, "invalid register");
        return;
      }
      const expectedToken = this.tokensByHostId.get(msg.hostId);
      if (!expectedToken || expectedToken !== msg.token) {
        socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER_DENIED, reason: "bad token" }));
        socket.close(1008, "auth failed");
        return;
      }

      hostId = msg.hostId;
      const previous = this.connections.get(hostId);
      if (previous && previous !== socket) {
        this.#dropConnection(hostId, previous, `host '${hostId}' connection replaced`);
        previous.terminate();
      }

      this.connections.set(hostId, socket);
      this.heartbeatStates.set(socket, { hostId });
      socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER_OK }));
      console.log(`HostRegistry: host '${hostId}' connected (${msg.label ?? "no label"})`);

      socket.on("message", (raw2, isBinary2) =>
        this.#handleMessage(socket, raw2, isBinary2)
      );
      socket.on("close", () => {
        const wasCurrent = this.#dropConnection(
          hostId,
          socket,
          `host '${hostId}' disconnected`
        );
        if (wasCurrent) console.log(`HostRegistry: host '${hostId}' disconnected`);
      });
    });

    socket.on("error", (err) => console.error("HostRegistry socket error:", err.message));
  }

  #handleMessage(socket, raw, isBinary) {
    if (isBinary) {
      socket.close(1008, "invalid frame");
      return;
    }

    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      socket.close(1008, "invalid json");
      return;
    }

    if (isPongMessage(msg)) {
      this.#acceptPong(socket);
      return;
    }
    if (!isEventMessage(msg)) {
      socket.close(1008, "invalid event");
      return;
    }

    const pending = this.pendingRequests.get(msg.requestId);
    if (!pending) return;
    if (pending.socket !== socket) {
      socket.close(1008, "request owner mismatch");
      return;
    }

    if (msg.error !== undefined) {
      pending.resolve({ ok: false, error: msg.error });
      this.pendingRequests.delete(msg.requestId);
      return;
    }
    if (msg.event !== undefined) {
      const text = extractAssistantText(msg.event);
      if (text !== undefined) pending.text = text;
      pending.onEvent(msg.event);
    }
    if (msg.done) {
      pending.resolve({ ok: true, text: pending.text });
      this.pendingRequests.delete(msg.requestId);
    }
  }

  #failPendingForSocket(socket, error) {
    for (const [requestId, pending] of this.pendingRequests) {
      if (pending.socket !== socket) continue;
      pending.resolve({ ok: false, error });
      this.pendingRequests.delete(requestId);
    }
  }

  #acceptPong(socket) {
    const state = this.heartbeatStates.get(socket);
    if (!state?.timeout) return;

    this.timers.clearTimeout(state.timeout);
    state.timeout = undefined;
  }

  #clearHeartbeat(socket) {
    const state = this.heartbeatStates.get(socket);
    if (state?.timeout) this.timers.clearTimeout(state.timeout);
    this.heartbeatStates.delete(socket);
  }

  #dropConnection(hostId, socket, error) {
    const wasCurrent = this.connections.get(hostId) === socket;
    if (wasCurrent) this.connections.delete(hostId);
    this.#clearHeartbeat(socket);
    this.#failPendingForSocket(socket, error);
    return wasCurrent;
  }

  #expireHeartbeat(hostId, socket, timeout) {
    const state = this.heartbeatStates.get(socket);
    if (state?.timeout !== timeout) return;

    this.#dropConnection(hostId, socket, `host '${hostId}' heartbeat timed out`);
    socket.terminate();
  }

  #sendHeartbeats() {
    if (this.closed) return;

    for (const [hostId, socket] of this.connections) {
      const state = this.heartbeatStates.get(socket);
      if (!state || state.timeout) continue;
      if (socket.readyState !== WebSocket.OPEN) {
        this.#dropConnection(hostId, socket, `host '${hostId}' disconnected`);
        continue;
      }

      let timeout;
      timeout = this.timers.setTimeout(
        () => this.#expireHeartbeat(hostId, socket, timeout),
        this.heartbeatTimeoutMs
      );
      timeout.unref?.();
      state.timeout = timeout;

      try {
        socket.send(PING_PAYLOAD, (error) => {
          if (!error) return;
          this.#dropConnection(hostId, socket, `host '${hostId}' heartbeat failed`);
          socket.terminate();
        });
      } catch {
        this.#dropConnection(hostId, socket, `host '${hostId}' heartbeat failed`);
        socket.terminate();
      }
    }
  }

  close() {
    if (this.closePromise) return this.closePromise;

    this.closed = true;
    this.timers.clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = undefined;

    for (const socket of this.wss.clients) {
      const state = this.heartbeatStates.get(socket);
      if (state) {
        this.#dropConnection(state.hostId, socket, "HostRegistry shut down");
      } else {
        this.#clearHeartbeat(socket);
      }
      socket.terminate();
    }
    this.connections.clear();

    this.closePromise = new Promise((resolve, reject) => {
      this.wss.close((error) => (error ? reject(error) : resolve()));
    });
    return this.closePromise;
  }

  isOnline(hostId) {
    return this.connections.has(hostId);
  }

  listOnline() {
    return [...this.connections.keys()];
  }

  /**
   * Sends an invoke request to a host and resolves once the daemon reports
   * `done: true` for that requestId. Streamed events are delivered via onEvent
   * as they arrive, before the final resolution.
   *
   * @param {string} hostId
   * @param {string} workDir
   * @param {object} command
   * @param {(event: object) => void} onEvent
   * @param {number} timeoutMs
   */
  invoke(hostId, workDir, command, onEvent, timeoutMs = 10 * 60 * 1000) {
    const socket = this.connections.get(hostId);
    if (!socket) return Promise.resolve({ ok: false, error: `host '${hostId}' is not connected` });

    const requestId = randomUUID();
    const invoke = { type: MSG_TYPES.INVOKE, requestId, workDir, command };
    if (!isInvokeMessage(invoke)) {
      return Promise.resolve({ ok: false, error: "invalid invoke request" });
    }

    let payload;
    try {
      payload = JSON.stringify(invoke);
    } catch {
      return Promise.resolve({ ok: false, error: "invoke request is not serializable" });
    }
    if (Buffer.byteLength(payload) > MAX_WS_PAYLOAD_BYTES) {
      return Promise.resolve({ ok: false, error: "invoke request exceeds WebSocket payload limit" });
    }

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        resolve({ ok: false, error: "timed out waiting for host response" });
      }, timeoutMs);

      this.pendingRequests.set(requestId, {
        socket,
        resolve: (result) => {
          clearTimeout(timer);
          resolve(result);
        },
        onEvent,
      });

      socket.send(payload);
    });
  }
}

export function extractAssistantText(event) {
  const message = event?.message ?? event?.assistantMessageEvent?.message;
  if (message?.role !== "assistant") return undefined;

  const text = extractTextFromContent(message.content);
  return text.length > 0 ? text : undefined;
}

function extractTextFromContent(content) {
  if (typeof content === "string") return content;

  if (!Array.isArray(content)) return "";

  return content
    .map((part) => {
      if (typeof part === "string") return part;
      if (!part || typeof part !== "object") return "";
      if (typeof part.text === "string") return part.text;
      if (typeof part.value === "string") return part.value;
      if (typeof part.content === "string") return part.content;
      return "";
    })
    .join("");
}
