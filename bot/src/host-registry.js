import { WebSocketServer } from "ws";
import { randomUUID } from "node:crypto";
import { MSG_TYPES } from "@gjc-remote/shared";

/**
 * WS server that host daemons connect to (outbound from the daemon's side).
 * Tracks live connections by hostId and routes invoke/event frames between
 * the Discord layer and whichever daemon owns the target host.
 */
export class HostRegistry {
  /** @param {{ port: number, tokensByHostId: Map<string, string> }} opts */
  constructor({ port, tokensByHostId }) {
    this.tokensByHostId = tokensByHostId;
    /** @type {Map<string, import("ws").WebSocket>} */
    this.connections = new Map();
    /** @type {Map<string, { socket: import("ws").WebSocket, resolve: (v: any) => void, onEvent: (e: object) => void, text?: string }>} */
    this.pendingRequests = new Map();

    this.wss = new WebSocketServer({ port });
    this.wss.on("connection", (socket) => this.#handleConnection(socket));
    console.log(`HostRegistry: WS server listening on :${port}`);
  }

  #handleConnection(socket) {
    let hostId;

    socket.once("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        socket.close(1008, "invalid json");
        return;
      }
      if (msg.type !== MSG_TYPES.REGISTER) {
        socket.close(1008, "expected register");
        return;
      }
      const expectedToken = this.tokensByHostId.get(msg.hostId);
      if (!expectedToken || expectedToken !== msg.token) {
        socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER_DENIED, reason: "bad token" }));
        socket.close(1008, "auth failed");
        return;
      }

      hostId = msg.hostId;
      this.connections.set(hostId, socket);
      socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER_OK }));
      console.log(`HostRegistry: host '${hostId}' connected (${msg.label ?? "no label"})`);

      socket.on("message", (raw2) => this.#handleMessage(hostId, raw2));
      socket.on("close", () => {
        if (this.connections.get(hostId) === socket) this.connections.delete(hostId);
        this.#failPendingForSocket(socket, `host '${hostId}' disconnected`);
        console.log(`HostRegistry: host '${hostId}' disconnected`);
      });
    });

    socket.on("error", (err) => console.error("HostRegistry socket error:", err.message));
  }

  #handleMessage(hostId, raw) {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (msg.type !== MSG_TYPES.EVENT) return;

    const pending = this.pendingRequests.get(msg.requestId);
    if (!pending) return;

    if (msg.error) {
      pending.resolve({ ok: false, error: msg.error });
      this.pendingRequests.delete(msg.requestId);
      return;
    }
    if (msg.event) {
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

      socket.send(
        JSON.stringify({ type: MSG_TYPES.INVOKE, requestId, workDir, command })
      );
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
