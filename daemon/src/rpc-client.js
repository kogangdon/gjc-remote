import { randomUUID } from "node:crypto";
const DEBUG_RPC = process.env.GJC_REMOTE_DEBUG === "1";

/**
 * Wraps a `gjc --mode=rpc` child process's stdin/stdout as a command/event
 * channel. One instance == one live GJC RPC session for a given workDir.
 *
 * Protocol: write one JSON command per line to stdin; read newline-delimited
 * JSON events/responses from stdout. A `prompt`/`steer`/`follow_up` command's
 * lifecycle ends at `turn_end`/`agent_end`; other commands resolve on their
 * matching `{type:"response", command:<type>}` frame.
 *
 * GJC's streamed event frames do not echo the request `id`, so there is no
 * way to correlate a stray/late frame to a specific in-flight command when
 * more than one is outstanding. Commands are therefore serialized: only one
 * `send()` is ever active on the wire at a time, queued FIFO. This also
 * matches GJC's own session model (one turn completes before the next
 * begins), so it costs nothing in practice.
 */
export class RpcSession {
  /** @param {import("node:child_process").ChildProcess} child */
  constructor(child) {
    this.child = child;
    this.buf = "";
    /** @type {{ command: object, onEvent: (e: object) => void, timeoutMs: number, resolve: () => void, reject: (e: Error) => void, timer?: NodeJS.Timeout, settled: boolean } | undefined} */
    this.current = undefined;
    /** @type {Array<{ command: object, onEvent: (e: object) => void, timeoutMs: number, resolve: () => void, reject: (e: Error) => void, timer?: NodeJS.Timeout, settled: boolean }>} */
    this.queue = [];
    this.closed = false;
    this.draining = false;

    child.stdout.on("data", (chunk) => this.#onData(chunk));
    child.on("exit", () => this.#terminate(new Error("gjc rpc process exited")));
    child.on("error", (error) =>
      this.#terminate(error instanceof Error ? error : new Error("gjc rpc process failed"))
    );
  }

  #onData(chunk) {
    if (this.closed) return;
    this.buf += chunk.toString();
    let idx;
    while ((idx = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 1);
      if (!line.trim()) continue;

      let evt;
      try {
        evt = JSON.parse(line);
      } catch {
        continue;
      }
      if (evt.type === "ready") continue;

      const waiter = this.current;
      if (!waiter) {
        debugRpc("drop", summarizeFrame(evt, "none", this.queue.length));
        continue; // stray/late frame with nothing awaiting it (e.g. a trailing agent_end echo) — safe to drop
      }

      // Streamed frames arrive wrapped: {type:"event", payload:{event_type, event}}.
      // Direct command replies arrive flat: {type:"response", command, success}.
      const innerType = evt.type === "event" ? evt.payload?.event_type : evt.type;
      if (shouldDebugFrame(evt, innerType)) debugRpc("recv", summarizeFrame(evt, innerType, this.queue.length));

      waiter.onEvent(evt.type === "event" ? evt.payload.event : evt);

      // `turn_end` is a per-turn boundary, not the end of a full agent run.
      // Tool use can produce several turns before the final assistant text.
      // Resolve prompt-like commands only at `agent_end`; otherwise the relay
      // drops later tool-result/final-answer frames and Discord sees
      // "(no text output)" while the agent is still running.
      if (innerType === "agent_end" && isPromptLike(waiter.command.type)) {
        this.#settle(waiter, undefined, 1000);
      } else if (evt.type === "response") {
        if (evt.success === false) {
          this.#settle(waiter, new Error(typeof evt.error === "string" ? evt.error : JSON.stringify(evt.error)));
        } else if (evt.command !== "prompt" && evt.command !== "steer" && evt.command !== "follow_up") {
          this.#settle(waiter);
        }
      }
    }
  }

  #settle(request, error, drainDelayMs = 0) {
    if (this.current !== request || request.settled) return;

    clearTimeout(request.timer);
    this.current = undefined;
    this.draining = true;
    request.settled = true;
    debugRpc("settle", { drainDelayMs, queueLength: this.queue.length });
    if (error) request.reject(error);
    else request.resolve();

    setTimeout(() => {
      if (this.closed) return;
      this.draining = false;
      debugRpc("drain-ready", { queueLength: this.queue.length });
      this.#drainQueue();
    }, drainDelayMs);
  }

  #terminate(error) {
    if (this.closed) return false;

    this.closed = true;
    this.draining = false;

    const pending = [];
    if (this.current) pending.push(this.current);
    pending.push(...this.queue);
    this.current = undefined;
    this.queue.length = 0;

    for (const request of pending) {
      clearTimeout(request.timer);
      if (request.settled) continue;
      request.settled = true;
      request.reject(error);
    }
    return true;
  }

  #drainQueue() {
    if (this.closed || this.current || this.draining) return;
    const next = this.queue.shift();
    if (next) this.#dispatch(next);
  }

  #dispatch(request) {
    if (this.closed || request.settled) return;

    const id = request.command.id || randomUUID();
    debugRpc("dispatch", { id, command: request.command.type, queueLength: this.queue.length });
    const payload = { ...request.command, id };

    request.timer = setTimeout(() => {
      if (this.current !== request) return;
      const terminated = this.#terminate(new Error("RPC command timed out"));
      if (terminated) {
        try {
          this.child.kill();
        } catch {
          // The session is already poisoned and all requests are settled.
        }
      }
    }, request.timeoutMs);

    this.current = request;
    try {
      this.child.stdin.write(`${JSON.stringify(payload)}\n`);
    } catch (error) {
      this.#terminate(error instanceof Error ? error : new Error("gjc rpc process failed"));
    }
  }

  /**
   * @param {object} command - e.g. { type: "prompt", message: "..." }
   * @param {(event: object) => void} onEvent
   * @param {number} timeoutMs
   */
  send(command, onEvent, timeoutMs = 10 * 60 * 1000) {
    if (this.closed) return Promise.reject(new Error("gjc rpc process is not running"));

    return new Promise((resolve, reject) => {
      const request = {
        command,
        onEvent,
        timeoutMs,
        resolve,
        reject,
        timer: undefined,
        settled: false,
      };

      if (!this.current && !this.draining) {
        this.#dispatch(request);
        return;
      }

      debugRpc("queue", { command: command.type, queueLength: this.queue.length + 1, draining: this.draining });
      this.queue.push(request);
    });
  }
}

function debugRpc(label, data) {
  if (!DEBUG_RPC) return;
  console.error(`[rpc-client] ${label}`, JSON.stringify(data));
}

function summarizeFrame(evt, innerType, queueLength) {
  const event = evt.type === "event" ? evt.payload?.event : evt;
  return {
    outerType: evt.type,
    innerType,
    eventType: event?.type,
    command: evt.command,
    success: evt.success,
    role: event?.message?.role,
    contentTypes: Array.isArray(event?.message?.content) ? event.message.content.map((part) => part?.type ?? typeof part) : undefined,
    queueLength,
  };
}

function shouldDebugFrame(evt, innerType) {
  if (!DEBUG_RPC) return false;
  if (innerType === "message_update") return false;
  return true;
}

function isPromptLike(commandType) {
  return commandType === "prompt" || commandType === "steer" || commandType === "follow_up";
}
