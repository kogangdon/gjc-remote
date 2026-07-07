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
    /** @type {{ onEvent: (e: object) => void, resolve: () => void, reject: (e: Error) => void, timer: NodeJS.Timeout } | undefined} */
    this.current = undefined;
    /** @type {Array<() => void>} */
    this.queue = [];
    this.closed = false;
    this.draining = false;


    child.stdout.on("data", (chunk) => this.#onData(chunk));
    const onDeath = (err) => {
      if (this.closed) return;
      this.closed = true;
      this.current?.reject(err instanceof Error ? err : new Error("gjc rpc process exited"));
      this.current = undefined;
      this.queue.length = 0;
    };
    child.on("exit", () => onDeath(new Error("gjc rpc process exited")));
    child.on("error", onDeath);
  }

  #onData(chunk) {
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
      debugRpc("recv", summarizeFrame(evt, innerType, this.queue.length));

      waiter.onEvent(evt.type === "event" ? evt.payload.event : evt);

      // `turn_end` is the authoritative completion signal for a single RPC
      // turn. GJC also emits a trailing `agent_end` echo shortly afterwards
      // (meant for one-shot `-p` runs). Keep the wire drained briefly before
      // dispatching the next queued command so late terminal echoes cannot
      // race with the next prompt and trigger GJC's "already processing" guard.
      if (innerType === "turn_end") {
        this.#settle(() => waiter.resolve(), 1000);
      } else if (evt.type === "response") {
        if (evt.success === false) {
          this.#settle(() => waiter.reject(new Error(typeof evt.error === "string" ? evt.error : JSON.stringify(evt.error))));
        } else if (evt.command !== "prompt" && evt.command !== "steer" && evt.command !== "follow_up") {
          this.#settle(() => waiter.resolve());
        }
      }
    }
  }

  #settle(fn, drainDelayMs = 0) {
    clearTimeout(this.current.timer);
    this.current = undefined;
    this.draining = true;
    debugRpc("settle", { drainDelayMs, queueLength: this.queue.length });
    fn();
    setTimeout(() => {
      this.draining = false;
      debugRpc("drain-ready", { queueLength: this.queue.length });
      this.#drainQueue();
    }, drainDelayMs);
  }

  #drainQueue() {
    const next = this.queue.shift();
    if (next) next();
  }

  /**
   * @param {object} command - e.g. { type: "prompt", message: "..." }
   * @param {(event: object) => void} onEvent
   * @param {number} timeoutMs
   */
  send(command, onEvent, timeoutMs = 10 * 60 * 1000) {
    if (this.closed) return Promise.reject(new Error("gjc rpc process is not running"));

    const dispatch = () =>
      new Promise((resolve, reject) => {
        const id = command.id || randomUUID();
        debugRpc("dispatch", { id, command: command.type, queueLength: this.queue.length });
        const payload = { ...command, id };

        const timer = setTimeout(() => {
          this.current = undefined;
          this.draining = false;
          reject(new Error("RPC command timed out"));
          this.#drainQueue();
        }, timeoutMs);

        this.current = { onEvent, resolve, reject, timer };
        this.child.stdin.write(`${JSON.stringify(payload)}\n`);
      });

    if (!this.current && !this.draining) return dispatch();

    return new Promise((resolve, reject) => {
      debugRpc("queue", { command: command.type, queueLength: this.queue.length + 1, draining: this.draining });
      this.queue.push(() => dispatch().then(resolve, reject));
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
