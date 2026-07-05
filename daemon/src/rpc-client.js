import { randomUUID } from "node:crypto";

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
      if (!waiter) continue; // stray/late frame with nothing awaiting it (e.g. a trailing agent_end echo) — safe to drop

      // Streamed frames arrive wrapped: {type:"event", payload:{event_type, event}}.
      // Direct command replies arrive flat: {type:"response", command, success}.
      const innerType = evt.type === "event" ? evt.payload?.event_type : evt.type;

      waiter.onEvent(evt.type === "event" ? evt.payload.event : evt);

      // `turn_end` is the authoritative completion signal for a single RPC
      // turn. GJC also emits a trailing `agent_end` echo shortly afterwards
      // (meant for one-shot `-p` runs) — deliberately ignored here (it falls
      // through with `waiter` still cleared, so it's dropped by the `!waiter`
      // guard above once the next command has dispatched) so it can never be
      // misrouted onto whatever request is queued next.
      if (innerType === "turn_end") {
        this.#settle(() => waiter.resolve());
      } else if (evt.type === "response") {
        if (evt.success === false) {
          this.#settle(() => waiter.reject(new Error(typeof evt.error === "string" ? evt.error : JSON.stringify(evt.error))));
        } else if (evt.command !== "prompt" && evt.command !== "steer" && evt.command !== "follow_up") {
          this.#settle(() => waiter.resolve());
        }
      }
    }
  }

  #settle(fn) {
    clearTimeout(this.current.timer);
    this.current = undefined;
    fn();
    this.#drainQueue();
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
        const payload = { ...command, id };

        const timer = setTimeout(() => {
          this.current = undefined;
          reject(new Error("RPC command timed out"));
          this.#drainQueue();
        }, timeoutMs);

        this.current = { onEvent, resolve, reject, timer };
        this.child.stdin.write(`${JSON.stringify(payload)}\n`);
      });

    if (!this.current) return dispatch();

    return new Promise((resolve, reject) => {
      this.queue.push(() => dispatch().then(resolve, reject));
    });
  }
}
