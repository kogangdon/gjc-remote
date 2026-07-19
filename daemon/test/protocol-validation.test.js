import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  MAX_WS_PAYLOAD_BYTES,
  V0_LIMITS,
  isEventMessage,
  isInvokeMessage,
  normalizeProtocolError,
} from "@gjc-remote/shared";
import { WebSocketServer } from "ws";

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const CHILD_EXIT_TIMEOUT_MS = 2_000;

async function stopChild(child, timeoutMs = CHILD_EXIT_TIMEOUT_MS) {
  if (child.exitCode !== null || child.signalCode !== null) return;

  const exited = once(child, "exit");
  child.kill("SIGTERM");

  let forceTimer;
  await Promise.race([
    exited,
    new Promise((resolve) => {
      forceTimer = setTimeout(resolve, timeoutMs);
    }),
  ]);
  clearTimeout(forceTimer);

  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

async function startDaemon() {
  const wss = new WebSocketServer({ port: 0 });
  if (!wss.address()) await once(wss, "listening");
  const { port } = wss.address();
  let peer;
  let stderr = "";
  const registration = new Promise((resolve) => {
    wss.once("connection", (connection) => {
      peer = connection;
      connection.once("message", (raw) => resolve(JSON.parse(raw.toString())));
    });
  });

  const child = spawn(process.env.BUN_BIN || "bun", [daemonEntry], {
    env: {
      ...process.env,
      HOST_ID: "test-host",
      HOST_TOKEN: "test-token",
      BOT_WS_URL: `ws://127.0.0.1:${port}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  const register = await Promise.race([
    registration,
    once(child, "exit").then(([code]) => {
      throw new Error(`daemon exited before registering (${code}): ${stderr}`);
    }),
  ]);
  assert.equal(register.type, "register");

  return {
    child,
    peer,
    stderr: () => stderr,
    async close() {
      peer?.terminate();
      await stopChild(child);
      await new Promise((resolve, reject) => {
        wss.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

test("invoke validation rejects an empty model name", () => {
  assert.equal(
    isInvokeMessage({
      type: "invoke",
      requestId: "request-1",
      workDir: "/workspace",
      command: { kind: "set_model", modelName: "" },
    }),
    false
  );
});

test("stopChild escalates to SIGKILL after the graceful timeout", async () => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  const signals = [];
  child.kill = (signal) => {
    signals.push(signal);
    if (signal === "SIGKILL") {
      child.signalCode = signal;
      queueMicrotask(() => child.emit("exit", null, signal));
    }
    return true;
  };

  await stopChild(child, 1);

  assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
});

test("protocol errors are non-empty and bounded for Error and non-Error throws", () => {
  assert.equal(normalizeProtocolError(new Error("")), "Unknown daemon error");
  assert.equal(normalizeProtocolError(""), "Unknown daemon error");
  assert.equal(normalizeProtocolError({ reason: "failure" }), "[object Object]");
  const malformedError = new Error("ignored");
  malformedError.message = 42;
  assert.equal(normalizeProtocolError(malformedError), "42");
  assert.equal(
    normalizeProtocolError({
      [Symbol.toPrimitive]() {
        throw new Error("cannot stringify");
      },
    }),
    "Unknown daemon error"
  );
  const throwingMessage = new Error("ignored");
  Object.defineProperty(throwingMessage, "message", {
    get() {
      throw new Error("cannot read message");
    },
  });
  assert.equal(normalizeProtocolError(throwingMessage), "Unknown daemon error");
  assert.equal(
    normalizeProtocolError("x".repeat(V0_LIMITS.ERROR + 1)).length,
    V0_LIMITS.ERROR
  );
  assert.equal(
    isEventMessage({ type: "event", requestId: "request-1", error: "" }),
    false
  );
});

test("malformed invoke closes with a policy violation", async () => {
  const daemon = await startDaemon();
  try {
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
    const closed = once(daemon.peer, "close");
    daemon.peer.send(
      JSON.stringify({
        type: "invoke",
        requestId: "request-1",
        workDir: process.cwd(),
        command: { kind: "set_model", modelName: "" },
      })
    );
    const [code] = await closed;
    assert.equal(code, 1008);

    // Stop the child after the peer observes the policy close.
    await stopChild(daemon.child);
  } finally {
    await daemon.close();
  }
});

test("daemon sends a bounded error event when invoke setup fails", async () => {
  const daemon = await startDaemon();
  try {
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
    const response = once(daemon.peer, "message");
    daemon.peer.send(
      JSON.stringify({
        type: "invoke",
        requestId: "request-setup-failure",
        workDir: `${process.cwd()}/directory-that-does-not-exist-for-protocol-test`,
        command: { kind: "prompt", message: "hello" },
      })
    );

    const [raw] = await response;
    const event = JSON.parse(raw.toString());
    assert.equal(isEventMessage(event), true);
    assert.equal(event.requestId, "request-setup-failure");
    assert.equal(event.done, true);
    assert.equal(typeof event.error, "string");
    assert.ok(event.error.length > 0);
    assert.ok(event.error.length <= V0_LIMITS.ERROR);
  } finally {
    await daemon.close();
  }
});

test("daemon rejects an oversized inbound WebSocket payload", async () => {
  const daemon = await startDaemon();
  try {
    const closed = once(daemon.peer, "close");
    daemon.peer.send("x".repeat(MAX_WS_PAYLOAD_BYTES + 1));
    const [code] = await closed;
    assert.equal(code, 1009);
  } finally {
    await daemon.close();
  }
});
