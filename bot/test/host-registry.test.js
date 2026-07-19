import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import WebSocket from "ws";
import {
  MAX_WS_PAYLOAD_BYTES,
  PONG,
  V0_LIMITS,
  isEventMessage,
  isInvokeMessage,
  isModelName,
  isRegisterMessage,
} from "@gjc-remote/shared";
import { HostRegistry } from "../src/host-registry.js";

function createManualTimers() {
  const intervals = new Map();
  const timeouts = new Map();
  const clearedTimeouts = [];

  const add = (store, callback, delay) => {
    const timer = { unref() {} };
    store.set(timer, { callback, delay });
    return timer;
  };

  return {
    api: {
      setInterval: (callback, delay) => add(intervals, callback, delay),
      clearInterval: (timer) => intervals.delete(timer),
      setTimeout: (callback, delay) => add(timeouts, callback, delay),
      clearTimeout: (timer) => {
        const entry = timeouts.get(timer);
        if (entry) clearedTimeouts.push(entry.callback);
        return timeouts.delete(timer);
      },
    },
    runIntervals() {
      for (const { callback } of [...intervals.values()]) callback();
    },
    runTimeouts() {
      const entries = [...timeouts.values()];
      timeouts.clear();
      for (const { callback } of entries) callback();
    },
    runClearedTimeouts() {
      const callbacks = clearedTimeouts.splice(0);
      for (const callback of callbacks) callback();
    },
    get intervalCount() {
      return intervals.size;
    },
    get intervalDelays() {
      return [...intervals.values()].map(({ delay }) => delay);
    },
    get timeoutCount() {
      return timeouts.size;
    },
    get timeoutDelays() {
      return [...timeouts.values()].map(({ delay }) => delay);
    },
  };
}

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition was not met");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function startRegistry(
  tokens = new Map([["host-a", "token-a"]]),
  options = {}
) {
  const registry = new HostRegistry({
    port: 0,
    tokensByHostId: tokens,
    ...options,
  });
  if (!registry.wss.address()) await once(registry.wss, "listening");
  const { port } = registry.wss.address();

  return {
    registry,
    async connect(hostId, token) {
      const socket = new WebSocket(`ws://127.0.0.1:${port}`);
      await once(socket, "open");
      const response = once(socket, "message");
      socket.send(JSON.stringify({ type: "register", hostId, token }));
      const [raw] = await response;
      assert.deepEqual(JSON.parse(raw.toString()), { type: "register_ok" });
      return socket;
    },
    close() {
      return registry.close();
    },
  };
}

async function expectPolicyClose(socket, payload) {
  const closed = once(socket, "close");
  socket.send(payload);
  const [code] = await closed;
  assert.equal(code, 1008);
}

test("heartbeat durations must be positive finite values", () => {
  const tokensByHostId = new Map([["host-a", "token-a"]]);

  for (const heartbeatIntervalMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => new HostRegistry({ port: 0, tokensByHostId, heartbeatIntervalMs }),
      /heartbeatIntervalMs must be a positive duration/
    );
  }
  for (const heartbeatTimeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => new HostRegistry({ port: 0, tokensByHostId, heartbeatTimeoutMs }),
      /heartbeatTimeoutMs must be a positive duration/
    );
  }
});

test("v0 validators reject malformed required fields and preserve additive fields", () => {
  assert.equal(
    isRegisterMessage({
      type: "register",
      hostId: "host-a",
      token: "token-a",
      futureCapability: true,
    }),
    true
  );
  for (const message of [
    null,
    [],
    { type: "register", hostId: "", token: "token-a" },
    { type: "register", hostId: "x".repeat(V0_LIMITS.HOST_ID + 1), token: "token-a" },
    { type: "register", hostId: "host-a", token: "" },
    { type: "register", hostId: "host-a", token: "token-a", label: null },
  ]) {
    assert.equal(isRegisterMessage(message), false);
  }

  assert.equal(
    isInvokeMessage({
      type: "invoke",
      requestId: "request-1",
      workDir: "/workspace",
      command: { kind: "prompt", message: "", futureOption: true },
      futureCapability: true,
    }),
    true
  );
  const maxPrompt = {
    type: "invoke",
    requestId: "request-1",
    workDir: "/workspace",
    command: { kind: "prompt", message: "\0".repeat(V0_LIMITS.MESSAGE) },
  };
  assert.equal(isInvokeMessage(maxPrompt), true);
  assert.ok(Buffer.byteLength(JSON.stringify(maxPrompt)) < MAX_WS_PAYLOAD_BYTES);
  assert.equal(
    isInvokeMessage({
      ...maxPrompt,
      command: { kind: "prompt", message: "x".repeat(V0_LIMITS.MESSAGE + 1) },
    }),
    false
  );
  assert.equal(isModelName("x".repeat(V0_LIMITS.MODEL_NAME)), true);
  assert.equal(isModelName("x".repeat(V0_LIMITS.MODEL_NAME + 1)), false);
  for (const message of [
    { type: "invoke", workDir: "/workspace", command: { kind: "prompt", message: "x" } },
    { type: "invoke", requestId: "", workDir: "/workspace", command: { kind: "prompt", message: "x" } },
    { type: "invoke", requestId: "request-1", workDir: "", command: { kind: "prompt", message: "x" } },
    { type: "invoke", requestId: "request-1", workDir: "/workspace", command: null },
    { type: "invoke", requestId: "request-1", workDir: "/workspace", command: { kind: "prompt" } },
    { type: "invoke", requestId: "request-1", workDir: "/workspace", command: { kind: "unknown", message: "x" } },
    { type: "invoke", requestId: "request-1", workDir: "/workspace", command: { kind: "set_model", modelName: 1 } },
    { type: "invoke", requestId: "request-1", workDir: "/workspace", command: { kind: "set_model", modelName: "" } },
  ]) {
    assert.equal(isInvokeMessage(message), false);
  }

  assert.equal(
    isEventMessage({
      type: "event",
      requestId: "request-1",
      done: false,
      futureCapability: true,
    }),
    true
  );
  const inheritedEvent = Object.assign(Object.create({ done: true }), {
    type: "event",
    requestId: "request-1",
  });
  assert.equal(isEventMessage(inheritedEvent), false);
  for (const message of [
    { type: "event", done: true },
    { type: "event", requestId: "" },
    { type: "event", requestId: "request-1" },
    { type: "event", requestId: "request-1", event: null },
    { type: "event", requestId: "request-1", event: [] },
    { type: "event", requestId: "request-1", done: "true" },
    { type: "event", requestId: "request-1", error: 1 },
    { type: "event", requestId: "request-1", error: "" },
  ]) {
    assert.equal(isEventMessage(message), false);
  }
});

test("oversized inbound payloads close at the WebSocket boundary", async () => {
  const server = await startRegistry();
  const socket = new WebSocket(`ws://127.0.0.1:${server.registry.wss.address().port}`);
  try {
    await once(socket, "open");
    const closed = once(socket, "close");
    socket.send("x".repeat(MAX_WS_PAYLOAD_BYTES + 1));
    const [code] = await closed;
    assert.equal(code, 1009);
  } finally {
    socket.terminate();
    await server.close();
  }
});

test("invalid registration frames close with a policy violation", async () => {
  const server = await startRegistry();
  try {
    for (const payload of [
      "not json",
      "null",
      "[]",
      JSON.stringify({ type: "register", hostId: "", token: "token-a" }),
      JSON.stringify({ type: "register", hostId: "host-a", token: "token-a", label: null }),
    ]) {
      const socket = new WebSocket(`ws://127.0.0.1:${server.registry.wss.address().port}`);
      await once(socket, "open");
      await expectPolicyClose(socket, payload);
    }
    assert.equal(server.registry.listOnline().length, 0);
  } finally {
    await server.close();
  }
});

test("malformed event frames close safely", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    await expectPolicyClose(
      socket,
      JSON.stringify({ type: "event", requestId: "request-with-no-result" })
    );
  } finally {
    await server.close();
  }
});

test("valid invoke events relay callbacks and assistant text", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const events = [];
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      (event) => events.push(event),
      1000
    );
    const [raw] = await invokeFrame;
    const invoke = JSON.parse(raw.toString());
    assert.equal(invoke.type, "invoke");

    const event = { message: { role: "assistant", content: "answer" } };
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, event }));
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, done: true }));

    assert.deepEqual(await resultPromise, { ok: true, text: "answer" });
    assert.deepEqual(events, [event]);
  } finally {
    await server.close();
  }
});

test("invalid or oversized outbound invokes fail locally without disconnecting the host", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    let received = false;
    socket.once("message", () => {
      received = true;
    });

    const invalid = await server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "set_model", modelName: "x".repeat(V0_LIMITS.MODEL_NAME + 1) },
      () => {}
    );
    const oversized = await server.registry.invoke(
      "host-a",
      "/workspace",
      {
        kind: "prompt",
        message: "hello",
        futurePayload: "x".repeat(MAX_WS_PAYLOAD_BYTES),
      },
      () => {}
    );
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.deepEqual(invalid, { ok: false, error: "invalid invoke request" });
    assert.deepEqual(oversized, {
      ok: false,
      error: "invoke request exceeds WebSocket payload limit",
    });
    assert.equal(received, false);
    assert.equal(socket.readyState, WebSocket.OPEN);
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});

test("a different registered socket cannot spoof a pending requestId", async () => {
  const server = await startRegistry(
    new Map([
      ["host-a", "token-a"],
      ["host-b", "token-b"],
    ])
  );
  try {
    const owner = await server.connect("host-a", "token-a");
    const attacker = await server.connect("host-b", "token-b");
    const invokeFrame = once(owner, "message");
    const events = [];
    let settled = false;
    const resultPromise = server.registry
      .invoke("host-a", "/workspace", { kind: "prompt", message: "hello" }, (event) => events.push(event), 1000)
      .then((result) => {
        settled = true;
        return result;
      });
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    const attackerClosed = once(attacker, "close");
    attacker.send(
      JSON.stringify({
        type: "event",
        requestId,
        event: { message: { role: "assistant", content: "spoofed" } },
        done: true,
      })
    );
    const [closeCode] = await attackerClosed;
    assert.equal(closeCode, 1008);
    assert.equal(settled, false);
    assert.deepEqual(events, []);

    owner.send(JSON.stringify({ type: "event", requestId, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined });
  } finally {
    await server.close();
  }
});

test("heartbeat pong keeps a registered host online", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, { timers: timers.api });
  try {
    const socket = await server.connect("host-a", "token-a");
    assert.deepEqual(timers.intervalDelays, [30_000]);
    const ping = once(socket, "message");

    timers.runIntervals();
    const [raw] = await ping;
    assert.deepEqual(JSON.parse(raw.toString()), { type: "ping" });
    assert.equal(timers.timeoutCount, 1);
    assert.deepEqual(timers.timeoutDelays, [10_000]);

    socket.send(JSON.stringify(PONG));
    await waitFor(() => timers.timeoutCount === 0);

    assert.equal(timers.timeoutCount, 0);
    timers.runClearedTimeouts();
    assert.equal(server.registry.isOnline("host-a"), true);
    assert.equal(socket.readyState, WebSocket.OPEN);
  } finally {
    await server.close();
  }
});

test("heartbeat timeout disconnects a host and fails its pending invoke", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, { timers: timers.api });
  try {
    const socket = await server.connect("host-a", "token-a");
    const registeredSocket = server.registry.connections.get("host-a");
    assert.ok(registeredSocket);
    const invokeFrame = once(socket, "message");
    const result = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      1000
    );
    await invokeFrame;

    const ping = once(socket, "message");
    const closed = once(socket, "close");
    timers.runIntervals();
    await ping;
    assert.deepEqual(timers.timeoutDelays, [10_000]);
    timers.runTimeouts();
    await closed;

    assert.deepEqual(await result, {
      ok: false,
      error: "host 'host-a' heartbeat timed out",
    });
    assert.equal(server.registry.isOnline("host-a"), false);
    assert.equal(server.registry.pendingRequests.size, 0);
    registeredSocket.emit("message", Buffer.from(JSON.stringify(PONG)), false);
    assert.equal(server.registry.isOnline("host-a"), false);
    assert.equal(server.registry.heartbeatStates.has(registeredSocket), false);
  } finally {
    await server.close();
  }
});

test("replacement sockets are not removed by stale heartbeat state", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, { timers: timers.api });
  try {
    const original = await server.connect("host-a", "token-a");
    const invokeFrame = once(original, "message");
    const originalResult = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      1000
    );
    await invokeFrame;

    const originalPing = once(original, "message");
    timers.runIntervals();
    await originalPing;
    assert.equal(timers.timeoutCount, 1);

    const originalClosed = once(original, "close");
    const replacement = await server.connect("host-a", "token-a");
    await originalClosed;

    assert.deepEqual(await originalResult, {
      ok: false,
      error: "host 'host-a' connection replaced",
    });
    assert.equal(timers.timeoutCount, 0);
    timers.runClearedTimeouts();
    assert.equal(server.registry.isOnline("host-a"), true);
    assert.equal(replacement.readyState, WebSocket.OPEN);

    const replacementPing = once(replacement, "message");
    timers.runIntervals();
    const [raw] = await replacementPing;
    assert.deepEqual(JSON.parse(raw.toString()), { type: "ping" });
    replacement.send(JSON.stringify(PONG));
    await waitFor(() => timers.timeoutCount === 0);
    assert.equal(timers.timeoutCount, 0);
    timers.runClearedTimeouts();
    assert.equal(server.registry.isOnline("host-a"), true);
    assert.equal(replacement.readyState, WebSocket.OPEN);
  } finally {
    await server.close();
  }
});

test("registry shutdown clears heartbeat state and settles pending invokes", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, { timers: timers.api });
  const socket = await server.connect("host-a", "token-a");
  const invokeFrame = once(socket, "message");
  const result = server.registry.invoke(
    "host-a",
    "/workspace",
    { kind: "prompt", message: "hello" },
    () => {},
    1000
  );
  await invokeFrame;

  const ping = once(socket, "message");
  timers.runIntervals();
  await ping;
  assert.equal(timers.intervalCount, 1);
  assert.equal(timers.timeoutCount, 1);

  const closing = server.registry.close();
  assert.strictEqual(server.registry.close(), closing);
  await closing;

  assert.deepEqual(await result, {
    ok: false,
    error: "HostRegistry shut down",
  });
  assert.equal(timers.intervalCount, 0);
  assert.equal(timers.timeoutCount, 0);
  assert.equal(server.registry.connections.size, 0);
  assert.equal(server.registry.pendingRequests.size, 0);
});
