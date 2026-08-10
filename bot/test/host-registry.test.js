import { createServer } from "node:net";
import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import WebSocket from "ws";
import {
  CAPABILITIES,
  MAX_WS_PAYLOAD_BYTES,
  PONG,
  PROTOCOL_VERSION,
  V0_LIMITS,
  isEventMessage,
  isInvokeMessage,
  isCapabilityList,
  isModelName,
  isProtocolVersion,
  isRegisterMessage,
  isRegisterOkMessage,
  negotiateCapabilities,
  PROTOCOL_ERROR_CODES,
  WORKSPACE_READINESS_CAPABILITY,
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
    async connect(hostId, token, register = {}) {
      const socket = new WebSocket(`ws://127.0.0.1:${port}`);
      await once(socket, "open");
      const response = once(socket, "message");
      socket.send(
        JSON.stringify({
          type: "register",
          hostId,
          token,
          protocolVersion: PROTOCOL_VERSION,
          capabilities: CAPABILITIES,
          ...register,
        })
      );
      const [raw] = await response;
      assert.deepEqual(JSON.parse(raw.toString()), {
        type: "register_ok",
        protocolVersion: PROTOCOL_VERSION,
        capabilities: CAPABILITIES,
      });
      return socket;
    },
    close() {
      return registry.close();
    },
  };
}
async function connectV2(server, hostId = "host-a", token = "token-a", register = {}) {
  const port = server.registry.wss.address().port;
  const socket = new WebSocket(`ws://127.0.0.1:${port}`);
  await once(socket, "open");
  const response = once(socket, "message");
  socket.send(
    JSON.stringify({
      type: "register",
      hostId,
      token,
      protocolVersion: 2,
      capabilities: [...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY],
      ...register,
    })
  );
  const [raw] = await response;
  return { socket, response: JSON.parse(raw.toString()) };
}

function readinessFrame(overrides = {}) {
  return {
    type: "readiness",
    socketGeneration: 1,
    revision: 1,
    observedAt: Date.now(),
    ttlMs: 1_000,
    status: {
      connection: "online",
      runtime: "ready",
      providerAuth: "configured",
      modelProfile: "ready",
      workspace: "ready",
    },
    workspaceId: "workspace-1",
    workspaceGeneration: 1,
    ...overrides,
  };
}

async function sendReadiness(socket, frame) {
  socket.send(JSON.stringify(frame));
  await new Promise((resolve) => setTimeout(resolve, 5));
}

async function expectPolicyClose(socket, payload) {
  const closed = once(socket, "close");
  socket.send(payload);
  const [code] = await closed;
  assert.equal(code, 1008);
}

test("WebSocket server errors are surfaced through the registry callback", async () => {
  const blocker = createServer();
  await new Promise((resolve, reject) => {
    blocker.once("error", reject);
    blocker.listen(0, resolve);
  });
  const { port } = blocker.address();
  const errors = [];
  let reported;
  const registry = new HostRegistry({
    port,
    tokensByHostId: new Map([["host-a", "token-a"]]),
    onError: (error) => {
      errors.push(error);
      reported?.();
    },
  });

  try {
    await new Promise((resolve) => {
      reported = resolve;
      if (errors.length > 0) resolve();
    });
    assert.equal(errors.length, 1);
    assert.equal(errors[0]?.code, "EADDRINUSE");
  } finally {
    await registry.close().catch(() => {});
    await new Promise((resolve) => blocker.close(resolve));
  }
});
test("non-function onError values do not throw from WS server errors", async () => {
  const registry = new HostRegistry({
    port: 0,
    tokensByHostId: new Map([["host-a", "token-a"]]),
    onError: "not a callback",
  });

  try {
    assert.doesNotThrow(() => registry.wss.emit("error", new Error("synthetic WS error")));
  } finally {
    await registry.close().catch(() => {});
  }
});
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

test("adversarial: invoke idle/hard-cap durations must be positive finite values", () => {
  const tokensByHostId = new Map([["host-a", "token-a"]]);

  for (const invokeIdleTimeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => new HostRegistry({ port: 0, tokensByHostId, invokeIdleTimeoutMs }),
      /invokeIdleTimeoutMs must be a positive duration/
    );
  }
  for (const invokeHardCapMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => new HostRegistry({ port: 0, tokensByHostId, invokeHardCapMs }),
      /invokeHardCapMs must be a positive duration/
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
test("invoke idle timer resets on each streamed event", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 60,
    invokeHardCapMs: 5000,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {}
    );
    let settled = false;
    resultPromise.then(() => {
      settled = true;
    });
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    const event = { message: { role: "assistant", content: "still working" } };
    for (let i = 0; i < 4; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 25));
      socket.send(JSON.stringify({ type: "event", requestId, event }));
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(settled, false);

    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: "still working" });
  } finally {
    await server.close();
  }
});

test("invoke idle expiry fires with zero events", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 20,
    invokeHardCapMs: 5000,
  });
  try {
    await server.connect("host-a", "token-a");
    const result = await server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {}
    );
    assert.deepEqual(result, {
      ok: false,
      error: "timed out waiting for host response",
    });
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});

test("invoke hard cap fires despite continuous activity", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 1000,
    invokeHardCapMs: 40,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {}
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    let settled = false;
    resultPromise.then(() => {
      settled = true;
    });
    const event = { message: { role: "assistant", content: "still working" } };
    const interval = setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "event", requestId, event }));
      }
    }, 10);
    try {
      await waitFor(() => settled, 2000);
    } finally {
      clearInterval(interval);
    }

    assert.deepEqual(await resultPromise, {
      ok: false,
      error: "invoke exceeded absolute hard-cap",
    });
  } finally {
    await server.close();
  }
});

test("invoke timers are cleared on normal resolve", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 30,
    invokeHardCapMs: 200,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {}
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));

    const result = await resultPromise;
    assert.deepEqual(result, { ok: true, text: undefined });
    assert.equal(server.registry.pendingRequests.size, 0);

    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});
test("adversarial: a stale settle call after normal resolution is a safe no-op (double-resolve safety)", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 5000,
    invokeHardCapMs: 5000,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {}
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());
    const pendingEntry = server.registry.pendingRequests.get(requestId);
    assert.ok(pendingEntry);

    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    const result = await resultPromise;
    assert.deepEqual(result, { ok: true, text: undefined });
    assert.equal(server.registry.pendingRequests.size, 0);

    // Simulate a stale idle/hard-cap timer firing after the real done already
    // settled this request: calling settle again must be a safe no-op that
    // neither changes the resolved value nor corrupts registry state.
    assert.doesNotThrow(() => {
      pendingEntry.settle({ ok: false, error: "invoke exceeded absolute hard-cap" });
    });
    assert.deepEqual(await resultPromise, { ok: true, text: undefined });
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});

test("adversarial: N sequential invokes leave no pending requests or armed timers (timer-leak safety)", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 50,
    invokeHardCapMs: 5000,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const N = 5;
    for (let i = 0; i < N; i += 1) {
      const invokeFrame = once(socket, "message");
      const resultPromise = server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: `hi-${i}` },
        () => {}
      );
      const [raw] = await invokeFrame;
      const { requestId } = JSON.parse(raw.toString());
      socket.send(JSON.stringify({ type: "event", requestId, done: true }));
      const result = await resultPromise;
      assert.deepEqual(result, { ok: true, text: undefined });
      assert.equal(server.registry.pendingRequests.size, 0);
      assert.equal(server.registry.pendingCountBySocket.size, 0);
    }
    // Wait past the idle window: if a timer had leaked or been left armed on
    // a prior iteration it would fire (and corrupt state) by now.
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});

test("adversarial: an event frame arriving after done is ignored and does not resurrect the pending entry (boundary)", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const events = [];
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      (event) => events.push(event)
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined });
    assert.equal(server.registry.pendingRequests.size, 0);

    // A late event frame for the same (now-settled) requestId must not crash,
    // must not resurrect the pending entry, and must not re-arm a timer.
    assert.doesNotThrow(() => {
      socket.send(
        JSON.stringify({
          type: "event",
          requestId,
          event: { message: { role: "assistant", content: "late" } },
        })
      );
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(server.registry.pendingRequests.size, 0);
    assert.equal(events.length, 0);
    assert.equal(socket.readyState, WebSocket.OPEN);
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
      error: { code: "HEARTBEAT_TIMEOUT", retryable: true, action: "retry_later" },
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
      error: { code: "CONNECTION_LOST", retryable: true, action: "retry_later" },
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
    error: { code: "CONNECTION_LOST", retryable: true, action: "retry_later" },
  });
  assert.equal(timers.intervalCount, 0);
  assert.equal(timers.timeoutCount, 0);
  assert.equal(server.registry.connections.size, 0);
  assert.equal(server.registry.pendingRequests.size, 0);
});

test("per-host in-flight invokes are capped and freed on completion", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const cap = V0_LIMITS.MAX_PENDING_PER_HOST;

    for (let i = 0; i < cap; i += 1) {
      server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: "hello" },
        () => {},
        10_000
      );
    }
    assert.equal(server.registry.pendingRequests.size, cap);

    const overflow = await server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      10_000
    );
    assert.deepEqual(overflow, {
      ok: false,
      error: { code: "RESOURCE_EXHAUSTED", retryable: true, action: "retry_later" },
    });
    assert.equal(server.registry.pendingRequests.size, cap);

    const [freedRequestId] = [...server.registry.pendingRequests.keys()];
    socket.send(
      JSON.stringify({ type: "event", requestId: freedRequestId, done: true })
    );
    await waitFor(() => server.registry.pendingRequests.size === cap - 1);

    const invokeFrame = once(socket, "message");
    server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      10_000
    );
    await invokeFrame;
    assert.equal(server.registry.pendingRequests.size, cap);
  } finally {
    await server.close();
  }
});

test("a host's pending cap does not block a different host", async () => {
  const server = await startRegistry(
    new Map([
      ["host-a", "token-a"],
      ["host-b", "token-b"],
    ])
  );
  try {
    await server.connect("host-a", "token-a");
    const socketB = await server.connect("host-b", "token-b");
    const cap = V0_LIMITS.MAX_PENDING_PER_HOST;

    for (let i = 0; i < cap; i += 1) {
      server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: "hello" },
        () => {},
        10_000
      );
    }
    const overflowA = await server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      10_000
    );
    assert.equal(overflowA.ok, false);

    const invokeFrameB = once(socketB, "message");
    server.registry.invoke(
      "host-b",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      10_000
    );
    await invokeFrameB;
    assert.equal(server.registry.pendingRequests.size, cap + 1);
  } finally {
    await server.close();
  }
});
test("protocol version validators accept only supported versions", () => {
  assert.equal(isProtocolVersion(0), true);
  assert.equal(isProtocolVersion(1), true);
  assert.equal(isProtocolVersion(2), true);
  for (const bad of [-1, 3, 1.5, "1", Number.NaN, V0_LIMITS.PROTOCOL_VERSION_MAX]) {
    assert.equal(isProtocolVersion(bad), false);
  }

  assert.equal(isCapabilityList([]), true);
  assert.equal(isCapabilityList(["invoke", "set_model"]), true);
  assert.equal(isCapabilityList(Array(V0_LIMITS.MAX_CAPABILITIES).fill("x")), true);
  for (const bad of [
    "invoke",
    [1],
    [""],
    ["x".repeat(V0_LIMITS.CAPABILITY + 1)],
    Array(V0_LIMITS.MAX_CAPABILITIES + 1).fill("x"),
  ]) {
    assert.equal(isCapabilityList(bad), false);
  }

  // Register/register_ok accept the v1 fields but still pass with them absent.
  assert.equal(isRegisterMessage({ type: "register", hostId: "h", token: "t" }), true);
  assert.equal(
    isRegisterMessage({
      type: "register",
      hostId: "h",
      token: "t",
      protocolVersion: 1,
      capabilities: ["invoke"],
    }),
    true
  );
  for (const bad of [
    { type: "register", hostId: "h", token: "t", protocolVersion: -1 },
    { type: "register", hostId: "h", token: "t", capabilities: "invoke" },
  ]) {
    assert.equal(isRegisterMessage(bad), false);
  }
  assert.equal(isRegisterOkMessage({ type: "register_ok" }), true);
  assert.equal(
    isRegisterOkMessage({ type: "register_ok", protocolVersion: 1, capabilities: ["invoke"] }),
    true
  );
  assert.equal(isRegisterOkMessage({ type: "register_ok", capabilities: [1] }), false);

  // Negotiation intersects local with the peer's advertised set.
  assert.deepEqual(negotiateCapabilities(["invoke", "set_model"], ["set_model", "bogus"]), [
    "set_model",
  ]);
  assert.deepEqual(negotiateCapabilities(["invoke"], undefined), []);
  assert.deepEqual(negotiateCapabilities(["invoke"], "not-a-list"), []);
});

test("register handshake negotiates protocol version and shared capabilities", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a", {
      capabilities: ["invoke", "bogus"],
    });
    assert.deepEqual(server.registry.getHostInfo("host-a"), {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: ["invoke"],
    });

    const closed = once(socket, "close");
    socket.close();
    await closed;
    await waitFor(() => server.registry.getHostInfo("host-a") === undefined);
  } finally {
    await server.close();
  }
});

test("a legacy v0 daemon registers with version 0 and no shared capabilities", async () => {
  const server = await startRegistry();
  const port = server.registry.wss.address().port;
  const socket = new WebSocket(`ws://127.0.0.1:${port}`);
  try {
    await once(socket, "open");
    const response = once(socket, "message");
    socket.send(JSON.stringify({ type: "register", hostId: "host-a", token: "token-a" }));
    const [raw] = await response;
    assert.deepEqual(JSON.parse(raw.toString()), {
      type: "register_ok",
      protocolVersion: PROTOCOL_VERSION,
      capabilities: CAPABILITIES,
    });
    assert.deepEqual(server.registry.getHostInfo("host-a"), {
      protocolVersion: 0,
      capabilities: [],
    });
  } finally {
    socket.terminate();
    await server.close();
  }
});

test("future protocol versions fail closed", async () => {
  const server = await startRegistry();
  let socket;
  try {
    socket = new WebSocket(`ws://127.0.0.1:${server.registry.wss.address().port}`);
    await once(socket, "open");
    const closed = once(socket, "close");
    socket.send(
      JSON.stringify({
        type: "register",
        hostId: "host-a",
        token: "token-a",
        protocolVersion: PROTOCOL_VERSION + 5,
        capabilities: CAPABILITIES,
      })
    );
    await closed;
    assert.equal(server.registry.getHostInfo("host-a"), undefined);
  } finally {
    socket?.terminate();
    await server.close();
  }
});
// ---------------------------------------------------------------------------
// #35: workflow gate answer channel
// ---------------------------------------------------------------------------

test("#35 a gate_request fires onGate, suspends the invoke idle timer, and answerGate sends an answer frame", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 40,
    invokeHardCapMs: 5000,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const gates = [];
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {},
      undefined,
      (gate) => gates.push(gate)
    );
    let settled = false;
    resultPromise.then(() => {
      settled = true;
    });
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    const gateEvent = {
      type: "gate_request",
      gateId: "g1",
      prompt: "Pick a fruit",
      kind: "question",
      choices: [{ value: "a", label: "Apple" }],
    };
    socket.send(JSON.stringify({ type: "event", requestId, event: gateEvent }));

    await waitFor(() => gates.length === 1);
    assert.equal(gates[0].gateId, "g1");
    assert.equal(gates[0].requestId, requestId);
    assert.equal(gates[0].prompt, "Pick a fruit");
    assert.equal(gates[0].kind, "question");
    assert.deepEqual(gates[0].choices, [{ value: "a", label: "Apple" }]);

    // The idle window (40ms) must NOT reap the invoke while the gate is pending.
    await new Promise((resolve) => setTimeout(resolve, 120));
    assert.equal(settled, false);

    const answerFrame = once(socket, "message");
    const answerResult = server.registry.answerGate("host-a", requestId, "g1", "Apple");
    assert.deepEqual(answerResult, { ok: true });
    const [rawAnswer] = await answerFrame;
    assert.deepEqual(JSON.parse(rawAnswer.toString()), {
      type: "answer",
      requestId,
      gateId: "g1",
      answer: "Apple",
    });

    socket.send(
      JSON.stringify({
        type: "event",
        requestId,
        event: { message: { role: "assistant", content: "done" } },
      })
    );
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: "done" });
  } finally {
    await server.close();
  }
});

test("#35 answerGate rejects unknown requests, absent gates, stale gate ids, and wrong hosts", async () => {
  const server = await startRegistry(new Map([["host-a", "token-a"], ["host-b", "token-b"]]));
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {},
      undefined,
      () => {}
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    assert.deepEqual(server.registry.answerGate("host-a", "nope", "g1", "x"), {
      ok: false,
      error: "no in-flight request for that answer",
    });
    assert.deepEqual(server.registry.answerGate("host-a", requestId, "g1", "x"), {
      ok: false,
      error: "no matching pending gate for that answer",
    });

    socket.send(
      JSON.stringify({
        type: "event",
        requestId,
        event: { type: "gate_request", gateId: "g1", prompt: "p", kind: "question" },
      })
    );
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gatePending === true
    );

    assert.deepEqual(server.registry.answerGate("host-a", requestId, "WRONG", "x"), {
      ok: false,
      error: "no matching pending gate for that answer",
    });
    assert.equal(server.registry.answerGate("host-b", requestId, "g1", "x").ok, false);

    const answerFrame = once(socket, "message");
    assert.deepEqual(server.registry.answerGate("host-a", requestId, "g1", "yes"), { ok: true });
    await answerFrame;
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    await resultPromise;
  } finally {
    await server.close();
  }
});

test("#35 answering a gate re-arms the idle timer so a silent daemon still times out", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 40,
    invokeHardCapMs: 5000,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {},
      undefined,
      () => {}
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    socket.send(
      JSON.stringify({
        type: "event",
        requestId,
        event: { type: "gate_request", gateId: "g1", prompt: "p", kind: "question" },
      })
    );
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gatePending === true
    );

    const answerFrame = once(socket, "message");
    server.registry.answerGate("host-a", requestId, "g1", "yes");
    await answerFrame;

    // Daemon stays silent after the answer: the re-armed idle timer must fire.
    assert.deepEqual(await resultPromise, {
      ok: false,
      error: "timed out waiting for host response",
    });
  } finally {
    await server.close();
  }
});


test("adversarial: a late answer after the invoke has already settled (done) is rejected without throwing", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {},
      undefined,
      () => {}
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    socket.send(
      JSON.stringify({
        type: "event",
        requestId,
        event: { type: "gate_request", gateId: "g1", prompt: "p", kind: "question" },
      })
    );
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gatePending === true
    );

    server.registry.answerGate("host-a", requestId, "g1", "yes");
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    await resultPromise;

    // The request is gone: a late answer for the same (now-stale) requestId/gateId
    // must be rejected, not throw.
    assert.deepEqual(server.registry.answerGate("host-a", requestId, "g1", "late"), {
      ok: false,
      error: "no in-flight request for that answer",
    });
  } finally {
    await server.close();
  }
});

test("adversarial: a second answer for the same requestId/gateId after the gate was already answered is rejected", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {},
      undefined,
      () => {}
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    socket.send(
      JSON.stringify({
        type: "event",
        requestId,
        event: { type: "gate_request", gateId: "g1", prompt: "p", kind: "question" },
      })
    );
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gatePending === true
    );

    const firstAnswer = server.registry.answerGate("host-a", requestId, "g1", "yes");
    assert.deepEqual(firstAnswer, { ok: true });

    // Same requestId, same gateId, submitted again before `done`: gatePending is
    // already false, so this must be rejected rather than sending a duplicate
    // answer frame to the daemon.
    const secondAnswer = server.registry.answerGate("host-a", requestId, "g1", "yes-again");
    assert.deepEqual(secondAnswer, {
      ok: false,
      error: "no matching pending gate for that answer",
    });

    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    await resultPromise;
  } finally {
    await server.close();
  }
});

test("adversarial: a gate pending across multiple idle windows never times out, only silence after answering does", async () => {
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 30,
    invokeHardCapMs: 5000,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {},
      undefined,
      () => {}
    );
    let settled = false;
    resultPromise.then(() => {
      settled = true;
    });
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());

    socket.send(
      JSON.stringify({
        type: "event",
        requestId,
        event: { type: "gate_request", gateId: "g1", prompt: "p", kind: "question" },
      })
    );
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gatePending === true
    );

    // Wait across several multiples of the idle window while the gate is
    // pending: the invoke must survive every one of them.
    await new Promise((resolve) => setTimeout(resolve, 30 * 6));
    assert.equal(settled, false);

    server.registry.answerGate("host-a", requestId, "g1", "yes");

    // The daemon goes silent after the answer: the re-armed idle timer must
    // now fire.
    assert.deepEqual(await resultPromise, {
      ok: false,
      error: "timed out waiting for host response",
    });
  } finally {
    await server.close();
  }
});
test("phase 1 gates readiness capability advertisement atomically", async () => {
  const server = await startRegistry();
  try {
    const suppressed = await connectV2(server, "host-a", "token-a", {
      capabilities: CAPABILITIES,
    });
    assert.deepEqual(suppressed.response, {
      type: "register_ok",
      protocolVersion: PROTOCOL_VERSION,
      capabilities: CAPABILITIES,
    });
    suppressed.socket.terminate();
    await waitFor(() => server.registry.getHostInfo("host-a") === undefined);

    const committed = await connectV2(server);
    assert.deepEqual(committed.response, {
      type: "register_ok",
      protocolVersion: 2,
      capabilities: [...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY],
    });
    assert.deepEqual(server.registry.getHostInfo("host-a"), {
      protocolVersion: 2,
      capabilities: [...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY],
    });
  } finally {
    await server.close();
  }
});

test("phase 1 accepts bounded readiness, keeps ping/pong from refreshing TTL, and resets on replacement", async () => {
  let wall = 1_700_000_000_000;
  let monotonic = 0;
  const server = await startRegistry(undefined, {
    now: () => wall,
    monotonicNow: () => monotonic,
  });
  try {
    const first = await connectV2(server);
    await sendReadiness(first.socket, readinessFrame({ observedAt: wall }));
    assert.equal(server.registry.getHostReadiness("host-a").aggregate, "ready");
    const expiry = server.registry.getHostReadiness("host-a").expiresAt;

    first.socket.send(JSON.stringify({ type: "pong" }));
    monotonic = 1_000;
    const expired = server.registry.getHostReadiness("host-a");
    assert.equal(expired.aggregate, "degraded");
    assert.equal(expired.expiresAt, expiry);

    first.socket.terminate();
    await waitFor(() => server.registry.getHostReadiness("host-a") === undefined);
    const replacement = await connectV2(server);
    assert.deepEqual(server.registry.getHostReadiness("host-a"), {
      hostId: "host-a",
      aggregate: "connected-not-ready",
      dimensions: {
        connection: "online",
        runtime: "error",
        providerAuth: "unknown",
        modelProfile: "unknown",
        workspace: "unknown",
      },
      lastErrorAt: null,
      revision: 0,
      socketGeneration: null,
    });
    replacement.socket.terminate();
  } finally {
    await server.close();
  }
});
test("phase 1 preserves readiness fences across replacement and records replay state", async () => {
  const server = await startRegistry();
  try {
    const first = await connectV2(server);
    await sendReadiness(first.socket, readinessFrame({ socketGeneration: 7, observedAt: Date.now() }));
    first.socket.terminate();
    await waitFor(() => server.registry.getHostReadiness("host-a") === undefined);

    const replacement = await connectV2(server);
    const closed = once(replacement.socket, "close");
    replacement.socket.send(
      JSON.stringify(
        readinessFrame({
          socketGeneration: 7,
          revision: 2,
          observedAt: Date.now(),
        })
      )
    );
    await closed;
    assert.equal(
      server.registry.readinessStates.get("host-a")?.lastError?.code,
      PROTOCOL_ERROR_CODES.READINESS_REPLAYED
    );

    const current = await connectV2(server);
    await sendReadiness(
      current.socket,
      readinessFrame({ socketGeneration: 8, revision: 1, observedAt: Date.now() })
    );
    assert.equal(server.registry.getHostReadiness("host-a").socketGeneration, 8);
    current.socket.terminate();
  } finally {
    await server.close();
  }
});

test("phase 1 records invalid freshness and recovers degraded readiness on a fresh frame", async () => {
  let wall = 1_700_000_000_000;
  let monotonic = 0;
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    timers: timers.api,
    now: () => wall,
    monotonicNow: () => monotonic,
  });
  try {
    const { socket } = await connectV2(server);
    const invalid = readinessFrame({ observedAt: wall + 10 * 60 * 1000 });
    socket.send(JSON.stringify(invalid));
    await waitFor(
      () =>
        server.registry.readinessStates.get("host-a")?.lastError?.code ===
        PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID
    );
    assert.deepEqual(
      server.registry.readinessStates.get("host-a")?.lastError?.remediation,
      {
        code: PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID,
        retryable: false,
        action: "contact_admin",
      }
    );
    socket.terminate();
    await waitFor(() => server.registry.getHostReadiness("host-a") === undefined);
  } finally {
    await server.close();
  }

  const recovery = await startRegistry(undefined, {
    timers: createManualTimers().api,
    now: () => wall,
    monotonicNow: () => monotonic,
  });
  try {
    const { socket } = await connectV2(recovery);
    await sendReadiness(socket, readinessFrame({ observedAt: wall }));
    assert.equal(recovery.registry.getHostReadiness("host-a").aggregate, "ready");
    monotonic = 2_000;
    assert.equal(recovery.registry.getHostReadiness("host-a").aggregate, "degraded");
    await sendReadiness(socket, readinessFrame({ revision: 2, observedAt: wall }));
    assert.equal(recovery.registry.getHostReadiness("host-a").aggregate, "ready");
    socket.terminate();
  } finally {
    await recovery.close();
  }
});

test("phase 1 fences revisions and workspace generations before state mutation", async () => {
  const server = await startRegistry();
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({ observedAt: Date.now(), workspaceGeneration: 2 }));
    assert.equal(server.registry.getHostReadiness("host-a").workspaceGeneration, 2);

    await sendReadiness(
      socket,
      readinessFrame({
        revision: 2,
        observedAt: Date.now(),
        workspaceGeneration: 3,
      })
    );
    assert.equal(server.registry.getHostReadiness("host-a").workspaceGeneration, 3);
    socket.send(
      JSON.stringify(
        readinessFrame({
          revision: 3,
          observedAt: Date.now(),
          workspaceGeneration: 2,
        })
      )
    );

    await waitFor(
      () => server.registry.getHostReadiness("host-a") === undefined
    );
  } finally {
    await server.close();
  }
});

test("phase 1 aggregate precedence and not-ready invoke remediation allocate no requests", async () => {
  const tokens = new Map([
    ["offline", "offline-token"],
    ["incompatible", "incompatible-token"],
    ["degraded", "degraded-token"],
    ["missing", "missing-token"],
    ["ready", "ready-token"],
  ]);
  const server = await startRegistry(tokens);
  const sockets = [];
  try {
    const offline = await connectV2(server, "offline", "offline-token");
    const incompatible = await connectV2(server, "incompatible", "incompatible-token");
    const degraded = await connectV2(server, "degraded", "degraded-token");
    const missing = await connectV2(server, "missing", "missing-token");
    const ready = await connectV2(server, "ready", "ready-token");
    sockets.push(offline.socket, incompatible.socket, degraded.socket, missing.socket, ready.socket);

    await sendReadiness(
      offline.socket,
      readinessFrame({
        observedAt: Date.now(),
        status: { ...readinessFrame().status, connection: "offline" },
      })
    );
    await sendReadiness(
      incompatible.socket,
      readinessFrame({
        observedAt: Date.now(),
        status: { ...readinessFrame().status, runtime: "incompatible" },
      })
    );
    await sendReadiness(degraded.socket, readinessFrame({ observedAt: Date.now() }));
    await sendReadiness(
      degraded.socket,
      readinessFrame({
        revision: 2,
        observedAt: Date.now(),
        lastError: {
          code: "PROVIDER_UNAVAILABLE",
          at: Date.now(),
          remediation: { code: "PROVIDER_UNAVAILABLE", retryable: true, action: "retry_later" },
        },
      })
    );
    await sendReadiness(
      missing.socket,
      readinessFrame({
        observedAt: Date.now(),
        status: { ...readinessFrame().status, providerAuth: "missing" },
      })
    );
    await sendReadiness(ready.socket, readinessFrame({ observedAt: Date.now() }));

    assert.equal(server.registry.getHostReadiness("offline").aggregate, "offline");
    assert.equal(server.registry.getHostReadiness("incompatible").aggregate, "incompatible");
    assert.equal(server.registry.getHostReadiness("degraded").aggregate, "degraded");
    assert.equal(server.registry.getHostReadiness("missing").aggregate, "connected-not-ready");
    assert.equal(server.registry.getHostReadiness("ready").aggregate, "ready");

    const outcomes = await Promise.all([
      server.registry.invoke("offline", "/x", { kind: "prompt", message: "x" }, () => {}),
      server.registry.invoke("incompatible", "/x", { kind: "prompt", message: "x" }, () => {}),
      server.registry.invoke("degraded", "/x", { kind: "prompt", message: "x" }, () => {}),
      server.registry.invoke("missing", "/x", { kind: "prompt", message: "x" }, () => {}),
    ]);
    assert.deepEqual(
      outcomes.map((result) => result.error),
      [
        { code: "CONNECTION_LOST", retryable: true, action: "retry_later" },
        { code: "RUNTIME_INCOMPATIBLE", retryable: false, action: "contact_admin" },
        { code: "PROVIDER_UNAVAILABLE", retryable: true, action: "retry_later" },
        { code: "PROVIDER_MISSING", retryable: true, action: "login" },
      ]
    );
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    for (const socket of sockets) socket.terminate();
    await server.close();
  }
});

test("phase 1 host projections redact hostile identity and readiness diagnostics", async () => {
  const hostId = "host\nsecret";
  const token = "secret-token";
  const server = await startRegistry(new Map([[hostId, token]]));
  try {
    const { socket } = await connectV2(server, hostId, token);
    await sendReadiness(
      socket,
      readinessFrame({
        observedAt: Date.now(),
        lastError: {
          code: "PROVIDER_MISSING",
          at: Date.now(),
          remediation: { code: "PROVIDER_MISSING", retryable: true, action: "login" },
        },
      })
    );
    const projection = server.registry.getHostReadiness(hostId);
    assert.equal(projection.hostId, "[redacted-host]");
    assert.equal(projection.lastErrorAt > 0, true);
    assert.equal(JSON.stringify(projection).includes(token), false);
    assert.equal(JSON.stringify(projection).includes("/var/lib"), false);
    assert.equal(/[\u0000-\u001f]/.test(JSON.stringify(projection)), false);
    socket.terminate();
  } finally {
    await server.close();
  }
});
