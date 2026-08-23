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
  PROTOCOL_VERSION_V3,
  READINESS_MAX_TTL_MS,
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
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_READINESS_CAPABILITY,
} from "@gjc-remote/shared";
import { workspaceBindingFingerprint } from "@gjc-remote/shared/workspace-binding";
import {
  HostRegistry,
  MAX_BINDING_READINESS_STATES,
  extractAssistantText,
  freezeManagedAuthorityDescriptor,
} from "../src/host-registry.js";

function managedRoute(channelId, overrides = {}) {
  const authority = {
    authorityEpoch: 1,
    fenceGeneration: 1,
    hostId: "host-a",
    mappingId: `mapping-${channelId}`,
    mappingGeneration: 1,
    mappingVersion: 1,
    sourcePlatform: "posix",
    workspaceId: `workspace-${channelId}`,
    workspaceGeneration: 1,
    authorityFingerprint: "a".repeat(64),
    ...overrides.authority,
  };
  return Object.freeze({
    hostId: authority.hostId,
    workDir: null,
    mappingId: authority.mappingId,
    mappingGeneration: authority.mappingGeneration,
    mappingVersion: authority.mappingVersion,
    sourcePlatform: authority.sourcePlatform,
    workspaceId: authority.workspaceId,
    workspaceGeneration: authority.workspaceGeneration,
    routeFingerprint: "b".repeat(64),
    authority: Object.freeze(authority),
    ...overrides,
  });
}

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
    runTimeoutByDelay(delay) {
      const match = [...timeouts.entries()].find(
        ([, entry]) => entry.delay === delay
      );
      assert.ok(match, `expected an armed timeout with delay ${delay}`);
      const [timer, entry] = match;
      timeouts.delete(timer);
      entry.callback();
    },
    runTimeout(timer) {
      const entry = timeouts.get(timer);
      assert.ok(entry, "expected an armed timeout handle");
      timeouts.delete(timer);
      entry.callback();
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
    timeoutHandleByDelay(delay) {
      return [...timeouts.entries()].find(([, entry]) => entry.delay === delay)?.[0];
    },
  };
}

const registryBySocket = new WeakMap();

async function waitFor(predicate, timeoutMs = 5000) {
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
      registryBySocket.set(socket, { registry, hostId });
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
  registryBySocket.set(socket, { registry: server.registry, hostId });
  return { socket, response: JSON.parse(raw.toString()) };
}
async function connectV3(server, hostId = "host-a", token = "token-a", register = {}) {
  const port = server.registry.wss.address().port;
  const socket = new WebSocket(`ws://127.0.0.1:${port}`);
  await once(socket, "open");
  const frames = [];
  socket.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
  socket.send(JSON.stringify({
    type: "register",
    hostId,
    token,
    protocolVersion: PROTOCOL_VERSION_V3,
    capabilities: [
      ...CAPABILITIES,
      WORKSPACE_READINESS_CAPABILITY,
      WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
    ],
    ...register,
  }));
  await waitFor(() => frames.length > 0);
  const response = frames.shift();
  registryBySocket.set(socket, { registry: server.registry, hostId });
  return {
    socket,
    response,
    async nextFrame() {
      await waitFor(() => frames.length > 0);
      return frames.shift();
    },
    frames,
  };
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
  const registration = registryBySocket.get(socket);
  assert.ok(registration, "socket is associated with a registry");
  await waitFor(
    () =>
      registration.registry.readinessStates.get(registration.hostId)?.revision ===
      frame.revision
  );
}

async function expectPolicyClose(socket, payload) {
  const closed = once(socket, "close");
  socket.send(payload);
  const [code] = await closed;
  assert.equal(code, 1008);
}

test("assistant text extraction preserves delivery whitespace and mixed content", () => {
  assert.equal(
    extractAssistantText({
      message: {
        role: "assistant",
        content: [
          "  lead",
          { text: " middle" },
          { value: " value" },
          { content: " tail  " },
          { unsupported: true },
        ],
      },
    }),
    "  lead middle value tail  "
  );
  assert.equal(
    extractAssistantText({
      assistantMessageEvent: {
        message: { role: "assistant", content: "\n  answer  \n" },
      },
    }),
    "\n  answer  \n"
  );
  assert.equal(
    extractAssistantText({
      message: { role: "user", content: "ignored" },
    }),
    undefined
  );
  assert.equal(
    extractAssistantText({
      message: { role: "assistant", content: [] },
    }),
    undefined
  );
});

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

test("host registration rejects wrong tokens across equal and unequal byte lengths", async () => {
  const server = await startRegistry(new Map([["host-a", "tökén-a"]]));
  try {
    for (const token of ["tökén-b", "token-a", "short", "tökén-a-extra"]) {
      const socket = new WebSocket(
        `ws://127.0.0.1:${server.registry.wss.address().port}`
      );
      await once(socket, "open");
      const denied = once(socket, "message");
      const closed = once(socket, "close");
      socket.send(
        JSON.stringify({
          type: "register",
          hostId: "host-a",
          token,
        })
      );

      const [raw] = await denied;
      assert.deepEqual(JSON.parse(raw.toString()), {
        type: "register_denied",
        reason: "bad token",
      });
      const [code] = await closed;
      assert.equal(code, 1008);
    }
    assert.equal(server.registry.listOnline().length, 0);
    const accepted = await server.connect("host-a", "tökén-a");
    assert.equal(server.registry.isOnline("host-a"), true);
    accepted.terminate();
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

test("truncated invoke events produce a bounded visible result notice", async () => {
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
    const { requestId } = JSON.parse(raw.toString());
    const truncated = {
      type: "event_truncated",
      code: "EVENT_PAYLOAD_TOO_LARGE",
      originalType: "message_update",
    };

    socket.send(JSON.stringify({ type: "event", requestId, event: truncated }));
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));

    assert.deepEqual(await resultPromise, {
      ok: true,
      text: "[output truncated: too large]",
    });
    assert.deepEqual(events, [truncated]);
  } finally {
    await server.close();
  }
});

test("truncation preserves assistant text and appends one notice", async () => {
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
    const { requestId } = JSON.parse(raw.toString());
    const assistant = { message: { role: "assistant", content: "answer" } };
    const truncated = {
      type: "event_truncated",
      code: "EVENT_PAYLOAD_TOO_LARGE",
    };

    socket.send(JSON.stringify({ type: "event", requestId, event: assistant }));
    socket.send(JSON.stringify({ type: "event", requestId, event: truncated }));
    socket.send(JSON.stringify({ type: "event", requestId, event: truncated }));
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));

    assert.deepEqual(await resultPromise, {
      ok: true,
      text: "answer\n[output truncated: too large]",
    });
    assert.deepEqual(events, [assistant, truncated, truncated]);
  } finally {
    await server.close();
  }
});

test("truncation does not override errors or activate for near-match events", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const firstFrame = once(socket, "message");
    const firstResult = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "first" },
      () => {},
      1000
    );
    const firstRequestId = JSON.parse((await firstFrame)[0].toString()).requestId;
    socket.send(
      JSON.stringify({
        type: "event",
        requestId: firstRequestId,
        event: {
          type: "event_truncated",
          code: "EVENT_PAYLOAD_TOO_LARGE",
        },
      })
    );
    socket.send(
      JSON.stringify({
        type: "event",
        requestId: firstRequestId,
        error: "remote failed",
      })
    );
    assert.deepEqual(await firstResult, { ok: false, error: "remote failed" });

    const secondFrame = once(socket, "message");
    const events = [];
    const secondResult = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "second" },
      (event) => events.push(event),
      1000
    );
    const secondRequestId = JSON.parse((await secondFrame)[0].toString()).requestId;
    const nearMatch = {
      type: "event_truncated",
      code: "OTHER_DIAGNOSTIC",
    };
    socket.send(
      JSON.stringify({
        type: "event",
        requestId: secondRequestId,
        event: nearMatch,
      })
    );
    socket.send(
      JSON.stringify({
        type: "event",
        requestId: secondRequestId,
        done: true,
      })
    );

    assert.deepEqual(await secondResult, { ok: true, text: undefined });
    assert.deepEqual(events, [nearMatch]);
  } finally {
    await server.close();
  }
});

test("managed v2 invokes carry the bindingId selected by readiness", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(
      socket,
      readinessFrame({
        bindingId: "binding-1",
        observedAt: Date.now(),
      })
    );
    assert.equal(server.registry.getHostReadiness("host-a").bindingId, "binding-1");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "hello" },
      () => {},
      1000,
      undefined,
      {
        mappingId: "mapping-1",
        mappingGeneration: 1,
        mappingVersion: 1,
        workspaceId: "workspace-1",
        workspaceGeneration: 1,
      }
    );
    const [raw] = await invokeFrame;
    const invoke = JSON.parse(raw.toString());
    assert.equal(invoke.bindingId, "binding-1");
    assert.equal(invoke.workspaceId, "workspace-1");
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined });
  } finally {
    await server.close();
  }
});

test("managed v2 invokes select the matching binding from multiple readiness frames", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-b",
      revision: 2,
      workspaceId: "workspace-b",
      workspaceGeneration: 2,
      observedAt: Date.now(),
    }));
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "hello" },
      () => {},
      1000,
      undefined,
      {
        mappingId: "mapping-a",
        mappingGeneration: 1,
        mappingVersion: 1,
        workspaceId: "workspace-a",
        workspaceGeneration: 1,
      }
    );
    const [raw] = await invokeFrame;
    const invoke = JSON.parse(raw.toString());
    assert.equal(invoke.bindingId, "binding-a");
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined });
  } finally {
    await server.close();
  }
});

test("managed v2 readiness gates and projects each binding independently", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-b",
      revision: 2,
      workspaceId: "workspace-b",
      workspaceGeneration: 2,
      observedAt: Date.now(),
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "missing",
        modelProfile: "ready",
        workspace: "ready",
      },
    }));

    const projection = server.registry.getHostReadiness("host-a");
    assert.deepEqual(
      projection.bindings.map(({ bindingId, workspaceId, aggregate }) => ({
        bindingId,
        workspaceId,
        aggregate,
      })),
      [
        { bindingId: "binding-a", workspaceId: "workspace-a", aggregate: "ready" },
        {
          bindingId: "binding-b",
          workspaceId: "workspace-b",
          aggregate: "connected-not-ready",
        },
      ]
    );

    const invokeFrame = once(socket, "message");
    const readyResult = server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "hello" },
      () => {},
      1000,
      undefined,
      {
        mappingId: "mapping-a",
        mappingGeneration: 1,
        mappingVersion: 1,
        workspaceId: "workspace-a",
        workspaceGeneration: 1,
      }
    );
    const [raw] = await invokeFrame;
    const invoke = JSON.parse(raw.toString());
    assert.equal(invoke.bindingId, "binding-a");
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, done: true }));
    assert.deepEqual(await readyResult, { ok: true, text: undefined });

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "blocked" },
        () => {},
        1000,
        undefined,
        {
          mappingId: "mapping-b",
          mappingGeneration: 1,
          mappingVersion: 1,
          workspaceId: "workspace-b",
          workspaceGeneration: 2,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
          retryable: true,
          action: "login",
        },
      }
    );
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});

test("managed v2 invoke rejects a route without a live matching binding", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "blocked" },
        () => {},
        1000,
        undefined,
        {
          mappingId: "mapping-b",
          mappingGeneration: 1,
          mappingVersion: 1,
          workspaceId: "workspace-b",
          workspaceGeneration: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
          retryable: false,
          action: "refresh_workspace",
        },
      }
    );
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});

test("managed v2 invoke without any binding preserves the closed serving boundary", async () => {
  const server = await startRegistry();
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      workspaceId: undefined,
      workspaceGeneration: undefined,
      observedAt: Date.now(),
    }));

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "blocked" },
        () => {},
        1000,
        undefined,
        {
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
          workspaceId: "workspace-a",
          workspaceGeneration: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
          retryable: false,
          action: "contact_admin",
        },
      }
    );
  } finally {
    await server.close();
  }
});

test("managed v2 invoke without any binding fails closed when serving is enabled", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      workspaceId: undefined,
      workspaceGeneration: undefined,
      observedAt: Date.now(),
    }));

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "blocked" },
        () => {},
        1000,
        undefined,
        {
          bindingId: "binding-missing",
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
          retryable: false,
          action: "refresh_workspace",
        },
      }
    );
  } finally {
    await server.close();
  }
});

test("binding-scoped readiness expires from receiver monotonic time", async () => {
  let wall = 1_700_000_000_000;
  let monotonic = 100;
  const server = await startRegistry(undefined, {
    workspaceServingEnabled: true,
    now: () => wall,
    monotonicNow: () => monotonic,
    timers: createManualTimers().api,
  });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: wall,
      ttlMs: 1_000,
    }));
    monotonic = 1_101;

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "expired" },
        () => {},
        1000,
        undefined,
        {
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
          workspaceId: "workspace-a",
          workspaceGeneration: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.READINESS_EXPIRED,
          retryable: true,
          action: "retry_later",
        },
      }
    );
    assert.equal(wall, 1_700_000_000_000);
  } finally {
    await server.close();
  }
});

test("a never-ready binding stays connected-not-ready after monotonic expiry", async () => {
  let wall = 1_700_000_000_000;
  let monotonic = 100;
  const server = await startRegistry(undefined, {
    workspaceServingEnabled: true,
    now: () => wall,
    monotonicNow: () => monotonic,
    timers: createManualTimers().api,
  });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: wall,
      ttlMs: 1_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "missing",
        modelProfile: "ready",
        workspace: "ready",
      },
    }));
    monotonic = 1_101;

    const projection = server.registry.getHostReadiness("host-a");
    assert.equal(projection.bindings[0].aggregate, "connected-not-ready");
    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "blocked" },
        () => {},
        1000,
        undefined,
        {
          bindingId: "binding-a",
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
          retryable: true,
          action: "login",
        },
      }
    );
  } finally {
    await server.close();
  }
});

test("same-workspace binding replacement retires the superseded binding", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-old",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-new",
      revision: 2,
      workspaceId: "workspace-a",
      workspaceGeneration: 2,
      observedAt: Date.now(),
    }));

    assert.deepEqual(
      server.registry.getHostReadiness("host-a").bindings.map(
        ({ bindingId, workspaceGeneration }) => ({ bindingId, workspaceGeneration })
      ),
      [{ bindingId: "binding-new", workspaceGeneration: 2 }]
    );
    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "stale" },
        () => {},
        1000,
        undefined,
        {
          bindingId: "binding-old",
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
          retryable: false,
          action: "refresh_workspace",
        },
      }
    );
  } finally {
    await server.close();
  }
});

test("interleaved readiness cannot regress a retained workspace generation", async () => {
  const server = await startRegistry();
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a-new",
      workspaceId: "workspace-a",
      workspaceGeneration: 2,
      observedAt: Date.now(),
    }));
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-b",
      revision: 2,
      workspaceId: "workspace-b",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));

    const closed = once(socket, "close");
    socket.send(JSON.stringify(readinessFrame({
      bindingId: "binding-a-stale",
      revision: 3,
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    })));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await server.close();
  }
});

test("bindingless readiness advances the retained workspace generation fence", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 2,
      observedAt: Date.now(),
    }));
    await sendReadiness(socket, readinessFrame({
      bindingId: undefined,
      revision: 2,
      workspaceId: "workspace-a",
      workspaceGeneration: 3,
      observedAt: Date.now(),
    }));
    assert.deepEqual(server.registry.getHostReadiness("host-a").bindings, undefined);
    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "stale" },
        () => {},
        1000,
        undefined,
        {
          bindingId: "binding-a",
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
          retryable: false,
          action: "refresh_workspace",
        },
      }
    );
    assert.equal(server.registry.pendingRequests.size, 0);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-b",
      revision: 3,
      workspaceId: "workspace-b",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));

    const closed = once(socket, "close");
    socket.send(JSON.stringify(readinessFrame({
      bindingId: "binding-a-stale",
      revision: 4,
      workspaceId: "workspace-a",
      workspaceGeneration: 2,
      observedAt: Date.now(),
    })));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await server.close();
  }
});

test("managed v2 invoke matches an explicit bindingId without workspace selectors", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));

    const invokeFrame = once(socket, "message");
    const result = server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "hello" },
      () => {},
      1000,
      undefined,
      {
        bindingId: "binding-a",
        mappingId: "mapping-a",
        mappingGeneration: 1,
        mappingVersion: 1,
      }
    );
    const [raw] = await invokeFrame;
    const invoke = JSON.parse(raw.toString());
    assert.equal(invoke.bindingId, "binding-a");
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, done: true }));
    assert.deepEqual(await result, { ok: true, text: undefined });

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "blocked" },
        () => {},
        1000,
        undefined,
        {
          bindingId: "binding-stale",
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
          retryable: false,
          action: "refresh_workspace",
        },
      }
    );
  } finally {
    await server.close();
  }
});

test("managed v2 invoke rejects an ambiguous generation-only binding selector", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-b",
      revision: 2,
      workspaceId: "workspace-b",
      workspaceGeneration: 1,
      observedAt: Date.now(),
    }));

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "ambiguous" },
        () => {},
        1000,
        undefined,
        {
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
          workspaceGeneration: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
          retryable: false,
          action: "refresh_workspace",
        },
      }
    );
    assert.equal(server.registry.pendingRequests.size, 0);
  } finally {
    await server.close();
  }
});

test("binding-scoped remote errors preserve their remediation", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      bindingId: "binding-a",
      observedAt: Date.now(),
      lastError: {
        code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
        at: Date.now(),
        remediation: {
          code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
          retryable: true,
          action: "login",
        },
      },
    }));

    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "blocked" },
        () => {},
        1000,
        undefined,
        {
          mappingId: "mapping-a",
          mappingGeneration: 1,
          mappingVersion: 1,
          workspaceId: "workspace-1",
          workspaceGeneration: 1,
        }
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
          retryable: true,
          action: "login",
        },
      }
    );
  } finally {
    await server.close();
  }
});

test("binding readiness retention is bounded per socket", async () => {
  const server = await startRegistry();
  try {
    const { socket } = await connectV2(server);
    const observedAt = Date.now();
    for (let index = 0; index < MAX_BINDING_READINESS_STATES; index += 1) {
      await sendReadiness(socket, readinessFrame({
        bindingId: `binding-${index}`,
        revision: index + 1,
        workspaceId: `workspace-${index}`,
        observedAt,
      }));
    }

    const closed = once(socket, "close");
    socket.send(JSON.stringify(readinessFrame({
      bindingId: "binding-overflow",
      revision: MAX_BINDING_READINESS_STATES + 1,
      workspaceId: "workspace-overflow",
      observedAt,
    })));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await server.close();
  }
});
test("invoke idle timer resets on each streamed event", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 60,
    invokeHardCapMs: 5000,
    timers: timers.api,
  });
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
    let settled = false;
    resultPromise.then(() => {
      settled = true;
    });
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());
    const hardCapTimer = timers.timeoutHandleByDelay(5000);
    let idleTimer = timers.timeoutHandleByDelay(60);
    assert.ok(hardCapTimer);
    assert.ok(idleTimer);

    const event = { message: { role: "assistant", content: "still working" } };
    for (let i = 0; i < 4; i += 1) {
      socket.send(JSON.stringify({ type: "event", requestId, event }));
      await waitFor(() => events.length === i + 1);
      assert.equal(settled, false);
      assert.deepEqual(timers.timeoutDelays.sort((a, b) => a - b), [60, 5000]);
      assert.strictEqual(timers.timeoutHandleByDelay(5000), hardCapTimer);
      const replacementIdleTimer = timers.timeoutHandleByDelay(60);
      assert.ok(replacementIdleTimer);
      assert.notStrictEqual(replacementIdleTimer, idleTimer);
      timers.runClearedTimeouts();
      assert.equal(settled, false);
      assert.equal(server.registry.pendingRequests.has(requestId), true);
      idleTimer = replacementIdleTimer;
    }
    assert.equal(settled, false);

    socket.send(JSON.stringify({ type: "event", requestId, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: "still working" });
  } finally {
    await server.close();
  }
});

test("invoke idle expiry fires with zero events", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 20,
    invokeHardCapMs: 5000,
    timers: timers.api,
  });
  try {
    await server.connect("host-a", "token-a");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hi" },
      () => {}
    );
    assert.deepEqual(timers.timeoutDelays.sort((a, b) => a - b), [20, 5000]);
    timers.runTimeoutByDelay(20);
    const result = await resultPromise;
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
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 1000,
    invokeHardCapMs: 40,
    timers: timers.api,
  });
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
    const hardCapTimer = timers.timeoutHandleByDelay(40);
    assert.ok(hardCapTimer);

    const event = { message: { role: "assistant", content: "still working" } };
    for (let index = 0; index < 3; index += 1) {
      socket.send(JSON.stringify({ type: "event", requestId, event }));
      await waitFor(() => events.length === index + 1);
      assert.deepEqual(timers.timeoutDelays.sort((a, b) => a - b), [40, 1000]);
      assert.strictEqual(timers.timeoutHandleByDelay(40), hardCapTimer);
    }
    timers.runTimeout(hardCapTimer);

    assert.deepEqual(await resultPromise, {
      ok: false,
      error: "invoke exceeded absolute hard-cap",
    });
  } finally {
    await server.close();
  }
});

test("invoke timers are cleared on normal resolve", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 30,
    invokeHardCapMs: 200,
    timers: timers.api,
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
    assert.deepEqual(timers.timeoutDelays.sort((a, b) => a - b), [30, 200]);
    socket.send(JSON.stringify({ type: "event", requestId, done: true }));

    const result = await resultPromise;
    assert.deepEqual(result, { ok: true, text: undefined });
    assert.equal(server.registry.pendingRequests.size, 0);
    assert.equal(timers.timeoutCount, 0);
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
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 50,
    invokeHardCapMs: 5000,
    timers: timers.api,
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
      assert.equal(timers.timeoutCount, 0);
    }
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
    const barrierFrame = once(socket, "message");
    const barrierResult = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "barrier" },
      () => {}
    );
    const [barrierRaw] = await barrierFrame;
    const barrierRequestId = JSON.parse(barrierRaw.toString()).requestId;
    socket.send(JSON.stringify({ type: "event", requestId: barrierRequestId, done: true }));
    assert.deepEqual(await barrierResult, { ok: true, text: undefined });
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

test("managed path-free routes fail with structured remediation on a legacy host", async () => {
  for (const register of [
    { protocolVersion: undefined, capabilities: undefined },
    {},
  ]) {
    const server = await startRegistry();
    try {
      const socket = await server.connect("host-a", "token-a", register);
      const pendingBefore = server.registry.pendingRequests.size;
      const perSocketBefore =
        server.registry.pendingCountBySocket.get(socket) ?? 0;
      const managedIdentity = {
        mappingId: "mapping-a",
        mappingGeneration: 1,
        mappingVersion: 1,
        workspaceId: "workspace-a",
        workspaceGeneration: 1,
      };

      const managed = await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "hello" },
        () => {},
        undefined,
        undefined,
        managedIdentity
      );
      const unrelatedInvalid = await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "hello" },
        () => {}
      );
      const malformedManaged = await server.registry.invoke(
        "host-a",
        null,
        { kind: "prompt", message: "hello" },
        () => {},
        undefined,
        undefined,
        { ...managedIdentity, mappingId: null }
      );

      assert.deepEqual(managed, {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
          retryable: false,
          action: "contact_admin",
        },
      });
      assert.deepEqual(unrelatedInvalid, {
        ok: false,
        error: "invalid invoke request",
      });
      assert.deepEqual(malformedManaged, {
        ok: false,
        error: "invalid invoke request",
      });
      assert.equal(server.registry.pendingRequests.size, pendingBefore);
      assert.equal(
        server.registry.pendingCountBySocket.get(socket) ?? 0,
        perSocketBefore
      );

      const barrierFrame = once(socket, "message");
      const barrierResult = server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: "barrier" },
        () => {}
      );
      const [barrierRaw] = await barrierFrame;
      const barrier = JSON.parse(barrierRaw.toString());
      assert.equal(barrier.workDir, "/workspace");
      socket.send(
        JSON.stringify({
          type: "event",
          requestId: barrier.requestId,
          done: true,
        })
      );
      assert.deepEqual(await barrierResult, { ok: true, text: undefined });
      assert.equal(socket.readyState, WebSocket.OPEN);
      assert.equal(server.registry.pendingRequests.size, pendingBefore);
      assert.equal(
        server.registry.pendingCountBySocket.get(socket) ?? 0,
        perSocketBefore
      );
    } finally {
      await server.close();
    }
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
    assert.deepEqual(
      timers.timeoutDelays.sort((a, b) => a - b),
      [1_000, 10_000, 30 * 60 * 1_000]
    );
    timers.runTimeoutByDelay(10_000);
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
    assert.equal(timers.timeoutCount, 3);

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
  assert.equal(timers.timeoutCount, 3);

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
    const incompatibleManaged = await server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "hello" },
      () => {},
      10_000,
      undefined,
      {
        mappingId: "mapping-a",
        mappingGeneration: 1,
        mappingVersion: 1,
        workspaceId: "workspace-a",
        workspaceGeneration: 1,
      }
    );
    assert.deepEqual(incompatibleManaged, {
      ok: false,
      error: {
        code: PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
        retryable: false,
        action: "contact_admin",
      },
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
  assert.equal(isProtocolVersion(PROTOCOL_VERSION_V3), true);
  for (const bad of [-1, PROTOCOL_VERSION_V3 + 1, 1.5, "1", Number.NaN, V0_LIMITS.PROTOCOL_VERSION_MAX]) {
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
test("managed authority descriptors are revalidated, copied, and frozen", () => {
  const authority = {
    authorityEpoch: 3,
    fenceGeneration: 2,
    hostId: "host-a",
    mappingId: "mapping-1",
    mappingGeneration: 4,
    workspaceGeneration: 7,
    mappingVersion: 1,
    sourcePlatform: "posix",
    workspaceId: "workspace-1",
    authorityFingerprint: "a".repeat(64),
  };
  const routeIdentity = {
    mappingId: authority.mappingId,
    mappingGeneration: authority.mappingGeneration,
    mappingVersion: authority.mappingVersion,
    sourcePlatform: authority.sourcePlatform,
    workspaceId: authority.workspaceId,
    workspaceGeneration: authority.workspaceGeneration,
    authority,
  };
  const frozen = freezeManagedAuthorityDescriptor("host-a", routeIdentity);
  assert.deepEqual(frozen, authority);
  assert.notEqual(frozen, authority);
  assert.equal(Object.isFrozen(frozen), true);

  for (const invalid of [
    { ...routeIdentity, mappingGeneration: 5 },
    { ...routeIdentity, sourcePlatform: "windows-drive" },
    { ...routeIdentity, authority: { ...authority, routeFingerprint: "b".repeat(64) } },
  ]) {
    assert.throws(
      () => freezeManagedAuthorityDescriptor("host-a", invalid),
      { name: "TypeError" },
    );
  }
  assert.throws(
    () => freezeManagedAuthorityDescriptor("foreign-host", routeIdentity),
    { name: "TypeError", message: "MANAGED_AUTHORITY_INVALID" },
  );
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
    assert.deepEqual(server.registry.getHostReadiness("host-a"), {
      hostId: "host-a",
      aggregate: "online",
      lastErrorAt: null,
      revision: 0,
      socketGeneration: null,
      reconnectCount: 0,
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
    assert.deepEqual(server.registry.getHostReadiness("host-a"), {
      hostId: "host-a",
      aggregate: "online",
      lastErrorAt: null,
      revision: 0,
      socketGeneration: null,
      reconnectCount: 0,
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
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 40,
    invokeHardCapMs: 5000,
    timers: timers.api,
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
    const idleTimer = timers.timeoutHandleByDelay(40);
    const hardCapTimer = timers.timeoutHandleByDelay(5000);
    assert.ok(idleTimer);
    assert.ok(hardCapTimer);

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

    assert.deepEqual(timers.timeoutDelays, [5000]);
    timers.runClearedTimeouts();
    assert.equal(settled, false);
    assert.equal(server.registry.pendingRequests.has(requestId), true);
    assert.strictEqual(timers.timeoutHandleByDelay(5000), hardCapTimer);

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
    assert.deepEqual(
      timers.timeoutDelays.sort((a, b) => a - b),
      [40, 5000]
    );

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
      reconnectCount: 0,
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
    await sendReadiness(
      first.socket,
      readinessFrame({
        socketGeneration: 7,
        observedAt: Date.now(),
        workspaceId: "workspace-1",
        workspaceGeneration: 5,
      })
    );
    first.socket.terminate();
    await waitFor(() => server.registry.getHostReadiness("host-a") === undefined);

    const replacement = await connectV2(server);
    const closed = once(replacement.socket, "close");
    replacement.socket.send(
      JSON.stringify(
        readinessFrame({
          socketGeneration: 8,
          revision: 1,
          observedAt: Date.now(),
          workspaceId: "workspace-1",
          workspaceGeneration: 4,
        })
      )
    );
    await closed;
    assert.equal(
      server.registry.readinessStates.get("host-a")?.lastError?.code,
      PROTOCOL_ERROR_CODES.READINESS_REPLAYED
    );
    const reused = await connectV2(server);
    const reusedClosed = once(reused.socket, "close");
    reused.socket.send(
      JSON.stringify(
        readinessFrame({
          socketGeneration: 7,
          revision: 1,
          observedAt: Date.now(),
          workspaceId: "workspace-1",
          workspaceGeneration: 5,
        })
      )
    );
    await reusedClosed;
    assert.equal(
      server.registry.readinessStates.get("host-a")?.lastError?.code,
      PROTOCOL_ERROR_CODES.READINESS_REPLAYED
    );

    const current = await connectV2(server);
    await sendReadiness(
      current.socket,
      readinessFrame({
        socketGeneration: 9,
        revision: 1,
        observedAt: Date.now(),
        workspaceId: "workspace-1",
        workspaceGeneration: 5,
      })
    );
    assert.equal(server.registry.getHostReadiness("host-a").socketGeneration, 9);
    current.socket.terminate();
  } finally {
    await server.close();
  }
});

test("offline readiness authority expires after the maximum TTL horizon", async () => {
  const timers = createManualTimers();
  let monotonicNow = 0;
  const server = await startRegistry(undefined, {
    timers: timers.api,
    monotonicNow: () => monotonicNow,
  });
  const sockets = [];
  try {
    const first = await connectV2(server, "host-a", "token-a");
    sockets.push(first.socket);
    await sendReadiness(
      first.socket,
      readinessFrame({
        socketGeneration: 7,
        workspaceGeneration: 5,
      })
    );
    assert.equal(
      server.registry.readinessAuthorities.get("host-a")?.socketGeneration,
      7
    );

    first.socket.terminate();
    await waitFor(
      () =>
        !server.registry.isOnline("host-a") &&
        timers.timeoutDelays.includes(READINESS_MAX_TTL_MS)
    );

    monotonicNow = 1_000;
    const rejected = await connectV2(server, "host-a", "token-a");
    sockets.push(rejected.socket);
    await expectPolicyClose(
      rejected.socket,
      JSON.stringify(
        readinessFrame({
          socketGeneration: 6,
          workspaceGeneration: 5,
        })
      )
    );
    await waitFor(() =>
      timers.timeoutDelays.includes(READINESS_MAX_TTL_MS - monotonicNow)
    );
    assert.equal(
      server.registry.readinessAuthorities.get("host-a")?.socketGeneration,
      7
    );

    const remainingHorizon = READINESS_MAX_TTL_MS - monotonicNow;
    timers.runTimeoutByDelay(remainingHorizon);
    assert.equal(
      server.registry.readinessAuthorities.get("host-a")?.socketGeneration,
      7
    );
    assert.equal(timers.timeoutDelays.includes(remainingHorizon), true);

    const waiting = await connectV2(server, "host-a", "token-a");
    sockets.push(waiting.socket);
    monotonicNow = READINESS_MAX_TTL_MS;
    timers.runTimeoutByDelay(remainingHorizon);
    assert.equal(server.registry.readinessAuthorities.has("host-a"), false);

    await sendReadiness(
      waiting.socket,
      readinessFrame({
        socketGeneration: 1,
        workspaceGeneration: 1,
      })
    );
    assert.equal(
      server.registry.readinessAuthorities.get("host-a")?.socketGeneration,
      1
    );

    monotonicNow = READINESS_MAX_TTL_MS + 1_000;
    waiting.socket.terminate();
    await waitFor(() =>
      timers.timeoutDelays.includes(READINESS_MAX_TTL_MS)
    );
    const successor = await connectV2(server, "host-a", "token-a");
    sockets.push(successor.socket);
    await sendReadiness(
      successor.socket,
      readinessFrame({
        socketGeneration: 2,
        workspaceGeneration: 2,
      })
    );
    timers.runClearedTimeouts();
    assert.equal(
      server.registry.readinessAuthorities.get("host-a")?.socketGeneration,
      2
    );

    monotonicNow += 1_000;
    successor.socket.terminate();
    await waitFor(() =>
      timers.timeoutDelays.includes(READINESS_MAX_TTL_MS)
    );
    const delayed = await connectV2(server, "host-a", "token-a");
    sockets.push(delayed.socket);
    monotonicNow += READINESS_MAX_TTL_MS;
    await sendReadiness(
      delayed.socket,
      readinessFrame({
        socketGeneration: 1,
        workspaceGeneration: 1,
      })
    );
    assert.equal(
      server.registry.readinessAuthorities.get("host-a")?.socketGeneration,
      1
    );

    monotonicNow += 1_000;
    delayed.socket.terminate();
    await waitFor(() =>
      timers.timeoutDelays.includes(READINESS_MAX_TTL_MS)
    );
    const legacy = await server.connect("host-a", "token-a", {
      protocolVersion: undefined,
      capabilities: undefined,
    });
    sockets.push(legacy);
    monotonicNow += READINESS_MAX_TTL_MS;
    timers.runTimeoutByDelay(READINESS_MAX_TTL_MS);
    assert.equal(server.registry.readinessAuthorities.has("host-a"), false);
  } finally {
    for (const socket of sockets) socket.terminate();
    await server.close();
    assert.equal(timers.timeoutCount, 0);
  }
});

test("replacement socket preserves generation fences for every workspace", async () => {
  const server = await startRegistry();
  try {
    const first = await connectV2(server);
    await sendReadiness(first.socket, readinessFrame({
      socketGeneration: 7,
      revision: 1,
      observedAt: Date.now(),
      bindingId: "binding-a",
      workspaceId: "workspace-a",
      workspaceGeneration: 5,
    }));
    await sendReadiness(first.socket, readinessFrame({
      socketGeneration: 7,
      revision: 2,
      observedAt: Date.now(),
      bindingId: "binding-b",
      workspaceId: "workspace-b",
      workspaceGeneration: 2,
    }));
    first.socket.terminate();
    await waitFor(() => server.registry.getHostReadiness("host-a") === undefined);

    const stale = await connectV2(server);
    await sendReadiness(stale.socket, readinessFrame({
      socketGeneration: 8,
      revision: 1,
      observedAt: Date.now(),
      bindingId: "binding-b-current",
      workspaceId: "workspace-b",
      workspaceGeneration: 2,
    }));
    const staleClosed = once(stale.socket, "close");
    stale.socket.send(JSON.stringify(readinessFrame({
      socketGeneration: 8,
      revision: 2,
      observedAt: Date.now(),
      bindingId: "binding-a-replayed",
      workspaceId: "workspace-a",
      workspaceGeneration: 4,
    })));
    const [code] = await staleClosed;
    assert.equal(code, 1008);
    assert.equal(
      server.registry.readinessStates.get("host-a")?.lastError?.code,
      PROTOCOL_ERROR_CODES.READINESS_REPLAYED
    );

    const current = await connectV2(server);
    await sendReadiness(current.socket, readinessFrame({
      socketGeneration: 9,
      revision: 1,
      observedAt: Date.now(),
      bindingId: "binding-a-current",
      workspaceId: "workspace-a",
      workspaceGeneration: 5,
    }));
    assert.equal(
      server.registry.getHostReadiness("host-a").bindings[0].bindingId,
      "binding-a-current"
    );
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
        { code: "RUNTIME_INCOMPATIBLE", retryable: false, action: "contact_admin" },
        { code: "RUNTIME_INCOMPATIBLE", retryable: false, action: "contact_admin" },
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
        bindingId: "binding-1",
        observedAt: Date.now(),
        expiresAt: Date.now() + 250,
        lastError: {
          code: "PROVIDER_MISSING",
          at: Date.now(),
          remediation: { code: "PROVIDER_MISSING", retryable: true, action: "login" },
        },
      })
    );
    const projection = server.registry.getHostReadiness(hostId);
    assert.equal(projection.hostId, "[redacted-host]");
    assert.equal(projection.bindingId, "binding-1");
    assert.equal(projection.revision, 1);
    assert.equal(projection.socketGeneration, 1);
    assert.equal(projection.lastErrorAt > 0, true);
    assert.equal(projection.receivedAt > 0, true);
    assert.equal(projection.expiresAt, projection.receivedAt + 1_000);
    assert.equal(JSON.stringify(projection).includes(token), false);
    assert.equal(JSON.stringify(projection).includes("/var/lib"), false);
    assert.equal(/[\u0000-\u001f]/.test(JSON.stringify(projection)), false);
    socket.terminate();
  } finally {
    await server.close();
  }
});

test("managed routes retain offline desired state without exposing descriptors", async () => {
  const server = await startRegistry();
  try {
    const shared = managedRoute("shared");
    server.registry.setManagedRoutes({
      "channel-a": shared,
      "channel-b": managedRoute("shared", { routeFingerprint: "c".repeat(64) }),
    });
    const binding = server.registry.getManagedRouteBinding("channel-a");
    assert.deepEqual(binding, { compatible: false });
    assert.equal(Object.isFrozen(binding), true);
    assert.equal(JSON.stringify(binding).includes("workspace"), false);
    assert.equal(server.registry.getManagedRouteBinding("missing"), undefined);
    const result = await server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "offline" },
      () => {},
      1_000,
      undefined,
      {
        mappingId: shared.mappingId,
        mappingGeneration: shared.mappingGeneration,
        mappingVersion: shared.mappingVersion,
        sourcePlatform: shared.sourcePlatform,
        workspaceId: shared.workspaceId,
        workspaceGeneration: shared.workspaceGeneration,
        authority: shared.authority,
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "PROTOCOL_INCOMPATIBLE");
  } finally {
    await server.close();
  }
});

test("v3 deduplicates shared descriptors and accepts only the exact receipt", async () => {
  const server = await startRegistry();
  try {
    const shared = managedRoute("shared");
    server.registry.setManagedRoutes({
      "channel-a": shared,
      "channel-b": managedRoute("shared", { routeFingerprint: "c".repeat(64) }),
    });
    const connection = await connectV3(server);
    assert.equal(connection.response.protocolVersion, PROTOCOL_VERSION_V3);
    const bind = await connection.nextFrame();
    assert.deepEqual(Object.keys(bind).sort(), [
      "authorityEpoch", "authorityFingerprint", "bindingId", "fenceGeneration",
      "hostId", "mappingGeneration", "mappingId", "mappingVersion",
      "sourcePlatform", "type", "workspaceGeneration", "workspaceId",
    ].sort());
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(connection.frames.length, 0, "shared routes emit one bind");
    assert.deepEqual(server.registry.getManagedRouteBinding("channel-a"), {
      compatible: false,
    });

    const inventoryGeneration = 1;
    const inventoryFingerprint = "d".repeat(64);
    const bindingFingerprint = workspaceBindingFingerprint({
      authority: shared.authority,
      inventoryGeneration,
      inventoryFingerprint,
    });
    const ack = {
      type: "bind_ok",
      bindingId: bind.bindingId,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint,
    };
    connection.socket.send(JSON.stringify(ack));
    await waitFor(() =>
      server.registry.getManagedRouteBinding("channel-a")?.state === "bound"
    );
    const managedBinding = server.registry.getManagedRouteBinding("channel-a");
    const result = await server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "still disabled" },
      () => {},
      1_000,
      undefined,
      {
        bindingId: managedBinding.bindingId,
        mappingId: shared.mappingId,
        mappingGeneration: shared.mappingGeneration,
        mappingVersion: shared.mappingVersion,
        sourcePlatform: shared.sourcePlatform,
        workspaceId: shared.workspaceId,
        workspaceGeneration: shared.workspaceGeneration,
        authority: shared.authority,
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "RUNTIME_INCOMPATIBLE");
    assert.equal(
      server.registry.getManagedRouteBinding("channel-a").bindingId,
      server.registry.getManagedRouteBinding("channel-b").bindingId,
    );
    connection.socket.send(JSON.stringify(ack));
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(connection.socket.readyState, WebSocket.OPEN);

    const closed = once(connection.socket, "close");
    connection.socket.send(JSON.stringify({ ...ack, inventoryGeneration: 2 }));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await server.close();
  }
});

test("old v2 receipt-off sockets stay incompatible without bind timers", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, { timers: timers.api });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const { socket, response } = await connectV2(server);
    assert.equal(response.protocolVersion, 2);
    assert.deepEqual(server.registry.getManagedRouteBinding("channel-a"), {
      compatible: false,
    });
    assert.equal(timers.timeoutCount, 0);
    const result = await server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "blocked" },
      () => {},
      1_000,
      undefined,
      {
        mappingId: route.mappingId,
        mappingGeneration: route.mappingGeneration,
        mappingVersion: route.mappingVersion,
        sourcePlatform: route.sourcePlatform,
        workspaceId: route.workspaceId,
        workspaceGeneration: route.workspaceGeneration,
        authority: route.authority,
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "PROTOCOL_INCOMPATIBLE");
    socket.terminate();
  } finally {
    await server.close();
  }
});

test("positive readiness is held until the exact bind acknowledgement", async () => {
  const server = await startRegistry();
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    const inventoryGeneration = 1;
    const inventoryFingerprint = "d".repeat(64);
    const bindingFingerprint = workspaceBindingFingerprint({
      authority: route.authority,
      inventoryGeneration,
      inventoryFingerprint,
    });
    connection.socket.send(JSON.stringify(readinessFrame({
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "INVENTORY_PENDING",
        at: Date.now(),
        remediation: {
          code: "INVENTORY_PENDING",
          retryable: true,
          action: "retry_later",
        },
      },
    })));
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(connection.socket.readyState, WebSocket.OPEN);
    connection.socket.send(JSON.stringify(readinessFrame({
      revision: 2,
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint,
    })));
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(connection.socket.readyState, WebSocket.OPEN);
    assert.deepEqual(server.registry.getManagedRouteBinding("channel-a"), {
      compatible: false,
    });
    connection.socket.send(JSON.stringify({
      type: "bind_ok",
      bindingId: bind.bindingId,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint,
    }));
    await waitFor(() =>
      server.registry.getManagedRouteBinding("channel-a")?.state === "bound"
    );
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});

test("v3 host and binding readiness share one revision fence", async () => {
  const server = await startRegistry();
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    connection.socket.send(JSON.stringify(readinessFrame({
      revision: 2,
      workspaceId: undefined,
      workspaceGeneration: undefined,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
    })));
    await waitFor(() =>
      server.registry.getHostReadiness("host-a")?.revision === 2
    );
    const closed = once(connection.socket, "close");
    connection.socket.send(JSON.stringify(readinessFrame({
      revision: 1,
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "INVENTORY_PENDING",
        at: Date.now(),
        remediation: {
          code: "INVENTORY_PENDING",
          retryable: true,
          action: "retry_later",
        },
      },
    })));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await server.close();
  }
});

test("negative readiness ends the bind deadline and remains totally unbindable", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, { timers: timers.api });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    connection.socket.send(JSON.stringify(readinessFrame({
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "WORKSPACE_NOT_FOUND",
        at: Date.now(),
        remediation: {
          code: "WORKSPACE_NOT_FOUND",
          retryable: false,
          action: "refresh_workspace",
        },
      },
    })));
    await waitFor(() => timers.timeoutCount === 0);
    assert.deepEqual(server.registry.getManagedRouteBinding("channel-a"), {
      compatible: false,
    });
    server.registry.setManagedRoutes({});
    assert.deepEqual(await connection.nextFrame(), {
      type: "unbind_workspace",
      bindingId: bind.bindingId,
    });
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});

test("binding removal tombstones before unbind and late frames cannot repopulate it", async () => {
  const server = await startRegistry();
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    const inventoryGeneration = 1;
    const inventoryFingerprint = "d".repeat(64);
    const bindOk = {
      type: "bind_ok",
      bindingId: bind.bindingId,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint: workspaceBindingFingerprint({
        authority: route.authority,
        inventoryGeneration,
        inventoryFingerprint,
      }),
    };
    connection.socket.send(JSON.stringify(bindOk));
    await waitFor(() =>
      server.registry.getManagedRouteBinding("channel-a")?.state === "bound"
    );

    server.registry.setManagedRoutes({});
    assert.equal(server.registry.getManagedRouteBinding("channel-a"), undefined);
    const unbind = await connection.nextFrame();
    assert.deepEqual(unbind, {
      type: "unbind_workspace",
      bindingId: bind.bindingId,
    });
    connection.socket.send(JSON.stringify(bindOk));
    connection.socket.send(JSON.stringify(readinessFrame({
      bindingId: bind.bindingId,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "INVENTORY_PENDING",
        at: Date.now(),
        remediation: {
          code: "INVENTORY_PENDING",
          retryable: true,
          action: "retry_later",
        },
      },
    })));
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(connection.socket.readyState, WebSocket.OPEN);

    connection.socket.send(JSON.stringify({
      type: "unbind_ok",
      bindingId: bind.bindingId,
    }));
    await new Promise((resolve) => setTimeout(resolve, 10));
    const closed = once(connection.socket, "close");
    connection.socket.send(JSON.stringify(readinessFrame({
      bindingId: bind.bindingId,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "INVENTORY_PENDING",
        at: Date.now(),
        remediation: {
          code: "INVENTORY_PENDING",
          retryable: true,
          action: "retry_later",
        },
      },
    })));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await server.close();
  }
});

test("descriptor replacement unbinds a pending id before binding its successor", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, { timers: timers.api });
  try {
    server.registry.setManagedRoutes({ "channel-a": managedRoute("old") });
    const connection = await connectV3(server);
    const oldBind = await connection.nextFrame();
    server.registry.setManagedRoutes({ "channel-a": managedRoute("new") });
    const unbind = await connection.nextFrame();
    assert.deepEqual(unbind, {
      type: "unbind_workspace",
      bindingId: oldBind.bindingId,
    });
    timers.runClearedTimeouts();
    assert.equal(connection.socket.readyState, WebSocket.OPEN);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(connection.frames.length, 0, "successor waits for unbind_ok");
    connection.socket.send(JSON.stringify({
      type: "unbind_ok",
      bindingId: oldBind.bindingId,
    }));
    const newBind = await connection.nextFrame();
    assert.equal(newBind.type, "bind_workspace");
    assert.notEqual(newBind.bindingId, oldBind.bindingId);
    assert.equal(newBind.mappingId, "mapping-new");
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});

test("64 bindings are exact, the 65th is incompatible, and replacement gets fresh ids", async () => {
  const server = await startRegistry();
  try {
    const routes = Object.fromEntries(
      Array.from({ length: MAX_BINDING_READINESS_STATES + 1 }, (_, index) => [
        `channel-${index}`,
        managedRoute(String(index)),
      ])
    );
    server.registry.setManagedRoutes(routes);
    const first = await connectV3(server);
    await waitFor(() => first.frames.length === MAX_BINDING_READINESS_STATES);
    const firstIds = new Set(first.frames.map((frame) => frame.bindingId));
    assert.equal(firstIds.size, MAX_BINDING_READINESS_STATES);
    assert.deepEqual(
      server.registry.getManagedRouteBinding(`channel-${MAX_BINDING_READINESS_STATES}`),
      { compatible: false },
    );

    const replacement = await connectV3(server);
    await waitFor(() => replacement.frames.length === MAX_BINDING_READINESS_STATES);
    const replacementIds = new Set(replacement.frames.map((frame) => frame.bindingId));
    assert.equal([...replacementIds].some((id) => firstIds.has(id)), false);
    first.socket.terminate();
    replacement.socket.terminate();
  } finally {
    await server.close();
  }
});

test("bind deadline terminates a v3 socket that remains pending", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    timers: timers.api,
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    connection.socket.send(JSON.stringify(readinessFrame({
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "INVENTORY_PENDING",
        at: Date.now(),
        remediation: {
          code: "INVENTORY_PENDING",
          retryable: true,
          action: "retry_later",
        },
      },
    })));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(timers.timeoutDelays.includes(10_000), true);
    const closed = once(connection.socket, "close");
    timers.runTimeoutByDelay(10_000);
    await closed;
  } finally {
    await server.close();
  }
});

test("inventory bind lifecycle emits sanitized, path/native-fact-free observability events", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    await waitFor(() => events.some((e) => e.event === "bind.request"));
    const inventoryGeneration = 1;
    const inventoryFingerprint = "d".repeat(64);
    const bindingFingerprint = workspaceBindingFingerprint({
      authority: route.authority,
      inventoryGeneration,
      inventoryFingerprint,
    });
    connection.socket.send(JSON.stringify({
      type: "bind_ok",
      bindingId: bind.bindingId,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint,
    }));
    await waitFor(() => events.some((e) => e.event === "bind.ok"));

    const bindRequest = events.find((e) => e.event === "bind.request");
    assert.equal(bindRequest.phase, "request");
    assert.equal(bindRequest.workspaceId, "workspace-a");
    assert.equal(bindRequest.generation, 1);
    assert.ok(
      typeof bindRequest.bindingId === "string" && bindRequest.bindingId.length > 0
    );

    const bindOk = events.find((e) => e.event === "bind.ok");
    assert.equal(bindOk.generation, inventoryGeneration);
    assert.equal(bindOk.fingerprintPrefix, inventoryFingerprint.slice(0, 12));
    assert.equal(bindOk.fingerprintPrefix.length, 12);

    // Sentinel: only the bounded allowlist ever appears, and no full fingerprint,
    // token, workDir, or inventory bytes leak into any event.
    const allowedKeys = new Set([
      "event",
      "phase",
      "code",
      "bindingId",
      "workspaceId",
      "generation",
      "fingerprintPrefix",
    ]);
    const allowedEvents = new Set([
      "bind.request",
      "bind.ok",
      "bind.negative",
      "receipt.invalidate",
      "socket.retire",
    ]);
    const serialized = JSON.stringify(events);
    assert.ok(!serialized.includes(inventoryFingerprint), "full fingerprint never leaks");
    assert.ok(!serialized.includes("token-a"), "token never leaks");
    for (const event of events) {
      assert.ok(allowedEvents.has(event.event), `unexpected event ${event.event}`);
      for (const key of Object.keys(event)) {
        assert.ok(allowedKeys.has(key), `unexpected observability key ${key}`);
      }
    }
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});

test("connection loss invalidates inventory receipts and retires the v3 socket", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    const inventoryGeneration = 1;
    const inventoryFingerprint = "e".repeat(64);
    connection.socket.send(JSON.stringify({
      type: "bind_ok",
      bindingId: bind.bindingId,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint: workspaceBindingFingerprint({
        authority: route.authority,
        inventoryGeneration,
        inventoryFingerprint,
      }),
    }));
    await waitFor(() => events.some((e) => e.event === "bind.ok"));

    connection.socket.terminate();
    await waitFor(() =>
      events.some((e) => e.event === "receipt.invalidate" && e.phase === "offline")
    );
    await waitFor(() =>
      events.some((e) => e.event === "socket.retire" && e.phase === "offline")
    );

    const invalidate = events.find(
      (e) => e.event === "receipt.invalidate" && e.phase === "offline"
    );
    assert.equal(invalidate.code, "CONNECTION_LOST");
    assert.ok(typeof invalidate.bindingId === "string" && invalidate.bindingId.length > 0);
    const retire = events.find(
      (e) => e.event === "socket.retire" && e.phase === "offline"
    );
    assert.equal(retire.code, "CONNECTION_LOST");
  } finally {
    await server.close();
  }
});

test("a negative inventory readiness emits a bind.negative observability event", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    connection.socket.send(JSON.stringify(readinessFrame({
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "WORKSPACE_NOT_FOUND",
        at: Date.now(),
        remediation: {
          code: "WORKSPACE_NOT_FOUND",
          retryable: false,
          action: "refresh_workspace",
        },
      },
    })));
    await waitFor(() => events.some((e) => e.event === "bind.negative"));
    const negative = events.find((e) => e.event === "bind.negative");
    assert.equal(negative.code, "WORKSPACE_NOT_FOUND");
    assert.equal(negative.phase, "negative");
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});

test("off-mode managed routes stay incompatible with zero binds and zero reconnect churn", async () => {
  const events = [];
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    timers: timers.api,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const { socket } = await connectV2(server); // receipt capability withheld (off mode)
    assert.deepEqual(server.registry.getManagedRouteBinding("channel-a"), {
      compatible: false,
    });
    assert.equal(timers.timeoutCount, 0, "no bind deadline timers armed in off mode");
    assert.equal(server.registry.getHostReadiness("host-a").reconnectCount, 0);
    assert.ok(
      !events.some((e) => e.event.startsWith("bind.")),
      "no bind traffic emitted in off mode"
    );
    socket.terminate();
  } finally {
    await server.close();
  }
});

test("a bound binding drifting negative emits a drift-phase receipt.invalidate", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    const inventoryGeneration = 1;
    const inventoryFingerprint = "f".repeat(64);
    connection.socket.send(JSON.stringify({
      type: "bind_ok",
      bindingId: bind.bindingId,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint: workspaceBindingFingerprint({
        authority: route.authority,
        inventoryGeneration,
        inventoryFingerprint,
      }),
    }));
    await waitFor(() => events.some((e) => e.event === "bind.ok"));
    connection.socket.send(JSON.stringify(readinessFrame({
      revision: 2,
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
      lastError: {
        code: "WORKSPACE_NOT_FOUND",
        at: Date.now(),
        remediation: {
          code: "WORKSPACE_NOT_FOUND",
          retryable: false,
          action: "refresh_workspace",
        },
      },
    })));
    await waitFor(() =>
      events.some((e) => e.event === "receipt.invalidate" && e.phase === "drift")
    );
    const drift = events.find(
      (e) => e.event === "receipt.invalidate" && e.phase === "drift"
    );
    assert.equal(drift.code, "WORKSPACE_NOT_FOUND");
    assert.ok(typeof drift.bindingId === "string" && drift.bindingId.length > 0);
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});

test("unbinding a bound managed route emits an unbind-phase receipt.invalidate", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    const inventoryGeneration = 1;
    const inventoryFingerprint = "a".repeat(64);
    connection.socket.send(JSON.stringify({
      type: "bind_ok",
      bindingId: bind.bindingId,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint: workspaceBindingFingerprint({
        authority: route.authority,
        inventoryGeneration,
        inventoryFingerprint,
      }),
    }));
    await waitFor(() => events.some((e) => e.event === "bind.ok"));
    server.registry.setManagedRoutes({});
    await waitFor(() =>
      events.some((e) => e.event === "receipt.invalidate" && e.phase === "unbind")
    );
    const unbind = events.find(
      (e) => e.event === "receipt.invalidate" && e.phase === "unbind"
    );
    assert.equal(unbind.code, "WORKSPACE_UNBOUND");
    assert.ok(typeof unbind.bindingId === "string" && unbind.bindingId.length > 0);
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});
