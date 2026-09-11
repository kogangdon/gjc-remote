import { createServer } from "node:net";
import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import WebSocket from "ws";
import {
  CAPABILITIES,
  GATE_ANSWER_ERROR_CODES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
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
  TERMINAL_DISPOSITION_CAPABILITY,
  INVOKE_CANCELLATION_CAPABILITY,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
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

const BOT_CAPABILITIES = CAPABILITIES;

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
  const mapping = {
    mappingId: authority.mappingId,
    hostId: authority.hostId,
    fenceGeneration: authority.fenceGeneration,
    mappingGeneration: authority.mappingGeneration,
    workspaceGeneration: authority.workspaceGeneration,
    mappingVersion: authority.mappingVersion,
    sourcePlatform: authority.sourcePlatform,
    workspaceId: authority.workspaceId,
    workDir: null,
    sourceRoot: "/srv/repo",
    containerRoot: "/workspace",
    volumeIdentity: "volume-1",
    casePolicy: "sensitive",
    immutableDefault: false,
    mappingFingerprint: authority.authorityFingerprint,
    ...overrides.mapping,
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
    mapping: Object.freeze(mapping),
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
          capabilities: BOT_CAPABILITIES,
          ...register,
        })
      );
      const [raw] = await response;
      assert.deepEqual(JSON.parse(raw.toString()), {
        type: "register_ok",
        protocolVersion: PROTOCOL_VERSION,
        capabilities: BOT_CAPABILITIES,
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
  // v2 parser/readiness component tests remain useful below the Phase 4
  // registration floor. Temporarily close serving while this helper performs
  // the legacy handshake; production bot wiring has no equivalent bypass.
  const servingEnabled = server.registry.workspaceServingEnabled;
  server.registry.workspaceServingEnabled = false;
  const port = server.registry.wss.address().port;
  const socket = new WebSocket(`ws://127.0.0.1:${port}`);
  let raw;
  try {
    await once(socket, "open");
    const response = once(socket, "message");
    socket.send(
      JSON.stringify({
        type: "register",
        hostId,
        token,
        protocolVersion: 2,
        capabilities: [...BOT_CAPABILITIES, WORKSPACE_READINESS_CAPABILITY],
        ...register,
      })
    );
    [raw] = await response;
  } finally {
    server.registry.workspaceServingEnabled = servingEnabled;
  }
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
      ...BOT_CAPABILITIES,
      WORKSPACE_READINESS_CAPABILITY,
      WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
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

test("adversarial: invoke and gate-answer durations must be positive finite values", () => {
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
  for (const cancelReceiptTimeoutMs of [
    0,
    -1,
    1.5,
    2_147_483_648,
    Number.NaN,
    Number.POSITIVE_INFINITY,
  ]) {
    assert.throws(
      () =>
        new HostRegistry({
          port: 0,
          tokensByHostId,
          cancelReceiptTimeoutMs,
        }),
      /cancelReceiptTimeoutMs must be a positive duration/
    );
  }
  assert.throws(
    () =>
      new HostRegistry({
        port: 0,
        tokensByHostId,
        invokeHardCapMs: 86_400_000,
        cancelReceiptTimeoutMs: 1,
      }),
    /exceeds the safe timer bound/
  );
  for (const gateAnswerTimeoutMs of [0, -1, 1.5, 30_001, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => new HostRegistry({ port: 0, tokensByHostId, gateAnswerTimeoutMs }),
      /gateAnswerTimeoutMs must be an integer from 1 to 30000/
    );
  }
});

test("gate-answer timeout accepts its exact minimum and maximum", async () => {
  for (const gateAnswerTimeoutMs of [1, 30_000]) {
    const server = await startRegistry(undefined, { gateAnswerTimeoutMs });
    try {
      assert.equal(server.registry.gateAnswerTimeoutMs, gateAnswerTimeoutMs);
    } finally {
      await server.close();
    }
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
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));

    assert.deepEqual(await resultPromise, { ok: true, text: "answer" , terminalDisposition: "completed"});
    assert.deepEqual(events, [event]);
  } finally {
    await server.close();
  }
});

test("terminal dispositions settle invokes without conflating completion", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    for (const disposition of [
      "completed",
      "failed",
      "cancelled",
      "paused",
      "timed_out",
      "disconnected",
    ]) {
      const invokeFrame = once(socket, "message");
      const resultPromise = server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: disposition },
        () => {},
        1000
      );
      const { requestId } = JSON.parse((await invokeFrame)[0].toString());
      const event = { type: "invoke_terminal", disposition };
      if (disposition === "failed") event.code = PROTOCOL_ERROR_CODES.DAEMON_FATAL;
      if (disposition === "timed_out") {
        event.code = PROTOCOL_ERROR_CODES.SESSION_CREATE_TIMEOUT;
      }
      socket.send(JSON.stringify({ type: "event", requestId, event, done: true }));
      const result = await resultPromise;
      if (disposition === "completed") {
        assert.deepEqual(result, {
          ok: true,
          text: undefined,
          terminalDisposition: "completed",
        });
      } else {
        assert.equal(result.ok, false);
        assert.equal(result.error.terminalDisposition, disposition);
        assert.equal(typeof result.error.retryable, "boolean");
        assert.equal(typeof result.error.action, "string");
        if (event.code) assert.equal(result.error.code, event.code);
        else assert.equal(result.error.code, PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME);
      }
    }
  } finally {
    await server.close();
  }
});

test("terminal invokes reject legacy and non-exact terminal frames", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      1000
    );
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    await expectPolicyClose(
      socket,
      JSON.stringify({
        type: "event",
        requestId,
        event: { type: "invoke_terminal", disposition: "completed" },
        done: true,
        error: "contradictory",
      })
    );
    assert.deepEqual(await resultPromise, {
      ok: false,
      error: {
        terminalDisposition: "disconnected",
        code: PROTOCOL_ERROR_CODES.CONNECTION_LOST,
        retryable: true,
        action: "retry_later",
      },
    });
  } finally {
    await server.close();
  }
});

test("terminal invokes reject legacy done frames", async () => {
  const server = await startRegistry();
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
      1000
    );
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    await expectPolicyClose(
      socket,
      JSON.stringify({ type: "event", requestId, done: true })
    );
    assert.equal((await resultPromise).ok, false);
  } finally {
    await server.close();
  }
});

test("terminal invokes reject every non-exact outer frame", async () => {
  const invalidFrames = [
    {
      event: { type: "invoke_terminal", disposition: "completed" },
    },
    {
      event: { type: "invoke_terminal", disposition: "completed" },
      done: false,
    },
    {
      event: { type: "invoke_terminal", disposition: "completed" },
      done: true,
      extra: "forbidden",
    },
  ];

  for (const invalid of invalidFrames) {
    const server = await startRegistry();
    try {
      const socket = await server.connect("host-a", "token-a");
      const invokeFrame = once(socket, "message");
      const resultPromise = server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: "hello" },
        () => {},
        1000
      );
      const { requestId } = JSON.parse((await invokeFrame)[0].toString());
      await expectPolicyClose(
        socket,
        JSON.stringify({ type: "event", requestId, ...invalid })
      );
      assert.equal((await resultPromise).error.terminalDisposition, "disconnected");
      assert.equal(server.registry.pendingRequests.size, 0);
    } finally {
      await server.close();
    }
  }
});

test("the first terminal outcome survives conflicts, disconnect, and cleared timers", async () => {
  const timers = createManualTimers();
  const observability = [];
  const events = [];
  const server = await startRegistry(undefined, {
    timers: timers.api,
    onObservabilityEvent: (event) => observability.push(event),
  });
  try {
    const socket = await server.connect("host-a", "token-a");

    const completedFrame = once(socket, "message");
    const completedPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "completed-first" },
      (event) => events.push(event),
      1000
    );
    const completedInvoke = JSON.parse((await completedFrame)[0].toString());
    const completedPending = server.registry.pendingRequests.get(
      completedInvoke.requestId
    );
    socket.send(JSON.stringify({
      type: "event",
      requestId: completedInvoke.requestId,
      event: { type: "invoke_terminal", disposition: "completed" },
      done: true,
    }));
    const completed = await completedPromise;
    socket.send(JSON.stringify({
      type: "event",
      requestId: completedInvoke.requestId,
      event: {
        type: "invoke_terminal",
        disposition: "failed",
        code: PROTOCOL_ERROR_CODES.DAEMON_FATAL,
      },
      done: true,
    }));
    completedPending.resolve({
      ok: false,
      error: { terminalDisposition: "disconnected" },
    });
    timers.runClearedTimeouts();
    assert.deepEqual(completed, {
      ok: true,
      text: undefined,
      terminalDisposition: "completed",
    });

    const failedFrame = once(socket, "message");
    const failedPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "failed-first" },
      (event) => events.push(event),
      1000
    );
    const failedInvoke = JSON.parse((await failedFrame)[0].toString());
    socket.send(JSON.stringify({
      type: "event",
      requestId: failedInvoke.requestId,
      event: {
        type: "invoke_terminal",
        disposition: "failed",
        code: PROTOCOL_ERROR_CODES.DAEMON_FATAL,
      },
      done: true,
    }));
    const failed = await failedPromise;
    socket.send(JSON.stringify({
      type: "event",
      requestId: failedInvoke.requestId,
      event: { type: "invoke_terminal", disposition: "completed" },
      done: true,
    }));
    assert.equal(failed.error.terminalDisposition, "failed");

    const disconnectedFrame = once(socket, "message");
    const disconnectedPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "disconnect-first" },
      (event) => events.push(event),
      1000
    );
    const disconnectedInvoke = JSON.parse(
      (await disconnectedFrame)[0].toString()
    );
    const disconnectedPending = server.registry.pendingRequests.get(
      disconnectedInvoke.requestId
    );
    socket.terminate();
    const disconnected = await disconnectedPromise;
    disconnectedPending.resolve({
      ok: true,
      text: "late",
      terminalDisposition: "completed",
    });
    timers.runClearedTimeouts();

    assert.equal(disconnected.error.terminalDisposition, "disconnected");
    assert.deepEqual(events, []);
    assert.equal(server.registry.pendingRequests.size, 0);
    assert.equal(timers.timeoutCount, 0);
    const finishes = observability.filter(
      (event) => event.event === "invoke.finish"
    );
    assert.equal(finishes.length, 3);
    assert.deepEqual(
      finishes.map((event) => event.terminalDisposition),
      ["completed", "failed", "disconnected"]
    );
  } finally {
    await server.close();
  }
});

test("invoke refuses hosts missing either ownership capability", async () => {
  for (const missing of [
    TERMINAL_DISPOSITION_CAPABILITY,
    INVOKE_CANCELLATION_CAPABILITY,
  ]) {
    const server = await startRegistry();
    try {
      const socket = await server.connect("host-a", "token-a", {
        capabilities: CAPABILITIES.filter(
          (capability) => capability !== missing
        ),
      });
      assert.deepEqual(
        await server.registry.invoke(
          "host-a",
          "/workspace",
          { kind: "prompt", message: "hello" },
          () => {}
        ),
        {
          ok: false,
          error: {
            code: PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
            retryable: false,
            action: "contact_admin",
          },
        }
      );
      socket.terminate();
    } finally {
      await server.close();
    }
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
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));

    assert.deepEqual(await resultPromise, {
      ok: true,
      text: "[output truncated: too large]",
      terminalDisposition: "completed",
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
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));

    assert.deepEqual(await resultPromise, {
      ok: true,
      text: "answer\n[output truncated: too large]",
      terminalDisposition: "completed",
    });
    assert.deepEqual(events, [assistant, truncated, truncated]);
  } finally {
    await server.close();
  }
});

test("truncation does not override terminal failures or activate for near-match events", async () => {
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
        event: {
          type: "invoke_terminal",
          disposition: "failed",
          code: PROTOCOL_ERROR_CODES.DAEMON_FATAL,
        },
        done: true,
      })
    );
    assert.deepEqual(await firstResult, {
      ok: false,
      error: {
        terminalDisposition: "failed",
        code: PROTOCOL_ERROR_CODES.DAEMON_FATAL,
        retryable: false,
        action: "contact_admin",
      },
    });

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
        event: { type: "invoke_terminal", disposition: "completed" }, done: true,
      })
    );

    assert.deepEqual(await secondResult, { ok: true, text: undefined , terminalDisposition: "completed"});
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
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined , terminalDisposition: "completed"});
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
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined , terminalDisposition: "completed"});
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
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await readyResult, { ok: true, text: undefined , terminalDisposition: "completed"});

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
    socket.send(JSON.stringify({ type: "event", requestId: invoke.requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await result, { ok: true, text: undefined , terminalDisposition: "completed"});

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

    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: "still working" , terminalDisposition: "completed"});
  } finally {
    await server.close();
  }
});

test("invoke idle expiry fires with zero events", async () => {
  const timers = createManualTimers();
  const observability = [];
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 20,
    invokeHardCapMs: 5000,
    timers: timers.api,
    onObservabilityEvent: (event) => observability.push(event),
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
    const [invokeRaw] = await invokeFrame;
    const { requestId } = JSON.parse(invokeRaw.toString());
    assert.deepEqual(timers.timeoutDelays.sort((a, b) => a - b), [20, 5000]);
    const cancelFrame = once(socket, "message");
    timers.runTimeoutByDelay(20);
    const cancel = JSON.parse((await cancelFrame)[0].toString());
    assert.deepEqual(cancel, {
      type: MSG_TYPES.CANCEL_INVOKE,
      requestId,
      cancelId: cancel.cancelId,
      reason: "idle_timeout",
    });
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: cancel.cancelId,
        outcome: "cancellation_pending",
      },
    }));
    const result = await resultPromise;
    assert.deepEqual(result, {
      ok: false,
      error: {
        localOutcome: "cancellation_pending",
        code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
        retryable: false,
        action: "verify_host_state",
      },
    });
    assert.equal(server.registry.pendingRequests.size, 0);
    const finishes = observability.filter((event) => event.event === "invoke.finish");
    assert.equal(finishes.length, 1);
    assert.equal(finishes[0].phase, "cancellation_pending");
    assert.equal(finishes[0].code, PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME);
  } finally {
    await server.close();
  }
});

test("invoke hard cap fires despite continuous activity", async () => {
  const timers = createManualTimers();
  const observability = [];
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 1000,
    invokeHardCapMs: 40,
    timers: timers.api,
    onObservabilityEvent: (event) => observability.push(event),
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
    const cancelFrame = once(socket, "message");
    timers.runTimeout(hardCapTimer);
    const cancel = JSON.parse((await cancelFrame)[0].toString());
    assert.equal(cancel.type, MSG_TYPES.CANCEL_INVOKE);
    assert.equal(cancel.requestId, requestId);
    assert.equal(cancel.reason, "hard_cap");
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: cancel.cancelId,
        outcome: "cancellation_pending",
      },
    }));
    assert.deepEqual(await resultPromise, {
      ok: false,
      error: {
        localOutcome: "cancellation_pending",
        code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
        retryable: false,
        action: "verify_host_state",
      },
    });
    const finishes = observability.filter((entry) => entry.event === "invoke.finish");
    assert.equal(finishes.length, 1);
    assert.equal(finishes[0].phase, "cancellation_pending");
    assert.equal(finishes[0].code, PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME);
  } finally {
    await server.close();
  }
});

test("explicit cancellation remains pending until an authoritative terminal", async () => {
  const observability = [];
  const server = await startRegistry(undefined, {
    cancelIdFactory: () => "cancel-explicit-1",
    onObservabilityEvent: (event) => observability.push(event),
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    let createdRequestId;
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "active" },
      () => {},
      undefined,
      undefined,
      undefined,
      (requestId) => {
        createdRequestId = requestId;
      }
    );
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    assert.equal(createdRequestId, requestId);
    const cancelFrame = once(socket, "message");
    assert.deepEqual(
      server.registry.cancelInvoke("host-a", requestId, "user_cancelled"),
      { ok: true, cancelId: "cancel-explicit-1" }
    );
    assert.deepEqual(JSON.parse((await cancelFrame)[0].toString()), {
      type: MSG_TYPES.CANCEL_INVOKE,
      requestId,
      cancelId: "cancel-explicit-1",
      reason: "user_cancelled",
    });
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: "cancel-explicit-1",
        outcome: "cancellation_pending",
      },
    }));
    assert.deepEqual(await resultPromise, {
      ok: false,
      error: {
        localOutcome: "cancellation_pending",
        code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
        retryable: false,
        action: "verify_host_state",
      },
    });
    assert.equal(server.registry.pendingRequests.has(requestId), false);
    assert.equal(server.registry.cancelTombstones.has(requestId), true);

    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: { type: "invoke_terminal", disposition: "completed" },
      done: true,
    }));
    await waitFor(() => !server.registry.cancelTombstones.has(requestId));
    const finishes = observability.filter(
      (event) => event.event === "invoke.finish"
    );
    assert.equal(finishes.length, 1);
    assert.equal(finishes[0].phase, "cancellation_pending");
  } finally {
    await server.close();
  }
});

test("cancelled-before-start waits for the daemon terminal cancellation proof", async () => {
  const server = await startRegistry(undefined, {
    cancelIdFactory: () => "cancel-queued-1",
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "queued" },
      () => {}
    );
    let settled = false;
    void resultPromise.finally(() => {
      settled = true;
    });
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    const cancelFrame = once(socket, "message");
    server.registry.cancelInvoke("host-a", requestId, "user_cancelled");
    await cancelFrame;
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: "cancel-queued-1",
        outcome: "cancelled_before_start",
      },
    }));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
    assert.equal(server.registry.pendingRequests.has(requestId), true);

    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: { type: "invoke_terminal", disposition: "cancelled" },
      done: true,
    }));
    const result = await resultPromise;
    assert.equal(result.ok, false);
    assert.equal(result.error.terminalDisposition, "cancelled");
    assert.equal(server.registry.pendingRequests.has(requestId), false);
  } finally {
    await server.close();
  }
});

test("request-presentation failure immediately revokes daemon ownership", async () => {
  const server = await startRegistry(undefined, {
    cancelIdFactory: () => "cancel-presentation-1",
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const frames = [];
    socket.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "presentation" },
      () => {},
      undefined,
      undefined,
      undefined,
      () => {
        throw new Error("private presentation failure");
      }
    );
    await waitFor(() => frames.length === 2);
    const [invoke, cancel] = frames;
    assert.equal(invoke.type, MSG_TYPES.INVOKE);
    assert.deepEqual(cancel, {
      type: MSG_TYPES.CANCEL_INVOKE,
      requestId: invoke.requestId,
      cancelId: "cancel-presentation-1",
      reason: "presentation_failed",
    });
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId: invoke.requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: cancel.cancelId,
        outcome: "cancellation_pending",
      },
    }));
    assert.equal((await resultPromise).error.localOutcome, "cancellation_pending");
  } finally {
    await server.close();
  }
});

test("asynchronous gate presentation failure revokes request ownership", async () => {
  const server = await startRegistry(undefined, {
    cancelIdFactory: () => "cancel-gate-presentation-1",
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "gate" },
      () => {},
      undefined,
      async () => {
        throw new Error("private Discord delivery failure");
      }
    );
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    const cancelFrame = once(socket, "message");
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: "gate_request",
        gateId: "gate-presentation-1",
        prompt: "Approve?",
        kind: "approval",
      },
    }));
    const cancel = JSON.parse((await cancelFrame)[0].toString());
    assert.deepEqual(cancel, {
      type: MSG_TYPES.CANCEL_INVOKE,
      requestId,
      cancelId: "cancel-gate-presentation-1",
      reason: "presentation_failed",
    });
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: cancel.cancelId,
        outcome: "cancellation_pending",
      },
    }));
    assert.equal((await resultPromise).error.localOutcome, "cancellation_pending");
  } finally {
    await server.close();
  }
});

test("cancelled-before-start rejects a contradictory completed terminal", async () => {
  const server = await startRegistry(undefined, {
    cancelIdFactory: () => "cancel-conflicting-terminal-1",
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "queued" },
      () => {}
    );
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    const cancelFrame = once(socket, "message");
    server.registry.cancelInvoke("host-a", requestId, "user_cancelled");
    await cancelFrame;
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: "cancel-conflicting-terminal-1",
        outcome: "cancelled_before_start",
      },
    }));
    await waitFor(
      () =>
        server.registry.pendingRequests.get(requestId)?.cancellation
          ?.receipt === "cancelled_before_start"
    );
    const closed = once(socket, "close");
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: { type: "invoke_terminal", disposition: "completed" },
      done: true,
    }));
    assert.equal(
      (await resultPromise).error.localOutcome,
      "cancellation_terminal_conflict"
    );
    assert.equal((await closed)[0], 1008);
  } finally {
    await server.close();
  }
});

test("cancelled-before-start terminal wait has a bounded unconfirmed timeout", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    timers: timers.api,
    cancelReceiptTimeoutMs: 25,
    cancelIdFactory: () => "cancel-terminal-timeout-1",
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "queued" },
      () => {}
    );
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    const cancelFrame = once(socket, "message");
    server.registry.cancelInvoke("host-a", requestId, "user_cancelled");
    await cancelFrame;
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: "cancel-terminal-timeout-1",
        outcome: "cancelled_before_start",
      },
    }));
    await waitFor(
      () =>
        server.registry.pendingRequests.get(requestId)?.cancellation
          ?.receipt === "cancelled_before_start"
    );
    const terminalTimer = timers.timeoutHandleByDelay(25);
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: "cancel-terminal-timeout-1",
        outcome: "cancelled_before_start",
      },
    }));
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(timers.timeoutHandleByDelay(25), terminalTimer);
    timers.runTimeoutByDelay(25);
    assert.equal(
      (await resultPromise).error.localOutcome,
      "cancellation_terminal_timeout"
    );
    assert.equal(server.registry.pendingRequests.size, 0);
    assert.equal(server.registry.cancelTombstones.has(requestId), true);
  } finally {
    await server.close();
  }
});

test("cancellation receipt timeout is bounded and interruption-unconfirmed", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    timers: timers.api,
    cancelReceiptTimeoutMs: 25,
    cancelIdFactory: () => "cancel-timeout-1",
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "active" },
      () => {}
    );
    const { requestId } = JSON.parse((await invokeFrame)[0].toString());
    const cancelFrame = once(socket, "message");
    server.registry.cancelInvoke("host-a", requestId, "user_cancelled");
    await cancelFrame;
    timers.runTimeoutByDelay(25);
    assert.deepEqual(await resultPromise, {
      ok: false,
      error: {
        localOutcome: "cancellation_receipt_timeout",
        code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
        retryable: false,
        action: "verify_host_state",
      },
    });
    assert.equal(server.registry.pendingRequests.size, 0);
    assert.equal(server.registry.cancelTombstones.has(requestId), true);
  } finally {
    await server.close();
  }
});

test("retained cancellation tombstones refuse request-id reuse", async () => {
  const server = await startRegistry(undefined, {
    requestIdFactory: () => "retained-request-id",
    cancelIdFactory: () => "retained-cancel-id",
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const first = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "first" },
      () => {}
    );
    await invokeFrame;
    const cancelFrame = once(socket, "message");
    server.registry.cancelInvoke(
      "host-a",
      "retained-request-id",
      "user_cancelled"
    );
    await cancelFrame;
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId: "retained-request-id",
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: "retained-cancel-id",
        outcome: "cancellation_pending",
      },
    }));
    await first;
    assert.equal(
      server.registry.cancelTombstones.has("retained-request-id"),
      true
    );
    assert.deepEqual(
      await server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: "must not dispatch" },
        () => {}
      ),
      {
        ok: false,
        error: {
          code: PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
          retryable: true,
          action: "retry_later",
        },
      }
    );
  } finally {
    await server.close();
  }
});

test("cancellation tombstone saturation keeps exact ownership without eviction", async () => {
  let requestSequence = 0;
  let cancelSequence = 0;
  const server = await startRegistry(undefined, {
    requestIdFactory: () => `bounded-request-${++requestSequence}`,
    cancelIdFactory: () => `bounded-cancel-${++cancelSequence}`,
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    for (let index = 1; index <= 65; index += 1) {
      const invokeFrame = once(socket, "message");
      const resultPromise = server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: `request-${index}` },
        () => {}
      );
      const invoke = JSON.parse((await invokeFrame)[0].toString());
      const cancelFrame = once(socket, "message");
      server.registry.cancelInvoke(
        "host-a",
        invoke.requestId,
        "user_cancelled"
      );
      const cancel = JSON.parse((await cancelFrame)[0].toString());
      socket.send(JSON.stringify({
        type: MSG_TYPES.EVENT,
        requestId: invoke.requestId,
        event: {
          type: MSG_TYPES.CANCEL_RESULT,
          cancelId: cancel.cancelId,
          outcome: "cancellation_pending",
        },
      }));
      await resultPromise;
    }
    assert.equal(server.registry.cancelTombstones.size, 64);
    assert.equal(
      server.registry.cancelTombstones.has("bounded-request-1"),
      true
    );
    assert.equal(
      server.registry.pendingRequests.has("bounded-request-65"),
      true,
      "the saturated tracker remains exact and blocks capacity"
    );
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
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));

    const result = await resultPromise;
    assert.deepEqual(result, { ok: true, text: undefined , terminalDisposition: "completed"});
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

    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    const result = await resultPromise;
    assert.deepEqual(result, { ok: true, text: undefined , terminalDisposition: "completed"});
    assert.equal(server.registry.pendingRequests.size, 0);

    // Simulate a stale idle/hard-cap timer firing after the real done already
    // settled this request: calling settle again must be a safe no-op that
    // neither changes the resolved value nor corrupts registry state.
    assert.doesNotThrow(() => {
      pendingEntry.settle({ ok: false, error: "invoke exceeded absolute hard-cap" });
    });
    assert.deepEqual(await resultPromise, { ok: true, text: undefined , terminalDisposition: "completed"});
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
      socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
      const result = await resultPromise;
      assert.deepEqual(result, { ok: true, text: undefined , terminalDisposition: "completed"});
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
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined , terminalDisposition: "completed"});
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
    socket.send(JSON.stringify({ type: "event", requestId: barrierRequestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await barrierResult, { ok: true, text: undefined , terminalDisposition: "completed"});
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

      const expectsTerminalCapability =
        !Object.prototype.hasOwnProperty.call(register, "capabilities");
      const barrierFrame = expectsTerminalCapability
        ? once(socket, "message")
        : undefined;
      const barrierResult = server.registry.invoke(
        "host-a",
        "/workspace",
        { kind: "prompt", message: "barrier" },
        () => {}
      );
      if (expectsTerminalCapability) {
        const [barrierRaw] = await barrierFrame;
        const barrier = JSON.parse(barrierRaw.toString());
        assert.equal(barrier.workDir, "/workspace");
        socket.send(
          JSON.stringify({
            type: "event",
            requestId: barrier.requestId,
            event: { type: "invoke_terminal", disposition: "completed" },
            done: true,
          })
        );
        assert.deepEqual(await barrierResult, {
          ok: true,
          text: undefined,
          terminalDisposition: "completed",
        });
      } else {
        assert.deepEqual(await barrierResult, {
          ok: false,
          error: {
            code: PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
            retryable: false,
            action: "contact_admin",
          },
        });
      }
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
        event: { type: "invoke_terminal", disposition: "completed" }, done: true,
      })
    );
    const [closeCode] = await attackerClosed;
    assert.equal(closeCode, 1008);
    assert.equal(settled, false);
    assert.deepEqual(events, []);

    owner.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined , terminalDisposition: "completed"});
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
  const observability = [];
  const server = await startRegistry(undefined, {
    timers: timers.api,
    onObservabilityEvent: (event) => observability.push(event),
  });
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
      error: {
        terminalDisposition: "disconnected",
        code: "HEARTBEAT_TIMEOUT",
        retryable: true,
        action: "retry_later",
      },
    });
    assert.equal(server.registry.isOnline("host-a"), false);
    assert.equal(server.registry.pendingRequests.size, 0);
    const finishes = observability.filter((event) => event.event === "invoke.finish");
    assert.equal(finishes.length, 1);
    assert.equal(finishes[0].phase, "disconnect");
    assert.equal(finishes[0].code, PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT);
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
      error: {
        terminalDisposition: "disconnected",
        code: "CONNECTION_LOST",
        retryable: true,
        action: "retry_later",
      },
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

  const cancelFrame = once(socket, "message");
  const closing = server.registry.close();
  assert.strictEqual(server.registry.close(), closing);
  const cancel = JSON.parse((await cancelFrame)[0].toString());
  assert.equal(cancel.type, MSG_TYPES.CANCEL_INVOKE);
  assert.equal(cancel.reason, "disconnect");
  await closing;

  assert.deepEqual(await result, {
    ok: false,
    error: {
      terminalDisposition: "disconnected",
      code: "CONNECTION_LOST",
      retryable: true,
      action: "retry_later",
    },
  });
  assert.equal(timers.intervalCount, 0);
  assert.equal(timers.timeoutCount, 0);
  assert.equal(server.registry.connections.size, 0);
  assert.equal(server.registry.pendingRequests.size, 0);
});

test("per-host in-flight invokes are capped and freed on completion", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    onObservabilityEvent: (event) => events.push(event),
  });
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
    let snapshot = server.registry.getObservabilitySnapshot();
    assert.equal(snapshot.gauges["invokes.inFlight"], cap);
    assert.equal(snapshot.gauges["resourceDenials.total"], 1);
    const denial = events.find(
      (event) =>
        event.event === "invoke.deny" &&
        event.code === PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED,
    );
    assert.equal(denial.phase, "bot_admission");
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
    snapshot = server.registry.getObservabilitySnapshot();
    assert.equal(snapshot.gauges["resourceDenials.total"], 1);
    server.registry.resourceDenials = Number.MAX_SAFE_INTEGER;
    await server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "saturated" },
      () => {},
      10_000,
    );
    assert.equal(
      server.registry.getObservabilitySnapshot().gauges["resourceDenials.total"],
      Number.MAX_SAFE_INTEGER,
    );

    const [freedRequestId] = [...server.registry.pendingRequests.keys()];
    socket.send(
      JSON.stringify({ type: "event", requestId: freedRequestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true })
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
      capabilities: BOT_CAPABILITIES,
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

test("workspace serving admits only the exact managed v3 registration floor", async () => {
  const server = await startRegistry(undefined, { workspaceServingEnabled: true });
  const managedCapabilities = [
    ...CAPABILITIES,
    WORKSPACE_READINESS_CAPABILITY,
    WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
    WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
  ];
  const rejectedRegistrations = [
    { name: "omitted protocol", register: {} },
    {
      name: "v1 protocol",
      register: { protocolVersion: PROTOCOL_VERSION, capabilities: CAPABILITIES },
    },
    {
      name: "v2 protocol",
      register: {
        protocolVersion: 2,
        capabilities: [...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY],
      },
    },
    ...[
      WORKSPACE_READINESS_CAPABILITY,
      WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
    ].map((capability) => ({
      name: `missing ${capability}`,
      register: {
        protocolVersion: PROTOCOL_VERSION_V3,
        capabilities: managedCapabilities.filter((item) => item !== capability),
      },
    })),
  ];
  try {
    for (const { name, register } of rejectedRegistrations) {
      const socket = new WebSocket(`ws://127.0.0.1:${server.registry.wss.address().port}`);
      await once(socket, "open");
      const frames = [];
      socket.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
      const closed = once(socket, "close");
      socket.send(JSON.stringify({
        type: "register",
        hostId: "host-a",
        token: "token-a",
        ...register,
      }));
      await waitFor(() => frames.length === 1);
      assert.deepEqual(frames[0], {
        type: "register_denied",
        reason: PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
        code: PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
      }, name);
      const [code] = await closed;
      assert.equal(code, 1008, name);
      assert.equal(server.registry.connections.has("host-a"), false, name);
      assert.equal(server.registry.heartbeatStates.has(socket), false, name);
      assert.equal(server.registry.getHostInfo("host-a"), undefined, name);
      assert.equal(server.registry.getHostReadiness("host-a"), undefined, name);
      assert.equal(server.registry.readinessStates.has("host-a"), false, name);
    }

    const connection = await connectV3(server);
    assert.deepEqual(connection.response, {
      type: "register_ok",
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: managedCapabilities,
    });
    assert.deepEqual(server.registry.getHostInfo("host-a"), {
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: managedCapabilities,
    });
    connection.socket.terminate();
  } finally {
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

test("Finding-1: a binding-enabled peer missing the bind-authority-verification capability is denied, not bound", async () => {
  const server = await startRegistry();
  try {
    server.registry.setManagedRoutes({ "channel-a": managedRoute("a") });
    const port = server.registry.wss.address().port;
    const socket = new WebSocket(`ws://127.0.0.1:${port}`);
    await once(socket, "open");
    const frames = [];
    socket.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
    const closed = once(socket, "close");
    socket.send(JSON.stringify({
      type: "register",
      hostId: "host-a",
      token: "token-a",
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        ...CAPABILITIES,
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await waitFor(() => frames.length > 0);
    assert.deepEqual(frames[0], {
      type: "register_denied",
      reason: PROTOCOL_ERROR_CODES.BIND_AUTHORITY_VERIFICATION_REQUIRED,
      code: PROTOCOL_ERROR_CODES.BIND_AUTHORITY_VERIFICATION_REQUIRED,
    });
    await closed;
    assert.equal(server.registry.getHostInfo("host-a"), undefined);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(frames.length, 1, "no managed bind is ever emitted to a denied peer");
    assert.ok(
      frames.every((frame) => frame.type !== "bind_workspace"),
      "no BIND_WORKSPACE frame reaches a denied peer"
    );
  } finally {
    await server.close();
  }
});

test("Finding-1: a non-binding peer missing the bind-authority-verification capability is unaffected", async () => {
  const server = await startRegistry();
  try {
    const { socket, response } = await connectV2(server);
    assert.equal(response.protocolVersion, 2);
    assert.deepEqual(response.capabilities, [...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY]);
    assert.equal(response.type, "register_ok");
    assert.deepEqual(server.registry.getHostInfo("host-a"), {
      protocolVersion: 2,
      capabilities: [...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY],
    });
    socket.terminate();
  } finally {
    await server.close();
  }
});
// ---------------------------------------------------------------------------
// #35: workflow gate answer channel
// ---------------------------------------------------------------------------

test("#35 answerGate sends a correlated frame and resumes idle timing only after acceptance", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 40,
    invokeHardCapMs: 5000,
    gateAnswerTimeoutMs: 1000,
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
    const answerResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "Apple"
    );
    const [rawAnswer] = await answerFrame;
    const parsedAnswer = JSON.parse(rawAnswer.toString());
    assert.deepEqual(parsedAnswer, {
      type: "answer",
      requestId,
      gateId: "g1",
      answerId: parsedAnswer.answerId,
      answer: "Apple",
    });
    assert.equal(typeof parsedAnswer.answerId, "string");
    assert.ok(parsedAnswer.answerId.length <= V0_LIMITS.REQUEST_ID);
    assert.deepEqual(
      timers.timeoutDelays.sort((a, b) => a - b),
      [1000, 5000]
    );
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: parsedAnswer.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));
    assert.deepEqual(await answerResult, { ok: true });
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
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: "done" , terminalDisposition: "completed"});
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

    assert.deepEqual(await server.registry.answerGate("host-a", "nope", "g1", "x"), {
      ok: false,
      error: "no in-flight request for that answer",
    });
    assert.deepEqual(await server.registry.answerGate("host-a", requestId, "g1", "x"), {
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

    assert.deepEqual(await server.registry.answerGate("host-a", requestId, "WRONG", "x"), {
      ok: false,
      error: "no matching pending gate for that answer",
    });
    assert.equal(
      (await server.registry.answerGate("host-b", requestId, "g1", "x")).ok,
      false
    );

    const answerFrame = once(socket, "message");
    const answerResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "yes"
    );
    const [rawAnswer] = await answerFrame;
    const answer = JSON.parse(rawAnswer.toString());
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: answer.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));
    assert.deepEqual(await answerResult, { ok: true });
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    await resultPromise;
  } finally {
    await server.close();
  }
});

test("#35 a rejected answer retains the same gate so a valid retry can resume the invoke", async () => {
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

    const invalidFrame = once(socket, "message");
    const invalidResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "invalid"
    );
    const [rawInvalid] = await invalidFrame;
    const invalid = JSON.parse(rawInvalid.toString());
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: invalid.answerId,
        gateId: "g1",
        accepted: false,
        errorCode: GATE_ANSWER_ERROR_CODES.REJECTED,
      },
    }));
    assert.deepEqual(await invalidResult, {
      ok: false,
      error: "gate answer was rejected",
      code: GATE_ANSWER_ERROR_CODES.REJECTED,
    });
    assert.equal(
      server.registry.pendingRequests.get(requestId)?.gateId,
      "g1"
    );

    const validFrame = once(socket, "message");
    const validResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "valid"
    );
    const [rawValid] = await validFrame;
    const valid = JSON.parse(rawValid.toString());
    assert.notEqual(valid.answerId, invalid.answerId);
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: valid.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));
    assert.deepEqual(await validResult, { ok: true });

    // Only confirmed acceptance re-arms the invoke idle timer.
    const cancel = JSON.parse((await once(socket, "message"))[0].toString());
    assert.equal(cancel.type, MSG_TYPES.CANCEL_INVOKE);
    assert.equal(cancel.reason, "idle_timeout");
    socket.send(JSON.stringify({
      type: MSG_TYPES.EVENT,
      requestId,
      event: {
        type: MSG_TYPES.CANCEL_RESULT,
        cancelId: cancel.cancelId,
        outcome: "cancellation_pending",
      },
    }));
    assert.deepEqual(await resultPromise, {
      ok: false,
      error: {
        localOutcome: "cancellation_pending",
        code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
        retryable: false,
        action: "verify_host_state",
      },
    });
  } finally {
    await server.close();
  }
});


test("adversarial: DONE may precede an exact answer receipt without creating false success or a hang", async () => {
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

    const answerFrame = once(socket, "message");
    const answerResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "yes"
    );
    const [rawAnswer] = await answerFrame;
    const answer = JSON.parse(rawAnswer.toString());
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    await resultPromise;
    assert.equal(server.registry.pendingGateAnswers.has(answer.answerId), true);

    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: answer.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));
    assert.deepEqual(await answerResult, { ok: true });

    assert.deepEqual(await server.registry.answerGate("host-a", requestId, "g1", "late"), {
      ok: false,
      error: "no in-flight request for that answer",
    });
  } finally {
    await server.close();
  }
});

test("adversarial: a rejected receipt after DONE settles false without reviving the invoke", async () => {
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
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_request",
        gateId: "g1",
        prompt: "p",
        kind: "question",
      },
    }));
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gateId === "g1"
    );

    const answerFrame = once(socket, "message");
    const answerResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "invalid"
    );
    const [rawAnswer] = await answerFrame;
    const answer = JSON.parse(rawAnswer.toString());
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.equal((await resultPromise).ok, true);
    assert.equal(server.registry.pendingRequests.has(requestId), false);

    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: answer.answerId,
        gateId: "g1",
        accepted: false,
        errorCode: GATE_ANSWER_ERROR_CODES.REJECTED,
      },
    }));
    assert.deepEqual(await answerResult, {
      ok: false,
      error: "gate answer was rejected",
      code: GATE_ANSWER_ERROR_CODES.REJECTED,
    });
    assert.equal(server.registry.pendingGateAnswers.size, 0);
    assert.equal(server.registry.pendingRequests.has(requestId), false);
  } finally {
    await server.close();
  }
});

test("receipt capacity remains bounded after DONE and is isolated by socket", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(new Map([["host-a", "token-a"], ["host-b", "token-b"]]), {
    timers: timers.api,
  });
  const outstanding = [];
  try {
    const socket = await server.connect("host-a", "token-a");
    let sentAnswers = 0;
    socket.on("message", (raw) => {
      if (JSON.parse(raw.toString()).type === "answer") sentAnswers += 1;
    });
    async function openGate(host, peer) {
      const invokeFrame = once(peer, "message");
      const done = server.registry.invoke(host, "/workspace",
        { kind: "prompt", message: "gate" }, () => {}, undefined, () => {});
      const [raw] = await invokeFrame;
      const { requestId } = JSON.parse(raw.toString());
      peer.send(JSON.stringify({
        type: "event", requestId,
        event: { type: "gate_request", gateId: "gate", prompt: "p", kind: "question" },
      }));
      await waitFor(() => server.registry.pendingRequests.get(requestId)?.gatePending);
      return { requestId, done };
    }
    async function submit(host, peer, gate) {
      const frame = once(peer, "message");
      const result = server.registry.answerGate(host, gate.requestId, "gate", "yes");
      outstanding.push(result);
      const [raw] = await frame;
      return { answer: JSON.parse(raw.toString()), result };
    }
    const retained = [];
    for (let i = 0; i < V0_LIMITS.MAX_PENDING_PER_HOST; i += 1) {
      const gate = await openGate("host-a", socket);
      retained.push(await submit("host-a", socket, gate));
      socket.send(JSON.stringify({ type: "event", requestId: gate.requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
      await gate.done;
    }
    assert.equal(server.registry.pendingRequests.size, 0);
    assert.equal(server.registry.pendingGateAnswers.size, V0_LIMITS.MAX_PENDING_PER_HOST);
    const overflow = await openGate("host-a", socket);
    assert.deepEqual(await server.registry.answerGate("host-a", overflow.requestId, "gate", "yes"), {
      ok: false, error: "host has too many unconfirmed gate answers",
    });
    assert.equal(sentAnswers, V0_LIMITS.MAX_PENDING_PER_HOST);
    assert.equal(server.registry.pendingRequests.get(overflow.requestId).gatePending, true);

    const peer = await server.connect("host-b", "token-b");
    const otherGate = await openGate("host-b", peer);
    await submit("host-b", peer, otherGate);
    assert.equal(server.registry.pendingGateAnswers.size, V0_LIMITS.MAX_PENDING_PER_HOST + 1);

    const first = retained[0];
    socket.send(JSON.stringify({
      type: "event", requestId: first.answer.requestId,
      event: { type: "gate_answer_result", answerId: first.answer.answerId, gateId: "gate", accepted: true },
    }));
    assert.deepEqual(await first.result, { ok: true });
    await submit("host-a", socket, overflow);
    assert.equal(sentAnswers, V0_LIMITS.MAX_PENDING_PER_HOST + 1);
    assert.equal(server.registry.pendingGateAnswers.size, V0_LIMITS.MAX_PENDING_PER_HOST + 1);
    await server.close();
    await Promise.all([overflow.done, otherGate.done]);
    await Promise.all(outstanding);
    assert.equal(server.registry.pendingGateAnswers.size, 0);
  } finally {
    await server.close();
  }
});

test("adversarial: a second answer for the same gate is rejected while its receipt is outstanding", async () => {
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

    const answerFrame = once(socket, "message");
    const firstAnswer = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "yes"
    );
    const [rawAnswer] = await answerFrame;
    const answer = JSON.parse(rawAnswer.toString());

    // Only one answer attempt per gate may await a receipt at a time.
    const secondAnswer = await server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "yes-again"
    );
    assert.deepEqual(secondAnswer, {
      ok: false,
      error: "an answer for that gate is already pending",
    });

    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: answer.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));
    assert.deepEqual(await firstAnswer, { ok: true });
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    await resultPromise;
  } finally {
    await server.close();
  }
});

test("adversarial: a bounded answer-receipt timeout retains the gate and ignores a late receipt", async () => {
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    invokeIdleTimeoutMs: 30,
    invokeHardCapMs: 5000,
    gateAnswerTimeoutMs: 70,
    timers: timers.api,
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

    const firstFrame = once(socket, "message");
    const firstResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "first"
    );
    const [rawFirst] = await firstFrame;
    const first = JSON.parse(rawFirst.toString());
    timers.runTimeoutByDelay(70);
    assert.deepEqual(await firstResult, {
      ok: false,
      error: "timed out waiting for gate answer receipt",
      code: GATE_ANSWER_ERROR_CODES.FAILED,
    });
    assert.equal(server.registry.pendingRequests.get(requestId)?.gateId, "g1");

    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: first.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));

    const retryFrame = once(socket, "message");
    const retryResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "retry"
    );
    const [rawRetry] = await retryFrame;
    const retry = JSON.parse(rawRetry.toString());
    assert.notEqual(retry.answerId, first.answerId);
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: retry.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));
    assert.deepEqual(await retryResult, { ok: true });
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    await resultPromise;
  } finally {
    await server.close();
  }
});

test("adversarial: answer receipts are fenced by exact socket, request, gate, and answer ids", async () => {
  const server = await startRegistry(
    new Map([
      ["host-a", "token-a"],
      ["host-b", "token-b"],
    ])
  );
  try {
    const socket = await server.connect("host-a", "token-a");
    const otherSocket = await server.connect("host-b", "token-b");
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
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_request",
        gateId: "g1",
        prompt: "p",
        kind: "question",
      },
    }));
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gateId === "g1"
    );

    const answerFrame = once(socket, "message");
    const answerResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "yes"
    );
    let answerSettled = false;
    answerResult.then(() => {
      answerSettled = true;
    });
    const [rawAnswer] = await answerFrame;
    const answer = JSON.parse(rawAnswer.toString());
    const receipt = (overrides = {}) => JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: answer.answerId,
        gateId: "g1",
        accepted: true,
        ...overrides,
      },
    });

    socket.send(receipt({ answerId: "different-answer" }));
    socket.send(receipt({ gateId: "different-gate" }));
    socket.send(JSON.stringify({
      type: "event",
      requestId: "different-request",
      event: {
        type: "gate_answer_result",
        answerId: answer.answerId,
        gateId: "g1",
        accepted: true,
      },
    }));
    otherSocket.send(receipt());
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.equal(answerSettled, false);
    assert.equal(server.registry.pendingGateAnswers.has(answer.answerId), true);
    assert.equal(server.registry.pendingRequests.get(requestId)?.gateId, "g1");

    socket.send(receipt());
    assert.deepEqual(await answerResult, { ok: true });
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    await resultPromise;
    otherSocket.terminate();
  } finally {
    await server.close();
  }
});

test("adversarial: disconnect settles an outstanding answer false and clears its timer", async () => {
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
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_request",
        gateId: "g1",
        prompt: "p",
        kind: "question",
      },
    }));
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gateId === "g1"
    );

    const answerFrame = once(socket, "message");
    const answerResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "yes"
    );
    await answerFrame;
    const closed = once(socket, "close");
    socket.terminate();
    await closed;

    assert.deepEqual(await answerResult, {
      ok: false,
      error: "host disconnected before gate answer was confirmed",
      code: GATE_ANSWER_ERROR_CODES.FAILED,
    });
    assert.equal(server.registry.pendingGateAnswers.size, 0);
    assert.equal((await resultPromise).ok, false);
  } finally {
    await server.close();
  }
});

test("adversarial: registry disposal settles an outstanding answer false", async () => {
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
    socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_request",
        gateId: "g1",
        prompt: "p",
        kind: "question",
      },
    }));
    await waitFor(
      () => server.registry.pendingRequests.get(requestId)?.gateId === "g1"
    );

    const answerFrame = once(socket, "message");
    const answerResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "yes"
    );
    await answerFrame;
    await server.close();

    assert.deepEqual(await answerResult, {
      ok: false,
      error: "host disconnected before gate answer was confirmed",
      code: GATE_ANSWER_ERROR_CODES.FAILED,
    });
    assert.equal(server.registry.pendingGateAnswers.size, 0);
    assert.equal((await resultPromise).ok, false);
  } finally {
    await server.close();
  }
});

test("adversarial: accepting a predecessor receipt preserves a successor gate", async () => {
  const server = await startRegistry();
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
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());
    const sendGate = (gateId) => socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_request",
        gateId,
        prompt: gateId,
        kind: "question",
      },
    }));
    const sendAccepted = (answer) => socket.send(JSON.stringify({
      type: "event",
      requestId,
      event: {
        type: "gate_answer_result",
        answerId: answer.answerId,
        gateId: answer.gateId,
        accepted: true,
      },
    }));

    sendGate("g1");
    await waitFor(() => gates.length === 1);
    const firstFrame = once(socket, "message");
    const firstResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g1",
      "first"
    );
    const [rawFirst] = await firstFrame;
    const first = JSON.parse(rawFirst.toString());

    sendGate("g2");
    await waitFor(() => gates.length === 2);
    assert.equal(server.registry.pendingRequests.get(requestId)?.gateId, "g2");
    sendAccepted(first);
    assert.deepEqual(await firstResult, { ok: true });
    assert.equal(server.registry.pendingRequests.get(requestId)?.gateId, "g2");
    assert.equal(
      server.registry.pendingRequests.get(requestId)?.gatePending,
      true
    );

    const secondFrame = once(socket, "message");
    const secondResult = server.registry.answerGate(
      "host-a",
      requestId,
      "g2",
      "second"
    );
    const [rawSecond] = await secondFrame;
    const second = JSON.parse(rawSecond.toString());
    sendAccepted(second);
    assert.deepEqual(await secondResult, { ok: true });
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.equal((await resultPromise).ok, true);
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
      "hostId", "mappingGeneration", "mappingId", "mappingVersion", "mapping",
      "sourcePlatform", "type", "workspaceGeneration", "workspaceId",
    ].sort());
    assert.deepEqual(bind.mapping, shared.mapping);
    assert.equal(bind.authorityFingerprint, bind.mapping.mappingFingerprint);
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

test("v3 connection-wide readiness fence rejects binding-to-host regression", async () => {
  const server = await startRegistry();
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    connection.socket.send(JSON.stringify(readinessFrame({
      socketGeneration: 9,
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
        code: "INVENTORY_PENDING",
        at: Date.now(),
        remediation: {
          code: "INVENTORY_PENDING",
          retryable: true,
          action: "retry_later",
        },
      },
    })));
    await waitFor(() =>
      server.registry.readinessStates.get("host-a")?.receiptPrevious?.revision === 2
    );
    const closed = once(connection.socket, "close");
    connection.socket.send(JSON.stringify(readinessFrame({
      socketGeneration: 9,
      revision: 1,
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
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await server.close();
  }
});

test("v3 connection-wide readiness fence rejects cross-binding regression", async () => {
  const server = await startRegistry();
  try {
    const firstRoute = managedRoute("a");
    const secondRoute = managedRoute("b");
    server.registry.setManagedRoutes({
      "channel-a": firstRoute,
      "channel-b": secondRoute,
    });
    const connection = await connectV3(server);
    const firstBind = await connection.nextFrame();
    const secondBind = await connection.nextFrame();
    const pending = (bind, route, revision) => readinessFrame({
      socketGeneration: 9,
      revision,
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
    });
    connection.socket.send(JSON.stringify(pending(firstBind, firstRoute, 2)));
    await waitFor(() =>
      server.registry.readinessStates.get("host-a")?.receiptPrevious?.revision === 2
    );
    const closed = once(connection.socket, "close");
    connection.socket.send(JSON.stringify(pending(secondBind, secondRoute, 1)));
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
    assert.equal(bindRequest.schemaVersion, 1);
    assert.equal(bindRequest.component, "bot");
    assert.ok(
      typeof bindRequest.bindingId === "string" && bindRequest.bindingId.length > 0
    );

    const bindOk = events.find((e) => e.event === "bind.ok");
    assert.equal(bindOk.phase, "bound");
    assert.equal(Object.isFrozen(bindOk), true);

    // Sentinel: only the bounded allowlist ever appears, and no full fingerprint,
    // token, workDir, or inventory bytes leak into any event.
    const allowedKeys = new Set([
      "event",
      "phase",
      "schemaVersion",
      "component",
      "observedAt",
      "requestAt",
      "deadlineAt",
      "code",
      "hostId",
      "mappingId",
      "bindingId",
      "workspaceId",
      "fenceSequence",
      "socketGeneration",
      "revision",
      "receivedAt",
      "expiresAt",
      "transactionId",
      "durationMs",
    ]);
    const allowedEvents = new Set([
      "bind.request",
      "bind.ok",
      "bind.negative",
      "receipt.invalidate",
      "socket.retire",
      "readiness.accept",
      "readiness.expire",
      "invoke.start",
      "invoke.finish",
      "invoke.deny",
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

test("a v3 socket replacement advances reconnect churn while an off-mode replacement holds it", async () => {
  const server = await startRegistry();
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const first = await connectV3(server);
    await first.nextFrame(); // drain the initial BIND_WORKSPACE so the socket is live
    assert.equal(server.registry.getHostReadiness("host-a").reconnectCount, 0);

    // A binding-capable (v3) registration replacing the live socket is churn.
    const second = await connectV3(server);
    await waitFor(
      () => server.registry.getHostReadiness("host-a").reconnectCount === 1
    );
    await second.nextFrame();

    // An off-mode (v2) registration replacing the live v3 socket must NOT advance it.
    const { socket: third } = await connectV2(server);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(server.registry.getHostReadiness("host-a").reconnectCount, 1);

    third.terminate();
    second.socket.terminate();
    first.socket.terminate();
  } finally {
    await server.close();
  }
});

test("a bind-deadline retirement emits exactly one socket.retire in the deadline phase", async () => {
  const events = [];
  const timers = createManualTimers();
  const server = await startRegistry(undefined, {
    timers: timers.api,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    await connection.nextFrame(); // BIND_WORKSPACE arms the bind deadline
    await waitFor(() => timers.timeoutDelays.includes(10_000));
    const closed = once(connection.socket, "close");
    timers.runTimeoutByDelay(10_000);
    await closed;
    await new Promise((resolve) => setImmediate(resolve));

    const retires = events.filter((e) => e.event === "socket.retire");
    assert.equal(retires.length, 1, "exactly one socket.retire for one physical retirement");
    assert.equal(retires[0].phase, "deadline");
    assert.equal(retires[0].code, "BINDING_DEADLINE");
    assert.equal(
      events.filter((e) => e.event === "socket.retire" && e.phase === "offline").length,
      0,
      "the offline-phase retire is suppressed after a deadline retirement"
    );
  } finally {
    await server.close();
  }
});

test("observability uses receiver-local readiness time and monotonic expiry", async () => {
  const events = [];
  const timers = createManualTimers();
  let wall = 10_000;
  let monotonic = 100;
  let monotonicSequence = [];
  const server = await startRegistry(undefined, {
    timers: timers.api,
    now: () => wall,
    monotonicNow: () =>
      monotonicSequence.length > 0
        ? monotonicSequence.shift()
        : monotonic,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      observedAt: 9_000,
      expiresAt: 10_000,
      ttlMs: 1_000,
    }));
    const accepted = events.find((event) => event.event === "readiness.accept");
    assert.equal(accepted.receivedAt, 10_000);
    assert.equal(accepted.expiresAt, 11_000);
    assert.equal(accepted.code, null);
    assert.equal(Object.isFrozen(accepted), true);
    assert.equal(server.registry.getObservabilitySnapshot().gauges["hosts.ready"], 1);

    wall = 1;
    monotonic = 1_099.5;
    monotonicSequence = [1_099.5, 1_100.5];
    timers.runTimeoutByDelay(1_000);
    assert.equal(
      events.filter((event) => event.event === "readiness.expire").length,
      0,
    );
    assert.equal(timers.timeoutDelays.includes(1), true);
    monotonicSequence = [];
    monotonic = 1_100.5;
    timers.runTimeoutByDelay(1);
    const expiredSnapshot = server.registry.getObservabilitySnapshot();
    const expired = events.filter((event) => event.event === "readiness.expire");
    assert.deepEqual(
      expired.map((event) => event.phase).sort(),
      ["host", "workspace"],
    );
    for (const event of expired) {
      assert.equal(event.code, PROTOCOL_ERROR_CODES.READINESS_EXPIRED);
      assert.equal(event.receivedAt, 10_000);
      assert.equal(event.expiresAt, 11_000);
      assert.equal(event.durationMs, 1_000);
    }
    assert.equal(
      expiredSnapshot.gauges["hosts.expired"],
      1,
      "one host is expired",
    );
    assert.equal(
      events.filter((event) => event.event === "readiness.expire").length,
      2,
      "one event is emitted for each armed host/workspace expiry",
    );
    socket.terminate();
  } finally {
    await server.close();
  }
});

test("invoke observability settles exactly once and exposes constant-shape gauges", async () => {
  const events = [];
  let monotonic = 50;
  const server = await startRegistry(undefined, {
    monotonicNow: () => monotonic,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const resultPromise = server.registry.invoke(
      "host-a",
      "/workspace/private",
      { kind: "prompt", message: "secret-prompt" },
      () => {},
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());
    const pending = server.registry.pendingRequests.get(requestId);
    assert.equal(server.registry.getObservabilitySnapshot().gauges["invokes.inFlight"], 1);
    const start = events.find((event) => event.event === "invoke.start");
    assert.equal(start.phase, "dispatch");
    assert.equal(start.code, null);
    assert.ok(/^[0-9a-f-]{36}$/.test(start.transactionId));

    monotonic = 75;
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await resultPromise, { ok: true, text: undefined , terminalDisposition: "completed"});
    pending.settle({ ok: false, error: "late-secret-error" }, "hard_cap");
    const finishes = events.filter((event) => event.event === "invoke.finish");
    assert.equal(finishes.length, 1);
    assert.equal(finishes[0].phase, "success");
    assert.equal(finishes[0].code, null);
    assert.equal(finishes[0].durationMs, 25);
    assert.equal(server.registry.getObservabilitySnapshot().gauges["invokes.inFlight"], 0);
    const serialized = JSON.stringify(events);
    assert.equal(serialized.includes("/workspace/private"), false);
    assert.equal(serialized.includes("secret-prompt"), false);
    assert.equal(serialized.includes("late-secret-error"), false);

    const remoteFrame = once(socket, "message");
    const remoteResult = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "remote-error" },
      () => {},
    );
    const [remoteRaw] = await remoteFrame;
    const remoteInvoke = JSON.parse(remoteRaw.toString());
    socket.send(JSON.stringify({
      type: "event",
      requestId: remoteInvoke.requestId,
      event: {
        type: "invoke_terminal",
        disposition: "failed",
        code: PROTOCOL_ERROR_CODES.CONFIG_INVALID,
      },
      done: true,
    }));
    assert.deepEqual(await remoteResult, {
      ok: false,
      error: {
        terminalDisposition: "failed",
        code: PROTOCOL_ERROR_CODES.CONFIG_INVALID,
        retryable: false,
        action: "contact_admin",
      },
    });
    const remoteFinish = events.filter(
      (event) => event.event === "invoke.finish",
    )[1];
    assert.equal(remoteFinish.phase, "remote_error");
    assert.equal(remoteFinish.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);

    const unknownFrame = once(socket, "message");
    const unknownResult = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "unknown-error" },
      () => {},
    );
    const [unknownRaw] = await unknownFrame;
    const unknownInvoke = JSON.parse(unknownRaw.toString());
    socket.send(JSON.stringify({
      type: "event",
      requestId: unknownInvoke.requestId,
      error: JSON.stringify({
        code: "ARBITRARY_AUTHENTICATED_CODE",
        retryable: false,
        action: "contact_admin",
      }),
    }));
    assert.equal((await unknownResult).ok, false);
    const unknownFinish = events.filter(
      (event) => event.event === "invoke.finish",
    )[2];
    assert.equal(unknownFinish.code, PROTOCOL_ERROR_CODES.CONNECTION_LOST);
    assert.equal(
      JSON.stringify(events).includes("ARBITRARY_AUTHENTICATED_CODE"),
      false,
    );
  } finally {
    await server.close();
  }
});

test("observability sink failures cannot disrupt readiness, invoke, or snapshots", async () => {
  const server = await startRegistry(undefined, {
    onObservabilityEvent: () => {
      throw new Error("sink-secret");
    },
  });
  try {
    const socket = await server.connect("host-a", "token-a");
    const invokeFrame = once(socket, "message");
    const result = server.registry.invoke(
      "host-a",
      "/workspace",
      { kind: "prompt", message: "hello" },
      () => {},
    );
    const [raw] = await invokeFrame;
    const { requestId } = JSON.parse(raw.toString());
    socket.send(JSON.stringify({ type: "event", requestId, event: { type: "invoke_terminal", disposition: "completed" }, done: true }));
    assert.deepEqual(await result, { ok: true, text: undefined , terminalDisposition: "completed"});
    const snapshot = server.registry.getObservabilitySnapshot();
    assert.equal(Object.isFrozen(snapshot), true);
    assert.equal(Object.isFrozen(snapshot.gauges), true);
    assert.deepEqual(Object.keys(snapshot.gauges), [
      "hosts.connected",
      "hosts.ready",
      "hosts.degraded",
      "hosts.expired",
      "invokes.inFlight",
      "resourceDenials.total",
      "socketReplacements.total",
    ]);
  } finally {
    await server.close();
  }
});

test("v3 receipt readiness retains local freshness and expires once", async () => {
  const events = [];
  const timers = createManualTimers();
  let wall = 20_000;
  let monotonic = 200;
  let monotonicSequence = [];
  const server = await startRegistry(undefined, {
    timers: timers.api,
    now: () => wall,
    monotonicNow: () =>
      monotonicSequence.length > 0
        ? monotonicSequence.shift()
        : monotonic,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    const inventoryGeneration = 1;
    const inventoryFingerprint = "b".repeat(64);
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
    await waitFor(() => events.some((event) => event.event === "bind.ok"));
    connection.socket.send(JSON.stringify(readinessFrame({
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      observedAt: 10_000,
      expiresAt: 20_000,
      ttlMs: 10_000,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint,
    })));
    await waitFor(() =>
      events.some(
        (event) =>
          event.event === "readiness.accept" && event.phase === "receipt",
      )
    );
    const accepted = events.find(
      (event) =>
        event.event === "readiness.accept" && event.phase === "receipt",
    );
    assert.equal(accepted.receivedAt, 20_000);
    assert.equal(accepted.expiresAt, 30_000);
    assert.equal(accepted.code, null);

    wall = 0;
    monotonic = 10_199.5;
    monotonicSequence = [10_199.5, 10_200.5];
    timers.runTimeoutByDelay(10_000);
    assert.equal(
      events.filter(
        (event) =>
          event.event === "readiness.expire" && event.phase === "receipt",
      ).length,
      0,
    );
    assert.equal(timers.timeoutDelays.includes(1), true);
    monotonicSequence = [];
    monotonic = 10_200.5;
    const snapshot = server.registry.getObservabilitySnapshot();
    const expired = events.filter(
      (event) =>
        event.event === "readiness.expire" && event.phase === "receipt",
    );
    assert.equal(expired.length, 1);
    assert.equal(expired[0].code, PROTOCOL_ERROR_CODES.READINESS_EXPIRED);
    assert.equal(expired[0].durationMs, 10_000);
    assert.equal(snapshot.gauges["hosts.expired"], 1);
    assert.equal(timers.timeoutDelays.includes(10_000), false);
    assert.equal(
      events.filter(
        (event) =>
          event.event === "readiness.expire" && event.phase === "receipt",
      ).length,
      1,
    );
    connection.socket.terminate();
  } finally {
    await server.close();
  }
});

test("bound v3 receipt events retain receipt-local fences and reject mismatched proof", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    workspaceServingEnabled: true,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    const inventoryGeneration = 1;
    const inventoryFingerprint = "c".repeat(64);
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
    await waitFor(() => events.some((event) => event.event === "bind.ok"));
    connection.socket.send(JSON.stringify(readinessFrame({
      socketGeneration: 9,
      revision: 4,
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint,
    })));
    await waitFor(() => events.some(
      (event) => event.event === "readiness.accept" && event.phase === "receipt"
    ));
    const accepted = events.find(
      (event) => event.event === "readiness.accept" && event.phase === "receipt"
    );
    assert.equal(accepted.socketGeneration, 9);
    assert.equal(accepted.revision, 4);

    const invokeFrame = once(connection.socket, "message");
    const invokeRoute = {
      bindingId: bind.bindingId,
      mappingId: route.mappingId,
      mappingGeneration: route.mappingGeneration,
      mappingVersion: route.mappingVersion,
      sourcePlatform: route.sourcePlatform,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      authority: route.authority,
    };
    const invokeResult = server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "correlated" },
      () => {},
      1_000,
      undefined,
      invokeRoute,
    );
    const [invokeRaw] = await invokeFrame;
    const invoke = JSON.parse(invokeRaw.toString());
    assert.equal(Object.hasOwn(invoke, "transactionId"), false);
    const start = events.find((event) => event.event === "invoke.start");
    assert.equal(start.socketGeneration, 9);
    assert.equal(start.revision, 4);
    connection.socket.send(JSON.stringify(readinessFrame({
      socketGeneration: 9,
      revision: 5,
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      inventoryGeneration,
      inventoryFingerprint,
      bindingFingerprint,
    })));
    await waitFor(() =>
      events.filter(
        (event) =>
          event.event === "readiness.accept" && event.phase === "receipt",
      ).length === 2
    );
    invokeRoute.mappingId = "attacker-mutated";
    invokeRoute.workspaceId = "attacker-mutated";
    connection.socket.send(JSON.stringify({
      type: "event",
      requestId: invoke.requestId,
      event: { type: "invoke_terminal", disposition: "completed" }, done: true,
    }));
    assert.deepEqual(await invokeResult, { ok: true, text: undefined , terminalDisposition: "completed"});
    const finish = events.find((event) => event.event === "invoke.finish");
    for (const key of [
      "bindingId",
      "mappingId",
      "workspaceId",
      "fenceSequence",
      "socketGeneration",
      "revision",
    ]) {
      assert.equal(finish[key], start[key], `${key} is frozen at dispatch`);
    }
    assert.equal(finish.revision, 4);

    const closed = once(connection.socket, "close");
    connection.socket.send(JSON.stringify(readinessFrame({
      socketGeneration: 9,
      revision: 6,
      bindingId: bind.bindingId,
      workspaceId: route.workspaceId,
      workspaceGeneration: route.workspaceGeneration,
      ttlMs: 10_000,
      inventoryGeneration,
      inventoryFingerprint: "d".repeat(64),
      bindingFingerprint,
    })));
    await closed;
    assert.equal(
      events.filter((event) => event.event === "readiness.accept" && event.phase === "receipt").length,
      2,
    );
  } finally {
    await server.close();
  }
});

test("managed invoke never borrows host fences before binding readiness", async () => {
  const events = [];
  const server = await startRegistry(undefined, {
    workspaceServingEnabled: true,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const route = managedRoute("a");
    server.registry.setManagedRoutes({ "channel-a": route });
    const connection = await connectV3(server);
    const bind = await connection.nextFrame();
    connection.socket.send(JSON.stringify(readinessFrame({
      socketGeneration: 9,
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
    const inventoryGeneration = 1;
    const inventoryFingerprint = "e".repeat(64);
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
    await waitFor(() =>
      server.registry.getManagedRouteBinding("channel-a")?.state === "bound"
    );

    const invokeFrame = once(connection.socket, "message");
    const result = server.registry.invoke(
      "host-a",
      null,
      { kind: "prompt", message: "no borrowed fence" },
      () => {},
      1_000,
      undefined,
      {
        bindingId: bind.bindingId,
        mappingId: route.mappingId,
        mappingGeneration: route.mappingGeneration,
        mappingVersion: route.mappingVersion,
        sourcePlatform: route.sourcePlatform,
        workspaceId: route.workspaceId,
        workspaceGeneration: route.workspaceGeneration,
        authority: route.authority,
      },
    );
    const [raw] = await invokeFrame;
    const invoke = JSON.parse(raw.toString());
    const start = events.find((event) => event.event === "invoke.start");
    assert.equal(Object.hasOwn(start, "socketGeneration"), false);
    assert.equal(Object.hasOwn(start, "revision"), false);
    connection.socket.send(JSON.stringify({
      type: "event",
      requestId: invoke.requestId,
      event: { type: "invoke_terminal", disposition: "completed" }, done: true,
    }));
    await result;
  } finally {
    await server.close();
  }
});

test("host-only readiness does not replace workspace freshness metadata", async () => {
  const events = [];
  const timers = createManualTimers();
  let wall = 10_000;
  let monotonic = 100;
  const server = await startRegistry(undefined, {
    timers: timers.api,
    now: () => wall,
    monotonicNow: () => monotonic,
    onObservabilityEvent: (event) => events.push(event),
  });
  try {
    const { socket } = await connectV2(server);
    await sendReadiness(socket, readinessFrame({
      socketGeneration: 1,
      revision: 1,
      observedAt: 10_000,
      ttlMs: 1_000,
      workspaceId: "workspace-a",
      workspaceGeneration: 1,
    }));
    wall = 10_100;
    monotonic = 200;
    await sendReadiness(socket, readinessFrame({
      socketGeneration: 1,
      revision: 2,
      observedAt: 10_100,
      ttlMs: 5_000,
      workspaceId: undefined,
      workspaceGeneration: undefined,
    }));
    monotonic = 1_100;
    server.registry.getObservabilitySnapshot();
    const workspaceExpiry = events.find(
      (event) => event.event === "readiness.expire" && event.phase === "workspace"
    );
    assert.equal(workspaceExpiry.workspaceId, "workspace-a");
    assert.equal(workspaceExpiry.revision, 1);
    assert.equal(workspaceExpiry.receivedAt, 10_000);
    socket.terminate();
  } finally {
    await server.close();
  }
});
