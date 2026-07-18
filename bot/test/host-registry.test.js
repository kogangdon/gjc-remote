import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import WebSocket from "ws";
import {
  MAX_WS_PAYLOAD_BYTES,
  V0_LIMITS,
  isEventMessage,
  isInvokeMessage,
  isModelName,
  isRegisterMessage,
} from "@gjc-remote/shared";
import { HostRegistry } from "../src/host-registry.js";

async function startRegistry(tokens = new Map([["host-a", "token-a"]])) {
  const registry = new HostRegistry({ port: 0, tokensByHostId: tokens });
  if (!registry.wss.address()) await once(registry.wss, "listening");
  const { port } = registry.wss.address();
  const clients = [];

  return {
    registry,
    async connect(hostId, token) {
      const socket = new WebSocket(`ws://127.0.0.1:${port}`);
      clients.push(socket);
      await once(socket, "open");
      const response = once(socket, "message");
      socket.send(JSON.stringify({ type: "register", hostId, token }));
      const [raw] = await response;
      assert.deepEqual(JSON.parse(raw.toString()), { type: "register_ok" });
      return socket;
    },
    async close() {
      for (const client of clients) client.terminate();
      await new Promise((resolve, reject) => {
        registry.wss.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

async function expectPolicyClose(socket, payload) {
  const closed = once(socket, "close");
  socket.send(payload);
  const [code] = await closed;
  assert.equal(code, 1008);
}

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
