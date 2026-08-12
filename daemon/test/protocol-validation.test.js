import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  CAPABILITIES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PROTOCOL_VERSION,
  PROTOCOL_VERSION_V2,
  PROTOCOL_ERROR_CODES,
  READINESS_REMEDIATIONS,
  V0_LIMITS,
  READINESS_DEFAULT_TTL_MS,
  READINESS_DIMENSIONS,
  READINESS_MAX_TTL_MS,
  READINESS_MIN_TTL_MS,
  READINESS_STATUS_VALUES,
  WORKSPACE_ID_MAX_LENGTH,
  WORKSPACE_READINESS_CAPABILITY,
  isAnswerMessage,
  isBindOkMessage,
  isBindWorkspaceMessage,
  isEventMessage,
  isGateRequestEvent,
  isInvokeMessage,
  isReadinessCapabilityGate,
  isReadinessMessage,
  isReadinessStatus,
  isReadinessTtl,
  normalizeReadinessTtl,
  isRegisterMessage,
  isRegisterOkMessage,
  isWorkspaceId,
  normalizeProtocolError,
} from "@gjc-remote/shared";
import { WebSocketServer } from "ws";

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const CHILD_EXIT_TIMEOUT_MS = 2_000;

const validBinding = {
  type: MSG_TYPES.BIND_WORKSPACE,
  bindingId: "binding-1",
  hostId: "test-host",
  mappingId: "mapping-1",
  mappingGeneration: 2,
  mappingVersion: 1,
  workspaceId: "workspace-1",
  workspaceGeneration: 3,
  sourcePlatform: "posix",
  routeFingerprint: "a".repeat(64),
  authorityFingerprint: "b".repeat(64),
  inventoryGeneration: 4,
};

test("workspace binding is path-free and validates the complete identity tuple", () => {
  assert.equal(isBindWorkspaceMessage(validBinding), true);
  assert.equal(
    isBindOkMessage({
      type: MSG_TYPES.BIND_OK,
      bindingId: "binding-1",
      bindingFingerprint: "c".repeat(64),
    }),
    true
  );

  for (const field of [
    "bindingId",
    "mappingId",
    "workspaceId",
    "routeFingerprint",
    "authorityFingerprint",
    "inventoryGeneration",
  ]) {
    const invalid = { ...validBinding };
    invalid[field] = field.endsWith("Fingerprint") ? "not-a-fingerprint" : "../escape";
    assert.equal(isBindWorkspaceMessage(invalid), false, field);
  }
  assert.equal(
    isBindWorkspaceMessage({ ...validBinding, workDir: "/srv/workspace" }),
    false,
    "managed binding must not carry a path"
  );
});

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

async function startDaemon(extraEnv = {}) {
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
      ...extraEnv,
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
    register,
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

test("daemon accepts path-free workspace binding without promoting readiness", async () => {
  const daemon = await startDaemon({ GJC_READINESS_V2: "1" });
  try {
    const registerOk = new Promise((resolve) =>
      daemon.peer.once("message", (raw) => resolve(JSON.parse(raw.toString())))
    );
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    assert.equal((await registerOk).type, MSG_TYPES.READINESS);

    const bindOk = new Promise((resolve) => {
      const onMessage = (raw) => {
        const message = JSON.parse(raw.toString());
        if (message.type === MSG_TYPES.BIND_OK) {
          daemon.peer.off("message", onMessage);
          resolve(message);
        }
      };
      daemon.peer.on("message", onMessage);
    });
    daemon.peer.send(JSON.stringify(validBinding));
    const response = await bindOk;
    assert.equal(response.type, MSG_TYPES.BIND_OK);
    assert.equal(response.bindingId, validBinding.bindingId);
  } finally {
    await daemon.close();
  }
});

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

test("daemon advertises protocol version and capabilities in its register frame", async () => {
  const daemon = await startDaemon();
  try {
    // startDaemon() captures the first register frame from the child daemon.
    assert.equal(daemon.register.protocolVersion, PROTOCOL_VERSION);
    assert.deepEqual(daemon.register.capabilities, [...CAPABILITIES]);
    assert.equal(isRegisterMessage(daemon.register), true);
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
  } finally {
    await daemon.close();
  }
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
test("isAnswerMessage accepts a well-formed answer and rejects malformed ones (#35)", () => {
  assert.equal(
    isAnswerMessage({
      type: "answer",
      requestId: "request-1",
      gateId: "gate-1",
      answer: "yes",
    }),
    true
  );
  // Empty answer is allowed (a user may send an empty selection the daemon maps/rejects).
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "r", gateId: "g", answer: "" }),
    true
  );
  assert.equal(isAnswerMessage(null), false);
  assert.equal(isAnswerMessage({ type: "answer" }), false);
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "r", gateId: "g" }),
    false,
    "missing answer"
  );
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "", gateId: "g", answer: "x" }),
    false,
    "empty requestId"
  );
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "r", gateId: "", answer: "x" }),
    false,
    "empty gateId"
  );
  assert.equal(
    isAnswerMessage({
      type: "answer",
      requestId: "r",
      gateId: "x".repeat(V0_LIMITS.GATE_ID + 1),
      answer: "x",
    }),
    false,
    "oversized gateId"
  );
  assert.equal(
    isAnswerMessage({
      type: "answer",
      requestId: "r",
      gateId: "g",
      answer: "x".repeat(V0_LIMITS.MESSAGE + 1),
    }),
    false,
    "oversized answer"
  );
  assert.equal(
    isAnswerMessage({ type: "invoke", requestId: "r", gateId: "g", answer: "x" }),
    false,
    "wrong type"
  );
});

test("isGateRequestEvent validates the gate_request event subtype incl. bounds and choices (#35)", () => {
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      requestId: "request-1",
      gateId: "gate-1",
      prompt: "Pick one",
      kind: "question",
      choices: [
        { value: 0, label: "First" },
        { value: "b", label: "Second" },
      ],
    }),
    true
  );
  // requestId and choices are optional.
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "Approve?",
      kind: "approval",
    }),
    true
  );
  assert.equal(isGateRequestEvent({ type: "gate_request", gateId: "g", prompt: "p", kind: "execution" }), true);
  assert.equal(isGateRequestEvent(null), false);
  assert.equal(
    isGateRequestEvent({ type: "gate_request", gateId: "g", prompt: "p", kind: "bogus" }),
    false,
    "unknown kind"
  );
  assert.equal(
    isGateRequestEvent({ type: "gate_request", gateId: "", prompt: "p", kind: "question" }),
    false,
    "empty gateId"
  );
  assert.equal(
    isGateRequestEvent({ type: "gate_request", gateId: "g", prompt: "", kind: "question" }),
    false,
    "empty prompt"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "x".repeat(V0_LIMITS.GATE_PROMPT + 1),
      kind: "question",
    }),
    false,
    "oversized prompt"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      requestId: "",
    }),
    false,
    "present but empty requestId"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: "not-an-array",
    }),
    false,
    "choices must be an array"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: Array.from({ length: V0_LIMITS.MAX_CHOICES + 1 }, (_, i) => ({
        value: i,
        label: `c${i}`,
      })),
    }),
    false,
    "too many choices"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: [{ label: "missing value" }],
    }),
    false,
    "choice missing value"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: [{ value: 1, label: 123 }],
    }),
    false,
    "choice label must be a string"
  );
});

test("adding #35 message types does not break backward-compat validators", () => {
  // MSG_TYPES additions are present and additive.
  assert.equal(MSG_TYPES.ANSWER, "answer");
  assert.equal(MSG_TYPES.GATE_REQUEST, "gate_request");

  // A gate_request rides inside an EventMessage's `event` payload; isEventMessage
  // still accepts it as a normal event (it only requires event to be an object).
  const gateRequest = {
    type: "gate_request",
    gateId: "g",
    prompt: "p",
    kind: "question",
  };
  assert.equal(
    isEventMessage({ type: "event", requestId: "r", event: gateRequest }),
    true
  );

  // An unrecognized/new top-level type must not crash or be misclassified by the
  // legacy validators — a v0 peer safely ignores it.
  assert.equal(isEventMessage({ type: "answer", requestId: "r", gateId: "g", answer: "y" }), false);
  assert.equal(isInvokeMessage({ type: "answer", requestId: "r", gateId: "g", answer: "y" }), false);
  assert.equal(isAnswerMessage({ type: "event", requestId: "r", event: {} }), false);
  assert.equal(isGateRequestEvent({ type: "event", requestId: "r" }), false);
});
function makeReadinessFrame(overrides = {}) {
  return {
    type: MSG_TYPES.READINESS,
    socketGeneration: 1,
    revision: 1,
    observedAt: Date.now(),
    status: {
      connection: "online",
      runtime: "ready",
      providerAuth: "configured",
      modelProfile: "ready",
      workspace: "ready",
    },
    ...overrides,
  };
}

test("workspace readiness validates bounded opaque IDs and generation pairing", () => {
  assert.equal(isWorkspaceId("workspace-1"), true);
  assert.equal(isWorkspaceId("ws_01.alpha"), true);
  assert.equal(isWorkspaceId(""), false);
  assert.equal(isWorkspaceId("../escape"), false);
  assert.equal(isWorkspaceId("workspace/name"), false);
  assert.equal(isWorkspaceId("workspace\\name"), false);
  assert.equal(isWorkspaceId("workspace name"), false);
  assert.equal(isWorkspaceId("workspace\nname"), false);
  assert.equal(isWorkspaceId("x".repeat(WORKSPACE_ID_MAX_LENGTH + 1)), false);

  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ workspaceId: "workspace-1", workspaceGeneration: 7 })
    ),
    true
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ workspaceId: "workspace-1" })),
    false,
    "workspaceId requires workspaceGeneration"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ workspaceGeneration: 7 })),
    false,
    "workspaceGeneration cannot be host-level"
  );
});

test("readiness validates all five dimensions and every documented status value", () => {
  assert.deepEqual(READINESS_DIMENSIONS, [
    "connection",
    "runtime",
    "providerAuth",
    "modelProfile",
    "workspace",
  ]);
  assert.equal(isReadinessStatus(makeReadinessFrame().status), true);

  for (const dimension of READINESS_DIMENSIONS) {
    for (const status of READINESS_STATUS_VALUES[dimension]) {
      const frame = makeReadinessFrame();
      frame.status[dimension] = status;
      assert.equal(
        isReadinessMessage(frame),
        true,
        `${dimension}=${status} should be valid`
      );
    }
  }

  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({
        status: { ...makeReadinessFrame().status, runtime: "unknown" },
      })
    ),
    false,
    "unknown dimension value"
  );
  assert.equal(
    isReadinessStatus({
      ...makeReadinessFrame().status,
      unexpected: "ready",
    }),
    false,
    "unknown dimension"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ status: { connection: "online" } })),
    false,
    "missing dimensions"
  );
});

test("readiness enforces TTL bounds/default and bounded frame fields", () => {
  assert.equal(isReadinessTtl(READINESS_MIN_TTL_MS), true);
  assert.equal(isReadinessTtl(READINESS_MAX_TTL_MS), true);
  assert.equal(isReadinessTtl(READINESS_MIN_TTL_MS - 1), false);
  assert.equal(isReadinessTtl(READINESS_MAX_TTL_MS + 1), false);
  assert.equal(isReadinessTtl(1.5), false);
  assert.equal(normalizeReadinessTtl(undefined), READINESS_DEFAULT_TTL_MS);

  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MIN_TTL_MS })),
    true
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MAX_TTL_MS })),
    true
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MIN_TTL_MS - 1 })),
    false
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MAX_TTL_MS + 1 })),
    false
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ observedAt: "2026-08-03T00:00:00.000Z" })),
    false,
    "timestamps are bounded numeric wire values"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ revision: 0 })),
    false,
    "revision starts at one"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ socketGeneration: Number.MAX_SAFE_INTEGER + 1 })),
    false,
    "socket generation is a safe integer"
  );
});

test("readiness revision fences accept only newer data on the current socket", () => {
  const previous = makeReadinessFrame({ socketGeneration: 4, revision: 10 });
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 4, revision: 11 }),
      { currentSocketGeneration: 4, previous }
    ),
    true
  );
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 4, revision: 10 }),
      { currentSocketGeneration: 4, previous }
    ),
    false,
    "duplicate revision"
  );
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 4, revision: 9 }),
      { currentSocketGeneration: 4, previous }
    ),
    false,
    "lower revision"
  );
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 3, revision: 11 }),
      { currentSocketGeneration: 4, previous }
    ),
    false,
    "old socket generation"
  );
});

test("readiness capability gate requires both bounded v2 register frames", () => {
  const register = {
    type: "register",
    hostId: "host-1",
    token: "token-1",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };
  const registerOk = {
    type: "register_ok",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };
  assert.equal(isReadinessCapabilityGate(register, registerOk), true);
  assert.equal(isReadinessCapabilityGate({ register, registerOk }), true);
  assert.equal(
    isReadinessCapabilityGate(
      { ...register, capabilities: [...CAPABILITIES] },
      registerOk
    ),
    false,
    "register advertisement is required"
  );
  assert.equal(
    isReadinessCapabilityGate(register, { ...registerOk, capabilities: [] }),
    false,
    "register response capability is required"
  );
  assert.equal(
    isReadinessCapabilityGate(register, { ...registerOk, protocolVersion: PROTOCOL_VERSION }),
    false,
    "protocol v1 cannot commit v2"
  );
  assert.equal(
    isReadinessCapabilityGate(register, { type: "register_ok" }),
    false,
    "missing response negotiation fields fail closed"
  );
});
test("protocol negotiation rejects future versions and never down-negotiates readiness", () => {
  const register = {
    type: "register",
    hostId: "host-1",
    token: "token-1",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };
  const registerOk = {
    type: "register_ok",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };

  assert.equal(
    isRegisterMessage({ ...register, protocolVersion: PROTOCOL_VERSION_V2 + 1 }),
    false
  );
  assert.equal(
    isRegisterOkMessage({ ...registerOk, protocolVersion: PROTOCOL_VERSION_V2 + 1 }),
    false
  );
  assert.equal(
    isReadinessCapabilityGate(
      { ...register, protocolVersion: PROTOCOL_VERSION_V2 + 1 },
      registerOk
    ),
    false
  );
  assert.equal(
    isReadinessCapabilityGate(register, {
      ...registerOk,
      protocolVersion: PROTOCOL_VERSION_V2 + 1,
    }),
    false
  );
  assert.equal(
    isReadinessCapabilityGate({
      negotiatedVersion: PROTOCOL_VERSION_V2 + 1,
      localCapabilities: [WORKSPACE_READINESS_CAPABILITY],
      remoteCapabilities: [WORKSPACE_READINESS_CAPABILITY],
    }),
    false
  );
  assert.equal(
    isRegisterMessage({ ...register, protocolVersion: "2" }),
    false,
    "version strings are malformed"
  );
  assert.equal(
    isRegisterOkMessage({ ...registerOk, protocolVersion: null }),
    false,
    "null versions are malformed"
  );
});

test("v2 invoke identity is bounded, exact, and gated from legacy sockets", () => {
  const command = { kind: "prompt", message: "hello" };
  const legacy = {
    type: "invoke",
    requestId: "request-1",
    workDir: "/workspace",
    command,
  };
  assert.equal(isInvokeMessage(legacy), true);

  for (const field of [
    "mappingId",
    "mappingGeneration",
    "mappingVersion",
    "workspaceId",
    "workspaceGeneration",
  ]) {
    assert.equal(
      isInvokeMessage({ ...legacy, [field]: field === "mappingId" ? "mapping-1" : 1 }),
      false,
      `${field} is reserved before v2 capability commit`
    );
  }

  const valid = {
    type: "invoke",
    requestId: "request-2",
    mappingId: "mapping-1",
    mappingGeneration: 2,
    mappingVersion: 3,
    command,
  };
  assert.equal(isInvokeMessage(valid, { v2: true }), true);
  assert.equal(
    isInvokeMessage({ ...valid, workspaceId: "workspace-1" }, { v2: true }),
    true
  );
  assert.equal(
    isInvokeMessage({ ...valid, workDir: "/workspace" }, { v2: true }),
    true
  );
  assert.equal(
    isInvokeMessage(
      { ...valid, workspaceId: "workspace-1", workDir: "workspace-1" },
      { v2: true }
    ),
    true
  );
  assert.equal(
    isInvokeMessage(
      { ...valid, workspaceId: "workspace-1", workDir: "other-workspace" },
      { v2: true }
    ),
    true,
    "canonical mapping resolution, not string equality, binds workspaceId to workDir"
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingId: "../escape" }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingId: "x".repeat(129) }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingGeneration: 0 }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingGeneration: 1.5 }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingVersion: Number.MAX_SAFE_INTEGER + 1 }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, futureMappingField: "ignored" }, { v2: true }),
    false,
    "unknown v2 fields are not silently ignored"
  );
});

test("readiness remediation tuples are canonical and stable", () => {
  const expected = {
    [PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID]: {
      code: PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID,
      retryable: false,
      action: "contact_admin",
    },
    [PROTOCOL_ERROR_CODES.READINESS_REPLAYED]: {
      code: PROTOCOL_ERROR_CODES.READINESS_REPLAYED,
      retryable: false,
      action: "contact_admin",
    },
    [PROTOCOL_ERROR_CODES.CONNECTION_LOST]: {
      code: PROTOCOL_ERROR_CODES.CONNECTION_LOST,
      retryable: true,
      action: "retry_later",
    },
    [PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND]: {
      code: PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
      retryable: false,
      action: "refresh_workspace",
    },
    [PROTOCOL_ERROR_CODES.PROVIDER_MISSING]: {
      code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
      retryable: true,
      action: "login",
    },
    [PROTOCOL_ERROR_CODES.PROVIDER_INVALID]: {
      code: PROTOCOL_ERROR_CODES.PROVIDER_INVALID,
      retryable: false,
      action: "repair_profile",
    },
    [PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING]: {
      code: PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING,
      retryable: false,
      action: "repair_profile",
    },
    [PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID]: {
      code: PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID,
      retryable: false,
      action: "repair_profile",
    },
  };
  for (const [code, tuple] of Object.entries(expected)) {
    assert.deepEqual(READINESS_REMEDIATIONS[code], tuple);
    assert.equal(Object.isFrozen(READINESS_REMEDIATIONS[code]), true);
  }
});
