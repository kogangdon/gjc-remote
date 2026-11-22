import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import WebSocket from "ws";
import { CAPABILITIES, MSG_TYPES, PROTOCOL_VERSION } from "@gjc-remote/shared";
import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import {
  SDK_PROFILE_MANAGEMENT_CAPABILITY,
  SDK_PROFILE_MANAGEMENT_LIMITS,
  SDK_PROFILE_MANAGEMENT_TYPES,
  buildSdkProfileManagementRequest,
  buildSdkProfileManagementResult,
  isPublicSdkProfileDecision,
  isSdkProfileManagementRequest,
  isSdkProfileManagementResult,
  parseSdkProfileManagementRequest,
  parseSdkProfileManagementResult,
  sdkProfileDecisionFingerprint,
  validateSdkProfileManagementRequest,
  validateSdkProfileManagementResult,
} from "@gjc-remote/shared/sdk-profile-management.js";
import { HostRegistry } from "../src/host-registry.js";

const candidateId = "a".repeat(64);
const capabilities = [...CAPABILITIES, SDK_PROFILE_MANAGEMENT_CAPABILITY];
const absent = { version: 1, grantId: null, allowed: false, profileFingerprint: null };
const allowed = { version: 1, grantId: 1, allowed: true, profileFingerprint: candidateId };
const withdrawn = { ...allowed, allowed: false };

function request(operation = "status", fields = {}) {
  return buildSdkProfileManagementRequest({ requestId: "management-1", operation, ...fields });
}

function reply(frame, decision = absent, fields = {}) {
  return buildSdkProfileManagementResult({
    requestId: frame.requestId,
    operation: frame.operation,
    ok: true,
    decision,
    decisionFingerprint: sdkProfileDecisionFingerprint(decision),
    ...(frame.operation === "status" ? { candidateId } : {}),
    ...fields,
  }, frame);
}

async function nextFrame(socket) {
  const [raw] = await once(socket, "message", { signal: AbortSignal.timeout(5000) });
  return JSON.parse(raw.toString());
}

async function fixture(t, options = {}) {
  const registry = new HostRegistry({
    port: 0,
    tokensByHostId: new Map([["host-a", "token-a"], ["host-b", "token-b"]]),
    ...options,
  });
  t.after(() => registry.close());
  if (!registry.wss.address()) await once(registry.wss, "listening");
  return {
    registry,
    async connect(hostId = "host-a", offered = capabilities, version = PROTOCOL_VERSION) {
      const socket = new WebSocket(`ws://127.0.0.1:${registry.wss.address().port}`);
      await once(socket, "open");
      const registered = nextFrame(socket);
      socket.send(JSON.stringify({
        type: "register",
        hostId,
        token: hostId === "host-a" ? "token-a" : "token-b",
        protocolVersion: version,
        capabilities: offered,
      }));
      const frame = await registered;
      assert.equal(frame.type, MSG_TYPES.REGISTER_OK);
      assert.equal(frame.capabilities.includes(SDK_PROFILE_MANAGEMENT_CAPABILITY),
        offered.includes(SDK_PROFILE_MANAGEMENT_CAPABILITY));
      return socket;
    },
  };
}

function manualTimers() {
  const timeouts = new Map();
  return {
    api: {
      setInterval: () => ({ unref() {} }),
      clearInterval() {},
      setTimeout(callback) {
        const handle = { unref() {} };
        timeouts.set(handle, callback);
        return handle;
      },
      clearTimeout: (handle) => timeouts.delete(handle),
    },
    fire(handle) {
      const callback = timeouts.get(handle);
      assert.equal(typeof callback, "function");
      timeouts.delete(handle);
      callback();
    },
    get count() { return timeouts.size; },
  };
}

test("management requests are exact, path-free, and require full CAS fingerprints", () => {
  const status = request();
  const allow = request("allow", {
    candidateId,
    expectedDecisionFingerprint: sdkProfileDecisionFingerprint(absent),
  });
  const withdraw = request("withdraw", {
    expectedDecisionFingerprint: sdkProfileDecisionFingerprint(allowed),
  });
  for (const frame of [status, allow, withdraw]) {
    assert.equal(isSdkProfileManagementRequest(frame), true);
    assert.deepEqual(parseSdkProfileManagementRequest(Buffer.from(JSON.stringify(frame))), frame);
  }
  for (const invalid of [
    { ...status, workDir: "/private/home" },
    { ...allow, profile: { agentDir: "/private/home" } },
    { ...allow, actorPrincipal: "owner" },
    { ...allow, candidateId: "/private/home" },
    { ...allow, candidateId: "a".repeat(65) },
    { ...allow, expectedDecisionFingerprint: 1 },
    { ...allow, expectedDecisionFingerprint: null },
    { ...allow, expectedDecisionFingerprint: undefined },
    { ...withdraw, candidateId },
    { ...status, operation: "invoke" },
    { ...status, requestId: "../management" },
    { ...status, requestId: "m".repeat(129) },
    { ...status, version: 2 },
  ]) {
    assert.equal(isSdkProfileManagementRequest(invalid), false);
    assert.throws(() => validateSdkProfileManagementRequest(invalid),
      { message: "SDK_PROFILE_MANAGEMENT_INVALID" });
  }
});

test("CAS fingerprints cover grant, allow/withdraw, and complete profile identity", () => {
  const decisions = [
    absent,
    allowed,
    withdrawn,
    { ...allowed, grantId: 2 },
    { ...allowed, profileFingerprint: "b".repeat(64) },
  ];
  const fingerprints = decisions.map(sdkProfileDecisionFingerprint);
  assert.equal(new Set(fingerprints).size, decisions.length);
  for (let index = 0; index < decisions.length; index++) {
    assert.equal(fingerprints[index], canonicalJsonHash(decisions[index]));
  }
  for (const invalid of [
    { ...absent, allowed: true },
    { ...absent, profileFingerprint: candidateId },
    { ...allowed, grantId: 0 },
    { ...allowed, grantId: Number.MAX_SAFE_INTEGER + 1 },
    { ...allowed, grantId: 1.5 },
    { ...allowed, profileFingerprint: null },
    { ...allowed, agentDir: "/private/home" },
  ]) {
    assert.equal(isPublicSdkProfileDecision(invalid), false);
    assert.throws(() => sdkProfileDecisionFingerprint(invalid),
      { message: "SDK_PROFILE_MANAGEMENT_INVALID" });
  }
});

test("replies bind operation, selected candidate, full public decision, and bounded error codes", () => {
  const allow = request("allow", {
    candidateId,
    expectedDecisionFingerprint: sdkProfileDecisionFingerprint(absent),
  });
  const valid = reply(allow, allowed);
  const wrongCandidate = { ...allowed, profileFingerprint: "b".repeat(64) };
  assert.deepEqual(parseSdkProfileManagementResult(Buffer.from(JSON.stringify(valid)), allow), valid);
  for (const invalid of [
    { ...valid, requestId: "management-2" },
    { ...valid, operation: "withdraw" },
    { ...valid, decisionFingerprint: candidateId },
    { ...valid, decision: withdrawn, decisionFingerprint: sdkProfileDecisionFingerprint(withdrawn) },
    { ...valid, decision: wrongCandidate, decisionFingerprint: sdkProfileDecisionFingerprint(wrongCandidate) },
  ]) {
    assert.equal(isSdkProfileManagementResult(invalid, allow), false);
  }
  const conflict = buildSdkProfileManagementResult({
    requestId: allow.requestId, operation: "allow", ok: false, code: "DECISION_CONFLICT",
  }, allow);
  assert.equal(isSdkProfileManagementResult(conflict, allow), true);
  for (const invalid of [
    { ...conflict, code: "/private/auth.json: secret" },
    { ...conflict, message: "private error" },
    { ...valid, candidateId },
    { ...valid, paths: ["/private/home"] },
  ]) {
    assert.equal(isSdkProfileManagementResult(invalid, allow), false);
    assert.throws(() => validateSdkProfileManagementResult(invalid, allow),
      { message: "SDK_PROFILE_MANAGEMENT_INVALID" });
  }
});

test("wire parsing rejects duplicate fields, malformed UTF-8, and oversized frames", () => {
  const status = request();
  const duplicate = JSON.stringify(status).replace('"operation":"status"',
    '"operation":"status","operation":"status"');
  assert.throws(() => parseSdkProfileManagementRequest(Buffer.from(duplicate)));
  assert.throws(() => parseSdkProfileManagementRequest(Buffer.from([0xff])));
  assert.throws(() => parseSdkProfileManagementRequest(
    Buffer.from(`${JSON.stringify(status)}${" ".repeat(SDK_PROFILE_MANAGEMENT_LIMITS.maxBytes)}`)
  ));
  const result = JSON.stringify(reply(status));
  assert.throws(() => parseSdkProfileManagementResult(
    Buffer.from(result.replace('"ok":true', '"ok":true,"ok":true'))
  ));
});

test("management status, allow, and withdrawal never allocate SDK invocations", async (t) => {
  const { registry, connect } = await fixture(t, {
    requestIdFactory() { throw new Error("SDK invocation must not be allocated"); },
  });
  const socket = await connect();
  for (const [operation, decision] of [
    [{ operation: "status" }, absent],
    [{ operation: "allow", candidateId,
      expectedDecisionFingerprint: sdkProfileDecisionFingerprint(absent) }, allowed],
    [{ operation: "withdraw",
      expectedDecisionFingerprint: sdkProfileDecisionFingerprint(allowed) }, withdrawn],
  ]) {
    const incoming = nextFrame(socket);
    const outcome = registry.manageSdkProfile("host-a", operation);
    const frame = await incoming;
    assert.equal(frame.type, SDK_PROFILE_MANAGEMENT_TYPES.REQUEST);
    assert.equal(isSdkProfileManagementRequest(frame), true);
    assert.equal(registry.pendingRequests.size, 0);
    socket.send(JSON.stringify(reply(frame, decision)));
    const result = await outcome;
    assert.equal(result.ok, true);
    assert.deepEqual(result.decision, decision);
    assert.equal(Object.isFrozen(result.decision), true);
    assert.equal(registry.pendingSdkProfileManagement.size, 0);
  }
});

test("old or duplicate replies cannot settle a newer management request", async (t) => {
  const { registry, connect } = await fixture(t);
  const socket = await connect();
  const firstFrame = nextFrame(socket);
  const first = registry.manageSdkProfile("host-a", { operation: "status" });
  const old = reply(await firstFrame);
  socket.send(JSON.stringify(old));
  await first;
  const secondFrame = nextFrame(socket);
  const second = registry.manageSdkProfile("host-a", { operation: "status" });
  const current = await secondFrame;
  assert.notEqual(current.requestId, old.requestId);
  socket.send(JSON.stringify(old));
  socket.send(JSON.stringify(reply(current, allowed)));
  assert.deepEqual((await second).decision, allowed);
});

test("disconnect and socket replacement settle pending management without replay", async (t) => {
  const { registry, connect } = await fixture(t);
  const socket = await connect();
  const incoming = nextFrame(socket);
  const outcome = registry.manageSdkProfile("host-a", { operation: "status" });
  await incoming;
  const replacement = await connect();
  assert.equal((await outcome).code, "CONNECTION_LOST");
  assert.equal(registry.pendingSdkProfileManagement.size, 0);
  const replacementFrame = nextFrame(replacement);
  const replacementOutcome = registry.manageSdkProfile("host-a", { operation: "status" });
  await replacementFrame;
  replacement.terminate();
  assert.equal((await replacementOutcome).code, "CONNECTION_LOST");
  assert.equal(registry.pendingSdkProfileManagement.size, 0);
});

test("deadline releases capacity; its late reply cannot replace the next result", async (t) => {
  const timers = manualTimers();
  const { registry, connect } = await fixture(t, { timers: timers.api });
  const socket = await connect();
  const incoming = nextFrame(socket);
  const outcome = registry.manageSdkProfile("host-a", { operation: "status" });
  const expired = await incoming;
  const pending = registry.pendingSdkProfileManagement.get(expired.requestId);
  timers.fire(pending.timer);
  assert.equal((await outcome).code, "REQUEST_TIMEOUT");
  assert.equal(timers.count, 0);
  const next = nextFrame(socket);
  const nextOutcome = registry.manageSdkProfile("host-a", { operation: "status" });
  const current = await next;
  socket.send(JSON.stringify(reply(expired)));
  socket.send(JSON.stringify(reply(current, withdrawn)));
  assert.deepEqual((await nextOutcome).decision, withdrawn);
  assert.equal(timers.count, 0);
});

test("offline, capability skew, concurrent management, and caller paths fail closed", async (t) => {
  const { registry, connect } = await fixture(t);
  assert.equal((await registry.manageSdkProfile("offline", { operation: "status" })).code,
    "HOST_OFFLINE");
  await connect("host-b", CAPABILITIES);
  assert.equal((await registry.manageSdkProfile("host-b", { operation: "status" })).code,
    "UNSUPPORTED");
  const socket = await connect();
  await assert.rejects(registry.manageSdkProfile("host-a", {
    operation: "allow", candidateId, expectedDecisionFingerprint: sdkProfileDecisionFingerprint(absent),
    profilePath: "/private/home",
  }), { message: "SDK_PROFILE_MANAGEMENT_INVALID" });
  const incoming = nextFrame(socket);
  const first = registry.manageSdkProfile("host-a", { operation: "status" });
  const frame = await incoming;
  assert.equal((await registry.manageSdkProfile("host-a", { operation: "status" })).code, "BUSY");
  socket.send(JSON.stringify(reply(frame)));
  await first;
});

test("cross-host management replies cannot settle the actual owner's request", async (t) => {
  const { registry, connect } = await fixture(t);
  const socket = await connect();
  const other = await connect("host-b");
  const incoming = nextFrame(socket);
  const outcome = registry.manageSdkProfile("host-a", { operation: "status" });
  const frame = await incoming;
  const otherClosed = once(other, "close");
  other.send(JSON.stringify(reply(frame, allowed)));
  assert.equal((await otherClosed)[0], 1008);
  assert.equal(registry.pendingSdkProfileManagement.size, 1);
  socket.send(JSON.stringify(reply(frame, withdrawn)));
  assert.deepEqual((await outcome).decision, withdrawn);
});

test("malformed management replies expose no remote paths or errors", async (t) => {
  const { registry, connect } = await fixture(t);
  const socket = await connect();
  const incoming = nextFrame(socket);
  const outcome = registry.manageSdkProfile("host-a", { operation: "status" });
  const frame = await incoming;
  const closed = once(socket, "close");
  socket.send(JSON.stringify({ ...reply(frame), error: "/private/auth.json secret" }));
  const result = await outcome;
  assert.equal(result.code, "INVALID_RESPONSE");
  assert.equal(JSON.stringify(result).includes("private"), false);
  assert.equal((await closed)[0], 1008);
});

test("a correlated reply for the wrong operation closes rather than confirming a write", async (t) => {
  const { registry, connect } = await fixture(t);
  const socket = await connect();
  const incoming = nextFrame(socket);
  const outcome = registry.manageSdkProfile("host-a", { operation: "status" });
  const frame = await incoming;
  const closed = once(socket, "close");
  socket.send(JSON.stringify(buildSdkProfileManagementResult({
    requestId: frame.requestId,
    operation: "withdraw",
    ok: true,
    decision: withdrawn,
    decisionFingerprint: sdkProfileDecisionFingerprint(withdrawn),
  })));
  assert.equal((await outcome).code, "INVALID_RESPONSE");
  assert.equal((await closed)[0], 1008);
});

test("send failure and shutdown return fixed codes and remove management deadlines", async (t) => {
  const timers = manualTimers();
  const { registry, connect } = await fixture(t, { timers: timers.api });
  await connect();
  const serverSocket = registry.connections.get("host-a");
  const originalSend = serverSocket.send;
  serverSocket.send = (_body, callback) => callback(new Error("/private/auth.json secret"));
  const failed = await registry.manageSdkProfile("host-a", { operation: "status" });
  assert.equal(failed.code, "SEND_FAILED");
  assert.equal(JSON.stringify(failed).includes("private"), false);
  assert.equal(timers.count, 0);
  serverSocket.send = originalSend;
  const outcome = registry.manageSdkProfile("host-a", { operation: "status" });
  const closed = registry.close();
  assert.equal((await outcome).code, "CONNECTION_LOST");
  await closed;
  assert.equal(timers.count, 0);
  assert.equal(registry.pendingSdkProfileManagement.size, 0);
});

test("SDK invoke command grammar cannot carry sharing mutations", async (t) => {
  const { registry, connect } = await fixture(t);
  await connect();
  const result = await registry.invoke("host-a", "/workspace", {
    kind: "sdk_profile_management",
    operation: "allow",
    candidateId,
    expectedDecisionFingerprint: sdkProfileDecisionFingerprint(absent),
  }, () => {});
  assert.equal(result.ok, false);
  assert.equal(registry.pendingRequests.size, 0);
  assert.equal(registry.pendingSdkProfileManagement.size, 0);
});
