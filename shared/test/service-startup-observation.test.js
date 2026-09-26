import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Writable } from "node:stream";
import test from "node:test";
import {
  SERVICE_STARTUP_OBSERVATION_LIMITS,
  createServiceStartupObservationEmitter,
  createServiceStartupObservationReducer,
  validateServiceStartupObservationEvent,
} from "../service-startup-observation.js";
import { canonicalJsonHash, parseStrictJson } from "../strict-json.js";
import { createServiceStartupObserver } from "../../native-control/src/service-startup-observer.js";

const hash = (character) => character.repeat(64);
const botBinding = Object.freeze({
  component: "bot",
  serviceKey: "bot",
  processEpochFingerprint: hash("a"),
  effectiveConfigFingerprint: hash("b"),
  configSourceIdentityFingerprint: hash("c"),
});
const botExpected = Object.freeze({
  expectedHostSetFingerprint: hash("d"),
  expectedHostCount: 2,
});
const botState = (overrides = {}) => ({
  listener: "listening",
  discord: "connected",
  expectedHostSetFingerprint: botExpected.expectedHostSetFingerprint,
  expectedHostCount: botExpected.expectedHostCount,
  connectedHostSetFingerprint: botExpected.expectedHostSetFingerprint,
  connectedHostCount: botExpected.expectedHostCount,
  ...overrides,
});
const event = (sequence, state = botState(), overrides = {}) => ({
  schemaVersion: 1,
  kind: "service-startup-observation",
  component: botBinding.component,
  serviceKey: botBinding.serviceKey,
  processEpochFingerprint: botBinding.processEpochFingerprint,
  sequence,
  effectiveConfigFingerprint: botBinding.effectiveConfigFingerprint,
  configSourceIdentityFingerprint: botBinding.configSourceIdentityFingerprint,
  state,
  ...overrides,
});
const line = (value) => Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
const botReducer = () => createServiceStartupObservationReducer({
  binding: botBinding,
  expectedState: botExpected,
});

function daemonBinding() {
  return Object.freeze({
    component: "daemon",
    serviceKey: `svc-${hash("e")}`,
    processEpochFingerprint: hash("f"),
    effectiveConfigFingerprint: hash("1"),
    configSourceIdentityFingerprint: hash("2"),
  });
}
const daemonTarget = hash("3");
const daemonState = (overrides = {}) => ({
  targetFingerprint: daemonTarget,
  connectionGeneration: 1,
  attemptedGeneration: 1,
  acceptedGeneration: 1,
  registration: "accepted",
  ...overrides,
});
const daemonEvent = (sequence, state = daemonState(), overrides = {}) => ({
  schemaVersion: 1,
  kind: "service-startup-observation",
  component: "daemon",
  serviceKey: daemonBinding().serviceKey,
  processEpochFingerprint: daemonBinding().processEpochFingerprint,
  sequence,
  effectiveConfigFingerprint: daemonBinding().effectiveConfigFingerprint,
  configSourceIdentityFingerprint: daemonBinding().configSourceIdentityFingerprint,
  state,
  ...overrides,
});
const daemonReducer = () => createServiceStartupObservationReducer({
  binding: daemonBinding(),
  expectedState: { targetFingerprint: daemonTarget },
});

function consumeEvent(reducer, family, value) {
  return reducer.consume(family, line(value));
}

function sealed(record, field) {
  record[field] = canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
  return record;
}

function cursorSet(serviceKey = "bot", bootFingerprint = hash("4"), configFingerprint = hash("b")) {
  const baseStem = serviceKey === "bot" ? "gjc-remote-bot" : `gjc-remote-daemon-${serviceKey}`;
  const families = ["wrapper", "child"].map((family) => ({
    family,
    baseName: `${baseStem}-${family}`,
    directoryIdentityFingerprint: hash(family === "wrapper" ? "5" : "6"),
    files: [],
    nextLogicalOffset: 0,
    partialLineBytes: 0,
    absenceFingerprint: hash(family === "wrapper" ? "7" : "8"),
  }));
  return sealed({
    schemaVersion: 1,
    bootFingerprint,
    serviceKey,
    configFingerprint,
    families,
    cursorFingerprint: null,
  }, "cursorFingerprint");
}

function cursorSetWithChildLog(bytes) {
  const cursor = cursorSet();
  const families = cursor.families.map((family) => ({ ...family }));
  families[1] = {
    ...families[1],
    files: [{
      identityFingerprint: hash("3"),
      logicalStartOffset: 0,
      observedLength: bytes.byteLength,
      prefixSha256: createHash("sha256").update(bytes).digest("hex"),
    }],
    nextLogicalOffset: bytes.byteLength,
    absenceFingerprint: null,
  };
  return sealed({ ...cursor, families, cursorFingerprint: null }, "cursorFingerprint");
}

function nativeTrialObservation({ initialCursor = cursorSet(), boundaryOverrides = {} } = {}) {
  const bootFingerprint = hash("4");
  const effectiveConfigFingerprint = hash("b");
  const initial = initialCursor;
  const child = cursorSetWithChildLog(Buffer.from("previous child output\n"));
  const boundary = sealed({
    schemaVersion: 1,
    kind: "windows-service-trial-boundary",
    serviceKey: "bot",
    transactionId: "tx-startup-test",
    transactionNonce: "a".repeat(32),
    transitionFingerprint: hash("9"),
    attempt: 1,
    revision: 2,
    previousBoundaryFingerprint: hash("a"),
    phase: "observed",
    bootFingerprint,
    startTickMs: 100,
    deadlineTickMs: 60100,
    lastTickMs: 100,
    applicationManifestFingerprint: hash("c"),
    resourceFingerprint: hash("d"),
    effectiveConfigFingerprint,
    configSourceIdentityFingerprint: hash("e"),
    wrapperEpochFingerprint: hash("f"),
    childEpochFingerprint: hash("1"),
    initialCursor: initial,
    childCursor: child,
    boundaryFingerprint: null,
    ...boundaryOverrides,
  }, "boundaryFingerprint");
  return {
    component: "bot",
    serviceKey: "bot",
    serviceName: "gjc-remote-bot",
    bootFingerprint,
    wrapperEpochFingerprint: hash("f"),
    childEpochFingerprint: hash("1"),
    resourceFingerprint: hash("d"),
    applicationManifestFingerprint: hash("c"),
    effectiveConfigFingerprint,
    boundaryReceipt: { present: true, value: boundary },
  };
}

test("closed startup event schema rejects extra fields and validates component-specific snapshots", () => {
  const normalized = validateServiceStartupObservationEvent(event(1));
  assert.equal(normalized.kind, "service-startup-observation");
  assert.equal(normalized.state.connectedHostCount, 2);
  assert.throws(() => validateServiceStartupObservationEvent(event(1, botState(), { secret: "not-allowed" })), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.throws(() => validateServiceStartupObservationEvent(event(1, { ...botState(), state: "sdk-ready" })), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.throws(() => validateServiceStartupObservationEvent(daemonEvent(1, daemonState({ acceptedGeneration: 0 }))), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.throws(() => validateServiceStartupObservationEvent(daemonEvent(1, daemonState({ registration: "connected" }))), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("closed event and binding validation rejects accessors before invoking getters", () => {
  let getterCalls = 0;
  const accessedSequence = event(1);
  Object.defineProperty(accessedSequence, "sequence", {
    enumerable: true,
    get() { getterCalls += 1; return 1; },
  });
  assert.throws(() => validateServiceStartupObservationEvent(accessedSequence), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.equal(getterCalls, 0);

  const accessedState = event(1);
  Object.defineProperty(accessedState.state, "listener", {
    enumerable: true,
    get() { getterCalls += 1; return "listening"; },
  });
  assert.throws(() => validateServiceStartupObservationEvent(accessedState), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.equal(getterCalls, 0);

  const accessorOptions = {};
  Object.defineProperties(accessorOptions, {
    binding: { enumerable: true, get() { getterCalls += 1; return botBinding; } },
    expectedState: { enumerable: true, value: botExpected },
  });
  assert.throws(() => createServiceStartupObservationReducer(accessorOptions), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.equal(getterCalls, 0);

  const symbolEvent = event(1);
  symbolEvent[Symbol("unexpected")] = true;
  assert.throws(() => validateServiceStartupObservationEvent(symbolEvent), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  const hiddenEvent = event(1);
  Object.defineProperty(hiddenEvent, "hidden", { value: true, enumerable: false });
  assert.throws(() => validateServiceStartupObservationEvent(hiddenEvent), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.throws(() => validateServiceStartupObservationEvent(Object.assign(Object.create(null), event(1))), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("native observer rejects accessor-bearing private operation and LogRead data without invoking getters", async () => {
  let getterCalls = 0;
  const badOptions = {};
  Object.defineProperties(badOptions, {
    trialObservation: { enumerable: true, get() { getterCalls += 1; return nativeTrialObservation(); } },
    expectedState: { enumerable: true, value: botExpected },
  });
  assert.throws(() => createServiceStartupObserver(badOptions), /SERVICE_STARTUP_OBSERVER_INVALID/);
  assert.equal(getterCalls, 0);

  const badTrial = nativeTrialObservation();
  const badInitial = badTrial.boundaryReceipt.value.initialCursor;
  Object.defineProperty(badInitial.families, "0", {
    enumerable: true,
    configurable: true,
    get() { getterCalls += 1; return cursorSet().families[0]; },
  });
  assert.throws(() => createServiceStartupObserver({
    trialObservation: badTrial,
    expectedState: botExpected,
  }), /SERVICE_STARTUP_OBSERVER_INVALID/);
  assert.equal(getterCalls, 0);

  const observer = createServiceStartupObserver({
    trialObservation: nativeTrialObservation(),
    expectedState: botExpected,
  });
  const chunks = [];
  chunks.length = 1;
  Object.defineProperty(chunks, "0", {
    enumerable: true,
    get() { getterCalls += 1; return {}; },
  });
  const cursor = cursorSet();
  const logRead = {
    clock: { schemaVersion: 1, bootFingerprint: hash("4"), tickMs: 101, writes: 0 },
    beforeCursor: cursor,
    afterCursor: cursor,
    wrapperEpochFingerprint: hash("f"),
    childEpochFingerprint: hash("1"),
    treeFingerprint: hash("2"),
    chunks,
    eof: true,
    continuity: "complete",
    writes: 0,
  };
  await assert.rejects(observer.observeApplication(logRead), /SERVICE_STARTUP_OBSERVER_INVALID/);
  assert.equal(getterCalls, 0);
});

test("native observer binds complete child-log reduction to its fixed trial boundary and process epochs", async () => {
  const trialObservation = nativeTrialObservation();
  const observer = createServiceStartupObserver({ trialObservation, expectedState: botExpected });
  const bytes = line(event(1, botState(), {
    processEpochFingerprint: trialObservation.childEpochFingerprint,
    effectiveConfigFingerprint: trialObservation.effectiveConfigFingerprint,
    configSourceIdentityFingerprint: trialObservation.boundaryReceipt.value.configSourceIdentityFingerprint,
  }));
  const priorBytes = Buffer.from("previous child output\n");
  const afterCursor = cursorSetWithChildLog(Buffer.concat([priorBytes, bytes]));
  const result = await observer.observeApplication({
    clock: { schemaVersion: 1, bootFingerprint: hash("4"), tickMs: 101, writes: 0 },
    beforeCursor: trialObservation.boundaryReceipt.value.childCursor,
    afterCursor,
    wrapperEpochFingerprint: hash("f"),
    childEpochFingerprint: hash("1"),
    treeFingerprint: hash("2"),
    chunks: [{ family: "child", fileIdentityFingerprint: hash("3"), logicalOffset: priorBytes.byteLength, bytes }],
    eof: true,
    continuity: "complete",
    writes: 0,
  });
  assert.equal(result.ready, true);
  assert.equal(result.logEvidence.boundaryFingerprint, trialObservation.boundaryReceipt.value.boundaryFingerprint);
  assert.equal(result.logEvidence.completeEof, true);
  assert.equal(result.logEvidence.observedTickMs, 101);
  assert.match(result.applicationEvidenceFingerprint, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(result.logEvidence).sort(), [
    "applicationStateFingerprint", "bootFingerprint", "boundaryFingerprint", "childEpochFingerprint",
    "completeEof", "evidenceFingerprint", "fromCursorFingerprint", "observedTickMs", "toCursor",
    "schemaVersion", "treeFingerprint", "wrapperEpochFingerprint",
  ].sort());
});

test("reducer consumes mixed ordinary wrapper and combined-child logs without granting wrapper readiness", () => {
  const reducer = botReducer();
  reducer.consume("wrapper", Buffer.from("wrapper starting\nordinary wrapper JSON: {\"message\":\"hello\"}\n"));
  reducer.consume("child", Buffer.from("ordinary child line\n"));
  assert.equal(reducer.snapshot(), null);

  const complete = line(event(1));
  const splitAt = Math.floor(complete.length / 2);
  reducer.consume("child", complete.subarray(0, splitAt));
  assert.equal(reducer.snapshot(), null);
  assert.equal(reducer.hasPartialLine(), true);
  reducer.consume("child", complete.subarray(splitAt));
  assert.equal(reducer.snapshot().ready, true);
  assert.equal(reducer.hasPartialLine(), false);

  const escapedMarker = botReducer();
  const escapedEventLine = line(event(1)).toString("utf8").replace(
    "service-startup-observation",
    "service-startup-\\u006fbservation",
  );
  escapedMarker.consume("child", Buffer.from(escapedEventLine, "utf8"));
  assert.equal(escapedMarker.snapshot().ready, true);

  const wrapperEvent = botReducer();
  assert.throws(() => wrapperEvent.consume("wrapper", line(event(1))), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("partial frames stay non-ready, while overlong and malformed event-shaped frames invalidate", () => {
  const reducer = botReducer();
  const bytes = line(event(1));
  reducer.consume("child", bytes.subarray(0, bytes.length - 1));
  assert.equal(reducer.snapshot(), null);
  assert.equal(reducer.hasPartialLine(), true);

  const overlong = botReducer();
  assert.throws(() => overlong.consume("child", Buffer.alloc(SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes + 1, 0x78)), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  const overlongPartial = botReducer();
  overlongPartial.consume("child", Buffer.alloc(SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes, 0x78));
  assert.throws(() => overlongPartial.consume("child", Buffer.from("x")), /SERVICE_STARTUP_OBSERVATION_INVALID/);

  const exactUtf8Bound = botReducer();
  exactUtf8Bound.consume("child", Buffer.from(`${"é".repeat(SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes / 2)}\n`, "utf8"));
  const overUtf8Bound = botReducer();
  assert.throws(() => overUtf8Bound.consume("child", Buffer.from(`${"é".repeat(SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes / 2 + 1)}\n`, "utf8")), /SERVICE_STARTUP_OBSERVATION_INVALID/);

  const malformed = botReducer();
  assert.throws(() => malformed.consume("child", Buffer.from('{"kind":"service-startup-observation",\n')), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  const invalidUtf8 = botReducer();
  assert.throws(() => invalidUtf8.consume("child", Buffer.concat([Buffer.from([0xff]), Buffer.from('"kind":"service-startup-observation"\n')])), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("reducer resumes a bounded partial baseline by discarding through its line ending", () => {
  const reducer = createServiceStartupObservationReducer({
    binding: botBinding,
    expectedState: botExpected,
    initialPartialLineBytes: { wrapper: 0, child: 3 },
  });
  assert.equal(reducer.hasPartialLine(), true);
  assert.deepEqual(reducer.partialLineBytes(), { wrapper: 0, child: 3 });
  reducer.consume("child", Buffer.from("inary\n"));
  assert.equal(reducer.snapshot(), null);
  assert.equal(reducer.hasPartialLine(), false);
  consumeEvent(reducer, "child", event(1));
  assert.equal(reducer.snapshot().ready, true);
  assert.throws(() => createServiceStartupObservationReducer({
    binding: botBinding,
    expectedState: botExpected,
    initialPartialLineBytes: { wrapper: 0, child: SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes + 1 },
  }), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("sequence gaps and duplicates and stale process/config epochs fail closed", () => {
  const gap = botReducer();
  consumeEvent(gap, "child", event(1));
  assert.throws(() => consumeEvent(gap, "child", event(3)), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  const duplicate = botReducer();
  consumeEvent(duplicate, "child", event(1));
  assert.throws(() => consumeEvent(duplicate, "child", event(1)), /SERVICE_STARTUP_OBSERVATION_INVALID/);

  const staleEpoch = botReducer();
  assert.throws(() => consumeEvent(staleEpoch, "child", event(1, botState(), { processEpochFingerprint: hash("9") })), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  const staleConfig = botReducer();
  assert.throws(() => consumeEvent(staleConfig, "child", event(1, botState(), { effectiveConfigFingerprint: hash("8") })), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  const staleSource = botReducer();
  assert.throws(() => consumeEvent(staleSource, "child", event(1, botState(), { configSourceIdentityFingerprint: hash("7") })), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("bot readiness requires the exact configured connected-host hash and count and is revoked by disconnect", () => {
  const reducer = botReducer();
  consumeEvent(reducer, "child", event(1, botState({ connectedHostSetFingerprint: hash("9") })));
  assert.equal(reducer.snapshot().ready, false);
  consumeEvent(reducer, "child", event(2));
  assert.equal(reducer.snapshot().ready, true);
  consumeEvent(reducer, "child", event(3, botState({
    discord: "disconnected",
    connectedHostSetFingerprint: hash("5"),
    connectedHostCount: 1,
  })));
  assert.equal(reducer.snapshot().ready, false);
  consumeEvent(reducer, "child", event(4, botState({ listener: "closed" })));
  assert.equal(reducer.snapshot().ready, false);
});

test("daemon readiness requires current target and current attempted plus accepted generation", () => {
  const reducer = daemonReducer();
  consumeEvent(reducer, "child", daemonEvent(1));
  assert.equal(reducer.snapshot().ready, true);
  consumeEvent(reducer, "child", daemonEvent(2, daemonState({
    connectionGeneration: 2,
    attemptedGeneration: 2,
    acceptedGeneration: 1,
    registration: "attempted",
  })));
  assert.equal(reducer.snapshot().ready, false);
  assert.throws(() => consumeEvent(reducer, "child", daemonEvent(3, daemonState({
    connectionGeneration: 2,
    attemptedGeneration: 2,
    acceptedGeneration: 1,
    registration: "accepted",
  }))), /SERVICE_STARTUP_OBSERVATION_INVALID/);
  assert.throws(() => consumeEvent(daemonReducer(), "child", daemonEvent(1, daemonState({ targetFingerprint: hash("4") }))), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("daemon denied and disconnected snapshots invalidate prior acceptance without regressing history", () => {
  const denied = daemonReducer();
  consumeEvent(denied, "child", daemonEvent(1));
  consumeEvent(denied, "child", daemonEvent(2, daemonState({
    connectionGeneration: 2,
    attemptedGeneration: 2,
    acceptedGeneration: 1,
    registration: "denied",
  })));
  assert.equal(denied.snapshot().ready, false);

  const disconnected = daemonReducer();
  consumeEvent(disconnected, "child", daemonEvent(1));
  consumeEvent(disconnected, "child", daemonEvent(2, daemonState({ registration: "disconnected" })));
  assert.equal(disconnected.snapshot().ready, false);
  assert.throws(() => consumeEvent(disconnected, "child", daemonEvent(3, daemonState({
    attemptedGeneration: null,
    acceptedGeneration: null,
    registration: "disconnected",
  }))), /SERVICE_STARTUP_OBSERVATION_INVALID/);
});

test("emitter writes only bounded sanitized closed JSON frames with contiguous per-process sequence", async () => {
  const output = [];
  const writable = new Writable({
    write(chunk, _encoding, callback) {
      output.push(Buffer.from(chunk));
      callback();
    },
  });
  const emitter = createServiceStartupObservationEmitter({
    binding: botBinding,
    expectedState: botExpected,
    writable,
  });
  await emitter.emit(botState());
  await emitter.emit(botState({ discord: "disconnected", connectedHostSetFingerprint: hash("6"), connectedHostCount: 0 }));
  await emitter.close();
  assert.equal(output.length, 2);
  const records = output.map((chunk) => parseStrictJson(chunk.toString("utf8").trim()));
  assert.deepEqual(records.map((record) => record.sequence), [1, 2]);
  assert.equal(records[0].state.connectedHostCount, 2);
  assert.equal(records[1].state.discord, "disconnected");
  assert.deepEqual(Object.keys(records[0]).sort(), [
    "component", "configSourceIdentityFingerprint", "effectiveConfigFingerprint", "kind",
    "processEpochFingerprint", "schemaVersion", "sequence", "serviceKey", "state",
  ].sort());
});

test("emitter permanently refuses unsanitized state and bounds queued bytes under a blocked writer", async () => {
  const emitted = [];
  const writable = new Writable({
    write(chunk, _encoding, callback) {
      emitted.push(Buffer.from(chunk));
      callback();
    },
  });
  const sanitized = createServiceStartupObservationEmitter({
    binding: botBinding,
    expectedState: botExpected,
    writable,
  });
  await assert.rejects(sanitized.emit({ ...botState(), token: "never-print-this" }), (error) => {
    assert.doesNotMatch(error.message, /never-print-this/);
    return error.code === "SERVICE_STARTUP_OBSERVATION_EMITTER_FAILED";
  });
  await assert.rejects(sanitized.close(), /SERVICE_STARTUP_OBSERVATION_EMITTER_FAILED/);
  assert.equal(emitted.length, 0);

  let listener;
  const blockedWriter = {
    on(eventName, callback) { if (eventName === "error") listener = callback; },
    off() {},
    write() { return false; },
  };
  const bounded = createServiceStartupObservationEmitter({
    binding: botBinding,
    expectedState: botExpected,
    writable: blockedWriter,
  });
  const pending = Array.from({ length: 1000 }, () => bounded.emit(botState()));
  const results = await Promise.allSettled(pending);
  assert.ok(results.some((result) => result.status === "rejected" && result.reason.code === "SERVICE_STARTUP_OBSERVATION_EMITTER_FAILED"));
  assert.equal(typeof listener, "function");
  await assert.rejects(bounded.close(), /SERVICE_STARTUP_OBSERVATION_EMITTER_FAILED/);
});
