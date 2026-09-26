import {
  canonicalJson,
  canonicalJsonHash,
  isHex64,
  parseStrictJson,
} from "./strict-json.js";
import { validateServiceKey } from "./service-lifecycle-envelope.js";

export const SERVICE_STARTUP_OBSERVATION_LIMITS = Object.freeze({
  eventBytes: 16 * 1024,
  lineBytes: 16 * 1024,
  pageBytes: 1024 * 1024,
  attemptBytes: 16 * 1024 * 1024,
  emitterQueueBytes: 64 * 1024,
  hostCount: 100000,
});

const EVENT_KEYS = Object.freeze([
  "schemaVersion",
  "kind",
  "component",
  "serviceKey",
  "processEpochFingerprint",
  "sequence",
  "effectiveConfigFingerprint",
  "configSourceIdentityFingerprint",
  "state",
]);
const BINDING_KEYS = Object.freeze([
  "component",
  "serviceKey",
  "processEpochFingerprint",
  "effectiveConfigFingerprint",
  "configSourceIdentityFingerprint",
]);
const BOT_STATE_KEYS = Object.freeze([
  "listener",
  "discord",
  "expectedHostSetFingerprint",
  "expectedHostCount",
  "connectedHostSetFingerprint",
  "connectedHostCount",
]);
const DAEMON_STATE_KEYS = Object.freeze([
  "targetFingerprint",
  "connectionGeneration",
  "attemptedGeneration",
  "acceptedGeneration",
  "registration",
]);
const BOT_EXPECTED_KEYS = Object.freeze(["expectedHostSetFingerprint", "expectedHostCount"]);
const DAEMON_EXPECTED_KEYS = Object.freeze(["targetFingerprint"]);
const EVENT_MARKER = Buffer.from("service-startup-observation", "ascii");
const EVENT_SHAPE_MARKERS = Object.freeze([
  Buffer.from("processEpochFingerprint", "ascii"),
  Buffer.from("effectiveConfigFingerprint", "ascii"),
  Buffer.from("configSourceIdentityFingerprint", "ascii"),
]);
const STRICT_EVENT_JSON_LIMITS = Object.freeze({ maxBytes: SERVICE_STARTUP_OBSERVATION_LIMITS.eventBytes, maxDepth: 8, maxNodes: 64 });

// Exact daemon registration target: the bot WebSocket URL without userinfo
// plus the registering host id. Shared by the service producer and daemon.
export function serviceDaemonTargetFingerprint({ botWsUrl, hostId }) {
  if (typeof botWsUrl !== "string" || typeof hostId !== "string" || hostId.length === 0) invalid();
  let url;
  try {
    url = new URL(botWsUrl);
  } catch {
    invalid();
  }
  if (url.protocol !== "ws:" && url.protocol !== "wss:") invalid();
  url.username = "";
  url.password = "";
  url.hash = "";
  return canonicalJsonHash({ hostId, kind: "gjc-remote/daemon-service-target/v1", url: url.href });
}
function invalid() {
  const error = new TypeError("SERVICE_STARTUP_OBSERVATION_INVALID");
  error.code = "SERVICE_STARTUP_OBSERVATION_INVALID";
  throw error;
}

function emitterFailed() {
  const error = new Error("SERVICE_STARTUP_OBSERVATION_EMITTER_FAILED");
  error.code = "SERVICE_STARTUP_OBSERVATION_EMITTER_FAILED";
  return error;
}

function exactValues(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== "string") ||
        !keys.every((key) => ownKeys.includes(key))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.enumerable !== true || descriptor.get !== undefined ||
          descriptor.set !== undefined || !Object.hasOwn(descriptor, "value")) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

function optionValues(value, keys) {
  const result = exactValues(value, keys);
  if (!result) invalid();
  return result;
}

function validHash(value) {
  return isHex64(value);
}

function positive(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

function hostCount(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= SERVICE_STARTUP_OBSERVATION_LIMITS.hostCount;
}

function captureBinding(value) {
  const fields = exactValues(value, BINDING_KEYS);
  if (!fields || !["bot", "daemon"].includes(fields.component) ||
      !validHash(fields.processEpochFingerprint) || !validHash(fields.effectiveConfigFingerprint) ||
      !validHash(fields.configSourceIdentityFingerprint)) invalid();
  try {
    validateServiceKey(fields.serviceKey, fields.component);
  } catch {
    invalid();
  }
  return Object.freeze({ ...fields });
}

function captureExpectedState(component, value) {
  const keys = component === "bot" ? BOT_EXPECTED_KEYS : DAEMON_EXPECTED_KEYS;
  const fields = exactValues(value, keys);
  if (!fields) invalid();
  if (component === "bot") {
    if (!validHash(fields.expectedHostSetFingerprint) || !hostCount(fields.expectedHostCount)) invalid();
  } else if (!validHash(fields.targetFingerprint)) {
    invalid();
  }
  return Object.freeze({ ...fields });
}

function captureBotState(value, expectedState) {
  const fields = exactValues(value, BOT_STATE_KEYS);
  if (!fields || !["listening", "closed"].includes(fields.listener) ||
      !["connected", "disconnected"].includes(fields.discord) ||
      !validHash(fields.expectedHostSetFingerprint) || !hostCount(fields.expectedHostCount) ||
      !validHash(fields.connectedHostSetFingerprint) || !hostCount(fields.connectedHostCount) ||
      fields.expectedHostSetFingerprint !== expectedState.expectedHostSetFingerprint ||
      fields.expectedHostCount !== expectedState.expectedHostCount) invalid();
  return Object.freeze({ ...fields });
}

function captureDaemonState(value, expectedState) {
  const fields = exactValues(value, DAEMON_STATE_KEYS);
  if (!fields || !validHash(fields.targetFingerprint) ||
      !positive(fields.connectionGeneration) ||
      !(fields.attemptedGeneration === null || positive(fields.attemptedGeneration)) ||
      !(fields.acceptedGeneration === null || positive(fields.acceptedGeneration)) ||
      !["attempted", "accepted", "denied", "disconnected"].includes(fields.registration) ||
      fields.targetFingerprint !== expectedState.targetFingerprint ||
      (fields.attemptedGeneration !== null && fields.attemptedGeneration > fields.connectionGeneration) ||
      (fields.acceptedGeneration !== null && fields.acceptedGeneration > fields.connectionGeneration) ||
      (fields.acceptedGeneration !== null &&
        (fields.attemptedGeneration === null || fields.acceptedGeneration > fields.attemptedGeneration))) invalid();
  if ((fields.registration === "attempted" && fields.attemptedGeneration !== fields.connectionGeneration) ||
      (fields.registration === "accepted" &&
        (fields.attemptedGeneration !== fields.connectionGeneration || fields.acceptedGeneration !== fields.connectionGeneration)) ||
      (fields.registration === "denied" &&
        (fields.attemptedGeneration !== fields.connectionGeneration || fields.acceptedGeneration === fields.connectionGeneration))) invalid();
  return Object.freeze({ ...fields });
}

function stateReady(component, state, expectedState) {
  if (component === "bot") {
    return state.listener === "listening" && state.discord === "connected" &&
      state.expectedHostSetFingerprint === expectedState.expectedHostSetFingerprint &&
      state.expectedHostCount === expectedState.expectedHostCount &&
      state.connectedHostSetFingerprint === expectedState.expectedHostSetFingerprint &&
      state.connectedHostCount === expectedState.expectedHostCount;
  }
  return state.targetFingerprint === expectedState.targetFingerprint &&
    state.registration === "accepted" &&
    state.attemptedGeneration === state.connectionGeneration &&
    state.acceptedGeneration === state.connectionGeneration;
}

export function validateServiceStartupObservationEvent(event, options = undefined) {
  const fields = exactValues(event, EVENT_KEYS);
  if (!fields || fields.schemaVersion !== 1 || fields.kind !== "service-startup-observation" ||
      !["bot", "daemon"].includes(fields.component) || !positive(fields.sequence) ||
      !validHash(fields.processEpochFingerprint) || !validHash(fields.effectiveConfigFingerprint) ||
      !validHash(fields.configSourceIdentityFingerprint)) invalid();
  try {
    validateServiceKey(fields.serviceKey, fields.component);
  } catch {
    invalid();
  }
  const expectedState = captureExpectedState(fields.component, fields.component === "bot"
    ? (() => {
        const state = exactValues(fields.state, BOT_STATE_KEYS);
        return state && { expectedHostSetFingerprint: state.expectedHostSetFingerprint, expectedHostCount: state.expectedHostCount };
      })()
    : (() => {
        const state = exactValues(fields.state, DAEMON_STATE_KEYS);
        return state && { targetFingerprint: state.targetFingerprint };
      })());
  const state = fields.component === "bot"
    ? captureBotState(fields.state, expectedState)
    : captureDaemonState(fields.state, expectedState);
  if (options !== undefined) {
    const opts = optionValues(options, ["binding", "expectedState"]);
    const binding = captureBinding(opts.binding);
    const configured = captureExpectedState(binding.component, opts.expectedState);
    if (binding.component !== fields.component || binding.serviceKey !== fields.serviceKey ||
        binding.processEpochFingerprint !== fields.processEpochFingerprint ||
        binding.effectiveConfigFingerprint !== fields.effectiveConfigFingerprint ||
        binding.configSourceIdentityFingerprint !== fields.configSourceIdentityFingerprint ||
        (fields.component === "bot" &&
          (state.expectedHostSetFingerprint !== configured.expectedHostSetFingerprint ||
           state.expectedHostCount !== configured.expectedHostCount)) ||
        (fields.component === "daemon" && state.targetFingerprint !== configured.targetFingerprint)) invalid();
  }
  const normalized = Object.freeze({
    schemaVersion: 1,
    kind: "service-startup-observation",
    component: fields.component,
    serviceKey: fields.serviceKey,
    processEpochFingerprint: fields.processEpochFingerprint,
    sequence: fields.sequence,
    effectiveConfigFingerprint: fields.effectiveConfigFingerprint,
    configSourceIdentityFingerprint: fields.configSourceIdentityFingerprint,
    state,
  });
  if (Buffer.byteLength(canonicalJson(normalized), "utf8") > SERVICE_STARTUP_OBSERVATION_LIMITS.eventBytes) invalid();
  return normalized;
}

function eventShaped(line) {
  if (line.includes(EVENT_MARKER)) return true;
  let markers = 0;
  for (const marker of EVENT_SHAPE_MARKERS) if (line.includes(marker)) markers += 1;
  return markers >= 2;
}

function eventFieldCount(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) return 0;
  return ["schemaVersion", "kind", "component", "serviceKey", "processEpochFingerprint", "sequence",
    "effectiveConfigFingerprint", "configSourceIdentityFingerprint", "state"]
    .filter((key) => Object.hasOwn(value, key)).length;
}

function eventFieldCountFromText(value) {
  const matches = value.match(/"(?:schemaVersion|kind|component|serviceKey|processEpochFingerprint|sequence|effectiveConfigFingerprint|configSourceIdentityFingerprint|state)"\s*:/g);
  return matches?.length ?? 0;
}

function readChunk(family, bytes) {
  try {
    if (!["wrapper", "child"].includes(family) ||
        (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) ||
        bytes.byteLength > SERVICE_STARTUP_OBSERVATION_LIMITS.pageBytes) invalid();
    return Buffer.from(bytes);
  } catch {
    invalid();
  }
}

function daemonHistoryDoesNotRegress(previous, current) {
  if (current.connectionGeneration < previous.connectionGeneration) return false;
  if (previous.attemptedGeneration !== null &&
      (current.attemptedGeneration === null || current.attemptedGeneration < previous.attemptedGeneration)) return false;
  if (previous.acceptedGeneration !== null &&
      (current.acceptedGeneration === null || current.acceptedGeneration < previous.acceptedGeneration)) return false;
  return true;
}

export function createServiceStartupObservationReducer(options) {
  const opts = exactValues(options, ["binding", "expectedState", "initialPartialLineBytes"]) ??
    exactValues(options, ["binding", "expectedState"]);
  if (!opts) invalid();
  const binding = captureBinding(opts.binding);
  const expectedState = captureExpectedState(binding.component, opts.expectedState);
  const initialPartialLineBytes = opts.initialPartialLineBytes === undefined
    ? Object.freeze({ wrapper: 0, child: 0 })
    : (() => {
        const fields = exactValues(opts.initialPartialLineBytes, ["wrapper", "child"]);
        if (!fields || ![fields.wrapper, fields.child].every((value) =>
          Number.isSafeInteger(value) && value >= 0 && value <= SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes)) invalid();
        return Object.freeze({ ...fields });
      })();
  const streams = new Map([
    ["wrapper", Buffer.alloc(0)],
    ["child", Buffer.alloc(0)],
  ]);
  const discardedPartialBytes = new Map([
    ["wrapper", initialPartialLineBytes.wrapper],
    ["child", initialPartialLineBytes.child],
  ]);
  const discardedLastByte = new Map([
    ["wrapper", null],
    ["child", null],
  ]);
  let bytesRead = 0;
  let sequence = 0;
  let latest = null;
  let lastDaemonState = null;
  let faulted = false;

  const consumeLine = (family, line) => {
    let candidate = eventShaped(line);
    const jsonLooking = line.find((byte) => byte !== 0x20 && byte !== 0x09 && byte !== 0x0d) === 0x7b;
    if (!candidate && !jsonLooking) return;
    let text;
    let event;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(line);
    } catch {
      if (candidate) invalid();
      return;
    }
    try {
      event = parseStrictJson(text, STRICT_EVENT_JSON_LIMITS);
    } catch {
      if (candidate || eventFieldCountFromText(text) >= 3) invalid();
      return;
    }
    if (!candidate) candidate = event?.kind === "service-startup-observation" || eventFieldCount(event) >= 3;
    if (!candidate) return;
    if (family !== "child") invalid();
    if (event?.kind !== "service-startup-observation") invalid();
    const accepted = validateServiceStartupObservationEvent(event, { binding, expectedState });
    if (accepted.sequence !== sequence + 1) invalid();
    if (accepted.component === "daemon" && lastDaemonState !== null &&
        !daemonHistoryDoesNotRegress(lastDaemonState, accepted.state)) invalid();
    sequence = accepted.sequence;
    latest = accepted;
    if (accepted.component === "daemon") lastDaemonState = accepted.state;
  };

  function consume(family, bytes) {
    if (faulted) invalid();
    try {
      const chunk = readChunk(family, bytes);
      bytesRead += chunk.byteLength;
      if (bytesRead > SERVICE_STARTUP_OBSERVATION_LIMITS.attemptBytes) invalid();
      const combined = Buffer.concat([streams.get(family), chunk]);
      let start = 0;
      const discarded = discardedPartialBytes.get(family);
      if (discarded > 0) {
        const newline = combined.indexOf(0x0a);
        if (newline === -1) {
          const lineBytes = discarded + combined.byteLength;
          if (lineBytes > SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes + 1 ||
              (lineBytes === SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes + 1 && combined.at(-1) !== 0x0d)) invalid();
          discardedPartialBytes.set(family, lineBytes);
          discardedLastByte.set(family, combined.at(-1) ?? discardedLastByte.get(family));
          streams.set(family, Buffer.alloc(0));
          return snapshot();
        }
        const lastLineByte = newline > 0 ? combined[newline - 1] : discardedLastByte.get(family);
        const lineBytes = discarded + newline - (lastLineByte === 0x0d ? 1 : 0);
        if (lineBytes > SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes) invalid();
        discardedPartialBytes.set(family, 0);
        discardedLastByte.set(family, null);
        start = newline + 1;
      }
      for (let index = 0; index < combined.length; index += 1) {
        if (index < start) continue;
        if (combined[index] !== 0x0a) continue;
        let end = index;
        if (end > start && combined[end - 1] === 0x0d) end -= 1;
        if (end - start > SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes) invalid();
        consumeLine(family, combined.subarray(start, end));
        start = index + 1;
      }
      const remainder = combined.subarray(start);
      if (remainder.byteLength > SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes) invalid();
      streams.set(family, Buffer.from(remainder));
      return snapshot();
    } catch {
      faulted = true;
      invalid();
    }
  }

  function snapshot() {
    if (faulted) return null;
    if (latest === null) return null;
    const state = latest.state;
    const stateSnapshot = Object.freeze({
      component: binding.component,
      serviceKey: binding.serviceKey,
      processEpochFingerprint: binding.processEpochFingerprint,
      effectiveConfigFingerprint: binding.effectiveConfigFingerprint,
      configSourceIdentityFingerprint: binding.configSourceIdentityFingerprint,
      sequence: latest.sequence,
      state,
    });
    const partialLinePending = hasPartialLine();
    return Object.freeze({
      sequence: latest.sequence,
      state,
      applicationStateFingerprint: canonicalJsonHash(stateSnapshot),
      ready: !partialLinePending && stateReady(binding.component, state, expectedState),
      hasPartialLine: partialLinePending,
    });
  }

  function hasPartialLine() {
    return ["wrapper", "child"].some((family) =>
      discardedPartialBytes.get(family) > 0 || streams.get(family).byteLength > 0);
  }

  function partialLineBytes() {
    return Object.freeze({
      wrapper: discardedPartialBytes.get("wrapper") + streams.get("wrapper").byteLength,
      child: discardedPartialBytes.get("child") + streams.get("child").byteLength,
    });
  }

  return Object.freeze({ consume, snapshot, hasPartialLine, partialLineBytes });
}

export function createServiceStartupObservationEmitter(options) {
  const opts = optionValues(options, ["binding", "expectedState", "writable"]);
  const binding = captureBinding(opts.binding);
  const expectedState = captureExpectedState(binding.component, opts.expectedState);
  const writable = opts.writable;
  if (writable === null || typeof writable !== "object" || typeof writable.write !== "function" ||
      typeof writable.on !== "function" || typeof writable.off !== "function") invalid();

  let sequence = 0;
  let pendingBytes = 0;
  let active = null;
  let failed = null;
  let closing = false;
  let closed = false;
  const queue = [];
  const flushWaiters = new Set();

  const rejectWaiters = (error) => {
    for (const waiter of flushWaiters) waiter.reject(error);
    flushWaiters.clear();
  };
  const settleFailure = () => {
    if (failed === null) failed = emitterFailed();
    const pending = [...queue, ...(active === null ? [] : [active])];
    queue.length = 0;
    active = null;
    pendingBytes = 0;
    for (const item of pending) {
      if (item.settled) continue;
      item.settled = true;
      item.reject(failed);
    }
    rejectWaiters(failed);
    return failed;
  };
  const onError = () => { settleFailure(); };
  try {
    writable.on("error", onError);
  } catch {
    invalid();
  }

  const resolveFlushWaiters = () => {
    if (pendingBytes !== 0 || active !== null || queue.length !== 0 || failed !== null) return;
    for (const waiter of flushWaiters) waiter.resolve();
    flushWaiters.clear();
  };

  const pump = () => {
    if (active !== null || failed !== null) return;
    const item = queue.shift();
    if (item === undefined) {
      resolveFlushWaiters();
      return;
    }
    active = item;
    try {
      writable.write(item.bytes, (error) => {
        if (active !== item || item.settled) return;
        active = null;
        pendingBytes -= item.bytes.byteLength;
        item.settled = true;
        if (error) {
          const failure = settleFailure();
          item.reject(failure);
          return;
        }
        item.resolve();
        queueMicrotask(pump);
      });
    } catch {
      settleFailure();
    }
  };

  function emit(state) {
    if (failed !== null) return Promise.reject(failed);
    if (closing || closed) return Promise.reject(emitterFailed());
    if (sequence >= Number.MAX_SAFE_INTEGER) return Promise.reject(settleFailure());
    let event;
    let bytes;
    try {
      event = validateServiceStartupObservationEvent({
        schemaVersion: 1,
        kind: "service-startup-observation",
        component: binding.component,
        serviceKey: binding.serviceKey,
        processEpochFingerprint: binding.processEpochFingerprint,
        sequence: sequence + 1,
        effectiveConfigFingerprint: binding.effectiveConfigFingerprint,
        configSourceIdentityFingerprint: binding.configSourceIdentityFingerprint,
        state,
      }, { binding, expectedState });
      bytes = Buffer.from(`${canonicalJson(event)}\n`, "utf8");
    } catch {
      return Promise.reject(settleFailure());
    }
    if (bytes.byteLength > SERVICE_STARTUP_OBSERVATION_LIMITS.eventBytes + 1 ||
        pendingBytes + bytes.byteLength > SERVICE_STARTUP_OBSERVATION_LIMITS.emitterQueueBytes) {
      return Promise.reject(settleFailure());
    }
    sequence += 1;
    pendingBytes += bytes.byteLength;
    const promise = new Promise((resolve, reject) => {
      queue.push({ bytes, resolve, reject, settled: false });
    });
    pump();
    return promise;
  }

  function flush() {
    if (failed !== null) return Promise.reject(failed);
    if (pendingBytes === 0 && active === null && queue.length === 0) return Promise.resolve();
    return new Promise((resolve, reject) => flushWaiters.add({ resolve, reject }));
  }

  async function close() {
    if (closed) {
      if (failed !== null) throw failed;
      return;
    }
    closing = true;
    try {
      await flush();
    } finally {
      closed = true;
      try { writable.off("error", onError); } catch { settleFailure(); }
    }
    if (failed !== null) throw failed;
  }

  return Object.freeze({ emit, flush, close });
}
