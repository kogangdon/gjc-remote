import { canonicalJsonHash, isHex64 } from "@gjc-remote/shared/strict-json";
import {
  SERVICE_STARTUP_OBSERVATION_LIMITS,
  createServiceStartupObservationReducer,
} from "@gjc-remote/shared/service-startup-observation";
import {
  buildServiceLogEvidence,
  SERVICE_LIFECYCLE_LIMITS,
  validateServiceBootClock,
  validateServiceCursorSet,
  validateServiceTrialBoundary,
  validateServiceKey,
} from "@gjc-remote/shared/service-lifecycle-envelope";

const TRIAL_KEYS = Object.freeze([
  "component",
  "serviceKey",
  "serviceName",
  "bootFingerprint",
  "wrapperEpochFingerprint",
  "childEpochFingerprint",
  "resourceFingerprint",
  "applicationManifestFingerprint",
  "effectiveConfigFingerprint",
  "boundaryReceipt",
]);
const LOG_READ_KEYS = Object.freeze([
  "clock",
  "beforeCursor",
  "afterCursor",
  "wrapperEpochFingerprint",
  "childEpochFingerprint",
  "treeFingerprint",
  "chunks",
  "eof",
  "continuity",
  "writes",
]);
const LOG_CHUNK_KEYS = Object.freeze(["family", "fileIdentityFingerprint", "logicalOffset", "bytes"]);
const OBSERVER_OPTION_KEYS = Object.freeze(["trialObservation", "expectedState"]);
const BOT_EXPECTED_KEYS = Object.freeze(["expectedHostSetFingerprint", "expectedHostCount"]);
const DAEMON_EXPECTED_KEYS = Object.freeze(["targetFingerprint"]);
const SAFE_SERVICE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;
const CURSOR_LIMITS = Object.freeze({
  chunksPerPage: 4096,
});

function invalid() {
  const error = new TypeError("SERVICE_STARTUP_OBSERVER_INVALID");
  error.code = "SERVICE_STARTUP_OBSERVER_INVALID";
  throw error;
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

function capture(value, keys) {
  const result = exactValues(value, keys);
  if (!result) invalid();
  return result;
}

function captureArray(value, maximumLength, exactLength = undefined) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const lengthDescriptor = descriptors.length;
    if (!lengthDescriptor || lengthDescriptor.enumerable !== false ||
        lengthDescriptor.get !== undefined || lengthDescriptor.set !== undefined ||
        !Object.hasOwn(lengthDescriptor, "value")) invalid();
    const length = lengthDescriptor.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > maximumLength ||
        (exactLength !== undefined && length !== exactLength)) invalid();
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1 || keys.some((key) => typeof key === "symbol" ||
        (key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key)))) invalid();
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[index];
      if (!descriptor || descriptor.enumerable !== true || descriptor.get !== undefined ||
          descriptor.set !== undefined || !Object.hasOwn(descriptor, "value")) invalid();
      result.push(descriptor.value);
    }
    return result;
  } catch {
    invalid();
  }
}

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function validHash(value) {
  return isHex64(value);
}

function snapshotValidatedData(value) {
  if (value === null || typeof value !== "object") return value;
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const snapshot = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[index];
      if (!descriptor || !Object.hasOwn(descriptor, "value")) invalid();
      snapshot.push(snapshotValidatedData(descriptor.value));
    }
    return Object.freeze(snapshot);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const snapshot = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") invalid();
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, "value")) invalid();
    Object.defineProperty(snapshot, key, {
      value: snapshotValidatedData(descriptor.value),
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(snapshot);
}

function validateCursorSet(value, binding) {
  try {
    validateServiceCursorSet(value);
  } catch {
    invalid();
  }
  const snapshot = snapshotValidatedData(value);
  if (snapshot.bootFingerprint !== binding.bootFingerprint || snapshot.serviceKey !== binding.serviceKey ||
      snapshot.configFingerprint !== binding.effectiveConfigFingerprint) invalid();
  return snapshot;
}

function captureTrialObservation(value) {
  const fields = capture(value, TRIAL_KEYS);
  if (!["bot", "daemon"].includes(fields.component) || typeof fields.serviceName !== "string" ||
      !SAFE_SERVICE_NAME.test(fields.serviceName) ||
      !validHash(fields.bootFingerprint) || !validHash(fields.wrapperEpochFingerprint) ||
      !validHash(fields.childEpochFingerprint) || fields.wrapperEpochFingerprint === fields.childEpochFingerprint ||
      !validHash(fields.resourceFingerprint) ||
      !validHash(fields.applicationManifestFingerprint) || !validHash(fields.effectiveConfigFingerprint)) invalid();
  try {
    validateServiceKey(fields.serviceKey, fields.component);
  } catch {
    invalid();
  }
  const receipt = capture(fields.boundaryReceipt, ["present", "value"]);
  if (receipt.present !== true) invalid();
  try {
    validateServiceTrialBoundary(receipt.value);
  } catch {
    invalid();
  }
  const boundaryFields = snapshotValidatedData(receipt.value);
  if (boundaryFields.serviceKey !== fields.serviceKey || boundaryFields.phase !== "observed" ||
      boundaryFields.bootFingerprint !== fields.bootFingerprint ||
      boundaryFields.applicationManifestFingerprint !== fields.applicationManifestFingerprint ||
      boundaryFields.resourceFingerprint !== fields.resourceFingerprint ||
      boundaryFields.effectiveConfigFingerprint !== fields.effectiveConfigFingerprint ||
      boundaryFields.wrapperEpochFingerprint !== fields.wrapperEpochFingerprint ||
      boundaryFields.childEpochFingerprint !== fields.childEpochFingerprint ||
      boundaryFields.wrapperEpochFingerprint === boundaryFields.childEpochFingerprint) invalid();
  const binding = Object.freeze({
    component: fields.component,
    serviceKey: fields.serviceKey,
    bootFingerprint: fields.bootFingerprint,
    effectiveConfigFingerprint: fields.effectiveConfigFingerprint,
  });
  const initialCursor = validateCursorSet(boundaryFields.initialCursor, binding);
  const childCursor = boundaryFields.childCursor === null
    ? null
    : validateCursorSet(boundaryFields.childCursor, binding);
  const boundary = Object.freeze({ ...boundaryFields, initialCursor, childCursor });
  return Object.freeze({ ...fields, boundary });
}

function captureExpectedState(component, value) {
  const fields = capture(value, component === "bot" ? BOT_EXPECTED_KEYS : DAEMON_EXPECTED_KEYS);
  if (component === "bot") {
    if (!validHash(fields.expectedHostSetFingerprint) || !Number.isSafeInteger(fields.expectedHostCount) ||
        fields.expectedHostCount < 0 || fields.expectedHostCount > SERVICE_STARTUP_OBSERVATION_LIMITS.hostCount) invalid();
  } else if (!validHash(fields.targetFingerprint)) {
    invalid();
  }
  return Object.freeze({ ...fields });
}

function cursorEquals(left, right) {
  try { return canonicalJsonHash(left) === canonicalJsonHash(right); } catch { return false; }
}

function validateLogRead(value, trial, previousCursor, lastTickMs) {
  const fields = capture(value, LOG_READ_KEYS);
  try {
    validateServiceBootClock(fields.clock);
  } catch {
    invalid();
  }
  const clock = snapshotValidatedData(fields.clock);
  if (clock.bootFingerprint !== trial.bootFingerprint ||
      !nonnegative(clock.tickMs) || clock.tickMs < trial.boundary.startTickMs ||
      clock.tickMs > trial.boundary.deadlineTickMs || clock.tickMs < lastTickMs || clock.writes !== 0 ||
      fields.wrapperEpochFingerprint !== trial.wrapperEpochFingerprint ||
      fields.childEpochFingerprint !== trial.childEpochFingerprint || !validHash(fields.treeFingerprint) ||
      typeof fields.eof !== "boolean" ||
      fields.continuity !== "complete" || fields.writes !== 0) invalid();
  const rawChunks = captureArray(fields.chunks, CURSOR_LIMITS.chunksPerPage);
  const binding = {
    component: trial.component,
    serviceKey: trial.serviceKey,
    bootFingerprint: trial.bootFingerprint,
    effectiveConfigFingerprint: trial.effectiveConfigFingerprint,
  };
  const beforeCursor = validateCursorSet(fields.beforeCursor, binding);
  const afterCursor = validateCursorSet(fields.afterCursor, binding);
  if (!cursorEquals(beforeCursor, previousCursor)) invalid();
  for (let index = 0; index < 2; index += 1) {
    if (afterCursor.families[index].directoryIdentityFingerprint !== beforeCursor.families[index].directoryIdentityFingerprint ||
        afterCursor.families[index].nextLogicalOffset < beforeCursor.families[index].nextLogicalOffset) invalid();
  }
  if (afterCursor.families.some((family) => family.partialLineBytes > SERVICE_STARTUP_OBSERVATION_LIMITS.lineBytes)) invalid();
  let pageBytes = 0;
  const chunks = [];
  for (const rawChunk of rawChunks) {
    const chunk = capture(rawChunk, LOG_CHUNK_KEYS);
    if (!["wrapper", "child"].includes(chunk.family) || !validHash(chunk.fileIdentityFingerprint) ||
        !nonnegative(chunk.logicalOffset) || (!Buffer.isBuffer(chunk.bytes) && !(chunk.bytes instanceof Uint8Array))) invalid();
    if (chunk.logicalOffset > SERVICE_LIFECYCLE_LIMITS.startupCursorLogicalBytes) invalid();
    let byteLength;
    try { byteLength = chunk.bytes.byteLength; } catch { invalid(); }
    pageBytes += byteLength;
    if (pageBytes > SERVICE_STARTUP_OBSERVATION_LIMITS.pageBytes) invalid();
    let bytes;
    try { bytes = Buffer.from(chunk.bytes); } catch { invalid(); }
    const fileCursors = [
      ...beforeCursor.families[chunk.family === "wrapper" ? 0 : 1].files,
      ...afterCursor.families[chunk.family === "wrapper" ? 0 : 1].files,
    ];
    if (!fileCursors.some((candidate) => candidate.identityFingerprint === chunk.fileIdentityFingerprint)) invalid();
    chunks.push(Object.freeze({
      family: chunk.family,
      fileIdentityFingerprint: chunk.fileIdentityFingerprint,
      logicalOffset: chunk.logicalOffset,
      bytes,
    }));
  }
  if (pageBytes > 0 && beforeCursor.cursorFingerprint === afterCursor.cursorFingerprint) invalid();
  return Object.freeze({
    clock: Object.freeze({ schemaVersion: 1, bootFingerprint: clock.bootFingerprint, tickMs: clock.tickMs, writes: 0 }),
    beforeCursor,
    afterCursor,
    wrapperEpochFingerprint: fields.wrapperEpochFingerprint,
    childEpochFingerprint: fields.childEpochFingerprint,
    treeFingerprint: fields.treeFingerprint,
    chunks: Object.freeze(chunks),
    eof: fields.eof,
    continuity: "complete",
    writes: 0,
  });
}

function reduceChunks(reducer, chunks) {
  for (const chunk of chunks) reducer.consume(chunk.family, chunk.bytes);
}

function applicationEvidenceFingerprint(trial, stateSnapshot, logEvidence) {
  return canonicalJsonHash({
    schemaVersion: 1,
    kind: "service-startup-application-evidence",
    component: trial.component,
    serviceKey: trial.serviceKey,
    serviceName: trial.serviceName,
    boundaryFingerprint: trial.boundary.boundaryFingerprint,
    bootFingerprint: trial.bootFingerprint,
    wrapperEpochFingerprint: trial.wrapperEpochFingerprint,
    childEpochFingerprint: trial.childEpochFingerprint,
    resourceFingerprint: trial.resourceFingerprint,
    applicationManifestFingerprint: trial.applicationManifestFingerprint,
    effectiveConfigFingerprint: trial.effectiveConfigFingerprint,
    configSourceIdentityFingerprint: trial.boundary.configSourceIdentityFingerprint,
    sequence: stateSnapshot.sequence,
    applicationStateFingerprint: stateSnapshot.applicationStateFingerprint,
    logEvidenceFingerprint: logEvidence.evidenceFingerprint,
  });
}

export function createServiceStartupObserver(options) {
  const opts = capture(options, OBSERVER_OPTION_KEYS);
  const trial = captureTrialObservation(opts.trialObservation);
  const expectedState = captureExpectedState(trial.component, opts.expectedState);
  const reducer = createServiceStartupObservationReducer({
    binding: {
      component: trial.component,
      serviceKey: trial.serviceKey,
      processEpochFingerprint: trial.childEpochFingerprint,
      effectiveConfigFingerprint: trial.effectiveConfigFingerprint,
      configSourceIdentityFingerprint: trial.boundary.configSourceIdentityFingerprint,
    },
    expectedState,
    initialPartialLineBytes: Object.freeze({
      wrapper: trial.boundary.childCursor.families[0].partialLineBytes,
      child: trial.boundary.childCursor.families[1].partialLineBytes,
    }),
  });
  let cursor = trial.boundary.childCursor ?? trial.boundary.initialCursor;
  const resumeCursor = cursor;
  let lastTickMs = trial.boundary.lastTickMs;
  let faulted = false;

  async function observeApplication(logRead) {
    if (faulted) invalid();
    try {
      const read = validateLogRead(logRead, trial, cursor, lastTickMs);
      reduceChunks(reducer, read.chunks);
      const partialBytes = reducer.partialLineBytes();
      if (read.afterCursor.families[0].partialLineBytes !== partialBytes.wrapper ||
          read.afterCursor.families[1].partialLineBytes !== partialBytes.child) invalid();
      cursor = read.afterCursor;
      lastTickMs = read.clock.tickMs;
      if (!read.eof || read.clock.tickMs >= trial.boundary.deadlineTickMs) return null;
      const stateSnapshot = reducer.snapshot();
      if (stateSnapshot === null || !stateSnapshot.ready) return null;
      const logEvidence = buildServiceLogEvidence({
        boundaryFingerprint: trial.boundary.boundaryFingerprint,
        bootFingerprint: trial.bootFingerprint,
        observedTickMs: read.clock.tickMs,
        wrapperEpochFingerprint: trial.wrapperEpochFingerprint,
        childEpochFingerprint: trial.childEpochFingerprint,
        treeFingerprint: read.treeFingerprint,
        fromCursorFingerprint: resumeCursor.cursorFingerprint,
        toCursor: read.afterCursor,
        completeEof: true,
        applicationStateFingerprint: stateSnapshot.applicationStateFingerprint,
      }, trial.boundary);
      return Object.freeze({
        ready: true,
        applicationEvidenceFingerprint: applicationEvidenceFingerprint(trial, stateSnapshot, logEvidence),
        logEvidence,
      });
    } catch {
      faulted = true;
      invalid();
    }
  }

  // The function has no native/OS callback or loader argument. The caller must
  // supply a LogRead already returned by its private, session-bound native read.
  Object.defineProperties(observeApplication, {
    name: { value: "observeApplication", configurable: true },
    length: { value: 1, configurable: true },
  });
  return Object.freeze({ observeApplication });
}
