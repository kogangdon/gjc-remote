import assert from "node:assert/strict";
import { test } from "node:test";
import {
  SERVICE_LIFECYCLE_LIMITS,
  buildServiceBootClock,
  buildServiceCursorSet,
  buildServiceFamilyCursor,
  buildServiceFileCursor,
  buildServiceLogEvidence,
  buildServiceStartupProof,
  buildServiceTrialBoundary,
  buildServicePlatformState,
  serviceTrialDeadlineTickMs,
  serviceTrialBoundaryFingerprint,
  serviceNativeIdentityFingerprint,
  validateServiceBootClock,
  validateServiceCursorSet,
  validateServiceLogEvidence,
  validateServiceNativeIdentity,
  validateServiceStartupProof,
  validateServiceTrialBoundary,
  validateServiceTrialBoundarySuccessor,
  win32PhysicalSecurityIdentityFingerprint,
} from "../service-lifecycle-envelope.js";

const hash = (character) => character.repeat(64);

const physicalIdentity = Object.freeze({
  attributes: 32,
  fileId: "0123456789abcdef0123456789abcdef",
  kind: "gjc-remote/win32-physical-security-identity/v1",
  owner: "S-1-5-21-1001",
  securitySha256: hash("a"),
  volumeSerial: "0123456789abcdef",
});

test("Windows physical-security correlation binds every OS fact to its exact domain", () => {
  const expected = "8f4ebc6e334938400a88c546f4771de8ac3dad79f742b23f09ab8fb70130971d";
  assert.equal(win32PhysicalSecurityIdentityFingerprint(physicalIdentity), expected);
  for (const [key, value] of [
    ["attributes", 0], ["attributes", 0xffffffff],
    ["fileId", "f".repeat(32)], ["owner", "S-1-5-21-1002"],
    ["securitySha256", hash("b")], ["volumeSerial", "f".repeat(16)],
  ]) {
    assert.notEqual(win32PhysicalSecurityIdentityFingerprint({ ...physicalIdentity, [key]: value }), expected, key);
  }
  for (const [key, value] of [
    ["kind", "gjc-remote/win32-physical-security-identity/v2"],
    ["attributes", -1], ["attributes", 0x100000000], ["attributes", 1.5],
    ["fileId", "f".repeat(64)], ["fileId", "F".repeat(32)],
    ["volumeSerial", "f".repeat(64)], ["volumeSerial", "F".repeat(16)],
    ["owner", "S-2-5-21-1001"], ["owner", "S-1-5-4294967296"],
    ["securitySha256", "a".repeat(63)],
  ]) {
    assert.throws(() => win32PhysicalSecurityIdentityFingerprint({ ...physicalIdentity, [key]: value }),
      /SERVICE_LIFECYCLE_ENVELOPE_INVALID/, key);
  }
});

test("physical correlation never substitutes for full role-profile identity evidence", () => {
  const bot = { ...physicalIdentity, kind: "win32-service-object-v1", profile: "service-bot-config-file" };
  const daemon = { ...bot, profile: "service-daemon-config-file" };
  assert.notEqual(serviceNativeIdentityFingerprint(bot, "win32"), serviceNativeIdentityFingerprint(daemon, "win32"));
  assert.throws(() => validateServiceNativeIdentity(daemon, "win32", bot.profile), /SERVICE_LIFECYCLE_ENVELOPE_INVALID/);
  for (const profiled of [bot, daemon, { ...bot, profile: "service-control-file" }]) {
    assert.throws(() => win32PhysicalSecurityIdentityFingerprint(profiled), /SERVICE_LIFECYCLE_ENVELOPE_INVALID/);
    const raw = {
      attributes: profiled.attributes, fileId: profiled.fileId, kind: physicalIdentity.kind,
      owner: profiled.owner, securitySha256: profiled.securitySha256, volumeSerial: profiled.volumeSerial,
    };
    assert.equal(win32PhysicalSecurityIdentityFingerprint(raw), win32PhysicalSecurityIdentityFingerprint(physicalIdentity));
  }
});

test("physical-security correlation rejects accessor and non-data input before reading values", () => {
  let reads = 0;
  const accessor = { ...physicalIdentity };
  Object.defineProperty(accessor, "owner", { enumerable: true, get() { reads += 1; return physicalIdentity.owner; } });
  const hidden = { ...physicalIdentity };
  Object.defineProperty(hidden, "extra", { value: true });
  for (const value of [
    accessor, hidden, { ...physicalIdentity, [Symbol("extra")]: true },
    Object.assign(Object.create(null), physicalIdentity), { ...physicalIdentity, profile: "service-control-file" },
  ]) {
    assert.throws(() => win32PhysicalSecurityIdentityFingerprint(value), /SERVICE_LIFECYCLE_ENVELOPE_INVALID/);
  }
  assert.equal(reads, 0);
});

function familyCursor(family, { offset = 4_096, length = 128, partialLineBytes = 4, absent = false } = {}) {
  return buildServiceFamilyCursor({
    family,
    baseName: `gjc-remote-bot-${family}`,
    directoryIdentityFingerprint: hash(family === "wrapper" ? "a" : "b"),
    files: absent ? [] : [buildServiceFileCursor({
      identityFingerprint: hash(family === "wrapper" ? "c" : "d"),
      logicalStartOffset: offset,
      observedLength: length,
      prefixSha256: hash(family === "wrapper" ? "e" : "f"),
    })],
    nextLogicalOffset: absent ? 0 : offset + length,
    partialLineBytes: absent ? 0 : partialLineBytes,
    absenceFingerprint: absent ? hash("8") : null,
  });
}

function cursorSet({
  bootFingerprint = hash("1"),
  configFingerprint = hash("9"),
  wrapperOffset = 4_096,
  childOffset = 4_096,
  absentWrapper = false,
  absentChild = false,
} = {}) {
  return buildServiceCursorSet({
    bootFingerprint,
    serviceKey: "bot",
    configFingerprint,
    families: [
      familyCursor("wrapper", { offset: wrapperOffset, absent: absentWrapper }),
      familyCursor("child", { offset: childOffset, absent: absentChild }),
    ],
  });
}

function boundary(fields = {}) {
  const bootFingerprint = fields.bootFingerprint ?? hash("1");
  const effectiveConfigFingerprint = fields.effectiveConfigFingerprint ?? hash("9");
  const values = {
    serviceKey: "bot",
    transactionId: "tx-trial",
    transactionNonce: "a".repeat(32),
    transitionFingerprint: hash("2"),
    attempt: 1,
    revision: 1,
    previousBoundaryFingerprint: null,
    phase: "captured",
    bootFingerprint,
    startTickMs: 1_000,
    lastTickMs: 1_000,
    applicationManifestFingerprint: hash("3"),
    resourceFingerprint: hash("4"),
    effectiveConfigFingerprint,
    configSourceIdentityFingerprint: hash("5"),
    wrapperEpochFingerprint: null,
    childEpochFingerprint: null,
    initialCursor: fields.initialCursor ?? cursorSet({ bootFingerprint, configFingerprint: effectiveConfigFingerprint }),
    childCursor: null,
    ...fields,
  };
  for (const generated of ["schemaVersion", "kind", "deadlineTickMs", "boundaryFingerprint"]) delete values[generated];
  return buildServiceTrialBoundary(values);
}

function observedBoundary(previous, fields = {}) {
  return boundary({
    ...previous,
    phase: "observed",
    revision: previous.revision + 1,
    previousBoundaryFingerprint: previous.boundaryFingerprint,
    lastTickMs: previous.lastTickMs + 100,
    wrapperEpochFingerprint: hash("6"),
    childEpochFingerprint: hash("7"),
    childCursor: cursorSet({ bootFingerprint: previous.bootFingerprint, configFingerprint: previous.effectiveConfigFingerprint }),
    ...fields,
  });
}

test("BootClock and checked Windows deadline accept safe monotonic ticks only", () => {
  const clock = buildServiceBootClock({ bootFingerprint: hash("1"), tickMs: Number.MAX_SAFE_INTEGER - 60_000 });
  assert.equal(validateServiceBootClock(clock), clock);
  assert.equal(clock.writes, 0);
  assert.equal(serviceTrialDeadlineTickMs(clock.tickMs), Number.MAX_SAFE_INTEGER);
  assert.throws(() => serviceTrialDeadlineTickMs(Number.MAX_SAFE_INTEGER - 59_999), /INVALID/);
  assert.throws(() => buildServiceBootClock({ bootFingerprint: hash("1"), tickMs: -1 }), /INVALID/);
  assert.throws(() => buildServiceBootClock({ bootFingerprint: hash("1"), tickMs: 1.5 }), /INVALID/);
  assert.throws(() => validateServiceBootClock({ ...clock, writes: 1 }), /INVALID/);
});

test("cursor schemas bind both log families, preserve nonzero offsets, and anchor absence", () => {
  const set = cursorSet({ absentWrapper: true });
  assert.equal(validateServiceCursorSet(set), set);
  assert.equal(set.families[0].absenceFingerprint, hash("8"));
  assert.equal(set.families[0].nextLogicalOffset, 0);
  assert.equal(set.families[1].files[0].logicalStartOffset, 4_096);
  assert.deepEqual(set.families.map(({ family }) => family), ["wrapper", "child"]);

  const partialLineLimit = buildServiceFamilyCursor({
    family: "wrapper",
    baseName: "gjc-remote-bot-wrapper",
    directoryIdentityFingerprint: hash("a"),
    files: [buildServiceFileCursor({
      identityFingerprint: hash("c"),
      logicalStartOffset: 0,
      observedLength: SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes,
      prefixSha256: hash("e"),
    })],
    nextLogicalOffset: SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes,
    partialLineBytes: SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes,
    absenceFingerprint: null,
  });
  assert.equal(partialLineLimit.partialLineBytes, SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes);
  assert.throws(() => buildServiceFamilyCursor({
    ...partialLineLimit,
    files: [
      {
        ...partialLineLimit.files[0],
        observedLength: SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes + 1,
      },
    ],
    nextLogicalOffset: SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes + 1,
    partialLineBytes: SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes + 1,
  }), /INVALID/);

  assert.throws(() => buildServiceFamilyCursor({
    family: "wrapper",
    baseName: "gjc-remote-bot-wrapper",
    directoryIdentityFingerprint: hash("a"),
    files: [],
    nextLogicalOffset: 0,
    partialLineBytes: 1,
    absenceFingerprint: hash("8"),
  }), /INVALID/);
  assert.throws(() => buildServiceFamilyCursor({
    family: "wrapper",
    baseName: "gjc-remote-bot-wrapper",
    directoryIdentityFingerprint: hash("a"),
    files: [
      { identityFingerprint: hash("c"), logicalStartOffset: 8, observedLength: 4, prefixSha256: hash("e") },
      { identityFingerprint: hash("d"), logicalStartOffset: 13, observedLength: 1, prefixSha256: hash("f") },
    ],
    nextLogicalOffset: 14,
    partialLineBytes: 0,
    absenceFingerprint: null,
  }), /INVALID/);
  assert.throws(() => buildServiceFileCursor({
    identityFingerprint: hash("c"),
    logicalStartOffset: Number.MAX_SAFE_INTEGER,
    observedLength: 1,
    prefixSha256: hash("e"),
  }), /INVALID/);
  assert.throws(() => buildServiceFileCursor({
    identityFingerprint: hash("c"),
    logicalStartOffset: 0,
    observedLength: SERVICE_LIFECYCLE_LIMITS.startupCursorFileBytes + 1,
    prefixSha256: hash("e"),
  }), /INVALID/);
  assert.throws(() => buildServiceFamilyCursor({
    family: "child",
    baseName: "gjc-remote-bot-child",
    directoryIdentityFingerprint: hash("a"),
    files: Array.from({ length: SERVICE_LIFECYCLE_LIMITS.startupCursorFilesPerFamily + 1 }, (_, index) => ({
      identityFingerprint: hash("c"),
      logicalStartOffset: index,
      observedLength: 0,
      prefixSha256: hash("e"),
    })),
    nextLogicalOffset: SERVICE_LIFECYCLE_LIMITS.startupCursorFilesPerFamily + 1,
    partialLineBytes: 0,
    absenceFingerprint: null,
  }), /INVALID/);
});

test("trial boundary fixes a 60-second original budget and constrains same-attempt revisions", () => {
  const captured = boundary();
  assert.equal(validateServiceTrialBoundary(captured), captured);
  assert.equal(captured.deadlineTickMs, 61_000);
  assert.equal(captured.previousBoundaryFingerprint, null);
  assert.equal(captured.childCursor, null);

  const observed = observedBoundary(captured);
  assert.equal(validateServiceTrialBoundarySuccessor(captured, observed), observed);
  assert.equal(observed.initialCursor.cursorFingerprint, captured.initialCursor.cursorFingerprint);
  assert.equal(observed.startTickMs, captured.startTickMs);
  assert.equal(observed.deadlineTickMs, captured.deadlineTickMs);

  const replacedChild = observedBoundary(observed, {
    revision: observed.revision + 1,
    previousBoundaryFingerprint: observed.boundaryFingerprint,
    lastTickMs: 50_000,
    childEpochFingerprint: hash("8"),
    childCursor: cursorSet({ wrapperOffset: 4_300, childOffset: 4_300 }),
  });
  assert.equal(validateServiceTrialBoundarySuccessor(observed, replacedChild), replacedChild);
  assert.equal(replacedChild.initialCursor.cursorFingerprint, captured.initialCursor.cursorFingerprint);
  assert.equal(replacedChild.deadlineTickMs, captured.deadlineTickMs);

  assert.throws(() => validateServiceTrialBoundarySuccessor(observed, observedBoundary(observed, {
    startTickMs: 2_000,
    lastTickMs: 2_100,
  })), /INVALID/);
  assert.throws(() => validateServiceTrialBoundarySuccessor(observed, observedBoundary(observed, {
    bootFingerprint: hash("0"),
    childCursor: cursorSet({ bootFingerprint: hash("0"), configFingerprint: observed.effectiveConfigFingerprint }),
  })), /INVALID/);
  assert.throws(() => validateServiceTrialBoundarySuccessor(observed, observedBoundary(observed, {
    lastTickMs: observed.lastTickMs - 1,
  })), /INVALID/);
  assert.throws(() => boundary({ startTickMs: Number.MAX_SAFE_INTEGER - 59_999 }), /INVALID/);
  assert.throws(() => boundary({ lastTickMs: 61_001 }), /INVALID/);
  assert.throws(() => validateServiceTrialBoundarySuccessor(captured, boundary({
    ...captured,
    phase: "observed",
    revision: captured.revision + 1,
    previousBoundaryFingerprint: captured.boundaryFingerprint,
    lastTickMs: 999,
    wrapperEpochFingerprint: hash("6"),
    childEpochFingerprint: hash("7"),
    childCursor: cursorSet(),
  })), /INVALID/);

  const sameBootRetry = boundary({
    ...replacedChild,
    attempt: 2,
    revision: replacedChild.revision + 1,
    previousBoundaryFingerprint: replacedChild.boundaryFingerprint,
    phase: "captured",
    startTickMs: 10,
    lastTickMs: 10,
    wrapperEpochFingerprint: null,
    childEpochFingerprint: null,
    initialCursor: cursorSet({ bootFingerprint: replacedChild.bootFingerprint }),
    childCursor: null,
  });
  assert.throws(() => validateServiceTrialBoundarySuccessor(replacedChild, sameBootRetry), /INVALID/);

  const retry = boundary({
    ...replacedChild,
    attempt: 2,
    revision: replacedChild.revision + 1,
    previousBoundaryFingerprint: replacedChild.boundaryFingerprint,
    startTickMs: 10,
    lastTickMs: 10,
    phase: "captured",
    bootFingerprint: hash("0"),
    wrapperEpochFingerprint: null,
    childEpochFingerprint: null,
    initialCursor: cursorSet({ bootFingerprint: hash("0") }),
    childCursor: null,
  });
  assert.equal(validateServiceTrialBoundarySuccessor(replacedChild, retry), retry);
});

test("log evidence binds complete EOF, the observed boundary, epochs, cursors, and boot ticks", () => {
  const captured = boundary();
  const observed = observedBoundary(captured);
  const toCursor = cursorSet({ wrapperOffset: 4_300, childOffset: 4_300 });
  const evidence = buildServiceLogEvidence({
    boundaryFingerprint: observed.boundaryFingerprint,
    bootFingerprint: observed.bootFingerprint,
    observedTickMs: observed.lastTickMs + 10,
    wrapperEpochFingerprint: observed.wrapperEpochFingerprint,
    childEpochFingerprint: observed.childEpochFingerprint,
    treeFingerprint: hash("a"),
    fromCursorFingerprint: observed.childCursor.cursorFingerprint,
    toCursor,
    completeEof: true,
    applicationStateFingerprint: hash("b"),
  }, observed);
  assert.equal(validateServiceLogEvidence(evidence, observed), evidence);
  const { schemaVersion, evidenceFingerprint, ...evidenceFields } = evidence;
  assert.equal(schemaVersion, 1);
  assert.match(evidenceFingerprint, /^[0-9a-f]{64}$/);
  assert.throws(() => buildServiceLogEvidence({
    ...evidenceFields,
    completeEof: false,
  }, observed), /INVALID/);
  assert.throws(() => buildServiceLogEvidence({
    ...evidenceFields,
    observedTickMs: observed.deadlineTickMs + 1,
  }, observed), /INVALID/);
  assert.throws(() => buildServiceLogEvidence({
    ...evidenceFields,
    toCursor: cursorSet({ wrapperOffset: 4_000, childOffset: 4_000 }),
  }, observed), /INVALID/);
});

test("Windows startup proof has only boot-tick authorization; Linux wall schema remains unchanged", () => {
  const windows = buildServiceStartupProof({
    component: "bot",
    serviceKey: "bot",
    platform: "win32",
    architecture: "x64",
    serviceGeneration: 1,
    transactionId: "tx-trial",
    resourceProof: hash("1"),
    applicationManifestFingerprint: hash("2"),
    bootFingerprint: hash("3"),
    processEpochFingerprint: hash("4"),
    platformEvidenceFingerprint: hash("5"),
    applicationEvidenceFingerprint: hash("6"),
    platformState: buildServicePlatformState("win32", "trial"),
    clockKind: "windows-boot-tick",
    boundaryFingerprint: hash("7"),
    observedTickMs: 10_000,
    deadlineTickMs: 61_000,
    logEvidenceFingerprint: hash("8"),
    startupEvidence: "fresh-current-epoch",
    connectivityObservation: "last-observed-connected",
  });
  assert.equal(validateServiceStartupProof(windows), windows);
  assert.equal(Object.hasOwn(windows, "observedAtMs"), false);
  assert.throws(() => buildServiceStartupProof({
    component: "bot",
    serviceKey: "bot",
    platform: "win32",
    architecture: "x64",
    serviceGeneration: 1,
    transactionId: "tx-trial",
    resourceProof: hash("1"),
    applicationManifestFingerprint: hash("2"),
    bootFingerprint: hash("3"),
    processEpochFingerprint: hash("4"),
    platformEvidenceFingerprint: hash("5"),
    applicationEvidenceFingerprint: hash("6"),
    platformState: buildServicePlatformState("win32", "trial"),
    startBoundaryMs: 1_000,
    observedAtMs: 10_000,
    expiresAtMs: 61_000,
    startupEvidence: "fresh-current-epoch",
    connectivityObservation: "last-observed-connected",
  }), /INVALID/);
  const linux = buildServiceStartupProof({
    component: "bot",
    serviceKey: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 1,
    transactionId: "tx-trial",
    resourceProof: hash("1"),
    applicationManifestFingerprint: hash("2"),
    bootFingerprint: hash("3"),
    processEpochFingerprint: hash("4"),
    platformEvidenceFingerprint: hash("5"),
    applicationEvidenceFingerprint: hash("6"),
    platformState: buildServicePlatformState("linux", "trial"),
    startBoundaryMs: 1_000,
    observedAtMs: 10_000,
    expiresAtMs: 61_000,
    startupEvidence: "fresh-current-epoch",
    connectivityObservation: "last-observed-connected",
  });
  assert.equal(validateServiceStartupProof(linux), linux);
  assert.equal(Object.hasOwn(linux, "clockKind"), false);
});

test("Windows external-object identities use exact scoped profiles and the existing identity shape", () => {
  const profiles = [
    "service-external-anchor-directory",
    "service-bot-config-directory",
    "service-bot-config-file",
    "service-daemon-config-directory",
    "service-daemon-config-file",
    "service-sdk-install-directory",
    "service-sdk-install-file",
    "service-bot-retained-directory",
    "service-bot-retained-file",
    "service-daemon-retained-directory",
    "service-daemon-retained-file",
    "service-preserved-container-directory",
  ];
  const identity = (profile) => ({
    profile,
    kind: "win32-service-object-v1",
    volumeSerial: "0123456789abcdef",
    fileId: "0123456789abcdef0123456789abcdef",
    attributes: 0,
    owner: "S-1-5-18",
    securitySha256: hash("a"),
  });
  for (const profile of profiles) {
    const value = identity(profile);
    assert.equal(validateServiceNativeIdentity(value, "win32", profile), value);
  }
  assert.throws(() => validateServiceNativeIdentity(identity("service-bot-config-file"), "win32", "service-bot-config-directory"), /INVALID/);
  assert.throws(() => validateServiceNativeIdentity(identity("service-bot-config-file"), "linux"), /INVALID/);
  assert.throws(() => validateServiceNativeIdentity(identity("config"), "win32"), /INVALID/);
  assert.throws(() => validateServiceNativeIdentity({
    ...identity("service-control-directory"),
    device: "1",
    inode: "1",
    mode: 0,
  }, "win32"), /INVALID/);
});

test("new evidence validators reject getters, symbols, non-enumerables, and foreign prototypes before reads", () => {
  let getterCalls = 0;
  const accessorClock = { schemaVersion: 1, writes: 0 };
  Object.defineProperty(accessorClock, "bootFingerprint", { enumerable: true, get() { getterCalls += 1; return hash("1"); } });
  Object.defineProperty(accessorClock, "tickMs", { enumerable: true, value: 1 });
  assert.throws(() => validateServiceBootClock(accessorClock), /INVALID/);
  assert.equal(getterCalls, 0);
  const accessorFields = { tickMs: 1 };
  Object.defineProperty(accessorFields, "bootFingerprint", { enumerable: true, get() { getterCalls += 1; return hash("1"); } });
  assert.throws(() => buildServiceBootClock(accessorFields), /INVALID/);
  assert.equal(getterCalls, 0);

  const symbolClock = { ...buildServiceBootClock({ bootFingerprint: hash("1"), tickMs: 1 }), [Symbol("extra")]: true };
  assert.throws(() => validateServiceBootClock(symbolClock), /INVALID/);
  const hiddenClock = buildServiceBootClock({ bootFingerprint: hash("1"), tickMs: 1 });
  Object.defineProperty(hiddenClock, "extra", { enumerable: false, value: true });
  assert.throws(() => validateServiceBootClock(hiddenClock), /INVALID/);
  const foreignClock = Object.assign(Object.create({ inherited: true }), buildServiceBootClock({ bootFingerprint: hash("1"), tickMs: 1 }));
  assert.throws(() => validateServiceBootClock(foreignClock), /INVALID/);

  const nestedGetterCursor = cursorSet();
  const nestedFamily = nestedGetterCursor.families[0];
  Object.defineProperty(nestedFamily.files[0], "prefixSha256", { enumerable: true, get() { getterCalls += 1; return hash("e"); } });
  assert.throws(() => validateServiceCursorSet(nestedGetterCursor), /INVALID/);
  assert.equal(getterCalls, 0);

  const accessorBoundary = { ...boundary() };
  Object.defineProperty(accessorBoundary, "resourceFingerprint", {
    enumerable: true,
    get() { getterCalls += 1; return hash("4"); },
  });
  assert.throws(() => serviceTrialBoundaryFingerprint(accessorBoundary), /INVALID/);
  assert.throws(() => validateServiceTrialBoundary(accessorBoundary), /INVALID/);
  assert.equal(getterCalls, 0);
});
