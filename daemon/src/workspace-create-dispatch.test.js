import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

import { createLifecycleCreateDispatcher } from "../src/workspace-create-dispatch.js";
import { MSG_TYPES } from "@gjc-remote/shared";

// ---------------------------------------------------------------------------
// Test doubles. Deterministic: no fs, no subprocess, no native addon, no git.
// The real-git / native-containment end-to-end pipeline is descoped to S7
// (issue #171); this slice proves the authorization + derivation + refusal +
// orchestrator-wiring security core with injected fakes (mirrors the landed
// workspace-refresh-operation.test.js pattern).
// ---------------------------------------------------------------------------

const ROUTE_FP = "a".repeat(64);
const AUTH_FP = "b".repeat(64);
const IDEMPOTENCY_FP = "c".repeat(64);
const GIT_FP = "d".repeat(64);

const ROOT_IDENTITY = Object.freeze({ platform: "posix", volumeId: "vol-1", inode: "1001" });
const STORAGE_IDENTITY = Object.freeze({ platform: "posix", volumeId: "vol-1" });

function fakeHashIdentity(identity) {
  return createHash("sha256").update(JSON.stringify(identity)).digest("hex");
}

// The 9-field authority tuple, exactly as an accepted BIND_WORKSPACE binding
// record stores it, plus (deliberately) an extra field to prove the dispatcher
// projects only the 9 fields via workspaceLifecycleAuthority.
function baseAuthority(overrides = {}) {
  return {
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 1,
    sourcePlatform: "posix",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
    // extra, non-authority field that must be ignored by the 9-field projection:
    bindingId: "mapping-1",
    ...overrides,
  };
}

function createMessage(overrides = {}) {
  return {
    type: MSG_TYPES.WORKSPACE_CREATE,
    operation: "create",
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 1,
    sourcePlatform: "posix",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
    inventoryGeneration: 5,
    idempotencyFingerprint: IDEMPOTENCY_FP,
    ...overrides,
  };
}

const inventoryWorkspace = Object.freeze({
  hostId: "host-1",
  workspaceId: "workspace-1",
  sourcePlatform: "posix",
  workDir: "/srv/ws/workspace-1",
  rootIdentityFingerprint: "e".repeat(64),
  storageIdentityFingerprint: "f".repeat(64),
});

function liveReadiness() {
  return {
    connection: { state: "online", source: "live" },
    runtime: { state: "ready", source: "live" },
    providerAuth: { state: "configured", source: "live" },
    modelProfile: { state: "ready", source: "live" },
  };
}

function fakeContainment(overrides = {}) {
  return {
    identifyRoot: overrides.identifyRoot ??
      (async () => ({ rootIdentity: { ...ROOT_IDENTITY }, storageIdentity: { ...STORAGE_IDENTITY } })),
    verifyContained: overrides.verifyContained ??
      (async () => ({ identity: { inode: "leaf" }, rootIdentity: { ...ROOT_IDENTITY } })),
  };
}

function fakeGitVerifier(overrides = {}) {
  return {
    verifyRepositoryGraph: overrides.verifyRepositoryGraph ??
      (async () => ({ gitVersion: "2.44.0", bare: false, head: "b".repeat(40), refs: [], objectCount: 3, generationFingerprint: GIT_FP })),
  };
}

// In-memory live-pointer slot. `fail` names a publish step to throw at.
function fakePublishIo(initialBytes = null, { fail = null } = {}) {
  const state = { live: initialBytes, temp: null, order: [], replaceCount: 0 };
  const mark = (step) => {
    state.order.push(step);
    if (fail === step) { const e = new Error(`disk lost at ${step}`); e.code = "EIO"; throw e; }
  };
  return {
    state,
    readLivePointer: async () => { mark("readLivePointer"); return state.live; },
    writeTemp: async (bytes) => { mark("writeTemp"); state.temp = bytes; return "temp-ref"; },
    flushTemp: async () => { mark("flushTemp"); },
    replace: async () => { mark("replace"); state.replaceCount++; state.live = state.temp; },
    flushParent: async () => { mark("flushParent"); },
  };
}

function newSeen() {
  const set = new Set();
  return { has: (fp) => set.has(fp), add: (fp) => set.add(fp), set };
}

// Assemble a dispatcher + the mutable fakes it closes over, so tests can assert
// call counts / pointer state after dispatch. The trusted binding + inventory
// are per-CALL inputs (the daemon resolves them from its per-connection state),
// so they are NOT part of the harness config.
function makeHarness(over = {}) {
  const materializeCalls = { count: 0 };
  const publishIo = over.publishIo ?? fakePublishIo(null);
  const replaySeen = over.replaySeen ?? newSeen();
  const config = {
    workspaceRoot: over.workspaceRoot ?? "/srv/ws",
    containment: over.containment ?? fakeContainment(),
    gitVerifier: over.gitVerifier ?? fakeGitVerifier(),
    makeManifestIo: over.makeManifestIo ??
      (() => ({ readBytes: async (rel) => Buffer.from(`content:${rel}`) })),
    makePublisherIo: over.makePublisherIo ?? (async () => publishIo),
    materialize: over.materialize ?? (async () => { materializeCalls.count++; }),
    resolveManifestPaths: over.resolveManifestPaths ?? (async () => ["a.txt", "b.txt"]),
    clock: over.clock ?? { now: () => 1_000 },
    maxAgeMs: over.maxAgeMs ?? 5_000,
    replaySeen,
    hashIdentity: over.hashIdentity ?? fakeHashIdentity,
  };
  return { dispatcher: createLifecycleCreateDispatcher(config), publishIo, materializeCalls, replaySeen };
}

// Default happy-path call args.
function callArgs(over = {}) {
  return {
    message: over.message ?? createMessage(),
    trustedBinding: over.trustedBinding === undefined ? baseAuthority() : over.trustedBinding,
    trustedInventoryWorkspace: over.trustedInventoryWorkspace === undefined ? inventoryWorkspace : over.trustedInventoryWorkspace,
    readiness: over.readiness ?? liveReadiness(),
  };
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

test("factory refuses config missing workspaceRoot", () => {
  assert.throws(() => makeHarness({ workspaceRoot: "" }), (e) => e.code === "CONFIG_INVALID");
});

test("factory refuses config with a non-function makePublisherIo", () => {
  assert.throws(
    () => createLifecycleCreateDispatcher({ ...validConfig(), makePublisherIo: "nope" }),
    (e) => e.code === "CONFIG_INVALID",
  );
});

function validConfig() {
  return {
    workspaceRoot: "/srv/ws",
    containment: fakeContainment(),
    gitVerifier: fakeGitVerifier(),
    makeManifestIo: () => ({ readBytes: async () => Buffer.from("x") }),
    makePublisherIo: async () => fakePublishIo(null),
    materialize: async () => {},
    resolveManifestPaths: async () => ["a.txt"],
    clock: { now: () => 1 },
    maxAgeMs: 5_000,
    replaySeen: newSeen(),
    hashIdentity: fakeHashIdentity,
  };
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

test("create: authorized message + matching binding publishes the first generation", async () => {
  const { dispatcher, publishIo, materializeCalls } = makeHarness();
  const result = await dispatcher.dispatchCreate(callArgs());

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(materializeCalls.count, 1);
  assert.equal(publishIo.state.replaceCount, 1);
  assert.ok(publishIo.state.order.includes("replace"));
  assert.equal(result.receipt.operation, "create");
  assert.equal(result.receipt.gitGenerationFingerprint, GIT_FP);
  assert.equal(typeof result.receipt.generationPointerFingerprint, "string");
  assert.ok(Object.isFrozen(result));
});

test("create: clone operation is accepted", async () => {
  const { dispatcher } = makeHarness();
  const result = await dispatcher.dispatchCreate(callArgs({ message: createMessage({ operation: "clone" }) }));
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.receipt.operation, "clone");
});

// ---------------------------------------------------------------------------
// Negative authorization: message can NEVER self-authorize. The trusted tuple
// comes only from the accepted binding; a tampered field fails closed BEFORE
// the orchestrator (materialize/publish) is ever reached.
// ---------------------------------------------------------------------------

for (const [field, tampered] of [
  ["mappingGeneration", 99],
  ["routeFingerprint", "9".repeat(64)],
  ["authorityFingerprint", "8".repeat(64)],
  ["workspaceGeneration", 7],
  ["mappingId", "mapping-evil"],
]) {
  test(`create: tampered ${field} is refused unauthorized and never reaches the orchestrator`, async () => {
    const { dispatcher, publishIo, materializeCalls } = makeHarness();
    const result = await dispatcher.dispatchCreate(callArgs({ message: createMessage({ [field]: tampered }) }));
    assert.equal(result.ok, false);
    assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
    assert.equal(materializeCalls.count, 0, "materialize must not run on unauthorized create");
    assert.equal(publishIo.state.order.length, 0, "publishIo must not be touched on unauthorized create");
  });
}

// F1: cross-workspace swap. An attacker who controls workspace-1's binding
// targets workspace-2. The daemon resolves workspace-2's REAL trusted binding
// (its own fingerprints), so the attacker's workspace-1-derived message cannot
// match -- refused, orchestrator never reached.
test("create: workspaceId-swap against another workspace's binding is refused", async () => {
  const { dispatcher, publishIo, materializeCalls } = makeHarness();
  const victimBinding = baseAuthority({
    workspaceId: "workspace-2",
    routeFingerprint: "1".repeat(64),
    authorityFingerprint: "2".repeat(64),
  });
  // The attacker can only forge a message from workspace-1's authority (their
  // own binding's fingerprints), but sets workspaceId to the victim's.
  const forged = createMessage({
    workspaceId: "workspace-2",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
  });
  const result = await dispatcher.dispatchCreate({
    message: forged,
    trustedBinding: victimBinding,
    trustedInventoryWorkspace: { ...inventoryWorkspace, workspaceId: "workspace-2" },
    readiness: liveReadiness(),
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(materializeCalls.count, 0);
  assert.equal(publishIo.state.order.length, 0);
});

test("create: no accepted binding for the workspace is refused before the orchestrator", async () => {
  const { dispatcher, publishIo, materializeCalls } = makeHarness();
  const result = await dispatcher.dispatchCreate(callArgs({ trustedBinding: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(materializeCalls.count, 0);
  assert.equal(publishIo.state.order.length, 0);
});

test("create: missing trusted inventory workspace is refused", async () => {
  const { dispatcher, materializeCalls } = makeHarness();
  const result = await dispatcher.dispatchCreate({
    message: createMessage(),
    trustedBinding: baseAuthority(),
    trustedInventoryWorkspace: undefined,
    readiness: liveReadiness(),
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(materializeCalls.count, 0);
});

// ---------------------------------------------------------------------------
// Fail-closed durability (CRIT-F2): a publish/containment failure never
// corrupts the live pointer and never returns ok.
// ---------------------------------------------------------------------------

test("create: a throw at atomic replace preserves the prior (empty) live pointer", async () => {
  const publishIo = fakePublishIo(null, { fail: "replace" });
  const { dispatcher } = makeHarness({ publishIo });
  const result = await dispatcher.dispatchCreate(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_GENERATION_IO_FAILED");
  assert.equal(publishIo.state.live, null, "live pointer must be unchanged after a failed replace");
});

test("create: a containment escape is refused and publish is never reached", async () => {
  const containment = fakeContainment({
    verifyContained: async () => {
      const e = new Error("root escape");
      e.code = "WORKSPACE_ROOT_ESCAPE";
      throw e;
    },
  });
  const publishIo = fakePublishIo(null);
  const { dispatcher } = makeHarness({ containment, publishIo });
  const result = await dispatcher.dispatchCreate(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_ROOT_ESCAPE");
  assert.equal(publishIo.state.order.includes("replace"), false);
});

// ---------------------------------------------------------------------------
// Anti-replay (ARCH-F4): a REAL shared seen-set makes an identical second
// create fail closed with READINESS_REPLAYED (the orchestrator's single-use
// readiness attestation), proving replaySeen is not stubbed to always-unseen.
// ---------------------------------------------------------------------------

test("create: an identical second dispatch replays and is refused", async () => {
  const replaySeen = newSeen();
  const { dispatcher } = makeHarness({ replaySeen });
  const first = await dispatcher.dispatchCreate(callArgs());
  assert.equal(first.ok, true, JSON.stringify(first));
  const second = await dispatcher.dispatchCreate(callArgs());
  assert.equal(second.ok, false);
  assert.equal(second.code, "READINESS_REPLAYED");
});

// ---------------------------------------------------------------------------
// Platform vocabulary: windows-unc is not containment-verifiable and is
// refused up front (after authorization, before derivation).
// ---------------------------------------------------------------------------

test("create: windows-unc source platform is refused CONTAINMENT_UNSUPPORTED", async () => {
  const { dispatcher, materializeCalls } = makeHarness();
  const result = await dispatcher.dispatchCreate({
    message: createMessage({ sourcePlatform: "windows-unc" }),
    trustedBinding: baseAuthority({ sourcePlatform: "windows-unc" }),
    trustedInventoryWorkspace: { ...inventoryWorkspace, sourcePlatform: "windows-unc" },
    readiness: liveReadiness(),
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "CONTAINMENT_UNSUPPORTED");
  assert.equal(materializeCalls.count, 0);
});
