import assert from "node:assert/strict";
import test from "node:test";

import { createLifecycleRefreshDispatcher } from "../src/workspace-refresh-dispatch.js";
import { buildGenerationPointer, generationPointerBytes } from "../src/workspace-generation-publisher.js";
import { MSG_TYPES } from "@gjc-remote/shared";

// ---------------------------------------------------------------------------
// Test doubles. Deterministic: no fs, no subprocess, no git, no native addon.
// Mirrors the landed workspace-refresh-operation.test.js fake set; proves the
// authorization + successor derivation + fence + optimistic-base + refusal
// security core with injected fakes. Real-git/native end-to-end is S7 (#171).
//
// dispatchRefresh's signature mirrors the S6f.2 create dispatcher; the base
// generation being refreshed is read INTERNALLY from the injected publisher io
// (readLiveGeneration), never the wire message. `leaseCandidate` (the adopted
// fence identity) is the only extra per-call host-held parameter.
// ---------------------------------------------------------------------------

const ROUTE_FP = "a".repeat(64);
const AUTH_FP = "b".repeat(64);
const IDEMPOTENCY_FP = "c".repeat(64);
const GIT_FP = "d".repeat(64);

const ROOT_IDENTITY = Object.freeze({ platform: "posix", volumeId: "vol-1", inode: "1001" });
const STORAGE_IDENTITY = Object.freeze({ platform: "posix", volumeId: "vol-1" });

function baseAuthority(overrides = {}) {
  return {
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 2,
    sourcePlatform: "posix",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
    inventoryGeneration: 5,
    bindingId: "mapping-1",
    ...overrides,
  };
}

function refreshMessage(overrides = {}) {
  return {
    type: MSG_TYPES.WORKSPACE_REFRESH,
    operation: "refresh",
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 2,
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
});

// The full fence-authority record the daemon holds (adopted binding authority +
// bindingFingerprint). The dispatcher forwards it opaquely to acquireFence.
const leaseCandidate = Object.freeze({ ...baseAuthority(), bindingFingerprint: "e".repeat(64) });

function liveReadiness() {
  return {
    connection: { state: "online", source: "live" },
    runtime: { state: "ready", source: "live" },
    providerAuth: { state: "configured", source: "live" },
    modelProfile: { state: "ready", source: "live" },
  };
}

function pointerAt(activeGeneration, priorGeneration = null, priorPointerFingerprint = null) {
  return buildGenerationPointer({
    hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "posix",
    activeGeneration,
    generationPath: `generations/${String(activeGeneration).padStart(6, "0")}`,
    rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
    gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
    priorGeneration, priorPointerFingerprint,
  });
}

function basePointer() {
  return pointerAt(1);
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

// liveBytes is the constant live pointer; `sequence` (optional) overrides
// readLivePointer per-call (last element repeats) to simulate a concurrent
// advance between the dispatcher's read and the orchestrator's re-read.
function fakePublishIo(liveBytes, { fail = null, sequence = null } = {}) {
  const state = { live: liveBytes, temp: null, order: [], reads: 0 };
  const mark = (step) => {
    state.order.push(step);
    if (fail === step) { const e = new Error(`disk lost at ${step}`); e.code = "EIO"; throw e; }
  };
  return {
    state,
    readLivePointer: async () => {
      mark("readLivePointer");
      const i = state.reads++;
      if (sequence) return sequence[Math.min(i, sequence.length - 1)];
      return state.live;
    },
    writeTemp: async (bytes) => { mark("writeTemp"); state.temp = bytes; return "temp-ref"; },
    flushTemp: async () => { mark("flushTemp"); },
    replace: async () => { mark("replace"); state.live = state.temp; },
    flushParent: async () => { mark("flushParent"); },
  };
}

function fakeFence({ current = true } = {}) {
  const state = { current, acquired: 0, releases: 0 };
  const acquireFence = () => {
    state.acquired++;
    return { fence: 7, isCurrent: () => state.current, release: () => { state.releases++; } };
  };
  return { state, acquireFence };
}

function newSeen() {
  const set = new Set();
  return { has: (fp) => set.has(fp), add: (fp) => set.add(fp), set };
}

function validConfig(over = {}) {
  return {
    workspaceRoot: over.workspaceRoot ?? "/srv/ws",
    containment: over.containment ?? fakeContainment(),
    gitVerifier: over.gitVerifier ?? fakeGitVerifier(),
    makeManifestIo: over.makeManifestIo ?? (() => ({ readBytes: async (rel) => Buffer.from(`content:${rel}`) })),
    makePublisherIo: over.makePublisherIo,
    materialize: over.materialize ?? (async () => {}),
    resolveManifestPaths: over.resolveManifestPaths ?? (async () => ["a.txt", "b.txt"]),
    acquireFence: over.acquireFence,
    clock: over.clock ?? { now: () => 1_000 },
    maxAgeMs: over.maxAgeMs ?? 5_000,
    replaySeen: over.replaySeen ?? newSeen(),
  };
}

function makeHarness(over = {}) {
  const base = over.base ?? basePointer();
  const publishIo = over.publishIo ?? fakePublishIo(generationPointerBytes(base));
  const fence = over.fence ?? fakeFence();
  const materializeCalls = { count: 0 };
  const replaySeen = over.replaySeen ?? newSeen();
  const config = validConfig({
    ...over,
    makePublisherIo: over.makePublisherIo ?? (async () => publishIo),
    materialize: over.materialize ?? (async () => { materializeCalls.count++; }),
    acquireFence: over.acquireFence ?? fence.acquireFence,
    replaySeen,
  });
  return { dispatcher: createLifecycleRefreshDispatcher(config), base, publishIo, fence, materializeCalls, replaySeen };
}

function callArgs(over = {}) {
  return {
    message: over.message ?? refreshMessage(),
    trustedBinding: over.trustedBinding === undefined ? baseAuthority() : over.trustedBinding,
    trustedInventoryWorkspace: over.trustedInventoryWorkspace === undefined ? inventoryWorkspace : over.trustedInventoryWorkspace,
    leaseCandidate: over.leaseCandidate === undefined ? leaseCandidate : over.leaseCandidate,
    readiness: over.readiness ?? liveReadiness(),
  };
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

test("factory refuses config missing workspaceRoot", () => {
  assert.throws(
    () => createLifecycleRefreshDispatcher(validConfig({
      workspaceRoot: "",
      makePublisherIo: async () => fakePublishIo(generationPointerBytes(basePointer())),
      acquireFence: () => ({ isCurrent: () => true, release: () => {} }),
    })),
    (e) => e.code === "CONFIG_INVALID",
  );
});

test("factory refuses config with a non-function acquireFence", () => {
  assert.throws(
    () => createLifecycleRefreshDispatcher(validConfig({
      makePublisherIo: async () => fakePublishIo(generationPointerBytes(basePointer())),
      acquireFence: "nope",
    })),
    (e) => e.code === "CONFIG_INVALID",
  );
});

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

test("refresh: authorized message publishes a successor chained onto the live base", async () => {
  const { dispatcher, publishIo, materializeCalls, fence } = makeHarness();
  const result = await dispatcher.dispatchRefresh(callArgs());

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(materializeCalls.count, 1);
  assert.equal(fence.state.acquired, 1);
  assert.equal(fence.state.releases, 1);
  assert.equal(result.receipt.operation, "refresh");
  assert.equal(result.receipt.published.activeGeneration, 2);
  assert.equal(result.receipt.published.priorGeneration, 1);
  assert.equal(result.receipt.gitGenerationFingerprint, GIT_FP);
  assert.ok(Object.isFrozen(result));
  assert.ok(publishIo.state.order.includes("replace"));
});

// ---------------------------------------------------------------------------
// Negative authorization: message can NEVER self-authorize. A tampered field
// fails closed BEFORE the fence is acquired or the orchestrator runs.
// ---------------------------------------------------------------------------

for (const [field, tampered] of [
  ["mappingGeneration", 99],
  ["routeFingerprint", "9".repeat(64)],
  ["authorityFingerprint", "8".repeat(64)],
  ["workspaceGeneration", 7],
  ["mappingId", "mapping-evil"],
]) {
  test(`refresh: tampered ${field} is refused unauthorized and never acquires the fence`, async () => {
    const { dispatcher, publishIo, materializeCalls, fence } = makeHarness();
    const result = await dispatcher.dispatchRefresh(callArgs({ message: refreshMessage({ [field]: tampered }) }));
    assert.equal(result.ok, false);
    assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
    assert.equal(fence.state.acquired, 0, "fence must not be acquired on unauthorized refresh");
    assert.equal(materializeCalls.count, 0);
    assert.equal(publishIo.state.order.length, 0);
  });
}

test("refresh: no accepted binding is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRefresh(callArgs({ trustedBinding: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("refresh: inventory whose identity disagrees with the verified message is refused", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRefresh(callArgs({
    trustedInventoryWorkspace: { ...inventoryWorkspace, workspaceId: "workspace-2" },
  }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("refresh: a missing fence lease candidate is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRefresh(callArgs({ leaseCandidate: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

for (const bad of ["not-an-object", 42, true]) {
  test(`refresh: a non-object (${typeof bad}) fence lease candidate is refused before the fence`, async () => {
    const { dispatcher, fence } = makeHarness();
    const result = await dispatcher.dispatchRefresh(callArgs({ leaseCandidate: bad }));
    assert.equal(result.ok, false);
    assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
    assert.equal(fence.state.acquired, 0);
  });
}

// ---------------------------------------------------------------------------
// Optimistic concurrency + fence currency (orchestrator seams forwarded).
// ---------------------------------------------------------------------------

test("refresh: a workspace with no published live generation is refused STALE", async () => {
  const { dispatcher, fence } = makeHarness({ publishIo: fakePublishIo(null) });
  const result = await dispatcher.dispatchRefresh(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_GENERATION_STALE");
  // refused after the internal live read but never reaches the fence/orchestrator
  assert.equal(fence.state.acquired, 0);
});

test("refresh: a live pointer that advances between reads is refused STALE without flipping", async () => {
  const base = basePointer();
  const advanced = pointerAt(2, 1, base.pointerFingerprint);
  // dispatcher read #0 -> base (derives expected + successor 2); orchestrator
  // re-read #1 -> advanced -> assertExpectedBase mismatch -> STALE.
  const publishIo = fakePublishIo(generationPointerBytes(base), {
    sequence: [generationPointerBytes(base), generationPointerBytes(advanced)],
  });
  const { dispatcher } = makeHarness({ base, publishIo });
  const result = await dispatcher.dispatchRefresh(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_GENERATION_STALE");
  assert.equal(publishIo.state.order.includes("replace"), false);
});

test("refresh: a lost activity fence refuses LEASE_CONFLICT without flipping the pointer", async () => {
  const fence = fakeFence({ current: false });
  const { dispatcher, publishIo } = makeHarness({ fence });
  const result = await dispatcher.dispatchRefresh(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "LEASE_CONFLICT");
  assert.equal(fence.state.releases, 1, "a lost fence must still be released");
  assert.equal(publishIo.state.order.includes("replace"), false);
});

test("refresh: a throw at atomic replace preserves the prior live pointer", async () => {
  const base = basePointer();
  const publishIo = fakePublishIo(generationPointerBytes(base), { fail: "replace" });
  const priorLive = publishIo.state.live;
  const { dispatcher } = makeHarness({ base, publishIo });
  const result = await dispatcher.dispatchRefresh(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_GENERATION_IO_FAILED");
  assert.deepEqual(publishIo.state.live, priorLive, "live pointer must be unchanged after a failed replace");
});

// ---------------------------------------------------------------------------
// Anti-replay: a REAL shared seen-set makes an identical second refresh fail
// closed with READINESS_REPLAYED.
// ---------------------------------------------------------------------------

test("refresh: an identical second dispatch replays and is refused", async () => {
  const base = basePointer();
  const replaySeen = newSeen();
  const first = await makeHarness({ base, replaySeen, publishIo: fakePublishIo(generationPointerBytes(base)) })
    .dispatcher.dispatchRefresh(callArgs());
  assert.equal(first.ok, true, JSON.stringify(first));
  const second = await makeHarness({ base, replaySeen, publishIo: fakePublishIo(generationPointerBytes(base)) })
    .dispatcher.dispatchRefresh(callArgs());
  assert.equal(second.ok, false);
  assert.equal(second.code, "READINESS_REPLAYED");
});

// ---------------------------------------------------------------------------
// Platform vocabulary
// ---------------------------------------------------------------------------

test("refresh: windows-unc source platform is refused CONTAINMENT_UNSUPPORTED", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRefresh({
    message: refreshMessage({ sourcePlatform: "windows-unc" }),
    trustedBinding: baseAuthority({ sourcePlatform: "windows-unc" }),
    trustedInventoryWorkspace: { ...inventoryWorkspace, sourcePlatform: "windows-unc" },
    leaseCandidate,
    readiness: liveReadiness(),
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "CONTAINMENT_UNSUPPORTED");
  assert.equal(fence.state.acquired, 0);
});
