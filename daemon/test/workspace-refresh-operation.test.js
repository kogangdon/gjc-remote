import assert from "node:assert/strict";
import test from "node:test";

import { createWorkspaceRefreshOperation } from "../src/workspace-refresh-operation.js";
import { generationPointerBytes, buildGenerationPointer } from "../src/workspace-generation-publisher.js";

// ---------------------------------------------------------------------------
// Test doubles. Deterministic: no fs, no subprocess, no timing.
// ---------------------------------------------------------------------------

const ROOT_IDENTITY = Object.freeze({ platform: "windows-drive", volumeSerial: "AABBCCDD", fileId: "0001" });
const STORAGE_IDENTITY = Object.freeze({ platform: "windows-drive", volumeSerial: "AABBCCDD" });
const GIT_FINGERPRINT = "a".repeat(64);

function fakeContainment(overrides = {}) {
  return {
    identifyRoot: overrides.identifyRoot ?? (async () => ({ rootIdentity: { ...ROOT_IDENTITY }, storageIdentity: { ...STORAGE_IDENTITY } })),
    verifyContained: overrides.verifyContained ?? (async () => ({ identity: { fileId: "leaf" }, rootIdentity: { ...ROOT_IDENTITY } })),
  };
}

function fakeGitVerifier(overrides = {}) {
  return {
    verifyRepositoryGraph: overrides.verifyRepositoryGraph ?? (async () => ({
      gitVersion: "2.44.0", bare: false, head: "b".repeat(40), refs: [], objectCount: 3,
      generationFingerprint: GIT_FINGERPRINT,
    })),
  };
}

const manifestIo = { readBytes: async (relPath) => Buffer.from(`content:${relPath}`) };

// In-memory live-pointer slot. `readLivePointerSeq` optionally supplies a
// sequence of return values (to simulate the live pointer advancing between the
// step-2 read and the publish-time CAS read); otherwise readLivePointer returns
// the current live bytes. `fail` names a step to throw at (crash sim).
function fakePublishIo(initialBytes = null, { fail = null, readLivePointerSeq = null } = {}) {
  const state = { live: initialBytes, temp: null, order: [], readCount: 0 };
  const mark = (step) => {
    state.order.push(step);
    if (fail === step) { const e = new Error(`disk lost at ${step}`); e.code = "EIO"; throw e; }
  };
  return {
    state,
    readLivePointer: async () => {
      mark("readLivePointer");
      const i = state.readCount++;
      if (readLivePointerSeq) return readLivePointerSeq[Math.min(i, readLivePointerSeq.length - 1)];
      return state.live;
    },
    writeTemp: async (bytes) => { mark("writeTemp"); state.temp = bytes; return "temp-ref"; },
    flushTemp: async () => { mark("flushTemp"); },
    replace: async () => { mark("replace"); state.live = state.temp; },
    flushParent: async () => { mark("flushParent"); },
  };
}

function fakeFence({ current = true, acquireThrows = null } = {}) {
  const state = { current, releases: 0, acquired: 0 };
  const acquireFence = (candidate) => {
    state.acquired++;
    if (acquireThrows) throw acquireThrows;
    return {
      fence: 7,
      isCurrent: () => state.current,
      release: () => { state.releases++; },
    };
  };
  return { state, acquireFence };
}

function liveReadiness() {
  return {
    connection: { state: "online", source: "live" },
    runtime: { state: "ready", source: "live" },
    providerAuth: { state: "configured", source: "live" },
    modelProfile: { state: "ready", source: "live" },
  };
}

function baseGenerationPointer() {
  return buildGenerationPointer({
    hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
    activeGeneration: 1, generationPath: "generations/000001",
    rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
    gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
    priorGeneration: null, priorPointerFingerprint: null,
  });
}

function newSeen() {
  const set = new Set();
  return { has: (fp) => set.has(fp), add: (fp) => set.add(fp), set };
}

function makeDeps(over = {}) {
  const fence = over.fence ?? fakeFence();
  return {
    fence,
    deps: {
      containment: over.containment ?? fakeContainment(),
      gitVerifier: over.gitVerifier ?? fakeGitVerifier(),
      manifestIo: over.manifestIo ?? manifestIo,
      publishIo: over.publishIo,
      materialize: over.materialize ?? (async () => {}),
      acquireFence: over.acquireFence ?? fence.acquireFence,
      clock: over.clock ?? { now: () => 1_000 },
      maxAgeMs: over.maxAgeMs ?? 5_000,
      replaySeen: over.replaySeen ?? newSeen(),
      ...(over.hashIdentity ? { hashIdentity: over.hashIdentity } : {}),
    },
  };
}

function baseRequest(base, over = {}) {
  return {
    operation: "refresh",
    hostId: "host-1",
    workspaceId: "workspace-1",
    sourcePlatform: "windows-drive",
    workDir: "C:\\ws\\root",
    generationPath: "generations/000002",
    candidatePath: "C:\\ws\\root\\generations\\000002",
    gitDir: "C:\\ws\\root\\generations\\000002",
    manifestPaths: ["a.txt", "b.txt"],
    leaseCandidate: { workspaceId: "workspace-1", bindingFingerprint: "f".repeat(64) },
    expected: { pointerFingerprint: base.pointerFingerprint },
    probedAtMs: 900,
    readiness: liveReadiness(),
    ...over,
  };
}

async function expectRefusal(promise, code) {
  try {
    await promise;
    assert.fail(`expected refusal ${code} but resolved`);
  } catch (error) {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.reason ?? error.message}`);
    return error;
  }
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

test("refresh: publishes a successor chained onto the live base under a held fence", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps, fence } = makeDeps({ publishIo });
  const result = await createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base));

  assert.equal(result.operation, "refresh");
  assert.equal(result.published.published, true);
  assert.equal(result.published.activeGeneration, 2);
  assert.equal(result.published.priorGeneration, 1);
  assert.equal(result.published.priorPointerFingerprint, base.pointerFingerprint);
  assert.equal(result.fence, 7);
  assert.equal(result.gitGenerationFingerprint, GIT_FINGERPRINT);
  assert.ok(Object.isFrozen(result));
  // fence released exactly once on success
  assert.equal(fence.state.releases, 1);
  // live pointer now holds the successor
  assert.deepEqual(publishIo.state.live, generationPointerBytes(result.pointer));
});

test("refresh: post-op identity check runs after materialize, before the graph proof", async () => {
  const base = baseGenerationPointer();
  const order = [];
  const containment = fakeContainment({
    identifyRoot: async () => { order.push("identifyRoot"); return { rootIdentity: { ...ROOT_IDENTITY }, storageIdentity: { ...STORAGE_IDENTITY } }; },
    verifyContained: async () => { order.push("verifyContained"); return { identity: {}, rootIdentity: { ...ROOT_IDENTITY } }; },
  });
  const gitVerifier = fakeGitVerifier({ verifyRepositoryGraph: async () => { order.push("git"); return { generationFingerprint: GIT_FINGERPRINT, refs: [], head: "x", objectCount: 1, bare: false, gitVersion: "2.44.0" }; } });
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps } = makeDeps({ publishIo, containment, gitVerifier, materialize: async () => { order.push("materialize"); } });
  await createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base));
  assert.deepEqual(order, ["materialize", "identifyRoot", "verifyContained", "verifyContained", "git"]);
});

// ---------------------------------------------------------------------------
// Expected-base / stale generation
// ---------------------------------------------------------------------------

test("refresh with no live generation refuses WORKSPACE_GENERATION_STALE, releases fence", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(null);
  const { deps, fence } = makeDeps({ publishIo });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "WORKSPACE_GENERATION_STALE");
  assert.equal(fence.state.releases, 1);
  assert.ok(!publishIo.state.order.includes("replace"));
});

test("refresh whose expected base mismatches the live pointer refuses as stale", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps, fence } = makeDeps({ publishIo });
  const req = baseRequest(base, { expected: { pointerFingerprint: "9".repeat(64) } });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(req), "WORKSPACE_GENERATION_STALE");
  assert.equal(fence.state.releases, 1);
  assert.deepEqual(publishIo.state.live, generationPointerBytes(base));
});

// ---------------------------------------------------------------------------
// Prompt/read fencing
// ---------------------------------------------------------------------------

test("a fence lost before materialisation refuses LEASE_CONFLICT before any work", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const fence = fakeFence({ current: false });
  let materialized = false;
  const { deps } = makeDeps({ publishIo, fence, materialize: async () => { materialized = true; } });
  const err = await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "LEASE_CONFLICT");
  assert.equal(err.checkpoint, "materialisation");
  assert.equal(materialized, false);
  assert.equal(fence.state.releases, 1);
});

test("a fence lost during materialisation aborts before publish and preserves the prior generation", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const fence = fakeFence({ current: true });
  // The fetch/merge races a concurrent invalidation: the fence goes stale.
  const { deps } = makeDeps({ publishIo, fence, materialize: async () => { fence.state.current = false; } });
  const err = await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "LEASE_CONFLICT");
  assert.equal(err.checkpoint, "publication");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("a failed fence acquisition propagates and nothing is released or published", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const conflict = new Error("lease conflict"); conflict.code = "LEASE_CONFLICT";
  const fence = fakeFence({ acquireThrows: conflict });
  const { deps } = makeDeps({ publishIo, fence });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "LEASE_CONFLICT");
  assert.equal(fence.state.releases, 0); // never acquired -> nothing to release
  assert.deepEqual(publishIo.state.order, []);
});

// ---------------------------------------------------------------------------
// Downstream proof refusals (fail-closed, fence always released)
// ---------------------------------------------------------------------------

test("post-op containment refusal propagates its code and preserves the prior generation", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const containment = fakeContainment({ verifyContained: async () => { const e = new Error("reparse"); e.code = "REPARSE_POINT_REJECTED"; throw e; } });
  const { deps, fence } = makeDeps({ publishIo, containment });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "REPARSE_POINT_REJECTED");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("git graph refusal propagates and never publishes", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const gitVerifier = fakeGitVerifier({ verifyRepositoryGraph: async () => { const e = new Error("incomplete"); e.code = "GIT_GRAPH_INCOMPLETE"; throw e; } });
  const { deps, fence } = makeDeps({ publishIo, gitVerifier });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "GIT_GRAPH_INCOMPLETE");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.equal(fence.state.releases, 1);
});

test("non-live readiness source refuses as CONFIG_INVALID before publish", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps, fence } = makeDeps({ publishIo });
  const req = baseRequest(base, { readiness: { ...liveReadiness(), runtime: { state: "ready", source: "injected" } } });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(req), "CONFIG_INVALID");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.equal(fence.state.releases, 1);
});

// ---------------------------------------------------------------------------
// Freshness + anti-replay (S4e seam obligations owned here)
// ---------------------------------------------------------------------------

test("stale readiness (older than daemon maxAgeMs) refuses via the trusted clock", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps, fence } = makeDeps({ publishIo, clock: { now: () => 100_000 }, maxAgeMs: 5_000 });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base, { probedAtMs: 1_000 })), "READINESS_EXPIRED");
  assert.equal(fence.state.releases, 1);
});

test("a replayed readiness attestation refuses with READINESS_REPLAYED", async () => {
  const base = baseGenerationPointer();
  const replaySeen = newSeen();
  const firstIo = fakePublishIo(generationPointerBytes(base));
  const first = makeDeps({ publishIo: firstIo, replaySeen });
  const r1 = await createWorkspaceRefreshOperation(first.deps).runRefresh(baseRequest(base));
  assert.ok(replaySeen.set.has(r1.readinessFingerprint));

  const secondIo = fakePublishIo(generationPointerBytes(base));
  const second = makeDeps({ publishIo: secondIo, replaySeen });
  await expectRefusal(createWorkspaceRefreshOperation(second.deps).runRefresh(baseRequest(base)), "READINESS_REPLAYED");
  assert.ok(!secondIo.state.order.includes("replace"));
});

// ---------------------------------------------------------------------------
// Crash-sim + CAS conflict: atomic publication is the sole live mutation
// ---------------------------------------------------------------------------

test("crash at atomic replace preserves the prior live pointer (deterministic)", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes, { fail: "replace" });
  const { deps, fence } = makeDeps({ publishIo });
  const err = await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "WORKSPACE_GENERATION_IO_FAILED");
  assert.equal(err.step, "replace");
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("a live pointer that advances between read and publish refuses via CAS", async () => {
  const base = baseGenerationPointer();
  // Someone else published a different successor after our step-2 read.
  const other = buildGenerationPointer({
    hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
    activeGeneration: 2, generationPath: "generations/000002",
    rootIdentityFingerprint: "5".repeat(64), storageIdentityFingerprint: "6".repeat(64),
    gitGenerationFingerprint: "7".repeat(64), manifestFingerprint: "8".repeat(64),
    priorGeneration: 1, priorPointerFingerprint: base.pointerFingerprint,
  });
  const baseBytes = generationPointerBytes(base);
  const otherBytes = generationPointerBytes(other);
  // step-2 read sees base; the publish-time CAS read sees the advanced pointer.
  const publishIo = fakePublishIo(baseBytes, { readLivePointerSeq: [baseBytes, otherBytes] });
  const { deps, fence } = makeDeps({ publishIo });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "WORKSPACE_GENERATION_CAS_CONFLICT");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.equal(fence.state.releases, 1);
});

// ---------------------------------------------------------------------------
// Adversarial + validation
// ---------------------------------------------------------------------------

test("a caller-forged readiness.workspace dimension is ignored", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps } = makeDeps({ publishIo });
  const req = baseRequest(base);
  req.readiness.workspace = { state: "ready", source: "injected", generation: { junk: true }, expected: { junk: true } };
  const result = await createWorkspaceRefreshOperation(deps).runRefresh(req);
  assert.equal(result.published.published, true);
});

test("a malformed lease (missing isCurrent) is refused CONFIG_INVALID but still released", async () => {
  const base = baseGenerationPointer();
  let released = 0;
  const acquireFence = () => ({ fence: 1, release: () => { released++; } });
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)), acquireFence });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base)), "CONFIG_INVALID");
  assert.equal(released, 1);
});

test("construction rejects a missing acquireFence", () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  assert.throws(() => createWorkspaceRefreshOperation({ ...deps, acquireFence: undefined }), (e) => e.code === "CONFIG_INVALID");
});

test("request validation rejects a missing leaseCandidate", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  const req = baseRequest(base);
  delete req.leaseCandidate;
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(req), "CONFIG_INVALID");
});

test("request validation rejects a missing expected base generation", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  const req = baseRequest(base);
  delete req.expected;
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(req), "CONFIG_INVALID");
});

test("request validation rejects an empty manifestPaths", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  await expectRefusal(createWorkspaceRefreshOperation(deps).runRefresh(baseRequest(base, { manifestPaths: [] })), "CONFIG_INVALID");
});
