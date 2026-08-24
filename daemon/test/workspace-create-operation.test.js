import assert from "node:assert/strict";
import test from "node:test";

import { createWorkspaceCreateOperation } from "../src/workspace-create-operation.js";
import { generationPointerBytes, buildGenerationPointer } from "../src/workspace-generation-publisher.js";

// ---------------------------------------------------------------------------
// Test doubles for the five injected collaborators. Each is a faithful stand-in
// for the real S4a/S4b/S4c/S4d/S4e seam: the orchestrator only ever calls the
// listed methods, so these fakes exercise the exact composition contract while
// keeping the test deterministic (no fs, no subprocess, no timing).
// ---------------------------------------------------------------------------

const ROOT_IDENTITY = Object.freeze({ platform: "windows-drive", volumeSerial: "AABBCCDD", fileId: "0001" });
const STORAGE_IDENTITY = Object.freeze({ platform: "windows-drive", volumeSerial: "AABBCCDD" });
const GIT_FINGERPRINT = "a".repeat(64);

function fakeContainment(overrides = {}) {
  const calls = [];
  return {
    calls,
    identifyRoot: overrides.identifyRoot ?? (async (args) => {
      calls.push(["identifyRoot", args]);
      return { rootIdentity: { ...ROOT_IDENTITY }, storageIdentity: { ...STORAGE_IDENTITY } };
    }),
    verifyContained: overrides.verifyContained ?? (async (args) => {
      calls.push(["verifyContained", args]);
      return { identity: { fileId: "leaf" }, rootIdentity: { ...ROOT_IDENTITY } };
    }),
  };
}

function fakeGitVerifier(overrides = {}) {
  return {
    verifyRepositoryGraph: overrides.verifyRepositoryGraph ?? (async () => ({
      gitVersion: "2.44.0",
      bare: false,
      head: "b".repeat(40),
      refs: [],
      objectCount: 3,
      generationFingerprint: GIT_FINGERPRINT,
    })),
  };
}

const manifestIo = { readBytes: async (relPath) => Buffer.from(`content:${relPath}`) };

// In-memory live-pointer slot whose `replace` is a single atomic assignment.
// `fail` names a step to throw at (crash sim).
function fakePublishIo(initialBytes = null, { fail = null } = {}) {
  const state = { live: initialBytes, temp: null, order: [] };
  const mark = (step) => {
    state.order.push(step);
    if (fail === step) {
      const e = new Error(`disk lost at ${step}`);
      e.code = "EIO";
      throw e;
    }
  };
  return {
    state,
    readLivePointer: async () => { mark("readLivePointer"); return state.live; },
    writeTemp: async (bytes) => { mark("writeTemp"); state.temp = bytes; return "temp-ref"; },
    flushTemp: async () => { mark("flushTemp"); },
    replace: async () => { mark("replace"); state.live = state.temp; },
    flushParent: async () => { mark("flushParent"); },
  };
}

function liveReadiness() {
  return {
    connection: { state: "online", source: "live" },
    runtime: { state: "ready", source: "live" },
    providerAuth: { state: "configured", source: "live" },
    modelProfile: { state: "ready", source: "live" },
  };
}

function makeDeps(over = {}) {
  const materializeCalls = [];
  return {
    materializeCalls,
    deps: {
      containment: over.containment ?? fakeContainment(),
      gitVerifier: over.gitVerifier ?? fakeGitVerifier(),
      manifestIo: over.manifestIo ?? manifestIo,
      publishIo: over.publishIo ?? fakePublishIo(null),
      materialize: over.materialize ?? (async (req) => { materializeCalls.push(req); }),
      clock: over.clock ?? { now: () => 1_000 },
      maxAgeMs: over.maxAgeMs ?? 5_000,
      replaySeen: over.replaySeen ?? newSeen(),
      ...(over.hashIdentity ? { hashIdentity: over.hashIdentity } : {}),
    },
  };
}

function newSeen() {
  const set = new Set();
  return { has: (fp) => set.has(fp), add: (fp) => set.add(fp), set };
}

function baseRequest(over = {}) {
  return {
    operation: "create",
    hostId: "host-1",
    workspaceId: "workspace-1",
    sourcePlatform: "windows-drive",
    workDir: "C:\\ws\\root",
    generationPath: "generations/000001",
    candidatePath: "C:\\ws\\root\\generations\\000001",
    gitDir: "C:\\ws\\root\\generations\\000001",
    manifestPaths: ["a.txt", "b.txt"],
    activeGeneration: 1,
    priorGeneration: null,
    priorPointerFingerprint: null,
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

test("create: composes all five proofs and publishes the first generation", async () => {
  const { deps } = makeDeps();
  const op = createWorkspaceCreateOperation(deps);
  const result = await op.runCreateClone(baseRequest());

  assert.equal(result.operation, "create");
  assert.equal(result.published.published, true);
  assert.equal(result.published.activeGeneration, 1);
  assert.equal(result.published.priorGeneration, null);
  assert.equal(result.gitGenerationFingerprint, GIT_FINGERPRINT);
  assert.equal(result.generationPointerFingerprint, result.pointer.pointerFingerprint);
  assert.equal(result.rootIdentityFingerprint.length, 64);
  assert.equal(result.storageIdentityFingerprint.length, 64);
  assert.equal(result.manifestFingerprint.length, 64);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.pointer));
  // live pointer now holds exactly the published pointer bytes
  assert.deepEqual(deps.publishIo.state.live, generationPointerBytes(result.pointer));
});

test("clone: publishes a successor chained onto the live prior generation", async () => {
  // Seed a live prior generation.
  const prior = buildGenerationPointer({
    hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
    activeGeneration: 1, generationPath: "generations/000001",
    rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
    gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
    priorGeneration: null, priorPointerFingerprint: null,
  });
  const publishIo = fakePublishIo(generationPointerBytes(prior));
  const { deps } = makeDeps({ publishIo });
  const op = createWorkspaceCreateOperation(deps);

  const result = await op.runCreateClone(baseRequest({
    operation: "clone",
    generationPath: "generations/000002",
    candidatePath: "C:\\ws\\root\\generations\\000002",
    gitDir: "C:\\ws\\root\\generations\\000002",
    activeGeneration: 2,
    priorGeneration: 1,
    priorPointerFingerprint: prior.pointerFingerprint,
  }));

  assert.equal(result.operation, "clone");
  assert.equal(result.published.activeGeneration, 2);
  assert.equal(result.published.priorGeneration, 1);
  assert.equal(result.published.priorPointerFingerprint, prior.pointerFingerprint);
});

test("materialize runs after root identification and before containment proof", async () => {
  const order = [];
  const containment = fakeContainment({
    identifyRoot: async () => { order.push("identifyRoot"); return { rootIdentity: { ...ROOT_IDENTITY }, storageIdentity: { ...STORAGE_IDENTITY } }; },
    verifyContained: async () => { order.push("verifyContained"); return { identity: {}, rootIdentity: { ...ROOT_IDENTITY } }; },
  });
  const gitVerifier = fakeGitVerifier({
    verifyRepositoryGraph: async () => { order.push("git"); return { generationFingerprint: GIT_FINGERPRINT, refs: [], head: "x", objectCount: 1, bare: false, gitVersion: "2.44.0" }; },
  });
  const { deps } = makeDeps({ containment, gitVerifier, materialize: async () => { order.push("materialize"); } });
  await createWorkspaceCreateOperation(deps).runCreateClone(baseRequest());
  assert.deepEqual(order, ["identifyRoot", "materialize", "verifyContained", "verifyContained", "git"]);
});

// ---------------------------------------------------------------------------
// Fail-closed ordering + prior-generation preservation
// ---------------------------------------------------------------------------

test("materialize failure refuses and never publishes", async () => {
  const publishIo = fakePublishIo(null);
  const { deps } = makeDeps({ publishIo, materialize: async () => { const e = new Error("clone failed"); e.code = "GIT_PREFLIGHT_FAILED"; throw e; } });
  const op = createWorkspaceCreateOperation(deps);
  await expectRefusal(op.runCreateClone(baseRequest()), "GIT_PREFLIGHT_FAILED");
  assert.equal(publishIo.state.live, null);
  assert.deepEqual(publishIo.state.order, []);
});

test("containment refusal propagates its code and preserves the prior generation", async () => {
  const seededPrior = fakePublishIo(Buffer.from("PRIOR"));
  const containment = fakeContainment({
    verifyContained: async () => { const e = new Error("reparse"); e.code = "REPARSE_POINT_REJECTED"; throw e; },
  });
  const { deps } = makeDeps({ publishIo: seededPrior, containment });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(baseRequest()), "REPARSE_POINT_REJECTED");
  assert.deepEqual(seededPrior.state.live, Buffer.from("PRIOR"));
  assert.deepEqual(seededPrior.state.order, []);
});

test("git graph refusal propagates and never publishes", async () => {
  const publishIo = fakePublishIo(null);
  const gitVerifier = fakeGitVerifier({ verifyRepositoryGraph: async () => { const e = new Error("incomplete"); e.code = "GIT_GRAPH_INCOMPLETE"; throw e; } });
  const { deps } = makeDeps({ publishIo, gitVerifier });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(baseRequest()), "GIT_GRAPH_INCOMPLETE");
  assert.deepEqual(publishIo.state.order, []);
});

test("non-live / not-ready readiness dimension refuses before publish", async () => {
  const publishIo = fakePublishIo(null);
  const { deps } = makeDeps({ publishIo });
  const req = baseRequest({ readiness: { ...liveReadiness(), connection: { state: "offline", source: "live" } } });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(req), "CONNECTION_LOST");
  assert.deepEqual(publishIo.state.order, []);
});

test("dev/test-injected (non-live) readiness source refuses as CONFIG_INVALID", async () => {
  const publishIo = fakePublishIo(null);
  const { deps } = makeDeps({ publishIo });
  const req = baseRequest({ readiness: { ...liveReadiness(), runtime: { state: "ready", source: "injected" } } });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(req), "CONFIG_INVALID");
  assert.deepEqual(publishIo.state.order, []);
});

// ---------------------------------------------------------------------------
// Freshness + anti-replay (S4e seam obligations owned here)
// ---------------------------------------------------------------------------

test("stale readiness (older than maxAgeMs) refuses via trusted clock", async () => {
  const publishIo = fakePublishIo(null);
  const { deps } = makeDeps({ publishIo, clock: { now: () => 100_000 }, maxAgeMs: 5_000 });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(baseRequest({ probedAtMs: 1_000 })), "READINESS_EXPIRED");
  assert.deepEqual(publishIo.state.order, []);
});

test("maxAgeMs is daemon-owned; requester cannot widen it", async () => {
  // Requester places a bogus maxAgeMs on the request; it must be ignored.
  const publishIo = fakePublishIo(null);
  const { deps } = makeDeps({ publishIo, clock: { now: () => 100_000 }, maxAgeMs: 5_000 });
  const req = baseRequest({ probedAtMs: 1_000, maxAgeMs: 10_000_000, freshness: { maxAgeMs: 10_000_000 } });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(req), "READINESS_EXPIRED");
});

test("a replayed readiness attestation refuses with READINESS_REPLAYED", async () => {
  const replaySeen = newSeen();
  // First publication succeeds and consumes the fingerprint.
  const first = makeDeps({ replaySeen });
  const r1 = await createWorkspaceCreateOperation(first.deps).runCreateClone(baseRequest());
  assert.ok(replaySeen.set.has(r1.readinessFingerprint));

  // A second operation producing the identical attestation (same probedAtMs +
  // identical generation fingerprints) is rejected before any publish.
  const secondPublish = fakePublishIo(null);
  const second = makeDeps({ replaySeen, publishIo: secondPublish });
  await expectRefusal(createWorkspaceCreateOperation(second.deps).runCreateClone(baseRequest()), "READINESS_REPLAYED");
  assert.deepEqual(secondPublish.state.order, []);
});

// ---------------------------------------------------------------------------
// Crash-sim: atomic publication is the sole live mutation
// ---------------------------------------------------------------------------

test("crash at atomic replace preserves the prior live pointer (deterministic)", async () => {
  const prior = buildGenerationPointer({
    hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
    activeGeneration: 1, generationPath: "generations/000001",
    rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
    gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
    priorGeneration: null, priorPointerFingerprint: null,
  });
  const priorBytes = generationPointerBytes(prior);
  const publishIo = fakePublishIo(priorBytes, { fail: "replace" });
  const { deps } = makeDeps({ publishIo });
  const req = baseRequest({
    operation: "clone", generationPath: "generations/000002",
    candidatePath: "C:\\ws\\root\\generations\\000002",
    gitDir: "C:\\ws\\root\\generations\\000002",
    activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: prior.pointerFingerprint,
  });
  const err = await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(req), "WORKSPACE_GENERATION_IO_FAILED");
  assert.equal(err.step, "replace");
  // The live pointer is exactly the prior bytes: never torn, never the new one.
  assert.deepEqual(publishIo.state.live, priorBytes);
});

// ---------------------------------------------------------------------------
// Construction + request validation
// ---------------------------------------------------------------------------

test("construction rejects a publishIo missing a required method", () => {
  const { deps } = makeDeps();
  const broken = { ...deps.publishIo };
  delete broken.replace;
  assert.throws(() => createWorkspaceCreateOperation({ ...deps, publishIo: broken }), (e) => e.code === "CONFIG_INVALID");
});

test("construction rejects a non-positive maxAgeMs", () => {
  const { deps } = makeDeps();
  assert.throws(() => createWorkspaceCreateOperation({ ...deps, maxAgeMs: 0 }), (e) => e.code === "CONFIG_INVALID");
});

test("request validation rejects an unknown operation", async () => {
  const { deps } = makeDeps();
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(baseRequest({ operation: "refresh" })), "CONFIG_INVALID");
});

test("request validation rejects a non-integer probedAtMs", async () => {
  const { deps } = makeDeps();
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(baseRequest({ probedAtMs: 1.5 })), "READINESS_TIMESTAMP_INVALID");
});

test("request validation rejects a missing readiness dimension", async () => {
  const { deps } = makeDeps();
  const req = baseRequest();
  delete req.readiness.providerAuth;
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(req), "CONFIG_INVALID");
});

test("request validation rejects an empty manifestPaths (no vacuous manifest)", async () => {
  const { deps } = makeDeps();
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(baseRequest({ manifestPaths: [] })), "CONFIG_INVALID");
});

// ---------------------------------------------------------------------------
// Adversarial coverage (S4f review finding 3)
// ---------------------------------------------------------------------------

test("a caller-forged readiness.workspace dimension is ignored (orchestrator assembles it)", async () => {
  const { deps } = makeDeps();
  // Attach a bogus workspace dimension bound to junk fingerprints. The
  // orchestrator only reads the four CALLER_DIMENSIONS from request.readiness
  // and assembles the workspace dimension from its own proofs, so this forged
  // field is never consulted and the operation still succeeds normally.
  const req = baseRequest();
  req.readiness.workspace = { state: "ready", source: "injected", generation: { junk: true }, expected: { junk: true } };
  const result = await createWorkspaceCreateOperation(deps).runCreateClone(req);
  assert.equal(result.published.published, true);
});

test("an invalid POSIX generationPath refuses before publish", async () => {
  const publishIo = fakePublishIo(null);
  const { deps } = makeDeps({ publishIo });
  // A drive-prefixed / backslash generationPath is rejected by the publisher's
  // relative-POSIX guard while building the pointer, before any publish.
  const req = baseRequest({ generationPath: "C:\\generations\\1" });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(req), "WORKSPACE_GENERATION_PATH_REJECTED");
  assert.deepEqual(publishIo.state.order, []);
});

test("a stale priorPointerFingerprint refuses via CAS and preserves the live pointer", async () => {
  const prior = buildGenerationPointer({
    hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
    activeGeneration: 1, generationPath: "generations/000001",
    rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
    gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
    priorGeneration: null, priorPointerFingerprint: null,
  });
  const priorBytes = generationPointerBytes(prior);
  const publishIo = fakePublishIo(priorBytes);
  const { deps } = makeDeps({ publishIo });
  const req = baseRequest({
    operation: "clone", generationPath: "generations/000002",
    candidatePath: "C:\\ws\\root\\generations\\000002",
    gitDir: "C:\\ws\\root\\generations\\000002",
    activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: "9".repeat(64),
  });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(req), "WORKSPACE_GENERATION_CAS_CONFLICT");
  assert.deepEqual(publishIo.state.live, priorBytes);
});

test("a manifest read failure propagates and never publishes", async () => {
  const publishIo = fakePublishIo(null);
  const failingManifestIo = { readBytes: async () => { const e = new Error("read denied"); e.code = "EACCES"; throw e; } };
  const { deps } = makeDeps({ publishIo, manifestIo: failingManifestIo });
  await expectRefusal(createWorkspaceCreateOperation(deps).runCreateClone(baseRequest()), "WORKSPACE_MANIFEST_READ_FAILED");
  assert.deepEqual(publishIo.state.order, []);
});
