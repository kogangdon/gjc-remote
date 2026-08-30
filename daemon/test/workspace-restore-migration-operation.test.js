import assert from "node:assert/strict";
import test from "node:test";

import { createWorkspaceRestoreMigrationOperation } from "../src/workspace-restore-migration-operation.js";
import { generationPointerBytes, buildGenerationPointer } from "../src/workspace-generation-publisher.js";
import { buildWorkspaceManifest, computeManifestEntries } from "../src/workspace-backup-manifest.js";

// ---------------------------------------------------------------------------
// Test doubles. Deterministic: no fs, no subprocess, no timing.
// ---------------------------------------------------------------------------

const ROOT_IDENTITY = Object.freeze({ platform: "windows-drive", volumeSerial: "AABBCCDD", fileId: "0001" });
const STORAGE_IDENTITY = Object.freeze({ platform: "windows-drive", volumeSerial: "AABBCCDD" });
const GIT_FINGERPRINT = "a".repeat(64);

const AUTHORITY = Object.freeze({
  hostId: "host-1",
  roleFingerprint: "d".repeat(64),
  volumeIdentityFingerprint: "e".repeat(64),
  keyFingerprint: "c".repeat(64),
  manifestFingerprint: null,
  restoredFromWorkspaceId: "workspace-0",
  restoredFromGeneration: 3,
});

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

// A provenance record whose identity matches AUTHORITY field-for-field.
function fakeProvenanceIo(overrides = {}) {
  return {
    readProvenanceRecord: overrides.readProvenanceRecord ?? (async () => ({
      version: 2,
      kind: "workspace-restore-provenance",
      hostId: AUTHORITY.hostId,
      roleFingerprint: AUTHORITY.roleFingerprint,
      volumeIdentityFingerprint: AUTHORITY.volumeIdentityFingerprint,
      keyFingerprint: AUTHORITY.keyFingerprint,
      manifestFingerprint: FIXTURE_MANIFEST.manifestFingerprint,
      restoredFromWorkspaceId: "workspace-0",
      restoredFromGeneration: 3,
    })),
  };
}

const MANIFEST_PATHS = ["a.txt", "b.txt"];
// Deterministic content reader; the same io backs both manifest construction
// and the operation's checksum verification, so the happy path re-hashes clean.
const checksumIo = { readBytes: async (relPath) => Buffer.from(`content:${relPath}`) };

const FIXTURE_ENTRIES = await computeManifestEntries(checksumIo, MANIFEST_PATHS);
const FIXTURE_MANIFEST = buildWorkspaceManifest({
  hostId: "host-1", workspaceId: "workspace-1", workspaceGeneration: 2, sourcePlatform: "windows-drive",
  rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: GIT_FINGERPRINT, entries: FIXTURE_ENTRIES,
});

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
  const provenanceIo = over.provenanceIo ?? fakeProvenanceIo();
  const stagedChecksumIo = over.checksumIo ?? checksumIo;
  return {
    fence,
    deps: {
      containment: over.containment ?? fakeContainment(),
      gitVerifier: over.gitVerifier ?? fakeGitVerifier(),
      stagePromotion: over.stagePromotion ?? {
        async materializeAndVerify() {
          return Object.freeze({
            manifestFingerprint: FIXTURE_MANIFEST.manifestFingerprint,
            verifiedCount: FIXTURE_MANIFEST.entries.length,
          });
        },
        async cleanup() {},
      },
      makeStageReader: over.makeStageReader ?? (async () => ({
        async readBytes(relPath) {
          if (relPath === "restore-provenance.json") {
            const record = await provenanceIo.readProvenanceRecord({
              provenancePath: relPath,
            });
            return Buffer.from(JSON.stringify(record));
          }
          return stagedChecksumIo.readBytes(relPath);
        },
      })),
      makePublisherIo: over.makePublisherIo ?? (async () => over.publishIo),
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
    operation: "restore",
    hostId: "host-1",
    workspaceId: "workspace-1",
    sourcePlatform: "windows-drive",
    workspaceRoot: "C:\\ws\\root",
    workDir: "C:\\ws\\root",
    generationPath: "generations/000002",
    candidatePath: "C:\\ws\\root\\generations\\000002",
    gitDir: "C:\\ws\\root\\generations\\000002",
    stagingPath: "C:\\ws\\staging\\restore-1",
    leaseCandidate: { workspaceId: "workspace-1", bindingFingerprint: "f".repeat(64) },
    expectedWorkspaceGeneration: base.activeGeneration,
    expectedAuthority: {
      ...AUTHORITY,
      manifestFingerprint: FIXTURE_MANIFEST.manifestFingerprint,
    },
    manifest: FIXTURE_MANIFEST,
    restoredFromWorkspaceId: "workspace-0",
    restoredFromGeneration: 3,
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

test("restore: promotes a successor chained onto the live base and attaches out-of-band lineage", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps, fence } = makeDeps({ publishIo });
  const result = await createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base));

  assert.equal(result.operation, "restore");
  assert.equal(result.published.published, true);
  assert.equal(result.published.activeGeneration, 2);
  assert.equal(result.published.priorGeneration, 1);
  assert.equal(result.published.priorPointerFingerprint, base.pointerFingerprint);
  assert.equal(result.fence, 7);
  assert.equal(result.gitGenerationFingerprint, GIT_FINGERPRINT);
  assert.equal(result.manifestFingerprint, FIXTURE_MANIFEST.manifestFingerprint);
  assert.equal(result.restoredFromWorkspaceId, "workspace-0");
  assert.equal(result.restoredFromGeneration, 3);
  // out-of-band lineage record
  assert.equal(result.lineage.kind, "workspace-promotion-lineage");
  assert.equal(result.lineage.restoredFromWorkspaceId, "workspace-0");
  assert.equal(result.lineage.restoredFromGeneration, 3);
  assert.ok(Object.isFrozen(result));
  assert.equal(fence.state.releases, 1);
  assert.deepEqual(publishIo.state.live, generationPointerBytes(result.pointer));
});

test("restore: the published pointer bytes carry the exact S4d POINTER_KEYS and no restore lineage", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps } = makeDeps({ publishIo });
  const result = await createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base));

  const publishedText = new TextDecoder().decode(publishIo.state.live);
  assert.ok(!publishedText.includes("restoredFrom"), "pointer must not carry restore lineage");
  assert.ok(!publishedText.includes("lineageFingerprint"), "pointer must not carry a lineage fingerprint");
  assert.ok(!publishedText.includes("promotion-lineage"), "pointer must not carry the lineage kind");
  // pointer keys are exactly S4d's set (no restoredFrom* keys)
  assert.ok(!Object.keys(result.pointer).some((k) => k.startsWith("restoredFrom")));
});

test("restore: composes the steps in the fixed order quarantine->provenance->checksum->containment/OID->promotion", async () => {
  const base = baseGenerationPointer();
  const order = [];
  const provenanceIo = fakeProvenanceIo({ readProvenanceRecord: async () => { order.push("provenance"); return {
    version: 2, kind: "workspace-restore-provenance",
    hostId: AUTHORITY.hostId, roleFingerprint: AUTHORITY.roleFingerprint,
    volumeIdentityFingerprint: AUTHORITY.volumeIdentityFingerprint, keyFingerprint: AUTHORITY.keyFingerprint,
    manifestFingerprint: FIXTURE_MANIFEST.manifestFingerprint,
    restoredFromWorkspaceId: "workspace-0",
    restoredFromGeneration: 3,
  }; } });
  const orderChecksumIo = { readBytes: async (relPath) => { order.push("checksum"); return Buffer.from(`content:${relPath}`); } };
  const containment = fakeContainment({
    identifyRoot: async () => { order.push("containment"); return { rootIdentity: { ...ROOT_IDENTITY }, storageIdentity: { ...STORAGE_IDENTITY } }; },
    verifyContained: async () => { order.push("verifyContained"); return { identity: {}, rootIdentity: { ...ROOT_IDENTITY } }; },
  });
  const gitVerifier = fakeGitVerifier({ verifyRepositoryGraph: async () => { order.push("oid"); return { generationFingerprint: GIT_FINGERPRINT, refs: [], head: "x", objectCount: 1, bare: false, gitVersion: "2.44.0" }; } });
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps } = makeDeps({ publishIo, provenanceIo, checksumIo: orderChecksumIo, containment, gitVerifier });
  await createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base));

  // provenance precedes checksum precedes containment/OID; promotion (replace) is last.
  assert.equal(order[0], "provenance");
  const firstChecksum = order.indexOf("checksum");
  const firstContainment = order.indexOf("containment");
  const oidIdx = order.indexOf("oid");
  assert.ok(firstChecksum > 0 && firstChecksum < firstContainment, "checksum after provenance, before containment");
  assert.ok(firstContainment < oidIdx, "containment before OID proof");
  // promotion CAS (replace) happens only after all proofs
  assert.ok(publishIo.state.order.includes("replace"));
});

// ---------------------------------------------------------------------------
// Docker session-volume migration disabled (fixed public tuple, no leak)
// ---------------------------------------------------------------------------

test("a docker-session-volume migration is refused with the fixed public tuple before any fence or I/O", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps, fence } = makeDeps({ publishIo });
  const req = baseRequest(base, {
    migrationKind: "docker-session-volume",
    stagingPath: "C:\\ws\\SECRET-INTERNAL-STAGING\\restore-1",
  });
  const err = await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(req), "WORKSPACE_MIGRATION_UNSUPPORTED");
  assert.equal(err.reason, "docker session-volume migration is not supported");
  // zero mutation, fence never acquired
  assert.equal(fence.state.acquired, 0);
  assert.deepEqual(publishIo.state.order, []);
  // JSON-scan: no internal diagnostic (paths / staged / manifest) crosses the envelope
  const serialized = JSON.stringify({ code: err.code, operation: err.operation, reason: err.reason, message: err.message });
  assert.ok(!serialized.includes("SECRET-INTERNAL-STAGING"));
  assert.ok(!serialized.includes("candidatePath"));
  assert.ok(!serialized.includes("stagingPath"));
});

// ---------------------------------------------------------------------------
// Step-1 quarantine failure (pre-provenance, zero mutation)
// ---------------------------------------------------------------------------

test("a staging path nested under the live candidate is refused before provenance, zero mutation", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  let provenanceRead = false;
  const provenanceIo = fakeProvenanceIo({ readProvenanceRecord: async () => { provenanceRead = true; return {}; } });
  const { deps, fence } = makeDeps({ publishIo, provenanceIo });
  const req = baseRequest(base, { stagingPath: "C:\\ws\\root\\generations\\000002\\staging" });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(req), "WORKSPACE_STAGING_NOT_QUARANTINED");
  assert.equal(provenanceRead, false, "provenance must not be read after a quarantine refusal");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, generationPointerBytes(base));
  assert.equal(fence.state.releases, 1);
});

test("a workspace-internal sibling stage is not quarantined", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  let stageReads = 0;
  const { deps } = makeDeps({
    publishIo,
    makeStageReader: async () => ({
      async readBytes() { stageReads++; return new Uint8Array(); },
    }),
  });
  await expectRefusal(
    createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(
      baseRequest(base, {
        stagingPath: "C:\\ws\\root\\staging-sibling",
      })
    ),
    "WORKSPACE_STAGING_NOT_QUARANTINED"
  );
  assert.equal(stageReads, 0);
  assert.ok(!publishIo.state.order.includes("replace"));
});

// ---------------------------------------------------------------------------
// Step-2 provenance / checksum failures (pre-promotion, zero mutation)
// ---------------------------------------------------------------------------

test("a provenance identity mismatch is refused before promotion, prior generation intact", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const provenanceIo = fakeProvenanceIo({ readProvenanceRecord: async () => ({
    version: 1, kind: "workspace-restore-provenance",
    hostId: AUTHORITY.hostId, roleFingerprint: "9".repeat(64),
    volumeIdentityFingerprint: AUTHORITY.volumeIdentityFingerprint, keyFingerprint: AUTHORITY.keyFingerprint,
  }) });
  const { deps, fence } = makeDeps({ publishIo, provenanceIo });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_PROVENANCE_MISMATCH");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("a tampered manifest (checksum divergence) is refused before promotion, prior generation intact", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  // reader returns different bytes than the manifest recorded -> mismatch
  const tamperedIo = { readBytes: async (relPath) => Buffer.from(`TAMPERED:${relPath}`) };
  const { deps, fence } = makeDeps({ publishIo, checksumIo: tamperedIo });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_MANIFEST_MISMATCH");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

// ---------------------------------------------------------------------------
// Step-3 containment / OID recheck failures (A11 named negatives)
// ---------------------------------------------------------------------------

test("a containment root-escape on the staged root refuses before promotion, live intact", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const containment = fakeContainment({ verifyContained: async () => { const e = new Error("escape"); e.code = "WORKSPACE_ROOT_ESCAPE"; throw e; } });
  const { deps, fence } = makeDeps({ publishIo, containment });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_ROOT_ESCAPE");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("a reparse point on the staged root refuses before promotion, live intact", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const containment = fakeContainment({ verifyContained: async () => { const e = new Error("reparse"); e.code = "REPARSE_POINT_REJECTED"; throw e; } });
  const { deps, fence } = makeDeps({ publishIo, containment });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "REPARSE_POINT_REJECTED");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("an OID/graph incompleteness on the staged repo refuses before promotion, live intact", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const gitVerifier = fakeGitVerifier({ verifyRepositoryGraph: async () => { const e = new Error("incomplete"); e.code = "GIT_GRAPH_INCOMPLETE"; throw e; } });
  const { deps, fence } = makeDeps({ publishIo, gitVerifier });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "GIT_GRAPH_INCOMPLETE");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("a candidate graph fingerprint divergent from the manifest refuses", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const gitVerifier = fakeGitVerifier({
    verifyRepositoryGraph: async () => ({
      generationFingerprint: "9".repeat(64),
    }),
  });
  const { deps } = makeDeps({ publishIo, gitVerifier });
  await expectRefusal(
    createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(
      baseRequest(base)
    ),
    "WORKSPACE_MANIFEST_MISMATCH"
  );
  assert.ok(!publishIo.state.order.includes("replace"));
});

test("retained stage close failure prevents publication and cleans candidate", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  let cleanupCalls = 0;
  const { deps } = makeDeps({
    publishIo,
    stagePromotion: {
      async materializeAndVerify() {},
      async cleanup() { cleanupCalls++; },
    },
  });
  const makeStageReader = deps.makeStageReader;
  deps.makeStageReader = async (...args) => ({
    ...await makeStageReader(...args),
    async close() {
      const error = new Error("retained root close failed");
      error.code = "EIO";
      throw error;
    },
  });
  await assert.rejects(
    createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(
      baseRequest(base)
    ),
    (error) => error.code === "EIO"
  );
  assert.equal(cleanupCalls, 1);
  assert.ok(!publishIo.state.order.includes("replace"));
});

// ---------------------------------------------------------------------------
// Expected-base / stale generation
// ---------------------------------------------------------------------------

test("restore with no live generation refuses WORKSPACE_GENERATION_STALE, releases fence", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(null);
  const { deps, fence } = makeDeps({ publishIo });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_GENERATION_STALE");
  assert.equal(fence.state.releases, 1);
  assert.ok(!publishIo.state.order.includes("replace"));
});

test("restore whose expected base mismatches the live pointer refuses as stale, prior generation intact", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const { deps, fence } = makeDeps({ publishIo });
  const req = baseRequest(base, { expectedWorkspaceGeneration: 99 });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(req), "WORKSPACE_GENERATION_STALE");
  assert.equal(fence.state.releases, 1);
  assert.deepEqual(publishIo.state.live, baseBytes);
});

// ---------------------------------------------------------------------------
// Fencing (A7: real fence, never null)
// ---------------------------------------------------------------------------

test("a fence lost before promotion refuses LEASE_CONFLICT, live pointer intact, nothing published", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes);
  const fence = fakeFence({ current: true });
  // The proofs race a concurrent invalidation: the fence goes stale after the
  // OID proof (via the git verifier hook), before the promotion recheck.
  const gitVerifier = fakeGitVerifier({ verifyRepositoryGraph: async () => { fence.state.current = false; return { generationFingerprint: GIT_FINGERPRINT, refs: [], head: "x", objectCount: 1, bare: false, gitVersion: "2.44.0" }; } });
  const { deps } = makeDeps({ publishIo, fence, gitVerifier });
  const err = await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "LEASE_CONFLICT");
  assert.equal(err.checkpoint, "readiness");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("a failed exclusive fence acquisition propagates and nothing is released or published", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const busy = new Error("workspace busy"); busy.code = "WORKSPACE_BUSY";
  const fence = fakeFence({ acquireThrows: busy });
  const { deps } = makeDeps({ publishIo, fence });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_BUSY");
  assert.equal(fence.state.releases, 0);
  assert.deepEqual(publishIo.state.order, []);
});

// ---------------------------------------------------------------------------
// Freshness + anti-replay (S4e seam obligations owned here)
// ---------------------------------------------------------------------------

test("stale readiness (older than daemon maxAgeMs) refuses via the trusted clock, no promotion", async () => {
  const base = baseGenerationPointer();
  const publishIo = fakePublishIo(generationPointerBytes(base));
  const { deps, fence } = makeDeps({ publishIo, clock: { now: () => 100_000 }, maxAgeMs: 5_000 });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base, { probedAtMs: 1_000 })), "READINESS_EXPIRED");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.equal(fence.state.releases, 1);
});

test("a replayed readiness attestation refuses with READINESS_REPLAYED without a second live-pointer mutation", async () => {
  const base = baseGenerationPointer();
  const replaySeen = newSeen();
  const firstIo = fakePublishIo(generationPointerBytes(base));
  const first = makeDeps({ publishIo: firstIo, replaySeen });
  const r1 = await createWorkspaceRestoreMigrationOperation(first.deps).runRestoreMigration(baseRequest(base));
  assert.ok(replaySeen.set.has(r1.readinessFingerprint));

  const secondIo = fakePublishIo(generationPointerBytes(base));
  const second = makeDeps({ publishIo: secondIo, replaySeen });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(second.deps).runRestoreMigration(baseRequest(base)), "READINESS_REPLAYED");
  assert.ok(!secondIo.state.order.includes("replace"));
});

// ---------------------------------------------------------------------------
// Crash-sim + CAS conflict: atomic promotion is the sole live mutation
// ---------------------------------------------------------------------------

test("crash at atomic replace preserves the prior live pointer (deterministic)", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes, { fail: "replace" });
  let cleanupCalls = 0;
  const { deps, fence } = makeDeps({
    publishIo,
    stagePromotion: {
      async materializeAndVerify() {},
      async cleanup() { cleanupCalls++; },
    },
  });
  const err = await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_GENERATION_IO_FAILED");
  assert.equal(err.step, "replace");
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(cleanupCalls, 1);
  assert.equal(fence.state.releases, 1);
});

test("crash at flushParent (after replace committed) leaves the NEW pointer live (old-or-new per step)", async () => {
  const base = baseGenerationPointer();
  const baseBytes = generationPointerBytes(base);
  const publishIo = fakePublishIo(baseBytes, { fail: "flushParent" });
  let cleanupCalls = 0;
  const { deps, fence } = makeDeps({
    publishIo,
    stagePromotion: {
      async materializeAndVerify() {},
      async cleanup() { cleanupCalls++; },
    },
  });
  const err = await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_GENERATION_IO_FAILED");
  assert.equal(err.step, "flushParent");
  // replace already committed the new pointer bytes -> slot holds the NEW value
  assert.notDeepEqual(publishIo.state.live, baseBytes);
  assert.equal(cleanupCalls, 0, "a possibly-live generation candidate must be retained");
  assert.equal(fence.state.releases, 1);
});

test("a live pointer that advances between base read and publish refuses via CAS, no double mutation", async () => {
  const base = baseGenerationPointer();
  const other = buildGenerationPointer({
    hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
    activeGeneration: 2, generationPath: "generations/000002",
    rootIdentityFingerprint: "5".repeat(64), storageIdentityFingerprint: "6".repeat(64),
    gitGenerationFingerprint: "7".repeat(64), manifestFingerprint: "8".repeat(64),
    priorGeneration: 1, priorPointerFingerprint: base.pointerFingerprint,
  });
  const baseBytes = generationPointerBytes(base);
  const otherBytes = generationPointerBytes(other);
  const publishIo = fakePublishIo(baseBytes, { readLivePointerSeq: [baseBytes, otherBytes] });
  const { deps, fence } = makeDeps({ publishIo });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "WORKSPACE_GENERATION_CAS_CONFLICT");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.equal(fence.state.releases, 1);
});

// ---------------------------------------------------------------------------
// Construction + request validation
// ---------------------------------------------------------------------------

test("construction rejects a missing acquireFence", () => {
  const { deps } = makeDeps({ publishIo: fakePublishIo(null) });
  assert.throws(() => createWorkspaceRestoreMigrationOperation({ ...deps, acquireFence: undefined }), (e) => e.code === "CONFIG_INVALID");
});

test("construction rejects a missing stage reader factory", () => {
  const { deps } = makeDeps({ publishIo: fakePublishIo(null) });
  assert.throws(() => createWorkspaceRestoreMigrationOperation({ ...deps, makeStageReader: undefined }), (e) => e.code === "CONFIG_INVALID");
});

test("a malformed lease (missing isCurrent) is refused CONFIG_INVALID but still released", async () => {
  const base = baseGenerationPointer();
  let released = 0;
  const acquireFence = () => ({ fence: 1, release: () => { released++; } });
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)), acquireFence });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base)), "CONFIG_INVALID");
  assert.equal(released, 1);
});

test("request validation rejects a missing leaseCandidate", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  const req = baseRequest(base);
  delete req.leaseCandidate;
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(req), "CONFIG_INVALID");
});

test("request validation rejects a missing expectedAuthority", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  const req = baseRequest(base);
  delete req.expectedAuthority;
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(req), "CONFIG_INVALID");
});

test("request validation rejects a missing manifest fingerprint", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  const req = baseRequest(base, { manifest: { entries: [] } });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(req), "CONFIG_INVALID");
});

test("request validation rejects a non-integer restoredFromGeneration", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base, { restoredFromGeneration: 0 })), "CONFIG_INVALID");
});

test("request validation rejects a wrong operation kind", async () => {
  const base = baseGenerationPointer();
  const { deps } = makeDeps({ publishIo: fakePublishIo(generationPointerBytes(base)) });
  await expectRefusal(createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(baseRequest(base, { operation: "refresh" })), "CONFIG_INVALID");
});
