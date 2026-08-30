import assert from "node:assert/strict";
import test from "node:test";
import { join as joinPath } from "node:path";

import { createLifecycleRestoreMigrationDispatcher } from "../src/workspace-restore-migration-dispatch.js";
import { buildGenerationPointer, generationPointerBytes } from "../src/workspace-generation-publisher.js";
import { buildWorkspaceManifest, computeManifestEntries } from "../src/workspace-backup-manifest.js";
import { MSG_TYPES } from "@gjc-remote/shared";

// ---------------------------------------------------------------------------
// Test doubles. Deterministic: no fs, no subprocess, no timing. The dispatcher
// runs the REAL landed orchestrator (createWorkspaceRestoreMigrationOperation)
// over injected fakes, so the happy path exercises the real step-1
// assertQuarantined path check. That check canonicalizes paths per
// sourcePlatform, and the dispatcher derives candidatePath via host path.join,
// so the happy path is platform-adaptive: it uses the CI host's own platform
// vocabulary + absolute-path style so derived and asserted paths agree on both
// win32 and posix legs. Security-core assertions (authorization, fence,
// stale/refusal) are platform-independent.
// ---------------------------------------------------------------------------

const IS_WIN = process.platform === "win32";
const PLATFORM = IS_WIN ? "windows-drive" : "posix";
const WS_ROOT = IS_WIN ? "C:\\ws" : "/srv/ws";
const STAGING = IS_WIN ? "C:\\gjc-staging\\restore-1" : "/srv/gjc-staging/restore-1";

const HOST = "host-1";
const WORKSPACE = "workspace-1";
const ROUTE_FP = "a".repeat(64);
const AUTH_FP = "b".repeat(64);
const IDEMPOTENCY_FP = "c".repeat(64);
const GIT_FINGERPRINT = "a".repeat(64);

const WORKDIR = joinPath(WS_ROOT, WORKSPACE);

const AUTHORITY = Object.freeze({
  hostId: HOST,
  roleFingerprint: "d".repeat(64),
  volumeIdentityFingerprint: "e".repeat(64),
  keyFingerprint: "c".repeat(64),
  manifestFingerprint: null,
  restoredFromWorkspaceId: "workspace-0",
  restoredFromGeneration: 3,
});

const ROOT_IDENTITY = Object.freeze({ platform: PLATFORM, volumeSerial: "AABBCCDD", fileId: "0001" });
const STORAGE_IDENTITY = Object.freeze({ platform: PLATFORM, volumeSerial: "AABBCCDD" });

const MANIFEST_PATHS = ["a.txt", "b.txt"];
const checksumIo = { readBytes: async (relPath) => Buffer.from(`content:${relPath}`) };
const FIXTURE_ENTRIES = await computeManifestEntries(checksumIo, MANIFEST_PATHS);
const FIXTURE_MANIFEST = buildWorkspaceManifest({
  hostId: HOST, workspaceId: WORKSPACE, workspaceGeneration: 2, sourcePlatform: PLATFORM,
  rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: GIT_FINGERPRINT, entries: FIXTURE_ENTRIES,
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

function fakeProvenanceIo(overrides = {}) {
  return {
    readProvenanceRecord: overrides.readProvenanceRecord ?? (async () => ({
      version: 2, kind: "workspace-restore-provenance",
      hostId: AUTHORITY.hostId, roleFingerprint: AUTHORITY.roleFingerprint,
      volumeIdentityFingerprint: AUTHORITY.volumeIdentityFingerprint, keyFingerprint: AUTHORITY.keyFingerprint,
      manifestFingerprint: FIXTURE_MANIFEST.manifestFingerprint,
      restoredFromWorkspaceId: "workspace-0", restoredFromGeneration: 3,
    })),
  };
}

function fakePublishIo(initialBytes = null) {
  const state = { live: initialBytes, temp: null, order: [] };
  return {
    state,
    readLivePointer: async () => { state.order.push("readLivePointer"); return state.live; },
    writeTemp: async (bytes) => { state.order.push("writeTemp"); state.temp = bytes; return "temp-ref"; },
    flushTemp: async () => { state.order.push("flushTemp"); },
    replace: async () => { state.order.push("replace"); state.live = state.temp; },
    flushParent: async () => { state.order.push("flushParent"); },
  };
}

function makeExclusiveFence({ current = true, acquireThrows = null } = {}) {
  const state = { current, acquired: 0, releases: 0 };
  const acquireFence = () => {
    state.acquired++;
    if (acquireThrows) throw acquireThrows;
    return { fence: 7, isCurrent: () => state.current, release: () => { state.releases++; } };
  };
  return { state, acquireFence };
}

function newSeen() {
  const set = new Set();
  return { has: (fp) => set.has(fp), add: (fp) => set.add(fp), set };
}

function liveReadiness() {
  return {
    connection: { state: "online", source: "live" },
    runtime: { state: "ready", source: "live" },
    providerAuth: { state: "configured", source: "live" },
    modelProfile: { state: "ready", source: "live" },
  };
}

function basePointer() {
  return buildGenerationPointer({
    hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: PLATFORM,
    activeGeneration: 1, generationPath: "generations/000001",
    rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
    gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
    priorGeneration: null, priorPointerFingerprint: null,
  });
}

function baseAuthority(overrides = {}) {
  return {
    authorityEpoch: 1, fenceGeneration: 1,
    hostId: HOST, mappingId: "mapping-1", mappingGeneration: 3, mappingVersion: 1,
    workspaceId: WORKSPACE, workspaceGeneration: 1, sourcePlatform: PLATFORM,
    routeFingerprint: ROUTE_FP, authorityFingerprint: AUTH_FP, inventoryGeneration: 5,
    bindingId: "mapping-1", ...overrides,
  };
}

function restoreMessage(overrides = {}) {
  return {
    type: MSG_TYPES.WORKSPACE_RESTORE_MIGRATION,
    operation: "restore",
    hostId: HOST, mappingId: "mapping-1", mappingGeneration: 3, mappingVersion: 1,
    workspaceId: WORKSPACE, workspaceGeneration: 1, sourcePlatform: PLATFORM,
    routeFingerprint: ROUTE_FP, authorityFingerprint: AUTH_FP, inventoryGeneration: 5,
    idempotencyFingerprint: IDEMPOTENCY_FP, ...overrides,
  };
}

const inventoryWorkspace = Object.freeze({
  hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: PLATFORM, workDir: WORKDIR,
});

const leaseCandidate = Object.freeze({ ...baseAuthority(), bindingFingerprint: "f".repeat(64) });

function restoreContext(over = {}) {
  return Object.freeze({
    stagingPath: STAGING,
    expectedAuthority: {
      ...AUTHORITY,
      manifestFingerprint: FIXTURE_MANIFEST.manifestFingerprint,
    },
    manifest: FIXTURE_MANIFEST,
    restoredFromWorkspaceId: "workspace-0",
    restoredFromGeneration: 3,
    expectedGraph: {},
    probedAtMs: 900,
    ...over,
  });
}

function validConfig(over = {}) {
  const publishIo = over.publishIo ?? fakePublishIo(generationPointerBytes(basePointer()));
  const fence = over.fence ?? makeExclusiveFence();
  const provenanceIo = over.provenanceIo ?? fakeProvenanceIo();
  const stagedChecksumIo = over.checksumIo ?? checksumIo;
  const config = {
    workspaceRoot: over.workspaceRoot ?? WS_ROOT,
    makePublisherIo: over.makePublisherIo ?? (async () => publishIo),
    containment: over.containment ?? fakeContainment(),
    gitVerifier: over.gitVerifier ?? fakeGitVerifier(),
    stagePromotion: over.stagePromotion ?? {
      async materializeAndVerify() {},
      async cleanup() {},
    },
    makeStageReader: over.makeStageReader ?? (async () => ({
      async readBytes(relPath) {
        if (relPath === "restore-provenance.json") {
          return Buffer.from(JSON.stringify(
            await provenanceIo.readProvenanceRecord({ provenancePath: relPath })
          ));
        }
        return stagedChecksumIo.readBytes(relPath);
      },
    })),
    acquireFence: over.acquireFence ?? fence.acquireFence,
    clock: over.clock ?? { now: () => 1_000 },
    maxAgeMs: over.maxAgeMs ?? 5_000,
    replaySeen: over.replaySeen ?? newSeen(),
  };
  return { config, publishIo, fence };
}

function makeHarness(over = {}) {
  const built = validConfig(over);
  return { ...built, dispatcher: createLifecycleRestoreMigrationDispatcher(built.config) };
}

function callArgs(over = {}) {
  return {
    message: over.message ?? restoreMessage(),
    trustedBinding: over.trustedBinding === undefined ? baseAuthority() : over.trustedBinding,
    trustedInventoryWorkspace: over.trustedInventoryWorkspace === undefined ? inventoryWorkspace : over.trustedInventoryWorkspace,
    leaseCandidate: over.leaseCandidate === undefined ? leaseCandidate : over.leaseCandidate,
    restoreContext: over.restoreContext === undefined ? restoreContext() : over.restoreContext,
    readiness: over.readiness ?? liveReadiness(),
  };
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

test("factory refuses config missing workspaceRoot", () => {
  const { config } = validConfig();
  assert.throws(() => createLifecycleRestoreMigrationDispatcher({ ...config, workspaceRoot: "" }), (e) => e.code === "CONFIG_INVALID");
});

test("factory refuses config missing makeStageReader", () => {
  const { config } = validConfig();
  assert.throws(() => createLifecycleRestoreMigrationDispatcher({ ...config, makeStageReader: null }), (e) => e.code === "CONFIG_INVALID");
});

test("factory refuses config with a non-integer maxAgeMs", () => {
  const { config } = validConfig();
  assert.throws(() => createLifecycleRestoreMigrationDispatcher({ ...config, maxAgeMs: 0 }), (e) => e.code === "CONFIG_INVALID");
});

// ---------------------------------------------------------------------------
// Happy path (reversible promotion onto the live base)
// ---------------------------------------------------------------------------

test("restore: authorized restore promotes a successor chained onto the live base with out-of-band lineage", async () => {
  const { dispatcher, publishIo, fence } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs());

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.receipt.operation, "restore");
  assert.equal(result.receipt.published.published, true);
  assert.equal(result.receipt.published.activeGeneration, 2);
  assert.equal(result.receipt.published.priorGeneration, 1);
  assert.equal(result.receipt.restoredFromWorkspaceId, "workspace-0");
  assert.equal(result.receipt.lineage.kind, "workspace-promotion-lineage");
  assert.equal(fence.state.acquired, 1);
  assert.equal(fence.state.releases, 1);
  assert.ok(publishIo.state.order.includes("replace"));
  assert.ok(Object.isFrozen(result));
});

test("migration: a non-docker migration operation promotes via the same reversible path", async () => {
  const { dispatcher } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({
    message: restoreMessage({ operation: "migration" }),
    restoreContext: restoreContext({ migrationKind: "volume-copy" }),
  }));
  assert.equal(result.ok, true, JSON.stringify(result));
  // the orchestrator only accepts operation "restore"; the migration is expressed via migrationKind
  assert.equal(result.receipt.operation, "restore");
});

test("migration: a docker-session-volume migration is refused before any fence/I-O", async () => {
  const { dispatcher, publishIo, fence } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({
    message: restoreMessage({ operation: "migration" }),
    restoreContext: restoreContext({ migrationKind: "docker-session-volume" }),
  }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_MIGRATION_UNSUPPORTED");
  assert.equal(fence.state.acquired, 0);
  assert.deepEqual(publishIo.state.order, []);
});

// ---------------------------------------------------------------------------
// Negative authorization: the message can never self-authorize.
// ---------------------------------------------------------------------------

for (const [field, tampered] of [
  ["mappingGeneration", 99],
  ["authorityFingerprint", "8".repeat(64)],
  ["workspaceGeneration", 7],
  ["mappingId", "mapping-evil"],
]) {
  test(`restore: tampered ${field} is refused unauthorized and never acquires the fence`, async () => {
    const { dispatcher, fence } = makeHarness();
    const result = await dispatcher.dispatchRestoreMigration(callArgs({ message: restoreMessage({ [field]: tampered }) }));
    assert.equal(result.ok, false);
    assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
    assert.equal(fence.state.acquired, 0, "fence must not be acquired on unauthorized restore");
  });
}

test("restore: no accepted binding is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({ trustedBinding: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("restore: inventory whose identity disagrees with the verified message is refused", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({
    trustedInventoryWorkspace: { ...inventoryWorkspace, workspaceId: "workspace-2" },
  }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("restore: a missing exclusive-fence lease candidate is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({ leaseCandidate: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

// ---------------------------------------------------------------------------
// Host-held restore context (the staged-source payload the wire cannot carry).
// ---------------------------------------------------------------------------

test("restore: a missing restore context is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({ restoreContext: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("restore: a restore context missing its staging path is refused", async () => {
  const { dispatcher } = makeHarness();
  const { stagingPath: _, ...withoutStaging } = restoreContext();
  const ctx = Object.freeze(withoutStaging);
  const result = await dispatcher.dispatchRestoreMigration(callArgs({ restoreContext: ctx }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
});

test("restore: a restore context missing its manifest fingerprint is refused", async () => {
  const { dispatcher } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({ restoreContext: restoreContext({ manifest: { entries: [] } }) }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
});

test("restore: a migration operation without a migration kind is refused", async () => {
  const { dispatcher } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({
    message: restoreMessage({ operation: "migration" }),
    restoreContext: restoreContext(),
  }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
});

test("restore: a plain restore that smuggles a migration kind is refused", async () => {
  const { dispatcher } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({ restoreContext: restoreContext({ migrationKind: "volume-copy" }) }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
});

// ---------------------------------------------------------------------------
// Live-base derivation + orchestrator seams.
// ---------------------------------------------------------------------------

test("restore: no live generation is refused STALE under the exclusive fence", async () => {
  const { dispatcher, fence } = makeHarness({ publishIo: fakePublishIo(null) });
  const result = await dispatcher.dispatchRestoreMigration(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_GENERATION_STALE");
  assert.equal(fence.state.acquired, 1);
});

test("restore: a provenance identity mismatch on the staged source refuses, prior generation intact", async () => {
  const provenanceIo = fakeProvenanceIo({ readProvenanceRecord: async () => ({
    version: 1, kind: "workspace-restore-provenance",
    hostId: AUTHORITY.hostId, roleFingerprint: "9".repeat(64),
    volumeIdentityFingerprint: AUTHORITY.volumeIdentityFingerprint, keyFingerprint: AUTHORITY.keyFingerprint,
  }) });
  const baseBytes = generationPointerBytes(basePointer());
  const publishIo = fakePublishIo(baseBytes);
  const { dispatcher, fence } = makeHarness({ publishIo, provenanceIo });
  const result = await dispatcher.dispatchRestoreMigration(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_PROVENANCE_MISMATCH");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("restore: a staging path nested under the live candidate refuses WORKSPACE_STAGING_NOT_QUARANTINED", async () => {
  const nestedStaging = joinPath(WS_ROOT, WORKSPACE, "generations", "000002", "staging");
  const { dispatcher } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration(callArgs({ restoreContext: restoreContext({ stagingPath: nestedStaging }) }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_STAGING_NOT_QUARANTINED");
});

test("restore: a lost exclusive fence refuses LEASE_CONFLICT without a promotion", async () => {
  const baseBytes = generationPointerBytes(basePointer());
  const publishIo = fakePublishIo(baseBytes);
  const fence = makeExclusiveFence();
  // fence goes stale after the OID proof, before the readiness recheck
  const gitVerifier = fakeGitVerifier({ verifyRepositoryGraph: async () => { fence.state.current = false; return { generationFingerprint: GIT_FINGERPRINT, refs: [], head: "x", objectCount: 1, bare: false, gitVersion: "2.44.0" }; } });
  const { dispatcher } = makeHarness({ publishIo, fence, gitVerifier });
  const result = await dispatcher.dispatchRestoreMigration(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "LEASE_CONFLICT");
  assert.ok(!publishIo.state.order.includes("replace"));
  assert.deepEqual(publishIo.state.live, baseBytes);
  assert.equal(fence.state.releases, 1);
});

test("restore: a replayed readiness attestation refuses READINESS_REPLAYED without a second promotion", async () => {
  const replaySeen = newSeen();
  const first = makeHarness({ publishIo: fakePublishIo(generationPointerBytes(basePointer())), replaySeen });
  const r1 = await first.dispatcher.dispatchRestoreMigration(callArgs());
  assert.equal(r1.ok, true, JSON.stringify(r1));

  const secondIo = fakePublishIo(generationPointerBytes(basePointer()));
  const second = makeHarness({ publishIo: secondIo, replaySeen });
  const r2 = await second.dispatcher.dispatchRestoreMigration(callArgs());
  assert.equal(r2.ok, false);
  assert.equal(r2.code, "READINESS_REPLAYED");
  assert.ok(!secondIo.state.order.includes("replace"));
});

// ---------------------------------------------------------------------------
// Platform vocabulary
// ---------------------------------------------------------------------------

test("restore: windows-unc source platform is refused CONTAINMENT_UNSUPPORTED", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchRestoreMigration({
    message: restoreMessage({ sourcePlatform: "windows-unc" }),
    trustedBinding: baseAuthority({ sourcePlatform: "windows-unc" }),
    trustedInventoryWorkspace: { ...inventoryWorkspace, sourcePlatform: "windows-unc" },
    leaseCandidate,
    restoreContext: restoreContext(),
    readiness: liveReadiness(),
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "CONTAINMENT_UNSUPPORTED");
  assert.equal(fence.state.acquired, 0);
});
