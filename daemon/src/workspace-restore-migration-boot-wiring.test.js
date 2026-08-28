import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleRestoreMigrationDispatcher,
  buildRestoreMigrationLeaseCandidate,
} from "../src/workspace-restore-migration-boot-wiring.js";

const HEX64 = "a".repeat(64);

function fullNativeServingDeps() {
  return {
    makePublisherIo: async () => ({
      readLivePointer: async () => null,
      writeTemp: async () => {},
      flushTemp: async () => {},
      replace: async () => {},
      flushParent: async () => {},
    }),
    containment: { identifyRoot: async () => {}, verifyContained: async () => {} },
    gitVerifier: { verifyRepositoryGraph: async () => {} },
    makeProvenanceIo: () => ({ readProvenanceRecord: async () => ({}) }),
    makeChecksumIo: () => ({ readBytes: async () => Buffer.from("x") }),
    acquireFence: () => ({ isCurrent: () => true, release: () => {} }),
    clock: { now: () => 1 },
    maxAgeMs: 5_000,
    replaySeen: { has: () => false, add: () => {} },
  };
}

// ---------------------------------------------------------------------------
// resolveLifecycleRestoreMigrationDispatcher: fail-closed until gate + native deps.
// ---------------------------------------------------------------------------

test("dispatcher is null when serving is not enabled", () => {
  assert.equal(
    resolveLifecycleRestoreMigrationDispatcher({ enabled: false, workspaceRoot: "/srv/ws", nativeServingDeps: fullNativeServingDeps() }),
    null,
  );
});

test("dispatcher is null when workspaceRoot is empty even if enabled", () => {
  assert.equal(
    resolveLifecycleRestoreMigrationDispatcher({ enabled: true, workspaceRoot: "", nativeServingDeps: fullNativeServingDeps() }),
    null,
  );
});

test("dispatcher is null when the native serving deps bundle is absent (S7 gap)", () => {
  assert.equal(
    resolveLifecycleRestoreMigrationDispatcher({ enabled: true, workspaceRoot: "/srv/ws" }),
    null,
  );
  assert.equal(
    resolveLifecycleRestoreMigrationDispatcher({ enabled: true, workspaceRoot: "/srv/ws", nativeServingDeps: null }),
    null,
  );
});

test("dispatcher is constructed when enabled + workspaceRoot + full native deps", () => {
  const dispatcher = resolveLifecycleRestoreMigrationDispatcher({
    enabled: true,
    workspaceRoot: "/srv/ws",
    nativeServingDeps: fullNativeServingDeps(),
  });
  assert.ok(dispatcher);
  assert.equal(typeof dispatcher.dispatchRestoreMigration, "function");
});

test("resolveLifecycleRestoreMigrationDispatcher tolerates no arguments", () => {
  assert.equal(resolveLifecycleRestoreMigrationDispatcher(), null);
});

// ---------------------------------------------------------------------------
// buildRestoreMigrationLeaseCandidate: reconstruct the adopted exclusive-fence identity.
// ---------------------------------------------------------------------------

test("lease candidate augments the binding with its recomputed fingerprint", () => {
  const binding = { workspaceId: "workspace-1", mappingId: "mapping-1" };
  const candidate = buildRestoreMigrationLeaseCandidate(binding, () => HEX64);
  assert.deepEqual(candidate, { workspaceId: "workspace-1", mappingId: "mapping-1", bindingFingerprint: HEX64 });
  assert.ok(Object.isFrozen(candidate));
});

test("lease candidate is null when the binding is missing or not an object", () => {
  assert.equal(buildRestoreMigrationLeaseCandidate(null, () => HEX64), null);
  assert.equal(buildRestoreMigrationLeaseCandidate("nope", () => HEX64), null);
  assert.equal(buildRestoreMigrationLeaseCandidate([], () => HEX64), null);
});

test("lease candidate is null when the fingerprint fn is missing or throws", () => {
  const binding = { workspaceId: "workspace-1" };
  assert.equal(buildRestoreMigrationLeaseCandidate(binding, undefined), null);
  assert.equal(buildRestoreMigrationLeaseCandidate(binding, () => { throw new Error("boom"); }), null);
});

test("lease candidate is null when the recomputed fingerprint is not hex64", () => {
  const binding = { workspaceId: "workspace-1" };
  assert.equal(buildRestoreMigrationLeaseCandidate(binding, () => "short"), null);
  assert.equal(buildRestoreMigrationLeaseCandidate(binding, () => "Z".repeat(64)), null);
  assert.equal(buildRestoreMigrationLeaseCandidate(binding, () => 12345), null);
});
