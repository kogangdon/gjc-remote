import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleRefreshDispatcher,
  buildRefreshLeaseCandidate,
} from "../src/workspace-refresh-boot-wiring.js";

const HEX64 = "a".repeat(64);

function fullNativeServingDeps() {
  return {
    containment: { identifyRoot: async () => {}, verifyContained: async () => {} },
    gitVerifier: { verifyRepositoryGraph: async () => {} },
    makeManifestIo: () => ({ readBytes: async () => Buffer.from("x") }),
    makePublisherIo: async () => ({
      readLivePointer: async () => null,
      writeTemp: async () => {},
      flushTemp: async () => {},
      replace: async () => {},
      flushParent: async () => {},
    }),
    materialize: async () => {},
    resolveManifestPaths: async () => ["a.txt"],
    acquireFence: () => ({ isCurrent: () => true, release: () => {} }),
    clock: { now: () => 1 },
    maxAgeMs: 5_000,
    replaySeen: { has: () => false, add: () => {} },
  };
}

// ---------------------------------------------------------------------------
// resolveLifecycleRefreshDispatcher: fail-closed until gate + native deps.
// ---------------------------------------------------------------------------

test("dispatcher is null when serving is not enabled", () => {
  assert.equal(
    resolveLifecycleRefreshDispatcher({ enabled: false, workspaceRoot: "/srv/ws", nativeServingDeps: fullNativeServingDeps() }),
    null,
  );
});

test("dispatcher is null when workspaceRoot is empty even if enabled", () => {
  assert.equal(
    resolveLifecycleRefreshDispatcher({ enabled: true, workspaceRoot: "", nativeServingDeps: fullNativeServingDeps() }),
    null,
  );
});

test("dispatcher is null when the native serving deps bundle is absent (S7 gap)", () => {
  assert.equal(
    resolveLifecycleRefreshDispatcher({ enabled: true, workspaceRoot: "/srv/ws" }),
    null,
  );
  assert.equal(
    resolveLifecycleRefreshDispatcher({ enabled: true, workspaceRoot: "/srv/ws", nativeServingDeps: null }),
    null,
  );
});

test("dispatcher is constructed when enabled + workspaceRoot + full native deps", () => {
  const dispatcher = resolveLifecycleRefreshDispatcher({
    enabled: true,
    workspaceRoot: "/srv/ws",
    nativeServingDeps: fullNativeServingDeps(),
  });
  assert.ok(dispatcher);
  assert.equal(typeof dispatcher.dispatchRefresh, "function");
});

test("resolveLifecycleRefreshDispatcher tolerates no arguments", () => {
  assert.equal(resolveLifecycleRefreshDispatcher(), null);
});

// ---------------------------------------------------------------------------
// buildRefreshLeaseCandidate: reconstruct the adopted fence identity.
// ---------------------------------------------------------------------------

test("lease candidate augments the binding with its recomputed fingerprint", () => {
  const binding = { workspaceId: "workspace-1", mappingId: "mapping-1" };
  const candidate = buildRefreshLeaseCandidate(binding, () => HEX64);
  assert.deepEqual(candidate, { workspaceId: "workspace-1", mappingId: "mapping-1", bindingFingerprint: HEX64 });
  assert.ok(Object.isFrozen(candidate));
});

test("lease candidate is null when the binding is missing or not an object", () => {
  assert.equal(buildRefreshLeaseCandidate(null, () => HEX64), null);
  assert.equal(buildRefreshLeaseCandidate("nope", () => HEX64), null);
  assert.equal(buildRefreshLeaseCandidate([], () => HEX64), null);
});

test("lease candidate is null when the fingerprint fn is missing or throws", () => {
  const binding = { workspaceId: "workspace-1" };
  assert.equal(buildRefreshLeaseCandidate(binding, undefined), null);
  assert.equal(buildRefreshLeaseCandidate(binding, () => { throw new Error("boom"); }), null);
});

test("lease candidate is null when the recomputed fingerprint is not hex64", () => {
  const binding = { workspaceId: "workspace-1" };
  assert.equal(buildRefreshLeaseCandidate(binding, () => "short"), null);
  assert.equal(buildRefreshLeaseCandidate(binding, () => "Z".repeat(64)), null);
  assert.equal(buildRefreshLeaseCandidate(binding, () => 12345), null);
});
