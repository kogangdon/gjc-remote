import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleRestoreMigrationDispatcher,
} from "../src/workspace-restore-migration-boot-wiring.js";


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
