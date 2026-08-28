import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleRefreshDispatcher,
} from "../src/workspace-refresh-boot-wiring.js";


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
