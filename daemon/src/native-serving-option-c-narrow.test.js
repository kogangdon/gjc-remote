import test from "node:test";
import assert from "node:assert/strict";

import { resolveLifecycleCreateDispatcher } from "./workspace-create-boot-wiring.js";
import { resolveLifecycleRefreshDispatcher } from "./workspace-refresh-boot-wiring.js";
import { resolveLifecycleResetDeleteDispatcher } from "./workspace-reset-delete-boot-wiring.js";
import { resolveLifecycleRestoreMigrationDispatcher } from "./workspace-restore-migration-boot-wiring.js";
import { assembleNativeServingDeps } from "./native-serving-deps.js";

// Option C-narrow serving boundary (S6f.7d): CREATE and REFRESH may serve; the
// reset/delete and restore/migration lifecycle ops MUST stay fail-closed. The
// daemon enforces this by ONLY assembling + passing nativeServingDeps to the
// create/refresh resolvers, never to the excluded two. This test pins that
// contract so a future accidental wiring of the excluded ops is caught.

// A minimal well-formed serving bundle (via the real assembler + fakes) that
// satisfies the create/refresh dispatcher config assertions.
function servingBundles() {
  const marker = () => ({});
  return assembleNativeServingDeps({
    workspaceRoot: "/ws/root",
    workspaceLeases: { acquireActivity() {} },
    maxAgeMs: 30000,
    factories: {
      makeContainmentLowLevel: () => ({}),
      makeContainment: () => ({ identifyRoot() {}, verifyContained() {} }),
      makeGitVerifier: () => ({ verifyRepositoryGraph() {} }),
      makeMaterializer: () => ({ materialize: () => {} }),
      makeByteReader: () => ({ readBytes() {} }),
      makePublisher: () => ({}),
      makeManifestResolver: () => () => [],
      makeReplayWindow: () => ({ has() {}, add() {} }),
      makeActivityFence: () => () => ({ isCurrent() {}, release() {} }),
    },
  });
}

const enabledRoot = { enabled: true, workspaceRoot: "/ws/root" };

test("CREATE and REFRESH build a live dispatcher when a serving bundle is supplied", () => {
  const { create, refresh } = servingBundles();
  const createDispatcher = resolveLifecycleCreateDispatcher({ ...enabledRoot, nativeServingDeps: create });
  const refreshDispatcher = resolveLifecycleRefreshDispatcher({ ...enabledRoot, nativeServingDeps: refresh });
  assert.notEqual(createDispatcher, null);
  assert.notEqual(refreshDispatcher, null);
});

test("reset/delete and restore/migration stay null with the SAME enabled+root but no deps (daemon wiring)", () => {
  // This mirrors exactly how daemon.js wires the excluded two: no nativeServingDeps.
  assert.equal(resolveLifecycleResetDeleteDispatcher({ ...enabledRoot }), null);
  assert.equal(resolveLifecycleRestoreMigrationDispatcher({ ...enabledRoot }), null);
  assert.equal(resolveLifecycleResetDeleteDispatcher({ ...enabledRoot, nativeServingDeps: null }), null);
  assert.equal(resolveLifecycleRestoreMigrationDispatcher({ ...enabledRoot, nativeServingDeps: null }), null);
});

test("CREATE and REFRESH also stay null without a serving bundle (gate-false default)", () => {
  assert.equal(resolveLifecycleCreateDispatcher({ ...enabledRoot }), null);
  assert.equal(resolveLifecycleRefreshDispatcher({ ...enabledRoot }), null);
});
