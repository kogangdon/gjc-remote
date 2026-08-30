import test from "node:test";
import assert from "node:assert/strict";

import { resolveLifecycleCreateDispatcher } from "./workspace-create-boot-wiring.js";
import { resolveLifecycleRefreshDispatcher } from "./workspace-refresh-boot-wiring.js";
import { resolveLifecycleResetDeleteDispatcher } from "./workspace-reset-delete-boot-wiring.js";
import { resolveLifecycleRestoreMigrationDispatcher } from "./workspace-restore-migration-boot-wiring.js";
import { assembleNativeServingDeps } from "./native-serving-deps.js";

// Native serving boundary: each operation requires its own complete bundle.
// CREATE and REFRESH always have production assembly; RESET_DELETE has an
// additional residual-process capability floor; RESTORE_MIGRATION remains
// fail-closed until issue #197 supplies sealed staging authority and promotion.

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

test("reset/delete and restore/migration stay null with the SAME enabled+root but no deps", () => {
  assert.equal(resolveLifecycleResetDeleteDispatcher({ ...enabledRoot }), null);
  assert.equal(resolveLifecycleRestoreMigrationDispatcher({ ...enabledRoot }), null);
  assert.equal(resolveLifecycleResetDeleteDispatcher({ ...enabledRoot, nativeServingDeps: null }), null);
  assert.equal(resolveLifecycleRestoreMigrationDispatcher({ ...enabledRoot, nativeServingDeps: null }), null);
});

test("CREATE and REFRESH also stay null without a serving bundle (gate-false default)", () => {
  assert.equal(resolveLifecycleCreateDispatcher({ ...enabledRoot }), null);
  assert.equal(resolveLifecycleRefreshDispatcher({ ...enabledRoot }), null);
});
