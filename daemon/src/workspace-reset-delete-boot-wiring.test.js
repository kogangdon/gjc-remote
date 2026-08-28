import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleResetDeleteDispatcher,
  createResidualProcessPlaceholderIo,
} from "../src/workspace-reset-delete-boot-wiring.js";


function fullNativeServingDeps() {
  return {
    makePublisherIo: async () => ({
      readLivePointer: async () => null,
      writeTemp: async () => {},
      flushTemp: async () => {},
      replace: async () => {},
      flushParent: async () => {},
    }),
    makeBackupIo: () => ({ readBytes: async () => Buffer.from("x") }),
    resolveManifestPaths: async () => ["a.txt"],
    acquireFence: () => ({ isCurrent: () => true, release: () => {} }),
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    residualIo: createResidualProcessPlaceholderIo(),
  };
}

// ---------------------------------------------------------------------------
// resolveLifecycleResetDeleteDispatcher: fail-closed until gate + native deps.
// ---------------------------------------------------------------------------

test("dispatcher is null when serving is not enabled", () => {
  assert.equal(
    resolveLifecycleResetDeleteDispatcher({ enabled: false, workspaceRoot: "/srv/ws", nativeServingDeps: fullNativeServingDeps() }),
    null,
  );
});

test("dispatcher is null when workspaceRoot is empty even if enabled", () => {
  assert.equal(
    resolveLifecycleResetDeleteDispatcher({ enabled: true, workspaceRoot: "", nativeServingDeps: fullNativeServingDeps() }),
    null,
  );
});

test("dispatcher is null when the native serving deps bundle is absent (S7 gap)", () => {
  assert.equal(
    resolveLifecycleResetDeleteDispatcher({ enabled: true, workspaceRoot: "/srv/ws" }),
    null,
  );
  assert.equal(
    resolveLifecycleResetDeleteDispatcher({ enabled: true, workspaceRoot: "/srv/ws", nativeServingDeps: null }),
    null,
  );
});

test("dispatcher is constructed when enabled + workspaceRoot + full native deps", () => {
  const dispatcher = resolveLifecycleResetDeleteDispatcher({
    enabled: true,
    workspaceRoot: "/srv/ws",
    nativeServingDeps: fullNativeServingDeps(),
  });
  assert.ok(dispatcher);
  assert.equal(typeof dispatcher.dispatchResetDelete, "function");
});

test("resolveLifecycleResetDeleteDispatcher tolerates no arguments", () => {
  assert.equal(resolveLifecycleResetDeleteDispatcher(), null);
});

// ---------------------------------------------------------------------------
// createResidualProcessPlaceholderIo: Option-A fail-closed (S7 #171).
// ---------------------------------------------------------------------------

test("placeholder residual enumerator always refuses to certify absence", async () => {
  const io = createResidualProcessPlaceholderIo();
  assert.equal(typeof io.listResidualProcesses, "function");
  await assert.rejects(
    () => io.listResidualProcesses({ hostId: "h", workspaceId: "w" }),
    (e) => e.code === "CONFIG_INVALID",
  );
});

test("placeholder residual enumerator fails closed through assertResidualProcessAbsence", async () => {
  const { assertResidualProcessAbsence } = await import("../src/workspace-residual-process.js");
  const io = createResidualProcessPlaceholderIo();
  await assert.rejects(
    () => assertResidualProcessAbsence(io, { hostId: "h", workspaceId: "w" }),
    (e) => e.code === "CONFIG_INVALID",
  );
});
