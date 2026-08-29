import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleResetDeleteDispatcher,
  createResidualProcessPlaceholderIo,
  resolveResidualProcessIo,
} from "../src/workspace-reset-delete-boot-wiring.js";
import { assertResidualProcessAbsence } from "../src/workspace-residual-process.js";


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
  const io = createResidualProcessPlaceholderIo();
  await assert.rejects(
    () => assertResidualProcessAbsence(io, { hostId: "h", workspaceId: "w" }),
    (e) => e.code === "CONFIG_INVALID",
  );
});

// ---------------------------------------------------------------------------
// resolveResidualProcessIo: the single native/placeholder swap seam (S7.3 #171).
// ---------------------------------------------------------------------------

test("resolveResidualProcessIo returns the fail-closed placeholder when no native enumerator is present", async () => {
  for (const enumerator of [undefined, null]) {
    const io = resolveResidualProcessIo({ enumerator, hostId: "h", workspaceRoot: "/srv/ws", sourcePlatform: "posix" });
    await assert.rejects(
      () => io.listResidualProcesses({ hostId: "h", workspaceId: "w" }),
      (e) => e.code === "CONFIG_INVALID" && e.reason === "residual-process enumeration unavailable",
    );
  }
});

test("resolveResidualProcessIo wires the real native adapter when an enumerator is present", async () => {
  const calls = [];
  const enumerator = {
    enumerate_workspace_process_holders(workDir, sourcePlatform) {
      calls.push({ workDir, sourcePlatform });
      return [];
    },
  };
  const io = resolveResidualProcessIo({ enumerator, hostId: "host-A", workspaceRoot: "/srv/ws", sourcePlatform: "posix" });
  assert.deepEqual(await assertResidualProcessAbsence(io, { hostId: "host-A", workspaceId: "ws-1" }), { absent: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].sourcePlatform, "posix");
  // A cross-host request is refused by the native adapter without scanning.
  await assert.rejects(
    () => io.listResidualProcesses({ hostId: "other", workspaceId: "ws-1" }),
    (e) => e.code === "CONFIG_INVALID",
  );
  assert.equal(calls.length, 1);
});
