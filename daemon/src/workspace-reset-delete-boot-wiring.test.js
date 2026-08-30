import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleResetDeleteDispatcher,
  resolveResidualProcessIo,
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
    residualIo: { listResidualProcesses: async () => [] },
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

test("dispatcher stays null for every incomplete static reset/delete bundle", () => {
  for (const missing of [
    "makePublisherIo",
    "makeBackupIo",
    "resolveManifestPaths",
    "acquireFence",
    "residualIo",
  ]) {
    const deps = fullNativeServingDeps();
    delete deps[missing];
    assert.equal(
      resolveLifecycleResetDeleteDispatcher({ enabled: true, workspaceRoot: "/srv/ws", nativeServingDeps: deps }),
      null,
      `${missing} must be required`,
    );
  }
});

test("static reset/delete deps never carry global quiescence callbacks", () => {
  const deps = fullNativeServingDeps();
  assert.equal("probeQuiescence" in deps, false);
  const dispatcher = resolveLifecycleResetDeleteDispatcher({
    enabled: true,
    workspaceRoot: "/srv/ws",
    nativeServingDeps: deps,
  });
  assert.ok(dispatcher);
});

test("resolveLifecycleResetDeleteDispatcher tolerates no arguments", () => {
  assert.equal(resolveLifecycleResetDeleteDispatcher(), null);
});

// ---------------------------------------------------------------------------
// resolveResidualProcessIo: native residual-process adapter.
// ---------------------------------------------------------------------------

test("resolveResidualProcessIo refuses a missing native enumerator", () => {
  for (const enumerator of [undefined, null]) {
    assert.throws(
      () => resolveResidualProcessIo({ enumerator, hostId: "h", workspaceRoot: "/srv/ws", sourcePlatform: "posix" }),
      (e) => e.code === "CONFIG_INVALID",
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
  assert.deepEqual(await io.listResidualProcesses({
    hostId: "host-A",
    workspaceId: "ws-1",
    workDir: "/srv/ws/ws-1",
    sourcePlatform: "posix",
  }), []);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].sourcePlatform, "posix");
  // A cross-host request is refused by the native adapter without scanning.
  await assert.rejects(
    () => io.listResidualProcesses({
      hostId: "other",
      workspaceId: "ws-1",
      workDir: "/srv/ws/ws-1",
      sourcePlatform: "posix",
    }),
    (e) => e.code === "CONFIG_INVALID",
  );
  assert.equal(calls.length, 1);
});
