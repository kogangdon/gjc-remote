import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleResetDeleteDispatcher,
  buildResetDeleteLeaseCandidate,
  createResidualProcessPlaceholderIo,
} from "../src/workspace-reset-delete-boot-wiring.js";

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
// buildResetDeleteLeaseCandidate: reconstruct the adopted exclusive-fence identity.
// ---------------------------------------------------------------------------

test("lease candidate augments the binding with its recomputed fingerprint", () => {
  const binding = { workspaceId: "workspace-1", mappingId: "mapping-1" };
  const candidate = buildResetDeleteLeaseCandidate(binding, () => HEX64);
  assert.deepEqual(candidate, { workspaceId: "workspace-1", mappingId: "mapping-1", bindingFingerprint: HEX64 });
  assert.ok(Object.isFrozen(candidate));
});

test("lease candidate is null when the binding is missing or not an object", () => {
  assert.equal(buildResetDeleteLeaseCandidate(null, () => HEX64), null);
  assert.equal(buildResetDeleteLeaseCandidate("nope", () => HEX64), null);
  assert.equal(buildResetDeleteLeaseCandidate([], () => HEX64), null);
});

test("lease candidate is null when the fingerprint fn is missing or throws", () => {
  const binding = { workspaceId: "workspace-1" };
  assert.equal(buildResetDeleteLeaseCandidate(binding, undefined), null);
  assert.equal(buildResetDeleteLeaseCandidate(binding, () => { throw new Error("boom"); }), null);
});

test("lease candidate is null when the recomputed fingerprint is not hex64", () => {
  const binding = { workspaceId: "workspace-1" };
  assert.equal(buildResetDeleteLeaseCandidate(binding, () => "short"), null);
  assert.equal(buildResetDeleteLeaseCandidate(binding, () => "Z".repeat(64)), null);
  assert.equal(buildResetDeleteLeaseCandidate(binding, () => 12345), null);
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
