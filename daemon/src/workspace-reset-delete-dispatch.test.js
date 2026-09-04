import assert from "node:assert/strict";
import test from "node:test";

import { createLifecycleResetDeleteDispatcher } from "../src/workspace-reset-delete-dispatch.js";
import { buildGenerationPointer, generationPointerBytes } from "../src/workspace-generation-publisher.js";
import { buildTombstone, tombstoneBytes, readLiveDisposition } from "../src/workspace-tombstone-publisher.js";
import { MSG_TYPES } from "@gjc-remote/shared";

// ---------------------------------------------------------------------------
// Test doubles. Deterministic: no fs, no subprocess, no native addon. Mirrors
// the landed workspace-reset-delete-operation.test.js fake set; proves the
// authorization + live-disposition derivation + destructive-lock (exclusive
// fence + quiescence + residual-process) + refusal security core with injected
// fakes. Real-native end-to-end is S7 (#171).
//
// dispatchResetDelete mirrors the S6f.2/S6f.3 dispatchers; the base being
// destroyed is read INTERNALLY from the live disposition, never the wire
// message. `leaseCandidate` (exclusive-fence identity) and `lifecycleContext`
// (manual-cleanup tx-context plus exact quiescence/terminal callbacks) are
// host-held per-call parameters.
// ---------------------------------------------------------------------------

const ROUTE_FP = "a".repeat(64);
const AUTH_FP = "b".repeat(64);
const IDEMPOTENCY_FP = "c".repeat(64);
const HOST = "host-1";
const WORKSPACE = "workspace-1";

function baseAuthority(overrides = {}) {
  return {
    authorityEpoch: 6,
    fenceGeneration: 7,
    hostId: HOST,
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: WORKSPACE,
    workspaceGeneration: 3,
    sourcePlatform: "posix",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
    inventoryGeneration: 5,
    bindingId: "mapping-1",
    ...overrides,
  };
}

function resetDeleteMessage(overrides = {}) {
  return {
    type: MSG_TYPES.WORKSPACE_RESET_DELETE,
    operation: "delete",
    hostId: HOST,
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: WORKSPACE,
    workspaceGeneration: 3,
    sourcePlatform: "posix",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
    inventoryGeneration: 5,
    idempotencyFingerprint: IDEMPOTENCY_FP,
    ...overrides,
  };
}

const inventoryWorkspace = Object.freeze({
  hostId: HOST,
  workspaceId: WORKSPACE,
  sourcePlatform: "posix",
  workDir: "/srv/ws/workspace-1",
});

const leaseCandidate = Object.freeze({ ...baseAuthority(), bindingFingerprint: "e".repeat(64) });

const lifecycleAuthority = Object.freeze({
  anchorFingerprint: "1".repeat(64),
  fenceGeneration: 7,
  txId: "tx-reset-1",
  reason: "reset-owner-action",
  expectedFingerprint: null,
  observedFingerprint: null,
  expectedFloorFingerprint: null,
  observedFloorFingerprint: null,
});

function lifecycleContext(overrides = {}) {
  return Object.freeze({
    lifecycleAuthority: overrides.lifecycleAuthority ?? lifecycleAuthority,
    probeQuiescence: overrides.probeQuiescence ??
      (() => ({ pendingInvokes: 0, pendingSessions: 0 })),
    prepareTerminal: overrides.prepareTerminal ?? (() => {}),
    clearTerminalPreparation: overrides.clearTerminalPreparation ?? (() => {}),
    commitTerminal: overrides.commitTerminal ?? (() => {}),
  });
}

function liveReadiness() {
  return {
    connection: { state: "online", source: "live" },
    runtime: { state: "ready", source: "live" },
    providerAuth: { state: "configured", source: "live" },
    modelProfile: { state: "ready", source: "live" },
  };
}

function livePointer(overrides = {}) {
  return buildGenerationPointer({
    hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: "posix",
    activeGeneration: 3, generationPath: "generations/000003",
    rootIdentityFingerprint: "a".repeat(64), storageIdentityFingerprint: "b".repeat(64),
    gitGenerationFingerprint: "c".repeat(64), manifestFingerprint: "d".repeat(64),
    priorGeneration: 2, priorPointerFingerprint: "e".repeat(64),
    ...overrides,
  });
}

// Ordered single-slot io usable as both readLiveDisposition source and the
// tombstone publisher io. `throwAt` simulates an ordered-publish crash.
function makeTombstoneIo(initialBytes, order) {
  const state = { slot: initialBytes, order };
  const throwAt = new Set();
  return {
    state, throwAt,
    async readLivePointer() { order?.push("tombstone.readLivePointer"); return state.slot; },
    async writeTemp(bytes) { order?.push("tombstone.writeTemp"); if (throwAt.has("writeTemp")) throw new Error("writeTemp boom"); return { bytes }; },
    async flushTemp() { order?.push("tombstone.flushTemp"); if (throwAt.has("flushTemp")) throw new Error("flushTemp boom"); },
    async replace(ref) { order?.push("tombstone.replace"); if (throwAt.has("replace")) throw new Error("replace boom"); state.slot = ref.bytes; },
    async flushParent() { order?.push("tombstone.flushParent"); if (throwAt.has("flushParent")) throw new Error("flushParent boom"); },
  };
}

function makeBackupIo(files = { "README.md": "readme", "src/a.js": "alpha" }) {
  return {
    calls: 0,
    async readBytes(relPath) {
      this.calls++;
      if (!Object.hasOwn(files, relPath)) { const e = new Error(`missing ${relPath}`); e.code = "ENOENT"; throw e; }
      return new TextEncoder().encode(files[relPath]);
    },
  };
}

function makeResidualIo(residuals = []) {
  return { calls: 0, async listResidualProcesses() { this.calls++; return residuals; } };
}

function makeExclusiveFence({ current = true } = {}) {
  const state = { current, acquired: 0, releases: 0 };
  const acquireFence = () => {
    state.acquired++;
    return { fence: 42, isCurrent: () => state.current, release: () => { state.releases++; } };
  };
  return { state, acquireFence };
}

function validConfig(over = {}) {
  const pointer = over.pointer ?? livePointer();
  const slotBytes = "slotBytes" in over ? over.slotBytes : generationPointerBytes(pointer);
  const tombstoneIo = over.tombstoneIo ?? makeTombstoneIo(slotBytes, over.order);
  const backupIo = over.backupIo ?? makeBackupIo();
  const residualIo = over.residualIo ?? makeResidualIo();
  const fence = over.fence ?? makeExclusiveFence();
  const config = {
    workspaceRoot: over.workspaceRoot ?? "/srv/ws",
    makePublisherIo: over.makePublisherIo ?? (async () => tombstoneIo),
    makeBackupIo: over.makeBackupIo ?? (() => backupIo),
    resolveManifestPaths: over.resolveManifestPaths ?? (async () => ["README.md", "src/a.js"]),
    acquireFence: over.acquireFence ?? fence.acquireFence,
    residualIo,
  };
  return { config, pointer, tombstoneIo, backupIo, residualIo, fence };
}

function makeHarness(over = {}) {
  const built = validConfig(over);
  return { ...built, dispatcher: createLifecycleResetDeleteDispatcher(built.config) };
}

function callArgs(over = {}) {
  return {
    message: over.message ?? resetDeleteMessage(),
    trustedBinding: over.trustedBinding === undefined ? baseAuthority() : over.trustedBinding,
    trustedInventoryWorkspace: over.trustedInventoryWorkspace === undefined ? inventoryWorkspace : over.trustedInventoryWorkspace,
    leaseCandidate: over.leaseCandidate === undefined ? leaseCandidate : over.leaseCandidate,
    lifecycleContext: over.lifecycleContext === undefined
      ? lifecycleContext()
      : over.lifecycleContext,
    readiness: over.readiness ?? liveReadiness(),
  };
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

test("factory refuses config missing workspaceRoot", () => {
  const { config } = validConfig();
  assert.throws(() => createLifecycleResetDeleteDispatcher({ ...config, workspaceRoot: "" }), (e) => e.code === "CONFIG_INVALID");
});

test("factory refuses config with a non-function acquireFence", () => {
  const { config } = validConfig();
  assert.throws(() => createLifecycleResetDeleteDispatcher({ ...config, acquireFence: "nope" }), (e) => e.code === "CONFIG_INVALID");
});

test("factory refuses config with a residualIo lacking listResidualProcesses", () => {
  const { config } = validConfig();
  assert.throws(() => createLifecycleResetDeleteDispatcher({ ...config, residualIo: {} }), (e) => e.code === "CONFIG_INVALID");
});

// ---------------------------------------------------------------------------
// Happy path (committed tombstone)
// ---------------------------------------------------------------------------

test("reset/delete: authorized delete captures a backup then publishes a committed tombstone", async () => {
  const { dispatcher, tombstoneIo, backupIo, residualIo, fence } = makeHarness();
  const result = await dispatcher.dispatchResetDelete(callArgs());

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.cleanupState, "not_required");
  assert.equal(result.receipt.disposition, "committed");
  assert.equal(result.receipt.operation, "delete");
  assert.equal(result.receipt.published.published, true);
  assert.equal(result.receipt.tombstone.priorKind, "workspace-generation-pointer");
  assert.equal(fence.state.acquired, 1);
  assert.equal(fence.state.releases, 1);
  assert.ok(backupIo.calls >= 1);
  assert.equal(residualIo.calls, 1);
  assert.ok(Object.isFrozen(result));

  const disposition = await readLiveDisposition(tombstoneIo);
  assert.equal(disposition.kind, "workspace-tombstone");
});

test("reset/delete: a reset operation is also accepted", async () => {
  const { dispatcher } = makeHarness();
  const result = await dispatcher.dispatchResetDelete(callArgs({ message: resetDeleteMessage({ operation: "reset" }) }));
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.receipt.operation, "reset");
});

test("reset/delete: exact receipt binding shape authorizes without routeFingerprint", async () => {
  const { dispatcher } = makeHarness();
  const trusted = baseAuthority();
  delete trusted.routeFingerprint;
  const result = await dispatcher.dispatchResetDelete(callArgs({
    trustedBinding: trusted,
  }));
  assert.equal(result.ok, true, JSON.stringify(result));
});

// ---------------------------------------------------------------------------
// Negative authorization: message can NEVER self-authorize. A tampered field
// fails closed BEFORE the fence is acquired, backup captured, or residual scan.
// ---------------------------------------------------------------------------

for (const [field, tampered] of [
  ["mappingGeneration", 99],
  ["authorityFingerprint", "8".repeat(64)],
  ["workspaceGeneration", 7],
  ["mappingId", "mapping-evil"],
]) {
  test(`reset/delete: tampered ${field} is refused unauthorized and never acquires the fence`, async () => {
    const { dispatcher, backupIo, residualIo, fence } = makeHarness();
    const result = await dispatcher.dispatchResetDelete(callArgs({ message: resetDeleteMessage({ [field]: tampered }) }));
    assert.equal(result.ok, false);
    assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
    assert.equal(fence.state.acquired, 0, "fence must not be acquired on unauthorized reset/delete");
    assert.equal(backupIo.calls, 0);
    assert.equal(residualIo.calls, 0);
  });
}

test("reset/delete: no accepted binding is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchResetDelete(callArgs({ trustedBinding: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("reset/delete: inventory whose identity disagrees with the verified message is refused", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchResetDelete(callArgs({
    trustedInventoryWorkspace: { ...inventoryWorkspace, workspaceId: "workspace-2" },
  }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("reset/delete: a missing exclusive-fence lease candidate is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchResetDelete(callArgs({ leaseCandidate: null }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

test("reset/delete: a missing or malformed manual-cleanup authority is refused before the fence", async () => {
  const { dispatcher, fence } = makeHarness();
  const missing = await dispatcher.dispatchResetDelete(callArgs({ lifecycleContext: null }));
  assert.equal(missing.ok, false);
  assert.equal(missing.code, "RUNTIME_INCOMPATIBLE");
  // extra key -> not exact -> refused
  const malformed = await dispatcher.dispatchResetDelete(callArgs({
    lifecycleContext: lifecycleContext({
      lifecycleAuthority: { ...lifecycleAuthority, extra: 1 },
    }),
  }));
  assert.equal(malformed.ok, false);
  assert.equal(malformed.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(fence.state.acquired, 0);
});

// ---------------------------------------------------------------------------
// Live-disposition derivation + destructive locks (orchestrator seams).
// ---------------------------------------------------------------------------

test("reset/delete: a null live slot is refused STALE under the exclusive fence", async () => {
  const { dispatcher, fence } = makeHarness({ slotBytes: null });
  const result = await dispatcher.dispatchResetDelete(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_GENERATION_STALE");
  assert.equal(fence.state.acquired, 1);
  assert.equal(fence.state.releases, 1);
});

test("reset/delete: a residual process still bound refuses WORKSPACE_RESIDUAL_PROCESS without a tombstone", async () => {
  const residualIo = makeResidualIo([{ pid: 4242 }]);
  const { dispatcher, tombstoneIo, fence } = makeHarness({ residualIo });
  const result = await dispatcher.dispatchResetDelete(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_RESIDUAL_PROCESS");
  assert.equal(fence.state.releases, 1, "the exclusive fence must still be released");
  const disposition = await readLiveDisposition(tombstoneIo);
  assert.equal(disposition.kind, "workspace-generation-pointer", "live slot must be untouched");
});

test("reset/delete: an in-flight workload refuses WORKSPACE_BUSY (quiescence gate)", async () => {
  const { dispatcher, tombstoneIo } = makeHarness();
  const result = await dispatcher.dispatchResetDelete(callArgs({
    lifecycleContext: lifecycleContext({
      probeQuiescence: () => ({ pendingInvokes: 1, pendingSessions: 0 }),
    }),
  }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKSPACE_BUSY");
  const disposition = await readLiveDisposition(tombstoneIo);
  assert.equal(disposition.kind, "workspace-generation-pointer");
});

test("reset/delete: a lost exclusive fence refuses LEASE_CONFLICT without a tombstone", async () => {
  const fence = makeExclusiveFence({ current: false });
  const { dispatcher, tombstoneIo } = makeHarness({ fence });
  const result = await dispatcher.dispatchResetDelete(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "LEASE_CONFLICT");
  assert.equal(fence.state.releases, 1);
  const disposition = await readLiveDisposition(tombstoneIo);
  assert.equal(disposition.kind, "workspace-generation-pointer");
});

// ---------------------------------------------------------------------------
// A4 idempotent re-delete: a live tombstone chaining onto the same base
// short-circuits to already_tombstoned with no second CAS.
// ---------------------------------------------------------------------------

test("reset/delete: an already-tombstoned slot without replay evidence refuses stale", async () => {
  const tombstone = buildTombstone({
    hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: "posix",
    operation: "delete", tombstonedGeneration: 3,
    priorKind: "workspace-generation-pointer", priorPointerFingerprint: "e".repeat(64),
    dirtyBackupFingerprint: "f".repeat(64),
  });
  const { dispatcher, backupIo } = makeHarness({ slotBytes: tombstoneBytes(tombstone) });
  const result = await dispatcher.dispatchResetDelete(callArgs());
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.code, "WORKSPACE_GENERATION_STALE");
  assert.equal(result.cleanupState, "indeterminate");
  assert.equal(backupIo.calls, 0, "no dirty backup is captured on the idempotent path");
});

// ---------------------------------------------------------------------------
// manual_cleanup: an ordered-publish io failure yields an unproven-durability
// disposition surfaced as an ok:false refusal carrying the internal receipt.
// ---------------------------------------------------------------------------

test("reset/delete: a crash during the tombstone publish yields manual_cleanup surfaced as a refusal", async () => {
  const { config, tombstoneIo } = validConfig();
  tombstoneIo.throwAt.add("replace");
  const dispatcher = createLifecycleResetDeleteDispatcher(config);
  const result = await dispatcher.dispatchResetDelete(callArgs());
  assert.equal(result.ok, false);
  assert.equal(result.code, "RUNTIME_INCOMPATIBLE");
  assert.equal(result.cleanupState, "manual_required");
  assert.equal(result.receipt.disposition, "manual_cleanup");
  assert.ok(result.receipt.manualCleanup, "the manual-cleanup checkpoint record is preserved internally");
});

// ---------------------------------------------------------------------------
// Platform vocabulary
// ---------------------------------------------------------------------------

test("reset/delete: windows-unc source platform is refused CONTAINMENT_UNSUPPORTED", async () => {
  const { dispatcher, fence } = makeHarness();
  const result = await dispatcher.dispatchResetDelete({
    message: resetDeleteMessage({ sourcePlatform: "windows-unc" }),
    trustedBinding: baseAuthority({ sourcePlatform: "windows-unc" }),
    trustedInventoryWorkspace: { ...inventoryWorkspace, sourcePlatform: "windows-unc" },
    leaseCandidate,
    lifecycleContext: lifecycleContext(),
    readiness: liveReadiness(),
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "CONTAINMENT_UNSUPPORTED");
  assert.equal(result.cleanupState, "not_required");
  assert.equal(fence.state.acquired, 0);
});
