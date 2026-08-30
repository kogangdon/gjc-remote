import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { classifyWorkspaceLifecycleEvidence } from "@gjc-remote/shared/workspace-lifecycle-envelope.js";
import { validateManualCleanup } from "@gjc-remote/shared/recovery-envelope.js";
import { buildGenerationPointer, generationPointerBytes } from "../src/workspace-generation-publisher.js";
import { TOMBSTONE_STEPS, buildTombstone, tombstoneBytes, readLiveDisposition } from "../src/workspace-tombstone-publisher.js";
import { createWorkspaceResetDeleteOperation } from "../src/workspace-reset-delete-operation.js";

const HOST = "host-a";
const WORKSPACE = "workspace-a";
const AUTHORITY = Object.freeze({ anchorFingerprint: "1".repeat(64), fenceGeneration: 7, txId: "tx-reset-1", reason: "reset-owner-action", expectedFingerprint: null, observedFingerprint: null, expectedFloorFingerprint: null, observedFloorFingerprint: null });
function livePointer(overrides = {}) { return buildGenerationPointer({ hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: "posix", activeGeneration: 3, generationPath: "generations/3", rootIdentityFingerprint: "a".repeat(64), storageIdentityFingerprint: "b".repeat(64), gitGenerationFingerprint: "c".repeat(64), manifestFingerprint: "d".repeat(64), priorGeneration: 2, priorPointerFingerprint: "e".repeat(64), ...overrides }); }
function makeTombstoneIo(initialBytes, order) {
  const state = { slot: initialBytes }; const throwAt = new Set();
  return { state, throwAt,
    async readLivePointer() { order?.push("tombstone.readLivePointer"); return state.slot; },
    async writeTemp(bytes) { order?.push("tombstone.writeTemp"); if (throwAt.has("writeTemp")) throw new Error("writeTemp boom"); return { bytes }; },
    async flushTemp() { order?.push("tombstone.flushTemp"); if (throwAt.has("flushTemp")) throw new Error("flushTemp boom"); },
    async replace(ref) { order?.push("tombstone.replace"); if (throwAt.has("replace")) throw new Error("replace boom"); state.slot = ref.bytes; },
    async flushParent() { order?.push("tombstone.flushParent"); if (throwAt.has("flushParent")) throw new Error("flushParent boom"); },
  };
}
function makeBackupIo(order, files = { "README.md": "readme", "src/a.js": "alpha" }) { return { calls: 0, async readBytes(relPath) { order?.push(`backup.readBytes:${relPath}`); this.calls += 1; if (!Object.hasOwn(files, relPath)) { const error = new Error(`missing ${relPath}`); error.code = "ENOENT"; throw error; } return new TextEncoder().encode(files[relPath]); } }; }
function makeResidualIo(order, residuals = []) { return { calls: 0, async listResidualProcesses(query) { order?.push(`residual.list:${query.hostId}/${query.workspaceId}`); this.calls += 1; return residuals; } }; }
function makeLease() { return { fence: 42, released: false, lost: false, isCurrent() { return !this.lost; }, release() { this.released = true; } }; }
function dirtyDescriptor(pointer = livePointer()) { return { hostId: HOST, workspaceId: WORKSPACE, workspaceGeneration: pointer.activeGeneration, sourcePlatform: "posix", rootIdentityFingerprint: pointer.rootIdentityFingerprint, storageIdentityFingerprint: pointer.storageIdentityFingerprint, gitGenerationFingerprint: pointer.gitGenerationFingerprint, relativePaths: ["README.md", "src/a.js"] }; }
function baseRequest(overrides = {}) {
  const pointer = overrides.pointer ?? livePointer(); const order = overrides.order;
  const backupIo = overrides.backupIo ?? makeBackupIo(order);
  return { request: { operation: "delete", hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: "posix", workDir: `/srv/ws/${WORKSPACE}`, expectedWorkspaceGeneration: pointer.activeGeneration, leaseCandidate: { workspaceId: WORKSPACE },
    lifecycleContext: { lifecycleAuthority: { ...AUTHORITY }, async probeQuiescence() { order?.push("probeQuiescence"); return { pendingInvokes: 0, pendingSessions: 0 }; }, async prepareTerminal() { order?.push("prepareTerminal"); }, async clearTerminalPreparation() { order?.push("clearTerminalPreparation"); }, async commitTerminal(receipt) { order?.push(`terminal:${receipt.disposition}`); } },
    async prepareDirtyBackup(live) { order?.push("prepareDirtyBackup"); return { dirtyBackup: dirtyDescriptor(live.record), backupIo }; },
    ...overrides.request }, pointer, backupIo };
}
function operation({ acquireFence = () => makeLease(), residualIo = makeResidualIo(), tombstoneIo }) { return createWorkspaceResetDeleteOperation({ acquireFence, residualIo, tombstoneIo: async () => tombstoneIo }); }

test("happy path: captures backup then publishes a committed tombstone", async () => {
  const { request, pointer, backupIo } = baseRequest(); const io = makeTombstoneIo(generationPointerBytes(pointer)); const lease = makeLease();
  const result = await operation({ acquireFence: () => lease, residualIo: makeResidualIo(), tombstoneIo: io }).runResetDelete(request);
  assert.equal(result.disposition, "committed"); assert.equal(result.operation, "delete"); assert.equal(result.published.published, true); assert.equal(result.published.tombstonedGeneration, 3); assert.equal(result.tombstone.priorKind, "workspace-generation-pointer"); assert.equal(result.tombstone.priorPointerFingerprint, pointer.pointerFingerprint); assert.equal(result.dirtyBackupFingerprint, result.tombstone.dirtyBackupFingerprint); assert.ok(Object.isFrozen(result)); assert.equal(lease.released, true); assert.ok(backupIo.calls > 0);
  const disposition = await readLiveDisposition(io); assert.equal(disposition.kind, "workspace-tombstone"); assert.equal(disposition.record.tombstoneFingerprint, result.tombstone.tombstoneFingerprint);
});

test("ordered call sequence: acquire -> quiescence -> current -> live -> manifest/backup -> residual -> current -> publish -> terminal -> release", async () => {
  const order = []; const { request, pointer } = baseRequest({ order }); const io = makeTombstoneIo(generationPointerBytes(pointer), order); const lease = makeLease(); lease.isCurrent = () => { order.push("fence.isCurrent"); return true; }; lease.release = () => order.push("release");
  await operation({ acquireFence: () => { order.push("acquireFence"); return lease; }, residualIo: makeResidualIo(order), tombstoneIo: io }).runResetDelete(request);
  const idx = (needle) => order.findIndex((entry) => entry.startsWith(needle));
  assert.ok(idx("acquireFence") < idx("probeQuiescence")); assert.ok(idx("probeQuiescence") < idx("fence.isCurrent")); assert.ok(idx("fence.isCurrent") < idx("tombstone.readLivePointer")); assert.ok(idx("tombstone.readLivePointer") < idx("prepareDirtyBackup")); assert.ok(idx("prepareDirtyBackup") < idx("backup.readBytes")); assert.ok(idx("backup.readBytes") < idx("residual.list")); assert.ok(order.indexOf("fence.isCurrent") < idx("prepareTerminal")); assert.ok(idx("prepareTerminal") < order.lastIndexOf("fence.isCurrent")); assert.ok(order.lastIndexOf("fence.isCurrent") < idx("tombstone.writeTemp")); assert.ok(idx("tombstone.writeTemp") < idx("terminal:committed")); assert.ok(idx("terminal:committed") < idx("clearTerminalPreparation")); assert.ok(idx("clearTerminalPreparation") < idx("release"));
});

test("non-exclusive holder: acquireFence throws WORKSPACE_BUSY at step 1 with zero fs mutation", async () => {
  const { request, pointer, backupIo } = baseRequest(); const prior = generationPointerBytes(pointer); const io = makeTombstoneIo(prior); const residualIo = makeResidualIo();
  await assert.rejects(operation({ acquireFence: () => { const error = new Error("busy"); error.code = PROTOCOL_ERROR_CODES.WORKSPACE_BUSY; throw error; }, residualIo, tombstoneIo: io }).runResetDelete(request), (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_BUSY);
  assert.equal(backupIo.calls, 0); assert.equal(residualIo.calls, 0); assert.equal(io.state.slot, prior);
});

test("residual process present: refuses at step 5, backup captured, tombstone never published", async () => {
  const { request, pointer, backupIo } = baseRequest(); const prior = generationPointerBytes(pointer); const io = makeTombstoneIo(prior); const residualIo = makeResidualIo(null, [{ pid: 4321 }]);
  await assert.rejects(operation({ residualIo, tombstoneIo: io }).runResetDelete(request), (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_RESIDUAL_PROCESS);
  assert.ok(backupIo.calls > 0); assert.equal(io.state.slot, prior);
});

test("fence lost before publication (step 6): LEASE_CONFLICT, tombstone never published", async () => {
  const { request, pointer } = baseRequest(); const prior = generationPointerBytes(pointer); const io = makeTombstoneIo(prior); const lease = makeLease(); let residualDone = false; lease.isCurrent = () => !residualDone;
  await assert.rejects(operation({ acquireFence: () => lease, residualIo: { async listResidualProcesses(query) { residualDone = true; return makeResidualIo().listResidualProcesses(query); } }, tombstoneIo: io }).runResetDelete(request), (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT && error.checkpoint === "publication");
  assert.equal(io.state.slot, prior); assert.equal(lease.released, true);
});

test("fence lost during terminal preparation clears the contingency and refuses", async () => {
  const { request, pointer } = baseRequest();
  const lease = makeLease();
  let cleared = false;
  let committed = false;
  request.lifecycleContext.prepareTerminal = () => {
    lease.lost = true;
  };
  request.lifecycleContext.clearTerminalPreparation = () => {
    cleared = true;
  };
  request.lifecycleContext.commitTerminal = () => {
    committed = true;
  };
  await assert.rejects(
    operation({
      acquireFence: () => lease,
      residualIo: makeResidualIo(),
      tombstoneIo: makeTombstoneIo(generationPointerBytes(pointer)),
    }).runResetDelete(request),
    (error) =>
      error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT &&
      error.checkpoint === "terminal-preparation"
  );
  assert.equal(cleared, true);
  assert.equal(committed, false);
});

test("ambiguous terminal preparation failure commits manual cleanup before release", async () => {
  const order = [];
  const { request, pointer } = baseRequest({ order });
  request.lifecycleContext.prepareTerminal = () => {
    const error = new Error("flush parent failed");
    error.code = "IO_FAILED";
    error.terminalPreparationAmbiguous = true;
    throw error;
  };
  const result = await operation({
    residualIo: makeResidualIo(),
    tombstoneIo: makeTombstoneIo(generationPointerBytes(pointer), order),
  }).runResetDelete(request);
  assert.equal(result.disposition, "manual_cleanup");
  assert.equal(result.cause.step, "prepareTerminal");
  assert.ok(order.includes("terminal:manual_cleanup"));
});

test("fence lost before live pin (step 3): LEASE_CONFLICT, backup never captured", async () => {
  const { request, pointer, backupIo } = baseRequest(); const lease = makeLease(); lease.isCurrent = () => false;
  await assert.rejects(operation({ acquireFence: () => lease, residualIo: makeResidualIo(), tombstoneIo: makeTombstoneIo(generationPointerBytes(pointer)) }).runResetDelete(request), (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT && error.checkpoint === "live-read"); assert.equal(backupIo.calls, 0); assert.equal(lease.released, true);
});

test("quiescence violated: WORKSPACE_BUSY, backup never captured", async () => {
  const { request, pointer, backupIo } = baseRequest(); request.lifecycleContext.probeQuiescence = () => ({ pendingInvokes: 1, pendingSessions: 0 });
  await assert.rejects(operation({ residualIo: makeResidualIo(), tombstoneIo: makeTombstoneIo(generationPointerBytes(pointer)) }).runResetDelete(request), (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_BUSY); assert.equal(backupIo.calls, 0);
});

test("clean refusals never commit terminal state", async () => {
  for (const mode of ["quiescence", "fence", "residual"]) {
    const { request, pointer } = baseRequest(); let committed = false;
    request.lifecycleContext.commitTerminal = () => { committed = true; };
    if (mode === "quiescence") request.lifecycleContext.probeQuiescence = () => ({ pendingInvokes: 1, pendingSessions: 0 });
    const lease = makeLease(); if (mode === "fence") lease.isCurrent = () => false;
    const residualIo = makeResidualIo(null, mode === "residual" ? [{ pid: 1 }] : []);
    await assert.rejects(operation({ acquireFence: () => lease, residualIo, tombstoneIo: makeTombstoneIo(generationPointerBytes(pointer)) }).runResetDelete(request));
    assert.equal(committed, false, mode);
  }
});

test("crash-sim: a publication io failure at each step yields disposition manual_cleanup with a valid record", async () => {
  for (const step of TOMBSTONE_STEPS) { const order = []; const { request, pointer } = baseRequest({ order }); const prior = generationPointerBytes(pointer); const io = makeTombstoneIo(prior, order); io.throwAt.add(step); const lease = makeLease(); let committed = false; lease.release = () => order.push("release"); request.lifecycleContext.commitTerminal = () => { committed = true; order.push("terminal"); };
    const result = await operation({ acquireFence: () => lease, residualIo: makeResidualIo(order), tombstoneIo: io }).runResetDelete(request); assert.equal(result.disposition, "manual_cleanup", step); assert.equal(result.published, false); assert.equal(result.cause.step, step); assert.equal(order.indexOf("prepareTerminal") < order.indexOf("tombstone.writeTemp"), true); assert.equal(order.includes("clearTerminalPreparation"), false); assert.equal(order.indexOf("terminal") < order.indexOf("release"), true); assert.equal(committed, true); validateManualCleanup(result.manualCleanup); assert.equal(classifyWorkspaceLifecycleEvidence({ manualCleanup: result.manualCleanup }), "manual_cleanup"); assert.equal(result.manualCleanup.txId, AUTHORITY.txId); assert.ok(Object.isFrozen(result.manualCleanup));
    const expected = buildTombstone({ hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: "posix", operation: "delete", tombstonedGeneration: 3, priorKind: "workspace-generation-pointer", priorPointerFingerprint: pointer.pointerFingerprint, dirtyBackupFingerprint: result.dirtyBackupFingerprint }); const isOld = io.state.slot === prior; const isNew = io.state.slot !== null && Buffer.from(io.state.slot).equals(Buffer.from(tombstoneBytes(expected))); assert.ok(isOld || isNew); if (["writeTemp", "flushTemp", "replace"].includes(step)) assert.ok(isOld);
  }
});

test("an already-live tombstone without durable replay evidence refuses cleanly", async () => {
  const order = []; const pointer = livePointer(); const tombstone = buildTombstone({ hostId: HOST, workspaceId: WORKSPACE, sourcePlatform: "posix", operation: "delete", tombstonedGeneration: 3, priorKind: "workspace-generation-pointer", priorPointerFingerprint: pointer.pointerFingerprint, dirtyBackupFingerprint: "f".repeat(64) }); const { request, backupIo } = baseRequest({ pointer, order }); const io = makeTombstoneIo(tombstoneBytes(tombstone), order); const lease = makeLease(); lease.release = () => order.push("release"); let committed = false; request.lifecycleContext.commitTerminal = () => { committed = true; order.push("terminal"); };
  await assert.rejects(
    operation({ acquireFence: () => lease, residualIo: makeResidualIo(order), tombstoneIo: io }).runResetDelete(request),
    (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
  );
  assert.equal(backupIo.calls, 0);
  assert.equal(committed, false);
  assert.equal(order.includes("release"), true);
});

test("construction guards: missing collaborators refuse CONFIG_INVALID", () => {
  const good = { acquireFence: () => makeLease(), residualIo: makeResidualIo(), tombstoneIo: async () => makeTombstoneIo(null) };
  for (const key of ["acquireFence", "residualIo", "tombstoneIo"]) assert.throws(() => createWorkspaceResetDeleteOperation({ ...good, [key]: undefined }), (error) => error.code === PROTOCOL_ERROR_CODES.CONFIG_INVALID, key);
});

test("request guards: bad operation / missing lifecycleContext authority key refuse CONFIG_INVALID", async () => {
  const { pointer } = baseRequest(); const op = operation({ residualIo: makeResidualIo(), tombstoneIo: makeTombstoneIo(generationPointerBytes(pointer)) });
  await assert.rejects(op.runResetDelete(baseRequest({ request: { operation: "refresh" } }).request), (error) => error.code === PROTOCOL_ERROR_CODES.CONFIG_INVALID);
  const missing = baseRequest().request; delete missing.lifecycleContext.lifecycleAuthority.reason; await assert.rejects(op.runResetDelete(missing), (error) => error.code === PROTOCOL_ERROR_CODES.CONFIG_INVALID);
});

test("malformed lifecycleAuthority value: fails closed CONFIG_INVALID eagerly, before any fence or io", async () => {
  const { request, pointer, backupIo } = baseRequest(); request.lifecycleContext.lifecycleAuthority.anchorFingerprint = "not-hex"; const io = makeTombstoneIo(generationPointerBytes(pointer)); let acquired = false;
  await assert.rejects(operation({ acquireFence: () => { acquired = true; return makeLease(); }, residualIo: makeResidualIo(), tombstoneIo: io }).runResetDelete(request), (error) => error.code === PROTOCOL_ERROR_CODES.CONFIG_INVALID); assert.equal(acquired, false); assert.equal(backupIo.calls, 0);
});

test("live pointer generation must match the accepted binding before backup preparation", async () => {
  const diverged = livePointer({ activeGeneration: 5, priorGeneration: 4 }); const { request } = baseRequest(); let prepared = null; request.prepareDirtyBackup = async (live) => { prepared = live; return { dirtyBackup: dirtyDescriptor(live.record), backupIo: makeBackupIo() }; };
  await assert.rejects(
    operation({ residualIo: makeResidualIo(), tombstoneIo: makeTombstoneIo(generationPointerBytes(diverged)) }).runResetDelete(request),
    (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
  );
  assert.equal(prepared, null);
});

for (const [field, value] of [
  ["hostId", "host-b"],
  ["workspaceId", "workspace-b"],
  ["sourcePlatform", "windows-drive"],
]) {
  test(`live pointer ${field} must match accepted authority before backup`, async () => {
    const mismatched = livePointer({ [field]: value });
    const { request, backupIo } = baseRequest();
    let committed = false;
    request.lifecycleContext.commitTerminal = () => {
      committed = true;
    };
    await assert.rejects(
      operation({
        residualIo: makeResidualIo(),
        tombstoneIo: makeTombstoneIo(generationPointerBytes(mismatched)),
      }).runResetDelete(request),
      (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE
    );
    assert.equal(backupIo.calls, 0);
    assert.equal(committed, false);
  });
}

test("stale CAS base: a diverged slot refuses without manual cleanup or terminal commit", async () => {
  const pointer = livePointer(); const seed = generationPointerBytes(pointer); const diverged = generationPointerBytes(livePointer({ activeGeneration: 5, priorGeneration: 4 })); let reads = 0; const io = { state: { slot: seed }, async readLivePointer() { reads += 1; return reads >= 2 ? diverged : seed; }, async writeTemp(bytes) { return { bytes }; }, async flushTemp() {}, async replace(ref) { this.state.slot = ref.bytes; }, async flushParent() {} }; const { request } = baseRequest({ pointer }); let committed = false; request.lifecycleContext.commitTerminal = () => { committed = true; };
  await assert.rejects(operation({ residualIo: makeResidualIo(), tombstoneIo: io }).runResetDelete(request), (error) => error.code === "WORKSPACE_GENERATION_CAS_CONFLICT"); assert.equal(io.state.slot, seed); assert.equal(committed, false);
});
