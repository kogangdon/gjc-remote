import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { classifyWorkspaceLifecycleEvidence } from "@gjc-remote/shared/workspace-lifecycle-envelope.js";
import { validateManualCleanup } from "@gjc-remote/shared/recovery-envelope.js";
import {
  buildGenerationPointer,
  generationPointerBytes,
} from "../src/workspace-generation-publisher.js";
import {
  TOMBSTONE_STEPS,
  buildTombstone,
  tombstoneBytes,
  readLiveDisposition,
} from "../src/workspace-tombstone-publisher.js";
import { createWorkspaceResetDeleteOperation } from "../src/workspace-reset-delete-operation.js";

const HOST = "host-a";
const WORKSPACE = "workspace-a";

// ---------- fixtures ---------------------------------------------------------

function livePointer(overrides = {}) {
  return buildGenerationPointer({
    hostId: HOST,
    workspaceId: WORKSPACE,
    sourcePlatform: "posix",
    activeGeneration: 3,
    generationPath: "generations/3",
    rootIdentityFingerprint: "a".repeat(64),
    storageIdentityFingerprint: "b".repeat(64),
    gitGenerationFingerprint: "c".repeat(64),
    manifestFingerprint: "d".repeat(64),
    priorGeneration: 2,
    priorPointerFingerprint: "e".repeat(64),
    ...overrides,
  });
}

// Ordered single-slot tombstone io + a `throwAt` set for deterministic crash-sim.
function makeTombstoneIo(initialBytes, order) {
  const state = { slot: initialBytes };
  const throwAt = new Set();
  return {
    state,
    throwAt,
    async readLivePointer() {
      order?.push("tombstone.readLivePointer");
      return state.slot;
    },
    async writeTemp(bytes) {
      order?.push("tombstone.writeTemp");
      if (throwAt.has("writeTemp")) throw new Error("writeTemp boom");
      return { bytes };
    },
    async flushTemp() {
      order?.push("tombstone.flushTemp");
      if (throwAt.has("flushTemp")) throw new Error("flushTemp boom");
    },
    async replace(ref) {
      order?.push("tombstone.replace");
      if (throwAt.has("replace")) throw new Error("replace boom");
      state.slot = ref.bytes;
    },
    async flushParent() {
      order?.push("tombstone.flushParent");
      if (throwAt.has("flushParent")) throw new Error("flushParent boom");
    },
  };
}

// Dirty-backup reader over a fixed live file set.
function makeBackupIo(order, files = { "README.md": "readme", "src/a.js": "alpha" }) {
  return {
    calls: 0,
    async readBytes(relPath) {
      order?.push(`backup.readBytes:${relPath}`);
      this.calls += 1;
      if (!Object.hasOwn(files, relPath)) {
        const error = new Error(`missing ${relPath}`);
        error.code = "ENOENT";
        throw error;
      }
      return new TextEncoder().encode(files[relPath]);
    },
  };
}

function makeResidualIo(order, residuals = []) {
  return {
    calls: 0,
    async listResidualProcesses(query) {
      order?.push(`residual.list:${query.hostId}/${query.workspaceId}`);
      this.calls += 1;
      return residuals;
    },
  };
}

// A controllable exclusive fence. `loseAt` names a checkpoint after which
// isCurrent() flips to false, simulating a concurrent invalidation.
function makeLease({ loseAt = null } = {}) {
  const lease = {
    fence: 42,
    released: false,
    lost: false,
    _checkpoints: 0,
    isCurrent() {
      // Each call after the configured checkpoint index reports lost.
      if (this.lost) return false;
      return true;
    },
    release() {
      this.released = true;
    },
  };
  lease.loseNow = () => {
    lease.lost = true;
  };
  lease._loseAt = loseAt;
  return lease;
}

const DIRTY_BACKUP = Object.freeze({
  hostId: HOST,
  workspaceId: WORKSPACE,
  workspaceGeneration: 3,
  sourcePlatform: "posix",
  rootIdentityFingerprint: "a".repeat(64),
  storageIdentityFingerprint: "b".repeat(64),
  gitGenerationFingerprint: "c".repeat(64),
  relativePaths: ["README.md", "src/a.js"],
});

const LIFECYCLE_AUTHORITY = Object.freeze({
  anchorFingerprint: "1".repeat(64),
  fenceGeneration: 7,
  txId: "tx-reset-1",
  reason: "reset-owner-action",
  expectedFingerprint: null,
  observedFingerprint: null,
  expectedFloorFingerprint: null,
  observedFloorFingerprint: null,
});

function baseRequest(overrides = {}) {
  const pointer = overrides.pointer ?? livePointer();
  return {
    request: {
      operation: "delete",
      hostId: HOST,
      workspaceId: WORKSPACE,
      sourcePlatform: "posix",
      leaseCandidate: { workspaceId: WORKSPACE },
      dirtyBackup: { ...DIRTY_BACKUP },
      expected: { priorPointerFingerprint: pointer.pointerFingerprint },
      lifecycleAuthority: { ...LIFECYCLE_AUTHORITY },
      ...overrides.request,
    },
    pointer,
  };
}

// ---------- tests ------------------------------------------------------------

test("happy path: captures backup then publishes a committed tombstone", async () => {
  const order = [];
  const { request, pointer } = baseRequest();
  const tombstoneIo = makeTombstoneIo(generationPointerBytes(pointer), order);
  const lease = makeLease();
  const backupIo = makeBackupIo(order);
  const residualIo = makeResidualIo(order);

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => lease,
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo,
    residualIo,
    tombstoneIo,
  });

  const result = await op.runResetDelete(request);

  assert.equal(result.disposition, "committed");
  assert.equal(result.operation, "delete");
  assert.equal(result.published.published, true);
  assert.equal(result.published.tombstonedGeneration, 3);
  assert.equal(result.tombstone.priorKind, "workspace-generation-pointer");
  assert.equal(result.tombstone.priorPointerFingerprint, pointer.pointerFingerprint);
  assert.equal(result.dirtyBackupFingerprint, result.tombstone.dirtyBackupFingerprint);
  assert.ok(Object.isFrozen(result));
  assert.equal(lease.released, true);

  // The live slot is now the tombstone.
  const disposition = await readLiveDisposition(tombstoneIo);
  assert.equal(disposition.kind, "workspace-tombstone");
  assert.equal(disposition.record.tombstoneFingerprint, result.tombstone.tombstoneFingerprint);
});

test("ordered call sequence: quiescence -> fence -> backup -> residual -> fence -> publish", async () => {
  const order = [];
  const { request, pointer } = baseRequest();
  const tombstoneIo = makeTombstoneIo(generationPointerBytes(pointer), order);
  const lease = makeLease();
  const seq = [];
  lease.isCurrent = () => {
    seq.push("fence.isCurrent");
    order.push("fence.isCurrent");
    return true;
  };

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => {
      order.push("acquireFence");
      return lease;
    },
    probeQuiescence: () => {
      order.push("probeQuiescence");
      return { pendingInvokes: 0, pendingSessions: 0 };
    },
    backupIo: makeBackupIo(order),
    residualIo: makeResidualIo(order),
    tombstoneIo,
  });

  await op.runResetDelete(request);

  // Assert the key ordered milestones appear in the required relative order.
  const idx = (needle) => order.findIndex((entry) => entry.startsWith(needle));
  assert.ok(idx("acquireFence") < idx("probeQuiescence"));
  assert.ok(idx("probeQuiescence") < idx("backup.readBytes"));
  assert.ok(idx("backup.readBytes") < idx("residual.list"));
  assert.ok(idx("residual.list") < idx("tombstone.writeTemp"));
  // A fence recheck precedes both the backup and the publication.
  assert.ok(idx("fence.isCurrent") < idx("backup.readBytes"));
  assert.ok(order.lastIndexOf("fence.isCurrent") < idx("tombstone.writeTemp"));
  // The idempotency probe read happens before quiescence; the CAS read before writeTemp.
  assert.ok(idx("tombstone.readLivePointer") < idx("probeQuiescence"));
});

test("non-exclusive holder: acquireFence throws WORKSPACE_BUSY at step 1 with zero fs mutation", async () => {
  const order = [];
  const { request, pointer } = baseRequest();
  const priorBytes = generationPointerBytes(pointer);
  const tombstoneIo = makeTombstoneIo(priorBytes, order);
  const backupIo = makeBackupIo(order);
  const residualIo = makeResidualIo(order);

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => {
      const error = new Error("busy");
      error.code = PROTOCOL_ERROR_CODES.WORKSPACE_BUSY;
      throw error;
    },
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo,
    residualIo,
    tombstoneIo,
  });

  await assert.rejects(op.runResetDelete(request), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_BUSY);
    return true;
  });

  // Nothing was read or written: no backup, no residual probe, no slot mutation.
  assert.equal(backupIo.calls, 0);
  assert.equal(residualIo.calls, 0);
  assert.deepEqual(order, []);
  assert.equal(tombstoneIo.state.slot, priorBytes);
});

test("residual process present: refuses at step 5, backup captured, tombstone never published", async () => {
  const order = [];
  const { request, pointer } = baseRequest();
  const priorBytes = generationPointerBytes(pointer);
  const tombstoneIo = makeTombstoneIo(priorBytes, order);
  const backupIo = makeBackupIo(order);
  const residualIo = makeResidualIo(order, [{ pid: 4321 }]);

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => makeLease(),
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo,
    residualIo,
    tombstoneIo,
  });

  await assert.rejects(op.runResetDelete(request), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_RESIDUAL_PROCESS);
    return true;
  });

  // The backup WAS captured (destruction was gated on it) but no tombstone
  // publication began and the live slot is unchanged: not silently committed.
  assert.ok(backupIo.calls > 0);
  assert.equal(tombstoneIo.state.slot, priorBytes);
  assert.ok(!order.some((entry) => entry === "tombstone.writeTemp"));
});

test("fence lost before publication (step 6): LEASE_CONFLICT, tombstone never published", async () => {
  const order = [];
  const { request, pointer } = baseRequest();
  const priorBytes = generationPointerBytes(pointer);
  const tombstoneIo = makeTombstoneIo(priorBytes, order);
  const backupIo = makeBackupIo(order);
  const residualIo = makeResidualIo(order);

  // The fence is current through the step-3 recheck (before backup) but is lost
  // by the step-6 recheck. Flip after the residual probe (which is between them).
  const lease = makeLease();
  let residualDone = false;
  lease.isCurrent = () => !residualDone;
  const residualWrap = {
    async listResidualProcesses(query) {
      residualDone = true;
      return residualIo.listResidualProcesses(query);
    },
  };

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => lease,
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo,
    residualIo: residualWrap,
    tombstoneIo,
  });

  await assert.rejects(op.runResetDelete(request), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.LEASE_CONFLICT);
    assert.equal(error.checkpoint, "publication");
    return true;
  });
  assert.equal(tombstoneIo.state.slot, priorBytes);
  assert.ok(!order.some((entry) => entry === "tombstone.writeTemp"));
  assert.equal(lease.released, true);
});

test("fence lost before backup (step 3): LEASE_CONFLICT, backup never captured", async () => {
  const { request, pointer } = baseRequest();
  const tombstoneIo = makeTombstoneIo(generationPointerBytes(pointer));
  const backupIo = makeBackupIo();
  const lease = makeLease();
  lease.isCurrent = () => false;

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => lease,
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo,
    residualIo: makeResidualIo(),
    tombstoneIo,
  });

  await assert.rejects(op.runResetDelete(request), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.LEASE_CONFLICT);
    assert.equal(error.checkpoint, "dirty-backup");
    return true;
  });
  assert.equal(backupIo.calls, 0);
  assert.equal(lease.released, true);
});

test("quiescence violated: WORKSPACE_BUSY, backup never captured", async () => {
  const { request, pointer } = baseRequest();
  const tombstoneIo = makeTombstoneIo(generationPointerBytes(pointer));
  const backupIo = makeBackupIo();

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => makeLease(),
    probeQuiescence: () => ({ pendingInvokes: 1, pendingSessions: 0 }),
    backupIo,
    residualIo: makeResidualIo(),
    tombstoneIo,
  });

  await assert.rejects(op.runResetDelete(request), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_BUSY);
    return true;
  });
  assert.equal(backupIo.calls, 0);
});

test("crash-sim: a publication io failure at each step yields disposition manual_cleanup with a valid record", async () => {
  for (const step of TOMBSTONE_STEPS) {
    const { request, pointer } = baseRequest();
    const priorBytes = generationPointerBytes(pointer);
    const tombstoneIo = makeTombstoneIo(priorBytes);
    tombstoneIo.throwAt.add(step);

    const op = createWorkspaceResetDeleteOperation({
      acquireFence: () => makeLease(),
      probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
      backupIo: makeBackupIo(),
      residualIo: makeResidualIo(),
      tombstoneIo,
    });

    const result = await op.runResetDelete(request);
    assert.equal(result.disposition, "manual_cleanup", `step ${step}`);
    assert.equal(result.published, false, `step ${step}`);
    assert.equal(result.cause.step, step, `step ${step}`);

    // The manual-cleanup record is real shared vocabulary and classifies right.
    validateManualCleanup(result.manualCleanup);
    assert.equal(classifyWorkspaceLifecycleEvidence({ manualCleanup: result.manualCleanup }), "manual_cleanup");
    assert.equal(result.manualCleanup.txId, LIFECYCLE_AUTHORITY.txId);
    assert.equal(result.manualCleanup.anchorFingerprint, LIFECYCLE_AUTHORITY.anchorFingerprint);
    assert.ok(Object.isFrozen(result.manualCleanup));

    // A9 old-OR-new: the slot is either the prior pointer or the new tombstone.
    const expectedTombstone = buildTombstone({
      hostId: HOST,
      workspaceId: WORKSPACE,
      sourcePlatform: "posix",
      operation: "delete",
      tombstonedGeneration: 3,
      priorKind: "workspace-generation-pointer",
      priorPointerFingerprint: pointer.pointerFingerprint,
      dirtyBackupFingerprint: result.dirtyBackupFingerprint,
    });
    const isOld = tombstoneIo.state.slot === priorBytes;
    const isNew = tombstoneIo.state.slot !== null &&
      Buffer.from(tombstoneIo.state.slot).equals(Buffer.from(tombstoneBytes(expectedTombstone)));
    assert.ok(isOld || isNew, `step ${step}: slot torn`);
    // replace is the linearization point: pre-replace throws leave the old value.
    if (step === "writeTemp" || step === "flushTemp" || step === "replace") {
      assert.ok(isOld, `step ${step}: pre-commit throw must leave prior value`);
    }
  }
});

test("idempotent re-delete: an already-live tombstone short-circuits to already_tombstoned", async () => {
  const pointer = livePointer();
  const tombstone = buildTombstone({
    hostId: HOST,
    workspaceId: WORKSPACE,
    sourcePlatform: "posix",
    operation: "delete",
    tombstonedGeneration: 3,
    priorKind: "workspace-generation-pointer",
    priorPointerFingerprint: pointer.pointerFingerprint,
    dirtyBackupFingerprint: "f".repeat(64),
  });
  const order = [];
  const tombstoneIo = makeTombstoneIo(tombstoneBytes(tombstone), order);
  const backupIo = makeBackupIo(order);
  const { request } = baseRequest({ pointer });

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => makeLease(),
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo,
    residualIo: makeResidualIo(order),
    tombstoneIo,
  });

  const result = await op.runResetDelete(request);
  assert.equal(result.disposition, "already_tombstoned");
  assert.equal(result.published, false);
  assert.deepEqual(result.tombstone, tombstone);
  // Zero mutation, zero backup: pure short-circuit.
  assert.equal(backupIo.calls, 0);
  assert.ok(!order.some((entry) => entry.startsWith("backup") || entry === "tombstone.writeTemp"));
});

test("construction guards: missing collaborators refuse CONFIG_INVALID", () => {
  const good = {
    acquireFence: () => makeLease(),
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo: makeBackupIo(),
    residualIo: makeResidualIo(),
    tombstoneIo: makeTombstoneIo(null),
  };
  for (const key of ["acquireFence", "probeQuiescence", "backupIo", "residualIo", "tombstoneIo"]) {
    assert.throws(() => createWorkspaceResetDeleteOperation({ ...good, [key]: undefined }), (error) => {
      assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
      return true;
    }, key);
  }
});

test("request guards: bad operation / missing lifecycleAuthority key refuse CONFIG_INVALID", async () => {
  const { pointer } = baseRequest();
  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => makeLease(),
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo: makeBackupIo(),
    residualIo: makeResidualIo(),
    tombstoneIo: makeTombstoneIo(generationPointerBytes(pointer)),
  });

  // Wrong operation.
  await assert.rejects(op.runResetDelete(baseRequest({ pointer, request: { operation: "refresh" } }).request), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });

  // Missing an authority field -> A6 fail-closed before any fence acquisition.
  const missingAuthority = baseRequest({ pointer }).request;
  delete missingAuthority.lifecycleAuthority.reason;
  await assert.rejects(op.runResetDelete(missingAuthority), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });
});

test("malformed lifecycleAuthority value: manual_cleanup path fails closed CONFIG_INVALID (never a silent commit)", async () => {
  const { request, pointer } = baseRequest();
  // A structurally-present but semantically-invalid authority (non-hex anchor).
  request.lifecycleAuthority.anchorFingerprint = "not-hex";
  const tombstoneIo = makeTombstoneIo(generationPointerBytes(pointer));
  tombstoneIo.throwAt.add("replace"); // force the manual_cleanup path

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => makeLease(),
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo: makeBackupIo(),
    residualIo: makeResidualIo(),
    tombstoneIo,
  });

  await assert.rejects(op.runResetDelete(request), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });
});

test("stale CAS base: a diverged live slot refuses without a manual_cleanup disposition", async () => {
  const { request, pointer } = baseRequest();
  // The live slot is a DIFFERENT pointer than the tombstone will chain onto is
  // irrelevant here; instead seed a pointer whose generation the request does
  // not expect by mutating the slot between build and publish via a diverged
  // pointer. Simplest deterministic stale-base: seed the slot with a pointer,
  // but have readLivePointer return a different pointer on the CAS read.
  const seed = generationPointerBytes(pointer);
  const diverged = generationPointerBytes(livePointer({ activeGeneration: 5, priorGeneration: 4 }));
  let reads = 0;
  const tombstoneIo = {
    state: { slot: seed },
    async readLivePointer() {
      reads += 1;
      // First read (idempotency probe) and second (build) see the seed; the CAS
      // read inside publishTombstone sees the diverged slot.
      return reads >= 3 ? diverged : seed;
    },
    async writeTemp(bytes) { return { bytes }; },
    async flushTemp() {},
    async replace(ref) { this.state.slot = ref.bytes; },
    async flushParent() {},
  };

  const op = createWorkspaceResetDeleteOperation({
    acquireFence: () => makeLease(),
    probeQuiescence: () => ({ pendingInvokes: 0, pendingSessions: 0 }),
    backupIo: makeBackupIo(),
    residualIo: makeResidualIo(),
    tombstoneIo,
  });

  await assert.rejects(op.runResetDelete(request), (error) => {
    assert.equal(error.code, "WORKSPACE_GENERATION_CAS_CONFLICT");
    return true;
  });
  // No manual_cleanup: a stale base means no mutation occurred.
  assert.equal(tombstoneIo.state.slot, seed);
});
