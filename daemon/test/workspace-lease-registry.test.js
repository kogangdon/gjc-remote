import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { WorkspaceLeaseRegistry } from "../src/workspace-lease-registry.js";

const authority = Object.freeze({
  hostId: "host-a",
  mappingId: "mapping-a",
  mappingGeneration: 5,
  mappingVersion: 1,
  workspaceId: "workspace-a",
  workspaceGeneration: 7,
  sourcePlatform: "linux",
  routeFingerprint: "route-a",
  authorityFingerprint: "authority-a",
  inventoryGeneration: 3,
});

function activity(overrides = {}) {
  return {
    ...authority,
    bindingFingerprint: "binding-fingerprint-a",
    ...overrides,
  };
}

test("activity leases require process-wide adopted authority", () => {
  const registry = new WorkspaceLeaseRegistry();

  assert.throws(
    () => registry.acquireActivity(activity()),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );
  assert.equal(registry.adoptBinding(authority), true);
  const lease = registry.acquireActivity(activity());
  assert.equal(lease.isCurrent(), true);
  lease.release();
});

test("receipt authority retirement invalidates exact activity only", () => {
  const registry = new WorkspaceLeaseRegistry();
  const receiptAuthority = {
    authorityEpoch: 2,
    fenceGeneration: 3,
    hostId: "host-a",
    mappingId: "mapping-receipt",
    mappingGeneration: 4,
    mappingVersion: 1,
    workspaceId: "workspace-receipt",
    workspaceGeneration: 5,
    sourcePlatform: "posix",
    authorityFingerprint: "a".repeat(64),
    inventoryGeneration: 6,
    inventoryFingerprint: "b".repeat(64),
    socketGeneration: 1,
    bindingId: "receipt-binding",
    bindingFingerprint: "c".repeat(64),
  };
  assert.equal(registry.adoptBinding(receiptAuthority), true);
  const lease = registry.acquireActivity(receiptAuthority);
  assert.equal(lease.isCurrent(), true);
  assert.equal(registry.retireBinding({
    ...receiptAuthority,
    inventoryFingerprint: "d".repeat(64),
  }), false);
  assert.equal(lease.isCurrent(), true);
  assert.equal(registry.retireBinding(receiptAuthority), true);
  assert.equal(lease.isCurrent(), false);
  assert.deepEqual(registry.snapshot(), []);
});

test("receipt activities require the exact socket, binding, and fingerprint", () => {
  const registry = new WorkspaceLeaseRegistry();
  const receipt = {
    authorityEpoch: 2,
    fenceGeneration: 3,
    hostId: "host-a",
    mappingId: "mapping-receipt",
    mappingGeneration: 4,
    mappingVersion: 1,
    workspaceId: "workspace-receipt",
    workspaceGeneration: 5,
    sourcePlatform: "posix",
    authorityFingerprint: "a".repeat(64),
    inventoryGeneration: 6,
    inventoryFingerprint: "b".repeat(64),
    socketGeneration: 1,
    bindingId: "ab",
    bindingFingerprint: "c".repeat(64),
  };
  assert.equal(registry.adoptBinding(receipt), true);
  const lease = registry.acquireActivity(receipt);
  assert.equal(lease.isCurrent(), true);
  assert.throws(
    () => registry.acquireActivity({ ...receipt, bindingId: "a" }),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );
  const replacement = { ...receipt, socketGeneration: 2 };
  assert.equal(registry.adoptBinding(replacement), true);
  assert.equal(lease.isCurrent(), false);
  lease.release();
  const current = registry.acquireActivity(replacement);
  assert.equal(current.isCurrent(), true);
});

test("receipt identity rotates on inventory or socket fence advancement", () => {
  const registry = new WorkspaceLeaseRegistry();
  const first = {
    authorityEpoch: 1,
    fenceGeneration: 1,
    hostId: "host-a",
    mappingId: "mapping-a",
    mappingGeneration: 1,
    mappingVersion: 1,
    workspaceId: "workspace-a",
    workspaceGeneration: 1,
    sourcePlatform: "posix",
    authorityFingerprint: "a".repeat(64),
    inventoryGeneration: 1,
    inventoryFingerprint: "b".repeat(64),
    socketGeneration: 1,
    bindingId: "binding-a",
    bindingFingerprint: "c".repeat(64),
  };
  assert.equal(registry.adoptBinding(first), true);
  const inventorySuccessor = {
    ...first,
    inventoryGeneration: 2,
    inventoryFingerprint: "d".repeat(64),
    bindingId: "binding-b",
    bindingFingerprint: "e".repeat(64),
  };
  assert.equal(registry.adoptBinding(inventorySuccessor), true);
  const socketSuccessor = {
    ...inventorySuccessor,
    socketGeneration: 2,
    bindingId: "binding-c",
    bindingFingerprint: "f".repeat(64),
  };
  assert.equal(registry.adoptBinding(socketSuccessor), true);
  const lease = registry.acquireActivity(socketSuccessor);
  assert.equal(lease.isCurrent(), true);
});

test("activity leases share one fence for the same immutable binding identity", () => {
  const registry = new WorkspaceLeaseRegistry();
  registry.adoptBinding(authority);
  const first = registry.acquireActivity(activity());
  const second = registry.acquireActivity(activity());

  assert.equal(first.fence, second.fence);
  assert.deepEqual(registry.snapshot(), [
    {
      workspaceId: authority.workspaceId,
      workspaceGeneration: authority.workspaceGeneration,
      mappingGeneration: authority.mappingGeneration,
      inventoryGeneration: authority.inventoryGeneration,
      fence: first.fence,
      holders: 2,
      invalidated: false,
    },
  ]);

  first.release();
  first.release();
  assert.equal(first.isCurrent(), false);
  assert.equal(second.isCurrent(), true);
  second.release();
  assert.equal(registry.snapshot()[0].holders, 0);
});

test("new authority invalidates activity and waits for prior holders", () => {
  const registry = new WorkspaceLeaseRegistry();
  registry.adoptBinding(authority);
  const admitted = registry.acquireActivity(activity());
  const replacement = {
    ...authority,
    workspaceGeneration: authority.workspaceGeneration + 1,
  };

  assert.equal(registry.adoptBinding(replacement), true);
  assert.equal(admitted.isCurrent(), false);
  assert.throws(
    () =>
      registry.acquireActivity({
        ...replacement,
        bindingFingerprint: "binding-fingerprint-b",
      }),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );

  admitted.release();
  const next = registry.acquireActivity({
    ...replacement,
    bindingFingerprint: "binding-fingerprint-b",
  });
  assert.notEqual(next.fence, admitted.fence);
  next.release();
});

test("stale reconnect cannot replace newer idle process authority", () => {
  const registry = new WorkspaceLeaseRegistry();
  const newer = {
    ...authority,
    mappingGeneration: authority.mappingGeneration + 1,
    workspaceGeneration: authority.workspaceGeneration + 1,
    inventoryGeneration: authority.inventoryGeneration + 1,
  };
  registry.adoptBinding(authority);
  assert.equal(registry.adoptBinding(newer), true);

  assert.equal(registry.adoptBinding(authority), false);
  assert.throws(
    () => registry.acquireActivity(activity()),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );
  const current = registry.acquireActivity({
    ...newer,
    bindingFingerprint: "newer-binding",
  });
  assert.equal(current.isCurrent(), true);
  current.release();
});

test("authority drift requires a mapping or workspace generation advance", () => {
  const registry = new WorkspaceLeaseRegistry();
  registry.adoptBinding(authority);

  assert.equal(
    registry.adoptBinding({
      ...authority,
      authorityFingerprint: "foreign-authority",
      inventoryGeneration: authority.inventoryGeneration + 1,
    }),
    false
  );
  assert.equal(
    registry.adoptBinding({
      ...authority,
      authorityFingerprint: "replacement-authority",
      mappingGeneration: authority.mappingGeneration + 1,
    }),
    true
  );
});

test("unrelated workspace activity remains independently admissible", () => {
  const registry = new WorkspaceLeaseRegistry();
  const other = {
    ...authority,
    mappingId: "mapping-b",
    workspaceId: "workspace-b",
    workspaceGeneration: 1,
  };
  registry.adoptBinding(authority);
  registry.adoptBinding(other);
  const first = registry.acquireActivity(activity());
  const second = registry.acquireActivity({
    ...other,
    bindingFingerprint: "binding-fingerprint-b",
  });

  registry.adoptBinding({
    ...authority,
    workspaceGeneration: authority.workspaceGeneration + 1,
  });
  assert.equal(first.isCurrent(), false);
  assert.equal(second.isCurrent(), true);

  first.release();
  second.release();
});

test("workspace authority retention is bounded", () => {
  const registry = new WorkspaceLeaseRegistry({ maxWorkspaces: 1 });
  assert.equal(registry.adoptBinding(authority), true);
  assert.equal(
    registry.adoptBinding({
      ...authority,
      mappingId: "mapping-b",
      workspaceId: "workspace-b",
    }),
    false
  );
  assert.equal(registry.snapshot().length, 1);
});

test("invalid lease identities fail before registry mutation", () => {
  const registry = new WorkspaceLeaseRegistry();

  assert.throws(
    () => registry.adoptBinding({ ...authority, workspaceGeneration: -1 }),
    /workspace lease authority is invalid/
  );
  assert.throws(
    () => registry.acquireActivity({ ...activity(), bindingFingerprint: "" }),
    /workspace lease identity is invalid/
  );
  assert.deepEqual(registry.snapshot(), []);
});

// --- #43 host-wide active-workspace admission (maxActiveWorkspaces) ---------
//
// These tests prove the new bound entirely at the WorkspaceLeaseRegistry API
// surface. They construct ONLY a WorkspaceLeaseRegistry: no SessionPool and no
// AdmissionBudget exist in this object graph, so independence from the
// 8-session bound is structural (there is nothing to call), not merely observed
// via a spy. The bound is forward-scaffolding — dormant on the live invoke wire
// under the hard-disabled serving gate — and is exercised here, not via a live
// serving invoke.

function distinct(i) {
  return {
    ...authority,
    mappingId: `mapping-${i}`,
    workspaceId: `workspace-${i}`,
    bindingFingerprint: `binding-fingerprint-${i}`,
  };
}

test("maxActiveWorkspaces must be a positive safe integer", () => {
  for (const bad of [0, -1, 1.5, Number.NaN, "8"]) {
    assert.throws(
      () => new WorkspaceLeaseRegistry({ maxActiveWorkspaces: bad }),
      /maxActiveWorkspaces must be a positive safe integer/
    );
  }
  const registry = new WorkspaceLeaseRegistry();
  assert.equal(registry.maxActiveWorkspaces, 8);
});

test("host-wide active workspaces are bounded at exactly maxActiveWorkspaces", () => {
  const registry = new WorkspaceLeaseRegistry();
  const leases = [];
  for (let i = 0; i < 8; i += 1) {
    registry.adoptBinding(distinct(i));
    leases.push(registry.acquireActivity(distinct(i)));
  }
  assert.equal(registry.activities.size, 8);

  registry.adoptBinding(distinct(8));
  assert.throws(
    () => registry.acquireActivity(distinct(8)),
    (error) =>
      error.code === PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED
  );
  // The rejection did not create a phantom entry.
  assert.equal(registry.activities.size, 8);
  for (const lease of leases) lease.release();
});

test("releasing an active workspace frees exactly one admission slot", () => {
  const registry = new WorkspaceLeaseRegistry({ maxActiveWorkspaces: 2 });
  registry.adoptBinding(distinct(0));
  registry.adoptBinding(distinct(1));
  const first = registry.acquireActivity(distinct(0));
  registry.acquireActivity(distinct(1));

  registry.adoptBinding(distinct(2));
  assert.throws(
    () => registry.acquireActivity(distinct(2)),
    (error) =>
      error.code === PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED
  );

  first.release();
  const admitted = registry.acquireActivity(distinct(2));
  assert.equal(admitted.isCurrent(), true);
  assert.equal(registry.activities.size, 2);
});

test("re-acquiring an already-active workspace never consults the bound", () => {
  const registry = new WorkspaceLeaseRegistry({ maxActiveWorkspaces: 1 });
  registry.adoptBinding(distinct(0));
  const first = registry.acquireActivity(distinct(0));
  // Same workspaceId, same identity: an additional holder, not a new entry.
  const second = registry.acquireActivity(distinct(0));
  assert.equal(first.fence, second.fence);
  assert.equal(registry.activities.size, 1);

  // A genuinely distinct workspace is still fail-closed at capacity.
  registry.adoptBinding(distinct(1));
  assert.throws(
    () => registry.acquireActivity(distinct(1)),
    (error) =>
      error.code === PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED
  );
  first.release();
  second.release();
});

test("a stale same-workspace rotation is re-admissible at capacity", () => {
  // The stale-entry delete in acquireActivity runs BEFORE the size check, so a
  // legitimate re-admission of a workspace whose prior lease has drained is not
  // spuriously fail-closed by maxActiveWorkspaces.
  const registry = new WorkspaceLeaseRegistry({ maxActiveWorkspaces: 1 });
  registry.adoptBinding(distinct(0));
  const stale = registry.acquireActivity(distinct(0));
  // Rotate the same workspace's authority; the live activity is invalidated but
  // retained while the prior holder is outstanding.
  const rotated = {
    ...distinct(0),
    workspaceGeneration: authority.workspaceGeneration + 1,
    bindingFingerprint: "binding-fingerprint-0b",
  };
  assert.equal(registry.adoptBinding(rotated), true);
  assert.equal(stale.isCurrent(), false);
  // Prior holder drains -> zero-holder invalidated entry is removed.
  stale.release();
  // Re-admitting the same workspace at capacity 1 succeeds (size is 0 now).
  const fresh = registry.acquireActivity(rotated);
  assert.equal(fresh.isCurrent(), true);
  assert.equal(registry.activities.size, 1);
  fresh.release();
});

test("double-release under the bound is an idempotent no-op", () => {
  const registry = new WorkspaceLeaseRegistry({ maxActiveWorkspaces: 1 });
  registry.adoptBinding(distinct(0));
  const lease = registry.acquireActivity(distinct(0));
  lease.release();
  lease.release();
  assert.equal(registry.activities.size, 0);
  // The slot is genuinely free after the redundant release, not double-counted.
  registry.adoptBinding(distinct(1));
  const next = registry.acquireActivity(distinct(1));
  assert.equal(next.isCurrent(), true);
  next.release();
});

test("invalidateAll frees active-workspace slots once holders drain", () => {
  const registry = new WorkspaceLeaseRegistry({ maxActiveWorkspaces: 1 });
  registry.adoptBinding(distinct(0));
  const held = registry.acquireActivity(distinct(0));
  registry.invalidateAll();
  assert.equal(held.isCurrent(), false);
  // Holder still outstanding -> slot not yet free.
  held.release();
  registry.adoptBinding(distinct(1));
  const next = registry.acquireActivity(distinct(1));
  assert.equal(next.isCurrent(), true);
  next.release();
});
