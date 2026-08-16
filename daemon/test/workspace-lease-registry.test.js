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
