import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import {
  WorkspaceLeaseRegistry,
  assertQuiescent,
} from "./workspace-lease-registry.js";
import {
  createActivityFence,
  createExclusiveFence,
  createQuiescenceProbe,
} from "./workspace-lease-fence.js";

// Minimal inline fixture replicated from
// daemon/test/workspace-lease-registry.test.js (requireAuthority's V2 field
// shape plus a legacy bindingFingerprint identity).
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

function distinct(i) {
  return {
    ...authority,
    mappingId: `mapping-${i}`,
    workspaceId: `workspace-${i}`,
    bindingFingerprint: `binding-fingerprint-${i}`,
  };
}

// --- createActivityFence -----------------------------------------------

test("createActivityFence acquires a non-exclusive lease that stacks", () => {
  const registry = new WorkspaceLeaseRegistry();
  registry.adoptBinding(authority);
  const fence = createActivityFence(registry);

  const first = fence(activity());
  assert.equal(first.isCurrent(), true);

  const second = fence(activity());
  assert.equal(first.fence, second.fence);
  assert.equal(second.isCurrent(), true);

  first.release();
  assert.equal(first.isCurrent(), false);
  assert.equal(second.isCurrent(), true);
  second.release();
});

test("createActivityFence refuses LEASE_FENCE_CONFIG_INVALID for a malformed registry", () => {
  assert.throws(
    () => createActivityFence({}),
    (error) =>
      error.operation === "workspace_lease_fence" &&
      error.code === "LEASE_FENCE_CONFIG_INVALID"
  );
  assert.throws(
    () => createActivityFence(null),
    (error) => error.code === "LEASE_FENCE_CONFIG_INVALID"
  );
});

test("createActivityFence passes registry errors through unchanged", () => {
  const registry = new WorkspaceLeaseRegistry();
  const fence = createActivityFence(registry);
  // No adoptBinding: unbound authority -> LEASE_CONFLICT from the registry.
  assert.throws(
    () => fence(activity()),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );
});

// --- createExclusiveFence ------------------------------------------------

test("createExclusiveFence config validation matches createActivityFence", () => {
  assert.throws(
    () => createExclusiveFence({}),
    (error) =>
      error.operation === "workspace_lease_fence" &&
      error.code === "LEASE_FENCE_CONFIG_INVALID"
  );
});

test("createExclusiveFence serializes exclusive access and releases cleanly", () => {
  const registry = new WorkspaceLeaseRegistry();
  registry.adoptBinding(authority);
  const exclusiveFence = createExclusiveFence(registry);

  const held = exclusiveFence(activity());
  assert.equal(held.isCurrent(), true);

  assert.throws(
    () => exclusiveFence(activity()),
    (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_BUSY
  );
  const nonExclusiveFence = createActivityFence(registry);
  assert.throws(
    () => nonExclusiveFence(activity()),
    (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_BUSY
  );

  held.release();
  const fresh = exclusiveFence(activity());
  assert.equal(fresh.isCurrent(), true);
  fresh.release();
});

test("createExclusiveFence raises LEASE_CONFLICT on identity mismatch", () => {
  const registry = new WorkspaceLeaseRegistry();
  registry.adoptBinding(authority);
  const exclusiveFence = createExclusiveFence(registry);
  const held = exclusiveFence(activity());

  assert.throws(
    () =>
      exclusiveFence(activity({ bindingFingerprint: "binding-fingerprint-z" })),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );
  held.release();
});

test("createExclusiveFence raises WORKSPACE_ADMISSION_EXCEEDED at the active-workspace ceiling", () => {
  const registry = new WorkspaceLeaseRegistry({ maxActiveWorkspaces: 1 });
  registry.adoptBinding(distinct(0));
  registry.adoptBinding(distinct(1));
  const exclusiveFence = createExclusiveFence(registry);

  const held = exclusiveFence(distinct(0));
  assert.throws(
    () => exclusiveFence(distinct(1)),
    (error) =>
      error.code === PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED
  );
  held.release();
});

// --- createQuiescenceProbe -------------------------------------------------

test("createQuiescenceProbe resolves numeric counts and feeds assertQuiescent", async () => {
  const probe = createQuiescenceProbe({ pendingInvokes: 0, pendingSessions: 0 });
  const counts = await probe();
  assert.deepEqual(counts, { pendingInvokes: 0, pendingSessions: 0 });
  assert.equal(Object.isFrozen(counts), true);
  assert.deepEqual(assertQuiescent(await probe()), { quiescent: true });
});

test("createQuiescenceProbe non-zero counts fail assertQuiescent WORKSPACE_BUSY", async () => {
  const probe = createQuiescenceProbe({ pendingInvokes: 2, pendingSessions: 0 });
  const counts = await probe();
  assert.throws(
    () => assertQuiescent(counts),
    (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_BUSY
  );
});

test("createQuiescenceProbe resolves sync and async getter functions", async () => {
  const probe = createQuiescenceProbe({
    pendingInvokes: () => 3,
    pendingSessions: async () => 4,
  });
  assert.deepEqual(await probe(), { pendingInvokes: 3, pendingSessions: 4 });
});

test("createQuiescenceProbe rejects a malformed resolved value with QUIESCENCE_PROBE_INVALID", async () => {
  for (const bad of [-1, 1.5, Number.NaN]) {
    const probe = createQuiescenceProbe({
      pendingInvokes: bad,
      pendingSessions: 0,
    });
    await assert.rejects(
      () => probe(),
      (error) =>
        error.operation === "workspace_lease_fence" &&
        error.code === "QUIESCENCE_PROBE_INVALID"
    );
  }
  const asyncBadProbe = createQuiescenceProbe({
    pendingInvokes: async () => -5,
    pendingSessions: 0,
  });
  await assert.rejects(
    () => asyncBadProbe(),
    (error) => error.code === "QUIESCENCE_PROBE_INVALID"
  );

  // Getters resolving the canonical false-idle shapes (undefined / Infinity /
  // numeric string) MUST hard-fail at probe time, never coerce to 0 and let a
  // destructive op proceed against a busy workspace. These pass construction
  // (they are functions) so they pin the RESOLVED-value safety boundary.
  for (const badGetter of [() => undefined, () => Infinity, async () => "0"]) {
    const probe = createQuiescenceProbe({
      pendingInvokes: badGetter,
      pendingSessions: 0,
    });
    await assert.rejects(
      () => probe(),
      (error) =>
        error.operation === "workspace_lease_fence" &&
        error.code === "QUIESCENCE_PROBE_INVALID"
    );
  }
});

test("createQuiescenceProbe construction refuses non-object counts or invalid field types", () => {
  for (const bad of [undefined, null, 5, "counts"]) {
    assert.throws(
      () => createQuiescenceProbe(bad),
      (error) =>
        error.operation === "workspace_lease_fence" &&
        error.code === "QUIESCENCE_PROBE_INVALID"
    );
  }
  assert.throws(
    () => createQuiescenceProbe({ pendingInvokes: "0", pendingSessions: 0 }),
    (error) => error.code === "QUIESCENCE_PROBE_INVALID"
  );
  assert.throws(
    () => createQuiescenceProbe({ pendingInvokes: 0, pendingSessions: null }),
    (error) => error.code === "QUIESCENCE_PROBE_INVALID"
  );
});

// --- pre-mortem #3: restore-vs-admission interleaving ----------------------
//
// A restore/migration promotion holds the EXCLUSIVE fence while it runs. This
// proves, at the unit layer and against ONE real registry instance, that a
// concurrent admission attempt via the ordinary (non-exclusive) activity fence
// is refused WORKSPACE_BUSY for the entire duration the exclusive fence is
// held, and is only re-admissible after the exclusive holder releases --
// serializing restore-promotion against concurrent admission.

test("pre-mortem #3: exclusive restore fence serializes against concurrent activity-fence admission", () => {
  const registry = new WorkspaceLeaseRegistry();
  registry.adoptBinding(authority);
  const restoreFence = createExclusiveFence(registry);
  const admissionFence = createActivityFence(registry);

  // Restore promotion acquires the exclusive fence first.
  const restoring = restoreFence(activity());
  assert.equal(restoring.isCurrent(), true);

  // A concurrent admission attempt against the SAME identity while the
  // restore promotion is in flight is refused WORKSPACE_BUSY, not admitted.
  assert.throws(
    () => admissionFence(activity()),
    (error) => error.code === PROTOCOL_ERROR_CODES.WORKSPACE_BUSY
  );

  // The restore promotion completes and releases the exclusive fence.
  restoring.release();

  // Admission now succeeds against the same identity.
  const admitted = admissionFence(activity());
  assert.equal(admitted.isCurrent(), true);
  admitted.release();
});
