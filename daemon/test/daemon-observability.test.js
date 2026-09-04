import assert from "node:assert/strict";
import test from "node:test";

import { AdmissionBudget } from "../src/admission-budget.js";
import {
  DaemonObservability,
  emitOwnerEvent,
  projectOwnerEvent,
} from "../src/daemon-observability.js";
import { WorkspaceLeaseRegistry } from "../src/workspace-lease-registry.js";
import { SessionPool } from "../src/session-pool.js";

const WORK_DIR = process.platform === "win32" ? String.raw`C:\work` : "/work";

function createPool(overrides = {}) {
  return new SessionPool({
    statSyncFn: () => ({ isDirectory: () => true }),
    realpathSyncFn: () => WORK_DIR,
    reapIntervalMs: 60_000,
    ...overrides,
  });
}

function receiptIdentity() {
  return {
    socketGeneration: 1,
    bindingId: "binding",
    bindingFingerprint: "a".repeat(64),
  };
}

function authority(workspaceId, generation = 1) {
  return {
    authorityEpoch: generation,
    fenceGeneration: generation,
    hostId: "host",
    mappingId: "mapping",
    mappingGeneration: generation,
    mappingVersion: "v1",
    workspaceId,
    workspaceGeneration: generation,
    sourcePlatform: "test",
    authorityFingerprint: "authority",
    inventoryGeneration: generation,
    inventoryFingerprint: "inventory",
    socketGeneration: generation,
    bindingId: "binding",
    bindingFingerprint: "a".repeat(64),
  };
}

test("owner events are flat, frozen, schema-versioned, and isolate subscribers", () => {
  const observability = new DaemonObservability();
  const events = [];
  observability.subscribe(() => {
    throw new Error("subscriber failure");
  });
  const unsubscribe = observability.subscribe((event) => events.push(event));
  const event = observability.emitOwnerEvent({
    name: "admission_budget",
    action: "invoke_capacity",
    outcome: "denied",
    code: "RESOURCE_EXHAUSTED",
  });
  assert.deepEqual(Object.keys(event), [
    "schemaVersion", "name", "action", "outcome", "code", "cleanupState",
    "mappingId", "workspaceId", "transactionId", "fenceSequence", "durationMs",
  ]);
  assert.equal(Object.isFrozen(event), true);
  assert.equal(events.length, 1);
  unsubscribe();
  observability.emitOwnerEvent({
    name: "admission_budget", action: "invoke_capacity", outcome: "denied",
    code: "RESOURCE_EXHAUSTED",
  });
  assert.equal(events.length, 1);
  assert.throws(() => projectOwnerEvent({ name: "admission_budget", action: "invoke_capacity", outcome: "denied", path: "/secret" }));
  assert.throws(() => projectOwnerEvent({ name: "admission_budget", action: "invoke_capacity", outcome: "denied", code: { message: "error" } }));
  assert.throws(() => projectOwnerEvent({ name: "admission_budget", action: "invoke_capacity", outcome: "denied", workspaceId: "/secret" }));
  assert.throws(() => projectOwnerEvent({ name: "admission_budget", action: "invoke_capacity", outcome: "denied", workspaceId: "x".repeat(129) }));
  assert.throws(() => projectOwnerEvent({ name: "admission_budget", action: "invoke_capacity", outcome: "denied", fenceSequence: Number.MAX_SAFE_INTEGER + 1 }));
  assert.throws(() => emitOwnerEvent({ emit() {} }, {
    name: "admission_budget",
    action: "invoke_capacity",
    outcome: "denied",
  }));
});

test("owner snapshots are authoritative, frozen, and attached once", () => {
  const observability = new DaemonObservability();
  const budget = new AdmissionBudget({ maxInFlightInvokes: 1, observer: observability });
  const registry = new WorkspaceLeaseRegistry({ maxWorkspaces: 1, maxActiveWorkspaces: 1, observer: observability });
  const pool = { getObservabilitySnapshot: () => Object.freeze({ activeSessions: 0, pendingSessions: 0, admittedSessionWorkspaces: 0, maxSessions: 1, pendingReceiptRetirementCleanup: 0, failedManagedSessionCleanup: 0 }) };
  observability.attachOwners({ admissionBudget: budget, sessionPool: pool, workspaceLeaseRegistry: registry });
  const release = budget.tryAcquireInvoke();
  assert.equal(budget.tryAcquireInvoke(), undefined);
  const snapshot = observability.getSnapshot();
  assert.equal(snapshot.schemaVersion, 1);
  assert.equal(snapshot.inFlightInvokes, 1);
  assert.equal(snapshot.workspaceAuthorities, 0);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.throws(() => observability.attachOwners({ admissionBudget: budget, sessionPool: pool, workspaceLeaseRegistry: registry }));
  release();
});

test("registry counts invalidated held activity and emits one idempotent release", () => {
  const events = [];
  const registry = new WorkspaceLeaseRegistry({ observer: (event) => events.push(event) });
  const candidate = authority("workspace");
  assert.equal(registry.adoptBinding(candidate), true);
  const first = registry.acquireActivity(candidate);
  const second = registry.acquireActivity(candidate);
  registry.invalidateAll();
  const invalidations = events.filter(
    (event) => event.action === "invalidate",
  ).length;
  registry.invalidateAll();
  assert.equal(
    events.filter((event) => event.action === "invalidate").length,
    invalidations,
  );
  assert.deepEqual(registry.getAdmissionSnapshot(), {
    workspaceAuthorities: 0,
    activityWorkspaces: 1,
    activityHolders: 2,
    exclusiveActivityWorkspaces: 0,
    invalidatedActivityWorkspaces: 1,
    maxWorkspaceAuthorities: 64,
    maxActiveWorkspaces: 8,
  });
  first.release();
  first.release();
  second.release();
  assert.equal(events.filter((event) => event.action === "release").length, 2);
});

test("session creation joins once and receipt cleanup has one bounded terminal", async () => {
  const events = [];
  let createSession;
  const creation = new Promise((resolve) => {
    createSession = resolve;
  });
  let finishDispose;
  const disposal = new Promise((resolve) => {
    finishDispose = resolve;
  });
  let monotonic = 0;
  const session = {
    closed: false,
    dispose: () => disposal,
  };
  const pool = createPool({
    observer: (event) => events.push(event),
    monotonicNowFn: () => monotonic,
    sessionDisposeTimeoutMs: 5,
    sessionFactory: () => creation,
  });
  try {
    const first = pool.ensureSession(WORK_DIR, {
      receiptIdentity: receiptIdentity(),
    });
    const second = pool.ensureSession(WORK_DIR, {
      receiptIdentity: receiptIdentity(),
    });
    assert.equal(
      events.filter(
        (event) => event.action === "create" && event.outcome === "started",
      ).length,
      1,
    );
    createSession(session);
    assert.strictEqual(await first, session);
    assert.strictEqual(await second, session);
    assert.equal(
      events.filter(
        (event) => event.action === "create" && event.outcome === "settled",
      ).length,
      1,
    );

    monotonic = 10;
    await assert.rejects(
      pool.retireManagedReceipt(WORK_DIR, receiptIdentity()),
      (error) => error?.code === "LEASE_CONFLICT",
    );
    const cleanup = events.filter(
      (event) =>
        event.action === "managed_cleanup" && event.outcome === "settled",
    );
    assert.equal(cleanup.length, 1);
    assert.equal(cleanup[0].cleanupState, "timed_out");
    assert.equal(cleanup[0].durationMs, 0);
    assert.equal(
      pool.getObservabilitySnapshot().pendingReceiptRetirementCleanup,
      1,
    );
    finishDispose();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(
      events.filter(
        (event) =>
          event.action === "managed_cleanup" && event.outcome === "settled",
      ).length,
      1,
    );
    assert.equal(
      pool.getObservabilitySnapshot().pendingReceiptRetirementCleanup,
      0,
    );
  } finally {
    finishDispose();
    await pool.shutdown();
  }
});

test("lease adoption denials and authority-only invalidation emit exact facts", () => {
  const events = [];
  const registry = new WorkspaceLeaseRegistry({
    observer: (event) => events.push(event),
  });
  const first = authority("workspace", 2);
  assert.equal(registry.adoptBinding(first), true);
  assert.equal(registry.adoptBinding(authority("workspace", 1)), false);
  const sameGenerationDifferentAuthority = authority("workspace", 2);
  sameGenerationDifferentAuthority.bindingId = "other";
  assert.equal(
    registry.adoptBinding(sameGenerationDifferentAuthority),
    false,
  );
  registry.invalidateAll();
  assert.equal(
    events.filter(
      (event) =>
        event.action === "adopt" &&
        event.outcome === "denied" &&
        event.code === "LEASE_CONFLICT",
    ).length,
    2,
  );
  const invalidation = events.find(
    (event) => event.action === "invalidate",
  );
  assert.equal(invalidation.workspaceId, "workspace");
  assert.equal(invalidation.fenceSequence, null);
});
