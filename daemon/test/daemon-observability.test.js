import assert from "node:assert/strict";
import test from "node:test";

import { AdmissionBudget } from "../src/admission-budget.js";
import {
  DaemonObservability,
  emitOwnerEvent,
  isOpaqueId,
  projectOwnerEvent,
} from "../src/daemon-observability.js";
import { WorkspaceLeaseRegistry } from "../src/workspace-lease-registry.js";
import { SessionPool } from "../src/session-pool.js";

const WORK_DIR = process.platform === "win32" ? String.raw`C:\work` : "/work";
const SECOND_WORK_DIR = process.platform === "win32" ? String.raw`C:\other` : "/other";

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

const OWNER_EVENT_KEYS = [
  "schemaVersion", "name", "action", "outcome", "code", "cleanupState",
  "mappingId", "workspaceId", "transactionId", "fenceSequence", "durationMs",
  "socketGeneration", "readinessRevision", "mappingGeneration",
  "workspaceGeneration",
];

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
  assert.deepEqual(Object.keys(event), OWNER_EVENT_KEYS);
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
  const events = [];
  observability.subscribe((event) => events.push(event));
  const budget = new AdmissionBudget({ maxInFlightInvokes: 1, observer: observability });
  const registry = new WorkspaceLeaseRegistry({ maxWorkspaces: 1, maxActiveWorkspaces: 1, observer: observability });
  const pool = { getObservabilitySnapshot: () => Object.freeze({ activeSessions: 0, pendingSessions: 0, admittedSessionWorkspaces: 0, maxSessions: 1, pendingReceiptRetirementCleanup: 0, failedManagedSessionCleanup: 0 }) };
  observability.attachOwners({ admissionBudget: budget, sessionPool: pool, workspaceLeaseRegistry: registry });
  const release = budget.tryAcquireInvoke();
  assert.equal(budget.tryAcquireInvoke(), undefined);
  assert.deepEqual(
    events.filter((event) => event.name === "admission_budget"),
    [{
      schemaVersion: 1,
      name: "admission_budget",
      action: "invoke_capacity",
      outcome: "denied",
      code: "RESOURCE_EXHAUSTED",
      cleanupState: null,
      mappingId: null,
      workspaceId: null,
      transactionId: null,
      fenceSequence: null,
      durationMs: null,
      socketGeneration: null,
      readinessRevision: null,
      mappingGeneration: null,
      workspaceGeneration: null,
    }],
  );
  const snapshot = observability.getSnapshot();
  assert.equal(snapshot.schemaVersion, 1);
  assert.equal(snapshot.inFlightInvokes, 1);
  assert.equal(snapshot.workspaceAuthorities, 0);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.throws(() => observability.attachOwners({ admissionBudget: budget, sessionPool: pool, workspaceLeaseRegistry: registry }));
  release();
});

test("object observers receive only projected frozen owner events", () => {
  const received = [];
  const observer = {
    emitOwnerEvent(event) {
      received.push(event);
    },
  };
  emitOwnerEvent(observer, {
    name: "admission_budget",
    action: "invoke_capacity",
    outcome: "denied",
    code: "RESOURCE_EXHAUSTED",
  });
  assert.equal(received.length, 1);
  assert.equal(Object.isFrozen(received[0]), true);
  assert.deepEqual(Object.keys(received[0]), OWNER_EVENT_KEYS);
  emitOwnerEvent(observer, {
    name: "admission_budget",
    action: "invoke_capacity",
    outcome: "denied",
    path: "/secret",
  });
  assert.equal(received.length, 1);
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

test("lease authority retention capacity denial is projected exactly once", () => {
  const events = [];
  const registry = new WorkspaceLeaseRegistry({
    maxWorkspaces: 1,
    observer: (event) => events.push(event),
  });
  assert.equal(registry.adoptBinding(authority("workspace-a")), true);
  const denied = authority("workspace-b");
  denied.mappingId = "mapping-b";
  assert.equal(registry.adoptBinding(denied), false);
  const denials = events.filter(
    (event) =>
      event.action === "adopt" &&
      event.outcome === "denied" &&
      event.code === "WORKSPACE_ADMISSION_EXCEEDED",
  );
  assert.equal(denials.length, 1);
  assert.equal(denials[0].workspaceId, "workspace-b");
  assert.equal(denials[0].mappingId, "mapping-b");
});

test("owner constructors reject invalid observers before mutation", () => {
  const invalidObserver = { emitOwnerEvent: "not a function" };
  assert.throws(() => new AdmissionBudget({ observer: invalidObserver }), TypeError);
  assert.throws(
    () => new WorkspaceLeaseRegistry({ observer: invalidObserver }),
    TypeError,
  );
  let intervals = 0;
  assert.throws(
    () => new SessionPool({
      observer: invalidObserver,
      setIntervalFn: () => {
        intervals += 1;
        return {};
      },
    }),
    TypeError,
  );
  assert.equal(intervals, 0);
  assert.doesNotThrow(() => new AdmissionBudget({ observer: null }));
  assert.doesNotThrow(
    () => new WorkspaceLeaseRegistry({ observer: () => {} }),
  );
});

test("opaque owner IDs allow 128 characters and reject paths and controls", () => {
  const id128 = `a${"x".repeat(127)}`;
  assert.equal(isOpaqueId(id128), true);
  for (const invalid of [
    "x".repeat(129),
    "/secret",
    String.raw`C:\secret`,
    "workspace\nnext",
  ]) {
    assert.equal(isOpaqueId(invalid), false);
    assert.throws(() => projectOwnerEvent({
      name: "admission_budget",
      action: "invoke_capacity",
      outcome: "denied",
      workspaceId: invalid,
    }));
  }
  const events = [];
  const registry = new WorkspaceLeaseRegistry({
    observer: (event) => events.push(event),
  });
  assert.equal(registry.adoptBinding(authority(id128)), true);
  const unsafe = authority("/secret");
  unsafe.mappingId = String.raw`C:\mapping`;
  assert.equal(registry.adoptBinding(unsafe), true);
  const event = events.at(-1);
  assert.equal(event.workspaceId, null);
  assert.equal(event.mappingId, null);
});

test("owner snapshots reject reserved and cross-owner duplicate keys", () => {
  for (const sessionSnapshot of [
    { inFlightInvokes: 0 },
    { schemaVersion: 2 },
  ]) {
    const observability = new DaemonObservability();
    observability.attachOwners({
      admissionBudget: { snapshot: () => ({ inFlightInvokes: 0 }) },
      sessionPool: { getObservabilitySnapshot: () => sessionSnapshot },
      workspaceLeaseRegistry: { getAdmissionSnapshot: () => ({}) },
    });
    assert.throws(
      () => observability.getSnapshot(),
      { message: "observability owner snapshots contain duplicate keys" },
    );
  }
});

test("session pool emits one settled create failure and session-limit denial", async () => {
  const failureEvents = [];
  const failingPool = createPool({
    observer: (event) => failureEvents.push(event),
    sessionFactory: () => Promise.reject(new Error("raw failure")),
  });
  try {
    await assert.rejects(failingPool.ensureSession(WORK_DIR));
    assert.equal(
      failureEvents.filter((event) => event.action === "create" && event.outcome === "started").length,
      1,
    );
    assert.equal(
      failureEvents.filter((event) => event.action === "create" && event.outcome === "settled").length,
      1,
    );
  } finally {
    await failingPool.shutdown();
  }

  const events = [];
  const pool = createPool({
    maxSessions: 1,
    observer: (event) => events.push(event),
    realpathSyncFn: (workDir) => workDir,
    sessionFactory: () => ({ closed: false, dispose: async () => {} }),
  });
  try {
    await pool.ensureSession(WORK_DIR);
    await assert.rejects(
      pool.ensureSession(SECOND_WORK_DIR),
      (error) => error?.code === "SESSION_LIMIT",
    );
    assert.equal(
      events.filter(
        (event) => event.action === "create" && event.code === "SESSION_LIMIT",
      ).length,
      1,
    );
  } finally {
    await pool.shutdown();
  }
});

test("receipt retirement cleanup emits fulfilled and rejected terminals", async () => {
  for (const [dispose, expectedState] of [
    [async () => {}, "fulfilled"],
    [async () => { throw new Error("raw disposal failure"); }, "rejected"],
  ]) {
    const events = [];
    const pool = createPool({
      observer: (event) => events.push(event),
      sessionFactory: () => ({ closed: false, dispose }),
    });
    try {
      await pool.ensureSession(WORK_DIR, { receiptIdentity: receiptIdentity() });
      if (expectedState === "fulfilled") {
        await pool.retireManagedReceipt(WORK_DIR, receiptIdentity());
      } else {
        await assert.rejects(
          pool.retireManagedReceipt(WORK_DIR, receiptIdentity()),
          (error) => error?.code === "LEASE_CONFLICT",
        );
      }
      const cleanup = events.filter(
        (event) => event.action === "managed_cleanup",
      );
      assert.equal(cleanup.filter((event) => event.outcome === "started").length, 1);
      assert.deepEqual(
        cleanup.filter((event) => event.outcome === "settled").map(
          (event) => event.cleanupState,
        ),
        [expectedState],
      );
    } finally {
      await pool.shutdown();
    }
  }
});

test("lease registry emits authority, active-capacity, retire, and busy denials", () => {
  const events = [];
  const registry = new WorkspaceLeaseRegistry({
    maxActiveWorkspaces: 1,
    observer: (event) => events.push(event),
  });
  const first = authority("first");
  const second = authority("second");
  assert.throws(
    () => registry.acquireActivity(first),
    (error) => error?.code === "LEASE_CONFLICT",
  );
  assert.equal(registry.adoptBinding(first), true);
  assert.equal(registry.adoptBinding(second), true);
  const firstLease = registry.acquireActivity(first);
  assert.throws(
    () => registry.acquireActivity(second),
    (error) => error?.code === "WORKSPACE_ADMISSION_EXCEEDED",
  );
  firstLease.release();
  assert.equal(registry.retireBinding(first), true);
  assert.equal(registry.retireBinding(first), false);

  const busyEvents = [];
  const busy = new WorkspaceLeaseRegistry({
    observer: (event) => busyEvents.push(event),
  });
  const candidate = authority("busy");
  assert.equal(busy.adoptBinding(candidate), true);
  const exclusive = busy.acquireActivity(candidate, { exclusive: true });
  assert.throws(
    () => busy.acquireActivity(candidate),
    (error) => error?.code === "WORKSPACE_BUSY",
  );
  exclusive.release();
  const shared = busy.acquireActivity(candidate);
  assert.throws(
    () => busy.acquireActivity(candidate, { exclusive: true }),
    (error) => error?.code === "WORKSPACE_BUSY",
  );
  shared.release();

  assert.equal(
    events.filter((event) => event.action === "acquire" && event.code === "LEASE_CONFLICT").length,
    1,
  );
  assert.equal(
    events.filter((event) => event.action === "acquire" && event.code === "WORKSPACE_ADMISSION_EXCEEDED").length,
    1,
  );
  assert.equal(
    events.filter((event) => event.action === "retire" && event.outcome === "succeeded").length,
    1,
  );
  assert.equal(
    events.filter((event) => event.action === "retire" && event.code === "LEASE_CONFLICT").length,
    1,
  );
  assert.equal(
    busyEvents.filter(
      (event) => event.action === "acquire" && event.code === "WORKSPACE_BUSY",
    ).length,
    2,
  );
});
