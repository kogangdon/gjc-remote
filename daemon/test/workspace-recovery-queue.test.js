import assert from "node:assert/strict";
import test from "node:test";
import {
  planRecoveryBatches,
  MAX_RECOVERY_BATCH,
  MAX_RECOVERY_TOTAL,
  QUEUE_INVALID,
  ADMISSION_EXCEEDED,
} from "../src/workspace-recovery-queue.js";

const ids = (n, prefix = "ws") => Array.from({ length: n }, (_, i) => `${prefix}-${i}`);

test("fixed ceilings are 8 per batch and 64 total", () => {
  assert.equal(MAX_RECOVERY_BATCH, 8);
  assert.equal(MAX_RECOVERY_TOTAL, 64);
});

test("boundary arithmetic: batch counts across the range", () => {
  const cases = [
    [0, 0, []],
    [1, 1, [1]],
    [8, 1, [8]],
    [9, 2, [8, 1]],
    [16, 2, [8, 8]],
    [63, 8, [8, 8, 8, 8, 8, 8, 8, 7]],
    [64, 8, [8, 8, 8, 8, 8, 8, 8, 8]],
  ];
  for (const [n, expectedBatchCount, expectedSizes] of cases) {
    const plan = planRecoveryBatches(ids(n));
    assert.equal(plan.totalAdmitted, n, `total for ${n}`);
    assert.equal(plan.batchCount, expectedBatchCount, `batchCount for ${n}`);
    assert.deepEqual(plan.batches.map((b) => b.length), expectedSizes, `sizes for ${n}`);
    // every batch is 1..MAX and the union covers every id exactly once, in order
    const flat = plan.batches.flat();
    assert.deepEqual(flat, ids(n), `coverage/order for ${n}`);
    for (const b of plan.batches) assert.ok(b.length >= 1 && b.length <= MAX_RECOVERY_BATCH);
  }
});

test("exactly at the ceiling (64) admits all; one over (65) refuses ALL progress (zero processed)", () => {
  const atCeiling = planRecoveryBatches(ids(MAX_RECOVERY_TOTAL));
  assert.equal(atCeiling.totalAdmitted, 64);

  let error;
  try {
    planRecoveryBatches(ids(MAX_RECOVERY_TOTAL + 1));
    assert.fail("expected WORKSPACE_ADMISSION_EXCEEDED");
  } catch (e) {
    error = e;
  }
  assert.equal(error.code, ADMISSION_EXCEEDED);
  assert.equal(error.operation, "workspace_recovery_queue");
  // load-bearing: ZERO processed above the ceiling - no partial drain of the first 64
  assert.equal(error.admitted, 0, "zero workspaces processed above the total ceiling");
  assert.equal(error.requested, 65);
  assert.equal(error.ceiling, 64);
});

test("no-unbounded-queue proof: a very large backlog still processes nothing", () => {
  for (const n of [65, 100, 1000, 100000]) {
    assert.throws(() => planRecoveryBatches(ids(n)), (e) => e.code === ADMISSION_EXCEEDED && e.admitted === 0, `n=${n}`);
  }
});

test("returned plan is deeply frozen", () => {
  const plan = planRecoveryBatches(ids(9));
  assert.ok(Object.isFrozen(plan));
  assert.ok(Object.isFrozen(plan.batches));
  for (const b of plan.batches) assert.ok(Object.isFrozen(b));
});

test("input validation: non-array, bad id, and duplicates refuse with the local literal", () => {
  assert.throws(() => planRecoveryBatches(null), (e) => e.code === QUEUE_INVALID);
  assert.throws(() => planRecoveryBatches("ws"), (e) => e.code === QUEUE_INVALID);
  assert.throws(() => planRecoveryBatches(["ok", ""]), (e) => e.code === QUEUE_INVALID);
  assert.throws(() => planRecoveryBatches(["ok", 42]), (e) => e.code === QUEUE_INVALID);
  assert.throws(() => planRecoveryBatches(["dup", "dup"]), (e) => e.code === QUEUE_INVALID && /duplicate/.test(e.reason));
});
