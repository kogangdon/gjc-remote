import assert from "node:assert/strict";
import test from "node:test";

import {
  AdmissionBudget,
  DEFAULT_MAX_IN_FLIGHT_INVOKES,
} from "../src/admission-budget.js";

test("invoke admission rejects the sixty-fifth request without queueing", () => {
  const budget = new AdmissionBudget();
  const releases = Array.from(
    { length: DEFAULT_MAX_IN_FLIGHT_INVOKES },
    () => budget.tryAcquireInvoke()
  );

  assert.equal(releases.every((release) => typeof release === "function"), true);
  assert.equal(budget.tryAcquireInvoke(), undefined);
  assert.equal(budget.inFlightInvokes, DEFAULT_MAX_IN_FLIGHT_INVOKES);
  assert.deepEqual(budget.snapshot(), {
    inFlightInvokes: DEFAULT_MAX_IN_FLIGHT_INVOKES,
    maxInFlightInvokes: DEFAULT_MAX_IN_FLIGHT_INVOKES,
  });

  releases[0]();
  const replacement = budget.tryAcquireInvoke();
  assert.equal(typeof replacement, "function");
  replacement();
  for (const release of releases.slice(1)) release();
  assert.equal(budget.inFlightInvokes, 0);
  assert.deepEqual(budget.snapshot(), {
    inFlightInvokes: 0,
    maxInFlightInvokes: DEFAULT_MAX_IN_FLIGHT_INVOKES,
  });
});

test("invoke admission releases each reservation at most once", () => {
  const budget = new AdmissionBudget({ maxInFlightInvokes: 1 });
  const release = budget.tryAcquireInvoke();

  release();
  release();

  assert.equal(budget.inFlightInvokes, 0);
  assert.equal(typeof budget.tryAcquireInvoke(), "function");
});

test("invoke admission validates configured bounds", () => {
  assert.throws(
    () => new AdmissionBudget({ maxInFlightInvokes: 0 }),
    /positive safe integer/
  );
  assert.throws(
    () =>
      new AdmissionBudget({
        maxInFlightInvokes: Number.MAX_SAFE_INTEGER + 1,
      }),
    /positive safe integer/
  );
});
