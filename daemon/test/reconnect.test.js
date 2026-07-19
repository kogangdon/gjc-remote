import { test } from "node:test";
import assert from "node:assert/strict";

import {
  RECONNECT_BASE_MS,
  RECONNECT_MAX_MS,
  nextReconnect,
} from "../src/reconnect.js";

test("delay stays within the equal-jitter window and base doubles", () => {
  const low = nextReconnect(RECONNECT_BASE_MS, { random: () => 0 });
  assert.equal(low.delay, RECONNECT_BASE_MS / 2);
  assert.equal(low.nextBase, RECONNECT_BASE_MS * 2);

  const high = nextReconnect(RECONNECT_BASE_MS, { random: () => 1 });
  assert.equal(high.delay, RECONNECT_BASE_MS);
  assert.equal(high.nextBase, RECONNECT_BASE_MS * 2);

  const mid = nextReconnect(RECONNECT_BASE_MS, { random: () => 0.5 });
  assert.equal(mid.delay, Math.round(RECONNECT_BASE_MS * 0.75));
});

test("nextBase is clamped to the maximum and never overflows", () => {
  const near = nextReconnect(20_000);
  assert.equal(near.nextBase, RECONNECT_MAX_MS);

  const atMax = nextReconnect(RECONNECT_MAX_MS);
  assert.equal(atMax.nextBase, RECONNECT_MAX_MS);
  // Even an absurdly large base (e.g. a corrupted carry-over) stays clamped and
  // never doubles past the ceiling.
  const huge = nextReconnect(Number.MAX_SAFE_INTEGER);
  assert.equal(huge.nextBase, RECONNECT_MAX_MS);
  assert.ok(huge.nextBase <= RECONNECT_MAX_MS);
});

test("random draws across the unit interval keep delay in [base/2, base]", () => {
  const base = 8000;
  for (const r of [0, 0.13, 0.37, 0.5, 0.71, 0.99, 1]) {
    const { delay } = nextReconnect(base, { random: () => r });
    assert.ok(
      delay >= base / 2 && delay <= base,
      `delay ${delay} out of [${base / 2}, ${base}] for random ${r}`
    );
  }
});

test("jitter actually spreads consecutive draws (no synchronized herd)", () => {
  const base = 16_000;
  const values = new Set();
  const seq = [0.05, 0.2, 0.45, 0.6, 0.8, 0.95];
  let i = 0;
  for (let n = 0; n < seq.length; n++) {
    const { delay } = nextReconnect(base, { random: () => seq[i++] });
    values.add(delay);
  }
  assert.ok(values.size > 1, "expected distinct jittered delays");
});
