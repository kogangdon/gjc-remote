import test from "node:test";
import assert from "node:assert/strict";

import { createReadinessReplayWindow } from "./workspace-readiness-replay-window.js";

function fakeClock(start = 1000) {
  let nowMs = start;
  return {
    now: () => nowMs,
    advance: (deltaMs) => {
      nowMs += deltaMs;
    },
    set: (value) => {
      nowMs = value;
    },
  };
}

test("a fresh fingerprint is unseen, then seen after add", () => {
  const window = createReadinessReplayWindow({ maxAgeMs: 5000, clock: fakeClock() });
  assert.equal(window.has("fp-1"), false);
  window.add("fp-1");
  assert.equal(window.has("fp-1"), true);
});

test("a fingerprint aged past maxAgeMs is evicted and reads as unseen", () => {
  const clock = fakeClock(1000);
  const window = createReadinessReplayWindow({ maxAgeMs: 5000, clock });
  window.add("fp-1");
  clock.advance(4999);
  assert.equal(window.has("fp-1"), true); // still inside the window
  clock.advance(1); // now exactly maxAgeMs old -> evicted
  assert.equal(window.has("fp-1"), false);
});

test("eviction is time-based only: a still-fresh fingerprint is never dropped", () => {
  const clock = fakeClock(1000);
  const window = createReadinessReplayWindow({ maxAgeMs: 10000, clock });
  window.add("fp-old");
  clock.advance(9000);
  window.add("fp-new");
  clock.advance(500);
  assert.equal(window.has("fp-old"), true);
  assert.equal(window.has("fp-new"), true);
});

test("resident size stays bounded as fingerprints age beyond the window", () => {
  const clock = fakeClock(0);
  const maxAgeMs = 1000;
  const window = createReadinessReplayWindow({ maxAgeMs, clock });
  // Add 500 distinct fingerprints, advancing time by half the window each step.
  // At any moment at most ~2 fingerprints are within the window.
  for (let i = 0; i < 500; i += 1) {
    window.add(`fp-${i}`);
    clock.advance(maxAgeMs / 2);
  }
  // Count how many of all 500 are still reported seen: only the last couple
  // can remain fresh. This proves old entries are evicted (bounded memory).
  let stillSeen = 0;
  for (let i = 0; i < 500; i += 1) {
    if (window.has(`fp-${i}`)) stillSeen += 1;
  }
  assert.ok(stillSeen <= 3, `expected <=3 fresh fingerprints, got ${stillSeen}`);
});

test("re-adding a still-fresh fingerprint preserves its original expiry", () => {
  const clock = fakeClock(1000);
  const window = createReadinessReplayWindow({ maxAgeMs: 5000, clock });
  window.add("fp-1");
  clock.advance(3000);
  window.add("fp-1"); // must NOT refresh the expiry
  clock.advance(2000); // original insert now 5000ms old -> evicted
  assert.equal(window.has("fp-1"), false);
});

test("empty / non-string fingerprints fail closed with CONFIG_INVALID", () => {
  const window = createReadinessReplayWindow({ maxAgeMs: 5000, clock: fakeClock() });
  assert.throws(() => window.has(""), (e) => e.code === "CONFIG_INVALID");
  assert.throws(() => window.add(42), (e) => e.code === "CONFIG_INVALID");
});

test("invalid maxAgeMs and clock fail closed with CONFIG_INVALID", () => {
  assert.throws(() => createReadinessReplayWindow({ maxAgeMs: 0 }), (e) => e.code === "CONFIG_INVALID");
  assert.throws(() => createReadinessReplayWindow({ maxAgeMs: 1.5 }), (e) => e.code === "CONFIG_INVALID");
  assert.throws(
    () => createReadinessReplayWindow({ maxAgeMs: 5000, clock: {} }),
    (e) => e.code === "CONFIG_INVALID",
  );
});

test("default clock uses wall time and returns a frozen interface", () => {
  const window = createReadinessReplayWindow({ maxAgeMs: 60000 });
  assert.equal(typeof window.has, "function");
  assert.equal(typeof window.add, "function");
  assert.throws(() => {
    window.extra = 1;
  }, TypeError);
  window.add("fp-live");
  assert.equal(window.has("fp-live"), true);
});
