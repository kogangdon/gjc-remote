import { test } from "node:test";
import assert from "node:assert/strict";

import {
  RECONNECT_BASE_MS,
  RECONNECT_MAX_MS,
  REGISTER_DENIED_RETRY_MS,
  REGISTER_DENIED_RETRY_DEFAULT_MS,
  REGISTER_DENIED_RETRY_MIN_MS,
  SHUTDOWN_TIMEOUT_DEFAULT_MS,
  SHUTDOWN_TIMEOUT_MIN_MS,
  TIMER_MAX_MS,
  nextReconnect,
  parseRegisterDeniedRetryMs,
  parseShutdownTimeoutMs,
  createReconnectScheduler,
  sanitizeErrorMessage,
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
  const huge = nextReconnect(Number.MAX_SAFE_INTEGER, { random: () => 1 });
  assert.equal(huge.nextBase, RECONNECT_MAX_MS);
  assert.ok(huge.nextBase <= RECONNECT_MAX_MS);
  // The drawn delay itself is clamped by max, not just the carried base.
  assert.ok(huge.delay <= RECONNECT_MAX_MS);
  assert.equal(huge.delay, RECONNECT_MAX_MS);
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

test("registration-denied retry defaults to a bounded fixed delay", () => {
  const retryMs = parseRegisterDeniedRetryMs(undefined);
  assert.equal(retryMs, REGISTER_DENIED_RETRY_MS);
  assert.equal(retryMs, REGISTER_DENIED_RETRY_DEFAULT_MS);
  assert.ok(retryMs > RECONNECT_MAX_MS);
  assert.ok(retryMs >= REGISTER_DENIED_RETRY_MIN_MS);
  assert.ok(retryMs <= TIMER_MAX_MS);
  // Unlike normal reconnects, a denied registration does not carry an
  // exponential base or jitter into the next attempt.
  assert.equal(parseRegisterDeniedRetryMs(retryMs), retryMs);
});

test("registration-denied retry rejects hot-loop and unsafe configuration", () => {
  for (const value of [
    "",
    "not-a-number",
    "NaN",
    "Infinity",
    "-Infinity",
    "-1",
    "0",
    REGISTER_DENIED_RETRY_MIN_MS - 1,
    1.5,
    Number.MAX_SAFE_INTEGER,
    TIMER_MAX_MS + 1,
  ]) {
    assert.throws(() => parseRegisterDeniedRetryMs(value), {
      name: "RangeError",
    });
  }
});

test("registration-denied retry accepts the safe timer bounds", () => {
  assert.equal(
    parseRegisterDeniedRetryMs(String(REGISTER_DENIED_RETRY_MIN_MS)),
    REGISTER_DENIED_RETRY_MIN_MS
  );
  assert.equal(parseRegisterDeniedRetryMs(String(TIMER_MAX_MS)), TIMER_MAX_MS);
});

test("shutdown timeout defaults to fifteen seconds within the timer bounds", () => {
  const timeoutMs = parseShutdownTimeoutMs(undefined);
  assert.equal(timeoutMs, SHUTDOWN_TIMEOUT_DEFAULT_MS);
  assert.equal(timeoutMs, 15_000);
  assert.ok(timeoutMs >= SHUTDOWN_TIMEOUT_MIN_MS);
  assert.ok(timeoutMs <= TIMER_MAX_MS);
});

test("shutdown timeout rejects hot-loop and unsafe configuration", () => {
  for (const value of [
    "",
    "not-a-number",
    "NaN",
    "Infinity",
    "-Infinity",
    "-1",
    "0",
    SHUTDOWN_TIMEOUT_MIN_MS - 1,
    1.5,
    Number.MAX_SAFE_INTEGER,
    TIMER_MAX_MS + 1,
  ]) {
    assert.throws(() => parseShutdownTimeoutMs(value), {
      name: "RangeError",
    });
  }
});

test("shutdown timeout accepts the safe timer bounds", () => {
  assert.equal(
    parseShutdownTimeoutMs(String(SHUTDOWN_TIMEOUT_MIN_MS)),
    SHUTDOWN_TIMEOUT_MIN_MS
  );
  assert.equal(parseShutdownTimeoutMs(String(TIMER_MAX_MS)), TIMER_MAX_MS);
});
test("denied retry scheduling is isolated and accepted registration restores normal reconnects", () => {
  const timers = [];
  const cleared = [];
  const logs = [];
  const reconnects = [];
  const scheduler = createReconnectScheduler({
    deniedRetryMs: REGISTER_DENIED_RETRY_MIN_MS,
    onReconnect: () => reconnects.push("connect"),
    logger: (line) => logs.push(line),
    random: () => 0,
    setTimeoutFn: (callback, delay) => {
      const timer = { callback, delay };
      timers.push(timer);
      return timer;
    },
    clearTimeoutFn: (timer) => cleared.push(timer),
  });

  scheduler.markDenied();
  scheduler.scheduleDenied();
  scheduler.onClose({ deniedForConnection: true });
  scheduler.onClose({ deniedForConnection: false });

  assert.equal(timers.length, 1);
  assert.equal(timers[0].delay, REGISTER_DENIED_RETRY_MIN_MS);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /registration denied/);
  assert.equal(scheduler.isDenied(), true);

  scheduler.markAccepted();
  assert.deepEqual(cleared, [timers[0]]);
  assert.equal(scheduler.isDenied(), false);

  scheduler.onClose();
  assert.equal(timers.length, 2);
  assert.equal(timers[1].delay, RECONNECT_BASE_MS / 2);
  assert.match(logs[1], /disconnected from bot/);

  timers[1].callback();
  assert.deepEqual(reconnects, ["connect"]);
});
test("error diagnostics redact secrets, controls, and stacks", () => {
  const token = "host-token";
  const error = new Error(
    `failed ${token} ws://user:password@example.test/path\nstack line`
  );
  const message = sanitizeErrorMessage(error, [token]);

  assert.equal(
    message,
    "failed [redacted] ws://[redacted]@example.test/path stack line"
  );
  assert.equal(message.includes(error.stack), false);
  assert.equal(sanitizeErrorMessage({ stack: "private" }, [token]), "[object Object]");
});
