import assert from "node:assert/strict";
import test from "node:test";
import { basename, dirname, join } from "node:path";
import { watchConfigFile } from "../src/config-watcher.js";

function createHarness() {
  const harness = {
    clearCalls: [],
    closeCalls: 0,
    timers: [],
  };

  harness.watchFn = (directory, options, callback) => {
    harness.directory = directory;
    harness.watchOptions = options;
    harness.callback = callback;
    return {
      close() {
        harness.closeCalls++;
      },
    };
  };
  harness.setTimeoutFn = (callback, delay) => {
    const timer = { callback, delay };
    harness.timers.push(timer);
    return timer;
  };
  harness.clearTimeoutFn = (timer) => {
    harness.clearCalls.push(timer);
  };

  return harness;
}

function start(filePath, onChange, harness, options = {}) {
  return watchConfigFile(filePath, onChange, {
    watchFn: harness.watchFn,
    setTimeoutFn: harness.setTimeoutFn,
    clearTimeoutFn: harness.clearTimeoutFn,
    ...options,
  });
}

test("watches the containing directory with non-persistent watching", () => {
  const filePath = join("config", "nested", "channels.json");
  const harness = createHarness();

  start(filePath, () => {}, harness);

  assert.equal(harness.directory, dirname(filePath));
  assert.deepEqual(harness.watchOptions, { persistent: false });

  harness.callback("change", basename(filePath));
  assert.equal(harness.timers.length, 1);
  assert.equal(harness.timers[0].delay, 250);
});

test("ignores events for unrelated filenames", () => {
  const filePath = join("config", "channels.json");
  const harness = createHarness();

  start(filePath, () => {}, harness);
  harness.callback("rename", "other.json");
  harness.callback("change", Buffer.from("other.json"));

  assert.equal(harness.timers.length, 0);
});

test("accepts string, Buffer, null, and undefined target filenames", () => {
  const filePath = join("config", "channels.json");
  const target = basename(filePath);
  const harness = createHarness();

  start(filePath, () => {}, harness);
  harness.callback("rename", target);
  harness.callback("rename", Buffer.from(target));
  harness.callback("rename", null);
  harness.callback("rename", undefined);

  assert.equal(harness.timers.length, 4);
  assert.deepEqual(harness.clearCalls, harness.timers.slice(0, 3));
});

test("restarts the debounce timer and invokes onChange once with no arguments", () => {
  const filePath = join("config", "channels.json");
  const target = basename(filePath);
  const harness = createHarness();
  const calls = [];

  start(filePath, (...args) => calls.push(args), harness, { delayMs: 40 });
  harness.callback("change", target);
  const firstTimer = harness.timers[0];
  harness.callback("rename", target);
  const secondTimer = harness.timers[1];

  assert.deepEqual(harness.clearCalls, [firstTimer]);
  assert.equal(secondTimer.delay, 40);

  secondTimer.callback();
  assert.deepEqual(calls, [[]]);
});

test("close is idempotent, clears pending work, and blocks late callbacks", () => {
  const filePath = join("config", "channels.json");
  const target = basename(filePath);
  const harness = createHarness();
  let changeCalls = 0;
  const handle = start(filePath, () => changeCalls++, harness);

  harness.callback("change", target);
  const pendingTimer = harness.timers[0];
  handle.close();
  handle.close();

  assert.deepEqual(harness.clearCalls, [pendingTimer]);
  assert.equal(harness.closeCalls, 1);

  pendingTimer.callback();
  harness.callback("rename", target);
  harness.callback("rename", null);

  assert.equal(changeCalls, 0);
  assert.equal(harness.timers.length, 1);
  assert.equal(harness.closeCalls, 1);
});
