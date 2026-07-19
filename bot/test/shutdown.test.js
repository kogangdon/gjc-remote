import { test } from "node:test";
import assert from "node:assert/strict";

import { createShutdown } from "../src/shutdown.js";

function makeDeps(overrides = {}) {
  const calls = [];
  const deps = {
    registry: { close: async () => calls.push("registry.close") },
    client: { destroy: async () => calls.push("client.destroy") },
    log: () => {},
    logError: () => {},
    exit: (code) => calls.push(`exit:${code}`),
    ...overrides,
  };
  return { calls, deps };
}

test("shutdown closes the registry before the client and exits 0", async () => {
  const { calls, deps } = makeDeps();
  const shutdown = createShutdown(deps);

  await shutdown("SIGTERM");

  assert.deepEqual(calls, ["registry.close", "client.destroy", "exit:0"]);
});

test("shutdown is idempotent under repeated signals", async () => {
  const { calls, deps } = makeDeps();
  const shutdown = createShutdown(deps);

  await Promise.all([shutdown("SIGINT"), shutdown("SIGTERM")]);
  await shutdown("SIGINT");

  assert.deepEqual(calls, ["registry.close", "client.destroy", "exit:0"]);
});

test("a failing registry close still destroys the client and exits 0", async () => {
  const errors = [];
  const { calls, deps } = makeDeps({
    registry: {
      close: async () => {
        throw new Error("wss stuck");
      },
    },
    logError: (message) => errors.push(message),
  });
  const shutdown = createShutdown(deps);

  await shutdown("SIGTERM");

  assert.deepEqual(calls, ["client.destroy", "exit:0"]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /host registry shutdown failed/);
});

test("a failing client destroy still exits 0", async () => {
  const errors = [];
  const { calls, deps } = makeDeps({
    client: {
      destroy: async () => {
        throw new Error("gateway stuck");
      },
    },
    logError: (message) => errors.push(message),
  });
  const shutdown = createShutdown(deps);

  await shutdown("SIGINT");

  assert.deepEqual(calls, ["registry.close", "exit:0"]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /Discord client shutdown failed/);
});

test("the received signal name is logged", async () => {
  const logs = [];
  const { deps } = makeDeps({ log: (message) => logs.push(message) });
  const shutdown = createShutdown(deps);

  await shutdown("SIGTERM");

  assert.ok(logs.some((line) => line.includes("SIGTERM")));
});

test("a hanging teardown step is abandoned after the timeout and still exits 0", async () => {
  const errors = [];
  const { calls, deps } = makeDeps({
    registry: {
      // Never settles: simulates a wedged wss.close().
      close: () => new Promise(() => {}),
    },
    logError: (message) => errors.push(message),
    timeoutMs: 20,
  });
  const shutdown = createShutdown(deps);

  await shutdown("SIGTERM");

  assert.deepEqual(calls, ["client.destroy", "exit:0"]);
  assert.ok(errors.some((line) => /host registry shutdown timed out/.test(line)));
});
