import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import {
  parseSmokeHeartbeatTimeout,
  waitForHost,
  waitForRegisteredHeartbeatPong,
  waitForTelemetry,
} from "../local-smoke-heartbeat.js";

test("heartbeat timeout defaults and accepts its exact bounds", () => {
  assert.equal(parseSmokeHeartbeatTimeout(undefined), 30_000);
  assert.equal(parseSmokeHeartbeatTimeout("1000"), 1_000);
  assert.equal(parseSmokeHeartbeatTimeout("120000"), 120_000);
});

test("heartbeat timeout rejects invalid environment values", () => {
  for (const value of [
    "",
    " ",
    "NaN",
    "999",
    "120001",
    "1000.5",
    "1e3",
    "1e309",
    "9007199254740992",
    "9".repeat(400),
  ]) {
    assert.throws(
      () => parseSmokeHeartbeatTimeout(value),
      /SMOKE_HEARTBEAT_TIMEOUT_MS must be a base-10 integer from 1000 to 120000/,
      value,
    );
  }
});

test("heartbeat proof accepts a pong from the currently registered connection", async () => {
  const clock = createManualClock();
  const socket = new EventEmitter();
  const registry = fakeRegistry(socket);
  const proof = waitForRegisteredHeartbeatPong(
    registry,
    "host-a",
    1_000,
    clock.options,
  );

  socket.emit("message", Buffer.from(JSON.stringify({ type: "pong" })), false);

  assert.equal(await proof, socket);
  assert.equal(clock.pendingTimers, 0);
});

test("heartbeat proof rejects disconnect before pong", async () => {
  const clock = createManualClock();
  const socket = new EventEmitter();
  const registry = fakeRegistry(socket);
  const rejection = assert.rejects(
    waitForRegisteredHeartbeatPong(
      registry,
      "host-a",
      1_000,
      clock.options,
    ),
    /host 'host-a' disconnected before returning an application-level pong/,
  );

  registry.connections.delete("host-a");
  socket.emit("close");

  await rejection;
  assert.equal(clock.pendingTimers, 0);
});

test("heartbeat proof rejects a pong from a replaced connection", async () => {
  const clock = createManualClock();
  const predecessor = new EventEmitter();
  const registry = fakeRegistry(predecessor);
  const rejection = assert.rejects(
    waitForRegisteredHeartbeatPong(
      registry,
      "host-a",
      1_000,
      clock.options,
    ),
    /host 'host-a' connection changed before returning an application-level pong/,
  );

  registry.connections.set("host-a", new EventEmitter());
  predecessor.emit(
    "message",
    Buffer.from(JSON.stringify({ type: "pong" })),
    false,
  );

  await rejection;
  assert.equal(clock.pendingTimers, 0);
});

test("heartbeat proof fails explicitly at its monotonic deadline", async () => {
  const clock = createManualClock();
  const registry = fakeRegistry(new EventEmitter());
  const rejection = assert.rejects(
    waitForRegisteredHeartbeatPong(
      registry,
      "host-a",
      1_000,
      clock.options,
    ),
    /host 'host-a' did not return an application-level pong within 1000ms/,
  );

  clock.advance(1_000);

  await rejection;
  assert.equal(clock.pendingTimers, 0);
});

test("host startup wait has its own bounded monotonic deadline", async () => {
  let now = 0;
  const waits = [];
  const registry = {
    isOnline: () => false,
  };

  await assert.rejects(
    waitForHost(registry, "host-a", 250, {
      now: () => now,
      wait: async (delay) => {
        waits.push(delay);
        now += delay;
      },
    }),
    /host 'host-a' did not connect within 250ms/,
  );
  assert.deepEqual(waits, [100, 100, 50]);
});

test("telemetry wait accepts the requested event count before its deadline", async () => {
  let now = 0;
  const events = [];
  const matchingEvent = { outcome: "succeeded" };

  await waitForTelemetry(
    events,
    (event) => event.outcome === "succeeded",
    1,
    100,
    {
      now: () => now,
      wait: async (delay) => {
        now += delay;
        events.push(matchingEvent);
      },
    },
  );

  assert.equal(now, 10);
});

test("telemetry wait rejects events observed at or after its deadline", async () => {
  for (const observedAt of [100, 101]) {
    let now = 0;
    const events = [];

    await assert.rejects(
      waitForTelemetry(
        events,
        (event) => event.outcome === "succeeded",
        1,
        100,
        {
          now: () => now,
          wait: async () => {
            now = observedAt;
            events.push({ outcome: "succeeded" });
          },
        },
      ),
      /expected 1 matching daemon telemetry events within 100ms/,
    );
  }
});

test("telemetry wait counts only predicate matches toward the requested count", async () => {
  let now = 0;
  let waitCount = 0;
  const events = [{ outcome: "succeeded" }];

  await waitForTelemetry(
    events,
    (event) => event.outcome === "succeeded",
    2,
    100,
    {
      now: () => now,
      wait: async (delay) => {
        now += delay;
        waitCount += 1;
        events.push({
          outcome: waitCount === 1 ? "failed" : "succeeded",
        });
      },
    },
  );

  assert.equal(waitCount, 2);
  assert.equal(events.length, 3);
});

test("telemetry wait fails when a timer callback runs after the deadline", async () => {
  let now = 0;
  const events = [];
  const waits = [];

  await assert.rejects(
    waitForTelemetry(
      events,
      (event) => event.outcome === "succeeded",
      1,
      100,
      {
        now: () => now,
        wait: async (delay) => {
          waits.push(delay);
          now = 150;
          events.push({ outcome: "succeeded" });
        },
      },
    ),
    /expected 1 matching daemon telemetry events within 100ms/,
  );
  assert.deepEqual(waits, [10]);
});

function fakeRegistry(socket) {
  return {
    connections: new Map([["host-a", socket]]),
    isOnline(hostId) {
      return this.connections.has(hostId);
    },
  };
}

function createManualClock() {
  let now = 0;
  const timers = new Set();

  const clock = {
    options: {
      now: () => now,
      setTimeoutFn(callback, delay) {
        const timer = { callback, dueAt: now + delay };
        timers.add(timer);
        return timer;
      },
      clearTimeoutFn(timer) {
        timers.delete(timer);
      },
    },
    advance(delay) {
      now += delay;
      for (const timer of [...timers]) {
        if (timer.dueAt > now) continue;
        timers.delete(timer);
        timer.callback();
      }
    },
    get pendingTimers() {
      return timers.size;
    },
  };
  return clock;
}
