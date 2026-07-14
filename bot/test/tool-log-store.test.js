import assert from "node:assert/strict";
import test from "node:test";
import { ToolLogStore } from "../src/tool-log-store.js";

test("tool logs remain available before the TTL and expire at the boundary", () => {
  let now = 1_000;
  const store = new ToolLogStore({ now: () => now, ttlMs: 5_000 });
  const toolCalls = [{ name: "read" }];
  const id = store.add(toolCalls);

  now = 5_999;
  assert.equal(store.get(id)?.toolCalls, toolCalls);

  now = 6_000;
  assert.equal(store.get(id), undefined);
  assert.equal(store.size, 0);
});

test("reading one tool log removes every expired entry", () => {
  let now = 0;
  const store = new ToolLogStore({ now: () => now, ttlMs: 100 });
  const expiredId = store.add([{ name: "old" }]);

  now = 50;
  const liveId = store.add([{ name: "new" }]);

  now = 100;
  assert.equal(store.get(liveId)?.toolCalls[0].name, "new");
  assert.equal(store.get(expiredId), undefined);
  assert.equal(store.size, 1);
});

test("tool log capacity evicts the oldest entries", () => {
  let now = 0;
  const store = new ToolLogStore({ now: () => now++, ttlMs: 10_000, maxEntries: 2 });
  const firstId = store.add([{ name: "first" }]);
  const secondId = store.add([{ name: "second" }]);
  const thirdId = store.add([{ name: "third" }]);

  assert.equal(store.get(firstId), undefined);
  assert.equal(store.get(secondId)?.toolCalls[0].name, "second");
  assert.equal(store.get(thirdId)?.toolCalls[0].name, "third");
  assert.equal(store.size, 2);
});

test("tool log capacity rejects invalid limits", () => {
  for (const maxEntries of [-1, 1.5, Number.POSITIVE_INFINITY]) {
    assert.throws(() => new ToolLogStore({ maxEntries }), /maxEntries must be a non-negative integer/);
  }
});

test("zero tool log capacity discards new entries", () => {
  const store = new ToolLogStore({ maxEntries: 0 });
  const id = store.add([{ name: "discarded" }]);

  assert.equal(store.get(id), undefined);
  assert.equal(store.size, 0);
});

test("tool log store rejects invalid clocks and TTL values", () => {
  assert.throws(() => new ToolLogStore({ now: 0 }), /now must be a function/);

  for (const ttlMs of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => new ToolLogStore({ ttlMs }), /ttlMs must be a non-negative finite number/);
  }
});

test("tool log store rejects non-finite clock results", () => {
  for (const now of [Number.NaN, Number.POSITIVE_INFINITY]) {
    const store = new ToolLogStore({ now: () => now });
    assert.throws(() => store.add([{ name: "read" }]), /now must return a finite number/);
  }

  let now = 0;
  const store = new ToolLogStore({ now: () => now });
  const id = store.add([{ name: "read" }]);

  now = Number.NaN;
  assert.throws(() => store.get(id), /now must return a finite number/);
});
