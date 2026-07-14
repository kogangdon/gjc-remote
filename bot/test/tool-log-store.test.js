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
