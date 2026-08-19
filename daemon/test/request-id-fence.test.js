import assert from "node:assert/strict";
import test from "node:test";
import { RequestIdFence } from "../src/request-id-fence.js";

test("request IDs are exclusive until their owner releases", () => {
  const fence = new RequestIdFence();
  const release = fence.tryAcquire("request-1");

  assert.equal(typeof release, "function");
  assert.equal(fence.has("request-1"), true);
  assert.equal(fence.size, 1);
  assert.equal(fence.tryAcquire("request-1"), undefined);

  release();
  assert.equal(fence.has("request-1"), false);
  assert.equal(fence.size, 0);
});

test("different request IDs remain independently admissible", () => {
  const fence = new RequestIdFence();
  const releaseFirst = fence.tryAcquire("request-1");
  const releaseSecond = fence.tryAcquire("request-2");

  assert.equal(typeof releaseFirst, "function");
  assert.equal(typeof releaseSecond, "function");
  assert.equal(fence.size, 2);

  releaseFirst();
  assert.equal(fence.has("request-2"), true);
  releaseSecond();
  assert.equal(fence.size, 0);
});

test("stale and repeated releases cannot clear a successor reservation", () => {
  const fence = new RequestIdFence();
  const releasePrior = fence.tryAcquire("request-1");
  releasePrior();

  const releaseCurrent = fence.tryAcquire("request-1");
  assert.equal(typeof releaseCurrent, "function");
  releasePrior();
  assert.equal(fence.has("request-1"), true);

  releaseCurrent();
  releaseCurrent();
  assert.equal(fence.has("request-1"), false);
});
