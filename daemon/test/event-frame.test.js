import assert from "node:assert/strict";
import test from "node:test";

import { serializeEventFrame } from "../src/event-frame.js";

test("oversized event becomes a bounded diagnostic frame", () => {
  const serialized = serializeEventFrame(
    "request-1",
    { type: "tool_result", output: "x".repeat(10_000) },
    { done: true, error: "bounded error" },
    512
  );
  assert.equal(Buffer.byteLength(serialized) <= 512, true);

  const frame = JSON.parse(serialized);
  assert.equal(frame.type, "event");
  assert.equal(frame.requestId, "request-1");
  assert.deepEqual(frame.event, {
    type: "event_truncated",
    code: "EVENT_PAYLOAD_TOO_LARGE",
    originalType: "tool_result",
  });
  assert.equal(frame.done, true);
  assert.equal(frame.error, "bounded error");
});

test("normal event preserves its envelope", () => {
  const serialized = serializeEventFrame(
    "request-2",
    { type: "assistant", text: "hello" },
    { done: false },
    512
  );
  assert.deepEqual(JSON.parse(serialized), {
    type: "event",
    requestId: "request-2",
    event: { type: "assistant", text: "hello" },
    done: false,
  });
});
