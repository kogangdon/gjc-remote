import assert from "node:assert/strict";
import { test } from "node:test";
import {
  extractToolCall,
  formatToolLog,
  normalizeToolCall,
  recordToolCall,
  summarizeToolCalls,
  toolCallIdentity,
} from "../src/tool-calls.js";

function streamingEvent(part) {
  return { message: { role: "assistant", content: [part] } };
}

test("normalizeToolCall reads SDK `arguments` when `input` is absent", () => {
  const call = normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: { path: "a.js" } });
  assert.equal(call.name, "read");
  assert.deepEqual(call.input, { path: "a.js" });
  assert.equal(call.label, "a.js");
  assert.equal(call.id, "c1");
});

test("extractToolCall finds a tool call nested in a streaming assistant message", () => {
  const evt = streamingEvent({ type: "toolCall", id: "c1", name: "bash", arguments: { command: "ls" } });
  const call = extractToolCall(evt);
  assert.equal(call.name, "bash");
  assert.deepEqual(call.input, { command: "ls" });
});

test("a later frame with fuller arguments replaces the empty streaming snapshot", () => {
  const toolCalls = [];
  const index = new Map();

  // First frame: tool_use block streams in with empty arguments.
  const empty = normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: {} });
  assert.equal(recordToolCall(toolCalls, index, empty), true);

  // Later frame: same id, arguments now populated.
  const full = normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: { path: "bot/src/bot.js" } });
  assert.equal(recordToolCall(toolCalls, index, full), true);

  assert.equal(toolCalls.length, 1, "the two frames collapse into one entry");
  assert.deepEqual(toolCalls[0].input, { path: "bot/src/bot.js" });
  assert.match(formatToolLog(toolCalls), /bot\/src\/bot\.js/);
  assert.doesNotMatch(formatToolLog(toolCalls), /\{\}/);
});

test("a stale empty frame arriving after the full one does not clobber it", () => {
  const toolCalls = [];
  const index = new Map();

  const full = normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: { path: "x.js" } });
  recordToolCall(toolCalls, index, full);

  const empty = normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: {} });
  assert.equal(recordToolCall(toolCalls, index, empty), false);

  assert.deepEqual(toolCalls[0].input, { path: "x.js" });
});

test("distinct tool-call ids are recorded as separate entries", () => {
  const toolCalls = [];
  const index = new Map();

  recordToolCall(toolCalls, index, normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: { path: "a" } }));
  recordToolCall(toolCalls, index, normalizeToolCall({ type: "toolCall", id: "c2", name: "read", arguments: { path: "b" } }));

  assert.equal(toolCalls.length, 2);
  assert.equal(summarizeToolCalls(toolCalls), "#1 `read` a; #2 `read` b");
});

test("toolCallIdentity is stable by id regardless of argument completeness", () => {
  const empty = normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: {} });
  const full = normalizeToolCall({ type: "toolCall", id: "c1", name: "read", arguments: { path: "a.js" } });
  assert.equal(toolCallIdentity(empty), toolCallIdentity(full));
});

test("formatToolLog omits the JSON block only when input is undefined", () => {
  const withEmpty = formatToolLog([{ name: "read", label: "", input: {} }]);
  assert.match(withEmpty, /```json\n\{\}\n```/);

  const withoutInput = formatToolLog([{ name: "yield", label: "", input: undefined }]);
  assert.doesNotMatch(withoutInput, /```/);
});
