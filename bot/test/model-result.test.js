import assert from "node:assert/strict";
import test from "node:test";
import {
  formatModelResolvedResult,
  transformModelResult,
  validateModelResolvedEvent,
} from "../src/model-result.js";

const event = {
  type: "model_resolved",
  name: "Claude Sonnet 4",
  provider: "anthropic",
  modelId: "claude-sonnet-4",
};

test("valid model receipt is normalized and formatted with every identity field", () => {
  const receipt = validateModelResolvedEvent(event);

  assert.deepEqual(receipt, {
    name: "Claude Sonnet 4",
    provider: "anthropic",
    modelId: "claude-sonnet-4",
  });
  assert.equal(
    formatModelResolvedResult(receipt),
    "Model switched to `Claude Sonnet 4` (provider: `anthropic`, model ID: `claude-sonnet-4`)."
  );
});

test("control-heavy fields are collapsed and Discord mentions and inline-code delimiters are neutralized", () => {
  const receipt = validateModelResolvedEvent({
    type: "model_resolved",
    name: "  bad\u0000\n\t`name`  ",
    provider: "@everyone\r provider",
    modelId: "<@123>\u200b model",
  });
  const text = formatModelResolvedResult(receipt);

  assert.deepEqual(receipt, {
    name: "bad `name`",
    provider: "@everyone provider",
    modelId: "<@123> model",
  });
  assert.doesNotMatch(text, /[\u0000-\u001f\u007f]/);
  assert.equal(text.includes("@everyone"), false);
  assert.equal(text.includes("<@123>"), false);
  assert.equal(text.includes("`name`"), false);
  assert.match(text, /bad 'name'/);
});

test("display fields and final output remain bounded", () => {
  const receipt = validateModelResolvedEvent({
    type: "model_resolved",
    name: "n".repeat(500),
    provider: "p".repeat(500),
    modelId: "m".repeat(500),
  });
  const text = formatModelResolvedResult(receipt);

  assert.ok(receipt);
  assert.ok(text.length <= 700);
  assert.equal(text.includes("n".repeat(161)), false);
  assert.match(text, /…/);
});

test("malformed model events are rejected", () => {
  const malformed = [
    null,
    {},
    { ...event, type: "assistant" },
    { ...event, name: " \n\t " },
    { ...event, provider: 42 },
    { ...event, modelId: "" },
    { ...event, name: "x".repeat(1025) },
  ];

  for (const candidate of malformed) {
    assert.equal(validateModelResolvedEvent(candidate), undefined);
  }
});

test("successful model result is replaced with explicit receipt text", () => {
  const original = { ok: true, text: "ignored daemon output", requestId: "request-1" };
  const receipt = validateModelResolvedEvent(event);
  const result = transformModelResult({ kind: "set_model" }, original, receipt);

  assert.deepEqual(result, {
    ok: true,
    text: "Model switched to `Claude Sonnet 4` (provider: `anthropic`, model ID: `claude-sonnet-4`).",
    requestId: "request-1",
  });
});

test("successful model result without a valid receipt becomes a safe failure", () => {
  const result = transformModelResult(
    { kind: "set_model" },
    { ok: true, text: "untrusted model payload", requestId: "request-2" },
    undefined
  );

  assert.deepEqual(result, {
    ok: false,
    text: undefined,
    error: "Model switch failed: the host did not return a valid model confirmation.",
    requestId: "request-2",
  });
});

test("daemon model errors are preserved", () => {
  const original = { ok: false, error: "Model query is ambiguous." };

  assert.equal(transformModelResult({ kind: "set_model" }, original, undefined), original);
});

test("non-model results pass through unchanged", () => {
  const original = { ok: true, text: "assistant response" };

  assert.equal(transformModelResult({ kind: "prompt" }, original, validateModelResolvedEvent(event)), original);
});
