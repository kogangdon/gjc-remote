import test from "node:test";
import assert from "node:assert/strict";
import { resolveModel, validateModelList } from "../src/model-lookup.js";
import { setSessionModel } from "../src/model-command.js";

const MODELS = [
  { provider: "anthropic", id: "claude-haiku", name: "Claude Haiku (latest)" },
  { provider: "anthropic", id: "claude-haiku-20260101", name: "Claude Haiku" },
  { provider: "openrouter", id: "claude-haiku", name: "Claude Haiku" },
  { provider: "openai", id: "gpt-5", name: "GPT 5" },
];

test("qualified query resolves the exact provider and model id", () => {
  assert.deepEqual(resolveModel(MODELS, "openrouter:claude-haiku"), {
    status: "resolved",
    provider: "openrouter",
    modelId: "claude-haiku",
    name: "Claude Haiku",
  });
});

test("unqualified exact id resolves only when unique", () => {
  assert.deepEqual(resolveModel(MODELS, "gpt-5"), {
    status: "resolved",
    provider: "openai",
    modelId: "gpt-5",
    name: "GPT 5",
  });
});

test("fuzzy query resolves a uniquely top-ranked latest model", () => {
  const models = MODELS.filter((model) => model.provider === "anthropic");
  assert.deepEqual(resolveModel(models, "haiku"), {
    status: "resolved",
    provider: "anthropic",
    modelId: "claude-haiku",
    name: "Claude Haiku (latest)",
  });
});

test("not-found query has an explicit outcome", () => {
  assert.deepEqual(resolveModel(MODELS, "does-not-exist"), { status: "not_found" });
});

test("cross-provider exact id is ambiguous and deterministic", () => {
  assert.deepEqual(resolveModel(MODELS, "claude-haiku"), {
    status: "ambiguous",
    candidates: [
      { provider: "anthropic", id: "claude-haiku", name: "Claude Haiku (latest)" },
      { provider: "openrouter", id: "claude-haiku", name: "Claude Haiku" },
    ],
  });
});

test("equal fuzzy ranks are ambiguous rather than selected by list order", () => {
  const models = [
    { provider: "zeta", id: "model-aa", name: "Shared" },
    { provider: "alpha", id: "model-bb", name: "Shared" },
  ];
  assert.deepEqual(resolveModel(models, "shared"), {
    status: "ambiguous",
    candidates: [models[1], models[0]],
  });
});

test("malformed model lists fail with a generic error", () => {
  const rawPayload = "RAW_PAYLOAD_MUST_NOT_ESCAPE";
  assert.throws(
    () => validateModelList([{ provider: "openai", id: "gpt-5", name: rawPayload.repeat(30) }]),
    (error) => error.message === "Available model list is invalid." && !error.message.includes(rawPayload)
  );
  assert.throws(() => validateModelList({ models: MODELS }), /Available model list is invalid\./);
  for (const models of [
    [{ provider: " openai", id: "gpt-5", name: "GPT 5" }],
    [{ provider: "openai", id: "gpt-\u00005", name: "GPT 5" }],
    Array.from({ length: 1_001 }, (_, index) => ({
      provider: "provider",
      id: `model-${index}`,
      name: `Model ${index}`,
    })),
  ]) {
    assert.throws(() => validateModelList(models), /Available model list is invalid\./);
  }
});

test("duplicate provider and id identity is rejected case-insensitively", () => {
  assert.throws(
    () =>
      validateModelList([
        { provider: "OpenAI", id: "GPT-5", name: "First" },
        { provider: "openai", id: "gpt-5", name: "Second" },
      ]),
    /Available model list is invalid\./
  );
});

test("setSessionModel sends the exact set_model payload and receipt after success", async () => {
  const commands = [];
  const order = [];
  const receipts = [];
  const session = {
    async send(command, onEvent) {
      commands.push(command);
      if (command.type === "get_available_models") {
        onEvent({ command: "get_available_models", data: { models: MODELS } });
        onEvent({ type: "response", command: "get_available_models", success: true });
        return;
      }
      onEvent({ type: "response", command: "set_model", success: true });
      order.push("set-resolved");
    },
  };

  await setSessionModel(session, { modelName: "openai:gpt-5" }, (event) => {
    if (event.type === "model_resolved") {
      receipts.push(event);
      order.push("receipt");
    }
  });

  assert.deepEqual(commands, [
    { type: "get_available_models" },
    { type: "set_model", provider: "openai", modelId: "gpt-5" },
  ]);
  assert.deepEqual(order, ["set-resolved", "receipt"]);
  assert.deepEqual(receipts, [
    { type: "model_resolved", name: "GPT 5", provider: "openai", modelId: "gpt-5" },
  ]);
});

test("setSessionModel emits no success receipt when set_model fails", async () => {
  const events = [];
  const session = {
    async send(command, onEvent) {
      if (command.type === "get_available_models") {
        onEvent({ command: "get_available_models", data: { models: MODELS } });
        return;
      }
      throw new Error("raw provider failure");
    },
  };

  await assert.rejects(
    setSessionModel(session, { modelName: "openai:gpt-5" }, (event) => events.push(event)),
    { message: "Could not set the selected model." }
  );
  assert.deepEqual(events, []);
});

test("ambiguous errors are sanitized, deterministic, and capped at five candidates", async () => {
  const models = Array.from({ length: 8 }, (_, index) => ({
    provider: `p@${index}`,
    id: `unsafe${index}`,
    name: `Target @everyone ${index} \`RAW\``,
  }));
  const session = listOnlySession(models);

  await assert.rejects(
    setSessionModel(session, { modelName: "target" }, () => {}),
    (error) => {
      assert.ok(error.message.startsWith("Model selection is ambiguous. Use provider:modelId."));
      assert.equal(error.message.includes("@everyone"), false);
      assert.equal(error.message.includes("`RAW`"), false);
      assert.equal(error.message.split("\n").length, 6);
      assert.ok(error.message.length < 1500);
      return true;
    }
  );
});

test("not-found and malformed-list errors do not echo unsafe query or payload text", async () => {
  const unsafeQuery = `@everyone\n${"Q".repeat(2000)}`;
  await assert.rejects(
    setSessionModel(listOnlySession(MODELS), { modelName: unsafeQuery }, () => {}),
    (error) => error.message.length < 200 && !error.message.includes("@everyone")
  );

  const rawPayload = "PRIVATE_MODEL_PAYLOAD";
  await assert.rejects(
    setSessionModel(listOnlySession([{ id: rawPayload }]), { modelName: "x" }, () => {}),
    (error) => error.message.length < 200 && !error.message.includes(rawPayload)
  );
});

function listOnlySession(models) {
  return {
    async send(command, onEvent) {
      assert.equal(command.type, "get_available_models");
      onEvent({ command: "get_available_models", data: { models } });
    },
  };
}
