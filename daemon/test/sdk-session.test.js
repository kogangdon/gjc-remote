import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve } from "node:path";
import test from "node:test";

import {
  SdkSession,
  applyConfiguredModelProfile,
  createSdkSession,
  resolveSdkSessionDirectory,
} from "../src/sdk-session.js";
import { V0_LIMITS, isGateRequestEvent } from "@gjc-remote/shared";

const usage = {
  input: 0,
  output: 1,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 1,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

function assistantMessage(text = "done", overrides = {}) {
  return {
    role: "assistant",
    content: [{ type: "text", text }],
    api: "fake-api",
    provider: "fake-provider",
    model: "fake-model",
    usage,
    stopReason: "stop",
    timestamp: 1,
    ...overrides,
  };
}

// AgentEvent.agent_end in @gajae-code/agent-core 0.16.6 always carries the
// run's messages. Tests use this source-shaped boundary instead of fabricating
// a bare terminal that the installed SDK cannot emit.
function terminalEvent({ text = "done", messages, ...overrides } = {}) {
  return {
    type: "agent_end",
    messages: messages ?? [assistantMessage(text)],
    stopReason: "completed",
    ...overrides,
  };
}

function attemptScope(generation, attemptId = `attempt-${generation}`) {
  return Object.freeze({
    attemptId,
    generation,
    lineage: "main",
  });
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function schemaHash(schema) {
  return createHash("sha256").update(canonicalJson(schema)).digest("hex");
}

// Exact output shape of SDK 0.16.6 buildAskGateAnswerSchema() and
// buildAskGateStageState(); see workflow-gate-types.ts:206-293. Keeping the
// generated schema on every fake gate makes scalar-answer regressions visible.
function sdkAskGate({
  gate_id,
  kind = "question",
  stage = "deep-interview",
  context = {},
  options = [],
  multi = false,
  allowEmpty = false,
  customMaxLength,
}) {
  const labels = options.map((option) => option.label);
  const selectedItems = { type: "string", enum: labels };
  const selectedBase = {
    type: "array",
    items: selectedItems,
    uniqueItems: true,
  };
  const selectedOnly = {
    ...selectedBase,
    minItems: allowEmpty ? 0 : 1,
    ...(multi ? {} : { maxItems: 1 }),
  };
  const selectedWithOther = {
    ...selectedBase,
    ...(multi ? {} : { maxItems: 0 }),
  };
  const schema = {
    type: "object",
    properties: {
      selected: selectedBase,
      other: {
        type: "boolean",
        description: "set true to provide a free-text answer in `custom`",
      },
      custom: {
        type: "string",
        minLength: 1,
        ...(customMaxLength === undefined
          ? {}
          : { maxLength: customMaxLength }),
        pattern: "\\S",
        description: "free-text answer; required when `other` is true",
      },
      action: {
        type: "string",
        enum: ["answer", "clarify"],
        description:
          "set to `clarify` to ask about the choices without answering the round",
      },
      question: {
        type: "string",
        minLength: 1,
        pattern: "\\S",
        description: "clarification question; required when action is `clarify`",
      },
    },
    additionalProperties: false,
    anyOf: [
      {
        type: "object",
        properties: {
          selected: selectedOnly,
          other: { const: false },
          action: { const: "answer" },
        },
        required: ["selected"],
        additionalProperties: false,
      },
      {
        type: "object",
        properties: {
          selected: selectedWithOther,
          other: { const: true },
          custom: {
            type: "string",
            minLength: 1,
            ...(customMaxLength === undefined
              ? {}
              : { maxLength: customMaxLength }),
            pattern: "\\S",
          },
          action: { const: "answer" },
        },
        required: ["selected", "other", "custom"],
        additionalProperties: false,
      },
      {
        type: "object",
        properties: {
          action: { const: "clarify" },
          question: { type: "string", minLength: 1, pattern: "\\S" },
        },
        required: ["action", "question"],
        additionalProperties: false,
      },
    ],
  };
  const canonicalOptions = options.map((option) => ({
    value: option.label,
    label: option.label,
    ...(option.description === undefined
      ? {}
      : { description: option.description }),
  }));
  const gate = {
    type: "workflow_gate",
    gate_id,
    stage,
    kind,
    schema,
    schema_hash: schemaHash(schema),
    options: canonicalOptions,
    context: {
      ...context,
      stage_state: {
        question_id: gate_id,
        multi,
        options: labels,
        other_option: "Other (type your own)",
        clarification_action: "clarify",
        allow_empty: allowEmpty,
        ...(context.stage_state ?? {}),
      },
    },
    created_at: "2026-09-06T00:00:00.000Z",
    required: true,
  };
  return gate;
}

// Exact schemas/options from SDK 0.16.6 approval-gate.ts:54-94.
function sdkDecisionGate({ gate_id, kind, context = {} }) {
  const approval = kind === "approval";
  const decisions = approval
    ? ["approve", "request-changes", "reject"]
    : ["approve", "decline"];
  const detailKey = approval ? "comments" : "reason";
  const schema = {
    type: "object",
    properties: {
      decision: { type: "string", enum: decisions },
      [detailKey]: {
        type: "string",
        description: approval
          ? "required when requesting changes"
          : "optional rationale; required when declining",
      },
    },
    required: ["decision"],
    additionalProperties: false,
  };
  return {
    type: "workflow_gate",
    gate_id,
    stage: approval ? "ralplan" : "ultragoal",
    kind,
    schema,
    schema_hash: schemaHash(schema),
    options: decisions.map((decision) => ({
      value: decision,
      label: decision,
    })),
    context,
    created_at: "2026-09-06T00:00:00.000Z",
    required: true,
  };
}

// The fake emitter evaluates the constrained schema subset used by the exact
// fixtures above, matching workflow-gate-schema.ts rather than accepting an
// arbitrary answer selected by the test.
function schemaAccepts(schema, value) {
  if (schema.type === "object" && (typeof value !== "object" || value === null || Array.isArray(value))) {
    return false;
  }
  if (schema.type === "array" && !Array.isArray(value)) return false;
  if (schema.type === "string" && typeof value !== "string") return false;
  if (schema.type === "boolean" && typeof value !== "boolean") return false;
  if (Object.hasOwn(schema, "const") && canonicalJson(value) !== canonicalJson(schema.const)) {
    return false;
  }
  if (
    Array.isArray(schema.enum) &&
    !schema.enum.some((candidate) => canonicalJson(candidate) === canonicalJson(value))
  ) {
    return false;
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && [...value].length < schema.minLength) return false;
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) return false;
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) return false;
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) return false;
    if (schema.maxItems !== undefined && value.length > schema.maxItems) return false;
    if (schema.uniqueItems && new Set(value.map(canonicalJson)).size !== value.length) {
      return false;
    }
    if (schema.items && !value.every((item) => schemaAccepts(schema.items, item))) {
      return false;
    }
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) return false;
    }
    const properties = schema.properties ?? {};
    for (const [key, propertyValue] of Object.entries(value)) {
      if (properties[key]) {
        if (!schemaAccepts(properties[key], propertyValue)) return false;
      } else if (schema.additionalProperties === false) {
        return false;
      }
    }
  }
  if (Array.isArray(schema.anyOf)) {
    return schema.anyOf.some((branch) => schemaAccepts(branch, value));
  }
  return true;
}

class FakeAgentSession {
  constructor() {
    this.listeners = new Set();
    this.models = [
      { provider: "provider-a", id: "model-a", name: "Model A", extra: true },
    ];
    this.calls = [];
    this.disposeCalls = 0;
    this.profileCalls = [];
    this.modelRegistry = { id: "fake-model-registry" };
    this.settings = {
      get: (key) => (key === "modelProfile.default" ? "copilot-claude" : undefined),
    };
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(event) {
    for (const listener of this.listeners) listener(event);
  }

  getAvailableModels() {
    return this.models;
  }

  async setModel(model) {
    this.calls.push(["set_model", model]);
  }

  async prompt(message) {
    this.calls.push(["prompt", message]);
    this.emit({ type: "message_update", value: message });
    this.emit(terminalEvent({ text: message }));
  }

  async activateModelProfileForControl(profileName) {
    this.profileCalls.push(profileName);
    return true;
  }

  async dispose() {
    this.disposeCalls += 1;
  }
}

// #35: a fake BrokerWorkflowGateEmitter. emitGate() fires the registered
// listeners (as the real emitter does when the `ask` tool opens a gate) and
// returns a promise that resolves only when resolveGate() is called with the
// matching gate_id — mirroring how emitGate suspends the agent loop until an
// answer arrives.
class FakeGateEmitter {
  constructor() {
    this.listeners = new Set();
    this.resolveCalls = [];
    this.prepareCalls = [];
    this.clearPreparedCalls = [];
    this.quarantineCalls = [];
    this.resolvers = new Map();
    this.pending = new Map();
    this.prepared = new Set();
    this.completed = new Map();
    this.acceptedIncompleteKeys = new Set();
    this.beforeReceipt = undefined;
  }
  supportsRemoteGateAnswers() {
    return true;
  }
  onGateEmitted(listener) {
    this.listeners.add(listener);
    for (const gate of this.pending.values()) listener(gate);
    return () => this.listeners.delete(listener);
  }
  emitGate(gate) {
    return new Promise((resolve, reject) => {
      this.pending.set(gate.gate_id, gate);
      this.resolvers.set(gate.gate_id, { resolve, reject });
      for (const listener of this.listeners) listener(gate);
    });
  }
  prepareTerminalization(gateId, proof) {
    this.prepareCalls.push([gateId, proof]);
    if (!this.pending.has(gateId)) return false;
    this.prepared.add(gateId);
    return true;
  }
  clearPreparedTerminalization(gateId) {
    this.clearPreparedCalls.push(gateId);
    this.prepared.delete(gateId);
  }
  async resolveGate(response) {
    this.resolveCalls.push(response);
    if (!this.prepared.has(response.gate_id)) {
      throw new Error("workflow gate has no terminalization proof");
    }
    const gate = this.pending.get(response.gate_id);
    if (!gate || !schemaAccepts(gate.schema, response.answer)) {
      return {
        gate_id: response.gate_id,
        status: "rejected",
        answer_hash: "rejected-hash",
        error: { code: "invalid_workflow_gate_answer" },
      };
    }
    const resolver = this.resolvers.get(response.gate_id);
    if (resolver) {
      this.resolvers.delete(response.gate_id);
      this.pending.delete(response.gate_id);
      this.prepared.delete(response.gate_id);
      resolver.resolve(response.answer);
    }
    const resolution = {
      gate_id: response.gate_id,
      status: "accepted",
      answer_hash: "hash",
    };
    this.completed.set(response.idempotency_key, { response, resolution });
    await this.beforeReceipt?.(response);
    return resolution;
  }
  lookupCompletedResolution(response) {
    const completed = this.completed.get(response.idempotency_key);
    if (!completed) return { kind: "none" };
    if (
      completed.response.gate_id === response.gate_id &&
      completed.response.answer === response.answer
    ) {
      if (this.acceptedIncompleteKeys.has(response.idempotency_key)) {
        return { kind: "accepted_incomplete" };
      }
      return { kind: "completed", resolution: completed.resolution };
    }
    throw new Error("idempotency_conflict");
  }
  async recoverAcceptedGates() {
    return [];
  }
  quarantineGate(gateId) {
    this.quarantineCalls.push(gateId);
    this.pending.delete(gateId);
    this.prepared.delete(gateId);
    const resolver = this.resolvers.get(gateId);
    if (resolver) {
      this.resolvers.delete(gateId);
      resolver.reject(new Error(`workflow gate ${gateId} continuation was fenced`));
    }
  }
  listPendingGates() {
    return [...this.pending.values()];
  }
}

const gateResponse = (gateId, answer) => ({
  gate_id: gateId,
  answer,
  idempotency_key: `gjc-remote:${gateId}`,
});

// #35: a session whose prompt() opens one or more gates and blocks on each until
// answered, then emits agent_end.
class GatingAgentSession extends FakeAgentSession {
  constructor(gates) {
    super();
    this.gateEmitter = new FakeGateEmitter();
    this.gates = (Array.isArray(gates) ? gates : [gates]).map((gate) =>
      gate?.schema ? gate : sdkAskGate(gate)
    );
    this.answers = [];
  }
  getWorkflowGateEmitter() {
    return this.gateEmitter;
  }
  async prompt(message) {
    this.calls.push(["prompt", message]);
    this.emit({ type: "message_update", value: message });
    for (const gate of this.gates) {
      this.answers.push(await this.gateEmitter.emitGate(gate));
    }
    this.emit(terminalEvent());
  }
}

const gateDelay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createManualTimeouts() {
  let now = 0;
  const timers = new Map();

  return {
    setTimeout(callback, delay) {
      const timer = {};
      timers.set(timer, { callback, dueAt: now + delay });
      return timer;
    },
    clearTimeout(timer) {
      timers.delete(timer);
    },
    advance(ms) {
      now += ms;
      for (const [timer, { callback, dueAt }] of [...timers]) {
        if (dueAt > now) continue;
        timers.delete(timer);
        callback();
      }
    },
    get size() {
      return timers.size;
    },
  };
}

async function waitForImmediate(predicate, maxTurns = 1_000) {
  for (let turn = 0; turn < maxTurns; turn += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error("condition was not met within the immediate-turn bound");
}

test("createSdkSession uses the canonical workDir and dedicated session directory", async () => {
  const calls = [];
  const agent = new FakeAgentSession();
  let manager;
  const sdk = {
    SessionManager: {
      create(workDir, sessionDir) {
        calls.push(["manager", workDir, sessionDir]);
        manager = { workDir, sessionDir };
        return manager;
      },
    },
    async createAgentSession(options) {
      calls.push(["session", options]);
      return { session: agent };
    },
  };

  const session = await createSdkSession("/workspace", async () => sdk);

  assert.ok(session instanceof SdkSession);
  assert.deepEqual(calls[0], [
    "manager",
    "/workspace",
    join("/workspace", ".gjc-remote-session"),
  ]);
  assert.equal(calls[1][0], "session");
  assert.equal(calls[1][1].cwd, "/workspace");
  assert.strictEqual(calls[1][1].sessionManager, manager);
  assert.equal(
    Object.hasOwn(calls[1][1], "settings"),
    false,
    "SDK 0.16.6 must own and close its Settings.loadForScope instance"
  );
  assert.deepEqual(agent.profileCalls, ["copilot-claude"]);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
});

test("resolveSdkSessionDirectory preserves the native workDir session directory by default", () => {
  assert.equal(
    resolveSdkSessionDirectory("/workspace"),
    join("/workspace", ".gjc-remote-session")
  );
});

test("resolveSdkSessionDirectory derives opaque deterministic container directories", () => {
  const sessionRoot = resolve("container-sessions");
  const first = resolveSdkSessionDirectory("/workspace/one", sessionRoot);
  const firstAgain = resolveSdkSessionDirectory("/workspace/one", sessionRoot);
  const second = resolveSdkSessionDirectory("/workspace/two", sessionRoot);

  assert.equal(first, firstAgain);
  assert.notEqual(first, second);
  assert.equal(isAbsolute(first), true);
  assert.equal(relative(sessionRoot, first).startsWith(".."), false);
  assert.equal(first.includes("workspace"), false);
  assert.match(first.slice(sessionRoot.length + 1), /^[a-f0-9]{64}$/);
});

test("resolveSdkSessionDirectory rejects invalid container session roots", () => {
  for (const sessionRoot of ["relative-sessions", "", null, 1]) {
    assert.throws(
      () => resolveSdkSessionDirectory("/workspace", sessionRoot),
      /sessionRoot must be an absolute path/
    );
  }
});

test("createSdkSession passes the configured container session directory to SessionManager", async () => {
  const agent = new FakeAgentSession();
  const sessionRoot = resolve("container-sessions");
  let sessionDir;
  const sdk = {
    SessionManager: {
      create(workDir, directory) {
        sessionDir = directory;
        return { workDir, sessionDir: directory };
      },
    },
    async createAgentSession() {
      return { session: agent };
    },
  };

  const session = await createSdkSession("/workspace", async () => sdk, { sessionRoot });

  assert.equal(sessionDir, resolveSdkSessionDirectory("/workspace", sessionRoot));
  await session.dispose();
});

test("createSdkSession rejects invalid container session roots without loading the SDK", async () => {
  let loadCalls = 0;

  await assert.rejects(
    createSdkSession(
      "/workspace",
      async () => {
        loadCalls += 1;
        throw new Error("SDK should not load");
      },
      { sessionRoot: "relative-sessions" }
    ),
    /sessionRoot must be an absolute path/
  );
  assert.equal(loadCalls, 0);
});

test("SDK adapter forwards prompt events and preserves model command receipts", async () => {
  const agent = new FakeAgentSession();
  const session = new SdkSession(agent);
  const events = [];

  await session.send({ type: "prompt", message: "hello" }, (event) => events.push(event));
  await session.send({ type: "get_available_models" }, (event) => events.push(event));
  await session.send(
    { type: "set_model", provider: "provider-a", modelId: "model-a" },
    (event) => events.push(event)
  );

  assert.deepEqual(agent.calls, [
    ["prompt", "hello"],
    ["set_model", agent.models[0]],
  ]);
  assert.deepEqual(events[0], { type: "message_update", value: "hello" });
  assert.equal(events[1].type, "agent_end");
  assert.deepEqual(events[2].data.models, [
    { provider: "provider-a", id: "model-a", name: "Model A" },
  ]);
  assert.deepEqual(events[3].data, { provider: "provider-a", modelId: "model-a" });

  await session.dispose();
});

test("prompt completion waits for the final agent_end event", async () => {
  const agent = new FakeAgentSession();
  const timers = createManualTimeouts();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  const session = new SdkSession(agent, {
    setTimeoutFn: timers.setTimeout,
    clearTimeoutFn: timers.clearTimeout,
  });
  let settled = false;

  const result = session.send(
    { type: "prompt", message: "hello" },
    () => {},
    100
  );
  const observed = result.then(
    () => {
      settled = true;
      return { ok: true };
    },
    (error) => {
      settled = true;
      return { ok: false, error };
    }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  assert.equal(timers.size, 2);

  agent.emit(terminalEvent());
  try {
    await waitForImmediate(() => settled, 20);
    const outcome = await observed;
    if (!outcome.ok) throw outcome.error;
  } catch (error) {
    timers.advance(100);
    await observed;
    assert.equal(timers.size, 0);
    throw error;
  }
  assert.equal(settled, true);
  assert.equal(timers.size, 0);
  await session.dispose();
});

test("continuing maintenance agent_end checkpoints do not complete a prompt", async () => {
  const agent = new FakeAgentSession();
  const events = [];
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    for (const maintenanceOutcome of ["pruned", "compacted", "promoted"]) {
      agent.emit(terminalEvent({
        stopReason: "maintenance",
        maintenanceOutcome,
      }));
    }
  };
  const session = new SdkSession(agent);
  let settled = false;

  const prompt = session
    .send({ type: "prompt", message: "first" }, (event) => events.push(event), 100)
    .finally(() => {
      settled = true;
    });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(settled, false);
  assert.equal(events.length, 3, "maintenance checkpoints remain visible");

  agent.emit(terminalEvent());
  await prompt;
  assert.equal(settled, true);
  await session.dispose();
});

test("a prompt rejection after agent_end still fails the invocation", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    agent.emit(terminalEvent({ text: message }));
    throw Object.assign(new Error("raw provider detail must not escape"), {
      code: "provider_down",
    });
  };
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send({ type: "prompt", message: "first" }, () => {}, 100),
    (error) => {
      assert.equal(error.code, "provider_down");
      assert.match(error.message, /provider_down/);
      assert.doesNotMatch(error.message, /raw provider detail/);
      return true;
    }
  );
  await session.dispose();
});

test("a provider-error terminal is readiness evidence but not success", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async () => {
    agent.emit(
      terminalEvent({
        messages: [
          assistantMessage("", {
            stopReason: "error",
            errorMessage: "credential-bearing provider detail",
            errorStatus: 429,
          }),
        ],
      })
    );
  };
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send({ type: "prompt", message: "first" }, () => {}, 100),
    (error) => {
      assert.equal(error.code, "provider_http_429");
      assert.doesNotMatch(error.message, /credential-bearing/);
      return true;
    }
  );
  await session.dispose();
});

test("agent_failed is retained until its terminal boundary", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async () => {
    agent.emit({
      type: "agent_failed",
      error: {
        code: "provider_unavailable",
        message: "Prompt submission failed.",
      },
    });
    agent.emit(
      terminalEvent({
        messages: [assistantMessage("", { stopReason: "error" })],
      })
    );
  };
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send({ type: "prompt", message: "first" }, () => {}, 100),
    (error) => {
      assert.equal(error.code, "provider_unavailable");
      return true;
    }
  );
  await session.dispose();
});

test("failed maintenance terminal does not report successful completion", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async () => {
    agent.emit(
      terminalEvent({
        stopReason: "maintenance",
        maintenanceOutcome: "failed",
        messages: [assistantMessage("", { stopReason: "error" })],
      })
    );
  };
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send({ type: "prompt", message: "first" }, () => {}, 100),
    (error) => {
      assert.equal(error.code, "context_maintenance_failed");
      return true;
    }
  );
  await session.dispose();
});

test("a terminal without assistant activity fails closed", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async () => {
    agent.emit(terminalEvent({ messages: [] }));
  };
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send({ type: "prompt", message: "first" }, () => {}, 100),
    (error) => {
      assert.equal(error.code, "prompt_failed");
      return true;
    }
  );
  await session.dispose();
});

test("event consumer failures do not block agent_end lifecycle", async () => {
  const agent = new FakeAgentSession();
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send(
      { type: "prompt", message: "first" },
      () => {
        throw new Error("consumer failed");
      },
      100
    ),
    /consumer failed/
  );

  assert.equal(session.closed, false);
  await session.send({ type: "prompt", message: "second" }, () => {}, 100);
  await session.dispose();
});

test("SDK adapter serializes commands per session", async () => {
  const agent = new FakeAgentSession();
  let releaseFirst;
  const firstGate = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    if (message === "first") await firstGate;
    agent.emit(terminalEvent({ text: message }));
  };
  const session = new SdkSession(agent);

  const first = session.send({ type: "prompt", message: "first" }, () => {});
  const second = session.send({ type: "prompt", message: "second" }, () => {});
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(agent.calls, [["prompt", "first"]]);

  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["prompt", "second"],
  ]);
  await session.dispose();
});

test("live steer and follow-up fail closed without calling SDK queue hooks", async () => {
  const agent = new FakeAgentSession();
  let finishPrompt;
  agent.prompt = (message) => {
    agent.calls.push(["prompt", message]);
    return new Promise((resolve) => {
      finishPrompt = resolve;
    });
  };
  const session = new SdkSession(agent);
  const prompt = session.send(
    { type: "prompt", message: "active" },
    () => {},
    100
  );
  await new Promise((resolve) => setImmediate(resolve));

  for (const type of ["steer", "follow_up"]) {
    await assert.rejects(
      session.send({ type, message: "unsupported live control" }, () => {}, 100),
      (error) => {
        assert.equal(error.code, "SDK_LIVE_CONTROL_UNSUPPORTED");
        assert.match(error.message, /supported queued-input ownership contract/);
        return true;
      }
    );
  }
  assert.deepEqual(agent.calls, [["prompt", "active"]]);
  assert.equal(session.closed, false);

  agent.emit(terminalEvent());
  finishPrompt();
  await prompt;
  agent.prompt = FakeAgentSession.prototype.prompt.bind(agent);
  await session.send(
    { type: "follow_up", message: "idle retry" },
    () => {},
    100
  );
  assert.deepEqual(agent.calls, [
    ["prompt", "active"],
    ["prompt", "idle retry"],
  ]);
  await session.dispose();
});

test("idle follow-up starts a prompt run and keeps its event stream", async () => {
  const agent = new FakeAgentSession();
  const session = new SdkSession(agent);
  const events = [];

  await session.send(
    { type: "follow_up", message: "continue" },
    (event) => events.push(event),
    100
  );

  assert.deepEqual(agent.calls, [["prompt", "continue"]]);
  assert.deepEqual(events, [
    { type: "message_update", value: "continue" },
    terminalEvent({ text: "continue" }),
  ]);
  await session.dispose();
});

test("idle controls serialize behind an in-flight model switch", async () => {
  const agent = new FakeAgentSession();
  let releaseModel;
  const modelGate = new Promise((resolve) => {
    releaseModel = resolve;
  });
  agent.setModel = async (model) => {
    agent.calls.push(["set_model", model]);
    await modelGate;
  };
  const session = new SdkSession(agent);

  const modelSwitch = session.send(
    { type: "set_model", provider: "provider-a", modelId: "model-a" },
    () => {},
    100
  );
  const followUp = session.send(
    { type: "follow_up", message: "after model" },
    () => {},
    100
  );
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(agent.calls, [["set_model", agent.models[0]]]);
  releaseModel();
  await Promise.all([modelSwitch, followUp]);
  assert.deepEqual(agent.calls, [
    ["set_model", agent.models[0]],
    ["prompt", "after model"],
  ]);
  await session.dispose();
});

test("multiple idle controls remain FIFO prompt runs", async () => {
  const agent = new FakeAgentSession();
  let releaseFirst;
  const firstGate = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    if (message === "first") await firstGate;
    agent.emit(terminalEvent({ text: message }));
  };
  const session = new SdkSession(agent);

  const first = session.send({ type: "follow_up", message: "first" }, () => {}, 100);
  const second = session.send({ type: "steer", message: "second" }, () => {}, 100);
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(agent.calls, [["prompt", "first"]]);
  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["prompt", "second"],
  ]);
  await session.dispose();
});

test("SDK adapter poisons and disposes a timed-out session", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = () => new Promise(() => {});
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send({ type: "prompt", message: "never" }, () => {}, 1),
    /SDK command timed out/
  );
  assert.equal(session.closed, true);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
  await assert.rejects(
    session.send({ type: "prompt", message: "later" }, () => {}),
    /not running/
  );
});

test("model switches use the same timeout and poison lifecycle", async () => {
  const agent = new FakeAgentSession();
  agent.setModel = () => new Promise(() => {});
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send(
      { type: "set_model", provider: "provider-a", modelId: "model-a" },
      () => {},
      1
    ),
    /SDK command timed out/
  );
  assert.equal(session.closed, true);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
});

test("prompt idle timer resets on streamed activity and completes past the idle window", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    await delay(25);
    agent.emit({ type: "message_update", value: "a" });
    await delay(25);
    agent.emit({ type: "message_update", value: "b" });
    await delay(25);
    agent.emit({ type: "message_update", value: "c" });
    await delay(25);
    agent.emit(terminalEvent());
  };
  const session = new SdkSession(agent, { idleTimeoutMs: 60, hardCapMs: 5000 });

  await session.send({ type: "prompt", message: "hi" }, () => {});

  assert.equal(session.closed, false);
  await session.dispose();
});

test("prompt hard cap fires and disposes despite continuous activity", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = () => {
    agent.calls.push(["prompt", "x"]);
    const interval = setInterval(() => {
      agent.emit({ type: "message_update", value: "tick" });
    }, 10);
    interval.unref?.();
    agent._activityInterval = interval;
    return new Promise(() => {});
  };
  const session = new SdkSession(agent, { idleTimeoutMs: 1000, hardCapMs: 40 });

  try {
    await assert.rejects(
      session.send({ type: "prompt", message: "x" }, () => {}),
      /exceeded absolute hard-cap/
    );
  } finally {
    clearInterval(agent._activityInterval);
  }

  assert.equal(session.closed, true);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
});

test("per-instance idle/hard-cap config is honored independently", async () => {
  const agentFast = new FakeAgentSession();
  agentFast.prompt = () => new Promise(() => {});
  const sessionFast = new SdkSession(agentFast, { idleTimeoutMs: 10, hardCapMs: 5000 });

  const agentSlow = new FakeAgentSession();
  agentSlow.prompt = () => new Promise(() => {});
  const sessionSlow = new SdkSession(agentSlow, { idleTimeoutMs: 40, hardCapMs: 5000 });

  let fastSettledAt;
  let slowSettledAt;
  const fast = sessionFast
    .send({ type: "prompt", message: "fast" }, () => {})
    .catch((error) => {
      fastSettledAt = Date.now();
      throw error;
    });
  const slow = sessionSlow
    .send({ type: "prompt", message: "slow" }, () => {})
    .catch((error) => {
      slowSettledAt = Date.now();
      throw error;
    });

  await assert.rejects(fast, /SDK command timed out/);
  await assert.rejects(slow, /SDK command timed out/);

  assert.ok(fastSettledAt <= slowSettledAt);
  assert.equal(sessionFast.closed, true);
  assert.equal(sessionSlow.closed, true);
  await sessionFast.dispose();
  await sessionSlow.dispose();
});
test("adversarial: non-positive/NaN/undefined idle and hard-cap config fall back to defaults (resolveDuration)", async () => {
  const DEFAULT_IDLE_MS = 5 * 60 * 1000;
  const DEFAULT_HARD_CAP_MS = 30 * 60 * 1000;
  const previousIdleEnv = process.env.GJC_SDK_IDLE_TIMEOUT_MS;
  const previousHardCapEnv = process.env.GJC_SDK_HARD_CAP_MS;
  delete process.env.GJC_SDK_IDLE_TIMEOUT_MS;
  delete process.env.GJC_SDK_HARD_CAP_MS;

  try {
    // Invalid explicit options with no env override fall back to defaults.
    const noOptions = new SdkSession(new FakeAgentSession());
    assert.equal(noOptions.idleTimeoutMs, DEFAULT_IDLE_MS);
    assert.equal(noOptions.hardCapMs, DEFAULT_HARD_CAP_MS);

    for (const bad of [0, -1, Number.NaN, undefined]) {
      const session = new SdkSession(new FakeAgentSession(), {
        idleTimeoutMs: bad,
        hardCapMs: bad,
      });
      assert.equal(session.idleTimeoutMs, DEFAULT_IDLE_MS);
      assert.equal(session.hardCapMs, DEFAULT_HARD_CAP_MS);
    }

    // A non-numeric/non-positive env value is likewise ignored, falling back
    // to the default rather than throwing or coercing to NaN/negative delays.
    process.env.GJC_SDK_IDLE_TIMEOUT_MS = "not-a-number";
    process.env.GJC_SDK_HARD_CAP_MS = "-5";
    const envInvalid = new SdkSession(new FakeAgentSession());
    assert.equal(envInvalid.idleTimeoutMs, DEFAULT_IDLE_MS);
    assert.equal(envInvalid.hardCapMs, DEFAULT_HARD_CAP_MS);

    // A valid env override is honored when no explicit option is given.
    process.env.GJC_SDK_IDLE_TIMEOUT_MS = "1234";
    process.env.GJC_SDK_HARD_CAP_MS = "5678";
    const envValid = new SdkSession(new FakeAgentSession());
    assert.equal(envValid.idleTimeoutMs, 1234);
    assert.equal(envValid.hardCapMs, 5678);

    // An explicit positive option still wins over a valid env override.
    process.env.GJC_SDK_IDLE_TIMEOUT_MS = "9999";
    const optionWins = new SdkSession(new FakeAgentSession(), { idleTimeoutMs: 42 });
    assert.equal(optionWins.idleTimeoutMs, 42);
  } finally {
    if (previousIdleEnv === undefined) delete process.env.GJC_SDK_IDLE_TIMEOUT_MS;
    else process.env.GJC_SDK_IDLE_TIMEOUT_MS = previousIdleEnv;
    if (previousHardCapEnv === undefined) delete process.env.GJC_SDK_HARD_CAP_MS;
    else process.env.GJC_SDK_HARD_CAP_MS = previousHardCapEnv;
  }
});


test("dispose cancels adapter waiters without relying on an SDK terminal", async () => {
  const agent = new FakeAgentSession();
  const timers = createManualTimeouts();
  agent.prompt = () => new Promise(() => {});
  agent.dispose = async () => {
    agent.disposeCalls += 1;
  };
  const session = new SdkSession(agent, {
    idleTimeoutMs: 100,
    hardCapMs: 1_000,
    setTimeoutFn: timers.setTimeout,
    clearTimeoutFn: timers.clearTimeout,
  });

  const prompt = session.send({ type: "prompt", message: "active" }, () => {}, 100);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(timers.size, 2);

  const resultsPromise = Promise.allSettled([prompt]);
  await session.dispose();
  const results = await resultsPromise;
  assert.equal(results[0].status, "rejected");
  assert.match(results[0].reason.message, /disposed/);
  assert.equal(timers.size, 0);
  assert.equal(agent.disposeCalls, 1);
});

test("timeout-triggered disposal rejections are handled immediately", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = () => new Promise(() => {});
  agent.dispose = async () => {
    agent.disposeCalls += 1;
    throw new Error("dispose failed");
  };
  const session = new SdkSession(agent);

  await assert.rejects(
    session.send({ type: "prompt", message: "never" }, () => {}, 1),
    /SDK command timed out/
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(agent.disposeCalls, 1);
  await assert.rejects(session.dispose(), /dispose failed/);
});
function activationHarness() {
  const activateCalls = [];
  const settings = { get: () => undefined };
  const session = {
    settings,
    async activateModelProfileForControl(profileName) {
      activateCalls.push(profileName);
      return true;
    },
  };
  return {
    activateCalls,
    session,
    settings,
  };
}

test("applyConfiguredModelProfile activates the host-configured profile in-memory", async () => {
  const h = activationHarness();
  h.settings.get = (key) =>
    key === "modelProfile.default" ? "copilot-claude" : undefined;

  await applyConfiguredModelProfile(h.session);

  assert.deepEqual(h.activateCalls, ["copilot-claude"]);
});

test("applyConfiguredModelProfile lets GJC_MODEL_PROFILE override the configured profile", async () => {
  const h = activationHarness();
  h.settings.get = () => "copilot-claude";
  const previous = process.env.GJC_MODEL_PROFILE;
  process.env.GJC_MODEL_PROFILE = "  custom-profile  ";
  try {
    await applyConfiguredModelProfile(h.session);
  } finally {
    if (previous === undefined) delete process.env.GJC_MODEL_PROFILE;
    else process.env.GJC_MODEL_PROFILE = previous;
  }

  assert.equal(h.activateCalls.length, 1);
  assert.equal(h.activateCalls[0], "custom-profile");
});

test("applyConfiguredModelProfile skips activation and warns when no profile is configured", async () => {
  const h = activationHarness();
  h.settings.get = () => undefined;
  const previous = process.env.GJC_MODEL_PROFILE;
  delete process.env.GJC_MODEL_PROFILE;
  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  try {
    await applyConfiguredModelProfile(h.session);
  } finally {
    console.warn = originalWarn;
    if (previous !== undefined) process.env.GJC_MODEL_PROFILE = previous;
  }

  assert.equal(h.activateCalls.length, 0);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /no model profile configured/);
});

test("applyConfiguredModelProfile warns distinctly when modelProfile.default is set but unusable", async () => {
  const h = activationHarness();
  h.settings.get = (key) => (key === "modelProfile.default" ? 42 : undefined);
  const previous = process.env.GJC_MODEL_PROFILE;
  delete process.env.GJC_MODEL_PROFILE;
  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  try {
    await applyConfiguredModelProfile(h.session);
  } finally {
    console.warn = originalWarn;
    if (previous !== undefined) process.env.GJC_MODEL_PROFILE = previous;
  }

  assert.equal(h.activateCalls.length, 0);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /modelProfile\.default is set but not a usable/);
  assert.match(warnings[0], /42/);
});

test("applyConfiguredModelProfile ignores a whitespace-only GJC_MODEL_PROFILE and uses the configured profile", async () => {
  const h = activationHarness();
  h.settings.get = (key) =>
    key === "modelProfile.default" ? "copilot-claude" : undefined;
  const previous = process.env.GJC_MODEL_PROFILE;
  process.env.GJC_MODEL_PROFILE = "   ";
  try {
    await applyConfiguredModelProfile(h.session);
  } finally {
    if (previous === undefined) delete process.env.GJC_MODEL_PROFILE;
    else process.env.GJC_MODEL_PROFILE = previous;
  }

  assert.equal(h.activateCalls.length, 1);
  assert.equal(h.activateCalls[0], "copilot-claude");
});

test("applyConfiguredModelProfile surfaces activation failures loudly", async () => {
  const h = activationHarness();
  h.settings.get = () => "copilot-claude";
  h.session.activateModelProfileForControl = async () => {
    throw new Error("missing credentials for provider github-copilot");
  };

  await assert.rejects(
    applyConfiguredModelProfile(h.session),
    (error) => {
      assert.match(error.message, /failed to activate model profile "copilot-claude"/);
      assert.match(error.message, /missing credentials for provider github-copilot/);
      assert.equal(error.cause instanceof Error, true);
      return true;
    }
  );
});
test("createSdkSession disposes the raw session when profile activation fails", async () => {
  const agent = new FakeAgentSession();
  agent.activateModelProfileForControl = async () => {
    throw new Error("missing credentials for provider github-copilot");
  };
  const sdk = {
    SessionManager: { create: (workDir, sessionDir) => ({ workDir, sessionDir }) },
    async createAgentSession() {
      return { session: agent };
    },
  };

  await assert.rejects(
    createSdkSession("/workspace", async () => sdk),
    /failed to activate model profile "copilot-claude"/
  );
  assert.equal(agent.disposeCalls, 1);
});
// ---------------------------------------------------------------------------
// #35: workflow gate answer channel
// ---------------------------------------------------------------------------

test("gate emission produces a gate_request event and resolves on a label answer", async () => {
  const timers = createManualTimeouts();
  const agent = new GatingAgentSession({
    gate_id: "g1",
    kind: "question",
    context: { prompt: "Pick a fruit" },
    options: [
      { value: "a", label: "Apple" },
      { value: "b", label: "Banana" },
    ],
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 40,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 5_000,
    setTimeoutFn: timers.setTimeout,
    clearTimeoutFn: timers.clearTimeout,
  });

  const events = [];
  const done = session.send({ type: "prompt", message: "hi" }, (e) => events.push(e));

  await waitForImmediate(() => events.some((e) => e?.type === "gate_request"));
  const gateReq = events.find((e) => e && e.type === "gate_request");
  assert.ok(gateReq, "a gate_request event is emitted");
  assert.equal(gateReq.gateId, "g1");
  assert.equal(gateReq.kind, "question");
  assert.equal(gateReq.prompt, "Pick a fruit");
  assert.deepEqual(gateReq.choices, [
    { value: "Apple", label: "Apple" },
    { value: "Banana", label: "Banana" },
  ]);
  assert.equal(session.pendingGates.size, 1);

  timers.advance(120);
  assert.equal(session.closed, false);

  const result = await session.answerGate("g1", "Banana");
  assert.equal(result.ok, true);
  await done;

  assert.deepEqual(agent.gateEmitter.prepareCalls, [["g1", "not_published"]]);
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g1", { selected: ["Banana"] }),
  ]);
  assert.equal(session.pendingGates.size, 0);
  await session.dispose();
});

test("gate answer maps a 1-based index to the Ask selected-object schema", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g2",
    kind: "question",
    context: { title: "Choose" },
    options: [
      { value: "x", label: "First" },
      { value: "y", label: "Second" },
    ],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const events = [];
  const done = session.send({ type: "prompt", message: "hi" }, (e) => events.push(e));

  await gateDelay(0);
  const gateReq = events.find((e) => e && e.type === "gate_request");
  assert.equal(gateReq.prompt, "Choose"); // falls back to context.title

  await session.answerGate("g2", "2");
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g2", { selected: ["Second"] }),
  ]);
  await session.dispose();
});

test("free text is encoded as the Ask other/custom object", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g3",
    kind: "question",
    context: { prompt: "Describe it" },
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const events = [];
  const done = session.send({ type: "prompt", message: "hi" }, (e) => events.push(e));

  await gateDelay(0);
  const gateReq = events.find((e) => e && e.type === "gate_request");
  assert.equal(gateReq.choices, undefined);

  await session.answerGate("g3", "a long free-form answer");
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g3", {
      selected: [],
      other: true,
      custom: "a long free-form answer",
    }),
  ]);
  await session.dispose();
});

test("structured Ask answers preserve clarification and explicit custom semantics", async () => {
  for (const { gateId, answer, expected } of [
    {
      gateId: "g-clarify",
      answer:
        '{"action":"clarify","question":"What does the recommended choice change?"}',
      expected: {
        action: "clarify",
        question: "What does the recommended choice change?",
      },
    },
    {
      gateId: "g-custom",
      answer:
        '{"selected":[],"other":true,"custom":"Apple","action":"answer"}',
      expected: {
        selected: [],
        other: true,
        custom: "Apple",
        action: "answer",
      },
    },
  ]) {
    const agent = new GatingAgentSession({
      gate_id: gateId,
      context: { prompt: "Pick or explain" },
      options: [{ label: "Apple" }],
    });
    const session = new SdkSession(agent, {
      idleTimeoutMs: 5_000,
      hardCapMs: 10_000,
    });
    const done = session.send({ type: "prompt", message: "hi" }, () => {});
    await waitForImmediate(() => session.pendingGates.has(gateId));

    const result = await session.answerGate(gateId, answer);
    assert.equal(result.ok, true);
    await done;
    assert.deepEqual(agent.gateEmitter.resolveCalls, [
      gateResponse(gateId, expected),
    ]);
    await session.dispose();
  }
});

test("approval answers preserve denial and require comments for changes", async () => {
  const rejectAgent = new GatingAgentSession(
    sdkDecisionGate({
      gate_id: "g-approval-reject",
      kind: "approval",
      context: { title: "Approve the plan?" },
    })
  );
  const rejectSession = new SdkSession(rejectAgent);
  const rejectDone = rejectSession.send(
    { type: "prompt", message: "review" },
    () => {}
  );
  await waitForImmediate(() =>
    rejectSession.pendingGates.has("g-approval-reject")
  );
  assert.equal(
    (await rejectSession.answerGate("g-approval-reject", "reject")).ok,
    true
  );
  await rejectDone;
  assert.deepEqual(rejectAgent.gateEmitter.resolveCalls, [
    gateResponse("g-approval-reject", { decision: "reject" }),
  ]);
  await rejectSession.dispose();

  const changesAgent = new GatingAgentSession(
    sdkDecisionGate({
      gate_id: "g-approval-changes",
      kind: "approval",
      context: { title: "Approve the plan?" },
    })
  );
  const changesSession = new SdkSession(changesAgent);
  const changesDone = changesSession.send(
    { type: "prompt", message: "review" },
    () => {}
  );
  await waitForImmediate(() =>
    changesSession.pendingGates.has("g-approval-changes")
  );

  const unsupported = await changesSession.answerGate(
    "g-approval-changes",
    "request-changes"
  );
  assert.deepEqual(unsupported, {
    ok: false,
    error: "request-changes requires structured comments",
  });
  assert.deepEqual(changesAgent.gateEmitter.resolveCalls, []);

  const accepted = await changesSession.answerGate(
    "g-approval-changes",
    '{"decision":"request-changes","comments":"Cover the failure branch."}'
  );
  assert.equal(accepted.ok, true);
  await changesDone;
  assert.deepEqual(changesAgent.gateEmitter.resolveCalls, [
    gateResponse("g-approval-changes", {
      decision: "request-changes",
      comments: "Cover the failure branch.",
    }),
  ]);
  await changesSession.dispose();
});

test("execution decline is encoded as an explicit decision object", async () => {
  const agent = new GatingAgentSession(
    sdkDecisionGate({
      gate_id: "g-execution-decline",
      kind: "execution",
      context: { title: "Approve execution?" },
    })
  );
  const session = new SdkSession(agent);
  const done = session.send({ type: "prompt", message: "execute" }, () => {});
  await waitForImmediate(() =>
    session.pendingGates.has("g-execution-decline")
  );

  const result = await session.answerGate("g-execution-decline", "2");
  assert.equal(result.ok, true);
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g-execution-decline", { decision: "decline" }),
  ]);
  await session.dispose();
});

test("unsupported structured answer shapes are rejected before SDK resolution", async () => {
  const agent = new GatingAgentSession(
    sdkDecisionGate({
      gate_id: "g-unsupported-answer",
      kind: "execution",
    })
  );
  const session = new SdkSession(agent);
  const done = session.send({ type: "prompt", message: "execute" }, () => {});
  await waitForImmediate(() =>
    session.pendingGates.has("g-unsupported-answer")
  );

  const rejected = await session.answerGate(
    "g-unsupported-answer",
    '{"decision":"approve","extra":true}'
  );
  assert.deepEqual(rejected, {
    ok: false,
    error: "unsupported gate answer shape",
  });
  assert.deepEqual(agent.gateEmitter.resolveCalls, []);

  assert.equal(
    (await session.answerGate("g-unsupported-answer", "approve")).ok,
    true
  );
  await done;
  await session.dispose();
});

test("a rejected SDK gate answer remains pending for a valid retry", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-retry",
    kind: "question",
    context: { prompt: "Try again" },
    customMaxLength: 3,
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
  });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await waitForImmediate(() => session.pendingGates.has("g-retry"));

  const rejected = await session.answerGate(
    "g-retry",
    '{"selected":[],"other":true,"custom":"invalid"}'
  );
  assert.equal(rejected.ok, false);
  assert.equal(rejected.resolution.status, "rejected");
  assert.equal(session.pendingGates.has("g-retry"), true);
  assert.deepEqual(agent.gateEmitter.clearPreparedCalls, ["g-retry"]);

  const accepted = await session.answerGate("g-retry", "ok");
  assert.equal(accepted.ok, true);
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g-retry", {
      selected: [],
      other: true,
      custom: "invalid",
    }),
    gateResponse("g-retry", {
      selected: [],
      other: true,
      custom: "ok",
    }),
  ]);
  await session.dispose();
});

test("a lost resolveGate response reconciles a durably completed answer", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-reconcile",
    kind: "question",
    context: { prompt: "Continue?" },
  });
  const resolveGate = agent.gateEmitter.resolveGate.bind(agent.gateEmitter);
  agent.gateEmitter.resolveGate = async (response) => {
    await resolveGate(response);
    throw new Error("control response lost");
  };
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
  });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await waitForImmediate(() => session.pendingGates.has("g-reconcile"));

  const answered = await session.answerGate("g-reconcile", "yes");
  assert.equal(answered.ok, true);
  assert.equal(answered.resolution.status, "accepted");
  assert.equal(session.pendingGates.size, 0);
  await done;
  await session.dispose();
});

test("a proven successor gate is admitted while predecessor receipt is pending", async () => {
  const agent = new GatingAgentSession([
    sdkAskGate({
      gate_id: "g-successor-1",
      context: { prompt: "First question" },
      options: [{ label: "Continue" }],
    }),
    sdkAskGate({
      gate_id: "g-successor-2",
      context: { prompt: "Second question" },
      options: [{ label: "Finish" }],
    }),
  ]);
  let releaseFirstReceipt;
  const firstReceiptBarrier = new Promise((resolve) => {
    releaseFirstReceipt = resolve;
  });
  agent.gateEmitter.beforeReceipt = async (response) => {
    if (response.gate_id === "g-successor-1") await firstReceiptBarrier;
  };
  const timers = createManualTimeouts();
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 100,
    setTimeoutFn: timers.setTimeout,
    clearTimeoutFn: timers.clearTimeout,
  });
  const events = [];
  const done = session.send(
    { type: "prompt", message: "ask twice" },
    (event) => events.push(event)
  );
  await waitForImmediate(() => session.pendingGates.has("g-successor-1"));

  timers.advance(90);
  const firstAnswer = session.answerGate("g-successor-1", "Continue");
  await waitForImmediate(() => session.pendingGates.has("g-successor-2"));
  timers.advance(20);
  assert.equal(session.closed, false, "the successor receives its own gate window");
  assert.equal(session.pendingGates.has("g-successor-1"), false);
  assert.deepEqual(agent.gateEmitter.quarantineCalls, []);
  assert.equal(
    events.some(
      (event) =>
        event.type === "gate_request" && event.gateId === "g-successor-2"
    ),
    true
  );

  releaseFirstReceipt();
  assert.equal((await firstAnswer).ok, true);
  assert.equal(
    (await session.answerGate("g-successor-2", "Finish")).ok,
    true
  );
  await done;
  assert.deepEqual(agent.gateEmitter.quarantineCalls, []);
  await session.dispose();
});

test("an accepted-incomplete predecessor retains ownership until completed proof", async () => {
  const agent = new GatingAgentSession([
    sdkAskGate({
      gate_id: "g-incomplete-1",
      context: { prompt: "First question" },
      options: [{ label: "Continue" }],
    }),
    sdkAskGate({
      gate_id: "g-incomplete-2",
      context: { prompt: "Second question" },
      options: [{ label: "Finish" }],
    }),
  ]);
  const key = "gjc-remote:g-incomplete-1";
  agent.gateEmitter.acceptedIncompleteKeys.add(key);
  let releaseReceipt;
  const receiptBarrier = new Promise((resolve) => {
    releaseReceipt = resolve;
  });
  agent.gateEmitter.beforeReceipt = async (response) => {
    if (response.gate_id === "g-incomplete-1") await receiptBarrier;
  };
  const events = [];
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 5_000,
  });
  const done = session.send(
    { type: "prompt", message: "ask twice" },
    (event) => events.push(event)
  );
  await waitForImmediate(() => session.pendingGates.has("g-incomplete-1"));

  const firstAnswer = session.answerGate("g-incomplete-1", "Continue");
  await waitForImmediate(
    () => session.deferredGateCandidate?.gate?.gate_id === "g-incomplete-2"
  );
  assert.strictEqual(
    session.pendingGates.get("g-incomplete-1").response,
    agent.gateEmitter.resolveCalls[0]
  );
  assert.equal(session.pendingGates.has("g-incomplete-1"), true);
  assert.equal(session.pendingGates.has("g-incomplete-2"), false);
  assert.equal(
    events.some(
      (event) =>
        event.type === "gate_request" && event.gateId === "g-incomplete-2"
    ),
    false
  );
  assert.deepEqual(agent.gateEmitter.quarantineCalls, []);

  agent.gateEmitter.acceptedIncompleteKeys.delete(key);
  releaseReceipt();
  assert.equal((await firstAnswer).ok, true);
  await waitForImmediate(() => session.pendingGates.has("g-incomplete-2"));
  assert.equal(session.pendingGates.has("g-incomplete-1"), false);
  assert.equal(
    events.some(
      (event) =>
        event.type === "gate_request" && event.gateId === "g-incomplete-2"
    ),
    true
  );

  assert.equal(
    (await session.answerGate("g-incomplete-2", "Finish")).ok,
    true
  );
  await done;
  await session.dispose();
});

test("a deferred accepted-incomplete candidate is bounded by the gate window", async () => {
  const agent = new GatingAgentSession([
    sdkAskGate({
      gate_id: "g-bounded-1",
      context: { prompt: "First question" },
      options: [{ label: "Continue" }],
    }),
    sdkAskGate({
      gate_id: "g-bounded-2",
      context: { prompt: "Second question" },
      options: [{ label: "Finish" }],
    }),
  ]);
  agent.gateEmitter.acceptedIncompleteKeys.add("gjc-remote:g-bounded-1");
  agent.gateEmitter.beforeReceipt = () => new Promise(() => {});
  const timers = createManualTimeouts();
  const session = new SdkSession(agent, {
    idleTimeoutMs: 1_000,
    hardCapMs: 100,
    gateAnswerWindowMs: 40,
    setTimeoutFn: timers.setTimeout,
    clearTimeoutFn: timers.clearTimeout,
  });
  const done = session.send(
    { type: "prompt", message: "ask twice" },
    () => {}
  );
  const doneResult = Promise.allSettled([done]);
  await waitForImmediate(() => session.pendingGates.has("g-bounded-1"));
  const answer = session.answerGate("g-bounded-1", "Continue");
  await waitForImmediate(
    () => session.deferredGateCandidate?.gate?.gate_id === "g-bounded-2"
  );

  timers.advance(40);
  const [promptResult] = await doneResult;
  assert.equal(promptResult.status, "rejected");
  assert.match(promptResult.reason.message, /gate answer window expired/);
  assert.deepEqual(await answer, {
    ok: false,
    error: "session is closed",
  });
  assert.equal(session.deferredGateCandidate, undefined);
  assert.equal(
    agent.gateEmitter.quarantineCalls.includes("g-bounded-2"),
    true
  );
  await session.dispose();
});

test("dispose settles an adapter-owned gate receipt waiter", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-dispose-receipt",
    context: { prompt: "Continue?" },
    options: [{ label: "Continue" }],
  });
  agent.gateEmitter.beforeReceipt = () => new Promise(() => {});
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
  });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await waitForImmediate(() =>
    session.pendingGates.has("g-dispose-receipt")
  );

  const answer = session.answerGate("g-dispose-receipt", "Continue");
  const answerResult = answer.then(
    (result) => result,
    (error) => ({ ok: false, error: error.message })
  );
  await waitForImmediate(() => agent.gateEmitter.resolveCalls.length === 1);

  await session.dispose();
  assert.deepEqual(await answerResult, {
    ok: false,
    error: "session is closed",
  });
  await Promise.allSettled([done]);
  assert.equal(agent.disposeCalls, 1);
});

test("onGateEmitted replay is attributed to the run before subscription", async () => {
  const agent = new FakeAgentSession();
  const emitter = new FakeGateEmitter();
  const gate = sdkAskGate({
    gate_id: "g-replay",
    kind: "question",
    context: { prompt: "Recovered question" },
  });
  const gateAnswer = emitter.emitGate(gate);
  agent.getWorkflowGateEmitter = () => emitter;
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    await gateAnswer;
    agent.emit(terminalEvent());
  };
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
  });
  const events = [];

  const done = session.send(
    { type: "prompt", message: "resume" },
    (event) => events.push(event)
  );
  await waitForImmediate(() => session.pendingGates.has("g-replay"));
  assert.equal(
    events.some((event) => event.type === "gate_request" && event.gateId === "g-replay"),
    true
  );
  assert.deepEqual(emitter.quarantineCalls, []);

  const answered = await session.answerGate("g-replay", "continue");
  assert.equal(answered.ok, true);
  await done;
  await session.dispose();
});


test("gate-answer window expiry disposes the session with a distinct error", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g4",
    kind: "question",
    context: { prompt: "Answer me" },
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 20,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 60,
  });

  await assert.rejects(
    session.send({ type: "prompt", message: "hi" }, () => {}),
    /gate answer window expired/
  );
  assert.equal(session.closed, true);
  await session.dispose();
  assert.equal(agent.disposeCalls >= 1, true);
});
test("a failed run removes its pending workflow gate", async () => {
  class FailingGatingAgent extends GatingAgentSession {
    async prompt(message) {
      this.calls.push(["prompt", message]);
      void this.gateEmitter.emitGate(this.gates[0]).catch(() => {});
      throw new Error("SDK prompt failed");
    }
  }

  const agent = new FailingGatingAgent({
    gate_id: "g-failure",
    kind: "question",
    context: { prompt: "Will fail" },
  });
  const session = new SdkSession(agent);
  await assert.rejects(
    session.send({ type: "prompt", message: "first" }, () => {}),
    /prompt_failed/
  );
  assert.equal(session.pendingGates.size, 0);
  await session.dispose();
});

test("answerGate on an unknown/stale gate id is a safe no-op", async () => {
  const agent = new FakeAgentSession();
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const result = await session.answerGate("nope", "x");
  assert.equal(result.ok, false);
  await session.dispose();
});

test("a concurrent second gate is rejected without overwriting the first resolver", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g5",
    kind: "question",
    context: { prompt: "First" },
    options: [{ value: "a", label: "A" }],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const events = [];
  const done = session.send({ type: "prompt", message: "hi" }, (e) => events.push(e));
  await gateDelay(0);
  assert.equal(session.pendingGates.size, 1);

  // Simulate a second gate arriving on the same session while the first is pending.
  const emitter = agent.getWorkflowGateEmitter();
  for (const listener of emitter.listeners) {
    listener({ gate_id: "g5b", kind: "question", context: { prompt: "Second" } });
  }
  // The first gate is untouched; only one gate is tracked.
  assert.equal(session.pendingGates.size, 1);
  assert.ok(session.pendingGates.has("g5"));
  // The newcomer was fenced through the SDK's explicit quarantine operation.
  assert.deepEqual(emitter.quarantineCalls, ["g5b"]);

  await session.answerGate("g5", "A");
  await done;
  assert.deepEqual(emitter.resolveCalls, [
    gateResponse("g5", { selected: ["A"] }),
  ]);
  await session.dispose();
});

test("gate-answer window is clamped to the hard-cap with a warning", async () => {
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(" "));
  try {
    const session = new SdkSession(new FakeAgentSession(), {
      hardCapMs: 1_000,
      gateAnswerWindowMs: 5_000,
    });
    assert.equal(session.gateAnswerWindowMs, 1_000);
    assert.ok(warnings.some((w) => /clamping to the hard-cap/.test(w)));
  } finally {
    console.warn = originalWarn;
  }
});


test("adversarial: the absolute hard-cap still fires while a gate is suspended, even after the gate is answered and the run goes silent again", async () => {
  // Regression guard for #1: suspendForGate/resumeAfterGate must never touch
  // hardCapTimer. The hard-cap is the outer backstop and must bound the whole
  // run (gate wait + post-answer silence) regardless of gate suspension.
  class SlowResumeAgentSession extends GatingAgentSession {
    async prompt(message) {
      this.calls.push(["prompt", message]);
      this.emit({ type: "message_update", value: message });
      for (const gate of this.gates) {
        this.answers.push(await this.gateEmitter.emitGate(gate));
      }
      // Silent stretch after the gate resolves, long enough to blow the hard-cap
      // even though the idle timer was freshly re-armed by resumeAfterGate.
      await gateDelay(200);
      this.emit(terminalEvent());
    }
  }
  const agent = new SlowResumeAgentSession({
    gate_id: "g-hardcap",
    kind: "question",
    context: { prompt: "Answer fast" },
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 150,
    gateAnswerWindowMs: 100,
  });

  const events = [];
  const done = session.send({ type: "prompt", message: "hi" }, (e) => events.push(e));
  await gateDelay(0);
  const answerResult = await session.answerGate("g-hardcap", "anything");
  assert.equal(answerResult.ok, true);

  await assert.rejects(done, /exceeded absolute hard-cap/);
  assert.equal(session.closed, true);
  await session.dispose();
});

test("adversarial: answering the same gate twice is a safe no-op the second time (no double resolveGate)", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-double",
    kind: "question",
    context: { prompt: "Pick one" },
    options: [{ value: "a", label: "A" }],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await gateDelay(0);

  const first = await session.answerGate("g-double", "A");
  assert.equal(first.ok, true);
  const second = await session.answerGate("g-double", "A");
  assert.deepEqual(second, { ok: false, error: "no pending gate for id" });

  await done;
  // Only one resolveGate call reached the emitter for this gate id.
  assert.equal(
    agent.gateEmitter.resolveCalls.filter((r) => r.gate_id === "g-double").length,
    1
  );
  assert.equal(session.pendingGates.size, 0);
  await session.dispose();
});

test("adversarial: an answer submitted after the gate-answer window already expired must be a safe no-op", async () => {
  // #35 spec requires the timeout close path to fence the continuation and make
  // a post-expiry answer a no-op before public dispose() is called.
  const agent = new GatingAgentSession({
    gate_id: "g-late",
    kind: "question",
    context: { prompt: "Answer me" },
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 30,
  });

  await assert.rejects(
    session.send({ type: "prompt", message: "hi" }, () => {}),
    /gate answer window expired/
  );
  assert.equal(session.closed, true);

  // The run already errored out on the gate-answer window; a late answer for
  // that same gate must be rejected, not honored.
  const lateAnswer = await session.answerGate("g-late", "too late");
  assert.deepEqual(lateAnswer, { ok: false, error: "session is closed" });

  await session.dispose();
});

test("adversarial: a gate answered normally, followed by silence, still idle-times-out (resumeAfterGate re-arms correctly)", async () => {
  class SilentAfterGateAgentSession extends GatingAgentSession {
    async prompt(message) {
      this.calls.push(["prompt", message]);
      this.emit({ type: "message_update", value: message });
      for (const gate of this.gates) {
        this.answers.push(await this.gateEmitter.emitGate(gate));
      }
      // Never emits agent_end and never streams again: the idle timer (re-armed
      // by resumeAfterGate) must be the one to bound this, not a stray timer.
      await new Promise(() => {});
    }
  }
  const agent = new SilentAfterGateAgentSession({
    gate_id: "g-silent",
    kind: "question",
    context: { prompt: "Answer" },
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 30,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 5_000,
  });

  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await gateDelay(0);
  const answerResult = await session.answerGate("g-silent", "ok");
  assert.equal(answerResult.ok, true);

  await assert.rejects(done, /SDK command timed out/);
  assert.equal(session.closed, true);
  await session.dispose();
});

test("adversarial: a concurrent gate rejection leaves pendingGates empty once the first gate is answered", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g6",
    kind: "question",
    context: { prompt: "First" },
    options: [{ value: "a", label: "A" }],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await gateDelay(0);

  const emitter = agent.getWorkflowGateEmitter();
  for (const listener of emitter.listeners) {
    listener({ gate_id: "g6b", kind: "question", context: { prompt: "Second" } });
  }
  assert.equal(session.pendingGates.size, 1);

  await session.answerGate("g6", "A");
  await done;
  assert.equal(session.pendingGates.size, 0);
  await session.dispose();
});

test("adversarial: a numeric-looking Ask label wins over positional index parsing", async () => {
  // options[0].label is "2"; an index-based reading of answer "2" would pick
  // options[1] instead. Label matching must run first and win.
  const agent = new GatingAgentSession({
    gate_id: "g-numlabel",
    kind: "question",
    context: { prompt: "Pick" },
    options: [
      { value: "label-two", label: "2" },
      { value: "only", label: "Only" },
    ],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await gateDelay(0);

  await session.answerGate("g-numlabel", "2");
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g-numlabel", { selected: ["2"] }),
  ]);
  await session.dispose();
});

test("adversarial: duplicate Ask labels still encode one schema-valid selection", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-dup",
    kind: "question",
    context: { prompt: "Pick" },
    options: [
      { value: "first", label: "Yes" },
      { value: "second", label: "Yes" },
    ],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await gateDelay(0);

  await session.answerGate("g-dup", "yes");
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g-dup", { selected: ["Yes"] }),
  ]);
  await session.dispose();
});

test("adversarial: whitespace/case variance still matches an Ask label", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-ws",
    kind: "question",
    context: { prompt: "Pick" },
    options: [{ value: "a", label: "Apple" }],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await gateDelay(0);

  await session.answerGate("g-ws", "  APPLE  ");
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g-ws", { selected: ["Apple"] }),
  ]);
  await session.dispose();
});

test("adversarial: an out-of-range index is an explicit Ask custom answer", async () => {
  for (const bad of ["0", "-1", "5"]) {
    const agent = new GatingAgentSession({
      gate_id: "g-range",
      kind: "question",
      context: { prompt: "Pick" },
      options: [
        { value: "a", label: "A" },
        { value: "b", label: "B" },
      ],
    });
    const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
    const done = session.send({ type: "prompt", message: "hi" }, () => {});
    await gateDelay(0);

    await session.answerGate("g-range", bad);
    await done;
    assert.deepEqual(agent.gateEmitter.resolveCalls, [
      gateResponse("g-range", {
        selected: [],
        other: true,
        custom: bad,
      }),
    ]);
    await session.dispose();
  }
});

test("adversarial: a required Ask rejects an empty answer before resolution", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-empty",
    kind: "question",
    context: { prompt: "Pick" },
    options: [
      { value: "a", label: "A" },
      { value: "b", label: "B" },
    ],
  });
  const session = new SdkSession(agent, { idleTimeoutMs: 5_000, hardCapMs: 10_000 });
  const done = session.send({ type: "prompt", message: "hi" }, () => {});
  await gateDelay(0);

  const rejected = await session.answerGate("g-empty", "");
  assert.deepEqual(rejected, {
    ok: false,
    error: "gate answer must not be empty",
  });
  assert.deepEqual(agent.gateEmitter.resolveCalls, []);
  await session.answerGate("g-empty", "A");
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g-empty", { selected: ["A"] }),
  ]);
  await session.dispose();
});
test("#35 concurrency: the workflow-gate listener is registered once per session, not per run", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-one",
    kind: "question",
    context: { prompt: "Q" },
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 5_000,
  });
  const run = session.send({ type: "prompt", message: "a" }, () => {});
  await gateDelay(0);

  // Exactly ONE session-level listener — the old per-run design added a listener
  // per #runPromptCommand, so a second concurrent run's listener fired on the same
  // emit and quarantined the pending gate.
  assert.equal(agent.gateEmitter.listeners.size, 1);
  assert.equal(session.pendingGates.size, 1);
  assert.deepEqual(agent.gateEmitter.resolveCalls, []);

  const answered = await session.answerGate("g-one", "ok");
  assert.equal(answered.ok, true);
  await run;

  // The subscription is session-scoped: it survives run completion and is only
  // torn down on dispose (not per run).
  assert.equal(agent.gateEmitter.listeners.size, 1);
  await session.dispose();
  assert.equal(agent.gateEmitter.listeners.size, 0);
});

test("#35 concurrency: answerGate resumes the OWNING run's idle controller", async () => {
  // With a single shared controller slot a concurrent run could null/clobber it,
  // so answering could not re-arm the parked run's idle timer. The per-entry
  // controller must still resume the owning run.
  const agent = new GatingAgentSession({
    gate_id: "g-owner",
    kind: "question",
    context: { prompt: "Park here" },
  });
  let releaseTerminal;
  const terminalGate = new Promise((resolve) => {
    releaseTerminal = resolve;
  });
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    agent.answers.push(await agent.gateEmitter.emitGate(agent.gates[0]));
    await terminalGate;
    agent.emit(terminalEvent());
  };
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 5_000,
  });
  const parked = session.send({ type: "prompt", message: "a" }, () => {});
  await gateDelay(0);
  const entry = session.pendingGates.get("g-owner");
  assert.ok(entry, "the parked run registered its gate");
  assert.ok(entry.controller, "the entry captured the parked run's controller");

  const resumeCalls = [];
  const realResume = entry.controller.resumeAfterGate;
  entry.controller.resumeAfterGate = (...args) => {
    resumeCalls.push(args);
    return realResume.apply(entry.controller, args);
  };

  const answered = await session.answerGate("g-owner", "ok");
  assert.equal(answered.ok, true);
  assert.equal(resumeCalls.length, 1, "the owning run's controller was resumed exactly once");
  releaseTerminal();
  await parked;
  await session.dispose();
});

test("#35 an oversized supported gate is clamped for the protocol", async () => {
  const hugePrompt = "P".repeat(V0_LIMITS.GATE_PROMPT + 500);
  const hugeLabel = "L".repeat(V0_LIMITS.CHOICE_LABEL + 200);
  const agent = new GatingAgentSession({
    gate_id: "g-clamp",
    kind: "question",
    context: { prompt: hugePrompt },
    options: [{ value: "a", label: hugeLabel }],
  });
  const session = new SdkSession(agent, {
    idleTimeoutMs: 5_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 5_000,
  });
  const events = [];
  const done = session.send({ type: "prompt", message: "hi" }, (evt) => events.push(evt));
  await gateDelay(0);

  const gateEvent = events.find((evt) => evt.type === "gate_request");
  assert.ok(gateEvent, "a gate_request event was emitted");
  assert.equal(gateEvent.kind, "question");
  assert.equal(gateEvent.prompt.length, V0_LIMITS.GATE_PROMPT, "prompt clamped to the limit");
  assert.equal(gateEvent.choices[0].label.length, V0_LIMITS.CHOICE_LABEL, "label clamped to the limit");
  assert.equal(isGateRequestEvent(gateEvent), true, "the clamped event passes the bot's validator");

  await session.answerGate("g-clamp", "1");
  await done;
  await session.dispose();
});

test("unsupported gate kinds are quarantined instead of coerced", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-unsupported-kind",
    kind: "totally-unknown-kind",
    context: { prompt: "Unsupported" },
    options: [{ label: "A" }],
  });
  const session = new SdkSession(agent);
  const events = [];

  await assert.rejects(
    session.send(
      { type: "prompt", message: "hi" },
      (event) => events.push(event),
      100
    ),
    /prompt_failed/
  );
  assert.equal(events.some((event) => event.type === "gate_request"), false);
  assert.deepEqual(agent.gateEmitter.quarantineCalls, [
    "g-unsupported-kind",
  ]);
  await session.dispose();
});
