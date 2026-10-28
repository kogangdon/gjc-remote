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

async function answerGate(session, gateId, answer) {
  const entry = session.pendingGates.get(gateId);
  assert.ok(entry, `gate ${gateId} is pending`);
  assert.equal(
    session.presentGate(
      entry.ownerId,
      gateId,
      entry.presentationId,
      `test-presentation-${gateId}`
    ),
    true
  );
  return session.answerGate(entry.ownerId, gateId, entry.presentationId, answer);
}

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

// AgentEvent.agent_end in @gajae-code/agent-core 0.19.0 always carries the
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

// Exact output shape of SDK 0.19.0 buildAskGateAnswerSchema() and
// buildAskGateStageState() in workflow-gate-types.ts. Keeping the
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

// Exact schemas/options from SDK 0.19.0 approval-gate.ts.
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
    this.rawListeners = new Set();
    this.agent = {
      subscribe: (listener) => {
        this.rawListeners.add(listener);
        return () => this.rawListeners.delete(listener);
      },
    };
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

  emitRaw(event) {
    for (const listener of this.rawListeners) listener(event);
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

// #35: a fake public WorkflowGateEmitter. emitGate() fires the registered
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
    this.recoveryCalls = 0;
    this.recoverAccepted = undefined;
    this.lookupCalls = [];
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
    this.lookupCalls.push(response);
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
    this.recoveryCalls += 1;
    return this.recoverAccepted ? this.recoverAccepted() : [];
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
    "SDK 0.19.0 must own and close its Settings.loadForScope instance"
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

  const promptResult = await session.send(
    { type: "prompt", message: "hello" },
    (event) => events.push(event)
  );
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
  assert.deepEqual(events[1].data.models, [
    { provider: "provider-a", id: "model-a", name: "Model A" },
  ]);
  assert.deepEqual(events[2].data, { provider: "provider-a", modelId: "model-a" });
  assert.deepEqual(promptResult, { disposition: "completed" });

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
  assert.equal(events.length, 0, "internal maintenance terminals stay off the wire");

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
  const events = [];

  await assert.rejects(
    session.send(
      { type: "prompt", message: "first" },
      (event) => events.push(event),
      100
    ),
    (error) => {
      assert.equal(error.code, "provider_down");
      assert.equal(error.terminalDisposition, "failed");
      assert.match(error.message, /provider_down/);
      assert.doesNotMatch(error.message, /raw provider detail/);
      return true;
    }
  );
  assert.equal(JSON.stringify(events).includes("credential-bearing"), false);
  assert.deepEqual(events, []);
  await session.dispose();
});

test("scoped diagnostics bind only to the exact terminal and never outrun the prompt promise", async (t) => {
  const current = attemptScope(2, "main-attempt");
  const cases = [
    { name: "matching main attempt", scope: current, code: "provider_down", expected: "provider_down" },
    { name: "stale generation", scope: attemptScope(1, current.attemptId), code: "stale_failure" },
    { name: "different attempt", scope: attemptScope(2, "other-attempt"), code: "other_failure" },
    { name: "different lineage", scope: { ...current, lineage: "child" }, code: "child_failure" },
    { name: "missing generation", scope: { attemptId: current.attemptId, lineage: "main" }, code: "invalid_scope" },
    { name: "unsafe generation", scope: { ...current, generation: Number.MAX_SAFE_INTEGER + 1 }, code: "invalid_scope" },
    { name: "non-record scope", scope: [current], code: "invalid_scope" },
    { name: "null scope", scope: null, code: "invalid_scope" },
    { name: "maximum safe diagnostic length", scope: current, code: "x".repeat(64), expected: "x".repeat(64) },
    { name: "later stale diagnostic cannot override matching failure", scope: current, code: "matching_failure", laterStale: true, expected: "matching_failure" },
    { name: "unsafe diagnostic code", scope: current, code: "credential-bearing secret", expected: "prompt_failed" },
    { name: "oversized diagnostic code", scope: current, code: "x".repeat(65), expected: "prompt_failed" },
    { name: "prompt rejection after successful scoped terminal", scope: attemptScope(1, current.attemptId), code: "stale_failure", promptCode: "submission_failed", expected: "submission_failed" },
  ];
  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const agent = new FakeAgentSession();
      let releasePrompt;
      const promptBarrier = new Promise((resolve) => { releasePrompt = resolve; });
      agent.prompt = async () => {
        agent.emit({ type: "agent_start", scope: current });
        await promptBarrier;
        if (scenario.promptCode) {
          throw Object.assign(new Error("credential-bearing prompt secret"), { code: scenario.promptCode });
        }
      };
      const session = new SdkSession(agent);
      const events = [];
      let settled = false;
      const observed = session.send(
        { type: "prompt", message: "scoped" },
        (event) => events.push(event)
      ).then(
        (value) => { settled = true; return { value }; },
        (error) => { settled = true; return { error }; }
      );
      await waitForImmediate(() => agent.listeners.size === 1);
      agent.emit({
        type: "agent_failed",
        scope: scenario.scope,
        error: { code: scenario.code, message: "credential-bearing diagnostic secret" },
      });
      if (scenario.laterStale) {
        agent.emit({
          type: "agent_failed",
          scope: attemptScope(1, current.attemptId),
          error: { code: "stale_failure", message: "credential-bearing stale secret" },
        });
      }
      agent.emit(terminalEvent({ scope: current }));
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(settled, false, "terminal readiness cannot settle a pending prompt promise");
      releasePrompt();
      const outcome = await observed;
      if (scenario.expected) {
        assert.equal(outcome.error?.code, scenario.expected);
        assert.equal(outcome.error?.terminalDisposition, "failed");
        assert.doesNotMatch(outcome.error.message, /credential-bearing|secret/);
      } else {
        assert.deepEqual(outcome, { value: { disposition: "completed" } });
      }
      assert.deepEqual(events, [{ type: "agent_start", scope: current }]);
      assert.doesNotMatch(JSON.stringify(events), /credential-bearing|secret|agent_failed|agent_end/);
      assert.equal(agent.listeners.size, 0);
      await session.dispose();
      assert.equal(agent.disposeCalls, 1);
    });
  }
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
      assert.equal(error.terminalDisposition, "failed");
      assert.doesNotMatch(error.message, /credential-bearing/);
      return true;
    }
  );
  await session.dispose();
});

test("terminal dispositions preserve explicit stop reasons over assistant activity", async () => {
  const cases = [
    {
      name: "paused",
      event: terminalEvent({
        stopReason: "paused",
        messages: [assistantMessage("partial response", { stopReason: "error" })],
      }),
      disposition: "paused",
      code: undefined,
      reportedFailure: "provider_down",
    },
    {
      name: "cancelled",
      event: terminalEvent({
        stopReason: "cancelled",
        messages: [assistantMessage("partial response", { stopReason: "error" })],
      }),
      disposition: "cancelled",
      code: "aborted",
    },
    {
      name: "maintenance failure",
      event: terminalEvent({
        stopReason: "maintenance",
        maintenanceOutcome: "failed",
        messages: [assistantMessage("partial response")],
      }),
      disposition: "failed",
      code: "context_maintenance_failed",
    },
    {
      name: "maintenance abort",
      event: terminalEvent({
        stopReason: "maintenance",
        maintenanceOutcome: "aborted",
        messages: [assistantMessage("partial response")],
      }),
      disposition: "failed",
      code: "aborted",
    },
    {
      name: "assistant abort",
      event: terminalEvent({
        messages: [assistantMessage("partial response", { stopReason: "aborted" })],
      }),
      disposition: "cancelled",
      code: "aborted",
    },
    {
      name: "malformed terminal messages",
      event: terminalEvent({ messages: { role: "assistant" } }),
      disposition: "failed",
      code: "prompt_failed",
    },
    {
      name: "missing outer stop reason",
      event: terminalEvent({
        stopReason: undefined,
        messages: [assistantMessage("partial response")],
      }),
      disposition: "failed",
      code: "prompt_failed",
    },
    {
      name: "unknown outer stop reason",
      event: terminalEvent({
        stopReason: "future-terminal",
        messages: [assistantMessage("partial response")],
      }),
      disposition: "failed",
      code: "prompt_failed",
    },
  ];

  for (const fixture of cases) {
    const agent = new FakeAgentSession();
    agent.prompt = async () => {
      if (fixture.reportedFailure) {
        agent.emit({
          type: "agent_failed",
          error: { code: fixture.reportedFailure },
        });
      }
      agent.emit(fixture.event);
    };
    const session = new SdkSession(agent);

    await assert.rejects(
      session.send({ type: "prompt", message: fixture.name }, () => {}, 100),
      (error) => {
        assert.equal(error.terminalDisposition, fixture.disposition);
        assert.equal(error.code, fixture.code);
        return true;
      }
    );
    await session.dispose();
  }
});

test("agent_failed is retained until its terminal boundary", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async () => {
    agent.emit({
      type: "agent_failed",
      error: {
        code: "provider_unavailable",
        message: "credential-bearing agent failure",
      },
    });
    agent.emit(
      terminalEvent({
        messages: [assistantMessage("", { stopReason: "error" })],
      })
    );
  };
  const session = new SdkSession(agent);
  const events = [];

  await assert.rejects(
    session.send(
      { type: "prompt", message: "first" },
      (event) => events.push(event),
      100
    ),
    (error) => {
      assert.equal(error.code, "provider_unavailable");
      assert.equal(error.terminalDisposition, "failed");
      return true;
    }
  );
  assert.deepEqual(events, []);
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
      assert.equal(error.terminalDisposition, "failed");
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
      assert.equal(error.terminalDisposition, "failed");
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

test("owned queued tickets revoke before dispatch and let the FIFO tail advance", async () => {
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
  await waitForImmediate(() => agent.calls.length === 1);
  const second = session.sendOwned("channel-1", { type: "prompt", message: "second" }, () => {});
  const third = session.send({ type: "prompt", message: "third" }, () => {});

  assert.equal(second.phase, "queued");
  assert.equal(second.revokeBeforeStart(), true);
  assert.equal(second.revokeBeforeStart(), false);
  assert.equal(second.phase, "terminal");
  assert.deepEqual(await second.result, { revokedBeforeStart: true });
  assert.deepEqual(agent.calls, [["prompt", "first"]]);

  releaseFirst();
  await Promise.all([first, third]);
  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["prompt", "third"],
  ]);
  assert.equal(session.queuedCommands, 0);
  assert.equal(session.isBusy(), false);
  await session.dispose();
});

test("owned ticket activation synchronously wins its revoke CAS", async () => {
  const agent = new FakeAgentSession();
  let activations = 0;
  let releaseActive;
  const activeGate = new Promise((resolve) => {
    releaseActive = resolve;
  });
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    if (message === "active") await activeGate;
    agent.emit(terminalEvent({ text: message }));
  };
  const session = new SdkSession(agent);

  const queued = session.sendOwned("channel-1", { type: "prompt", message: "queued" }, () => {});
  assert.equal(queued.revokeBeforeStart(), true);
  assert.deepEqual(await queued.result, { revokedBeforeStart: true });

  const active = session.sendOwned(
    "channel-1",
    { type: "prompt", message: "active" },
    () => {},
    undefined,
    { onActivate: () => { activations += 1; } }
  );
  await waitForImmediate(() => active.phase === "active");
  assert.equal(activations, 1);
  assert.deepEqual(agent.calls, [["prompt", "active"]]);
  assert.equal(active.revokeBeforeStart(), false);

  releaseActive();
  assert.deepEqual(await active.result, { disposition: "completed" });
  assert.equal(active.phase, "terminal");
  assert.equal(active.revokeBeforeStart(), false);
  assert.deepEqual(agent.calls, [["prompt", "active"]]);
  await session.dispose();
});

test("dispose rejects owned queued tickets without dispatching them", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = (message) => {
    agent.calls.push(["prompt", message]);
    return new Promise(() => {});
  };
  const session = new SdkSession(agent);

  const active = session.send({ type: "prompt", message: "active" }, () => {}, 10_000);
  await waitForImmediate(() => agent.calls.length === 1);
  const queued = session.sendOwned("channel-1", { type: "prompt", message: "queued" }, () => {});
  const activeRejected = assert.rejects(active, /disposed/);
  const queuedRejected = assert.rejects(queued.result, /disposed/);

  await session.dispose();
  await Promise.all([activeRejected, queuedRejected]);
  assert.equal(queued.phase, "terminal");
  assert.equal(queued.revokeBeforeStart(), false);
  assert.deepEqual(agent.calls, [["prompt", "active"]]);
});

function trackedDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

class TrackedAgentSession extends FakeAgentSession {
  constructor() {
    super();
    this.inputs = [];
    this.root = trackedDeferred();
    this.rootScope = attemptScope(1);
  }
  prompt(message) {
    this.calls.push(["prompt", message]);
    this.emit({ type: "agent_start", scope: this.rootScope });
    return this.root.promise;
  }
  submitUserMessage(message, options) {
    const admitted = trackedDeferred();
    const execution = trackedDeferred();
    const terminal = trackedDeferred();
    const input = {
      message, options, admitted, execution, terminal,
      executed: false, removed: false,
      identity: { submissionId: `input-${this.inputs.length + 1}`, delivery: options.deliverAs },
    };
    input.remove = () => {
      if (input.executed || input.removed) return false;
      input.removed = true;
      const receipt = { ...input.identity, disposition: "removed", reason: "cancelled" };
      execution.resolve(receipt);
      terminal.resolve(receipt);
      return true;
    };
    input.execute = (scope, disposition = "joined-current-run") => {
      input.executed = true;
      execution.resolve({ ...input.identity, disposition, attemptScope: scope });
    };
    input.complete = (scope) => terminal.resolve({ ...input.identity, disposition: "completed", attemptScope: scope });
    this.inputs.push(input);
    options.onPreflightAcceptCommit?.();
    admitted.resolve({ ...input.identity, queuePolicy: options.queuePolicy });
    return Promise.resolve({
      submissionId: input.identity.submissionId,
      admitted: admitted.promise,
      execution: execution.promise,
      terminal: terminal.promise,
      cancel: input.remove,
    });
  }
  finishRoot(scope = this.rootScope, overrides = {}) {
    this.emit(terminalEvent({ scope, ...overrides }));
    this.root.resolve();
  }
}

test("coalesced root readiness uses owned raw evidence and exact prompt settlement without output duplication", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const events = [];
  const root = session.send({ type: "prompt", message: "root" }, (event) => events.push(event));
  await waitForImmediate(() => agent.calls.length === 1);
  const cohort = session.inputRouter.primary;
  assert.equal(agent.listeners.size, 1);
  assert.equal(agent.rawListeners.size, 1);
  const control = session.sendOwned("next", { type: "follow_up", message: "next" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  const update = { type: "message_update", scope: agent.rootScope, value: "one public copy" };
  agent.emit(update);
  agent.emitRaw(update);
  agent.emitRaw(terminalEvent({ scope: agent.rootScope, text: "raw terminal must not stream" }));
  const next = attemptScope(2, "promoted");
  agent.emit({ type: "agent_start", scope: next });
  agent.inputs[0].execute(next, "promoted-to-run");
  await waitForImmediate(() => control.phase === "active");
  let rootSettled = false;
  void root.then(() => { rootSettled = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(rootSettled, false, "raw execution alone is not root prompt finalization");
  agent.root.resolve();
  assert.deepEqual(await root, { disposition: "completed" });
  assert.equal(cohort.ended, false);
  assert.equal(cohort.outcome, undefined);
  assert.equal(session.inputRouter.record(agent.rootScope).terminal, undefined);
  assert.equal(control.phase, "active");
  assert.equal(events.filter((event) => event.value === "one public copy").length, 1);
  assert.doesNotMatch(JSON.stringify(events), /raw terminal must not stream|agent_end/);
  // Only the promoted handle publishes a genuine SDK terminal in this oracle.
  agent.inputs[0].complete(next);
  agent.emit(terminalEvent({ scope: next }));
  assert.deepEqual(await control.result, { disposition: "completed" });
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
  await session.dispose();
});

test("prompt fulfillment and unowned or continuing raw events cannot settle a root", async (t) => {
  const cases = [
    ["fulfillment alone", () => []],
    ["unscoped terminal", () => [terminalEvent()]],
    ["foreign attempt", (scope) => [terminalEvent({ scope: { ...scope, attemptId: "foreign" } })]],
    ["foreign generation", (scope) => [terminalEvent({ scope: { ...scope, generation: 99 } })]],
    ["foreign lineage", (scope) => [terminalEvent({ scope: { ...scope, lineage: "foreign" } })]],
    ["raw-only scope proof", () => [
      { type: "agent_start", scope: attemptScope(99) }, terminalEvent({ scope: attemptScope(99) }),
    ]],
    ["earlier success invalidated by continuing maintenance", (scope) => [
      terminalEvent({ scope }),
      terminalEvent({ scope, stopReason: "maintenance", maintenanceOutcome: "compacted" }),
    ]],
    ...["pruned", "compacted", "promoted"].map((maintenanceOutcome) => [maintenanceOutcome, (scope) => [
      terminalEvent({ scope, stopReason: "maintenance", maintenanceOutcome }),
    ]]),
  ];
  for (const [name, rawEvents] of cases) await t.test(name, async () => {
    const agent = new TrackedAgentSession();
    const session = new SdkSession(agent);
    const root = session.send({ type: "prompt", message: "root" }, () => {});
    let settled = false;
    void root.then(() => { settled = true; }, () => { settled = true; });
    await waitForImmediate(() => agent.calls.length === 1);
    agent.root.resolve();
    for (const event of rawEvents(agent.rootScope)) agent.emitRaw(event);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
    assert.equal(session.inputRouter.primary.ended, false);
    const check = assert.rejects(root, /disposed/);
    await session.dispose();
    await check;
    assert.equal(agent.listeners.size, 0);
    assert.equal(agent.rawListeners.size, 0);
  });
});

test("raw evidence observed before SDK scope proof cannot be reused after prompt fulfillment", async () => {
  const agent = new TrackedAgentSession();
  agent.prompt = (message) => {
    agent.calls.push(["prompt", message]);
    agent.emitRaw(terminalEvent({ scope: agent.rootScope }));
    agent.emit({ type: "agent_start", scope: agent.rootScope });
    return agent.root.promise;
  };
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  let settled = false;
  void root.then(() => { settled = true; });
  await waitForImmediate(() => agent.calls.length === 1);
  agent.root.resolve();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  agent.emitRaw(terminalEvent({ scope: agent.rootScope }));
  assert.deepEqual(await root, { disposition: "completed" });
  assert.equal(agent.rawListeners.size, 0);
  await session.dispose();
});

test("post-start foreign public tuples cannot stream or settle a fulfilled root prompt", async (t) => {
  for (const change of [
    { attemptId: "foreign" }, { generation: 99 }, { lineage: "child" },
  ]) {
    for (const ownProof of [false, true]) await t.test(`${JSON.stringify(change)}: own proof ${ownProof}`, async () => {
      const agent = new TrackedAgentSession();
      const timers = createManualTimeouts();
      const session = new SdkSession(agent, {
        idleTimeoutMs: 100, hardCapMs: 1_000,
        setTimeoutFn: timers.setTimeout, clearTimeoutFn: timers.clearTimeout,
      });
      const events = [];
      const root = session.send({ type: "prompt", message: "root" }, (event) => events.push(event));
      const check = assert.rejects(root, (error) => ownProof
        ? error.code === "SDK_TRACKED_INPUT_CONTRACT"
        : error.terminalDisposition === "timed_out");
      let settled = false;
      void root.then(() => { settled = true; }, () => { settled = true; });
      await waitForImmediate(() => agent.calls.length === 1);
      const cohort = session.inputRouter.primary;
      const foreign = { ...agent.rootScope, ...change };
      agent.emit({ type: "message_update", scope: foreign, value: "foreign private output" });
      agent.emit({ type: "agent_failed", scope: foreign, error: { code: "foreign_failure", message: "private diagnostic" } });
      agent.emit(terminalEvent({ scope: foreign }));
      agent.emitRaw(terminalEvent({ scope: foreign }));
      agent.root.resolve();
      agent.emit({ type: "message_update", scope: agent.rootScope, value: "own output" });
      agent.emit({ type: "turn_start", scope: agent.rootScope });
      session.inputRouter.flush();
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(settled, false, "foreign SDK-public events plus own prompt fulfillment are not own completion proof");
      assert.equal(cohort.ended, false);
      assert.equal(cohort.rawOutcome, undefined);
      const record = session.inputRouter.record(foreign);
      assert.equal(record.cohort, undefined);
      assert.equal(record.terminal, undefined);
      assert.deepEqual(record.failure, { code: "foreign_failure", message: "Prompt submission failed." });
      assert.deepEqual(events.filter((event) => event.value).map((event) => event.value), ["own output"]);
      assert.doesNotMatch(JSON.stringify([events, record]), /private|agent_failed|agent_end/);
      if (ownProof) agent.emit(terminalEvent({ scope: agent.rootScope }));
      else timers.advance(100);
      await check;
      assert.equal(cohort.ended, ownProof);
      if (ownProof) assert.deepEqual(cohort.outcome, { disposition: "completed" });
      assert.equal(session.closed, true, "unresolved foreign output cannot survive command cleanup");
      await session.dispose();
      assert.equal(agent.listeners.size, 0);
      assert.equal(agent.rawListeners.size, 0);
      assert.equal(session.inputRouter.buffer.length, 0);
      assert.equal(session.inputRouter.bufferBytes, 0);
      assert.equal(session.inputRouter.scopes.size, 0);
      assert.equal(session.adapterWaiterCancellations.size, 0);
      assert.equal(timers.size, 0);
    });
  }
});

test("root result chooses the latest proven primary continuation, not an earlier raw success", async (t) => {
  for (const stopReason of ["completed", "paused"]) await t.test(stopReason, async () => {
    const agent = new TrackedAgentSession();
    const session = new SdkSession(agent);
    const root = session.send({ type: "prompt", message: "root" }, () => {});
    let settled = false;
    void root.then(() => { settled = true; }, () => { settled = true; });
    await waitForImmediate(() => agent.calls.length === 1);
    agent.emitRaw(terminalEvent({ scope: agent.rootScope }));
    const final = attemptScope(2, "primary-continuation");
    agent.emit({ type: "turn_start", scope: final });
    agent.root.resolve();
    agent.emitRaw(terminalEvent({ scope: agent.rootScope }));
    agent.emitRaw(terminalEvent({ scope: attemptScope(99, "unrelated-latest") }));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
    const check = stopReason === "completed"
      ? root.then((outcome) => assert.deepEqual(outcome, { disposition: "completed" }))
      : assert.rejects(root, (error) => error.terminalDisposition === "paused");
    agent.emitRaw(terminalEvent({ scope: final, stopReason }));
    await check;
    assert.equal(agent.listeners.size, 0);
    assert.equal(agent.rawListeners.size, 0);
    await session.dispose();
  });
});

test("raw root classification and late exact SDK prompt rejection cannot report success", async (t) => {
  const cases = [
    { name: "failed", terminal: { stopReason: "failed" }, disposition: "failed", code: "prompt_failed" },
    { name: "cancelled", terminal: { stopReason: "cancelled" }, disposition: "cancelled", code: "aborted" },
    { name: "paused", terminal: { stopReason: "paused" }, disposition: "paused" },
    { name: "provider failure", terminal: { messages: [assistantMessage("private", { stopReason: "error", errorStatus: 429 })] }, disposition: "failed", code: "provider_http_429" },
    { name: "raw diagnostic", diagnostic: true, terminal: {}, disposition: "failed", code: "provider_unavailable" },
    { name: "maintenance failure", terminal: { stopReason: "maintenance", maintenanceOutcome: "failed" }, disposition: "failed", code: "context_maintenance_failed" },
    { name: "late SDK rejection", rejection: true, terminal: {}, disposition: "failed", code: "submission_failed" },
  ];
  for (const fixture of cases) await t.test(fixture.name, async () => {
    const agent = new TrackedAgentSession();
    const session = new SdkSession(agent);
    const events = [];
    const root = session.send({ type: "prompt", message: "root" }, (event) => events.push(event));
    const check = assert.rejects(root, (error) => {
      assert.equal(error.terminalDisposition, fixture.disposition);
      if (fixture.code) assert.equal(error.code, fixture.code);
      assert.doesNotMatch(error.message, /private secret/);
      return true;
    });
    await waitForImmediate(() => agent.calls.length === 1);
    if (fixture.diagnostic) agent.emitRaw({
      type: "agent_failed", scope: agent.rootScope,
      error: { code: "provider_unavailable", message: "private secret" },
    });
    agent.emitRaw(terminalEvent({ scope: agent.rootScope, ...fixture.terminal }));
    if (fixture.rejection) agent.root.reject(Object.assign(new Error("private secret"), { code: "submission_failed" }));
    else agent.root.resolve();
    await check;
    assert.doesNotMatch(JSON.stringify(events), /private secret|agent_failed|agent_end/);
    assert.equal(agent.listeners.size, 0);
    assert.equal(agent.rawListeners.size, 0);
    await session.dispose();
  });
});

test("late scoped SDK and raw diagnostics defeat completed raw proof before own prompt fulfills", async (t) => {
  for (const lane of ["public", "raw"]) {
    for (const code of ["provider_unavailable", "invalid private code"]) await t.test(`${lane}: ${code}`, async () => {
      const agent = new TrackedAgentSession();
      const session = new SdkSession(agent);
      const events = [];
      const root = session.send({ type: "prompt", message: "root" }, (event) => events.push(event));
      const check = assert.rejects(root, (error) => {
        assert.equal(error.terminalDisposition, "failed");
        assert.equal(error.code, code === "provider_unavailable" ? code : "prompt_failed");
        assert.doesNotMatch(error.message, /private/);
        return true;
      });
      await waitForImmediate(() => agent.calls.length === 1);
      const cohort = session.inputRouter.primary;
      const record = session.inputRouter.record(agent.rootScope);
      agent.emitRaw(terminalEvent({ scope: agent.rootScope, text: "private raw body" }));
      const diagnostic = { type: "agent_failed", scope: agent.rootScope, error: { code, message: "private diagnostic body" } };
      if (lane === "public") agent.emit(diagnostic);
      else agent.emitRaw(diagnostic);
      let settled = false;
      void root.then(() => { settled = true; }, () => { settled = true; });
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(settled, false, "failure evidence still awaits the exact SDK prompt settlement");
      agent.root.resolve();
      await check;
      assert.equal(cohort.ended, false);
      assert.equal(cohort.outcome, undefined);
      assert.equal(record.terminal, undefined);
      assert.doesNotMatch(JSON.stringify([events, record, cohort.rawOutcome, cohort.rawFailure]), /private|messages|agent_failed|agent_end/);
      assert.equal(agent.listeners.size, 0);
      assert.equal(agent.rawListeners.size, 0);
      await session.dispose();
    });
  }
});

test("late diagnostic scope and terminal precedence remain exact for raw root results", async (t) => {
  const cases = [
    { name: "unscoped", scopes: () => [undefined], terminal: {}, disposition: "completed" },
    { name: "foreign", scopes: (scope) => [
      { ...scope, attemptId: "foreign" }, { ...scope, generation: 99 }, { ...scope, lineage: "foreign" },
    ], terminal: {}, disposition: "completed" },
    { name: "paused", terminal: { stopReason: "paused" }, disposition: "paused" },
    { name: "cancelled", terminal: { stopReason: "cancelled" }, disposition: "cancelled", code: "aborted" },
    { name: "maintenance failed", terminal: { stopReason: "maintenance", maintenanceOutcome: "failed" }, disposition: "failed", code: "context_maintenance_failed" },
    { name: "maintenance aborted", terminal: { stopReason: "maintenance", maintenanceOutcome: "aborted" }, disposition: "failed", code: "aborted" },
    { name: "provider rejected", terminal: { messages: [assistantMessage("private", { stopReason: "error", errorStatus: 429 })] }, disposition: "failed", code: "provider_http_429" },
  ];
  for (const fixture of cases) await t.test(fixture.name, async () => {
    const agent = new TrackedAgentSession();
    const session = new SdkSession(agent);
    const events = [];
    const root = session.send({ type: "prompt", message: "root" }, (event) => events.push(event));
    const check = fixture.disposition === "completed"
      ? root.then((outcome) => assert.deepEqual(outcome, { disposition: "completed" }))
      : assert.rejects(root, (error) => {
        assert.equal(error.terminalDisposition, fixture.disposition);
        if (fixture.code) assert.equal(error.code, fixture.code);
        assert.doesNotMatch(error.message, /private|late_failure/);
        return true;
      });
    await waitForImmediate(() => agent.calls.length === 1);
    agent.emitRaw(terminalEvent({ scope: agent.rootScope, ...fixture.terminal }));
    for (const scope of fixture.scopes?.(agent.rootScope) ?? [agent.rootScope]) {
      const diagnostic = { type: "agent_failed", scope, error: { code: "late_failure", message: "private body" } };
      agent.emit(diagnostic);
      agent.emitRaw(diagnostic);
    }
    agent.root.resolve();
    await check;
    assert.doesNotMatch(JSON.stringify(events), /private|agent_failed|agent_end/);
    assert.equal(agent.listeners.size, 0);
    assert.equal(agent.rawListeners.size, 0);
    await session.dispose();
  });
});

test("a raw-completed root still awaits genuine tracked receipts and a later SDK publication is not a duplicate", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("joined", { type: "steer", message: "joined" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.inputs[0].execute(agent.rootScope);
  await waitForImmediate(() => control.phase === "active");
  agent.emitRaw(terminalEvent({ scope: agent.rootScope }));
  agent.root.resolve();
  assert.deepEqual(await root, { disposition: "completed" });
  let settled = false;
  void control.result.then(() => { settled = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false, "raw evidence cannot synthesize handle.terminal");
  agent.inputs[0].complete(agent.rootScope);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false, "a handle receipt still requires its genuine SDK-public terminal");
  assert.equal(session.inputRouter.record(agent.rootScope).terminal, undefined);
  agent.emit(terminalEvent({ scope: agent.rootScope }));
  assert.deepEqual(await control.result, { disposition: "completed" });
  assert.equal(session.closed, false);
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
  await session.dispose();
});

test("raw root proof leaves true SDK gate overlap unowned and bounded", async () => {
  const agent = new TrackedAgentSession();
  const emitter = new FakeGateEmitter();
  agent.getWorkflowGateEmitter = () => emitter;
  const timers = createManualTimeouts();
  const session = new SdkSession(agent, {
    idleTimeoutMs: 100, hardCapMs: 1_000, gateAnswerWindowMs: 50,
    setTimeoutFn: timers.setTimeout, clearTimeoutFn: timers.clearTimeout,
  });
  const events = [];
  const root = session.send({ type: "prompt", message: "root" }, (event) => events.push(event));
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("next", { type: "follow_up", message: "next" }, (event) => events.push(event));
  const controlCheck = assert.rejects(control.result, (error) => error.code === "SDK_TRACKED_INPUT_GATE_OWNERSHIP");
  await waitForImmediate(() => agent.inputs.length === 1);
  const next = attemptScope(2, "next");
  agent.emit({ type: "agent_start", scope: next });
  agent.inputs[0].execute(next, "promoted-to-run");
  await waitForImmediate(() => control.phase === "active");
  agent.emitRaw(terminalEvent({ scope: agent.rootScope }));
  agent.root.resolve();
  assert.deepEqual(await root, { disposition: "completed" });
  const gate = emitter.emitGate(sdkAskGate({ gate_id: "raw-does-not-retire-root" }));
  const gateCheck = assert.rejects(gate, /fenced/);
  assert.equal(session.inputRouter.primary.ended, false);
  assert.equal(session.pendingGates.size, 0);
  assert.equal(session.inputRouter.hasPendingGate(), true);
  assert.equal(events.some((event) => event.type === "gate_request"), false);
  assert.deepEqual(emitter.resolveCalls, []);
  timers.advance(50);
  await Promise.all([controlCheck, gateCheck]);
  await session.dispose();
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
  assert.equal(emitter.listeners.size, 0);
  assert.equal(timers.size, 0);
});

test("missing or failing public core subscription closes without leaking either listener", async (t) => {
  const cases = [
    ["missing agent", (agent) => { agent.agent = undefined; }],
    ["missing subscribe", (agent) => { agent.agent = {}; }],
    ["throwing core subscribe", (agent) => { agent.agent.subscribe = () => { throw new Error("core subscription failed"); }; }],
    ["core missing disposal", (agent) => { agent.agent.subscribe = () => undefined; }],
    ["throwing session subscribe", (agent) => { agent.subscribe = () => { throw new Error("session subscription failed"); }; }],
    ["session missing disposal", (agent) => { agent.subscribe = () => undefined; }],
  ];
  for (const [name, configure] of cases) await t.test(name, async () => {
    const agent = new FakeAgentSession();
    configure(agent);
    const session = new SdkSession(agent);
    await assert.rejects(session.send({ type: "prompt", message: "root" }, () => {}), (error) => {
      if (name.startsWith("missing")) assert.equal(error.code, "SDK_TRACKED_INPUT_CONTRACT");
      return /subscribe|subscription|disposal/.test(error.message);
    });
    await session.dispose();
    assert.equal(session.closed, true);
    assert.equal(session.activePromptRuns, 0);
    assert.equal(session.activeGateRuns.length, 0);
    assert.equal(agent.listeners.size, 0);
    assert.equal(agent.rawListeners.size, 0);
    assert.equal(agent.calls.length, 0);
    assert.equal(agent.disposeCalls, 1);
  });
});

test("fatal raw evidence closes both subscriptions without exposing raw getter failures", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const check = assert.rejects(root, (error) => {
    assert.equal(error.code, "SDK_TRACKED_INPUT_CONTRACT");
    assert.doesNotMatch(error.message, /private secret/);
    return true;
  });
  await waitForImmediate(() => agent.calls.length === 1);
  agent.emitRaw({
    type: "agent_end", scope: agent.rootScope,
    get stopReason() { throw new Error("private secret"); },
  });
  await check;
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
  await session.dispose();
});

test("root success is published only after both subscription cleanups succeed", async () => {
  const agent = new FakeAgentSession();
  const subscribe = agent.agent.subscribe;
  agent.agent.subscribe = (listener) => {
    const unsubscribe = subscribe(listener);
    return () => { unsubscribe(); throw new Error("core subscription cleanup failed"); };
  };
  const session = new SdkSession(agent);
  await assert.rejects(
    session.send({ type: "prompt", message: "root" }, () => {}),
    /core subscription cleanup failed/,
  );
  assert.equal(session.closed, true);
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
  await session.dispose();
});

test("both live delivery modes use distinct public tracked handles and join the same run", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const primaryEvents = [];
  const controlEvents = [];
  const activations = [];
  const prompt = session.sendOwned("primary", { type: "prompt", message: "root" }, (event) => primaryEvents.push(event));
  const controls = ["steer", "follow_up"].map((type) => session.sendOwned(type,
    { type, message: "identical input" }, (event) => controlEvents.push(event), undefined,
    { onActivate: () => activations.push(type) }));
  await waitForImmediate(() => agent.inputs.length === 2);
  for (const [index, input] of agent.inputs.entries()) {
    assert.equal(input.options.deliverAs, index === 0 ? "steer" : "followUp");
    assert.equal(input.options.trackSubmission, true);
    assert.equal(input.options.queuePolicy, "sequential");
    assert.ok(input.options.preflightSignal instanceof AbortSignal);
    assert.deepEqual(Object.keys(input.options).sort(), [
      "deliverAs", "onPreflightAcceptCommit", "preflightSignal", "queuePolicy", "trackSubmission",
    ]);
    assert.equal(controls[index].phase, "queued");
  }
  assert.notEqual(agent.inputs[0].identity.submissionId, agent.inputs[1].identity.submissionId);
  const middle = attemptScope(2);
  agent.emit({ type: "turn_start", scope: middle });
  agent.inputs[0].execute(middle);
  agent.inputs[1].execute(middle);
  await waitForImmediate(() => controls.every((ticket) => ticket.phase === "active"));
  assert.deepEqual(activations, ["steer", "follow_up"]);
  for (const ticket of controls) assert.equal(ticket.revokeBeforeStart(), false);
  const final = attemptScope(3);
  agent.emit({ type: "turn_start", scope: final });
  agent.emit({ type: "message_update", scope: final, value: "shared output" });
  for (const input of agent.inputs) input.complete(final);
  agent.finishRoot(final);
  assert.deepEqual(await Promise.all([prompt.result, ...controls.map((ticket) => ticket.result)]), [
    { disposition: "completed" }, { disposition: "completed" }, { disposition: "completed" },
  ]);
  assert.equal(primaryEvents.filter((event) => event.type === "message_update").length, 1);
  assert.deepEqual(controlEvents, []);
  await waitForImmediate(() => !session.isBusy());
  assert.equal(agent.listeners.size, 0);
  assert.equal(session.isBusy(), false);
  await session.dispose();
});

test("SDK queue cancellation and a lost dequeue race have different authoritative results", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const cancelled = session.sendOwned("cancelled", { type: "steer", message: "same" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(cancelled.phase, "queued");
  assert.equal(cancelled.revokeBeforeStart(), true);
  assert.deepEqual(await cancelled.result, { revokedBeforeStart: true });
  const raced = session.sendOwned("raced", { type: "follow_up", message: "same" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 2);
  await new Promise((resolve) => setImmediate(resolve));
  agent.inputs[1].execute(agent.rootScope);
  // The SDK has consumed it, but promise reactions have not activated it yet.
  assert.equal(raced.phase, "queued");
  assert.equal(raced.revokeBeforeStart(), false);
  await waitForImmediate(() => raced.phase === "active");
  agent.inputs[1].complete(agent.rootScope);
  agent.finishRoot();
  assert.deepEqual(await raced.result, { disposition: "completed" });
  await root;
  await session.dispose();
});

test("a promoted successor can start before predecessor terminal and receipt reactions", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const primaryEvents = [];
  const successorEvents = [];
  const root = session.send({ type: "prompt", message: "root" }, (event) => primaryEvents.push(event));
  await waitForImmediate(() => agent.calls.length === 1);
  const successor = session.sendOwned("next", { type: "follow_up", message: "next" }, (event) => successorEvents.push(event));
  await waitForImmediate(() => agent.inputs.length === 1);
  const next = attemptScope(2, "successor");
  agent.emit({ type: "agent_start", scope: next });
  agent.emit({ type: "message_update", scope: next, value: "successor-only" });
  assert.equal(primaryEvents.some((event) => event.value === "successor-only"), false);
  assert.deepEqual(successorEvents, []);
  agent.inputs[0].execute(next, "promoted-to-run");
  agent.finishRoot();
  await root;
  await waitForImmediate(() => successor.phase === "active");
  assert.equal(successorEvents.some((event) => event.value === "successor-only"), true);
  const final = attemptScope(3, "successor-final");
  agent.emit({ type: "turn_start", scope: final });
  agent.inputs[0].complete(final);
  agent.emit(terminalEvent({ scope: final }));
  assert.deepEqual(await successor.result, { disposition: "completed" });
  assert.equal(primaryEvents.some((event) => event.value === "successor-only"), false);
  assert.equal(agent.listeners.size, 0);
  await session.dispose();
});

test("tracked lifecycle completion classifies the matching FINAL public terminal", async (t) => {
  const cases = [
    { name: "provider failure", terminal: { messages: [assistantMessage("partial", { stopReason: "error", errorCode: "provider_down" })] }, code: "provider_down", disposition: "failed" },
    { name: "cancelled", terminal: { stopReason: "cancelled" }, code: "aborted", disposition: "cancelled" },
    { name: "paused", terminal: { stopReason: "paused" }, disposition: "paused" },
    { name: "maintenance failure", terminal: { stopReason: "maintenance", maintenanceOutcome: "failed" }, code: "context_maintenance_failed", disposition: "failed" },
    { name: "scoped diagnostic", diagnostic: "provider_unavailable", terminal: {}, code: "provider_unavailable", disposition: "failed" },
  ];
  for (const fixture of cases) await t.test(fixture.name, async () => {
    const agent = new TrackedAgentSession();
    const session = new SdkSession(agent);
    const root = session.send({ type: "prompt", message: "root" }, () => {});
    const rootCheck = assert.rejects(root, (error) => error.terminalDisposition === fixture.disposition);
    await waitForImmediate(() => agent.calls.length === 1);
    const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
    const controlCheck = assert.rejects(control.result, (error) => {
      assert.equal(error.terminalDisposition, fixture.disposition);
      assert.equal(error.code, fixture.code);
      assert.doesNotMatch(error.message, /private provider secret/);
      return true;
    });
    await waitForImmediate(() => agent.inputs.length === 1);
    agent.inputs[0].execute(agent.rootScope);
    await waitForImmediate(() => control.phase === "active");
    const final = attemptScope(2);
    agent.emit({ type: "turn_start", scope: final });
    if (fixture.diagnostic) agent.emit({ type: "agent_failed", scope: final,
      error: { code: fixture.diagnostic, message: "private provider secret" } });
    agent.inputs[0].complete(final);
    agent.finishRoot(final, fixture.terminal);
    await Promise.all([rootCheck, controlCheck]);
    await session.dispose();
  });
});

test("malformed tracked identities, policies, and scopes fail explicitly and dispose sibling waiters", async (t) => {
  const cases = [
    { name: "admission id", change: (input) => input.admitted.resolve({ ...input.identity, submissionId: "wrong", queuePolicy: "sequential" }) },
    { name: "admission delivery", change: (input) => input.admitted.resolve({ ...input.identity, delivery: "followUp", queuePolicy: "sequential" }) },
    { name: "queue policy", change: (input) => input.admitted.resolve({ ...input.identity, queuePolicy: "respect-mode" }) },
    { name: "execution id", change: (input) => input.execution.resolve({ ...input.identity, submissionId: "wrong", disposition: "joined-current-run", attemptScope: attemptScope(1) }) },
    { name: "execution delivery", change: (input) => input.execution.resolve({ ...input.identity, delivery: "followUp", disposition: "joined-current-run", attemptScope: attemptScope(1) }) },
    { name: "execution scope", change: (input) => input.execution.resolve({ ...input.identity, disposition: "joined-current-run", attemptScope: { attemptId: "missing-parts" } }) },
    { name: "terminal id", execute: true, change: (input) => input.terminal.resolve({ ...input.identity, submissionId: "wrong", disposition: "completed", attemptScope: attemptScope(1) }) },
    { name: "terminal delivery", execute: true, change: (input) => input.terminal.resolve({ ...input.identity, delivery: "followUp", disposition: "completed", attemptScope: attemptScope(1) }) },
    { name: "terminal scope", execute: true, change: (input) => input.terminal.resolve({ ...input.identity, disposition: "completed", attemptScope: { attemptId: "missing-parts" } }) },
    { name: "executed then removed", execute: true, change: (input) => input.terminal.resolve({ ...input.identity, disposition: "removed", reason: "cancelled" }) },
  ];
  for (const fixture of cases) await t.test(fixture.name, async () => {
    const agent = new TrackedAgentSession();
    // Hold admission so each malformed receipt is the first actual settlement.
    const submit = agent.submitUserMessage.bind(agent);
    agent.submitUserMessage = (message, options) => {
      const result = submit(message, options);
      const input = agent.inputs.at(-1);
      const admitted = trackedDeferred();
      input.admitted = admitted;
      return result.then((handle) => ({ ...handle, admitted: admitted.promise }));
    };
    const session = new SdkSession(agent);
    const root = session.send({ type: "prompt", message: "root" }, () => {});
    const rootCheck = assert.rejects(root, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
    await waitForImmediate(() => agent.calls.length === 1);
    const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
    const controlCheck = assert.rejects(control.result, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
    await waitForImmediate(() => agent.inputs.length === 1);
    const input = agent.inputs[0];
    if (!fixture.name.startsWith("admission") && fixture.name !== "queue policy") {
      input.admitted.resolve({ ...input.identity, queuePolicy: "sequential" });
    }
    if (fixture.execute) input.execute(agent.rootScope);
    fixture.change(input);
    await Promise.all([rootCheck, controlCheck]);
    assert.equal(session.closed, true);
    await session.dispose();
    assert.equal(agent.listeners.size, 0);
    assert.equal(session.adapterWaiterCancellations.size, 0);
  });
});

test("queue removal is not a final ticket result until both removed receipts match", async () => {
  const agent = new TrackedAgentSession();
  const submit = agent.submitUserMessage.bind(agent);
  agent.submitUserMessage = (message, options) => submit(message, options).then((handle) => ({
    ...handle,
    cancel: () => {
      const input = agent.inputs.at(-1);
      input.execution.resolve({ ...input.identity, disposition: "removed", reason: "cancelled" });
      return true;
    },
  }));
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  await new Promise((resolve) => setImmediate(resolve));
  let settled = false;
  void control.result.then(() => { settled = true; });
  assert.equal(control.revokeBeforeStart(), true);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  assert.equal(control.phase, "queued");
  const input = agent.inputs[0];
  input.terminal.resolve({ ...input.identity, disposition: "removed", reason: "cancelled" });
  assert.deepEqual(await control.result, { revokedBeforeStart: true });
  agent.finishRoot();
  await root;
  await session.dispose();
});

test("a completed tracked receipt still waits for its exact scoped genuine terminal", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.inputs[0].execute(agent.rootScope);
  await waitForImmediate(() => control.phase === "active");
  const final = attemptScope(2);
  agent.inputs[0].complete(final);
  agent.emit(terminalEvent({ scope: agent.rootScope, stopReason: "maintenance", maintenanceOutcome: "compacted" }));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(control.phase, "active");
  agent.emit({ type: "turn_start", scope: final });
  agent.finishRoot(final);
  assert.deepEqual(await control.result, { disposition: "completed" });
  await root;
  await session.dispose();
});

test("a mismatched final scope cannot borrow a completed cohort terminal", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
  const check = assert.rejects(control.result, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.inputs[0].execute(agent.rootScope);
  await waitForImmediate(() => control.phase === "active");
  agent.finishRoot();
  await root;
  agent.inputs[0].complete(attemptScope(9, "wrong-final"));
  await check;
  assert.equal(session.closed, true);
  await session.dispose();
});

test("an unseen final public scope waits for the genuine handle terminal reaction", async (t) => {
  for (const diagnostic of [undefined, "provider_unavailable"]) await t.test(diagnostic ?? "completed", async () => {
    const agent = new TrackedAgentSession();
    const session = new SdkSession(agent);
    const events = [];
    const root = session.send({ type: "prompt", message: "root" }, (event) => events.push(event));
    const rootCheck = diagnostic
      ? assert.rejects(root, (error) => error.code === diagnostic)
      : root.then((outcome) => assert.deepEqual(outcome, { disposition: "completed" }));
    await waitForImmediate(() => agent.calls.length === 1);
    const control = session.sendOwned("joined", { type: "steer", message: "joined" }, () => {});
    const controlCheck = diagnostic
      ? assert.rejects(control.result, (error) => error.code === diagnostic)
      : control.result.then((outcome) => assert.deepEqual(outcome, { disposition: "completed" }));
    await waitForImmediate(() => agent.inputs.length === 1);
    agent.inputs[0].execute(agent.rootScope);
    await waitForImmediate(() => control.phase === "active");
    const final = { ...attemptScope(2, "changed-final"), lineage: "final-lineage" };
    agent.emit({ type: "message_update", scope: final, value: "authorized final output" });
    if (diagnostic) agent.emit({ type: "agent_failed", scope: final, error: { code: diagnostic, message: "private diagnostic" } });
    agent.emit(terminalEvent({ scope: final, text: "private terminal body" }));
    agent.root.resolve();
    agent.emit({ type: "message_update", scope: agent.rootScope, value: "own flush" });
    await new Promise((resolve) => setImmediate(resolve));
    const record = session.inputRouter.record(final);
    assert.equal(record.cohort, undefined);
    assert.equal(record.terminal, undefined);
    assert.equal(session.inputRouter.primary.ended, false);
    assert.equal(control.phase, "active");
    assert.equal(events.some((event) => event.value === "authorized final output"), false);
    // No public start introduced this tuple. Only the actual SDK handle's
    // completed receipt may authorize its already-buffered public terminal.
    agent.inputs[0].complete(final);
    assert.equal(record.cohort, undefined, "promise fulfillment precedes its adapter reaction");
    await Promise.all([rootCheck, controlCheck]);
    assert.equal(events.filter((event) => event.value === "authorized final output").length, 1);
    assert.doesNotMatch(JSON.stringify(events), /private|agent_failed|agent_end/);
    assert.equal(session.closed, false);
    assert.equal(agent.listeners.size, 0);
    assert.equal(agent.rawListeners.size, 0);
    assert.equal(session.inputRouter.buffer.length, 0);
    await session.dispose();
  });
});

test("duplicate unseen final terminals fail when the genuine receipt binds their scope", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("joined", { type: "steer", message: "joined" }, () => {});
  const controlCheck = assert.rejects(control.result, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.inputs[0].execute(agent.rootScope);
  await waitForImmediate(() => control.phase === "active");
  const final = attemptScope(2, "final");
  agent.emit(terminalEvent({ scope: final }));
  agent.emit(terminalEvent({ scope: final }));
  assert.equal(session.inputRouter.primary.ended, false);
  agent.inputs[0].complete(final);
  await Promise.all([rootCheck, controlCheck]);
  assert.equal(session.closed, true);
  await session.dispose();
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
  assert.equal(session.inputRouter.buffer.length, 0);
  assert.equal(session.adapterWaiterCancellations.size, 0);
});

test("an unscoped diagnostic buffered before promotion cannot fail the scoped successor", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const rootEvents = [];
  const successorEvents = [];
  const root = session.send({ type: "prompt", message: "root" }, (event) => rootEvents.push(event));
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("next", { type: "follow_up", message: "next" }, (event) => successorEvents.push(event));
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.emit(terminalEvent({ scope: agent.rootScope }));
  const next = attemptScope(2, "next");
  agent.emit({ type: "agent_start", scope: next });
  agent.emit({ type: "agent_failed", error: { code: "unscoped_failure", message: "private diagnostic" } });
  agent.emit({ type: "message_update", scope: next, value: "successor output" });
  assert.equal(successorEvents.length, 0);
  assert.equal(rootEvents.some((event) => event.value === "successor output"), false);
  agent.inputs[0].execute(next, "promoted-to-run");
  await waitForImmediate(() => control.phase === "active");
  assert.equal(session.inputRouter.record(next).failure, undefined);
  assert.equal(successorEvents.filter((event) => event.value === "successor output").length, 1);
  assert.doesNotMatch(JSON.stringify([rootEvents, successorEvents]), /private|agent_failed|unscoped_failure/);
  agent.inputs[0].complete(next);
  agent.emit(terminalEvent({ scope: next }));
  agent.root.resolve();
  assert.deepEqual(await control.result, { disposition: "completed" });
  assert.deepEqual(await root, { disposition: "completed" });
  assert.equal(session.closed, false);
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
  assert.equal(session.inputRouter.buffer.length, 0);
  await session.dispose();
});

test("joined controls retain a primary prompt rejection after an otherwise completed terminal", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, (error) => error.code === "submission_failed");
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
  const controlCheck = assert.rejects(control.result, (error) => error.code === "submission_failed");
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.inputs[0].execute(agent.rootScope);
  await waitForImmediate(() => control.phase === "active");
  agent.inputs[0].complete(agent.rootScope);
  agent.emit(terminalEvent({ scope: agent.rootScope }));
  agent.root.reject(Object.assign(new Error("private provider secret"), { code: "submission_failed" }));
  await Promise.all([rootCheck, controlCheck]);
  await session.dispose();
});

test("root/model commands cannot overtake tracked admission and do not block later live admission", async () => {
  const agent = new TrackedAgentSession();
  const admission = trackedDeferred();
  const submit = agent.submitUserMessage.bind(agent);
  agent.submitUserMessage = (message, options) => {
    const result = submit(message, options);
    return agent.inputs.length === 1 ? admission.promise.then(() => result) : result;
  };
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const first = session.sendOwned("first", { type: "follow_up", message: "first" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  const model = session.send({ type: "set_model", provider: "provider-a", modelId: "model-a" }, () => {});
  agent.finishRoot();
  await root;
  const second = session.sendOwned("second", { type: "steer", message: "second" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 2);
  assert.deepEqual(agent.calls, [["prompt", "root"]]);
  const successor = attemptScope(2, "successor");
  agent.emit({ type: "agent_start", scope: successor });
  agent.inputs[0].execute(successor, "promoted-to-run");
  admission.resolve();
  await waitForImmediate(() => first.phase === "active");
  agent.inputs[1].execute(successor);
  await waitForImmediate(() => second.phase === "active");
  for (const input of agent.inputs) input.complete(successor);
  agent.emit(terminalEvent({ scope: successor }));
  await Promise.all([first.result, second.result, model]);
  assert.deepEqual(agent.calls.map(([type]) => type), ["prompt", "set_model"]);
  await session.dispose();
});

test("admission cancellation proves pre-start only before its public acceptance commit", async () => {
  const agent = new TrackedAgentSession();
  const preflight = trackedDeferred();
  const submit = agent.submitUserMessage.bind(agent);
  let publicOptions;
  agent.submitUserMessage = async (message, options) => {
    publicOptions = options;
    await preflight.promise;
    if (options.preflightSignal.aborted) throw Object.assign(new Error("revoked"), { code: "prompt_preflight_cancelled" });
    return submit(message, options);
  };
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
  await waitForImmediate(() => publicOptions !== undefined);
  assert.equal(control.revokeBeforeStart(), true);
  assert.equal(publicOptions.preflightSignal.aborted, true);
  assert.deepEqual(await control.result, { revokedBeforeStart: true });
  preflight.resolve();
  await waitForImmediate(() => session.trackedWork.size === 0);
  assert.equal(agent.inputs.length, 0);
  assert.equal(session.closed, false);
  agent.finishRoot();
  await root;
  await session.dispose();
});

test("after acceptance commit but before handle delivery revoke cannot claim removal", async () => {
  const agent = new TrackedAgentSession();
  const handleDelivery = trackedDeferred();
  const submit = agent.submitUserMessage.bind(agent);
  agent.submitUserMessage = (message, options) => {
    const handle = submit(message, options);
    return handleDelivery.promise.then(() => handle);
  };
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  assert.equal(control.revokeBeforeStart(), false);
  assert.equal(control.phase, "queued");
  handleDelivery.resolve();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(control.revokeBeforeStart(), true);
  assert.deepEqual(await control.result, { revokedBeforeStart: true });
  agent.finishRoot();
  await root;
  await session.dispose();
});

test("close owns unsettled SDK admission and contains a late rejecting handle", async () => {
  const agent = new TrackedAgentSession();
  const admission = trackedDeferred();
  agent.submitUserMessage = () => admission.promise;
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, /disposed/);
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "steer", message: "control" }, () => {});
  const controlCheck = assert.rejects(control.result, /disposed/);
  await waitForImmediate(() => session.trackedWork.size === 1);
  await session.dispose();
  await Promise.all([rootCheck, controlCheck]);
  let cancelled = 0;
  admission.resolve({
    submissionId: "late", admitted: Promise.reject(new Error("late admission")),
    execution: Promise.reject(new Error("late execution")), terminal: Promise.reject(new Error("late terminal")),
    cancel: () => { cancelled += 1; return true; },
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(cancelled, 1);
  assert.equal(agent.listeners.size, 0);
  assert.equal(session.adapterWaiterCancellations.size, 0);
  assert.equal(session.trackedWork.size, 0);
});

test("joined controls do not borrow gate authority and never overwrite a host runtime provider", async () => {
  const agent = new TrackedAgentSession();
  const emitter = new FakeGateEmitter();
  let providerWrites = 0;
  emitter.setRuntimeTurnProvider = () => { providerWrites += 1; };
  agent.getWorkflowGateEmitter = () => emitter;
  const session = new SdkSession(agent);
  const rootEvents = [];
  const controlEvents = [];
  const root = session.sendOwned("primary", { type: "prompt", message: "root" }, (event) => rootEvents.push(event));
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("follower", { type: "follow_up", message: "follow" }, (event) => controlEvents.push(event));
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.inputs[0].execute(agent.rootScope);
  await waitForImmediate(() => control.phase === "active");
  const gate = emitter.emitGate(sdkAskGate({ gate_id: "joined-gate", options: [{ value: "yes", label: "Yes" }] }));
  const entry = session.pendingGates.get("joined-gate");
  assert.equal(entry.ownerId, "primary");
  assert.equal(controlEvents.length, 0);
  assert.equal(rootEvents.filter((event) => event.type === "gate_request").length, 1);
  assert.equal(session.presentGate("follower", "joined-gate", entry.presentationId, "wrong-owner"), false);
  await answerGate(session, "joined-gate", "Yes");
  await gate;
  agent.inputs[0].complete(agent.rootScope);
  agent.finishRoot();
  await Promise.all([root.result, control.result]);
  assert.equal(providerWrites, 0);
  await session.dispose();
});

test("a late public terminal callback still admits tracked control while root promise unwinds", async () => {
  const agent = new TrackedAgentSession();
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  await waitForImmediate(() => agent.calls.length === 1);
  agent.emit(terminalEvent({ scope: agent.rootScope }));
  const control = session.sendOwned("late", { type: "follow_up", message: "late" }, () => {});
  await waitForImmediate(() => agent.inputs.length === 1);
  assert.deepEqual(agent.calls, [["prompt", "root"]]);
  const next = attemptScope(2, "late-successor");
  agent.emit({ type: "agent_start", scope: next });
  agent.inputs[0].execute(next, "promoted-to-run");
  agent.root.resolve();
  await root;
  await waitForImmediate(() => control.phase === "active");
  agent.inputs[0].complete(next);
  agent.emit(terminalEvent({ scope: next }));
  await control.result;
  await session.dispose();
});

test("a unique promoted gate is buffered before execution receipt and presented only after activation", async () => {
  const agent = new TrackedAgentSession();
  const emitter = new FakeGateEmitter();
  agent.getWorkflowGateEmitter = () => emitter;
  const session = new SdkSession(agent);
  const rootEvents = [];
  const root = session.send({ type: "prompt", message: "root" }, (event) => rootEvents.push(event));
  await waitForImmediate(() => agent.calls.length === 1);
  let activated = false;
  const controlEvents = [];
  const control = session.sendOwned("promoted", { type: "follow_up", message: "next" }, (event) => {
    assert.equal(activated, true);
    controlEvents.push(event);
  }, undefined, { onActivate: () => { activated = true; } });
  await waitForImmediate(() => agent.inputs.length === 1);
  agent.finishRoot();
  const next = attemptScope(2, "next");
  agent.emit({ type: "agent_start", scope: next });
  const gate = emitter.emitGate(sdkAskGate({ gate_id: "promoted-gate" }));
  assert.equal(session.pendingGates.size, 0);
  assert.equal(session.inputRouter.hasPendingGate(), true);
  agent.inputs[0].execute(next, "promoted-to-run");
  await waitForImmediate(() => session.pendingGates.size === 1);
  const entry = session.pendingGates.get("promoted-gate");
  assert.equal(entry.ownerId, "promoted");
  assert.equal(rootEvents.some((event) => event.type === "gate_request"), false);
  assert.equal(controlEvents.filter((event) => event.type === "gate_request").length, 1);
  await answerGate(session, "promoted-gate", "answer");
  await gate;
  agent.inputs[0].complete(next);
  agent.emit(terminalEvent({ scope: next }));
  await Promise.all([root, control.result]);
  await session.dispose();
});

test("ambiguous overlapping gate ownership fails within the existing answer window", async () => {
  const agent = new TrackedAgentSession();
  const emitter = new FakeGateEmitter();
  agent.getWorkflowGateEmitter = () => emitter;
  const timers = createManualTimeouts();
  const session = new SdkSession(agent, {
    idleTimeoutMs: 100, hardCapMs: 1_000, gateAnswerWindowMs: 50,
    setTimeoutFn: timers.setTimeout, clearTimeoutFn: timers.clearTimeout,
  });
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, (error) => error.code === "SDK_TRACKED_INPUT_GATE_OWNERSHIP");
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("next", { type: "follow_up", message: "next" }, () => {});
  const controlCheck = assert.rejects(control.result, (error) => error.code === "SDK_TRACKED_INPUT_GATE_OWNERSHIP");
  await waitForImmediate(() => agent.inputs.length === 1);
  const next = attemptScope(2, "next");
  agent.emit({ type: "agent_start", scope: next });
  agent.inputs[0].execute(next, "promoted-to-run");
  await waitForImmediate(() => control.phase === "active");
  const gate = emitter.emitGate(sdkAskGate({ gate_id: "ambiguous-gate" }));
  const gateCheck = assert.rejects(gate, /fenced/);
  assert.equal(session.pendingGates.size, 0);
  assert.equal(session.inputRouter.hasPendingGate(), true);
  timers.advance(50);
  await Promise.all([rootCheck, controlCheck, gateCheck]);
  await session.dispose();
  assert.equal(session.closed, true);
  assert.equal(timers.size, 0);
  assert.equal(agent.listeners.size, 0);
  assert.equal(emitter.listeners.size, 0);
});

test("duplicate SDK submission identities fail instead of conflating equal or distinct text", async () => {
  const agent = new TrackedAgentSession();
  const submit = agent.submitUserMessage.bind(agent);
  agent.submitUserMessage = (message, options) => {
    const result = submit(message, options);
    const input = agent.inputs.at(-1);
    input.identity.submissionId = "duplicate-id";
    return result.then((handle) => ({ ...handle, submissionId: "duplicate-id",
      admitted: Promise.resolve({ ...input.identity, queuePolicy: "sequential" }),
    }));
  };
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await waitForImmediate(() => agent.calls.length === 1);
  const first = session.sendOwned("first", { type: "steer", message: "equal text" }, () => {});
  const firstCheck = assert.rejects(first.result, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await waitForImmediate(() => session.submissionIds.size === 1);
  const second = session.sendOwned("second", { type: "steer", message: "equal text" }, () => {});
  const secondCheck = assert.rejects(second.result, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await Promise.all([rootCheck, firstCheck, secondCheck]);
  await session.dispose();
  assert.equal(session.submissionIds.size, 0);
});

test("malformed public tracked handles are rejected without independent prompt subscribers", async (t) => {
  for (const [name, value] of [
    ["missing handle", undefined],
    ["missing lifecycle", { submissionId: "incomplete", cancel: () => true }],
    ["non-promise lifecycle", { submissionId: "non-promise", admitted: {}, execution: {}, terminal: {}, cancel: () => true }],
  ]) await t.test(name, async () => {
    const agent = new TrackedAgentSession();
    agent.submitUserMessage = () => Promise.resolve(value);
    const session = new SdkSession(agent);
    const root = session.send({ type: "prompt", message: "root" }, () => {});
    const rootCheck = assert.rejects(root, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
    await waitForImmediate(() => agent.calls.length === 1);
    await assert.rejects(session.send({ type: "steer", message: "control" }, () => {}),
      (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
    await rootCheck;
    await session.dispose();
    assert.equal(agent.listeners.size, 0);
  });
});

test("admitted tracked work waits without an execution idle timeout, then arms idle on consumption", async () => {
  const agent = new TrackedAgentSession();
  const timers = createManualTimeouts();
  const session = new SdkSession(agent, {
    idleTimeoutMs: 100, hardCapMs: 1_000,
    setTimeoutFn: timers.setTimeout, clearTimeoutFn: timers.clearTimeout,
  });
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, (error) => error.terminalDisposition === "timed_out");
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("queued", { type: "steer", message: "wait" }, () => {}, 30);
  const controlCheck = assert.rejects(control.result, (error) => error.terminalDisposition === "timed_out");
  await waitForImmediate(() => agent.inputs.length === 1);
  await new Promise((resolve) => setImmediate(resolve));
  timers.advance(31);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(session.closed, false, "waiting SDK input must not time out an unrelated active root");
  assert.equal(control.phase, "queued");
  agent.inputs[0].execute(agent.rootScope);
  await waitForImmediate(() => control.phase === "active");
  timers.advance(29);
  assert.equal(session.closed, false);
  timers.advance(1);
  await Promise.all([rootCheck, controlCheck]);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
  assert.equal(timers.size, 0);
});

test("tracked admission timeouts poison the session and settle every owned waiter", async () => {
  const agent = new TrackedAgentSession();
  agent.submitUserMessage = () => new Promise(() => {});
  const timers = createManualTimeouts();
  const session = new SdkSession(agent, {
    idleTimeoutMs: 100, hardCapMs: 1_000,
    setTimeoutFn: timers.setTimeout, clearTimeoutFn: timers.clearTimeout,
  });
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, (error) => error.terminalDisposition === "timed_out");
  await waitForImmediate(() => agent.calls.length === 1);
  const control = session.sendOwned("control", { type: "follow_up", message: "control" }, () => {}, 30);
  const controlCheck = assert.rejects(control.result, (error) => error.terminalDisposition === "timed_out");
  await waitForImmediate(() => session.trackedWork.size === 1);
  timers.advance(30);
  await Promise.all([rootCheck, controlCheck]);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
  assert.equal(agent.listeners.size, 0);
  assert.equal(session.adapterWaiterCancellations.size, 0);
  assert.equal(session.trackedWork.size, 0);
  assert.equal(timers.size, 0);
});

test("missing public tracked API is explicit rather than a legacy queue fallback", async () => {
  const agent = new TrackedAgentSession();
  agent.submitUserMessage = undefined;
  const session = new SdkSession(agent);
  const root = session.send({ type: "prompt", message: "root" }, () => {});
  const rootCheck = assert.rejects(root, (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await waitForImmediate(() => agent.calls.length === 1);
  await assert.rejects(session.send({ type: "steer", message: "not a fake prompt" }, () => {}),
    (error) => error.code === "SDK_TRACKED_INPUT_CONTRACT");
  await rootCheck;
  assert.deepEqual(agent.calls, [["prompt", "root"]]);
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
  assert.deepEqual(events, [{ type: "message_update", value: "continue" }]);
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

test("multiple idle controls remain FIFO prompt runs", async (t) => {
  // FIFO is driven by explicit gates, not a 100 ms wall-clock scheduling race.
  t.mock.timers.enable({ apis: ["setTimeout"] });
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
    (error) => {
      assert.match(error.message, /SDK command timed out/);
      assert.equal(error.terminalDisposition, "timed_out");
      assert.equal(error.interruptionConfirmed, false);
      return true;
    }
  );
  assert.equal(session.closed, true);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
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
    (error) => {
      assert.match(error.message, /SDK command timed out/);
      assert.equal(error.terminalDisposition, "timed_out");
      assert.equal(error.interruptionConfirmed, false);
      return true;
    }
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
      (error) => {
        assert.match(error.message, /exceeded absolute hard-cap/);
        assert.equal(error.terminalDisposition, "timed_out");
        assert.equal(error.interruptionConfirmed, false);
        return true;
      }
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

    for (const bad of [0, -1, 1.5, 86_400_001, Number.NaN, undefined]) {
      const session = new SdkSession(new FakeAgentSession(), {
        idleTimeoutMs: bad,
        hardCapMs: bad,
      });
      assert.equal(session.idleTimeoutMs, DEFAULT_IDLE_MS);
      assert.equal(session.hardCapMs, DEFAULT_HARD_CAP_MS);
    }
    const maximum = new SdkSession(new FakeAgentSession(), {
      idleTimeoutMs: 86_400_000,
      hardCapMs: 86_400_000,
    });
    assert.equal(maximum.idleTimeoutMs, 86_400_000);
    assert.equal(maximum.hardCapMs, 86_400_000);

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
  assert.equal(agent.listeners.size, 0);
  assert.equal(agent.rawListeners.size, 0);
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

  const result = await answerGate(session, "g1", "Banana");
  assert.equal(result.ok, true);
  await done;

  assert.deepEqual(agent.gateEmitter.prepareCalls, [["g1", "not_published"]]);
  assert.deepEqual(agent.gateEmitter.resolveCalls, [
    gateResponse("g1", { selected: ["Banana"] }),
  ]);
  assert.equal(session.pendingGates.size, 0);
  await session.dispose();
});

test("owned gates require their exact presentation before an answer is accepted", async () => {
  const agent = new GatingAgentSession({
    gate_id: "g-presentation",
    kind: "question",
    context: { prompt: "Pick one" },
    options: [{ value: "a", label: "A" }],
  });
  const session = new SdkSession(agent);
  const events = [];
  const ticket = session.sendOwned(
    "socket-1:request-1",
    { type: "prompt", message: "hi" },
    (event) => events.push(event)
  );
  await waitForImmediate(() => session.pendingGates.has("g-presentation"));
  const entry = session.pendingGates.get("g-presentation");
  const request = events.find((event) => event.type === "gate_request");
  assert.ok(request);
  assert.equal(entry.state, "awaiting_presentation");
  assert.equal(request.presentationId, entry.presentationId);
  assert.equal(
    (await session.answerGate(entry.ownerId, "g-presentation", entry.presentationId, "A"))
      .ok,
    false
  );
  assert.equal(
    session.presentGate(
      "socket-2:request-1",
      "g-presentation",
      entry.presentationId,
      "attempt-1"
    ),
    false
  );
  assert.equal(
    session.presentGate(
      entry.ownerId,
      "g-presentation",
      entry.presentationId,
      "attempt-1"
    ),
    true
  );
  assert.equal(entry.state, "answerable");
  assert.equal(
    session.presentGate(
      entry.ownerId,
      "g-presentation",
      entry.presentationId,
      "attempt-1"
    ),
    true
  );
  assert.equal(
    session.presentGate(
      entry.ownerId,
      "g-presentation",
      entry.presentationId,
      "attempt-2"
    ),
    false
  );
  assert.equal(
    (await session.answerGate("socket-2:request-1", "g-presentation", entry.presentationId, "A"))
      .ok,
    false
  );
  assert.equal(
    (await session.answerGate(entry.ownerId, "g-presentation", "stale-presentation", "A"))
      .ok,
    false
  );
  assert.equal(
    (await session.answerGate(entry.ownerId, "g-presentation", entry.presentationId, "A")).ok,
    true
  );
  await ticket.result;
  await session.dispose();
});

test("multi-select ownership is carried to the presentation event", async () => {
  const agent = new GatingAgentSession(
    sdkAskGate({
      gate_id: "g-multi",
      context: { prompt: "Pick several" },
      options: [{ label: "A" }, { label: "B" }],
      multi: true,
    })
  );
  const session = new SdkSession(agent);
  const events = [];
  const ticket = session.sendOwned(
    "socket-1:request-multi",
    { type: "prompt", message: "hi" },
    (event) => events.push(event)
  );
  await waitForImmediate(() => session.pendingGates.has("g-multi"));
  const request = events.find((event) => event.type === "gate_request");
  assert.equal(request.multi, true);
  assert.equal(
    session.presentGate(
      "socket-1:request-multi",
      request.gateId,
      request.presentationId,
      "attempt-multi"
    ),
    true
  );
  assert.equal(
    (
      await session.answerGate(
        "socket-1:request-multi",
        request.gateId,
        request.presentationId,
        JSON.stringify({ selected: ["A", "B"] })
      )
    ).ok,
    true
  );
  await ticket.result;
  await session.dispose();
});

test("abandonment and owner quarantine synchronously remove only matching gates", async () => {
  const firstAgent = new GatingAgentSession({
    gate_id: "g-abandon-before",
    kind: "question",
    context: { prompt: "Pick one" },
    options: [{ value: "a", label: "A" }],
  });
  const first = new SdkSession(firstAgent);
  const firstTicket = first.sendOwned(
    "socket-a:request-1",
    { type: "prompt", message: "hi" },
    () => {}
  );
  await waitForImmediate(() => first.pendingGates.has("g-abandon-before"));
  const before = first.pendingGates.get("g-abandon-before");
  assert.equal(
    first.abandonGate(before.ownerId, "g-abandon-before", before.presentationId),
    true
  );
  assert.equal(first.pendingGates.size, 0);
  assert.deepEqual(firstAgent.gateEmitter.quarantineCalls, ["g-abandon-before"]);
  assert.equal(
    first.abandonGate(before.ownerId, "g-abandon-before", before.presentationId),
    false
  );
  await assert.rejects(firstTicket.result);
  await first.dispose();

  const secondAgent = new GatingAgentSession({
    gate_id: "g-abandon-after",
    kind: "question",
    context: { prompt: "Pick one" },
    options: [{ value: "a", label: "A" }],
  });
  const second = new SdkSession(secondAgent);
  const secondTicket = second.sendOwned(
    "socket-b:request-1",
    { type: "prompt", message: "hi" },
    () => {}
  );
  await waitForImmediate(() => second.pendingGates.has("g-abandon-after"));
  const after = second.pendingGates.get("g-abandon-after");
  assert.equal(
    second.presentGate(after.ownerId, "g-abandon-after", after.presentationId, "attempt-1"),
    true
  );
  assert.equal(second.quarantineOwnedGates("socket-other:request-1"), false);
  assert.equal(second.pendingGates.size, 1);
  assert.equal(second.quarantineOwnedGates(after.ownerId), true);
  assert.equal(second.pendingGates.size, 0);
  assert.deepEqual(secondAgent.gateEmitter.quarantineCalls, ["g-abandon-after"]);
  await assert.rejects(secondTicket.result);
  await second.dispose();
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

  await answerGate(session, "g2", "2");
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

  await answerGate(session, "g3", "a long free-form answer");
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

    const result = await answerGate(session, gateId, answer);
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
    (await answerGate(rejectSession, "g-approval-reject", "reject")).ok,
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

  const unsupported = await answerGate(changesSession,
    "g-approval-changes",
    "request-changes"
  );
  assert.deepEqual(unsupported, {
    ok: false,
    error: "request-changes requires structured comments",
  });
  assert.deepEqual(changesAgent.gateEmitter.resolveCalls, []);

  const accepted = await answerGate(changesSession,
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

  const result = await answerGate(session, "g-execution-decline", "2");
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

  const rejected = await answerGate(session,
    "g-unsupported-answer",
    '{"decision":"approve","extra":true}'
  );
  assert.deepEqual(rejected, {
    ok: false,
    error: "unsupported gate answer shape",
  });
  assert.deepEqual(agent.gateEmitter.resolveCalls, []);

  assert.equal(
    (await answerGate(session, "g-unsupported-answer", "approve")).ok,
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

  const rejected = await answerGate(session,
    "g-retry",
    '{"selected":[],"other":true,"custom":"invalid"}'
  );
  assert.equal(rejected.ok, false);
  assert.equal(rejected.resolution.status, "rejected");
  assert.equal(session.pendingGates.has("g-retry"), true);
  assert.deepEqual(agent.gateEmitter.clearPreparedCalls, ["g-retry"]);

  const accepted = await answerGate(session, "g-retry", "ok");
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

  const answered = await answerGate(session, "g-reconcile", "yes");
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
  const firstAnswer = answerGate(session, "g-successor-1", "Continue");
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
    (await answerGate(session, "g-successor-2", "Finish")).ok,
    true
  );
  await done;
  assert.deepEqual(agent.gateEmitter.quarantineCalls, []);
  await session.dispose();
});

test("recovery completes the same immutable accepted-incomplete answer before admitting its successor", async () => {
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
  let releaseRecovery;
  const recoveryBarrier = new Promise((resolve) => {
    releaseRecovery = resolve;
  });
  agent.gateEmitter.beforeReceipt = (response) => {
    if (response.gate_id === "g-incomplete-1") {
      Object.freeze(response.answer.selected);
      Object.freeze(response.answer);
      Object.freeze(response);
    }
  };
  agent.gateEmitter.recoverAccepted = async () => {
    await recoveryBarrier;
    agent.gateEmitter.acceptedIncompleteKeys.delete(key);
    return [agent.gateEmitter.completed.get(key).resolution];
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

  const firstAnswer = answerGate(session, "g-incomplete-1", "Continue");
  await waitForImmediate(
    () => session.deferredGateCandidate?.gate?.gate_id === "g-incomplete-2" &&
      agent.gateEmitter.recoveryCalls === 1
  );
  const immutableResponse = agent.gateEmitter.resolveCalls[0];
  const originalResponse = JSON.stringify(immutableResponse);
  assert.equal(Object.isFrozen(immutableResponse), true);
  assert.equal(Object.isFrozen(immutableResponse.answer), true);
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

  releaseRecovery();
  assert.deepEqual(await firstAnswer, {
    ok: true,
    resolution: agent.gateEmitter.completed.get(key).resolution,
  });
  assert.equal(agent.gateEmitter.recoveryCalls, 1);
  assert.equal(agent.gateEmitter.resolveCalls.length, 1);
  assert.equal(JSON.stringify(immutableResponse), originalResponse);
  assert.ok(agent.gateEmitter.lookupCalls.every((response) => response === immutableResponse));
  assert.deepEqual(agent.answers, [immutableResponse.answer]);
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
    (await answerGate(session, "g-incomplete-2", "Finish")).ok,
    true
  );
  await done;
  await session.dispose();
});

test("recovery no-op, throw and answer conflict never publish an unproven successor", async (t) => {
  for (const mode of ["no-op", "throw", "answer-conflict", "lookup-no-op", "lookup-throw"]) {
    await t.test(mode, async () => {
      const firstId = `g-recovery-${mode}-1`;
      const secondId = `g-recovery-${mode}-2`;
      const key = `gjc-remote:${firstId}`;
      const agent = new GatingAgentSession([
        sdkAskGate({ gate_id: firstId, options: [{ label: "Continue" }] }),
        sdkAskGate({ gate_id: secondId, options: [{ label: "Finish" }] }),
      ]);
      const emitter = agent.gateEmitter;
      emitter.acceptedIncompleteKeys.add(key);
      emitter.beforeReceipt = (response) => {
        Object.freeze(response.answer.selected);
        Object.freeze(response.answer);
        Object.freeze(response);
      };
      let releaseRecovery;
      const recoveryBarrier = new Promise((resolve) => { releaseRecovery = resolve; });
      emitter.recoverAccepted = async () => {
        await recoveryBarrier;
        if (mode === "throw") throw new Error("credential-bearing recovery detail");
        if (mode === "answer-conflict") {
          const accepted = emitter.completed.get(key);
          emitter.completed.set(key, {
            ...accepted,
            response: { ...accepted.response, answer: { selected: ["Different"] } },
          });
        }
        if (mode === "lookup-no-op" || mode === "lookup-throw") {
          emitter.lookupCompletedResolution = (response) => {
            emitter.lookupCalls.push(response);
            if (mode === "lookup-throw") throw new Error("credential-bearing lookup detail");
            return { kind: "none" };
          };
        }
        return [];
      };
      const session = new SdkSession(agent);
      const events = [];
      const done = session.send({ type: "prompt", message: "recover" }, (event) => events.push(event));
      const doneResult = Promise.allSettled([done]);
      await waitForImmediate(() => session.pendingGates.has(firstId));
      const entry = session.pendingGates.get(firstId);
      const answer = answerGate(session, firstId, "Continue");
      await waitForImmediate(() => emitter.recoveryCalls === 1 && session.deferredGateCandidate?.gate.gate_id === secondId);
      const response = emitter.resolveCalls[0];
      const originalResponse = JSON.stringify(response);
      assert.strictEqual(entry.response, response);
      assert.equal(emitter.lookupCompletedResolution(response).kind, "accepted_incomplete");
      releaseRecovery();
      const result = await answer;
      assert.equal(result.ok, false);
      assert.equal(result.error, mode === "throw" ? "workflow gate answer failed" : "workflow gate resolution is incomplete");
      assert.doesNotMatch(JSON.stringify(result), /credential-bearing|recovery detail/);
      assert.equal(emitter.recoveryCalls, mode === "throw" ? 2 : 1);
      assert.equal(emitter.resolveCalls.length, 1);
      assert.equal(JSON.stringify(response), originalResponse);
      assert.deepEqual(agent.answers, [response.answer]);
      if (mode === "answer-conflict") {
        assert.throws(() => emitter.lookupCompletedResolution(response), /idempotency_conflict/);
      } else if (mode !== "lookup-no-op" && mode !== "lookup-throw") {
        assert.equal(emitter.lookupCompletedResolution(response).kind, "accepted_incomplete");
      }
      assert.equal(session.pendingGates.has(secondId), false);
      assert.equal(events.some((event) => event.type === "gate_request" && event.gateId === secondId), false);
      if (mode !== "lookup-no-op" && mode !== "lookup-throw") {
        assert.throws(
          () => emitter.lookupCompletedResolution({ ...response, answer: { selected: ["Replay conflict"] } }),
          /idempotency_conflict/
        );
      }
      try {
        assert.strictEqual(session.pendingGates.get(firstId), entry);
        assert.strictEqual(entry.response, response);
        for (const replayAnswer of ["Continue", "Different", null, '{"selected":42}']) {
          const replay = await session.answerGate(entry.ownerId, firstId, entry.presentationId, replayAnswer);
          assert.deepEqual(replay, { ok: false, error: "workflow gate is no longer answerable" });
          assert.equal(emitter.resolveCalls.length, 1);
          assert.strictEqual(entry.response, response);
          if (mode === "answer-conflict") {
            assert.throws(() => emitter.lookupCompletedResolution(entry.response), /idempotency_conflict/);
          } else if (mode !== "lookup-no-op" && mode !== "lookup-throw") {
            assert.equal(emitter.lookupCompletedResolution(entry.response).kind, "accepted_incomplete");
          }
        }
        assert.equal(emitter.prepareCalls.length, 1);
        assert.deepEqual(emitter.clearPreparedCalls, []);
        assert.deepEqual(emitter.quarantineCalls, []);
        assert.equal(session.deferredGateCandidate?.gate.gate_id, secondId);
      } finally {
        await session.dispose();
      }
      assert.strictEqual(entry.response, response);
      await session.dispose();
      const [promptResult] = await doneResult;
      assert.equal(promptResult.status, "rejected");
      assert.equal(session.pendingGates.size, 0);
      assert.equal(session.deferredGateCandidate, undefined);
      assert.equal(emitter.listeners.size, 0);
      assert.equal(agent.disposeCalls, 1);
    });
  }
});

test("successor-observed acceptance survives a lost receipt and later lookup none", async (t) => {
  for (const finish of ["dispose", "exact-completion"]) {
    await t.test(finish, async () => {
      const firstId = `g-observed-accepted-${finish}-1`;
      const secondId = `g-observed-accepted-${finish}-2`;
      const key = `gjc-remote:${firstId}`;
      const agent = new GatingAgentSession([
        sdkAskGate({ gate_id: firstId, options: [{ label: "Continue" }] }),
        sdkAskGate({ gate_id: secondId, options: [{ label: "Finish" }] }),
      ]);
      const emitter = agent.gateEmitter;
      emitter.acceptedIncompleteKeys.add(key);
      let releaseReceipt;
      const receiptBarrier = new Promise((resolve) => { releaseReceipt = resolve; });
      emitter.beforeReceipt = async (response) => {
        if (response.gate_id !== firstId) return;
        Object.freeze(response.answer.selected);
        Object.freeze(response.answer);
        Object.freeze(response);
        await receiptBarrier;
        throw new Error("resolve receipt lost");
      };
      const lookup = emitter.lookupCompletedResolution.bind(emitter);
      let lookupUnavailable = false;
      emitter.lookupCompletedResolution = (response) => {
        if (!lookupUnavailable) return lookup(response);
        emitter.lookupCalls.push(response);
        return { kind: "none" };
      };
      const events = [];
      const session = new SdkSession(agent);
      const doneResult = Promise.allSettled([
        session.send({ type: "prompt", message: "observe acceptance" }, (event) => events.push(event)),
      ]);
      await waitForImmediate(() => session.pendingGates.has(firstId));
      const entry = session.pendingGates.get(firstId);
      const answer = answerGate(session, firstId, "Continue");
      await waitForImmediate(() => session.deferredGateCandidate?.gate.gate_id === secondId);
      const response = emitter.resolveCalls[0];
      const candidate = session.deferredGateCandidate;
      assert.equal(entry.accepted, true, "successor lookup records acceptance before the receipt arrives");
      assert.strictEqual(entry.response, response);
      lookupUnavailable = true;
      releaseReceipt();
      assert.deepEqual(await answer, { ok: false, error: "workflow gate answer failed" });
      assert.strictEqual(session.pendingGates.get(firstId), entry);
      assert.strictEqual(entry.response, response);
      assert.strictEqual(session.deferredGateCandidate, candidate);
      assert.equal(entry.accepted, true);
      assert.equal(emitter.listPendingGates().some((gate) => gate.gate_id === firstId), false);
      for (const replayAnswer of ["Continue", "Different", null]) {
        assert.deepEqual(await session.answerGate(entry.ownerId, firstId, entry.presentationId, replayAnswer), {
          ok: false, error: "workflow gate is no longer answerable",
        });
        assert.strictEqual(entry.response, response);
        assert.strictEqual(session.deferredGateCandidate, candidate);
      }
      assert.equal(emitter.resolveCalls.length, 1);
      assert.equal(emitter.prepareCalls.length, 1);
      assert.equal(emitter.recoveryCalls, 0);
      assert.deepEqual(emitter.clearPreparedCalls, []);
      assert.deepEqual(emitter.quarantineCalls, []);
      assert.deepEqual(agent.answers, [response.answer]);
      assert.ok(emitter.lookupCalls.every((lookupResponse) => lookupResponse === response));
      assert.equal(events.some((event) => event.type === "gate_request" && event.gateId === secondId), false);
      if (finish === "exact-completion") {
        lookupUnavailable = false;
        emitter.acceptedIncompleteKeys.delete(key);
        assert.deepEqual(await session.answerGate(entry.ownerId, firstId, entry.presentationId, null), {
          ok: true, resolution: emitter.completed.get(key).resolution,
        });
        assert.equal(events.filter((event) => event.type === "gate_request" && event.gateId === secondId).length, 1);
        assert.equal((await answerGate(session, secondId, "Finish")).ok, true);
        assert.equal((await doneResult)[0].status, "fulfilled");
        assert.equal(emitter.resolveCalls.length, 2);
        assert.deepEqual(agent.answers, [response.answer, emitter.resolveCalls[1].answer]);
      }
      await session.dispose();
      assert.strictEqual(entry.response, response);
      assert.equal(session.pendingGates.size, 0);
      assert.equal(session.deferredGateCandidate, undefined);
      if (finish === "dispose") assert.equal((await doneResult)[0].status, "rejected");
    });
  }
});

test("an unknown resolution with pending proof retains its response until disposal", async () => {
  const gateId = "g-unknown-pending";
  const agent = new GatingAgentSession(sdkAskGate({
    gate_id: gateId, options: [{ label: "Continue" }],
  }));
  const emitter = agent.gateEmitter;
  emitter.resolveGate = async (response) => {
    emitter.resolveCalls.push(response);
    throw new Error("resolution receipt unavailable");
  };
  emitter.lookupCompletedResolution = (response) => {
    emitter.lookupCalls.push(response);
    throw new Error("lookup unavailable");
  };
  const session = new SdkSession(agent);
  const doneResult = Promise.allSettled([
    session.send({ type: "prompt", message: "unknown resolution" }, () => {}),
  ]);
  await waitForImmediate(() => session.pendingGates.has(gateId));
  const entry = session.pendingGates.get(gateId);
  assert.deepEqual(await answerGate(session, gateId, "Continue"), {
    ok: false, error: "workflow gate answer failed",
  });
  const response = emitter.resolveCalls[0];
  assert.equal(emitter.listPendingGates().length, 1);
  for (const replayAnswer of ["Continue", "Different", null]) {
    assert.deepEqual(await session.answerGate(entry.ownerId, gateId, entry.presentationId, replayAnswer), {
      ok: false, error: "workflow gate is no longer answerable",
    });
    assert.strictEqual(entry.response, response);
  }
  assert.equal(emitter.resolveCalls.length, 1);
  assert.equal(emitter.prepareCalls.length, 1);
  assert.deepEqual(emitter.clearPreparedCalls, []);
  assert.deepEqual(emitter.quarantineCalls, []);
  assert.deepEqual(agent.answers, []);
  await session.dispose();
  assert.strictEqual(entry.response, response);
  assert.equal((await doneResult)[0].status, "rejected");
});

test("a completed retained binding admits its successor once without resolving a replay", async () => {
  const firstId = "g-completed-replay-1";
  const secondId = "g-completed-replay-2";
  const key = `gjc-remote:${firstId}`;
  const agent = new GatingAgentSession([
    sdkAskGate({ gate_id: firstId, options: [{ label: "Continue" }] }),
    sdkAskGate({ gate_id: secondId, options: [{ label: "Finish" }] }),
  ]);
  const emitter = agent.gateEmitter;
  emitter.acceptedIncompleteKeys.add(key);
  const events = [];
  const session = new SdkSession(agent);
  const done = session.send({ type: "prompt", message: "completed replay" }, (event) => events.push(event));
  await waitForImmediate(() => session.pendingGates.has(firstId));
  const entry = session.pendingGates.get(firstId);
  assert.equal((await answerGate(session, firstId, "Continue")).ok, false);
  await waitForImmediate(() => session.deferredGateCandidate?.gate.gate_id === secondId);
  const response = emitter.resolveCalls[0];
  assert.strictEqual(entry.response, response);
  emitter.acceptedIncompleteKeys.delete(key);
  const replay = await session.answerGate(entry.ownerId, firstId, entry.presentationId, null);
  assert.deepEqual(replay, { ok: true, resolution: emitter.completed.get(key).resolution });
  assert.strictEqual(entry.response, response);
  assert.equal(emitter.resolveCalls.length, 1);
  assert.equal(emitter.prepareCalls.length, 1);
  assert.deepEqual(emitter.clearPreparedCalls, []);
  assert.ok(emitter.lookupCalls.every((lookupResponse) => lookupResponse === response));
  assert.deepEqual(agent.answers, [response.answer]);
  assert.equal(session.pendingGates.has(firstId), false);
  assert.equal(session.pendingGates.has(secondId), true);
  assert.equal(events.filter((event) => event.type === "gate_request" && event.gateId === secondId).length, 1);
  assert.deepEqual(await session.answerGate(entry.ownerId, firstId, entry.presentationId, "Different"), {
    ok: false, error: "no pending gate for id",
  });
  assert.equal((await answerGate(session, secondId, "Finish")).ok, true);
  await done;
  assert.equal(emitter.resolveCalls.length, 2);
  assert.equal(agent.answers.length, 2);
  assert.deepEqual(emitter.quarantineCalls, []);
  await session.dispose();
});

test("dispose settles a recovery waiter and fences its late completion", async () => {
  const firstId = "g-dispose-recovery-1";
  const secondId = "g-dispose-recovery-2";
  const key = `gjc-remote:${firstId}`;
  const agent = new GatingAgentSession([
    sdkAskGate({ gate_id: firstId, options: [{ label: "Continue" }] }),
    sdkAskGate({ gate_id: secondId, options: [{ label: "Finish" }] }),
  ]);
  const emitter = agent.gateEmitter;
  emitter.acceptedIncompleteKeys.add(key);
  let releaseRecovery;
  const recoveryBarrier = new Promise((resolve) => { releaseRecovery = resolve; });
  let recovered = false;
  emitter.recoverAccepted = async () => {
    await recoveryBarrier;
    emitter.acceptedIncompleteKeys.delete(key);
    recovered = true;
    return [emitter.completed.get(key).resolution];
  };
  const events = [];
  const session = new SdkSession(agent);
  const doneResult = Promise.allSettled([
    session.send({ type: "prompt", message: "dispose recovery" }, (event) => events.push(event)),
  ]);
  await waitForImmediate(() => session.pendingGates.has(firstId));
  const entry = session.pendingGates.get(firstId);
  const answer = answerGate(session, firstId, "Continue");
  await waitForImmediate(() => emitter.recoveryCalls === 1 && session.deferredGateCandidate?.gate.gate_id === secondId);
  const response = emitter.resolveCalls[0];
  assert.strictEqual(entry.response, response);
  assert.deepEqual(await session.answerGate(entry.ownerId, firstId, entry.presentationId, null), {
    ok: false, error: "gate answer is already being resolved",
  });
  assert.strictEqual(entry.response, response);
  await session.dispose();
  assert.strictEqual(entry.response, response);
  assert.equal(recovered, false, "adapter disposal does not wait on the underlying recovery promise");
  assert.deepEqual(await answer, { ok: false, error: "session is closed" });
  assert.equal((await doneResult)[0].status, "rejected");
  releaseRecovery();
  await waitForImmediate(() => recovered);
  assert.strictEqual(entry.response, response);
  assert.equal(emitter.lookupCompletedResolution(emitter.resolveCalls[0]).kind, "completed");
  assert.deepEqual(await session.answerGate(entry.ownerId, firstId, entry.presentationId, "Continue"), {
    ok: false, error: "session is closed",
  });
  assert.equal(events.some((event) => event.type === "gate_request" && event.gateId === secondId), false);
  assert.equal(session.pendingGates.size, 0);
  assert.equal(session.deferredGateCandidate, undefined);
  assert.equal(emitter.listeners.size, 0);
  assert.equal(agent.listeners.size, 0);
  assert.equal(emitter.resolveCalls.length, 1);
  assert.equal(emitter.recoveryCalls, 1);
  await session.dispose();
  assert.equal(agent.disposeCalls, 1);
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
  const answer = answerGate(session, "g-bounded-1", "Continue");
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

  const answer = answerGate(session, "g-dispose-receipt", "Continue");
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

  const answered = await answerGate(session, "g-replay", "continue");
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
    (error) => {
      assert.match(error.message, /gate answer window expired/);
      assert.equal(error.terminalDisposition, "timed_out");
      assert.equal(error.interruptionConfirmed, false);
      return true;
    }
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
  const result = await session.answerGate(
    "socket-1:request-1",
    "nope",
    "stale-presentation",
    "x"
  );
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

  await answerGate(session, "g5", "A");
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
  const answerResult = await answerGate(session, "g-hardcap", "anything");
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

  const pending = session.pendingGates.get("g-double");
  assert.ok(pending);
  const first = await answerGate(session, "g-double", "A");
  assert.equal(first.ok, true);
  const second = await session.answerGate(
    pending.ownerId,
    "g-double",
    pending.presentationId,
    "A"
  );
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
  const lateAnswer = await session.answerGate(
    "socket-1:request-1",
    "g-late",
    "stale-presentation",
    "too late"
  );
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
  const answerResult = await answerGate(session, "g-silent", "ok");
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

  await answerGate(session, "g6", "A");
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

  await answerGate(session, "g-numlabel", "2");
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

  await answerGate(session, "g-dup", "yes");
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

  await answerGate(session, "g-ws", "  APPLE  ");
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

    await answerGate(session, "g-range", bad);
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

  const rejected = await answerGate(session, "g-empty", "");
  assert.deepEqual(rejected, {
    ok: false,
    error: "gate answer must not be empty",
  });
  assert.deepEqual(agent.gateEmitter.resolveCalls, []);
  await answerGate(session, "g-empty", "A");
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

  const answered = await answerGate(session, "g-one", "ok");
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

  const answered = await answerGate(session, "g-owner", "ok");
  assert.equal(answered.ok, true);
  assert.equal(resumeCalls.length, 1, "the owning run's controller was resumed exactly once");
  releaseTerminal();
  await parked;
  await session.dispose();
});

test("oversized gate content is quarantined without silent truncation", async () => {
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
  const rejected = assert.rejects(done, /prompt_failed/);
  await gateDelay(0);

  assert.equal(events.some((evt) => evt.type === "gate_request"), false);
  assert.deepEqual(agent.gateEmitter.quarantineCalls, ["g-clamp"]);
  await rejected;
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
