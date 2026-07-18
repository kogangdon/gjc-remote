import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";

import { SdkSession, createSdkSession } from "../src/sdk-session.js";

class FakeAgentSession {
  constructor() {
    this.listeners = new Set();
    this.models = [
      { provider: "provider-a", id: "model-a", name: "Model A", extra: true },
    ];
    this.calls = [];
    this.disposeCalls = 0;
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
    this.emit({ type: "agent_end" });
  }

  async steer(message) {
    this.calls.push(["steer", message]);
    queueMicrotask(() => this.emit({ type: "agent_end" }));
  }

  async followUp(message) {
    this.calls.push(["follow_up", message]);
    queueMicrotask(() => this.emit({ type: "agent_end" }));
  }

  async dispose() {
    this.disposeCalls += 1;
  }
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
  await session.dispose();
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

test("SDK adapter serializes commands per session", async () => {
  const agent = new FakeAgentSession();
  let releaseFirst;
  const firstGate = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    if (message === "first") await firstGate;
    agent.emit({ type: "agent_end" });
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
