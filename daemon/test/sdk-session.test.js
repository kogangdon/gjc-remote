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

test("prompt completion waits for the final agent_end event", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  const session = new SdkSession(agent);
  let settled = false;

  const result = session
    .send({ type: "prompt", message: "hello" }, () => {}, 100)
    .then(() => {
      settled = true;
    });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);

  agent.emit({ type: "agent_end" });
  await result;
  assert.equal(settled, true);
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

test("live controls dispatch during a prompt and keep their event streams open", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  agent.steer = async (message) => {
    agent.calls.push(["steer", message]);
  };
  agent.followUp = async (message) => {
    agent.calls.push(["follow_up", message]);
  };
  const session = new SdkSession(agent);
  const promptEvents = [];
  const steerEvents = [];
  const followUpEvents = [];
  let promptSettled = false;
  let steerSettled = false;
  let followUpSettled = false;

  const prompt = session
    .send({ type: "prompt", message: "first" }, (event) => promptEvents.push(event), 100)
    .finally(() => {
      promptSettled = true;
    });
  const steer = session
    .send({ type: "steer", message: "adjust" }, (event) => steerEvents.push(event), 100)
    .finally(() => {
      steerSettled = true;
    });
  const followUp = session
    .send(
      { type: "follow_up", message: "then continue" },
      (event) => followUpEvents.push(event),
      100
    )
    .finally(() => {
      followUpSettled = true;
    });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(promptSettled, false);
  assert.equal(steerSettled, false);
  assert.equal(followUpSettled, false);
  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["steer", "adjust"],
    ["follow_up", "then continue"],
  ]);

  const update = { type: "message_update", value: "controlled" };
  const end = { type: "agent_end" };
  agent.emit(update);
  agent.emit(end);
  await Promise.all([prompt, steer, followUp]);

  assert.deepEqual(promptEvents, [update, end]);
  assert.deepEqual(steerEvents, [update, end]);
  assert.deepEqual(followUpEvents, [update, end]);
  await session.dispose();
});

test("idle follow-up keeps its own event stream through agent_end", async () => {
  const agent = new FakeAgentSession();
  const session = new SdkSession(agent);
  const events = [];

  await session.send(
    { type: "follow_up", message: "continue" },
    (event) => events.push(event),
    100
  );

  assert.deepEqual(agent.calls, [["follow_up", "continue"]]);
  assert.deepEqual(events, [{ type: "agent_end" }]);
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
    ["follow_up", "after model"],
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
test("dispose ignores prior control failures after underlying cleanup succeeds", async () => {
  const agent = new FakeAgentSession();
  let rejectSteer;
  const steerGate = new Promise((_, reject) => {
    rejectSteer = reject;
  });
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  agent.steer = async (message) => {
    agent.calls.push(["steer", message]);
    await steerGate;
  };
  agent.dispose = async () => {
    agent.disposeCalls += 1;
    rejectSteer(new Error("control failed"));
    agent.emit({ type: "agent_end" });
  };
  const session = new SdkSession(agent);

  const prompt = session.send({ type: "prompt", message: "active" }, () => {}, 100);
  await new Promise((resolve) => setImmediate(resolve));
  const steer = session.send({ type: "steer", message: "adjust" }, () => {}, 100);
  const steerFailure = assert.rejects(steer, /control failed/);
  await new Promise((resolve) => setImmediate(resolve));

  await session.dispose();
  await Promise.all([prompt, steerFailure]);
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
