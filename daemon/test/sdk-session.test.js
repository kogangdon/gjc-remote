import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";

import {
  SdkSession,
  applyConfiguredModelProfile,
  createSdkSession,
} from "../src/sdk-session.js";
import { V0_LIMITS, isGateRequestEvent } from "@gjc-remote/shared";

class FakeAgentSession {
  constructor() {
    this.listeners = new Set();
    this.models = [
      { provider: "provider-a", id: "model-a", name: "Model A", extra: true },
    ];
    this.calls = [];
    this.disposeCalls = 0;
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

// #35: a fake BrokerWorkflowGateEmitter. emitGate() fires the registered
// listeners (as the real emitter does when the `ask` tool opens a gate) and
// returns a promise that resolves only when resolveGate() is called with the
// matching gate_id — mirroring how emitGate suspends the agent loop until an
// answer arrives.
class FakeGateEmitter {
  constructor() {
    this.listeners = new Set();
    this.resolveCalls = [];
    this.resolvers = new Map();
  }
  onGateEmitted(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  emitGate(gate) {
    for (const listener of this.listeners) listener(gate);
    return new Promise((resolve) => this.resolvers.set(gate.gate_id, resolve));
  }
  async resolveGate(response) {
    this.resolveCalls.push(response);
    const resolve = this.resolvers.get(response.gate_id);
    if (resolve) {
      this.resolvers.delete(response.gate_id);
      resolve({ gate_id: response.gate_id, status: "accepted", answer: response.answer });
    }
    return { gate_id: response.gate_id, status: "accepted", answer_hash: "hash" };
  }
  listPendingGates() {
    return [...this.resolvers.keys()].map((gate_id) => ({ gate_id }));
  }
}

// #35: a session whose prompt() opens one or more gates and blocks on each until
// answered, then emits agent_end.
class GatingAgentSession extends FakeAgentSession {
  constructor(gates) {
    super();
    this.gateEmitter = new FakeGateEmitter();
    this.gates = Array.isArray(gates) ? gates : [gates];
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
    this.emit({ type: "agent_end" });
  }
}

const gateDelay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("createSdkSession uses the canonical workDir and dedicated session directory", async () => {
  const calls = [];
  const agent = new FakeAgentSession();
  let manager;
  const activateCalls = [];
  let cloneForCwdArg;
  const scopedSettings = {
    get: (key) => (key === "modelProfile.default" ? "copilot-claude" : undefined),
  };
  const sdk = {
    Settings: {
      async init() {
        return {
          async cloneForCwd(cwd) {
            cloneForCwdArg = cwd;
            return scopedSettings;
          },
        };
      },
    },
    SessionManager: {
      create(workDir, sessionDir) {
        calls.push(["manager", workDir, sessionDir]);
        manager = { workDir, sessionDir };
        return manager;
      },
    },
    async createAgentSession(options) {
      calls.push(["session", options]);
      // Model reality: the session reads the settings passed in (the clone).
      agent.settings = options.settings;
      return { session: agent };
    },
    async activateModelProfile(options, applyOptions) {
      activateCalls.push([options, applyOptions]);
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
  assert.strictEqual(calls[1][1].settings, scopedSettings);
  assert.equal(cloneForCwdArg, "/workspace");
  assert.equal(activateCalls.length, 1);
  const [activateOptions, activateApplyOptions] = activateCalls[0];
  assert.equal(activateOptions.profileName, "copilot-claude");
  assert.strictEqual(activateOptions.session, agent);
  assert.strictEqual(activateOptions.modelRegistry, agent.modelRegistry);
  assert.strictEqual(activateOptions.settings, agent.settings);
  assert.deepEqual(activateApplyOptions, { persistDefault: false });
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

test("agent_end marks a prompt inactive before prompt() settles", async () => {
  const agent = new FakeAgentSession();
  let releasePrompt;
  const promptGate = new Promise((resolve) => {
    releasePrompt = resolve;
  });
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
    agent.emit({ type: "agent_end" });
    if (message === "first") await promptGate;
  };
  const session = new SdkSession(agent);

  const first = session.send({ type: "prompt", message: "first" }, () => {}, 100);
  await new Promise((resolve) => setImmediate(resolve));
  const followUp = session.send(
    { type: "follow_up", message: "after end" },
    () => {},
    100
  );
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(agent.calls, [["prompt", "first"]]);
  releasePrompt();
  await Promise.all([first, followUp]);
  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["prompt", "after end"],
  ]);
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

  const currentUpdate = { type: "message_update", value: "controlled" };
  const currentEnd = { type: "agent_end" };
  agent.emit(currentUpdate);
  agent.emit(currentEnd);
  await Promise.all([prompt, steer]);
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(followUpSettled, false);

  const followUpUpdate = { type: "message_update", value: "follow-up" };
  const followUpEnd = { type: "agent_end" };
  agent.emit(followUpUpdate);
  agent.emit(followUpEnd);
  await followUp;

  assert.deepEqual(promptEvents, [currentUpdate, currentEnd]);
  assert.deepEqual(steerEvents, [currentUpdate, currentEnd]);
  assert.deepEqual(followUpEvents, [
    currentUpdate,
    currentEnd,
    followUpUpdate,
    followUpEnd,
  ]);
  await session.dispose();
});

test("controls retain SDK semantics during an active follow-up run", async () => {
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
  let secondSettled = false;

  const prompt = session.send({ type: "prompt", message: "initial" }, () => {}, 100);
  const first = session.send({ type: "follow_up", message: "first" }, () => {}, 100);
  await new Promise((resolve) => setImmediate(resolve));

  agent.emit({ type: "agent_end" });
  await prompt;

  const steer = session.send({ type: "steer", message: "adjust" }, () => {}, 100);
  const second = session
    .send({ type: "follow_up", message: "second" }, () => {}, 100)
    .finally(() => {
      secondSettled = true;
    });
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(agent.calls, [
    ["prompt", "initial"],
    ["follow_up", "first"],
    ["steer", "adjust"],
    ["follow_up", "second"],
  ]);

  agent.emit({ type: "agent_end" });
  await Promise.all([first, steer]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(secondSettled, false);

  agent.emit({ type: "agent_end" });
  await second;
  assert.equal(secondSettled, true);
  await session.dispose();
});

test("queued commands wait for an active follow-up run to complete", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  agent.followUp = async (message) => {
    agent.calls.push(["follow_up", message]);
  };
  const session = new SdkSession(agent);

  const prompt = session.send({ type: "prompt", message: "first" }, () => {}, 100);
  const followUp = session.send(
    { type: "follow_up", message: "continue" },
    () => {},
    100
  );
  const modelSwitch = session.send(
    { type: "set_model", provider: "provider-a", modelId: "model-a" },
    () => {},
    100
  );
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["follow_up", "continue"],
  ]);

  agent.emit({ type: "agent_end" });
  await prompt;
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["follow_up", "continue"],
  ]);

  agent.emit({ type: "agent_end" });
  await Promise.all([followUp, modelSwitch]);
  assert.deepEqual(agent.calls, [
    ["prompt", "first"],
    ["follow_up", "continue"],
    ["set_model", agent.models[0]],
  ]);
  await session.dispose();
});

test("multiple active follow-ups wait for their own queued run boundaries", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  agent.followUp = async (message) => {
    agent.calls.push(["follow_up", message]);
  };
  const session = new SdkSession(agent);
  let firstSettled = false;
  let secondSettled = false;

  const prompt = session.send({ type: "prompt", message: "initial" }, () => {}, 100);
  const first = session
    .send({ type: "follow_up", message: "first" }, () => {}, 100)
    .finally(() => {
      firstSettled = true;
    });
  const second = session
    .send({ type: "follow_up", message: "second" }, () => {}, 100)
    .finally(() => {
      secondSettled = true;
    });
  await new Promise((resolve) => setImmediate(resolve));

  agent.emit({ type: "agent_end" });
  await prompt;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(firstSettled, false);
  assert.equal(secondSettled, false);

  agent.emit({ type: "agent_end" });
  await first;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(firstSettled, true);
  assert.equal(secondSettled, false);

  agent.emit({ type: "agent_end" });
  await second;
  assert.equal(secondSettled, true);
  await session.dispose();
});

test("rejected live follow-ups do not reserve completion boundaries", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  let followUpCalls = 0;
  agent.followUp = async (message) => {
    agent.calls.push(["follow_up", message]);
    followUpCalls += 1;
    if (followUpCalls === 1) throw new Error("queue rejected");
  };
  const session = new SdkSession(agent);
  let secondSettled = false;

  const prompt = session.send({ type: "prompt", message: "initial" }, () => {}, 100);
  const first = session.send({ type: "follow_up", message: "rejected" }, () => {}, 100);
  const firstRejection = assert.rejects(first, /queue rejected/);
  const second = session
    .send({ type: "follow_up", message: "accepted" }, () => {}, 100)
    .finally(() => {
      secondSettled = true;
    });
  await new Promise((resolve) => setImmediate(resolve));

  agent.emit({ type: "agent_end" });
  await Promise.all([prompt, firstRejection]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(secondSettled, false);

  agent.emit({ type: "agent_end" });
  await second;
  assert.equal(secondSettled, true);
  await session.dispose();
});

test("active follow-up subscribes before a queued agent_end callback", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = async (message) => {
    agent.calls.push(["prompt", message]);
  };
  agent.followUp = async (message) => {
    agent.calls.push(["follow_up", message]);
  };
  const session = new SdkSession(agent);
  let followUpSettled = false;

  const prompt = session.send({ type: "prompt", message: "initial" }, () => {}, 100);
  const followUp = session
    .send({ type: "follow_up", message: "continue" }, () => {}, 100)
    .finally(() => {
      followUpSettled = true;
    });
  queueMicrotask(() => agent.emit({ type: "agent_end" }));

  await prompt;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(followUpSettled, false);

  agent.emit({ type: "agent_end" });
  await followUp;
  assert.equal(followUpSettled, true);
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
    { type: "agent_end" },
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
    agent.emit({ type: "agent_end" });
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
    agent.emit({ type: "agent_end" });
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

test("concurrent live-control sibling settles boundedly when the other hard-caps and disposes", async () => {
  const agent = new FakeAgentSession();
  agent.prompt = () => new Promise(() => {});
  agent.steer = () => new Promise(() => {});
  const session = new SdkSession(agent, { idleTimeoutMs: 5000, hardCapMs: 30 });

  const prompt = session.send({ type: "prompt", message: "hard-cap me" }, () => {});
  await new Promise((resolve) => setImmediate(resolve));
  const steer = session.send({ type: "steer", message: "sibling" }, () => {}, 10);

  const guard = new Promise((_, reject) => {
    setTimeout(() => reject(new Error("test guard: settlement hung")), 2000).unref?.();
  });

  const results = await Promise.race([
    Promise.allSettled([prompt, steer]),
    guard,
  ]);

  assert.equal(results[0].status, "rejected");
  assert.match(results[0].reason.message, /exceeded absolute hard-cap/);
  assert.equal(results[1].status, "rejected");
  assert.equal(session.closed, true);
  await session.dispose();
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
function activationHarness() {
  const activateCalls = [];
  const settings = { get: () => undefined };
  const session = { modelRegistry: { id: "registry" }, settings };
  return {
    activateCalls,
    session,
    settings,
    sdk: {
      async activateModelProfile(options, applyOptions) {
        activateCalls.push([options, applyOptions]);
      },
    },
  };
}

test("applyConfiguredModelProfile activates the host-configured profile in-memory", async () => {
  const h = activationHarness();
  h.settings.get = (key) =>
    key === "modelProfile.default" ? "copilot-claude" : undefined;

  await applyConfiguredModelProfile(h.session, h.sdk);

  assert.equal(h.activateCalls.length, 1);
  const [options, applyOptions] = h.activateCalls[0];
  assert.equal(options.profileName, "copilot-claude");
  assert.strictEqual(options.session, h.session);
  assert.strictEqual(options.modelRegistry, h.session.modelRegistry);
  assert.strictEqual(options.settings, h.settings);
  assert.deepEqual(applyOptions, { persistDefault: false });
});

test("applyConfiguredModelProfile lets GJC_MODEL_PROFILE override the configured profile", async () => {
  const h = activationHarness();
  h.settings.get = () => "copilot-claude";
  const previous = process.env.GJC_MODEL_PROFILE;
  process.env.GJC_MODEL_PROFILE = "  custom-profile  ";
  try {
    await applyConfiguredModelProfile(h.session, h.sdk);
  } finally {
    if (previous === undefined) delete process.env.GJC_MODEL_PROFILE;
    else process.env.GJC_MODEL_PROFILE = previous;
  }

  assert.equal(h.activateCalls.length, 1);
  assert.equal(h.activateCalls[0][0].profileName, "custom-profile");
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
    await applyConfiguredModelProfile(h.session, h.sdk);
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
    await applyConfiguredModelProfile(h.session, h.sdk);
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
    await applyConfiguredModelProfile(h.session, h.sdk);
  } finally {
    if (previous === undefined) delete process.env.GJC_MODEL_PROFILE;
    else process.env.GJC_MODEL_PROFILE = previous;
  }

  assert.equal(h.activateCalls.length, 1);
  assert.equal(h.activateCalls[0][0].profileName, "copilot-claude");
});

test("applyConfiguredModelProfile surfaces activation failures loudly", async () => {
  const h = activationHarness();
  h.settings.get = () => "copilot-claude";
  h.sdk.activateModelProfile = async () => {
    throw new Error("missing credentials for provider github-copilot");
  };

  await assert.rejects(
    applyConfiguredModelProfile(h.session, h.sdk),
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
  const sdk = {
    Settings: {
      async init() {
        return { async cloneForCwd() { return agent.settings; } };
      },
    },
    SessionManager: { create: (workDir, sessionDir) => ({ workDir, sessionDir }) },
    async createAgentSession(options) {
      agent.settings = options.settings ?? agent.settings;
      return { session: agent };
    },
    async activateModelProfile() {
      throw new Error("missing credentials for provider github-copilot");
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
  });

  const events = [];
  const done = session.send({ type: "prompt", message: "hi" }, (e) => events.push(e));

  await gateDelay(0);
  const gateReq = events.find((e) => e && e.type === "gate_request");
  assert.ok(gateReq, "a gate_request event is emitted");
  assert.equal(gateReq.gateId, "g1");
  assert.equal(gateReq.kind, "question");
  assert.equal(gateReq.prompt, "Pick a fruit");
  assert.deepEqual(gateReq.choices, [
    { value: "a", label: "Apple" },
    { value: "b", label: "Banana" },
  ]);
  assert.equal(session.pendingGates.size, 1);

  // Idle is suspended while the gate is pending: waiting well past idleTimeoutMs
  // must NOT reap the session.
  await gateDelay(120);
  assert.equal(session.closed, false);

  const result = await session.answerGate("g1", "Banana");
  assert.equal(result.ok, true);
  await done;

  assert.deepEqual(agent.gateEmitter.resolveCalls, [{ gate_id: "g1", answer: "b" }]);
  assert.equal(session.pendingGates.size, 0);
  await session.dispose();
});

test("gate answer maps a 1-based index to the option value", async () => {
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
  assert.deepEqual(agent.gateEmitter.resolveCalls, [{ gate_id: "g2", answer: "y" }]);
  await session.dispose();
});

test("free-text gate (no options) passes the answer through verbatim", async () => {
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
    { gate_id: "g3", answer: "a long free-form answer" },
  ]);
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
  // The newcomer was best-effort rejected (answer: null).
  assert.ok(emitter.resolveCalls.some((r) => r.gate_id === "g5b" && r.answer === null));

  await session.answerGate("g5", "A");
  await done;
  assert.ok(emitter.resolveCalls.some((r) => r.gate_id === "g5" && r.answer === "a"));
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
      this.emit({ type: "agent_end" });
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
  // #35 spec requires a post-expiry/disposal answer to be a safe no-op. The
  // private disposal path (idle/hard-cap/gate-window rejection inside
  // #withStreamingTimeout) only disposes the underlying session; it does NOT
  // clear `pendingGates` (only the public dispose() does that). So a late
  // answerGate() call after a gate-window expiry still finds the stale entry
  // and "succeeds" against an abandoned gate emitter instead of no-op'ing.
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

test("adversarial: mapAnswerToGate — a numeric-looking label wins over positional index parsing", async () => {
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
    { gate_id: "g-numlabel", answer: "label-two" },
  ]);
  await session.dispose();
});

test("adversarial: mapAnswerToGate — duplicate labels resolve to the first matching option", async () => {
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
  assert.deepEqual(agent.gateEmitter.resolveCalls, [{ gate_id: "g-dup", answer: "first" }]);
  await session.dispose();
});

test("adversarial: mapAnswerToGate — whitespace/case variance still matches by label", async () => {
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
  assert.deepEqual(agent.gateEmitter.resolveCalls, [{ gate_id: "g-ws", answer: "a" }]);
  await session.dispose();
});

test("adversarial: mapAnswerToGate — out-of-range index (0, negative, overflow) passes the raw answer through", async () => {
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
    assert.deepEqual(agent.gateEmitter.resolveCalls, [{ gate_id: "g-range", answer: bad }]);
    await session.dispose();
  }
});

test("adversarial: mapAnswerToGate — an empty-string answer passes through rather than matching any option", async () => {
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

  await session.answerGate("g-empty", "");
  await done;
  assert.deepEqual(agent.gateEmitter.resolveCalls, [{ gate_id: "g-empty", answer: "" }]);
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
  // emit and self-rejected the pending gate with answer:null.
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
  await parked;
  await session.dispose();
});

test("#35 an oversized / unknown-kind gate is clamped so the bot's isGateRequestEvent still accepts it", async () => {
  const hugePrompt = "P".repeat(V0_LIMITS.GATE_PROMPT + 500);
  const hugeLabel = "L".repeat(V0_LIMITS.CHOICE_LABEL + 200);
  const agent = new GatingAgentSession({
    gate_id: "g-clamp",
    kind: "totally-unknown-kind",
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
  assert.equal(gateEvent.kind, "question", "unknown kind is coerced to a valid kind");
  assert.equal(gateEvent.prompt.length, V0_LIMITS.GATE_PROMPT, "prompt clamped to the limit");
  assert.equal(gateEvent.choices[0].label.length, V0_LIMITS.CHOICE_LABEL, "label clamped to the limit");
  assert.equal(isGateRequestEvent(gateEvent), true, "the clamped event passes the bot's validator");

  await session.answerGate("g-clamp", "a");
  await done;
  await session.dispose();
});
