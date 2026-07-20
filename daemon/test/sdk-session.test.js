import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";

import {
  SdkSession,
  applyConfiguredModelProfile,
  createSdkSession,
} from "../src/sdk-session.js";

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
