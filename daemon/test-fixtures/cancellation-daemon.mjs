import { SdkSession } from "../src/sdk-session.js";

const sessionFactorySymbol = Symbol.for("@gjc-remote/daemon/test-session-factory");
const agents = new Set();
let nextAgentId = 1;
let disposalBlocked = process.env.GJC_CANCELLATION_FIXTURE_BLOCK_DISPOSAL === "1";
const disposalRejects =
  process.env.GJC_CANCELLATION_FIXTURE_REJECT_DISPOSAL === "1";
let releaseDisposal;
let creationBlocked = process.env.GJC_CANCELLATION_FIXTURE_BLOCK_CREATION === "1";
let releaseCreation;

function report(event) {
  if (typeof process.send !== "function" || process.connected !== true) return;
  process.send({ type: "cancellation_fixture", ...event }, () => {});
}

class CancellationAgent {
  constructor() {
    this.id = nextAgentId++;
    this.listeners = new Set();
    this.pendingPrompts = new Map();
    agents.add(this);
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  getWorkflowGateEmitter() {
    return undefined;
  }

  getAvailableModels() {
    report({ event: "models_listed", agentId: this.id });
    return [{ provider: "fixture", id: "model-a", name: "Model A" }];
  }

  async setModel(model) {
    report({
      event: "model_set",
      agentId: this.id,
      provider: model.provider,
      modelId: model.id,
    });
  }

  emit(event) {
    for (const listener of [...this.listeners]) listener(event);
  }

  prompt(message) {
    report({ event: "prompt_started", agentId: this.id, message });
    this.emit({ type: "agent_start" });
    return new Promise((resolve) => {
      this.pendingPrompts.set(message, () => {
        this.emit({
          type: "agent_end",
          stopReason: "completed",
          messages: [{
            role: "assistant",
            content: [{ type: "text", text: `completed:${message}` }],
            stopReason: "stop",
            timestamp: 1,
          }],
        });
        this.pendingPrompts.delete(message);
        resolve();
      });
    });
  }

  async dispose() {
    report({ event: "dispose_started", agentId: this.id });
    if (disposalRejects) throw new Error("fixture disposal rejected");
    if (disposalBlocked) {
      await new Promise((resolve) => {
        releaseDisposal = resolve;
      });
      disposalBlocked = false;
    }
    for (const finish of [...this.pendingPrompts.values()]) finish();
    report({ event: "dispose_completed", agentId: this.id });
  }
}

process.on("message", (message) => {
  if (message?.type === "cancellation_fixture_release_prompt") {
    for (const agent of agents) agent.pendingPrompts.get(message.message)?.();
  }
  if (message?.type === "cancellation_fixture_release_disposal") {
    releaseDisposal?.();
  }
  if (message?.type === "cancellation_fixture_release_creation") {
    releaseCreation?.();
  }
});

Object.defineProperty(globalThis, sessionFactorySymbol, {
  configurable: false,
  enumerable: false,
  writable: false,
  value: async () => {
    if (creationBlocked) {
      report({ event: "creation_started" });
      await new Promise((resolve) => {
        releaseCreation = resolve;
      });
      creationBlocked = false;
    }
    return new SdkSession(new CancellationAgent(), {
      idleTimeoutMs: 60_000,
      hardCapMs: 120_000,
    });
  },
});

await import("../src/daemon.js");
