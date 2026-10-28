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
const delayActivation =
  process.env.GJC_CANCELLATION_FIXTURE_DELAY_ACTIVATION === "1";
const pendingActivations = new Set();
const delayRemoval =
  process.env.GJC_CANCELLATION_FIXTURE_DELAY_REMOVAL === "1";
const removalResult = process.env.GJC_CANCELLATION_FIXTURE_REMOVAL_RESULT;
const pendingRemovals = new Set();

function report(event) {
  if (typeof process.send !== "function" || process.connected !== true) return;
  process.send({ type: "cancellation_fixture", ...event }, () => {});
}

class CancellationAgent {
  constructor() {
    this.id = nextAgentId++;
    this.listeners = new Set();
    this.rawListeners = new Set();
    this.agent = {
      subscribe: (listener) => {
        this.rawListeners.add(listener);
        return () => this.rawListeners.delete(listener);
      },
    };
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
    report({ event: "dispose_started", agentId: this.id, pendingPrompts: this.pendingPrompts.size });
    if (disposalRejects) {
      report({ event: "dispose_rejected", agentId: this.id });
      throw new Error("fixture disposal rejected");
    }
    if (disposalBlocked) {
      await new Promise((resolve) => {
        releaseDisposal = resolve;
      });
      disposalBlocked = false;
    }
    for (const finish of [...this.pendingPrompts.values()]) finish();
    report({ event: "dispose_completed", agentId: this.id, pendingPrompts: this.pendingPrompts.size });
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
  if (message?.type === "cancellation_fixture_release_activation") {
    for (const activation of pendingActivations) {
      if (activation.message === message.message) activation.deliver();
    }
  }
  if (message?.type === "cancellation_fixture_release_removal") {
    for (const removal of pendingRemovals) {
      if (removal.message === message.message) removal.deliver();
    }
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
    const agent = new CancellationAgent();
    const session = new SdkSession(agent, {
      idleTimeoutMs: 60_000,
      hardCapMs: 120_000,
    });
    report({ event: "session_created", agentId: agent.id });
    const sendOwned = session.sendOwned.bind(session);
    session.sendOwned = (ownerId, command, onEvent, timeoutMs, { onActivate } = {}) => {
      // Expose the dequeue/activation-notification gap deterministically without
      // changing SDK internals or relying on cross-process microtask timing.
      let activationDelivered = !delayActivation;
      const activation = {
        message: command.message,
        deliver() {
          pendingActivations.delete(activation);
          activationDelivered = true;
          onActivate?.();
        },
      };
      const ticket = sendOwned(ownerId, command, onEvent, timeoutMs, {
        onActivate() {
          if (!delayActivation) {
            onActivate?.();
            return;
          }
          pendingActivations.add(activation);
          report({ event: "activation_deferred", agentId: agent.id, message: command.message });
        },
      });
      void ticket.result.then(
        () => pendingActivations.delete(activation),
        (error) => {
          pendingActivations.delete(activation);
          report({
            event: "ticket_failed",
            agentId: agent.id,
            message: command.message,
            code: error?.code,
            terminalDisposition: error?.terminalDisposition,
            closed: session.closed,
          });
        },
      );
      const result = ticket.result.then(async (value) => {
        if (value?.revokedBeforeStart !== true) return value;
        if (delayRemoval) {
          await new Promise((resolve) => {
            const removal = {
              message: command.message,
              deliver() {
                pendingRemovals.delete(removal);
                resolve();
              },
            };
            pendingRemovals.add(removal);
            report({ event: "removal_receipt_deferred", message: command.message });
          });
        }
        if (removalResult === "reject") {
          throw new Error("fixture removal receipt validation failed");
        }
        if (removalResult === "completed") {
          report({ event: "removal_result_overridden", message: command.message, closed: session.closed });
          return { disposition: "completed" };
        }
        return value;
      });
      report({ event: "ticket_created", agentId: agent.id, message: command.message });
      return {
        result,
        get phase() {
          return !activationDelivered && ticket.phase === "active" ? "queued" : ticket.phase;
        },
        revokeBeforeStart() {
          const phase = this.phase;
          const accepted = ticket.revokeBeforeStart();
          report({ event: "ticket_revoked", agentId: agent.id, message: command.message, phase, accepted });
          return accepted;
        },
      };
    };
    return session;
  },
});

await import("../src/daemon.js");
