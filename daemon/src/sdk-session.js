import { join } from "node:path";

const COMMAND_TIMEOUT_MS = 10 * 60 * 1000;

export async function createSdkSession(workDir, loadSdk = () => import("@gajae-code/coding-agent")) {
  const { createAgentSession, SessionManager } = await loadSdk();
  const sessionManager = SessionManager.create(
    workDir,
    join(workDir, ".gjc-remote-session")
  );
  const { session } = await createAgentSession({ cwd: workDir, sessionManager });
  return new SdkSession(session);
}

/**
 * Adapts an embedded AgentSession to the command/event interface formerly
 * provided by the RPC transport.
 */
export class SdkSession {
  constructor(session) {
    this.session = session;
    this.closed = false;
    this.queue = Promise.resolve();
    this.inFlightControls = new Set();
    this.disposePromise = undefined;
  }

  send(command, onEvent, timeoutMs = COMMAND_TIMEOUT_MS) {
    if (this.closed) return Promise.reject(new Error("GJC SDK session is not running"));

    const isLiveControl = command?.type === "steer" || command?.type === "follow_up";
    if (isLiveControl) {
      const result = Promise.resolve().then(() => {
        if (this.closed) throw new Error("GJC SDK session is not running");
        return this.#runPromptCommand(command, onEvent, timeoutMs);
      });
      this.inFlightControls.add(result);
      result.then(
        () => this.inFlightControls.delete(result),
        () => this.inFlightControls.delete(result)
      );
      return result;
    }

    const result = this.queue.then(() => {
      if (this.closed) throw new Error("GJC SDK session is not running");
      return this.#dispatch(command, onEvent, timeoutMs);
    });
    this.queue = result.catch(() => {});
    return result;
  }

  async #dispatch(command, onEvent, timeoutMs) {
    if (!command || typeof command !== "object") {
      throw new Error("Invalid SDK session command");
    }

    switch (command.type) {
      case "get_available_models":
      case "list_models": {
        const models = this.session.getAvailableModels().map(({ id, name, provider }) => ({
          id,
          name,
          provider,
        }));
        onEvent({
          type: "response",
          command: command.type,
          success: true,
          models,
          data: { models },
        });
        return;
      }
      case "set_model": {
        const model = this.session
          .getAvailableModels()
          .find(
            (candidate) =>
              candidate.provider === command.provider && candidate.id === command.modelId
          );
        if (!model) {
          throw new Error(`Model is not available: ${command.provider}/${command.modelId}`);
        }
        await this.#withTimeout(() => this.session.setModel(model), timeoutMs);
        onEvent({
          type: "response",
          command: command.type,
          success: true,
          data: { provider: model.provider, modelId: model.id },
        });
        return;
      }
      case "prompt":
        await this.#runPromptCommand(command, onEvent, timeoutMs);
        return;
      default:
        throw new Error(`Unknown SDK session command: ${command.type}`);
    }
  }

  async #runPromptCommand(command, onEvent, timeoutMs) {
    let resolveAgentEnd;
    const agentEnd = new Promise((resolve) => {
      resolveAgentEnd = resolve;
    });
    const unsubscribe = this.session.subscribe((event) => {
      onEvent(event);
      if (event.type === "agent_end") resolveAgentEnd();
    });

    try {
      await this.#withTimeout(async () => {
        if (command.type === "prompt") {
          await this.session.prompt(command.message);
        } else if (command.type === "steer") {
          await this.session.steer(command.message);
        } else {
          await this.session.followUp(command.message);
        }
        await agentEnd;
      }, timeoutMs);
    } finally {
      unsubscribe();
    }
  }

  async #withTimeout(operation, timeoutMs) {
    const timeoutError = new Error("SDK command timed out");
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(timeoutError), timeoutMs);
    });

    try {
      return await Promise.race([Promise.resolve().then(operation), timeout]);
    } catch (error) {
      if (error === timeoutError) {
        this.closed = true;
        void this.#disposeUnderlying().catch(() => {});
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  #disposeUnderlying() {
    if (!this.disposePromise) {
      this.disposePromise = Promise.resolve().then(() => this.session.dispose());
    }
    return this.disposePromise;
  }

  async dispose() {
    this.closed = true;
    const disposal = this.#disposeUnderlying();
    await Promise.all([this.queue, ...this.inFlightControls, disposal]);
  }
}
