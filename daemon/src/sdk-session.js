import { join } from "node:path";

const COMMAND_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * Load only the canonical SDK surfaces this daemon needs, rather than the
 * package-root barrel (`@gajae-code/coding-agent`) which pulls the entire
 * runtime graph — TUI/modes and browser/puppeteer tools — into the daemon
 * process. `@gajae-code/coding-agent/sdk` exports `createAgentSession` and
 * re-exports `Settings`; `.../session/session-manager` provides `SessionManager`.
 *
 * `config/model-profile-activation` is the config-layer surface used to honour
 * the host's model profile (see `applyConfiguredModelProfile`). It is
 * lower-level than `/sdk`, so it is more version-coupled — the trade accepted
 * so config discovery stays GJC's own concern (robust to config-path/schema
 * changes) instead of hand-parsed.
 */
async function loadCanonicalSdk() {
  const [
    { createAgentSession, Settings },
    { SessionManager },
    { activateModelProfile },
  ] = await Promise.all([
    import("@gajae-code/coding-agent/sdk"),
    import("@gajae-code/coding-agent/session/session-manager"),
    import("@gajae-code/coding-agent/config/model-profile-activation"),
  ]);
  return { createAgentSession, Settings, SessionManager, activateModelProfile };
}

export async function createSdkSession(workDir, loadSdk = loadCanonicalSdk) {
  const { createAgentSession, Settings, SessionManager, activateModelProfile } =
    await loadSdk();
  const sessionManager = SessionManager.create(
    workDir,
    join(workDir, ".gjc-remote-session")
  );
  // `Settings.init()` returns a process-global singleton whose cwd is frozen at
  // first call, so it cannot scope per pooled session. Clone it per workDir so
  // each session reads that directory's merged config AND so profile activation
  // (which mutates modelRoles/agentModelOverrides via settings.override) stays
  // isolated to this session instead of clobbering every other live session.
  const settings = await (await Settings.init()).cloneForCwd(workDir);
  const { session } = await createAgentSession({
    cwd: workDir,
    sessionManager,
    settings,
  });
  try {
    await applyConfiguredModelProfile(session, { activateModelProfile });
  } catch (error) {
    // The raw AgentSession is not yet owned by an SdkSession/SessionPool, so
    // dispose it here to avoid leaking the underlying runtime on a failed
    // activation before propagating the failure.
    await Promise.resolve()
      .then(() => session.dispose())
      .catch((disposeError) => {
        console.error(
          `gjc-remote daemon: failed to dispose session after activation failure for ${workDir}:`,
          disposeError
        );
      });
    throw error;
  }
  return new SdkSession(session);
}

/**
 * Replicate the model-profile activation the interactive CLI runs at startup.
 *
 * Bare `createAgentSession` only reads an already-resolved `settings.model`; it
 * does NOT expand `modelProfile.default` (a profile reference) into concrete
 * role→model assignments. A host configured with a profile (and empty
 * `modelRoles`) therefore falls through to the SDK's "first available" model —
 * commonly an unauthenticated model — so prompts return empty text under a
 * hidden `stopReason: "error"` (the "ok:true, hasText:false" silent failure).
 *
 * Resolution is delegated to GJC's own `activateModelProfile`, reading the
 * profile from `session.settings` — the per-workDir clone `createSdkSession`
 * built, so a project-level `modelProfile.default` override is honoured the same
 * way interactive GJC would in that directory, and the activation's in-memory
 * mutations never leak to other sessions. `persistDefault` is false: activation
 * is in-memory for this session only and never mutates the host's `config.yml`.
 * A misconfigured/uncredentialed profile throws here (e.g.
 * `ModelProfileCredentialError`), which fails session creation loudly instead
 * of silently serving a broken session.
 *
 * `GJC_MODEL_PROFILE` overrides the configured profile name when set.
 */
export async function applyConfiguredModelProfile(session, { activateModelProfile }) {
  const settings = session.settings;
  const configured = settings.get("modelProfile.default");
  const envOverride = (process.env.GJC_MODEL_PROFILE ?? "").trim();
  const configuredName = typeof configured === "string" ? configured.trim() : "";
  const profileName = envOverride || configuredName;

  if (!profileName) {
    if (configured !== undefined && configuredName === "") {
      // A present-but-unusable modelProfile.default (non-string or blank) is a
      // misconfiguration, not an unconfigured host — do not mask it as "none".
      console.warn(
        "gjc-remote daemon: modelProfile.default is set but not a usable " +
          `profile name (${JSON.stringify(configured)}); ignoring it. The SDK ` +
          "default model may be unauthenticated and return empty responses."
      );
    } else {
      console.warn(
        "gjc-remote daemon: no model profile configured " +
          "(modelProfile.default / GJC_MODEL_PROFILE); the SDK default model may " +
          "be unauthenticated and return empty responses."
      );
    }
    return;
  }

  try {
    await activateModelProfile(
      { session, modelRegistry: session.modelRegistry, settings, profileName },
      { persistDefault: false }
    );
  } catch (error) {
    throw new Error(
      `gjc-remote daemon: failed to activate model profile "${profileName}": ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error }
    );
  }
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
    this.activePromptRuns = 0;
    this.pendingLiveFollowUps = 0;
    this.liveFollowUpAcceptance = Promise.resolve();
    this.outstandingAcceptedFollowUps = 0;
    this.liveFollowUpBarrier = undefined;
    this.disposePromise = undefined;
  }

  send(command, onEvent, timeoutMs = COMMAND_TIMEOUT_MS) {
    if (this.closed) return Promise.reject(new Error("GJC SDK session is not running"));

    const isLiveControl = command?.type === "steer" || command?.type === "follow_up";
    if (!isLiveControl) return this.#enqueue(command, onEvent, timeoutMs);

    const result = Promise.resolve().then(() => {
      if (this.closed) throw new Error("GJC SDK session is not running");
      if (this.activePromptRuns <= 0 && !this.liveFollowUpBarrier) {
        return this.#enqueue(command, onEvent, timeoutMs);
      }
      if (command.type !== "follow_up") {
        return this.#runPromptCommand(command, onEvent, timeoutMs);
      }

      if (this.pendingLiveFollowUps === 0) {
        this.liveFollowUpAcceptance = Promise.resolve();
      }
      this.pendingLiveFollowUps += 1;
      const previousAcceptance = this.liveFollowUpAcceptance;
      let releaseAcceptance;
      let accepted = false;
      this.liveFollowUpAcceptance = new Promise((resolve) => {
        releaseAcceptance = resolve;
      });
      const settleAcceptance = async (queued, observedAgentEnds) => {
        await previousAcceptance;
        let agentEndsToWait;
        if (queued) {
          agentEndsToWait =
            observedAgentEnds +
            this.outstandingAcceptedFollowUps +
            (this.activePromptRuns > 0 ? 1 : 0) +
            1;
          this.outstandingAcceptedFollowUps += 1;
          accepted = true;
        }
        releaseAcceptance();
        return agentEndsToWait;
      };
      const control = this.#runPromptCommand(
        command,
        onEvent,
        timeoutMs,
        settleAcceptance
      );
      const priorBarrier = this.liveFollowUpBarrier;
      const barrier = Promise.allSettled(
        priorBarrier ? [priorBarrier, control] : [control]
      ).then(() => {});
      this.liveFollowUpBarrier = barrier;
      barrier.then(() => {
        if (this.liveFollowUpBarrier === barrier) {
          this.liveFollowUpBarrier = undefined;
        }
      });
      control.then(
        () => {
          this.pendingLiveFollowUps -= 1;
          if (accepted) this.outstandingAcceptedFollowUps -= 1;
        },
        () => {
          this.pendingLiveFollowUps -= 1;
          if (accepted) this.outstandingAcceptedFollowUps -= 1;
        }
      );
      return control;
    });
    this.inFlightControls.add(result);
    result.then(
      () => this.inFlightControls.delete(result),
      () => this.inFlightControls.delete(result)
    );
    return result;
  }

  #enqueue(command, onEvent, timeoutMs) {
    const result = this.queue.then(async () => {
      if (this.closed) throw new Error("GJC SDK session is not running");
      const barrier = this.liveFollowUpBarrier;
      if (barrier) await barrier;
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
      case "steer":
      case "follow_up":
        await this.#runPromptCommand(
          { type: "prompt", message: command.message },
          onEvent,
          timeoutMs
        );
        return;
      default:
        throw new Error(`Unknown SDK session command: ${command.type}`);
    }
  }

  async #runPromptCommand(command, onEvent, timeoutMs, settleFollowUpAcceptance) {
    let resolveAgentEnd;
    const agentEnd = new Promise((resolve) => {
      resolveAgentEnd = resolve;
    });
    const startsPrompt = command.type === "prompt";
    let promptActive = startsPrompt;
    let eventConsumerError;
    let observedAgentEnds = 0;
    let requiredAgentEnds = settleFollowUpAcceptance ? undefined : 1;
    if (startsPrompt) this.activePromptRuns += 1;

    const resolveIfComplete = () => {
      if (
        requiredAgentEnds !== undefined &&
        observedAgentEnds >= requiredAgentEnds
      ) {
        resolveAgentEnd();
      }
    };
    const markPromptInactive = () => {
      if (!promptActive) return;
      promptActive = false;
      this.activePromptRuns -= 1;
    };
    const unsubscribe = this.session.subscribe((event) => {
      if (event.type === "agent_end") {
        markPromptInactive();
        observedAgentEnds += 1;
        resolveIfComplete();
      }
      try {
        onEvent(event);
      } catch (error) {
        eventConsumerError ??=
          error instanceof Error
            ? error
            : new Error("SDK event consumer failed", { cause: error });
      }
    });

    try {
      await this.#withTimeout(async () => {
        if (command.type === "prompt") {
          await this.session.prompt(command.message);
        } else if (command.type === "steer") {
          await this.session.steer(command.message);
        } else {
          try {
            await this.session.followUp(command.message);
          } catch (error) {
            await settleFollowUpAcceptance?.(false);
            throw error;
          }
          if (settleFollowUpAcceptance) {
            requiredAgentEnds = await settleFollowUpAcceptance(true, observedAgentEnds);
            resolveIfComplete();
          }
        }
        await agentEnd;
      }, timeoutMs);
      if (eventConsumerError) throw eventConsumerError;
    } finally {
      markPromptInactive();
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
    const commands = Promise.allSettled([this.queue, ...this.inFlightControls]);
    await disposal;
    await commands;
  }
}
