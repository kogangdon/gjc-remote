import { join } from "node:path";
import { V0_LIMITS, isGateRequestEvent } from "@gjc-remote/shared";

const GATE_KINDS = new Set(["question", "approval", "execution"]);

const SDK_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const SDK_HARD_CAP_MS = 30 * 60 * 1000;
// #35: while a workflow gate is pending the agent loop is blocked awaiting the
// answer, so NO events stream and the idle timer would otherwise reap a healthy
// session. The idle timer is suspended for the gate's lifetime and replaced by
// this dedicated window; on expiry the run fails (and the session disposes) with
// a distinct error, converting the ask.timeout default-0 infinite hang into a
// bounded failure. Clamped to <= hardCapMs (the absolute backstop still wins).
const SDK_GATE_ANSWER_WINDOW_MS = 10 * 60 * 1000;

function resolveDuration(optionValue, envValue, fallback, envName) {
  const candidates = [optionValue, Number(envValue), fallback];
  for (const candidate of candidates) {
    if (typeof candidate === "number" && Number.isFinite(candidate) && candidate > 0) {
      return candidate;
    }
  }
  if (envName && envValue !== undefined && `${envValue}`.trim() !== "") {
    console.warn(
      `gjc-remote daemon: ${envName}=${JSON.stringify(envValue)} is not a positive ` +
        `duration; falling back to ${fallback}ms.`
    );
  }
  return fallback;
}

// #35: resolve the gate-answer window, then clamp it to hardCapMs so the
// absolute backstop always remains the outer bound. A configured window that
// exceeds hardCapMs is honoured up to the cap with a one-time warning.
function resolveGateWindow(optionValue, envValue, fallback, hardCapMs, envName) {
  const resolved = resolveDuration(optionValue, envValue, fallback, envName);
  if (resolved > hardCapMs) {
    // Only warn when an operator explicitly configured an oversized window; a
    // default that merely exceeds a (small) hard-cap is clamped silently.
    const envNumber = Number(envValue);
    const explicit =
      (typeof optionValue === "number" &&
        Number.isFinite(optionValue) &&
        optionValue > 0) ||
      (Number.isFinite(envNumber) && envNumber > 0);
    if (explicit) {
      console.warn(
        `gjc-remote daemon: gate-answer window ${resolved}ms exceeds the hard-cap ` +
          `${hardCapMs}ms; clamping to the hard-cap.`
      );
    }
    return hardCapMs;
  }
  return resolved;
}

// #35: derive a human-facing prompt for a gate_request event from a WorkflowGate.
function gatePrompt(gate) {
  const context = gate?.context ?? {};
  for (const candidate of [context.prompt, context.title, context.summary]) {
    if (typeof candidate === "string" && candidate.trim().length > 0) {
      return candidate;
    }
  }
  return "The workflow is waiting for your answer.";
}

// #35: map a user's free-text answer onto a WorkflowGateResponse `answer`. For a
// choice gate, resolve the text to the matching option's `value` (by exact label,
// case-insensitive, then by 1-based index). Otherwise pass the text through and
// let the SDK's schema validation decide.
function mapAnswerToGate(gate, answer) {
  const options = Array.isArray(gate?.options) ? gate.options : [];
  if (options.length === 0) return answer;
  const text = typeof answer === "string" ? answer.trim() : answer;
  const byLabel = options.find(
    (option) =>
      typeof option.label === "string" &&
      option.label.toLowerCase() === String(text).toLowerCase()
  );
  if (byLabel) return byLabel.value;
  const index = Number(text);
  if (Number.isInteger(index) && index >= 1 && index <= options.length) {
    return options[index - 1].value;
  }
  return answer;
}

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
  // Caveat: the clone isolates settings-derived state (model roles, profile
  // activation), but the SDK's capability/discovery layer keeps a module-global
  // bound to the most recently created session's settings, so disabledProviders
  // /capability resolution is still last-writer-wins across pooled sessions —
  // an upstream SDK limitation the clone cannot fix, no worse than before.
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
  constructor(session, options = {}) {
    this.session = session;
    this.closed = false;
    this.queue = Promise.resolve();
    this.queuedCommands = 0;
    this.inFlightControls = new Set();
    this.activePromptRuns = 0;
    this.pendingLiveFollowUps = 0;
    this.liveFollowUpAcceptance = Promise.resolve();
    this.outstandingAcceptedFollowUps = 0;
    this.liveFollowUpBarrier = undefined;
    this.disposePromise = undefined;
    this.setTimeoutFn = options.setTimeoutFn ?? setTimeout;
    this.clearTimeoutFn = options.clearTimeoutFn ?? clearTimeout;
    // idleTimeoutMs bounds silence between streamed events; hardCapMs is the
    // absolute per-run backstop that fires even under continuous activity and
    // always disposes the underlying session. Both default to the same values
    // as the bot's invoke idle/hard-cap (5min / 30min). There is deliberately
    // NO cross-process comparison here: the bot and daemon run in separate
    // processes with independent env, so the daemon cannot see the bot's cap.
    // Guaranteeing daemon hardCapMs >= bot invokeHardCapMs (so a bot that gives
    // up first never orphans a still-running daemon session) requires the bot
    // to advertise its cap over the wire plus a daemon-side warning / cancel
    // frame — tracked as the #35 (R10) follow-up, out of scope for #36.
    this.idleTimeoutMs = resolveDuration(
      options.idleTimeoutMs,
      process.env.GJC_SDK_IDLE_TIMEOUT_MS,
      SDK_IDLE_TIMEOUT_MS,
      "GJC_SDK_IDLE_TIMEOUT_MS"
    );
    this.hardCapMs = resolveDuration(
      options.hardCapMs,
      process.env.GJC_SDK_HARD_CAP_MS,
      SDK_HARD_CAP_MS,
      "GJC_SDK_HARD_CAP_MS"
    );
    this.gateAnswerWindowMs = resolveGateWindow(
      options.gateAnswerWindowMs,
      process.env.GJC_GATE_ANSWER_WINDOW_MS,
      SDK_GATE_ANSWER_WINDOW_MS,
      this.hardCapMs,
      "GJC_GATE_ANSWER_WINDOW_MS"
    );
    // #35: gateId -> { gate, emitter, controller }. At most one gate is
    // registered at a time; a concurrent gate is rejected (see #handleGateEmitted)
    // so the first resolver is never overwritten. Each entry stores the OWNING
    // run's idle controller so answerGate resumes exactly that run (multiple
    // prompt runs can share this session when channels map to one workDir).
    this.pendingGates = new Map();
    // #35: active prompt runs, most-recent last ({ onEvent, controller }). A gate
    // emitted on the shared session-level emitter is attributed to the most
    // recently started run.
    this.activeGateRuns = [];
    // #35: the session-level workflow-gate subscription is registered ONCE
    // (lazily, on the first prompt run) rather than per-run, so a single emitted
    // gate is not delivered to — and self-rejected by — every concurrent run's
    // listener.
    this.gateSubscribed = false;
    this.gateEmitter = undefined;
    this.gateUnsubscribe = undefined;
  }

  isBusy() {
    return (
      this.queuedCommands > 0 ||
      this.activePromptRuns > 0 ||
      this.inFlightControls.size > 0 ||
      this.pendingLiveFollowUps > 0 ||
      this.outstandingAcceptedFollowUps > 0 ||
      this.pendingGates.size > 0
    );
  }
  send(command, onEvent, timeoutMs = this.idleTimeoutMs) {
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
      const settleAcceptance = async (queued, getObservedAgentEnds) => {
        await previousAcceptance;
        let agentEndsToWait;
        if (queued) {
          const observedAgentEnds = getObservedAgentEnds();
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
    this.queuedCommands += 1;
    const result = this.queue
      .then(async () => {
        while (this.liveFollowUpBarrier) {
          const barrier = this.liveFollowUpBarrier;
          await barrier;
        }
        if (this.closed) throw new Error("GJC SDK session is not running");
        return this.#dispatch(command, onEvent, timeoutMs);
      })
      .finally(() => {
        this.queuedCommands -= 1;
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
    let resetIdle = () => {};
    // #35: register the session-level workflow-gate subscription once and track
    // this run so a gate emitted mid-run is attributed to it. The gate's onEvent
    // stream and idle controller both come from the owning run context, so a
    // second concurrent run on this session cannot clobber either.
    this.#ensureGateSubscription();
    const gateRun = { onEvent, controller: undefined };
    this.activeGateRuns.push(gateRun);
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
      resetIdle();
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
      await this.#withStreamingTimeout(
        async () => {
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
              requiredAgentEnds = await settleFollowUpAcceptance(true, () => observedAgentEnds);
              resolveIfComplete();
            }
          }
          await agentEnd;
        },
        timeoutMs,
        this.hardCapMs,
        this.gateAnswerWindowMs,
        (controller) => {
          resetIdle = controller.arm;
          gateRun.controller = controller;
          if (this.pendingGates.size > 0) {
            controller.suspendForGate();
          }
        }
      );
      if (eventConsumerError) throw eventConsumerError;
    } finally {
      markPromptInactive();
      unsubscribe();
      for (const [gateId, entry] of this.pendingGates) {
        if (entry.owner !== gateRun) continue;
        this.pendingGates.delete(gateId);
        for (const activeRun of this.activeGateRuns) {
          activeRun.controller?.resumeAfterGate();
        }
        void this.#rejectGate(entry.emitter, gateId);
      }
      const runIndex = this.activeGateRuns.indexOf(gateRun);
      if (runIndex >= 0) this.activeGateRuns.splice(runIndex, 1);
    }
  }

  // #35: register the workflow-gate subscription once for the whole session.
  // Legacy sessions without an emitter are marked subscribed so we never retry.
  #ensureGateSubscription() {
    if (this.gateSubscribed) return;
    this.gateSubscribed = true;
    const emitter = this.session.getWorkflowGateEmitter?.();
    if (typeof emitter?.onGateEmitted !== "function") return;
    this.gateEmitter = emitter;
    this.gateUnsubscribe = emitter.onGateEmitted((gate) =>
      this.#handleGateEmitted(gate, emitter)
    );
  }

  // #35: a workflow gate opened during an active run. Register it, suspend the
  // owning run's idle timer, and synthesize a clamped gate_request event onto
  // that run's stream so the bot can render it and collect an answer.
  #handleGateEmitted(gate, gateEmitter) {
    const gateId = gate?.gate_id;
    if (typeof gateId !== "string" || gateId.length === 0) return;
    // The single session-level listener can be invoked more than once for the
    // same gate on some SDK builds; treat a re-delivery as an idempotent no-op.
    if (this.pendingGates.has(gateId)) return;
    if (this.pendingGates.size > 0) {
      // Concurrent-gate guard: never overwrite the first resolver. Best-effort
      // reject the newcomer so it does not hang; the first gate stays pending.
      console.warn(
        `gjc-remote daemon: rejecting concurrent workflow gate ${gateId}; a gate is already pending.`
      );
      void this.#rejectGate(gateEmitter, gateId);
      return;
    }
    // Attribute the gate to the most recently started run (gates emit while that
    // run's prompt() is executing). With no active run there is nothing to
    // suspend or stream to, so reject rather than leak a pending gate.
    const gateRun = this.activeGateRuns[this.activeGateRuns.length - 1];
    if (!gateRun) {
      void this.#rejectGate(gateEmitter, gateId);
      return;
    }
    const event = this.#buildGateRequestEvent(gate, gateId);
    if (!event) {
      // A malformed/oversized gate the bot could not render; do not hang the run.
      console.error(
        `gjc-remote daemon: dropping unrenderable workflow gate ${gateId}.`
      );
      void this.#rejectGate(gateEmitter, gateId);
      return;
    }
    this.pendingGates.set(gateId, {
      gate,
      emitter: gateEmitter,
      owner: gateRun,
      controller: gateRun.controller,
    });
    for (const activeRun of this.activeGateRuns) {
      activeRun.controller?.suspendForGate();
    }
    try {
      gateRun.onEvent(event);
    } catch (error) {
      console.error("gjc-remote daemon: failed to emit gate_request event:", error);
    }
  }

  // #35: build a protocol-conforming gate_request event, clamping the prompt,
  // kind, and choices to V0_LIMITS so the bot's isGateRequestEvent never silently
  // drops a valid-but-oversized SDK gate. Returns undefined if it cannot be made
  // to validate.
  #buildGateRequestEvent(gate, gateId) {
    const kind = GATE_KINDS.has(gate?.kind) ? gate.kind : "question";
    const prompt = gatePrompt(gate).slice(0, V0_LIMITS.GATE_PROMPT);
    const options = Array.isArray(gate?.options) ? gate.options : [];
    const choices =
      options.length > 0
        ? options.slice(0, V0_LIMITS.MAX_CHOICES).map((option) => ({
            value: option.value,
            label:
              typeof option.label === "string"
                ? option.label.slice(0, V0_LIMITS.CHOICE_LABEL)
                : String(option.label ?? "").slice(0, V0_LIMITS.CHOICE_LABEL),
          }))
        : undefined;
    const event = {
      type: "gate_request",
      gateId,
      prompt,
      kind,
      ...(choices ? { choices } : {}),
    };
    return isGateRequestEvent(event) ? event : undefined;
  }

  // #35: resolve a pending gate with a user's answer (called from daemon message
  // routing when an ANSWER frame arrives). Runs concurrently with the blocked
  // prompt run that is awaiting the gate. A stale/unknown gateId is a safe no-op.
  async answerGate(gateId, answer) {
    if (this.closed) return { ok: false, error: "session is closed" };
    const entry = this.pendingGates.get(gateId);
    if (!entry) return { ok: false, error: "no pending gate for id" };
    this.pendingGates.delete(gateId);
    for (const activeRun of this.activeGateRuns) {
      activeRun.controller?.resumeAfterGate();
    }
    try {
      const resolution = await entry.emitter.resolveGate({
        gate_id: gateId,
        answer: mapAnswerToGate(entry.gate, answer),
      });
      return { ok: true, resolution };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async #rejectGate(gateEmitter, gateId) {
    try {
      await gateEmitter?.resolveGate?.({ gate_id: gateId, answer: null });
    } catch {
      // Best-effort: the concurrent run's own idle/hard-cap still bounds it.
    }
  }

  async #withTimeout(operation, timeoutMs) {
    const timeoutError = new Error("SDK command timed out");
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = this.setTimeoutFn(() => reject(timeoutError), timeoutMs);
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
      this.clearTimeoutFn(timer);
    }
  }
  async #withStreamingTimeout(operation, idleMs, hardCapMs, gateWindowMs, onArm) {
    const idleError = new Error("SDK command timed out");
    const hardCapError = new Error("SDK command exceeded absolute hard-cap");
    const gateError = new Error("SDK gate answer window expired");
    let idleTimer;
    let hardCapTimer;
    let gateTimer;
    let rejectTimeout;
    const timeout = new Promise((_, reject) => {
      rejectTimeout = reject;
    });
    let settled = false;
    let gateSuspended = false;
    const armIdle = () => {
      if (settled || gateSuspended) return;
      this.clearTimeoutFn(idleTimer);
      idleTimer = this.setTimeoutFn(() => rejectTimeout(idleError), idleMs);
    };
    // #35: while a workflow gate is pending, stop the idle timer and bound the
    // wait by the dedicated gate-answer window instead. Idempotent: repeated
    // suspend/resume calls are safe no-ops.
    const suspendForGate = () => {
      if (settled || gateSuspended) return;
      gateSuspended = true;
      this.clearTimeoutFn(idleTimer);
      gateTimer = this.setTimeoutFn(() => rejectTimeout(gateError), gateWindowMs);
    };
    const resumeAfterGate = () => {
      if (settled || !gateSuspended) return;
      gateSuspended = false;
      this.clearTimeoutFn(gateTimer);
      armIdle();
    };
    armIdle();
    hardCapTimer = this.setTimeoutFn(() => rejectTimeout(hardCapError), hardCapMs);

    onArm?.({ arm: armIdle, suspendForGate, resumeAfterGate });

    try {
      return await Promise.race([Promise.resolve().then(operation), timeout]);
    } catch (error) {
      if (error === idleError || error === hardCapError || error === gateError) {
        this.closed = true;
        // #35: a timeout/hard-cap/gate-window expiry tears down the session via
        // #disposeUnderlying (not the public dispose()), so drop any pending gate
        // here too — otherwise a late answerGate() would resolve an orphaned gate.
        this.pendingGates.clear();
        void this.#disposeUnderlying().catch(() => {});
      }
      throw error;
    } finally {
      settled = true;
      this.clearTimeoutFn(idleTimer);
      this.clearTimeoutFn(hardCapTimer);
      this.clearTimeoutFn(gateTimer);
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
    // #35: drop any pending gate so a later answer is a no-op, unsubscribe the
    // session-level gate listener, and forget active runs; the awaiting run is
    // already being torn down by the disposal below.
    this.pendingGates.clear();
    this.activeGateRuns.length = 0;
    try {
      this.gateUnsubscribe?.();
    } catch {
      // Best-effort: the underlying session is being disposed anyway.
    }
    this.gateUnsubscribe = undefined;
    const disposal = this.#disposeUnderlying();
    const commands = Promise.allSettled([this.queue, ...this.inFlightControls]);
    await disposal;
    await commands;
  }
}
