import { createHash } from "node:crypto";
import { isAbsolute, join, resolve } from "node:path";
import {
  PROTOCOL_ERROR_CODES,
  V0_LIMITS,
  INVOKE_OWNERSHIP_RETENTION_MS,
  isGateRequestEvent,
} from "@gjc-remote/shared";

const GATE_KINDS = new Set(["question", "approval", "execution"]);
// @gajae-code/agent-core 0.16.6 can emit an `agent_end` checkpoint before
// continuing these mid-run maintenance outcomes. AgentSession normally
// suppresses them, but they still are not terminal if an injected/session seam
// exposes one.
const CONTINUING_MAINTENANCE_OUTCOMES = new Set([
  "pruned",
  "compacted",
  "promoted",
]);
const APPROVAL_DECISIONS = ["approve", "request-changes", "reject"];
const EXECUTION_DECISIONS = ["approve", "decline"];
const SAFE_FAILURE_CODE = /^[A-Za-z0-9._-]+$/;
const SAFE_FAILURE_CODE_MAX = 64;
const LIVE_CONTROL_UNSUPPORTED_CODE =
  PROTOCOL_ERROR_CODES.LIVE_CONTROL_UNSUPPORTED;

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
    if (
      Number.isInteger(candidate) &&
      candidate > 0 &&
      candidate <= INVOKE_OWNERSHIP_RETENTION_MS
    ) {
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

function isPlainRecord(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.has(key));
}

function sameArray(left, right) {
  return (
    Array.isArray(left) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

// SDK 0.16.6 has two concrete gate-answer schema families. AskTool gates use
// buildAskGateAnswerSchema() and approval/execution gates use decision objects.
// Recognize only those producer shapes: inventing a scalar fallback would turn a
// transport limitation into a workflow decision the SDK never received.
function gateAnswerCodec(gate) {
  if (!GATE_KINDS.has(gate?.kind) || !isPlainRecord(gate?.schema)) return undefined;
  const schema = gate.schema;
  const properties = schema.properties;
  if (
    schema.type !== "object" ||
    schema.additionalProperties !== false ||
    !isPlainRecord(properties)
  ) {
    return undefined;
  }

  const options = Array.isArray(gate.options) ? gate.options : [];
  const labels = [];
  for (const option of options) {
    if (
      !isPlainRecord(option) ||
      typeof option.label !== "string" ||
      option.label.length === 0
    ) {
      return undefined;
    }
    labels.push(option.label);
  }

  const selected = properties.selected;
  const state = gate.context?.stage_state;
  if (
    isPlainRecord(selected) &&
    selected.type === "array" &&
    selected.uniqueItems === true &&
    isPlainRecord(selected.items) &&
    sameArray(selected.items.enum, labels) &&
    isPlainRecord(properties.other) &&
    properties.other.type === "boolean" &&
    isPlainRecord(properties.custom) &&
    properties.custom.type === "string" &&
    isPlainRecord(properties.action) &&
    sameArray(properties.action.enum, ["answer", "clarify"]) &&
    isPlainRecord(properties.question) &&
    properties.question.type === "string" &&
    Array.isArray(schema.anyOf) &&
    schema.anyOf.length === 3 &&
    isPlainRecord(state) &&
    typeof state.multi === "boolean" &&
    typeof state.allow_empty === "boolean" &&
    sameArray(state.options, labels) &&
    state.other_option === "Other (type your own)" &&
    state.clarification_action === "clarify" &&
    options.every((option) => option.value === option.label)
  ) {
    return {
      type: "ask",
      labels,
      multi: state.multi,
      allowEmpty: state.allow_empty,
    };
  }

  const decision = properties.decision;
  const expectedDecisions =
    gate.kind === "approval"
      ? APPROVAL_DECISIONS
      : gate.kind === "execution"
        ? EXECUTION_DECISIONS
        : undefined;
  const detailKey = gate.kind === "approval" ? "comments" : "reason";
  if (
    expectedDecisions &&
    isPlainRecord(decision) &&
    decision.type === "string" &&
    sameArray(decision.enum, expectedDecisions) &&
    sameArray(schema.required, ["decision"]) &&
    hasOnlyKeys(properties, new Set(["decision", detailKey])) &&
    isPlainRecord(properties[detailKey]) &&
    properties[detailKey].type === "string" &&
    options.length === expectedDecisions.length &&
    options.every(
      (option, index) =>
        option.value === expectedDecisions[index] &&
        option.label === expectedDecisions[index]
    )
  ) {
    return { type: gate.kind, decisions: expectedDecisions, detailKey };
  }

  return undefined;
}

function parseStructuredGateAnswer(answer) {
  if (typeof answer !== "string") {
    return { ok: false, error: "gate answer must be text" };
  }
  const text = answer.trim();
  if (!text.startsWith("{") && !text.startsWith("[")) {
    return { ok: true, text };
  }
  try {
    const parsed = JSON.parse(text);
    if (!isPlainRecord(parsed)) {
      return { ok: false, error: "structured gate answer must be an object" };
    }
    return { ok: true, text, structured: parsed };
  } catch {
    return { ok: false, error: "structured gate answer is not valid JSON" };
  }
}

function validateAskAnswerShape(answer, codec) {
  if (!isPlainRecord(answer)) return false;
  if (answer.action === "clarify") {
    return (
      hasOnlyKeys(answer, new Set(["action", "question"])) &&
      typeof answer.question === "string" &&
      /\S/u.test(answer.question)
    );
  }
  if (
    !hasOnlyKeys(answer, new Set(["selected", "other", "custom", "action"])) ||
    (answer.action !== undefined && answer.action !== "answer") ||
    !Array.isArray(answer.selected) ||
    !answer.selected.every(
      (selection) =>
        typeof selection === "string" && codec.labels.includes(selection)
    ) ||
    new Set(answer.selected).size !== answer.selected.length ||
    (!codec.multi && answer.selected.length > 1)
  ) {
    return false;
  }
  if (answer.other === true) {
    return (
      (codec.multi || answer.selected.length === 0) &&
      typeof answer.custom === "string" &&
      /\S/u.test(answer.custom)
    );
  }
  return (
    (answer.other === undefined || answer.other === false) &&
    answer.custom === undefined &&
    (codec.allowEmpty || answer.selected.length > 0)
  );
}

function validateDecisionAnswerShape(answer, codec) {
  if (
    !isPlainRecord(answer) ||
    !hasOnlyKeys(answer, new Set(["decision", codec.detailKey])) ||
    !codec.decisions.includes(answer.decision)
  ) {
    return false;
  }
  const detail = answer[codec.detailKey];
  if (detail !== undefined && typeof detail !== "string") return false;
  return !(
    codec.type === "approval" &&
    answer.decision === "request-changes" &&
    (typeof detail !== "string" || detail.trim() === "")
  );
}

function matchGateChoice(options, text) {
  const byLabel = options.find(
    (option) => option.label.toLowerCase() === text.toLowerCase()
  );
  if (byLabel) return byLabel;
  const index = Number(text);
  if (Number.isInteger(index) && index >= 1 && index <= options.length) {
    return options[index - 1];
  }
  return undefined;
}

// Encode the daemon's bounded text answer into the exact object unions emitted
// by SDK 0.16.6. JSON objects are the explicit route for multi-select,
// clarification, custom-answer disambiguation, and decision comments/reasons.
function encodeGateAnswer(gate, answer) {
  const codec = gateAnswerCodec(gate);
  if (!codec) return { ok: false, error: "unsupported workflow gate schema" };
  const parsed = parseStructuredGateAnswer(answer);
  if (!parsed.ok) return parsed;

  if (parsed.structured) {
    const valid =
      codec.type === "ask"
        ? validateAskAnswerShape(parsed.structured, codec)
        : validateDecisionAnswerShape(parsed.structured, codec);
    return valid
      ? { ok: true, answer: parsed.structured }
      : { ok: false, error: "unsupported gate answer shape" };
  }

  const options = Array.isArray(gate.options) ? gate.options : [];
  const choice = matchGateChoice(options, parsed.text);
  if (codec.type === "ask") {
    if (choice) return { ok: true, answer: { selected: [choice.label] } };
    if (parsed.text === "") {
      return codec.allowEmpty
        ? { ok: true, answer: { selected: [] } }
        : { ok: false, error: "gate answer must not be empty" };
    }
    return {
      ok: true,
      answer: { selected: [], other: true, custom: answer },
    };
  }

  if (!choice) return { ok: false, error: "unsupported gate decision" };
  if (codec.type === "approval" && choice.value === "request-changes") {
    return {
      ok: false,
      error: "request-changes requires structured comments",
    };
  }
  return { ok: true, answer: { decision: choice.value } };
}

function sanitizedFailure(error, fallbackCode = "prompt_failed") {
  let candidate;
  try {
    candidate = error?.code;
  } catch {
    candidate = undefined;
  }
  const code =
    typeof candidate === "string" &&
    candidate.length <= SAFE_FAILURE_CODE_MAX &&
    SAFE_FAILURE_CODE.test(candidate)
      ? candidate
      : fallbackCode;
  return { code, message: "Prompt submission failed." };
}

function sdkTerminalError(outcome) {
  const error = new Error(
    `GJC SDK invocation failed${outcome.code ? ` (${outcome.code})` : ""}`
  );
  if (outcome.code) error.code = outcome.code;
  error.terminalDisposition = outcome.disposition;
  return error;
}

function failedTerminalOutcome(failure) {
  return { disposition: "failed", code: failure.code };
}

function timedOutTerminalError(message) {
  const error = new Error(message);
  error.terminalDisposition = "timed_out";
  error.interruptionConfirmed = false;
  return error;
}

function lastAssistantMessage(messages) {
  if (!Array.isArray(messages)) return undefined;
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (isPlainRecord(message) && message.role === "assistant") return message;
  }
  return undefined;
}

function assistantHasActivity(message) {
  let content;
  try {
    content = message.content;
  } catch {
    return false;
  }
  if (typeof content === "string") return content.trim().length > 0;
  if (!Array.isArray(content)) return false;
  return content.some((block) => {
    if (!isPlainRecord(block) || typeof block.type !== "string") return false;
    if (block.type !== "text") return block.type.length > 0;
    return typeof block.text === "string" && block.text.trim().length > 0;
  });
}

// An agent_end is a readiness boundary, not evidence that its work succeeded.
// Mirror the installed SDK host's terminal classification without retaining raw
// provider error text. Explicit event-level dispositions win over all assistant
// content because a partial assistant message is not proof that a paused,
// cancelled, or failed run completed.
function terminalOutcome(event, reportedFailure) {
  if (event?.stopReason === "paused") return { disposition: "paused" };
  if (event?.stopReason === "cancelled") {
    return { disposition: "cancelled", code: "aborted" };
  }
  if (event.stopReason === "maintenance") {
    if (event.maintenanceOutcome === "failed") {
      return failedTerminalOutcome(
        sanitizedFailure(undefined, "context_maintenance_failed")
      );
    }
    if (event.maintenanceOutcome === "aborted") {
      return failedTerminalOutcome(sanitizedFailure(undefined, "aborted"));
    }
  }
  if (reportedFailure) {
    return failedTerminalOutcome(reportedFailure);
  }
  if (event.stopReason !== "completed") {
    return failedTerminalOutcome(sanitizedFailure(undefined));
  }

  let messages;
  try {
    messages = event.messages;
  } catch {
    messages = undefined;
  }
  const assistant = lastAssistantMessage(messages);
  if (!assistant) {
    return failedTerminalOutcome(sanitizedFailure(undefined));
  }

  let stopReason;
  try {
    stopReason = assistant.stopReason;
  } catch {
    return failedTerminalOutcome(sanitizedFailure(undefined));
  }
  if (stopReason === "aborted") {
    return {
      disposition: "cancelled",
      code: sanitizedFailure(undefined, "aborted").code,
    };
  }
  if (stopReason === "error") {
    let status;
    try {
      status = assistant.errorStatus ?? assistant.transportFailure?.status;
    } catch {
      status = undefined;
    }
    if (status === 402 || status === 429) {
      return failedTerminalOutcome(
        sanitizedFailure(undefined, `provider_http_${status}`)
      );
    }
    return failedTerminalOutcome(
      sanitizedFailure({ code: assistant.errorCode }, "provider_rejected")
    );
  }
  return assistantHasActivity(assistant)
    ? { disposition: "completed" }
    : failedTerminalOutcome(sanitizedFailure(undefined));
}

function isTerminalAgentEnd(event) {
  return (
    event?.type === "agent_end" &&
    !(
      event.stopReason === "maintenance" &&
      CONTINUING_MAINTENANCE_OUTCOMES.has(event.maintenanceOutcome)
    )
  );
}

function attemptScopeBoundary(scope) {
  if (
    !isPlainRecord(scope) ||
    typeof scope.attemptId !== "string" ||
    !Number.isSafeInteger(scope.generation) ||
    typeof scope.lineage !== "string"
  ) {
    return undefined;
  }
  return {
    attemptId: scope.attemptId,
    generation: scope.generation,
    lineage: scope.lineage,
  };
}

function attemptScopesEqual(left, right) {
  return (
    left?.attemptId === right?.attemptId &&
    left?.generation === right?.generation &&
    left?.lineage === right?.lineage
  );
}

/**
 * Load only the canonical SDK surfaces this daemon needs, rather than the
 * package-root barrel (`@gajae-code/coding-agent`) which pulls the entire
 * runtime graph — TUI/modes and browser/puppeteer tools — into the daemon
 * process. `@gajae-code/coding-agent/sdk` exports `createAgentSession`;
 * `.../session/session-manager` provides the public `SessionManager` needed for
 * the daemon's dedicated transcript directory.
 */
async function loadCanonicalSdk() {
  const [{ createAgentSession }, { SessionManager }] = await Promise.all([
    import("@gajae-code/coding-agent/sdk"),
    import("@gajae-code/coding-agent/session/session-manager"),
  ]);
  return { createAgentSession, SessionManager };
}

export function resolveSdkSessionDirectory(workDir, sessionRoot) {
  if (sessionRoot === undefined) {
    return join(workDir, ".gjc-remote-session");
  }
  if (typeof sessionRoot !== "string" || !isAbsolute(sessionRoot)) {
    throw new TypeError("sessionRoot must be an absolute path");
  }
  const workDirHash = createHash("sha256").update(resolve(workDir)).digest("hex");
  return join(sessionRoot, workDirHash);
}

export async function createSdkSession(workDir, loadSdk = loadCanonicalSdk, { sessionRoot } = {}) {
  const sessionDir = resolveSdkSessionDirectory(workDir, sessionRoot);
  const { createAgentSession, SessionManager } = await loadSdk();
  const sessionManager = SessionManager.create(workDir, sessionDir);
  // SDK 0.16.6 creates an isolated Settings.loadForScope({ cwd, agentDir })
  // instance when `settings` is omitted and closes that owned scope from
  // AgentSession.dispose(). Supplying a clone here would transfer ownership to
  // the daemon and bypass that lifecycle.
  const { session } = await createAgentSession({
    cwd: workDir,
    sessionManager,
  });
  try {
    await applyConfiguredModelProfile(session);
  } catch (error) {
    // The raw AgentSession is not yet owned by an SdkSession/SessionPool, so
    // dispose it here to avoid leaking the underlying runtime on a failed
    // activation before propagating the failure.
    await Promise.resolve()
      .then(() => session.dispose())
      .catch(() => {
        console.error(
          "gjc-remote daemon: failed to dispose session after activation failure."
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
 * Resolution reads the profile from the SDK-owned scope-local
 * `session.settings`, so a project-level `modelProfile.default` override is
 * honoured in that directory. `AgentSession.activateModelProfileForControl()`
 * is the 0.16.6 public nonvisual, session-scoped activation surface; it never
 * persists `modelProfile.default`. A misconfigured/uncredentialed profile
 * throws here, which fails session creation loudly instead of silently serving
 * a broken session.
 *
 * `GJC_MODEL_PROFILE` overrides the configured profile name when set.
 */
export async function applyConfiguredModelProfile(session) {
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
    await session.activateModelProfileForControl(profileName);
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
    this.ownedQueueTickets = new Set();
    this.activePromptRuns = 0;
    this.adapterWaiterCancellations = new Set();
    this.inFlightGateAnswers = new Set();
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
    // #35: gateId -> { gate, emitter, controller, response? }. At most one gate is
    // registered at a time; a concurrent gate is rejected (see #handleGateEmitted)
    // so the first resolver is never overwritten. Each entry stores the OWNING
    // run's idle controller so answerGate resumes exactly that run (multiple
    // prompt runs can share this session when channels map to one workDir).
    this.pendingGates = new Map();
    // One successor may be emitted while its accepted predecessor is still
    // advancing. It is held off-stream until the predecessor's exact response
    // has a completed resolution; the owning run's existing gate/hard-cap
    // timers bound this candidate.
    this.deferredGateCandidate = undefined;
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
      this.pendingGates.size > 0 ||
      this.deferredGateCandidate !== undefined
    );
  }
  send(command, onEvent, timeoutMs = this.idleTimeoutMs) {
    if (this.closed) return Promise.reject(new Error("GJC SDK session is not running"));

    const isLiveControl = command?.type === "steer" || command?.type === "follow_up";
    if (!isLiveControl) return this.#enqueue(command, onEvent, timeoutMs).result;

    return Promise.resolve().then(() => {
      if (this.closed) throw new Error("GJC SDK session is not running");
      if (this.activePromptRuns <= 0) {
        return this.#enqueue(command, onEvent, timeoutMs).result;
      }
      const error = new Error(
        `Live SDK ${command.type} is unavailable until the SDK exposes a supported queued-input ownership contract`
      );
      error.code = LIVE_CONTROL_UNSUPPORTED_CODE;
      throw error;
    });
  }

  sendOwned(
    ownerId,
    command,
    onEvent,
    timeoutMs = this.idleTimeoutMs,
    { onActivate } = {}
  ) {
    const ticket = this.#createOwnedQueueTicket(ownerId);
    if (typeof ownerId !== "string") {
      this.#rejectOwnedQueueTicket(ticket, new Error("Invalid SDK queue owner"));
      return ticket.publicTicket;
    }
    if (this.closed) {
      this.#rejectOwnedQueueTicket(ticket, new Error("GJC SDK session is not running"));
      return ticket.publicTicket;
    }
    if (onActivate !== undefined && typeof onActivate !== "function") {
      this.#rejectOwnedQueueTicket(
        ticket,
        new Error("Invalid SDK queue activation callback")
      );
      return ticket.publicTicket;
    }
    const isLiveControl =
      command?.type === "steer" || command?.type === "follow_up";
    if (isLiveControl) {
      this.ownedQueueTickets.add(ticket);
      void Promise.resolve().then(() => {
        if (ticket.phase !== "queued") return;
        if (this.closed) {
          this.#rejectOwnedQueueTicket(
            ticket,
            new Error("GJC SDK session is not running")
          );
          return;
        }
        if (this.activePromptRuns > 0) {
          const error = new Error(
            `Live SDK ${command.type} is unavailable until the SDK exposes a supported queued-input ownership contract`
          );
          error.code = LIVE_CONTROL_UNSUPPORTED_CODE;
          this.#rejectOwnedQueueTicket(ticket, error);
          return;
        }
        this.#enqueue(command, onEvent, timeoutMs, ticket, onActivate);
      });
      return ticket.publicTicket;
    }
    this.#enqueue(command, onEvent, timeoutMs, ticket, onActivate);
    return ticket.publicTicket;
  }

  #createOwnedQueueTicket(ownerId) {
    const ticket = {
      ownerId,
      phase: "queued",
      settled: false,
      resolve: undefined,
      reject: undefined,
      publicTicket: undefined,
    };
    const result = new Promise((resolve, reject) => {
      ticket.resolve = resolve;
      ticket.reject = reject;
    });
    ticket.publicTicket = {
      result,
      revokeBeforeStart: () => {
        if (ticket.phase !== "queued") return false;
        ticket.phase = "terminal";
        ticket.settled = true;
        this.ownedQueueTickets.delete(ticket);
        ticket.resolve({ revokedBeforeStart: true });
        return true;
      },
      get phase() {
        return ticket.phase;
      },
    };
    return ticket;
  }

  #resolveOwnedQueueTicket(ticket, value) {
    if (ticket.settled) return;
    ticket.phase = "terminal";
    ticket.settled = true;
    this.ownedQueueTickets.delete(ticket);
    ticket.resolve(value);
  }

  #rejectOwnedQueueTicket(ticket, error) {
    if (ticket.settled) return;
    ticket.phase = "terminal";
    ticket.settled = true;
    this.ownedQueueTickets.delete(ticket);
    ticket.reject(error);
  }

  #enqueue(
    command,
    onEvent,
    timeoutMs,
    ticket = this.#createOwnedQueueTicket(undefined),
    onActivate
  ) {
    this.queuedCommands += 1;
    this.ownedQueueTickets.add(ticket);
    const run = this.queue
      .then(async () => {
        if (ticket.phase !== "queued") return;
        if (this.closed) throw new Error("GJC SDK session is not running");
        ticket.phase = "active";
        onActivate?.();
        return this.#dispatch(command, onEvent, timeoutMs);
      })
      .then(
        (value) => this.#resolveOwnedQueueTicket(ticket, value),
        (error) => this.#rejectOwnedQueueTicket(ticket, error)
      )
      .finally(() => {
        this.queuedCommands -= 1;
      });
    this.queue = run.catch(() => {});
    return ticket.publicTicket;
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
        return this.#runPromptCommand(command, onEvent, timeoutMs);
      case "steer":
      case "follow_up":
        return this.#runPromptCommand(
          { type: "prompt", message: command.message },
          onEvent,
          timeoutMs
        );
      default:
        throw new Error(`Unknown SDK session command: ${command.type}`);
    }
  }

  async #runPromptCommand(command, onEvent, timeoutMs) {
    let resolveAgentEnd;
    const agentEnd = new Promise((resolve) => {
      resolveAgentEnd = resolve;
    });
    let promptActive = true;
    let eventConsumerError;
    const reportedFailures = [];
    let promptFailure;
    const terminalOutcomes = [];
    let sawAgentStart = false;
    let observedAgentEnds = 0;
    let resetIdle = () => {};
    // #35: track this run before registering the session-level gate listener.
    // SDK 0.16.6 replays durable pending gates synchronously from
    // onGateEmitted(), so subscribing first would see no owner and quarantine a
    // valid resumed gate.
    const gateRun = { onEvent, controller: undefined };
    this.activeGateRuns.push(gateRun);
    this.#ensureGateSubscription();
    this.activePromptRuns += 1;
    const markPromptInactive = () => {
      if (!promptActive) return;
      promptActive = false;
      this.activePromptRuns -= 1;
    };
    const unsubscribe = this.session.subscribe((event) => {
      resetIdle();
      if (event?.type === "agent_start") {
        sawAgentStart = true;
      }
      if (event?.type === "agent_failed") {
        reportedFailures.push({
          scope: attemptScopeBoundary(event.scope),
          failure: sanitizedFailure(event.error),
        });
      }
      if (isTerminalAgentEnd(event)) {
        markPromptInactive();
        const terminalScope = attemptScopeBoundary(event.scope);
        let failureIndex = -1;
        for (let index = reportedFailures.length - 1; index >= 0; index -= 1) {
          const reported = reportedFailures[index];
          if (
            (terminalScope === undefined && reported.scope === undefined) ||
            attemptScopesEqual(reported.scope, terminalScope)
          ) {
            failureIndex = index;
            break;
          }
        }
        const reportedFailure =
          failureIndex >= 0
            ? reportedFailures.splice(failureIndex, 1)[0].failure
            : undefined;
        terminalOutcomes.push(terminalOutcome(event, reportedFailure));
        observedAgentEnds += 1;
        if (observedAgentEnds >= 1) resolveAgentEnd();
      }
      if (event?.type === "agent_failed" || event?.type === "agent_end") {
        return;
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
          let promptSubmission;
          try {
            promptSubmission = this.session.prompt(command.message);
          } catch (error) {
            promptSubmission = Promise.reject(error);
          }
          const promptOutcome = Promise.resolve(promptSubmission).then(
            () => ({ ok: true }),
            (error) => ({
              ok: false,
              failure: sanitizedFailure(error),
            })
          );
          const first = await Promise.race([
            promptOutcome.then((outcome) => ({ type: "prompt", outcome })),
            agentEnd.then(() => ({ type: "terminal" })),
          ]);
          if (
            first.type === "prompt" &&
            !first.outcome.ok &&
            !sawAgentStart &&
            observedAgentEnds === 0
          ) {
            throw sdkTerminalError(failedTerminalOutcome(first.outcome.failure));
          }
          await agentEnd;
          const outcome =
            first.type === "prompt" ? first.outcome : await promptOutcome;
          if (!outcome.ok) promptFailure = outcome.failure;
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
      const outcomeAtTerminal = terminalOutcomes[0];
      if (outcomeAtTerminal?.disposition !== "completed") {
        throw sdkTerminalError(
          outcomeAtTerminal ?? failedTerminalOutcome(sanitizedFailure(undefined))
        );
      }
      if (promptFailure) {
        throw sdkTerminalError(failedTerminalOutcome(promptFailure));
      }
      if (eventConsumerError) throw eventConsumerError;
      return outcomeAtTerminal;
    } finally {
      markPromptInactive();
      unsubscribe();
      for (const [gateId, entry] of this.pendingGates) {
        if (entry.owner !== gateRun) continue;
        // answerGate owns cleanup while a direct resolution is in flight. The
        // accepted gate can wake the run before resolveGate returns its receipt;
        // quarantining it in that window would race the 0.16.6 completion path.
        if (entry.resolving) continue;
        this.pendingGates.delete(gateId);
        for (const activeRun of this.activeGateRuns) {
          activeRun.controller?.resumeAfterGate();
        }
        this.#quarantineGate(entry.emitter, gateId);
      }
      if (this.deferredGateCandidate?.owner === gateRun) {
        const candidate = this.deferredGateCandidate;
        this.deferredGateCandidate = undefined;
        this.#quarantineGate(candidate.emitter, candidate.gate.gate_id);
      }
      const runIndex = this.activeGateRuns.indexOf(gateRun);
      if (runIndex >= 0) this.activeGateRuns.splice(runIndex, 1);
    }
  }

  // #35: register the workflow-gate subscription once for the whole session.
  // Sessions without a remote-answer emitter are marked subscribed so we never
  // install a partial gate path.
  #ensureGateSubscription() {
    if (this.gateSubscribed) return;
    this.gateSubscribed = true;
    const emitter = this.session.getWorkflowGateEmitter?.();
    if (
      emitter?.supportsRemoteGateAnswers?.() !== true ||
      typeof emitter.onGateEmitted !== "function"
    ) {
      return;
    }
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
    if (
      this.pendingGates.has(gateId) ||
      this.deferredGateCandidate?.gate?.gate_id === gateId
    ) {
      return;
    }
    const predecessorState =
      this.#retireCompletedGateBeforeSuccessor(gateEmitter);
    if (this.pendingGates.size > 0) {
      if (predecessorState === "accepted_incomplete") {
        this.#deferGateCandidate(gate, gateEmitter);
        return;
      }
      // Concurrent-gate guard: never overwrite the first resolver. Best-effort
      // reject the newcomer so it does not hang; the first gate stays pending.
      console.warn(
        `gjc-remote daemon: rejecting concurrent workflow gate ${gateId}; a gate is already pending.`
      );
      this.#quarantineGate(gateEmitter, gateId);
      return;
    }
    this.#presentGate(gate, gateEmitter);
  }

  #presentGate(gate, gateEmitter, deferredOwner, deferredEvent) {
    const gateId = gate.gate_id;
    // Attribute the gate to the most recently started run (gates emit while that
    // run's prompt() is executing). With no active run there is nothing to
    // suspend or stream to, so reject rather than leak a pending gate.
    const gateRun =
      deferredOwner ?? this.activeGateRuns[this.activeGateRuns.length - 1];
    if (!gateRun || !this.activeGateRuns.includes(gateRun)) {
      this.#quarantineGate(gateEmitter, gateId);
      return;
    }
    const event = deferredEvent ?? this.#buildGateRequestEvent(gate, gateId);
    if (!event) {
      // A malformed/oversized gate the bot could not render; do not hang the run.
      console.error(
        `gjc-remote daemon: dropping unrenderable workflow gate ${gateId}.`
      );
      this.#quarantineGate(gateEmitter, gateId);
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
    } catch {
      console.error("gjc-remote daemon: failed to emit gate_request event.");
    }
  }

  #deferGateCandidate(gate, gateEmitter) {
    const gateId = gate.gate_id;
    if (this.deferredGateCandidate) {
      console.warn(
        `gjc-remote daemon: rejecting concurrent workflow gate ${gateId}; a successor is already deferred.`
      );
      this.#quarantineGate(gateEmitter, gateId);
      return;
    }
    const owner = this.activeGateRuns[this.activeGateRuns.length - 1];
    const event = this.#buildGateRequestEvent(gate, gateId);
    if (!owner || !event) {
      this.#quarantineGate(gateEmitter, gateId);
      return;
    }
    this.deferredGateCandidate = {
      gate,
      emitter: gateEmitter,
      owner,
      event,
    };
  }

  #discardDeferredGateCandidate() {
    const candidate = this.deferredGateCandidate;
    if (!candidate) return;
    this.deferredGateCandidate = undefined;
    this.#quarantineGate(candidate.emitter, candidate.gate.gate_id);
  }

  // #35: build a protocol-conforming gate_request event for one supported SDK
  // schema, clamping its prompt and choices to V0_LIMITS. Returns undefined for
  // an unknown kind/schema or an event that cannot be made to validate.
  #buildGateRequestEvent(gate, gateId) {
    if (!gateAnswerCodec(gate)) return undefined;
    const kind = gate.kind;
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

  #gateResolutionState(entry) {
    if (
      !entry.response ||
      typeof entry.emitter.lookupCompletedResolution !== "function"
    ) {
      return { kind: "none" };
    }
    try {
      const state = entry.emitter.lookupCompletedResolution(entry.response);
      return state?.kind === "completed" ||
        state?.kind === "accepted_incomplete"
        ? state
        : { kind: "none" };
    } catch {
      return { kind: "none" };
    }
  }

  // Accepted persistence removes a gate from listPendingGates before its
  // continuation is terminalized and advanced. Only the SDK's exact
  // response-bound completed lookup authorizes retirement.
  #retireCompletedGateBeforeSuccessor(gateEmitter) {
    for (const [gateId, entry] of this.pendingGates) {
      if (entry.emitter !== gateEmitter || !entry.resolving || !entry.response) {
        continue;
      }
      const state = this.#gateResolutionState(entry);
      if (state.kind === "completed") {
        this.#retirePendingGate(gateId, entry);
        this.#flushDeferredGateCandidate(entry);
        return "completed";
      }
      if (state.kind === "accepted_incomplete") return state.kind;
    }
    return "none";
  }

  #flushDeferredGateCandidate(completedEntry) {
    if (
      this.pendingGates.size > 0 ||
      this.#gateResolutionState(completedEntry).kind !== "completed"
    ) {
      return false;
    }
    const candidate = this.deferredGateCandidate;
    if (!candidate) return false;
    this.deferredGateCandidate = undefined;
    this.#presentGate(
      candidate.gate,
      candidate.emitter,
      candidate.owner,
      candidate.event
    );
    return true;
  }

  #retirePendingGate(gateId, entry) {
    if (this.pendingGates.get(gateId) !== entry) return false;
    this.pendingGates.delete(gateId);
    if (this.pendingGates.size === 0) {
      for (const activeRun of this.activeGateRuns) {
        activeRun.controller?.resumeAfterGate();
      }
    }
    return true;
  }

  // #35: resolve a pending gate with a user's answer (called from daemon message
  // routing when an ANSWER frame arrives). Runs concurrently with the blocked
  // prompt run that is awaiting the gate. A stale/unknown gateId is a safe no-op.
  async answerGate(gateId, answer) {
    if (this.closed) return { ok: false, error: "session is closed" };
    const entry = this.pendingGates.get(gateId);
    if (!entry) return { ok: false, error: "no pending gate for id" };
    if (entry.resolving) {
      return { ok: false, error: "gate answer is already being resolved" };
    }
    const encoded = encodeGateAnswer(entry.gate, answer);
    if (!encoded.ok) return encoded;
    entry.resolving = true;
    const response = {
      gate_id: gateId,
      answer: encoded.answer,
      // One gate accepts one answer. Binding retries to its immutable gate id
      // gives the 0.16.6 recovery APIs a stable idempotency identity without
      // retaining or hashing user answer content.
      idempotency_key: `gjc-remote:${gateId}`,
    };
    entry.response = response;
    try {
      // This adapter does not publish through the SDK presentation arbiter, so
      // the direct-control proof is `not_published`, matching the SDK 0.16.6
      // workflow.gate_answer path. Without this proof resolveGate accepts the
      // answer durably and then rejects because no terminal controller exists.
      if (entry.emitter.prepareTerminalization?.(gateId, "not_published") !== true) {
        entry.response = undefined;
        return { ok: false, error: "workflow gate is no longer answerable" };
      }
      const resolution = await this.#awaitGateOperation(
        () => entry.emitter.resolveGate(response)
      );
      if (resolution?.status === "rejected") {
        entry.response = undefined;
        this.#discardDeferredGateCandidate();
        entry.emitter.clearPreparedTerminalization?.(gateId);
        return {
          ok: false,
          error: "workflow gate answer was rejected",
          resolution,
        };
      }
      if (resolution?.status !== "accepted") {
        entry.response = undefined;
        this.#discardDeferredGateCandidate();
        entry.emitter.clearPreparedTerminalization?.(gateId);
        return {
          ok: false,
          error: "workflow gate returned an invalid resolution",
        };
      }
      let completed = this.#gateResolutionState(entry);
      if (completed.kind === "accepted_incomplete") {
        await this.#awaitGateOperation(
          () => entry.emitter.recoverAcceptedGates?.()
        );
        completed = this.#gateResolutionState(entry);
      }
      if (completed.kind !== "completed") {
        return {
          ok: false,
          error: "workflow gate resolution is incomplete",
          resolution,
        };
      }
      this.#retirePendingGate(gateId, entry);
      this.#flushDeferredGateCandidate(entry);
      return { ok: true, resolution: completed.resolution };
    } catch (error) {
      if (this.closed) {
        return { ok: false, error: "session is closed" };
      }
      // resolveGate can lose its response after durable acceptance. Reconcile
      // through the exact public recovery surfaces before classifying failure.
      try {
        let completed = this.#gateResolutionState(entry);
        if (completed?.kind === "accepted_incomplete") {
          await this.#awaitGateOperation(
            () => entry.emitter.recoverAcceptedGates?.()
          );
          completed = this.#gateResolutionState(entry);
        }
        if (completed?.kind === "completed") {
          this.#retirePendingGate(gateId, entry);
          this.#flushDeferredGateCandidate(entry);
          return { ok: true, resolution: completed.resolution };
        }
        if (completed?.kind === "accepted_incomplete") {
          return {
            ok: false,
            error: "workflow gate resolution is incomplete",
          };
        }
      } catch {
        // Preserve the original resolution failure below.
      }
      if (this.closed) {
        return { ok: false, error: "session is closed" };
      }
      const stillPending =
        entry.emitter
          .listPendingGates?.()
          .some((gate) => gate?.gate_id === gateId) === true;
      if (stillPending) {
        entry.emitter.clearPreparedTerminalization?.(gateId);
      } else {
        this.#retirePendingGate(gateId, entry);
        this.#quarantineGate(entry.emitter, gateId);
        this.#discardDeferredGateCandidate();
      }
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      };
    } finally {
      if (this.pendingGates.get(gateId) === entry) {
        entry.resolving = false;
      }
    }
  }

  #quarantineGate(gateEmitter, gateId) {
    try {
      // SDK 0.16.6's quarantine surface revokes the continuation and rejects
      // its waiter. Sending `answer:null` is not a rejection operation: schema
      // validation can leave the gate pending forever.
      gateEmitter?.quarantineGate?.(gateId);
    } catch {
      // Best-effort: the concurrent run's own idle/hard-cap still bounds it.
    }
  }

  #withAdapterClose(operation) {
    let active = true;
    let rejectClosed;
    const closed = new Promise((_, reject) => {
      rejectClosed = reject;
    });
    const cancel = (error) => {
      if (!active) return;
      active = false;
      rejectClosed(error);
    };
    this.adapterWaiterCancellations.add(cancel);
    let result;
    try {
      result = operation();
    } catch (error) {
      result = Promise.reject(error);
    }
    return Promise.race([Promise.resolve(result), closed]).finally(() => {
      active = false;
      this.adapterWaiterCancellations.delete(cancel);
    });
  }

  async #awaitGateOperation(operation) {
    const waiter = this.#withAdapterClose(operation);
    this.inFlightGateAnswers.add(waiter);
    try {
      return await waiter;
    } finally {
      this.inFlightGateAnswers.delete(waiter);
    }
  }

  #closeAdapter(error) {
    this.closed = true;
    try {
      this.gateUnsubscribe?.();
    } catch {
      // Best-effort: the underlying session is being disposed below.
    }
    this.gateUnsubscribe = undefined;
    for (const [gateId, entry] of this.pendingGates) {
      this.#quarantineGate(entry.emitter, gateId);
    }
    this.pendingGates.clear();
    this.#discardDeferredGateCandidate();
    for (const ticket of [...this.ownedQueueTickets]) {
      if (ticket.phase === "queued") this.#rejectOwnedQueueTicket(ticket, error);
    }
    for (const cancel of [...this.adapterWaiterCancellations]) {
      cancel(error);
    }
  }

  async #withTimeout(operation, timeoutMs) {
    const timeoutError = timedOutTerminalError("SDK command timed out");
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = this.setTimeoutFn(() => reject(timeoutError), timeoutMs);
    });

    try {
      return await Promise.race([this.#withAdapterClose(operation), timeout]);
    } catch (error) {
      if (error === timeoutError) {
        this.#closeAdapter(timeoutError);
        void this.#disposeUnderlying().catch(() => {});
      }
      throw error;
    } finally {
      this.clearTimeoutFn(timer);
    }
  }
  async #withStreamingTimeout(operation, idleMs, hardCapMs, gateWindowMs, onArm) {
    const idleError = timedOutTerminalError("SDK command timed out");
    const hardCapError = timedOutTerminalError(
      "SDK command exceeded absolute hard-cap"
    );
    const gateError = timedOutTerminalError("SDK gate answer window expired");
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
      return await Promise.race([this.#withAdapterClose(operation), timeout]);
    } catch (error) {
      if (error === idleError || error === hardCapError || error === gateError) {
        this.#closeAdapter(error);
        // #35: a timeout/hard-cap/gate-window expiry tears down the session via
        // #disposeUnderlying (not the public dispose()). #closeAdapter already
        // rejects every sibling waiter and fences any pending gate.
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
    this.#closeAdapter(new Error("GJC SDK session was disposed"));
    const disposal = this.#disposeUnderlying();
    const commands = Promise.allSettled([
      this.queue,
      ...this.inFlightGateAnswers,
    ]);
    const [disposalResult] = await Promise.allSettled([disposal]);
    await commands;
    this.activeGateRuns.length = 0;
    if (disposalResult.status === "rejected") throw disposalResult.reason;
  }
}
