#!/usr/bin/env bun
/*
 * Real installed SDK 0.19.0 tracked-control contract oracle.
 * Stdout contains one bounded receipt.
 */
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const RECEIPT_SCHEMA = "sdk-contract-probe-v1";
const EXPECTED_SDK_VERSION = "0.19.0";
const HISTORICAL_SDK_VERSION = "0.16.4";
const DECISION_GATE_CODE =
  "DECISION_GATE_BUILDERS_NOT_PUBLIC";
const PROMOTED_GATE_OWNERSHIP_CODE = "SDK_TRACKED_INPUT_GATE_OWNERSHIP";
const OVERLAP_GATE_WINDOW_MS = 500;
const STEP_TIMEOUT_MS = 3_000;
const CLEANUP_TIMEOUT_MS = 4_000;
const HARD_TIMEOUT_MS = 45_000;

class ProbeError extends Error {
  constructor(code, state) {
    super(code);
    this.name = "ProbeError";
    this.code = code;
    this.state = state;
  }
}

class HarnessError extends ProbeError {
  constructor(primaryFailure, cleanupFailures) {
    super(primaryFailure?.code ?? "HARNESS_CLEANUP_FAILED");
    this.primaryFailure = primaryFailure;
    this.cleanupFailures = cleanupFailures;
  }
}

function requireCondition(condition, code, state) {
  if (!condition) throw new ProbeError(code, state);
}

function failureCode(error, fallback) {
  return error instanceof ProbeError ? error.code : fallback;
}

function observedFailureCode(error) {
  for (const candidate of [error?.code, error?.name]) {
    if (
      typeof candidate === "string" &&
      /^[A-Za-z0-9._-]{1,80}$/.test(candidate)
    ) {
      return candidate;
    }
  }
  return "UNCLASSIFIED_ERROR";
}

function boundedDiagnosticState(value, depth = 0) {
  if (depth > 3) return "DEPTH_LIMIT";
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : "NON_FINITE";
  if (typeof value === "string") {
    return /^[A-Za-z0-9._:<>=-]{0,96}$/.test(value)
      ? value
      : "REDACTED_STRING";
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, 16)
      .map((item) => boundedDiagnosticState(item, depth + 1));
  }
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, item] of Object.entries(value).slice(0, 24)) {
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(key)) continue;
      output[key] = boundedDiagnosticState(item, depth + 1);
    }
    return output;
  }
  return "UNSUPPORTED";
}

function deferred() {
  let settled = false;
  let resolvePromise;
  const promise = new Promise((resolveValue) => {
    resolvePromise = resolveValue;
  });
  return {
    promise,
    resolve() {
      if (settled) return;
      settled = true;
      resolvePromise();
    },
  };
}

async function withDeadline(promise, timeoutMs, code) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve(promise),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new ProbeError(code)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitFor(predicate, code, timeoutMs = STEP_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await Bun.sleep(5);
  }
  throw new ProbeError(code);
}

function observe(promise) {
  const state = { status: "pending", failureCode: "NONE" };
  state.settled = Promise.resolve(promise).then(
    (value) => {
      state.status = "fulfilled";
      state.value = value;
    },
    (error) => {
      state.status = "rejected";
      state.failureCode = observedFailureCode(error);
      state.error = error;
    }
  );
  return state;
}

function terminalEvents(events) {
  return events.filter((event) => event?.type === "agent_end");
}

function toolResultText(context) {
  return context.messages
    .filter((message) => message?.role === "toolResult" && Array.isArray(message.content))
    .flatMap((message) => message.content)
    .filter((item) => item?.type === "text")
    .map((item) => item.text)
    .join("\n");
}

const fixtureFile = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(fixtureFile), "../..");
const installedSdkRoot = join(
  repoRoot,
  "node_modules",
  "@gajae-code",
  "coding-agent"
);
let networkAttempts = 0;
let harnessSequence = 0;
const harnessCleanupOutcomes = [];
const completedCells = {};
let activeCancelDiagnostic;
let Agent;
let createMockModel;
let AgentSession;
let SessionManager;
let Settings;
let AuthStorage;
let ModelRegistry;
let kNoAuth;
let AskTool;
let SdkSession;
let closeModelCache;

function modelDefinition(id) {
  return {
    id,
    name: `SDK contract ${id}`,
    reasoning: false,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 16_384,
    maxTokens: 1_024,
  };
}

async function createHarness(
  ownerRoot,
  responseSets,
  options = {}
) {
  const sequence = ++harnessSequence;
  const ownedRoot = await mkdtemp(join(ownerRoot, `runtime-${sequence}-`));
  const harness = {
    sequence,
    ownedRoot,
    subscriptions: new Set(),
    calls: {},
    releases: [],
  };
  try {
    return await initializeHarness(harness, responseSets, options);
  } catch (error) {
    const cleanup = await closeHarness(harness);
    throw new HarnessError(
      { stage: "harness-creation", code: failureCode(error, "HARNESS_CREATION_FAILED") },
      cleanup.failures
    );
  }
}

function trackMethod(harness, target, method, key) {
  const original = target[method];
  requireCondition(typeof original === "function", "TRACKED_PUBLIC_METHOD_MISSING");
  harness.calls[key] = 0;
  target[method] = function (...args) {
    harness.calls[key] += 1;
    return original.apply(this, args);
  };
}

function trackSubscriptions(harness, target, method, kind) {
  const original = target[method];
  requireCondition(typeof original === "function", "TRACKED_PUBLIC_SUBSCRIPTION_MISSING");
  target[method] = function (...args) {
    const release = original.apply(this, args);
    const subscription = { kind, release: undefined };
    subscription.release = () => {
      if (!harness.subscriptions.delete(subscription)) return;
      release();
    };
    harness.subscriptions.add(subscription);
    return subscription.release;
  };
}

async function initializeHarness(
  harness,
  responseSets,
  { withAsk = false, onRawAgentEvent, shouldPause, gateAnswerWindowMs = 6_000 } = {}
) {
  const { sequence, ownedRoot } = harness;
  const cwd = join(ownedRoot, "workspace");
  const agentDir = join(ownedRoot, "agent");
  await Promise.all([mkdir(cwd, { recursive: true }), mkdir(agentDir, { recursive: true })]);

  const settings = await Settings.loadForScope({ cwd, agentDir });
  harness.settings = settings;
  trackMethod(harness, settings, "close", "settingsClose");
  settings.override("ask.notify", "off");
  settings.override("memory.backend", "off");
  settings.override("sessionMemory.mode", "off");
  settings.override("compaction.enabled", false);
  settings.override("todo.enabled", false);
  settings.override("todo.reminders", false);
  settings.override("tools.discoveryMode", "off");
  settings.override("retry.requestMaxRetries", 0);
  settings.override("retry.streamMaxRetries", 0);
  settings.override("skills.enabled", false);

  const authDbPath = join(agentDir, "auth.db");
  const authStorage = await AuthStorage.create(authDbPath);
  harness.authStorage = authStorage;
  trackMethod(harness, authStorage, "close", "authClose");
  requireCondition(existsSync(authDbPath), "FILE_BACKED_AUTH_STORAGE_NOT_CREATED");
  const modelsPath = join(agentDir, "models.json");
  const modelsDbPath = join(agentDir, "models.db");
  harness.modelsDbPath = modelsDbPath;
  const modelRegistry = new ModelRegistry(authStorage, modelsPath, settings, {
    agentDir,
    automaticRefresh: false,
  });
  harness.modelRegistry = modelRegistry;
  trackMethod(harness, modelRegistry, "dispose", "registryDispose");
  trackMethod(harness, modelRegistry, "clearSourceRegistrations", "providerRelease");
  const provider = `sdk-contract-${sequence}`;
  const api = `sdk-contract-mock-${sequence}`;
  const sourceId = `sdk-contract-probe/${sequence}`;
  harness.sourceId = sourceId;
  const mockModels = new Map(
    Object.entries(responseSets).map(([id, responses]) => [
      id,
      createMockModel({ id, provider, responses }),
    ])
  );

  modelRegistry.registerProvider(
    provider,
    {
      api,
      baseUrl: "https://sdk-contract.invalid",
      // Public runtime registration has no `auth: "none"` field. `kNoAuth` is
      // the SDK's exported credentialless sentinel, not a provider credential.
      apiKey: kNoAuth,
      authHeader: false,
      streamSimple(model, context, options) {
        const mock = mockModels.get(model.id);
        if (!mock) throw new ProbeError("UNSCRIPTED_MODEL_SELECTED");
        return mock.stream(mock, context, options);
      },
      models: [...mockModels.keys()].map(modelDefinition),
    },
    sourceId
  );

  const sessionManager = SessionManager.inMemory(cwd);
  harness.sessionManager = sessionManager;
  trackMethod(harness, sessionManager, "closeStrict", "managerClose");
  const primaryId = mockModels.keys().next().value;
  const primaryModel = modelRegistry.find(provider, primaryId);
  requireCondition(primaryModel, "PRIMARY_MODEL_NOT_REGISTERED");

  let session;
  let adapter;
  const toolSession = {
    cwd,
    home: ownedRoot,
    hasUI: false,
    workflowGateEligible: true,
    settings,
    modelRegistry,
    getSessionFile: () => sessionManager.getSessionFile(),
    getSessionId: () => sessionManager.getSessionId(),
    getSessionAgentDir: () => agentDir,
    getWorkflowGateEmitter: () => session?.getWorkflowGateEmitter(),
  };
  const askTool = withAsk ? AskTool.createIf(toolSession) : undefined;
  if (withAsk) requireCondition(askTool, "ASK_TOOL_NOT_AVAILABLE");
  const tools = askTool ? [askTool] : [];
  const toolRegistry = new Map(tools.map((tool) => [tool.name, tool]));
  const agent = new Agent({
    initialState: {
      systemPrompt: ["Deterministic SDK contract probe."],
      model: primaryModel,
      tools,
    },
    steeringMode: "one-at-a-time",
    followUpMode: "one-at-a-time",
    requestMaxRetries: 0,
    streamMaxRetries: 0,
    shouldPause,
  });
  harness.agent = agent;
  trackSubscriptions(harness, agent, "subscribe", "agent");
  const unsubscribeRawAgent =
    typeof onRawAgentEvent === "function"
      ? agent.subscribe((event) =>
          onRawAgentEvent(
            event,
            () => adapter,
            () => ({ agent, session })
          )
        )
      : () => {};
  harness.unsubscribeRawAgent = unsubscribeRawAgent;

  session = new AgentSession({
    agent,
    sessionManager,
    settings,
    agentDir,
    modelRegistry,
    toolRegistry,
    builtinToolIdentities: new Set(tools),
    workflowGateToolSession: withAsk ? toolSession : undefined,
    workflowGatePublication: "local",
    skills: [],
    promptTemplates: [],
    slashCommands: [],
    customCommands: [],
  });
  harness.session = session;
  harness.promptCalls = [];
  const publicPrompt = session.prompt;
  session.prompt = function (...args) {
    const result = publicPrompt.apply(this, args);
    harness.promptCalls.push(observe(result));
    return result;
  };
  // Observe the real public handles without replacing receipts, options, queue
  // callbacks, capabilities, or the handle returned to the adapter.
  harness.submissions = [];
  const submitUserMessage = session.submitUserMessage;
  session.submitUserMessage = async function (...args) {
    const handle = await submitUserMessage.apply(this, args);
    harness.submissions.push({
      handle,
      admitted: observe(handle.admitted),
      execution: observe(handle.execution),
      terminal: observe(handle.terminal),
    });
    return handle;
  };
  trackMethod(harness, session, "dispose", "sessionDispose");
  trackSubscriptions(harness, session, "subscribe", "session");
  if (withAsk) {
    const emitter = session.getWorkflowGateEmitter();
    requireCondition(emitter, "REAL_GATE_EMITTER_UNAVAILABLE");
    trackSubscriptions(harness, emitter, "onGateEmitted", "gate");
  }
  session.setDisposeTimeoutForTests(3_000);
  const events = [];
  const unsubscribe = session.subscribe((event) => events.push(event));
  adapter = new SdkSession(session, {
    idleTimeoutMs: 6_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs,
  });

  return Object.assign(harness, {
    adapter,
    agent,
    events,
    mockModels,
    modelRegistry,
    provider,
    session,
    settings,
    authStorage,
    modelsDbPath,
    sourceId,
    unsubscribe,
    unsubscribeRawAgent,
  });
}

async function closeHarness(harness) {
  const failures = [];
  const completed = [];
  const cleanup = async (operation, timeoutCode, run) => {
    try {
      await withDeadline(
        Promise.resolve().then(run),
        CLEANUP_TIMEOUT_MS,
        timeoutCode
      );
      completed.push(operation);
    } catch (error) {
      failures.push({
        operation,
        code: failureCode(error, "OPERATION_FAILED"),
      });
    }
  };

  // The adapter owns the AgentSession and must be its sole disposal caller.
  // The fixture owns the injected registry/auth/settings and closes them after
  // the adapter has stopped every consumer of those resources.
  await cleanup("event-subscription-release", "SUBSCRIPTION_CLEANUP_TIMEOUT", () => {
    for (const release of harness.releases) release();
    harness.unsubscribeRawAgent?.();
    harness.unsubscribe?.();
  });
  await cleanup("adapter-session-dispose", "ADAPTER_CLEANUP_TIMEOUT", () =>
    harness.adapter
      ? harness.adapter.dispose()
      : harness.session
        ? harness.session.dispose()
        : harness.sessionManager?.closeStrict()
  );
  if (failures.some((failure) => failure.operation === "adapter-session-dispose") && harness.session) {
    // A public disposal deadline can reject before its retained SDK teardown
    // finishes. Do not close injected dependencies while that owner is live.
    await cleanup("retained-session-dispose-join", "RETAINED_DISPOSAL_CLEANUP_TIMEOUT", () =>
      harness.session.awaitDisposeCompletion()
    );
    if (failures.some((failure) => failure.operation === "retained-session-dispose-join")) {
      const outcome = {
        completed,
        failures,
        modelCacheState: "retained-until-child-exit",
        calls: { ...harness.calls },
        subscriptionsRemaining: harness.subscriptions.size,
      };
      harnessCleanupOutcomes.push(outcome);
      return outcome;
    }
  }
  for (const subscription of [...harness.subscriptions]) {
    await cleanup("retained-subscription-release", "SUBSCRIPTION_CLEANUP_TIMEOUT", () =>
      subscription.release()
    );
  }
  await cleanup("provider-registration-release", "PROVIDER_RELEASE_TIMEOUT", () =>
    harness.modelRegistry?.clearSourceRegistrations(harness.sourceId)
  );
  await cleanup("model-registry-dispose", "MODEL_REGISTRY_CLEANUP_TIMEOUT", () =>
    harness.modelRegistry?.dispose()
  );
  let modelCacheState = "not-open";
  await cleanup("model-cache-close", "MODEL_CACHE_CLEANUP_TIMEOUT", () => {
    requireCondition(
      harness.modelsDbPath && closeModelCache(harness.modelsDbPath) === true,
      "OWNED_MODEL_CACHE_NOT_CLOSED"
    );
    modelCacheState = "closed";
    requireCondition(closeModelCache(harness.modelsDbPath) === false, "CLOSED_MODEL_CACHE_STILL_OWNED");
  });
  await cleanup("auth-storage-close", "AUTH_STORAGE_CLEANUP_TIMEOUT", () =>
    harness.authStorage?.close()
  );
  await cleanup("settings-close", "SETTINGS_CLEANUP_TIMEOUT", () =>
    harness.settings?.close()
  );
  // Prove public close releases Windows SQLite handles while this process is
  // still alive. A child exit, GC, retry, or delayed parent removal cannot prove
  // this lifecycle. Retain scratch on cleanup failure rather than hiding it.
  let ownedScratchRemoved = false;
  if (failures.length === 0) {
    await cleanup("immediate-owned-scratch-removal", "OWNED_SCRATCH_REMOVAL_TIMEOUT", async () => {
      await rm(harness.ownedRoot, { recursive: true });
      requireCondition(!existsSync(harness.ownedRoot), "OWNED_SCRATCH_STILL_PRESENT");
      ownedScratchRemoved = true;
    });
  }

  const outcome = {
    stage: harness.stage,
    completed,
    failures,
    modelCacheState,
    ownedScratchRemoved,
    calls: { ...harness.calls },
    subscriptionsRemaining: harness.subscriptions.size,
  };
  harnessCleanupOutcomes.push(outcome);
  return outcome;
}

async function withHarness(stage, ownerRoot, responseSets, options, run) {
  const harness = await createHarness(ownerRoot, responseSets, options);
  harness.stage = stage;
  let value;
  let primaryFailure;
  const secondaryFailures = [];
  try {
    value = await run(harness);
  } catch (error) {
    if (Array.isArray(error?.secondaryFailures)) secondaryFailures.push(...error.secondaryFailures);
    primaryFailure = {
      stage,
      code: failureCode(error, "UNEXPECTED_SCENARIO_FAILURE"),
      state: boundedDiagnosticState({
        ...(error instanceof ProbeError && error.state !== undefined ? error.state : {}),
        providerCalls: [...harness.mockModels.values()].reduce((count, model) => count + model.calls.length, 0),
        publicTerminalCount: terminalEvents(harness.events).length,
        publicRootPromptStatus: harness.promptCalls[0]?.status ?? "not-started",
        sdkPendingGateCount: harness.session.getWorkflowGateEmitter()?.listPendingGates().length ?? 0,
        adapterPendingGateCount: harness.adapter.pendingGates.size,
        trackedSubmissions: harness.submissions.map((record) => ({
          submissionId: record.handle.submissionId,
          admittedStatus: record.admitted.status,
          executionStatus: record.execution.status,
          executionDisposition: record.execution.value?.disposition ?? "pending",
          terminalStatus: record.terminal.status,
          terminalDisposition: record.terminal.value?.disposition ?? "pending",
          removalReason: record.terminal.value?.reason ?? "none",
        })),
      }),
    };
  }
  const cleanup = await closeHarness(harness);
  if (!(Object.values(cleanup.calls).every((count) => count === 1) && cleanup.subscriptionsRemaining === 0)) {
    cleanup.failures.push({
      operation: "harness-exact-once-validation",
      code: "HARNESS_RESOURCE_RELEASE_NOT_EXACT_ONCE",
      state: boundedDiagnosticState({ calls: cleanup.calls, subscriptionsRemaining: cleanup.subscriptionsRemaining }),
    });
  }
  if (primaryFailure || cleanup.failures.length > 0 || secondaryFailures.length > 0) {
    throw new HarnessError(primaryFailure, [...secondaryFailures, ...cleanup.failures]);
  }
  return value;
}
function scopeKey(scope) {
  requireCondition(
    scope && typeof scope.attemptId === "string" && Number.isSafeInteger(scope.generation) &&
      typeof scope.lineage === "string",
    "GENUINE_ATTEMPT_SCOPE_MISSING"
  );
  return JSON.stringify([scope.attemptId, scope.generation, scope.lineage]);
}

function startOwned(harness, owner, command) {
  const events = [];
  let activations = 0;
  let executionIdsAtActivation = [];
  let settledAtTerminalScopes;
  const ticket = harness.adapter.sendOwned(owner, command, (event) => events.push(event), 8_000, {
    onActivate: () => {
      activations += 1;
      executionIdsAtActivation = harness.submissions.filter((record) => record.execution.status === "fulfilled")
        .map((record) => record.handle.submissionId);
    },
  });
  const captureSettlement = () => {
    settledAtTerminalScopes = terminalEvents(harness.events).map((event) => scopeKey(event.scope));
  };
  const result = Promise.resolve(ticket.result).then((value) => {
    captureSettlement();
    return value;
  }, (error) => {
    captureSettlement();
    throw error;
  });
  return { ticket, events, run: observe(result), get activations() { return activations; },
    get executionIdsAtActivation() { return executionIdsAtActivation; },
    get settledAtTerminalScopes() { return settledAtTerminalScopes; } };
}

async function requireSubmission(harness, index, delivery) {
  await waitFor(() => harness.submissions.length > index, "TRACKED_SUBMISSION_NOT_OBSERVED");
  const record = harness.submissions[index];
  await withDeadline(record.admitted.settled, STEP_TIMEOUT_MS, "TRACKED_ADMISSION_TIMEOUT");
  requireCondition(
    typeof record.handle.submissionId === "string" && record.handle.submissionId.length > 0 &&
      record.admitted.status === "fulfilled" &&
      record.admitted.value.submissionId === record.handle.submissionId &&
      record.admitted.value.delivery === delivery && record.admitted.value.queuePolicy === "sequential",
    "TRACKED_ADMISSION_MISMATCH"
  );
  return record;
}

async function requireOwningTerminal(harness, control, record, status = "fulfilled") {
  await withDeadline(Promise.all([control.run.settled, record.execution.settled, record.terminal.settled]),
    STEP_TIMEOUT_MS, "TRACKED_OWNER_DID_NOT_SETTLE");
  const execution = record.execution.value;
  const terminal = record.terminal.value;
  requireCondition(
    record.execution.status === "fulfilled" && record.terminal.status === "fulfilled" &&
      execution.submissionId === record.handle.submissionId && terminal.submissionId === record.handle.submissionId &&
      execution.delivery === record.admitted.value.delivery && terminal.delivery === execution.delivery &&
      ["joined-current-run", "promoted-to-run"].includes(execution.disposition) && terminal.disposition === "completed",
    "TRACKED_LIFECYCLE_IDENTITY_MISMATCH"
  );
  const scope = scopeKey(terminal.attemptScope);
  const owning = terminalEvents(harness.events).filter((event) => scopeKey(event.scope) === scope);
  // Terminal callbacks are deliberately suppressed; settlement still requires
  // the exact genuine public SDK terminal, not an admission acknowledgement.
  requireCondition(owning.length === 1 && control.settledAtTerminalScopes.includes(scope) &&
    terminalEvents(control.events).length === 0,
    "TRACKED_EXACT_TERMINAL_MISMATCH");
  requireCondition(control.run.status === status && control.ticket.phase === "terminal" && control.activations === 1,
    "TRACKED_ADAPTER_SETTLEMENT_MISMATCH", { status: control.run.status, failureCode: control.run.failureCode });
  requireCondition(control.executionIdsAtActivation.includes(record.handle.submissionId), "ACTIVATED_BEFORE_GENUINE_EXECUTION_RECEIPT");
  requireCondition(record.handle.cancel() === false && control.ticket.revokeBeforeStart() === false,
    "EXECUTED_SUBMISSION_CANCELLED");
  return {
    delivery: execution.delivery,
    executionDisposition: execution.disposition,
    finalScopeChanged: scopeKey(execution.attemptScope) !== scope,
    exactOwningTerminal: true,
    activatedAfterExecution: true,
    adapterStatus: control.run.status,
    cancelAfterExecution: false,
  };
}

function userTexts(context) {
  return context.messages.filter((message) => message.role === "user").map((message) =>
    typeof message.content === "string" ? message.content : message.content
      .filter((part) => part.type === "text").map((part) => part.text).join("\n"));
}

function submissionEvidence(record) {
  return {
    submissionId: record.handle.submissionId,
    admitted: record.admitted.value,
    execution: record.execution.value,
    terminal: record.terminal.value,
  };
}

async function probeTrackedControls(ownerRoot, fail = false) {
  const release = deferred();
  const releaseExecuting = deferred();
  const stage = fail ? "tracked-control-failure" : "tracked-control-sequential";
  const texts = fail ? ["failure-steer", "failure-follow"] :
    ["steer-one", "steer-two", "duplicate-follow", "duplicate-follow", "follow-tail"];
  const consumed = [];
  const responses = [async () => {
    await release.promise;
    return { content: ["initial complete"] };
  }];
  for (let index = 0; index < (fail ? 2 : 4); index += 1) {
    responses.push(async (context) => {
      const matching = userTexts(context).filter((text) => texts.includes(text));
      requireCondition(matching.length === consumed.length + 1, "SEQUENTIAL_CONTROLS_BATCHED_OR_LOST");
      consumed.push(matching.at(-1));
      if (index === 0) await releaseExecuting.promise;
      return fail && index === 1 ? { throw: "fixture-owned-control-failure" } : { content: ["control complete"] };
    });
  }
  responses.push({ content: ["unrelated successor"] });
  return withHarness(stage, ownerRoot, { primary: responses }, {}, async (harness) => {
    harness.releases.push(() => release.resolve());
    harness.releases.push(() => releaseExecuting.resolve());
    // The explicit sequential policy must override both SDK batching modes.
    harness.agent.setSteeringMode("all");
    harness.agent.setFollowUpMode("all");
    const primary = startOwned(harness, "tracked-primary", { type: "prompt", message: "initial" });
    await waitFor(() => harness.mockModels.get("primary").calls.length === 1, "ACTIVE_PROVIDER_NOT_ENTERED");
    const controls = [];
    const records = [];
    for (let index = 0; index < texts.length; index += 1) {
      const type = index < (fail ? 1 : 2) ? "steer" : "follow_up";
      controls.push(startOwned(harness, `tracked-control-${index}`, { type, message: texts[index] }));
      records.push(await requireSubmission(harness, index, type === "steer" ? "steer" : "followUp"));
      requireCondition(controls[index].ticket.phase === "queued" && controls[index].activations === 0 &&
        controls[index].run.status === "pending" && records[index].execution.status === "pending",
      "QUEUED_CONTROL_ACTIVATED_BEFORE_EXECUTION");
    }
    requireCondition(new Set(records.map((record) => record.handle.submissionId)).size === records.length,
      "TRACKED_SUBMISSION_IDS_REUSED");
    if (!fail) {
      requireCondition(controls[2].ticket.revokeBeforeStart() === true && controls[2].ticket.revokeBeforeStart() === false,
        "EXACT_QUEUED_REVOCATION_FAILED");
      await withDeadline(Promise.all([controls[2].run.settled, records[2].execution.settled, records[2].terminal.settled]),
        STEP_TIMEOUT_MS, "CANCELLED_CONTROL_DID_NOT_SETTLE");
      for (const value of [records[2].execution.value, records[2].terminal.value]) {
        requireCondition(value.submissionId === records[2].handle.submissionId && value.disposition === "removed" &&
          value.reason === "cancelled", "CANCELLED_CONTROL_RECEIPT_WRONG");
      }
      requireCondition(controls[2].run.status === "fulfilled" && controls[2].run.value?.revokedBeforeStart === true &&
        controls[2].activations === 0 &&
        controls[2].ticket.phase === "terminal", "CANCELLED_CONTROL_ACTIVATED");
    }
    release.resolve();
    await waitFor(() => records[0].execution.status === "fulfilled" && controls[0].ticket.phase === "active" &&
      harness.mockModels.get("primary").calls.length === 2, "EXECUTING_CONTROL_NOT_OBSERVED");
    requireCondition(records[0].handle.cancel() === false && controls[0].ticket.revokeBeforeStart() === false &&
      controls[0].run.status === "pending", "EXECUTING_CONTROL_WRONGLY_CANCELLED");
    releaseExecuting.resolve();
    const receipts = [];
    for (let index = 0; index < controls.length; index += 1) {
      if (!fail && index === 2) continue;
      receipts.push(await requireOwningTerminal(harness, controls[index], records[index], fail ? "rejected" : "fulfilled"));
      requireCondition(receipts.at(-1).executionDisposition === "joined-current-run", "ACTIVE_CONTROL_NOT_JOINED");
    }
    await withDeadline(primary.run.settled, STEP_TIMEOUT_MS, "PRIMARY_DID_NOT_SETTLE");
    const terminal = terminalEvents(harness.events);
    requireCondition(terminal.length === 1 && terminalEvents(primary.events).length === 0 &&
      primary.settledAtTerminalScopes.includes(scopeKey(terminal[0].scope)) &&
      primary.run.status === (fail ? "rejected" : "fulfilled"), "PRIMARY_COHORT_TERMINAL_WRONG");
    if (fail) requireCondition(terminal[0].messages.some((message) => message.role === "assistant" && message.stopReason === "error"),
      "OWNING_TERMINAL_FAILURE_MISSING");
    if (fail) requireCondition(controls.every((control) => control.run.failureCode === primary.run.failureCode),
      "OWNING_FAILURE_NOT_SHARED_BY_COHORT");
    requireCondition(receipts.some((receipt) => receipt.finalScopeChanged), "FINAL_SCOPE_CHANGE_NOT_EXERCISED");
    const steeringTexts = texts.slice(0, fail ? 1 : 2);
    const followUpTexts = fail ? texts.slice(1) : ["duplicate-follow", "follow-tail"];
    requireCondition(JSON.stringify(consumed.filter((text) => steeringTexts.includes(text))) ===
      JSON.stringify(steeringTexts), "STEERING_PER_QUEUE_ORDER_WRONG");
    requireCondition(JSON.stringify(consumed.filter((text) => !steeringTexts.includes(text))) ===
      JSON.stringify(followUpTexts), "FOLLOW_UP_PER_QUEUE_ORDER_WRONG");
    const counts = [primary, ...controls].map((control) => control.events.length);
    await withDeadline(harness.adapter.send({ type: "prompt", message: "unrelated successor" }, () => {}, 5_000),
      STEP_TIMEOUT_MS, "SUCCESSOR_SEND_DID_NOT_SETTLE");
    requireCondition([primary, ...controls].every((control, index) => control.events.length === counts[index]),
      "SUCCESSOR_EVENTS_LEAKED_TO_PREDECESSOR");
    return {
      status: "qualified", acceptedDuringProviderExecution: true,
      queuePolicy: "sequential", ordering: "per-delivery-not-global-FIFO",
      providerCalls: harness.mockModels.get("primary").calls.length,
      exactPrimaryTerminal: true, receipts,
      submissions: records.map(submissionEvidence),
      duplicateTextDistinctIds: !fail, exactlyOneQueuedHandleCancelled: !fail,
      cancellationReason: fail ? "not-exercised" : "cancelled",
      noSuccessorEventLeakage: true, owningFailureObserved: fail,
      fabricatedReceiptUsed: false,
    };
  });
}

async function probeLateControl(ownerRoot, delivery, { overlapGate = false } = {}) {
  let late;
  let boundaryObserved = false;
  let boundaryState;
  let boundaryScope;
  let originalRawScope;
  let rawTerminalStopReason;
  let rawTerminalBeforeLateSubmission = false;
  let initial;
  let harnessRef;
  const isFollowUp = delivery === "followUp";
  const options = {
    withAsk: overlapGate,
    ...(overlapGate ? { gateAnswerWindowMs: OVERLAP_GATE_WINDOW_MS } : {}),
    onRawAgentEvent(event, getAdapter, getState) {
      if (event.type === "agent_start" && !originalRawScope) {
        originalRawScope = structuredClone(event.scope);
      }
      if (event.type !== "agent_end" || boundaryObserved) return;
      boundaryObserved = true;
      boundaryScope = scopeKey(event.scope);
      rawTerminalStopReason = event.stopReason;
      requireCondition(scopeKey(originalRawScope) === boundaryScope,
        "LATE_RAW_TERMINAL_NOT_ORIGINALLY_OWNED");
      requireCondition(rawTerminalStopReason === "completed" && !event.messages.some((message) =>
        message.role === "assistant" && ["error", "aborted", "cancelled"].includes(message.stopReason)),
      "LATE_RAW_ROOT_NOT_SUCCESSFUL");
      rawTerminalBeforeLateSubmission = !late && harnessRef.submissions.length === 0;
      requireCondition(rawTerminalBeforeLateSubmission, "LATE_RAW_PROOF_AFTER_SUBMISSION");
      const { agent, session } = getState();
      boundaryState = { agentStreaming: agent.state.isStreaming, sessionStreaming: session.isStreaming };
      requireCondition(getAdapter() === harnessRef.adapter, "LATE_ADAPTER_BINDING_CHANGED");
      late = startOwned(harnessRef, "late-control-owner", {
        type: isFollowUp ? "follow_up" : "steer", message: "late boundary control",
      });
    },
  };
  const responses = [{ content: ["initial boundary complete"] },
    overlapGate ? { content: [{ type: "toolCall", name: "ask", arguments: {
      questions: [{ id: "promoted-question", question: "Choose promoted answer", options: [{ label: "Proceed" }], multi: false }],
    } }] } : { content: ["late control consumed"] }];
  // This response must never run in the deliberate overlapping-gate case.
  responses.push({ content: ["unrelated boundary successor"] });
  const stage = overlapGate ? "late-follow-up-gate-overlap" : isFollowUp ? "late-follow-up-continuation" : "late-steer-rearm";
  return withHarness(stage, ownerRoot,
    { primary: responses }, options, async (harness) => {
      harnessRef = harness;
      const rawGates = [];
      let resolveCalls = 0;
      if (overlapGate) {
        const emitter = harness.session.getWorkflowGateEmitter();
        const originalResolve = emitter.resolveGate;
        emitter.resolveGate = function (...args) {
          resolveCalls += 1;
          return originalResolve.apply(this, args);
        };
        harness.releases.push(() => { emitter.resolveGate = originalResolve; });
        harness.releases.push(emitter.onGateEmitted((gate) => rawGates.push({
          gate,
          publicTerminalCount: terminalEvents(harness.events).length,
          publicRootPromptStatus: harness.promptCalls[0]?.status ?? "not-started",
          initialStatus: initial.run.status,
          lateStatus: late.run.status,
        })));
      }
      initial = startOwned(harness, "late-initial-owner", { type: "prompt", message: "initial boundary" });
      await waitFor(() => boundaryObserved && late, "RAW_UNWIND_BOUNDARY_NOT_OBSERVED");
      requireCondition(boundaryState.agentStreaming === false && boundaryState.sessionStreaming === true,
        "LATE_CONTROL_NOT_IN_UNWIND_WINDOW", boundaryState);
      const record = await requireSubmission(harness, 0, delivery);
      await withDeadline(record.execution.settled, STEP_TIMEOUT_MS, "LATE_CONTROL_NOT_EXECUTED");
      requireCondition(record.execution.value?.disposition === "promoted-to-run", "LATE_CONTROL_NOT_ACTUALLY_PROMOTED");
      await waitFor(() => harness.mockModels.get("primary").calls.length >= 2, "LATE_CONTROL_PROVIDER_NOT_INVOKED");
      requireCondition(userTexts(harness.mockModels.get("primary").calls[1].context).includes("late boundary control"),
        "LATE_CONTROL_NOT_CONSUMED_BY_PROVIDER");
      if (overlapGate) {
        await waitFor(() => rawGates.length === 1, "ACTUAL_PROMOTED_OVERLAP_GATE_MISSING");
        const emitted = rawGates[0];
        const emitter = harness.session.getWorkflowGateEmitter();
        requireCondition(emitted.gate.kind === "question" && emitted.publicTerminalCount === 0 &&
          ["pending", "fulfilled"].includes(emitted.initialStatus) &&
          ["pending", "fulfilled"].includes(emitted.publicRootPromptStatus) &&
          (emitted.initialStatus !== "fulfilled" || emitted.publicRootPromptStatus === "fulfilled") &&
          rawTerminalBeforeLateSubmission &&
          emitted.lateStatus === "pending" && record.terminal.status === "pending" &&
          emitter.listPendingGates().some((gate) => gate.gate_id === emitted.gate.gate_id),
        "PROMOTED_GATE_OVERLAP_NOT_REPRODUCED");
        const execution = record.execution.value;
        requireCondition(execution.submissionId === record.handle.submissionId && execution.delivery === "followUp" &&
          scopeKey(execution.attemptScope) !== boundaryScope &&
          late.executionIdsAtActivation.includes(record.handle.submissionId) && late.activations === 1 &&
          record.handle.cancel() === false && late.ticket.revokeBeforeStart() === false,
        "PROMOTED_OVERLAP_EXECUTION_NOT_GENUINE");
        const beforeTeardown = {
          publicTerminalCount: emitted.publicTerminalCount,
          publicRootPromptStatus: emitted.publicRootPromptStatus,
          initialStatus: emitted.initialStatus,
          lateStatus: emitted.lateStatus,
          trackedTerminalStatus: record.terminal.status,
        };
        const adapterGateRelease = harness.adapter.gateUnsubscribe;
        requireCondition([...harness.subscriptions].some((subscription) => subscription.release === adapterGateRelease),
          "PROMOTED_GATE_ADAPTER_LISTENER_NOT_REGISTERED");
        await withDeadline(Promise.all([initial.run.settled, late.run.settled]),
          STEP_TIMEOUT_MS, "PROMOTED_GATE_REFUSAL_NOT_BOUNDED");
        const originalPublicPromptStatus = harness.promptCalls[0]?.status ?? "not-started";
        const originalRootProven = rawTerminalBeforeLateSubmission &&
          scopeKey(originalRawScope) === boundaryScope && originalPublicPromptStatus === "fulfilled";
        // A completed original result cannot be retroactively failed by the
        // ambiguous promoted gate. The unresolved tracked caller must refuse it.
        requireCondition(late.run.status === "rejected" &&
          late.run.failureCode === PROMOTED_GATE_OWNERSHIP_CODE && late.ticket.phase === "terminal" &&
          initial.ticket.phase === "terminal" &&
          (initial.run.status === "fulfilled" ? originalRootProven :
            initial.run.status === "rejected" && initial.run.failureCode === PROMOTED_GATE_OWNERSHIP_CODE),
        "PROMOTED_GATE_OWNERSHIP_NOT_REFUSED", {
          initialStatus: initial.run.status, initialFailureCode: initial.run.failureCode,
          publicRootPromptStatus: originalPublicPromptStatus,
          followUpStatus: late.run.status, followUpFailureCode: late.run.failureCode,
        });
        requireCondition(![...initial.events, ...late.events].some((event) => event.type === "gate_request") &&
          resolveCalls === 0 && harness.mockModels.get("primary").calls.length === 2,
        "AMBIGUOUS_PROMOTED_GATE_PRESENTED_OR_ANSWERED");
        await withDeadline(harness.adapter.dispose(), STEP_TIMEOUT_MS, "PROMOTED_GATE_REFUSAL_TEARDOWN_TIMEOUT");
        requireCondition(emitter.listPendingGates().length === 0 && harness.adapter.pendingGates.size === 0 &&
          harness.adapter.activeGateRuns.length === 0 && harness.adapter.ownedQueueTickets.size === 0 &&
          harness.adapter.adapterWaiterCancellations.size === 0 && !harness.adapter.isBusy() &&
          harness.adapter.inFlightGateAnswers.size === 0 && harness.adapter.deferredGateCandidate === undefined &&
          ![...harness.subscriptions].some((subscription) => subscription.release === adapterGateRelease) &&
          harness.calls.sessionDispose === 1 && harness.calls.managerClose === 1 &&
          harness.calls.registryDispose === 0 && harness.calls.providerRelease === 0 &&
          harness.calls.authClose === 0 && harness.calls.settingsClose === 0,
        "PROMOTED_GATE_REFUSAL_TEARDOWN_INCOMPLETE");
        requireCondition(resolveCalls === 0 && harness.mockModels.get("primary").calls.length === 2 &&
          ![...initial.events, ...late.events].some((event) => event.type === "gate_request"),
        "PROMOTED_GATE_REFUSAL_CONTINUATION_OR_PRESENTATION_LEAKED");
        return {
          status: "bounded-refusal-qualified", code: PROMOTED_GATE_OWNERSHIP_CODE,
          boundary: "raw-Agent-agent_end-before-AgentSession-unwind",
          actualSuccessorProviderInvoked: true, actualQueuedTextConsumed: true,
          submissionId: record.handle.submissionId, admitted: record.admitted.value, execution,
          beforeTeardown, gateWindowMs: OVERLAP_GATE_WINDOW_MS,
          originalRootResult: {
            evidenceKind: "public-AgentSession.agent-raw-scope-and-own-public-prompt",
            rawScope: originalRawScope, rawTerminalStopReason, rawTerminalBeforeLateSubmission,
            publicPromptCallIndex: 0, publicPromptStatus: originalPublicPromptStatus,
            adapterStatus: initial.run.status, fulfilledWithOwnProof: initial.run.status === "fulfilled" && originalRootProven,
            sdkPublicRootTerminalCountAtGateEmission: emitted.publicTerminalCount,
          },
          initialFailureCode: initial.run.failureCode, promotedFailureCode: late.run.failureCode,
          gateRequestCount: 0, sdkResolveCalls: resolveCalls, continuationProviderCalls: 0,
          pendingGatesRetired: true, realTeardownCompleted: true,
          fixtureResourcesOpenUntilOwnerTeardown: true,
          promotedGateExactOwnerAndPresentation: false,
          fabricatedReceiptUsed: false,
        };
      }
      const receipt = await requireOwningTerminal(harness, late, record);
      await withDeadline(initial.run.settled, STEP_TIMEOUT_MS, "LATE_INITIAL_DID_NOT_SETTLE");
      const terminals = terminalEvents(harness.events);
      const publicRootTerminals = terminals.filter((event) => scopeKey(event.scope) === boundaryScope);
      const trackedFinalScope = scopeKey(record.terminal.value.attemptScope);
      // SDK publication may coalesce to the promoted scope. Raw root execution
      // plus its own prompt proves only the root result, not SDK readiness or a
      // tracked terminal; requireOwningTerminal above still requires both real
      // successor handle completion and its exact public SDK terminal.
      requireCondition(rawTerminalBeforeLateSubmission && scopeKey(originalRawScope) === boundaryScope &&
        harness.promptCalls[0]?.status === "fulfilled" && initial.run.status === "fulfilled" &&
        publicRootTerminals.length <= 1 &&
        terminals.every((event) => [boundaryScope, trackedFinalScope].includes(scopeKey(event.scope))) &&
        terminalEvents(initial.events).length === 0 &&
        boundaryScope !== scopeKey(record.execution.value.attemptScope) && boundaryScope !== trackedFinalScope &&
        initial.events.filter((event) => event.scope).every((event) => scopeKey(event.scope) === boundaryScope) &&
        !late.events.some((event) => event.scope && scopeKey(event.scope) === boundaryScope),
      "LATE_INITIAL_TERMINAL_OWNERSHIP_WRONG");
      const initialCount = initial.events.length;
      const lateCount = late.events.length;
      await withDeadline(harness.adapter.send({ type: "prompt", message: "boundary successor" }, () => {}, 5_000),
        STEP_TIMEOUT_MS, "LATE_SUCCESSOR_DID_NOT_SETTLE");
      requireCondition(initial.events.length === initialCount && late.events.length === lateCount, "LATE_SUCCESSOR_EVENTS_LEAKED");
      return {
        status: "qualified", boundary: "raw-Agent-agent_end-before-AgentSession-unwind",
        actualSuccessorProviderInvoked: true, actualQueuedTextConsumed: true,
        executionDisposition: receipt.executionDisposition, exactOwningTerminal: true,
        submission: submissionEvidence(record),
        originalRootResult: {
          evidenceKind: "public-AgentSession.agent-raw-scope-and-own-public-prompt",
          rawScope: originalRawScope, rawTerminalStopReason, rawTerminalBeforeLateSubmission,
          publicPromptCallIndex: 0, publicPromptStatus: "fulfilled", adapterStatus: initial.run.status,
          sdkPublicRootTerminalCount: publicRootTerminals.length,
          sdkPublicTerminalCount: terminals.length,
        },
        trackedTerminalProof: "genuine-handle-terminal-and-matching-public-SDK-agent_end",
        noSuccessorEventLeakage: true, cancelAfterExecution: false,
        providerCalls: harness.mockModels.get("primary").calls.length, fabricatedReceiptUsed: false,
      };
    });
}

async function probeJoinedAsk(ownerRoot) {
  const ownerId = "joined-ask-primary-owner";
  const joinerId = "joined-ask-steer-owner";
  const steerText = "joined ask steer";
  let resultText = "";
  const askResponse = (id, label) => ({ content: [{ type: "toolCall", name: "ask", arguments: {
    questions: [{ id, question: "Choose a joined run answer", options: [{ label }], multi: false }],
  } }] });
  return withHarness("joined-steer-ask", ownerRoot, { primary: [
    askResponse("primary-held-question", "Primary answer"),
    (context) => {
      requireCondition(userTexts(context).includes(steerText), "JOINED_ASK_STEER_NOT_CONSUMED");
      return askResponse("joined-continuation-question", "Joined answer");
    },
    (context) => {
      resultText = toolResultText(context);
      return { content: ["joined ask run complete"] };
    },
  ] }, { withAsk: true }, async (harness) => {
    const emitter = harness.session.getWorkflowGateEmitter();
    const rawGates = [];
    const originalResolve = emitter.resolveGate;
    let resolveCalls = 0;
    emitter.resolveGate = function (...args) {
      resolveCalls += 1;
      return originalResolve.apply(this, args);
    };
    harness.releases.push(() => { emitter.resolveGate = originalResolve; });
    harness.releases.push(emitter.onGateEmitted((gate) => rawGates.push(structuredClone(gate))));
    const primary = startOwned(harness, ownerId, { type: "prompt", message: "hold primary for joined ask" });
    await waitFor(() => rawGates.length === 1 && primary.events.some((event) => event.type === "gate_request"),
      "JOINED_ASK_PRIMARY_GATE_MISSING");
    const firstGate = primary.events.find((event) => event.type === "gate_request");
    const joined = startOwned(harness, joinerId, { type: "steer", message: steerText });
    const record = await requireSubmission(harness, 0, "steer");
    requireCondition(primary.run.status === "pending" && harness.promptCalls[0]?.status === "pending" &&
      joined.run.status === "pending" && joined.ticket.phase === "queued" && joined.activations === 0 &&
      record.execution.status === "pending" && record.terminal.status === "pending" &&
      emitter.listPendingGates().some((gate) => gate.gate_id === firstGate.gateId) &&
      harness.mockModels.get("primary").calls.length === 1,
    "JOINED_ASK_PRIMARY_NOT_HELD_AT_ADMISSION");
    requireCondition(harness.adapter.presentGate(ownerId, firstGate.gateId, firstGate.presentationId,
      "joined-primary-presentation") === true, "JOINED_ASK_PRIMARY_PRESENTATION_REFUSED");
    const firstAnswer = await withDeadline(harness.adapter.answerGate(ownerId, firstGate.gateId,
      firstGate.presentationId, "Primary answer"), STEP_TIMEOUT_MS, "JOINED_ASK_PRIMARY_ANSWER_TIMEOUT");
    requireCondition(firstAnswer?.ok === true, "JOINED_ASK_PRIMARY_ANSWER_REFUSED");
    await withDeadline(record.execution.settled, STEP_TIMEOUT_MS, "JOINED_ASK_EXECUTION_MISSING");
    requireCondition(record.execution.value?.disposition === "joined-current-run",
      "JOINED_ASK_NOT_GENUINELY_JOINED", { executionDisposition: record.execution.value?.disposition });
    await waitFor(() => rawGates.length === 2 &&
      primary.events.filter((event) => event.type === "gate_request").length === 2,
    "JOINED_ASK_CONTINUATION_GATE_MISSING");
    const secondGate = primary.events.filter((event) => event.type === "gate_request")[1];
    requireCondition(rawGates.every((gate, index) => gate.type === "workflow_gate" && gate.kind === "question" &&
      gate.gate_id === [firstGate, secondGate][index].gateId) && firstGate.gateId !== secondGate.gateId &&
      primary.run.status === "pending" && joined.run.status === "pending" &&
      record.terminal.status === "pending" && joined.activations === 1 &&
      joined.executionIdsAtActivation.includes(record.handle.submissionId) &&
      !joined.events.some((event) => event.type === "gate_request") && resolveCalls === 1 &&
      harness.mockModels.get("primary").calls.length === 2,
    "JOINED_ASK_LOGICAL_OWNER_CHANGED");
    requireCondition(harness.adapter.presentGate(joinerId, secondGate.gateId, secondGate.presentationId,
      "wrong-joined-presentation") === false, "JOINED_ASK_JOINER_PRESENTATION_ACCEPTED");
    requireCondition(harness.adapter.presentGate(ownerId, secondGate.gateId, secondGate.presentationId,
      "joined-continuation-presentation") === true, "JOINED_ASK_OWNER_PRESENTATION_REFUSED");
    // Try the wrong owner only after a real owner has made the gate answerable,
    // so refusal cannot be explained by the presentation barrier alone.
    const wrongAnswer = await withDeadline(harness.adapter.answerGate(joinerId, secondGate.gateId,
      secondGate.presentationId, "Joined answer"), STEP_TIMEOUT_MS, "JOINED_ASK_WRONG_ANSWER_TIMEOUT");
    requireCondition(wrongAnswer?.ok === false && resolveCalls === 1 &&
      emitter.listPendingGates().some((gate) => gate.gate_id === secondGate.gateId),
    "JOINED_ASK_JOINER_ANSWER_CONSUMED");
    const secondAnswer = await withDeadline(harness.adapter.answerGate(ownerId, secondGate.gateId,
      secondGate.presentationId, "Joined answer"), STEP_TIMEOUT_MS, "JOINED_ASK_OWNER_ANSWER_TIMEOUT");
    requireCondition(secondAnswer?.ok === true, "JOINED_ASK_OWNER_ANSWER_REFUSED");
    const owning = await requireOwningTerminal(harness, joined, record);
    await withDeadline(primary.run.settled, STEP_TIMEOUT_MS, "JOINED_ASK_PRIMARY_DID_NOT_SETTLE");
    const terminals = terminalEvents(harness.events);
    const finalScope = scopeKey(record.terminal.value.attemptScope);
    requireCondition(primary.run.status === "fulfilled" && primary.ticket.phase === "terminal" &&
      harness.promptCalls[0]?.status === "fulfilled" && terminals.length === 1 &&
      scopeKey(terminals[0].scope) === finalScope && primary.settledAtTerminalScopes.includes(finalScope) &&
      joined.settledAtTerminalScopes.includes(finalScope) && terminalEvents(primary.events).length === 0 &&
      !joined.events.some((event) => event.type === "gate_request") && rawGates.length === 2 && resolveCalls === 2 &&
      harness.mockModels.get("primary").calls.length === 3 &&
      resultText.includes("Primary answer") && resultText.includes("Joined answer") &&
      emitter.listPendingGates().length === 0 && harness.adapter.pendingGates.size === 0,
    "JOINED_ASK_SHARED_PUBLIC_TERMINAL_MISMATCH");
    return {
      status: "qualified", evidenceKind: "installed-public-SDK-Ask-with-credentialless-mock-provider",
      primaryAskHeldAtAdmission: true, actualQueuedTextConsumed: true,
      executionDisposition: owning.executionDisposition, submission: submissionEvidence(record),
      emittedGateCount: rawGates.length, originalOwnerGateRequestCount: 2, joinedCallerGateRequestCount: 0,
      joinedCallerPresentationRefused: true, joinedCallerAnswerRefused: true,
      originalOwnerAnsweredBothGates: true, sdkResolveCalls: resolveCalls, providerCalls: 3,
      originalPublicPromptStatus: harness.promptCalls[0].status,
      adapterStatuses: { original: primary.run.status, joined: joined.run.status },
      sharedPublicTerminalCount: terminals.length, exactSharedPublicTerminalAndHandleScope: true,
      trackedTerminalProof: "genuine-handle-terminal-and-matching-public-SDK-agent_end",
      fabricatedReceiptUsed: false,
    };
  });
}

async function probeGates(ownerRoot) {
  let resultText = "";
  const customAnswer = "fixture custom answer";
  return withHarness(
    "workflow-gates",
    ownerRoot,
    {
      primary: [
        {
          content: [
            {
              type: "toolCall",
              name: "ask",
              arguments: {
                questions: [
                  {
                    id: "selection",
                    question: "Choose a contract option",
                    options: [{ label: "Alpha" }, { label: "Beta" }],
                    multi: false,
                  },
                  {
                    id: "custom",
                    question: "Provide a custom contract answer",
                    options: [{ label: "Use default" }],
                    multi: false,
                  },
                ],
              },
            },
          ],
        },
        (context) => {
          resultText = toolResultText(context);
          return { content: ["gate sequence complete"] };
        },
      ],
    },
    { withAsk: true },
    async (harness) => {
      const emitter = harness.session.getWorkflowGateEmitter();
      requireCondition(emitter?.supportsRemoteGateAnswers() === true, "REAL_GATE_EMITTER_UNAVAILABLE");
      const rawGates = [];
      const gateEvents = [];
      const originalResolve = emitter.resolveGate;
      const originalLookup = emitter.lookupCompletedResolution;
      let lostResponse;
      let lostResponseSnapshot;
      let actualSuccessfulResolutions = 0;
      let lostResponseCount = 0;
      let exactCompletedLookups = 0;
      const resolveCalls = new Map();
      // Inject only a transport-like loss of the return value. The installed
      // public SDK gate emitter must have completed the real Ask continuation first.
      emitter.resolveGate = async function (response) {
        resolveCalls.set(response.gate_id, (resolveCalls.get(response.gate_id) ?? 0) + 1);
        const resolution = await originalResolve.call(this, response);
        requireCondition(resolution?.status === "accepted", "REAL_RESOLUTION_NOT_ACCEPTED");
        actualSuccessfulResolutions += 1;
        if (lostResponseCount === 0) {
          const completed = originalLookup.call(this, response);
          requireCondition(completed?.kind === "completed", "REAL_RESOLUTION_NOT_COMPLETED_BEFORE_LOSS");
          lostResponse = structuredClone(response);
          lostResponseSnapshot = JSON.stringify(response);
          lostResponseCount += 1;
          throw new ProbeError("INJECTED_COMPLETED_RESPONSE_LOSS");
        }
        return resolution;
      };
      emitter.lookupCompletedResolution = function (response) {
        const state = originalLookup.call(this, response);
        if (lostResponse && response.gate_id === lostResponse.gate_id) {
          requireCondition(JSON.stringify(response) === lostResponseSnapshot, "COMPLETED_LOOKUP_RESPONSE_CHANGED");
          requireCondition(state?.kind === "completed", "EXACT_COMPLETED_LOOKUP_MISSING");
          exactCompletedLookups += 1;
        }
        return state;
      };
      const unsubscribeGate = emitter.onGateEmitted((gate) => rawGates.push(structuredClone(gate)));
      try {
        const ownerId = "sdk-contract-probe-owner";
        const run = observe(
          harness.adapter.sendOwned(
            ownerId,
            { type: "prompt", message: "exercise real ask gates" },
            (event) => {
              if (event?.type === "gate_request") gateEvents.push(event);
            },
            5_000
          ).result
        );

        await waitFor(() => gateEvents.length === 1 && rawGates.length === 1, "FIRST_GATE_NOT_EMITTED");
        requireCondition(
          harness.adapter.presentGate(
            ownerId,
            gateEvents[0].gateId,
            gateEvents[0].presentationId,
            "sdk-contract-presentation-1"
          ) === true,
          "SELECTION_GATE_PRESENTATION_REJECTED"
        );
        const selection = await withDeadline(
          harness.adapter.answerGate(
            ownerId,
            gateEvents[0].gateId,
            gateEvents[0].presentationId,
            "Beta"
          ),
          STEP_TIMEOUT_MS,
          "SELECTION_GATE_ANSWER_TIMEOUT"
        );
        requireCondition(selection?.ok === true, "SELECTION_GATE_REJECTED");
        requireCondition(lostResponseCount === 1 && exactCompletedLookups >= 1, "LOST_RESPONSE_NOT_RECONCILED");
        const completed = emitter.lookupCompletedResolution(lostResponse);
        requireCondition(
          JSON.stringify(selection.resolution) === JSON.stringify(completed.resolution),
          "RECONCILED_RESOLUTION_CHANGED"
        );
        const duplicate = await harness.adapter.answerGate(
          ownerId,
          gateEvents[0].gateId,
          gateEvents[0].presentationId,
          "Beta"
        );
        requireCondition(duplicate?.ok === false, "COMPLETED_GATE_DUPLICATE_ANSWER_ACCEPTED");
        requireCondition(resolveCalls.get(gateEvents[0].gateId) === 1, "COMPLETED_GATE_REANSWERED_IN_SDK");
        let conflictCode;
        try {
          originalLookup.call(emitter, {
            ...lostResponse,
            answer: { selected: ["Alpha"] },
          });
        } catch (error) {
          conflictCode = observedFailureCode(error);
        }
        requireCondition(conflictCode === "idempotency_conflict", "COMPLETED_LOOKUP_NOT_RESPONSE_BOUND");

        await waitFor(() => gateEvents.length === 2 && rawGates.length === 2, "SUCCESSOR_GATE_NOT_EMITTED");
        requireCondition(gateEvents[0].gateId !== gateEvents[1].gateId, "SUCCESSOR_GATE_ID_REUSED");
        requireCondition(
          harness.adapter.presentGate(
            ownerId,
            gateEvents[1].gateId,
            gateEvents[1].presentationId,
            "sdk-contract-presentation-2"
          ) === true,
          "CUSTOM_GATE_PRESENTATION_REJECTED"
        );
        const invalid = await withDeadline(
          harness.adapter.answerGate(
            ownerId,
            gateEvents[1].gateId,
            gateEvents[1].presentationId,
            "   "
          ),
          STEP_TIMEOUT_MS,
          "INVALID_CUSTOM_GATE_ANSWER_TIMEOUT"
        );
        requireCondition(invalid?.ok === false, "INVALID_CUSTOM_GATE_ANSWER_ACCEPTED");
        const custom = await withDeadline(
          harness.adapter.answerGate(
            ownerId,
            gateEvents[1].gateId,
            gateEvents[1].presentationId,
            customAnswer
          ),
          STEP_TIMEOUT_MS,
          "CUSTOM_GATE_ANSWER_TIMEOUT"
        );
        requireCondition(custom?.ok === true, "CUSTOM_GATE_ANSWER_REJECTED");
        requireCondition(
          actualSuccessfulResolutions === 2 &&
            resolveCalls.size === 2 &&
            [...resolveCalls.values()].every((count) => count === 1),
          "REAL_GATE_RESOLUTION_COUNT_WRONG"
        );

        await withDeadline(run.settled, STEP_TIMEOUT_MS, "GATED_PROMPT_DID_NOT_SETTLE");
        requireCondition(run.status === "fulfilled", "GATED_PROMPT_FAILED");
        requireCondition(terminalEvents(harness.events).length === 1, "GATED_PROMPT_TERMINAL_COUNT_WRONG");
        requireCondition(harness.mockModels.get("primary").calls.length === 2, "GATED_PROVIDER_CALL_COUNT_WRONG");
        requireCondition(resultText.includes("Beta"), "SELECTION_MISSING_FROM_TOOL_RESULT");
        requireCondition(resultText.includes(customAnswer), "CUSTOM_ANSWER_MISSING_FROM_TOOL_RESULT");
        requireCondition(
          rawGates.every(
            (gate) =>
              gate?.type === "workflow_gate" &&
              gate?.kind === "question" &&
              gate?.schema?.type === "object" &&
              gate?.schema?.properties?.selected?.type === "array" &&
              Array.isArray(gate?.schema?.anyOf) &&
              /^[0-9a-f]{64}$/.test(gate?.schema_hash)
          ),
          "REAL_ASK_GATE_SCHEMA_MISSING"
        );

        return {
          emittedGateCount: rawGates.length,
          distinctSuccessorGateIds: true,
          sdkObjectSchemaObserved: true,
          selectionAccepted: true,
          invalidCustomRejectedWithoutConsumption: true,
          customAcceptedOnRetry: true,
          toolResultObservedBothAnswers: true,
          terminalCount: 1,
          completedResponseLoss: {
            evidenceKind: "installed-public-SDK-with-credentialless-mock-provider",
            injectedBoundary: "returned-response-after-actual-completed-resolution",
            lostResponseCount,
            completedLookupKind: completed.kind,
            exactResponseBound: true,
            conflictRejected: true,
            actualSuccessfulResolutions,
            firstGateResolveCalls: resolveCalls.get(gateEvents[0].gateId),
            duplicateAnswerRefused: true,
            continuationProviderCalls: harness.mockModels.get("primary").calls.length - 1,
            fabricatedCompletionUsed: false,
          },
        };
      } finally {
        unsubscribeGate();
        emitter.resolveGate = originalResolve;
        emitter.lookupCompletedResolution = originalLookup;
      }
    }
  );
}

async function probeFailureTerminal(ownerRoot) {
  return withHarness(
    "failure-terminal",
    ownerRoot,
    { primary: [{ throw: "fixture-provider-failure" }] },
    {},
    async (harness) => {
      const run = observe(
        harness.adapter.send({ type: "prompt", message: "fail deterministically" }, () => {}, 5_000)
      );
      await withDeadline(run.settled, STEP_TIMEOUT_MS, "FAILURE_SEND_DID_NOT_SETTLE");
      const terminals = terminalEvents(harness.events);
      const terminalContainsFailure = terminals.some(
        (event) =>
          Array.isArray(event?.messages) &&
          event.messages.some(
            (message) => message?.role === "assistant" && message?.stopReason === "error"
          )
      );
      const failedMessageObserved = harness.events.some(
        (event) =>
          event?.type === "message_end" &&
          event?.message?.role === "assistant" &&
          event?.message?.stopReason === "error"
      );
      requireCondition(terminals.length === 1, "FAILURE_TERMINAL_COUNT_WRONG");
      requireCondition(terminalContainsFailure, "FAILURE_NOT_CARRIED_BY_TERMINAL");
      requireCondition(failedMessageObserved, "FAILED_ASSISTANT_MESSAGE_NOT_OBSERVED");
      requireCondition(run.status === "rejected", "FAILED_PROVIDER_RUN_REPORTED_SUCCESS");

      return {
        providerFailureMessageObserved: true,
        terminalContainsFailure: true,
        terminalCount: 1,
        adapterRejected: true,
      };
    }
  );
}

async function probeDisposeWithoutTerminal(ownerRoot) {
  return withHarness(
    "dispose-without-terminal",
    ownerRoot,
    { primary: [{ delayMs: 60_000, content: ["must never complete"] }] },
    {},
    async (harness) => {
      const run = observe(
        harness.adapter.send({ type: "prompt", message: "dispose active work" }, () => {}, 8_000)
      );
      await waitFor(
        () => harness.mockModels.get("primary").calls.length === 1,
        "DISPOSAL_PROVIDER_CALL_MISSING"
      );
      const disposal = observe(harness.adapter.dispose());
      await withDeadline(disposal.settled, STEP_TIMEOUT_MS, "ADAPTER_DISPOSAL_DID_NOT_SETTLE");
      await withDeadline(run.settled, 250, "DISPOSED_SEND_DID_NOT_SETTLE");
      requireCondition(disposal.status === "fulfilled", "ADAPTER_DISPOSAL_FAILED");
      requireCondition(run.status === "rejected", "DISPOSED_SEND_REPORTED_SUCCESS");
      requireCondition(terminalEvents(harness.events).length === 0, "DISPOSAL_FABRICATED_TERMINAL");

      return {
        disposeSettled: true,
        activeSendRejected: true,
        underlyingTerminalCount: 0,
      };
    }
  );
}

async function probePendingAskDisposal(ownerRoot) {
  return withHarness(
    "pending-ask-disposal",
    ownerRoot,
    {
      primary: [{
        content: [{
          type: "toolCall",
          name: "ask",
          arguments: {
            questions: [{
              id: "pending-disposal",
              question: "Keep this real Ask gate pending",
              options: [{ label: "Continue" }],
              multi: false,
            }],
          },
        }],
      }],
    },
    { withAsk: true },
    async (harness) => {
      const ownerId = "sdk-contract-pending-ask-owner";
      const events = [];
      const emitter = harness.session.getWorkflowGateEmitter();
      const originalResolve = emitter.resolveGate;
      let resolveCalls = 0;
      emitter.resolveGate = function (...args) {
        resolveCalls += 1;
        return originalResolve.apply(this, args);
      };
      try {
        const ticket = harness.adapter.sendOwned(
          ownerId,
          { type: "prompt", message: "dispose an acknowledged pending Ask gate" },
          (event) => events.push(event),
          5_000
        );
        const run = observe(ticket.result);
        await waitFor(
          () => events.filter((event) => event?.type === "gate_request").length === 1,
          "PENDING_ASK_GATE_NOT_EMITTED"
        );
        const gate = events.find((event) => event?.type === "gate_request");
        requireCondition(
          emitter.listPendingGates().some((pending) => pending.gate_id === gate.gateId),
          "ACTUAL_ASK_GATE_NOT_PENDING"
        );
        requireCondition(
          harness.adapter.presentGate(ownerId, gate.gateId, gate.presentationId, "pending-ask-presentation"),
          "PENDING_ASK_PRESENTATION_NOT_ACKNOWLEDGED"
        );
        requireCondition(run.status === "pending" && ticket.phase === "active", "PENDING_ASK_OWNER_NOT_ACTIVE");
        // Ask itself also subscribes through the public onGateEmitted API
        // while awaiting emitGate, then unsubscribes in its finally block.
        // Prove this adapter's exact release handle, not a private assumption
        // that the entire SDK emitter has only one listener.
        requireCondition(
          [...harness.subscriptions].some(
            (subscription) => subscription.kind === "gate" &&
              subscription.release === harness.adapter.gateUnsubscribe
          ),
          "PENDING_ASK_LISTENER_NOT_REGISTERED"
        );
        const disposal = observe(Promise.all([
          harness.adapter.dispose(),
          harness.adapter.dispose(),
        ]));
        await withDeadline(disposal.settled, STEP_TIMEOUT_MS, "PENDING_ASK_DISPOSAL_DID_NOT_SETTLE");
        await withDeadline(run.settled, 250, "PENDING_ASK_OWNED_SEND_DID_NOT_SETTLE");
        requireCondition(disposal.status === "fulfilled", "PENDING_ASK_DISPOSAL_FAILED");
        requireCondition(run.status === "rejected" && ticket.phase === "terminal", "PENDING_ASK_OWNED_SEND_NOT_REJECTED");
        await harness.adapter.dispose();
        const lateAnswer = await harness.adapter.answerGate(ownerId, gate.gateId, gate.presentationId, "Continue");
        requireCondition(lateAnswer?.ok === false, "DISPOSED_ASK_LATE_ANSWER_ACCEPTED");
        requireCondition(
          harness.adapter.presentGate(ownerId, gate.gateId, gate.presentationId, "late-presentation") === false,
          "DISPOSED_ASK_LATE_PRESENTATION_ACCEPTED"
        );
        requireCondition(resolveCalls === 0, "DISPOSED_ASK_ANSWER_REACHED_SDK");
        requireCondition(emitter.listPendingGates().length === 0, "DISPOSED_SDK_ASK_STILL_PENDING");
        requireCondition(
          harness.adapter.pendingGates.size === 0 &&
            harness.adapter.deferredGateCandidate === undefined &&
            harness.adapter.activeGateRuns.length === 0 &&
            harness.adapter.inFlightGateAnswers.size === 0 &&
            harness.adapter.adapterWaiterCancellations.size === 0 &&
            harness.adapter.ownedQueueTickets.size === 0 &&
            harness.adapter.gateUnsubscribe === undefined &&
            !harness.adapter.isBusy(),
          "DISPOSED_ASK_ADAPTER_OWNERSHIP_RETAINED"
        );
        requireCondition(
          [...harness.subscriptions].every((subscription) => subscription.kind === "session") &&
            harness.subscriptions.size === 1,
          "DISPOSED_ASK_ADAPTER_LISTENER_RETAINED"
        );
        requireCondition(
          harness.calls.sessionDispose === 1 && harness.calls.managerClose === 1 &&
            harness.calls.registryDispose === 0 && harness.calls.providerRelease === 0 &&
            harness.calls.authClose === 0 && harness.calls.settingsClose === 0,
          "DISPOSED_ASK_RESOURCE_OWNERSHIP_WRONG",
          harness.calls
        );
        requireCondition(terminalEvents(harness.events).length === 0 && terminalEvents(events).length === 0, "PENDING_ASK_DISPOSAL_FABRICATED_TERMINAL");
        requireCondition(harness.mockModels.get("primary").calls.length === 1, "DISPOSED_ASK_CONTINUATION_RAN");
        return {
          evidenceKind: "installed-public-SDK-Ask-with-credentialless-mock-provider",
          exactPresentationAcknowledged: true,
          cancellationSurface: "adapter.dispose-quarantines-owned-gate",
          ownedSendRejected: true,
          ownerTicketPhase: ticket.phase,
          underlyingTerminalCount: terminalEvents(harness.events).length,
          lateAnswerRefused: true,
          sdkResolveCalls: resolveCalls,
          continuationProviderCalls: 0,
          pendingAndDeferredRetired: true,
          adapterListenersRetired: true,
          listenerOwnershipProof: "exact-adapter-public-unsubscribe-handle",
          sessionDisposeCalls: harness.calls.sessionDispose,
          managerCloseCalls: harness.calls.managerClose,
          fixtureResourcesOpenUntilOwnerTeardown: true,
          fabricatedTerminalUsed: false,
        };
      } finally {
        emitter.resolveGate = originalResolve;
      }
    }
  );
}

async function probePendingAskActiveCancel(ownerRoot) {
  return withHarness(
    "pending-ask-active-cancel",
    ownerRoot,
    {
      primary: [{
        content: [{
          type: "toolCall",
          name: "ask",
          arguments: {
            questions: [{
              id: "pending-active-cancel",
              question: "Cancel this acknowledged real Ask gate",
              options: [{ label: "Continue" }],
              multi: false,
            }],
          },
        }],
      }],
    },
    { withAsk: true },
    async (harness) => {
      const ownerId = "sdk-contract-active-cancel-owner";
      const events = [];
      const emitter = harness.session.getWorkflowGateEmitter();
      const ticket = harness.adapter.sendOwned(
        ownerId,
        { type: "prompt", message: "cancel an acknowledged pending Ask gate" },
        (event) => events.push(event),
        5_000
      );
      const run = observe(ticket.result);
      await waitFor(
        () => events.filter((event) => event?.type === "gate_request").length === 1,
        "ACTIVE_CANCEL_ASK_GATE_NOT_EMITTED"
      );
      const gate = events.find((event) => event?.type === "gate_request");
      requireCondition(
        emitter.listPendingGates().some((pending) => pending.gate_id === gate.gateId),
        "ACTIVE_CANCEL_REAL_ASK_NOT_PENDING"
      );
      requireCondition(
        harness.adapter.presentGate(ownerId, gate.gateId, gate.presentationId, "active-cancel-presentation"),
        "ACTIVE_CANCEL_PRESENTATION_NOT_ACKNOWLEDGED"
      );
      requireCondition(run.status === "pending" && ticket.phase === "active", "ACTIVE_CANCEL_OWNER_NOT_ACTIVE");
      const adapterGateRelease = harness.adapter.gateUnsubscribe;
      requireCondition(
        [...harness.subscriptions].some(
          (subscription) => subscription.kind === "gate" && subscription.release === adapterGateRelease
        ),
        "ACTIVE_CANCEL_EXACT_LISTENER_NOT_REGISTERED"
      );
      // This is the installed public cancellation API, not daemon wire cancel:
      // cancellation_pending acknowledges intent only and never proves terminal.
      // Do not pass timeoutMs: SDK force-recovery is a different surface from
      // an honest standalone abort unwind of this real pending Ask.
      const cancellation = observe(harness.session.abort({ cause: "user_interrupt" }));
      let boundedOwnedPromptSettled = true;
      try {
        await withDeadline(run.settled, 250, "ACTIVE_CANCEL_OWNED_PROMPT_BOUND_EXPIRED");
      } catch (error) {
        if (!(error instanceof ProbeError) || error.code !== "ACTIVE_CANCEL_OWNED_PROMPT_BOUND_EXPIRED") throw error;
        boundedOwnedPromptSettled = false;
      }
      const beforeLateAnswer = {
        ownedPromptStatus: run.status,
        ownerTicketPhase: ticket.phase,
        publicAbortStatus: cancellation.status,
        underlyingTerminalCount: terminalEvents(harness.events).length,
        sdkGateStillPending: emitter.listPendingGates().some((pending) => pending.gate_id === gate.gateId),
        adapterGateStillExposed: harness.adapter.pendingGates.has(gate.gateId),
      };
      const lateAnswer = await withDeadline(
        harness.adapter.answerGate(ownerId, gate.gateId, gate.presentationId, "Continue"),
        STEP_TIMEOUT_MS,
        "ACTIVE_CANCEL_LATE_ANSWER_DID_NOT_SETTLE"
      );
      await withDeadline(
        Promise.all([run.settled, cancellation.settled]),
        STEP_TIMEOUT_MS,
        "ACTIVE_CANCEL_UNWIND_DID_NOT_SETTLE_AFTER_LATE_ANSWER"
      );
      const duplicateAnswer = await harness.adapter.answerGate(ownerId, gate.gateId, gate.presentationId, "Continue");
      requireCondition(duplicateAnswer?.ok === false, "ACTIVE_CANCEL_DUPLICATE_ANSWER_ACCEPTED");
      let cancellationMismatch;
      try {
      requireCondition(
        run.status === "rejected" && run.failureCode === "aborted" &&
          ticket.phase === "terminal" && cancellation.status === "fulfilled" &&
          terminalEvents(harness.events).length === 1 &&
          terminalEvents(harness.events)[0].stopReason === "cancelled",
        "ACTIVE_CANCEL_REAL_TERMINAL_NOT_OBSERVED",
        {
          boundedOwnedPromptSettled,
          beforeLateAnswer,
          ownedPromptStatus: run.status,
          ownedPromptFailureCode: run.failureCode,
          ownerTicketPhase: ticket.phase,
          publicAbortStatus: cancellation.status,
          underlyingTerminalCount: terminalEvents(harness.events).length,
          underlyingTerminalStopReasons: terminalEvents(harness.events).map(
            (event) => observedFailureCode({ code: event.stopReason })
          ),
          underlyingAssistantStopReasons: terminalEvents(harness.events).map((event) => {
            const assistant = Array.isArray(event.messages)
              ? event.messages.filter((message) => message?.role === "assistant").at(-1)
              : undefined;
            return observedFailureCode({ code: assistant?.stopReason });
          }),
          lateAnswerAccepted: lateAnswer?.ok === true,
          duplicateAnswerRefused: duplicateAnswer?.ok === false,
          providerCalls: harness.mockModels.get("primary").calls.length,
          continuationProviderCalls: Math.max(0, harness.mockModels.get("primary").calls.length - 1),
          sdkPendingGateCount: emitter.listPendingGates().length,
          adapterPendingGateCount: harness.adapter.pendingGates.size,
        }
      );
      } catch (error) {
        cancellationMismatch = error;
      }
      const secondaryFailures = [];
      const checkAfterCancellation = async (operation, check) => {
        try {
          await check();
        } catch (error) {
          secondaryFailures.push({ operation, code: failureCode(error, "ACTIVE_CANCEL_SECONDARY_FAILURE") });
        }
      };
      await checkAfterCancellation("active-cancel-provider-validation", () => {
      requireCondition(harness.mockModels.get("primary").calls.length === 1, "ACTIVE_CANCEL_CONTINUATION_PROVIDER_RAN");
      });
      const afterLateAnswer = {
        ownedPromptStatus: run.status,
        ownedPromptFailureCode: run.failureCode,
        ownerTicketPhase: ticket.phase,
        publicAbortStatus: cancellation.status,
        underlyingTerminalCount: terminalEvents(harness.events).length,
        underlyingTerminalStopReason: terminalEvents(harness.events)[0]?.stopReason,
        lateAnswerAccepted: lateAnswer?.ok === true,
        duplicateAnswerRefused: true,
        continuationProviderCalls: 0,
      };
      await checkAfterCancellation("active-cancel-adapter-teardown", () =>
        withDeadline(harness.adapter.dispose(), STEP_TIMEOUT_MS, "ACTIVE_CANCEL_TEARDOWN_DID_NOT_SETTLE")
      );
      await checkAfterCancellation("active-cancel-listener-validation", () => {
      requireCondition(
        ![...harness.subscriptions].some((subscription) => subscription.release === adapterGateRelease) &&
          harness.subscriptions.size === 1 &&
          [...harness.subscriptions].every((subscription) => subscription.kind === "session"),
        "ACTIVE_CANCEL_TEARDOWN_LISTENER_RETAINED"
      );
      });
      await checkAfterCancellation("active-cancel-ownership-validation", () => {
      requireCondition(
        harness.adapter.pendingGates.size === 0 && emitter.listPendingGates().length === 0 &&
          harness.adapter.deferredGateCandidate === undefined && harness.adapter.activeGateRuns.length === 0 &&
          harness.adapter.inFlightGateAnswers.size === 0 && harness.adapter.adapterWaiterCancellations.size === 0 &&
          harness.adapter.ownedQueueTickets.size === 0 && !harness.adapter.isBusy(),
        "ACTIVE_CANCEL_TEARDOWN_OWNERSHIP_RETAINED"
      );
      });
      await checkAfterCancellation("active-cancel-resource-validation", () => {
      requireCondition(
        harness.calls.sessionDispose === 1 && harness.calls.managerClose === 1 &&
          harness.calls.registryDispose === 0 && harness.calls.providerRelease === 0 &&
          harness.calls.authClose === 0 && harness.calls.settingsClose === 0,
        "ACTIVE_CANCEL_TEARDOWN_RESOURCE_OWNERSHIP_WRONG"
      );
      });
      await checkAfterCancellation("active-cancel-terminal-stability", () => {
        requireCondition(
          terminalEvents(harness.events).length === 1 &&
            terminalEvents(harness.events)[0].stopReason === "cancelled" &&
            harness.mockModels.get("primary").calls.length === 1,
          "ACTIVE_CANCEL_TERMINAL_OR_PROVIDER_CHANGED_DURING_TEARDOWN"
        );
      });
      const teardownState = {
        phase: "adapter-teardown-before-fixture-close",
        calls: { ...harness.calls },
        subscriptionsRemaining: harness.subscriptions.size,
        exactAdapterListenerRemaining: [...harness.subscriptions].some((subscription) => subscription.release === adapterGateRelease),
        sdkPendingGateCount: emitter.listPendingGates().length,
        adapterPendingGateCount: harness.adapter.pendingGates.size,
        deferredGateRemaining: harness.adapter.deferredGateCandidate !== undefined,
        activeGateRunCount: harness.adapter.activeGateRuns.length,
        inFlightGateAnswerCount: harness.adapter.inFlightGateAnswers.size,
        adapterWaiterCount: harness.adapter.adapterWaiterCancellations.size,
        ownedQueueTicketCount: harness.adapter.ownedQueueTickets.size,
        adapterBusy: harness.adapter.isBusy(),
      };
      if (cancellationMismatch) {
        cancellationMismatch.state.teardown = teardownState;
        cancellationMismatch.secondaryFailures = secondaryFailures;
        throw cancellationMismatch;
      }
      if (secondaryFailures.length > 0) {
        const error = new ProbeError(secondaryFailures[0].code, { teardown: teardownState });
        error.secondaryFailures = secondaryFailures.slice(1);
        throw error;
      }
      activeCancelDiagnostic = {
        boundedOwnedPromptSettled,
        beforeLateAnswer,
        afterLateAnswer,
        underlyingTerminalStopReasons: terminalEvents(harness.events).map(
          (event) => observedFailureCode({ code: event.stopReason })
        ),
        underlyingAssistantStopReasons: terminalEvents(harness.events).map((event) => {
          const assistant = Array.isArray(event.messages)
            ? event.messages.filter((message) => message?.role === "assistant").at(-1)
            : undefined;
          return observedFailureCode({ code: assistant?.stopReason });
        }),
        providerCalls: harness.mockModels.get("primary").calls.length,
        continuationProviderCalls: Math.max(0, harness.mockModels.get("primary").calls.length - 1),
        teardown: teardownState,
        fabricatedTerminalUsed: false,
      };
      return {
        evidenceKind: "installed-public-SDK-Ask-with-credentialless-mock-provider",
        cancellationSurface: "AgentSession.abort-user_interrupt",
        wireCancelAck: "cancellation_pending-is-nonterminal-not-SDK-abort",
        exactPresentationAcknowledged: true,
        settleBoundMs: 250,
        boundedOwnedPromptSettled,
        status: boundedOwnedPromptSettled ? "bounded-settle-observed" : "not-qualified-pending-Ask-requires-late-answer",
        beforeLateAnswer,
        afterLateAnswer,
        pendingAndDeferredRetiredAtTeardown: true,
        exactAdapterListenerRetiredAtTeardown: true,
        sessionDisposeCalls: harness.calls.sessionDispose,
        managerCloseCalls: harness.calls.managerClose,
        fixtureResourcesOpenUntilOwnerTeardown: true,
        fabricatedTerminalUsed: false,
      };
    }
  );
}

async function decisionGateLimitation() {
  const packagePath = join(installedSdkRoot, "package.json");
  const modesIndexPath = join(
    installedSdkRoot,
    "src",
    "modes",
    "index.ts"
  );
  const rootIndexPath = join(
    installedSdkRoot,
    "src",
    "index.ts"
  );
  const [packageJson, modesIndex, rootIndex, sdkIndex, sdkSession] = await Promise.all([
    readFile(packagePath, "utf8").then(JSON.parse),
    readFile(modesIndexPath, "utf8"),
    readFile(rootIndexPath, "utf8"),
    readFile(join(installedSdkRoot, "src", "sdk", "index.ts"), "utf8"),
    readFile(join(installedSdkRoot, "src", "sdk", "session.ts"), "utf8"),
  ]);
  const exportKeys = Object.keys(packageJson.exports ?? {});
  const explicitDecisionBuilderExport = exportKeys.some((key) =>
    /(?:approval-gate|execution-gate)/.test(key)
  );
  const internalWireBlocked = packageJson.exports?.["./modes/shared/agent-wire/*"] === null;
  const rootModesReexportsBuilders = /\b(?:approvalGate|executionGate)\b/.test(
    `${rootIndex}\n${modesIndex}\n${sdkIndex}\n${sdkSession}`
  );
  requireCondition(
    internalWireBlocked && !explicitDecisionBuilderExport && !rootModesReexportsBuilders,
    "DECISION_GATE_PUBLIC_EXPORT_ASSUMPTION_CHANGED"
  );
  return {
    status: "blocked",
    blockedCase: "structured_decision_denial",
    code: DECISION_GATE_CODE,
    internalWireSubpathsBlocked: true,
    fabricatedSchemaUsed: false,
  };
}

async function readExpectedDeclaration(artifact, segments) {
  try {
    return await readFile(join(installedSdkRoot, ...segments), "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    throw new ProbeError("MISSING_DECLARED_PACKAGE_ARTIFACT", {
      declaredArtifact: artifact,
      operation: "expected-declaration-read",
      filesystemCode: "ENOENT",
    });
  }
}

async function queuedControlOwnershipQualification(sdkPackage, scenarios) {
  const [agentSessionTypes, extensionTypes, sessionRuntimeSource, agentSessionSource, sdkSource, sdkTypes] =
    await Promise.all([
      readExpectedDeclaration(
        "agent-session-types",
        ["dist", "types", "session", "agent-session.d.ts"]
      ),
      readExpectedDeclaration(
        "extension-types",
        ["dist", "types", "extensibility", "extensions", "types.d.ts"]
      ),
      readFile(
        join(installedSdkRoot, "src", "sdk", "host", "session-runtime.ts"),
        "utf8"
      ),
      readFile(
        join(installedSdkRoot, "src", "session", "agent-session.ts"),
        "utf8"
      ),
      readFile(join(installedSdkRoot, "src", "sdk", "index.ts"), "utf8"),
      readExpectedDeclaration("canonical-sdk-types", ["dist", "types", "sdk", "index.d.ts"]),
    ]);

  const sendUserMessageDeclaresQueuedAtDispatch =
    agentSessionTypes.includes("queuedAtDispatch?: boolean;");
  const sendUserMessageDeclaresPromotionHook =
    agentSessionTypes.includes("onQueuedPromoted?: (promotion:");
  const queuedAtDispatchMarkedInternal = extensionTypes.includes(
    "Internal SDK signal preserving a busy dispatch across async admission fences."
  );
  const sdkHostConsumesPromotionHook =
    sessionRuntimeSource.includes("onQueuedPromoted: (promotion?:") &&
    sessionRuntimeSource.includes("queuedAtDispatch,");
  const publicSteerHasNoPromotionReceipt = agentSessionTypes.includes(
    "steer(text: string, images?: ImageContent[]): Promise<void>;"
  );
  const publicFollowUpHasNoPromotionReceipt = agentSessionTypes.includes(
    'followUp(text: string, images?: ImageContent[], options?: Pick<PromptOptions, "followUpQueuePolicy">): Promise<void>;'
  );
  const publicQueueEntryIsTextOnly =
    /export interface QueuedMessageEditEntry\s*\{\s*id: string;\s*text: string;\s*mode: QueuedMessageEditMode;\s*label: string;\s*\}/.test(
      agentSessionTypes
    );
  const sdkRunCapabilitySubpathBlocked =
    sdkPackage.exports?.["./session/sdk-run-capability"] === null;
  const upstream5371FixMarkerObserved = agentSessionSource.includes(
    "#scheduleNonAdmittedQueuedContinuation"
  );
  const publicTrackedSubmissionDeclared =
    agentSessionTypes.includes("export interface QueuedInputSubmission") &&
    agentSessionTypes.includes("submitUserMessage(content:") &&
    agentSessionTypes.includes("options: TrackedSendUserMessageOptions): Promise<QueuedInputSubmission>;") &&
    agentSessionSource.includes("async submitUserMessage(") &&
    typeof AgentSession.prototype.submitUserMessage === "function";
  const publicTrackedLifecycleDeclared = [
    "readonly submissionId: string;",
    "readonly admitted: Promise<QueuedInputAdmission>;",
    "readonly execution: Promise<QueuedInputExecution>;",
    "readonly terminal: Promise<QueuedInputTerminal>;",
    "readonly cancel: () => boolean;",
    "trackSubmission: true;",
  ].every((declaration) => agentSessionTypes.includes(declaration));
  const canonicalTrackedTypesExported = [
    "QueuedInputSubmission",
    "QueuedInputAdmission",
    "QueuedInputExecution",
    "QueuedInputTerminal",
    "TrackedSendUserMessageOptions",
  ].every((name) => sdkSource.includes(name) && sdkTypes.includes(name));

  requireCondition(
    sendUserMessageDeclaresQueuedAtDispatch &&
      sendUserMessageDeclaresPromotionHook &&
      queuedAtDispatchMarkedInternal &&
      sdkHostConsumesPromotionHook &&
      publicSteerHasNoPromotionReceipt &&
      publicFollowUpHasNoPromotionReceipt &&
      publicQueueEntryIsTextOnly &&
      sdkRunCapabilitySubpathBlocked &&
      upstream5371FixMarkerObserved &&
      publicTrackedSubmissionDeclared &&
      publicTrackedLifecycleDeclared &&
      canonicalTrackedTypesExported,
    "QUEUED_CONTROL_CONTRACT_EVIDENCE_CHANGED"
  );
  requireCondition(
    scenarios.trackedControls.status === "qualified" && scenarios.trackedControlFailure.owningFailureObserved &&
      scenarios.lateFollowUp.actualSuccessorProviderInvoked && scenarios.lateFollowUp.executionDisposition === "promoted-to-run" &&
      scenarios.lateSteer.actualSuccessorProviderInvoked && scenarios.lateSteer.executionDisposition === "promoted-to-run" &&
      scenarios.joinedAsk.status === "qualified" && scenarios.joinedAsk.executionDisposition === "joined-current-run" &&
      scenarios.joinedAsk.exactSharedPublicTerminalAndHandleScope,
    "TRACKED_CONTROL_RUNTIME_QUALIFICATION_MISSING"
  );

  return {
    status: "qualified",
    affectedAdapterPath: "SdkSession.send-sendOwned-public-tracked-submissions",
    sendUserMessageHooksStructurallyDeclared: true,
    queuedAtDispatchClassification: "internal-sdk-signal",
    onQueuedPromotedClassification: "sdk-host-ownership-correlation",
    legacySteerFollowUpReturnLifecycleReceipt: false,
    editableQueueEntryCarriesExecutionScope: false,
    sdkRunCapabilitySubpathBlocked: true,
    upstream5371FixMarkerObserved: true,
    publicTrackedSubmissionDeclared: true,
    publicTrackedLifecycleDeclared: true,
    canonicalTrackedTypesExported: true,
    trackedSubmissionIntegrated: true,
    trackedSubmissionBehaviorallyQualified: true,
    joinedGateExactOwnerAndPresentationQualified: true,
    promotedGateExactOwnerAndPresentationQualified: false,
    successfulScenarioEvidence: Object.keys(scenarios),
    unsupportedFallbackUsed: false,
    publicContractRequestIssue: 5429,
  };
}

async function probeCanonicalImports(sdkPackage) {
  const sdk = await import("@gajae-code/coding-agent/sdk");
  requireCondition(typeof sdk.createAgentSession === "function", "CANONICAL_SESSION_FACTORY_MISSING");
  requireCondition(sdk.Settings === Settings, "CANONICAL_SETTINGS_EXPORT_MISMATCH");
  requireCondition(
    typeof sdk.host === "object" && sdk.host !== null &&
      typeof sdk.lifecycle === "object" && sdk.lifecycle !== null,
    "CANONICAL_PUBLIC_NAMESPACES_MISSING"
  );
  const blockedSubpaths = ["./sdk/broker", "./sdk/client", "./sdk/models"];
  for (const subpath of blockedSubpaths) {
    requireCondition(sdkPackage.exports?.[subpath] === null, "PRIVATE_SDK_EXPORT_BOUNDARY_CHANGED");
    let rejectedByExportMap = false;
    try {
      await import(`@gajae-code/coding-agent/${subpath.slice(2)}`);
    } catch (error) {
      // Bun reports null-exported subpaths as ERR_MODULE_NOT_FOUND. The
      // successful canonical import and exact null-map check above distinguish
      // this refusal from an absent SDK package.
      rejectedByExportMap =
        error?.code === "ERR_PACKAGE_PATH_NOT_EXPORTED" ||
        (process.versions.bun !== undefined &&
          error?.code === "ERR_MODULE_NOT_FOUND" &&
          error?.name === "ResolveMessage");
    }
    requireCondition(rejectedByExportMap, "PRIVATE_SDK_IMPORT_NOT_REJECTED_BY_EXPORT_MAP");
  }
  return {
    canonicalSdkImported: true,
    createAgentSessionExported: true,
    settingsExportMatches: true,
    publicNamespacesExported: ["host", "lifecycle"],
    privateSubpathsRejected: blockedSubpaths,
  };
}

async function runProbe(ownerRoot) {
  const [sdkPackage, daemonPackage] = await Promise.all([
    readFile(join(installedSdkRoot, "package.json"), "utf8").then(JSON.parse),
    readFile(join(repoRoot, "daemon", "package.json"), "utf8").then(JSON.parse),
  ]);
  requireCondition(sdkPackage.version === EXPECTED_SDK_VERSION, "SDK_VERSION_MISMATCH");
  requireCondition(
    daemonPackage.dependencies?.["@gajae-code/coding-agent"] === EXPECTED_SDK_VERSION,
    "DAEMON_SDK_PIN_MISMATCH"
  );

  [
    { Agent },
    { createMockModel },
    { AgentSession },
    { SessionManager },
    { Settings },
    { AuthStorage },
    { ModelRegistry, kNoAuth },
    { AskTool },
    { closeModelCache },
    { SdkSession },
  ] = await Promise.all([
    import("@gajae-code/agent-core"),
    import("@gajae-code/ai/providers/mock"),
    import("@gajae-code/coding-agent/session/agent-session"),
    import("@gajae-code/coding-agent/session/session-manager"),
    import("@gajae-code/coding-agent/config/settings"),
    import("@gajae-code/coding-agent/session/auth-storage"),
    import("@gajae-code/coding-agent/config/model-registry"),
    import("@gajae-code/coding-agent/tools/ask"),
    import("@gajae-code/ai/model-cache"),
    import("../src/sdk-session.js"),
  ]);

  const completed = async (name, probe) => {
    const result = await probe();
    completedCells[name] = boundedDiagnosticState(result);
    return result;
  };
  const canonicalImports = await completed("canonicalImports", () => probeCanonicalImports(sdkPackage));
  const gates = await completed("gates", () => probeGates(ownerRoot));
  const failureTerminal = await completed("failureTerminal", () => probeFailureTerminal(ownerRoot));
  const disposal = await completed("disposal", () => probeDisposeWithoutTerminal(ownerRoot));
  const pendingAskDisposal = await completed("pendingAskDisposal", () => probePendingAskDisposal(ownerRoot));
  const pendingAskActiveCancel = await completed("pendingAskActiveCancel", () => probePendingAskActiveCancel(ownerRoot));
  const trackedControls = await completed("trackedControls", () => probeTrackedControls(ownerRoot));
  const trackedControlFailure = await completed("trackedControlFailure", () => probeTrackedControls(ownerRoot, true));
  const lateFollowUp = await completed("lateFollowUp", () => probeLateControl(ownerRoot, "followUp"));
  const lateSteer = await completed("lateSteer", () => probeLateControl(ownerRoot, "steer"));
  const promotedGateOverlap = await completed("promotedGateOverlap", () => probeLateControl(ownerRoot, "followUp", { overlapGate: true }));
  const joinedAsk = await completed("joinedAsk", () => probeJoinedAsk(ownerRoot));
  const decisionGate = await completed("decisionGate", () => decisionGateLimitation());
  const queuedControlOwnership =
    await completed("queuedControlOwnership", () => queuedControlOwnershipQualification(sdkPackage, {
      trackedControls, trackedControlFailure, lateFollowUp, lateSteer, joinedAsk,
    }));
  requireCondition(networkAttempts === 0, "NETWORK_ACCESS_ATTEMPTED");
  const harnessNames = ["workflow-gates", "failure-terminal", "dispose-without-terminal", "pending-ask-disposal",
    "pending-ask-active-cancel", "tracked-control-sequential", "tracked-control-failure", "late-follow-up-continuation",
    "late-steer-rearm", "late-follow-up-gate-overlap", "joined-steer-ask"];
  requireCondition(harnessCleanupOutcomes.length === harnessNames.length &&
    harnessCleanupOutcomes.every((outcome, index) => outcome.stage === harnessNames[index]),
    "CLEANUP_OUTCOME_COUNT_OR_NAME_WRONG");
  requireCondition(
    harnessCleanupOutcomes.every(
      (outcome) => outcome.failures.length === 0 && outcome.completed.length === 8 && outcome.ownedScratchRemoved === true
    ),
    "HARNESS_CLEANUP_INCOMPLETE"
  );

  return {
    sdkVersionExpected: EXPECTED_SDK_VERSION,
    sdkVersionObserved: sdkPackage.version,
    daemonDependencyVersion: daemonPackage.dependencies["@gajae-code/coding-agent"],
    upgradeAssessment: {
      verdict: "PASS",
      oracleStatus: "completed",
      liveControls: "public-tracked-submissions-behaviorally-qualified",
      limitationCodes: [DECISION_GATE_CODE, promotedGateOverlap.code],
    },
    historicalProvenance: {
      oracleOriginSdkVersion: HISTORICAL_SDK_VERSION,
      originalReasonCode:
        "SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
      upstreamIssue: 5351,
      upstreamFixPullRequest: 5371,
      upstreamFixBranch: "dev",
      upstreamFixMarkerPresentInObservedVersion: true,
      continuationBehaviorQualifiedByOracle: lateFollowUp.actualSuccessorProviderInvoked,
    },
    environment: {
      credentialVariableCount: Object.keys(process.env).filter((key) =>
        /(?:API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|PASSWORD|AUTHORIZATION|COOKIE|CREDENTIAL|BROKER|OAUTH)/i.test(
          key
        )
      ).length,
      networkAttempts,
      settingsAndStateOwnedByFixture: true,
    },
    cleanup: {
      harnessCount: harnessCleanupOutcomes.length,
      harnessNames: harnessCleanupOutcomes.map((outcome) => outcome.stage),
      sdkResourcesClosed: true,
      modelCacheStates: harnessCleanupOutcomes.map((outcome) => outcome.modelCacheState),
      ownedScratchRemoved: harnessCleanupOutcomes.map((outcome) => outcome.ownedScratchRemoved),
      authStorageBacking: "owned-file",
      resourceReleaseCalls: harnessCleanupOutcomes.map((outcome) => outcome.calls),
      subscriptionsRemaining: harnessCleanupOutcomes.map((outcome) => outcome.subscriptionsRemaining),
      cleanupOrder: harnessCleanupOutcomes[0].completed,
      ownedScratchRemoval: {
        owner: "fixture",
        afterPublicClose: true,
        beforeChildExit: true,
        attemptsPerHarness: 1,
        forcedGcUsed: false,
        delayedRetryUsed: false,
      },
      wrapperRootRemoval: {
        owner: "parent-wrapper",
        childAttempted: false,
        mustRunAfterChildExit: true,
      },
    },
    canonicalImports,
    trackedControls,
    trackedControlFailure,
    lateFollowUp,
    lateSteer,
    promotedGateOverlap,
    gates,
    joinedAsk,
    failureTerminal,
    disposal,
    pendingAskDisposal,
    pendingAskActiveCancel,
    decisionGate,
    queuedControlOwnership,
    limitations: {
      lateFollowUpAutoContinuation: {
        status: lateFollowUp.status,
        boundary: lateFollowUp.boundary,
        actualSuccessorProviderInvoked: lateFollowUp.actualSuccessorProviderInvoked,
      },
      successorGateCompletion: {
        status: "completed-response-loss-qualified-with-public-SDK-mock-provider",
        code: "ACTUAL_COMPLETED_GATE_RESPONSE_LOSS_RECONCILED",
        excludedCase: "accepted-incomplete-predecessor",
        observedEvidence: "exact-response lookupCompletedResolution.kind=completed",
      },
      lateSteerRearm: {
        status: lateSteer.status,
        boundary: lateSteer.boundary,
        actualSuccessorProviderInvoked: lateSteer.actualSuccessorProviderInvoked,
      },
      joinedSteerGate: {
        status: joinedAsk.status,
        positiveOwnerPresentationQualification: true,
        executionDisposition: joinedAsk.executionDisposition,
        gateOwner: "original-logical-run-owner-not-joined-submission",
        actualSharedPublicTerminalAndHandleScope: joinedAsk.exactSharedPublicTerminalAndHandleScope,
      },
      promotedFollowUpGate: {
        status: "unavailable-public-scope-correlation",
        code: promotedGateOverlap.code,
        positiveOwnerPresentationQualification: promotedGateOverlap.promotedGateExactOwnerAndPresentation,
        negativeOverlapRefusalQualified: promotedGateOverlap.status === "bounded-refusal-qualified",
        reason: "public-gate-runtime_turn_id-has-no-public-attempt-scope-mapping",
        publicTerminalBarrier: "live-prompts-must-unwind-before-AgentSession-agent_end-publication",
        delayedHandleCandidate: "unqualified-return-delay-does-not-release-SDK-live-prompt-barrier",
      },
      excludedCases: ["structured-decision-denial-builders-not-public", "accepted-incomplete-predecessor-gate",
        "global-cross-mode-FIFO", "real-provider-network-or-credentials", "positive-promoted-overlap-gate-binding"],
    },
  };
}

let wroteReceipt = false;
function writeReceipt(receipt) {
  if (wroteReceipt) return;
  wroteReceipt = true;
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
}

const hardTimer = setTimeout(() => {
  writeReceipt({
    schema: RECEIPT_SCHEMA,
    ok: false,
    code: "HARD_TIMEOUT",
    primaryFailure: { stage: "probe", code: "HARD_TIMEOUT" },
    cleanupFailures: [],
  });
  process.exit(124);
}, HARD_TIMEOUT_MS);
hardTimer.unref?.();

const ownerRoot = process.env.SDK_CONTRACT_ROOT;
const credentialVariableCount = Object.keys(process.env).filter((key) =>
  /(?:API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|PASSWORD|AUTHORIZATION|COOKIE|CREDENTIAL|BROKER|OAUTH)/i.test(
    key
  )
).length;
const guardedFetch = (..._args) => {
  networkAttempts += 1;
  return Promise.reject(new ProbeError("NETWORK_ACCESS_ATTEMPTED"));
};
guardedFetch.preconnect = (..._args) => {
  networkAttempts += 1;
  throw new ProbeError("NETWORK_PRECONNECT_ATTEMPTED");
};
globalThis.fetch = guardedFetch;

try {
  requireCondition(typeof ownerRoot === "string" && ownerRoot.length > 0, "OWNER_ROOT_MISSING");
  requireCondition(credentialVariableCount === 0, "CREDENTIAL_ENVIRONMENT_NOT_EMPTY");
  await mkdir(ownerRoot, { recursive: true });
  const data = await runProbe(ownerRoot);
  writeReceipt({ schema: RECEIPT_SCHEMA, ok: true, ...data });
} catch (error) {
  const primaryFailure =
    error instanceof HarnessError
      ? error.primaryFailure
      : {
          stage: "probe",
          code: failureCode(error, "UNEXPECTED_PROBE_FAILURE"),
          ...(error instanceof ProbeError && error.state !== undefined
            ? { state: boundedDiagnosticState(error.state) }
            : {}),
        };
  const cleanupFailures =
    error instanceof HarnessError ? error.cleanupFailures : [];
  writeReceipt({
    schema: RECEIPT_SCHEMA,
    ok: false,
    code: failureCode(error, "UNEXPECTED_PROBE_FAILURE"),
    primaryFailure,
    cleanupFailures,
    partialEvidence: {
      status: "diagnostic-only-not-whole-contract-PASS",
      completedCells,
      ...(completedCells.pendingAskActiveCancel && activeCancelDiagnostic
        ? { pendingAskActiveCancel: boundedDiagnosticState(activeCancelDiagnostic) }
        : {}),
      ...(primaryFailure?.stage === "joined-steer-ask"
        ? { joinedAsk: {
            status: "blocked", blockedCase: "joined-current-run-Ask-owner-presentation",
            code: primaryFailure.code, positiveOwnerPresentationQualification: false,
            observedState: primaryFailure.state, fabricatedReceiptUsed: false,
          } }
        : {}),
    },
    harnessCleanupOutcomes: boundedDiagnosticState(harnessCleanupOutcomes),
    wrapperRootRemoval: {
      owner: "parent-wrapper",
      childAttempted: false,
      mustRunAfterChildExit: true,
    },
    networkAttempts,
  });
  process.exitCode = 1;
}
