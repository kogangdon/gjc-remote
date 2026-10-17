#!/usr/bin/env bun
/*
 * Real installed SDK 0.18.12 contract oracle. It verifies fail-closed live
 * controls without qualifying the new public tracked-submission integration.
 * Stdout contains one bounded receipt.
 */
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const RECEIPT_SCHEMA = "sdk-contract-probe-v1";
const EXPECTED_SDK_VERSION = "0.18.12";
const HISTORICAL_SDK_VERSION = "0.16.4";
const QUEUED_CONTROL_OWNERSHIP_CODE =
  "PUBLIC_TRACKED_SUBMISSION_NOT_INTEGRATED_OR_QUALIFIED";
const DECISION_GATE_CODE =
  "DECISION_GATE_BUILDERS_NOT_PUBLIC";
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
    () => {
      state.status = "fulfilled";
    },
    (error) => {
      state.status = "rejected";
      state.failureCode = observedFailureCode(error);
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
  { withAsk = false, onRawAgentEvent, shouldPause } = {}
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
    gateAnswerWindowMs: 6_000,
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
      ...(error instanceof ProbeError && error.state !== undefined
        ? { state: boundedDiagnosticState(error.state) }
        : {}),
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
async function probeLiveControlContainment(ownerRoot) {
  const releasePrompt = deferred();
  try {
    return await withHarness(
      "live-control-containment",
      ownerRoot,
      {
        primary: [
          async () => {
            await releasePrompt.promise;
            return { content: ["initial complete"] };
          },
        ],
      },
      {},
      async (harness) => {
        harness.releases.push(() => releasePrompt.resolve());
        const prompt = observe(
          harness.adapter.send(
            { type: "prompt", message: "initial" },
            () => {},
            5_000
          )
        );
        await waitFor(
          () => harness.mockModels.get("primary").calls.length === 1,
          "INITIAL_PROVIDER_CALL_MISSING"
        );

        const steer = observe(
          harness.adapter.send(
            { type: "steer", message: "adjust" },
            () => {},
            5_000
          )
        );
        const followUp = observe(
          harness.adapter.send(
            { type: "follow_up", message: "continue" },
            () => {},
            5_000
          )
        );
        await withDeadline(
          Promise.all([steer.settled, followUp.settled]),
          STEP_TIMEOUT_MS,
          "LIVE_CONTROLS_DID_NOT_FAIL_CLOSED"
        );

        requireCondition(
          steer.status === "rejected" &&
            steer.failureCode === "SDK_LIVE_CONTROL_UNSUPPORTED" &&
            followUp.status === "rejected" &&
            followUp.failureCode === "SDK_LIVE_CONTROL_UNSUPPORTED",
          "LIVE_CONTROL_REJECTION_WRONG",
          {
            steerStatus: steer.status,
            steerFailureCode: steer.failureCode,
            followUpStatus: followUp.status,
            followUpFailureCode: followUp.failureCode,
          }
        );
        const queues = harness.agent.snapshotQueues();
        requireCondition(
          queues.steering.length === 0 && queues.followUp.length === 0,
          "LIVE_CONTROL_REACHED_SDK_QUEUE"
        );
        requireCondition(prompt.status === "pending", "ACTIVE_PROMPT_SETTLED_TOO_EARLY");

        releasePrompt.resolve();
        await withDeadline(
          prompt.settled,
          STEP_TIMEOUT_MS,
          "ACTIVE_PROMPT_DID_NOT_SETTLE"
        );
        requireCondition(prompt.status === "fulfilled", "ACTIVE_PROMPT_FAILED");

        return {
          mode: "fail-closed",
          errorCode: "SDK_LIVE_CONTROL_UNSUPPORTED",
          steerStatus: steer.status,
          followUpStatus: followUp.status,
          executableSteeringCount: queues.steering.length,
          executableFollowUpCount: queues.followUp.length,
          promptStatus: prompt.status,
        };
      }
    );
  } finally {
    releasePrompt.resolve();
  }
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

async function queuedControlOwnershipLimitation(sdkPackage) {
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

  return {
    status: "contained",
    code: QUEUED_CONTROL_OWNERSHIP_CODE,
    affectedAdapterPath: "SdkSession.send rejects live steer/follow_up",
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
    trackedSubmissionIntegrated: false,
    trackedSubmissionBehaviorallyQualified: false,
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
  const liveControlContainment =
    await completed("liveControlContainment", () => probeLiveControlContainment(ownerRoot));
  const decisionGate = await completed("decisionGate", () => decisionGateLimitation());
  const queuedControlOwnership =
    await queuedControlOwnershipLimitation(sdkPackage);
  requireCondition(networkAttempts === 0, "NETWORK_ACCESS_ATTEMPTED");
  requireCondition(harnessCleanupOutcomes.length === 6, "CLEANUP_OUTCOME_COUNT_WRONG");
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
      containment: "live-controls-fail-closed",
      limitationCodes: [QUEUED_CONTROL_OWNERSHIP_CODE],
    },
    historicalProvenance: {
      oracleOriginSdkVersion: HISTORICAL_SDK_VERSION,
      originalReasonCode:
        "SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
      upstreamIssue: 5351,
      upstreamFixPullRequest: 5371,
      upstreamFixBranch: "dev",
      upstreamFixMarkerPresentInObservedVersion: true,
      continuationBehaviorQualifiedByOracle: false,
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
    liveControlContainment,
    gates,
    failureTerminal,
    disposal,
    pendingAskDisposal,
    pendingAskActiveCancel,
    decisionGate,
    queuedControlOwnership,
    limitations: {
      lateFollowUpAutoContinuation: {
        status: "not-behaviorally-qualified",
        code: "LATE_FOLLOW_UP_CONTINUATION_NOT_QUALIFIED",
        boundary: "live controls rejected before SDK queue admission",
        evidence:
          "The published package contains the continuation marker; the adapter does not enter that queue path and this oracle does not qualify it.",
      },
      successorGateCompletion: {
        status: "completed-response-loss-qualified-with-public-SDK-mock-provider",
        code: "ACTUAL_COMPLETED_GATE_RESPONSE_LOSS_RECONCILED",
        excludedCase: "accepted-incomplete-predecessor",
        observedEvidence: "exact-response lookupCompletedResolution.kind=completed",
      },
      lateSteerRearm: {
        status: "unsupported-fail-closed",
        code: "LATE_STEER_REARM_NOT_OBSERVED",
        excludedCase: "live steer",
        reason:
          "Public tracked submission is present, but its daemon lifecycle integration and behavior are not qualified by this oracle.",
      },
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
