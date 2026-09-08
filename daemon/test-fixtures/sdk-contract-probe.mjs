#!/usr/bin/env bun
/*
 * Real installed SDK 0.16.6 contract oracle. It verifies fail-closed live
 * controls while retaining static evidence for upstream #5351/#5371 and #5429.
 * Stdout contains one bounded receipt.
 */
import { mkdir, mkdtemp, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const RECEIPT_SCHEMA = "sdk-contract-probe-v1";
const EXPECTED_SDK_VERSION = "0.16.6";
const HISTORICAL_SDK_VERSION = "0.16.4";
const LATE_FOLLOW_UP_CODE =
  "SDK_0_16_6_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED";
const QUEUED_CONTROL_OWNERSHIP_CODE =
  "SDK_0_16_6_QUEUED_CONTROL_OWNERSHIP_REQUIRES_INTERNAL_HOOKS";
const DECISION_GATE_CODE =
  "SDK_0_16_6_DECISION_GATE_BUILDERS_NOT_PUBLIC";
const STEP_TIMEOUT_MS = 3_000;
const CLEANUP_TIMEOUT_MS = 4_000;
const HARD_TIMEOUT_MS = 20_000;

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
  { withAsk = false, onRawAgentEvent, shouldPause } = {}
) {
  const sequence = ++harnessSequence;
  const ownedRoot = await mkdtemp(join(ownerRoot, `runtime-${sequence}-`));
  const cwd = join(ownedRoot, "workspace");
  const agentDir = join(ownedRoot, "agent");
  await Promise.all([mkdir(cwd, { recursive: true }), mkdir(agentDir, { recursive: true })]);

  const settings = await Settings.loadForScope({ cwd, agentDir });
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

  const authStorage = await AuthStorage.create(":memory:");
  const modelsPath = join(agentDir, "models.json");
  const modelsDbPath = join(agentDir, "models.db");
  const modelRegistry = new ModelRegistry(authStorage, modelsPath, settings, {
    agentDir,
    automaticRefresh: false,
  });
  const provider = `sdk-contract-${sequence}`;
  const api = `sdk-contract-mock-${sequence}`;
  const sourceId = `sdk-contract-probe/${sequence}`;
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
  session.setDisposeTimeoutForTests(3_000);
  const events = [];
  const unsubscribe = session.subscribe((event) => events.push(event));
  adapter = new SdkSession(session, {
    idleTimeoutMs: 6_000,
    hardCapMs: 10_000,
    gateAnswerWindowMs: 6_000,
  });

  return {
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
  };
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
    harness.unsubscribeRawAgent();
    harness.unsubscribe();
  });
  await cleanup("adapter-session-dispose", "ADAPTER_CLEANUP_TIMEOUT", () =>
    harness.adapter.dispose()
  );
  await cleanup("provider-registration-release", "PROVIDER_RELEASE_TIMEOUT", () =>
    harness.modelRegistry.clearSourceRegistrations(harness.sourceId)
  );
  await cleanup("model-registry-dispose", "MODEL_REGISTRY_CLEANUP_TIMEOUT", () =>
    harness.modelRegistry.dispose()
  );
  let modelCacheState = "not-open";
  await cleanup("model-cache-close", "MODEL_CACHE_CLEANUP_TIMEOUT", () => {
    if (closeModelCache(harness.modelsDbPath)) modelCacheState = "closed";
  });
  await cleanup("auth-storage-close", "AUTH_STORAGE_CLEANUP_TIMEOUT", () =>
    harness.authStorage.close()
  );
  await cleanup("settings-close", "SETTINGS_CLEANUP_TIMEOUT", () =>
    harness.settings.close()
  );

  const outcome = {
    completed,
    failures,
    modelCacheState,
  };
  harnessCleanupOutcomes.push(outcome);
  return outcome;
}

async function withHarness(stage, ownerRoot, responseSets, options, run) {
  const harness = await createHarness(ownerRoot, responseSets, options);
  let value;
  let primaryFailure;
  try {
    value = await run(harness);
  } catch (error) {
    primaryFailure = {
      stage,
      code: failureCode(error, "UNEXPECTED_SCENARIO_FAILURE"),
      ...(error instanceof ProbeError && error.state !== undefined
        ? { state: boundedDiagnosticState(error.state) }
        : {}),
    };
  }
  const cleanup = await closeHarness(harness);
  if (primaryFailure || cleanup.failures.length > 0) {
    throw new HarnessError(primaryFailure, cleanup.failures);
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
      const unsubscribeGate = emitter.onGateEmitted((gate) => rawGates.push(structuredClone(gate)));
      try {
        const run = observe(
          harness.adapter.send(
            { type: "prompt", message: "exercise real ask gates" },
            (event) => {
              if (event?.type === "gate_request") gateEvents.push(event);
            },
            5_000
          )
        );

        await waitFor(() => gateEvents.length === 1 && rawGates.length === 1, "FIRST_GATE_NOT_EMITTED");
        const selection = await withDeadline(
          harness.adapter.answerGate(gateEvents[0].gateId, "Beta"),
          STEP_TIMEOUT_MS,
          "SELECTION_GATE_ANSWER_TIMEOUT"
        );
        requireCondition(selection?.ok === true, "SELECTION_GATE_REJECTED");

        await waitFor(() => gateEvents.length === 2 && rawGates.length === 2, "SUCCESSOR_GATE_NOT_EMITTED");
        requireCondition(gateEvents[0].gateId !== gateEvents[1].gateId, "SUCCESSOR_GATE_ID_REUSED");
        const invalid = await withDeadline(
          harness.adapter.answerGate(gateEvents[1].gateId, "   "),
          STEP_TIMEOUT_MS,
          "INVALID_CUSTOM_GATE_ANSWER_TIMEOUT"
        );
        requireCondition(invalid?.ok === false, "INVALID_CUSTOM_GATE_ANSWER_ACCEPTED");
        const custom = await withDeadline(
          harness.adapter.answerGate(gateEvents[1].gateId, customAnswer),
          STEP_TIMEOUT_MS,
          "CUSTOM_GATE_ANSWER_TIMEOUT"
        );
        requireCondition(custom?.ok === true, "CUSTOM_GATE_ANSWER_REJECTED");

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
        };
      } finally {
        unsubscribeGate();
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
  const [packageJson, modesIndex, rootIndex] = await Promise.all([
    readFile(packagePath, "utf8").then(JSON.parse),
    readFile(modesIndexPath, "utf8"),
    readFile(rootIndexPath, "utf8"),
  ]);
  const exportKeys = Object.keys(packageJson.exports ?? {});
  const explicitDecisionBuilderExport = exportKeys.some((key) =>
    /(?:approval-gate|execution-gate)/.test(key)
  );
  const internalWireBlocked = packageJson.exports?.["./modes/shared/agent-wire/*"] === null;
  const rootModesReexportsBuilders = /\b(?:approvalGate|executionGate)\b/.test(
    `${rootIndex}\n${modesIndex}`
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

async function queuedControlOwnershipLimitation(sdkPackage) {
  const [agentSessionTypes, extensionTypes, sessionRuntimeSource, agentSessionSource] =
    await Promise.all([
      readFile(
        join(installedSdkRoot, "dist", "types", "session", "agent-session.d.ts"),
        "utf8"
      ),
      readFile(
        join(
          installedSdkRoot,
          "dist",
          "types",
          "extensibility",
          "extensions",
          "types.d.ts"
        ),
        "utf8"
      ),
      readFile(
        join(installedSdkRoot, "src", "sdk", "host", "session-runtime.ts"),
        "utf8"
      ),
      readFile(
        join(installedSdkRoot, "src", "session", "agent-session.ts"),
        "utf8"
      ),
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

  requireCondition(
    sendUserMessageDeclaresQueuedAtDispatch &&
      sendUserMessageDeclaresPromotionHook &&
      queuedAtDispatchMarkedInternal &&
      sdkHostConsumesPromotionHook &&
      publicSteerHasNoPromotionReceipt &&
      publicFollowUpHasNoPromotionReceipt &&
      publicQueueEntryIsTextOnly &&
      sdkRunCapabilitySubpathBlocked &&
      !upstream5371FixMarkerObserved,
    "QUEUED_CONTROL_CONTRACT_EVIDENCE_CHANGED"
  );

  return {
    status: "contained",
    code: QUEUED_CONTROL_OWNERSHIP_CODE,
    affectedAdapterPath: "SdkSession.send rejects live steer/follow_up",
    sendUserMessageHooksStructurallyDeclared: true,
    queuedAtDispatchClassification: "internal-sdk-signal",
    onQueuedPromotedClassification: "sdk-host-ownership-correlation",
    publicSteerFollowUpPromotionReceiptObserved: false,
    publicQueueEntryExecutableIdentityObserved: false,
    sdkRunCapabilitySubpathBlocked: true,
    upstream5371FixMarkerObserved: false,
    unsupportedFallbackUsed: false,
    publicContractRequestIssue: 5429,
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

  const gates = await probeGates(ownerRoot);
  const failureTerminal = await probeFailureTerminal(ownerRoot);
  const disposal = await probeDisposeWithoutTerminal(ownerRoot);
  const liveControlContainment =
    await probeLiveControlContainment(ownerRoot);
  const decisionGate = await decisionGateLimitation();
  const queuedControlOwnership =
    await queuedControlOwnershipLimitation(sdkPackage);
  requireCondition(networkAttempts === 0, "NETWORK_ACCESS_ATTEMPTED");
  requireCondition(harnessCleanupOutcomes.length === 4, "CLEANUP_OUTCOME_COUNT_WRONG");
  requireCondition(
    harnessCleanupOutcomes.every(
      (outcome) => outcome.failures.length === 0 && outcome.completed.length === 7
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
      limitationCodes: [
        LATE_FOLLOW_UP_CODE,
        QUEUED_CONTROL_OWNERSHIP_CODE,
      ],
    },
    historicalProvenance: {
      oracleOriginSdkVersion: HISTORICAL_SDK_VERSION,
      originalReasonCode:
        "SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
      upstreamIssue: 5351,
      upstreamFixPullRequest: 5371,
      upstreamFixBranch: "dev",
      upstreamFixPublishedInObservedVersion: false,
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
      filesystemRemoval: {
        owner: "parent-wrapper",
        childAttempted: false,
        mustRunAfterChildExit: true,
      },
    },
    liveControlContainment,
    gates,
    failureTerminal,
    disposal,
    decisionGate,
    queuedControlOwnership,
    limitations: {
      lateFollowUpAutoContinuation: {
        status: "contained-sdk-gap",
        code: LATE_FOLLOW_UP_CODE,
        boundary: "live controls rejected before SDK queue admission",
        evidence:
          "The published package lacks the upstream continuation marker; the adapter does not enter that queue path.",
      },
      successorGateCompletion: {
        status: "not-exercised",
        code: "COMPLETED_GATE_RECEIPT_NOT_OBSERVED",
        excludedCase: "accepted-incomplete-predecessor",
        requiredEvidence: "lookupCompletedResolution.kind=completed",
      },
      lateSteerRearm: {
        status: "unsupported-fail-closed",
        code: "LATE_STEER_REARM_NOT_OBSERVED",
        excludedCase: "live steer",
        reason:
          "Live controls remain disabled until upstream issue #5429 provides a supported ownership contract.",
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
    filesystemRemoval: {
      owner: "parent-wrapper",
      childAttempted: false,
      mustRunAfterChildExit: true,
    },
    networkAttempts,
  });
  process.exitCode = 1;
}
