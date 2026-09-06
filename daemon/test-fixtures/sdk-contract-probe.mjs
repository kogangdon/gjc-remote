#!/usr/bin/env bun
/* Real SDK 0.16.4 contract oracle. Stdout contains one bounded JSON receipt. */
import { AsyncResource } from "node:async_hooks";
import { mkdir, mkdtemp, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const RECEIPT_SCHEMA = "sdk-contract-probe-v1";
const EXPECTED_SDK_VERSION = "0.16.4";
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

function latestUserText(context) {
  for (let index = context.messages.length - 1; index >= 0; index -= 1) {
    const message = context.messages[index];
    if (message?.role !== "user" || !Array.isArray(message.content)) continue;
    return message.content
      .filter((item) => item?.type === "text")
      .map((item) => item.text)
      .join("");
  }
  return undefined;
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

async function probeFollowUps(ownerRoot) {
  const releaseInitial = deferred();
  const releaseQueued = deferred();
  const observedPrompts = [];
  try {
    return await withHarness(
      "follow-ups",
      ownerRoot,
      {
        primary: [
          async (context) => {
            observedPrompts.push(latestUserText(context));
            await releaseInitial.promise;
            return { content: ["initial complete"] };
          },
          (context) => {
            observedPrompts.push(latestUserText(context));
            return { content: ["first follow-up complete"] };
          },
          (context) => {
            observedPrompts.push(latestUserText(context));
            return { content: ["second follow-up complete"] };
          },
        ],
        secondary: [
          async (context) => {
            observedPrompts.push(latestUserText(context));
            await releaseQueued.promise;
            return { content: ["queued prompt complete"] };
          },
        ],
      },
      {},
      async (harness) => {
        const initial = observe(
          harness.adapter.send({ type: "prompt", message: "initial" }, () => {}, 5_000)
        );
        await waitFor(
          () => harness.mockModels.get("primary").calls.length === 1,
          "INITIAL_PROVIDER_CALL_MISSING"
        );

        const first = observe(
          harness.adapter.send({ type: "follow_up", message: "follow-one" }, () => {}, 5_000)
        );
        const second = observe(
          harness.adapter.send({ type: "follow_up", message: "follow-two" }, () => {}, 5_000)
        );
        const modelEvents = [];
        const modelSwitch = observe(
          harness.adapter.send(
            { type: "set_model", provider: harness.provider, modelId: "secondary" },
            (event) => modelEvents.push(event),
            5_000
          )
        );
        const queuedPrompt = observe(
          harness.adapter.send({ type: "prompt", message: "queued-next" }, () => {}, 5_000)
        );

        await waitFor(
          () => harness.agent.snapshotQueues().followUp.length === 2,
          "FOLLOW_UPS_NOT_ADMITTED"
        );
        releaseInitial.resolve();
        await waitFor(
          () => harness.mockModels.get("secondary").calls.length === 1,
          "QUEUED_PROMPT_NOT_STARTED"
        );
        await Bun.sleep(0);

        requireCondition(terminalEvents(harness.events).length === 1, "FOLLOW_UP_TERMINAL_COUNT_WRONG");
        requireCondition(initial.status === "fulfilled", "INITIAL_SEND_NOT_SETTLED");
        requireCondition(first.status === "fulfilled", "FIRST_FOLLOW_UP_NOT_SETTLED");
        requireCondition(second.status === "fulfilled", "SECOND_FOLLOW_UP_NOT_SETTLED");
        requireCondition(modelSwitch.status === "fulfilled", "QUEUED_MODEL_SWITCH_NOT_SETTLED");
        requireCondition(queuedPrompt.status === "pending", "QUEUED_PROMPT_SETTLED_TOO_EARLY");
        requireCondition(
          modelEvents.some(
            (event) =>
              event?.type === "response" &&
              event?.success === true &&
              event?.data?.modelId === "secondary"
          ),
          "MODEL_SWITCH_RESPONSE_MISSING"
        );

        releaseQueued.resolve();
        await withDeadline(
          Promise.all([
            initial.settled,
            first.settled,
            second.settled,
            modelSwitch.settled,
            queuedPrompt.settled,
          ]),
          STEP_TIMEOUT_MS,
          "FOLLOW_UP_SENDS_DID_NOT_SETTLE"
        );
        requireCondition(queuedPrompt.status === "fulfilled", "QUEUED_PROMPT_FAILED");
        requireCondition(terminalEvents(harness.events).length === 2, "TOTAL_TERMINAL_COUNT_WRONG");
        requireCondition(
          JSON.stringify(observedPrompts) ===
            JSON.stringify(["initial", "follow-one", "follow-two", "queued-next"]),
          "PROVIDER_PROMPT_ORDER_WRONG"
        );
        requireCondition(harness.session.model?.id === "secondary", "MODEL_SWITCH_NOT_APPLIED");

        return {
          providerPrompts: observedPrompts,
          sharedRunTerminalCount: 1,
          totalTerminalCount: 2,
          followUpsSettledAtSharedTerminal: true,
          queuedModelSwitchSettled: true,
          queuedPromptWaitedForSharedRun: true,
          finalModelId: harness.session.model.id,
        };
      }
    );
  } finally {
    releaseInitial.resolve();
    releaseQueued.resolve();
  }
}

async function probeSameTextQueueDivergence(ownerRoot) {
  const text = "same-text-control";
  const rawAdmissionRequested = deferred();
  const rawOriginalMessageObserved = deferred();
  const followUpEvents = [];
  let followUp;
  let rawListenerFailure;
  let rawAgentStarts = 0;
  let rawUserMessageStarts = 0;
  let rawTerminalCount = 0;
  let executableMessage;
  let beforeDisplayCleanup;
  let atRawPausedTerminal;

  const onRawAgentEvent = (event, getAdapter, getRuntime) => {
    if (event?.type === "agent_start") {
      rawAgentStarts += 1;
      if (rawAgentStarts !== 1) return;
      const adapter = getAdapter();
      if (!adapter) {
        rawListenerFailure = "SAME_TEXT_ADAPTER_UNAVAILABLE";
        rawAdmissionRequested.resolve();
        return;
      }
      // SdkSession dispatches controls in a promise turn. Submit at the raw
      // agent_start so its real SDK queue entry exists when the immediately
      // following original message_start reaches this pre-AgentSession listener.
      followUp = observe(
        adapter.send(
          { type: "follow_up", message: text },
          (sessionEvent) => followUpEvents.push(sessionEvent),
          5_000
        )
      );
      rawAdmissionRequested.resolve();
      return;
    }

    const rawUserText =
      event?.type === "message_start" && event.message?.role === "user"
        ? latestUserText({ messages: [event.message] })
        : undefined;
    if (rawUserText === text && rawUserMessageStarts === 0) {
      rawUserMessageStarts += 1;
      const runtime = getRuntime();
      const displayEntries = runtime?.session?.getQueuedMessageEntries?.();
      const executable = runtime?.agent?.snapshotQueues?.();
      if (
        !followUp ||
        !Array.isArray(displayEntries) ||
        !Array.isArray(executable?.steering) ||
        !Array.isArray(executable?.followUp) ||
        executable.steering.length !== 0 ||
        executable.followUp.length !== 1
      ) {
        rawListenerFailure = "SAME_TEXT_QUEUE_NOT_READY_BEFORE_DISPLAY_CLEANUP";
      } else {
        executableMessage = executable.followUp[0];
        beforeDisplayCleanup = {
          displayEntries,
          executableFollowUpCount: executable.followUp.length,
          executableRetained:
            executable.followUp.includes(executableMessage) ||
            executable.steering.includes(executableMessage),
          followUpStatus: followUp.status,
        };
      }
      rawOriginalMessageObserved.resolve();
      return;
    }

    if (event?.type === "agent_end") {
      rawTerminalCount += 1;
      if (rawTerminalCount !== 1 || !executableMessage) return;
      const runtime = getRuntime();
      const executable = runtime.agent.snapshotQueues();
      atRawPausedTerminal = {
        stopReason: event.stopReason,
        displayEntries: runtime.session.getQueuedMessageEntries(),
        executableSteeringCount: executable.steering.length,
        executableFollowUpCount: executable.followUp.length,
        executableRetained:
          executable.followUp.includes(executableMessage) ||
          executable.steering.includes(executableMessage),
        followUpStatus: followUp?.status ?? "not-created",
      };
    }
  };

  return withHarness(
    "same-text-queue-divergence",
    ownerRoot,
    { primary: [{ content: ["paused predecessor complete"] }] },
    {
      onRawAgentEvent,
      // Public Agent pause hook: stop at the predecessor boundary before the
      // loop can consume the queued same-text follow-up.
      shouldPause: () => true,
    },
    async (harness) => {
      let afterDisplayCleanup;
      let atPublicPausedTerminal;
      let publicTerminalCount = 0;
      const unsubscribe = harness.session.subscribe((event) => {
        const userText =
          event?.type === "message_start" && event.message?.role === "user"
            ? latestUserText({ messages: [event.message] })
            : undefined;
        if (userText === text && !afterDisplayCleanup && executableMessage) {
          const executable = harness.agent.snapshotQueues();
          afterDisplayCleanup = {
            displayEntries: harness.session.getQueuedMessageEntries(),
            executableFollowUpCount: executable.followUp.length,
            executableRetained:
              executable.followUp.includes(executableMessage) ||
              executable.steering.includes(executableMessage),
            followUpStatus: followUp?.status ?? "not-created",
          };
        }
        if (event?.type === "agent_end") {
          publicTerminalCount += 1;
          if (publicTerminalCount !== 1 || !executableMessage) return;
          const executable = harness.agent.snapshotQueues();
          atPublicPausedTerminal = {
            stopReason: event.stopReason,
            displayEntries: harness.session.getQueuedMessageEntries(),
            executableFollowUpCount: executable.followUp.length,
            executableRetained:
              executable.followUp.includes(executableMessage) ||
              executable.steering.includes(executableMessage),
            followUpStatus: followUp?.status ?? "not-created",
          };
        }
      });

      try {
        const initial = observe(
          harness.adapter.send({ type: "prompt", message: text }, () => {}, 5_000)
        );
        await withDeadline(
          rawAdmissionRequested.promise,
          STEP_TIMEOUT_MS,
          "SAME_TEXT_ADMISSION_NOT_REQUESTED"
        );
        await withDeadline(
          rawOriginalMessageObserved.promise,
          STEP_TIMEOUT_MS,
          "SAME_TEXT_ORIGINAL_MESSAGE_NOT_OBSERVED"
        );
        requireCondition(!rawListenerFailure, rawListenerFailure);
        requireCondition(followUp, "SAME_TEXT_FOLLOW_UP_NOT_CREATED");
        await withDeadline(
          initial.settled,
          STEP_TIMEOUT_MS,
          "SAME_TEXT_PREDECESSOR_DID_NOT_SETTLE"
        );
        await waitFor(
          () => atPublicPausedTerminal !== undefined,
          "SAME_TEXT_PUBLIC_PAUSED_TERMINAL_MISSING"
        );
        await Bun.sleep(0);

        const originalDisplayEntry = beforeDisplayCleanup.displayEntries.find(
          (entry) => entry.text === text
        );
        requireCondition(
          originalDisplayEntry && beforeDisplayCleanup.displayEntries.length === 1,
          "SAME_TEXT_DISPLAY_ENTRY_NOT_CREATED"
        );
        requireCondition(
          JSON.stringify(Object.keys(originalDisplayEntry).sort()) ===
            JSON.stringify(["id", "label", "mode", "text"]) &&
            /^followUp:\d+$/.test(originalDisplayEntry.id) &&
            originalDisplayEntry.mode === "followUp" &&
            originalDisplayEntry.label === "Queued",
          "SAME_TEXT_DISPLAY_ENTRY_SHAPE_WRONG"
        );
        requireCondition(
          beforeDisplayCleanup.executableRetained &&
            beforeDisplayCleanup.executableFollowUpCount === 1 &&
            beforeDisplayCleanup.followUpStatus === "pending",
          "SAME_TEXT_EXECUTABLE_NOT_RETAINED_BEFORE_DISPLAY_CLEANUP"
        );
        requireCondition(
          afterDisplayCleanup &&
            afterDisplayCleanup.displayEntries.length === 0 &&
            afterDisplayCleanup.executableFollowUpCount === 1 &&
            afterDisplayCleanup.executableRetained &&
            afterDisplayCleanup.followUpStatus === "pending",
          "SAME_TEXT_DISPLAY_EXECUTABLE_DIVERGENCE_MISSING"
        );
        requireCondition(
          atRawPausedTerminal?.stopReason === "paused" &&
            atRawPausedTerminal.displayEntries.length === 0 &&
            atRawPausedTerminal.executableSteeringCount === 0 &&
            atRawPausedTerminal.executableFollowUpCount === 1 &&
            atRawPausedTerminal.executableRetained &&
            atRawPausedTerminal.followUpStatus === "pending",
          "SAME_TEXT_RAW_PAUSED_CUTOFF_WRONG"
        );
        requireCondition(
          atPublicPausedTerminal.stopReason === "paused" &&
            atPublicPausedTerminal.displayEntries.length === 0 &&
            atPublicPausedTerminal.executableFollowUpCount === 1 &&
            atPublicPausedTerminal.executableRetained &&
            atPublicPausedTerminal.followUpStatus === "pending",
          "SAME_TEXT_PUBLIC_PAUSED_CUTOFF_WRONG"
        );
        requireCondition(initial.status === "fulfilled", "SAME_TEXT_PREDECESSOR_FAILED");
        requireCondition(
          followUp.status === "pending" &&
            terminalEvents(followUpEvents).length === 1 &&
            harness.mockModels.get("primary").calls.length === 1,
          "SAME_TEXT_CONTROL_FALSELY_COMPLETED"
        );

        const disposal = observe(harness.adapter.dispose());
        await withDeadline(
          Promise.all([disposal.settled, followUp.settled]),
          STEP_TIMEOUT_MS,
          "SAME_TEXT_DISPOSAL_DID_NOT_SETTLE"
        );
        requireCondition(disposal.status === "fulfilled", "SAME_TEXT_DISPOSAL_FAILED");
        requireCondition(
          followUp.status === "rejected" &&
            rawTerminalCount === 1 &&
            publicTerminalCount === 1,
          "SAME_TEXT_DISPOSAL_TERMINALIZED_CONTROL"
        );

        return {
          rawListenerPrecedesAgentSession: true,
          admissionTrigger: "raw-agent-start-before-original-message",
          cleanupTrigger: "original-user-message-start",
          textCollision: true,
          displayEntryShape: {
            idPattern: "followUp:<sequence>",
            mode: originalDisplayEntry.mode,
            label: originalDisplayEntry.label,
          },
          displayEntryPresentBeforeCleanup: true,
          displayEntryCountBeforeCleanup: beforeDisplayCleanup.displayEntries.length,
          displayEntryAbsentAfterCleanup: true,
          displayEntryCountAfterCleanup: afterDisplayCleanup.displayEntries.length,
          exactExecutableIdentityRetainedAfterCleanup: true,
          exactExecutableIdentityRetainedAtPausedTerminal: true,
          executableFollowUpCountAtPausedTerminal:
            atPublicPausedTerminal.executableFollowUpCount,
          predecessorStopReason: "paused",
          followUpPendingAtPredecessorTerminal: true,
          providerCallCountAtCutoff: 1,
          followUpRejectedOnDispose: true,
          rawTerminalCount,
          publicTerminalCount,
        };
      } finally {
        unsubscribe();
      }
    }
  );
}

async function probeNearTerminalQueue(ownerRoot) {
  const followUpText = "near-terminal-follow-up";
  // Constructed outside AgentSession's AsyncLocalStorage admission scope. The
  // raw Agent callback below is synchronous but inherits the prompt's scope;
  // dispatching through this public Node host resource models an independent
  // adapter caller without bypassing any SDK admission API.
  const hostDispatch = new AsyncResource("sdk-contract-host-dispatch");
  const rawInjection = deferred();
  const successorStarted = deferred();
  const releaseSuccessor = deferred();
  const followUpEvents = [];
  let followUp;
  let rawListenerFailure;
  let rawTerminalCount = 0;
  let publicTerminalCount = 0;
  let publicTerminalCountAtAdmission;
  let followUpStatusAfterRawDispatch;
  let followUpFailureCodeAfterRawDispatch;
  let executableMessage;
  let successorUserText;

  const onRawAgentEvent = (event, getAdapter) => {
    if (event?.type !== "agent_end") return;
    rawTerminalCount += 1;
    if (rawTerminalCount !== 1) return;
    const adapter = getAdapter();
    if (!adapter) {
      rawListenerFailure = "RAW_LISTENER_ADAPTER_UNAVAILABLE";
      rawInjection.resolve();
      return;
    }
    publicTerminalCountAtAdmission = publicTerminalCount;
    hostDispatch.runInAsyncScope(() => {
      followUp = observe(
        adapter.send(
          { type: "follow_up", message: followUpText },
          (sessionEvent) => followUpEvents.push(sessionEvent),
          5_000
        )
      );
    });
    rawInjection.resolve();
  };

  try {
    return await withHarness(
      "near-terminal-queue",
      ownerRoot,
      {
        primary: [
          { content: ["predecessor complete"] },
          async (context) => {
            successorUserText = latestUserText(context);
            successorStarted.resolve();
            await releaseSuccessor.promise;
            return { content: ["successor complete"] };
          },
        ],
      },
      { onRawAgentEvent },
      async (harness) => {
        let consumedMessageStarts = 0;
        let predecessorTerminalSnapshot;
        let consumptionSnapshot;
        const admissionState = () => {
          const queues = harness.agent.snapshotQueues();
          return {
            followUpStatus: followUp?.status ?? "not-created",
            followUpFailureCode: followUp?.failureCode ?? "NONE",
            initialStatus: initial?.status ?? "not-created",
            rawTerminalCount,
            publicTerminalCount,
            publicTerminalCountAtAdmission:
              publicTerminalCountAtAdmission ?? -1,
            agentStreaming: harness.agent.state.isStreaming === true,
            executableSteeringCount: queues.steering.length,
            executableFollowUpCount: queues.followUp.length,
            displayQueueCount: harness.session.getQueuedMessageEntries().length,
            primaryProviderCallCount:
              harness.mockModels.get("primary").calls.length,
            consumedMessageStarts,
          };
        };
        const unsubscribe = harness.session.subscribe((event) => {
          if (
            event?.type === "message_start" &&
            latestUserText({ messages: [event.message] }) === followUpText
          ) {
            consumedMessageStarts += 1;
            consumptionSnapshot = {
              entries: harness.session.getQueuedMessageEntries(),
              followUpStatus: followUp?.status ?? "not-created",
            };
          }
          if (event?.type === "agent_end") {
            publicTerminalCount += 1;
            if (!predecessorTerminalSnapshot) {
              predecessorTerminalSnapshot = {
                entries: harness.session.getQueuedMessageEntries(),
                followUpStatus: followUp?.status ?? "not-created",
                consumedMessageStarts,
              };
            }
          }
        });

        let initial;
        try {
          initial = observe(
            harness.adapter.send(
              { type: "prompt", message: "finish before queued admission" },
              () => {},
              5_000
            )
          );
          await withDeadline(
            rawInjection.promise,
            STEP_TIMEOUT_MS,
            "RAW_NEAR_TERMINAL_INJECTION_MISSING"
          );
          requireCondition(!rawListenerFailure, rawListenerFailure);
          requireCondition(followUp, "RAW_NEAR_TERMINAL_FOLLOW_UP_MISSING");
          requireCondition(
            publicTerminalCountAtAdmission === 0,
            "NEAR_TERMINAL_ADMISSION_MISSED_RAW_WINDOW",
            admissionState()
          );
          requireCondition(
            followUp.status !== "rejected",
            "NEAR_TERMINAL_ADMISSION_REJECTED",
            admissionState()
          );
          try {
            await waitFor(
              () =>
                followUp.status === "rejected" ||
                harness.agent.snapshotQueues().followUp.length === 1,
              "NEAR_TERMINAL_EXECUTABLE_QUEUE_NOT_OBSERVED"
            );
          } catch {
            throw new ProbeError(
              "NEAR_TERMINAL_EXECUTABLE_QUEUE_NOT_OBSERVED",
              admissionState()
            );
          }
          requireCondition(
            followUp.status !== "rejected",
            "NEAR_TERMINAL_ADMISSION_REJECTED",
            admissionState()
          );
          const queuedAtAdmission = harness.agent.snapshotQueues();
          requireCondition(
            queuedAtAdmission.steering.length === 0 &&
              queuedAtAdmission.followUp.length === 1,
            "NEAR_TERMINAL_EXECUTABLE_QUEUE_SHAPE_WRONG",
            admissionState()
          );
          [executableMessage] = queuedAtAdmission.followUp;
          followUpStatusAfterRawDispatch = followUp.status;
          followUpFailureCodeAfterRawDispatch = followUp.failureCode;
          await withDeadline(
            initial.settled,
            STEP_TIMEOUT_MS,
            "PREDECESSOR_SEND_DID_NOT_SETTLE"
          );
          requireCondition(
            followUp.status !== "rejected",
            "NEAR_TERMINAL_CONTROL_REJECTED_AT_PREDECESSOR",
            admissionState()
          );

          let successorTimer;
          const successorOutcome = await Promise.race([
            successorStarted.promise.then(() => "started"),
            followUp.settled.then(() => "control-settled"),
            harness.session.waitForIdle().then(
              () => "session-idle",
              () => "idle-rejected"
            ),
            new Promise((resolveOutcome) => {
              successorTimer = setTimeout(
                () => resolveOutcome("timed-out"),
                STEP_TIMEOUT_MS
              );
            }),
          ]);
          clearTimeout(successorTimer);
          if (successorOutcome !== "session-idle") {
            throw new ProbeError(
              successorOutcome === "control-settled" &&
                  followUp.status === "rejected"
                ? "NEAR_TERMINAL_CONTROL_REJECTED_BEFORE_SUCCESSOR"
                : successorOutcome === "control-settled"
                  ? "NEAR_TERMINAL_CONTROL_FALSELY_COMPLETED"
                  : successorOutcome === "started"
                    ? "NEAR_TERMINAL_SDK_GAP_BEHAVIOR_CHANGED"
                    : successorOutcome === "idle-rejected"
                      ? "NEAR_TERMINAL_IDLE_BOUNDARY_REJECTED"
                      : "NEAR_TERMINAL_IDLE_BOUNDARY_TIMEOUT",
              admissionState()
            );
          }

          requireCondition(initial.status === "fulfilled", "PREDECESSOR_SEND_FAILED");
          requireCondition(
            predecessorTerminalSnapshot,
            "PREDECESSOR_PUBLIC_TERMINAL_MISSING"
          );
          const queuedEntry = predecessorTerminalSnapshot.entries.find(
            (entry) => entry.text === followUpText
          );
          requireCondition(queuedEntry, "FOLLOW_UP_NOT_QUEUED_AT_PREDECESSOR_TERMINAL");
          requireCondition(
            JSON.stringify(Object.keys(queuedEntry).sort()) ===
              JSON.stringify(["id", "label", "mode", "text"]),
            "QUEUED_ENTRY_PUBLIC_SHAPE_WRONG"
          );
          requireCondition(
            /^followUp:\d+$/.test(queuedEntry.id) &&
              queuedEntry.mode === "followUp" &&
              queuedEntry.label === "Queued",
            "QUEUED_ENTRY_IDENTITY_WRONG"
          );
          requireCondition(
            predecessorTerminalSnapshot.followUpStatus === "pending" &&
              predecessorTerminalSnapshot.consumedMessageStarts === 0,
            "FOLLOW_UP_SETTLED_OR_CONSUMED_AT_PREDECESSOR_TERMINAL"
          );
          const queuesAtIdle = harness.agent.snapshotQueues();
          requireCondition(
            consumedMessageStarts === 0 &&
              consumptionSnapshot === undefined &&
              queuesAtIdle.steering.length === 0 &&
              queuesAtIdle.followUp.length === 1 &&
              queuesAtIdle.followUp.includes(executableMessage) &&
              followUp.status === "pending" &&
              harness.agent.state.isStreaming === false &&
              harness.mockModels.get("primary").calls.length === 1,
            "FOLLOW_UP_NOT_RETAINED_AT_IDLE_BOUNDARY",
            admissionState()
          );
          requireCondition(
            successorUserText === undefined &&
              rawTerminalCount === 1 &&
              publicTerminalCount === 1,
            "SUCCESSOR_STARTED_BEFORE_IDLE_GAP_WAS_RECORDED",
            admissionState()
          );

          const disposal = observe(harness.adapter.dispose());
          await withDeadline(
            Promise.all([disposal.settled, followUp.settled]),
            STEP_TIMEOUT_MS,
            "NEAR_TERMINAL_GAP_DISPOSAL_DID_NOT_SETTLE"
          );
          requireCondition(
            disposal.status === "fulfilled" &&
              followUp.status === "rejected" &&
              rawTerminalCount === 1 &&
              publicTerminalCount === 1 &&
              terminalEvents(followUpEvents).length === 1 &&
              harness.mockModels.get("primary").calls.length === 1,
            "NEAR_TERMINAL_GAP_DISPOSAL_WRONG"
          );

          return {
            rawListenerPrecedesAgentSession: true,
            admissionContext: "independent-host-async-resource",
            publicTerminalCountAtAdmission,
            followUpStatusAfterRawDispatch,
            followUpFailureCodeAfterRawDispatch,
            evidenceScope: "unique-text-only",
            queuedEntry: {
              idPattern: "followUp:<sequence>",
              text: queuedEntry.text,
              mode: queuedEntry.mode,
              label: queuedEntry.label,
            },
            pendingAtPredecessorTerminal: true,
            publicIdleBoundary: "session.waitForIdle",
            sdkOutcome: "queued-without-auto-continuation",
            consumedMessageStartCount: 0,
            successorProviderCallStarted: false,
            exactExecutableIdentityRetainedAtIdle: true,
            executableFollowUpCountAtIdle: queuesAtIdle.followUp.length,
            pendingAtIdleBoundary: true,
            rejectedOnDispose: true,
            rawTerminalCount,
            publicTerminalCount,
          };
        } finally {
          releaseSuccessor.resolve();
          unsubscribe();
        }
      }
    );
  } finally {
    releaseSuccessor.resolve();
    hostDispatch.emitDestroy();
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
  const packagePath = join(
    repoRoot,
    "node_modules",
    "@gajae-code",
    "coding-agent",
    "package.json"
  );
  const modesIndexPath = join(
    repoRoot,
    "node_modules",
    "@gajae-code",
    "coding-agent",
    "src",
    "modes",
    "index.ts"
  );
  const rootIndexPath = join(
    repoRoot,
    "node_modules",
    "@gajae-code",
    "coding-agent",
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
    code: "SDK_0_16_4_DECISION_GATE_BUILDERS_NOT_PUBLIC",
    internalWireSubpathsBlocked: true,
    fabricatedSchemaUsed: false,
  };
}

async function runProbe(ownerRoot) {
  const [sdkPackage, daemonPackage] = await Promise.all([
    readFile(
      join(repoRoot, "node_modules", "@gajae-code", "coding-agent", "package.json"),
      "utf8"
    ).then(JSON.parse),
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

  const followUps = await probeFollowUps(ownerRoot);
  const sameTextQueueDivergence = await probeSameTextQueueDivergence(ownerRoot);
  const nearTerminalQueue = await probeNearTerminalQueue(ownerRoot);
  const gates = await probeGates(ownerRoot);
  const failureTerminal = await probeFailureTerminal(ownerRoot);
  const disposal = await probeDisposeWithoutTerminal(ownerRoot);
  const decisionGate = await decisionGateLimitation();
  requireCondition(networkAttempts === 0, "NETWORK_ACCESS_ATTEMPTED");
  requireCondition(harnessCleanupOutcomes.length === 6, "CLEANUP_OUTCOME_COUNT_WRONG");
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
      verdict: "BLOCK",
      oracleStatus: "completed",
      reasonCodes: ["SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED"],
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
    followUps,
    sameTextQueueDivergence,
    nearTerminalQueue,
    gates,
    failureTerminal,
    disposal,
    decisionGate,
    limitations: {
      lateFollowUpAutoContinuation: {
        status: "observed-sdk-gap",
        code: "SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
        boundary: "raw-agent-end-before-agent-session-terminal",
        evidence:
          "session.waitForIdle resolved while the exact executable follow-up remained queued.",
      },
      successorGateCompletion: {
        status: "not-exercised",
        code: "COMPLETED_GATE_RECEIPT_NOT_OBSERVED",
        excludedCase: "accepted-incomplete-predecessor",
        requiredEvidence: "lookupCompletedResolution.kind=completed",
      },
      lateSteerRearm: {
        status: "not-exercised",
        code: "LATE_STEER_REARM_NOT_OBSERVED",
        excludedCase: "steer-rearmed-as-follow-up",
        reason:
          "The bounded near-terminal cases exercise follow-up ownership; steering promotion is a distinct SDK path.",
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
