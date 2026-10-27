import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const testFile = fileURLToPath(import.meta.url);
const daemonDir = resolve(dirname(testFile), "..");
const fixture = join(daemonDir, "test-fixtures", "sdk-contract-probe.mjs");
const RECEIPT_SCHEMA = "sdk-contract-probe-v1";
const SDK_VERSION = "0.19.0";
const CHILD_TIMEOUT_MS = 50_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const SECRET_ASSIGNMENT =
  /(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|authorization|cookie|credential|broker[_ -]?(?:key|token)|oauth[_ -]?token)\s*[:=]\s*["']?[^\s,"'}]+/i;

function childEnvironment(root) {
  const inheritedNames = [
    "PATH",
    "Path",
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "COMSPEC",
    "PATHEXT",
    "BUN_INSTALL",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "OS",
    "LANG",
    "LC_ALL",
  ];
  const env = {};
  for (const name of inheritedNames) {
    if (process.env[name]) env[name] = process.env[name];
  }
  const home = join(root, "home");
  const temp = join(root, "tmp");
  Object.assign(env, {
    HOME: home,
    USERPROFILE: home,
    APPDATA: join(root, "appdata"),
    LOCALAPPDATA: join(root, "localappdata"),
    TMP: temp,
    TEMP: temp,
    XDG_CONFIG_HOME: join(root, "xdg-config"),
    XDG_CACHE_HOME: join(root, "xdg-cache"),
    SDK_CONTRACT_ROOT: join(root, "owned"),
    CI: "1",
    NO_COLOR: "1",
  });
  return env;
}

async function removeRoot(root) {
  await rm(root, { recursive: true, force: true });
}

function parseReceipt(stdout) {
  const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      const value = JSON.parse(lines[index]);
      if (value?.schema === RECEIPT_SCHEMA) return value;
    } catch {
      // Bun diagnostics may precede the bounded receipt.
    }
  }
  assert.fail("real SDK contract fixture emitted no structured receipt");
}

function failureSummary(receipt, signal) {
  const safeCode = (value, fallback) =>
    typeof value === "string" && /^[A-Za-z0-9._-]{1,80}$/.test(value)
      ? value
      : fallback;
  const parts = [safeCode(receipt?.code, safeCode(signal, "unknown"))];
  if (receipt?.primaryFailure && typeof receipt.primaryFailure === "object") {
    parts.push(
      `${safeCode(receipt.primaryFailure.stage, "stage")}:${safeCode(
        receipt.primaryFailure.code,
        "failure"
      )}`
    );
    const state = receipt.primaryFailure.state;
    if (state && typeof state === "object" && !Array.isArray(state)) {
      const stateKeys = [
        "declaredArtifact",
        "operation",
        "filesystemCode",
        "followUpStatus",
        "followUpFailureCode",
        "initialStatus",
        "rawTerminalCount",
        "publicTerminalCount",
        "publicTerminalCountAtAdmission",
        "agentStreaming",
        "executableSteeringCount",
        "executableFollowUpCount",
        "displayQueueCount",
        "primaryProviderCallCount",
        "consumedMessageStarts",
        "boundedOwnedPromptSettled",
        "ownedPromptStatus",
        "ownedPromptFailureCode",
        "ownerTicketPhase",
        "publicAbortStatus",
        "underlyingTerminalCount",
        "lateAnswerAccepted",
        "duplicateAnswerRefused",
        "providerCalls",
        "continuationProviderCalls",
        "sdkPendingGateCount",
        "adapterPendingGateCount",
      ];
      const safeState = [];
      for (const key of stateKeys) {
        const value = state[key];
        if (typeof value === "boolean") {
          safeState.push(`${key}=${value}`);
        } else if (typeof value === "number" && Number.isFinite(value)) {
          safeState.push(`${key}=${Math.trunc(value)}`);
        } else if (
          typeof value === "string" &&
          /^[A-Za-z0-9._:<>=-]{0,96}$/.test(value)
        ) {
          safeState.push(`${key}=${value}`);
        }
      }
      const beforeLateAnswer = state.beforeLateAnswer;
      if (beforeLateAnswer && typeof beforeLateAnswer === "object" && !Array.isArray(beforeLateAnswer)) {
        for (const key of [
          "ownedPromptStatus",
          "ownerTicketPhase",
          "publicAbortStatus",
          "underlyingTerminalCount",
          "sdkGateStillPending",
          "adapterGateStillExposed",
        ]) {
          const value = beforeLateAnswer[key];
          if (typeof value === "boolean") {
            safeState.push(`beforeLateAnswer.${key}=${value}`);
          } else if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000) {
            safeState.push(`beforeLateAnswer.${key}=${value}`);
          } else if (typeof value === "string" && /^[A-Za-z0-9._-]{1,80}$/.test(value)) {
            safeState.push(`beforeLateAnswer.${key}=${value}`);
          }
        }
      }
      for (const key of ["underlyingTerminalStopReasons", "underlyingAssistantStopReasons"]) {
        if (!Array.isArray(state[key])) continue;
        for (const [index, value] of state[key].slice(0, 4).entries()) {
          if (typeof value === "string" && /^[A-Za-z0-9._-]{1,80}$/.test(value)) {
            safeState.push(`${key}.${index}=${value}`);
          }
        }
      }
      const teardown = state.teardown;
      if (teardown && typeof teardown === "object" && !Array.isArray(teardown)) {
        for (const key of [
          "phase", "subscriptionsRemaining", "exactAdapterListenerRemaining",
          "sdkPendingGateCount", "adapterPendingGateCount", "deferredGateRemaining",
          "activeGateRunCount", "inFlightGateAnswerCount", "adapterWaiterCount",
          "ownedQueueTicketCount", "adapterBusy",
        ]) {
          const value = teardown[key];
          if (typeof value === "boolean" ||
              (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000) ||
              (typeof value === "string" && /^[A-Za-z0-9._-]{1,80}$/.test(value))) {
            safeState.push(`teardown.${key}=${value}`);
          }
        }
        for (const key of ["sessionDispose", "managerClose", "registryDispose", "providerRelease", "authClose", "settingsClose"]) {
          const value = teardown.calls?.[key];
          if (Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000) safeState.push(`teardown.${key}=${value}`);
        }
      }
      if (safeState.length > 0) parts.push(`state[${safeState.join(";")}]`);
    }
  }
  if (Array.isArray(receipt?.cleanupFailures)) {
    for (const failure of receipt.cleanupFailures.slice(0, 16)) {
      if (!failure || typeof failure !== "object") continue;
      parts.push(
        `${safeCode(failure.operation, "cleanup")}:${safeCode(
          failure.code,
          "failure"
        )}`
      );
    }
  }
  if (Array.isArray(receipt?.harnessCleanupOutcomes)) {
    for (const [index, outcome] of receipt.harnessCleanupOutcomes.slice(0, 8).entries()) {
      if (!outcome || typeof outcome !== "object") continue;
      const fields = [`phase=fixture-owner-close`, `modelCacheState=${safeCode(outcome.modelCacheState, "unknown")}`];
      for (const key of ["sessionDispose", "managerClose", "registryDispose", "providerRelease", "authClose", "settingsClose"]) {
        const value = outcome.calls?.[key];
        if (Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000) fields.push(`${key}=${value}`);
      }
      if (Number.isSafeInteger(outcome.subscriptionsRemaining) && outcome.subscriptionsRemaining >= 0 && outcome.subscriptionsRemaining <= 1_000_000) {
        fields.push(`subscriptionsRemaining=${outcome.subscriptionsRemaining}`);
      }
      parts.push(`cleanup.${index}[${fields.join(";")}]`);
    }
  }
  const partial = receipt?.partialEvidence;
  if (partial?.status === "diagnostic-only-not-whole-contract-PASS") {
    parts.push(`partialEvidence.status=${partial.status}`);
    const cellNames = [
      "canonicalImports", "gates", "failureTerminal", "disposal",
      "pendingAskDisposal", "pendingAskActiveCancel", "liveControlContainment",
      "decisionGate",
    ];
    for (const name of cellNames) {
      if (partial.completedCells?.[name] && typeof partial.completedCells[name] === "object") {
        parts.push(`completedCell=${name}`);
      }
    }
    const fields = [];
    const appendState = (value, path, depth = 0) => {
      if (depth > 4 || fields.length >= 80) return;
      if (typeof value === "boolean" ||
          (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000) ||
          (typeof value === "string" && /^[A-Za-z0-9._:<>=-]{0,96}$/.test(value))) {
        fields.push(`${path}=${value}`);
      } else if (Array.isArray(value)) {
        for (const [index, item] of value.slice(0, 4).entries()) appendState(item, `${path}.${index}`, depth + 1);
      } else if (value && typeof value === "object") {
        for (const [key, item] of Object.entries(value).slice(0, 24)) {
          if (/^[A-Za-z0-9._-]{1,64}$/.test(key)) appendState(item, `${path}.${key}`, depth + 1);
        }
      }
    };
    appendState(partial.pendingAskActiveCancel, "pendingAskActiveCancel");
    if (fields.length > 0) parts.push(`partialEvidence[${fields.join(";")}]`);
  }
  return parts.join(", ");
}

function spawnProbe(root) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.env.BUN_BIN || "bun", [fixture], {
      cwd: root,
      env: childEnvironment(root),
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let overflow = false;
    let settled = false;
    let killTimer;
    const timeout = setTimeout(() => {
      if (settled) return;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => {
        if (!settled) child.kill("SIGKILL");
      }, 2_000);
      killTimer.unref?.();
    }, CHILD_TIMEOUT_MS);

    const append = (target, chunk) => {
      const next = target + chunk.toString("utf8");
      if (Buffer.byteLength(next) > MAX_OUTPUT_BYTES) {
        overflow = true;
        child.kill("SIGTERM");
        return target;
      }
      return next;
    };
    child.stdout.on("data", (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(stderr, chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      clearTimeout(killTimer);
      if (settled) return;
      settled = true;
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timeout);
      clearTimeout(killTimer);
      if (settled) return;
      settled = true;
      resolveResult({ code, signal, stdout, stderr, overflow });
    });
  });
}

test("failure diagnostics preserve partial cells without qualifying the whole contract", () => {
  const summary = failureSummary({
    code: "MISSING_DECLARED_PACKAGE_ARTIFACT",
    primaryFailure: {
      stage: "probe",
      code: "MISSING_DECLARED_PACKAGE_ARTIFACT",
      state: {
        declaredArtifact: "agent-session-types",
        operation: "expected-declaration-read",
        filesystemCode: "ENOENT",
        rawPath: "D:/private/owned/root",
      },
    },
    partialEvidence: {
      status: "diagnostic-only-not-whole-contract-PASS",
      completedCells: { gates: {}, pendingAskActiveCancel: {} },
      pendingAskActiveCancel: {
        afterLateAnswer: {
          ownedPromptStatus: "rejected",
          ownedPromptFailureCode: "aborted",
          publicAbortStatus: "fulfilled",
          underlyingTerminalCount: 1,
          lateAnswerAccepted: false,
        },
        underlyingAssistantStopReasons: ["cancelled"],
        providerCalls: 1,
        continuationProviderCalls: 0,
        teardown: { calls: { sessionDispose: 1, managerClose: 1 }, exactAdapterListenerRemaining: false },
        rawPath: "D:/private/owned/root",
        secret: "authorization=private credential",
      },
    },
  });
  assert.match(summary, /MISSING_DECLARED_PACKAGE_ARTIFACT/);
  assert.match(summary, /declaredArtifact=agent-session-types/);
  assert.match(summary, /partialEvidence.status=diagnostic-only-not-whole-contract-PASS/);
  assert.match(summary, /completedCell=gates/);
  assert.match(summary, /completedCell=pendingAskActiveCancel/);
  for (const field of [
    "afterLateAnswer.ownedPromptStatus=rejected", "afterLateAnswer.ownedPromptFailureCode=aborted",
    "afterLateAnswer.publicAbortStatus=fulfilled", "afterLateAnswer.underlyingTerminalCount=1",
    "afterLateAnswer.lateAnswerAccepted=false", "underlyingAssistantStopReasons.0=cancelled",
    "providerCalls=1", "continuationProviderCalls=0", "teardown.calls.sessionDispose=1",
    "teardown.calls.managerClose=1", "teardown.exactAdapterListenerRemaining=false",
  ]) assert.ok(summary.includes(`pendingAskActiveCancel.${field}`), field);
  assert.doesNotMatch(summary, /private|authorization|rawPath|secret=/);
});

test(
  "SDK 0.19.0 real AgentSession contracts contain live controls and govern gates, failures, and disposal",
  { timeout: 55_000 },
  async () => {
    assert.ok(existsSync(fixture), "real SDK contract fixture is missing");
    const root = await mkdtemp(join(tmpdir(), "gjc-sdk-contract-"));
    await Promise.all([
      mkdir(join(root, "home"), { recursive: true }),
      mkdir(join(root, "tmp"), { recursive: true }),
    ]);

    let result;
    try {
      result = await spawnProbe(root);
    } finally {
      await removeRoot(root);
    }

    assert.equal(result.overflow, false, "real SDK contract fixture exceeded its output bound");
    assert.doesNotMatch(result.stdout, SECRET_ASSIGNMENT, "fixture stdout exposed credential material");
    assert.doesNotMatch(result.stderr, SECRET_ASSIGNMENT, "fixture stderr exposed credential material");
    assert.equal(result.stdout.includes(root), false, "fixture stdout exposed its owned root");
    assert.equal(result.stderr.includes(root), false, "fixture stderr exposed its owned root");

    const receipt = parseReceipt(result.stdout);
    assert.equal(
      result.code,
      0,
      `real SDK contract fixture failed (${failureSummary(receipt, result.signal)})`
    );
    assert.equal(receipt.ok, true);
    assert.equal(receipt.sdkVersionExpected, SDK_VERSION);
    assert.equal(receipt.sdkVersionObserved, SDK_VERSION);
    assert.equal(receipt.daemonDependencyVersion, SDK_VERSION);
    assert.deepEqual(receipt.upgradeAssessment, {
      verdict: "PASS",
      oracleStatus: "completed",
      containment: "live-controls-fail-closed",
      limitationCodes: [
        "PUBLIC_TRACKED_SUBMISSION_NOT_INTEGRATED_OR_QUALIFIED",
      ],
    });
    assert.deepEqual(receipt.historicalProvenance, {
      oracleOriginSdkVersion: "0.16.4",
      originalReasonCode:
        "SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
      upstreamIssue: 5351,
      upstreamFixPullRequest: 5371,
      upstreamFixBranch: "dev",
      upstreamFixMarkerPresentInObservedVersion: true,
      continuationBehaviorQualifiedByOracle: false,
    });
    assert.deepEqual(receipt.environment, {
      credentialVariableCount: 0,
      networkAttempts: 0,
      settingsAndStateOwnedByFixture: true,
    });
    assert.equal(existsSync(root), false, "parent wrapper did not remove its fixture root");
    assert.deepEqual(receipt.cleanup, {
      harnessCount: 6,
      sdkResourcesClosed: true,
      modelCacheStates: ["closed", "closed", "closed", "closed", "closed", "closed"],
      ownedScratchRemoved: [true, true, true, true, true, true],
      authStorageBacking: "owned-file",
      resourceReleaseCalls: Array.from({ length: 6 }, () => ({
        settingsClose: 1,
        authClose: 1,
        registryDispose: 1,
        providerRelease: 1,
        managerClose: 1,
        sessionDispose: 1,
      })),
      subscriptionsRemaining: [0, 0, 0, 0, 0, 0],
      cleanupOrder: [
        "event-subscription-release",
        "adapter-session-dispose",
        "provider-registration-release",
        "model-registry-dispose",
        "model-cache-close",
        "auth-storage-close",
        "settings-close",
        "immediate-owned-scratch-removal",
      ],
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
    });

    assert.deepEqual(receipt.canonicalImports, {
      canonicalSdkImported: true,
      createAgentSessionExported: true,
      settingsExportMatches: true,
      publicNamespacesExported: ["host", "lifecycle"],
      privateSubpathsRejected: ["./sdk/broker", "./sdk/client", "./sdk/models"],
    });
    assert.deepEqual(receipt.liveControlContainment, {
      mode: "fail-closed",
      errorCode: "SDK_LIVE_CONTROL_UNSUPPORTED",
      steerStatus: "rejected",
      followUpStatus: "rejected",
      executableSteeringCount: 0,
      executableFollowUpCount: 0,
      promptStatus: "fulfilled",
    });

    assert.equal(receipt.gates.emittedGateCount, 2);
    assert.equal(receipt.gates.distinctSuccessorGateIds, true);
    assert.equal(receipt.gates.sdkObjectSchemaObserved, true);
    assert.equal(receipt.gates.selectionAccepted, true);
    assert.equal(receipt.gates.invalidCustomRejectedWithoutConsumption, true);
    assert.equal(receipt.gates.customAcceptedOnRetry, true);
    assert.equal(receipt.gates.toolResultObservedBothAnswers, true);
    assert.equal(receipt.gates.terminalCount, 1);
    assert.deepEqual(receipt.gates.completedResponseLoss, {
      evidenceKind: "installed-public-SDK-with-credentialless-mock-provider",
      injectedBoundary: "returned-response-after-actual-completed-resolution",
      lostResponseCount: 1,
      completedLookupKind: "completed",
      exactResponseBound: true,
      conflictRejected: true,
      actualSuccessfulResolutions: 2,
      firstGateResolveCalls: 1,
      duplicateAnswerRefused: true,
      continuationProviderCalls: 1,
      fabricatedCompletionUsed: false,
    });

    assert.deepEqual(receipt.failureTerminal, {
      providerFailureMessageObserved: true,
      terminalContainsFailure: true,
      terminalCount: 1,
      adapterRejected: true,
    });
    assert.deepEqual(receipt.disposal, {
      disposeSettled: true,
      activeSendRejected: true,
      underlyingTerminalCount: 0,
    });
    assert.deepEqual(receipt.pendingAskDisposal, {
      evidenceKind: "installed-public-SDK-Ask-with-credentialless-mock-provider",
      exactPresentationAcknowledged: true,
      cancellationSurface: "adapter.dispose-quarantines-owned-gate",
      ownedSendRejected: true,
      ownerTicketPhase: "terminal",
      underlyingTerminalCount: 0,
      lateAnswerRefused: true,
      sdkResolveCalls: 0,
      continuationProviderCalls: 0,
      pendingAndDeferredRetired: true,
      adapterListenersRetired: true,
      listenerOwnershipProof: "exact-adapter-public-unsubscribe-handle",
      sessionDisposeCalls: 1,
      managerCloseCalls: 1,
      fixtureResourcesOpenUntilOwnerTeardown: true,
      fabricatedTerminalUsed: false,
    });
    const activeCancelSettled = receipt.pendingAskActiveCancel.boundedOwnedPromptSettled;
    assert.equal(typeof activeCancelSettled, "boolean");
    assert.deepEqual(receipt.pendingAskActiveCancel, {
      evidenceKind: "installed-public-SDK-Ask-with-credentialless-mock-provider",
      cancellationSurface: "AgentSession.abort-user_interrupt",
      wireCancelAck: "cancellation_pending-is-nonterminal-not-SDK-abort",
      exactPresentationAcknowledged: true,
      settleBoundMs: 250,
      boundedOwnedPromptSettled: activeCancelSettled,
      status: activeCancelSettled ? "bounded-settle-observed" : "not-qualified-pending-Ask-requires-late-answer",
      beforeLateAnswer: {
        ownedPromptStatus: activeCancelSettled ? "rejected" : "pending",
        ownerTicketPhase: activeCancelSettled ? "terminal" : "active",
        publicAbortStatus: receipt.pendingAskActiveCancel.beforeLateAnswer.publicAbortStatus,
        underlyingTerminalCount: activeCancelSettled ? 1 : 0,
        sdkGateStillPending: !activeCancelSettled,
        adapterGateStillExposed: !activeCancelSettled,
      },
      afterLateAnswer: {
        ownedPromptStatus: "rejected",
        ownedPromptFailureCode: "aborted",
        ownerTicketPhase: "terminal",
        publicAbortStatus: "fulfilled",
        underlyingTerminalCount: 1,
        underlyingTerminalStopReason: "cancelled",
        lateAnswerAccepted: !activeCancelSettled,
        duplicateAnswerRefused: true,
        continuationProviderCalls: 0,
      },
      pendingAndDeferredRetiredAtTeardown: true,
      exactAdapterListenerRetiredAtTeardown: true,
      sessionDisposeCalls: 1,
      managerCloseCalls: 1,
      fixtureResourcesOpenUntilOwnerTeardown: true,
      fabricatedTerminalUsed: false,
    });
    assert.ok(
      ["pending", "fulfilled"].includes(receipt.pendingAskActiveCancel.beforeLateAnswer.publicAbortStatus),
      "public abort rejected before late-answer probe"
    );

    // SDK 0.19.0 does not publicly export the decision-gate builders. This
    // oracle deliberately reports that boundary instead of copying a private
    // approval/execution schema and accidentally turning another fake into truth.
    assert.deepEqual(receipt.decisionGate, {
      status: "blocked",
      blockedCase: "structured_decision_denial",
      code: "DECISION_GATE_BUILDERS_NOT_PUBLIC",
      internalWireSubpathsBlocked: true,
      fabricatedSchemaUsed: false,
    });
    assert.deepEqual(receipt.queuedControlOwnership, {
      status: "contained",
      code:
        "PUBLIC_TRACKED_SUBMISSION_NOT_INTEGRATED_OR_QUALIFIED",
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
    });
    assert.deepEqual(receipt.limitations, {
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
    });
  }
);
