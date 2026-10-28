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
        "initialFailureCode",
        "rawTerminalCount",
        "publicTerminalCount",
        "publicRootPromptStatus",
        "publicTerminalCountAtAdmission",
        "agentStreaming",
        "sessionStreaming",
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
      if (Array.isArray(state.trackedSubmissions)) {
        for (const [index, record] of state.trackedSubmissions.slice(0, 8).entries()) {
          for (const key of ["submissionId", "admittedStatus", "executionStatus", "executionDisposition",
            "terminalStatus", "terminalDisposition", "removalReason"]) {
            const value = record?.[key];
            if (typeof value === "string" && /^[A-Za-z0-9._-]{1,80}$/.test(value)) {
              safeState.push(`trackedSubmissions.${index}.${key}=${value}`);
            }
          }
        }
      }
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
    for (const [index, outcome] of receipt.harnessCleanupOutcomes.slice(0, 12).entries()) {
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
      "canonicalImports", "gates", "joinedAsk", "failureTerminal", "disposal",
      "pendingAskDisposal", "pendingAskActiveCancel", "trackedControls", "trackedControlFailure",
      "lateFollowUp", "lateSteer", "promotedGateOverlap", "decisionGate", "queuedControlOwnership",
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
    appendState(partial.joinedAsk, "joinedAsk");
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
        trackedSubmissions: [{ submissionId: "queued-diagnostic", admittedStatus: "fulfilled",
          executionStatus: "fulfilled", executionDisposition: "promoted-to-run", terminalStatus: "pending",
          terminalDisposition: "pending", removalReason: "none", rawText: "authorization=private credential" }],
        rawPath: "D:/private/owned/root",
      },
    },
    partialEvidence: {
      status: "diagnostic-only-not-whole-contract-PASS",
      completedCells: { gates: {}, pendingAskActiveCancel: {} },
      joinedAsk: {
        status: "blocked", blockedCase: "joined-current-run-Ask-owner-presentation",
        code: "JOINED_ASK_CONTINUATION_GATE_MISSING", positiveOwnerPresentationQualification: false,
        observedState: { publicRootPromptStatus: "pending", sdkPendingGateCount: 1 },
        fabricatedReceiptUsed: false,
      },
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
  assert.match(summary, /trackedSubmissions.0.submissionId=queued-diagnostic/);
  assert.match(summary, /trackedSubmissions.0.executionDisposition=promoted-to-run/);
  assert.match(summary, /trackedSubmissions.0.terminalStatus=pending/);
  for (const field of [
    "afterLateAnswer.ownedPromptStatus=rejected", "afterLateAnswer.ownedPromptFailureCode=aborted",
    "afterLateAnswer.publicAbortStatus=fulfilled", "afterLateAnswer.underlyingTerminalCount=1",
    "afterLateAnswer.lateAnswerAccepted=false", "underlyingAssistantStopReasons.0=cancelled",
    "providerCalls=1", "continuationProviderCalls=0", "teardown.calls.sessionDispose=1",
    "teardown.calls.managerClose=1", "teardown.exactAdapterListenerRemaining=false",
  ]) assert.ok(summary.includes(`pendingAskActiveCancel.${field}`), field);
  for (const field of [
    "status=blocked", "blockedCase=joined-current-run-Ask-owner-presentation",
    "code=JOINED_ASK_CONTINUATION_GATE_MISSING", "positiveOwnerPresentationQualification=false",
    "observedState.publicRootPromptStatus=pending", "observedState.sdkPendingGateCount=1",
    "fabricatedReceiptUsed=false",
  ]) assert.ok(summary.includes(`joinedAsk.${field}`), field);
  assert.doesNotMatch(summary, /private|authorization|rawPath|secret=/);
});

function assertSubmissionEvidence(record, delivery, disposition, removed = false) {
  assert.equal(typeof record.submissionId, "string");
  assert.ok(record.submissionId.length > 0);
  assert.deepEqual(record.admitted, { submissionId: record.submissionId, delivery, queuePolicy: "sequential" });
  for (const value of [record.execution, record.terminal]) {
    assert.equal(value.submissionId, record.submissionId);
    assert.equal(value.delivery, delivery);
    if (!removed) {
      assert.equal(typeof value.attemptScope.attemptId, "string");
      assert.ok(value.attemptScope.attemptId.length > 0);
      assert.ok(Number.isSafeInteger(value.attemptScope.generation));
      assert.equal(value.attemptScope.lineage, "main");
    }
  }
  assert.equal(record.execution.disposition, removed ? "removed" : disposition);
  assert.equal(record.terminal.disposition, removed ? "removed" : "completed");
  if (removed) {
    assert.equal(record.execution.reason, "cancelled");
    assert.equal(record.terminal.reason, "cancelled");
  }
}

test(
  "SDK 0.19.0 real tracked controls qualify ownership, sequential delivery, late rearm, joined Ask, gates, failures, and disposal",
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
      liveControls: "public-tracked-submissions-behaviorally-qualified",
      limitationCodes: ["DECISION_GATE_BUILDERS_NOT_PUBLIC", "SDK_TRACKED_INPUT_GATE_OWNERSHIP"],
    });
    assert.deepEqual(receipt.historicalProvenance, {
      oracleOriginSdkVersion: "0.16.4",
      originalReasonCode:
        "SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
      upstreamIssue: 5351,
      upstreamFixPullRequest: 5371,
      upstreamFixBranch: "dev",
      upstreamFixMarkerPresentInObservedVersion: true,
      continuationBehaviorQualifiedByOracle: true,
    });
    assert.deepEqual(receipt.environment, {
      credentialVariableCount: 0,
      networkAttempts: 0,
      settingsAndStateOwnedByFixture: true,
    });
    assert.equal(existsSync(root), false, "parent wrapper did not remove its fixture root");
    assert.deepEqual(receipt.cleanup, {
      harnessCount: 11,
      harnessNames: ["workflow-gates", "failure-terminal", "dispose-without-terminal", "pending-ask-disposal",
        "pending-ask-active-cancel", "tracked-control-sequential", "tracked-control-failure", "late-follow-up-continuation",
        "late-steer-rearm", "late-follow-up-gate-overlap", "joined-steer-ask"],
      sdkResourcesClosed: true,
      modelCacheStates: Array(11).fill("closed"),
      ownedScratchRemoved: Array(11).fill(true),
      authStorageBacking: "owned-file",
      resourceReleaseCalls: Array.from({ length: 11 }, () => ({
        settingsClose: 1,
        authClose: 1,
        registryDispose: 1,
        providerRelease: 1,
        managerClose: 1,
        sessionDispose: 1,
      })),
      subscriptionsRemaining: Array(11).fill(0),
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
    for (const [name, failure, providerCalls, deliveries] of [
      ["trackedControls", false, 6, ["steer", "steer", "followUp", "followUp"]],
      ["trackedControlFailure", true, 4, ["steer", "followUp"]],
    ]) {
      const actual = receipt[name];
      assert.equal(actual.receipts.length, deliveries.length);
      const submittedDeliveries = failure ? ["steer", "followUp"] : ["steer", "steer", "followUp", "followUp", "followUp"];
      assert.equal(actual.submissions.length, submittedDeliveries.length);
      assert.equal(new Set(actual.submissions.map((item) => item.submissionId)).size, submittedDeliveries.length);
      actual.submissions.forEach((item, index) => assertSubmissionEvidence(item, submittedDeliveries[index],
        "joined-current-run", !failure && index === 2));
      assert.ok(actual.receipts.some((item) => item.finalScopeChanged), "final owning scope change was not exercised");
      assert.deepEqual(actual, {
        status: "qualified", acceptedDuringProviderExecution: true,
        queuePolicy: "sequential", ordering: "per-delivery-not-global-FIFO", providerCalls,
        exactPrimaryTerminal: true,
        submissions: actual.submissions,
        receipts: deliveries.map((delivery, index) => ({
          delivery, executionDisposition: "joined-current-run",
          finalScopeChanged: actual.receipts[index].finalScopeChanged,
          exactOwningTerminal: true, activatedAfterExecution: true,
          adapterStatus: failure ? "rejected" : "fulfilled", cancelAfterExecution: false,
        })),
        duplicateTextDistinctIds: !failure, exactlyOneQueuedHandleCancelled: !failure,
        cancellationReason: failure ? "not-exercised" : "cancelled",
        noSuccessorEventLeakage: true, owningFailureObserved: failure, fabricatedReceiptUsed: false,
      });
      for (const item of actual.receipts) assert.equal(typeof item.finalScopeChanged, "boolean");
    }
    for (const [name, delivery] of [["lateFollowUp", "followUp"], ["lateSteer", "steer"]]) {
      assertSubmissionEvidence(receipt[name].submission, delivery, "promoted-to-run");
      const proof = receipt[name].originalRootResult;
      assert.equal(typeof proof.rawScope.attemptId, "string");
      assert.ok(proof.rawScope.attemptId.length > 0);
      assert.ok(Number.isSafeInteger(proof.rawScope.generation));
      assert.equal(proof.rawScope.lineage, "main");
      assert.notDeepEqual(proof.rawScope, receipt[name].submission.execution.attemptScope);
      assert.notDeepEqual(proof.rawScope, receipt[name].submission.terminal.attemptScope);
      assert.ok([0, 1].includes(proof.sdkPublicRootTerminalCount));
      assert.equal(proof.sdkPublicTerminalCount, proof.sdkPublicRootTerminalCount + 1);
      assert.deepEqual(proof, {
        evidenceKind: "public-AgentSession.agent-raw-scope-and-own-public-prompt",
        rawScope: proof.rawScope, rawTerminalStopReason: "completed", rawTerminalBeforeLateSubmission: true,
        publicPromptCallIndex: 0, publicPromptStatus: "fulfilled", adapterStatus: "fulfilled",
        sdkPublicRootTerminalCount: proof.sdkPublicRootTerminalCount,
        sdkPublicTerminalCount: proof.sdkPublicTerminalCount,
      });
      assert.deepEqual(receipt[name], {
        status: "qualified", boundary: "raw-Agent-agent_end-before-AgentSession-unwind",
        actualSuccessorProviderInvoked: true, actualQueuedTextConsumed: true,
        executionDisposition: "promoted-to-run", exactOwningTerminal: true,
        submission: receipt[name].submission,
        originalRootResult: proof,
        trackedTerminalProof: "genuine-handle-terminal-and-matching-public-SDK-agent_end",
        noSuccessorEventLeakage: true, cancelAfterExecution: false, providerCalls: 3, fabricatedReceiptUsed: false,
      });
    }
    const overlap = receipt.promotedGateOverlap;
    assert.deepEqual(overlap.admitted, {
      submissionId: overlap.submissionId, delivery: "followUp", queuePolicy: "sequential",
    });
    assert.equal(typeof overlap.submissionId, "string");
    assert.ok(overlap.submissionId.length > 0);
    assert.equal(overlap.execution.submissionId, overlap.submissionId);
    assert.equal(overlap.execution.delivery, "followUp");
    assert.equal(overlap.execution.disposition, "promoted-to-run");
    assert.equal(typeof overlap.execution.attemptScope.attemptId, "string");
    assert.ok(Number.isSafeInteger(overlap.execution.attemptScope.generation));
    assert.equal(overlap.execution.attemptScope.lineage, "main");
    const originalRoot = overlap.originalRootResult;
    assert.equal(typeof originalRoot.rawScope.attemptId, "string");
    assert.ok(originalRoot.rawScope.attemptId.length > 0);
    assert.ok(Number.isSafeInteger(originalRoot.rawScope.generation));
    assert.equal(originalRoot.rawScope.lineage, "main");
    assert.notDeepEqual(originalRoot.rawScope, overlap.execution.attemptScope);
    assert.ok(["pending", "fulfilled"].includes(overlap.beforeTeardown.initialStatus));
    assert.ok(["pending", "fulfilled"].includes(overlap.beforeTeardown.publicRootPromptStatus));
    assert.ok(["fulfilled", "rejected"].includes(originalRoot.adapterStatus));
    assert.ok(["pending", "fulfilled", "rejected"].includes(originalRoot.publicPromptStatus));
    if (overlap.beforeTeardown.initialStatus === "fulfilled") {
      assert.equal(overlap.beforeTeardown.publicRootPromptStatus, "fulfilled");
      assert.equal(originalRoot.adapterStatus, "fulfilled", "completed root was retroactively rejected");
    }
    if (originalRoot.adapterStatus === "fulfilled") assert.equal(originalRoot.publicPromptStatus, "fulfilled");
    assert.deepEqual(originalRoot, {
      evidenceKind: "public-AgentSession.agent-raw-scope-and-own-public-prompt",
      rawScope: originalRoot.rawScope, rawTerminalStopReason: "completed", rawTerminalBeforeLateSubmission: true,
      publicPromptCallIndex: 0, publicPromptStatus: originalRoot.publicPromptStatus,
      adapterStatus: originalRoot.adapterStatus, fulfilledWithOwnProof: originalRoot.adapterStatus === "fulfilled",
      sdkPublicRootTerminalCountAtGateEmission: 0,
    });
    assert.deepEqual(overlap, {
      status: "bounded-refusal-qualified", code: "SDK_TRACKED_INPUT_GATE_OWNERSHIP",
      boundary: "raw-Agent-agent_end-before-AgentSession-unwind",
      actualSuccessorProviderInvoked: true, actualQueuedTextConsumed: true,
      submissionId: overlap.submissionId, admitted: overlap.admitted, execution: overlap.execution,
      beforeTeardown: {
        publicTerminalCount: 0, publicRootPromptStatus: overlap.beforeTeardown.publicRootPromptStatus,
        initialStatus: overlap.beforeTeardown.initialStatus, lateStatus: "pending", trackedTerminalStatus: "pending",
      },
      gateWindowMs: 500, originalRootResult: originalRoot,
      initialFailureCode: originalRoot.adapterStatus === "fulfilled" ? "NONE" : "SDK_TRACKED_INPUT_GATE_OWNERSHIP",
      promotedFailureCode: "SDK_TRACKED_INPUT_GATE_OWNERSHIP",
      gateRequestCount: 0, sdkResolveCalls: 0, continuationProviderCalls: 0,
      pendingGatesRetired: true, realTeardownCompleted: true, fixtureResourcesOpenUntilOwnerTeardown: true,
      promotedGateExactOwnerAndPresentation: false, fabricatedReceiptUsed: false,
    });

    const joinedAsk = receipt.joinedAsk;
    assertSubmissionEvidence(joinedAsk.submission, "steer", "joined-current-run");
    assert.deepEqual(joinedAsk, {
      status: "qualified", evidenceKind: "installed-public-SDK-Ask-with-credentialless-mock-provider",
      primaryAskHeldAtAdmission: true, actualQueuedTextConsumed: true,
      executionDisposition: "joined-current-run", submission: joinedAsk.submission,
      emittedGateCount: 2, originalOwnerGateRequestCount: 2, joinedCallerGateRequestCount: 0,
      joinedCallerPresentationRefused: true, joinedCallerAnswerRefused: true,
      originalOwnerAnsweredBothGates: true, sdkResolveCalls: 2, providerCalls: 3,
      originalPublicPromptStatus: "fulfilled", adapterStatuses: { original: "fulfilled", joined: "fulfilled" },
      sharedPublicTerminalCount: 1, exactSharedPublicTerminalAndHandleScope: true,
      trackedTerminalProof: "genuine-handle-terminal-and-matching-public-SDK-agent_end",
      fabricatedReceiptUsed: false,
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
      successfulScenarioEvidence: ["trackedControls", "trackedControlFailure", "lateFollowUp", "lateSteer", "joinedAsk"],
      unsupportedFallbackUsed: false,
      publicContractRequestIssue: 5429,
    });
    assert.deepEqual(receipt.limitations, {
      lateFollowUpAutoContinuation: {
        status: "qualified",
        boundary: "raw-Agent-agent_end-before-AgentSession-unwind",
        actualSuccessorProviderInvoked: true,
      },
      successorGateCompletion: {
        status: "completed-response-loss-qualified-with-public-SDK-mock-provider",
        code: "ACTUAL_COMPLETED_GATE_RESPONSE_LOSS_RECONCILED",
        excludedCase: "accepted-incomplete-predecessor",
        observedEvidence: "exact-response lookupCompletedResolution.kind=completed",
      },
      lateSteerRearm: {
        status: "qualified",
        boundary: "raw-Agent-agent_end-before-AgentSession-unwind",
        actualSuccessorProviderInvoked: true,
      },
      joinedSteerGate: {
        status: "qualified",
        positiveOwnerPresentationQualification: true,
        executionDisposition: "joined-current-run",
        gateOwner: "original-logical-run-owner-not-joined-submission",
        actualSharedPublicTerminalAndHandleScope: true,
      },
      promotedFollowUpGate: {
        status: "unavailable-public-scope-correlation",
        code: "SDK_TRACKED_INPUT_GATE_OWNERSHIP",
        positiveOwnerPresentationQualification: false,
        negativeOverlapRefusalQualified: true,
        reason: "public-gate-runtime_turn_id-has-no-public-attempt-scope-mapping",
        publicTerminalBarrier: "live-prompts-must-unwind-before-AgentSession-agent_end-publication",
        delayedHandleCandidate: "unqualified-return-delay-does-not-release-SDK-live-prompt-barrier",
      },
      excludedCases: ["structured-decision-denial-builders-not-public", "accepted-incomplete-predecessor-gate",
        "global-cross-mode-FIFO", "real-provider-network-or-credentials", "positive-promoted-overlap-gate-binding"],
    });
  }
);
