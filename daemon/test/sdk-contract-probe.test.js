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
const SDK_VERSION = "0.16.6";
const CHILD_TIMEOUT_MS = 25_000;
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
  let lastError;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      await rm(root, { recursive: true, force: true });
      return;
    } catch (error) {
      lastError = error;
      if (error?.code !== "EBUSY" && error?.code !== "EPERM") throw error;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
    }
  }
  throw lastError;
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

test(
  "SDK 0.16.6 real AgentSession contracts contain live controls and govern gates, failures, and disposal",
  { timeout: 30_000 },
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
        "SDK_0_16_6_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
        "SDK_0_16_6_QUEUED_CONTROL_OWNERSHIP_REQUIRES_INTERNAL_HOOKS",
      ],
    });
    assert.deepEqual(receipt.historicalProvenance, {
      oracleOriginSdkVersion: "0.16.4",
      originalReasonCode:
        "SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
      upstreamIssue: 5351,
      upstreamFixPullRequest: 5371,
      upstreamFixBranch: "dev",
      upstreamFixPublishedInObservedVersion: false,
    });
    assert.deepEqual(receipt.environment, {
      credentialVariableCount: 0,
      networkAttempts: 0,
      settingsAndStateOwnedByFixture: true,
    });
    assert.equal(existsSync(root), false, "parent wrapper did not remove its fixture root");
    assert.deepEqual(receipt.cleanup, {
      harnessCount: 4,
      sdkResourcesClosed: true,
      modelCacheStates: ["closed", "closed", "closed", "closed"],
      filesystemRemoval: {
        owner: "parent-wrapper",
        childAttempted: false,
        mustRunAfterChildExit: true,
      },
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

    // SDK 0.16.6 does not publicly export the decision-gate builders. This
    // oracle deliberately reports that boundary instead of copying a private
    // approval/execution schema and accidentally turning another fake into truth.
    assert.deepEqual(receipt.decisionGate, {
      status: "blocked",
      blockedCase: "structured_decision_denial",
      code: "SDK_0_16_6_DECISION_GATE_BUILDERS_NOT_PUBLIC",
      internalWireSubpathsBlocked: true,
      fabricatedSchemaUsed: false,
    });
    assert.deepEqual(receipt.queuedControlOwnership, {
      status: "contained",
      code:
        "SDK_0_16_6_QUEUED_CONTROL_OWNERSHIP_REQUIRES_INTERNAL_HOOKS",
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
    });
    assert.deepEqual(receipt.limitations, {
      lateFollowUpAutoContinuation: {
        status: "contained-sdk-gap",
        code: "SDK_0_16_6_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED",
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
    });
  }
);
