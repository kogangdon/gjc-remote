import "dotenv/config";
import { createHash } from "node:crypto";
import WebSocket from "ws";
import {
  CAPABILITIES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PONG,
  PROTOCOL_ERROR_CODES,
  PROTOCOL_VERSION,
  PROTOCOL_VERSION_V2,
  PROTOCOL_VERSION_V3,
  READINESS_DEFAULT_TTL_MS,
  READINESS_DIMENSIONS,
  READINESS_MAX_TTL_MS,
  READINESS_MIN_TTL_MS,
  READINESS_REMEDIATIONS,
  V0_LIMITS,
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  INVENTORY_RECEIPT_TTL_MS,
  isWorkspaceId,
  isReadinessWorkspaceGeneration,
  isAnswerMessage,
  isBindWorkspaceMessage,
  isInventoryReceiptBindWorkspaceMessage,
  isInventoryReceiptBindOkMessage,
  isInventoryReceiptCapabilityGate,
  isInventoryReceiptReadinessMessage,
  isUnbindWorkspaceMessage,
  isInvokeMessage,
  isPingMessage,
  isReadinessCapabilityGate,
  isReadinessMessage,
  isReadinessTtl,
  isRegisterDeniedMessage,
  isRegisterOkMessage,
  isWorkspaceLifecycleMessage,
  negotiateCapabilities,
  normalizeProtocolError,
} from "@gjc-remote/shared";
import { workspaceBindingFingerprint } from "@gjc-remote/shared/workspace-binding";
import { whitelistProtocolCode, formatManualCleanupLog } from "./lifecycle-wire-sanitizers.js";
import { SessionPool } from "./session-pool.js";
import { invalidateBindingRequests as disposeReplacedBindingRequests } from "./binding-fence.js";
import {
  AdmissionBudget,
  LEGACY_RESOURCE_EXHAUSTED_ERROR,
} from "./admission-budget.js";
import { modelCommandDiagnostic, setSessionModel } from "./model-command.js";
import {
  webSocketPayloadByteLength,
  webSocketPayloadToUtf8,
} from "./ws-payload.js";
import { serializeEventFrame } from "./event-frame.js";
import { findWorkspaceInventory } from "./workspace-inventory.js";
import { createWorkspaceInventoryProvider } from "./workspace-inventory-provider.js";
import { resolveInventoryProviderConfig } from "./inventory-boot-wiring.js";
import { resolveWorkspaceRecoveryConfig, runBootRecovery } from "./workspace-recovery-boot-wiring.js";
import { resolveLifecycleCreateDispatcher, resolveTrustedCreateBinding, projectServingReadiness } from "./workspace-create-boot-wiring.js";
import { resolveLifecycleRefreshDispatcher, buildRefreshLeaseCandidate } from "./workspace-refresh-boot-wiring.js";
import { resolveLifecycleResetDeleteDispatcher, buildResetDeleteLeaseCandidate } from "./workspace-reset-delete-boot-wiring.js";
import { resolveLifecycleRestoreMigrationDispatcher, buildRestoreMigrationLeaseCandidate } from "./workspace-restore-migration-boot-wiring.js";
import {
  initializeInventoryConfig,
  inventoryConfigDiagnostic,
} from "./inventory-config.js";
import {
  WorkspaceLeaseRegistry,
  DEFAULT_MAX_ACTIVE_WORKSPACES,
} from "./workspace-lease-registry.js";
import { isLeaseBoundaryRejection } from "./readiness-classification.js";
import { RequestIdFence } from "./request-id-fence.js";

import {
  parseRegisterDeniedRetryMs,
  parseShutdownTimeoutMs,
  REGISTER_DENIED_RETRY_MS,
  SHUTDOWN_TIMEOUT_DEFAULT_MS,
  sanitizeErrorMessage,
  createReconnectScheduler,
} from "./reconnect.js";
import { assertNoRemovedDevFlags } from "./workspace-removed-flags.js";

const { HOST_ID, HOST_TOKEN, HOST_LABEL, BOT_WS_URL } = process.env;

if (!HOST_ID || !HOST_TOKEN || !BOT_WS_URL) {
  console.error("Missing HOST_ID, HOST_TOKEN, or BOT_WS_URL in environment (.env).");
  process.exit(1);
}

// Fail closed at boot if a retired interim dev flag lingers in the environment
// (GJC_DEV_NATIVE_SINGLE_WRITER_LOCK / GJC_DEV_CONNECTIVITY_PROBE). Presence-based
// rejection, per-retired-gate unique diagnostic. This does NOT flip the
// native-serving boundary (that remains the human-approved S6f decision).
assertNoRemovedDevFlags(process.env);
function readBotWsUrlCredentials(value) {
  try {
    const url = new URL(value);
    return [
      url.username,
      url.password,
      ...url.searchParams.values(),
      url.hash.slice(1),
    ].filter(Boolean);
  } catch {
    return [];
  }
}

const daemonSensitiveValues = [
  HOST_TOKEN,
  ...readBotWsUrlCredentials(BOT_WS_URL),
].filter((value) => typeof value === "string" && value.length > 0);

function sanitizeDaemonError(error) {
  return sanitizeErrorMessage(error, daemonSensitiveValues);
}
const readinessV2Advertised = process.env.GJC_READINESS_V2 === "1";
const READINESS_TEST_INJECTION_ENABLED =
  process.env.GJC_READINESS_TEST_INJECTION === "1";
const nativeInventoryMode =
  `${process.env.GJC_NATIVE_INVENTORY_MODE ?? "off"}`.trim().toLowerCase();
if (nativeInventoryMode !== "off" && nativeInventoryMode !== "verify") {
  console.error("daemon: GJC_NATIVE_INVENTORY_MODE must be off or verify");
  process.exit(1);
}
// Dedicated config resolution: verify-mode failures map to a structured,
// path-free, secret-free diagnostic and terminate boot (never sanitizeDaemonError).
const inventoryConfigResult = await resolveInventoryProviderConfig(
  {
    testInjectionEnabled: READINESS_TEST_INJECTION_ENABLED,
    nativeInventoryMode,
    hostId: HOST_ID,
    platform: process.platform,
  },
  { initializeInventoryConfig, inventoryConfigDiagnostic },
);
if (inventoryConfigResult.ok !== true) {
  console.error(
    `daemon: native inventory verify configuration failed: ${JSON.stringify(inventoryConfigResult.diagnostic)}`,
  );
  process.exit(1);
}
let inventoryProvider;
let initialInventoryRead;
try {
  inventoryProvider = createWorkspaceInventoryProvider(inventoryConfigResult.providerOptions);
  initialInventoryRead = await inventoryProvider.read();
} catch (error) {
  console.error(`daemon: workspace inventory provider failed: ${sanitizeDaemonError(error)}`);
  process.exit(1);
}
const inventoryReceiptAdvertised =
  nativeInventoryMode === "verify" &&
  readinessV2Advertised &&
  inventoryProvider.receiptCapable === true;
const DAEMON_PROTOCOL_VERSION = inventoryReceiptAdvertised
  ? PROTOCOL_VERSION_V3
  : readinessV2Advertised
  ? Math.max(PROTOCOL_VERSION, PROTOCOL_VERSION_V2)
  : PROTOCOL_VERSION;
const DAEMON_CAPABILITIES = Object.freeze(
  readinessV2Advertised
    ? [...new Set([
        ...CAPABILITIES,
        WORKSPACE_READINESS_CAPABILITY,
        ...(inventoryReceiptAdvertised ? [WORKSPACE_INVENTORY_RECEIPT_CAPABILITY] : []),
      ])]
    : [...CAPABILITIES]
);

function parseReadinessTtl(value) {
  if (value === undefined) {
    return READINESS_DEFAULT_TTL_MS;
  }
  if (`${value}`.trim() === "") {
    throw new Error(
      `GJC_READINESS_TTL_MS must be an integer between ${READINESS_MIN_TTL_MS} and ${READINESS_MAX_TTL_MS}`
    );
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || !isReadinessTtl(parsed)) {
    throw new Error(
      `GJC_READINESS_TTL_MS must be an integer between ${READINESS_MIN_TTL_MS} and ${READINESS_MAX_TTL_MS}`
    );
  }
  return parsed;
}

let READINESS_TTL_MS = READINESS_DEFAULT_TTL_MS;
try {
  READINESS_TTL_MS = parseReadinessTtl(process.env.GJC_READINESS_TTL_MS);
} catch (error) {
  console.error(`daemon: invalid GJC_READINESS_TTL_MS: ${sanitizeDaemonError(error)}`);
  process.exit(1);
}

const READINESS_ERROR_CODES = new Set(Object.values(PROTOCOL_ERROR_CODES));

function readinessRemediation(code) {
  return {
    code,
    ...(READINESS_REMEDIATIONS[code] ?? {
      retryable: true,
      action: "retry_later",
    }),
  };
}

function makeReadinessError(code, at = Date.now()) {
  const stableCode = READINESS_ERROR_CODES.has(code)
    ? code
    : PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME;
  return {
    code: stableCode,
    at: Number.isSafeInteger(at) && at >= 0 ? at : Date.now(),
    remediation: readinessRemediation(stableCode),
  };
}

function classifyReadinessError(error, fallback = PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME) {
  const explicitCode = error && typeof error === "object" ? error.code : undefined;
  if (typeof explicitCode === "string" && READINESS_ERROR_CODES.has(explicitCode)) {
    return explicitCode;
  }
  const text = sanitizeDaemonError(normalizeProtocolError(error)).trim();
  if (READINESS_ERROR_CODES.has(text)) return text;
  return READINESS_ERROR_CODES.has(fallback)
    ? fallback
    : PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME;
}

const NATIVE_WORKSPACE_SERVING_ENABLED = false;
// S6f.1: workspaces barred by boot crash-recovery; consulted by the serving-admission gate (dead code until S6f.7). Empty until GJC_NATIVE_WORKSPACE_ROOT is set.
let barredWorkspaceIds = new Set();
const MAX_BINDINGS_PER_SOCKET = 64;
const localWorkspaceInventory =
  initialInventoryRead?.status === "present" ? initialInventoryRead.inventory : undefined;

// issue #184: emit the sanitized manual_cleanup checkpoint log (partial-CAS
// operator reconciliation signal) when a lifecycle result carries one. The
// formatting is a pure, unit-tested helper; only the console.error side effect
// lives here.
function surfaceManualCleanup(msg, result) {
  const line = formatManualCleanupLog(msg, result);
  if (line) console.error(line);
}

function readReadinessTestEvidence() {
  if (!READINESS_TEST_INJECTION_ENABLED) return undefined;
  const probe = `${process.env.GJC_READINESS_TEST_PROBE ?? "fail"}`
    .trim()
    .toLowerCase();
  const workspaceId = `${process.env.GJC_READINESS_TEST_WORKSPACE_ID ?? ""}`.trim();
  const workspaceGeneration = Number(
    `${process.env.GJC_READINESS_TEST_WORKSPACE_GENERATION ?? ""}`.trim()
  );
  const mappingId = `${process.env.GJC_READINESS_TEST_MAPPING_ID ?? ""}`.trim();
  const mappingGeneration = Number(
    `${process.env.GJC_READINESS_TEST_MAPPING_GENERATION ?? ""}`.trim()
  );
  const mappingVersion = Number(
    `${process.env.GJC_READINESS_TEST_MAPPING_VERSION ?? ""}`.trim()
  );
  const workDir = `${process.env.GJC_READINESS_TEST_WORK_DIR ?? ""}`.trim();
  const mapping =
    isWorkspaceId(workspaceId) &&
    isReadinessWorkspaceGeneration(workspaceGeneration) &&
    isWorkspaceId(mappingId) &&
    isReadinessWorkspaceGeneration(mappingGeneration) &&
    isReadinessWorkspaceGeneration(mappingVersion) &&
    workDir.length > 0
      ? {
          workspaceId,
          workspaceGeneration,
          mappingId,
          mappingGeneration,
          mappingVersion,
          workDir,
        }
      : undefined;
  return Object.freeze({
    probe,
    probeErrorCode: `${process.env.GJC_READINESS_TEST_PROBE_ERROR_CODE ?? ""}`.trim(),
    mapping,
    staticSecurity:
      `${process.env.GJC_READINESS_TEST_SECURITY ?? "pass"}`.trim().toLowerCase(),
  });
}

const readinessTestEvidence = readReadinessTestEvidence();

function runStaticSecurityPreflight() {
  const result = {
    connection: "offline",
    runtime: "ready",
    providerAuth: "missing",
    modelProfile: "missing",
    workspace: "unknown",
    errors: [],
  };
  if (readinessTestEvidence && readinessTestEvidence.staticSecurity !== "pass") {
    result.runtime = "incompatible";
    result.errors.push(PROTOCOL_ERROR_CODES.CONFIG_INVALID);
  }
  const controlCharacters = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
  if (
    HOST_ID.length > V0_LIMITS.HOST_ID ||
    HOST_TOKEN.length > V0_LIMITS.TOKEN ||
    controlCharacters.test(HOST_ID) ||
    controlCharacters.test(HOST_TOKEN)
  ) {
    result.runtime = "incompatible";
    result.errors.push(PROTOCOL_ERROR_CODES.CONFIG_INVALID);
  }
  try {
    const url = new URL(BOT_WS_URL);
    if (url.protocol !== "ws:" && url.protocol !== "wss:") {
      result.runtime = "incompatible";
      result.errors.push(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE);
    }
  } catch {
    result.runtime = "error";
    result.errors.push(PROTOCOL_ERROR_CODES.CONFIG_INVALID);
  }
  if (readinessTestEvidence?.mapping) {
    result.workspace = "unknown";
  }
  return {
    ...result,
    workspaceId: readinessTestEvidence?.mapping?.workspaceId,
    workspaceGeneration: readinessTestEvidence?.mapping?.workspaceGeneration,
    mappingId: readinessTestEvidence?.mapping?.mappingId,
    mappingGeneration: readinessTestEvidence?.mapping?.mappingGeneration,
    mappingVersion: readinessTestEvidence?.mapping?.mappingVersion,
    workDir: readinessTestEvidence?.mapping?.workDir,
  };
}

const staticReadiness = runStaticSecurityPreflight();

let registerDeniedRetryMs = REGISTER_DENIED_RETRY_MS;
try {
  registerDeniedRetryMs = parseRegisterDeniedRetryMs(
    process.env.GJC_REGISTER_DENIED_RETRY_MS
  );
} catch (error) {
  console.error(
    `daemon: invalid GJC_REGISTER_DENIED_RETRY_MS: ${sanitizeDaemonError(error)}`
  );
  process.exit(1);
}

let DAEMON_SHUTDOWN_TIMEOUT_MS = SHUTDOWN_TIMEOUT_DEFAULT_MS;
try {
  DAEMON_SHUTDOWN_TIMEOUT_MS = parseShutdownTimeoutMs(
    process.env.GJC_SHUTDOWN_TIMEOUT_MS
  );
} catch (error) {
  console.error(
    `daemon: invalid GJC_SHUTDOWN_TIMEOUT_MS: ${sanitizeDaemonError(error)}`
  );
  process.exit(1);
}

const pool = new SessionPool({ sensitiveValues: daemonSensitiveValues });
const admissionBudget = new AdmissionBudget();
const workspaceLeases = new WorkspaceLeaseRegistry({
  maxActiveWorkspaces: DEFAULT_MAX_ACTIVE_WORKSPACES,
});
const requestIds = new RequestIdFence();
// #35: map an in-flight invoke's requestId to its SdkSession so an ANSWER frame
// (which arrives as a separate message while the invoke is blocked on a gate)
// can be routed to the session that owns the pending gate.
const inFlightByRequestId = new Map();
const connections = new Set();
let shuttingDown = false;
let shutdownPromise = null;
let shutdownExitCode = null;
let readinessSocketGeneration = 0;
const readinessByConnection = new WeakMap();

// --- Live provider refresh and atomic invalidation (verify mode) ---------
// The daemon proves each positive receipt against a durable inventory snapshot
// at bind time. A background poll re-verifies that the snapshot has not drifted,
// expired, or become unreadable. Any change performs an ordered atomic cascade
// that retires every derived binding, lease, and in-flight request and closes
// the socket. Serving stays hard-false, so these fences prepare rather than
// authorize serving; no SDK session is ever created while the gate is closed.
const INVENTORY_SNAPSHOT_TTL_MS = Math.min(10_000, INVENTORY_RECEIPT_TTL_MS);
const INVENTORY_POLL_DEFAULT_MS = 5_000;

// Snapshot-age comparisons use a monotonic clock so a forward wall-clock jump
// (NTP step, host suspend/resume) larger than the TTL cannot spuriously age a
// still-fresh verified snapshot and trigger an unnecessary cascade. The stamp
// and the age comparison MUST share this source to stay coherent.
function monotonicNowMs() {
  return performance.now();
}

function parseInventoryPollMs(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 60_000) {
    throw new RangeError("GJC_INVENTORY_POLL_MS must be an integer in [1, 60000]");
  }
  return parsed;
}

let INVENTORY_POLL_MS = INVENTORY_POLL_DEFAULT_MS;
if (READINESS_TEST_INJECTION_ENABLED && process.env.GJC_INVENTORY_POLL_MS !== undefined) {
  try {
    INVENTORY_POLL_MS = parseInventoryPollMs(process.env.GJC_INVENTORY_POLL_MS);
  } catch (error) {
    console.error(`daemon: invalid GJC_INVENTORY_POLL_MS: ${sanitizeDaemonError(error)}`);
    process.exit(1);
  }
}

// Serialize boot/read-before-bind/poll/read-before-admission provider reads
// under one mutex so concurrent operations never observe a torn read.
let inventoryReadMutex = Promise.resolve();
function serializedInventoryRead() {
  const result = inventoryReadMutex.then(() => inventoryProvider.read());
  inventoryReadMutex = result.then(() => undefined, () => undefined);
  return result;
}

// Monotonic epoch bumped once per atomic cascade. A session-creation recheck
// compares the epoch it captured before creation against the current epoch.
let providerEpoch = 0;
let inventoryCascading = false;
let inventoryPollTimer = undefined;
let inventoryPollInFlight = false;
let inventorySnapshot = undefined;

function hasReceiptCommittedConnection() {
  for (const connection of connections) {
    if (readinessByConnection.get(connection)?.receiptCommitted) return true;
  }
  return false;
}

function hasActiveReceiptBindings() {
  for (const connection of connections) {
    const state = readinessByConnection.get(connection);
    if (state?.committed && state.receiptCommitted && state.bindings.size > 0) {
      return true;
    }
  }
  return false;
}

// Every committed positive receipt binding proved against a specific inventory
// generation/fingerprint. The poll re-verifies the live read against these
// authoritative proofs so drift that landed before the poll's own baseline was
// taken (e.g. between a positive bind and the first tick) is still caught.
function collectCommittedReceiptProofs() {
  const proofs = [];
  for (const connection of connections) {
    const state = readinessByConnection.get(connection);
    if (!state?.committed || !state.receiptCommitted) continue;
    for (const [, bindingState] of state.bindings) {
      if (bindingState.proof) proofs.push(bindingState.proof);
    }
  }
  return proofs;
}

function ensureInventoryPollStarted() {
  if (!inventoryReceiptAdvertised || inventoryPollTimer || shuttingDown) return;
  inventoryPollTimer = setInterval(() => {
    void runInventoryPoll();
  }, INVENTORY_POLL_MS);
  inventoryPollTimer.unref?.();
}

function stopInventoryPoll() {
  if (inventoryPollTimer) {
    clearInterval(inventoryPollTimer);
    inventoryPollTimer = undefined;
  }
  inventorySnapshot = undefined;
}

function maybeStopInventoryPoll() {
  if (!hasReceiptCommittedConnection()) stopInventoryPoll();
}

async function runInventoryPoll() {
  if (inventoryPollInFlight || inventoryCascading || shuttingDown) return;
  if (!hasActiveReceiptBindings()) {
    inventorySnapshot = undefined;
    return;
  }
  inventoryPollInFlight = true;
  try {
    const now = monotonicNowMs();
    if (inventorySnapshot && now - inventorySnapshot.verifiedAt > INVENTORY_SNAPSHOT_TTL_MS) {
      await cascadeInventoryInvalidation(PROTOCOL_ERROR_CODES.INVENTORY_STALE);
      return;
    }
    let read;
    try {
      read = await serializedInventoryRead();
    } catch {
      await cascadeInventoryInvalidation(PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED);
      return;
    }
    if (read?.status !== "present") {
      await cascadeInventoryInvalidation(
        receiptInventoryError(read) ?? PROTOCOL_ERROR_CODES.INVENTORY_STALE
      );
      return;
    }
    // Authoritative drift: the live read must still match every committed
    // positive binding's proof. This closes the window where drift occurs
    // between a positive bind and the poll's first baseline tick.
    for (const proof of collectCommittedReceiptProofs()) {
      if (
        read.inventory.inventoryGeneration !== proof.inventoryGeneration ||
        read.inventory.inventoryFingerprint !== proof.inventoryFingerprint
      ) {
        await cascadeInventoryInvalidation(PROTOCOL_ERROR_CODES.INVENTORY_STALE);
        return;
      }
    }
    const fingerprint = {
      epoch: read.epoch,
      inventoryGeneration: read.inventory.inventoryGeneration,
      inventoryFingerprint: read.inventory.inventoryFingerprint,
    };
    if (
      inventorySnapshot &&
      (inventorySnapshot.epoch !== fingerprint.epoch ||
        inventorySnapshot.inventoryGeneration !== fingerprint.inventoryGeneration ||
        inventorySnapshot.inventoryFingerprint !== fingerprint.inventoryFingerprint)
    ) {
      await cascadeInventoryInvalidation(PROTOCOL_ERROR_CODES.INVENTORY_STALE);
      return;
    }
    inventorySnapshot = { ...fingerprint, verifiedAt: monotonicNowMs() };
  } finally {
    inventoryPollInFlight = false;
  }
}

// Atomic invalidation cascade. Order (per plan section 7): set provider
// invalidating; invalidate the WorkspaceLeaseRegistry; dispose each binding's
// in-flight requests; await exact-bound session disposal; emit one bounded
// negative frame if safe; close the socket and require fresh registration.
async function cascadeInventoryInvalidation(code) {
  if (inventoryCascading) return;
  inventoryCascading = true;
  providerEpoch += 1;
  inventorySnapshot = undefined;
  try {
    workspaceLeases.invalidateAll();
    const disposals = [];
    for (const connection of [...connections]) {
      const state = readinessByConnection.get(connection);
      if (!state) continue;
      clearReadinessTimer(state);
      // Fence receipt commits synchronously (before the disposal await) so a
      // bind resuming mid-cascade fails its currentReceiptBinding() re-check
      // and never commits a proof/BIND_OK against retired inventory.
      state.receiptCommitted = false;
      for (const [, bindingState] of state.bindings) {
        invalidateBindingRequests(state, bindingState);
        disposals.push(
          Promise.resolve(retireReceiptSession(state, bindingState)).catch(() => {})
        );
        bindingState.ready = false;
        bindingState.phase = "negative";
        bindingState.proof = undefined;
        bindingState.lastError = makeReadinessError(code);
      }
    }
    await Promise.all(disposals);
    for (const connection of [...connections]) {
      const state = readinessByConnection.get(connection);
      if (!state) continue;
      try {
        publishReadiness(state);
      } catch {}
      state.committed = false;
      state.receiptCommitted = false;
      try {
        connection.close(1013, "inventory retired");
      } catch {}
    }
  } finally {
    inventoryCascading = false;
    stopInventoryPoll();
  }
}

function bindingFingerprint(binding) {
  return createHash("sha256")
    .update(
      JSON.stringify([
        binding.bindingId,
        binding.hostId,
        binding.mappingId,
        binding.mappingGeneration,
        binding.mappingVersion,
        binding.workspaceId,
        binding.workspaceGeneration,
        binding.sourcePlatform,
        binding.routeFingerprint,
        binding.authorityFingerprint,
        binding.inventoryGeneration,
      ])
    )
    .digest("hex");
}

const BINDING_IDENTITY_FIELDS = [
  "bindingId",
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "routeFingerprint",
  "authorityFingerprint",
  "inventoryGeneration",
];
const BINDING_AUTHORITY_FIELDS = BINDING_IDENTITY_FIELDS.filter(
  (field) => field !== "bindingId" && field !== "inventoryGeneration"
);

function hasBindingGenerationRegression(previous, candidate) {
  return (
    candidate.mappingGeneration < previous.mappingGeneration ||
    candidate.workspaceGeneration < previous.workspaceGeneration ||
    candidate.inventoryGeneration < previous.inventoryGeneration
  );
}

function sameBindingFields(previous, candidate, fields = BINDING_IDENTITY_FIELDS) {
  return fields.every((field) => previous[field] === candidate[field]);
}

function invalidateBindingRequests(state, bindingState) {
  if (!bindingState) return;
  bindingState.invalidated = true;
  disposeReplacedBindingRequests(
    inFlightByRequestId,
    state.connection,
    bindingState.binding.bindingId
  );
}

function currentBindingState(state, bindingState, fingerprint) {
  return (
    state?.committed === true &&
    state?.bindings.get(bindingState?.binding.bindingId) === bindingState &&
    !bindingState.invalidated &&
    (bindingState.receipt
      ? bindingState.proof?.bindingFingerprint === fingerprint
      : bindingFingerprint(bindingState.binding) === fingerprint)
  );
}

function receiptActivityIdentity(state, bindingState) {
  const bindingFingerprintValue = bindingState?.proof?.bindingFingerprint;
  if (
    !bindingState?.receipt ||
    !Number.isSafeInteger(state?.socketGeneration) ||
    state.socketGeneration < 1 ||
    typeof bindingState.binding.bindingId !== "string" ||
    !/^[0-9a-f]{64}$/.test(bindingFingerprintValue ?? "")
  ) {
    return undefined;
  }
  return Object.freeze({
    socketGeneration: state.socketGeneration,
    bindingId: bindingState.binding.bindingId,
    bindingFingerprint: bindingFingerprintValue,
  });
}

function retireReceiptSession(state, bindingState) {
  const workDir = bindingState?.inventoryWorkspace?.workDir;
  const identity = receiptActivityIdentity(state, bindingState);
  if (!workDir || !identity) return Promise.resolve(true);
  return pool.retireManagedReceipt(workDir, identity).then(
    () => true,
    (error) => {
      console.error(
        `daemon: failed to retire receipt session: ${sanitizeDaemonError(error)}`
      );
      return false;
    }
  );
}

function nextReadinessSocketGeneration() {
  readinessSocketGeneration =
    readinessSocketGeneration >= Number.MAX_SAFE_INTEGER
      ? 1
      : readinessSocketGeneration + 1;
  return readinessSocketGeneration;
}

function createReadinessState(connection) {
  const staticErrorCode =
    staticReadiness.errors.find((code) => READINESS_ERROR_CODES.has(code)) ??
    (staticReadiness.runtime === "error"
      ? PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME
      : staticReadiness.runtime !== "ready"
        ? PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE
        : staticReadiness.providerAuth === "invalid"
          ? PROTOCOL_ERROR_CODES.PROVIDER_INVALID
          : staticReadiness.providerAuth === "unknown"
            ? PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE
            : staticReadiness.providerAuth !== "configured"
              ? PROTOCOL_ERROR_CODES.PROVIDER_MISSING
              : staticReadiness.modelProfile === "invalid"
                ? PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID
                : staticReadiness.modelProfile === "unknown"
                  ? PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE
                  : staticReadiness.modelProfile !== "ready"
                    ? PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING
                    : undefined);
  const state = {
    connection,
    socketGeneration: nextReadinessSocketGeneration(),
    revision: 0,
    committed: false,
    handshakeAccepted: false,
    probeStarted: false,
    probePassed: false,
    timer: undefined,
    status: {
      connection: "offline",
      runtime: staticReadiness.runtime,
      providerAuth: staticReadiness.providerAuth,
      modelProfile: staticReadiness.modelProfile,
      workspace: staticReadiness.workspace,
    },
    mappingId: staticReadiness.mappingId,
    mappingGeneration: staticReadiness.mappingGeneration,
    mappingVersion: staticReadiness.mappingVersion,
    mappingWorkDir: staticReadiness.workDir,
    workspaceKey: undefined,
    workspaceId: staticReadiness.workspaceId,
    workspaceGeneration: staticReadiness.workspaceGeneration,
    bindings: new Map(),
    retiredBindings: new Map(),
    receiptWorkspaceFloors: new Map(),
    receiptCommitted: false,
    receiptUnbound: false,
    lastError: staticErrorCode ? makeReadinessError(staticErrorCode) : undefined,
  };
  readinessByConnection.set(connection, state);
  return state;
}

function receiptAuthority(message) {
  const {
    authorityEpoch,
    fenceGeneration,
    hostId,
    mappingId,
    mappingGeneration,
    mappingVersion,
    workspaceId,
    workspaceGeneration,
    sourcePlatform,
    authorityFingerprint,
  } = message;
  return {
    authorityEpoch,
    fenceGeneration,
    hostId,
    mappingId,
    mappingGeneration,
    workspaceGeneration,
    mappingVersion,
    sourcePlatform,
    workspaceId,
    authorityFingerprint,
  };
}

function sameReceiptBinding(left, right) {
  return JSON.stringify(receiptAuthority(left)) === JSON.stringify(receiptAuthority(right));
}

function receiptInventoryError(read) {
  if (read?.status === "missing" || read?.status === "transient") {
    return PROTOCOL_ERROR_CODES.INVENTORY_PENDING;
  }
  if (read?.status === "present") return PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND;
  return classifyReadinessError(read, PROTOCOL_ERROR_CODES.INVENTORY_INVALID);
}

const RECEIPT_AUTHORITY_GENERATIONS = [
  "authorityEpoch",
  "fenceGeneration",
  "mappingGeneration",
  "workspaceGeneration",
];
const RECEIPT_AUTHORITY_IDENTITY = [
  "hostId",
  "mappingId",
  "mappingVersion",
  "sourcePlatform",
  "workspaceId",
  "authorityFingerprint",
];

function reserveReceiptAuthorityFloor(state, binding) {
  const candidate = receiptAuthority(binding);
  const floor = state.receiptWorkspaceFloors.get(candidate.workspaceId);
  let generationAdvanced = false;
  if (floor) {
    if (RECEIPT_AUTHORITY_GENERATIONS.some(
      (field) => candidate[field] < floor[field]
    )) return false;
    generationAdvanced = RECEIPT_AUTHORITY_GENERATIONS.some(
      (field) => candidate[field] > floor[field]
    );
    if (
      !generationAdvanced &&
      RECEIPT_AUTHORITY_IDENTITY.some((field) => candidate[field] !== floor[field])
    ) return false;
    if (
      !generationAdvanced &&
      [...state.bindings.values()].some(
        (bindingState) =>
          bindingState.binding.workspaceId === candidate.workspaceId &&
          bindingState.binding.bindingId !== binding.bindingId
      )
    ) return false;
  }
  if (generationAdvanced) {
    for (const bindingState of [...state.bindings.values()]) {
      if (bindingState.binding.workspaceId === candidate.workspaceId) {
        retireSupersededReceiptBinding(state, bindingState);
      }
    }
  }
  state.receiptWorkspaceFloors.set(candidate.workspaceId, Object.freeze({
    ...candidate,
    inventoryGeneration: floor?.inventoryGeneration,
    inventoryFingerprint: floor?.inventoryFingerprint,
  }));
  return true;
}

function acceptReceiptInventoryFloor(state, binding, inventory) {
  const floor = state.receiptWorkspaceFloors.get(binding.workspaceId);
  if (!floor) return false;
  if (
    floor.inventoryGeneration !== undefined &&
    inventory.inventoryGeneration < floor.inventoryGeneration
  ) return false;
  if (
    inventory.inventoryGeneration === floor.inventoryGeneration &&
    inventory.inventoryFingerprint !== floor.inventoryFingerprint
  ) return false;
  state.receiptWorkspaceFloors.set(binding.workspaceId, Object.freeze({
    ...floor,
    inventoryGeneration: inventory.inventoryGeneration,
    inventoryFingerprint: inventory.inventoryFingerprint,
  }));
  return true;
}

function currentReceiptBinding(state, bindingState) {
  return state?.receiptCommitted === true &&
    connections.has(state.connection) &&
    state.bindings.get(bindingState.binding.bindingId) === bindingState &&
    !bindingState.invalidated;
}

function ownsReceiptAuthorityFloor(state, binding) {
  const floor = state.receiptWorkspaceFloors.get(binding.workspaceId);
  const authority = receiptAuthority(binding);
  return floor !== undefined &&
    [...RECEIPT_AUTHORITY_GENERATIONS, ...RECEIPT_AUTHORITY_IDENTITY].every(
      (field) => floor[field] === authority[field]
    );
}

function retireSupersededReceiptBinding(state, bindingState) {
  if (state.bindings.get(bindingState.binding.bindingId) !== bindingState) return;
  state.bindings.delete(bindingState.binding.bindingId);
  bindingState.invalidated = true;
  invalidateBindingRequests(state, bindingState);
  if (bindingState.proof) {
    workspaceLeases.retireBinding({
      ...receiptAuthority(bindingState.binding),
      ...bindingState.proof,
      socketGeneration: state.socketGeneration,
      bindingId: bindingState.binding.bindingId,
    });
    bindingState.retirement = retireReceiptSession(state, bindingState);
  }
  state.retiredBindings.set(bindingState.binding.bindingId, bindingState);
}

async function acceptReceiptBinding(state, message) {
  if (!state?.receiptCommitted || message.hostId !== HOST_ID) return false;
  const existing = state.bindings.get(message.bindingId) ??
    state.retiredBindings.get(message.bindingId);
  if (existing) {
    if (state.retiredBindings.get(message.bindingId) === existing) return false;
    if (!sameReceiptBinding(existing.binding, message)) return false;
    if (state.bindings.get(message.bindingId) === existing && existing.proof) {
      connectionSendBindOk(state.connection, message.bindingId, existing.proof);
    }
    return true;
  }
  if (state.bindings.size + state.retiredBindings.size >= MAX_BINDINGS_PER_SOCKET) return false;
  if (!reserveReceiptAuthorityFloor(state, message)) return false;

  const binding = Object.freeze({ ...message });
  const bindingState = {
    binding,
    inventoryWorkspace: undefined,
    proof: undefined,
    ready: false,
    lastError: makeReadinessError(PROTOCOL_ERROR_CODES.INVENTORY_PENDING),
    receipt: true,
    invalidated: false,
    phase: "pending",
  };
  state.bindings.set(message.bindingId, bindingState);
  state.receiptUnbound = false;
  publishReadiness(state);

  let first;
  try {
    first = await serializedInventoryRead();
  } catch (error) {
    if (!currentReceiptBinding(state, bindingState)) return true;
    bindingState.phase = "negative";
    bindingState.lastError = makeReadinessError(
      classifyReadinessError(error, PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED)
    );
    publishReadiness(state);
    return true;
  }
  if (!currentReceiptBinding(state, bindingState)) return true;
  if (!ownsReceiptAuthorityFloor(state, binding)) {
    retireSupersededReceiptBinding(state, bindingState);
    return true;
  }
  let inventoryWorkspace;
  let proof;
  let errorCode = receiptInventoryError(first);
  if (first?.status === "present") {
    inventoryWorkspace = first.inventory.workspaces.find((workspace) =>
      workspace.hostId === message.hostId &&
      workspace.workspaceId === message.workspaceId &&
      workspace.sourcePlatform === message.sourcePlatform
    );
    if (inventoryWorkspace) {
      let second;
      try {
        second = await serializedInventoryRead();
      } catch (error) {
        if (!currentReceiptBinding(state, bindingState)) return true;
        second = {
          status: "error",
          code: classifyReadinessError(
            error,
            PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED
          ),
        };
      }
      if (!currentReceiptBinding(state, bindingState)) return true;
      if (!ownsReceiptAuthorityFloor(state, binding)) {
        retireSupersededReceiptBinding(state, bindingState);
        return true;
      }
      if (second?.status !== "present") {
        errorCode = receiptInventoryError(second);
      } else if (second.epoch !== first.epoch) {
        errorCode = PROTOCOL_ERROR_CODES.INVENTORY_PENDING;
      } else if (
        second.inventory.inventoryGeneration !== first.inventory.inventoryGeneration ||
        second.inventory.inventoryFingerprint !== first.inventory.inventoryFingerprint
      ) {
        errorCode = PROTOCOL_ERROR_CODES.INVENTORY_STALE;
      } else if (!acceptReceiptInventoryFloor(state, message, first.inventory)) {
        errorCode = PROTOCOL_ERROR_CODES.INVENTORY_STALE;
      } else {
        proof = Object.freeze({
          inventoryGeneration: first.inventory.inventoryGeneration,
          inventoryFingerprint: first.inventory.inventoryFingerprint,
          bindingFingerprint: workspaceBindingFingerprint({
            authority: receiptAuthority(message),
            inventoryGeneration: first.inventory.inventoryGeneration,
            inventoryFingerprint: first.inventory.inventoryFingerprint,
          }),
        });
      }
    } else {
      let second;
      try {
        second = await serializedInventoryRead();
      } catch (error) {
        if (!currentReceiptBinding(state, bindingState)) return true;
        second = {
          status: "error",
          code: classifyReadinessError(
            error,
            PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED
          ),
        };
      }
      if (!currentReceiptBinding(state, bindingState)) return true;
      if (!ownsReceiptAuthorityFloor(state, binding)) {
        retireSupersededReceiptBinding(state, bindingState);
        return true;
      }
      if (second?.status !== "present") {
        errorCode = receiptInventoryError(second);
      } else if (second.epoch !== first.epoch) {
        errorCode = PROTOCOL_ERROR_CODES.INVENTORY_PENDING;
      } else if (
        second.inventory.inventoryGeneration !== first.inventory.inventoryGeneration ||
        second.inventory.inventoryFingerprint !== first.inventory.inventoryFingerprint ||
        !acceptReceiptInventoryFloor(state, message, first.inventory)
      ) {
        errorCode = PROTOCOL_ERROR_CODES.INVENTORY_STALE;
      }
    }
  }
  if (!currentReceiptBinding(state, bindingState)) return true;
  if (!ownsReceiptAuthorityFloor(state, binding)) {
    retireSupersededReceiptBinding(state, bindingState);
    return true;
  }
  bindingState.inventoryWorkspace = inventoryWorkspace;
  bindingState.proof = proof;
  bindingState.phase = proof ? "positive" : "negative";
  bindingState.lastError = proof ? undefined : makeReadinessError(errorCode);
  if (
    proof &&
    !workspaceLeases.adoptBinding({
      ...receiptAuthority(message),
      ...proof,
      socketGeneration: state.socketGeneration,
      bindingId: message.bindingId,
    })
  ) {
    bindingState.proof = undefined;
    bindingState.phase = "negative";
    bindingState.lastError = makeReadinessError(PROTOCOL_ERROR_CODES.INVENTORY_STALE);
    proof = undefined;
  }
  if (proof) {
    // Seed the poll baseline from the read this binding proved against so the
    // very first poll tick compares the live read against the proven state
    // rather than against a self-referential re-read.
    if (!inventorySnapshot) {
      inventorySnapshot = {
        epoch: first.epoch,
        inventoryGeneration: proof.inventoryGeneration,
        inventoryFingerprint: proof.inventoryFingerprint,
        verifiedAt: monotonicNowMs(),
      };
    }
    connectionSendBindOk(state.connection, message.bindingId, proof);
    // Receipt bindings always expose the pre-probe observation, even when a
    // probe completed between registration and bind delivery.
    publishReadiness(state);
    queueMicrotask(() => {
      if (state.bindings.get(message.bindingId) !== bindingState) return;
      promoteWorkspaceIfProven(state, bindingState);
      publishReadiness(state);
    });
  } else {
    publishReadiness(state);
  }
  return true;
}

function connectionSendBindOk(connection, bindingId, proof) {
  const frame = {
    type: MSG_TYPES.BIND_OK,
    bindingId,
    inventoryGeneration: proof.inventoryGeneration,
    inventoryFingerprint: proof.inventoryFingerprint,
    bindingFingerprint: proof.bindingFingerprint,
  };
  if (isInventoryReceiptBindOkMessage(frame)) connection.send(JSON.stringify(frame));
}

async function unbindReceiptBinding(state, bindingId) {
  const bindingState = state?.bindings.get(bindingId);
  if (!bindingState) {
    const retired = state?.retiredBindings.get(bindingId);
    if (!retired) return false;
    return retired.retirement ? await retired.retirement : true;
  }
  state.bindings.delete(bindingId);
  bindingState.invalidated = true;
  invalidateBindingRequests(state, bindingState);
  state.retiredBindings.set(bindingId, bindingState);
  if (bindingState.proof) {
    workspaceLeases.retireBinding({
      ...receiptAuthority(bindingState.binding),
      ...bindingState.proof,
      socketGeneration: state.socketGeneration,
      bindingId: bindingState.binding.bindingId,
    });
    bindingState.retirement = retireReceiptSession(state, bindingState);
    if (!(await bindingState.retirement)) return false;
  }
  if (state.bindings.size === 0) state.receiptUnbound = true;
  return true;
}

function acceptWorkspaceBinding(state, message) {
  if (
    !state?.committed ||
    message.hostId !== HOST_ID ||
    message.workspaceId === undefined
  ) {
    return false;
  }
  const previousState = state.bindings.get(message.bindingId);
  const previous = previousState?.binding;
  if (previous) {
    if (sameBindingFields(previous, message)) return true;
    // A bindingId is immutable for the lifetime of a socket. Reusing it for
    // another identity would make replayed bind receipts indistinguishable
    // from an authorized remap.
    return false;
  }
  if (!previousState && state.bindings.size >= MAX_BINDINGS_PER_SOCKET) return false;

  const previousWorkspaceState = [...state.bindings.values()].find(
    (candidate) => candidate.binding.workspaceId === message.workspaceId
  );
  if (previousWorkspaceState) {
    const previousWorkspace = previousWorkspaceState.binding;
    if (hasBindingGenerationRegression(previousWorkspace, message)) return false;

    const authorityChanged = !sameBindingFields(
      previousWorkspace,
      message,
      BINDING_AUTHORITY_FIELDS
    );
    const mappingGenerationAdvanced =
      message.mappingGeneration > previousWorkspace.mappingGeneration ||
      message.workspaceGeneration > previousWorkspace.workspaceGeneration;
    const inventoryGenerationAdvanced =
      message.inventoryGeneration > previousWorkspace.inventoryGeneration;
    if (!mappingGenerationAdvanced && !inventoryGenerationAdvanced) return false;
    if (authorityChanged && !mappingGenerationAdvanced) return false;
    if (!workspaceLeases.adoptBinding(message)) return false;

    // A workspace has one active binding per socket. Replace the old receipt
    // only after the new identity passes monotonic fencing; old invokes are
    // disposed and can no longer cross the remap boundary.
    state.bindings.delete(previousWorkspace.bindingId);
    invalidateBindingRequests(state, previousWorkspaceState);
  } else if (!workspaceLeases.adoptBinding(message)) {
    return false;
  }

  const binding = Object.freeze({ ...message });
  const inventoryWorkspace = findWorkspaceInventory(localWorkspaceInventory, message);
  state.bindings.set(message.bindingId, {
    binding,
    inventoryWorkspace,
    ready: false,
    lastError: makeReadinessError(
      localWorkspaceInventory !== undefined && inventoryWorkspace === undefined
        ? PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND
        : PROTOCOL_ERROR_CODES.INVENTORY_PENDING
    ),
  });
  // Binding acceptance is intentionally separate from readiness. The daemon
  // still needs a verified local inventory match before it can serve.
  promoteWorkspaceIfProven(state, state.bindings.get(message.bindingId));
  return true;
}

function promoteWorkspaceIfProven(state, bindingState) {
  if (!state?.probePassed || !bindingState?.inventoryWorkspace) return false;
  if (bindingState.receipt === true && !bindingState.proof) return false;
  bindingState.ready = true;
  bindingState.lastError = undefined;
  return true;
}

function clearReadinessTimer(state) {
  if (!state?.timer) return;
  clearInterval(state.timer);
  state.timer = undefined;
}

function readinessFrame(state, bindingState = undefined) {
  const binding = bindingState?.binding;
  const ready = bindingState?.ready ?? state.status.workspace === "ready";
  const receiptBinding = bindingState?.receipt === true;
  const ttlMs = receiptBinding ? INVENTORY_RECEIPT_TTL_MS : READINESS_TTL_MS;
  const frame = {
    type: MSG_TYPES.READINESS,
    socketGeneration: state.socketGeneration,
    revision: state.revision + 1,
    observedAt: Date.now(),
    ttlMs,
    status: Object.fromEntries(
      READINESS_DIMENSIONS.map((dimension) => [
        dimension,
        dimension === "workspace"
          ? (ready ? "ready" : "unknown")
          : state.status[dimension],
      ])
    ),
    expiresAt: Date.now() + ttlMs,
  };
  if (binding) {
    frame.bindingId = binding.bindingId;
    frame.workspaceId = binding.workspaceId;
    frame.workspaceGeneration = binding.workspaceGeneration;
  } else if (state.workspaceId !== undefined && state.workspaceGeneration !== undefined) {
    frame.workspaceId = state.workspaceId;
    frame.workspaceGeneration = state.workspaceGeneration;
  }
  if (receiptBinding && bindingState.proof) {
    frame.inventoryGeneration = bindingState.proof.inventoryGeneration;
    frame.inventoryFingerprint = bindingState.proof.inventoryFingerprint;
    frame.bindingFingerprint = bindingState.proof.bindingFingerprint;
  }
  const lastError = receiptBinding
    ? bindingState.lastError
    : bindingState?.lastError ?? state.lastError;
  if (lastError) frame.lastError = lastError;
  return frame;
}

function publishReadiness(state) {
  if (!state?.committed || !connections.has(state.connection)) return false;
  if (state.receiptCommitted && state.receiptUnbound && state.bindings.size === 0) {
    return true;
  }
  if (
    state.connection.readyState !== undefined &&
    state.connection.readyState !== WebSocket.OPEN
  ) {
    return false;
  }
  const records = state.bindings.size > 0
    ? [...state.bindings.values()]
    : [undefined];
  try {
    for (const bindingState of records) {
      const frame = readinessFrame(state, bindingState);
      if (!(bindingState?.receipt
        ? isInventoryReceiptReadinessMessage(frame)
        : isReadinessMessage(frame))) {
        state.lastError = makeReadinessError(PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME);
        return false;
      }
      state.connection.send(JSON.stringify(frame));
      state.revision = frame.revision;
    }
    return true;
  } catch {
    state.lastError = makeReadinessError(PROTOCOL_ERROR_CODES.CONNECTION_LOST);
    return false;
  }
}

function scheduleReadinessPublication(state) {
  clearReadinessTimer(state);
  state.timer = setInterval(() => {
    if (!state.committed || !connections.has(state.connection)) {
      clearReadinessTimer(state);
      return;
    }
    publishReadiness(state);
  }, Math.max(
    1,
    Math.floor(
      (state.receiptCommitted ? INVENTORY_RECEIPT_TTL_MS : READINESS_TTL_MS) / 2
    )
  ));
  state.timer.unref?.();
}

function readinessRejection(state, bindingState = undefined) {
  const dimensions = state.status;
  if (
    !bindingState &&
    (state.lastError?.code === PROTOCOL_ERROR_CODES.CONFIG_INVALID ||
      state.lastError?.code === PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED)
  ) {
    return state.lastError;
  }
  if (dimensions.connection !== "online") return makeReadinessError(PROTOCOL_ERROR_CODES.CONNECTION_LOST);
  if (dimensions.runtime === "incompatible") {
    return makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE);
  }
  if (dimensions.runtime !== "ready") {
    return makeReadinessError(PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME);
  }
  if (dimensions.providerAuth !== "configured") {
    const code =
      dimensions.providerAuth === "invalid"
        ? PROTOCOL_ERROR_CODES.PROVIDER_INVALID
        : dimensions.providerAuth === "unknown"
          ? PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE
          : PROTOCOL_ERROR_CODES.PROVIDER_MISSING;
    return makeReadinessError(code);
  }
  if (dimensions.modelProfile !== "ready") {
    const code =
      dimensions.modelProfile === "invalid"
        ? PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID
        : dimensions.modelProfile === "unknown"
          ? PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE
          : PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING;
    return makeReadinessError(code);
  }
  if (bindingState && !bindingState.ready) {
    return bindingState.lastError ?? makeReadinessError(PROTOCOL_ERROR_CODES.INVENTORY_PENDING);
  }
  if (!bindingState && dimensions.workspace !== "ready") {
    return makeReadinessError(
      state.lastError?.code ?? PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND
    );
  }
  return undefined;
}

function setReadinessError(state, error, fallback) {
  const code = classifyReadinessError(error, fallback);
  state.lastError = makeReadinessError(code);
  if (
    code === PROTOCOL_ERROR_CODES.PROVIDER_MISSING ||
    code === PROTOCOL_ERROR_CODES.PROVIDER_EXPIRED
  ) {
    state.status.providerAuth = "missing";
  }
  if (code === PROTOCOL_ERROR_CODES.PROVIDER_INVALID) state.status.providerAuth = "invalid";
  if (code === PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE) state.status.providerAuth = "unknown";
  if (code === PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING) state.status.modelProfile = "missing";
  if (code === PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID) state.status.modelProfile = "invalid";
  if (code === PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE) state.status.runtime = "incompatible";
  if (code === PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME) state.status.runtime = "error";
  if (code === PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND) state.status.workspace = "unavailable";
}

async function runCurrentRunProbe() {
  if (staticReadiness.runtime !== "ready") {
    const error = new Error("static security preflight failed");
    error.code =
      staticReadiness.errors.find((code) => READINESS_ERROR_CODES.has(code)) ??
      PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE;
    throw error;
  }
  if (!READINESS_TEST_INJECTION_ENABLED) {
    const error = new Error("current-run readiness probe unavailable");
    error.code = PROTOCOL_ERROR_CODES.PROVIDER_MISSING;
    throw error;
  }
  if (!readinessTestEvidence || !["pass", "ready", "success"].includes(readinessTestEvidence.probe)) {
    const error = new Error("current-run readiness probe failed");
    error.code = classifyReadinessError(
      readinessTestEvidence?.probeErrorCode,
      PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME
    );
    throw error;
  }
  return {
    runtime: "ready",
    providerAuth: "configured",
    modelProfile: "ready",
  };
}

async function probeReadiness(state) {
  if (!state?.committed || state.probeStarted || state.probePassed) return;
  state.probeStarted = true;
  try {
    const evidence = await runCurrentRunProbe();
    state.status.runtime = evidence.runtime;
    state.status.providerAuth = evidence.providerAuth;
    state.status.modelProfile = evidence.modelProfile;
    state.probePassed = true;
    if (state.bindings.size > 0) {
      for (const bindingState of state.bindings.values()) {
        promoteWorkspaceIfProven(state, bindingState);
      }
    } else if (!promoteWorkspaceIfProven(state)) {
      state.status.workspace = "unknown";
      state.lastError = makeReadinessError(PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED);
    }
  } catch (error) {
    setReadinessError(state, error, PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME);
    for (const bindingState of state.bindings.values()) {
      if (!bindingState.ready) bindingState.lastError = state.lastError;
    }
    state.probeStarted = false;
  }
  publishReadiness(state);
}

function invokeMappingRejection(state, message) {
  const bindingState = message.bindingId !== undefined
    ? state.bindings.get(message.bindingId)
    : undefined;
  if (message.bindingId !== undefined && !bindingState) {
    return makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED);
  }
  if (bindingState && !bindingState.ready) {
    return bindingState.lastError ?? makeReadinessError(PROTOCOL_ERROR_CODES.INVENTORY_PENDING);
  }
  const identity = bindingState?.binding ?? state;
  const mappingFields = [
    "mappingId",
    "mappingGeneration",
    "mappingVersion",
    "workspaceId",
  ];
  const hasMappingIdentity = mappingFields.some((field) =>
    Object.prototype.hasOwnProperty.call(message, field)
  );
  if (!hasMappingIdentity || identity.mappingId === undefined) {
    return makeReadinessError(PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED);
  }
  if (
    message.workspaceGeneration !== undefined &&
    message.workspaceGeneration !== identity.workspaceGeneration
  ) {
    return makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE);
  }
  if (
    message.mappingId !== identity.mappingId ||
    message.mappingGeneration !== identity.mappingGeneration ||
    message.mappingVersion !== identity.mappingVersion ||
    (message.workspaceId !== undefined && message.workspaceId !== identity.workspaceId)
  ) {
    return makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED);
  }
  return undefined;
}

async function admitReadyWorkload(state, workDir, message) {
  const bindingState = message.bindingId !== undefined
    ? state.bindings.get(message.bindingId)
    : undefined;
  if (message.bindingId !== undefined && !bindingState) {
    return {
      error: makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED),
    };
  }
  const early = readinessRejection(state, bindingState);
  if (early) return { error: early };
  const mappingError = invokeMappingRejection(state, message);
  if (mappingError) return { error: mappingError };
  const effectiveWorkDir = workDir ?? bindingState?.inventoryWorkspace?.workDir ?? state.mappingWorkDir;
  if (state.workspaceKey !== undefined && state.workspaceKey !== effectiveWorkDir) {
    return {
      error: makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE),
    };
  }
  if (effectiveWorkDir === undefined) {
    return { error: makeReadinessError(PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED) };
  }
  // Read-before-admission fence: re-verify the durable snapshot the positive
  // receipt was proved against. Any drift, unreadable object, or in-progress
  // cascade retires the binding before admission rather than serving a session
  // against a snapshot that has since changed.
  const admissionEpoch = providerEpoch;
  if (bindingState?.receipt && bindingState.proof) {
    let admissionRead;
    try {
      admissionRead = await serializedInventoryRead();
    } catch {
      admissionRead = undefined;
    }
    const stale =
      inventoryCascading ||
      admissionEpoch !== providerEpoch ||
      admissionRead?.status !== "present" ||
      admissionRead.inventory.inventoryGeneration !== bindingState.proof.inventoryGeneration ||
      admissionRead.inventory.inventoryFingerprint !== bindingState.proof.inventoryFingerprint;
    if (stale) {
      invalidateBindingRequests(state, bindingState);
      bindingState.ready = false;
      bindingState.phase = "negative";
      bindingState.proof = undefined;
      bindingState.lastError = makeReadinessError(PROTOCOL_ERROR_CODES.INVENTORY_STALE);
      publishReadiness(state);
      return { error: bindingState.lastError };
    }
  }
  if (!NATIVE_WORKSPACE_SERVING_ENABLED) {
    return { error: makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE) };
  }
  // S6f.1/ARCH-F6: a workspace barred by boot crash-recovery stays unservable
  // even once the gate flips (S6f.7). Dead code until NATIVE_WORKSPACE_SERVING_ENABLED is true.
  const barredWorkspaceId = bindingState?.binding?.workspaceId;
  if (barredWorkspaceId !== undefined && barredWorkspaceIds.has(barredWorkspaceId)) {
    return { error: makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE) };
  }
  const receiptIdentity = receiptActivityIdentity(state, bindingState);
  const bindingFingerprintValue = receiptIdentity?.bindingFingerprint ??
    (bindingState ? bindingFingerprint(bindingState.binding) : undefined);
  let activityLease;
  try {
    if (bindingState) {
      activityLease = workspaceLeases.acquireActivity({
        ...(bindingState.receipt
          ? receiptAuthority(bindingState.binding)
          : bindingState.binding),
        bindingFingerprint: bindingFingerprintValue,
        ...(receiptIdentity ?? {}),
      });
    }
    const session = await pool.ensureSession(effectiveWorkDir, {
      ...(receiptIdentity ? { receiptIdentity } : {
        managedIdentity: bindingFingerprintValue,
      }),
    });
    // Session-creation epoch recheck: a snapshot rotation between admission and
    // publication disposes the just-created session and returns no admission.
    if (bindingState?.receipt) {
      let publishRead;
      try {
        publishRead = await serializedInventoryRead();
      } catch {
        publishRead = undefined;
      }
      const rotated =
        inventoryCascading ||
        admissionEpoch !== providerEpoch ||
        publishRead?.status !== "present" ||
        publishRead.inventory.inventoryFingerprint !== bindingState.proof?.inventoryFingerprint ||
        publishRead.inventory.inventoryGeneration !== bindingState.proof?.inventoryGeneration;
      if (rotated) {
        await Promise.resolve(session.dispose()).catch(() => {});
        activityLease?.release();
        return {
          error: makeReadinessError(PROTOCOL_ERROR_CODES.INVENTORY_STALE),
        };
      }
    }
    if (
      bindingState &&
      (!activityLease.isCurrent() ||
        !currentBindingState(state, bindingState, bindingFingerprintValue))
    ) {
      activityLease.release();
      return {
        error: makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED),
      };
    }
    return {
      session,
      bindingState,
      bindingFingerprint: bindingFingerprintValue,
      activityLease,
    };
  } catch (error) {
    activityLease?.release();
    const errorCode = classifyReadinessError(
      error,
      PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND
    );
    // WORKSPACE_ADMISSION_EXCEEDED, like LEASE_CONFLICT, is a synchronous
    // rejection at the lease-acquisition boundary itself (acquireActivity threw
    // fail-closed at the host-wide active-workspace ceiling), not a downstream
    // session/readiness-state fault. Return the distinct fail-closed error
    // directly without polluting the binding's readiness state.
    if (isLeaseBoundaryRejection(errorCode)) {
      return { error: makeReadinessError(errorCode) };
    }
    setReadinessError(state, error, PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND);
    publishReadiness(state);
    return { error: state.lastError };
  }
}

function formatReadinessRejection(error) {
  const normalized = error?.code ? error : makeReadinessError(PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME);
  return JSON.stringify({
    code: normalized.code,
    ...normalized.remediation,
  });
}
const retryScheduler = createReconnectScheduler({
  deniedRetryMs: registerDeniedRetryMs,
  onReconnect: () => {
    if (!shuttingDown) connectToBot();
  },
});

function clearReconnectTimer() {
  retryScheduler.clear();
}


function scheduleDeniedRetry() {
  if (shuttingDown) return;
  retryScheduler.scheduleDenied();
}

function hasRegistrationReason(reason) {
  if (typeof reason !== "string") return false;
  return (
    reason
      .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ")
      .trim()
      .slice(0, 200).length > 0
  );
}

function connectToBot() {
  if (shuttingDown) return;
  const connection = new WebSocket(BOT_WS_URL, {
    maxPayload: MAX_WS_PAYLOAD_BYTES,
  });
  const readinessState = createReadinessState(connection);
  let deniedForConnection = false;
  connections.add(connection);

  connection.on("open", () => {
    const registration = {
      type: MSG_TYPES.REGISTER,
      hostId: HOST_ID,
      token: HOST_TOKEN,
      label: HOST_LABEL,
      protocolVersion: DAEMON_PROTOCOL_VERSION,
      capabilities: DAEMON_CAPABILITIES,
    };
    readinessState.registration = registration;
    connection.send(JSON.stringify(registration));
    console.log(
      `daemon: connected to bot at ${sanitizeDaemonError(BOT_WS_URL)}, ` +
        `registering as '${sanitizeDaemonError(HOST_ID)}'`
    );
  });

  connection.on("message", (raw, isBinary) =>
    handleMessage(connection, raw, isBinary, {
      wasDenied: () => deniedForConnection,
      markDenied: () => {
        deniedForConnection = true;
        retryScheduler.markDenied();
      },
    }).catch((err) =>
      console.error(`daemon: handler error: ${sanitizeDaemonError(err)}`)
    )
  );

  connection.on("close", () => {
    clearReadinessTimer(readinessState);
    readinessState.committed = false;
    if (readinessState.receiptCommitted) {
      for (const [bindingId, bindingState] of readinessState.bindings) {
        invalidateBindingRequests(readinessState, bindingState);
        if (bindingState.proof) {
          workspaceLeases.retireBinding({
            ...receiptAuthority(bindingState.binding),
            ...bindingState.proof,
            socketGeneration: readinessState.socketGeneration,
            bindingId: bindingState.binding.bindingId,
          });
          retireReceiptSession(readinessState, bindingState);
        }
        readinessState.bindings.delete(bindingId);
      }
      readinessState.retiredBindings.clear();
      readinessState.receiptCommitted = false;
    }
    // Transport loss alone does not invalidate an already admitted immutable
    // mapping generation. Its run may finish coherently, but no pending
    // admission can cross the committed-state recheck below. Authority remaps
    // remain the separate path that disposes captured binding requests.
    readinessState.status.connection = "offline";
    readinessState.lastError = makeReadinessError(PROTOCOL_ERROR_CODES.CONNECTION_LOST);
    connections.delete(connection);
    maybeStopInventoryPoll();
    if (shuttingDown) return;
    retryScheduler.onClose({ deniedForConnection });
  });

  connection.on("error", (err) =>
    console.error(`daemon: ws error: ${sanitizeDaemonError(err)}`)
  );
}

async function handleMessage(
  connection,
  raw,
  isBinary,
  { wasDenied = () => false, markDenied = () => {} } = {}
) {
  const readinessState = readinessByConnection.get(connection);
  let payloadBytes;
  try {
    payloadBytes = webSocketPayloadByteLength(raw);
  } catch {
    connection.close(1008, "invalid frame");
    return;
  }
  if (payloadBytes > MAX_WS_PAYLOAD_BYTES) {
    connection.close(1009, "message too big");
    return;
  }
  if (isBinary) {
    connection.close(1008, "invalid frame");
    return;
  }

  let msg;
  try {
    msg = JSON.parse(webSocketPayloadToUtf8(raw));
  } catch {
    connection.close(1008, "invalid json");
    return;
  }

  if (isRegisterOkMessage(msg)) {
    if (readinessState?.handshakeAccepted) return;
    readinessState.handshakeAccepted = true;
    // A denied registration remains denied across transport failures. Only a
    // successful registration clears the fixed-denial retry state.
    retryScheduler.markAccepted();
    const negotiatedVersion = Math.min(
      DAEMON_PROTOCOL_VERSION,
      msg.protocolVersion ?? 0
    );
    const shared = negotiateCapabilities(DAEMON_CAPABILITIES, msg.capabilities);
    readinessState.status.connection = "online";
    const readinessV2Committed = isReadinessCapabilityGate(
      readinessState.registration,
      msg
    );
    readinessState.receiptCommitted = isInventoryReceiptCapabilityGate(
      readinessState.registration,
      msg
    );
    readinessState.committed =
      readinessV2Committed || readinessState.receiptCommitted;
    if (readinessState.committed) {
      publishReadiness(readinessState);
      scheduleReadinessPublication(readinessState);
      if (readinessState.receiptCommitted) ensureInventoryPollStarted();
      void probeReadiness(readinessState);
    } else {
      clearReadinessTimer(readinessState);
    }
    console.log(
      `daemon: registration accepted (negotiated protocol v${negotiatedVersion}, ` +
        `shared capabilities: ${shared.join(", ") || "none"})`
    );
    return;
  }
  if (isRegisterDeniedMessage(msg)) {
    if (!wasDenied()) {
      markDenied();
      const hasSafeReason = hasRegistrationReason(msg.reason);
      console.warn(
        `daemon: registration denied${hasSafeReason ? " (details redacted)" : ""}; ` +
          `retrying in ${registerDeniedRetryMs}ms`
      );
    }
    try {
      connection.close(1008, "registration denied");
    } catch (error) {
      console.error(
        `daemon: failed to close denied websocket: ${sanitizeDaemonError(error)}`
      );
    } finally {
      scheduleDeniedRetry();
    }
    return;
  }
  if (isPingMessage(msg)) {
    connection.send(JSON.stringify(PONG));
    return;
  }
  if (isAnswerMessage(msg)) {
    // #35: route a gate answer to the in-flight session that owns the gate.
    // Stale/unknown requestIds are silently ignored (the gate may have already
    // resolved, timed out, or the session disposed).
    const request = inFlightByRequestId.get(msg.requestId);
    if (request) {
      try {
        await request.session.answerGate(msg.gateId, msg.answer);
      } catch (err) {
        console.error(
          `daemon: failed to answer gate: ${sanitizeDaemonError(err)}`
        );
      }
    }
    return;
  }
  if (msg?.type === MSG_TYPES.BIND_WORKSPACE) {
    if (readinessState?.receiptCommitted) {
      if (!isInventoryReceiptBindWorkspaceMessage(msg) ||
          !(await acceptReceiptBinding(readinessState, msg))) {
        connection.close(1008, "invalid workspace binding");
      }
      return;
    }
    if (!isBindWorkspaceMessage(msg) || !acceptWorkspaceBinding(readinessState, msg)) {
      connection.close(1008, "invalid workspace binding");
      return;
    }
    connection.send(
      JSON.stringify({
        type: MSG_TYPES.BIND_OK,
        bindingId: msg.bindingId,
        // This is an acknowledgement receipt, not authority proof. The
        // fingerprint covers sender-supplied fields; local inventory and
        // authenticated mapping verification remain separate gates.
        bindingFingerprint: bindingFingerprint(msg),
      })
    );
    publishReadiness(readinessState);
    return;
  }
  if (msg?.type === MSG_TYPES.UNBIND_WORKSPACE) {
    if (!readinessState?.receiptCommitted ||
        !isUnbindWorkspaceMessage(msg) ||
        !(await unbindReceiptBinding(readinessState, msg.bindingId))) {
      connection.close(1008, "invalid workspace unbind");
      return;
    }
    connection.send(JSON.stringify({ type: MSG_TYPES.UNBIND_OK, bindingId: msg.bindingId }));
    return;
  }
  if (msg?.type === MSG_TYPES.WORKSPACE_CREATE) {
    if (!isWorkspaceLifecycleMessage(msg)) {
      connection.close(1008, "invalid workspace lifecycle message");
      return;
    }
    // S6f.2 (#81): the reviewed create/clone security core
    // (workspace-create-dispatch.js) runs via the boot-singleton
    // lifecycleCreateDispatcher. It is null until the serving gate flips
    // (S6f.7) AND native serving low-level deps land (S7 #171), so today this
    // branch fails closed identically to the S6f.1b contract stub. When served,
    // resolve the trusted per-connection accepted binding + local inventory +
    // live readiness (never the message's own claims) and run the dispatcher.
    if (NATIVE_WORKSPACE_SERVING_ENABLED && lifecycleCreateDispatcher) {
      const trustedBinding = resolveTrustedCreateBinding(readinessState?.bindings, msg.workspaceId);
      const trustedInventoryWorkspace = findWorkspaceInventory(localWorkspaceInventory, msg);
      const readiness = projectServingReadiness(readinessState?.status);
      const result = await lifecycleCreateDispatcher.dispatchCreate({
        message: msg,
        trustedBinding,
        trustedInventoryWorkspace,
        readiness,
      });
      // Trust-boundary sanitization (review F2): serialize ONLY a whitelisted
      // protocol code, never the raw internal reason/path fragments. Unknown or
      // orchestrator-internal codes collapse to RUNTIME_INCOMPATIBLE.
      connection.send(
        JSON.stringify({
          type: MSG_TYPES.EVENT,
          requestId: msg.idempotencyFingerprint,
          event: {
            type: result.ok ? "workspace_lifecycle_committed" : "workspace_lifecycle_refused",
            operation: msg.operation,
            workspaceId: msg.workspaceId,
            ...(result.ok ? { receipt: result.receipt } : {}),
          },
          ...(result.ok
            ? {}
            : {
                error: formatReadinessRejection(
                  makeReadinessError(
                    whitelistProtocolCode(result.code)
                  )
                ),
              }),
          done: true,
        })
      );
      return;
    }
    connection.send(
      JSON.stringify({
        type: MSG_TYPES.EVENT,
        requestId: msg.idempotencyFingerprint,
        event: {
          type: "workspace_lifecycle_refused",
          operation: msg.operation,
          workspaceId: msg.workspaceId,
        },
        error: formatReadinessRejection(
          makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE)
        ),
        done: true,
      })
    );
    return;
  }
  if (msg?.type === MSG_TYPES.WORKSPACE_REFRESH) {
    if (!isWorkspaceLifecycleMessage(msg)) {
      connection.close(1008, "invalid workspace lifecycle message");
      return;
    }
    // S6f.3 (#81): the reviewed refresh security core
    // (workspace-refresh-dispatch.js) runs via the boot-singleton
    // lifecycleRefreshDispatcher. It is null until the serving gate flips
    // (S6f.7) AND native serving low-level deps land (S7 #171), so today this
    // branch fails closed identically to the S6f.1b contract stub. When served,
    // resolve the trusted per-connection accepted binding + local inventory +
    // live readiness + the adopted fence identity (never the message's own
    // claims); the base generation is read from the live pointer by the
    // dispatcher, and the successor is chained under a non-exclusive fence.
    if (NATIVE_WORKSPACE_SERVING_ENABLED && lifecycleRefreshDispatcher) {
      const trustedBinding = resolveTrustedCreateBinding(readinessState?.bindings, msg.workspaceId);
      const trustedInventoryWorkspace = findWorkspaceInventory(localWorkspaceInventory, msg);
      const readiness = projectServingReadiness(readinessState?.status);
      // S7 PLACEHOLDER (issue #182): fence identity must be sourced from the
      // adopted WorkspaceLeaseRegistry candidate before S6f.7; the legacy
      // bindingFingerprint recompute below fails closed for receipt bindings.
      const leaseCandidate = buildRefreshLeaseCandidate(trustedBinding, bindingFingerprint);
      const result = await lifecycleRefreshDispatcher.dispatchRefresh({
        message: msg,
        trustedBinding,
        trustedInventoryWorkspace,
        leaseCandidate,
        readiness,
      });
      // Trust-boundary sanitization (review F2): serialize ONLY a whitelisted
      // protocol code, never the raw internal reason/path fragments. Unknown or
      // orchestrator-internal codes collapse to RUNTIME_INCOMPATIBLE.
      connection.send(
        JSON.stringify({
          type: MSG_TYPES.EVENT,
          requestId: msg.idempotencyFingerprint,
          event: {
            type: result.ok ? "workspace_lifecycle_committed" : "workspace_lifecycle_refused",
            operation: msg.operation,
            workspaceId: msg.workspaceId,
            ...(result.ok ? { receipt: result.receipt } : {}),
          },
          ...(result.ok
            ? {}
            : {
                error: formatReadinessRejection(
                  makeReadinessError(
                    whitelistProtocolCode(result.code)
                  )
                ),
              }),
          done: true,
        })
      );
      return;
    }
    connection.send(
      JSON.stringify({
        type: MSG_TYPES.EVENT,
        requestId: msg.idempotencyFingerprint,
        event: {
          type: "workspace_lifecycle_refused",
          operation: msg.operation,
          workspaceId: msg.workspaceId,
        },
        error: formatReadinessRejection(
          makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE)
        ),
        done: true,
      })
    );
    return;
  }
  if (msg?.type === MSG_TYPES.WORKSPACE_RESET_DELETE) {
    if (!isWorkspaceLifecycleMessage(msg)) {
      connection.close(1008, "invalid workspace lifecycle message");
      return;
    }
    // S6f.4 (#81): the reviewed reset/delete security core
    // (workspace-reset-delete-dispatch.js) runs via the boot-singleton
    // lifecycleResetDeleteDispatcher. It is null until the serving gate flips
    // (S6f.7) AND native serving low-level deps land (S7 #171), so today this
    // branch fails closed identically to the S6f.1b contract stub. When served,
    // resolve the trusted per-connection accepted binding + local inventory +
    // live readiness + the adopted EXCLUSIVE fence identity + the host-held
    // manual-cleanup authority (never the message's own claims); the base being
    // destroyed is read from the live disposition by the dispatcher, gated by a
    // dirty-backup capture, workload quiescence, and residual-process absence.
    if (NATIVE_WORKSPACE_SERVING_ENABLED && lifecycleResetDeleteDispatcher) {
      const trustedBinding = resolveTrustedCreateBinding(readinessState?.bindings, msg.workspaceId);
      const trustedInventoryWorkspace = findWorkspaceInventory(localWorkspaceInventory, msg);
      const readiness = projectServingReadiness(readinessState?.status);
      // S7 PLACEHOLDER (issue #182): fence identity must be sourced from the
      // adopted WorkspaceLeaseRegistry candidate before S6f.7; the legacy
      // bindingFingerprint recompute below fails closed for receipt bindings.
      const leaseCandidate = buildResetDeleteLeaseCandidate(trustedBinding, bindingFingerprint);
      // S7 PLACEHOLDER (issue #171): the manual-cleanup tx-context authority is
      // host-held serving state not yet tracked; a null candidate makes the
      // dispatcher refuse fail-closed until S7 wires it.
      const lifecycleAuthority = null;
      const result = await lifecycleResetDeleteDispatcher.dispatchResetDelete({
        message: msg,
        trustedBinding,
        trustedInventoryWorkspace,
        leaseCandidate,
        lifecycleAuthority,
        readiness,
      });
      surfaceManualCleanup(msg, result);
      // Trust-boundary sanitization (review F2): serialize ONLY a whitelisted
      // protocol code, never the raw internal reason/path fragments. Unknown or
      // orchestrator-internal codes collapse to RUNTIME_INCOMPATIBLE.
      connection.send(
        JSON.stringify({
          type: MSG_TYPES.EVENT,
          requestId: msg.idempotencyFingerprint,
          event: {
            type: result.ok ? "workspace_lifecycle_committed" : "workspace_lifecycle_refused",
            operation: msg.operation,
            workspaceId: msg.workspaceId,
            ...(result.ok ? { receipt: result.receipt } : {}),
          },
          ...(result.ok
            ? {}
            : {
                error: formatReadinessRejection(
                  makeReadinessError(
                    whitelistProtocolCode(result.code)
                  )
                ),
              }),
          done: true,
        })
      );
      return;
    }
    connection.send(
      JSON.stringify({
        type: MSG_TYPES.EVENT,
        requestId: msg.idempotencyFingerprint,
        event: {
          type: "workspace_lifecycle_refused",
          operation: msg.operation,
          workspaceId: msg.workspaceId,
        },
        error: formatReadinessRejection(
          makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE)
        ),
        done: true,
      })
    );
    return;
  }
  if (msg?.type === MSG_TYPES.WORKSPACE_RESTORE_MIGRATION) {
    if (!isWorkspaceLifecycleMessage(msg)) {
      connection.close(1008, "invalid workspace lifecycle message");
      return;
    }
    // S6f.5 (#81): the reviewed restore/migration security core
    // (workspace-restore-migration-dispatch.js) runs via the boot-singleton
    // lifecycleRestoreMigrationDispatcher. It is null until the serving gate
    // flips (S6f.7) AND native serving low-level deps land (S7 #171), so today
    // this branch fails closed identically to the S6f.1b contract stub. When
    // served, resolve the trusted per-connection accepted binding + local
    // inventory + live readiness + the adopted EXCLUSIVE fence identity + the
    // host-held restore context (the quarantined staged source, provenance
    // authority, manifest, and lineage the thin wire message cannot carry).
    // The base being promoted onto is read from the live pointer by the
    // dispatcher; the promotion is a reversible successor generation.
    if (NATIVE_WORKSPACE_SERVING_ENABLED && lifecycleRestoreMigrationDispatcher) {
      const trustedBinding = resolveTrustedCreateBinding(readinessState?.bindings, msg.workspaceId);
      const trustedInventoryWorkspace = findWorkspaceInventory(localWorkspaceInventory, msg);
      const readiness = projectServingReadiness(readinessState?.status);
      // S7 PLACEHOLDER (issue #182): fence identity must be sourced from the
      // adopted WorkspaceLeaseRegistry candidate before S6f.7; the legacy
      // bindingFingerprint recompute below fails closed for receipt bindings.
      const leaseCandidate = buildRestoreMigrationLeaseCandidate(trustedBinding, bindingFingerprint);
      // S7 PLACEHOLDER (issue #171): the quarantined staged-source payload
      // (stagingPath, provenance authority, manifest, lineage) is host-held
      // serving state not yet tracked; a null context makes the dispatcher
      // refuse fail-closed until S7 wires it.
      const restoreContext = null;
      const result = await lifecycleRestoreMigrationDispatcher.dispatchRestoreMigration({
        message: msg,
        trustedBinding,
        trustedInventoryWorkspace,
        leaseCandidate,
        restoreContext,
        readiness,
      });
      surfaceManualCleanup(msg, result);
      // Trust-boundary sanitization (review F2): serialize ONLY a whitelisted
      // protocol code, never the raw internal reason/path fragments. Unknown or
      // orchestrator-internal codes collapse to RUNTIME_INCOMPATIBLE.
      connection.send(
        JSON.stringify({
          type: MSG_TYPES.EVENT,
          requestId: msg.idempotencyFingerprint,
          event: {
            type: result.ok ? "workspace_lifecycle_committed" : "workspace_lifecycle_refused",
            operation: msg.operation,
            workspaceId: msg.workspaceId,
            ...(result.ok ? { receipt: result.receipt } : {}),
          },
          ...(result.ok
            ? {}
            : {
                error: formatReadinessRejection(
                  makeReadinessError(
                    whitelistProtocolCode(result.code)
                  )
                ),
              }),
          done: true,
        })
      );
      return;
    }
    // S6f.1b contract stub fallback (#81): serving stays gated off
    // (NATIVE_WORKSPACE_SERVING_ENABLED=false) or the dispatcher is null.
    // Refuse with RUNTIME_INCOMPATIBLE using the same readiness-rejection shape
    // the INVOKE path uses for a gated/unready operation.
    connection.send(
      JSON.stringify({
        type: MSG_TYPES.EVENT,
        requestId: msg.idempotencyFingerprint,
        event: {
          type: "workspace_lifecycle_refused",
          operation: msg.operation,
          workspaceId: msg.workspaceId,
        },
        error: formatReadinessRejection(
          makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE)
        ),
        done: true,
      })
    );
    return;
  }
  const hasV2RouteField = [
    "mappingId",
    "mappingGeneration",
    "mappingVersion",
    "workspaceId",
  ].some((field) => Object.prototype.hasOwnProperty.call(msg, field));
  const invokeValid = hasV2RouteField
    ? isInvokeMessage(msg, { v2: readinessState?.committed })
    : isInvokeMessage(msg);
  if (!invokeValid) {
    connection.close(1008, "invalid message");
    return;
  }

  const { requestId, workDir, command } = msg;
  const send = (event, extra = {}) =>
    connection.send(serializeEventFrame(requestId, event, extra));
  const releaseRequestId = requestIds.tryAcquire(requestId);
  if (!releaseRequestId) {
    connection.close(1008, "duplicate request id");
    return;
  }
  const releaseAdmission = admissionBudget.tryAcquireInvoke();
  if (!releaseAdmission) {
    releaseRequestId();
    const exhausted = makeReadinessError(PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED);
    send(undefined, {
      error: readinessState?.committed
        ? formatReadinessRejection(exhausted)
        : LEGACY_RESOURCE_EXHAUSTED_ERROR,
      done: true,
    });
    return;
  }
  let session;
  let activityLease;

  try {
    if (readinessState?.committed) {
      const admission = await admitReadyWorkload(readinessState, workDir, msg);
      if (admission.error) {
        send(undefined, {
          error: formatReadinessRejection(admission.error),
          done: true,
        });
        return;
      }
      session = admission.session;
      activityLease = admission.activityLease;
      if (
        admission.bindingState &&
        (!activityLease?.isCurrent() ||
          !currentBindingState(
            readinessState,
            admission.bindingState,
            admission.bindingFingerprint
          ))
      ) {
        send(undefined, {
          error: formatReadinessRejection(
            makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED)
          ),
          done: true,
        });
        return;
      }
    } else {
      session = await pool.ensureSession(workDir);
    }
    inFlightByRequestId.set(requestId, {
      connection,
      session,
      bindingId: msg.bindingId,
    });

    if (command.kind === "set_model") {
      await setSessionModel(session, command, (event) => send(event));
    } else {
      const rpcCommand = toRpcCommand(command);
      await session.send(rpcCommand, (event) => send(event));
    }

    send(undefined, { done: true });
  } catch (err) {
    const modelDiagnostic =
      command.kind === "set_model" ? modelCommandDiagnostic(err) : undefined;
    if (modelDiagnostic !== undefined) {
      console.error(
        `daemon: set_model failed: ${sanitizeDaemonError(modelDiagnostic)}`
      );
    }
    if (readinessState?.committed) {
      send(undefined, {
        error: formatReadinessRejection(
          makeReadinessError(classifyReadinessError(err, PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME))
        ),
        done: true,
      });
    } else {
      send(undefined, {
        error: sanitizeDaemonError(normalizeProtocolError(err)),
        done: true,
      });
    }
  } finally {
    releaseRequestId();
    activityLease?.release();
    releaseAdmission();
    const request = inFlightByRequestId.get(requestId);
    if (request?.connection === connection && request.session === session) {
      inFlightByRequestId.delete(requestId);
    }
  }
}


function toRpcCommand(command) {
  switch (command.kind) {
    case "prompt":
      return { type: "prompt", message: command.message };
    case "steer":
      return { type: "steer", message: command.message };
    case "follow_up":
      return { type: "follow_up", message: command.message };
    default:
      throw new Error(`Unknown command kind: ${command.kind}`);
  }
}

function closeConnections() {
  stopInventoryPoll();
  for (const connection of connections) {
    const readinessState = readinessByConnection.get(connection);
    clearReadinessTimer(readinessState);
    if (readinessState) readinessState.committed = false;
    try {
      connection.close(1000, "daemon shutting down");
    } catch (error) {
      console.error(
        `daemon: failed to close websocket during shutdown: ${sanitizeDaemonError(
          error
        )}`
      );
    }
  }
}
function formatPendingShutdownOperations() {
  let pending;
  try {
    pending = pool.getPendingShutdownOperations?.() ?? [];
  } catch (error) {
    return `unavailable (${sanitizeDaemonError(error)})`;
  }
  if (!Array.isArray(pending) || pending.length === 0) return "none";
  return pending
    .map(({ workDir, operation }) => {
      const label = sanitizeDaemonError(operation || "operation");
      const path = sanitizeDaemonError(workDir || "unknown workDir");
      return `${label} for ${path}`;
    })
    .join(", ");
}

async function shutdownAndExit(exitCode) {
  if (shutdownPromise) return shutdownPromise;
  // The first signal or fatal event owns the eventual exit code. A later
  // signal must not turn a fatal exit into success (or vice versa).
  shutdownExitCode = exitCode;
  shuttingDown = true;
  clearReconnectTimer();
  shutdownPromise = (async () => {
    let timer;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => {
        console.error(
          `daemon: shutdown timed out after ${DAEMON_SHUTDOWN_TIMEOUT_MS}ms; ` +
            `session disposals were abandoned; ` +
            `pending operations: ${formatPendingShutdownOperations()}`
        );
        resolve();
      }, DAEMON_SHUTDOWN_TIMEOUT_MS);
    });
    try {
      closeConnections();
      await Promise.race([Promise.resolve().then(() => pool.shutdown()), timeout]);
    } catch (error) {
      // Signal shutdown remains successful even if disposal fails. Fatal
      // shutdown keeps the first caller's non-zero exit code.
      console.error(`daemon: shutdown failed: ${sanitizeDaemonError(error)}`);
    } finally {
      clearTimeout(timer);
      process.exit(shutdownExitCode);
    }
  })();
  return shutdownPromise;
}

process.on("SIGINT", () => {
  void shutdownAndExit(0);
});
process.on("SIGTERM", () => {
  void shutdownAndExit(0);
});
process.on("unhandledRejection", (reason) => {
  console.error(`daemon: unhandled rejection: ${sanitizeDaemonError(reason)}`);
  void shutdownAndExit(1);
});
process.on("uncaughtException", (error) => {
  console.error(`daemon: uncaught exception: ${sanitizeDaemonError(error)}`);
  void shutdownAndExit(1);
});

const workspaceRecoveryConfig = resolveWorkspaceRecoveryConfig({ env: process.env });
if (workspaceRecoveryConfig.ok !== true) {
  console.error(`daemon: native workspace recovery configuration failed: ${JSON.stringify(workspaceRecoveryConfig.diagnostic)}`);
  process.exit(1);
}
if (workspaceRecoveryConfig.enabled) {
  try {
    const recoveryResult = await runBootRecovery({ workspaceRoot: workspaceRecoveryConfig.workspaceRoot });
    barredWorkspaceIds = new Set(recoveryResult.barredWorkspaceIds);
  } catch (error) {
    console.error(`daemon: boot workspace recovery failed: ${sanitizeDaemonError(error)}`);
    process.exit(1);
  }
}

// S6f.2 (#81): boot-singleton create/clone dispatcher. Stays null until the
// serving gate flips (S6f.7) AND a native serving low-level deps bundle is
// supplied (S7, issue #171); a null dispatcher keeps WORKSPACE_CREATE
// fail-closed (RUNTIME_INCOMPATIBLE), identical to the S6f.1b contract stub.
const lifecycleCreateDispatcher = resolveLifecycleCreateDispatcher({
  enabled: workspaceRecoveryConfig.enabled,
  workspaceRoot: workspaceRecoveryConfig.workspaceRoot,
});

// S6f.3 (#81): boot-singleton refresh dispatcher. Stays null until the serving
// gate flips (S6f.7) AND a native serving low-level deps bundle is supplied
// (S7, issue #171); a null dispatcher keeps WORKSPACE_REFRESH fail-closed
// (RUNTIME_INCOMPATIBLE), identical to the S6f.1b contract stub.
const lifecycleRefreshDispatcher = resolveLifecycleRefreshDispatcher({
  enabled: workspaceRecoveryConfig.enabled,
  workspaceRoot: workspaceRecoveryConfig.workspaceRoot,
});

// S6f.4 (#81): the boot-singleton reset/delete dispatcher stays null until the
// serving gate flips (S6f.7) AND a native serving low-level deps bundle is
// supplied (S7, issue #171); a null dispatcher keeps WORKSPACE_RESET_DELETE
// fail-closed (RUNTIME_INCOMPATIBLE), identical to the S6f.1b contract stub.
const lifecycleResetDeleteDispatcher = resolveLifecycleResetDeleteDispatcher({
  enabled: workspaceRecoveryConfig.enabled,
  workspaceRoot: workspaceRecoveryConfig.workspaceRoot,
});

// S6f.5 (#81): the restore/migration boot-singleton. Null until the serving
// gate flips (S6f.7) AND the native serving low-level deps bundle lands
// (S7 #171); no nativeServingDeps are supplied today, so the resolver returns
// null and the WORKSPACE_RESTORE_MIGRATION served branch stays inert, failing
// closed (RUNTIME_INCOMPATIBLE) identically to the S6f.1b contract stub.
const lifecycleRestoreMigrationDispatcher = resolveLifecycleRestoreMigrationDispatcher({
  enabled: workspaceRecoveryConfig.enabled,
  workspaceRoot: workspaceRecoveryConfig.workspaceRoot,
});

connectToBot();

export {
  DAEMON_SHUTDOWN_TIMEOUT_MS,
  shutdownAndExit,
  sanitizeDaemonError,
};
