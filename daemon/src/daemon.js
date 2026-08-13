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
  READINESS_DEFAULT_TTL_MS,
  READINESS_DIMENSIONS,
  READINESS_MAX_TTL_MS,
  READINESS_MIN_TTL_MS,
  READINESS_REMEDIATIONS,
  V0_LIMITS,
  WORKSPACE_READINESS_CAPABILITY,
  isWorkspaceId,
  isReadinessWorkspaceGeneration,
  isAnswerMessage,
  isBindWorkspaceMessage,
  isInvokeMessage,
  isPingMessage,
  isReadinessCapabilityGate,
  isReadinessMessage,
  isReadinessTtl,
  isRegisterDeniedMessage,
  isRegisterOkMessage,
  negotiateCapabilities,
  normalizeProtocolError,
} from "@gjc-remote/shared";
import { SessionPool } from "./session-pool.js";
import { setSessionModel } from "./model-command.js";
import {
  webSocketPayloadByteLength,
  webSocketPayloadToUtf8,
} from "./ws-payload.js";
import { serializeEventFrame } from "./event-frame.js";
import { findWorkspaceInventory, parseWorkspaceInventory } from "./workspace-inventory.js";

import {
  parseRegisterDeniedRetryMs,
  parseShutdownTimeoutMs,
  REGISTER_DENIED_RETRY_MS,
  SHUTDOWN_TIMEOUT_DEFAULT_MS,
  sanitizeErrorMessage,
  createReconnectScheduler,
} from "./reconnect.js";

const { HOST_ID, HOST_TOKEN, HOST_LABEL, BOT_WS_URL } = process.env;

if (!HOST_ID || !HOST_TOKEN || !BOT_WS_URL) {
  console.error("Missing HOST_ID, HOST_TOKEN, or BOT_WS_URL in environment (.env).");
  process.exit(1);
}
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
const DAEMON_PROTOCOL_VERSION = readinessV2Advertised
  ? Math.max(PROTOCOL_VERSION, PROTOCOL_VERSION_V2)
  : PROTOCOL_VERSION;
const DAEMON_CAPABILITIES = Object.freeze(
  readinessV2Advertised
    ? [...new Set([...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY])]
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

const READINESS_TEST_INJECTION_ENABLED =
  process.env.GJC_READINESS_TEST_INJECTION === "1";
const NATIVE_WORKSPACE_SERVING_ENABLED = false;
const MAX_BINDINGS_PER_SOCKET = 64;

let localWorkspaceInventory;
if (process.env.GJC_WORKSPACE_INVENTORY !== undefined) {
  try {
    localWorkspaceInventory = parseWorkspaceInventory(process.env.GJC_WORKSPACE_INVENTORY);
  } catch (error) {
    console.error(`daemon: invalid GJC_WORKSPACE_INVENTORY: ${sanitizeDaemonError(error)}`);
    process.exit(1);
  }
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
    binding: undefined,
    bindingAccepted: false,
    inventoryWorkspace: undefined,
    bindings: new Map(),
    lastError: staticErrorCode ? makeReadinessError(staticErrorCode) : undefined,
  };
  readinessByConnection.set(connection, state);
  return state;
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
    const sameBinding = [
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
    ].every((field) => previous[field] === message[field]);
    if (!sameBinding && (
      message.mappingGeneration < previous.mappingGeneration ||
      message.workspaceGeneration < previous.workspaceGeneration ||
      message.inventoryGeneration < previous.inventoryGeneration
    )) {
      return false;
    }
    if (sameBinding) return true;
  }
  if (!previousState && state.bindings.size >= MAX_BINDINGS_PER_SOCKET) return false;
  const binding = Object.freeze({ ...message });
  const inventoryWorkspace = findWorkspaceInventory(localWorkspaceInventory, message);
  state.bindings.set(message.bindingId, {
    binding,
    inventoryWorkspace,
    ready: false,
    lastError: makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND),
  });
  // Binding acceptance is intentionally separate from readiness. The daemon
  // still needs a verified local inventory match before it can serve.
  promoteWorkspaceIfProven(state, state.bindings.get(message.bindingId));
  return true;
}

function promoteWorkspaceIfProven(state, bindingState) {
  if (!state?.probePassed || !bindingState?.inventoryWorkspace) return false;
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
  const binding = bindingState?.binding ?? state.binding;
  const ready = bindingState?.ready ?? state.status.workspace === "ready";
  const frame = {
    type: MSG_TYPES.READINESS,
    socketGeneration: state.socketGeneration,
    revision: state.revision + 1,
    observedAt: Date.now(),
    ttlMs: READINESS_TTL_MS,
    status: Object.fromEntries(
      READINESS_DIMENSIONS.map((dimension) => [
        dimension,
        dimension === "workspace"
          ? (ready ? "ready" : "unknown")
          : state.status[dimension],
      ])
    ),
    expiresAt: Date.now() + READINESS_TTL_MS,
  };
  if (binding) {
    frame.bindingId = binding.bindingId;
    frame.workspaceId = binding.workspaceId;
    frame.workspaceGeneration = binding.workspaceGeneration;
  } else if (state.workspaceId !== undefined && state.workspaceGeneration !== undefined) {
    frame.workspaceId = state.workspaceId;
    frame.workspaceGeneration = state.workspaceGeneration;
  }
  const lastError = bindingState?.lastError ?? state.lastError;
  if (lastError) frame.lastError = lastError;
  return frame;
}

function publishReadiness(state) {
  if (!state?.committed || !connections.has(state.connection)) return false;
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
      if (!isReadinessMessage(frame)) {
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
  }, Math.max(1, Math.floor(READINESS_TTL_MS / 2)));
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
    return bindingState.lastError ?? makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND);
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
    return bindingState.lastError ?? makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND);
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
  if (
    message.workDir !== undefined &&
    (bindingState
      ? message.workDir !== bindingState.inventoryWorkspace?.workDir
      : state.mappingWorkDir !== undefined && message.workDir !== state.mappingWorkDir)
  ) {
    return makeReadinessError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED);
  }
  return undefined;
}

async function admitReadyWorkload(state, workDir, message) {
  const bindingState = message.bindingId !== undefined
    ? state.bindings.get(message.bindingId)
    : undefined;
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
  if (!NATIVE_WORKSPACE_SERVING_ENABLED) {
    return { error: makeReadinessError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE) };
  }
  try {
    const session = await pool.ensureSession(effectiveWorkDir);
    return { session };
  } catch (error) {
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
    retryScheduler.resetBackoff();
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
    readinessState.status.connection = "offline";
    readinessState.lastError = makeReadinessError(PROTOCOL_ERROR_CODES.CONNECTION_LOST);
    connections.delete(connection);
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
    readinessState.committed = isReadinessCapabilityGate(
      readinessState.registration,
      msg
    );
    if (readinessState.committed) {
      publishReadiness(readinessState);
      scheduleReadinessPublication(readinessState);
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
    const session = inFlightByRequestId.get(msg.requestId);
    if (session) {
      try {
        await session.answerGate(msg.gateId, msg.answer);
      } catch (err) {
        console.error(
          `daemon: failed to answer gate: ${sanitizeDaemonError(err)}`
        );
      }
    }
    return;
  }
  if (msg?.type === MSG_TYPES.BIND_WORKSPACE) {
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

  try {
    let session;
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
    } else {
      session = await pool.ensureSession(workDir);
    }
    inFlightByRequestId.set(requestId, session);

    if (command.kind === "set_model") {
      await setSessionModel(session, command, (event) => send(event));
    } else {
      const rpcCommand = toRpcCommand(command);
      await session.send(rpcCommand, (event) => send(event));
    }

    send(undefined, { done: true });
  } catch (err) {
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
    inFlightByRequestId.delete(requestId);
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

connectToBot();

export {
  DAEMON_SHUTDOWN_TIMEOUT_MS,
  shutdownAndExit,
  sanitizeDaemonError,
};
