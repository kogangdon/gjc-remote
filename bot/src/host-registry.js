import { WebSocket, WebSocketServer } from "ws";
import { randomUUID, timingSafeEqual } from "node:crypto";
import {
  CAPABILITIES,
  GATE_PRESENTATION_CAPABILITY,
  GATE_ANSWER_ERROR_CODES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PING,
  PROTOCOL_VERSION,
  PROTOCOL_VERSION_V2,
  PROTOCOL_VERSION_V3,
  READINESS_DIMENSIONS,
  READINESS_MAX_SKEW_MS,
  READINESS_MAX_TTL_MS,
  PROTOCOL_ERROR_CODES,
  V0_LIMITS,
  TERMINAL_DISPOSITION_CAPABILITY,
  INVOKE_CANCELLATION_CAPABILITY,
  INVOKE_OWNERSHIP_RETENTION_MS,
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
  isAnswerMessage,
  isPresentGateMessage,
  isAbandonGateMessage,
  isEventMessage,
  isGateAnswerResultEvent,
  isGatePresentationResultMessage,
  isGateAbandonResultMessage,
  isGateRequestEvent,
  isInvokeMessage,
  isInvokeTerminalEvent,
  isCancelInvokeMessage,
  isCancelResultMessage,
  isMappingGeneration,
  isMappingId,
  isMappingVersion,
  isPongMessage,
  isReadinessCapabilityGate,
  isInventoryReceiptBindOkMessage,
  isInventoryReceiptCapabilityGate,
  isInventoryReceiptReadinessMessage,
  isUnbindOkMessage,
  isReadinessMessage,
  isRegisterMessage,
  isRegisterOkMessage,
  isReadinessWorkspaceGeneration,
  isWorkspaceId,
  negotiateCapabilities,
  normalizeReadinessTtl,
  READINESS_REMEDIATIONS,
} from "@gjc-remote/shared";
import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { satisfiesManagedProtocolFloor } from "@gjc-remote/shared/managed-protocol-policy";
import {
  validateWorkspaceAuthorityDescriptor,
  workspaceBindingFingerprint,
} from "@gjc-remote/shared/workspace-binding";

const HEARTBEAT_INTERVAL_MS = 30_000;
const HEARTBEAT_TIMEOUT_MS = 10_000;
const INVOKE_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const INVOKE_HARD_CAP_MS = 30 * 60 * 1000;
const CANCEL_RECEIPT_TIMEOUT_MS = 10_000;
const MAX_CANCEL_TOMBSTONES = 64;
const GATE_ANSWER_TIMEOUT_MS = 30 * 1000;
const GATE_PRESENTATION_TIMEOUT_MS = 30 * 1000;
const MAX_GATE_PRESENTATION_ATTEMPTS = 64;
const OUTPUT_TRUNCATED_NOTICE = "[output truncated: too large]";
export const MAX_BINDING_READINESS_STATES = 64;
const BINDING_DEADLINE_MS = 10_000;
// Local-only observability. The schema deliberately has no extensibility
// fields: this callback must never become a path, prompt, token, error, or
// fingerprint transport.
const OBSERVABILITY_EVENTS = Object.freeze([
  "bind.request",
  "bind.ok",
  "bind.negative",
  "receipt.invalidate",
  "socket.retire",
  "readiness.accept",
  "readiness.expire",
  "invoke.start",
  "invoke.finish",
  "invoke.deny",
]);
const OBSERVABILITY_KEYS = Object.freeze(new Set([
  "schemaVersion", "component", "event", "phase", "observedAt", "receivedAt",
  "expiresAt", "requestAt", "deadlineAt", "durationMs", "hostId", "mappingId",
  "workspaceId", "bindingId", "fenceSequence", "socketGeneration", "revision",
  "transactionId", "code", "terminalDisposition",
]));
const OBSERVABILITY_CODES = Object.freeze(new Set([
  ...Object.values(PROTOCOL_ERROR_CODES),
  "BINDING_DEADLINE",
  "WORKSPACE_UNBOUND",
]));
const MAX_UINT53 = Number.MAX_SAFE_INTEGER;
const PING_PAYLOAD = JSON.stringify(PING);
const BOT_CAPABILITIES = CAPABILITIES;
const V2_CAPABILITIES = Object.freeze([...BOT_CAPABILITIES, WORKSPACE_READINESS_CAPABILITY]);
const V3_CAPABILITIES = Object.freeze([
  ...V2_CAPABILITIES,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
]);
const SYSTEM_TIMERS = {
  setInterval: (callback, delay) => setInterval(callback, delay),
  clearInterval: (timer) => clearInterval(timer),
  setTimeout: (callback, delay) => setTimeout(callback, delay),
  clearTimeout: (timer) => clearTimeout(timer),
};

function isPositiveDuration(value) {
  return (
    Number.isInteger(value) &&
    value > 0 &&
    value <= INVOKE_OWNERSHIP_RETENTION_MS
  );
}
function redactOpaqueId(value) {
  return isWorkspaceId(String(value)) ? String(value) : "[redacted-host]";
}
function boundedOpaque(value) {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
    ? value
    : "[redacted]";
}
function boundedCode(value) {
  return typeof value === "string" && OBSERVABILITY_CODES.has(value)
    ? value
    : PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME;
}
function uint53(value) {
  return Number.isSafeInteger(value) && value >= 0
    ? Math.min(value, MAX_UINT53)
    : undefined;
}
function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
function hostTokenMatches(expected, actual) {
  if (typeof expected !== "string" || typeof actual !== "string") return false;
  const expectedBytes = Buffer.from(expected, "utf8");
  const actualBytes = Buffer.from(actual, "utf8");
  return (
    expectedBytes.length === actualBytes.length &&
    timingSafeEqual(expectedBytes, actualBytes)
  );
}
function isManagedPathFreeRoute(workDir, routeIdentity) {
  return (
    workDir === null &&
    isMappingId(routeIdentity?.mappingId) &&
    isMappingGeneration(routeIdentity?.mappingGeneration) &&
    isMappingVersion(routeIdentity?.mappingVersion) &&
    isWorkspaceId(routeIdentity?.workspaceId) &&
    isReadinessWorkspaceGeneration(routeIdentity?.workspaceGeneration)
  );
}
const AUTHORITY_ROUTE_FIELDS = Object.freeze([
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "sourcePlatform",
  "workspaceId",
  "workspaceGeneration",
]);
export function freezeManagedAuthorityDescriptor(hostId, routeIdentity) {
  if (routeIdentity?.authority === undefined) return undefined;
  const authority = { ...routeIdentity.authority };
  validateWorkspaceAuthorityDescriptor(authority);
  if (
    authority.hostId !== hostId ||
    AUTHORITY_ROUTE_FIELDS.some((field) => routeIdentity[field] !== authority[field])
  ) {
    throw new TypeError("MANAGED_AUTHORITY_INVALID");
  }
  return Object.freeze(authority);
}
function remediationError(code) {
  return {
    ...(READINESS_REMEDIATIONS[code] ??
      READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME]),
    code,
  };
}
function terminalError(disposition, code) {
  const remediation = code
    ? remediationError(code)
    : READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME];
  return {
    terminalDisposition: disposition,
    ...remediation,
  };
}
function localDeadlineError(kind) {
  return {
    localOutcome: kind,
    code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
    retryable: false,
    action: "verify_host_state",
  };
}
function interruptionUnconfirmedError(kind) {
  return {
    localOutcome: kind,
    code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
    retryable: false,
    action: "verify_host_state",
  };
}

/**
 * WS server that host daemons connect to (outbound from the daemon's side).
 * Tracks live connections by hostId and routes invoke/event frames between
 * the Discord layer and whichever daemon owns the target host.
 */
export class HostRegistry {
  /**
   * @param {{
   *   port: number,
   *   tokensByHostId: Map<string, string>,
   *   heartbeatIntervalMs?: number,
   *   heartbeatTimeoutMs?: number,
   *   invokeIdleTimeoutMs?: number,
   *   invokeHardCapMs?: number,
   *   cancelReceiptTimeoutMs?: number,
   *   cancelIdFactory?: () => string,
   *   requestIdFactory?: () => string,
   *   gateAnswerTimeoutMs?: number,
   *   gatePresentationTimeoutMs?: number,
   *   workspaceServingEnabled?: boolean,
   *   timers?: typeof SYSTEM_TIMERS,
   *   now?: () => number,
   *   monotonicNow?: () => number,
   *   onError?: (error: unknown) => void,
   *   onObservabilityEvent?: (event: object) => void,
   * }} opts
   */
  constructor({
    port,
    tokensByHostId,
    heartbeatIntervalMs = HEARTBEAT_INTERVAL_MS,
    heartbeatTimeoutMs = HEARTBEAT_TIMEOUT_MS,
    invokeIdleTimeoutMs = INVOKE_IDLE_TIMEOUT_MS,
    invokeHardCapMs = INVOKE_HARD_CAP_MS,
    cancelReceiptTimeoutMs = CANCEL_RECEIPT_TIMEOUT_MS,
    cancelIdFactory = randomUUID,
    requestIdFactory = randomUUID,
    gateAnswerTimeoutMs = GATE_ANSWER_TIMEOUT_MS,
    gatePresentationTimeoutMs = GATE_PRESENTATION_TIMEOUT_MS,
    workspaceServingEnabled = false,
    timers = SYSTEM_TIMERS,
    now = () => Date.now(),
    monotonicNow = () =>
      typeof performance?.now === "function"
        ? performance.now()
        : Number(process.hrtime.bigint()) / 1e6,
    onError,
    onObservabilityEvent,
  }) {
    if (!isPositiveDuration(heartbeatIntervalMs)) {
      throw new Error("heartbeatIntervalMs must be a positive duration");
    }
    if (!isPositiveDuration(heartbeatTimeoutMs)) {
      throw new Error("heartbeatTimeoutMs must be a positive duration");
    }
    if (!isPositiveDuration(invokeIdleTimeoutMs)) {
      throw new Error("invokeIdleTimeoutMs must be a positive duration");
    }
    if (!isPositiveDuration(invokeHardCapMs)) {
      throw new Error("invokeHardCapMs must be a positive duration");
    }
    if (!isPositiveDuration(cancelReceiptTimeoutMs)) {
      throw new Error("cancelReceiptTimeoutMs must be a positive duration");
    }
    if (
      invokeHardCapMs + cancelReceiptTimeoutMs >
      INVOKE_OWNERSHIP_RETENTION_MS
    ) {
      throw new Error(
        "invokeHardCapMs plus cancelReceiptTimeoutMs exceeds the safe timer bound"
      );
    }
    if (typeof cancelIdFactory !== "function") {
      throw new Error("cancelIdFactory must be a function");
    }
    if (typeof requestIdFactory !== "function") {
      throw new Error("requestIdFactory must be a function");
    }
    if (
      !Number.isInteger(gateAnswerTimeoutMs) ||
      gateAnswerTimeoutMs < 1 ||
      gateAnswerTimeoutMs > GATE_ANSWER_TIMEOUT_MS
    ) {
      throw new Error("gateAnswerTimeoutMs must be an integer from 1 to 30000");
    }
    if (
      !Number.isInteger(gatePresentationTimeoutMs) ||
      gatePresentationTimeoutMs < 1 ||
      gatePresentationTimeoutMs > GATE_PRESENTATION_TIMEOUT_MS
    ) {
      throw new Error("gatePresentationTimeoutMs must be an integer from 1 to 30000");
    }
    this.tokensByHostId = tokensByHostId;
    this.heartbeatTimeoutMs = heartbeatTimeoutMs;
    this.invokeIdleTimeoutMs = invokeIdleTimeoutMs;
    this.workspaceServingEnabled = workspaceServingEnabled === true;
    this.invokeHardCapMs = invokeHardCapMs;
    this.cancelReceiptTimeoutMs = cancelReceiptTimeoutMs;
    this.cancelTombstoneTtlMs = INVOKE_OWNERSHIP_RETENTION_MS;
    this.cancelIdFactory = cancelIdFactory;
    this.requestIdFactory = requestIdFactory;
    this.gateAnswerTimeoutMs = gateAnswerTimeoutMs;
    this.gatePresentationTimeoutMs = gatePresentationTimeoutMs;
    this.bindingDeadlineMs = BINDING_DEADLINE_MS;
    this.timers = timers;
    this.now = now;
    this.monotonicNow = monotonicNow;
    /** @type {Map<string, import("ws").WebSocket>} */
    this.connections = new Map();
    /** @type {Map<import("ws").WebSocket, number>} */
    this.connectionIdentities = new Map();
    this.nextConnectionIdentity = 0;
    /** @type {Map<import("ws").WebSocket, { hostId: string, timeout?: object }>} */
    this.heartbeatStates = new Map();
    /** @type {Map<string, { socket: import("ws").WebSocket, resolve: (v: any) => void, onEvent: (e: object) => void, text?: string, truncated?: boolean }>} */
    this.pendingRequests = new Map();
    /** @type {Map<string, { socket: import("ws").WebSocket, cancelId: string, timer?: object }>} */
    this.cancelTombstones = new Map();
    /** @type {Map<string, { answerId: string, requestId: string, gateId: string, socket: import("ws").WebSocket, pending: object, timer?: object, resolve: (v: any) => void }>} */
    this.pendingGateAnswers = new Map();
    /** @type {Map<string, { presentationAttemptId: string, requestId: string, gateId: string, presentationId: string, socket: import("ws").WebSocket, pending: object, timer?: object }>} */
    this.pendingGatePresentations = new Map();
    /** @type {Map<string, { abandonId: string, requestId: string, gateId: string, presentationId: string, socket: import("ws").WebSocket, timer?: object }>} */
    this.pendingGateAbandons = new Map();
    /** @type {Map<string, { accepted: boolean, socket: import("ws").WebSocket, connectionIdentity: number, requestId: string, gateId: string, presentationId: string }>} */
    this.gatePresentationReceipts = new Map();
    /** @type {Map<string, { accepted: boolean, socket: import("ws").WebSocket, connectionIdentity: number, requestId: string, gateId: string, presentationId: string }>} */
    this.gateAbandonReceipts = new Map();
    /** @type {Map<import("ws").WebSocket, number>} */
    this.pendingCountBySocket = new Map();
    /** @type {Map<string, { protocolVersion: number, capabilities: string[] }>} */
    this.hostInfo = new Map();
    /** @type {Map<string, { socketGeneration: number, revision: number, observedAt: number, bindingId?: string, workspaceId?: string, workspaceGeneration?: number, workspaceGenerationHighWater: Map<string, number>, offlineRetireAt?: number, retirementTimer?: object }>} */
    this.readinessAuthorities = new Map();
    /** @type {Map<string, object>} */
    this.readinessStates = new Map();
    /** @type {Map<string, { hostId: string, descriptorKey: string }>} */
    this.managedRoutes = new Map();
    /** @type {Map<string, { hostId: string, authority: object, mapping: object, channelIds: Set<string> }>} */
    this.managedDescriptors = new Map();
    this.closed = false;
    this.closePromise = undefined;

    this.wss = new WebSocketServer({ port, maxPayload: MAX_WS_PAYLOAD_BYTES });
    this.wss.on("connection", (socket) => this.#handleConnection(socket));
    this.onError = onError;
    this.onObservabilityEvent =
      typeof onObservabilityEvent === "function" ? onObservabilityEvent : undefined;
    /** @type {Map<string, number>} Socket replacements observed per host; stays 0 in off mode. */
    this.reconnectCounts = new Map();
    this.resourceDenials = 0;
    this.wss.on("error", (error) => {
      if (typeof this.onError === "function") this.onError(error);
      else console.error(`HostRegistry: WS server error: ${error?.message ?? String(error)}`);
    });
    this.heartbeatTimer = this.timers.setInterval(
      () => this.#sendHeartbeats(),
      heartbeatIntervalMs
    );
    this.heartbeatTimer.unref?.();
    this.wss.on("listening", () => {
      console.log(`HostRegistry: WS server listening on :${port}`);
    });
  }

  #handleConnection(socket) {
    let hostId;

    socket.once("message", (raw, isBinary) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        socket.close(1008, "invalid json");
        return;
      }
      if (isBinary || !isRegisterMessage(msg)) {
        socket.close(1008, "invalid register");
        return;
      }
      const expectedToken = this.tokensByHostId.get(msg.hostId);
      if (!hostTokenMatches(expectedToken, msg.token)) {
        socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER_DENIED, reason: "bad token" }));
        socket.close(1008, "auth failed");
        return;
      }

      hostId = msg.hostId;
      const wantsInventoryReceipt =
        (msg.protocolVersion ?? 0) >= PROTOCOL_VERSION_V3 &&
        Array.isArray(msg.capabilities) &&
        msg.capabilities.includes(WORKSPACE_READINESS_CAPABILITY) &&
        msg.capabilities.includes(WORKSPACE_INVENTORY_RECEIPT_CAPABILITY);
      const wantsReadiness =
        !wantsInventoryReceipt &&
        (msg.protocolVersion ?? 0) >= PROTOCOL_VERSION_V2 &&
        Array.isArray(msg.capabilities) &&
        msg.capabilities.includes(WORKSPACE_READINESS_CAPABILITY);
      const registerOk = wantsInventoryReceipt
        ? {
            type: MSG_TYPES.REGISTER_OK,
            protocolVersion: PROTOCOL_VERSION_V3,
            capabilities: negotiateCapabilities(V3_CAPABILITIES, msg.capabilities),
          }
        : wantsReadiness
        ? {
            type: MSG_TYPES.REGISTER_OK,
            protocolVersion: PROTOCOL_VERSION_V2,
            capabilities: negotiateCapabilities(V2_CAPABILITIES, msg.capabilities),
          }
        : {
            type: MSG_TYPES.REGISTER_OK,
            protocolVersion: PROTOCOL_VERSION,
            capabilities: negotiateCapabilities(BOT_CAPABILITIES, msg.capabilities),
          };
      if (!isRegisterOkMessage(registerOk)) {
        socket.close(1008, "invalid register response");
        return;
      }
      if (
        this.workspaceServingEnabled &&
        !satisfiesManagedProtocolFloor(msg, registerOk)
      ) {
        socket.send(
          JSON.stringify({
            type: MSG_TYPES.REGISTER_DENIED,
            reason: PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
            code: PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE,
          })
        );
        socket.close(1008, PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE);
        return;
      }
      const bindingEnabled = isInventoryReceiptCapabilityGate(msg, registerOk);
      if (
        bindingEnabled &&
        !(Array.isArray(msg.capabilities) &&
          msg.capabilities.includes(WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY))
      ) {
        console.error(
          `HostRegistry: host '${hostId}' rejected -- binding-enabled peer missing required ` +
            `capability '${WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY}' ` +
            `(BIND_AUTHORITY_VERIFICATION_REQUIRED)`
        );
        socket.send(
          JSON.stringify({
            type: MSG_TYPES.REGISTER_DENIED,
            reason: PROTOCOL_ERROR_CODES.BIND_AUTHORITY_VERIFICATION_REQUIRED,
            code: PROTOCOL_ERROR_CODES.BIND_AUTHORITY_VERIFICATION_REQUIRED,
          })
        );
        socket.close(1008, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_VERIFICATION_REQUIRED);
        return;
      }
      const previous = this.connections.get(hostId);
      if (previous && previous !== socket) {
        // Only binding-capable (v3) registrations count as reconnect churn;
        // off-mode (v0/v2) socket replacements leave the counter at rest.
        if (wantsInventoryReceipt) {
          this.reconnectCounts.set(
            hostId,
            Math.min(MAX_UINT53, (this.reconnectCounts.get(hostId) ?? 0) + 1)
          );
        } else if (!this.reconnectCounts.has(hostId)) {
          this.reconnectCounts.set(hostId, 0);
        }
        this.#dropConnection(hostId, previous, remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST));
        previous.terminate();
      } else if (!this.reconnectCounts.has(hostId)) {
        this.reconnectCounts.set(hostId, 0);
      }
      this.connections.set(hostId, socket);
      this.nextConnectionIdentity = Math.min(MAX_UINT53, this.nextConnectionIdentity + 1);
      this.connectionIdentities.set(socket, this.nextConnectionIdentity);
      this.heartbeatStates.set(socket, { hostId });
      const readinessEnabled =
        isReadinessCapabilityGate(msg, registerOk) || bindingEnabled;
      const protocolVersion = Math.min(
        registerOk.protocolVersion,
        msg.protocolVersion ?? 0
      );
      const capabilities = negotiateCapabilities(
        bindingEnabled ? V3_CAPABILITIES : readinessEnabled ? V2_CAPABILITIES : BOT_CAPABILITIES,
        msg.capabilities
      );
      this.hostInfo.set(hostId, { protocolVersion, capabilities });
      this.readinessStates.set(hostId, {
        socket,
        hostId,
        readinessEnabled,
        bindingEnabled,
        revision: 0,
        socketGeneration: undefined,
        observedAt: undefined,
        receivedAt: undefined,
        monoReceivedAt: undefined,
        expiresAt: undefined,
        monoExpiresAt: undefined,
        expiryTimer: undefined,
        hostDimensions: {
          connection: "online",
          runtime: "error",
          providerAuth: "unknown",
          modelProfile: "unknown",
          workspace: "unknown",
        },
        workspaceId: undefined,
        workspaceGeneration: undefined,
        bindingId: undefined,
        /** @type {Map<string, object>} */
        bindingReadiness: new Map(),
        /** @type {Map<string, object>} */
        bindingsById: new Map(),
        /** @type {Map<string, object>} */
        bindingsByDescriptor: new Map(),
        /** @type {Map<string, number>} */
        workspaceGenerationHighWater: new Map(),
        workspaceDimensions: undefined,
        workspaceSocketGeneration: undefined,
        workspaceRevision: undefined,
        workspaceObservedAt: undefined,
        workspaceReceivedAt: undefined,
        workspaceMonoReceivedAt: undefined,
        workspaceExpiresAt: undefined,
        workspaceMonoExpiresAt: undefined,
        workspaceExpiryTimer: undefined,
        hostExpired: false,
        hostPriorReady: false,
        workspaceExpired: false,
        workspacePriorReady: false,
        degraded: false,
        lastErrorAt: undefined,
        lastError: undefined,
        connected: true,
        rejected: false,
      });
      socket.send(JSON.stringify(registerOk));
      this.#reconcileManagedBindings(hostId);
      console.log(
        `HostRegistry: host '${hostId}' connected (${msg.label ?? "no label"}, ` +
          `protocol v${protocolVersion}, capabilities: ${capabilities.join(", ") || "none"})`
      );

      socket.on("message", (raw2, isBinary2) =>
        this.#handleMessage(socket, raw2, isBinary2)
      );
      socket.on("close", () => {
        const wasCurrent = this.#dropConnection(
          hostId,
          socket,
          remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST)
        );
        if (wasCurrent) console.log(`HostRegistry: host '${hostId}' disconnected`);
      });
    });

    socket.on("error", (err) => console.error("HostRegistry socket error:", err.message));
  }

  #handleMessage(socket, raw, isBinary) {
    if (isBinary) {
      socket.close(1008, "invalid frame");
      return;
    }

    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      socket.close(1008, "invalid json");
      return;
    }

    if (isPongMessage(msg)) {
      this.#acceptPong(socket);
      return;
    }
    if (msg?.type === MSG_TYPES.BIND_OK || msg?.type === MSG_TYPES.UNBIND_OK) {
      if (!this.#acceptBindingReply(socket, msg)) {
        socket.close(1008, "invalid binding reply");
      }
      return;
    }
    if (msg?.type === MSG_TYPES.READINESS) {
      const state = this.#bindingState(socket);
      if (state?.bindingEnabled) {
        if (!this.#acceptInventoryReceiptReadiness(state, msg)) {
          socket.close(1008, "invalid receipt readiness");
        }
        return;
      }
      if (!this.#acceptReadiness(socket, msg)) {
        socket.close(1008, "invalid readiness");
      }
      return;
    }
    if (!isEventMessage(msg)) {
      socket.close(1008, "invalid event");
      return;
    }

    if (msg.event?.type === MSG_TYPES.GATE_PRESENTATION_RESULT) {
      if (!isGatePresentationResultMessage(msg)) {
        socket.close(1008, "invalid gate presentation result");
        return;
      }
      this.#acceptGatePresentationResult(socket, msg);
      return;
    }
    if (msg.event?.type === MSG_TYPES.GATE_ABANDON_RESULT) {
      if (!isGateAbandonResultMessage(msg)) {
        socket.close(1008, "invalid gate abandon result");
        return;
      }
      this.#acceptGateAbandonResult(socket, msg);
      return;
    }
    if (msg.event?.type === MSG_TYPES.GATE_ANSWER_RESULT) {
      if (
        msg.done !== undefined ||
        msg.error !== undefined ||
        !isGateAnswerResultEvent(msg.event)
      ) {
        socket.close(1008, "invalid gate answer result");
        return;
      }
      this.#acceptGateAnswerResult(socket, msg.requestId, msg.event);
      return;
    }
    if (msg.event?.type === MSG_TYPES.CANCEL_RESULT) {
      if (!isCancelResultMessage(msg)) {
        socket.close(1008, "invalid cancel result");
        return;
      }
      this.#acceptCancelResult(socket, msg);
      return;
    }

    const pending = this.pendingRequests.get(msg.requestId);
    if (!pending) {
      const tombstone = this.cancelTombstones.get(msg.requestId);
      if (
        tombstone?.socket === socket &&
        tombstone.connectionIdentity === this.connectionIdentities.get(socket)
      ) {
        if (msg.event?.type === "invoke_terminal") {
          if (
            msg.done !== true ||
            msg.error !== undefined ||
            Object.keys(msg).length !== 4 ||
            !isInvokeTerminalEvent(msg.event)
          ) {
            socket.close(1008, "invalid invoke terminal");
            return;
          }
          this.#deleteCancelTombstone(msg.requestId);
        }
      }
      return;
    }
    if (
      pending.socket !== socket ||
      pending.connectionIdentity !== this.connectionIdentities.get(socket)
    ) {
      socket.close(1008, "request owner mismatch");
      return;
    }

    const isTerminal = msg.event?.type === "invoke_terminal";
    if (isTerminal) {
      if (
        msg.error !== undefined ||
        msg.done !== true ||
        Object.keys(msg).length !== 4 ||
        !isInvokeTerminalEvent(msg.event)
      ) {
        socket.close(1008, "invalid invoke terminal");
        return;
      }
      if (
        pending.cancellation?.receipt === "cancelled_before_start" &&
        msg.event.disposition !== "cancelled"
      ) {
        pending.settle({
          ok: false,
          error: interruptionUnconfirmedError(
            "cancellation_terminal_conflict"
          ),
        }, "cancellation_terminal_conflict");
        this.#retireCancellationTracker(pending);
        socket.close(1008, "conflicting cancellation terminal");
        return;
      }
      const { disposition, code } = msg.event;
      if (disposition === "completed") {
        const text = pending.truncated
          ? pending.text
            ? `${pending.text}\n${OUTPUT_TRUNCATED_NOTICE}`
            : OUTPUT_TRUNCATED_NOTICE
          : pending.text;
        pending.resolve({ ok: true, text, terminalDisposition: disposition });
      } else {
        pending.resolve({
          ok: false,
          error: terminalError(disposition, code),
        });
      }
      if (pending.gatePending) {
        this.#deactivateGateHandle(pending.gatePresentation ?? {}, "Expired");
      }
      this.#abandonGate(pending, "invoke_terminal");
      this.#deletePending(msg.requestId);
      this.#deleteCancelTombstone(msg.requestId);
      return;
    }
    if (msg.error !== undefined || msg.done !== undefined) {
      socket.close(1008, "invalid invoke terminal");
      return;
    }
    if (msg.event !== undefined) {
      if (pending.cancellation) return;
      const event = msg.event;
      // #35: a gate_request means the daemon's agent loop is now blocked awaiting
      // a user answer. Suspend the invoke idle timer (the user may take minutes);
      // the absolute hard-cap remains the backstop. onEvent renders the prompt to
      // the Discord channel; the answer is collected out of band via answerGate().
      if (isGateRequestEvent(event)) {
        if (!this.hostInfo.get(pending.hostId)?.capabilities.includes(GATE_PRESENTATION_CAPABILITY)) {
          socket.close(1008, "gate presentation not negotiated");
          return;
        }
        if (
          pending.gatePresentation?.gateId === event.gateId &&
          pending.gatePresentation.presentationId === event.presentationId
        ) {
          return;
        }
        this.#deactivateGateHandle(pending.gatePresentation ?? {}, "Replaced");
        this.#abandonGate(pending, "replaced");
        pending.gatePending = true;
        pending.gateId = event.gateId;
        this.timers.clearTimeout(pending.idleTimer);
        pending.idleTimer = undefined;
        // Route to the dedicated gate callback (carries requestId, needed to send
        // the answer back). Not forwarded to onEvent — gates are not stream text.
        const gate = {
            gateId: event.gateId,
            requestId: msg.requestId,
            presentationId: event.presentationId,
            prompt: event.prompt,
            kind: event.kind,
            multi: event.multi,
            choices: event.choices,
        };
        const presentation = {
          gateId: event.gateId,
          presentationId: event.presentationId,
          state: "awaiting_handle",
        };
        pending.gatePresentation = presentation;
        try {
          if (typeof pending.onGate !== "function") throw new Error("missing gate presenter");
          Promise.resolve(pending.onGate(gate)).then((handle) => {
            if (pending.gatePresentation !== presentation) {
              this.#deactivateGateHandle({ handle }, "Replaced");
              return;
            }
            if (
              !handle ||
              typeof handle.messageId !== "string" ||
              handle.messageId.length === 0 ||
              typeof handle.activate !== "function" ||
              typeof handle.update !== "function"
            ) {
              throw new Error("invalid gate presentation handle");
            }
            presentation.handle = handle;
            this.#presentGate(pending, presentation);
          }).catch(() => {
            if (pending.gatePresentation !== presentation) return;
            this.#deactivateGateHandle(presentation, "Presentation failed");
            this.#abandonGate(pending, "send_failed");
            this.#initiateCancellation(pending, "presentation_failed");
          });
        } catch {
          this.#abandonGate(pending, "send_failed");
          this.#initiateCancellation(pending, "presentation_failed");
        }
        return;
      }
      if (
        event?.type === "event_truncated" &&
        event?.code === "EVENT_PAYLOAD_TOO_LARGE"
      ) {
        pending.truncated = true;
      } else {
        const text = extractAssistantText(event);
        if (text !== undefined) pending.text = text;
      }
      pending.onEvent(event);
      this.#armIdleTimer(pending);
    }
  }

  #bindingState(socket) {
    const hostId = this.heartbeatStates.get(socket)?.hostId;
    const state = hostId ? this.readinessStates.get(hostId) : undefined;
    return state?.socket === socket && this.connections.get(hostId) === socket
      ? state
      : undefined;
  }

  /** Emits a local, flat, deeply frozen schema-v1 record. */
  #emitObservability(event, fields = {}) {
    const sink = this.onObservabilityEvent;
    if (typeof sink !== "function" || !OBSERVABILITY_EVENTS.includes(event)) return;
    const payload = {
      schemaVersion: 1,
      component: "bot",
      event,
      phase: boundedOpaque(fields.phase ?? "unknown"),
      observedAt: uint53(fields.observedAt) ?? uint53(this.now()) ?? 0,
    };
    for (const key of [
      "receivedAt", "expiresAt", "requestAt", "deadlineAt", "durationMs",
      "fenceSequence", "socketGeneration", "revision",
    ]) {
      const value = uint53(fields[key]);
      if (value !== undefined) payload[key] = value;
    }
    for (const key of ["hostId", "mappingId", "workspaceId", "bindingId", "transactionId"]) {
      if (fields[key] !== undefined) payload[key] = boundedOpaque(fields[key]);
    }
    if (fields.code !== undefined) {
      payload.code = fields.code === null ? null : boundedCode(fields.code);
    }
    if (fields.terminalDisposition !== undefined) {
      payload.terminalDisposition = boundedOpaque(
        fields.terminalDisposition
      );
    }
    // Keep the explicit check close to the boundary; additions require a
    // deliberate schema review rather than accidentally leaking a field.
    for (const key of Object.keys(payload)) {
      if (!OBSERVABILITY_KEYS.has(key)) return;
    }
    try {
      sink(deepFreeze(payload));
    } catch {
      // Observers must never disrupt host bookkeeping.
    }
  }

  #bindingObservabilityFields(state, binding, fields = {}) {
    const authority = binding?.authority;
    return {
      hostId: state?.hostId,
      mappingId: authority?.mappingId,
      workspaceId: authority?.workspaceId,
      bindingId: binding?.bindingId,
      fenceSequence: authority?.fenceGeneration,
      socketGeneration: binding?.socketGeneration,
      revision: binding?.revision,
      ...fields,
    };
  }

  #bindingDuration(binding) {
    return binding?.requestMonoAt === undefined
      ? undefined
      : Math.max(
          0,
          Math.min(
            MAX_UINT53,
            Math.trunc(this.monotonicNow() - binding.requestMonoAt),
          ),
        );
  }

  #armBindingDeadline(socket, binding) {
    const deadline = this.timers.setTimeout(() => {
      if (binding.deadline === deadline) {
        binding.deadline = undefined;
        this.#clearBindingReadinessExpiry(binding);
        const state = this.#bindingState(socket);
        this.#emitObservability("socket.retire", this.#bindingObservabilityFields(state, binding, {
          phase: "deadline",
          code: "BINDING_DEADLINE",
          durationMs: this.#bindingDuration(binding),
        }));
        // The ensuing close would otherwise emit a second, offline-phase
        // socket.retire for the same physical retirement; suppress it.
        if (state) state.socketRetired = true;
        socket.terminate();
      }
    }, this.bindingDeadlineMs);
    binding.deadline = deadline;
    deadline.unref?.();
  }

  #clearBindingDeadline(binding) {
    if (binding.deadline !== undefined) {
      this.timers.clearTimeout(binding.deadline);
      binding.deadline = undefined;
    }
  }

  #acceptBindingReply(socket, msg) {
    const state = this.#bindingState(socket);
    if (!state?.bindingEnabled) return false;
    if (msg.type === MSG_TYPES.BIND_OK) {
      if (!isInventoryReceiptBindOkMessage(msg)) return false;
      const binding = state.bindingsById.get(msg.bindingId);
      if (binding?.status === "unbinding") return true;
      if (binding?.status === "bound") {
        return binding.receipt?.inventoryGeneration === msg.inventoryGeneration &&
          binding.receipt?.inventoryFingerprint === msg.inventoryFingerprint &&
          binding.receipt?.bindingFingerprint === msg.bindingFingerprint;
      }
      if (
        !binding ||
        (binding.status !== "binding" && binding.status !== "pending")
      ) return false;
      const fingerprint = workspaceBindingFingerprint({
        authority: binding.authority,
        inventoryGeneration: msg.inventoryGeneration,
        inventoryFingerprint: msg.inventoryFingerprint,
      });
      if (fingerprint !== msg.bindingFingerprint) return false;
      if (binding.heldReadiness) {
        if (!this.#receiptMatchesReadiness(msg, binding.heldReadiness)) return false;
        binding.readiness = binding.heldReadiness;
        binding.heldReadiness = undefined;
      }
      this.#clearBindingDeadline(binding);
      binding.status = "bound";
      binding.receipt = Object.freeze({
        inventoryGeneration: msg.inventoryGeneration,
        inventoryFingerprint: msg.inventoryFingerprint,
        bindingFingerprint: msg.bindingFingerprint,
      });
      this.#emitObservability("bind.ok", this.#bindingObservabilityFields(state, binding, {
        phase: "bound",
        code: null,
        durationMs: this.#bindingDuration(binding),
      }));
      return true;
    }
    if (!isUnbindOkMessage(msg)) return false;
    const binding = state.bindingsById.get(msg.bindingId);
    if (!binding || binding.status !== "unbinding") return false;
    this.#clearBindingDeadline(binding);
    binding.status = "tombstone";
    state.bindingsByDescriptor.delete(binding.descriptorKey);
    this.#reconcileManagedBindings(state.hostId);
    return true;
  }

  #unbindBinding(state, binding) {
    if (binding.status === "unbinding" || binding.status === "tombstone") return;
    const hadReceipt = binding.status === "bound" && binding.receipt !== undefined;
    binding.status = "unbinding";
    binding.receipt = undefined;
    binding.readiness = undefined;
    binding.heldReadiness = undefined;
    this.#clearBindingReadinessExpiry(binding);
    binding.expiresAt = undefined;
    binding.monoExpiresAt = undefined;
    state.bindingsByDescriptor.delete(binding.descriptorKey);
    this.#clearBindingDeadline(binding);
    binding.requestAt = this.now();
    binding.requestMonoAt = this.monotonicNow();
    this.#armBindingDeadline(state.socket, binding);
    state.socket.send(JSON.stringify({
      type: MSG_TYPES.UNBIND_WORKSPACE,
      bindingId: binding.bindingId,
    }));
    if (hadReceipt) {
      this.#emitObservability("receipt.invalidate", this.#bindingObservabilityFields(state, binding, {
        phase: "unbind",
        code: "WORKSPACE_UNBOUND",
      }));
    }
  }

  #receiptMatchesReadiness(receipt, readiness) {
    return receipt.inventoryGeneration === readiness.inventoryGeneration &&
      receipt.inventoryFingerprint === readiness.inventoryFingerprint &&
      receipt.bindingFingerprint === readiness.bindingFingerprint;
  }

  #acceptInventoryReceiptReadiness(state, msg) {
    const receivedAt = this.now();
    if (!isInventoryReceiptReadinessMessage(msg, {
      currentSocketGeneration: state.receiptSocketGeneration,
      previous: state.receiptPrevious,
      receivedAt,
    })) return false;
    if (msg.bindingId === undefined) {
      const accepted = this.#acceptReadiness(state.socket, msg, receivedAt);
      if (accepted) {
        state.receiptSocketGeneration ??= msg.socketGeneration;
        state.receiptPrevious = msg;
      }
      return accepted;
    }
    const binding = state.bindingsById.get(msg.bindingId);
    if (!binding || binding.status === "tombstone") return false;
    if (binding.status === "unbinding") return true;
    if (
      binding.status !== "binding" &&
      binding.status !== "pending" &&
      binding.status !== "bound"
    ) return false;
    if (
      msg.workspaceId !== binding.authority.workspaceId ||
      msg.workspaceGeneration !== binding.authority.workspaceGeneration
    ) return false;
    if (!isInventoryReceiptReadinessMessage(msg, {
      currentSocketGeneration: binding.socketGeneration,
      previous: binding.receiptPrevious,
      receivedAt,
    })) return false;
    // A bound receipt must prove its exact accepted binding before it can
    // refresh any local freshness state or produce an acceptance event.
    if (
      binding.status === "bound" &&
      msg.lastError === undefined &&
      (!binding.receipt || !this.#receiptMatchesReadiness(binding.receipt, msg))
    ) return false;
    const ttlMs = normalizeReadinessTtl(msg.ttlMs);
    const monotonicReceivedAt = this.monotonicNow();
    state.receiptSocketGeneration ??= msg.socketGeneration;
    state.receiptPrevious = msg;
    this.#clearBindingReadinessExpiry(binding);
    binding.socketGeneration ??= msg.socketGeneration;
    binding.revision = msg.revision;
    binding.observedAt = msg.observedAt;
    binding.receiptPrevious = msg;
    binding.receivedAt = receivedAt;
    binding.monoReceivedAt = monotonicReceivedAt;
    binding.expiresAt = receivedAt + ttlMs;
    binding.monoExpiresAt = monotonicReceivedAt + Math.min(ttlMs, READINESS_MAX_TTL_MS);
    binding.expired = false;
    if (msg.lastError !== undefined) {
      const pending =
        msg.lastError.code === PROTOCOL_ERROR_CODES.INVENTORY_PENDING;
      const hadReceipt = binding.status === "bound" && binding.receipt !== undefined;
      if (!pending) this.#clearBindingDeadline(binding);
      binding.status = pending ? "pending" : "negative";
      binding.receipt = undefined;
      binding.readiness = Object.freeze({ ...msg });
      binding.heldReadiness = undefined;
      this.#clearBindingReadinessExpiry(binding);
      binding.expiresAt = undefined;
      binding.monoExpiresAt = undefined;
      if (hadReceipt) {
        this.#emitObservability("receipt.invalidate", this.#bindingObservabilityFields(state, binding, {
          phase: "drift",
          code: msg.lastError.code,
        }));
      }
      if (!pending) {
        this.#emitObservability("bind.negative", this.#bindingObservabilityFields(state, binding, {
          phase: "negative",
          code: msg.lastError.code,
          durationMs: this.#bindingDuration(binding),
        }));
      }
      return true;
    }
    this.#armBindingReadinessExpiry(state, binding, ttlMs);
    this.#emitObservability("readiness.accept", this.#bindingObservabilityFields(state, binding, {
      phase: "receipt",
      observedAt: receivedAt,
      receivedAt,
      expiresAt: binding.expiresAt,
      code: null,
    }));
    if (binding.status === "binding" || binding.status === "pending") {
      binding.heldReadiness = Object.freeze({ ...msg });
      return true;
    }
    if (binding.status !== "bound" || !binding.receipt) return false;
    binding.readiness = Object.freeze({ ...msg });
    return true;
  }

  #reconcileManagedBindings(hostId) {
    const state = this.readinessStates.get(hostId);
    if (
      !state?.bindingEnabled ||
      this.connections.get(hostId) !== state.socket
    ) return;
    const desired = [...this.managedDescriptors.entries()]
      .filter(([, descriptor]) => descriptor.hostId === hostId);

    for (const binding of state.bindingsByDescriptor.values()) {
      if (!this.managedDescriptors.has(binding.descriptorKey)) {
        this.#unbindBinding(state, binding);
      }
    }
    if ([...state.bindingsById.values()].some((binding) => binding.status === "unbinding")) {
      return;
    }
    for (const [descriptorKey, descriptor] of desired) {
      if (state.bindingsByDescriptor.has(descriptorKey)) continue;
      if (state.bindingsById.size >= MAX_BINDING_READINESS_STATES) continue;
      const requestAt = this.now();
      const binding = {
        bindingId: randomUUID(),
        descriptorKey,
        authority: descriptor.authority,
        mapping: descriptor.mapping,
        status: "binding",
        deadline: undefined,
        receipt: undefined,
        readiness: undefined,
        heldReadiness: undefined,
        requestAt,
        requestMonoAt: this.monotonicNow(),
        socketGeneration: undefined,
        revision: undefined,
        observedAt: undefined,
        receiptPrevious: undefined,
      };
      state.bindingsById.set(binding.bindingId, binding);
      state.bindingsByDescriptor.set(descriptorKey, binding);
      this.#armBindingDeadline(state.socket, binding);
      state.socket.send(JSON.stringify({
        type: MSG_TYPES.BIND_WORKSPACE,
        bindingId: binding.bindingId,
        ...binding.authority,
        mapping: binding.mapping,
      }));
      this.#emitObservability("bind.request", this.#bindingObservabilityFields(state, binding, {
        phase: "request",
        observedAt: requestAt,
        requestAt,
        deadlineAt: requestAt + this.bindingDeadlineMs,
        code: null,
      }));
    }
  }

  #addPending(requestId, entry) {
    this.pendingRequests.set(requestId, entry);
    this.pendingCountBySocket.set(
      entry.socket,
      (this.pendingCountBySocket.get(entry.socket) ?? 0) + 1
    );
  }

  #denyInvoke(hostId, error, fields = {}, code = error?.code) {
    this.#emitObservability("invoke.deny", {
      phase: "local_validation",
      hostId,
      code: code ?? PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
      ...fields,
    });
    return Promise.resolve({ ok: false, error });
  }
  #acceptReadiness(socket, msg, acceptedReceivedAt) {
    const heartbeat = this.heartbeatStates.get(socket);
    const hostId = heartbeat?.hostId;
    const state = hostId ? this.readinessStates.get(hostId) : undefined;
    if (
      !hostId ||
      this.connections.get(hostId) !== socket ||
      !state?.readinessEnabled ||
      state.socket !== socket ||
      state.rejected
    ) {
      return false;
    }

    const receivedAt = acceptedReceivedAt ?? this.now();
    const timestampInvalid =
      !Number.isSafeInteger(receivedAt) ||
      receivedAt < 0 ||
      !Number.isSafeInteger(msg?.observedAt) ||
      msg.observedAt < 0 ||
      (msg?.expiresAt !== undefined &&
        (!Number.isSafeInteger(msg.expiresAt) || msg.expiresAt < 0)) ||
      (msg?.lastError?.at !== undefined &&
        (!Number.isSafeInteger(msg.lastError.at) || msg.lastError.at < 0)) ||
      Math.abs(msg.observedAt - receivedAt) > READINESS_MAX_SKEW_MS;
    if (timestampInvalid) {
      this.#recordReadinessError(state, PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID, receivedAt);
      return false;
    }
    if (!isReadinessMessage(msg)) return false;

    const authority = this.#getReadinessAuthority(hostId);
    let authorityWorkspaceGenerationHighWater;
    if (state.socketGeneration === undefined && authority) {
      authorityWorkspaceGenerationHighWater = new Map(
        authority.workspaceGenerationHighWater ?? []
      );
      if (
        authority.workspaceId !== undefined &&
        authority.workspaceGeneration !== undefined
      ) {
        const retained = authorityWorkspaceGenerationHighWater.get(
          authority.workspaceId
        );
        authorityWorkspaceGenerationHighWater.set(
          authority.workspaceId,
          retained === undefined
            ? authority.workspaceGeneration
            : Math.max(retained, authority.workspaceGeneration)
        );
      }
      const authorityWorkspaceGeneration =
        msg.workspaceId !== undefined
          ? authorityWorkspaceGenerationHighWater.get(msg.workspaceId)
          : undefined;
      if (
        msg.socketGeneration <= authority.socketGeneration ||
        msg.observedAt < authority.observedAt ||
        (authorityWorkspaceGeneration !== undefined &&
          msg.workspaceGeneration < authorityWorkspaceGeneration)
      ) {
        this.#recordReadinessError(state, PROTOCOL_ERROR_CODES.READINESS_REPLAYED, receivedAt);
        return false;
      }
    }

    const previous =
      state.socketGeneration === undefined
        ? undefined
        : {
            socketGeneration: state.socketGeneration,
            revision: state.revision,
            observedAt: state.observedAt,
          };
    if (
      !isReadinessMessage(msg, {
        currentSocketGeneration: state.socketGeneration,
        previous,
        receivedAt,
      })
    ) {
      this.#recordReadinessError(state, PROTOCOL_ERROR_CODES.READINESS_REPLAYED, receivedAt);
      return false;
    }

    const hasWorkspace = msg.workspaceId !== undefined;
    const workspaceGenerationFence =
      authorityWorkspaceGenerationHighWater ??
      state.workspaceGenerationHighWater;
    const workspaceGenerationHighWater = hasWorkspace
      ? workspaceGenerationFence.get(msg.workspaceId)
      : undefined;
    const retainedWorkspaceBinding = hasWorkspace
      ? [...state.bindingReadiness.values()].find(
          (binding) => binding.workspaceId === msg.workspaceId
        )
      : undefined;
    if (
      hasWorkspace &&
      ((state.workspaceGeneration !== undefined &&
        msg.workspaceId === state.workspaceId &&
        msg.workspaceGeneration < state.workspaceGeneration) ||
        (workspaceGenerationHighWater !== undefined &&
          msg.workspaceGeneration < workspaceGenerationHighWater) ||
        (retainedWorkspaceBinding &&
          msg.workspaceGeneration < retainedWorkspaceBinding.workspaceGeneration))
    ) {
      this.#recordReadinessError(state, PROTOCOL_ERROR_CODES.READINESS_REPLAYED, receivedAt);
      return false;
    }
    if (
      hasWorkspace &&
      workspaceGenerationHighWater === undefined &&
      workspaceGenerationFence.size >= MAX_BINDING_READINESS_STATES
    ) {
      this.#recordReadinessError(
        state,
        PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED,
        receivedAt
      );
      return false;
    }

    if (authorityWorkspaceGenerationHighWater) {
      state.workspaceGenerationHighWater =
        authorityWorkspaceGenerationHighWater;
    }
    const ttlMs = normalizeReadinessTtl(msg.ttlMs);
    const monotonicReceivedAt = this.monotonicNow();
    this.#refreshExpired(state);
    const wasReadyBeforeFrame = this.#isCurrentReady(state);

    state.socketGeneration ??= msg.socketGeneration;
    state.revision = msg.revision;
    state.observedAt = msg.observedAt;
    state.receivedAt = receivedAt;
    state.monoReceivedAt = monotonicReceivedAt;
    state.connected = true;
    state.lastError = msg.lastError
      ? {
          code: msg.lastError.code,
          at: msg.lastError.at,
          remediation: {
            code: msg.lastError.remediation.code,
            retryable: msg.lastError.remediation.retryable,
            action: msg.lastError.remediation.action,
          },
        }
      : undefined;
    if (msg.lastError) {
      state.lastErrorAt = receivedAt;
      state.degraded = wasReadyBeforeFrame;
      if (wasReadyBeforeFrame) {
        state.hostPriorReady = true;
        if (hasWorkspace) state.workspacePriorReady = true;
      }
    }

    if (hasWorkspace) {
      state.workspaceGenerationHighWater.set(
        msg.workspaceId,
        msg.workspaceGeneration
      );
      for (const [bindingId, binding] of state.bindingReadiness) {
        if (
          binding.workspaceId === msg.workspaceId &&
          binding.workspaceGeneration < msg.workspaceGeneration
        ) {
          state.bindingReadiness.delete(bindingId);
        }
      }
      const generationChanged =
        state.workspaceId !== msg.workspaceId ||
        state.workspaceGeneration !== msg.workspaceGeneration;
      if (generationChanged) {
        this.#clearWorkspaceExpiry(state);
        state.workspacePriorReady = false;
        state.workspaceExpired = false;
      }
      state.workspaceId = msg.workspaceId;
      state.workspaceGeneration = msg.workspaceGeneration;
      state.bindingId = msg.bindingId;
      state.workspaceSocketGeneration = msg.socketGeneration;
      state.workspaceRevision = msg.revision;
      state.workspaceObservedAt = msg.observedAt;
      state.workspaceReceivedAt = receivedAt;
      state.workspaceMonoReceivedAt = monotonicReceivedAt;
      if (msg.bindingId !== undefined) {
        for (const [bindingId, binding] of state.bindingReadiness) {
          if (
            bindingId !== msg.bindingId &&
            binding.workspaceId === msg.workspaceId
          ) {
            state.bindingReadiness.delete(bindingId);
          }
        }
        if (
          !state.bindingReadiness.has(msg.bindingId) &&
          state.bindingReadiness.size >= MAX_BINDING_READINESS_STATES
        ) {
          const expired = [...state.bindingReadiness.values()]
            .filter((binding) => binding.monoExpiresAt <= monotonicReceivedAt)
            .sort(
              (left, right) =>
                left.monoExpiresAt - right.monoExpiresAt ||
                left.bindingId.localeCompare(right.bindingId)
            );
          if (expired.length === 0) {
            this.#recordReadinessError(
              state,
              PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED,
              receivedAt
            );
            return false;
          }
          state.bindingReadiness.delete(expired[0].bindingId);
        }
        state.bindingReadiness.set(msg.bindingId, {
          bindingId: msg.bindingId,
          workspaceId: msg.workspaceId,
          workspaceGeneration: msg.workspaceGeneration,
          socketGeneration: msg.socketGeneration,
          revision: msg.revision,
          dimensions: { ...msg.status },
          lastError: msg.lastError
            ? {
                code: state.lastError.code,
                at: state.lastError.at,
                remediation: { ...state.lastError.remediation },
              }
            : undefined,
          priorReady:
            state.bindingReadiness.get(msg.bindingId)?.priorReady === true ||
            (!msg.lastError && this.#dimensionsReady(msg.status)),
          receivedAt,
          expiresAt: receivedAt + ttlMs,
          monoExpiresAt:
            monotonicReceivedAt + Math.min(ttlMs, READINESS_MAX_TTL_MS),
        });
      }
      state.hostDimensions = { ...msg.status };
      state.workspaceDimensions = { ...msg.status };
      state.workspaceExpiresAt = receivedAt + ttlMs;
      state.workspaceMonoExpiresAt =
        monotonicReceivedAt + Math.min(ttlMs, READINESS_MAX_TTL_MS);
      state.workspaceExpired = false;
      state.hostExpired = false;
      state.expiresAt = receivedAt + ttlMs;
      state.monoExpiresAt =
        monotonicReceivedAt + Math.min(ttlMs, READINESS_MAX_TTL_MS);
      this.#armReadinessExpiry(state, false, ttlMs);
      this.#armReadinessExpiry(state, true, ttlMs);
    } else {
      state.hostDimensions = { ...msg.status };
      state.expiresAt = receivedAt + ttlMs;
      state.monoExpiresAt = monotonicReceivedAt + Math.min(ttlMs, READINESS_MAX_TTL_MS);
      state.hostExpired = false;
      this.#armReadinessExpiry(state, false, ttlMs);
    }

    if (!msg.lastError) {
      state.degraded = false;
      state.hostPriorReady = false;
      if (hasWorkspace) state.workspacePriorReady = false;
    }

    const priorAuthority = this.readinessAuthorities.get(hostId);
    if (priorAuthority?.retirementTimer) {
      this.timers.clearTimeout(priorAuthority.retirementTimer);
      priorAuthority.retirementTimer = undefined;
    }
    this.readinessAuthorities.set(hostId, {
      socketGeneration: state.socketGeneration,
      revision: state.revision,
      observedAt: state.observedAt,
      bindingId: hasWorkspace ? state.bindingId : undefined,
      workspaceId: hasWorkspace ? state.workspaceId : undefined,
      workspaceGeneration: hasWorkspace ? state.workspaceGeneration : undefined,
      workspaceGenerationHighWater: new Map(
        state.workspaceGenerationHighWater
      ),
    });
    this.#emitObservability("readiness.accept", {
      phase: state.bindingEnabled ? "v3-host" : "v2",
      observedAt: receivedAt,
      hostId,
      workspaceId: hasWorkspace ? state.workspaceId : undefined,
      bindingId: hasWorkspace ? state.bindingId : undefined,
      socketGeneration: state.socketGeneration,
      revision: state.revision,
      receivedAt,
      expiresAt: state.expiresAt,
      code: null,
    });
    return true;
  }

  #recordReadinessError(state, code, receivedAt) {
    const at =
      Number.isSafeInteger(receivedAt) && receivedAt >= 0
        ? receivedAt
        : Number.isSafeInteger(Date.now()) && Date.now() >= 0
          ? Date.now()
          : 0;
    const remediation = READINESS_REMEDIATIONS[code];
    if (!remediation) return;
    state.lastErrorAt = at;
    state.lastError = {
      code,
      at,
      remediation: { ...remediation },
    };
    state.degraded = true;
    state.rejected = true;
  }

  #armReadinessExpiry(state, workspace, ttlMs) {
    const key = workspace ? "workspaceExpiryTimer" : "expiryTimer";
    if (state[key]) this.timers.clearTimeout(state[key]);
    const delay = Math.min(ttlMs, READINESS_MAX_TTL_MS);
    state[key] = this.timers.setTimeout(() => {
      if (state[key] === undefined) return;
      const now = this.monotonicNow();
      if (!this.#transitionReadinessExpiry(state, workspace, now)) {
        const deadlineKey = workspace
          ? "workspaceMonoExpiresAt"
          : "monoExpiresAt";
        const deadline = state[deadlineKey];
        if (
          !state[workspace ? "workspaceExpired" : "hostExpired"] &&
          deadline !== undefined &&
          now < deadline
        ) {
          this.#armReadinessExpiry(
            state,
            workspace,
            Math.max(1, Math.ceil(deadline - now)),
          );
        } else {
          state[key] = undefined;
        }
      }
    }, delay);
    state[key]?.unref?.();
  }

  #transitionReadinessExpiry(
    state,
    workspace,
    now = this.monotonicNow(),
  ) {
    const deadlineKey = workspace ? "workspaceMonoExpiresAt" : "monoExpiresAt";
    const expiredKey = workspace ? "workspaceExpired" : "hostExpired";
    const priorReadyKey = workspace ? "workspacePriorReady" : "hostPriorReady";
    const timerKey = workspace ? "workspaceExpiryTimer" : "expiryTimer";
    const receivedKey = workspace ? "workspaceReceivedAt" : "receivedAt";
    const monoReceivedKey = workspace ? "workspaceMonoReceivedAt" : "monoReceivedAt";
    const expiresKey = workspace ? "workspaceExpiresAt" : "expiresAt";
    if (
      state[expiredKey] ||
      state[deadlineKey] === undefined ||
      now < state[deadlineKey]
    ) return false;
    if (state[timerKey]) this.timers.clearTimeout(state[timerKey]);
    state[timerKey] = undefined;
    const wasReady = this.#isCurrentReady(state);
    state[expiredKey] = true;
    if (wasReady) {
      state[priorReadyKey] = true;
      state.degraded = true;
    }
    this.#emitObservability("readiness.expire", {
      phase: workspace ? "workspace" : "host",
      hostId: state.hostId,
      workspaceId: workspace ? state.workspaceId : undefined,
      bindingId: workspace ? state.bindingId : undefined,
      socketGeneration: workspace ? state.workspaceSocketGeneration : state.socketGeneration,
      revision: workspace ? state.workspaceRevision : state.revision,
      receivedAt: state[receivedKey],
      expiresAt: state[expiresKey],
      durationMs: Math.max(
        0,
        Math.min(MAX_UINT53, Math.trunc(now - (state[monoReceivedKey] ?? 0))),
      ),
      code: PROTOCOL_ERROR_CODES.READINESS_EXPIRED,
    });
    return true;
  }

  #clearWorkspaceExpiry(state) {
    if (state.workspaceExpiryTimer) this.timers.clearTimeout(state.workspaceExpiryTimer);
    state.workspaceExpiryTimer = undefined;
    state.workspaceExpiresAt = undefined;
    state.workspaceMonoExpiresAt = undefined;
  }

  #clearBindingReadinessExpiry(binding) {
    if (binding?.expiryTimer) this.timers.clearTimeout(binding.expiryTimer);
    if (binding) binding.expiryTimer = undefined;
  }

  #armBindingReadinessExpiry(state, binding, ttlMs) {
    this.#clearBindingReadinessExpiry(binding);
    const timer = this.timers.setTimeout(() => {
      if (binding.expiryTimer !== timer) return;
      const now = this.monotonicNow();
      if (!this.#transitionBindingExpiry(state, binding, now)) {
        if (
          !binding.expired &&
          binding.monoExpiresAt !== undefined &&
          now < binding.monoExpiresAt
        ) {
          this.#armBindingReadinessExpiry(
            state,
            binding,
            Math.max(1, Math.ceil(binding.monoExpiresAt - now)),
          );
        } else {
          binding.expiryTimer = undefined;
        }
      }
    }, Math.min(ttlMs, READINESS_MAX_TTL_MS));
    binding.expiryTimer = timer;
    timer?.unref?.();
  }

  #transitionBindingExpiry(
    state,
    binding,
    now = this.monotonicNow(),
  ) {
    if (
      (binding.status !== "binding" &&
        binding.status !== "pending" &&
        binding.status !== "bound") ||
      binding.expired ||
      binding.monoExpiresAt === undefined ||
      now < binding.monoExpiresAt
    ) return false;
    this.#clearBindingReadinessExpiry(binding);
    binding.expired = true;
    this.#emitObservability("readiness.expire", this.#bindingObservabilityFields(state, binding, {
      phase: "receipt",
      receivedAt: binding.receivedAt,
      expiresAt: binding.expiresAt,
      durationMs: Math.max(
        0,
        Math.min(MAX_UINT53, Math.trunc(now - (binding.monoReceivedAt ?? 0))),
      ),
      code: PROTOCOL_ERROR_CODES.READINESS_EXPIRED,
    }));
    return true;
  }

  #isCurrentReady(state) {
    if (
      !state ||
      state.lastError ||
      state.hostExpired ||
      state.workspaceExpired ||
      !state.workspaceDimensions
    ) {
      return false;
    }
    return this.#allDimensionsReady(state);
  }

  #effectiveDimensions(state) {
    const dimensions = { ...state.hostDimensions };
    if (state.hostExpired) {
      dimensions.runtime = "error";
      dimensions.providerAuth = "unknown";
      dimensions.modelProfile = "unknown";
      dimensions.workspace = "unknown";
    } else if (state.workspaceExpired) {
      dimensions.workspace = "unknown";
    } else if (state.workspaceDimensions) {
      dimensions.workspace = state.workspaceDimensions.workspace;
    }
    return dimensions;
  }

  #refreshExpired(state) {
    this.#transitionReadinessExpiry(state, false);
    this.#transitionReadinessExpiry(state, true);
  }
  #allDimensionsReady(state) {
    const dimensions = this.#effectiveDimensions(state);
    return this.#dimensionsReady(dimensions);
  }

  #dimensionsReady(dimensions) {
    return READINESS_DIMENSIONS.every(
      (dimension) =>
        dimensions[dimension] === "ready" ||
        dimensions[dimension] === "configured" ||
        (dimension === "connection" && dimensions[dimension] === "online")
    );
  }

  #aggregate(state) {
    if (!state || this.connections.get(state.hostId) !== state.socket) return "offline";
    this.#refreshExpired(state);
    if (!state.readinessEnabled) return "online";
    const dimensions = this.#effectiveDimensions(state);
    if (dimensions.connection === "offline") return "offline";
    if (dimensions.runtime === "incompatible") return "incompatible";
    if (state.degraded || state.hostPriorReady || state.workspacePriorReady) return "degraded";
    if (!this.#isCurrentReady(state)) return "connected-not-ready";
    return "ready";
  }

  #bindingAggregate(state, binding) {
    if (!binding || this.connections.get(state.hostId) !== state.socket) return "offline";
    this.#transitionBindingExpiry(state, binding);
    const dimensions = binding.dimensions;
    if (!dimensions) return "connected-not-ready";
    if (dimensions.connection === "offline") return "offline";
    if (dimensions.runtime === "incompatible") return "incompatible";
    if (binding.lastError) {
      return "degraded";
    }
    if (binding.monoExpiresAt <= this.monotonicNow()) {
      return binding.priorReady ? "degraded" : "connected-not-ready";
    }
    return this.#dimensionsReady(dimensions) ? "ready" : "connected-not-ready";
  }

  #projectHost(hostId, state) {
    const projection = {
      hostId: redactOpaqueId(hostId),
      aggregate: this.#aggregate(state),
      lastErrorAt: state.lastErrorAt ?? null,
      revision: state.revision,
      socketGeneration: state.socketGeneration ?? null,
      reconnectCount: this.reconnectCounts.get(hostId) ?? 0,
    };
    if (state.readinessEnabled) {
      projection.dimensions = { ...this.#effectiveDimensions(state) };
    }
    if (state.workspaceId !== undefined) {
      if (state.bindingId !== undefined) projection.bindingId = redactOpaqueId(state.bindingId);
      projection.workspaceId = redactOpaqueId(state.workspaceId);
      projection.workspaceGeneration = state.workspaceGeneration;
    }
    if (state.observedAt !== undefined) projection.observedAt = state.observedAt;
    if (state.receivedAt !== undefined) projection.receivedAt = state.receivedAt;
    const localExpiry = state.workspaceExpiresAt ?? state.expiresAt;
    if (localExpiry !== undefined) projection.expiresAt = localExpiry;
    if (state.bindingReadiness.size > 0) {
      projection.bindings = [...state.bindingReadiness.values()]
        .map((binding) => ({
          bindingId: redactOpaqueId(binding.bindingId),
          workspaceId: redactOpaqueId(binding.workspaceId),
          workspaceGeneration: binding.workspaceGeneration,
          aggregate: this.#bindingAggregate(state, binding),
          dimensions: { ...binding.dimensions },
          receivedAt: binding.receivedAt,
          expiresAt: binding.expiresAt,
          lastErrorAt: binding.lastError ? binding.receivedAt : null,
        }))
        .sort((left, right) => left.bindingId.localeCompare(right.bindingId));
    }
    return projection;
  }

  #notReadyResult(state, aggregate) {
    return this.#notReadyFromDimensions(
      this.#effectiveDimensions(state),
      state.lastError,
      aggregate
    );
  }

  #bindingNotReadyResult(binding, aggregate) {
    return this.#notReadyFromDimensions(
      binding.dimensions,
      binding.lastError,
      aggregate
    );
  }

  #notReadyFromDimensions(dimensions, lastError, aggregate) {
    if (aggregate === "offline") {
      return { ...READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.CONNECTION_LOST] };
    }
    if (aggregate === "incompatible") {
      return {
        code: PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
        retryable: false,
        action: "contact_admin",
      };
    }
    if (aggregate === "degraded") {
      const remediation = lastError?.remediation;
      return remediation
        ? { ...remediation }
        : { ...READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.READINESS_EXPIRED] };
    }
    if (dimensions.providerAuth === "missing") {
      return { code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING, retryable: true, action: "login" };
    }
    if (dimensions.providerAuth === "invalid") {
      return {
        code: PROTOCOL_ERROR_CODES.PROVIDER_INVALID,
        retryable: false,
        action: "repair_profile",
      };
    }
    if (dimensions.modelProfile === "missing") {
      return {
        code: PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING,
        retryable: false,
        action: "repair_profile",
      };
    }
    if (dimensions.modelProfile === "invalid") {
      return {
        code: PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID,
        retryable: false,
        action: "repair_profile",
      };
    }
    if (dimensions.workspace === "unavailable") {
      return {
        code: PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
        retryable: false,
        action: "refresh_workspace",
      };
    }
    return {
      code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
      retryable: true,
      action: "retry_later",
    };
  }

  #settleGateAnswer(entry, result) {
    if (this.pendingGateAnswers.get(entry.answerId) !== entry) return false;
    this.pendingGateAnswers.delete(entry.answerId);
    this.timers.clearTimeout(entry.timer);
    entry.timer = undefined;
    if (entry.pending.gateAnswers?.get(entry.gateId) === entry) {
      entry.pending.gateAnswers.delete(entry.gateId);
    }
    entry.resolve(result);
    return true;
  }

  #acceptGateAnswerResult(socket, requestId, event) {
    const entry = this.pendingGateAnswers.get(event.answerId);
    if (
      !entry ||
      entry.socket !== socket ||
      entry.connectionIdentity !== this.connectionIdentities.get(socket) ||
      entry.requestId !== requestId ||
      entry.gateId !== event.gateId ||
      entry.presentationId !== event.presentationId
    ) {
      return;
    }

    if (!event.accepted) {
      this.#settleGateAnswer(entry, {
        ok: false,
        error: "gate answer was rejected",
        code: event.errorCode,
      });
      return;
    }

    const pending = entry.pending;
    // The SDK may publish a successor before the predecessor's answer receipt
    // arrives. Retire only the exact accepted predecessor.
    if (
      pending.gatePending &&
      pending.gateId === entry.gateId &&
      pending.gatePresentation?.presentationId === entry.presentationId
    ) {
      pending.gatePending = false;
      pending.gateId = undefined;
    }
    this.#settleGateAnswer(entry, { ok: true });
    if (
      !pending.gatePending &&
      this.pendingRequests.get(requestId) === pending
    ) {
      this.#armIdleTimer(pending);
    }
  }

  #rememberGateReceipt(receipts, id, entry, accepted) {
    const prior = receipts.get(id);
    if (prior) {
      return (
        prior.accepted === accepted &&
        prior.socket === entry.socket &&
        prior.connectionIdentity === entry.connectionIdentity &&
        prior.requestId === entry.requestId &&
        prior.gateId === entry.gateId &&
        prior.presentationId === entry.presentationId
      );
    }
    if (receipts.size >= MAX_GATE_PRESENTATION_ATTEMPTS) return false;
    receipts.set(id, { ...entry, accepted });
    const timer = this.timers.setTimeout(() => receipts.delete(id), this.gatePresentationTimeoutMs);
    timer?.unref?.();
    return true;
  }

  #deactivateGateHandle(presentation, state) {
    try {
      void Promise.resolve(presentation.handle?.update(state)).catch(() => {});
    } catch {
      // Discord presentation updates are best effort and never alter authority.
    }
  }

  #presentGate(pending, presentation) {
    if (
      this.pendingRequests.get(pending.requestId) !== pending ||
      pending.gatePresentation !== presentation
    ) return;
    if (
      pending.socket.readyState !== WebSocket.OPEN ||
      this.connections.get(pending.hostId) !== pending.socket ||
      this.pendingGatePresentations.size >= MAX_GATE_PRESENTATION_ATTEMPTS
    ) {
      this.#deactivateGateHandle(presentation, "Presentation failed");
      this.#abandonGate(pending, "send_failed");
      this.#initiateCancellation(pending, "presentation_failed");
      return;
    }
    const presentationAttemptId = randomUUID();
    const frame = {
      type: MSG_TYPES.PRESENT_GATE,
      requestId: pending.requestId,
      gateId: presentation.gateId,
      presentationId: presentation.presentationId,
      presentationAttemptId,
    };
    if (!isPresentGateMessage(frame)) {
      this.#deactivateGateHandle(presentation, "Presentation failed");
      this.#abandonGate(pending, "send_failed");
      this.#initiateCancellation(pending, "presentation_failed");
      return;
    }
    const entry = {
      ...frame,
      socket: pending.socket,
      connectionIdentity: pending.connectionIdentity,
      pending,
      timer: undefined,
    };
    presentation.presentationAttemptId = presentationAttemptId;
    presentation.state = "awaiting_receipt";
    this.pendingGatePresentations.set(presentationAttemptId, entry);
    entry.timer = this.timers.setTimeout(() => {
      if (this.pendingGatePresentations.get(presentationAttemptId) !== entry) return;
      this.pendingGatePresentations.delete(presentationAttemptId);
      this.#deactivateGateHandle(presentation, "Presentation timed out");
      if (pending.gatePresentation !== presentation) return;
      this.#abandonGate(pending, "presentation_timeout");
      this.#initiateCancellation(pending, "presentation_failed");
    }, this.gatePresentationTimeoutMs);
    entry.timer?.unref?.();
    try {
      pending.socket.send(JSON.stringify(frame), (error) => {
        if (!error || this.pendingGatePresentations.get(presentationAttemptId) !== entry) return;
        this.timers.clearTimeout(entry.timer);
        this.pendingGatePresentations.delete(presentationAttemptId);
        this.#deactivateGateHandle(presentation, "Presentation failed");
        if (pending.gatePresentation !== presentation) return;
        this.#abandonGate(pending, "send_failed");
        this.#initiateCancellation(pending, "presentation_failed");
      });
    } catch {
      this.timers.clearTimeout(entry.timer);
      this.pendingGatePresentations.delete(presentationAttemptId);
      this.#deactivateGateHandle(presentation, "Presentation failed");
      if (pending.gatePresentation !== presentation) return;
      this.#abandonGate(pending, "send_failed");
      this.#initiateCancellation(pending, "presentation_failed");
    }
  }

  #acceptGatePresentationResult(socket, msg) {
    const event = msg.event;
    const entry = this.pendingGatePresentations.get(event.presentationAttemptId);
    if (!entry) {
      const prior = this.gatePresentationReceipts.get(event.presentationAttemptId);
      if (
        prior &&
        !this.#rememberGateReceipt(this.gatePresentationReceipts, event.presentationAttemptId, {
          socket, connectionIdentity: this.connectionIdentities.get(socket),
          requestId: msg.requestId, gateId: event.gateId, presentationId: event.presentationId,
        }, event.accepted)
      ) {
        socket.close(1008, "conflicting gate presentation result");
      }
      return;
    }
    if (
      entry.socket !== socket ||
      entry.connectionIdentity !== this.connectionIdentities.get(socket) ||
      entry.requestId !== msg.requestId ||
      entry.gateId !== event.gateId ||
      entry.presentationId !== event.presentationId
    ) {
      socket.close(1008, "conflicting gate presentation result");
      return;
    }
    this.timers.clearTimeout(entry.timer);
    this.pendingGatePresentations.delete(event.presentationAttemptId);
    this.#rememberGateReceipt(this.gatePresentationReceipts, event.presentationAttemptId, entry, event.accepted);
    const presentation = entry.pending.gatePresentation;
    if (!presentation || presentation.presentationAttemptId !== event.presentationAttemptId) return;
    if (!event.accepted) {
      this.#deactivateGateHandle(presentation, "Presentation rejected");
      this.#abandonGate(entry.pending, "send_failed");
      this.#initiateCancellation(entry.pending, "presentation_failed");
      return;
    }
    presentation.state = "accepted";
    try {
      void Promise.resolve(presentation.handle.activate()).catch(() => {
        if (entry.pending.gatePresentation !== presentation) return;
        this.#deactivateGateHandle(presentation, "Presentation failed");
        this.#abandonGate(entry.pending, "send_failed");
        this.#initiateCancellation(entry.pending, "presentation_failed");
      });
    } catch {
      this.#deactivateGateHandle(presentation, "Presentation failed");
      this.#abandonGate(entry.pending, "send_failed");
      this.#initiateCancellation(entry.pending, "presentation_failed");
    }
  }

  #abandonGate(pending, reason) {
    const presentation = pending.gatePresentation;
    if (!presentation || presentation.abandonId || !presentation.presentationId) return;
    if (
      pending.socket.readyState !== WebSocket.OPEN ||
      this.connections.get(pending.hostId) !== pending.socket ||
      this.pendingGateAbandons.size >= MAX_GATE_PRESENTATION_ATTEMPTS
    ) return;
    const abandonId = randomUUID();
    const frame = {
      type: MSG_TYPES.ABANDON_GATE,
      requestId: pending.requestId,
      gateId: presentation.gateId,
      presentationId: presentation.presentationId,
      abandonId,
      reason,
    };
    if (!isAbandonGateMessage(frame)) return;
    const entry = {
      ...frame,
      socket: pending.socket,
      connectionIdentity: pending.connectionIdentity,
      timer: undefined,
    };
    presentation.abandonId = abandonId;
    this.pendingGateAbandons.set(abandonId, entry);
    entry.timer = this.timers.setTimeout(() => {
      if (this.pendingGateAbandons.get(abandonId) === entry) {
        this.pendingGateAbandons.delete(abandonId);
      }
    }, this.gatePresentationTimeoutMs);
    entry.timer?.unref?.();
    try {
      pending.socket.send(JSON.stringify(frame));
    } catch {
      this.timers.clearTimeout(entry.timer);
      this.pendingGateAbandons.delete(abandonId);
    }
  }

  #acceptGateAbandonResult(socket, msg) {
    const event = msg.event;
    const entry = this.pendingGateAbandons.get(event.abandonId);
    if (!entry) {
      const prior = this.gateAbandonReceipts.get(event.abandonId);
      if (
        prior &&
        !this.#rememberGateReceipt(this.gateAbandonReceipts, event.abandonId, {
          socket, connectionIdentity: this.connectionIdentities.get(socket),
          requestId: msg.requestId, gateId: event.gateId, presentationId: event.presentationId,
        }, event.accepted)
      ) {
        socket.close(1008, "conflicting gate abandon result");
      }
      return;
    }
    if (
      entry.socket !== socket ||
      entry.connectionIdentity !== this.connectionIdentities.get(socket) ||
      entry.requestId !== msg.requestId ||
      entry.gateId !== event.gateId ||
      entry.presentationId !== event.presentationId
    ) {
      socket.close(1008, "conflicting gate abandon result");
      return;
    }
    this.timers.clearTimeout(entry.timer);
    this.pendingGateAbandons.delete(event.abandonId);
    this.#rememberGateReceipt(this.gateAbandonReceipts, event.abandonId, entry, event.accepted);
  }

  #armIdleTimer(pending) {
    // #35: while a gate is pending the invoke is deliberately not idle-bounded
    // (it is waiting on a human); never re-arm until the gate is answered.
    if (pending.gatePending) return;
    this.timers.clearTimeout(pending.idleTimer);
    const idleTimer = this.timers.setTimeout(() => {
      if (
        pending.idleTimer !== idleTimer ||
        pending.gatePending ||
        this.pendingRequests.get(pending.requestId) !== pending
      ) {
        return;
      }
      pending.idleTimer = undefined;
      this.#initiateCancellation(pending, "idle_timeout");
    }, pending.idleMs);
    pending.idleTimer = idleTimer;
    idleTimer?.unref?.();
  }

  #deletePending(requestId) {
    const entry = this.pendingRequests.get(requestId);
    if (!entry) return;
    this.timers.clearTimeout(entry.idleTimer);
    this.timers.clearTimeout(entry.hardCapTimer);
    this.timers.clearTimeout(entry.cancelReceiptTimer);
    entry.idleTimer = undefined;
    entry.hardCapTimer = undefined;
    entry.cancelReceiptTimer = undefined;
    for (const [attemptId, presentation] of this.pendingGatePresentations) {
      if (presentation.requestId !== requestId) continue;
      this.timers.clearTimeout(presentation.timer);
      this.pendingGatePresentations.delete(attemptId);
    }

    this.pendingRequests.delete(requestId);
    const next = (this.pendingCountBySocket.get(entry.socket) ?? 0) - 1;
    if (next > 0) this.pendingCountBySocket.set(entry.socket, next);
    else this.pendingCountBySocket.delete(entry.socket);
  }

  #deleteCancelTombstone(requestId) {
    const entry = this.cancelTombstones.get(requestId);
    if (!entry) return;
    this.timers.clearTimeout(entry.timer);
    this.cancelTombstones.delete(requestId);
  }

  #retainCancelTombstone(pending) {
    this.#deleteCancelTombstone(pending.requestId);
    if (this.cancelTombstones.size >= MAX_CANCEL_TOMBSTONES) return false;
    const entry = {
      socket: pending.socket,
      connectionIdentity: pending.connectionIdentity,
      cancelId: pending.cancellation.cancelId,
    };
    const timer = this.timers.setTimeout(() => {
      if (this.cancelTombstones.get(pending.requestId) === entry) {
        this.cancelTombstones.delete(pending.requestId);
      }
    }, this.cancelTombstoneTtlMs);
    entry.timer = timer;
    timer?.unref?.();
    this.cancelTombstones.set(pending.requestId, entry);
    return true;
  }

  #retireCancellationTracker(pending) {
    if (this.#retainCancelTombstone(pending)) {
      this.#deletePending(pending.requestId);
    }
  }

  #initiateCancellation(pending, reason) {
    if (this.pendingRequests.get(pending.requestId) !== pending) return false;
    if (pending.cancellation) return true;
    if (
      pending.socket.readyState !== WebSocket.OPEN ||
      this.connections.get(pending.hostId) !== pending.socket
    ) {
      pending.settle({
        ok: false,
        error: terminalError("disconnected", PROTOCOL_ERROR_CODES.CONNECTION_LOST),
      }, "disconnect");
      this.#deletePending(pending.requestId);
      return false;
    }
    if (pending.gatePending) {
      this.#deactivateGateHandle(pending.gatePresentation ?? {}, "Expired");
      this.#abandonGate(
        pending,
        reason === "presentation_failed"
          ? "send_failed"
          : "presentation_timeout"
      );
    }
    const cancelId = this.cancelIdFactory();
    const cancelFrame = {
      type: MSG_TYPES.CANCEL_INVOKE,
      requestId: pending.requestId,
      cancelId,
      reason,
    };
    if (!isCancelInvokeMessage(cancelFrame)) {
      pending.settle({ ok: false, error: interruptionUnconfirmedError("cancellation_unconfirmed") });
      this.#deletePending(pending.requestId);
      return false;
    }
    pending.cancellation = { cancelId, reason };
    this.timers.clearTimeout(pending.idleTimer);
    this.timers.clearTimeout(pending.hardCapTimer);
    pending.idleTimer = undefined;
    pending.hardCapTimer = undefined;
    const receiptTimer = this.timers.setTimeout(() => {
      if (
        pending.cancelReceiptTimer !== receiptTimer ||
        this.pendingRequests.get(pending.requestId) !== pending
      ) return;
      pending.cancelReceiptTimer = undefined;
      pending.settle({
        ok: false,
        error: interruptionUnconfirmedError("cancellation_receipt_timeout"),
      }, "cancellation_receipt_timeout");
      this.#retireCancellationTracker(pending);
    }, this.cancelReceiptTimeoutMs);
    pending.cancelReceiptTimer = receiptTimer;
    receiptTimer?.unref?.();
    try {
      pending.socket.send(JSON.stringify(cancelFrame));
      return true;
    } catch {
      this.timers.clearTimeout(receiptTimer);
      pending.cancelReceiptTimer = undefined;
      pending.settle({
        ok: false,
        error: interruptionUnconfirmedError("cancellation_send_failed"),
      }, "cancellation_send_failed");
      this.#retireCancellationTracker(pending);
      return false;
    }
  }

  #acceptCancelResult(socket, msg) {
    const pending = this.pendingRequests.get(msg.requestId);
    if (
      !pending ||
      pending.socket !== socket ||
      pending.connectionIdentity !== this.connectionIdentities.get(socket) ||
      pending.cancellation?.cancelId !== msg.event.cancelId
    ) return;
    if (pending.cancellation.receipt !== undefined) {
      if (pending.cancellation.receipt !== msg.event.outcome) {
        socket.close(1008, "conflicting cancel result");
      }
      return;
    }
    this.timers.clearTimeout(pending.cancelReceiptTimer);
    pending.cancelReceiptTimer = undefined;
    if (msg.event.outcome === "cancelled_before_start") {
      pending.cancellation.receipt = msg.event.outcome;
      const terminalTimer = this.timers.setTimeout(() => {
        if (
          pending.cancelReceiptTimer !== terminalTimer ||
          this.pendingRequests.get(pending.requestId) !== pending
        ) {
          return;
        }
        pending.cancelReceiptTimer = undefined;
        pending.settle({
          ok: false,
          error: interruptionUnconfirmedError(
            "cancellation_terminal_timeout"
          ),
        }, "cancellation_terminal_timeout");
        this.#retireCancellationTracker(pending);
      }, this.cancelReceiptTimeoutMs);
      pending.cancelReceiptTimer = terminalTimer;
      terminalTimer?.unref?.();
      return;
    }
    if (msg.event.outcome === "cancellation_pending") {
      pending.settle({
        ok: false,
        error: interruptionUnconfirmedError("cancellation_pending"),
      }, "cancellation_pending");
      this.#retireCancellationTracker(pending);
      return;
    }
    pending.settle({
      ok: false,
      error: interruptionUnconfirmedError(msg.event.outcome),
    }, msg.event.outcome);
    this.#retireCancellationTracker(pending);
  }

  #failPendingForSocket(socket, error) {
    for (const [requestId, pending] of this.pendingRequests) {
      if (pending.socket !== socket) continue;
      this.#deactivateGateHandle(pending.gatePresentation ?? {}, "Disconnected");
      pending.resolve({
        ok: false,
        error: terminalError(
          "disconnected",
          typeof error?.code === "string" ? error.code : undefined
        ),
      });
      this.#deletePending(requestId);
    }
    for (const [requestId, tombstone] of this.cancelTombstones) {
      if (tombstone.socket === socket) this.#deleteCancelTombstone(requestId);
    }
    for (const entry of [...this.pendingGateAnswers.values()]) {
      if (entry.socket !== socket) continue;
      this.#settleGateAnswer(entry, {
        ok: false,
        error: "host disconnected before gate answer was confirmed",
        code: GATE_ANSWER_ERROR_CODES.FAILED,
      });
    }
    for (const [attemptId, presentation] of this.pendingGatePresentations) {
      if (presentation.socket !== socket) continue;
      this.timers.clearTimeout(presentation.timer);
      this.pendingGatePresentations.delete(attemptId);
    }
    for (const [abandonId, abandonment] of this.pendingGateAbandons) {
      if (abandonment.socket !== socket) continue;
      this.timers.clearTimeout(abandonment.timer);
      this.pendingGateAbandons.delete(abandonId);
    }
  }

  #acceptPong(socket) {
    const state = this.heartbeatStates.get(socket);
    if (!state?.timeout) return;

    this.timers.clearTimeout(state.timeout);
    state.timeout = undefined;
  }

  #clearHeartbeat(socket) {
    const state = this.heartbeatStates.get(socket);
    if (state?.timeout) this.timers.clearTimeout(state.timeout);
    this.heartbeatStates.delete(socket);
  }

  #dropConnection(hostId, socket, error) {
    // A replacement/heartbeat retirement can still have a live transport.
    // Send the single ownership-revocation frame before clearing local owner
    // state; a physical close has no writable transport and skips this path.
    if (socket.readyState === WebSocket.OPEN) {
      for (const pending of this.pendingRequests.values()) {
        if (pending.socket === socket) this.#initiateCancellation(pending, "disconnect");
      }
    }
    const wasCurrent = this.connections.get(hostId) === socket;
    if (wasCurrent) {
      this.connections.delete(hostId);
      this.hostInfo.delete(hostId);
      const readiness = this.readinessStates.get(hostId);
      if (readiness) this.#markOfflineReadiness(readiness);
    }
    this.#clearHeartbeat(socket);
    this.connectionIdentities.delete(socket);
    this.#failPendingForSocket(socket, error);
    return wasCurrent;
  }

  #markOfflineReadiness(state) {
    if (state.expiryTimer) this.timers.clearTimeout(state.expiryTimer);
    if (state.workspaceExpiryTimer) this.timers.clearTimeout(state.workspaceExpiryTimer);
    state.expiryTimer = undefined;
    state.workspaceExpiryTimer = undefined;
    state.expiresAt = undefined;
    state.monoExpiresAt = undefined;
    state.workspaceExpiresAt = undefined;
    state.workspaceMonoExpiresAt = undefined;
    for (const binding of state.bindingsById?.values() ?? []) {
      this.#clearBindingDeadline(binding);
      this.#clearBindingReadinessExpiry(binding);
      if (binding.status === "bound" && binding.receipt !== undefined) {
        this.#emitObservability("receipt.invalidate", this.#bindingObservabilityFields(state, binding, {
          phase: "offline",
          code: "CONNECTION_LOST",
        }));
      }
    }
    state.bindingsById?.clear();
    state.bindingsByDescriptor?.clear();
    if (state.bindingEnabled && !state.socketRetired) {
      this.#emitObservability("socket.retire", {
        phase: "offline",
        code: "CONNECTION_LOST",
        hostId: state.hostId,
        socketGeneration: state.socketGeneration,
        revision: state.revision,
      });
    }
    state.connected = false;
    state.hostDimensions = { ...state.hostDimensions, connection: "offline" };
    if (state.workspaceDimensions) {
      state.workspaceDimensions = { ...state.workspaceDimensions, connection: "offline" };
    }
    const authority = this.#getReadinessAuthority(state.hostId);
    if (authority && authority.offlineRetireAt === undefined) {
      authority.offlineRetireAt =
        this.monotonicNow() + READINESS_MAX_TTL_MS;
    }
    if (authority) this.#armAuthorityRetirement(state.hostId, authority);
  }

  #getReadinessAuthority(hostId) {
    const authority = this.readinessAuthorities.get(hostId);
    if (!authority || authority.offlineRetireAt === undefined) return authority;
    if (this.monotonicNow() < authority.offlineRetireAt) return authority;
    if (authority.retirementTimer) {
      this.timers.clearTimeout(authority.retirementTimer);
      authority.retirementTimer = undefined;
    }
    if (this.readinessAuthorities.get(hostId) === authority) {
      this.readinessAuthorities.delete(hostId);
    }
    return undefined;
  }

  #armAuthorityRetirement(hostId, authority) {
    if (authority.retirementTimer) {
      this.timers.clearTimeout(authority.retirementTimer);
      authority.retirementTimer = undefined;
    }
    if (
      this.closed ||
      authority.offlineRetireAt === undefined ||
      this.readinessAuthorities.get(hostId) !== authority
    ) {
      return;
    }
    const delay = Math.max(
      0,
      authority.offlineRetireAt - this.monotonicNow()
    );

    const timer = this.timers.setTimeout(() => {
      if (authority.retirementTimer !== timer) return;
      authority.retirementTimer = undefined;
      if (this.closed || this.readinessAuthorities.get(hostId) !== authority) {
        return;
      }
      if (this.monotonicNow() < authority.offlineRetireAt) {
        this.#armAuthorityRetirement(hostId, authority);
        return;
      }
      this.readinessAuthorities.delete(hostId);
    }, delay);
    authority.retirementTimer = timer;
    timer?.unref?.();
  }

  #expireHeartbeat(hostId, socket, timeout) {
    const state = this.heartbeatStates.get(socket);
    if (state?.timeout !== timeout) return;

    this.#dropConnection(hostId, socket, remediationError(PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT));
    socket.terminate();
  }

  #sendHeartbeats() {
    if (this.closed) return;

    for (const [hostId, socket] of this.connections) {
      const state = this.heartbeatStates.get(socket);
      if (!state || state.timeout) continue;
      if (socket.readyState !== WebSocket.OPEN) {
        this.#dropConnection(hostId, socket, remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST));
        continue;
      }

      let timeout;
      timeout = this.timers.setTimeout(
        () => this.#expireHeartbeat(hostId, socket, timeout),
        this.heartbeatTimeoutMs
      );
      timeout.unref?.();
      state.timeout = timeout;

      try {
        socket.send(PING_PAYLOAD, (error) => {
          if (!error) return;
          this.#dropConnection(hostId, socket, remediationError(PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT));
          socket.terminate();
        });
      } catch {
        this.#dropConnection(hostId, socket, remediationError(PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT));
        socket.terminate();
      }
    }
  }

  close() {
    if (this.closePromise) return this.closePromise;

    this.closed = true;
    this.timers.clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = undefined;

    for (const socket of this.wss.clients) {
      for (const pending of this.pendingRequests.values()) {
        if (pending.socket === socket) {
          this.#initiateCancellation(pending, "disconnect");
        }
      }
      const state = this.heartbeatStates.get(socket);
      if (state) {
        this.#dropConnection(state.hostId, socket, remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST));
      } else {
        this.#clearHeartbeat(socket);
      }
      socket.close(1001, "bot shutting down");
    }
    for (const entry of [...this.pendingGateAnswers.values()]) {
      this.#settleGateAnswer(entry, {
        ok: false,
        error: "host disconnected before gate answer was confirmed",
        code: GATE_ANSWER_ERROR_CODES.FAILED,
      });
    }
    this.connections.clear();
    this.hostInfo.clear();
    for (const state of this.readinessStates.values()) {
      for (const key of [
        "expiryTimer",
        "workspaceExpiryTimer",
      ]) {
        if (state[key]) this.timers.clearTimeout(state[key]);
        state[key] = undefined;
      }
      for (const binding of state.bindingsById?.values() ?? []) {
        this.#clearBindingDeadline(binding);
        this.#clearBindingReadinessExpiry(binding);
      }
    }
    this.readinessStates.clear();
    this.reconnectCounts.clear();
    for (const authority of this.readinessAuthorities.values()) {
      if (authority.retirementTimer) {
        this.timers.clearTimeout(authority.retirementTimer);
        authority.retirementTimer = undefined;
      }
    }
    this.readinessAuthorities.clear();

    this.closePromise = new Promise((resolve, reject) => {
      this.wss.close((error) => (error ? reject(error) : resolve()));
    });
    return this.closePromise;
  }

  setManagedRoutes(routes) {
    if (routes === null || typeof routes !== "object" || Array.isArray(routes)) {
      throw new TypeError("MANAGED_ROUTES_INVALID");
    }
    const nextRoutes = new Map();
    const nextDescriptors = new Map();
    for (const [channelId, route] of Object.entries(routes)) {
      if (typeof channelId !== "string" || channelId.length === 0 || !route) {
        throw new TypeError("MANAGED_ROUTES_INVALID");
      }
      const authority = freezeManagedAuthorityDescriptor(route.hostId, route);
      if (!authority) throw new TypeError("MANAGED_AUTHORITY_INVALID");
      const descriptorKey = canonicalJsonHash(authority);
      let descriptor = nextDescriptors.get(descriptorKey);
      if (!descriptor) {
        descriptor = { hostId: authority.hostId, authority, mapping: route.mapping, channelIds: new Set() };
        nextDescriptors.set(descriptorKey, descriptor);
      }
      descriptor.channelIds.add(channelId);
      nextRoutes.set(channelId, { hostId: authority.hostId, descriptorKey });
    }
    const affectedHosts = new Set([
      ...[...this.managedDescriptors.values()].map((descriptor) => descriptor.hostId),
      ...[...nextDescriptors.values()].map((descriptor) => descriptor.hostId),
    ]);
    this.managedRoutes = nextRoutes;
    this.managedDescriptors = nextDescriptors;
    for (const hostId of affectedHosts) this.#reconcileManagedBindings(hostId);
  }

  getManagedRouteBinding(channelId) {
    const route = this.managedRoutes.get(channelId);
    if (!route) return undefined;
    const state = this.readinessStates.get(route.hostId);
    if (!state?.bindingEnabled || this.connections.get(route.hostId) !== state.socket) {
      return Object.freeze({ compatible: false });
    }
    const binding = state.bindingsByDescriptor.get(route.descriptorKey);
    if (!binding || binding.status !== "bound") {
      return Object.freeze({ compatible: false });
    }
    return Object.freeze({
      compatible: true,
      bindingId: binding.bindingId,
      state: binding.status,
    });
  }

  isOnline(hostId) {
    return this.connections.has(hostId);
  }

  listOnline() {
    return [...this.connections.keys()];
  }

  /**
   * Returns the redacted, receiver-local readiness projection for one host.
   * No token, workDir, path, URL, credential, prompt, or raw error crosses
   * this boundary.
   */
  getHostReadiness(hostId) {
    const state = this.readinessStates.get(hostId);
    if (!state || this.connections.get(hostId) !== state.socket) return undefined;
    return this.#projectHost(hostId, state);
  }

  /** Returns redacted readiness projections for connected and safely retained offline hosts. */
  listHosts() {
    return [...this.readinessStates.entries()].map(([hostId, state]) =>
      this.#projectHost(hostId, state)
    );
  }

  /**
   * Returns the negotiated protocol version and shared capabilities for a
   * connected host, or `undefined` if the host is not currently registered.
   * A legacy (v0) daemon reports `{ protocolVersion: 0, capabilities: [] }`.
   *
   * @param {string} hostId
   */
  getHostInfo(hostId) {
    const info = this.hostInfo.get(hostId);
    if (!info) return undefined;
    return {
      protocolVersion: info.protocolVersion,
      capabilities: [...info.capabilities],
    };
  }

  /** Returns a constant-shape, receiver-local schema-v1 gauge snapshot. */
  getObservabilitySnapshot() {
    let ready = 0;
    let degraded = 0;
    let expired = 0;
    for (const state of this.readinessStates.values()) {
      for (const binding of state.bindingsById.values()) {
        this.#transitionBindingExpiry(state, binding);
      }
      const aggregate = this.#aggregate(state);
      if (aggregate === "ready") ready++;
      if (aggregate === "degraded") degraded++;
      if (
        state.hostExpired ||
        state.workspaceExpired ||
        [...state.bindingsById.values()].some((binding) => binding.expired)
      ) {
        expired++;
      }
    }
    const replacements = [...this.reconnectCounts.values()]
      .reduce((total, count) => Math.min(MAX_UINT53, total + count), 0);
    return deepFreeze({
      schemaVersion: 1,
      component: "bot",
      observedAt: uint53(this.now()) ?? 0,
      gauges: {
        "hosts.connected": Math.min(MAX_UINT53, this.connections.size),
        "hosts.ready": Math.min(MAX_UINT53, ready),
        "hosts.degraded": Math.min(MAX_UINT53, degraded),
        "hosts.expired": Math.min(MAX_UINT53, expired),
        "invokes.inFlight": Math.min(MAX_UINT53, this.pendingRequests.size),
        "resourceDenials.total": this.resourceDenials,
        "socketReplacements.total": replacements,
      },
    });
  }

  #findBindingReadiness(state, routeIdentity = {}) {
    let match;
    for (const binding of state.bindingReadiness.values()) {
      if (
        routeIdentity.bindingId !== undefined &&
        binding.bindingId !== routeIdentity.bindingId
      ) continue;
      if (
        routeIdentity.workspaceId !== undefined &&
        binding.workspaceId !== routeIdentity.workspaceId
      ) continue;
      if (
        routeIdentity.workspaceGeneration !== undefined &&
        binding.workspaceGeneration !== routeIdentity.workspaceGeneration
      ) continue;
      if (match) return undefined;
      match = binding;
    }
    return match;
  }

/**
 * Sends an invoke request to a host and resolves once the daemon reports
 * an exact `invoke_terminal` event with `done: true` for that requestId.
 * Streamed events are delivered via onEvent before that authoritative terminal
 * frame. Bot-local idle and hard-cap expiry are unconfirmed wait failures, not
 * daemon terminal dispositions.
 *
 * @param {string} hostId
 * @param {string} workDir
 * @param {object} command
 * @param {(event: object) => void} onEvent
 * @param {number} timeoutMs Idle timeout: resets on each streamed event.
 * @param {(gate: { gateId: string, requestId: string, presentationId: string, prompt: string, kind: string, multi?: boolean, choices?: {value: unknown, label: string}[] }) => Promise<{messageId: string, activate: () => unknown, update: (state: string) => unknown}> | {messageId: string, activate: () => unknown, update: (state: string) => unknown}} [onGate]
 *   Renders the exact Discord presentation and returns its inactive handle;
 *   answer routing activates only after the daemon accepts present_gate.
 * @param {{ bindingId?: string, mappingId?: string, mappingGeneration?: number, mappingVersion?: number,
 *   sourcePlatform?: string, workspaceId?: string, workspaceGeneration?: number, authority?: object }} [routeIdentity]
 * @param {(requestId: string) => void} [onRequestCreated]
 */
  async invoke(
    hostId,
    workDir,
    command,
    onEvent,
    timeoutMs = this.invokeIdleTimeoutMs,
    onGate,
    routeIdentity,
    onRequestCreated
  ) {
    let managedAuthority;
    try {
      managedAuthority = freezeManagedAuthorityDescriptor(hostId, routeIdentity);
      if (managedAuthority) {
        routeIdentity = Object.freeze({ ...routeIdentity, authority: managedAuthority });
      }
    } catch {
      return this.#denyInvoke(hostId, remediationError(PROTOCOL_ERROR_CODES.CONFIG_INVALID));
    }
    const socket = this.connections.get(hostId);
    const readiness = this.readinessStates.get(hostId);
    let selectedBindingId;
    let selectedBindingTelemetry;
    if (managedAuthority) {
      const descriptorKey = canonicalJsonHash(managedAuthority);
      const binding =
        socket &&
        readiness?.socket === socket &&
        readiness.bindingEnabled
        ? readiness.bindingsByDescriptor.get(descriptorKey)
        : undefined;
      if (
        !binding ||
        binding.status !== "bound" ||
        routeIdentity.bindingId !== binding.bindingId
      ) {
        return this.#denyInvoke(
          hostId,
          remediationError(PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE)
        );
      }
      selectedBindingId = binding.bindingId;
      selectedBindingTelemetry = binding;
      if (!this.workspaceServingEnabled) {
        return this.#denyInvoke(
          hostId,
          remediationError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE)
        );
      }
    }
    if (!socket) {
      return this.#denyInvoke(
        hostId,
        remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST)
      );
    }
    if (readiness?.readinessEnabled && !readiness.bindingEnabled) {
      const hasBindingSelector =
        routeIdentity?.bindingId !== undefined ||
        routeIdentity?.workspaceId !== undefined ||
        routeIdentity?.workspaceGeneration !== undefined;
      const binding =
        hasBindingSelector
          ? this.#findBindingReadiness(readiness, routeIdentity)
          : undefined;
      selectedBindingId = binding?.bindingId;
      selectedBindingTelemetry = binding;
      const aggregate =
        hasBindingSelector && binding
          ? this.#bindingAggregate(readiness, binding)
          : this.#aggregate(readiness);
      if (aggregate === "offline") {
        return this.#denyInvoke(hostId, this.#notReadyResult(readiness, aggregate));
      }
      if (!this.workspaceServingEnabled) {
        return this.#denyInvoke(
          hostId,
          remediationError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE)
        );
      }
      if (hasBindingSelector && !binding) {
        return this.#denyInvoke(
          hostId,
          remediationError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED)
        );
      }
      if (aggregate !== "ready") {
        return this.#denyInvoke(
          hostId,
          binding
            ? this.#bindingNotReadyResult(binding, aggregate)
            : this.#notReadyResult(readiness, aggregate)
        );
      }
    }

    const usesV2 = readiness?.readinessEnabled === true;
    if (!usesV2 && isManagedPathFreeRoute(workDir, routeIdentity)) {
      return this.#denyInvoke(
        hostId,
        remediationError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE)
      );
    }
    const requiresGatePresentation =
      command?.kind === "prompt" ||
      command?.kind === "steer" ||
      command?.kind === "follow_up";
    const capabilities = this.hostInfo.get(hostId)?.capabilities ?? [];
    if (requiresGatePresentation && !capabilities.includes(GATE_PRESENTATION_CAPABILITY)) {
      return this.#denyInvoke(
        hostId,
        remediationError(PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE)
      );
    }

    // Bot-side network backpressure guard, NOT host-wide resource admission
    // authority. This per-socket pending cap bounds how many invokes the bot
    // will forward to a single daemon connection before applying flow control;
    // it is a thin, two-layer safeguard that intentionally mirrors (by
    // convention, asserted equal in test) the daemon's authoritative
    // AdmissionBudget in-flight-invoke ceiling. The single source of truth for
    // host-wide admission (8 active workspaces / 8 SDK sessions / 64 in-flight
    // invokes) is the daemon process; this is layer-two, not a second
    // authority.
    const pendingForSocket = this.pendingCountBySocket.get(socket) ?? 0;
    if (pendingForSocket >= V0_LIMITS.MAX_PENDING_PER_HOST) {
      this.resourceDenials = Math.min(MAX_UINT53, this.resourceDenials + 1);
      return this.#denyInvoke(
        hostId,
        remediationError(PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED),
        {
          phase: "bot_admission",
          socketGeneration: readiness?.socketGeneration,
          revision: readiness?.revision,
        }
      );
    }

    const requestId = this.requestIdFactory();
    if (
      this.pendingRequests.has(requestId) ||
      this.cancelTombstones.has(requestId)
    ) {
      return this.#denyInvoke(
        hostId,
        remediationError(PROTOCOL_ERROR_CODES.LEASE_CONFLICT)
      );
    }
    const invoke = { type: MSG_TYPES.INVOKE, requestId, command };
    if (usesV2) {
      const {
        authority: _authority,
        sourcePlatform: _sourcePlatform,
        ...wireRouteIdentity
      } = routeIdentity ?? {};
      const effectiveRouteIdentity = {
        ...wireRouteIdentity,
        bindingId: routeIdentity?.bindingId ?? selectedBindingId,
      };
      for (const [key, value] of Object.entries(effectiveRouteIdentity)) {
        if (value !== undefined && value !== null) invoke[key] = value;
      }
      if (workDir !== undefined && workDir !== null) invoke.workDir = workDir;
      if (!isInvokeMessage(invoke, { v2: true })) {
        return this.#denyInvoke(
          hostId,
          remediationError(PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED)
        );
      }
    } else {
      invoke.workDir = workDir;
      if (!isInvokeMessage(invoke)) {
        return this.#denyInvoke(
          hostId,
          "invalid invoke request",
          {},
          PROTOCOL_ERROR_CODES.CONFIG_INVALID
        );
      }
    }

    let payload;
    try {
      payload = JSON.stringify(invoke);
    } catch {
      return this.#denyInvoke(
        hostId,
        "invoke request is not serializable",
        {},
        PROTOCOL_ERROR_CODES.CONFIG_INVALID
      );
    }
    if (Buffer.byteLength(payload) > MAX_WS_PAYLOAD_BYTES) {
      return this.#denyInvoke(
        hostId,
        "invoke request exceeds WebSocket payload limit",
        {},
        PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED
      );
    }
    if (
      !capabilities.includes(TERMINAL_DISPOSITION_CAPABILITY) ||
      !capabilities.includes(INVOKE_CANCELLATION_CAPABILITY)
    ) {
      return this.#denyInvoke(
        hostId,
        remediationError(PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE)
      );
    }

    const invokeTelemetryContext = Object.freeze({
      hostId,
      bindingId: selectedBindingId,
      workspaceId: routeIdentity?.workspaceId,
      mappingId: routeIdentity?.mappingId,
      fenceSequence: managedAuthority?.fenceGeneration,
      socketGeneration: selectedBindingTelemetry
        ? selectedBindingTelemetry.socketGeneration
        : readiness?.socketGeneration,
      revision: selectedBindingTelemetry
        ? selectedBindingTelemetry.revision
        : readiness?.revision,
    });
    return new Promise((resolve) => {
      let settled = false;
      const transactionId = randomUUID();
      const requestAt = this.now();
      const monotonicStartedAt = this.monotonicNow();
      const pending = {
        requestId,
        hostId,
        socket,
        connectionIdentity: this.connectionIdentities.get(socket),
        onEvent,
        onGate,
        idleMs: timeoutMs,
        idleTimer: undefined,
        hardCapTimer: undefined,
        cancelReceiptTimer: undefined,
        cancellation: undefined,
        gatePending: false,
        gateId: undefined,
        gatePresentation: undefined,
        gateAnswers: new Map(),
        settle: (result, terminalPhase) => {
          if (settled) return;
          settled = true;
          this.timers.clearTimeout(pending.idleTimer);
          this.timers.clearTimeout(pending.hardCapTimer);
          const finishedAt = this.monotonicNow();
          this.#emitObservability("invoke.finish", {
            phase: terminalPhase ??
              (result.ok
                ? "success"
                : result.error?.code === PROTOCOL_ERROR_CODES.CONNECTION_LOST ||
                    result.error?.code === PROTOCOL_ERROR_CODES.HEARTBEAT_TIMEOUT
                  ? "disconnect"
                  : "remote_error"),
            ...invokeTelemetryContext,
            transactionId,
            requestAt,
            durationMs: Math.max(0, Math.min(MAX_UINT53, Math.trunc(finishedAt - monotonicStartedAt))),
            code: result.ok
              ? null
              : result.error?.code ?? PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
            terminalDisposition:
              result.terminalDisposition ??
              result.error?.terminalDisposition,
          });
          resolve(result);
        },
        resolve: (result) => pending.settle(result),
      };
      pending.hardCapTimer = this.timers.setTimeout(() => {
        this.#initiateCancellation(pending, "hard_cap");
      }, this.invokeHardCapMs);
      pending.hardCapTimer?.unref?.();

      this.#addPending(requestId, pending);
      this.#armIdleTimer(pending);
      this.#emitObservability("invoke.start", {
        phase: "dispatch",
        ...invokeTelemetryContext,
        transactionId,
        requestAt,
        deadlineAt: requestAt + this.invokeHardCapMs,
        code: null,
      });

      socket.send(payload);
      try {
        onRequestCreated?.(requestId);
      } catch {
        this.#initiateCancellation(pending, "presentation_failed");
      }
    });
  }

  /**
   * Begins cancellation of one exact, currently bot-owned invocation. The
   * daemon terminal frame remains the only proof that it actually stopped.
   *
   * @param {string} hostId
   * @param {string} requestId
   * @param {"user_cancelled"|"presentation_failed"} reason
   */
  cancelInvoke(hostId, requestId, reason) {
    if (reason !== "user_cancelled" && reason !== "presentation_failed") {
      return { ok: false, error: "invalid cancellation reason" };
    }
    const pending = this.pendingRequests.get(requestId);
    if (
      !pending ||
      pending.hostId !== hostId ||
      this.connections.get(hostId) !== pending.socket
    ) {
      return { ok: false, error: "no owned in-flight request" };
    }
    const started = this.#initiateCancellation(pending, reason);
    return started
      ? { ok: true, cancelId: pending.cancellation.cancelId }
      : { ok: false, error: "cancellation could not be sent" };
  }

  /**
   * Deliver a user's answer to a pending workflow gate and await the daemon's
   * receipt for that exact attempt. A rejection or bounded receipt timeout
   * retains the gate so the user can retry. The invoke idle timer resumes only
   * after an accepted receipt retires the currently presented gate.
   *
   * @param {string} hostId
   * @param {string} requestId
   * @param {string} gateId
   * @param {string} presentationId
   * @param {string} answer
   */
  async answerGate(hostId, requestId, gateId, presentationId, answer) {
    const pending = this.pendingRequests.get(requestId);
    if (!pending) {
      return { ok: false, error: "no in-flight request for that answer" };
    }
    const socket = this.connections.get(hostId);
    if (
      !socket ||
      socket !== pending.socket ||
      socket.readyState !== WebSocket.OPEN
    ) {
      return { ok: false, error: `host '${hostId}' is not connected` };
    }
    if (
      !pending.gatePending ||
      pending.gateId !== gateId ||
      pending.gatePresentation?.presentationId !== presentationId ||
      pending.gatePresentation?.state !== "accepted"
    ) {
      return { ok: false, error: "no matching pending gate for that answer" };
    }
    if (pending.gateAnswers.has(gateId)) {
      return { ok: false, error: "an answer for that gate is already pending" };
    }
    let outstanding = 0;
    for (const entry of this.pendingGateAnswers.values()) {
      if (entry.socket === socket) outstanding += 1;
    }
    if (outstanding >= V0_LIMITS.MAX_PENDING_PER_HOST) {
      return { ok: false, error: "host has too many unconfirmed gate answers" };
    }

    const answerId = randomUUID();
    const message = {
      type: MSG_TYPES.ANSWER,
      requestId,
      gateId,
      presentationId,
      answerId,
      answer,
    };
    if (!isAnswerMessage(message)) {
      return { ok: false, error: "invalid gate answer" };
    }
    let payload;
    try {
      payload = JSON.stringify(message);
    } catch {
      return { ok: false, error: "gate answer is not serializable" };
    }
    if (Buffer.byteLength(payload) > MAX_WS_PAYLOAD_BYTES) {
      return { ok: false, error: "gate answer exceeds WebSocket payload limit" };
    }

    return new Promise((resolve) => {
      const entry = {
        answerId,
        requestId,
        gateId,
        presentationId,
        socket,
        connectionIdentity: pending.connectionIdentity,
        pending,
        timer: undefined,
        resolve,
      };
      pending.gateAnswers.set(gateId, entry);
      this.pendingGateAnswers.set(answerId, entry);
      entry.timer = this.timers.setTimeout(() => {
        this.#settleGateAnswer(entry, {
          ok: false,
          error: "timed out waiting for gate answer receipt",
          code: GATE_ANSWER_ERROR_CODES.FAILED,
        });
      }, this.gateAnswerTimeoutMs);
      entry.timer?.unref?.();

      try {
        socket.send(payload, (error) => {
          if (!error) return;
          this.#settleGateAnswer(entry, {
            ok: false,
            error: "failed to send gate answer",
            code: GATE_ANSWER_ERROR_CODES.FAILED,
          });
        });
      } catch {
        this.#settleGateAnswer(entry, {
          ok: false,
          error: "failed to send gate answer",
          code: GATE_ANSWER_ERROR_CODES.FAILED,
        });
      }
    });
  }
}

export function extractAssistantText(event) {
  const message = event?.message ?? event?.assistantMessageEvent?.message;
  if (message?.role !== "assistant") return undefined;

  const text = extractTextFromContent(message.content);
  return text.length > 0 ? text : undefined;
}

function extractTextFromContent(content) {
  if (typeof content === "string") return content;

  if (!Array.isArray(content)) return "";

  return content
    .map((part) => {
      if (typeof part === "string") return part;
      if (!part || typeof part !== "object") return "";
      if (typeof part.text === "string") return part.text;
      if (typeof part.value === "string") return part.value;
      if (typeof part.content === "string") return part.content;
      return "";
    })
    .join("");
}
