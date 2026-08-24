import { WebSocket, WebSocketServer } from "ws";
import { randomUUID, timingSafeEqual } from "node:crypto";
import {
  CAPABILITIES,
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
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  isAnswerMessage,
  isEventMessage,
  isGateRequestEvent,
  isInvokeMessage,
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
import {
  validateWorkspaceAuthorityDescriptor,
  workspaceBindingFingerprint,
} from "@gjc-remote/shared/workspace-binding";

const HEARTBEAT_INTERVAL_MS = 30_000;
const HEARTBEAT_TIMEOUT_MS = 10_000;
const INVOKE_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const INVOKE_HARD_CAP_MS = 30 * 60 * 1000;
const OUTPUT_TRUNCATED_NOTICE = "[output truncated: too large]";
export const MAX_BINDING_READINESS_STATES = 64;
const BINDING_DEADLINE_MS = 10_000;
// Observability: bounded inventory-lifecycle events for the /hosts and E2E
// surfaces. Only these names are allowed, and every field is passed through a
// strict allowlist so tokens, workDir, raw identities, ACLs, and inventory
// bytes can never leak. Fingerprints are truncated to a short prefix.
const OBSERVABILITY_EVENTS = Object.freeze([
  "bind.request",
  "bind.ok",
  "bind.negative",
  "receipt.invalidate",
  "socket.retire",
]);
const OBSERVABILITY_FINGERPRINT_PREFIX_LENGTH = 12;
const PING_PAYLOAD = JSON.stringify(PING);
const V2_CAPABILITIES = Object.freeze([...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY]);
const V3_CAPABILITIES = Object.freeze([
  ...V2_CAPABILITIES,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
]);
const SYSTEM_TIMERS = {
  setInterval: (callback, delay) => setInterval(callback, delay),
  clearInterval: (timer) => clearInterval(timer),
  setTimeout: (callback, delay) => setTimeout(callback, delay),
  clearTimeout: (timer) => clearTimeout(timer),
};

function isPositiveDuration(value) {
  return Number.isFinite(value) && value > 0;
}
function redactOpaqueId(value) {
  return isWorkspaceId(String(value)) ? String(value) : "[redacted-host]";
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
function normalizeRemoteError(error) {
  if (error && typeof error === "object") {
    const code = typeof error.code === "string" ? error.code : undefined;
    const remediation = code ? READINESS_REMEDIATIONS[code] : undefined;
    return remediation
      ? { code, ...remediation }
      : { code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME, ...READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME] };
  }
  if (typeof error !== "string") {
    return {
      code: PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
      ...READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME],
    };
  }
  try {
    const parsed = JSON.parse(error);
    if (parsed && typeof parsed === "object") return normalizeRemoteError(parsed);
  } catch {
    // Legacy daemon errors are already bounded and sanitized by the daemon.
  }
  return error;
}
function remediationError(code) {
  return {
    ...(READINESS_REMEDIATIONS[code] ??
      READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME]),
    code,
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
    this.tokensByHostId = tokensByHostId;
    this.heartbeatTimeoutMs = heartbeatTimeoutMs;
    this.invokeIdleTimeoutMs = invokeIdleTimeoutMs;
    this.workspaceServingEnabled = workspaceServingEnabled === true;
    this.invokeHardCapMs = invokeHardCapMs;
    this.bindingDeadlineMs = BINDING_DEADLINE_MS;
    this.timers = timers;
    this.now = now;
    this.monotonicNow = monotonicNow;
    /** @type {Map<string, import("ws").WebSocket>} */
    this.connections = new Map();
    /** @type {Map<import("ws").WebSocket, { hostId: string, timeout?: object }>} */
    this.heartbeatStates = new Map();
    /** @type {Map<string, { socket: import("ws").WebSocket, resolve: (v: any) => void, onEvent: (e: object) => void, text?: string, truncated?: boolean }>} */
    this.pendingRequests = new Map();
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
    /** @type {Map<string, { hostId: string, authority: object, channelIds: Set<string> }>} */
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
      const previous = this.connections.get(hostId);
      if (previous && previous !== socket) {
        // Only binding-capable (v3) registrations count as reconnect churn;
        // off-mode (v0/v2) socket replacements leave the counter at rest.
        if (wantsInventoryReceipt) {
          this.reconnectCounts.set(hostId, (this.reconnectCounts.get(hostId) ?? 0) + 1);
        } else if (!this.reconnectCounts.has(hostId)) {
          this.reconnectCounts.set(hostId, 0);
        }
        this.#dropConnection(hostId, previous, remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST));
        previous.terminate();
      } else if (!this.reconnectCounts.has(hostId)) {
        this.reconnectCounts.set(hostId, 0);
      }
      this.connections.set(hostId, socket);
      this.heartbeatStates.set(socket, { hostId });
      const wantsReadiness =
        !wantsInventoryReceipt &&
        (msg.protocolVersion ?? 0) >= PROTOCOL_VERSION_V2 &&
        Array.isArray(msg.capabilities) &&
        msg.capabilities.includes(WORKSPACE_READINESS_CAPABILITY);
      const registerOk = wantsInventoryReceipt
        ? {
            type: MSG_TYPES.REGISTER_OK,
            protocolVersion: PROTOCOL_VERSION_V3,
            capabilities: V3_CAPABILITIES,
          }
        : wantsReadiness
        ? {
            type: MSG_TYPES.REGISTER_OK,
            protocolVersion: PROTOCOL_VERSION_V2,
            capabilities: V2_CAPABILITIES,
          }
        : {
            type: MSG_TYPES.REGISTER_OK,
            protocolVersion: PROTOCOL_VERSION,
            capabilities: CAPABILITIES,
          };
      if (!isRegisterOkMessage(registerOk)) {
        socket.close(1008, "invalid register response");
        return;
      }
      const bindingEnabled = isInventoryReceiptCapabilityGate(msg, registerOk);
      const readinessEnabled =
        isReadinessCapabilityGate(msg, registerOk) || bindingEnabled;
      const protocolVersion = Math.min(
        registerOk.protocolVersion,
        msg.protocolVersion ?? 0
      );
      const capabilities = negotiateCapabilities(
        bindingEnabled ? V3_CAPABILITIES : readinessEnabled ? V2_CAPABILITIES : CAPABILITIES,
        msg.capabilities
      );
      this.hostInfo.set(hostId, { protocolVersion, capabilities });
      this.readinessStates.set(hostId, {
        socket,
        hostId,
        readinessEnabled,
        bindingEnabled,
        receiptSocketGeneration: undefined,
        receiptPrevious: undefined,
        revision: 0,
        socketGeneration: undefined,
        observedAt: undefined,
        receivedAt: undefined,
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

    const pending = this.pendingRequests.get(msg.requestId);
    if (!pending) return;
    if (pending.socket !== socket) {
      socket.close(1008, "request owner mismatch");
      return;
    }

    if (msg.error !== undefined) {
      pending.resolve({ ok: false, error: normalizeRemoteError(msg.error) });
      this.#deletePending(msg.requestId);
      return;
    }
    if (msg.event !== undefined) {
      const event = msg.event;
      // #35: a gate_request means the daemon's agent loop is now blocked awaiting
      // a user answer. Suspend the invoke idle timer (the user may take minutes);
      // the absolute hard-cap remains the backstop. onEvent renders the prompt to
      // the Discord channel; the answer is collected out of band via answerGate().
      if (isGateRequestEvent(event)) {
        pending.gatePending = true;
        pending.gateId = event.gateId;
        this.timers.clearTimeout(pending.idleTimer);
        pending.idleTimer = undefined;
        // Route to the dedicated gate callback (carries requestId, needed to send
        // the answer back). Not forwarded to onEvent — gates are not stream text.
        try {
          pending.onGate?.({
            gateId: event.gateId,
            requestId: msg.requestId,
            prompt: event.prompt,
            kind: event.kind,
            choices: event.choices,
          });
        } catch (error) {
          console.error(
            "HostRegistry gate handler failed:",
            error instanceof Error ? error.message : String(error)
          );
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
      // Any non-gate event means the agent resumed, so the gate (if any) resolved.
      pending.gatePending = false;
      pending.gateId = undefined;
      pending.onEvent(event);
      this.#armIdleTimer(pending);
    }
    if (msg.done) {
      const text = pending.truncated
        ? pending.text
          ? `${pending.text}\n${OUTPUT_TRUNCATED_NOTICE}`
          : OUTPUT_TRUNCATED_NOTICE
        : pending.text;
      pending.resolve({ ok: true, text });
      this.#deletePending(msg.requestId);
    }
  }

  #bindingState(socket) {
    const hostId = this.heartbeatStates.get(socket)?.hostId;
    const state = hostId ? this.readinessStates.get(hostId) : undefined;
    return state?.socket === socket && this.connections.get(hostId) === socket
      ? state
      : undefined;
  }

  /**
   * Emits a bounded inventory-lifecycle event to the optional observer. Only
   * allowlisted, sanitized fields are forwarded: identities are redacted with
   * the same grammar as /hosts projections and fingerprints are truncated to a
   * short prefix, so tokens, workDir, raw identities, ACLs, and inventory bytes
   * can never leak. Observer failures never disrupt the registry.
   */
  #emitObservability(event, fields = {}) {
    const sink = this.onObservabilityEvent;
    if (typeof sink !== "function" || !OBSERVABILITY_EVENTS.includes(event)) return;
    const payload = { event };
    if (typeof fields.phase === "string") payload.phase = fields.phase;
    if (typeof fields.code === "string") payload.code = fields.code;
    if (typeof fields.bindingId === "string") {
      payload.bindingId = redactOpaqueId(fields.bindingId);
    }
    if (typeof fields.workspaceId === "string") {
      payload.workspaceId = redactOpaqueId(fields.workspaceId);
    }
    if (Number.isSafeInteger(fields.generation)) payload.generation = fields.generation;
    if (typeof fields.fingerprint === "string" && fields.fingerprint.length > 0) {
      payload.fingerprintPrefix = fields.fingerprint.slice(
        0,
        OBSERVABILITY_FINGERPRINT_PREFIX_LENGTH
      );
    }
    try {
      sink(Object.freeze(payload));
    } catch {
      // Observers must never disrupt host bookkeeping.
    }
  }

  #armBindingDeadline(socket, binding) {
    const deadline = this.timers.setTimeout(() => {
      if (binding.deadline === deadline) {
        binding.deadline = undefined;
        this.#emitObservability("socket.retire", {
          phase: "deadline",
          code: "BINDING_DEADLINE",
          bindingId: binding.bindingId,
        });
        // The ensuing close would otherwise emit a second, offline-phase
        // socket.retire for the same physical retirement; suppress it.
        const state = this.#bindingState(socket);
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
      this.#emitObservability("bind.ok", {
        phase: "bound",
        bindingId: binding.bindingId,
        workspaceId: binding.authority?.workspaceId,
        generation: msg.inventoryGeneration,
        fingerprint: msg.inventoryFingerprint,
      });
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
    state.bindingsByDescriptor.delete(binding.descriptorKey);
    this.#clearBindingDeadline(binding);
    this.#armBindingDeadline(state.socket, binding);
    state.socket.send(JSON.stringify({
      type: MSG_TYPES.UNBIND_WORKSPACE,
      bindingId: binding.bindingId,
    }));
    if (hadReceipt) {
      this.#emitObservability("receipt.invalidate", {
        phase: "unbind",
        code: "WORKSPACE_UNBOUND",
        bindingId: binding.bindingId,
        workspaceId: binding.authority?.workspaceId,
      });
    }
  }

  #receiptMatchesReadiness(receipt, readiness) {
    return receipt.inventoryGeneration === readiness.inventoryGeneration &&
      receipt.inventoryFingerprint === readiness.inventoryFingerprint &&
      receipt.bindingFingerprint === readiness.bindingFingerprint;
  }

  #acceptInventoryReceiptReadiness(state, msg) {
    if (!isInventoryReceiptReadinessMessage(msg, {
      currentSocketGeneration: state.receiptSocketGeneration,
      previous: state.receiptPrevious,
      receivedAt: this.now(),
    })) return false;
    if (msg.bindingId === undefined) {
      const accepted = this.#acceptReadiness(state.socket, msg);
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
      msg.workspaceId !== binding.authority.workspaceId ||
      msg.workspaceGeneration !== binding.authority.workspaceGeneration
    ) return false;
    if (
      state.receiptSocketGeneration !== undefined &&
      state.receiptSocketGeneration !== msg.socketGeneration
    ) return false;
    state.receiptSocketGeneration ??= msg.socketGeneration;
    state.receiptPrevious = msg;
    if (msg.lastError !== undefined) {
      const pending =
        msg.lastError.code === PROTOCOL_ERROR_CODES.INVENTORY_PENDING;
      const hadReceipt = binding.status === "bound" && binding.receipt !== undefined;
      if (!pending) this.#clearBindingDeadline(binding);
      binding.status = pending ? "pending" : "negative";
      binding.receipt = undefined;
      binding.readiness = Object.freeze({ ...msg });
      binding.heldReadiness = undefined;
      if (hadReceipt) {
        this.#emitObservability("receipt.invalidate", {
          phase: "drift",
          code: msg.lastError.code,
          bindingId: binding.bindingId,
          workspaceId: binding.authority?.workspaceId,
        });
      }
      if (!pending) {
        this.#emitObservability("bind.negative", {
          phase: "negative",
          code: msg.lastError.code,
          bindingId: binding.bindingId,
          workspaceId: binding.authority?.workspaceId,
        });
      }
      return true;
    }
    if (binding.status === "binding" || binding.status === "pending") {
      binding.heldReadiness = Object.freeze({ ...msg });
      return true;
    }
    if (binding.status !== "bound" || !binding.receipt) return false;
    if (!this.#receiptMatchesReadiness(binding.receipt, msg)) return false;
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
      const binding = {
        bindingId: randomUUID(),
        descriptorKey,
        authority: descriptor.authority,
        status: "binding",
        deadline: undefined,
        receipt: undefined,
        readiness: undefined,
        heldReadiness: undefined,
      };
      state.bindingsById.set(binding.bindingId, binding);
      state.bindingsByDescriptor.set(descriptorKey, binding);
      this.#armBindingDeadline(state.socket, binding);
      state.socket.send(JSON.stringify({
        type: MSG_TYPES.BIND_WORKSPACE,
        bindingId: binding.bindingId,
        ...binding.authority,
      }));
      this.#emitObservability("bind.request", {
        phase: "request",
        bindingId: binding.bindingId,
        workspaceId: binding.authority?.workspaceId,
        generation: binding.authority?.workspaceGeneration,
      });
    }
  }

  #addPending(requestId, entry) {
    this.pendingRequests.set(requestId, entry);
    this.pendingCountBySocket.set(
      entry.socket,
      (this.pendingCountBySocket.get(entry.socket) ?? 0) + 1
    );
  }
  #acceptReadiness(socket, msg) {
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

    const receivedAt = this.now();
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
      bindingId: state.bindingId,
      workspaceId: state.workspaceId,
      workspaceGeneration: state.workspaceGeneration,
      workspaceGenerationHighWater: new Map(
        state.workspaceGenerationHighWater
      ),
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
    const expiredKey = workspace ? "workspaceExpired" : "hostExpired";
    const priorReadyKey = workspace ? "workspacePriorReady" : "hostPriorReady";
    if (state[key]) this.timers.clearTimeout(state[key]);
    const delay = Math.min(ttlMs, READINESS_MAX_TTL_MS);
    state[key] = this.timers.setTimeout(() => {
      const wasReady = this.#isCurrentReady(state);
      state[expiredKey] = true;
      if (wasReady) {
        state[priorReadyKey] = true;
        state.degraded = true;
      }
      state[key] = undefined;
    }, delay);
    state[key]?.unref?.();
  }

  #clearWorkspaceExpiry(state) {
    if (state.workspaceExpiryTimer) this.timers.clearTimeout(state.workspaceExpiryTimer);
    state.workspaceExpiryTimer = undefined;
    state.workspaceExpiresAt = undefined;
    state.workspaceMonoExpiresAt = undefined;
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
    const now = this.monotonicNow();
    for (const [deadlineKey, expiredKey, priorReadyKey] of [
      ["monoExpiresAt", "hostExpired", "hostPriorReady"],
      ["workspaceMonoExpiresAt", "workspaceExpired", "workspacePriorReady"],
    ]) {
      if (state[expiredKey] || state[deadlineKey] === undefined || now < state[deadlineKey]) {
        continue;
      }
      const wasReady = this.#isCurrentReady(state);
      state[expiredKey] = true;
      if (wasReady) {
        state[priorReadyKey] = true;
        state.degraded = true;
      }
    }
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
    const dimensions = binding.dimensions;
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
      this.#deletePending(pending.requestId);
      pending.settle({ ok: false, error: "timed out waiting for host response" });
    }, pending.idleMs);
    pending.idleTimer = idleTimer;
    idleTimer?.unref?.();
  }

  #deletePending(requestId) {
    const entry = this.pendingRequests.get(requestId);
    if (!entry) return;
    this.timers.clearTimeout(entry.idleTimer);
    this.timers.clearTimeout(entry.hardCapTimer);
    entry.idleTimer = undefined;
    entry.hardCapTimer = undefined;
    this.pendingRequests.delete(requestId);
    const next = (this.pendingCountBySocket.get(entry.socket) ?? 0) - 1;
    if (next > 0) this.pendingCountBySocket.set(entry.socket, next);
    else this.pendingCountBySocket.delete(entry.socket);
  }

  #failPendingForSocket(socket, error) {
    for (const [requestId, pending] of this.pendingRequests) {
      if (pending.socket !== socket) continue;
      pending.resolve({ ok: false, error });
      this.#deletePending(requestId);
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
    const wasCurrent = this.connections.get(hostId) === socket;
    if (wasCurrent) {
      this.connections.delete(hostId);
      this.hostInfo.delete(hostId);
      const readiness = this.readinessStates.get(hostId);
      if (readiness) this.#markOfflineReadiness(readiness);
    }
    this.#clearHeartbeat(socket);
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
      if (binding.status === "bound" && binding.receipt !== undefined) {
        this.#emitObservability("receipt.invalidate", {
          phase: "offline",
          code: "CONNECTION_LOST",
          bindingId: binding.bindingId,
          workspaceId: binding.authority?.workspaceId,
        });
      }
    }
    state.bindingsById?.clear();
    state.bindingsByDescriptor?.clear();
    if (state.bindingEnabled && !state.socketRetired) {
      this.#emitObservability("socket.retire", {
        phase: "offline",
        code: "CONNECTION_LOST",
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
      const state = this.heartbeatStates.get(socket);
      if (state) {
        this.#dropConnection(state.hostId, socket, remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST));
      } else {
        this.#clearHeartbeat(socket);
      }
      socket.terminate();
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
        descriptor = { hostId: authority.hostId, authority, channelIds: new Set() };
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
 * `done: true` for that requestId. Streamed events are delivered via onEvent
 * as they arrive, before the final resolution.
 *
 * @param {string} hostId
 * @param {string} workDir
 * @param {object} command
 * @param {(event: object) => void} onEvent
 * @param {number} timeoutMs Idle timeout: resets on each streamed event.
 * @param {(gate: { gateId: string, requestId: string, prompt: string, kind: string, choices?: {value: unknown, label: string}[] }) => void} [onGate]
 *   #35: invoked when the daemon opens a workflow gate; carries the requestId
 *   needed to route the answer back via answerGate().
 * @param {{ bindingId?: string, mappingId?: string, mappingGeneration?: number, mappingVersion?: number,
 *   sourcePlatform?: string, workspaceId?: string, workspaceGeneration?: number, authority?: object }} [routeIdentity]
 */
invoke(hostId, workDir, command, onEvent, timeoutMs = this.invokeIdleTimeoutMs, onGate, routeIdentity) {
    let managedAuthority;
    try {
      managedAuthority = freezeManagedAuthorityDescriptor(hostId, routeIdentity);
      if (managedAuthority) {
        routeIdentity = Object.freeze({ ...routeIdentity, authority: managedAuthority });
      }
    } catch {
      return Promise.resolve({
        ok: false,
        error: remediationError(PROTOCOL_ERROR_CODES.CONFIG_INVALID),
      });
    }
    const socket = this.connections.get(hostId);
    const readiness = this.readinessStates.get(hostId);
    let selectedBindingId;
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
        return Promise.resolve({
          ok: false,
          error: remediationError(PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE),
        });
      }
      selectedBindingId = binding.bindingId;
      if (!this.workspaceServingEnabled) {
        return Promise.resolve({
          ok: false,
          error: remediationError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE),
        });
      }
    }
    if (!socket) {
      return Promise.resolve({
        ok: false,
        error: { ...READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.CONNECTION_LOST] },
      });
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
      const aggregate =
        hasBindingSelector && binding
          ? this.#bindingAggregate(readiness, binding)
          : this.#aggregate(readiness);
      if (aggregate === "offline") {
        return Promise.resolve({
          ok: false,
          error: this.#notReadyResult(readiness, aggregate),
        });
      }
      if (!this.workspaceServingEnabled) {
        return Promise.resolve({
          ok: false,
          error: remediationError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE),
        });
      }
      if (hasBindingSelector && !binding) {
        return Promise.resolve({
          ok: false,
          error: remediationError(PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED),
        });
      }
      if (aggregate !== "ready") {
        return Promise.resolve({
          ok: false,
          error: binding
            ? this.#bindingNotReadyResult(binding, aggregate)
            : this.#notReadyResult(readiness, aggregate),
        });
      }
    }

    const usesV2 = readiness?.readinessEnabled === true;
    if (!usesV2 && isManagedPathFreeRoute(workDir, routeIdentity)) {
      return Promise.resolve({
        ok: false,
        error: remediationError(PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE),
      });
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
      return Promise.resolve({
        ok: false,
        error: remediationError(PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED),
      });
    }

    const requestId = randomUUID();
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
        return Promise.resolve({
          ok: false,
          error: { ...READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.MAPPING_ID_REQUIRED] },
        });
      }
    } else {
      invoke.workDir = workDir;
      if (!isInvokeMessage(invoke)) {
        return Promise.resolve({ ok: false, error: "invalid invoke request" });
      }
    }

    let payload;
    try {
      payload = JSON.stringify(invoke);
    } catch {
      return Promise.resolve({ ok: false, error: "invoke request is not serializable" });
    }
    if (Buffer.byteLength(payload) > MAX_WS_PAYLOAD_BYTES) {
      return Promise.resolve({ ok: false, error: "invoke request exceeds WebSocket payload limit" });
    }

    return new Promise((resolve) => {
      let settled = false;
      const pending = {
        requestId,
        socket,
        onEvent,
        onGate,
        idleMs: timeoutMs,
        idleTimer: undefined,
        hardCapTimer: undefined,
        gatePending: false,
        gateId: undefined,
        settle: (result) => {
          if (settled) return;
          settled = true;
          this.timers.clearTimeout(pending.idleTimer);
          this.timers.clearTimeout(pending.hardCapTimer);
          resolve(result);
        },
        resolve: (result) => pending.settle(result),
      };
      pending.hardCapTimer = this.timers.setTimeout(() => {
        this.#deletePending(requestId);
        pending.settle({ ok: false, error: "invoke exceeded absolute hard-cap" });
      }, this.invokeHardCapMs);
      pending.hardCapTimer?.unref?.();

      this.#addPending(requestId, pending);
      this.#armIdleTimer(pending);

      socket.send(payload);
    });
  }

  /**
   * #35: deliver a user's answer to a pending workflow gate on an in-flight
   * invoke. Sends an `answer` frame to the owning daemon and re-arms the invoke
   * idle timer (so the daemon's continuation is bounded again). Returns a
   * synchronous result; a stale gateId or resolved/missing request is rejected
   * without side effects.
   *
   * @param {string} hostId
   * @param {string} requestId
   * @param {string} gateId
   * @param {string} answer
   */
  answerGate(hostId, requestId, gateId, answer) {
    const pending = this.pendingRequests.get(requestId);
    if (!pending) {
      return { ok: false, error: "no in-flight request for that answer" };
    }
    const socket = this.connections.get(hostId);
    if (!socket || socket !== pending.socket) {
      return { ok: false, error: `host '${hostId}' is not connected` };
    }
    if (!pending.gatePending || pending.gateId !== gateId) {
      return { ok: false, error: "no matching pending gate for that answer" };
    }

    const message = { type: MSG_TYPES.ANSWER, requestId, gateId, answer };
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

    // The gate is answered: stop suppressing the idle timer and re-arm it so the
    // daemon's post-answer continuation is bounded like any other streamed work.
    pending.gatePending = false;
    pending.gateId = undefined;
    this.#armIdleTimer(pending);
    socket.send(payload);
    return { ok: true };
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
