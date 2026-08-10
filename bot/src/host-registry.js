import { WebSocket, WebSocketServer } from "ws";
import { randomUUID } from "node:crypto";
import {
  CAPABILITIES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PING,
  PROTOCOL_VERSION,
  PROTOCOL_VERSION_V2,
  READINESS_DIMENSIONS,
  READINESS_MAX_SKEW_MS,
  READINESS_MAX_TTL_MS,
  PROTOCOL_ERROR_CODES,
  V0_LIMITS,
  WORKSPACE_READINESS_CAPABILITY,
  isAnswerMessage,
  isEventMessage,
  isGateRequestEvent,
  isInvokeMessage,
  isPongMessage,
  isReadinessCapabilityGate,
  isReadinessMessage,
  isRegisterMessage,
  isRegisterOkMessage,
  isWorkspaceId,
  negotiateCapabilities,
  normalizeReadinessTtl,
  READINESS_REMEDIATIONS,
} from "@gjc-remote/shared";

const HEARTBEAT_INTERVAL_MS = 30_000;
const HEARTBEAT_TIMEOUT_MS = 10_000;
const INVOKE_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const INVOKE_HARD_CAP_MS = 30 * 60 * 1000;
const PING_PAYLOAD = JSON.stringify(PING);
const V2_CAPABILITIES = Object.freeze([...CAPABILITIES, WORKSPACE_READINESS_CAPABILITY]);
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
    code,
    ...(READINESS_REMEDIATIONS[code] ??
      READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME]),
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
    this.timers = timers;
    this.now = now;
    this.monotonicNow = monotonicNow;
    /** @type {Map<string, import("ws").WebSocket>} */
    this.connections = new Map();
    /** @type {Map<import("ws").WebSocket, { hostId: string, timeout?: object }>} */
    this.heartbeatStates = new Map();
    /** @type {Map<string, { socket: import("ws").WebSocket, resolve: (v: any) => void, onEvent: (e: object) => void, text?: string }>} */
    this.pendingRequests = new Map();
    /** @type {Map<import("ws").WebSocket, number>} */
    this.pendingCountBySocket = new Map();
    /** @type {Map<string, { protocolVersion: number, capabilities: string[] }>} */
    this.hostInfo = new Map();
    /** @type {Map<string, { socketGeneration: number, revision: number, observedAt: number, workspaceId?: string, workspaceGeneration?: number }>} */
    this.readinessAuthorities = new Map();
    /** @type {Map<string, object>} */
    this.readinessStates = new Map();
    this.closed = false;
    this.closePromise = undefined;

    this.wss = new WebSocketServer({ port, maxPayload: MAX_WS_PAYLOAD_BYTES });
    this.wss.on("connection", (socket) => this.#handleConnection(socket));
    this.onError = onError;
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
      if (!expectedToken || expectedToken !== msg.token) {
        socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER_DENIED, reason: "bad token" }));
        socket.close(1008, "auth failed");
        return;
      }

      hostId = msg.hostId;
      const previous = this.connections.get(hostId);
      if (previous && previous !== socket) {
        this.#dropConnection(hostId, previous, remediationError(PROTOCOL_ERROR_CODES.CONNECTION_LOST));
        previous.terminate();
      }

      this.connections.set(hostId, socket);
      this.heartbeatStates.set(socket, { hostId });
      const wantsReadiness =
        (msg.protocolVersion ?? 0) >= PROTOCOL_VERSION_V2 &&
        Array.isArray(msg.capabilities) &&
        msg.capabilities.includes(WORKSPACE_READINESS_CAPABILITY);
      const registerOk = wantsReadiness
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
      const readinessEnabled = isReadinessCapabilityGate(msg, registerOk);
      const protocolVersion = Math.min(
        registerOk.protocolVersion,
        msg.protocolVersion ?? 0
      );
      const capabilities = negotiateCapabilities(
        readinessEnabled ? V2_CAPABILITIES : CAPABILITIES,
        msg.capabilities
      );
      this.hostInfo.set(hostId, { protocolVersion, capabilities });
      this.readinessStates.set(hostId, {
        socket,
        hostId,
        readinessEnabled,
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
    if (msg?.type === MSG_TYPES.READINESS) {
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
        clearTimeout(pending.idleTimer);
        // Route to the dedicated gate callback (carries requestId, needed to send
        // the answer back). Not forwarded to onEvent — gates are not stream text.
        pending.onGate?.({
          gateId: event.gateId,
          requestId: msg.requestId,
          prompt: event.prompt,
          kind: event.kind,
          choices: event.choices,
        });
        return;
      }
      const text = extractAssistantText(event);
      if (text !== undefined) pending.text = text;
      // Any non-gate event means the agent resumed, so the gate (if any) resolved.
      pending.gatePending = false;
      pending.gateId = undefined;
      pending.onEvent(event);
      this.#armIdleTimer(pending);
    }
    if (msg.done) {
      pending.resolve({ ok: true, text: pending.text });
      this.#deletePending(msg.requestId);
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

    const authority = this.readinessAuthorities.get(hostId);
    if (state.socketGeneration === undefined && authority) {
      if (
        msg.socketGeneration <= authority.socketGeneration ||
        msg.observedAt < authority.observedAt ||
        (msg.workspaceId !== undefined &&
          msg.workspaceId === authority.workspaceId &&
          authority.workspaceGeneration !== undefined &&
          msg.workspaceGeneration < authority.workspaceGeneration)
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
    if (
      hasWorkspace &&
      state.workspaceGeneration !== undefined &&
      (msg.workspaceId === state.workspaceId &&
        msg.workspaceGeneration < state.workspaceGeneration)
    ) {
      this.#recordReadinessError(state, PROTOCOL_ERROR_CODES.READINESS_REPLAYED, receivedAt);
      return false;
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

    this.readinessAuthorities.set(hostId, {
      socketGeneration: state.socketGeneration,
      revision: state.revision,
      observedAt: state.observedAt,
      workspaceId: state.workspaceId,
      workspaceGeneration: state.workspaceGeneration,
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

  #projectHost(hostId, state) {
    const projection = {
      hostId: redactOpaqueId(hostId),
      aggregate: this.#aggregate(state),
      dimensions: { ...this.#effectiveDimensions(state) },
      lastErrorAt: state.lastErrorAt ?? null,
      revision: state.revision,
      socketGeneration: state.socketGeneration ?? null,
    };
    if (state.workspaceId !== undefined) {
      projection.workspaceId = redactOpaqueId(state.workspaceId);
      projection.workspaceGeneration = state.workspaceGeneration;
    }
    if (state.observedAt !== undefined) projection.observedAt = state.observedAt;
    if (state.receivedAt !== undefined) projection.receivedAt = state.receivedAt;
    const localExpiry = state.workspaceExpiresAt ?? state.expiresAt;
    if (localExpiry !== undefined) projection.expiresAt = localExpiry;
    return projection;
  }

  #notReadyResult(state, aggregate) {
    const dimensions = this.#effectiveDimensions(state);
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
      const remediation = state.lastError?.remediation;
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
    clearTimeout(pending.idleTimer);
    pending.idleTimer = setTimeout(() => {
      this.#deletePending(pending.requestId);
      pending.settle({ ok: false, error: "timed out waiting for host response" });
    }, pending.idleMs);
  }

  #deletePending(requestId) {
    const entry = this.pendingRequests.get(requestId);
    if (!entry) return;
    clearTimeout(entry.idleTimer);
    clearTimeout(entry.hardCapTimer);
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
    state.connected = false;
    state.hostDimensions = { ...state.hostDimensions, connection: "offline" };
    if (state.workspaceDimensions) {
      state.workspaceDimensions = { ...state.workspaceDimensions, connection: "offline" };
    }
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
    this.readinessStates.clear();
    this.readinessAuthorities.clear();

    this.closePromise = new Promise((resolve, reject) => {
      this.wss.close((error) => (error ? reject(error) : resolve()));
    });
    return this.closePromise;
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
 * @param {{ mappingId?: string, mappingGeneration?: number, mappingVersion?: number,
 *   workspaceId?: string, workspaceGeneration?: number }} [routeIdentity]
 */
invoke(hostId, workDir, command, onEvent, timeoutMs = this.invokeIdleTimeoutMs, onGate, routeIdentity) {
    const socket = this.connections.get(hostId);
    if (!socket) {
      return Promise.resolve({
        ok: false,
        error: { ...READINESS_REMEDIATIONS[PROTOCOL_ERROR_CODES.CONNECTION_LOST] },
      });
    }
    const readiness = this.readinessStates.get(hostId);
    if (readiness?.readinessEnabled) {
      const aggregate = this.#aggregate(readiness);
      if (aggregate !== "ready") {
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
    }

    const pendingForSocket = this.pendingCountBySocket.get(socket) ?? 0;
    if (pendingForSocket >= V0_LIMITS.MAX_PENDING_PER_HOST) {
      return Promise.resolve({
        ok: false,
        error: remediationError(PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED),
      });
    }

    const requestId = randomUUID();
    const usesV2 = readiness?.readinessEnabled === true;
    const invoke = { type: MSG_TYPES.INVOKE, requestId, command };
    if (usesV2) {
      for (const [key, value] of Object.entries(routeIdentity ?? {})) {
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
          clearTimeout(pending.idleTimer);
          clearTimeout(pending.hardCapTimer);
          resolve(result);
        },
        resolve: (result) => pending.settle(result),
      };
      pending.hardCapTimer = setTimeout(() => {
        this.#deletePending(requestId);
        pending.settle({ ok: false, error: "invoke exceeded absolute hard-cap" });
      }, this.invokeHardCapMs);

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
