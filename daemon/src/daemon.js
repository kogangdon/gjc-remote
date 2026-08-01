import "dotenv/config";
import WebSocket from "ws";
import {
  CAPABILITIES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PONG,
  PROTOCOL_VERSION,
  isAnswerMessage,
  isInvokeMessage,
  isPingMessage,
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
  let deniedForConnection = false;
  connections.add(connection);

  connection.on("open", () => {
    retryScheduler.resetBackoff();
    connection.send(
      JSON.stringify({
        type: MSG_TYPES.REGISTER,
        hostId: HOST_ID,
        token: HOST_TOKEN,
        label: HOST_LABEL,
        protocolVersion: PROTOCOL_VERSION,
        capabilities: CAPABILITIES,
      })
    );
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
    // A denied registration remains denied across transport failures. Only a
    // successful registration clears the fixed-denial retry state.
    retryScheduler.markAccepted();
    const negotiatedVersion = Math.min(
      PROTOCOL_VERSION,
      msg.protocolVersion ?? 0
    );
    const shared = negotiateCapabilities(CAPABILITIES, msg.capabilities);
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
  if (!isInvokeMessage(msg)) {
    connection.close(1008, "invalid message");
    return;
  }

  const { requestId, workDir, command } = msg;
  const send = (event, extra = {}) =>
    connection.send(
      JSON.stringify({ type: MSG_TYPES.EVENT, requestId, event, ...extra })
    );

  try {
    const session = await pool.ensureSession(workDir);
    inFlightByRequestId.set(requestId, session);

    if (command.kind === "set_model") {
      await setSessionModel(session, command, (event) => send(event));
    } else {
      const rpcCommand = toRpcCommand(command);
      await session.send(rpcCommand, (event) => send(event));
    }

    send(undefined, { done: true });
  } catch (err) {
    send(undefined, {
      error: sanitizeDaemonError(normalizeProtocolError(err)),
      done: true,
    });
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
