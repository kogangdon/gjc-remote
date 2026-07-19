import "dotenv/config";
import WebSocket from "ws";
import {
  CAPABILITIES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PONG,
  PROTOCOL_VERSION,
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
  RECONNECT_BASE_MS,
  nextReconnect,
} from "./reconnect.js";

const { HOST_ID, HOST_TOKEN, HOST_LABEL, BOT_WS_URL } = process.env;

if (!HOST_ID || !HOST_TOKEN || !BOT_WS_URL) {
  console.error("Missing HOST_ID, HOST_TOKEN, or BOT_WS_URL in environment (.env).");
  process.exit(1);
}


const pool = new SessionPool();
let reconnectDelay = RECONNECT_BASE_MS;
let shuttingDown = false;

function connectToBot() {
  const connection = new WebSocket(BOT_WS_URL, {
    maxPayload: MAX_WS_PAYLOAD_BYTES,
  });

  connection.on("open", () => {
    reconnectDelay = RECONNECT_BASE_MS;
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
    console.log(`daemon: connected to bot at ${BOT_WS_URL}, registering as '${HOST_ID}'`);
  });

  connection.on("message", (raw, isBinary) =>
    handleMessage(connection, raw, isBinary).catch((err) =>
      console.error("daemon: handler error", err)
    )
  );

  connection.on("close", () => {
    if (shuttingDown) return;
    const { delay, nextBase } = nextReconnect(reconnectDelay);
    console.log(`daemon: disconnected from bot, retrying in ${delay}ms`);
    setTimeout(connectToBot, delay);
    reconnectDelay = nextBase;
  });

  connection.on("error", (err) => console.error("daemon: ws error", err.message));
}

async function handleMessage(connection, raw, isBinary) {
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
    console.error("daemon: registration denied:", msg.reason);
    await shutdownAndExit(1);
    return;
  }
  if (isPingMessage(msg)) {
    connection.send(JSON.stringify(PONG));
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

    if (command.kind === "set_model") {
      await setSessionModel(session, command, (event) => send(event));
    } else {
      const rpcCommand = toRpcCommand(command);
      await session.send(rpcCommand, (event) => send(event));
    }

    send(undefined, { done: true });
  } catch (err) {
    send(undefined, {
      error: normalizeProtocolError(err),
      done: true,
    });
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

connectToBot();

async function shutdownAndExit(exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    await pool.shutdown();
  } catch (error) {
    console.error("daemon: shutdown failed", error);
    exitCode = 1;
  }
  process.exit(exitCode);
}

process.on("SIGINT", () => {
  void shutdownAndExit(0);
});
process.on("SIGTERM", () => {
  void shutdownAndExit(0);
});
