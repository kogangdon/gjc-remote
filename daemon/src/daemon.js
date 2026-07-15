import "dotenv/config";
import WebSocket from "ws";
import { MSG_TYPES } from "@gjc-remote/shared";
import { SessionPool } from "./session-pool.js";
import { setSessionModel } from "./model-command.js";

const { HOST_ID, HOST_TOKEN, HOST_LABEL, BOT_WS_URL } = process.env;

if (!HOST_ID || !HOST_TOKEN || !BOT_WS_URL) {
  console.error("Missing HOST_ID, HOST_TOKEN, or BOT_WS_URL in environment (.env).");
  process.exit(1);
}


const pool = new SessionPool();
let socket;
let reconnectDelay = 1000;

function connectToBot() {
  socket = new WebSocket(BOT_WS_URL);

  socket.on("open", () => {
    reconnectDelay = 1000;
    socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER, hostId: HOST_ID, token: HOST_TOKEN, label: HOST_LABEL }));
    console.log(`daemon: connected to bot at ${BOT_WS_URL}, registering as '${HOST_ID}'`);
  });

  socket.on("message", (raw) => handleMessage(raw).catch((err) => console.error("daemon: handler error", err)));

  socket.on("close", () => {
    console.log(`daemon: disconnected from bot, retrying in ${reconnectDelay}ms`);
    setTimeout(connectToBot, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 2, 30_000);
  });

  socket.on("error", (err) => console.error("daemon: ws error", err.message));
}

async function handleMessage(raw) {
  let msg;
  try {
    msg = JSON.parse(raw.toString());
  } catch {
    return;
  }

  if (msg.type === MSG_TYPES.REGISTER_OK) {
    console.log("daemon: registration accepted");
    return;
  }
  if (msg.type === MSG_TYPES.REGISTER_DENIED) {
    console.error("daemon: registration denied:", msg.reason);
    process.exit(1);
  }
  if (msg.type !== MSG_TYPES.INVOKE) return;

  const { requestId, workDir, command } = msg;
  const send = (event, extra = {}) => socket.send(JSON.stringify({ type: MSG_TYPES.EVENT, requestId, event, ...extra }));

  try {
    const session = pool.ensureSession(workDir);

    if (command.kind === "set_model") {
      await setSessionModel(session, command, (event) => send(event));
    } else {
      const rpcCommand = toRpcCommand(command);
      await session.send(rpcCommand, (event) => send(event));
    }

    socket.send(JSON.stringify({ type: MSG_TYPES.EVENT, requestId, done: true }));
  } catch (err) {
    socket.send(JSON.stringify({ type: MSG_TYPES.EVENT, requestId, error: err.message, done: true }));
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

process.on("SIGINT", () => {
  pool.shutdown();
  process.exit(0);
});
process.on("SIGTERM", () => {
  pool.shutdown();
  process.exit(0);
});
