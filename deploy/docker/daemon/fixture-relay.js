import { WebSocketServer } from "ws";
import {
  MSG_TYPES,
  PROTOCOL_VERSION_V2,
  WORKSPACE_READINESS_CAPABILITY,
} from "@gjc-remote/shared";

let token;
try {
  const tokenFile = process.env.FIXTURE_HOST_TOKEN_FILE;
  const raw = await Bun.file(tokenFile).text();
  token = raw.endsWith("\r\n")
    ? raw.slice(0, -2)
    : raw.endsWith("\n")
      ? raw.slice(0, -1)
      : raw;
} catch {
  token = undefined;
}
if (typeof token !== "string" || token.length === 0 || token !== token.trim()) {
  console.error("fixture-relay: configuration invalid");
  process.exit(1);
}

const server = new WebSocketServer({
  host: "0.0.0.0",
  port: (() => {
    const value = Number(process.env.FIXTURE_PORT ?? "7711");
    if (!Number.isSafeInteger(value) || value < 1 || value > 65535) {
      console.error("fixture-relay: configuration invalid");
      process.exit(1);
    }
    return value;
  })(),
  maxPayload: 64 * 1024,
});

server.on("connection", (socket) => {
  let registered = false;
  socket.on("message", (raw, isBinary) => {
    if (isBinary) {
      socket.close(1008, "invalid frame");
      return;
    }
    let message;
    try {
      message = JSON.parse(raw.toString("utf8"));
    } catch {
      socket.close(1008, "invalid frame");
      return;
    }
    if (!registered) {
      if (
        message?.type !== MSG_TYPES.REGISTER ||
        message.token !== token ||
        typeof message.hostId !== "string"
      ) {
        socket.send(JSON.stringify({ type: MSG_TYPES.REGISTER_DENIED }));
        socket.close(1008, "registration denied");
        return;
      }
      registered = true;
      socket.send(JSON.stringify({
        type: MSG_TYPES.REGISTER_OK,
        protocolVersion: PROTOCOL_VERSION_V2,
        capabilities: [WORKSPACE_READINESS_CAPABILITY],
      }));
      console.log("fixture-relay: daemon registered");
    }
  });
});

function shutdown() {
  for (const client of server.clients) client.close(1000, "fixture stopping");
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
console.log("fixture-relay: listening");
