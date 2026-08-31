import { connect } from "node:net";

const rawPort = process.env.HOST_WS_PORT?.trim() || "7711";
const port = Number(rawPort);
if (!Number.isInteger(port) || port < 1 || port > 65535) process.exit(1);

const socket = connect({ host: "127.0.0.1", port });
const timer = setTimeout(() => {
  socket.destroy();
  process.exit(1);
}, 2_000);

timer.unref();
socket.once("connect", () => {
  clearTimeout(timer);
  socket.end();
  process.exit(0);
});
socket.once("error", () => {
  clearTimeout(timer);
  process.exit(1);
});
