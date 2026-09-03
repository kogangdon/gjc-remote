import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import WebSocket from "ws";
import {
  MSG_TYPES,
  PROTOCOL_VERSION_V2,
  WORKSPACE_READINESS_CAPABILITY,
} from "@gjc-remote/shared";

async function freePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  server.close();
  await once(server, "close");
  return port;
}

function firstFrame(url, registration) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.once("error", reject);
    socket.once("open", () => socket.send(JSON.stringify(registration)));
    socket.once("message", (raw) => {
      resolve(JSON.parse(raw.toString("utf8")));
      socket.close();
    });
  });
}

test("daemon Compose relay authenticates registration and negotiates readiness v2", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "gjc-daemon-relay-"));
  const tokenFile = join(root, "host-token");
  await writeFile(tokenFile, "fixture-secret\n", { mode: 0o600 });
  const port = await freePort();
  const child = spawn("bun", ["deploy/docker/daemon/fixture-relay.js"], {
    cwd: new URL("../../", import.meta.url),
    env: {
      ...process.env,
      FIXTURE_HOST_TOKEN_FILE: tokenFile,
      FIXTURE_PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(async () => {
    if (child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await Promise.race([
        exited,
        new Promise((resolve) => setTimeout(resolve, 2_000)),
      ]);
    }
    await rm(root, { recursive: true, force: true });
  });
  let stdout = "";
  child.stdout.setEncoding("utf8");
  while (!stdout.includes("fixture-relay: listening")) {
    const [chunk] = await once(child.stdout, "data");
    stdout += chunk;
  }

  const denied = await firstFrame(`ws://127.0.0.1:${port}`, {
    type: MSG_TYPES.REGISTER,
    hostId: "fixture-host",
    token: "wrong-token",
  });
  assert.equal(denied.type, MSG_TYPES.REGISTER_DENIED);

  const accepted = await firstFrame(`ws://127.0.0.1:${port}`, {
    type: MSG_TYPES.REGISTER,
    hostId: "fixture-host",
    token: "fixture-secret",
  });
  assert.deepEqual(accepted, {
    type: MSG_TYPES.REGISTER_OK,
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  });
});
