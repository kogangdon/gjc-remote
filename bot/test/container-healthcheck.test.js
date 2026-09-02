import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("../src/container-healthcheck.js", import.meta.url));

function run(port) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, HOST_WS_PORT: `${port}` },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal, stderr }));
  });
}

test("container healthcheck succeeds when the bot WebSocket port accepts TCP", async () => {
  const server = createServer((socket) => socket.on("error", () => {}));
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const result = await run(server.address().port);
    assert.deepEqual(result, { code: 0, signal: null, stderr: "" });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("container healthcheck fails for invalid or closed ports", async () => {
  for (const port of [0, 65536]) {
    const result = await run(port);
    assert.equal(result.code, 1);
    assert.equal(result.stderr, "");
  }
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  const result = await run(port);
  assert.equal(result.code, 1);
  assert.equal(result.stderr, "");
});
