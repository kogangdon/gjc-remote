import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { WebSocketServer } from "ws";

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const TEST_TIMEOUT_MS = 8_000;

function waitForOutput(output, text, timeoutMs = TEST_TIMEOUT_MS) {
  if (output.value.includes(text)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let poll;
    const deadline = setTimeout(
      () => {
        clearInterval(poll);
        reject(
          new Error(`timed out waiting for daemon output: ${text}; got ${output.value}`)
        );
      },
      timeoutMs
    );
    poll = setInterval(() => {
      if (!output.value.includes(text)) return;
      clearTimeout(deadline);
      clearInterval(poll);
      resolve();
    }, 10);
  });
}
function waitForLength(collection, length, description, timeoutMs = TEST_TIMEOUT_MS) {
  if (collection.length >= length) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let poll;
    const deadline = setTimeout(
      () => {
        clearInterval(poll);
        reject(new Error(`timed out waiting for ${description}`));
      },
      timeoutMs
    );
    poll = setInterval(() => {
      if (collection.length < length) return;
      clearTimeout(deadline);
      clearInterval(poll);
      resolve();
    }, 10);
  });
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  await Promise.race([
    exited,
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

test("denied registration uses one fixed retry and accepted recovery restores normal reconnects", async () => {
  const token = "lifecycle-test-secret";
  const registrations = [];
  const sockets = [];
  const wss = new WebSocketServer({ port: 0 });
  await once(wss, "listening");
  const { port } = wss.address();
  const output = { value: "" };

  wss.on("connection", (socket) => {
    sockets.push(socket);
    const registrationIndex = registrations.length;
    socket.once("message", (raw) => {
      const message = JSON.parse(raw.toString());
      registrations.push(message);
      if (registrationIndex === 0) {
        socket.send(
          JSON.stringify({
            type: "register_denied",
            reason: `invalid token ${token}\nwith controls`,
          })
        );
      } else if (registrationIndex === 1) {
        socket.send(JSON.stringify({ type: "register_ok" }));
      }
    });
  });

  const child = spawn(process.env.BUN_BIN || "bun", [daemonEntry], {
    env: {
      ...process.env,
      HOST_ID: "lifecycle-test-host",
      HOST_TOKEN: token,
      GJC_REGISTER_DENIED_RETRY_MS: "1000",
      BOT_WS_URL: `ws://url-user:url-pass@127.0.0.1:${port}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.on("data", (chunk) => {
    output.value += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output.value += chunk.toString();
  });

  try {
    await waitForOutput(output, "daemon: registration denied (details redacted); retrying in 1000ms");
    await waitForLength(
      registrations,
      2,
      "accepted retry registration"
    );
    await waitForOutput(output, "daemon: registration accepted");

    assert.equal(registrations.length, 2);
    assert.equal(registrations[0].token, token);
    assert.equal(registrations[1].token, token);
    assert.equal(output.value.includes(token), false);
    assert.equal(output.value.includes("url-user"), false);
    assert.equal(output.value.includes("url-pass"), false);
    assert.match(output.value, /connected to bot at ws:\/\/\[redacted\]@127\.0\.0\.1:/);

    sockets[1].close();
    await waitForOutput(output, "daemon: disconnected from bot, retrying in ");
  } finally {
    await stopChild(child);
    for (const socket of sockets) socket.terminate();
    await new Promise((resolve) => wss.close(() => resolve()));
  }
});
