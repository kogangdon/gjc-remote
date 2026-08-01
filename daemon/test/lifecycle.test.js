import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { WebSocketServer } from "ws";
// Fixtures live OUTSIDE test/: bare `node --test` (the CI invocation)
// discovers every .mjs under a directory named `test` and would run the
// fixtures as test files.
const fixturesDir = new URL("../test-fixtures/", import.meta.url);

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
// Spawn a test-fixtures/ entry under bun and wait for the process to finish.
// Fixtures deliver "signals" by invoking the daemon's captured handlers, so
// these tests behave identically on POSIX and Windows.
async function runFixture(name, envOverrides = {}) {
  const child = spawn(
    process.env.BUN_BIN || "bun",
    [fileURLToPath(new URL(name, fixturesDir))],
    {
      env: {
        ...process.env,
        HOST_ID: "lifecycle-test-host",
        HOST_TOKEN: "lifecycle-test-secret",
        BOT_WS_URL: "ws://127.0.0.1:9",
        GJC_LIFECYCLE_FIXTURE: "1",
        ...envOverrides,
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    }
  );

  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });

  try {
    // "close" (not "exit") so both stdio pipes have flushed before the
    // caller asserts on output.
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`fixture ${name} did not exit; output: ${output}`));
      }, TEST_TIMEOUT_MS);
      child.once("close", (code, signal) => {
        clearTimeout(timer);
        resolve({ code, signal });
      });
    });
    return { ...result, output };
  } finally {
    await stopChild(child);
  }
}

test("SIGTERM with a failing session disposal still exits 0", async () => {
  const { code, signal, output } = await runFixture("shutdown-dispose-failure.mjs");

  assert.equal(
    code,
    0,
    `expected exit 0, got ${code}; signal: ${signal}; output: ${output}`
  );
  assert.match(output, /daemon: shutdown failed: .*injected dispose failure/);
  assert.doesNotMatch(output, /\n\s+at /);
});

test("the shutdown deadline unblocks a hanging disposal and keeps exit 0", async () => {
  // 1000ms is the validated minimum for GJC_SHUTDOWN_TIMEOUT_MS.
  const { code, signal, output } = await runFixture("shutdown-hang.mjs", {
    GJC_SHUTDOWN_TIMEOUT_MS: "1000",
  });

  assert.equal(
    code,
    0,
    `expected exit 0, got ${code}; signal: ${signal}; output: ${output}`
  );
  assert.match(
    output,
    /daemon: shutdown timed out after 1000ms; session disposals were abandoned; pending operations: none/
  );
});

test("a fatal during signal-initiated shutdown neither re-enters nor changes exit 0", async () => {
  const { code, signal, output } = await runFixture(
    "reentrancy-signal-then-fatal.mjs"
  );

  assert.equal(
    code,
    0,
    `expected exit 0, got ${code}; signal: ${signal}; output: ${output}`
  );
  // The shutdown latch must hold: pool shutdown starts exactly once.
  assert.equal((output.match(/POOL_SHUTDOWN_CALLED/g) ?? []).length, 1, output);
  // The late fatal is recorded, not swallowed — it just cannot change the code.
  assert.match(output, /daemon: uncaught exception: .*late fatal/);
});

test("a signal during fatal-initiated shutdown neither re-enters nor changes exit 1", async () => {
  const { code, signal, output } = await runFixture(
    "reentrancy-fatal-then-signal.mjs"
  );

  assert.equal(
    code,
    1,
    `expected exit 1, got ${code}; signal: ${signal}; output: ${output}`
  );
  assert.equal((output.match(/POOL_SHUTDOWN_CALLED/g) ?? []).length, 1, output);
  assert.match(output, /daemon: uncaught exception: .*early fatal/);
});
