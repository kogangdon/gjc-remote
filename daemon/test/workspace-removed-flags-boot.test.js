import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { WebSocketServer } from "ws";

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const TEST_TIMEOUT_MS = 8_000;

// Spawn daemon.js against a throwaway bot WS server; collect register frame (if
// it connects) and the child's terminal exit + captured output. Mirrors the
// GJC_NATIVE_INVENTORY_MODE subprocess-boot harness (inventory-boot-verify.test.js).
async function bootDaemon(envOverrides) {
  const wss = new WebSocketServer({ port: 0 });
  await once(wss, "listening");
  const { port } = wss.address();

  let registerFrame;
  let resolveRegister;
  const registered = new Promise((resolve) => {
    resolveRegister = resolve;
  });
  wss.on("connection", (socket) => {
    socket.on("message", (raw) => {
      const message = JSON.parse(raw.toString());
      if (message.type === "register") {
        registerFrame = message;
        resolveRegister(message);
      }
    });
  });

  const child = spawn(process.env.BUN_BIN || "bun", [daemonEntry], {
    env: {
      ...process.env,
      HOST_ID: "removed-flag-test-host",
      HOST_TOKEN: "removed-flag-test-token",
      BOT_WS_URL: `ws://127.0.0.1:${port}`,
      GJC_READINESS_TTL_MS: "1000",
      GJC_READINESS_V2: "1",
      GJC_READINESS_TEST_INJECTION: "0",
      GJC_NATIVE_INVENTORY_MODE: "off",
      // Ensure the harness's own environment does not carry a removed flag in.
      GJC_DEV_NATIVE_SINGLE_WRITER_LOCK: undefined,
      GJC_DEV_CONNECTIVITY_PROBE: undefined,
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  const exited = once(child, "exit");
  const cleanup = async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    wss.close();
  };

  return { child, registered, getRegisterFrame: () => registerFrame, get stdout() { return stdout; }, get stderr() { return stderr; }, exited, cleanup };
}

function waitMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const REMOVED = [
  { name: "GJC_DEV_NATIVE_SINGLE_WRITER_LOCK", gate: "FINAL_LEASE_FENCE_TESTS_PASS" },
  { name: "GJC_DEV_CONNECTIVITY_PROBE", gate: "FULL_GRAPH_PUBLICATION_TESTS_PASS" },
];

// Per-flag-per-value rejection matrix: presence at ANY value fails the daemon
// closed at startup with the flag's unique per-gate diagnostic, and it never
// registers with the bot.
for (const flag of REMOVED) {
  for (const value of ["1", "0", ""]) {
    test(`removed flag ${flag.name}=${JSON.stringify(value)} fails boot closed with per-gate evidence`, async () => {
      const daemon = await bootDaemon({ [flag.name]: value });
      try {
        const [code] = await Promise.race([
          daemon.exited,
          waitMs(TEST_TIMEOUT_MS).then(() => {
            throw new Error(`daemon did not exit; stderr=${daemon.stderr}`);
          }),
        ]);
        assert.notEqual(code, 0, "removed flag present must exit non-zero");
        assert.match(daemon.stderr, new RegExp(flag.name));
        assert.match(daemon.stderr, new RegExp(flag.gate));
        assert.match(daemon.stderr, /was removed/);
        assert.equal(daemon.getRegisterFrame(), undefined, "must never register with a removed flag set");
      } finally {
        await daemon.cleanup();
      }
    });
  }
}

test("both removed flags present emit both distinct diagnostics and fail boot closed", async () => {
  const daemon = await bootDaemon({
    GJC_DEV_NATIVE_SINGLE_WRITER_LOCK: "1",
    GJC_DEV_CONNECTIVITY_PROBE: "1",
  });
  try {
    const [code] = await Promise.race([
      daemon.exited,
      waitMs(TEST_TIMEOUT_MS).then(() => {
        throw new Error(`daemon did not exit; stderr=${daemon.stderr}`);
      }),
    ]);
    assert.notEqual(code, 0);
    for (const flag of REMOVED) {
      assert.match(daemon.stderr, new RegExp(flag.name));
      assert.match(daemon.stderr, new RegExp(flag.gate));
    }
    assert.equal(daemon.getRegisterFrame(), undefined);
  } finally {
    await daemon.cleanup();
  }
});

test("control: with no removed flag the guard does not fire and the daemon registers", async () => {
  const daemon = await bootDaemon({});
  try {
    const frame = await Promise.race([
      daemon.registered,
      waitMs(TEST_TIMEOUT_MS).then(() => null),
    ]);
    assert.ok(frame, `daemon did not register; stderr=${daemon.stderr}`);
    assert.ok(!/was removed/.test(daemon.stderr), "removed-flag guard must not fire on a clean env");
  } finally {
    await daemon.cleanup();
  }
});
