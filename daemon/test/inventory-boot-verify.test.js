import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { WebSocketServer } from "ws";
import {
  PROTOCOL_VERSION_V3,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_READINESS_CAPABILITY,
} from "@gjc-remote/shared";

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const TEST_TIMEOUT_MS = 8_000;

// Platform-appropriate, contract-valid role bindings (exact 5 roles, distinct
// principals, system pinned). Used only for the best-effort real-addon case.
const validRoleBindings =
  process.platform === "win32"
    ? {
        management: { kind: "sid", value: "S-1-5-21-1001" },
        bot: { kind: "sid", value: "S-1-5-21-1002" },
        recovery: { kind: "sid", value: "S-1-5-21-1003" },
        daemon: { kind: "sid", value: "S-1-5-21-1004" },
        system: { kind: "sid", value: "S-1-5-18" },
      }
    : {
        management: { kind: "uid", value: "uid:1001" },
        bot: { kind: "uid", value: "uid:1002" },
        recovery: { kind: "uid", value: "uid:1003" },
        daemon: { kind: "uid", value: "uid:1004" },
        system: { kind: "uid", value: "uid:0" },
      };

// Spawn the daemon against a throwaway bot WS server and collect the register
// frame (if it connects) and the child's terminal exit + captured output.
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
      HOST_ID: "boot-test-host",
      HOST_TOKEN: "boot-test-token",
      BOT_WS_URL: `ws://127.0.0.1:${port}`,
      GJC_READINESS_TTL_MS: "1000",
      GJC_READINESS_V2: "1",
      GJC_READINESS_TEST_INJECTION: "0",
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
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
    wss.close();
  };

  return { child, registered, getRegisterFrame: () => registerFrame, get stdout() { return stdout; }, get stderr() { return stderr; }, exited, cleanup };
}

function waitMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("AC1: off mode (injection disabled) boots and never advertises the inventory-receipt capability", async () => {
  const daemon = await bootDaemon({ GJC_NATIVE_INVENTORY_MODE: "off" });
  try {
    const frame = await Promise.race([
      daemon.registered,
      waitMs(TEST_TIMEOUT_MS).then(() => null),
    ]);
    assert.ok(frame, `daemon did not register; stderr=${daemon.stderr}`);
    assert.notEqual(frame.protocolVersion, PROTOCOL_VERSION_V3);
    assert.ok(
      frame.capabilities.includes(WORKSPACE_READINESS_CAPABILITY),
      "off mode with GJC_READINESS_V2=1 still advertises readiness v2",
    );
    assert.ok(
      !frame.capabilities.includes(WORKSPACE_INVENTORY_RECEIPT_CAPABILITY),
      "off mode must NOT advertise the inventory-receipt capability",
    );
  } finally {
    await daemon.cleanup();
  }
});

test("AC3: verify mode with invalid role bindings fails closed with a structured diagnostic and no receipt", async () => {
  const daemon = await bootDaemon({
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_INVENTORY_ROLE_BINDINGS: "{}",
  });
  try {
    const [code] = await Promise.race([
      daemon.exited,
      waitMs(TEST_TIMEOUT_MS).then(() => {
        throw new Error(`daemon did not exit; stdout=${daemon.stdout} stderr=${daemon.stderr}`);
      }),
    ]);
    assert.notEqual(code, 0, "verify with invalid roles must exit non-zero");
    assert.match(daemon.stderr, /native inventory verify configuration failed/);
    assert.match(daemon.stderr, /CONFIG_INVALID/);
    assert.match(daemon.stderr, /"operation":"initialize_inventory_config"/);
    assert.match(daemon.stderr, /"writes":0/);
    // Structured diagnostic must be path-free and secret-free.
    assert.ok(!/[A-Za-z]:\\|\/home\/|\/Users\//.test(daemon.stderr), "diagnostic leaked a path");
    // No inventory-receipt capability advertised (it never registered).
    assert.equal(daemon.getRegisterFrame(), undefined);
    assert.ok(!daemon.stdout.includes(WORKSPACE_INVENTORY_RECEIPT_CAPABILITY));
  } finally {
    await daemon.cleanup();
  }
});

test("AC2b (best-effort): verify mode with valid roles produces a coherent real-addon outcome", async () => {
  const daemon = await bootDaemon({
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_INVENTORY_ROLE_BINDINGS: JSON.stringify(validRoleBindings),
  });
  try {
    const outcome = await Promise.race([
      daemon.registered.then(() => "registered"),
      daemon.exited.then(([code]) => ({ exit: code })),
      waitMs(TEST_TIMEOUT_MS).then(() => "timeout"),
    ]);

    if (outcome === "registered") {
      // Real addon built, loaded, and self-tested clean -> receipt + v3 advertised.
      const frame = daemon.getRegisterFrame();
      assert.equal(frame.protocolVersion, PROTOCOL_VERSION_V3);
      assert.ok(frame.capabilities.includes(WORKSPACE_INVENTORY_RECEIPT_CAPABILITY));
      console.log(`AC2b: real-addon verify PASS on ${process.platform}-${process.arch}; receipt+v3 advertised`);
    } else if (outcome && typeof outcome === "object") {
      // Real addon absent/refused -> genuine fail-closed evidence (not a mock).
      assert.notEqual(outcome.exit, 0);
      assert.match(daemon.stderr, /native inventory verify configuration failed/);
      console.log(
        `AC2b: SKIPPED real self-test PASS on ${process.platform}-${process.arch} ` +
          `— native addon unavailable/refused; observed genuine fail-closed exit=${outcome.exit}`,
      );
    } else {
      assert.fail(`AC2b: daemon neither registered nor exited within timeout; stderr=${daemon.stderr}`);
    }
  } finally {
    await daemon.cleanup();
  }
});
