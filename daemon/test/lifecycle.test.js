import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
} from "@gjc-remote/shared";
import {
  fingerprintManagedMappingRecord,
  fingerprintManagedRouteRecord,
} from "@gjc-remote/shared/mapping-envelope";
import {
  buildWorkspaceInventory,
  workspaceInventoryBytes,
} from "@gjc-remote/shared/workspace-inventory";
import { WebSocketServer } from "ws";
// Fixtures live OUTSIDE test/: bare `node --test` (the CI invocation)
// discovers every .mjs under a directory named `test` and would run the
// fixtures as test files.
const fixturesDir = new URL("../test-fixtures/", import.meta.url);

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const TEST_TIMEOUT_MS = 8_000;
const TEST_INVENTORY = workspaceInventoryBytes(buildWorkspaceInventory({
  hostId: "readiness-test-host",
  inventoryGeneration: 1,
  workspaces: [{
    hostId: "readiness-test-host",
    workspaceId: "workspace-test",
    sourcePlatform: "windows-drive",
    workDir: "C:\\workspace",
    rootIdentityFingerprint: "1".repeat(64),
    storageIdentityFingerprint: "2".repeat(64),
  }],
})).toString("utf8");

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
function waitForFrame(collection, predicate, description, timeoutMs = TEST_TIMEOUT_MS) {
  if (collection.some(predicate)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let poll;
    const deadline = setTimeout(() => {
      clearInterval(poll);
      reject(new Error(`timed out waiting for ${description}`));
    }, timeoutMs);
    poll = setInterval(() => {
      if (!collection.some(predicate)) return;
      clearTimeout(deadline);
      clearInterval(poll);
      resolve();
    }, 10);
  });
}

function waitForDaemonOutput(daemon, text, timeoutMs = TEST_TIMEOUT_MS) {
  return waitForOutput(
    {
      get value() {
        return daemon.output();
      },
    },
    text,
    timeoutMs
  );
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

function readinessV2Bind() {
  const mapping = fingerprintManagedMappingRecord({
    mappingId: "mapping-test",
    hostId: "readiness-test-host",
    fenceGeneration: 1,
    mappingGeneration: 1,
    workspaceGeneration: 1,
    mappingVersion: 1,
    sourcePlatform: "windows-drive",
    workspaceId: "workspace-test",
    workDir: null,
    sourceRoot: "C:\\native\\workspace-test",
    containerRoot: null,
    volumeIdentity: "volume-test",
    casePolicy: "insensitive",
    immutableDefault: false,
    mappingFingerprint: null,
  });
  const route = fingerprintManagedRouteRecord({
    channelId: "123",
    hostId: mapping.hostId,
    mappingId: mapping.mappingId,
    fenceGeneration: mapping.fenceGeneration,
    mappingGeneration: mapping.mappingGeneration,
    workspaceGeneration: mapping.workspaceGeneration,
    mappingVersion: mapping.mappingVersion,
    sourcePlatform: mapping.sourcePlatform,
    workspaceId: mapping.workspaceId,
    workDir: null,
    routeFingerprint: null,
  }, mapping);
  return {
    type: "bind_workspace",
    bindingId: "binding-test",
    hostId: route.hostId,
    mappingId: route.mappingId,
    mappingGeneration: route.mappingGeneration,
    mappingVersion: route.mappingVersion,
    workspaceId: route.workspaceId,
    workspaceGeneration: route.workspaceGeneration,
    sourcePlatform: route.sourcePlatform,
    routeFingerprint: route.routeFingerprint,
    authorityFingerprint: mapping.mappingFingerprint,
    inventoryGeneration: 1,
    route,
    mapping,
  };
}

async function startReadinessDaemon({
  registerResponse = {
    type: "register_ok",
    protocolVersion: 2,
    capabilities: ["workspace_readiness_v2"],
  },
  envOverrides = {},
  onMessage,
  beforeRegisterResponse,
  afterRegisterResponse,
  testInjection = true,
  autoBind = false,
  observabilityDaemonTestMode = true,
  observabilityTestIpc = false,
} = {}) {
  const frames = [];
  const telemetry = [];
  const policyCloses = [];
  const registrations = [];
  const sockets = [];
  const closes = [];
  const wss = new WebSocketServer({ port: 0 });
  await once(wss, "listening");
  const { port } = wss.address();
  wss.on("connection", (socket) => {
    sockets.push(socket);
    socket.on("close", (code, reason) => {
      closes.push({ code, reason: reason.toString() });
    });
    socket.on("message", (raw) => {
      const message = JSON.parse(raw.toString());
      if (message.type === "register") {
        registrations.push(message);
        if (beforeRegisterResponse?.(socket) === false) return;
        socket.send(JSON.stringify(registerResponse));
        afterRegisterResponse?.(socket);
        if (autoBind && registerResponse.protocolVersion === 2) {
          socket.send(JSON.stringify(readinessV2Bind()));
        }
        return;
      }
      frames.push(message);
      onMessage?.(message, socket);
    });
  });

  const child = spawn(process.env.BUN_BIN || "bun", [daemonEntry], {
    env: {
      ...process.env,
      HOST_ID: "readiness-test-host",
      HOST_TOKEN: "readiness-test-token",
      BOT_WS_URL: `ws://127.0.0.1:${port}`,
      GJC_READINESS_TTL_MS: "1000",
      GJC_READINESS_V2: "1",
      GJC_READINESS_TEST_INJECTION: testInjection ? "1" : "0",
      GJC_DAEMON_TEST_MODE: observabilityDaemonTestMode ? "1" : "0",
      GJC_OBSERVABILITY_TEST_IPC: observabilityTestIpc ? "1" : "0",
      GJC_READINESS_TEST_PROBE: "pass",
      GJC_READINESS_TEST_WORKSPACE_ID: "workspace-test",
      GJC_READINESS_TEST_WORKSPACE_GENERATION: "1",
      GJC_READINESS_TEST_MAPPING_ID: "mapping-test",
      GJC_READINESS_TEST_MAPPING_GENERATION: "1",
      GJC_READINESS_TEST_MAPPING_VERSION: "1",
      GJC_READINESS_TEST_WORK_DIR: "C:\\workspace",
      ...(testInjection
        ? {
            GJC_WORKSPACE_INVENTORY: TEST_INVENTORY,
          }
        : {}),
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    windowsHide: true,
  });
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.on("message", (message) => {
    if (message?.type === "daemon_observability") telemetry.push(message.event);
    if (message?.type === "daemon_policy_close") policyCloses.push(message);
  });

  return {
    frames,
    telemetry,
    policyCloses,
    registrations,
    sockets,
    closes,
    output: () => output,
    async stop() {
      await stopChild(child);
      for (const socket of sockets) socket.terminate();
      await new Promise((resolve) => wss.close(() => resolve()));
    },
  };
}

test("observability IPC requires both dedicated test gate terms and stays out of WS frames", async () => {
  for (const {
    observabilityDaemonTestMode,
    observabilityTestIpc,
    expectTelemetry,
  } of [
    {
      observabilityDaemonTestMode: false,
      observabilityTestIpc: true,
      expectTelemetry: false,
    },
    {
      observabilityDaemonTestMode: true,
      observabilityTestIpc: false,
      expectTelemetry: false,
    },
    {
      observabilityDaemonTestMode: true,
      observabilityTestIpc: true,
      expectTelemetry: true,
    },
  ]) {
    let invoked = false;
    const daemon = await startReadinessDaemon({
      observabilityDaemonTestMode,
      observabilityTestIpc,
      envOverrides: {
        GJC_READINESS_TEST_WORKSPACE_ID: "",
        GJC_READINESS_TEST_WORKSPACE_GENERATION: "",
        GJC_READINESS_TEST_MAPPING_ID: "",
        GJC_READINESS_TEST_MAPPING_GENERATION: "",
        GJC_READINESS_TEST_MAPPING_VERSION: "",
        GJC_READINESS_TEST_WORK_DIR: "",
      },
      onMessage(message, socket) {
        if (
          message.type === "readiness" &&
          message.lastError?.code === "MAPPING_ID_REQUIRED" &&
          !invoked
        ) {
          invoked = true;
          socket.send(JSON.stringify({
            type: "invoke",
            requestId: "ipc-gate-request",
            workDir: "C:\\private\\workspace",
            command: { kind: "prompt", message: "private prompt" },
          }));
        }
      },
    });
    try {
      await waitForFrame(
        daemon.frames,
        (message) =>
          message.type === "event" &&
          message.requestId === "ipc-gate-request",
        "IPC-gated invoke rejection",
      );
      const frame = daemon.frames.find(
        (message) =>
          message.type === "event" &&
          message.requestId === "ipc-gate-request",
      );
      for (const field of [
        "transactionId",
        "durationMs",
        "fenceSequence",
        "socketGeneration",
        "readinessRevision",
        "mappingGeneration",
        "workspaceGeneration",
      ]) {
        assert.equal(Object.hasOwn(frame, field), false);
      }
      if (expectTelemetry) {
        await waitForFrame(
          daemon.telemetry,
          (event) =>
            event.name === "daemon" &&
            event.action === "invoke" &&
            event.transactionId === "ipc-gate-request",
          "IPC-gated daemon telemetry",
        );
      } else {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const terminals = daemon.telemetry.filter(
        (event) =>
          event.name === "daemon" &&
          event.action === "invoke" &&
          event.transactionId === "ipc-gate-request",
      );
      assert.equal(terminals.length, expectTelemetry ? 1 : 0);
    } finally {
      await daemon.stop();
    }
  }
});

test("lifecycle gate refusals emit local-only terminals for every frame family", async () => {
  const requests = [
    ["workspace_create", "create", "1".repeat(64)],
    ["workspace_create", "clone", "2".repeat(64)],
    ["workspace_refresh", "refresh", "3".repeat(64)],
    ["workspace_reset_delete", "reset", "4".repeat(64)],
    ["workspace_reset_delete", "delete", "5".repeat(64)],
    ["workspace_restore_migration", "restore", "6".repeat(64)],
    ["workspace_restore_migration", "migration", "7".repeat(64)],
  ];
  const daemon = await startReadinessDaemon({
    observabilityTestIpc: true,
    afterRegisterResponse(socket) {
      for (const [type, operation, transactionId] of requests) {
        socket.send(JSON.stringify({
          type,
          operation,
          hostId: "readiness-test-host",
          mappingId: "mapping-test",
          mappingGeneration: 1,
          mappingVersion: 1,
          workspaceId: "workspace-test",
          workspaceGeneration: 1,
          sourcePlatform: "windows-drive",
          routeFingerprint: "a".repeat(64),
          authorityFingerprint: "b".repeat(64),
          inventoryGeneration: 1,
          idempotencyFingerprint: transactionId,
        }));
      }
    },
  });
  try {
    for (const [, operation, transactionId] of requests) {
      await waitForFrame(
        daemon.frames,
        (frame) => frame.type === "event" && frame.requestId === transactionId,
        `${operation} lifecycle gate refusal`,
      );
      await waitForFrame(
        daemon.telemetry,
        (event) => event.action === operation && event.transactionId === transactionId,
        `${operation} lifecycle telemetry`,
      );
      const frame = daemon.frames.find((candidate) => candidate.requestId === transactionId);
      assert.equal(Object.hasOwn(frame, "transactionId"), false);
      const terminals = daemon.telemetry.filter(
        (event) => event.action === operation && event.transactionId === transactionId,
      );
      assert.equal(terminals.length, 1);
      assert.deepEqual(
        {
          outcome: terminals[0].outcome,
          code: terminals[0].code,
          mappingId: terminals[0].mappingId,
          workspaceId: terminals[0].workspaceId,
          fenceSequence: terminals[0].fenceSequence,
          cleanupState: terminals[0].cleanupState,
        },
        {
          outcome: "refused",
          code: "RUNTIME_INCOMPATIBLE",
          mappingId: null,
          workspaceId: null,
          fenceSequence: null,
          cleanupState: ["reset", "delete", "restore", "migration"].includes(
            operation,
          )
            ? "not_required"
            : "not_applicable",
        },
      );
    }
  } finally {
    await daemon.stop();
  }
});

test("bound lifecycle admission projects daemon-owned correlation without wire leakage", async () => {
  const binding = readinessV2Bind();
  const transactionId = "8".repeat(64);
  const barrierTransactionId = "9".repeat(64);
  let lifecycleSent = false;
  let barrierSent = false;
  const lifecycleFrame = (id) => ({
    type: "workspace_create",
    operation: "create",
    hostId: binding.hostId,
    mappingId: "wire-mapping-divergent",
    mappingGeneration: 9,
    mappingVersion: binding.mappingVersion,
    workspaceId: binding.workspaceId,
    workspaceGeneration: 9,
    sourcePlatform: binding.sourcePlatform,
    routeFingerprint: binding.routeFingerprint,
    authorityFingerprint: binding.authorityFingerprint,
    inventoryGeneration: binding.inventoryGeneration,
    idempotencyFingerprint: id,
  });
  const daemon = await startReadinessDaemon({
    autoBind: true,
    observabilityTestIpc: true,
    envOverrides: {
      GJC_NATIVE_INVENTORY_MODE: "off",
      GJC_NATIVE_WORKSPACE_ROOT: "",
      GJC_NATIVE_WORKSPACE_SERVING: "0",
    },
    onMessage(message, socket) {
      if (message.type === "bind_ok" && !lifecycleSent) {
        lifecycleSent = true;
        socket.send(JSON.stringify(lifecycleFrame(transactionId)));
      }
      if (
        message.type === "event" &&
        message.requestId === transactionId &&
        !barrierSent
      ) {
        barrierSent = true;
        socket.send(JSON.stringify(lifecycleFrame(barrierTransactionId)));
      }
    },
  });
  try {
    await waitForFrame(
      daemon.telemetry,
      (event) =>
        event.name === "daemon" &&
        event.action === "create" &&
        event.transactionId === transactionId,
      "bound lifecycle telemetry",
    );
    const terminal = daemon.telemetry.find(
      (event) =>
        event.name === "daemon" &&
        event.action === "create" &&
        event.transactionId === transactionId,
    );
    // workspaceId must stay equal on the wire because it is the lookup key for
    // both accepted binding and inventory; the divergent mapping/generations
    // above are what prove correlation provenance.
    assert.deepEqual(
      {
        outcome: terminal.outcome,
        code: terminal.code,
        mappingGeneration: terminal.mappingGeneration,
        workspaceGeneration: terminal.workspaceGeneration,
        mappingId: terminal.mappingId,
        workspaceId: terminal.workspaceId,
        fenceSequence: terminal.fenceSequence,
        cleanupState: terminal.cleanupState,
      },
      {
        outcome: "refused",
        code: "RUNTIME_INCOMPATIBLE",
        mappingGeneration: 1,
        workspaceGeneration: 1,
        mappingId: "mapping-test",
        workspaceId: "workspace-test",
        fenceSequence: null,
        cleanupState: "not_applicable",
      },
    );
    assert.equal(Number.isSafeInteger(terminal.socketGeneration), true);
    assert.equal(terminal.socketGeneration >= 1, true);
    assert.equal(Number.isSafeInteger(terminal.readinessRevision), true);
    assert.equal(terminal.readinessRevision >= 0, true);
    await waitForFrame(
      daemon.frames,
      (message) =>
        message.type === "event" &&
        message.requestId === transactionId,
      "bound lifecycle refusal frame",
    );
    await waitForFrame(
      daemon.telemetry,
      (event) =>
        event.name === "daemon" &&
        event.action === "create" &&
        event.transactionId === barrierTransactionId,
      "bound lifecycle telemetry barrier",
    );
    assert.equal(
      daemon.telemetry.filter(
        (event) =>
          event.name === "daemon" &&
          event.action === "create" &&
          event.transactionId === transactionId,
      ).length,
      1,
    );
    const frame = daemon.frames.find(
      (message) =>
        message.type === "event" &&
        message.requestId === transactionId,
    );
    assert.deepEqual(Object.keys(frame).sort(), [
      "done",
      "error",
      "event",
      "requestId",
      "type",
    ]);
    assert.deepEqual(frame.event, {
      type: "workspace_lifecycle_refused",
      operation: "create",
      workspaceId: "workspace-test",
    });
    assert.deepEqual(JSON.parse(frame.error), {
      code: "RUNTIME_INCOMPATIBLE",
      retryable: false,
      action: "contact_admin",
    });
  } finally {
    await daemon.stop();
  }
});

test("denied registration uses one fixed retry and accepted recovery restores normal reconnects", async () => {
  // Deliberately overlaps the credential-bearing BOT_WS_URL to prove the
  // whole URL is redacted before shorter sensitive substrings.
  const token = "url-user";
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
    assert.match(output.value, /connected to bot at \[redacted\]/);

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
test("v2 starts connected-not-ready and ignores legacy readiness labels and workspace identity", async () => {
  const daemon = await startReadinessDaemon({
    testInjection: false,
    envOverrides: {
      GJC_READINESS_PROVIDER_AUTH_STATUS: "configured",
      GJC_MODEL_PROFILE: "legacy-profile",
      GJC_WORKSPACE_ID: "legacy-workspace",
      GJC_WORKSPACE_GENERATION: "99",
    },
  });
  try {
    await waitForFrame(
      daemon.frames,
      (message) => message.type === "readiness" && message.revision === 1,
      "initial connected-not-ready readiness"
    );
    const initial = daemon.frames.find(
      (message) => message.type === "readiness" && message.revision === 1
    );
    assert.deepEqual(initial.status, {
      connection: "online",
      runtime: "ready",
      providerAuth: "missing",
      modelProfile: "missing",
      workspace: "unknown",
    });
    assert.equal(Object.hasOwn(initial, "workspaceId"), false);
    assert.equal(Object.hasOwn(initial, "workspaceGeneration"), false);
  } finally {
    await daemon.stop();
  }
});

test("v2 probe success promotes all dimensions only with explicit mapping evidence", async () => {
  const daemon = await startReadinessDaemon({ autoBind: true });
  try {
    await waitForFrame(
      daemon.frames,
      (message) =>
        message.type === "readiness" &&
        message.status.providerAuth === "configured" &&
        message.status.modelProfile === "ready" &&
        message.status.workspace === "ready",
      "successful current-run probe"
    );
    const ready = daemon.frames.find(
      (message) =>
        message.type === "readiness" &&
        message.status.providerAuth === "configured" &&
        message.status.workspace === "ready"
    );
    assert.equal(ready.workspaceId, "workspace-test");
    assert.equal(ready.workspaceGeneration, 1);
  } finally {
    await daemon.stop();
  }
});

test("missing authenticated mapping stays non-ready and rejects before session creation", async () => {
  let invoked = false;
  const daemon = await startReadinessDaemon({
    observabilityTestIpc: true,
    envOverrides: {
      GJC_READINESS_TEST_WORKSPACE_ID: "",
      GJC_READINESS_TEST_WORKSPACE_GENERATION: "",
      GJC_READINESS_TEST_MAPPING_ID: "",
      GJC_READINESS_TEST_MAPPING_GENERATION: "",
      GJC_READINESS_TEST_MAPPING_VERSION: "",
      GJC_READINESS_TEST_WORK_DIR: "",
    },
    onMessage(message, socket) {
      if (
        message.type === "readiness" &&
        message.lastError?.code === "MAPPING_ID_REQUIRED" &&
        !invoked
      ) {
        invoked = true;
        socket.send(
          JSON.stringify({
            type: "invoke",
            requestId: "missing-mapping-request",
            workDir: "C:\\private\\workspace",
            command: { kind: "prompt", message: "hello" },
          })
        );
      }
    },
  });
  try {
    await waitForFrame(
      daemon.frames,
      (message) =>
        message.type === "event" &&
        message.requestId === "missing-mapping-request",
      "missing mapping rejection"
    );
    const event = daemon.frames.find(
      (message) =>
        message.type === "event" &&
        message.requestId === "missing-mapping-request"
    );
    const error = JSON.parse(event.error);
    assert.equal(error.code, "MAPPING_ID_REQUIRED");
    assert.equal(event.error.includes("private"), false);
    await waitForFrame(
      daemon.telemetry,
      (record) =>
        record.name === "daemon" &&
        record.action === "invoke" &&
        record.transactionId === "missing-mapping-request",
      "daemon invoke telemetry",
    );
    const records = daemon.telemetry.filter(
      (record) =>
        record.name === "daemon" &&
        record.action === "invoke" &&
        record.transactionId === "missing-mapping-request",
    );
    assert.equal(records.length, 1);
    assert.deepEqual(Object.keys(records[0]), [
      "schemaVersion", "name", "action", "outcome", "code", "cleanupState",
      "mappingId", "workspaceId", "transactionId", "fenceSequence", "durationMs",
      "socketGeneration", "readinessRevision", "mappingGeneration", "workspaceGeneration",
    ]);
    assert.deepEqual(records[0], {
      schemaVersion: 1,
      name: "daemon",
      action: "invoke",
      outcome: "refused",
      code: "MAPPING_ID_REQUIRED",
      cleanupState: null,
      mappingId: null,
      workspaceId: null,
      transactionId: "missing-mapping-request",
      fenceSequence: null,
      durationMs: records[0].durationMs,
      socketGeneration: null,
      readinessRevision: null,
      mappingGeneration: null,
      workspaceGeneration: null,
    });
    assert.equal(Number.isSafeInteger(records[0].durationMs), true);
    assert.equal(records[0].durationMs >= 0, true);
    assert.equal(JSON.stringify(records[0]).includes("private"), false);
    assert.equal(JSON.stringify(records[0]).includes("hello"), false);
  } finally {
    await daemon.stop();
  }
});

test("duplicate register_ok cannot change a committed readiness handshake", async () => {
  let duplicateSent = false;
  const daemon = await startReadinessDaemon({
    autoBind: true,
    onMessage(message, socket) {
      if (message.type === "readiness" && !duplicateSent) {
        duplicateSent = true;
        socket.send(
          JSON.stringify({
            type: "register_ok",
            protocolVersion: 1,
            capabilities: [],
          })
        );
      }
    },
  });
  try {
    await waitForFrame(
      daemon.frames,
      (message) =>
        message.type === "readiness" &&
        message.status.providerAuth === "configured" &&
        message.status.workspace === "ready" &&
        message.revision >= 3,
      "readiness after duplicate register_ok"
    );
    const ready = daemon.frames.find(
      (message) =>
        message.type === "readiness" &&
        message.status.providerAuth === "configured" &&
        message.status.workspace === "ready"
    );
    assert.equal(ready.workspaceId, "workspace-test");
    assert.equal(daemon.registrations.length, 1);
  } finally {
    await daemon.stop();
  }
});
test("v2 readiness publishes at TTL/2 and ping/pong never refreshes it", async () => {
  let pingSent = false;
  const daemon = await startReadinessDaemon({
    onMessage(message, socket) {
      if (message.type === "readiness" && !pingSent) {
        pingSent = true;
        socket.send(JSON.stringify({ type: "ping" }));
      }
    },
  });
  try {
    await waitForFrame(
      daemon.frames,
      (message) => message.type === "readiness" && message.revision >= 3,
      "two TTL/2 readiness publications"
    );
    const readiness = daemon.frames.filter((message) => message.type === "readiness");
    assert.ok(readiness.length >= 3);
    assert.equal(readiness[0].status.providerAuth, "missing");
    const steady = readiness.slice(1);
    assert.ok(
      steady[1].observedAt - steady[0].observedAt >= 400,
      "readiness must not publish faster than TTL/2"
    );
    assert.ok(daemon.frames.some((message) => message.type === "pong"));
    assert.deepEqual(
      daemon.frames.filter((message) => message.type === "pong"),
      [{ type: "pong" }]
    );
    assert.equal(steady[0].revision, 2);
    assert.equal(steady[1].revision, 3);
  } finally {
    await daemon.stop();
  }
});

test("v1 register response suppresses readiness egress and ping remains a plain pong", async () => {
  const daemon = await startReadinessDaemon({
    registerResponse: { type: "register_ok" },
  });
  try {
    await waitForLength(daemon.registrations, 1, "v1 registration");
    daemon.sockets[0].send(JSON.stringify({ type: "ping" }));
    await waitForFrame(
      daemon.frames,
      (message) => message.type === "pong",
      "plain pong"
    );
    await new Promise((resolve) => setTimeout(resolve, 1_200));
    assert.equal(
      daemon.frames.filter((message) => message.type === "readiness").length,
      0
    );
    assert.deepEqual(
      daemon.frames.filter((message) => message.type === "pong"),
      [{ type: "pong" }]
    );
  } finally {
    await daemon.stop();
  }
});

test("replacement sockets reset readiness generation and revision", async () => {
  let closedFirst = false;
  const daemon = await startReadinessDaemon({
    onMessage(message, socket) {
      if (message.type === "readiness" && !closedFirst) {
        closedFirst = true;
        socket.close();
      }
    },
  });
  try {
    await waitForLength(daemon.registrations, 2, "replacement registration", 6_000);
    await waitForFrame(
      daemon.frames,
      (message) => message.type === "readiness" && message.socketGeneration >= 2,
      "replacement readiness"
    );
    const readiness = daemon.frames.filter((message) => message.type === "readiness");
    const generations = [...new Set(readiness.map((message) => message.socketGeneration))];
    assert.ok(generations.length >= 2);
    const replacement = readiness.find(
      (message) => message.socketGeneration === generations[1]
    );
    assert.equal(replacement.revision, 1);
    assert.notEqual(replacement.socketGeneration, readiness[0].socketGeneration);
    assert.equal(replacement.workspaceGeneration, 1);
  } finally {
    await daemon.stop();
  }
});

test("failed current-run readiness probes stay non-ready and expose only bounded taxonomy", async () => {
  const secret = "probe-secret-value";
  let invoked = false;
  const daemon = await startReadinessDaemon({
    observabilityTestIpc: true,
    envOverrides: {
      GJC_READINESS_TEST_PROBE: "fail",
      GJC_READINESS_TEST_PROBE_ERROR_CODE: "UNKNOWN_RUNTIME",
      HOST_TOKEN: secret,
    },
    onMessage(message, socket) {
      if (
        message.type === "readiness" &&
        message.lastError?.code === "UNKNOWN_RUNTIME" &&
        !invoked
      ) {
        invoked = true;
        setTimeout(() => {
          socket.send(
            JSON.stringify({
              type: "invoke",
              requestId: "probe/request",
              workDir: "C:\\private\\workspace",
              command: { kind: "prompt", message: "hello" },
            })
          );
        }, 0);
      }
    },
  });
  try {
    await waitForFrame(
      daemon.frames,
      (message) => message.type === "event" && message.requestId === "probe/request",
      "probe rejection event"
    );
    const rejection = daemon.frames.find(
      (message) => message.type === "event" && message.requestId === "probe/request"
    );
    const error = JSON.parse(rejection.error);
    assert.equal(error.code, "UNKNOWN_RUNTIME");
    assert.equal(error.action, "retry_later");
    assert.equal(rejection.error.includes(secret), false);
    assert.equal(rejection.error.includes("private"), false);
    const readiness = daemon.frames.filter((message) => message.type === "readiness");
    const failed = readiness.find(
      (message) => message.lastError?.code === "UNKNOWN_RUNTIME"
    );
    assert.ok(failed);
    assert.equal(failed.status.workspace, "unknown");
    assert.equal(JSON.stringify(failed).includes(secret), false);
    assert.equal(JSON.stringify(failed).includes("private"), false);
    await waitForFrame(
      daemon.telemetry,
      (record) =>
        record.name === "daemon" &&
        record.action === "invoke" &&
        record.code === "UNKNOWN_RUNTIME",
      "non-opaque invoke telemetry",
    );
    const telemetry = daemon.telemetry.find(
      (record) =>
        record.name === "daemon" &&
        record.action === "invoke" &&
        record.code === "UNKNOWN_RUNTIME",
    );
    assert.equal(telemetry.transactionId, null);
    assert.equal(telemetry.mappingId, null);
    assert.equal(telemetry.workspaceId, null);
    assert.equal(JSON.stringify(telemetry).includes("probe/request"), false);
    assert.equal(JSON.stringify(telemetry).includes("private"), false);
    assert.equal(JSON.stringify(telemetry).includes("hello"), false);
  } finally {
    await daemon.stop();
  }
});

const RECEIPT_HOST = "readiness-test-host";
const RECEIPT_INVENTORY = workspaceInventoryBytes(buildWorkspaceInventory({
  hostId: RECEIPT_HOST,
  inventoryGeneration: 4,
  workspaces: [{
    hostId: RECEIPT_HOST,
    workspaceId: "workspace-test",
    sourcePlatform: "windows-drive",
    workDir: "C:\\workspace",
    rootIdentityFingerprint: "1".repeat(64),
    storageIdentityFingerprint: "2".repeat(64),
  }],
})).toString("utf8");
const RECEIPT_MAPPING = fingerprintManagedMappingRecord({
  mappingId: "mapping-test",
  hostId: RECEIPT_HOST,
  fenceGeneration: 1,
  mappingGeneration: 1,
  workspaceGeneration: 1,
  mappingVersion: 1,
  sourcePlatform: "windows-drive",
  workspaceId: "workspace-test",
  workDir: null,
  sourceRoot: "C:\\native\\workspace-test",
  containerRoot: null,
  volumeIdentity: "volume-1",
  casePolicy: "insensitive",
  immutableDefault: false,
  mappingFingerprint: null,
});
const RECEIPT_BIND = {
  type: "bind_workspace",
  bindingId: "receipt-binding-1",
  authorityEpoch: 1,
  fenceGeneration: 1,
  hostId: RECEIPT_HOST,
  mappingId: "mapping-test",
  mappingGeneration: 1,
  mappingVersion: 1,
  workspaceId: "workspace-test",
  workspaceGeneration: 1,
  sourcePlatform: "windows-drive",
  authorityFingerprint: RECEIPT_MAPPING.mappingFingerprint,
  mapping: RECEIPT_MAPPING,
};

test("live inventory drift drains receipt bindings and retires the socket without a stale ready", async () => {
  let bound = false;
  const daemon = await startReadinessDaemon({
    registerResponse: {
      type: "register_ok",
      protocolVersion: 3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
        WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
      ],
    },
    envOverrides: {
      GJC_NATIVE_INVENTORY_MODE: "verify",
      GJC_WORKSPACE_INVENTORY: RECEIPT_INVENTORY,
      GJC_WORKSPACE_INVENTORY_TEST_EPOCH_MISMATCH: "1",
      GJC_INVENTORY_POLL_MS: "40",
    },
    onMessage(message, socket) {
      if (message.type === "readiness" && !bound) {
        bound = true;
        socket.send(JSON.stringify(RECEIPT_BIND));
      }
    },
  });
  try {
    // The atomic cascade retires the socket once the background poll observes
    // provider epoch drift under the live receipt binding.
    await waitForLength(daemon.sockets, 1, "daemon websocket connection");
    await once(daemon.sockets[0], "close");
    // Serving is hard-false: the binding never promoted, so no positive
    // receipt, no ready workspace frame, and no session was ever created.
    assert.equal(daemon.frames.some((f) => f.type === "bind_ok"), false);
    assert.equal(
      daemon.frames.some(
        (f) => f.type === "readiness" && f.status?.workspace === "ready"
      ),
      false
    );
  } finally {
    await daemon.stop();
  }
});

test("managed registration rejects omitted, v1, and v2 REGISTER_OK floors before readiness work", async (t) => {
  const requiredCapabilities = [
    WORKSPACE_READINESS_CAPABILITY,
    WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
    WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
  ];
  const responses = [
    { name: "omitted", response: { type: "register_ok" } },
    {
      name: "v1",
      response: {
        type: "register_ok",
        protocolVersion: 1,
        capabilities: requiredCapabilities,
      },
    },
    {
      name: "v2",
      response: {
        type: "register_ok",
        protocolVersion: 2,
        capabilities: requiredCapabilities,
      },
    },
  ];

  for (const { name, response } of responses) {
    await t.test(name, async () => {
      const daemon = await startReadinessDaemon({
        registerResponse: response,
        envOverrides: {
          GJC_NATIVE_INVENTORY_MODE: "verify",
          GJC_WORKSPACE_INVENTORY: RECEIPT_INVENTORY,
        },
      });
      try {
        await waitForLength(daemon.registrations, 1, "managed registration");
        await waitForLength(daemon.closes, 1, "managed protocol refusal");

        assert.equal(daemon.closes[0].code, 1008);
        assert.equal(
          ["PROTOCOL_INCOMPATIBLE", ""].includes(daemon.closes[0].reason),
          true,
        );
        assert.equal(daemon.frames.length, 0);
        assert.equal(daemon.output().includes("daemon: registration accepted"), false);
        await waitForDaemonOutput(
          daemon,
          "daemon: disconnected from bot, retrying in "
        );
      } finally {
        await daemon.stop();
      }
    });
  }
});

test("daemon rejects workload frames before and after an incompatible managed handshake", async (t) => {
  const invoke = (requestId) => JSON.stringify({
    type: "invoke",
    requestId,
    workDir: "C:\\private\\workspace",
    command: { kind: "prompt", message: "must not run" },
  });
  for (const [name, hook] of [
    ["before", {
      beforeRegisterResponse(socket) {
        socket.send(invoke("before-handshake"));
        return false;
      },
    }],
    ["after", {
      afterRegisterResponse(socket) {
        socket.send(invoke("after-refusal"));
      },
    }],
  ]) {
    await t.test(name, async () => {
      const daemon = await startReadinessDaemon({
        registerResponse: { type: "register_ok" },
        observabilityTestIpc: true,
        envOverrides: {
          GJC_NATIVE_INVENTORY_MODE: "verify",
          GJC_WORKSPACE_INVENTORY: RECEIPT_INVENTORY,
        },
        ...hook,
      });
      try {
        await waitForLength(daemon.closes, 1, "managed policy close");
        await waitForFrame(
          daemon.policyCloses,
          (entry) =>
            entry.code === 1008 &&
            entry.reason === "PROTOCOL_INCOMPATIBLE",
          "daemon-side managed policy close",
        );
        if (name === "before") {
          assert.equal(daemon.closes[0].code, 1008);
        } else {
          assert.equal(
            [1008, 1006].includes(daemon.closes[0].code),
            true,
          );
        }
        assert.equal(daemon.frames.length, 0);
        assert.equal(
          daemon.telemetry.some((event) => event.action === "invoke"),
          false,
        );
        assert.equal(daemon.output().includes("must not run"), false);
        assert.equal(daemon.output().includes("fatal"), false);
        assert.equal(daemon.output().includes("unhandled rejection"), false);
      } finally {
        await daemon.stop();
      }
    });
  }
});

test("exact native-serving opt-in rejects a v3 peer when the daemon registration is below the floor", async () => {
  const daemon = await startReadinessDaemon({
    registerResponse: {
      type: "register_ok",
      protocolVersion: 3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
        WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
      ],
    },
    envOverrides: {
      GJC_NATIVE_INVENTORY_MODE: "off",
      GJC_NATIVE_WORKSPACE_SERVING: "1",
    },
  });
  try {
    await waitForLength(daemon.closes, 1, "managed protocol refusal");

    assert.equal(daemon.closes[0].code, 1008);
    assert.equal(
      ["PROTOCOL_INCOMPATIBLE", ""].includes(daemon.closes[0].reason),
      true,
    );
    assert.equal(daemon.frames.length, 0);
    assert.equal(daemon.output().includes("daemon: registration accepted"), false);
  } finally {
    await daemon.stop();
  }
});

test("managed registration accepts only the exact v3 protocol floor", async () => {
  const daemon = await startReadinessDaemon({
    registerResponse: {
      type: "register_ok",
      protocolVersion: 3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
        WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
      ],
    },
    envOverrides: {
      GJC_NATIVE_INVENTORY_MODE: "verify",
      GJC_WORKSPACE_INVENTORY: RECEIPT_INVENTORY,
    },
  });
  try {
    await waitForDaemonOutput(daemon, "daemon: registration accepted");
    await waitForFrame(
      daemon.frames,
      (frame) => frame.type === "readiness",
      "managed readiness publication"
    );

    assert.equal(daemon.registrations[0].protocolVersion, 3);
    assert.equal(daemon.closes.length, 0);
  } finally {
    await daemon.stop();
  }
});

test("off-mode preserves legacy v1 REGISTER_OK acceptance", async () => {
  const daemon = await startReadinessDaemon({
    registerResponse: {
      type: "register_ok",
      protocolVersion: 1,
      capabilities: [],
    },
    envOverrides: {
      GJC_NATIVE_INVENTORY_MODE: "off",
      GJC_NATIVE_WORKSPACE_SERVING: "0",
      GJC_READINESS_V2: "0",
    },
  });
  try {
    await waitForDaemonOutput(daemon, "daemon: registration accepted");

    assert.equal(daemon.registrations[0].protocolVersion, 1);
    assert.equal(daemon.closes.length, 0);
    assert.equal(daemon.frames.length, 0);
  } finally {
    await daemon.stop();
  }
});
