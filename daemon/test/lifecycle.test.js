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
  testInjection = true,
  autoBind = false,
} = {}) {
  const frames = [];
  const registrations = [];
  const sockets = [];
  const wss = new WebSocketServer({ port: 0 });
  await once(wss, "listening");
  const { port } = wss.address();
  wss.on("connection", (socket) => {
    sockets.push(socket);
    socket.on("message", (raw) => {
      const message = JSON.parse(raw.toString());
      if (message.type === "register") {
        registrations.push(message);
        socket.send(JSON.stringify(registerResponse));
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
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });

  return {
    frames,
    registrations,
    sockets,
    output: () => output,
    async stop() {
      await stopChild(child);
      for (const socket of sockets) socket.terminate();
      await new Promise((resolve) => wss.close(() => resolve()));
    },
  };
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
              requestId: "probe-request",
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
      (message) => message.type === "event" && message.requestId === "probe-request",
      "probe rejection event"
    );
    const rejection = daemon.frames.find(
      (message) => message.type === "event" && message.requestId === "probe-request"
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
