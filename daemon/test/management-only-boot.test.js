import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  CAPABILITIES,
  WORKSPACE_READINESS_CAPABILITY,
  isReadinessMessage,
} from "@gjc-remote/shared";
import { SDK_PROFILE_MANAGEMENT_CAPABILITY } from "@gjc-remote/shared/sdk-profile-management.js";
import { WebSocketServer } from "ws";

const local = (path) => fileURLToPath(new URL(path, import.meta.url));
const WAIT_MS = 8_000;

async function bounded(promise, description, timeoutMs = WAIT_MS) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out waiting for ${description}`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function startDaemon(t, readinessNegotiated) {
  const root = mkdtempSync(join(tmpdir(), "gjc-management-only-boot-"));
  const hostState = mkdtempSync(join(root, "host-state-"));
  const directories = Object.fromEntries([
    "home", "config", "data", "state", "cache", "appdata", "localappdata", "work", "tmp",
  ].map((name) => {
    const directory = join(root, name);
    mkdirSync(directory, { mode: 0o700 });
    return [name, directory];
  }));
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  const frames = [];
  const ipc = [];
  const registrations = [];
  let socket;
  let child;
  let closed;
  let childClosed = false;
  let failure;
  let output = "";
  t.after(async () => {
    try {
      if (child && !childClosed) child.kill("SIGKILL");
      if (closed) await bounded(closed, "daemon termination", 3_000);
    } finally {
      for (const client of server.clients) client.terminate();
      try {
        await bounded(new Promise((resolve) => server.close(resolve)), "test bot closure", 3_000);
      } finally {
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    }
  });
  await bounded(once(server, "listening"), "test bot listener");
  server.on("error", (error) => { failure = error; });
  server.on("connection", (connection) => {
    socket = connection;
    connection.on("error", (error) => { failure = error; });
    connection.on("message", (raw) => {
      try {
        const message = JSON.parse(raw.toString());
        if (message.type === "register") {
          registrations.push(message);
          connection.send(JSON.stringify({
            type: "register_ok",
            protocolVersion: readinessNegotiated ? 2 : 1,
            capabilities: [
              ...CAPABILITIES,
              ...(readinessNegotiated ? [WORKSPACE_READINESS_CAPABILITY] : []),
            ],
          }));
        } else {
          frames.push(message);
        }
      } catch (error) {
        failure = error;
      }
    });
  });

  // Deliberately do not inherit credentials, SDK overrides, inspector/preload
  // settings, or native workspace configuration. Retain only OS launch needs.
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(path|pathext|systemroot|windir|systemdrive|comspec)$/i.test(key)) env[key] = value;
  }
  Object.assign(env, {
    HOME: directories.home,
    USERPROFILE: directories.home,
    APPDATA: directories.appdata,
    LOCALAPPDATA: directories.localappdata,
    XDG_CONFIG_HOME: directories.config,
    XDG_DATA_HOME: directories.data,
    XDG_STATE_HOME: directories.state,
    XDG_CACHE_HOME: directories.cache,
    TEMP: directories.tmp,
    TMP: directories.tmp,
    TMPDIR: directories.tmp,
    DOTENV_CONFIG_PATH: join(root, "absent.env"),
    GJC_FIXTURE_HOST_STATE: hostState,
    GJC_MANAGEMENT_ONLY_BOOT_FIXTURE: "1",
    HOST_ID: "management-only-boot-host",
    HOST_TOKEN: "management-only-boot-fixture-token",
    BOT_WS_URL: `ws://127.0.0.1:${server.address().port}`,
    GJC_NATIVE_INVENTORY_MODE: "off",
    GJC_NATIVE_WORKSPACE_SERVING: "0",
    GJC_SHUTDOWN_TIMEOUT_MS: "1000",
    GJC_READINESS_V2: "1",
    GJC_READINESS_TTL_MS: "1000",
    GJC_DAEMON_TEST_MODE: "1",
    GJC_OBSERVABILITY_TEST_IPC: "1",
    GJC_SESSION_FACTORY_TEST_INJECTION: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_READINESS_TEST_SECURITY: "pass",
    GJC_READINESS_TEST_WORKSPACE_ID: "fixture-workspace",
    GJC_READINESS_TEST_WORKSPACE_GENERATION: "1",
    GJC_READINESS_TEST_MAPPING_ID: "fixture-mapping",
    GJC_READINESS_TEST_MAPPING_GENERATION: "1",
    GJC_READINESS_TEST_MAPPING_VERSION: "1",
    GJC_READINESS_TEST_WORK_DIR: directories.work,
  });
  child = spawn(process.env.BUN_BIN || "bun", [
    "--no-env-file",
    "--preload", local("../test-fixtures/management-only-boot.mjs"),
    local("../src/daemon.js"),
  ], {
    cwd: directories.work,
    env,
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    windowsHide: true,
    timeout: 20_000,
    killSignal: "SIGKILL",
  });
  closed = new Promise((resolve) => child.once("close", (code, signal) => {
    childClosed = true;
    resolve({ code, signal });
  }));
  child.on("error", (error) => { failure = error; });
  child.on("message", (message) => ipc.push(message));
  const capture = (chunk) => { output = (output + chunk.toString()).slice(-64 * 1024); };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);

  function waitFor(predicate, description) {
    return new Promise((resolve, reject) => {
      let poll;
      let timer;
      function finish(error, value) {
        clearInterval(poll);
        clearTimeout(timer);
        if (error) reject(error);
        else resolve(value);
      }
      function check() {
        try {
          if (failure) throw failure;
          const value = predicate();
          if (value) return finish(null, value);
          if (childClosed) throw new Error(`daemon exited before ${description}; ${output}`);
        } catch (error) {
          finish(error);
        }
      }
      timer = setTimeout(() => finish(new Error(`timed out waiting for ${description}; ${output}`)), WAIT_MS);
      poll = setInterval(check, 10);
      check();
    });
  }
  let snapshotId = 0;
  return {
    frames, ipc, registrations, directories, hostState, waitFor,
    send(message) { socket.send(JSON.stringify(message)); },
    async snapshot() {
      const requestId = `snapshot-${++snapshotId}`;
      child.send({ type: "management_only_boot_snapshot_request", requestId }, (error) => {
        if (error) failure = error;
      });
      return waitFor(() => ipc.find((message) =>
        message.type === "management_only_boot_snapshot" && message.requestId === requestId,
      ), "preload counter snapshot");
    },
  };
}

// These are application-branch tests with a modeled consumed context, NOT
// qualification of the signed service bootstrap, native profile authority, or SDK.
for (const readinessNegotiated of [true, false]) {
  test(`management-only boot ignores hostile fixture flags (${readinessNegotiated ? "readiness v2" : "peer v1"})`, { timeout: 25_000 }, async (t) => {
    const daemon = await startDaemon(t, readinessNegotiated);
    const registration = await daemon.waitFor(() => daemon.registrations[0], "registration");
    assert.equal(registration.hostId, "management-only-boot-host");
    assert.equal(registration.token, "management-only-boot-fixture-token");
    assert.equal(registration.capabilities.includes(WORKSPACE_READINESS_CAPABILITY), true);
    assert.equal(registration.capabilities.includes(SDK_PROFILE_MANAGEMENT_CAPABILITY), false);
    assert.equal(registration.capabilities.some((capability) => capability.startsWith("sdk_profile_")), false);
    daemon.send({ type: "ping" });
    await daemon.waitFor(() => daemon.frames.find((frame) => frame.type === "pong"), "registered heartbeat");

    if (readinessNegotiated) {
      const unavailable = await daemon.waitFor(() => daemon.frames.find((frame) =>
        frame.type === "readiness" && frame.lastError?.code === "SDK_PROFILE_UNAVAILABLE",
      ), "profile-unavailable readiness");
      await daemon.waitFor(() => daemon.frames.find((frame) =>
        frame.type === "readiness" && frame.revision > unavailable.revision,
      ), "subsequent readiness publication");
    }

    for (const [index, command] of [
      { kind: "prompt", message: "must not reach any SDK or fixture session" },
      { kind: "set_model", modelName: "fixture:must-not-resolve" },
    ].entries()) {
      const requestId = `management-only-${index}`;
      daemon.send({ type: "invoke", requestId, workDir: daemon.directories.work, command });
      const terminal = await daemon.waitFor(() => daemon.frames.find((frame) =>
        frame.requestId === requestId && frame.done === true,
      ), `${command.kind} refusal`);
      assert.equal(terminal.type, "event");
      assert.deepEqual(terminal.event, {
        type: "invoke_terminal", disposition: "failed", code: "SDK_PROFILE_UNAVAILABLE",
      });
      assert.equal(daemon.frames.filter((frame) => frame.requestId === requestId).length, 1);
    }

    const snapshot = await daemon.snapshot();
    assert.deepEqual(snapshot, {
      type: "management_only_boot_snapshot",
      requestId: "snapshot-1",
      bootstrapConsumes: 1,
      sessionFactoryReads: 0,
      sessionFactoryCalls: 0,
      sdkSessionManagerCreates: 0,
      sdkSessionCreates: 0,
    });
    assert.equal(daemon.ipc.some((message) => message.type === "daemon_observability" ||
      message.type === "daemon_policy_close"), false, "service context must disable observability fixture IPC");
    const readiness = daemon.frames.filter((frame) => frame.type === "readiness");
    assert.equal(readiness.length > 0, readinessNegotiated);
    for (const frame of readiness) {
      assert.equal(isReadinessMessage(frame), true);
      assert.equal(frame.status.connection, "online");
      assert.equal(frame.status.providerAuth, "unknown");
      assert.equal(frame.status.modelProfile, "unknown");
      assert.notEqual(frame.status.workspace, "ready");
      assert.equal(Object.hasOwn(frame, "workspaceId"), false, "fixture mapping must not become readiness evidence");
    }
    assert.equal(existsSync(join(daemon.hostState, "sdk-profile-sharing.json")), false);
    for (const name of ["home", "config", "data", "state", "appdata", "localappdata", "work"]) {
      assert.deepEqual(readdirSync(daemon.directories[name]), [], `no dummy profile or SDK state in isolated ${name}`);
    }
  });
}
