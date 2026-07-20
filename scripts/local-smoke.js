import { spawn } from "node:child_process";
import { join } from "node:path";
import { once } from "node:events";
import { HostRegistry } from "../bot/src/host-registry.js";

const port = Number(process.env.SMOKE_HOST_WS_PORT || 7788);
const hostId = process.env.SMOKE_HOST_ID || "local-smoke";
const token = process.env.SMOKE_HOST_TOKEN || "local-smoke-token";
// A second, distinct canonical workDir so the smoke exercises two concurrent
// pooled sessions. Each session clones Settings for its own cwd, so activating
// one host profile must not clobber the other session (regression guard for the
// per-workDir Settings isolation fix). Defaults to the repo's daemon/ subdir.
const workDir = process.env.SMOKE_WORK_DIR || process.cwd();
const workDir2 = process.env.SMOKE_WORK_DIR_2 || join(process.cwd(), "daemon");
const expected = "SMOKE_OK";
const modelQuery = process.env.SMOKE_MODEL_QUERY;
const heartbeatIntervalMs = 100;
const heartbeatTimeoutMs = 5000;
const heartbeatTimers = createObservedHeartbeatTimers();

const registry = new HostRegistry({
  port,
  tokensByHostId: new Map([[hostId, token]]),
  heartbeatIntervalMs,
  heartbeatTimeoutMs,
  timers: heartbeatTimers.api,
});

await once(registry.wss, "listening");

const daemon = spawn(process.env.BUN_BIN || "bun", ["daemon/src/daemon.js"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    HOST_ID: hostId,
    HOST_TOKEN: token,
    HOST_LABEL: "local smoke test",
    BOT_WS_URL: `ws://localhost:${port}`,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

daemon.stdout.on("data", (chunk) => process.stderr.write(chunk));
daemon.stderr.on("data", (chunk) => process.stderr.write(chunk));

try {
  await waitForHost(registry, hostId, 10_000);
  await new Promise((resolve) =>
    setTimeout(resolve, heartbeatIntervalMs + heartbeatTimeoutMs + 100)
  );
  if (!registry.isOnline(hostId)) {
    throw new Error("host failed the application-level heartbeat");
  }
  if (
    heartbeatTimers.scheduledTimeouts === 0 ||
    heartbeatTimers.clearedTimeouts === 0
  ) {
    throw new Error("application-level ping/pong exchange was not observed");
  }

  const promptExact = async (dir) => {
    const r = await registry.invoke(
      hostId,
      dir,
      { kind: "prompt", message: `reply with exactly: ${expected}` },
      () => {},
      120_000
    );
    if (!r.ok) throw new Error(`invoke failed for ${dir}: ${r.error ?? "unknown error"}`);
    if (r.text !== expected) {
      throw new Error(
        `unexpected text for ${dir}: ${JSON.stringify(r.text)} (expected ${expected})`
      );
    }
    return r.text;
  };

  const result = { text: await promptExact(workDir) };

  // Two-workDir isolation: create a second pooled session (its own Settings
  // clone + profile activation), then re-prompt the first. If the second
  // session's activation clobbered shared model state, the first session would
  // now break — a passing re-prompt proves per-session isolation end to end.
  await promptExact(workDir2);
  await promptExact(workDir);

  let model;
  if (modelQuery) {
    const modelEvents = [];
    const modelResult = await registry.invoke(
      hostId,
      workDir,
      { kind: "set_model", modelName: modelQuery },
      (event) => modelEvents.push(event),
      120_000
    );
    if (!modelResult.ok) {
      throw new Error(`model invoke failed: ${modelResult.error ?? "unknown error"}`);
    }

    model = modelEvents.find((event) => event?.type === "model_resolved");
    if (!model) throw new Error("model invoke returned no model_resolved receipt");
  }
  console.log(
    JSON.stringify({ ok: true, hostId, workDir, workDir2, text: result.text, model })
  );
} finally {
  daemon.kill();
  await closeRegistry(registry);
}
function createObservedHeartbeatTimers() {
  const activeTimeouts = new Set();
  let scheduledTimeouts = 0;
  let clearedTimeouts = 0;

  return {
    api: {
      setInterval: (callback, delay) => setInterval(callback, delay),
      clearInterval: (timer) => clearInterval(timer),
      setTimeout(callback, delay) {
        let timer;
        timer = setTimeout(() => {
          activeTimeouts.delete(timer);
          callback();
        }, delay);
        activeTimeouts.add(timer);
        scheduledTimeouts += 1;
        return timer;
      },
      clearTimeout(timer) {
        if (activeTimeouts.delete(timer)) clearedTimeouts += 1;
        clearTimeout(timer);
      },
    },
    get scheduledTimeouts() {
      return scheduledTimeouts;
    },
    get clearedTimeouts() {
      return clearedTimeouts;
    },
  };
}

async function waitForHost(registry, id, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (!registry.isOnline(id)) {
    if (Date.now() > deadline) {
      throw new Error(`host '${id}' did not connect within ${timeoutMs}ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function closeRegistry(registry) {
  await registry.close();
}
