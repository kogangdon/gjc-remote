import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import { once } from "node:events";
import { HostRegistry } from "../bot/src/host-registry.js";

const port = Number(process.env.SMOKE_HOST_WS_PORT || 7788);
const hostId = process.env.SMOKE_HOST_ID || "local-smoke";
const token = process.env.SMOKE_HOST_TOKEN || "local-smoke-token";
// A second, distinct canonical workDir so the smoke drives two concurrent
// pooled sessions (each session clones Settings for its own cwd). This guards
// against gross cross-session breakage: session A must keep working after
// session B is created and activates the host profile. NOTE: when both workDirs
// resolve the SAME effective modelProfile.default (the default case), this does
// NOT exercise the specific per-role clobber that #25 fixed — to make it a true
// isolation regression guard, point SMOKE_WORK_DIR_2 at a directory whose
// project-level config sets a DIFFERENT modelProfile.default. Assumes the smoke
// runs from the repo root; defaults to the repo's daemon/ subdir.
const workDir = process.env.SMOKE_WORK_DIR || process.cwd();
const workDir2 = process.env.SMOKE_WORK_DIR_2 || join(process.cwd(), "daemon");
if (resolve(workDir) === resolve(workDir2)) {
  throw new Error(
    `SMOKE_WORK_DIR and SMOKE_WORK_DIR_2 must differ; both resolved to ${resolve(workDir)}`
  );
}
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

// Capture daemon output so the smoke can assert profile activation actually ran
// (see the profile-activation check below), while still forwarding it live.
let daemonOutput = "";
const captureDaemon = (chunk) => {
  daemonOutput += chunk.toString();
  process.stderr.write(chunk);
};
daemon.stdout.on("data", captureDaemon);
daemon.stderr.on("data", captureDaemon);

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

  // Create a second pooled session (its own Settings clone + profile
  // activation), then re-prompt the first. A passing re-prompt proves session A
  // survives session B's creation/activation end to end — a guard against gross
  // cross-session breakage (see the workDir2 note above for its limits).
  await promptExact(workDir2);
  await promptExact(workDir);
  // Prove profile activation ran against the real SDK rather than silently
  // falling back to the SDK default model. applyConfiguredModelProfile warns
  // and skips when it finds no usable profile; if that warning appears, the
  // session never routed through activateModelProfile (the exact surface this
  // smoke exists to regression-guard on an SDK bump), so fail loudly.
  const skipWarnings = [
    "gjc-remote daemon: no model profile configured",
    "gjc-remote daemon: modelProfile.default is set but not a usable",
  ].filter((needle) => daemonOutput.includes(needle));
  if (skipWarnings.length > 0) {
    throw new Error(
      "daemon skipped model-profile activation (SDK default fallback); this " +
        `host needs a usable modelProfile.default / GJC_MODEL_PROFILE. Saw: ${skipWarnings.join(
          "; "
        )}`
    );
  }

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
