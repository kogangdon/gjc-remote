import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, mkdir, mkdtemp, realpath, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const testFile = fileURLToPath(import.meta.url);
const daemonDir = resolve(dirname(testFile), "..");
const repoRoot = resolve(daemonDir, "..");
const fixture = join(daemonDir, "test-fixtures", "sdk-isolation-probe.mjs");
const CHANGE_FILES = [
  "daemon/test-fixtures/sdk-isolation-probe.mjs",
  "daemon/test/sdk-isolation-probe.test.js",
  "docs/verification/issue62-evidence.md",
  "CONTEXT.md",
];
const artifactsDir = join(repoRoot, "artifacts");
const BASE_COMMIT = "a5bb530bd5a063b6571a7ba963e938bb6f97616f";
const SDK_VERSION = "0.18.12";
const MIN_BUN_VERSION = [1, 4, 0];
const FIXTURE_ROOT_PREFIX = "gjc-issue62-sdk-";
const MAX_RECEIPT_BYTES = 100_000;
const MAX_TIMEOUT_MS = 90_000;
const wrapperOwnedRoots = new Set();
const secretKey = /(?:api.?key|access.?token|refresh.?token|password|authorization|cookie|credential|broker|secret|oauth|token)/i;
const WINDOWS_ABSOLUTE_PATH = /(^|[\s"'([{=:])([A-Za-z]:[\\/](?:[^\\/\s"'<>]+[\\/])*[^\\/\s"'<>]+)/;
const UNC_PATH = /(^|[\s"'([{=:])((?:\\\\|\/\/)[^\\/\s"'<>]+(?:[\\/][^\\/\s"'<>]+)+)/;
const POSIX_ABSOLUTE_PATH = /(^|[\s"'([{=:])((?:\/[^\/\s"'<>]+)+)/;
const SECRET_KEY_PATTERN = String.raw`[A-Z0-9_]*(?:API[\s_-]*KEY|ACCESS[\s_-]*TOKEN|REFRESH[\s_-]*TOKEN|OAUTH|PASSWORD|AUTHORIZATION|COOKIE|BROKER|CREDENTIAL|SECRET|TOKEN)`;
const SECRET_KEY_VALUE_PATTERN = new RegExp(
  String.raw`\b${SECRET_KEY_PATTERN}\b\s*(?:[:=]\s*|\s+)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:Bearer\s+)?[^\s"',;}]+)`,
  "gi",
);
const SECRET_KEY_ONLY_PATTERN = new RegExp(String.raw`\b${SECRET_KEY_PATTERN}\b`, "gi");

function versionAtLeast(value, minimum) {
  const match = String(value).match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) return false;
  const observed = match.slice(1).map(Number);
  for (let index = 0; index < minimum.length; index += 1) {
    if (observed[index] > minimum[index]) return true;
    if (observed[index] < minimum[index]) return false;
  }
  return true;
}

function classifyProviderSet(providers, order, providerForLabel) {
  const observed = [...new Set(providers)].sort();
  const labels = order.split(",");
  const firstProvider = providerForLabel(labels[0]);
  const lastProvider = providerForLabel(labels[1]);
  if (observed.length === 1 && observed[0] === lastProvider) return "LAST_CREATED";
  if (observed.length === 1 && observed[0] === firstProvider) return "FIRST_CREATED";
  if (observed.length === 2 && observed.includes(firstProvider) && observed.includes(lastProvider)) return "BOTH";
  if (observed.length === 0) return "NONE";
  return "MIXED";
}

function redactPathLikeText(text) {
  text = text.replace(
    /(^|[\s"'([{=:])((?:\\\\|\/\/)[^\\/\s"'<>]+(?:[\\/][^\\/\s"'<>]+)+)/g,
    "$1<path-redacted>",
  );
  text = text.replace(
    /(^|[\s"'([{=:])([A-Za-z]:[\\/](?:[^\\/\s"'<>]+[\\/])*[^\\/\s"'<>]+)/g,
    "$1<path-redacted>",
  );
  return text.replace(
    /(^|[\s"'([{=:])((?:\/[^\/\s"'<>]+)+)/g,
    "$1<path-redacted>",
  );
}


async function stableEnv(order) {
  const allowed = new Set([
    "PATH", "Path", "SystemRoot", "WINDIR", "ComSpec", "COMSPEC", "PATHEXT",
    "BUN_INSTALL", "ProgramFiles", "PROGRAMFILES", "ProgramFiles(x86)", "CommonProgramFiles",
    "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "HOMEDRIVE", "HOMEPATH", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "OS", "LANG", "LC_ALL",
  ]);
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (allowed.has(key) && value) env[key] = value;
  const root = await realpath(await mkdtemp(join(tmpdir(), `issue62-wrapper-${process.pid}-${order.replace(",", "-")}-`)));
  wrapperOwnedRoots.add(root);
  env.HOME = root;
  env.USERPROFILE = root;
  env.TEMP = join(root, "tmp");
  env.TMP = join(root, "tmp");
  env.LOCALAPPDATA = join(root, "local-appdata");
  env.APPDATA = join(root, "appdata");
  const launcherRoot = join(root, "launcher");
  env.XDG_DATA_HOME = join(launcherRoot, "data");
  await mkdir(env.TMP, { recursive: true });
  await mkdir(join(env.XDG_DATA_HOME, "gjc", "natives"), { recursive: true });
  return { env, roots: [root, join(root, "tmp")], launcherRoot };
}
async function orderedChangeDigest() {
  const digest = createHash("sha256");
  for (const relativePath of CHANGE_FILES) {
    digest.update(relativePath);
    digest.update("\0");
    digest.update(await readFile(join(repoRoot, relativePath)));
    digest.update("\0");
  }
  return digest.digest("hex");
}

function sanitize(value, roots = []) {
  if (typeof value === "string") {
    let text = value;
    for (const root of [...roots].filter(Boolean).sort((a, b) => b.length - a.length)) {
      text = text.split(root).join("<wrapper-root>");
    }
    text = text.replace(/(?:https?|wss?):\/\/[^\s"']+/gi, "<url-redacted>");
    return redactPathLikeText(text)
      .replace(SECRET_KEY_VALUE_PATTERN, "<secret-redacted>")
      .replace(SECRET_KEY_ONLY_PATTERN, "<secret-redacted>")
      .replace(/<+secret-redacted>(?:-redacted>)*/g, "<secret-redacted>")
      .slice(0, 512);
  }
  if (Array.isArray(value)) return value.slice(0, 32).map(item => sanitize(item, roots));
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      if (secretKey.test(key)) continue;
      output[key] = sanitize(item, roots);
    }
    return output;
  }
  return value;
}

function assertNoRawPaths(value, roots = []) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const root of roots.filter(Boolean)) {
    assert.equal(text.includes(root), false, `raw fixture root leaked: ${root}`);
    if (root.includes("\\")) {
      assert.equal(text.includes(root.replaceAll("\\", "\\\\")), false, "escaped fixture root leaked");
    }
  }
  assert.doesNotMatch(text, WINDOWS_ABSOLUTE_PATH, "raw Windows path leaked");
  assert.doesNotMatch(text, UNC_PATH, "raw UNC path leaked");
  assert.doesNotMatch(text, POSIX_ABSOLUTE_PATH, "raw POSIX path leaked");
}

function parseReceipt(stdout, roots = []) {
  const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
  assert.ok(lines.length > 0, "Bun fixture emitted no JSON receipt");
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      const candidate = JSON.parse(lines[index]);
      if (candidate && typeof candidate === "object" && candidate.schema === "issue62-sdk-isolation-probe-v1") return candidate;
    } catch {
      // Bun diagnostics may precede the final structured line; raw output is never persisted.
    }
  }
  const diagnostic = sanitize(lines.at(-1), roots);
  assertNoRawPaths(diagnostic, roots);
  assert.fail(`Bun fixture emitted no structured receipt: ${diagnostic}`);
}

async function spawnBun(args, envInfo, entry = fixture) {
  const { env } = envInfo;
  await mkdir(env.HOME, { recursive: true });
  await mkdir(env.TMP, { recursive: true });
  return new Promise((resolveResult, reject) => {
    const bun = process.env.BUN_BIN || "bun";
    const child = spawn(bun, [entry, ...args], {
      cwd: repoRoot,
      env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let childError;
    const timer = setTimeout(() => {
      if (settled) return;
      child.kill("SIGTERM");
      setTimeout(() => {
        if (!settled) child.kill("SIGKILL");
      }, 2_000).unref?.();
    }, MAX_TIMEOUT_MS);
    child.stdout.on("data", chunk => { stdout += chunk; if (stdout.length > MAX_RECEIPT_BYTES * 2) stdout = stdout.slice(-MAX_RECEIPT_BYTES * 2); });
    child.stderr.on("data", chunk => { stderr += chunk; if (stderr.length > 20_000) stderr = stderr.slice(-20_000); });
    child.on("error", error => {
      // An error is not an exit boundary (for example, a failed kill).
      // Retain it, but never let finally remove a live child's loader cache.
      childError ??= error;
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (childError) { reject(childError); return; }
      resolveResult({ code, signal, stdout, stderr, childExited: true });
    });
  });
}

async function spawnFixture(order, envInfo, fixtureRoot) {
  return spawnBun([`--order=${order}`, "--json", `--fixture-root=${fixtureRoot}`], envInfo);
}

async function spawnRedactionProbe() {
  const envInfo = await stableEnv("redaction-probe");
  try {
    return await spawnBun(["--redaction-probe"], envInfo);
  } finally {
    await removeOwnedRoot(envInfo.roots[0]);
  }
}

async function runGuardLifecycleProbe(scenario) {
  const envInfo = await stableEnv("guard-lifecycle");
  try {
    const modulePath = join(envInfo.roots[0], "mock-sdk.mjs");
    const runnerPath = join(envInfo.roots[0], "guard-runner.mjs");
    await writeFile(modulePath, `
      const scenario = ${JSON.stringify(scenario)};
      const attempt = () => {
        const invoke = () => scenario.kind === "fetch"
          ? globalThis.fetch("https://guard.invalid/API_KEY=q7M4vN9xC2pL8rK")
          : globalThis.fetch.preconnect("https://guard.invalid/API_KEY=q7M4vN9xC2pL8rK");
        if (scenario.swallowed) {
          try { invoke(); } catch { /* Deliberately model an SDK-swallowed attempt. */ }
        } else invoke();
      };
      if (scenario.phase === "sdk-import") attempt();
      if (scenario.failure === "import") throw Object.assign(new Error("import primary"), { code: "MOCK_IMPORT_FAILED" });
      export async function dispose() {
        // A queued attempt during tracked disposal must remain guarded too.
        await Promise.resolve();
        if (scenario.phase === "sdk-teardown") attempt();
      }
    `);
    await writeFile(runnerPath, `
      import { observeGuardedSdkLifecycle } from ${JSON.stringify(pathToFileURL(fixture).href)};
      const scenario = ${JSON.stringify(scenario)};
      let escapedCalls = 0, restorationCount = 0, runStarted = false, disposals = 0;
      let sdk, receipt, failure;
      const originalFetch = () => { escapedCalls += 1; throw new Error("guard bypassed"); };
      originalFetch.preconnect = originalFetch;
      let installedFetch = originalFetch;
      Object.defineProperty(globalThis, "fetch", { configurable: true,
        get: () => installedFetch,
        set: value => { installedFetch = value; if (value === originalFetch) restorationCount += 1; },
      });
      try {
        receipt = await observeGuardedSdkLifecycle(async () => {
          sdk = await import(${JSON.stringify(pathToFileURL(modulePath).href)});
          if (scenario.failure === "setup") throw Object.assign(new Error("setup primary"), { code: "MOCK_SETUP_FAILED" });
        }, async guard => {
          runStarted = true;
          let primary;
          try {
            if (scenario.failure === "session") throw Object.assign(new Error("session primary"), { code: "MOCK_SESSION_FAILED" });
          } catch (error) { primary = error; }
          finally {
            guard.beginTeardown();
            disposals += 1;
            try { await guard.trackTeardown("mock-dispose", () => sdk.dispose()); }
            catch (error) {
              if (!primary) primary = error;
              else primary.details = { cleanupErrors: [{ operation: "mock-dispose", code: error.code }] };
            }
          }
          if (primary) throw primary;
          return { cleanup: { mockDisposed: true } };
        });
      } catch (error) {
        failure = { code: error.code, message: error.message, details: error.details };
      }
      // Identity and setter counts independently observe restoration, including
      // import/setup errors. The original stub cannot make a real connection.
      const output = { schema: "issue62-sdk-isolation-probe-v1", receipt, failure,
        escapedCalls, restorationCount, runStarted, disposals,
        restoredIdentity: globalThis.fetch === originalFetch && globalThis.fetch.preconnect === originalFetch,
        inheritedSensitiveNames: Object.keys(process.env).filter(key => /(?:API_KEY|TOKEN|SECRET|AUTHORIZATION|CREDENTIAL)/i.test(key)) };
      console.log(JSON.stringify(output));
    `);
    const result = await spawnBun([], envInfo, runnerPath);
    assert.equal(result.code, 0, `guard child failed: ${sanitize(result.stderr, envInfo.roots)}`);
    const receipt = sanitize(parseReceipt(result.stdout, envInfo.roots), envInfo.roots);
    assertNoRawPaths(receipt, envInfo.roots);
    assertNoDistinctiveSentinels(JSON.stringify(receipt), ["q7M4vN9xC2pL8rK"]);
    assert.equal(receipt.escapedCalls, 0, "no intercepted call reaches an original transport");
    assert.equal(receipt.restorationCount, 1, "original fetch restored exactly once");
    assert.equal(receipt.restoredIdentity, true, "original fetch/preconnect identity restored");
    assert.deepEqual(receipt.inheritedSensitiveNames, [], "child inherits no provider credentials");
    return receipt;
  } finally {
    await removeOwnedRoot(envInfo.roots[0]);
  }
}

async function runPooledFailureProbe(scenario) {
  const envInfo = await stableEnv("pooled-failure");
  try {
    const root = envInfo.roots[0];
    const runnerPath = join(root, "pooled-failure-runner.mjs");
    await writeFile(runnerPath, `
      import { observePooledFailureLifecycle } from ${JSON.stringify(pathToFileURL(fixture).href)};
      import { SessionPool } from ${JSON.stringify(pathToFileURL(join(daemonDir, "src/session-pool.js")).href)};
      const scenario = ${JSON.stringify(scenario)};
      const root = ${JSON.stringify(root)};
      const retainedScenario = scenario.startsWith("retained-");
      const creationScenario = scenario.startsWith("creation-");
      const afterObservation = scenario === "creation-after-observation-withheld";
      const pendingCleanupRejects = scenario.endsWith("pending-cleanup-rejected");
      const fixtureTimeout = retainedScenario && scenario.includes("timeout");
      const publicOwner = creationScenario || (retainedScenario && !scenario.includes("raw-timeout"));
      const withhold = (retainedScenario || creationScenario) && scenario.endsWith("withheld");
      const poolFailure = scenario.includes("pool-public");
      let restorationCount = 0, managerCloses = 0, disposals = 0, factories = 0, guardedCloses = 0;
      let escapedCalls = 0, completionJoins = 0, completionSettled = false, restoredBeforeSettlement = false;
      let adapterConstructions = 0, adapterDisposals = 0, startupCompleted = false, observationSettled = false;
      let pendingCleanupStatus = "pending", beforeRetainedRelease, observationBeforeStartup;
      const blockedAttempts = [], deadlineTimeouts = [], guardDeadlineSchedules = [];
      const releaseFactory = Promise.withResolvers();
      const factoryStarted = Promise.withResolvers();
      const pendingCleanupObserved = Promise.withResolvers();
      const releaseTeardown = Promise.withResolvers();
      const disposalStarted = Promise.withResolvers();
      const cleanupReached = Promise.withResolvers();
      const completionJoined = Promise.withResolvers();
      let retainedOwner;
      const pendingTimers = [];
      let timerScheduled = Promise.withResolvers();
      const schedule = (callback, timeoutMs, source) => {
        const timer = { callback, timeoutMs, source, active: true };
        pendingTimers.push(timer);
        timerScheduled.resolve();
        timerScheduled = Promise.withResolvers();
        return timer;
      };
      const timers = {
        setTimeout(callback, timeoutMs) {
          guardDeadlineSchedules.push(timeoutMs);
          return schedule(callback, timeoutMs, "guard");
        },
        clearTimeout(timer) { timer.active = false; },
      };
      const waitForDeadline = async (timeoutMs, source, active = true) => {
        for (;;) {
          const timer = pendingTimers.find(timer => (!active || timer.active) &&
            (timeoutMs === undefined || timer.timeoutMs === timeoutMs) &&
            (source === undefined || timer.source === source));
          if (timer) return timer;
          await timerScheduled.promise;
        }
      };
      const expireDeadline = timer => {
        if (!timer.active) throw new Error("deadline was cleared before its owner settled");
        timer.active = false;
        deadlineTimeouts.push(timer.timeoutMs);
        timer.callback();
      };
      const expireNextDeadline = async (timeoutMs, source) => expireDeadline(await waitForDeadline(timeoutMs, source));
      const originalSetTimeout = globalThis.setTimeout, originalClearTimeout = globalThis.clearTimeout;
      if (creationScenario) {
        // Exercise the actual pool's deadlines without elapsed-time waits.
        globalThis.setTimeout = (callback, timeoutMs, ...args) => schedule(() => callback(...args), timeoutMs, "pool");
        globalThis.clearTimeout = timer => { timer.active = false; };
      }
      const managerCloseCounts = [];
      const original = () => { escapedCalls += 1; throw new Error("transport escaped"); };
      original.preconnect = original;
      let installed = original;
      Object.defineProperty(globalThis, "fetch", { configurable: true, get: () => installed,
        set: value => { installed = value; if (value === original) {
          restorationCount += 1;
          if ((retainedScenario || creationScenario) && !completionSettled) restoredBeforeSettlement = true;
        } } });
      const attemptTransport = phase => {
        for (const kind of ["fetch", "preconnect"]) {
          try {
            if (kind === "fetch") globalThis.fetch("https://guard.invalid/API_KEY=q7M4vN9xC2pL8rK");
            else globalThis.fetch.preconnect("https://guard.invalid/API_KEY=q7M4vN9xC2pL8rK");
          } catch (error) { blockedAttempts.push({ ...(phase ? { phase } : {}), kind, code: error.code }); }
        }
      };
      const models = ["a", "b"].map(letter => ({ provider: "issue62-provider-" + letter, id: "issue62-model-" + letter }));
      const disposalMessage = scenario === "nested-pool-long-secret"
        ? 'distinctive disposal API_KEY="longQuotedPrefixZ9 ' + "x".repeat(2_100) + ' longQuotedSuffixY8" ' + root
        : "distinctive disposal API_KEY=q7M4vN9xC2pL8rK " + root;
      const distinctive = () => Object.assign(new Error(disposalMessage),
        { code: "DISTINCTIVE_DISPOSAL", cause: Object.assign(new Error("distinctive cause"), { code: "INNER_CAUSE" }) });
      const factoryFailure = () => {
        const primary = Object.assign(new Error("factory primary"), { code: "FACTORY_PRIMARY" });
        if (!scenario.startsWith("factory-diagnostic-")) return primary;
        primary.cause = Object.assign(new Error("factory cause API_KEY=q7M4vN9xC2pL8rK " + root), { code: "FACTORY_CAUSE" });
        const startupCleanup = Object.assign(new AggregateError([distinctive()], "startup cleanup " + root),
          { code: "STARTUP_CLEANUP_AGGREGATE" });
        Object.defineProperty(primary, "cleanupDiagnostic", { enumerable: false, value: {
          code: "MCP_MANAGER_CLEANUP_FAILED", cause: distinctive(),
        } });
        // Match the SDK's frozen-error AggregateError fallback, including the
        // shared primary/cleanup references in cause, errors and attached fields.
        const failure = scenario.endsWith("aggregate")
          ? new AggregateError([Object.freeze(primary), startupCleanup], primary.message, { cause: primary })
          : primary;
        Object.defineProperty(failure, "startupCleanupDiagnostic", { enumerable: false, value: {
          code: "STARTUP_RESOURCE_CLEANUP_FAILED", cause: startupCleanup,
        } });
        if (Object.keys(failure).includes("startupCleanupDiagnostic") || Object.keys(primary).includes("cleanupDiagnostic"))
          throw new Error("diagnostic fields must be non-enumerable");
        return failure;
      };
      const dependencies = {
        SessionPool: creationScenario ? class extends SessionPool {
          async ensureSession(workDir) {
            try {
              return await super.ensureSession(workDir,
                pendingCleanupRejects ? { managedIdentity: "issue62-admission-root" } : undefined);
            } catch (error) {
              if (error.pendingCleanup) void error.pendingCleanup.then(
                () => { pendingCleanupStatus = "fulfilled"; pendingCleanupObserved.resolve(); },
                () => { pendingCleanupStatus = "rejected"; pendingCleanupObserved.resolve(); },
              );
              throw error;
            }
          }
        } : SessionPool,
        SdkSession: class {
          constructor(raw) { adapterConstructions += 1; this.raw = raw; }
          dispose() { adapterDisposals += 1; return this.raw.dispose(); }
        },
        SessionManager: { create() { const index = managerCloseCounts.push(0) - 1; return { async close() {
          await Promise.resolve(); managerCloses += 1; guardedCloses += Number(installed !== original);
          managerCloseCounts[index] += 1;
          if (scenario === "manager-rejection") throw distinctive();
        } }; } },
        Settings: { get instance() { throw new Error("Settings not initialized"); } },
        getAllProvidersInfo: () => [], getCapabilityInfo: () => ({}),
        closeModelCache: () => { cleanupReached.resolve(); return true; },
        async createAgentSession(options) {
          factories += 1;
          if (scenario === "early" || scenario === "manager-rejection" || scenario.startsWith("factory-diagnostic-") || factories === 2)
            throw factoryFailure();
          if (creationScenario) {
            factoryStarted.resolve();
            await releaseFactory.promise;
            attemptTransport("startup");
            startupCompleted = true;
          }
          const order = models.map(model => model.provider);
          const values = { disabledProviders: [], enabledModels: models.map(model => model.provider + "/" + model.id),
            modelRoles: { default: "issue62-provider-a/issue62-model-a" },
            "task.agentModelOverrides": { planner: "issue62-provider-a/issue62-model-a" },
            modelProviderOrder: order, "startup.networkPrewarm": false };
          const settings = { getCwd: () => scenario === "validation" || (retainedScenario && !poolFailure) ? "wrong-scope" : options.cwd,
            getAgentDir: () => options.agentDir, get: key => values[key], getGlobal: key => values[key],
            getModelRole: () => values.modelRoles.default, getStorage: () => null };
          const registry = { authStorage: { getAll: () => ({}) }, getAll: () => models,
            getAvailable: () => models, getCanonicalId: () => "issue62-canonical-model",
            getCanonicalVariants: () => models.map(model => ({ model })),
            getCanonicalModels: () => [{ id: "issue62-canonical-model", variants: models.map(model => ({ model })) }],
            resolveCanonicalModel: () => models[0] };
          const raw = { settings, modelRegistry: registry, model: models[0], isDisposed: false,
            async dispose() {
              raw.isDisposed = true; disposals += 1;
              if (retainedScenario || creationScenario) {
                retainedOwner = releaseTeardown.promise.then(async () => {
                  attemptTransport(creationScenario ? "disposal" : undefined);
                  await options.sessionManager.close();
                  completionSettled = true;
                  if (scenario.endsWith("completion-rejected")) throw distinctive();
                });
                void retainedOwner.catch(() => {});
                disposalStarted.resolve();
                if (fixtureTimeout) return retainedOwner;
                throw Object.assign(new Error("Session disposal exceeded its bounded caller deadline."),
                  { name: "SessionDisposalIncompleteError" });
              }
              await options.sessionManager.close();
              throw new AggregateError([new AggregateError([distinctive()], "nested SDK cleanup")], "SDK cleanup");
            } };
          if (publicOwner) raw.awaitDisposeCompletion = () => {
            completionJoins += 1; completionJoined.resolve(); return retainedOwner;
          };
          return { session: raw };
        },
      };
      let failure;
      const observation = observePooledFailureLifecycle(dependencies, {
        root, agentDir: root, modelsPath: root + "/models.json",
        workDirs: { A: root + "/A", B: root + "/B", C: root + "/C" },
      }, retainedScenario || creationScenario ? timers : undefined).catch(error => {
        failure = { code: error.code, message: error.message, details: error.details };
      }).finally(() => { observationSettled = true; });
      if (creationScenario) {
        await factoryStarted.promise;
        await expireNextDeadline(30_000, "pool");
        await cleanupReached.promise;
        const finalTimer = await waitForDeadline(5_000, "guard", false);
        if (afterObservation) {
          expireDeadline(finalTimer);
          await observation;
          observationBeforeStartup = { startupCompleted, adapterConstructions, managerCloses,
            restorationCount, restored: installed === original };
        }
        releaseFactory.resolve();
        await disposalStarted.promise;
        await completionJoined.promise;
        await pendingCleanupObserved.promise;
        // Flush admitted promise reactions, not an elapsed cleanup delay.
        await new Promise(resolve => setImmediate(resolve));
        beforeRetainedRelease = { observationSettled, completionSettled, restorationCount,
          finalTimerActive: finalTimer.active, pendingCleanupStatus,
          guardDeadlineSchedules: [...guardDeadlineSchedules] };
        if (withhold && !afterObservation) {
          expireDeadline(finalTimer);
          await observation;
        }
        releaseTeardown.resolve();
        await retainedOwner.catch(() => {});
        await observation;
        await new Promise(resolve => setImmediate(resolve));
      }
      if (retainedScenario) {
        await disposalStarted.promise;
        if (fixtureTimeout) await expireNextDeadline();
        else await completionJoined.promise;
        await cleanupReached.promise;
        if (withhold) {
          await expireNextDeadline();
          await observation;
          // Attempt transport only AFTER the bounded observer has failed.
          // A stage flag or rejected public promise cannot release the guard.
          releaseTeardown.resolve();
        } else releaseTeardown.resolve();
        await retainedOwner.catch(() => {});
        if (publicOwner) await completionJoined.promise;
      }
      await observation;
      if (creationScenario) {
        globalThis.setTimeout = originalSetTimeout;
        globalThis.clearTimeout = originalClearTimeout;
      }
      console.log(JSON.stringify({ schema: "issue62-sdk-isolation-probe-v1", failure,
        managerCloses, managerCloseCounts, guardedCloses, disposals, factories, restorationCount, restored: installed === original,
        escapedCalls, completionJoins, completionSettled, restoredBeforeSettlement, blockedAttempts, deadlineTimeouts,
        adapterConstructions, adapterDisposals, startupCompleted, beforeRetainedRelease, observationBeforeStartup,
        pendingCleanupStatus, guardDeadlineSchedules }));
    `);
    // Distinct canonical directories are required by the actual factory router.
    for (const label of ["A", "B", "C"]) await mkdir(join(root, label));
    const result = await spawnBun([], envInfo, runnerPath);
    assert.equal(result.code, 0, sanitize(result.stderr, envInfo.roots));
    assertNoDistinctiveSentinels(result.stdout, ["q7M4vN9xC2pL8rK", "longQuotedPrefixZ9", "longQuotedSuffixY8"]);
    const rawOutput = JSON.parse(result.stdout.trim());
    assertNoRawPaths(rawOutput.failure.details.cleanupErrors, envInfo.roots);
    if (rawOutput.failure.details.originalDiagnostic) assertNoRawPaths(rawOutput.failure.details.originalDiagnostic, envInfo.roots);
    if (scenario.startsWith("factory-diagnostic-")) assertNoRawPaths(rawOutput.failure, envInfo.roots);
    const output = sanitize(parseReceipt(result.stdout, envInfo.roots), envInfo.roots);
    if (scenario.startsWith("retained-") || scenario.startsWith("creation-")) return output;
    assert.equal(output.restorationCount, 1);
    assert.equal(output.restored, true);
    const nestedPool = scenario === "nested-pool" || scenario === "nested-pool-long-secret";
    assert.equal(output.managerCloses, nestedPool ? 2 : 1);
    assert.deepEqual(output.managerCloseCounts, nestedPool ? [1, 1] : [1]);
    assert.equal(output.factories, nestedPool ? 2 : 1);
    assert.equal(output.guardedCloses, output.managerCloses);
    assert.equal(output.disposals, scenario === "early" || scenario === "manager-rejection" || scenario.startsWith("factory-diagnostic-") ? 0 : 1);
    assert.equal(output.failure.details.preconnectGuard.attempts, 0);
    assert.equal(output.failure.details.preconnectGuard.checkedAfterTrackedTeardown, true);
    return output.failure;
  } finally {
    await removeOwnedRoot(envInfo.roots[0]);
  }
}

test("issue #62 actual factory failure closes caller manager once under guard", async () => {
  const failure = await runPooledFailureProbe("early");
  assert.equal(failure.code, "FACTORY_PRIMARY");
  assert.equal(failure.message, "FACTORY_PRIMARY: factory primary");
  assert.deepEqual(failure.details.cleanupErrors, []);
});

test("issue #62 manager rejection retains factory primary and redacted original cause", async () => {
  const failure = await runPooledFailureProbe("manager-rejection");
  assert.equal(failure.code, "FACTORY_PRIMARY");
  const diagnostic = failure.details.cleanupErrors.find(item => item.operation === "create-A-manager-close");
  assert.equal(diagnostic.details.error.code, "DISTINCTIVE_DISPOSAL");
  assert.equal(diagnostic.details.error.cause.code, "INNER_CAUSE");
  assert.equal(failure.details.cleanup.callerManagerOutcomes[0].closed, false);
  assert.ok(failure.details.cleanup.leaks.some(item => item.kind === "caller-session-manager"));
});

test("issue #62 actual validation failure retains nested disposal rejection without double close", async () => {
  const failure = await runPooledFailureProbe("validation");
  assert.equal(failure.code, "API_CONTRACT_MISMATCH");
  const diagnostic = failure.details.cleanupErrors.find(item => item.operation === "create-A-dispose");
  assert.equal(diagnostic.details.error.errors[0].errors[0].code, "DISTINCTIVE_DISPOSAL");
  assert.equal(failure.details.cleanup.sessionDisposals[0].closed, false);
  assert.equal(failure.details.cleanup.sdkOwnedResourcesClosed, false);
});

test("issue #62 actual pool shutdown preserves nested SDK errors beside factory primary", async () => {
  const failure = await runPooledFailureProbe("nested-pool");
  assert.equal(failure.code, "FACTORY_PRIMARY");
  const diagnostic = failure.details.cleanupErrors.find(item => item.operation === "pool-shutdown");
  assert.equal(diagnostic.errors[0].errors[0].errors[0].code, "DISTINCTIVE_DISPOSAL");
  assert.equal(diagnostic.errors[0].errors[0].errors[0].cause.code, "INNER_CAUSE");
  assert.equal(failure.details.cleanup.sessionDisposals[0].closed, false);
  assert.equal(failure.details.cleanup.poolShutdown, false);
});

test("issue #62 deep pooled cleanup redacts complete long quoted secrets before truncation", async () => {
  const failure = await runPooledFailureProbe("nested-pool-long-secret");
  assert.equal(failure.code, "FACTORY_PRIMARY");
  const diagnostic = failure.details.cleanupErrors.find(item => item.operation === "pool-shutdown");
  const original = diagnostic.errors[0].errors[0].errors[0];
  assert.equal(original.code, "DISTINCTIVE_DISPOSAL");
  assert.equal(original.cause.code, "INNER_CAUSE");
  assert.match(original.error, /distinctive disposal <secret-redacted>/);
  assert.ok(original.error.length <= 512);
  assert.equal(failure.details.cleanup.sessionDisposals[0].closed, false);
});

for (const scenario of [
  "retained-public-rejection-settled",
  "retained-pool-public-rejection-settled",
  "retained-public-rejection-completion-rejected",
  "retained-public-timeout-settled",
  "retained-raw-timeout-settled",
  "retained-public-rejection-withheld",
  "retained-public-timeout-withheld",
  "retained-raw-timeout-withheld",
]) {
  test(`issue #62 ${scenario} keeps late teardown transport intercepted`, async () => {
    const output = await runPooledFailureProbe(scenario);
    const withheld = scenario.endsWith("withheld");
    const timeout = scenario.includes("timeout");
    const poolFailure = scenario.includes("pool-public");
    const publicOwner = !scenario.includes("raw-timeout");
    const failure = output.failure;
    assert.equal(failure.code, poolFailure ? "FACTORY_PRIMARY" : "API_CONTRACT_MISMATCH");
    assert.equal(output.disposals, 1, "no disposal retry after rejection or deadline");
    assert.equal(output.managerCloses, poolFailure ? 2 : 1);
    assert.equal(output.guardedCloses, output.managerCloses);
    assert.equal(output.escapedCalls, 0, "neither late fetch nor preconnect reaches original transport");
    assert.deepEqual(output.blockedAttempts, [
      { kind: "fetch", code: "ENVIRONMENT_BLOCKED" },
      { kind: "preconnect", code: "ENVIRONMENT_BLOCKED" },
    ]);
    assert.equal(output.completionSettled, true, "test releases the real retained owner deterministically");
    assert.equal(output.completionJoins, publicOwner ? 1 : 0);
    assert.equal(output.restoredBeforeSettlement, false);
    assert.equal(output.restorationCount, withheld ? 0 : 1);
    assert.equal(output.restored, !withheld);
    assert.deepEqual(output.deadlineTimeouts, Array(Number(timeout) + Number(withheld)).fill(5_000));
    const guard = failure.details.preconnectGuard;
    assert.equal(guard.completionConfirmed, !withheld);
    assert.equal(guard.checkedAfterTrackedTeardown, !withheld, "a teardown stage alone cannot certify completion");
    assert.equal(guard.restored, !withheld);
    assert.equal(guard.restorationBoundary, withheld ? "withheld-until-child-termination" : "after-owner-settlement");
    assert.equal(guard.attempts, withheld ? 0 : 2, "withheld case attempts transport after the failure receipt");
    if (!withheld) assert.deepEqual(guard.events.map(({ kind, stage }) => ({ kind, stage })), [
      { kind: "fetch", stage: "sdk-teardown" },
      { kind: "preconnect", stage: "sdk-teardown" },
    ]);
    const owner = guard.teardownOwners.find(owner => owner.label === (poolFailure ? "pool-A" : "create-A"));
    assert.equal(owner.retainedCompletion, publicOwner);
    assert.equal(owner.publicStatus, timeout ? (withheld ? "pending" : "fulfilled") : "rejected");
    assert.equal(owner.completionStatus, withheld ? "pending" : scenario.endsWith("completion-rejected") ? "rejected" : "fulfilled");
    const disposalFailure = failure.details.cleanupErrors.find(error =>
      error.operation === (poolFailure ? "pool-shutdown" : "create-A-dispose"));
    assert.ok(disposalFailure, "original disposal failure survives the later settlement");
    if (timeout) {
      assert.equal(disposalFailure.code, "SESSION_LIFECYCLE_FAILURE");
      assert.match(disposalFailure.error, /raw session disposal timed out/);
      assert.equal(disposalFailure.details.timeoutMs, 5_000);
    } else {
      assert.match(JSON.stringify(disposalFailure), /"name":"SessionDisposalIncompleteError"/);
      assert.match(JSON.stringify(disposalFailure), /Session disposal exceeded its bounded caller deadline\./);
    }
    if (scenario.endsWith("completion-rejected")) {
      const retainedFailure = failure.details.cleanupErrors.find(error => error.operation === "create-A-retained-completion");
      assert.equal(retainedFailure.code, "DISTINCTIVE_DISPOSAL");
      assert.equal(retainedFailure.cause.code, "INNER_CAUSE");
    }
    assert.equal(failure.details.cleanup.sessionDisposals[0].closed, false,
      "late completion cannot rewrite a failed public close into success");
    assert.equal(failure.details.cleanup.sdkOwnedResourcesClosed, false);
  });
}

for (const scenario of [
  "creation-after-observation-withheld",
  "creation-during-join-fulfilled",
  "creation-during-join-completion-rejected",
  "creation-during-join-withheld",
  "creation-during-join-pending-cleanup-rejected",
]) {
  test(`issue #62 ${scenario} retains factory-driven teardown admission`, async () => {
    const output = await runPooledFailureProbe(scenario);
    const afterObservation = scenario === "creation-after-observation-withheld";
    const withheld = scenario.endsWith("withheld");
    const pendingCleanupRejects = scenario.endsWith("pending-cleanup-rejected");
    const completionRejects = scenario.endsWith("completion-rejected");
    const failure = output.failure;
    assert.equal(failure.code, "SESSION_CREATE_TIMEOUT");
    assert.equal(failure.message, "SESSION_CREATE_TIMEOUT: GJC SDK session creation timed out");
    assert.equal(failure.details.originalDiagnostic.code, "SESSION_CREATE_TIMEOUT");
    assert.equal(output.factories, 1);
    assert.equal(output.adapterConstructions, 1, "late factory retains its injected adapter binding");
    assert.equal(output.adapterDisposals, 1);
    assert.equal(output.disposals, 1);
    assert.equal(output.managerCloses, 1);
    assert.deepEqual(output.managerCloseCounts, [1]);
    assert.equal(output.guardedCloses, 1);
    assert.equal(output.completionJoins, 1);
    assert.equal(output.startupCompleted, true);
    assert.equal(output.completionSettled, true);
    assert.equal(output.escapedCalls, 0, "startup and disposal never reach original transport");
    assert.deepEqual(output.blockedAttempts, ["startup", "disposal"].flatMap(phase =>
      ["fetch", "preconnect"].map(kind => ({ phase, kind, code: "ENVIRONMENT_BLOCKED" }))));
    assert.equal(output.restoredBeforeSettlement, false);
    assert.equal(output.restorationCount, withheld ? 0 : 1, "withholding cannot be undone by late settlement");
    assert.equal(output.restored, !withheld);
    assert.deepEqual(output.deadlineTimeouts, withheld ? [30_000, 5_000] : [30_000]);
    assert.deepEqual(output.guardDeadlineSchedules, [5_000], "one final budget, never restarted for another owner batch");
    assert.deepEqual(output.beforeRetainedRelease, {
      observationSettled: afterObservation,
      completionSettled: false,
      restorationCount: 0,
      finalTimerActive: !afterObservation,
      pendingCleanupStatus: pendingCleanupRejects ? "rejected" : "fulfilled",
      guardDeadlineSchedules: [5_000],
    }, "public pendingCleanup settlement cannot close admission ahead of retained raw teardown");
    if (afterObservation) assert.deepEqual(output.observationBeforeStartup, {
      startupCompleted: false, adapterConstructions: 0, managerCloses: 0,
      restorationCount: 0, restored: false,
    });
    const guard = failure.details.preconnectGuard;
    assert.equal(guard.completionConfirmed, !withheld);
    assert.equal(guard.checkedAfterTrackedTeardown, !withheld);
    assert.equal(guard.restored, !withheld);
    assert.equal(guard.restorationBoundary, withheld ? "withheld-until-child-termination" : "after-owner-settlement");
    assert.equal(guard.attempts, afterObservation ? 0 : withheld ? 2 : 4);
    const root = guard.teardownOwners.find(owner => owner.label === "factory-pending-cleanup");
    assert.ok(root, "retained factory/pendingCleanup root is registered before finalization");
    assert.equal(root.retainedCompletion, false);
    assert.equal(root.publicStatus, afterObservation ? "pending" : pendingCleanupRejects ? "rejected" : "fulfilled");
    assert.equal(root.completionStatus, root.publicStatus);
    const late = guard.teardownOwners.find(owner => owner.label === "pool-A");
    if (afterObservation) assert.equal(late, undefined, "late disposal is admitted only after failure capture");
    else {
      assert.ok(late, "dynamic final drain includes the late adapter/raw owner");
      assert.equal(late.publicStatus, "rejected");
      assert.equal(late.retainedCompletion, true);
      assert.equal(late.completionStatus, withheld ? "pending" : completionRejects ? "rejected" : "fulfilled");
      const publicFailure = failure.details.cleanupErrors.find(error => error.operation === "pool-A-public-dispose");
      assert.equal(publicFailure.name, "SessionDisposalIncompleteError");
      assert.equal(publicFailure.error, "Session disposal exceeded its bounded caller deadline.");
    }
    if (completionRejects) {
      const retainedFailure = failure.details.cleanupErrors.find(error => error.operation === "pool-A-retained-completion");
      assert.equal(retainedFailure.code, "DISTINCTIVE_DISPOSAL");
      assert.equal(retainedFailure.cause.code, "INNER_CAUSE");
    }
    if (pendingCleanupRejects) {
      const cleanupFailure = failure.details.cleanupErrors.find(error => error.operation === "factory-pending-cleanup");
      assert.equal(cleanupFailure.code, "SESSION_RETIREMENT_FAILED");
    }
    assert.equal(failure.details.cleanup.sdkOwnedResourcesClosed, false,
      "late owner settlement does not rewrite the failed observation into successful cleanup");
  });
}

for (const form of ["attached", "aggregate"]) {
  test(`issue #62 factory ${form} diagnostics preserve non-enumerable SDK cleanup failures`, async () => {
    const failure = await runPooledFailureProbe(`factory-diagnostic-${form}`);
    assert.equal(failure.code, form === "attached" ? "FACTORY_PRIMARY" : "PROBE_FAILURE");
    assert.equal(failure.message, `${failure.code}: factory primary`);
    const original = failure.details.originalDiagnostic;
    assert.equal(original.stage, "create-A");
    const startup = original.startupCleanupDiagnostic;
    assert.equal(startup.code, "STARTUP_RESOURCE_CLEANUP_FAILED");
    assert.equal(startup.cause.name, "AggregateError");
    assert.equal(startup.cause.code, "STARTUP_CLEANUP_AGGREGATE");
    assert.equal(startup.cause.errors[0].code, "DISTINCTIVE_DISPOSAL");
    assert.equal(startup.cause.errors[0].cause.code, "INNER_CAUSE");
    const primary = form === "aggregate" ? original.cause : original;
    assert.equal(primary.code, "FACTORY_PRIMARY");
    assert.equal(primary.error, "factory primary");
    assert.equal(primary.cause.code, "FACTORY_CAUSE");
    assert.equal(primary.cleanupDiagnostic.code, "MCP_MANAGER_CLEANUP_FAILED");
    assert.equal(primary.cleanupDiagnostic.cause.code, "DISTINCTIVE_DISPOSAL");
    assert.equal(primary.cleanupDiagnostic.cause.cause.code, "INNER_CAUSE");
    if (form === "aggregate") {
      assert.equal(original.name, "AggregateError");
      assert.equal(original.errors[0].code, "FACTORY_PRIMARY");
      assert.equal(original.errors[1].code, "STARTUP_CLEANUP_AGGREGATE");
      assert.equal(original.errors[1].errors[0].code, "DISTINCTIVE_DISPOSAL");
      assert.equal(original.errors[0].cleanupDiagnostic.code, "MCP_MANAGER_CLEANUP_FAILED");
    }
    const serialized = JSON.stringify(original);
    assert.ok(serialized.length < 12_000, "diagnostic remains bounded");
    assertNoDistinctiveSentinels(serialized, ["q7M4vN9xC2pL8rK"]);
    assertNoRawPaths(original);
    assert.match(serialized, /<secret-redacted>/);
    assert.match(serialized, /<(?:wrapper-root|fixture-root|path-redacted)>/);
    assert.deepEqual(failure.details.cleanupErrors, []);
  });
}

async function withImmediateRemovalProbe(run) {
  const { observeImmediateFixtureRemoval } = await import(pathToFileURL(fixture).href);
  const root = resolve(await mkdtemp(join(tmpdir(), FIXTURE_ROOT_PREFIX)));
  wrapperOwnedRoots.add(root);
  try {
    await run(root, observeImmediateFixtureRemoval);
  } finally {
    await removeOwnedRoot(root);
  }
}

async function withLauncherCacheProbe(run) {
  const { validateLauncherCacheRoot } = await import(pathToFileURL(fixture).href);
  const envInfo = await stableEnv("native-cache");
  const root = await realpath(await mkdtemp(join(envInfo.env.TMP, FIXTURE_ROOT_PREFIX)));
  wrapperOwnedRoots.add(root);
  try {
    await run(root, envInfo, validateLauncherCacheRoot);
  } finally {
    if (wrapperOwnedRoots.has(root)) await removeOwnedRoot(root);
    if (wrapperOwnedRoots.has(envInfo.roots[0])) await removeOwnedRoot(envInfo.roots[0]);
  }
}

test("issue #62 native cache is a separate launcher-owned root within the disposable wrapper", async () => {
  await withLauncherCacheProbe(async (root, envInfo, validate) => {
    const cache = await validate(root, envInfo.env);
    assert.equal(cache.wrapperRoot, envInfo.roots[0]);
    assert.equal(cache.launcherRoot, join(cache.wrapperRoot, "launcher"));
    assert.equal(cache.dataHome, envInfo.env.XDG_DATA_HOME);
    assert.equal(cache.nativesDir, join(cache.launcherRoot, "data", "gjc", "natives"));
    assert.equal(dirname(root), join(cache.wrapperRoot, "tmp"));
    assert.notEqual(dirname(root), cache.launcherRoot);
    assert.equal(existsSync(join(cache.dataHome, "gjc")), true, "official loader requires a pre-existing gjc directory");
  });
});

test("issue #62 cache scope refuses missing, relative, session-nested and external environment roots", async () => {
  await withLauncherCacheProbe(async (root, envInfo, validate) => {
    for (const overrides of [
      { XDG_DATA_HOME: undefined },
      { XDG_DATA_HOME: "relative-native-cache" },
      { XDG_DATA_HOME: root },
      { XDG_DATA_HOME: join(root, "data") },
      { XDG_DATA_HOME: repoRoot },
      { HOME: repoRoot },
      { USERPROFILE: repoRoot },
      { TEMP: repoRoot },
      { TMP: root },
    ]) {
      await assert.rejects(validate(root, { ...envInfo.env, ...overrides }), { code: "CLEANUP_SCOPE_VIOLATION" });
    }
    for (const candidate of [envInfo.launcherRoot, envInfo.roots[0], envInfo.env.TMP, repoRoot]) {
      await assert.rejects(validate(candidate, envInfo.env), { code: "CLEANUP_SCOPE_VIOLATION" });
    }
    assert.equal(existsSync(root), true, "scope rejection does not remove session scratch");
  });
});

for (const redirected of ["session", "natives"]) {
  test(`issue #62 cache scope refuses a redirected ${redirected} directory`, async () => {
    await withLauncherCacheProbe(async (root, envInfo, validate) => {
      const cache = await validate(root, envInfo.env);
      const target = join(envInfo.roots[0], "outside-cache");
      await mkdir(target);
      await writeFile(join(target, "preserved"), "do not remove through link");
      const link = redirected === "session" ? root : cache.nativesDir;
      await rm(link, { recursive: true, force: false, maxRetries: 0 });
      await symlink(target, link, process.platform === "win32" ? "junction" : "dir");
      await assert.rejects(validate(root, envInfo.env), { code: "CLEANUP_SCOPE_VIOLATION" });
      assert.equal(await readFile(join(target, "preserved"), "utf8"), "do not remove through link");
    });
  });
}

test("issue #62 cache scope refuses session data in launcher storage and missing loader prerequisites", async () => {
  await withLauncherCacheProbe(async (root, envInfo, validate) => {
    const dataRoot = join(envInfo.env.XDG_DATA_HOME, "gjc");
    await writeFile(join(dataRoot, "agent.db"), "not a native cache resource");
    await assert.rejects(validate(root, envInfo.env), { code: "CLEANUP_SCOPE_VIOLATION" });
    assert.equal(await readFile(join(dataRoot, "agent.db"), "utf8"), "not a native cache resource");
    await rm(dataRoot, { recursive: true, force: false, maxRetries: 0 });
    await assert.rejects(validate(root, envInfo.env), { code: "ENOENT" });
    assert.equal(existsSync(dataRoot), false, "validation never repairs the missing XDG prerequisite or falls back to home");
  });
});

test("issue #62 parent cache cleanup refuses pre-exit, external and redirected roots", async () => {
  await withLauncherCacheProbe(async (root, envInfo) => {
    await assert.rejects(removeLauncherCache(envInfo, { childExited: false }), /observed child exit/);
    await assert.rejects(removeLauncherCache({ ...envInfo, launcherRoot: root }, { childExited: true }), /exact launcher root/);
    await assert.rejects(removeLauncherCache({ ...envInfo, roots: [repoRoot] }, { childExited: true }), /belong to this wrapper/);
    const displaced = join(envInfo.roots[0], "displaced-launcher");
    await rename(envInfo.launcherRoot, displaced);
    await symlink(displaced, envInfo.launcherRoot, process.platform === "win32" ? "junction" : "dir");
    await assert.rejects(removeLauncherCache(envInfo, { childExited: true }), /redirected launcher cache/);
    assert.equal(existsSync(join(displaced, "data", "gjc", "natives")), true);
    assert.equal(existsSync(root), true);
  });
});

test("issue #62 modeled native cache outlives immediate session removal and is removed only after child exit", async () => {
  await withLauncherCacheProbe(async (root, envInfo, validate) => {
    const cache = await validate(root, envInfo.env);
    // This marker models ownership lifetime, not a DLL unload or SDK pass.
    const marker = join(cache.nativesDir, "modeled-process-lifetime.node");
    await writeFile(marker, "modeled cache bytes");
    const runner = join(envInfo.roots[0], "cache-lifetime-runner.mjs");
    await writeFile(runner, `
      import { existsSync } from "node:fs";
      import { mkdir, writeFile } from "node:fs/promises";
      import { join } from "node:path";
      import { observeImmediateFixtureRemoval, validateLauncherCacheRoot } from ${JSON.stringify(pathToFileURL(fixture).href)};
      const root = ${JSON.stringify(root)};
      const cache = await validateLauncherCacheRoot(root);
      const events = [];
      const removal = await observeImmediateFixtureRemoval(root, async owned => {
        for (const name of ["auth", "model-cache", "settings", "workdir"]) {
          await mkdir(join(owned, name));
          await writeFile(join(owned, name, "owned-marker"), "session-owned");
          events.push(name + "-close");
        }
      });
      events.push("session-removed");
      console.log(JSON.stringify({ schema: "issue62-sdk-isolation-probe-v1", modeledCacheLifetime: true,
        removal, events, scratchAbsentBeforeChildExit: !existsSync(root),
        cachePresentBeforeChildExit: existsSync(join(cache.nativesDir, "modeled-process-lifetime.node")) }));
    `);
    await assert.rejects(removeLauncherCache(envInfo), /observed child exit/);
    const result = await spawnBun([], envInfo, runner);
    assert.equal(result.code, 0, `cache lifetime child failed: ${sanitize(result.stderr, envInfo.roots)}`);
    const receipt = parseReceipt(result.stdout, envInfo.roots);
    assert.equal(receipt.modeledCacheLifetime, true);
    assert.equal(receipt.scratchAbsentBeforeChildExit, true);
    assert.equal(receipt.cachePresentBeforeChildExit, true);
    assert.equal(receipt.removal.attempts, 1);
    assert.equal(receipt.removal.removed, true);
    assert.equal(receipt.removal.immediateAfterPublicClose, true);
    assert.equal(receipt.removal.beforeChildExit, true);
    assert.deepEqual(receipt.events, ["auth-close", "model-cache-close", "settings-close", "workdir-close", "session-removed"]);
    assert.equal(existsSync(root), false);
    assert.equal(await readFile(marker, "utf8"), "modeled cache bytes");
    const cleanup = await removeLauncherCache(envInfo, result);
    assert.equal(cleanup.removed, true);
    assert.equal(cleanup.attempts, 1);
    assert.equal(cleanup.scope, "launcher-cache-only");
    assert.equal(cleanup.afterChildExit, true);
    assert.equal(cleanup.immediateAfterPublicClose, false);
    assert.equal(cleanup.immediateSessionCloseProof, false);
    assert.equal(existsSync(cache.launcherRoot), false);
  });
});

test("issue #62 fixture lifecycle closes before immediate owned scratch removal", async () => {
  await withImmediateRemovalProbe(async (root, observe) => {
    const events = [];
    const outcome = await observe(root, async owned => {
      await writeFile(join(owned, "owned-marker"), "fixture only");
      events.push("auth-close", "model-cache-close");
    }, async (owned, options) => {
      events.push("remove");
      assert.equal(owned, await realpath(root));
      assert.deepEqual(options, { recursive: true, force: false, maxRetries: 0 });
      await rm(owned, options);
    });
    assert.deepEqual(events, ["auth-close", "model-cache-close", "remove"]);
    assert.equal(existsSync(root), false);
    assert.equal(outcome.removed, true);
    assert.equal(outcome.attempts, 1);
    assert.equal(outcome.immediateAfterPublicClose, true);
    assert.equal(outcome.beforeChildExit, true);
    assert.equal(outcome.firstFailure, null);
  });
});

for (const code of ["EACCES", "EBUSY", "ENOTEMPTY", "EPERM", "EIO"]) {
  test(`issue #62 immediate ${code} removal failure is retained without retry or repair`, async () => {
    await withImmediateRemovalProbe(async (root, observe) => {
      let removals = 0;
      await assert.rejects(observe(root, async owned => {
        await writeFile(join(owned, "owned-marker"), "fixture only");
      }, async () => {
        removals += 1;
        throw Object.assign(new Error("distinctive removal failure"), { code, syscall: "rmdir" });
      }), error => {
        assert.equal(error.code, "SESSION_LIFECYCLE_FAILURE");
        assert.equal(error.details.fixtureRemoval.attempts, 1);
        assert.equal(error.details.fixtureRemoval.removed, false);
        assert.equal(error.details.fixtureRemoval.firstFailure.code, code);
        assert.equal(error.details.fixtureRemoval.firstFailure.syscall, "rmdir");
        assert.equal(error.details.fixtureRemoval.classification, "immediate-removal-failed");
        return true;
      });
      assert.equal(removals, 1);
      assert.equal(await readFile(join(root, "owned-marker"), "utf8"), "fixture only");
    });
  });
}

test("issue #62 resolved removal without absence cannot pass", async () => {
  await withImmediateRemovalProbe(async (root, observe) => {
    let removals = 0;
    await assert.rejects(observe(root, async () => {}, async () => { removals += 1; }), error => {
      assert.equal(error.code, "SESSION_LIFECYCLE_FAILURE");
      assert.equal(error.details.fixtureRemoval.removed, false);
      return true;
    });
    assert.equal(removals, 1);
    assert.equal(existsSync(root), true);
  });
});

test("issue #62 public close rejection is not hidden by scratch removal", async () => {
  await withImmediateRemovalProbe(async (root, observe) => {
    const failure = new Error("public close failed");
    let removals = 0;
    await assert.rejects(observe(root, async () => { throw failure; }, async () => { removals += 1; }),
      error => error === failure);
    assert.equal(removals, 0);
    assert.equal(existsSync(root), true);
  });
});

test("issue #62 immediate cleanup fails rather than repairing process cwd", async () => {
  await withImmediateRemovalProbe(async (root, observe) => {
    const cwd = process.cwd();
    let removals = 0;
    try {
      await assert.rejects(observe(root, async owned => { process.chdir(owned); },
        async () => { removals += 1; }), error => {
        assert.equal(error.code, "SESSION_LIFECYCLE_FAILURE");
        assert.equal(error.details.fixtureRemoval.cwd.insideFixtureBefore, true);
        assert.equal(error.details.fixtureRemoval.attempts, 0);
        return true;
      });
      assert.equal(removals, 0);
      assert.equal(await realpath(process.cwd()), await realpath(root));
    } finally {
      process.chdir(cwd);
    }
  });
});

test("issue #62 immediate cleanup refuses nonempty or non-prefixed wrapper roots", async () => {
  await withImmediateRemovalProbe(async (root, observe) => {
    let closes = 0;
    let removals = 0;
    const close = async () => { closes += 1; };
    const remove = async () => { removals += 1; };
    await writeFile(join(root, "preexisting"), "do not touch");
    await assert.rejects(observe(root, close, remove), { code: "CLEANUP_SCOPE_VIOLATION" });
    await assert.rejects(observe(dirname(root), close, remove), { code: "CLEANUP_SCOPE_VIOLATION" });
    assert.equal(closes, 0);
    assert.equal(removals, 0);
    assert.equal(await readFile(join(root, "preexisting"), "utf8"), "do not touch");
  });
});

async function removeOwnedRoot(root) {
  root = resolve(root);
  assert.equal(wrapperOwnedRoots.has(root), true, "refusing to remove a root not created by this wrapper");
  const existedBefore = existsSync(root);
  if (!existedBefore) {
    wrapperOwnedRoots.delete(root);
    return {
      scope: "wrapper-owned-root-only",
      attempted: false,
      existedBefore: false,
      removed: false,
      attempts: 0,
    };
  }
  try {
    await rm(root, { recursive: true, force: false, maxRetries: 0 });
    assert.equal(existsSync(root), false, "wrapper-owned root still existed after rm resolved");
    wrapperOwnedRoots.delete(root);
    return { scope: "wrapper-owned-root-only", attempted: true, existedBefore, removed: true, attempts: 1 };
  } catch (error) {
    // Do not retry the failed root again from the wrapper's outer finally.
    wrapperOwnedRoots.delete(root);
    const failure = new Error("wrapper-owned root removal failed", { cause: error });
    failure.cleanup = {
      scope: "wrapper-owned-root-only",
      attempted: true,
      existedBefore,
      removed: !existsSync(root),
      attempts: 1,
      errorCode: error?.code ?? "UNKNOWN",
      syscall: error?.syscall ?? null,
    };
    throw failure;
  }
}

async function removeLauncherCache(envInfo, childResult) {
  assert.equal(childResult?.childExited, true, "launcher cache removal requires observed child exit");
  const wrapperRoot = envInfo.roots[0];
  assert.equal(wrapperOwnedRoots.has(wrapperRoot), true, "launcher cache must belong to this wrapper");
  const root = envInfo.launcherRoot;
  assert.equal(root, join(wrapperRoot, "launcher"), "refusing a cache outside the exact launcher root");
  assert.equal(await realpath(root), root, "refusing a redirected launcher cache root");
  wrapperOwnedRoots.add(root);
  try {
    return {
      ...await removeOwnedRoot(root),
      owner: "wrapper",
      scope: "launcher-cache-only",
      afterChildExit: true,
      immediateAfterPublicClose: false,
      immediateSessionCloseProof: false,
    };
  } catch (error) {
    // Removing an ancestor in finally would retry this failed cache cleanup.
    wrapperOwnedRoots.delete(wrapperRoot);
    error.cleanup = {
      ...error.cleanup,
      owner: "wrapper",
      scope: "launcher-cache-only",
      afterChildExit: true,
      immediateAfterPublicClose: false,
      immediateSessionCloseProof: false,
    };
    throw error;
  }
}

async function validateReceipt(receipt, order, roots = []) {
  assert.equal(receipt.issue, 62);
  assert.equal(receipt.approvedBaseCommit, BASE_COMMIT);
  assert.match(receipt.sourceCommit, /^[0-9a-f]{40}$/);
  assert.equal(receipt.sdkVersionExpected, SDK_VERSION);
  assert.equal(receipt.sdkVersionObserved, SDK_VERSION);
  assert.equal(receipt.daemonDependencyVersion, SDK_VERSION);
  assert.equal(receipt.lockfileVersionEvidence, SDK_VERSION);
  assert.deepEqual(receipt.sdkDependencyProvenance, ["agent-core", "ai"].map(name => ({
    packageName: `@gajae-code/${name}`,
    installedVersion: SDK_VERSION,
    lockedVersion: SDK_VERSION,
    declaredVersion: SDK_VERSION,
  })));
  assert.equal(versionAtLeast(receipt.bunVersion, MIN_BUN_VERSION), true);
  assert.deepEqual(receipt.order, order.split(","));
  assert.deepEqual(receipt.changeSet.files, CHANGE_FILES);
  assert.equal(receipt.changeSet.algorithm, "sha256");
  assert.match(receipt.changeSet.digest, /^[0-9a-f]{64}$/);
  assert.equal(receipt.changeSet.digest, await orderedChangeDigest());
  assert.equal(receipt.sourceIdentity.historicalBaseline.commit, BASE_COMMIT);
  assert.match(receipt.sourceIdentity.historicalBaseline.semantics, /Historical/);
  assert.equal(receipt.sourceIdentity.runtimeHead.commit, receipt.sourceCommit);
  assert.match(receipt.sourceIdentity.runtimeHead.semantics, /Git HEAD/);
  assert.deepEqual(receipt.sourceIdentity.workingTreeEvidence.files, CHANGE_FILES);
  assert.equal(receipt.sourceIdentity.workingTreeEvidence.algorithm, "sha256");
  assert.equal(receipt.sourceIdentity.workingTreeEvidence.digest, receipt.changeSet.digest);
  assert.match(receipt.sourceIdentity.workingTreeEvidence.semantics, /working tree/);
  assert.ok(Array.isArray(receipt.runner.argv));
  assert.equal(receipt.runner.command, receipt.runner.argv.join(" "));
  assert.ok(receipt.runner.argv.includes(`--order=${order}`));
  assert.ok(receipt.runner.argv.includes("--json"));
  assert.match(
    receipt.runner.argv.find(item => item.startsWith("--fixture-root=")) ?? "",
    /^--fixture-root=<(?:fixture-root|path-redacted)>$/,
  );
  assert.equal(receipt.runner.orderCommand, `--order=${order}`);
  assert.equal(receipt.globalSettingsBootstrap.initCalls, 0);
  assert.equal(receipt.globalSettingsBootstrap.initialized, false);
  assert.deepEqual(receipt.globalSettingsBootstrap.before, { initialized: false });
  assert.deepEqual(receipt.globalSettingsBootstrap.after, { initialized: false });
  assert.equal(receipt.globalSettingsBootstrap.strategy, "createAgentSession-owned Settings.loadForScope");
  assert.deepEqual(receipt.globalSettingsBootstrap.scopes.map(scope => scope.label), ["A", "B"]);
  assert.ok(receipt.globalSettingsBootstrap.scopes.every(scope => scope.cwd.startsWith("<") && scope.agentDir.startsWith("<")));
  assert.equal(receipt.liveSessionCount, 2);
  assert.equal(receipt.liveWorkDirs.length, 2);
  assert.deepEqual(receipt.liveWorkDirLabels, ["A", "B"]);
  assert.equal(receipt.cPreSessionCandidates, 0);
  assert.equal(receipt.modelFallback, false);
  assert.deepEqual(receipt.failureCodes, []);
  assert.equal(receipt.preconnectGuard.available, true);
  assert.deepEqual(receipt.preconnectGuard.events, []);
  assert.equal(receipt.preconnectGuard.attempts, 0);
  assert.equal(receipt.preconnectGuard.observed, false);
  assert.equal(receipt.preconnectGuard.checkedAfterTrackedTeardown, true);
  assert.equal(receipt.preconnectGuard.restored, true);
  assert.equal(receipt.preconnectGuard.completionConfirmed, true);
  assert.equal(receipt.preconnectGuard.restorationBoundary, "after-owner-settlement");
  assert.deepEqual(receipt.preconnectGuard.teardownOwners.map(owner => owner.label).sort(), ["pool-A", "pool-B"]);
  assert.ok(receipt.preconnectGuard.teardownOwners.every(owner =>
    owner.publicStatus === "fulfilled" && owner.completionStatus === "fulfilled" && owner.retainedCompletion === true));
  assert.match(receipt.preconnectGuard.scope, /guarded SDK\/daemon imports through tracked resource teardown/);
  assert.match(receipt.preconnectGuard.scope, /excludes other network APIs, calls after restoration/);
  assert.equal(receipt.networkPrewarm.global, false);
  assert.equal(receipt.networkPrewarm.A, false);
  assert.equal(receipt.networkPrewarm.B, false);
  assert.equal(receipt.networkPrewarm.C, false);
  assert.deepEqual(receipt.networkIsolation.modelPresetRegistry, {
    fixtureEnvironment: "GJC_MODEL_PRESET_REGISTRY_DISABLED=1",
    setBeforeSdkImport: true,
  });
  assert.deepEqual(
    receipt.networkIsolation.disabledBackgroundDiscoveryProviders,
    ["ollama", "llama.cpp", "lm-studio", "omlx", "opencodex", "vllm", "sglang"],
  );
  assert.equal(receipt.networkIsolation.staticFixtureProviderApi, "anthropic-messages");
  assert.match(receipt.networkIsolation.scope, /Fixture-only/);
  assert.equal(receipt.negativeCases.unknownCapabilityRejected, true);
  assert.deepEqual(receipt.negativeCases.unknownCapability, {
    requestedId: "issue62-unknown-capability",
    rejected: true,
    error: {
      name: "Error",
      code: null,
      message: 'Unknown capability: "issue62-unknown-capability"',
    },
  });
  assert.equal(receipt.negativeCases.noPrompt, true);
  assert.equal(receipt.negativeCases.cSessionConstructionAttempts, 0);
  assert.equal(receipt.negativeCases.cPromptAttempts, 0);
  assert.equal(receipt.negativeCases.cRegistryBoundary, "nonmatching-enabledModels");
  assert.deepEqual(
    new Set(receipt.fixturePolicy.C.disabledProviders),
    new Set(["ollama", "llama.cpp", "lm-studio", "omlx", "opencodex", "vllm", "sglang"]),
  );
  assert.equal(receipt.fixturePolicy.C.disabledProviders.includes("issue62-provider-a"), false);
  assert.equal(receipt.fixturePolicy.C.disabledProviders.includes("issue62-provider-b"), false);
  assert.equal(receipt.canonicalVariants.variants.length, 2);
  assert.deepEqual(new Set(receipt.canonicalVariants.variants), new Set(["issue62-provider-a/issue62-model-a", "issue62-provider-b/issue62-model-b"]));
  assert.equal(receipt.capability.sessionReads.length, 2);
  for (const read of receipt.capability.sessionReads) {
    assert.equal(read.explicit.items.length, 1);
    assert.equal(read.cwdFallback.items.length, 1);
    const expectedProvider = read.label === "A" ? "issue62-capability-a" : "issue62-capability-b";
    assert.equal(read.explicit.items[0].source.provider, expectedProvider);
    assert.equal(read.cwdFallback.items[0].source.provider, expectedProvider);
    assert.ok(read.explicit.items[0].source.providerName);
    assert.ok(read.explicit.items[0].source.path.startsWith("<"));
    assert.equal(read.explicit.items[0].source.level, "project");
  }
  assert.deepEqual(receipt.capability.scopedCounters, {
    "issue62-capability-a": 2,
    "issue62-capability-b": 2,
    "issue62-capability-throwing": 4,
  });
  assert.equal(receipt.capability.unregisteredCwdFallback.cwdRegistration, "absent");
  assert.ok(receipt.capability.unregisteredCwdFallback.items.length > 0);
  assert.equal(
    receipt.capability.unregisteredCwdFallback.classification,
    classifyProviderSet(
      receipt.capability.unregisteredCwdFallback.providers.filter(provider =>
        provider === "issue62-capability-a" || provider === "issue62-capability-b"
      ),
      order,
      label => label === "A" ? "issue62-capability-a" : "issue62-capability-b",
    ),
  );
  const labels = new Set(receipt.model.sessions.map(item => item.label));
  assert.deepEqual(labels, new Set(["A", "B"]));
  for (const session of receipt.model.sessions) {
    assert.equal(session.activeModel, session.label === "A" ? "issue62-provider-a/issue62-model-a" : "issue62-provider-b/issue62-model-b");
    assert.equal(session.authEntryProviderCount, 0);
  }
  assert.deepEqual(receipt.registryClassification.availableResolvedProvider, {
    A: "issue62-provider-a",
    B: "issue62-provider-b",
  });
  assert.deepEqual(receipt.registryClassification.mergedProviderOrder, {
    A: ["issue62-provider-a", "issue62-provider-b"],
    B: ["issue62-provider-b", "issue62-provider-a"],
  });
  assert.deepEqual(receipt.registryClassification.globalProviderOrder, {
    A: ["issue62-provider-a", "issue62-provider-b"],
    B: ["issue62-provider-a", "issue62-provider-b"],
  });
  assert.equal(receipt.registrySnapshots.creationOrder.length, 2);
  assert.deepEqual(receipt.registrySnapshots.creationOrder.map(item => item.label), order.split(","));
  for (const { label, registry: snapshot } of [...receipt.registrySnapshots.creationOrder, ...receipt.registrySnapshots.perSession]) {
    assert.ok(["issue62-provider-a", "issue62-provider-b"].includes(snapshot.resolvedProvider));
    assert.ok(["issue62-provider-a/issue62-model-a", "issue62-provider-b/issue62-model-b"].includes(snapshot.resolvedSelector));
    assert.equal(snapshot.availableResolvedProvider, label === "A" ? "issue62-provider-a" : "issue62-provider-b");
    assert.equal(snapshot.availableResolvedSelector, label === "A" ? "issue62-provider-a/issue62-model-a" : "issue62-provider-b/issue62-model-b");
  }
  assert.deepEqual(receipt.isolationObservations.settings, {
    construction: "createAgentSession-owned Settings.loadForScope",
    instancesDistinct: true,
    policiesDistinct: true,
    stableAfterSiblingCreation: true,
  });
  assert.equal(receipt.isolationObservations.model.activeSelectionPerWorkDir, true);
  assert.equal(receipt.isolationObservations.model.availableCanonicalResolutionPerWorkDir, true);
  assert.equal(receipt.isolationObservations.discovery.explicitSettingsPerWorkDir, true);
  assert.equal(receipt.isolationObservations.discovery.registeredCwdFallbackPerWorkDir, true);
  assert.deepEqual(receipt.isolationObservations.discovery.scopedRegistrySuccess.labels, ["A", "B"]);
  assert.equal(receipt.isolationObservations.discovery.scopedRegistrySuccess.scopeBound, true);
  assert.match(receipt.isolationObservations.discovery.scopedRegistrySuccess.semantics, /own enabled provider/);
  assert.equal(receipt.isolationObservations.discovery.unregisteredCwdFallback.scopeBound, false);
  assert.equal(
    receipt.isolationObservations.discovery.unregisteredCwdFallback.classification,
    receipt.capability.unregisteredCwdFallback.classification,
  );
  assert.equal(receipt.isolationObservations.discovery.unscopedCapabilityFallback.scopeBound, false);
  assert.equal(
    receipt.isolationObservations.discovery.unscopedCapabilityFallback.classification,
    receipt.capability.unregisteredCwdFallback.classification,
  );
  assert.match(
    receipt.isolationObservations.discovery.unscopedCapabilityFallback.semantics,
    /not evidence of per-workDir isolation/,
  );
  assert.equal(
    receipt.globalIntrospection.classification,
    classifyProviderSet(
      receipt.globalIntrospection.final.enabledFixtureProviders,
      order,
      label => label === "A" ? "issue62-capability-a" : "issue62-capability-b",
    ),
  );
  assert.equal(receipt.globalIntrospection.scopeBound, false);
  assert.equal(receipt.cleanup.poolShutdown, true);
  assert.equal(receipt.cleanup.storesClosed, true);
  assert.equal(receipt.cleanup.sdkOwnedResourcesClosed, true);
  assert.equal(receipt.cleanup.sdkOwnedResourceOutcomes.length, 2);
  assert.deepEqual(
    receipt.cleanup.sdkOwnedResourceOutcomes.map(outcome => outcome.label).sort(),
    ["A", "B"],
  );
  assert.ok(receipt.cleanup.sdkOwnedResourceOutcomes.every(outcome =>
    outcome.modelRegistryOwnership === "createAgentSession" &&
    outcome.authStorageOwnership === "createAgentSession" &&
    outcome.settingsOwnership === "createAgentSession" &&
    outcome.settingsStorageClosed === true
  ));
  assert.match(receipt.cleanup.sdkLifecycleSourceContract.scopedSettings, /Settings\.loadForScope/);
  assert.match(receipt.cleanup.sdkLifecycleSourceContract.ownedResources, /ModelRegistry, AuthStorage, Settings, and SessionManager/);
  assert.match(receipt.cleanup.sdkLifecycleSourceContract.sharedModelCache, /exact fixture models\.db/);
  assert.match(receipt.cleanup.sdkLifecycleSourceContract.processGlobalDrain, /No aggregate process-global drain/);
  assert.equal(receipt.cleanup.fixtureRemoved, true);
  assert.equal(receipt.cleanup.fixtureRemoval.owner, "child");
  assert.equal(receipt.cleanup.fixtureRemoval.scope, "fixture-root-only");
  assert.equal(receipt.cleanup.fixtureRemoval.attempted, true);
  assert.equal(receipt.cleanup.fixtureRemoval.removed, true);
  assert.equal(receipt.cleanup.fixtureRemoval.attempts, 1);
  assert.equal(receipt.cleanup.fixtureRemoval.immediateAfterPublicClose, true);
  assert.equal(receipt.cleanup.fixtureRemoval.beforeChildExit, true);
  assert.equal(receipt.cleanup.fixtureRemoval.cwd.insideFixtureBefore, false);
  assert.equal(receipt.cleanup.fixtureRemoval.firstFailure, null);
  assert.equal(receipt.cleanup.fixtureRemoval.classification, "removed-first-attempt");
  assert.equal(receipt.cleanup.fixtureRemoval.activeResourcesBefore.available, true);
  assert.equal(typeof receipt.cleanup.fixtureRemoval.activeResourcesBefore.counts, "object");
  assert.equal(receipt.cleanup.parentSalvage.existedBefore, false);
  assert.equal(receipt.cleanup.parentSalvage.attempted, false);
  assert.equal(receipt.cleanup.parentSalvage.attempts, 0);
  assert.deepEqual(receipt.cleanup.nativeCache, {
    owner: "wrapper",
    scope: "launcher-cache-only",
    lifetime: "child-process",
    configuration: "XDG_DATA_HOME/gjc/natives",
    configuredBeforeSdkImport: true,
    insideWrapperRoot: true,
    outsideSessionScratch: true,
    presentAfterSessionRemoval: true,
    stagedAddonPresent: receipt.platform.platform === "win32",
    childRemovalAttempted: false,
    cleanupBoundary: "parent-after-child-exit",
    immediateSessionCloseProof: false,
  });
  assert.deepEqual(receipt.cleanup.parentCacheRemoval, {
    owner: "wrapper",
    scope: "launcher-cache-only",
    attempted: true,
    existedBefore: true,
    removed: true,
    attempts: 1,
    afterChildExit: true,
    immediateAfterPublicClose: false,
    immediateSessionCloseProof: false,
  });
  assert.deepEqual(receipt.cleanup.leaks, []);
  assert.match(receipt.cleanup.leakScope, /filesystem removal is reported separately/);
  assert.equal(receipt.cleanup.storeOutcomes.length, 4);
  assert.ok(receipt.cleanup.storeOutcomes.every(outcome => outcome.closed));
  assert.deepEqual(receipt.cleanup.storeOutcomes.map(outcome => outcome.name),
    ["model-registry-C", "auth-C", "settings-C", "model-cache"]);
  assert.equal(receipt.artifactName, null);
  assert.match(receipt.customFactoryBoundary, /Profile activation and live provider transport are not covered\./);
  assert.equal(receipt.coverage.auth, "SDK-owned empty fixture auth for A/B; fixture-owned empty auth for C");
  assert.equal(receipt.coverage.sessionHostAccess, "not-exercised");
  assert.ok(JSON.stringify(receipt).length < MAX_RECEIPT_BYTES);
  const serialized = JSON.stringify(receipt);
  assert.doesNotMatch(serialized, /OPENROUTER_API_KEY|access_token|refresh_token|Authorization|credential|secret|token/i);
  assert.doesNotMatch(serialized, /[A-Za-z]:\\Users\\/i);
  assertNoRawPaths(receipt, roots);
}

async function writeReceiptArtifact(name, receipt, roots = []) {
  const sanitized = sanitize({ ...receipt, artifactName: name }, roots);
  const output = JSON.stringify(sanitized, null, 2) + "\n";
  assert.ok(Buffer.byteLength(output, "utf8") < MAX_RECEIPT_BYTES);
  const target = join(artifactsDir, name);
  const temporary = `${target}.tmp-${process.pid}`;
  await writeFile(temporary, output, { encoding: "utf8", flag: "w" });
  await rename(temporary, target);
}

async function runOrder(order) {
  const name = order === "A,B" ? "issue62-A-B.json" : "issue62-B-A.json";
  const target = join(artifactsDir, name);
  const envInfo = await stableEnv(order);
  let fixtureRoot;
  try {
    try {
      await unlink(target);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await mkdir(artifactsDir, { recursive: true });
    fixtureRoot = resolve(await mkdtemp(join(envInfo.env.TMP, FIXTURE_ROOT_PREFIX)));
    wrapperOwnedRoots.add(fixtureRoot);
    const result = await spawnFixture(order, envInfo, fixtureRoot);
    const existedAfterChildExit = existsSync(fixtureRoot);
    let parentRemoval;
    let parentRemovalError;
    try {
      parentRemoval = await removeOwnedRoot(fixtureRoot);
    } catch (error) {
      parentRemovalError = error;
      parentRemoval = error?.cleanup ?? {
        scope: "wrapper-owned-root-only",
        attempted: true,
        existedBefore: existedAfterChildExit,
        removed: false,
        attempts: 0,
        errorCode: error?.code ?? "UNKNOWN",
      };
    }
    let parentCacheRemoval;
    let parentCacheRemovalError;
    try {
      parentCacheRemoval = await removeLauncherCache(envInfo, result);
    } catch (error) {
      parentCacheRemovalError = error;
      parentCacheRemoval = error?.cleanup ?? {
        owner: "wrapper",
        scope: "launcher-cache-only",
        attempted: false,
        removed: false,
        afterChildExit: true,
        immediateAfterPublicClose: false,
        immediateSessionCloseProof: false,
        errorCode: error?.code ?? "UNKNOWN",
      };
    }
    if (parentRemovalError) wrapperOwnedRoots.delete(envInfo.roots[0]);
    const receipt = parseReceipt(result.stdout, envInfo.roots);
    receipt.cleanup = {
      ...receipt.cleanup,
      // Parent salvage cannot replace the child's immediate-removal verdict.
      parentSalvage: parentRemoval,
      // Loaded native code belongs to the launcher, not to the session stores.
      parentCacheRemoval,
    };
    const failureReceipt = sanitize({
      error: receipt.error ?? null,
      details: receipt.details ?? {},
      cleanup: receipt.cleanup ?? {},
    }, envInfo.roots);
    const sanitizedStderr = sanitize(result.stderr, envInfo.roots);
    assertNoRawPaths(failureReceipt, envInfo.roots);
    assertNoRawPaths(sanitizedStderr, envInfo.roots);
    assert.equal(
      result.code,
      0,
      `${order} fixture failed (${result.signal}): ${sanitizedStderr}\n` +
        `Sanitized receipt diagnostics: ${JSON.stringify(failureReceipt)}\n` +
        `Parent cleanup diagnostics: ${JSON.stringify(sanitize({ parentRemoval, parentCacheRemoval }, envInfo.roots))}`,
    );
    if (parentRemovalError || parentCacheRemovalError) {
      assert.fail(
        `parent cleanup failed after child exit: ${JSON.stringify(sanitize({ parentRemoval, parentCacheRemoval }, envInfo.roots))}\n` +
          `Completed child cleanup receipt: ${JSON.stringify(failureReceipt.cleanup)}`,
      );
    }
    assert.equal(existedAfterChildExit, false, "child must remove its owned fixture before exit");
    await validateReceipt(receipt, order, envInfo.roots);
    await writeReceiptArtifact(name, { ...receipt, nodeWrapperVersion: process.version }, envInfo.roots);
    return receipt;
  } finally {
    if (fixtureRoot && wrapperOwnedRoots.has(fixtureRoot)) {
      await removeOwnedRoot(fixtureRoot);
    }
    if (wrapperOwnedRoots.has(envInfo.roots[0])) await removeOwnedRoot(envInfo.roots[0]);
  }
}

function assertNoDistinctiveSentinels(text, sentinels) {
  const fragments = [
    ...new Set([
      ...sentinels,
      ...sentinels.map(value => value.slice(0, 8)),
      ...sentinels.map(value => value.slice(-8)),
    ]),
  ];
  for (const [index, fragment] of fragments.entries()) {
    assert.equal(text.includes(fragment), false, `redaction leaked sentinel fragment ${index}`);
  }
}

test("issue #62 redaction consumes complete secret values", () => {
  const sentinels = [
    "q7M4vN9xC2pL8rK",
    "h3W8sD1kF6yT0mQ",
    "z5R2cV9nJ4bX7pH",
    "n8G1uK6eP3aS0wY",
    "f4Q9mL2xZ7dC5rV",
    "b6H0tN3jA8kE1sU",
    "p2Y7gR4wM9cD6vX",
    "x9C5nB1qT8hV3kL",
    "d8K2sF7wL4nP0yR",
    "m5V1cX8qH3tB6zJ",
    "r4J8aD2sW6fQ0cM",
    "v6N1pH9yC3kR7bT",
    "u2L7eX4mS9qV5dF",
    "w8C3gT6nK1zP4hY",
    "e5P0bV7jL2xS9qN",
  ];
  const input = [
    `API_KEY = ${sentinels[0]}`,
    `API key = ${sentinels[1]}`,
    `API key: Bearer ${sentinels[2]}`,
    `Api_Key = "${sentinels[3]} quoted"`,
    `API-KEY: '${sentinels[4]} quoted'`,
    `APIKEY ${sentinels[5]}`,
    `client_secret=${sentinels[6]}`,
    `Authorization: Bearer ${sentinels[7]}`,
    `token = "${sentinels[8]} quoted"`,
    `generic token: ${sentinels[9]}`,
    `credential=${sentinels[10]}`,
    `url=https://issue62.example/${sentinels[11]}`,
    `windows=C:\\Users\\issue62\\${sentinels[12]}`,
    `unc=\\\\issue62-server\\share\\${sentinels[13]}`,
    `posix=/tmp/issue62/${sentinels[14]}`,
  ].join("\n");
  const sanitized = sanitize(input);
  assertNoDistinctiveSentinels(sanitized, sentinels);
  assertNoRawPaths(sanitized);
  assert.match(sanitized, /<secret-redacted>/);
  assert.match(sanitized, /<url-redacted>/);
});

test("issue #62 Bun redaction probe consumes opaque values and fragments", async () => {
  assert.ok(existsSync(fixture), `missing Bun fixture ${fixture}`);
  const result = await spawnRedactionProbe();
  assert.equal(result.code, 0, `Bun redaction probe failed (${result.signal})`);
  const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean);
  assert.equal(lines.length, 1, "Bun redaction probe emitted unexpected output");
  let receipt;
  try {
    receipt = JSON.parse(lines[0]);
  } catch {
    assert.fail("Bun redaction probe emitted invalid JSON");
  }
  assert.deepEqual(receipt, {
    schema: "issue62-sdk-isolation-redaction-probe-v1",
    sentinelCount: 10,
    fragmentCount: 30,
    secretMarker: true,
  });
});
for (const phase of ["sdk-import", "sdk-teardown"]) {
  for (const kind of ["fetch", "preconnect"]) {
    for (const swallowed of [false, true]) {
      test(`issue #62 guard rejects ${swallowed ? "swallowed" : "propagated"} ${kind} during ${phase}`, async () => {
        const result = await runGuardLifecycleProbe({ phase, kind, swallowed });
        assert.equal(result.failure.code, "ENVIRONMENT_BLOCKED");
        assert.equal(result.receipt, undefined, "attempt cannot produce a successful receipt");
        const guard = result.failure.details.preconnectGuard;
        assert.equal(guard.attempts, 1);
        assert.deepEqual(guard.events.map(event => ({ kind: event.kind, stage: event.stage })), [{ kind, stage: phase }]);
        assert.equal(guard.observed, true);
        assert.equal(guard.restored, true);
        assert.equal(result.runStarted, phase === "sdk-teardown" || swallowed);
        assert.equal(result.disposals, result.runStarted ? 1 : 0);
      });
    }
  }
}

for (const failure of ["import", "setup", "session"]) {
  test(`issue #62 guard restores fetch after ${failure} failure without masking primary error`, async () => {
    const result = await runGuardLifecycleProbe({ failure });
    assert.equal(result.failure.code, `MOCK_${failure.toUpperCase()}_FAILED`);
    assert.equal(result.receipt, undefined);
    assert.equal(result.failure.details.preconnectGuard.attempts, 0);
    assert.equal(result.failure.details.preconnectGuard.restored, true);
    assert.equal(result.runStarted, failure === "session");
    assert.equal(result.disposals, failure === "session" ? 1 : 0);
  });
}

test("issue #62 guard retains primary and cleanup errors plus swallowed background events", async () => {
  for (const swallowed of [false, true]) {
    const result = await runGuardLifecycleProbe({ failure: "session", phase: "sdk-teardown", kind: "fetch", swallowed });
    assert.equal(result.failure.code, "MOCK_SESSION_FAILED");
    assert.equal(result.failure.details.preconnectGuard.attempts, 1);
    assert.ok(result.failure.details.cleanupErrors.some(error => error.operation === "network-guard-verification"));
    assert.equal(result.failure.details.cleanupErrors.some(error => error.operation === "mock-dispose"), !swallowed);
    assert.equal(result.disposals, 1);
  }
});

test("issue #62 guard restores fetch after successful tracked teardown", async () => {
  const result = await runGuardLifecycleProbe({});
  assert.equal(result.failure, undefined);
  assert.equal(result.receipt.cleanup.mockDisposed, true);
  assert.equal(result.receipt.preconnectGuard.attempts, 0);
  assert.equal(result.receipt.preconnectGuard.checkedAfterTrackedTeardown, true);
  assert.equal(result.runStarted, true);
  assert.equal(result.disposals, 1);
});

test("issue #62 real SDK divergent-session probe", async () => {
  assert.ok(existsSync(fixture), `missing Bun fixture ${fixture}`);
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  assert.ok(Number.isInteger(nodeMajor) && nodeMajor >= 26, `Node >=26 required, observed ${process.version}`);
  await runOrder("A,B");
  await runOrder("B,A");
});
