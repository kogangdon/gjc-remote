#!/usr/bin/env bun
/* Issue #62: real SDK/session-pool isolation probe. Bun-only; stdout is not an artifact. */
import { readFile, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { closeModelCache } from "@gajae-code/ai/core";

import { Settings } from "@gajae-code/coding-agent/sdk";
import { SessionManager } from "@gajae-code/coding-agent/session/session-manager";
import { AuthStorage, SqliteAuthCredentialStore } from "@gajae-code/coding-agent/session/auth-storage";
import { ModelRegistry } from "@gajae-code/coding-agent/config/model-registry";
import { resolveAllowedModels } from "@gajae-code/coding-agent/config/model-resolver";
import {
  defineCapability,
  getAllProvidersInfo,
  getCapabilityInfo,
  initializeWithSettings,
  loadCapability,
  registerProvider,
} from "@gajae-code/coding-agent/capability";
import { createAgentSession } from "@gajae-code/coding-agent/sdk";
import "@gajae-code/coding-agent/discovery";
import { SessionPool } from "../src/session-pool.js";
import { SdkSession } from "../src/sdk-session.js";

const ISSUE = 62;
const BASE_COMMIT = "a5bb530bd5a063b6571a7ba963e938bb6f97616f";
const EXPECTED_SDK = "0.12.21";
const MIN_BUN = [1, 3, 14];
const PROVIDER_A = "issue62-provider-a";
const PROVIDER_B = "issue62-provider-b";
const MODEL_A = `${PROVIDER_A}/issue62-model-a`;
const MODEL_B = `${PROVIDER_B}/issue62-model-b`;
const CANONICAL = "issue62-canonical-model";
const ALLOW_LIST = [MODEL_A, MODEL_B];
const CAPABILITY_ID = "issue62-capability";
const CAP_A = "issue62-capability-a";
const CAP_B = "issue62-capability-b";
const CAP_THROW = "issue62-capability-throwing";
const LOCAL_PROVIDERS = ["ollama", "llama.cpp", "lm-studio"];
const fixtureFile = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(fixtureFile), "../..");
const CHANGE_FILES = [
  "daemon/test-fixtures/sdk-isolation-probe.mjs",
  "daemon/test/sdk-isolation-probe.test.js",
  "docs/verification/issue62-evidence.md",
  "CONTEXT.md",
];
const UNKNOWN_CAPABILITY_ID = "issue62-unknown-capability";
const UNKNOWN_CAPABILITY_MESSAGE = `Unknown capability: "${UNKNOWN_CAPABILITY_ID}"`;
const RAW_SESSION_DISPOSE_TIMEOUT_MS = 5_000;
const WORK_DIR_REALPATH_TIMEOUT_MS = 5_000;
const AUTH_STORE_DIAGNOSTIC_MAX_METHODS = 32;
const AUTH_STORE_DIAGNOSTIC_MAX_TEXT = 128;

class ProbeFailure extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = "ProbeFailure";
    this.code = code;
    this.details = details;
  }
}

function fail(code, message, details) {
  throw new ProbeFailure(code, message, details);
}

function requireCondition(value, code, message, details) {
  if (!value) fail(code, message, details);
}
async function canonicalWorkDir(value) {
  if (typeof value !== "string") return undefined;
  let timer;
  const result = await Promise.race([
    realpath(value).then(
      canonical => ({ status: "fulfilled", canonical }),
      error => ({ status: "rejected", error }),
    ),
    new Promise(resolve => {
      timer = setTimeout(() => resolve({ status: "timed_out" }), WORK_DIR_REALPATH_TIMEOUT_MS);
    }),
  ]);
  clearTimeout(timer);
  return result.status === "fulfilled" ? result.canonical : undefined;
}

function comparableWorkDir(value) {
  if (typeof value !== "string") return undefined;
  const normalized = resolve(value).replaceAll("\\", "/");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function sortedStrings(value) {
  return [...new Set((Array.isArray(value) ? value : []).filter(item => typeof item === "string"))].sort();
}

function modelSelector(model) {
  return model && typeof model.provider === "string" && typeof model.id === "string"
    ? `${model.provider}/${model.id}`
    : undefined;
}

function policySnapshot(settings) {
  return {
    cwd: settings.getCwd(),
    disabledProviders: sortedStrings(settings.get("disabledProviders")),
    enabledModels: [...settings.get("enabledModels")],
    modelRolesDefault: settings.getModelRole("default"),
    planner: settings.get("task.agentModelOverrides")?.planner,
    modelProviderOrder: [...settings.get("modelProviderOrder")],
    networkPrewarm: settings.get("startup.networkPrewarm"),
  };
}

function policyFingerprint(policy) {
  return JSON.stringify({
    disabledProviders: policy.disabledProviders,
    enabledModels: policy.enabledModels,
    modelRolesDefault: policy.modelRolesDefault,
    planner: policy.planner,
    modelProviderOrder: policy.modelProviderOrder,
  });
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
const SECRET_KEY_PATTERN = String.raw`[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|OAUTH|PASSWORD|AUTHORIZATION|COOKIE|BROKER|CREDENTIAL|SECRET|TOKEN)`;
const SECRET_KEY_VALUE_PATTERN = new RegExp(
  String.raw`\b${SECRET_KEY_PATTERN}\b\s*(?:[:=]\s*|\s+)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:Bearer\s+)?[^\s"',;}]+)`,
  "gi",
);
const SECRET_KEY_ONLY_PATTERN = new RegExp(String.raw`\b${SECRET_KEY_PATTERN}\b`, "gi");

function redactedText(value, root, fixture) {
  let text = String(value ?? "");
  for (const [path, token] of [
    [root.root, "<fixture-root>"],
    [root.home, "<fixture-home>"],
    [root.agentDir, "<agent-dir>"],
    [root.workDirs?.A, "<workdir-A>"],
    [root.workDirs?.B, "<workdir-B>"],
    [root.workDirs?.C, "<workdir-C>"],
    [root.markerA, "<marker-A>"],
    [root.markerB, "<marker-B>"],
    [root.markerC, "<marker-C>"],
    [repoRoot, "<repo-root>"],
    [process.cwd(), "<cwd>"],
  ]) {
    if (path) text = text.split(path).join(token);
  }
  text = text.replace(/(?:https?|wss?):\/\/[^\s"']+/gi, "<url-redacted>");
  text = redactPathLikeText(text);
  text = text.replace(SECRET_KEY_VALUE_PATTERN, "<secret-redacted>");
  text = text.replace(SECRET_KEY_ONLY_PATTERN, "<secret-redacted>");
  text = text.replace(/<+secret-redacted>(?:-redacted>)*/g, "<secret-redacted>");
  if (fixture) text = text.replace(fixture, "<fixture-root>");
  return text.length > 512 ? `${text.slice(0, 509)}...` : text;
}

function redactValue(value, root) {
  if (typeof value === "string") return redactedText(value, root, root.root);
  if (Array.isArray(value)) return value.slice(0, 32).map(item => redactValue(item, root));
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      if (/(?:api.?key|access.?token|refresh.?token|password|authorization|cookie|credential|broker|secret|oauth|token)/i.test(key)) continue;
      output[key] = redactValue(item, root);
    }
    return output;
  }
  return value;
}

function boundedDiagnosticText(value, root) {
  const text = redactedText(value, root, root.root);
  return text.length > AUTH_STORE_DIAGNOSTIC_MAX_TEXT
    ? `${text.slice(0, AUTH_STORE_DIAGNOSTIC_MAX_TEXT - 3)}...`
    : text;
}

function nonOwnedAuthStoreDiagnostic(store, root) {
  const runtimeType = typeof store;
  let prototype = null;
  if (store !== null && store !== undefined) {
    try {
      prototype = Object.getPrototypeOf(store);
    } catch {
      // A diagnostic must not change fail-closed cleanup behavior.
    }
  }

  let constructorName = null;
  const prototypeMethods = [];
  if (prototype !== null) {
    try {
      const constructorDescriptor = Object.getOwnPropertyDescriptor(prototype, "constructor");
      if (typeof constructorDescriptor?.value?.name === "string") {
        constructorName = constructorDescriptor.value.name;
      }
    } catch {
      // A diagnostic must not change fail-closed cleanup behavior.
    }
    try {
      for (const name of Object.getOwnPropertyNames(prototype)) {
        if (name === "constructor" || prototypeMethods.length >= AUTH_STORE_DIAGNOSTIC_MAX_METHODS) continue;
        let descriptor;
        try {
          descriptor = Object.getOwnPropertyDescriptor(prototype, name);
        } catch {
          continue;
        }
        if (typeof descriptor?.value === "function") {
          prototypeMethods.push(boundedDiagnosticText(name, root));
        }
      }
    } catch {
      // A diagnostic must not change fail-closed cleanup behavior.
    }
  }

  return {
    runtimeType: boundedDiagnosticText(runtimeType, root),
    constructorName: constructorName === null ? null : boundedDiagnosticText(constructorName, root),
    prototypeMethods,
  };
}

function parseOrder() {
  const equalsArg = process.argv.find(item => item.startsWith("--order="));
  const separateIndex = process.argv.indexOf("--order");
  const valueArg = equalsArg?.slice("--order=".length) ?? (separateIndex >= 0 ? process.argv[separateIndex + 1] : "A,B");
  const value = valueArg.split(",").map(item => item.trim().toUpperCase());
  requireCondition(value.length === 2 && value.every(item => item === "A" || item === "B") && value[0] !== value[1], "API_CONTRACT_MISMATCH", "order must be A,B or B,A");
  return value;
}

function parseVersion(value) {
  const match = String(value).match(/(\d+)\.(\d+)\.(\d+)/);
  return match ? match.slice(1).map(Number) : null;
}

function versionAtLeast(value, minimum) {
  const parsed = parseVersion(value);
  return parsed !== null && parsed[0] > minimum[0] || parsed !== null && parsed[0] === minimum[0] && (parsed[1] > minimum[1] || parsed[1] === minimum[1] && parsed[2] >= minimum[2]);
}

async function gitHead() {
  const child = Bun.spawn(["git", "rev-parse", "HEAD"], { cwd: repoRoot, stdout: "pipe", stderr: "pipe" });
  const stdout = await new Response(child.stdout).text();
  const status = await child.exited;
  requireCondition(status === 0, "PROVENANCE_UNAVAILABLE", "git base commit could not be read");
  return stdout.trim();
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

async function assertSdkProvenance() {
  const daemonPackage = JSON.parse(await readFile(join(repoRoot, "daemon", "package.json"), "utf8"));
  const installedPackage = JSON.parse(await readFile(join(repoRoot, "node_modules", "@gajae-code", "coding-agent", "package.json"), "utf8"));
  const lock = await readFile(join(repoRoot, "bun.lock"), "utf8");
  const lockEvidence = lock.match(/"@gajae-code\/coding-agent": \["@gajae-code\/coding-agent@([^"]+)"/)?.[1];
  const bunVersion = Bun.version;
  const sourceCommit = await gitHead();
  requireCondition(daemonPackage.dependencies?.["@gajae-code/coding-agent"] === EXPECTED_SDK, "SDK_VERSION_MISMATCH", "daemon dependency is not pinned to 0.12.21", { daemon: daemonPackage.dependencies?.["@gajae-code/coding-agent"] });
  requireCondition(installedPackage.version === EXPECTED_SDK && lockEvidence === EXPECTED_SDK, "SDK_VERSION_MISMATCH", "installed package or lockfile is not 0.12.21", { installed: installedPackage.version, lock: lockEvidence });
  requireCondition(versionAtLeast(bunVersion, MIN_BUN), "SDK_VERSION_MISMATCH", "Bun is older than 1.3.14", { bunVersion });
  return {
    sdkPackage: "@gajae-code/coding-agent",
    sdkVersionExpected: EXPECTED_SDK,
    sdkVersionObserved: installedPackage.version,
    daemonDependencyVersion: daemonPackage.dependencies["@gajae-code/coding-agent"],
    lockfileVersionEvidence: lockEvidence,
    bunVersion,
    nodeVersion: process.version,
    platform: { platform: process.platform, arch: process.arch },
    approvedBaseCommit: BASE_COMMIT,
    sourceCommit,
    changeSet: {
      algorithm: "sha256",
      files: [...CHANGE_FILES],
      digest: await orderedChangeDigest(),
    },
  };
}

function rejectHostEnvironment() {
  const blocked = Object.entries(process.env)
    .filter(([name, value]) => value && /(?:API[_-]?KEY|OAUTH|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|PASSWORD|SECRET|AUTHORIZATION|BROKER|PROXY|GJC_MODEL|GJC_PROFILE|GJC_AUTH|GJC_CREDENTIAL|GITHUB_TOKEN|HF_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|VAULT_TOKEN|CI_JOB_TOKEN|(?:^|_)(?:PAT|TOKEN)$|OPENAI_|OPENROUTER_|ANTHROPIC_|GOOGLE_|AWS_)/i.test(name))
    .map(([name]) => name)
    .sort();
  requireCondition(blocked.length === 0, "ENVIRONMENT_BLOCKED", "credential/proxy/host override variables are present", { variables: blocked });
}

async function createHermeticFixture() {
  const root = await mkdtemp(join(tmpdir(), "gjc-issue62-sdk-"));
  setupRoot = root;
  const home = join(root, "home");
  const agentDir = join(home, ".gjc", "agent");
  const workDirs = { A: join(root, "work-A"), B: join(root, "work-B"), C: join(root, "work-C") };
  const markerA = join(root, "marker-A.txt");
  const markerB = join(root, "marker-B.txt");
  const markerC = join(root, "marker-C.txt");
  await mkdir(agentDir, { recursive: true });
  await mkdir(join(root, "tmp"), { recursive: true });
  await Promise.all(Object.values(workDirs).map(dir => mkdir(join(dir, ".gjc"), { recursive: true })));
  await writeFile(markerA, "issue62 capability marker A\n");
  await writeFile(markerB, "issue62 capability marker B\n");
  await writeFile(markerC, "issue62 capability marker C\n");
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.env.TEMP = join(root, "tmp");
  process.env.TMP = join(root, "tmp");
  const globalConfig = `configSchemaVersion: 1\nstartup:\n  networkPrewarm: false\ndisabledProviders:\n  - ollama\n  - llama.cpp\n  - lm-studio\nenabledModels:\n  - ${MODEL_A}\n  - ${MODEL_B}\nmodelRoles:\n  default: ${MODEL_A}\ntask:\n  agentModelOverrides:\n    planner: ${MODEL_A}\nmodelProviderOrder:\n  - ${PROVIDER_A}\n  - ${PROVIDER_B}\n`;
  await writeFile(join(agentDir, "config.yml"), globalConfig);
  const policies = {
    A: {
      disabledProviders: [PROVIDER_B, CAP_B, ...LOCAL_PROVIDERS],
      default: MODEL_A,
      planner: MODEL_A,
      modelProviderOrder: [PROVIDER_A, PROVIDER_B],
    },
    B: {
      disabledProviders: [PROVIDER_A, CAP_A, ...LOCAL_PROVIDERS],
      default: MODEL_B,
      planner: MODEL_B,
      modelProviderOrder: [PROVIDER_B, PROVIDER_A],
    },
    C: {
      disabledProviders: [...LOCAL_PROVIDERS],
      default: "issue62-no-such-provider/issue62-no-such-model",
      planner: "issue62-no-such-provider/issue62-no-such-model",
      modelProviderOrder: [PROVIDER_A, PROVIDER_B],
    },
  };
  for (const label of ["A", "B", "C"]) {
    const policy = policies[label];
    const config = `configSchemaVersion: 1\nstartup:\n  networkPrewarm: false\ndisabledProviders:\n${policy.disabledProviders.map(item => `  - ${item}`).join("\n")}\nenabledModels:\n  - ${label === "C" ? "issue62-no-such-provider/issue62-no-such-model" : MODEL_A}\n  - ${label === "C" ? "issue62-no-such-provider/issue62-no-such-model-2" : MODEL_B}\nmodelRoles:\n  default: ${policy.default}\ntask:\n  agentModelOverrides:\n    planner: ${policy.planner}\nmodelProviderOrder:\n${policy.modelProviderOrder.map(item => `  - ${item}`).join("\n")}\n`;
    await writeFile(join(workDirs[label], ".gjc", "config.yml"), config);
  }
  const modelsPath = join(agentDir, "models.yml");
  const modelsConfig = `providers:\n  ${PROVIDER_A}:\n    baseUrl: http://127.0.0.1:1/issue62-a\n    api: openai-completions\n    auth: none\n    models:\n      - id: issue62-model-a\n        name: Issue62 fixture model A\n        contextWindow: 4096\n        maxTokens: 512\n        input: [text]\n        output: [text]\n        cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0}\n  ${PROVIDER_B}:\n    baseUrl: http://127.0.0.1:1/issue62-b\n    api: openai-completions\n    auth: none\n    models:\n      - id: issue62-model-b\n        name: Issue62 fixture model B\n        contextWindow: 4096\n        maxTokens: 512\n        input: [text]\n        output: [text]\n        cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0}\nequivalence:\n  overrides:\n    ${MODEL_A}: ${CANONICAL}\n    ${MODEL_B}: ${CANONICAL}\n`;
  await writeFile(modelsPath, modelsConfig);
  setupRoot = undefined;
  return { root, home, agentDir, workDirs, markerA, markerB, markerC, modelsPath, policies, authDir: join(root, "auth") };
}
async function removeFixtureRoot(root) {
  let lastError;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      await rm(root, { recursive: true, force: true });
      return;
    } catch (error) {
      lastError = error;
      if (error?.code !== "EBUSY" && error?.code !== "EPERM") throw error;
      await Bun.sleep(100);
    }
  }
  throw lastError;
}

const capability = defineCapability({
  id: CAPABILITY_ID,
  displayName: "Issue 62 capability probe",
  description: "Fixture-only capability isolation probe",
  key: item => item?.name,
  validate: item => (item?._source ? undefined : "missing source metadata"),
});
const counters = { [CAP_A]: 0, [CAP_B]: 0, [CAP_THROW]: 0 };
const capabilityInvocations = [];
let capabilityFixture;
let setupRoot;
registerProvider(CAPABILITY_ID, {
  id: CAP_A,
  displayName: "Issue 62 provider A",
  description: "fixture A",
  priority: 20,
  async load(ctx) {
    counters[CAP_A] += 1;
    capabilityInvocations.push({ provider: CAP_A, cwd: ctx.cwd });
    return { items: [{ name: "issue62-item-A", value: "A", _source: { provider: CAP_A, providerName: "Issue 62 provider A", path: capabilityFixture?.markerA ?? "", level: "project" } }] };
  },
});
registerProvider(CAPABILITY_ID, {
  id: CAP_B,
  displayName: "Issue 62 provider B",
  description: "fixture B",
  priority: 10,
  async load(ctx) {
    counters[CAP_B] += 1;
    capabilityInvocations.push({ provider: CAP_B, cwd: ctx.cwd });
    return { items: [{ name: "issue62-item-B", value: "B", _source: { provider: CAP_B, providerName: "Issue 62 provider B", path: capabilityFixture?.markerB ?? "", level: "project" } }] };
  },
});
registerProvider(CAPABILITY_ID, {
  id: CAP_THROW,
  displayName: "Issue 62 throwing provider",
  description: "fixture warning path",
  priority: 1,
  async load() {
    counters[CAP_THROW] += 1;
    throw new Error("issue62 controlled provider warning");
  },
});

function armNetworkGuard() {
  const originalFetch = globalThis.fetch;
  const originalPreconnect = originalFetch?.preconnect;
  requireCondition(typeof originalFetch === "function" && typeof originalPreconnect === "function", "PRECONNECT_GUARD_UNAVAILABLE", "Bun fetch.preconnect is unavailable");
  const events = [];
  const guardedFetch = (...args) => {
    events.push({ kind: "fetch", stage: currentStage, target: typeof args[0] === "string" ? args[0] : "request" });
    throw new ProbeFailure("ENVIRONMENT_BLOCKED", "unexpected network fetch");
  };
  guardedFetch.preconnect = (...args) => {
    events.push({ kind: "preconnect", stage: currentStage, target: typeof args[0] === "string" ? args[0] : "request" });
    throw new ProbeFailure("ENVIRONMENT_BLOCKED", "unexpected fetch.preconnect");
  };
  globalThis.fetch = guardedFetch;
  return { originalFetch, originalPreconnect, events, restore: () => { globalThis.fetch = originalFetch; } };
}

let currentStage = "preflight";

function registrySnapshot(registry, phase) {
  const all = registry.getAll().filter(model => model.provider === PROVIDER_A || model.provider === PROVIDER_B);
  const available = registry.getAvailable().filter(model => model.provider === PROVIDER_A || model.provider === PROVIDER_B);
  const ids = all.map(model => modelSelector(model));
  const canonicalIds = [...new Set(all.map(model => registry.getCanonicalId(model)).filter(Boolean))];
  const variants = registry.getCanonicalVariants(CANONICAL, { availableOnly: false }).map(item => modelSelector(item.model));
  const availableVariants = registry.getCanonicalVariants(CANONICAL, { availableOnly: true }).map(item => modelSelector(item.model));
  const canonicalModels = registry.getCanonicalModels({ availableOnly: true }).filter(item => item.id === CANONICAL).map(item => ({ id: item.id, variants: item.variants.map(variant => modelSelector(variant.model)) }));
  const resolved = registry.resolveCanonicalModel(CANONICAL, { availableOnly: false, candidates: registry.getAll() });
  requireCondition(
    resolved && [PROVIDER_A, PROVIDER_B].includes(resolved.provider) &&
      [MODEL_A, MODEL_B].includes(modelSelector(resolved)),
    "CANONICAL_ORACLE_FAILURE",
    "canonical resolver did not return a concrete fixture provider/model",
    { phase, resolvedProvider: resolved?.provider, resolvedSelector: modelSelector(resolved) },
  );
  return {
    phase,
    all: ids,
    available: available.map(modelSelector),
    canonicalIds,
    variants,
    availableVariants,
    canonicalModels,
    resolvedProvider: resolved?.provider,
    resolvedSelector: modelSelector(resolved),
    providerOrder: [...globalSettingsForRegistry.get("modelProviderOrder")],
  };
}

let globalSettingsForRegistry;

function assertCapabilityItems(result, expectedProvider, expectedMarker, expectedName) {
  requireCondition(result.items.length === 1, "CAPABILITY_FIXTURE_CONTRACT", "capability returned an unexpected item count", { expectedName, items: result.items });
  const item = result.items[0];
  requireCondition(item.name === expectedName && item._source?.provider === expectedProvider, "CAPABILITY_FIXTURE_CONTRACT", "capability contribution was not session-local", { expectedName, observed: item });
  requireCondition(item._source.providerName && item._source.path === expectedMarker && item._source.level === "project", "CAPABILITY_FIXTURE_CONTRACT", "capability item has invalid _source metadata", { source: item._source });
}

async function capabilityRead(settings, cwd, label, marker) {
  const expectedProvider = label === "A" ? CAP_A : CAP_B;
  const expectedName = label === "A" ? "issue62-item-A" : "issue62-item-B";
  const explicit = await loadCapability(CAPABILITY_ID, { settings, cwd });
  const fallback = await loadCapability(CAPABILITY_ID, { cwd });
  assertCapabilityItems(explicit, expectedProvider, marker, expectedName);
  assertCapabilityItems(fallback, expectedProvider, marker, expectedName);
  const opposite = label === "A" ? CAP_B : CAP_A;
  const oppositeInvocations = capabilityInvocations.filter(item => item.provider === opposite && item.cwd === cwd);
  const expectedInvocations = capabilityInvocations.filter(item => item.provider === expectedProvider && item.cwd === cwd);
  requireCondition(oppositeInvocations.length === 0, "CAPABILITY_POLICY_BLEED", "disabled capability provider was invoked", { label, invocations: capabilityInvocations });
  requireCondition(expectedInvocations.length >= 2, "CAPABILITY_FIXTURE_CONTRACT", "enabled capability provider did not contribute twice", { label, invocations: capabilityInvocations });
  requireCondition(explicit.warnings.some(item => item.includes("throwing provider")), "CAPABILITY_FIXTURE_CONTRACT", "controlled throwing provider warning was not observed", { warnings: explicit.warnings });
  return {
    explicit: { providers: explicit.providers, items: explicit.items.map(item => ({ name: item.name, source: item._source })), warnings: explicit.warnings.slice(0, 4) },
    cwdFallback: { providers: fallback.providers, items: fallback.items.map(item => ({ name: item.name, source: item._source })), warnings: fallback.warnings.slice(0, 4) },
  };
}

function classifyDirection(seed, afterFirst, afterSecond, final, firstLabel, secondLabel) {
  const values = [seed, afterFirst, afterSecond, final];
  requireCondition(
    values.length === 4 && values.every(value => value === PROVIDER_A || value === PROVIDER_B),
    "CANONICAL_ORACLE_FAILURE",
    "canonical direction oracle observed an unknown provider value",
    { seed, afterFirst, afterSecond, final, firstLabel, secondLabel },
  );
  if (values.every(value => value === seed)) return "GLOBAL_SEED";
  const firstValue = firstLabel === "A" ? PROVIDER_A : PROVIDER_B;
  const secondValue = secondLabel === "A" ? PROVIDER_A : PROVIDER_B;
  if (afterFirst === firstValue && afterSecond === secondValue && final === secondValue) return "LAST_CREATED";
  if (afterFirst === firstValue && afterSecond === firstValue && final === firstValue) return "FIRST_CREATED";
  if (values.every(value => value === PROVIDER_A)) return "A";
  if (values.every(value => value === PROVIDER_B)) return "B";
  if (values.every(value => value === seed)) return "NEUTRAL";
  const set = new Set(values);
  return set.size === 1 ? "NEUTRAL" : "MIXED";
}
async function disposeRawSessionBounded(rawSession, label) {
  if (!rawSession || typeof rawSession.dispose !== "function") return;
  let timer;
  const timeout = new Promise(resolve => {
    timer = setTimeout(() => resolve({ status: "timed_out" }), RAW_SESSION_DISPOSE_TIMEOUT_MS);
  });
  const settled = Promise.resolve()
    .then(() => rawSession.dispose())
    .then(value => ({ status: "fulfilled", value }), reason => ({ status: "rejected", reason }));
  const result = await Promise.race([settled, timeout]);
  clearTimeout(timer);
  if (result.status === "timed_out") {
    throw new ProbeFailure("SESSION_LIFECYCLE_FAILURE", `${label} raw session disposal timed out`, { timeoutMs: RAW_SESSION_DISPOSE_TIMEOUT_MS });
  }
  if (result.status === "rejected") {
    throw new ProbeFailure("SESSION_LIFECYCLE_FAILURE", `${label} raw session disposal rejected`, { error: result.reason?.message ?? String(result.reason) });
  }
}

function observeCSessionPrompt(session, label, cAttempts) {
  if (label !== "C") return session;
  return new Proxy(session, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (property !== "prompt" || typeof value !== "function") return value;
      return (...args) => {
        cAttempts.promptAttempts += 1;
        return Reflect.apply(value, target, args);
      };
    },
  });
}

async function createPooledSession(fixture, globalSettings, workDir, label, guard, registries, settingsByLabel, ownedAuthResources, cAttempts) {
  const settings = await globalSettings.cloneForCwd(workDir);
  settings.override("modelProviderOrder", label === "A" ? [PROVIDER_A, PROVIDER_B] : [PROVIDER_B, PROVIDER_A]);
  settings.override("startup.networkPrewarm", false);
  const policy = policySnapshot(settings);
  requireCondition(JSON.stringify(policy.modelProviderOrder) === JSON.stringify(label === "A" ? [PROVIDER_A, PROVIDER_B] : [PROVIDER_B, PROVIDER_A]), "API_CONTRACT_MISMATCH", "A/B provider orders did not remain divergent", { label, policy });
  const expectedModel = label === "A" ? MODEL_A : MODEL_B;
  requireCondition(policy.modelRolesDefault === expectedModel && policy.planner === expectedModel, "API_CONTRACT_MISMATCH", "A/B role policy did not remain session-local", { label, policy });
  requireCondition(policy.networkPrewarm === false, "API_CONTRACT_MISMATCH", "clone startup.networkPrewarm is not false", { label, policy });
  requireCondition(JSON.stringify(policy.enabledModels) === JSON.stringify(ALLOW_LIST), "API_CONTRACT_MISMATCH", "A/B enabled-model allow-list diverged unexpectedly", { label, policy });
  const record = {
    label,
    workDir,
    settings,
    authStore: null,
    authStoreClose: null,
    authStorage: null,
    modelRegistry: null,
    rawSession: null,
    sdkSession: null,
    policy,
    active: null,
    beforeSiblingRegistry: null,
  };
  registries[label] = record;
  try {
    if (label === "C") {
      cAttempts.sessionConstructionAttempts += 1;
      fail("MODEL_FALLBACK", "C session construction was attempted");
    }
    const rawStore = await SqliteAuthCredentialStore.open(join(fixture.authDir, `auth-${label}.db`));
    ownedAuthResources.push({ name: `auth-${label}`, close: () => rawStore.close(), diagnosticStore: rawStore });
    record.authStoreClose = () => rawStore.close();
    record.authStore = rawStore;
    record.authStorage = new AuthStorage(rawStore);
    await record.authStorage.reload();
    record.modelRegistry = new ModelRegistry(record.authStorage, fixture.modelsPath);
    requireCondition(record.modelRegistry.getCanonicalVariants(CANONICAL, { availableOnly: false }).length === 2, "API_CONTRACT_MISMATCH", "canonical equivalence did not produce two variants");
    for (const selector of [MODEL_A, MODEL_B]) {
      const model = record.modelRegistry.getAll().find(item => modelSelector(item) === selector);
      requireCondition(model && record.modelRegistry.getCanonicalId(model) === CANONICAL, "API_CONTRACT_MISMATCH", "canonical model mapping is missing", { selector });
    }
    globalSettingsForRegistry = globalSettings;
    if (!registries.seed) registries.seed = registrySnapshot(record.modelRegistry, "global-seed");
    globalSettings.override("modelProviderOrder", policy.modelProviderOrder);
    initializeWithSettings(settings);
    settingsByLabel[label] = settings;
    currentStage = `create-${label}`;
    const manager = SessionManager.create(workDir, join(workDir, ".gjc-remote-session"));
    const created = await createAgentSession({
      cwd: workDir,
      sessionManager: manager,
      settings,
      authStorage: record.authStorage,
      modelRegistry: record.modelRegistry,
      enableLsp: false,
      disableExtensionDiscovery: true,
      skills: [],
      rules: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      hasUI: false,
    });
    record.rawSession = observeCSessionPrompt(created.session, label, cAttempts);
    record.sdkSession = new SdkSession(record.rawSession);
    const active = record.rawSession.model;
    requireCondition(active && ALLOW_LIST.includes(modelSelector(active)), "MODEL_FALLBACK", "session selected no fixture model", { label, active: modelSelector(active) });
    requireCondition(!policy.disabledProviders.includes(active.provider), "MODEL_FALLBACK", "session selected a disabled provider", { label, active: modelSelector(active), disabledProviders: policy.disabledProviders });
    requireCondition(active.provider === (label === "A" ? PROVIDER_A : PROVIDER_B), "MODEL_FALLBACK", "session selected the sibling fixture model", { label, active: modelSelector(active) });
    record.active = modelSelector(active);
    record.beforeSiblingRegistry = registrySnapshot(record.modelRegistry, `after-${label}`);
    return record.sdkSession;
  } catch (error) {
    if (record.rawSession) await disposeRawSessionBounded(record.rawSession, `create-${label}`);
    throw error;
  }
}

async function readSession(record, fixture) {
  currentStage = `read-${record.label}`;
  const marker = record.label === "A" ? fixture.markerA : fixture.markerB;
  const capabilityResult = await capabilityRead(record.settings, record.workDir, record.label, marker);
  const active = record.rawSession.model;
  const settingsAfterSibling = policySnapshot(record.settings);
  requireCondition(policyFingerprint(settingsAfterSibling) === policyFingerprint(record.policy), "SESSION_POLICY_BLEED", "session settings changed after sibling creation", { label: record.label, before: record.policy, after: settingsAfterSibling });
  const registry = registrySnapshot(record.modelRegistry, `final-${record.label}`);
  return {
    label: record.label,
    cwd: record.settings.getCwd(),
    settings: settingsAfterSibling,
    activeModel: modelSelector(active),
    activeProvider: active?.provider,
    capability: capabilityResult,
    registry,
  };
}

async function runOrder(order, fixture, provenance) {
  const guard = armNetworkGuard();
  const cAttempts = { sessionConstructionAttempts: 0, promptAttempts: 0 };
  const registries = {};
  const settingsByLabel = {};
  const ownedAuthResources = [];
  const canonicalFixtureWorkDirs = {
    A: await canonicalWorkDir(fixture.workDirs.A),
    B: await canonicalWorkDir(fixture.workDirs.B),
    C: await canonicalWorkDir(fixture.workDirs.C),
  };
  const pool = new SessionPool({
    sessionFactory: async workDir => {
      const canonicalIncomingPath = await canonicalWorkDir(workDir);
      const comparable = comparableWorkDir(canonicalIncomingPath);
      const canonicalAPath = canonicalFixtureWorkDirs.A;
      const canonicalBPath = canonicalFixtureWorkDirs.B;
      const canonicalCPath = canonicalFixtureWorkDirs.C;
      const normalizedAPath = comparableWorkDir(canonicalAPath);
      const normalizedBPath = comparableWorkDir(canonicalBPath);
      const normalizedCPath = comparableWorkDir(canonicalCPath);
      const label = comparable === normalizedAPath
        ? "A"
        : comparable === normalizedBPath
          ? "B"
          : undefined;
      if (comparable === normalizedCPath) {
        cAttempts.sessionConstructionAttempts += 1;
        fail("MODEL_FALLBACK", "pool attempted to construct a C session");
      }
      requireCondition(
        label,
        "API_CONTRACT_MISMATCH",
        "pool requested an unexpected workDir",
        {
          workDir,
          canonicalIncomingPath,
          canonicalAPath,
          canonicalBPath,
          normalizedIncomingPath: comparable,
          normalizedAPath,
          normalizedBPath,
          fixtureWorkDirs: {
            A: canonicalAPath,
            B: canonicalBPath,
          },
        },
      );
      return createPooledSession(fixture, fixture.globalSettings, workDir, label, guard, registries, settingsByLabel, ownedAuthResources, cAttempts);
    },
    sessionCreateTimeoutMs: 30_000,
    sessionDisposeTimeoutMs: 5_000,
  });
  const startedAt = new Date().toISOString();
  const runnerArgv = [...process.argv];
  const runnerOrderCommand = runnerArgv.find(item => item.startsWith("--order=")) ?? `--order=${order.join(",")}`;
  const cResources = { label: "C", authStore: null, authStoreClose: null, authStorage: null, modelRegistry: null };
  registries.C = cResources;
  let receipt;
  try {
    fixture.globalSettings = await Settings.init({ cwd: fixture.root, agentDir: fixture.agentDir });
    fixture.globalSettingsInitCalls = 1;
    requireCondition(Settings.instance === fixture.globalSettings && fixture.globalSettings.getCwd() === fixture.root && fixture.globalSettings.getAgentDir() === fixture.agentDir, "API_CONTRACT_MISMATCH", "global Settings singleton bootstrap is not fixture-owned");
    requireCondition(fixture.globalSettings.get("startup.networkPrewarm") === false, "API_CONTRACT_MISMATCH", "global startup.networkPrewarm is not false");
    globalSettingsForRegistry = fixture.globalSettings;
    initializeWithSettings(fixture.globalSettings);
    fixture.globalSeed = policySnapshot(fixture.globalSettings);
    fixture.globalIntrospectionSeed = { capability: getCapabilityInfo(CAPABILITY_ID), providers: getAllProvidersInfo().filter(item => item.id.startsWith("issue62-capability")) };
    const sessions = {};
    for (const label of order) sessions[label] = await pool.ensureSession(fixture.workDirs[label]);
    requireCondition(pool.sessions.size === 2, "SESSION_LIFECYCLE_FAILURE", "pool did not retain two sessions");
    requireCondition(new Set([...pool.sessions.keys()]).size === 2, "SESSION_LIFECYCLE_FAILURE", "pool canonicalized two workDirs to one key");
    requireCondition(Object.values(registries).filter(record => record.rawSession).every(record => !record.rawSession.isDisposed), "SESSION_LIFECYCLE_FAILURE", "one or more raw AgentSession instances is not live");
    const afterFirst = registries[order[0]].beforeSiblingRegistry;
    const afterSecond = registries[order[1]].beforeSiblingRegistry;
    const reads = await Promise.all(order.map(label => readSession(registries[label], fixture)));
    const finalRegistry = registries[order[1]].modelRegistry;
    const finalSnapshot = registrySnapshot(finalRegistry, "global-final");
    const rawStore = await SqliteAuthCredentialStore.open(join(fixture.authDir, "auth-C.db"));
    ownedAuthResources.push({ name: "auth-C", close: () => rawStore.close(), diagnosticStore: rawStore });
    cResources.authStoreClose = () => rawStore.close();
    cResources.authStore = rawStore;
    cResources.authStorage = new AuthStorage(rawStore);
    await cResources.authStorage.reload();
    const cSettings = await fixture.globalSettings.cloneForCwd(fixture.workDirs.C);
    requireCondition(cSettings.get("startup.networkPrewarm") === false, "API_CONTRACT_MISMATCH", "C startup.networkPrewarm is not false");
    cResources.modelRegistry = new ModelRegistry(cResources.authStorage, fixture.modelsPath);
    const cCandidates = await resolveAllowedModels(cResources.modelRegistry, cSettings);
    const cPolicy = policySnapshot(cSettings);
    const cSyntheticModels = cResources.modelRegistry.getAvailable()
      .filter(model => [PROVIDER_A, PROVIDER_B].includes(model.provider));
    const cSyntheticSelectors = cSyntheticModels.map(modelSelector);
    const cEnabledModels = [...cPolicy.enabledModels];
    requireCondition(
      cSyntheticModels.length === 2 &&
        cSyntheticModels.every(model => !cPolicy.disabledProviders.includes(model.provider)),
      "MODEL_FALLBACK",
      "C synthetic providers were not available to the allow-list oracle",
      {
        available: cSyntheticSelectors,
        disabledProviders: cPolicy.disabledProviders,
      },
    );
    requireCondition(
      cEnabledModels.length > 0 &&
        cEnabledModels.every(selector => !cSyntheticSelectors.includes(selector)),
      "MODEL_FALLBACK",
      "C enabledModels unexpectedly matched a synthetic model",
      { enabledModels: cEnabledModels, available: cSyntheticSelectors },
    );
    const cWithoutAllowList = await cSettings.cloneForCwd(fixture.workDirs.C);
    cWithoutAllowList.override("enabledModels", []);
    const cUnrestrictedCandidates = await resolveAllowedModels(cResources.modelRegistry, cWithoutAllowList);
    requireCondition(
      cCandidates.length === 0 &&
        cUnrestrictedCandidates.some(model => [MODEL_A, MODEL_B].includes(modelSelector(model))),
      "MODEL_FALLBACK",
      "C zero candidates was not caused by its nonmatching enabledModels allow-list",
      {
        candidates: cCandidates.map(modelSelector),
        unrestrictedCandidates: cUnrestrictedCandidates.map(modelSelector),
        enabledModels: cEnabledModels,
        disabledProviders: cPolicy.disabledProviders,
      },
    );
    const noPrompt = cAttempts.sessionConstructionAttempts === 0 && cAttempts.promptAttempts === 0;
    requireCondition(
      noPrompt,
      "MODEL_FALLBACK",
      "C session construction or prompt was attempted",
      { ...cAttempts },
    );
    const unknownCapability = {
      requestedId: UNKNOWN_CAPABILITY_ID,
      rejected: false,
      error: null,
    };
    try {
      await loadCapability(UNKNOWN_CAPABILITY_ID, { settings: cSettings, cwd: fixture.workDirs.C });
    } catch (error) {
      unknownCapability.rejected = true;
      unknownCapability.error = {
        name: error?.name ?? "Error",
        code: error?.code ?? null,
        message: error?.message ?? String(error),
      };
    }
    requireCondition(
      unknownCapability.rejected &&
        unknownCapability.error?.name === "Error" &&
        unknownCapability.error?.code === null &&
        unknownCapability.error?.message === UNKNOWN_CAPABILITY_MESSAGE &&
        unknownCapability.requestedId === UNKNOWN_CAPABILITY_ID,
      "CAPABILITY_FIXTURE_CONTRACT",
      "unknown capability did not fail with the exact SDK error and requested id",
      { unknownCapability },
    );
    const allPolicies = reads.map(item => item.settings);
    requireCondition(policyFingerprint(allPolicies[0]) !== policyFingerprint(allPolicies[1]), "SESSION_POLICY_BLEED", "A/B policy fingerprints are equal");
    requireCondition(reads.every(item => item.activeModel === (item.label === "A" ? MODEL_A : MODEL_B)), "MODEL_FALLBACK", "active model changed during read phase");
    requireCondition(guard.events.length === 0, "ENVIRONMENT_BLOCKED", "network or preconnect guard observed an unexpected call", { events: guard.events });
    const globalDirection = {
      resolvedProvider: classifyDirection(
        registries.seed?.resolvedProvider,
        afterFirst.resolvedProvider,
        afterSecond.resolvedProvider,
        finalSnapshot.resolvedProvider,
        order[0],
        order[1],
      ),
      providerOrder: classifyDirection(
        fixture.globalSeed.modelProviderOrder?.[0],
        afterFirst.providerOrder?.[0],
        afterSecond.providerOrder?.[0],
        finalSnapshot.providerOrder?.[0],
        order[0],
        order[1],
      ),
    };
    receipt = {
      schema: "issue62-sdk-isolation-probe-v1",
      issue: ISSUE,
      ...provenance,
      order,
      runner: {
        argv: runnerArgv,
        command: runnerArgv.join(" "),
        orderCommand: runnerOrderCommand,
      },
      globalSettingsBootstrap: { initCalls: fixture.globalSettingsInitCalls, initialized: true, cwd: fixture.globalSettings.getCwd(), agentDir: fixture.globalSettings.getAgentDir(), networkPrewarm: fixture.globalSettings.get("startup.networkPrewarm") },
      globalSeed: fixture.globalSeed,
      fixturePolicy: { A: fixture.policies.A, B: fixture.policies.B, C: fixture.policies.C },
      canonicalVariants: { id: CANONICAL, variants: registries["A"].modelRegistry.getCanonicalVariants(CANONICAL, { availableOnly: false }).map(item => modelSelector(item.model)), equivalentIds: [MODEL_A, MODEL_B].map(selector => ({ selector, canonicalId: CANONICAL })) },
      liveSessionCount: pool.sessions.size,
      liveWorkDirs: [...pool.sessions.keys()],
      liveWorkDirLabels: Object.values(registries)
        .filter(record => record?.label === "A" || record?.label === "B")
        .map(record => record.label)
        .sort(),
      capability: { counters: { ...counters }, invocations: capabilityInvocations, sessionReads: reads.map(item => ({ label: item.label, explicit: item.capability.explicit, cwdFallback: item.capability.cwdFallback })), expectedDisabled: { A: CAP_B, B: CAP_A }, globalIntrospection: fixture.globalIntrospectionSeed },
      model: { sessions: reads.map(item => ({ label: item.label, activeModel: item.activeModel, activeProvider: item.activeProvider, settings: item.settings })), modelFallback: false },
      registrySnapshots: { seed: registries.seed, afterFirst, afterSecond, final: finalSnapshot, perSession: reads.map(item => ({ label: item.label, registry: item.registry })) },
      registryClassification: globalDirection,
      globalIntrospection: { seed: fixture.globalIntrospectionSeed, final: { capability: getCapabilityInfo(CAPABILITY_ID), providers: getAllProvidersInfo().filter(item => item.id.startsWith("issue62-capability")) } },
      negativeCases: {
        unknownCapabilityRejected: unknownCapability.rejected,
        unknownCapability,
        controlledThrowWarning: true,
        disabledLoaderNonInvocation: true,
        noPrompt,
        cSessionConstructionAttempts: cAttempts.sessionConstructionAttempts,
        cPromptAttempts: cAttempts.promptAttempts,
        cRegistryBoundary: "nonmatching-enabledModels",
      },
      cPreSessionCandidates: cCandidates.length,
      modelFallback: false,
      networkPrewarm: { global: fixture.globalSettings.get("startup.networkPrewarm"), A: reads.find(item => item.label === "A").settings.networkPrewarm, B: reads.find(item => item.label === "B").settings.networkPrewarm, C: cSettings.get("startup.networkPrewarm") },
      preconnectGuard: { available: true, events: guard.events, observed: false },
      failureCodes: [],
      startedAt,
      finishedAt: new Date().toISOString(),
      cleanup: { pending: true },
      artifactName: null,
      coverage: {
        auth: "empty-fixture-auth-storage-only",
        sessionHostAccess: "not-exercised",
        profileActivation: "not-exercised",
        liveProviderTransport: "not-exercised",
      },
      customFactoryBoundary: "Fixture-owned AuthStorage/ModelRegistry and explicit role selectors exercise the real Settings/SessionManager/createAgentSession/AgentSession/SdkSession/SessionPool seam; profile activation and live provider transport are not covered.",
    };
  } finally {
    const cleanup = {
      poolShutdown: false,
      storesClosed: false,
      fixtureRemoved: false,
      leaks: [],
      storeOutcomes: [],
      sessionDisposals: [],
    };
    const cleanupErrors = [];
    let poolShutdownResolved = false;
    try {
      await pool.shutdown();
      poolShutdownResolved = true;
    } catch (error) {
      cleanupErrors.push({ operation: "pool-shutdown", error: error?.message ?? String(error) });
    }
    for (const [label, record] of Object.entries(registries)) {
      if (!record?.rawSession) continue;
      let closed = record.rawSession.isDisposed === true;
      if (!closed) {
        try {
          await disposeRawSessionBounded(record.rawSession, `cleanup-${label}`);
        } catch (error) {
          cleanupErrors.push({
            operation: `raw-session-${label}`,
            error: error?.message ?? String(error),
            details: error?.details,
          });
        }
        closed = record.rawSession.isDisposed === true;
      }
      cleanup.sessionDisposals.push({ label, closed });
      if (!closed) {
        cleanupErrors.push({ operation: `raw-session-${label}`, error: "session did not reach disposed state after pool shutdown" });
      }
    }
    cleanup.poolShutdown = poolShutdownResolved &&
      cleanup.sessionDisposals.every(outcome => outcome.closed);
    const stores = [
      ...ownedAuthResources,
      { name: "settings", close: fixture.globalSettings?.getStorage?.() },
      { name: "model-cache", close: () => closeModelCache(join(dirname(fixture.modelsPath), "models.db")) },
    ];
    for (const { name, close, diagnosticStore } of stores) {
      const owned = typeof close === "function" || typeof close?.close === "function";
      if (!owned) {
        const outcome = { name, closed: false, error: "store was not owned" };
        if (name === "auth-A" || name === "auth-B" || name === "auth-C") {
          outcome.diagnostic = nonOwnedAuthStoreDiagnostic(diagnosticStore, fixture);
        }
        cleanup.storeOutcomes.push(outcome);
        cleanupErrors.push({ operation: `close-${name}`, error: "store was not owned" });
        continue;
      }
      try {
        if (typeof close === "function") await close();
        else await close.close();
        cleanup.storeOutcomes.push({ name, closed: true });
      } catch (error) {
        cleanup.storeOutcomes.push({ name, closed: false, error: error?.message ?? String(error) });
        cleanupErrors.push({ operation: `close-${name}`, error: error?.message ?? String(error) });
      }
    }
    await Bun.sleep(250);
    try {
      guard.restore();
    } catch (error) {
      cleanupErrors.push({ operation: "network-guard-restore", error: error?.message ?? String(error) });
    }
    const pending = pool.getPendingShutdownOperations();
    const leaks = [];
    if (pool.sessions.size !== 0) leaks.push({ kind: "pool-sessions", count: pool.sessions.size });
    for (const operation of pending) leaks.push({ kind: "pending-operation", operation: operation.operation });
    for (const outcome of cleanup.sessionDisposals) if (!outcome.closed) leaks.push({ kind: "raw-session", label: outcome.label });
    for (const outcome of cleanup.storeOutcomes) if (!outcome.closed) leaks.push({ kind: "store", name: outcome.name });
    cleanup.leaks = leaks;
    cleanup.storesClosed = cleanup.storeOutcomes.length === stores.length && cleanup.storeOutcomes.every(outcome => outcome.closed);
    if (receipt) {
      receipt.cleanup = cleanup;
      receipt.finishedAt = new Date().toISOString();
    }
    if (cleanupErrors.length > 0 || !cleanup.poolShutdown || !cleanup.storesClosed || cleanup.leaks.length > 0) {
      throw new ProbeFailure("SESSION_LIFECYCLE_FAILURE", "probe cleanup did not close every owned resource", { cleanup, errors: cleanupErrors });
    }
  }
  return receipt;
}

async function main() {
  const order = parseOrder();
  let fixture;
  let receipt;
  let provenance = {
    approvedBaseCommit: BASE_COMMIT,
    sourceCommit: null,
    changeSet: { algorithm: "sha256", files: [...CHANGE_FILES], digest: null },
  };
  try {
    provenance.sourceCommit = await gitHead();
    provenance.changeSet.digest = await orderedChangeDigest();
    rejectHostEnvironment();
    provenance = { ...provenance, ...await assertSdkProvenance() };
    fixture = await createHermeticFixture();
    capabilityFixture = fixture;
    receipt = await runOrder(order, fixture, provenance);
    await removeFixtureRoot(fixture.root);
    receipt.cleanup.fixtureRemoved = !existsSync(fixture.root);
    requireCondition(receipt.cleanup.fixtureRemoved, "SESSION_LIFECYCLE_FAILURE", "fixture root was not removed");
    receipt = redactValue(receipt, fixture);
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    const cleanupRoot = fixture?.root ?? setupRoot;
    let fixtureRemoved = false;
    if (cleanupRoot) {
      await removeFixtureRoot(cleanupRoot).catch(() => {});
      fixtureRemoved = !existsSync(cleanupRoot);
      setupRoot = undefined;
    }
    const failure = redactValue({
      schema: "issue62-sdk-isolation-probe-v1",
      issue: ISSUE,
      ...provenance,
      order,
      runner: {
        argv: [...process.argv],
        command: process.argv.join(" "),
        orderCommand: process.argv.find(item => item.startsWith("--order=")) ?? `--order=${order.join(",")}`,
      },
      failureCodes: [error?.code ?? "PROBE_FAILURE"],
      error: error?.message ?? String(error),
      details: error?.details ?? {},
      cleanup: {
        ...error?.details?.cleanup,
        poolShutdown: error?.details?.cleanup?.poolShutdown ?? false,
        storesClosed: error?.details?.cleanup?.storesClosed ?? false,
        fixtureRemoved,
        leaks: error?.details?.cleanup?.leaks ?? [],
      },
    }, fixture ?? { root: cleanupRoot ?? "" });
    process.stdout.write(`${JSON.stringify(failure)}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.main) await main();
