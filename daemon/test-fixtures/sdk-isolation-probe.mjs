#!/usr/bin/env bun
/* Issue #62: real SDK/session-pool isolation probe. Bun-only; stdout is not an artifact. */
import { chmod, lstat, readFile, readdir, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { SessionPool } from "../src/session-pool.js";
import { SdkSession } from "../src/sdk-session.js";

let closeModelCache;
let createAgentSession;
let Settings;
let SessionManager;
let AuthStorage;
let SqliteAuthCredentialStore;
let ModelRegistry;
let resolveAllowedModels;
let defineCapability;
let getAllProvidersInfo;
let getCapabilityInfo;
let loadCapability;
let registerProvider;

const ISSUE = 62;
const BASE_COMMIT = "a5bb530bd5a063b6571a7ba963e938bb6f97616f";
const EXPECTED_SDK = "0.16.4";
const MIN_BUN = [1, 4, 0];
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
const BACKGROUND_DISCOVERY_PROVIDERS = [
  "ollama",
  "llama.cpp",
  "lm-studio",
  "omlx",
  "opencodex",
  "vllm",
  "sglang",
];
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
const FIXTURE_ROOT_PREFIX = "gjc-issue62-sdk-";
const FIXTURE_REMOVAL_ATTEMPTS = 20;
const FIXTURE_REMOVAL_RETRY_MS = 100;
const FIXTURE_INVENTORY_LIMIT = 32;
const FIXTURE_REMOVAL_RETRY_CODES = new Set(["EACCES", "EBUSY", "ENOTEMPTY", "EPERM"]);
const initialProcessCwd = process.cwd();
const childOwnedFixtureRoots = new Set();

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

async function loadProbeSdk() {
  process.env.GJC_MODEL_PRESET_REGISTRY_DISABLED = "1";
  const [ai, sdk, sessionManager, authStorage, modelRegistry, modelResolver, capability] = await Promise.all([
    import("@gajae-code/ai/core"),
    import("@gajae-code/coding-agent/sdk"),
    import("@gajae-code/coding-agent/session/session-manager"),
    import("@gajae-code/coding-agent/session/auth-storage"),
    import("@gajae-code/coding-agent/config/model-registry"),
    import("@gajae-code/coding-agent/config/model-resolver"),
    import("@gajae-code/coding-agent/capability"),
  ]);
  closeModelCache = ai.closeModelCache;
  createAgentSession = sdk.createAgentSession;
  Settings = sdk.Settings;
  SessionManager = sessionManager.SessionManager;
  AuthStorage = authStorage.AuthStorage;
  SqliteAuthCredentialStore = authStorage.SqliteAuthCredentialStore;
  ModelRegistry = modelRegistry.ModelRegistry;
  resolveAllowedModels = modelResolver.resolveAllowedModels;
  defineCapability = capability.defineCapability;
  getAllProvidersInfo = capability.getAllProvidersInfo;
  getCapabilityInfo = capability.getCapabilityInfo;
  loadCapability = capability.loadCapability;
  registerProvider = capability.registerProvider;
  registerCapabilityFixture();
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
    globalModelProviderOrder: [...(settings.getGlobal("modelProviderOrder") ?? [])],
    networkPrewarm: settings.get("startup.networkPrewarm"),
  };
}

function globalPolicySnapshot(settings) {
  return {
    disabledProviders: sortedStrings(settings.getGlobal("disabledProviders")),
    enabledModels: [...(settings.getGlobal("enabledModels") ?? [])],
    modelRolesDefault: settings.getGlobal("modelRoles")?.default,
    planner: settings.getGlobal("task.agentModelOverrides")?.planner,
    modelProviderOrder: [...(settings.getGlobal("modelProviderOrder") ?? [])],
    networkPrewarm: settings.getGlobal("startup.networkPrewarm"),
  };
}

function globalSettingsSingletonSnapshot() {
  try {
    const settings = Settings.instance;
    return {
      initialized: true,
      cwd: settings.getCwd(),
      agentDir: settings.getAgentDir(),
    };
  } catch (error) {
    requireCondition(
      error instanceof Error && error.message.includes("Settings not initialized"),
      "API_CONTRACT_MISMATCH",
      "global Settings singleton inspection failed unexpectedly",
      { name: error?.name, message: error?.message ?? String(error) },
    );
    return { initialized: false };
  }
}

function policyFingerprint(policy) {
  return JSON.stringify({
    disabledProviders: policy.disabledProviders,
    enabledModels: policy.enabledModels,
    modelRolesDefault: policy.modelRolesDefault,
    planner: policy.planner,
    modelProviderOrder: policy.modelProviderOrder,
    globalModelProviderOrder: policy.globalModelProviderOrder,
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
const SECRET_KEY_PATTERN = String.raw`[A-Z0-9_]*(?:API[\s_-]*KEY|ACCESS[\s_-]*TOKEN|REFRESH[\s_-]*TOKEN|OAUTH|PASSWORD|AUTHORIZATION|COOKIE|BROKER|CREDENTIAL|SECRET|TOKEN)`;
const SECRET_KEY_VALUE_PATTERN = new RegExp(
  String.raw`\b${SECRET_KEY_PATTERN}\b\s*(?:[:=]\s*|\s+)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:Bearer\s+)?[^\s"',;}]+)`,
  "gi",
);
const SECRET_KEY_ONLY_PATTERN = new RegExp(String.raw`\b${SECRET_KEY_PATTERN}\b`, "gi");
const REDACTION_PROBE_SCHEMA = "issue62-sdk-isolation-redaction-probe-v1";
const REDACTION_PROBE_SENTINELS = Object.freeze([
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
]);
const REDACTION_PROBE_FRAGMENTS = Object.freeze([
  ...new Set([
    ...REDACTION_PROBE_SENTINELS,
    ...REDACTION_PROBE_SENTINELS.map(value => value.slice(0, 8)),
    ...REDACTION_PROBE_SENTINELS.map(value => value.slice(-8)),
  ]),
]);

function redactedText(value, root, fixture) {
  let text = String(value ?? "");
  for (const [path, token] of [
    [root.invocationRoot, "<fixture-root>"],
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
function runRedactionProbe() {
  const [apiAssignment, apiBearer, apiHyphen, apiQuoted, apiCompact, accessToken, refreshToken, credential, genericToken, tokenQuoted] = REDACTION_PROBE_SENTINELS;
  const input = [
    `API key = ${apiAssignment}`,
    `API key: Bearer ${apiBearer}`,
    `api-key = ${apiHyphen}`,
    `Api_Key: '${apiQuoted} quoted'`,
    `APIKEY ${apiCompact}`,
    `ACCESS TOKEN = ${accessToken}`,
    `refresh-token: Bearer ${refreshToken}`,
    `credential = ${credential}`,
    `generic token: ${genericToken}`,
    `token = "${tokenQuoted} quoted"`,
  ].join("\n");
  const redacted = redactedText(input, {});
  const leakedIndex = REDACTION_PROBE_FRAGMENTS.findIndex(fragment => redacted.includes(fragment));
  requireCondition(leakedIndex === -1, "REDACTION_LEAK", "redaction probe leaked an opaque sentinel", { leakedFragmentIndex: leakedIndex });
  requireCondition(redacted.includes("<secret-redacted>"), "REDACTION_PROBE_INVALID", "redaction probe produced no secret marker");
  process.stdout.write(`${JSON.stringify({
    schema: REDACTION_PROBE_SCHEMA,
    sentinelCount: REDACTION_PROBE_SENTINELS.length,
    fragmentCount: REDACTION_PROBE_FRAGMENTS.length,
    secretMarker: true,
  })}\n`);
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

function parseOrder() {
  const equalsArg = process.argv.find(item => item.startsWith("--order="));
  const separateIndex = process.argv.indexOf("--order");
  const valueArg = equalsArg?.slice("--order=".length) ?? (separateIndex >= 0 ? process.argv[separateIndex + 1] : "A,B");
  const value = valueArg.split(",").map(item => item.trim().toUpperCase());
  requireCondition(value.length === 2 && value.every(item => item === "A" || item === "B") && value[0] !== value[1], "API_CONTRACT_MISMATCH", "order must be A,B or B,A");
  return value;
}

function parseFixtureRoot() {
  const equalsArg = process.argv.find(item => item.startsWith("--fixture-root="));
  const separateIndex = process.argv.indexOf("--fixture-root");
  const value = equalsArg?.slice("--fixture-root=".length) ??
    (separateIndex >= 0 ? process.argv[separateIndex + 1] : undefined);
  if (value === undefined) return undefined;
  requireCondition(
    value.length > 0 && isAbsolute(value),
    "CLEANUP_SCOPE_VIOLATION",
    "--fixture-root must be an absolute wrapper-owned path",
  );
  return resolve(value);
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

function sourceIdentity(sourceCommit, changeSetDigest) {
  return {
    historicalBaseline: {
      commit: BASE_COMMIT,
      semantics: "Historical approved issue-62 baseline; it is not asserted to be the executing source tree.",
    },
    runtimeHead: {
      commit: sourceCommit,
      semantics: "Git HEAD at probe execution; it does not identify uncommitted working-tree bytes.",
    },
    workingTreeEvidence: {
      algorithm: "sha256",
      files: [...CHANGE_FILES],
      digest: changeSetDigest,
      semantics: "Ordered path names and live file bytes read from the working tree at probe execution.",
    },
  };
}

async function assertSdkProvenance(sourceCommit, changeSetDigest) {
  const daemonPackage = JSON.parse(await readFile(join(repoRoot, "daemon", "package.json"), "utf8"));
  const installedPackage = JSON.parse(await readFile(join(repoRoot, "node_modules", "@gajae-code", "coding-agent", "package.json"), "utf8"));
  const lock = await readFile(join(repoRoot, "bun.lock"), "utf8");
  const lockEvidence = lock.match(/"@gajae-code\/coding-agent": \["@gajae-code\/coding-agent@([^"]+)"/)?.[1];
  const bunVersion = Bun.version;
  requireCondition(daemonPackage.dependencies?.["@gajae-code/coding-agent"] === EXPECTED_SDK, "SDK_VERSION_MISMATCH", "daemon dependency is not pinned to 0.16.4", { daemon: daemonPackage.dependencies?.["@gajae-code/coding-agent"] });
  requireCondition(installedPackage.version === EXPECTED_SDK && lockEvidence === EXPECTED_SDK, "SDK_VERSION_MISMATCH", "installed package or lockfile is not 0.16.4", { installed: installedPackage.version, lock: lockEvidence });
  requireCondition(versionAtLeast(bunVersion, MIN_BUN), "SDK_VERSION_MISMATCH", "Bun is older than 1.4.0", { bunVersion });
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
      digest: changeSetDigest,
    },
    sourceIdentity: sourceIdentity(sourceCommit, changeSetDigest),
  };
}

function rejectHostEnvironment() {
  const blocked = Object.entries(process.env)
    .filter(([name, value]) => value && /(?:API[_-]?KEY|OAUTH|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|PASSWORD|SECRET|AUTHORIZATION|BROKER|PROXY|GJC_MODEL|GJC_PROFILE|GJC_AUTH|GJC_CREDENTIAL|GJC_(?:CODING_AGENT_DIR|CONFIG_DIR)|PI_(?:CODING_AGENT_DIR|CONFIG_DIR)|GITHUB_TOKEN|HF_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|VAULT_TOKEN|CI_JOB_TOKEN|(?:^|_)(?:PAT|TOKEN)$|OPENAI_|OPENROUTER_|ANTHROPIC_|GOOGLE_|AWS_)/i.test(name))
    .map(([name]) => name)
    .sort();
  requireCondition(blocked.length === 0, "ENVIRONMENT_BLOCKED", "credential/proxy/host override variables are present", { variables: blocked });
}

async function prepareFixtureRoot(explicitRoot) {
  if (explicitRoot === undefined) {
    const root = resolve(await mkdtemp(join(tmpdir(), FIXTURE_ROOT_PREFIX)));
    childOwnedFixtureRoots.add(root);
    return { root, invocationRoot: root, cleanupOwner: "child" };
  }
  const [canonicalRoot, canonicalTemp] = await Promise.all([
    realpath(explicitRoot),
    realpath(tmpdir()),
  ]);
  requireCondition(
    comparableWorkDir(dirname(canonicalRoot)) === comparableWorkDir(canonicalTemp) &&
      basename(canonicalRoot).startsWith(FIXTURE_ROOT_PREFIX),
    "CLEANUP_SCOPE_VIOLATION",
    "wrapper-owned fixture root must be a direct prefixed child of the isolated temp directory",
    { root: canonicalRoot, temp: canonicalTemp },
  );
  const entries = await readdir(canonicalRoot);
  requireCondition(
    entries.length === 0,
    "CLEANUP_SCOPE_VIOLATION",
    "wrapper-owned fixture root must be empty before child setup",
    { entryCount: entries.length },
  );
  return { root: canonicalRoot, invocationRoot: explicitRoot, cleanupOwner: "parent-wrapper" };
}

function isPathWithin(root, candidate) {
  const relation = relative(resolve(root), resolve(candidate));
  return relation === "" || (!relation.startsWith(`..${sep}`) && relation !== ".." && !isAbsolute(relation));
}

function activeResourceSnapshot() {
  if (typeof process.getActiveResourcesInfo !== "function") {
    return { available: false, counts: {} };
  }
  let resources;
  try {
    resources = process.getActiveResourcesInfo();
  } catch (error) {
    return {
      available: true,
      counts: {},
      error: {
        code: error?.code ?? "UNKNOWN",
        name: error?.name ?? "Error",
      },
    };
  }
  const counts = {};
  for (const resource of resources) counts[resource] = (counts[resource] ?? 0) + 1;
  return {
    available: true,
    counts: Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right))),
  };
}

async function fixtureTreeSnapshot(root) {
  const snapshot = {
    remainingEntries: 0,
    nonWritableEntries: 0,
    sample: [],
    inspectionErrors: [],
  };
  const visit = async current => {
    if (!isPathWithin(root, current)) {
      snapshot.inspectionErrors.push({ entry: "<outside-fixture>", code: "CLEANUP_SCOPE_VIOLATION" });
      return;
    }
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if (error?.code !== "ENOENT" && snapshot.inspectionErrors.length < FIXTURE_INVENTORY_LIMIT) {
        snapshot.inspectionErrors.push({
          entry: relative(root, current) || ".",
          code: error?.code ?? "UNKNOWN",
        });
      }
      return;
    }
    const entry = relative(root, current) || ".";
    snapshot.remainingEntries += 1;
    if ((metadata.mode & 0o200) === 0) snapshot.nonWritableEntries += 1;
    if (snapshot.sample.length < FIXTURE_INVENTORY_LIMIT) {
      snapshot.sample.push({
        entry,
        kind: metadata.isSymbolicLink() ? "symlink" : metadata.isDirectory() ? "directory" : "file",
        ownerWritable: (metadata.mode & 0o200) !== 0,
      });
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) return;
    let children;
    try {
      children = await readdir(current);
    } catch (error) {
      if (snapshot.inspectionErrors.length < FIXTURE_INVENTORY_LIMIT) {
        snapshot.inspectionErrors.push({ entry, code: error?.code ?? "UNKNOWN" });
      }
      return;
    }
    for (const child of children) await visit(join(current, child));
  };
  await visit(root);
  return snapshot;
}

async function makeFixtureTreeWritable(root) {
  const outcome = { attempted: true, changed: 0, symlinksSkipped: 0, errors: [] };
  const visit = async current => {
    if (!isPathWithin(root, current)) {
      outcome.errors.push({ entry: "<outside-fixture>", code: "CLEANUP_SCOPE_VIOLATION" });
      return;
    }
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if (error?.code !== "ENOENT" && outcome.errors.length < FIXTURE_INVENTORY_LIMIT) {
        outcome.errors.push({ entry: relative(root, current) || ".", code: error?.code ?? "UNKNOWN" });
      }
      return;
    }
    if (metadata.isSymbolicLink()) {
      outcome.symlinksSkipped += 1;
      return;
    }
    const entry = relative(root, current) || ".";
    try {
      await chmod(current, metadata.isDirectory() ? 0o700 : 0o600);
      outcome.changed += 1;
    } catch (error) {
      if (outcome.errors.length < FIXTURE_INVENTORY_LIMIT) {
        outcome.errors.push({ entry, code: error?.code ?? "UNKNOWN" });
      }
    }
    if (!metadata.isDirectory()) return;
    let children;
    try {
      children = await readdir(current);
    } catch (error) {
      if (outcome.errors.length < FIXTURE_INVENTORY_LIMIT) {
        outcome.errors.push({ entry, code: error?.code ?? "UNKNOWN" });
      }
      return;
    }
    for (const child of children) await visit(join(current, child));
  };
  await visit(root);
  return outcome;
}

async function createHermeticFixture(explicitRoot) {
  const { root, invocationRoot, cleanupOwner } = await prepareFixtureRoot(explicitRoot);
  setupRoot = root;
  setupCleanupOwner = cleanupOwner;
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
  const globalConfig = `configSchemaVersion: 2\nstartup:\n  networkPrewarm: false\ndisabledProviders:\n${BACKGROUND_DISCOVERY_PROVIDERS.map(item => `  - ${item}`).join("\n")}\nenabledModels:\n  - ${MODEL_A}\n  - ${MODEL_B}\nmodelRoles:\n  default: ${MODEL_A}\ntask:\n  agentModelOverrides:\n    planner: ${MODEL_A}\nmodelProviderOrder:\n  - ${PROVIDER_A}\n  - ${PROVIDER_B}\n`;
  await writeFile(join(agentDir, "config.yml"), globalConfig);
  const policies = {
    A: {
      disabledProviders: [PROVIDER_B, CAP_B, ...BACKGROUND_DISCOVERY_PROVIDERS],
      default: MODEL_A,
      planner: MODEL_A,
      modelProviderOrder: [PROVIDER_A, PROVIDER_B],
    },
    B: {
      disabledProviders: [PROVIDER_A, CAP_A, ...BACKGROUND_DISCOVERY_PROVIDERS],
      default: MODEL_B,
      planner: MODEL_B,
      modelProviderOrder: [PROVIDER_B, PROVIDER_A],
    },
    C: {
      disabledProviders: [...BACKGROUND_DISCOVERY_PROVIDERS],
      default: "issue62-no-such-provider/issue62-no-such-model",
      planner: "issue62-no-such-provider/issue62-no-such-model",
      modelProviderOrder: [PROVIDER_A, PROVIDER_B],
    },
  };
  for (const label of ["A", "B", "C"]) {
    const policy = policies[label];
    const config = `configSchemaVersion: 2\nstartup:\n  networkPrewarm: false\ndisabledProviders:\n${policy.disabledProviders.map(item => `  - ${item}`).join("\n")}\nenabledModels:\n  - ${label === "C" ? "issue62-no-such-provider/issue62-no-such-model" : MODEL_A}\n  - ${label === "C" ? "issue62-no-such-provider/issue62-no-such-model-2" : MODEL_B}\nmodelRoles:\n  default: ${policy.default}\ntask:\n  agentModelOverrides:\n    planner: ${policy.planner}\nmodelProviderOrder:\n${policy.modelProviderOrder.map(item => `  - ${item}`).join("\n")}\n`;
    await writeFile(join(workDirs[label], ".gjc", "config.yml"), config);
  }
  const modelsPath = join(agentDir, "models.yml");
  const modelsConfig = `providers:\n  ${PROVIDER_A}:\n    baseUrl: http://127.0.0.1:1/issue62-a\n    api: anthropic-messages\n    auth: none\n    models:\n      - id: issue62-model-a\n        name: Issue62 fixture model A\n        contextWindow: 4096\n        maxTokens: 512\n        input: [text]\n        output: [text]\n        cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0}\n  ${PROVIDER_B}:\n    baseUrl: http://127.0.0.1:1/issue62-b\n    api: anthropic-messages\n    auth: none\n    models:\n      - id: issue62-model-b\n        name: Issue62 fixture model B\n        contextWindow: 4096\n        maxTokens: 512\n        input: [text]\n        output: [text]\n        cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0}\nequivalence:\n  overrides:\n    ${MODEL_A}: ${CANONICAL}\n    ${MODEL_B}: ${CANONICAL}\n`;
  await writeFile(modelsPath, modelsConfig);
  setupRoot = undefined;
  setupCleanupOwner = undefined;
  return {
    root,
    invocationRoot,
    cleanupOwner,
    home,
    agentDir,
    workDirs,
    markerA,
    markerB,
    markerC,
    modelsPath,
    policies,
    authDir: join(root, "auth"),
  };
}
async function removeFixtureRoot(root) {
  root = resolve(root);
  requireCondition(
    childOwnedFixtureRoots.has(root),
    "CLEANUP_SCOPE_VIOLATION",
    "child refused to remove a root it did not create",
  );
  const cwdBefore = process.cwd();
  const fixtureRemoval = {
    owner: "child",
    scope: "fixture-root-only",
    attempted: true,
    removed: false,
    attempts: 0,
    cwd: {
      insideFixtureBefore: isPathWithin(root, cwdBefore),
      restoredToLaunchDirectory: false,
    },
    activeResourcesBefore: activeResourceSnapshot(),
    firstFailure: null,
    writableRepair: null,
    finalInventory: null,
  };
  if (fixtureRemoval.cwd.insideFixtureBefore) {
    requireCondition(
      !isPathWithin(root, initialProcessCwd) && existsSync(initialProcessCwd),
      "SESSION_LIFECYCLE_FAILURE",
      "process cwd remained inside the fixture and the launch directory was unavailable",
      { fixtureRemoval },
    );
    try {
      process.chdir(initialProcessCwd);
      fixtureRemoval.cwd.restoredToLaunchDirectory = true;
    } catch (error) {
      fixtureRemoval.cwd.restoreError = {
        code: error?.code ?? "UNKNOWN",
        syscall: error?.syscall ?? null,
      };
      throw new ProbeFailure(
        "SESSION_LIFECYCLE_FAILURE",
        "process cwd remained inside the fixture and could not be restored",
        { fixtureRemoval },
      );
    }
  }
  let lastError;
  for (let attempt = 1; attempt <= FIXTURE_REMOVAL_ATTEMPTS; attempt += 1) {
    fixtureRemoval.attempts = attempt;
    try {
      await rm(root, { recursive: true, force: true });
      fixtureRemoval.removed = !existsSync(root);
      requireCondition(
        fixtureRemoval.removed,
        "SESSION_LIFECYCLE_FAILURE",
        "fixture root still existed after rm resolved",
        { fixtureRemoval },
      );
      fixtureRemoval.classification = fixtureRemoval.cwd.insideFixtureBefore
        ? "process-cwd-restored"
        : fixtureRemoval.firstFailure?.inventory?.nonWritableEntries > 0
          ? "readonly-remediated"
          : fixtureRemoval.firstFailure
            ? "transient-unattributed-removal-block"
            : "removed-first-attempt";
      fixtureRemoval.activeResourcesAfter = activeResourceSnapshot();
      childOwnedFixtureRoots.delete(root);
      return fixtureRemoval;
    } catch (error) {
      lastError = error;
      if (fixtureRemoval.firstFailure === null) {
        fixtureRemoval.firstFailure = {
          attempt,
          code: error?.code ?? "UNKNOWN",
          syscall: error?.syscall ?? null,
          inventory: await fixtureTreeSnapshot(root),
        };
        fixtureRemoval.writableRepair = await makeFixtureTreeWritable(root);
      }
      if (!FIXTURE_REMOVAL_RETRY_CODES.has(error?.code)) {
        fixtureRemoval.finalInventory = await fixtureTreeSnapshot(root);
        fixtureRemoval.classification = fixtureRemoval.cwd.insideFixtureBefore
          ? "process-cwd-observed"
          : fixtureRemoval.firstFailure?.inventory?.nonWritableEntries > 0
            ? "readonly-remediation-insufficient"
            : "unattributed-no-cwd-or-mode-cause";
        throw new ProbeFailure(
          "SESSION_LIFECYCLE_FAILURE",
          "fixture root removal failed",
          {
            fixtureRemoval,
            removalError: {
              code: error?.code ?? "UNKNOWN",
              syscall: error?.syscall ?? null,
            },
          },
        );
      }
      await Bun.sleep(FIXTURE_REMOVAL_RETRY_MS);
    }
  }
  fixtureRemoval.finalInventory = await fixtureTreeSnapshot(root);
  fixtureRemoval.classification = fixtureRemoval.cwd.insideFixtureBefore
    ? "process-cwd-observed"
    : fixtureRemoval.firstFailure?.inventory?.nonWritableEntries > 0
      ? "readonly-remediation-insufficient"
      : "unattributed-no-cwd-or-mode-cause";
  fixtureRemoval.activeResourcesAfter = activeResourceSnapshot();
  throw new ProbeFailure(
    "SESSION_LIFECYCLE_FAILURE",
    "fixture root remained after bounded removal",
    {
      fixtureRemoval,
      removalError: {
        code: lastError?.code ?? "UNKNOWN",
        syscall: lastError?.syscall ?? null,
      },
    },
  );
}

const counters = { [CAP_A]: 0, [CAP_B]: 0, [CAP_THROW]: 0 };
const capabilityInvocations = [];
let capabilityFixture;
let setupRoot;
let setupCleanupOwner;
let capabilityRegistered = false;

function registerCapabilityFixture() {
  if (capabilityRegistered) return;
  defineCapability({
    id: CAPABILITY_ID,
    displayName: "Issue 62 capability probe",
    description: "Fixture-only capability isolation probe",
    key: item => item?.name,
    validate: item => (item?._source ? undefined : "missing source metadata"),
  });
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
  capabilityRegistered = true;
}

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

function registrySnapshot(registry, settings, phase) {
  const all = registry.getAll().filter(model => model.provider === PROVIDER_A || model.provider === PROVIDER_B);
  const available = registry.getAvailable().filter(model => model.provider === PROVIDER_A || model.provider === PROVIDER_B);
  const ids = all.map(model => modelSelector(model));
  const canonicalIds = [...new Set(all.map(model => registry.getCanonicalId(model)).filter(Boolean))];
  const variants = registry.getCanonicalVariants(CANONICAL, { availableOnly: false }).map(item => modelSelector(item.model));
  const availableVariants = registry.getCanonicalVariants(CANONICAL, { availableOnly: true }).map(item => modelSelector(item.model));
  const canonicalModels = registry.getCanonicalModels({ availableOnly: true }).filter(item => item.id === CANONICAL).map(item => ({ id: item.id, variants: item.variants.map(variant => modelSelector(variant.model)) }));
  const resolved = registry.resolveCanonicalModel(CANONICAL, { availableOnly: false, candidates: all });
  const availableResolved = registry.resolveCanonicalModel(CANONICAL, { availableOnly: true, candidates: available });
  requireCondition(
    resolved && [PROVIDER_A, PROVIDER_B].includes(resolved.provider) &&
      [MODEL_A, MODEL_B].includes(modelSelector(resolved)),
    "CANONICAL_ORACLE_FAILURE",
    "canonical resolver did not return a concrete fixture provider/model",
    { phase, resolvedProvider: resolved?.provider, resolvedSelector: modelSelector(resolved) },
  );
  requireCondition(
    availableResolved && [PROVIDER_A, PROVIDER_B].includes(availableResolved.provider) &&
      [MODEL_A, MODEL_B].includes(modelSelector(availableResolved)),
    "CANONICAL_ORACLE_FAILURE",
    "available-only canonical resolver did not return a concrete fixture provider/model",
    { phase, resolvedProvider: availableResolved?.provider, resolvedSelector: modelSelector(availableResolved) },
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
    availableResolvedProvider: availableResolved?.provider,
    availableResolvedSelector: modelSelector(availableResolved),
    providerOrder: [...settings.get("modelProviderOrder")],
    globalProviderOrder: [...(settings.getGlobal("modelProviderOrder") ?? [])],
  };
}

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

function providerForLabel(label) {
  return label === "A" ? PROVIDER_A : PROVIDER_B;
}

function capabilityProviderForLabel(label) {
  return label === "A" ? CAP_A : CAP_B;
}

function classifyProviderSet(providers, order, providerByLabel) {
  const observed = [...new Set(providers)].sort();
  const firstProvider = providerByLabel(order[0]);
  const lastProvider = providerByLabel(order[1]);
  if (observed.length === 1 && observed[0] === lastProvider) return "LAST_CREATED";
  if (observed.length === 1 && observed[0] === firstProvider) return "FIRST_CREATED";
  if (observed.length === 2 && observed.includes(firstProvider) && observed.includes(lastProvider)) return "BOTH";
  if (observed.length === 0) return "NONE";
  return "MIXED";
}

function capabilityIntrospectionSnapshot() {
  const capabilityInfo = getCapabilityInfo(CAPABILITY_ID);
  const providers = getAllProvidersInfo().filter(item => item.id.startsWith("issue62-capability"));
  return {
    capability: capabilityInfo,
    providers,
    enabledFixtureProviders: providers
      .filter(item => item.id === CAP_A || item.id === CAP_B)
      .filter(item => item.enabled)
      .map(item => item.id)
      .sort(),
  };
}

async function observeUnregisteredCwdCapability(fixture, order) {
  const result = await loadCapability(CAPABILITY_ID, { cwd: fixture.root });
  const contributing = result.providers.filter(provider => provider === CAP_A || provider === CAP_B);
  const items = result.items
    .filter(item => item?._source?.provider === CAP_A || item?._source?.provider === CAP_B)
    .map(item => ({ name: item.name, source: item._source }));
  requireCondition(
    contributing.length > 0 && items.length > 0,
    "CAPABILITY_FIXTURE_CONTRACT",
    "settings-unscoped capability observation produced no concrete fixture provider",
    { providers: result.providers, items: result.items },
  );
  return {
    cwdRegistration: "absent",
    classification: classifyProviderSet(contributing, order, capabilityProviderForLabel),
    providers: result.providers,
    items,
    warnings: result.warnings.slice(0, 4),
  };
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

async function createPooledSession(fixture, workDir, label, registries, cAttempts) {
  const record = {
    label,
    workDir,
    settings: null,
    modelRegistry: null,
    rawSession: null,
    sdkSession: null,
    policy: null,
    globalPolicy: null,
    authEntryProviderCount: null,
    active: null,
    beforeSiblingRegistry: null,
  };
  registries[label] = record;
  try {
    if (label === "C") {
      cAttempts.sessionConstructionAttempts += 1;
      fail("MODEL_FALLBACK", "C session construction was attempted");
    }
    currentStage = `create-${label}`;
    const manager = SessionManager.create(workDir, join(workDir, ".gjc-remote-session"));
    const created = await createAgentSession({
      cwd: workDir,
      agentDir: fixture.agentDir,
      sessionManager: manager,
      enableLsp: false,
      skipPythonPreflight: true,
      disableExtensionDiscovery: true,
      skills: [],
      rules: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMcpAutoload: false,
      hasUI: false,
      notificationHostModeSupported: false,
      sdkHostModeSupported: false,
      agentId: `issue62-${label}`,
      agentDisplayName: `issue62-${label}`,
    });
    record.rawSession = created.session;
    record.sdkSession = new SdkSession(record.rawSession);
    record.settings = record.rawSession.settings;
    record.modelRegistry = record.rawSession.modelRegistry;
    record.authEntryProviderCount = Object.keys(record.modelRegistry.authStorage.getAll()).length;
    record.policy = policySnapshot(record.settings);
    record.globalPolicy = globalPolicySnapshot(record.settings);
    const policy = record.policy;
    requireCondition(record.settings.getCwd() === workDir && record.settings.getAgentDir() === fixture.agentDir, "API_CONTRACT_MISMATCH", "SDK-owned settings scope is not fixture-owned", { label, cwd: record.settings.getCwd(), agentDir: record.settings.getAgentDir() });
    requireCondition(record.authEntryProviderCount === 0, "ENVIRONMENT_BLOCKED", "SDK-owned fixture auth storage was not empty", { label, providerCount: record.authEntryProviderCount });
    requireCondition(JSON.stringify(policy.modelProviderOrder) === JSON.stringify(label === "A" ? [PROVIDER_A, PROVIDER_B] : [PROVIDER_B, PROVIDER_A]), "API_CONTRACT_MISMATCH", "A/B merged provider orders did not remain divergent", { label, policy });
    requireCondition(JSON.stringify(policy.globalModelProviderOrder) === JSON.stringify([PROVIDER_A, PROVIDER_B]), "API_CONTRACT_MISMATCH", "global provider order did not remain fixture-owned", { label, policy });
    const expectedModel = label === "A" ? MODEL_A : MODEL_B;
    requireCondition(policy.modelRolesDefault === expectedModel && policy.planner === expectedModel, "API_CONTRACT_MISMATCH", "A/B role policy did not remain session-local", { label, policy });
    requireCondition(policy.networkPrewarm === false, "API_CONTRACT_MISMATCH", "SDK-owned scope startup.networkPrewarm is not false", { label, policy });
    requireCondition(JSON.stringify(policy.enabledModels) === JSON.stringify(ALLOW_LIST), "API_CONTRACT_MISMATCH", "A/B enabled-model allow-list diverged unexpectedly", { label, policy });
    requireCondition(record.modelRegistry.getCanonicalVariants(CANONICAL, { availableOnly: false }).length === 2, "API_CONTRACT_MISMATCH", "canonical equivalence did not produce two variants");
    for (const selector of [MODEL_A, MODEL_B]) {
      const model = record.modelRegistry.getAll().find(item => modelSelector(item) === selector);
      requireCondition(model && record.modelRegistry.getCanonicalId(model) === CANONICAL, "API_CONTRACT_MISMATCH", "canonical model mapping is missing", { selector });
    }
    const active = record.rawSession.model;
    requireCondition(active && ALLOW_LIST.includes(modelSelector(active)), "MODEL_FALLBACK", "session selected no fixture model", { label, active: modelSelector(active) });
    requireCondition(!policy.disabledProviders.includes(active.provider), "MODEL_FALLBACK", "session selected a disabled provider", { label, active: modelSelector(active), disabledProviders: policy.disabledProviders });
    requireCondition(active.provider === (label === "A" ? PROVIDER_A : PROVIDER_B), "MODEL_FALLBACK", "session selected the sibling fixture model", { label, active: modelSelector(active) });
    record.active = modelSelector(active);
    record.beforeSiblingRegistry = registrySnapshot(record.modelRegistry, record.settings, `after-${label}`);
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
  const registry = registrySnapshot(record.modelRegistry, record.settings, `final-${record.label}`);
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
      return createPooledSession(fixture, workDir, label, registries, cAttempts);
    },
    sessionCreateTimeoutMs: 30_000,
    sessionDisposeTimeoutMs: 5_000,
  });
  const startedAt = new Date().toISOString();
  const runnerArgv = [...process.argv];
  const runnerOrderCommand = runnerArgv.find(item => item.startsWith("--order=")) ?? `--order=${order.join(",")}`;
  const cResources = { label: "C", authStore: null, authStorage: null, modelRegistry: null, settings: null };
  registries.C = cResources;
  let receipt;
  let runError;
  try {
    fixture.globalSettingsSingletonSeed = globalSettingsSingletonSnapshot();
    fixture.globalIntrospectionSeed = capabilityIntrospectionSnapshot();
    fixture.globalIntrospectionAfterCreation = {};
    const sessions = {};
    for (const label of order) {
      sessions[label] = await pool.ensureSession(fixture.workDirs[label]);
      fixture.globalIntrospectionAfterCreation[label] = capabilityIntrospectionSnapshot();
    }
    fixture.globalSettingsSingletonFinal = globalSettingsSingletonSnapshot();
    requireCondition(pool.sessions.size === 2, "SESSION_LIFECYCLE_FAILURE", "pool did not retain two sessions");
    requireCondition(new Set([...pool.sessions.keys()]).size === 2, "SESSION_LIFECYCLE_FAILURE", "pool canonicalized two workDirs to one key");
    requireCondition(Object.values(registries).filter(record => record.rawSession).every(record => !record.rawSession.isDisposed), "SESSION_LIFECYCLE_FAILURE", "one or more raw AgentSession instances is not live");
    requireCondition(registries.A.settings !== registries.B.settings, "SESSION_POLICY_BLEED", "A/B sessions reused one Settings instance");
    const afterFirst = registries[order[0]].beforeSiblingRegistry;
    const afterSecond = registries[order[1]].beforeSiblingRegistry;
    const reads = await Promise.all(order.map(label => readSession(registries[label], fixture)));
    const rawStore = await SqliteAuthCredentialStore.open(join(fixture.authDir, "auth-C.db"));
    cResources.authStore = rawStore;
    cResources.authStorage = new AuthStorage(rawStore);
    await cResources.authStorage.reload();
    requireCondition(Object.keys(cResources.authStorage.getAll()).length === 0, "ENVIRONMENT_BLOCKED", "C fixture auth storage was not empty");
    const cSettings = await Settings.loadForScope({ cwd: fixture.workDirs.C, agentDir: fixture.agentDir });
    cResources.settings = cSettings;
    requireCondition(cSettings.get("startup.networkPrewarm") === false, "API_CONTRACT_MISMATCH", "C startup.networkPrewarm is not false");
    cResources.modelRegistry = new ModelRegistry(
      cResources.authStorage,
      fixture.modelsPath,
      cSettings,
      { agentDir: fixture.agentDir, automaticRefresh: false },
    );
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
    cSettings.override("enabledModels", []);
    const cUnrestrictedCandidates = await resolveAllowedModels(cResources.modelRegistry, cSettings);
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
    requireCondition(
      reads.every(item => item.registry.availableResolvedProvider === providerForLabel(item.label)),
      "SESSION_POLICY_BLEED",
      "available-only canonical resolution did not remain per-workDir",
      { registries: reads.map(item => ({ label: item.label, registry: item.registry })) },
    );
    requireCondition(
      reads.every(item =>
        registries[item.label].beforeSiblingRegistry.availableResolvedProvider === item.registry.availableResolvedProvider &&
        registries[item.label].beforeSiblingRegistry.availableResolvedSelector === item.registry.availableResolvedSelector
      ),
      "SESSION_POLICY_BLEED",
      "a session-scoped registry changed after sibling creation",
      { before: { A: registries.A.beforeSiblingRegistry, B: registries.B.beforeSiblingRegistry }, after: reads.map(item => ({ label: item.label, registry: item.registry })) },
    );
    const globalPolicies = reads.map(item => registries[item.label].globalPolicy);
    requireCondition(JSON.stringify(globalPolicies[0]) === JSON.stringify(globalPolicies[1]), "SESSION_POLICY_BLEED", "A/B settings scopes loaded different global policy", { globalPolicies });
    fixture.globalSeed = globalPolicies[0];
    const scopedCapabilityCounters = { ...counters };
    const unregisteredCwdCapability = await observeUnregisteredCwdCapability(fixture, order);
    const globalIntrospectionFinal = capabilityIntrospectionSnapshot();
    const introspectionClassification = classifyProviderSet(
      globalIntrospectionFinal.enabledFixtureProviders,
      order,
      capabilityProviderForLabel,
    );
    requireCondition(guard.events.length === 0, "ENVIRONMENT_BLOCKED", "network or preconnect guard observed an unexpected call", { events: guard.events });
    const readByLabel = Object.fromEntries(reads.map(item => [item.label, item]));
    const registryClassification = {
      availableResolvedProvider: {
        A: readByLabel.A.registry.availableResolvedProvider,
        B: readByLabel.B.registry.availableResolvedProvider,
      },
      unfilteredResolvedProvider: {
        A: readByLabel.A.registry.resolvedProvider,
        B: readByLabel.B.registry.resolvedProvider,
      },
      mergedProviderOrder: {
        A: readByLabel.A.registry.providerOrder,
        B: readByLabel.B.registry.providerOrder,
      },
      globalProviderOrder: {
        A: readByLabel.A.registry.globalProviderOrder,
        B: readByLabel.B.registry.globalProviderOrder,
      },
    };
    const isolationObservations = {
      settings: {
        construction: "createAgentSession-owned Settings.loadForScope",
        instancesDistinct: registries.A.settings !== registries.B.settings,
        policiesDistinct: policyFingerprint(readByLabel.A.settings) !== policyFingerprint(readByLabel.B.settings),
        stableAfterSiblingCreation: true,
      },
      model: {
        activeSelectionPerWorkDir: true,
        availableCanonicalResolutionPerWorkDir: true,
        unfilteredCanonicalResolution: registryClassification.unfilteredResolvedProvider,
      },
      discovery: {
        explicitSettingsPerWorkDir: true,
        registeredCwdFallbackPerWorkDir: true,
        scopedRegistrySuccess: {
          scopeBound: true,
          labels: ["A", "B"],
          semantics: "Explicit Settings and registered-cwd lookup both resolved each workDir's own enabled provider.",
        },
        unregisteredCwdFallback: {
          ...unregisteredCwdCapability,
          scopeBound: false,
          semantics: "No Settings scope is registered for this cwd, so the capability API falls back to its process-global active settings.",
        },
        unscopedCapabilityFallback: {
          classification: unregisteredCwdCapability.classification,
          scopeBound: false,
          semantics: "This process-global fallback is an observation, not evidence of per-workDir isolation.",
        },
        globalIntrospectionClassification: introspectionClassification,
        globalIntrospectionScopeBound: false,
      },
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
      globalSettingsBootstrap: {
        initCalls: 0,
        initialized: fixture.globalSettingsSingletonFinal.initialized,
        strategy: "createAgentSession-owned Settings.loadForScope",
        before: fixture.globalSettingsSingletonSeed,
        after: fixture.globalSettingsSingletonFinal,
        scopes: ["A", "B"].map(label => ({
          label,
          cwd: registries[label].settings.getCwd(),
          agentDir: registries[label].settings.getAgentDir(),
        })),
      },
      globalSeed: fixture.globalSeed,
      fixturePolicy: { A: fixture.policies.A, B: fixture.policies.B, C: fixture.policies.C },
      canonicalVariants: { id: CANONICAL, variants: registries["A"].modelRegistry.getCanonicalVariants(CANONICAL, { availableOnly: false }).map(item => modelSelector(item.model)), equivalentIds: [MODEL_A, MODEL_B].map(selector => ({ selector, canonicalId: CANONICAL })) },
      liveSessionCount: pool.sessions.size,
      liveWorkDirs: [...pool.sessions.keys()],
      liveWorkDirLabels: Object.values(registries)
        .filter(record => record?.label === "A" || record?.label === "B")
        .map(record => record.label)
        .sort(),
      capability: {
        counters: { ...counters },
        scopedCounters: scopedCapabilityCounters,
        invocations: capabilityInvocations,
        sessionReads: reads.map(item => ({ label: item.label, explicit: item.capability.explicit, cwdFallback: item.capability.cwdFallback })),
        expectedDisabled: { A: CAP_B, B: CAP_A },
        unregisteredCwdFallback: unregisteredCwdCapability,
      },
      model: {
        sessions: reads.map(item => ({
          label: item.label,
          activeModel: item.activeModel,
          activeProvider: item.activeProvider,
          settings: item.settings,
          authEntryProviderCount: registries[item.label].authEntryProviderCount,
        })),
        modelFallback: false,
      },
      registrySnapshots: {
        creationOrder: [
          { label: order[0], registry: afterFirst },
          { label: order[1], registry: afterSecond },
        ],
        perSession: reads.map(item => ({ label: item.label, registry: item.registry })),
      },
      registryClassification,
      isolationObservations,
      globalIntrospection: {
        seed: fixture.globalIntrospectionSeed,
        afterCreation: fixture.globalIntrospectionAfterCreation,
        final: globalIntrospectionFinal,
        classification: introspectionClassification,
        scopeBound: false,
      },
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
      networkPrewarm: { global: fixture.globalSeed.networkPrewarm, A: readByLabel.A.settings.networkPrewarm, B: readByLabel.B.settings.networkPrewarm, C: cSettings.get("startup.networkPrewarm") },
      networkIsolation: {
        modelPresetRegistry: {
          fixtureEnvironment: "GJC_MODEL_PRESET_REGISTRY_DISABLED=1",
          setBeforeSdkImport: true,
        },
        disabledBackgroundDiscoveryProviders: [...BACKGROUND_DISCOVERY_PROVIDERS],
        staticFixtureProviderApi: "anthropic-messages",
        scope: "Fixture-only startup control; this probe does not claim production startup is network-free.",
      },
      preconnectGuard: { available: true, events: guard.events, observed: false },
      failureCodes: [],
      startedAt,
      finishedAt: new Date().toISOString(),
      cleanup: { pending: true },
      artifactName: null,
      coverage: {
        auth: "SDK-owned empty fixture auth for A/B; fixture-owned empty auth for C",
        sessionHostAccess: "not-exercised",
        profileActivation: "not-exercised",
        liveProviderTransport: "not-exercised",
      },
      customFactoryBoundary: "A/B use the public createAgentSession path with SDK-owned Settings.loadForScope/AuthStorage/ModelRegistry under the fixture agentDir; C is a no-session allow-list oracle. Profile activation and live provider transport are not covered.",
    };
  } catch (error) {
    runError = error;
  } finally {
    const cleanup = {
      poolShutdown: false,
      storesClosed: false,
      sdkOwnedResourcesClosed: false,
      fixtureRemoved: false,
      leaks: [],
      storeOutcomes: [],
      sdkOwnedResourceOutcomes: [],
      sessionDisposals: [],
      leakScope: "Tracked SessionPool, AgentSession, Settings, auth, registry, session-manager, and model-cache resources; filesystem removal is reported separately.",
      sdkLifecycleSourceContract: {
        scopedSettings: "createAgentSession calls Settings.loadForScope when settings is omitted",
        ownedResources: "AgentSession.dispose awaits SDK-owned ModelRegistry, AuthStorage, Settings, and SessionManager cleanup",
        sharedModelCache: "probe closes the exact fixture models.db with closeModelCache",
        processGlobalDrain: "No aggregate process-global drain is exported by @gajae-code/coding-agent/sdk 0.16.4",
      },
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
      const settingsStorageClosed = record.settings?.getStorage?.() === null;
      cleanup.sdkOwnedResourceOutcomes.push({
        label,
        modelRegistryOwnership: "createAgentSession",
        authStorageOwnership: "createAgentSession",
        settingsOwnership: "createAgentSession",
        settingsStorageClosed,
      });
      if (!settingsStorageClosed) {
        cleanupErrors.push({
          operation: `sdk-owned-settings-${label}`,
          error: "SDK-owned Settings storage remained open after AgentSession.dispose",
        });
      }
    }
    cleanup.poolShutdown = poolShutdownResolved &&
      cleanup.sessionDisposals.every(outcome => outcome.closed);
    cleanup.sdkOwnedResourcesClosed =
      cleanup.sdkOwnedResourceOutcomes.length === 2 &&
      cleanup.sdkOwnedResourceOutcomes.every(outcome => outcome.settingsStorageClosed);
    const stores = [
      ...(cResources.modelRegistry ? [{ name: "model-registry-C", close: () => cResources.modelRegistry.dispose() }] : []),
      ...(cResources.authStorage
        ? [{ name: "auth-C", close: () => cResources.authStorage.close() }]
        : cResources.authStore
          ? [{ name: "auth-store-C", close: () => cResources.authStore.close() }]
          : []),
      ...(cResources.settings
        ? [{
            name: "settings-C",
            close: async () => {
              await cResources.settings.close();
              requireCondition(
                cResources.settings.getStorage() === null,
                "SESSION_LIFECYCLE_FAILURE",
                "fixture-owned C Settings storage remained open after close",
              );
            },
          }]
        : []),
      {
        name: "model-cache",
        close: () => {
          requireCondition(
            closeModelCache(join(dirname(fixture.modelsPath), "models.db")) === true,
            "SESSION_LIFECYCLE_FAILURE",
            "fixture model cache did not report closing its exact database path",
          );
        },
      },
    ];
    for (const { name, close } of stores) {
      const owned = typeof close === "function" || typeof close?.close === "function";
      if (!owned) {
        const outcome = { name, closed: false, error: "store was not owned" };
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
    for (const outcome of cleanup.sdkOwnedResourceOutcomes) {
      if (!outcome.settingsStorageClosed) leaks.push({ kind: "sdk-owned-settings-storage", label: outcome.label });
    }
    for (const outcome of cleanup.storeOutcomes) if (!outcome.closed) leaks.push({ kind: "store", name: outcome.name });
    cleanup.leaks = leaks;
    cleanup.storesClosed =
      cleanup.sdkOwnedResourcesClosed &&
      cleanup.storeOutcomes.length === stores.length &&
      cleanup.storeOutcomes.every(outcome => outcome.closed);
    if (receipt) {
      receipt.cleanup = cleanup;
      receipt.finishedAt = new Date().toISOString();
    }
    if (runError instanceof ProbeFailure) {
      runError.details = { ...runError.details, cleanup, cleanupErrors };
    } else if (runError) {
      runError = new ProbeFailure(
        runError?.code ?? "PROBE_FAILURE",
        runError?.message ?? String(runError),
        { originalName: runError?.name ?? null, cleanup, cleanupErrors },
      );
    } else if (cleanupErrors.length > 0 || !cleanup.poolShutdown || !cleanup.storesClosed || cleanup.leaks.length > 0) {
      runError = new ProbeFailure(
        "SESSION_LIFECYCLE_FAILURE",
        "probe cleanup did not close every owned resource",
        { cleanup, cleanupErrors },
      );
    }
  }
  if (runError) throw runError;
  return receipt;
}

async function main() {
  const order = parseOrder();
  const explicitFixtureRoot = parseFixtureRoot();
  let fixture;
  let receipt;
  let provenance = {
    approvedBaseCommit: BASE_COMMIT,
    sourceCommit: null,
    changeSet: { algorithm: "sha256", files: [...CHANGE_FILES], digest: null },
    sourceIdentity: sourceIdentity(null, null),
  };
  try {
    provenance.sourceCommit = await gitHead();
    provenance.changeSet.digest = await orderedChangeDigest();
    provenance.sourceIdentity = sourceIdentity(provenance.sourceCommit, provenance.changeSet.digest);
    rejectHostEnvironment();
    fixture = await createHermeticFixture(explicitFixtureRoot);
    await loadProbeSdk();
    provenance = {
      ...provenance,
      ...await assertSdkProvenance(provenance.sourceCommit, provenance.changeSet.digest),
    };
    capabilityFixture = fixture;
    receipt = await runOrder(order, fixture, provenance);
    if (fixture.cleanupOwner === "parent-wrapper") {
      receipt.cleanup.fixtureRemoved = false;
      receipt.cleanup.fixtureRemoval = {
        owner: "parent-wrapper",
        scope: "fixture-root-only",
        child: {
          attempted: false,
          removed: false,
          observedPresentAtReceipt: existsSync(fixture.root),
          cwdInsideFixtureAtReceipt: isPathWithin(fixture.root, process.cwd()),
          activeResourcesAtReceipt: activeResourceSnapshot(),
          reason: "Process-owned SDK resources may release only when the child exits.",
        },
        parent: {
          pending: true,
          mustRunAfterChildExit: true,
        },
      };
      requireCondition(
        !receipt.cleanup.fixtureRemoval.child.cwdInsideFixtureAtReceipt,
        "SESSION_LIFECYCLE_FAILURE",
        "SDK lifecycle left process cwd inside the wrapper-owned fixture root",
        { cleanup: receipt.cleanup },
      );
    } else {
      let fixtureRemoval;
      try {
        fixtureRemoval = await removeFixtureRoot(fixture.root);
      } catch (error) {
        receipt.cleanup.fixtureRemoved = false;
        receipt.cleanup.fixtureRemoval = error?.details?.fixtureRemoval ?? {
          owner: "child",
          scope: "fixture-root-only",
          attempted: true,
          removed: false,
        };
        if (error instanceof ProbeFailure) {
          error.details = {
            ...error.details,
            cleanup: receipt.cleanup,
          };
          throw error;
        }
        throw new ProbeFailure(
          error?.code ?? "SESSION_LIFECYCLE_FAILURE",
          error?.message ?? "fixture root removal failed",
          {
            ...error?.details,
            cleanup: receipt.cleanup,
          },
        );
      }
      receipt.cleanup.fixtureRemoved = fixtureRemoval.removed;
      receipt.cleanup.fixtureRemoval = fixtureRemoval;
      requireCondition(
        !fixtureRemoval.cwd.insideFixtureBefore,
        "SESSION_LIFECYCLE_FAILURE",
        "SDK lifecycle left process cwd inside the fixture root",
        { cleanup: receipt.cleanup },
      );
    }
    receipt = redactValue(receipt, fixture);
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    const cleanupRoot = fixture?.root ?? setupRoot;
    const cleanupOwner = fixture?.cleanupOwner ?? setupCleanupOwner;
    const cleanup = {
      poolShutdown: false,
      storesClosed: false,
      sdkOwnedResourcesClosed: false,
      fixtureRemoved: false,
      leaks: [],
      storeOutcomes: [],
      sdkOwnedResourceOutcomes: [],
      sessionDisposals: [],
      ...(receipt?.cleanup ?? error?.details?.cleanup),
    };
    const cleanupErrors = [...(error?.details?.cleanupErrors ?? [])];
    let removalFailure;
    if (cleanupRoot && cleanupOwner === "parent-wrapper") {
      cleanup.fixtureRemoved = false;
      cleanup.fixtureRemoval = {
        owner: "parent-wrapper",
        scope: "fixture-root-only",
        child: {
          attempted: false,
          removed: false,
          observedPresentAtReceipt: existsSync(cleanupRoot),
          cwdInsideFixtureAtReceipt: isPathWithin(cleanupRoot, process.cwd()),
          activeResourcesAtReceipt: activeResourceSnapshot(),
          reason: "Process-owned SDK resources may release only when the child exits.",
        },
        parent: {
          pending: true,
          mustRunAfterChildExit: true,
        },
      };
    } else if (cleanupRoot && existsSync(cleanupRoot)) {
      try {
        const fixtureRemoval = await removeFixtureRoot(cleanupRoot);
        cleanup.fixtureRemoved = fixtureRemoval.removed;
        cleanup.fixtureRemoval = fixtureRemoval;
      } catch (cleanupError) {
        removalFailure = cleanupError;
        cleanup.fixtureRemoved = false;
        cleanup.fixtureRemoval = cleanupError?.details?.fixtureRemoval ?? {
          owner: "child",
          scope: "fixture-root-only",
          attempted: true,
          removed: false,
        };
        cleanupErrors.push({
          operation: "fixture-root-removal",
          code: cleanupError?.code ?? "SESSION_LIFECYCLE_FAILURE",
          error: cleanupError?.message ?? String(cleanupError),
          details: cleanupError?.details,
        });
      }
    } else if (cleanupRoot) {
      cleanup.fixtureRemoved = true;
    }
    setupRoot = undefined;
    setupCleanupOwner = undefined;
    const primaryCode = error?.code ?? "PROBE_FAILURE";
    const failureCodes = [...new Set([
      primaryCode,
      ...(removalFailure && removalFailure?.code !== primaryCode ? [removalFailure.code] : []),
    ])];
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
      failureCodes,
      error: error?.message ?? String(error),
      details: {
        ...(error?.details ?? {}),
        cleanupErrors,
      },
      cleanup,
    }, fixture ?? { root: cleanupRoot ?? "" });
    process.stdout.write(`${JSON.stringify(failure)}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.main) {
  if (process.argv.includes("--redaction-probe")) runRedactionProbe();
  else await main();
}
