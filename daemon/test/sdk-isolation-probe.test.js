import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, mkdir, rename, rm, unlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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
const SDK_VERSION = "0.12.21";
const MAX_RECEIPT_BYTES = 100_000;
const MAX_TIMEOUT_MS = 90_000;
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


function stableEnv(order) {
  const allowed = new Set([
    "PATH", "Path", "SystemRoot", "WINDIR", "ComSpec", "COMSPEC", "PATHEXT",
    "BUN_INSTALL", "ProgramFiles", "PROGRAMFILES", "ProgramFiles(x86)", "CommonProgramFiles",
    "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "HOMEDRIVE", "HOMEPATH", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "OS", "LANG", "LC_ALL",
  ]);
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (allowed.has(key) && value) env[key] = value;
  const root = join(tmpdir(), `issue62-wrapper-${process.pid}-${order.replace(",", "-")}`);
  env.HOME = root;
  env.USERPROFILE = root;
  env.TEMP = join(root, "tmp");
  env.TMP = join(root, "tmp");
  return { env, roots: [root, join(root, "tmp")] };
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

async function spawnBun(args, envInfo) {
  const { env } = envInfo;
  await mkdir(env.HOME, { recursive: true });
  await mkdir(env.TMP, { recursive: true });
  return new Promise((resolveResult, reject) => {
    const bun = process.env.BUN_BIN || "bun";
    const child = spawn(bun, [fixture, ...args], {
      cwd: repoRoot,
      env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
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
      clearTimeout(timer);
      if (!settled) { settled = true; reject(error); }
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      resolveResult({ code, signal, stdout, stderr });
    });
  });
}

async function spawnFixture(order, envInfo) {
  return spawnBun([`--order=${order}`, "--json"], envInfo);
}

async function spawnRedactionProbe() {
  const envInfo = stableEnv("redaction-probe");
  try {
    return await spawnBun(["--redaction-probe"], envInfo);
  } finally {
    await removeWrapperRoot(envInfo.roots[0]);
  }
}

async function removeWrapperRoot(root) {
  let lastError;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      await rm(root, { recursive: true, force: true });
      return;
    } catch (error) {
      lastError = error;
      if (error?.code !== "EBUSY" && error?.code !== "EPERM") throw error;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  throw lastError;
}

async function validateReceipt(receipt, order, roots = []) {
  assert.equal(receipt.issue, 62);
  assert.equal(receipt.approvedBaseCommit, BASE_COMMIT);
  assert.match(receipt.sourceCommit, /^[0-9a-f]{40}$/);
  assert.equal(receipt.sdkVersionExpected, SDK_VERSION);
  assert.equal(receipt.sdkVersionObserved, SDK_VERSION);
  assert.equal(receipt.daemonDependencyVersion, SDK_VERSION);
  assert.equal(receipt.lockfileVersionEvidence, SDK_VERSION);
  assert.match(receipt.bunVersion, /^1\.([3-9]|[1-9]\d)\.\d+$/);
  assert.deepEqual(receipt.order, order.split(","));
  assert.deepEqual(receipt.changeSet.files, CHANGE_FILES);
  assert.equal(receipt.changeSet.algorithm, "sha256");
  assert.match(receipt.changeSet.digest, /^[0-9a-f]{64}$/);
  assert.equal(receipt.changeSet.digest, await orderedChangeDigest());
  assert.ok(Array.isArray(receipt.runner.argv));
  assert.equal(receipt.runner.command, receipt.runner.argv.join(" "));
  assert.equal(receipt.runner.argv.at(-2), `--order=${order}`);
  assert.equal(receipt.runner.argv.at(-1), "--json");
  assert.equal(receipt.runner.orderCommand, `--order=${order}`);
  assert.equal(receipt.globalSettingsBootstrap.initCalls, 1);
  assert.equal(receipt.globalSettingsBootstrap.initialized, true);
  assert.equal(receipt.globalSettingsBootstrap.networkPrewarm, false);
  assert.equal(receipt.liveSessionCount, 2);
  assert.equal(receipt.liveWorkDirs.length, 2);
  assert.deepEqual(receipt.liveWorkDirLabels, ["A", "B"]);
  assert.equal(receipt.cPreSessionCandidates, 0);
  assert.equal(receipt.modelFallback, false);
  assert.deepEqual(receipt.failureCodes, []);
  assert.equal(receipt.preconnectGuard.available, true);
  assert.deepEqual(receipt.preconnectGuard.events, []);
  assert.equal(receipt.preconnectGuard.observed, false);
  assert.equal(receipt.networkPrewarm.global, false);
  assert.equal(receipt.networkPrewarm.A, false);
  assert.equal(receipt.networkPrewarm.B, false);
  assert.equal(receipt.networkPrewarm.C, false);
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
  assert.deepEqual(new Set(receipt.fixturePolicy.C.disabledProviders), new Set(["ollama", "llama.cpp", "lm-studio"]));
  assert.equal(receipt.fixturePolicy.C.disabledProviders.includes("issue62-provider-a"), false);
  assert.equal(receipt.fixturePolicy.C.disabledProviders.includes("issue62-provider-b"), false);
  assert.equal(receipt.canonicalVariants.variants.length, 2);
  assert.deepEqual(new Set(receipt.canonicalVariants.variants), new Set(["issue62-provider-a/issue62-model-a", "issue62-provider-b/issue62-model-b"]));
  assert.equal(receipt.capability.sessionReads.length, 2);
  for (const read of receipt.capability.sessionReads) {
    assert.equal(read.explicit.items.length, 1);
    assert.equal(read.cwdFallback.items.length, 1);
    assert.ok(read.explicit.items[0].source.provider);
    assert.ok(read.explicit.items[0].source.providerName);
    assert.ok(read.explicit.items[0].source.path.startsWith("<"));
    assert.equal(read.explicit.items[0].source.level, "project");
  }
  const labels = new Set(receipt.model.sessions.map(item => item.label));
  assert.deepEqual(labels, new Set(["A", "B"]));
  for (const session of receipt.model.sessions) {
    assert.equal(session.activeModel, session.label === "A" ? "issue62-provider-a/issue62-model-a" : "issue62-provider-b/issue62-model-b");
  }
  assert.notEqual(receipt.registryClassification.resolvedProvider, "UNKNOWN");
  assert.notEqual(receipt.registryClassification.providerOrder, "UNKNOWN");
  for (const snapshot of [receipt.registrySnapshots.seed, receipt.registrySnapshots.afterFirst, receipt.registrySnapshots.afterSecond, receipt.registrySnapshots.final]) {
    assert.ok(["issue62-provider-a", "issue62-provider-b"].includes(snapshot.resolvedProvider));
    assert.ok(["issue62-provider-a/issue62-model-a", "issue62-provider-b/issue62-model-b"].includes(snapshot.resolvedSelector));
  }
  assert.equal(receipt.cleanup.poolShutdown, true);
  assert.equal(receipt.cleanup.storesClosed, true);
  assert.equal(receipt.cleanup.fixtureRemoved, true);
  assert.deepEqual(receipt.cleanup.leaks, []);
  assert.equal(receipt.cleanup.storeOutcomes.length, 5);
  assert.ok(receipt.cleanup.storeOutcomes.every(outcome => outcome.closed));
  assert.equal(receipt.artifactName, null);
  assert.match(receipt.customFactoryBoundary, /profile activation/);
  assert.equal(receipt.coverage.auth, "empty-fixture-auth-storage-only");
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
  const envInfo = stableEnv(order);
  try {
    await unlink(target).catch(() => {});
    await mkdir(artifactsDir, { recursive: true });
    const result = await spawnFixture(order, envInfo);
    const receipt = parseReceipt(result.stdout, envInfo.roots);
    const failureReceipt = sanitize({
      error: receipt.error ?? null,
      details: receipt.details ?? {},
      cleanup: receipt.cleanup ?? {},
    }, envInfo.roots);
    const sanitizedStderr = sanitize(result.stderr, envInfo.roots);
    assertNoRawPaths(failureReceipt, envInfo.roots);
    assertNoRawPaths(sanitizedStderr, envInfo.roots);
    assert.equal(result.code, 0, `${order} fixture failed (${result.signal}): ${sanitizedStderr}\nSanitized receipt diagnostics: ${JSON.stringify(failureReceipt)}`);
    await validateReceipt(receipt, order, envInfo.roots);
    await writeReceiptArtifact(name, { ...receipt, nodeWrapperVersion: process.version }, envInfo.roots);
    return receipt;
  } finally {
    await removeWrapperRoot(envInfo.roots[0]);
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
test("issue #62 real SDK divergent-session probe", async () => {
  assert.ok(existsSync(fixture), `missing Bun fixture ${fixture}`);
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  assert.ok(Number.isInteger(nodeMajor) && nodeMajor >= 26, `Node >=26 required, observed ${process.version}`);
  await runOrder("A,B");
  await runOrder("B,A");
});
