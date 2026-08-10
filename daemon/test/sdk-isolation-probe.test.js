import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, mkdir, rename, unlink, writeFile } from "node:fs/promises";
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
  return env;
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

function sanitize(value) {
  if (typeof value === "string") {
    return value
      .replace(/(?:https?|wss?):\/\/[^\s"']+/gi, "<url-redacted>")
      .replace(/[A-Za-z]:\\[^\s"']+/g, "<path-redacted>")
      .replace(/\b[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|OAUTH|PASSWORD|AUTHORIZATION|COOKIE|BROKER|CREDENTIAL|SECRET|TOKEN)\b/gi, "<secret-redacted>")
      .replace(/\b[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|OAUTH|PASSWORD|AUTHORIZATION|COOKIE|BROKER|CREDENTIAL|SECRET|TOKEN)\b\s*[:=]\s*["']?[^\s"',;}]+/gi, "<secret-redacted>")
      .replace(/\b(?:api.?key|access.?token|refresh.?token|password|authorization|cookie|credential|broker|secret|oauth|token)\b\s*[:=]\s*["']?[^\s"',;}]+/gi, "<secret-redacted>")
      .replace(/\b(?:api.?key|access.?token|refresh.?token|password|authorization|cookie|credential|broker|secret|oauth|token)\b[^\s,;]*/gi, "<secret-redacted>")
      .replace(/(?:api.?key|access.?token|refresh.?token|password|authorization|cookie|credential|broker|secret|oauth|token)/gi, "<secret-redacted>")
      .replace(/<+secret-redacted>(?:-redacted>)*/g, "<secret-redacted>")
      .slice(0, 512);
  }
  if (Array.isArray(value)) return value.slice(0, 32).map(sanitize);
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      if (secretKey.test(key)) continue;
      output[key] = sanitize(item);
    }
    return output;
  }
  return value;
}

function parseReceipt(stdout) {
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
  assert.fail(`Bun fixture emitted no structured receipt: ${sanitize(lines.at(-1))}`);
}

async function spawnFixture(order) {
  const env = stableEnv(order);
  await mkdir(env.HOME, { recursive: true });
  await mkdir(env.TMP, { recursive: true });
  return new Promise((resolveResult, reject) => {
    const bun = process.env.BUN_BIN || "bun";
    const child = spawn(bun, [fixture, `--order=${order}`, "--json"], {
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

async function validateReceipt(receipt, order) {
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
  assert.notEqual(receipt.liveWorkDirs[0], receipt.liveWorkDirs[1]);
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
  assert.equal(receipt.negativeCases.cRegistryBoundary, "nonmatching-enabledModels");
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
}

async function writeReceiptArtifact(name, receipt) {
  const sanitized = sanitize({ ...receipt, artifactName: name });
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
  await unlink(target).catch(() => {});
  await mkdir(artifactsDir, { recursive: true });
  const result = await spawnFixture(order);
  const receipt = parseReceipt(result.stdout);
  assert.equal(result.code, 0, `${order} fixture failed (${result.signal}): ${sanitize(result.stderr)}\n${sanitize(receipt.error ?? "")}`);
  await validateReceipt(receipt, order);
  await writeReceiptArtifact(name, { ...receipt, nodeWrapperVersion: process.version });
  return receipt;
}

test("issue #62 real SDK divergent-session probe", async () => {
  assert.ok(existsSync(fixture), `missing Bun fixture ${fixture}`);
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  assert.ok(Number.isInteger(nodeMajor) && nodeMajor >= 26, `Node >=26 required, observed ${process.version}`);
  await runOrder("A,B");
  await runOrder("B,A");
});
