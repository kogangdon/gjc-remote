import assert from "node:assert/strict";
import test from "node:test";
import { PassThrough } from "node:stream";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parseManagementArgs, runManagementCli } from "../src/management-cli.js";
import { EXIT } from "../src/management-runtime.js";

function inputStream(value) {
  const stream = new PassThrough();
  stream.end(JSON.stringify(value));
  return stream;
}

function outputStream() {
  let text = "";
  return {
    stream: { write(chunk) { text += chunk; } },
    read() { return text; },
  };
}

test("management CLI separates actor and target principals", () => {
  const parsed = parseManagementArgs([
    "auth-add",
    "--actor-principal", "sid:S-1-5-18",
    "--actor-secret-stdin", "true",
    "--target-principal", "sid:S-1-5-19",
    "--target-secret-stdin", "true",
    "--idempotency-key", "auth-add-001",
  ]);

  assert.deepEqual(parsed.input.actorPrincipal, { kind: "sid", value: "S-1-5-18" });
  assert.deepEqual(parsed.input.targetPrincipal, { kind: "sid", value: "S-1-5-19" });
  assert.notDeepEqual(parsed.input.actorPrincipal, parsed.input.targetPrincipal);
});

test("management CLI preserves canonical Linux UID argv values", () => {
  const parsed = parseManagementArgs([
    "auth-add",
    "--actor-principal", "uid:1000",
    "--actor-secret-stdin", "true",
    "--target-principal", "uid:1001",
    "--target-secret-stdin", "true",
    "--idempotency-key", "auth-add-uid-001",
  ]);

  assert.deepEqual(parsed.input.actorPrincipal, { kind: "uid", value: "uid:1000" });
  assert.deepEqual(parsed.input.targetPrincipal, { kind: "uid", value: "uid:1001" });
  for (const value of ["uid:01", "uid:4294967296", "uid:uid:1000", "sid:operator", "sid:S-1-05-18", "uid:1000:extra"]) {
    assert.throws(() => parseManagementArgs(["status", "--actor-principal", value, "--actor-secret-stdin", "true"]), /USAGE_ACTOR_PRINCIPAL_INVALID/);
  }
});

test("management CLI rejects secrets in argv", () => {
  assert.throws(
    () => parseManagementArgs([
      "status",
      "--actor-principal", "sid:S-1-5-18",
      "--actor-secret", "do-not-accept-this",
    ]),
    /USAGE_INVALID_ARGUMENT/
  );
});
test("management CLI accepts idempotency keys for successor and auth mutations and rejects missing, duplicate, unknown, and secret argv flags", () => {
  const auth = ["--actor-principal", "sid:S-1-5-18", "--actor-secret-stdin", "true"];
  const key = ["--idempotency-key", "successor-001"];
  for (const argv of [
    ["tokens-attest", ...auth, "--host-tokens-stdin", "true", ...key],
    ["mapping-reconcile", ...auth, "--mapping-id", "map", "--expected-revision", "12", "--expected-fingerprint", "a".repeat(64), ...key],
    ["mapping-revoke", ...auth, "--mapping-id", "map", "--expected-revision", "12", "--expected-fingerprint", "a".repeat(64), ...key],
    ["mapping-rollback", ...auth, "--mapping-id", "map", "--replacement-mapping-id", "replacement", "--expected-revision", "12", "--expected-fingerprint", "a".repeat(64), "--prior-generation", "2", ...key],
    ["recover", ...auth, ...key],
    ["auth-add", ...auth, "--target-principal", "sid:S-1-5-19", "--target-secret-stdin", "true", ...key],
    ["auth-rotate", ...auth, "--target-principal", "sid:S-1-5-19", "--target-secret-stdin", "true", ...key],
    ["auth-revoke", ...auth, "--target-principal", "sid:S-1-5-19", ...key],
  ]) {
    assert.equal(parseManagementArgs(argv).input.idempotencyKey, "successor-001");
  }
  for (const command of ["auth-add", "auth-rotate", "auth-revoke"]) {
    assert.throws(() => parseManagementArgs([
      command,
      ...auth,
      "--target-principal", "sid:S-1-5-19",
      ...(command === "auth-revoke" ? [] : ["--target-secret-stdin", "true"]),
    ]), /USAGE_IDEMPOTENCY_KEY_REQUIRED/);
  }
  assert.throws(() => parseManagementArgs(["tokens-attest", ...auth, "--host-tokens-stdin", "true"]), /USAGE_IDEMPOTENCY_KEY_REQUIRED/);
  assert.throws(() => parseManagementArgs(["recover", ...auth]), /USAGE_IDEMPOTENCY_KEY_REQUIRED/);
  assert.throws(() => parseManagementArgs(["status", ...auth, "--actor-secret-stdin", "true"]), /USAGE_DUPLICATE_ARGUMENT/);
  assert.throws(() => parseManagementArgs(["status", ...auth, "--mapping-id", "unexpected"]), /USAGE_INVALID_ARGUMENT/);
  assert.throws(() => parseManagementArgs(["tokens-attest", ...auth, "--host-tokens", "secret", ...key]), /USAGE_INVALID_ARGUMENT/);
  assert.throws(() => parseManagementArgs(["mapping-reconcile", ...auth, "--mapping-id", "map", "--expected-revision", "01", "--expected-fingerprint", "a".repeat(64), ...key]), /USAGE_EXPECTED_REVISION_INVALID/);
});
test("management CLI requires an explicit bound reader tuple and rollback generation", () => {
  const auth = ["--actor-principal", "sid:S-1-5-18", "--actor-secret-stdin", "true"];
  assert.throws(() => parseManagementArgs(["genesis", ...auth, "--idempotency-key", "genesis-001", "--requested-reader-mode", "handshake"]), /USAGE_GENESIS_ROLES_REQUIRED|USAGE_READER_BINDING_INVALID/);
  assert.throws(() => parseManagementArgs(["mapping-rollback", ...auth, "--idempotency-key", "rollback-001", "--mapping-id", "map", "--expected-revision", "1", "--expected-fingerprint", "a".repeat(64)]), /USAGE_ROLLBACK_TARGET_REQUIRED/);
  assert.throws(() => parseManagementArgs(["mapping-rollback", ...auth, "--idempotency-key", "rollback-001", "--mapping-id", "map", "--replacement-mapping-id", "replacement", "--expected-revision", "1", "--expected-fingerprint", "a".repeat(64), "--prior-generation", "0"]), /USAGE_PRIOR_GENERATION_INVALID/);
  const rollback = parseManagementArgs(["mapping-rollback", ...auth, "--idempotency-key", "rollback-001", "--mapping-id", "map", "--replacement-mapping-id", "replacement", "--expected-revision", "1", "--expected-fingerprint", "a".repeat(64), "--prior-generation", "2"]);
  assert.equal(rollback.input.priorGeneration, 2);
  assert.equal(rollback.input.replacementMappingId, "replacement");
});

test("management CLI consumes protected input and redacts unavailable-native output", async () => {
  const stdout = outputStream();
  const stderr = outputStream();
  const secret = "owner-secret-is-long-enough";
  const exitCode = await runManagementCli({
    argv: [
      "genesis",
      "--actor-principal", "sid:S-1-5-18",
      "--actor-secret-stdin", "true",
      "--target-principal", "sid:S-1-5-19",
      "--bot-principal", "sid:S-1-5-20",
      "--recovery-principal", "sid:S-1-5-21",
      "--management-provisioning-fingerprint", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "--bot-provisioning-fingerprint", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "--recovery-provisioning-fingerprint", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "--host-tokens-stdin", "true",
      "--idempotency-key", "bootstrap-1",
    ],
    stdin: inputStream({
      actorSecret: secret,
      hostTokens: "host=token-secret",
    }),
    stdout: stdout.stream,
    stderr: stderr.stream,
    native: null,
  });

  assert.equal(exitCode, EXIT.NATIVE);
  assert.match(stdout.read(), /MANAGED_NATIVE_UNAVAILABLE/);
  assert.doesNotMatch(stdout.read(), /owner-secret|token-secret/);
  assert.equal(stderr.read(), "");
});
test("management CLI accepts the documented token and successor-recovery argv and stdin forms", async () => {
  const cases = [
    {
      argv: [
        "tokens-attest",
        "--actor-principal", "uid:1000",
        "--idempotency-key", "token-rotation-001",
        "--actor-secret-stdin", "true",
        "--host-tokens-stdin", "true",
      ],
      stdin: { actorSecret: "owner-secret-is-long-enough", hostTokens: "host-a=token-secret\nhost-b=token-secret" },
    },
    {
      argv: [
        "recover",
        "--actor-principal", "uid:1000",
        "--idempotency-key", "recovery-001",
        "--actor-secret-stdin", "true",
      ],
      stdin: { actorSecret: "owner-secret-is-long-enough" },
    },
  ];
  for (const documented of cases) {
    const stdout = outputStream();
    const stderr = outputStream();
    const exitCode = await runManagementCli({
      ...documented,
      stdin: inputStream(documented.stdin),
      stdout: stdout.stream,
      stderr: stderr.stream,
      native: null,
    });
    assert.equal(exitCode, EXIT.NATIVE);
    assert.match(stdout.read(), /MANAGED_NATIVE_UNAVAILABLE/);
    assert.equal(stderr.read(), "");
  }
});
test("management CLI rejects obsolete mapping recovery input for public recover", async () => {
  const stdout = outputStream();
  const stderr = outputStream();
  const exitCode = await runManagementCli({
    argv: ["recover", "--actor-principal", "uid:1000", "--idempotency-key", "recovery-001", "--actor-secret-stdin", "true"],
    stdin: inputStream({ actorSecret: "owner-secret-is-long-enough", mapping: { mappingId: "obsolete" } }),
    stdout: stdout.stream,
    stderr: stderr.stream,
    native: null,
  });

  assert.equal(exitCode, EXIT.USAGE);
  assert.match(stderr.read(), /USAGE_STDIN_FIELD_INVALID/);
  assert.equal(stdout.read(), "");
});

function runFreshManagementEntrypoint({ command, roles, expectedRoles }) {
  const directory = mkdtempSync(join(tmpdir(), "gjc-remote-management-entrypoint-"));
  const capturePath = join(directory, "roles.json");
  const fakeNativePath = join(directory, "fake-native.mjs");
  const loaderSource = `
    export async function resolve(specifier, context, nextResolve) {
      if (specifier === "@gjc-remote/native-control") {
        return { shortCircuit: true, url: process.env.GJC_TEST_FAKE_NATIVE_URL };
      }
      return nextResolve(specifier, context);
    }
  `;
  writeFileSync(fakeNativePath, `
    import { writeFileSync } from "node:fs";
    export async function createManagementNative(options) {
      writeFileSync(process.env.GJC_TEST_ROLE_CAPTURE, JSON.stringify(options.roles));
      if (JSON.stringify(options.roles) !== process.env.GJC_TEST_EXPECTED_ROLES) return null;
      return new Proxy({}, { get: () => async () => undefined });
    }
  `);
  const loaderPath = join(directory, "native-loader.mjs");
  writeFileSync(loaderPath, loaderSource);
  try {
    const result = spawnSync(process.execPath, [
      "--experimental-loader", pathToFileURL(loaderPath).href,
      "src/management-entrypoint.js",
      command,
      "--actor-principal", "sid:S-1-5-18",
      "--actor-secret-stdin", "true",
    ], {
      cwd: fileURLToPath(new URL("../", import.meta.url)),
      encoding: "utf8",
      input: JSON.stringify({ actorSecret: "owner-secret-is-long-enough" }),
      env: {
        ...process.env,
        ...(roles === undefined ? { GJC_MANAGEMENT_ROLE_BINDINGS: "" } : { GJC_MANAGEMENT_ROLE_BINDINGS: roles }),
        GJC_TEST_EXPECTED_ROLES: expectedRoles,
        GJC_TEST_FAKE_NATIVE_URL: pathToFileURL(fakeNativePath).href,
        GJC_TEST_ROLE_CAPTURE: capturePath,
      },
    });
    return {
      ...result,
      capturedRoles: (() => {
        try {
          return JSON.parse(readFileSync(capturePath, "utf8"));
        } catch {
          return null;
        }
      })(),
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("fresh management status and recover construct native with exact trusted role bindings", () => {
  const roles = JSON.stringify({
    managementSid: "S-1-5-21-100",
    botSid: "S-1-5-21-101",
    recoverySid: "S-1-5-21-102",
    systemSid: "S-1-5-18",
  });
  for (const command of ["status", "recover"]) {
    const result = runFreshManagementEntrypoint({ command, roles, expectedRoles: roles });
    assert.equal(result.error, undefined);
    assert.deepEqual(result.capturedRoles, JSON.parse(roles));
    assert.doesNotMatch(result.stdout, /MANAGED_NATIVE_UNAVAILABLE/);
  }
});

test("fresh management entrypoint refuses missing, malformed, and swapped role bindings", () => {
  const expectedRoles = JSON.stringify({
    managementSid: "S-1-5-21-100",
    botSid: "S-1-5-21-101",
    recoverySid: "S-1-5-21-102",
    systemSid: "S-1-5-18",
  });
  for (const roles of [
    undefined,
    "{",
    JSON.stringify({
      managementSid: "S-1-5-21-101",
      botSid: "S-1-5-21-100",
      recoverySid: "S-1-5-21-102",
      systemSid: "S-1-5-18",
    }),
  ]) {
    const result = runFreshManagementEntrypoint({ command: "status", roles, expectedRoles });
    assert.equal(result.error, undefined);
    assert.match(result.stdout, /MANAGED_NATIVE_UNAVAILABLE/);
  }
});
