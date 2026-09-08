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
import { STRICT_JSON_LIMITS } from "../../shared/strict-json.js";

function inputStream(value) {
  const stream = new PassThrough();
  stream.end(JSON.stringify(value));
  return stream;
}

function rawInputStream(value) {
  const stream = new PassThrough();
  stream.end(value);
  return stream;
}

function outputStream() {
  let text = "";
  return {
    stream: { write(chunk) { text += chunk; } },
    read() { return text; },
  };
}

async function runCli({ argv, stdin, native = null }) {
  const stdout = outputStream();
  const stderr = outputStream();
  let nativeAccesses = 0;
  const guardedNative = native ?? new Proxy({}, {
    get() {
      nativeAccesses += 1;
      throw new Error("RUNTIME_MUST_NOT_BE_INVOKED");
    },
  });
  const exitCode = await runManagementCli({
    argv,
    stdin,
    stdout: stdout.stream,
    stderr: stderr.stream,
    native: guardedNative,
  });
  return {
    exitCode,
    stdout: stdout.read(),
    stderr: stderr.read(),
    nativeAccesses,
  };
}

const mappingPreconditionsArgv = (mappingId = "map-1") => [
  "mapping-preconditions",
  "--actor-principal", "sid:S-1-5-18",
  "--actor-secret-stdin", "true",
  "--mapping-id", mappingId,
];

function assertCliError(result, exitCode, error) {
  assert.equal(result.exitCode, exitCode);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, `${JSON.stringify({ ok: false, exitCode, error })}\n`);
  assert.equal(result.nativeAccesses, 0);
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
test("management CLI represents the Genesis-empty CAS boundary explicitly", () => {
  const parsed = parseManagementArgs([
    "mapping-reconcile",
    "--actor-principal", "uid:1001",
    "--actor-secret-stdin", "true",
    "--mapping-id", "map",
    "--expected-revision", "null",
    "--expected-fingerprint", "null",
    "--idempotency-key", "first-mapping",
  ]);
  assert.equal(parsed.input.expectedRevision, null);
  assert.equal(parsed.input.expectedFingerprint, null);
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

test("mapping-preconditions accepts only its exact argv grammar and preserves opaque IDs", () => {
  for (const [actorPrincipal, expectedPrincipal] of [
    ["sid:S-1-5-18", { kind: "sid", value: "S-1-5-18" }],
    ["uid:1000", { kind: "uid", value: "uid:1000" }],
  ]) {
    for (const mappingId of [
      "a",
      "a".repeat(128),
      "map.with_Every-9",
      "constructor",
      "toString",
      "hasOwnProperty",
    ]) {
      const parsed = parseManagementArgs([
        "mapping-preconditions",
        "--actor-principal", actorPrincipal,
        "--actor-secret-stdin", "true",
        "--mapping-id", mappingId,
      ]);
      assert.equal(parsed.command, "mapping-preconditions");
      assert.deepEqual(parsed.input, {
        actorPrincipal: expectedPrincipal,
        actorSecretStdin: true,
        mappingId,
      });
    }
  }

  assert.throws(
    () => parseManagementArgs([
      "mapping-preconditions",
      "--actor-principal", "sid:S-1-5-18",
      "--actor-secret-stdin", "true",
    ]),
    { message: "USAGE_MAPPING_ID_REQUIRED" },
  );
  for (const mappingId of [
    "",
    "a".repeat(129),
    ".leading",
    "_leading",
    "-leading",
    "white space",
    "é",
    "\u0000",
    "a/b",
    "a\\b",
    "a:b",
    "a%b",
    "..",
    "a/../b",
    null,
    false,
    1,
    ["map-1"],
    { value: "map-1" },
  ]) {
    assert.throws(
      () => parseManagementArgs([
        "mapping-preconditions",
        "--actor-principal", "sid:S-1-5-18",
        "--actor-secret-stdin", "true",
        "--mapping-id", mappingId,
      ]),
      { message: "USAGE_MAPPING_ID_INVALID" },
      JSON.stringify(mappingId),
    );
  }
});

test("mapping-preconditions argv failures use exact usage codes before runtime invocation", async () => {
  const cases = [
    [
      [
        "mapping-preconditions",
        "--actor-principal", "sid:S-1-5-18",
        "--actor-secret-stdin", "true",
      ],
      "USAGE_MAPPING_ID_REQUIRED",
    ],
    [[...mappingPreconditionsArgv(), "--mapping-id", "other"], "USAGE_DUPLICATE_ARGUMENT"],
    [[...mappingPreconditionsArgv(), "--idempotency-key", "forbidden"], "USAGE_INVALID_ARGUMENT"],
    [[...mappingPreconditionsArgv(), "--expected-revision", "12"], "USAGE_INVALID_ARGUMENT"],
    [[...mappingPreconditionsArgv(), "--target-principal", "sid:S-1-5-19"], "USAGE_INVALID_ARGUMENT"],
    [[...mappingPreconditionsArgv(), "--actor-secret", "forbidden"], "USAGE_INVALID_ARGUMENT"],
    [[...mappingPreconditionsArgv(), "positional", "value"], "USAGE_INVALID_ARGUMENT"],
    [["mapping-preconditions", "--actor-principal", "sid:S-1-5-18", "--actor-secret-stdin", "true", "--mapping-id"], "USAGE_INVALID_ARGUMENT"],
    [["mapping-preconditions", "--actor-principal", "sid:S-1-5-18", "--actor-secret-stdin", "false", "--mapping-id", "map-1"], "USAGE_INVALID_ARGUMENT"],
    [["mapping-preconditions", "--actor-principal", "sid:not-canonical", "--actor-secret-stdin", "true", "--mapping-id", "map-1"], "USAGE_ACTOR_PRINCIPAL_INVALID"],
    [["mapping-preconditions", "--actor-secret-stdin", "true", "--mapping-id", "map-1"], "USAGE_ACTOR_AUTH_REQUIRED"],
    [["mapping-preconditions", "--actor-principal", "sid:S-1-5-18", "--mapping-id", "map-1"], "USAGE_ACTOR_AUTH_REQUIRED"],
  ];
  for (const [argv, error] of cases) {
    const result = await runCli({
      argv,
      stdin: inputStream({ actorSecret: "owner-secret-is-long-enough" }),
    });
    assertCliError(result, EXIT.USAGE, error);
  }
  for (const mappingId of ["", ".leading", "a".repeat(129)]) {
    const result = await runCli({
      argv: mappingPreconditionsArgv(mappingId),
      stdin: inputStream({ actorSecret: "owner-secret-is-long-enough" }),
    });
    assertCliError(result, EXIT.USAGE, "USAGE_MAPPING_ID_INVALID");
  }
});

test("mapping-preconditions protected input is exactly one string actorSecret field", async () => {
  for (const value of [null, false, 1, "secret", []]) {
    const result = await runCli({
      argv: mappingPreconditionsArgv(),
      stdin: inputStream(value),
    });
    assertCliError(result, EXIT.USAGE, "USAGE_STDIN_INVALID");
  }
  for (const body of [
    { actorSecret: "owner-secret-is-long-enough", mappingId: "map-1" },
    { actorSecret: "owner-secret-is-long-enough", extra: true },
    { actorSecret: "owner-secret-is-long-enough", hostTokens: "host=secret" },
  ]) {
    const result = await runCli({
      argv: mappingPreconditionsArgv(),
      stdin: inputStream(body),
    });
    assertCliError(result, EXIT.USAGE, "USAGE_STDIN_FIELD_INVALID");
  }
  for (const actorSecret of [undefined, null, false, 1, [], {}]) {
    const body = actorSecret === undefined ? {} : { actorSecret };
    const result = await runCli({
      argv: mappingPreconditionsArgv(),
      stdin: inputStream(body),
    });
    assertCliError(result, EXIT.USAGE, "USAGE_ACTOR_SECRET_REQUIRED");
  }
});

test("mapping-preconditions preserves strict-input failures and the existing message-prefix split", async () => {
  const deep = `{"actorSecret":${"[".repeat(STRICT_JSON_LIMITS.maxDepth + 1)}"secret"${"]".repeat(STRICT_JSON_LIMITS.maxDepth + 1)}}`;
  const tooManyNodes = JSON.stringify({
    actorSecret: "owner-secret-is-long-enough",
    nodes: Array.from({ length: STRICT_JSON_LIMITS.maxNodes }, () => null),
  });
  const cases = [
    [rawInputStream(Buffer.from("{")), EXIT.INVALID, "INPUT_INVALID"],
    [rawInputStream(Buffer.from('{"actorSecret":"first","actorSecret":"second"}')), EXIT.INVALID, "INPUT_INVALID"],
    [rawInputStream(Buffer.from('{"actorSecret":"first","actor\\u0053ecret":"second"}')), EXIT.INVALID, "INPUT_INVALID"],
    [rawInputStream(Buffer.from([0xc3, 0x28])), EXIT.INVALID, "INPUT_INVALID"],
    [rawInputStream(Buffer.from('{"actorSecret":"bad\u0001text"}')), EXIT.INVALID, "INPUT_INVALID"],
    [rawInputStream(Buffer.alloc(STRICT_JSON_LIMITS.maxBytes + 1, 0x20)), EXIT.INVALID, "INPUT_INVALID"],
    [rawInputStream(Buffer.from(deep)), EXIT.INVALID, "INPUT_INVALID"],
    [rawInputStream(Buffer.from(tooManyNodes)), EXIT.INVALID, "INPUT_INVALID"],
    [{
      async *[Symbol.asyncIterator]() {
        throw new Error("stream failure contains a private path");
      },
    }, EXIT.INVALID, "INPUT_INVALID"],
    [{
      async *[Symbol.asyncIterator]() {
        throw new Error("USAGE_STREAM_SENTINEL");
      },
    }, EXIT.USAGE, "USAGE_STREAM_SENTINEL"],
  ];
  for (const [stdin, exitCode, error] of cases) {
    const result = await runCli({
      argv: mappingPreconditionsArgv(),
      stdin,
    });
    assertCliError(result, exitCode, error);
  }
});

test("valid mapping-preconditions input reaches the runtime boundary on stdout only", async () => {
  const stdout = outputStream();
  const stderr = outputStream();
  const exitCode = await runManagementCli({
    argv: mappingPreconditionsArgv(),
    stdin: inputStream({ actorSecret: "owner-secret-is-long-enough" }),
    stdout: stdout.stream,
    stderr: stderr.stream,
    native: null,
  });
  const result = JSON.parse(stdout.read());
  assert.equal(exitCode, EXIT.NATIVE);
  assert.equal(stderr.read(), "");
  assert.deepEqual(Object.keys(result).sort(), ["error", "exitCode", "ok", "routeDisposition"]);
  assert.deepEqual(result, {
    exitCode: EXIT.NATIVE,
    ok: false,
    error: "MANAGED_NATIVE_UNAVAILABLE",
    routeDisposition: "no-route",
  });
  assert.equal(stdout.read(), `${JSON.stringify(result)}\n`);
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

function runScriptedMappingPreconditionsEntrypoint({
  mappingId = "map-1",
  stateMappingId = "map-1",
  actorSecret = "owner-secret-is-long-enough",
  storedSecret = actorSecret,
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "gjc-remote-mapping-preconditions-"));
  const capturePath = join(directory, "capture.json");
  const fakeNativePath = join(directory, "fake-native.mjs");
  const bootstrapPath = join(directory, "register-loader.mjs");
  writeFileSync(bootstrapPath, `
    import { registerHooks } from "node:module";
    registerHooks({
      resolve(specifier, context, nextResolve) {
        if (specifier === "@gjc-remote/native-control") {
          return { shortCircuit: true, url: process.env.GJC_TEST_FAKE_NATIVE_URL };
        }
        return nextResolve(specifier, context);
      }
    });
  `);
  writeFileSync(fakeNativePath, `
    import { writeFileSync } from "node:fs";

    const calls = [];
    const persist = (extra = {}) => writeFileSync(
      process.env.GJC_TEST_CAPTURE_PATH,
      JSON.stringify({ calls, ...extra }),
    );
    const requiredMethods = ${JSON.stringify([
      "readManagementState",
      "compareAndSwapManagementState",
      "readManagementAuth",
      "compareAndSwapManagementAuth",
      "readManagedHistoryMarker",
      "commitManagedHistoryMarker",
      "configureManagementRoles",
      "currentOsPrincipal",
      "managementAnchorFingerprint",
      "withManagementLocks",
      "probeProspectiveCleanup",
      "writeGenesisAuthorityRequest",
      "validateGenesisAuthorityBinding",
      "writeGenesisAuthorityReceipt",
      "reserveFenceGeneration",
      "commitFenceGeneration",
      "readFenceGenerationFloor",
      "reserveAuthorityEpoch",
      "commitAuthorityEpoch",
      "writeAuthorityReservation",
      "writeAuthorityCommitSnapshot",
      "writeAuthorityBaseline",
      "writeReaderFenceBinding",
      "casReaderVersionFloor",
      "reserveTokenFloor",
      "writeTokenConfigAttestation",
      "writeAttestedTokenFloor",
      "writeGenesisRequest",
      "commitTokenFloor",
      "writePublicationGraph",
      "writeZFinality",
      "writeAdmissionRequest",
      "writeAdmissionGrant",
      "readBoundReaderProof",
      "readSuccessorTokenLineage",
      "readAuthoritySuccessorHeadRaw",
      "completePendingGenesis",
      "writeFinalityProof",
      "writeGenesisReceipt",
      "recheckAdmissionFinality",
      "publishMapping",
      "reopenAdmission",
      "revokeMapping",
      "writeMappingGeneration",
      "readMappingGeneration",
      "writeMappingTombstone",
      "writeMappingHandoffReceipt",
      "mappingTargetProof",
      "recoverGenesisSuffix",
      "appendAudit",
      "terminalCloseOrManualCleanup",
      "rotateTokenSidecar",
    ])};

    export async function createManagementNative(options) {
      const { bootstrapOwner } = await import(process.env.GJC_TEST_MANAGEMENT_AUTH_URL);
      const {
        fingerprintManagedMappingRecord,
        fingerprintManagedRouteRecord,
      } = await import(process.env.GJC_TEST_MAPPING_ENVELOPE_URL);
      const actorPrincipal = { kind: "sid", value: "S-1-5-18" };
      const mapping = fingerprintManagedMappingRecord({
        mappingId: process.env.GJC_TEST_STATE_MAPPING_ID,
        hostId: "host-A",
        fenceGeneration: 3,
        mappingGeneration: 3,
        workspaceGeneration: 2,
        mappingVersion: 1,
        sourcePlatform: "posix",
        workspaceId: "workspace-1",
        workDir: null,
        sourceRoot: "/srv/repo",
        containerRoot: "/workspace",
        volumeIdentity: "dev:42",
        casePolicy: "sensitive",
        immutableDefault: false,
      });
      const route = fingerprintManagedRouteRecord({
        channelId: "123456789",
        hostId: mapping.hostId,
        mappingId: mapping.mappingId,
        fenceGeneration: mapping.fenceGeneration,
        mappingGeneration: mapping.mappingGeneration,
        workspaceGeneration: mapping.workspaceGeneration,
        mappingVersion: mapping.mappingVersion,
        sourcePlatform: mapping.sourcePlatform,
        workspaceId: mapping.workspaceId,
        workDir: mapping.workDir,
      }, mapping);
      const authState = { auth: null };
      bootstrapOwner(authState, {
        actorPrincipal,
        osPrincipal: actorPrincipal,
        secret: process.env.GJC_TEST_STORED_SECRET,
      });
      const state = {
        version: 1,
        revision: 12,
        authorityEpoch: 7,
        fenceGeneration: 3,
        tokenConfigGeneration: 2,
        mappingGeneration: 3,
        roleBindings: structuredClone(options.roles),
        mappings: { [mapping.mappingId]: mapping },
        routes: { [route.channelId]: route },
        tokenAttestation: {
          fingerprint: "f".repeat(64),
          generation: 2,
          attestationFingerprint: "a".repeat(64),
          finalityFingerprint: "b".repeat(64),
        },
        recovery: { phase: "terminal" },
        genesis: { txId: "genesis-fixture" },
        admission: { phase: "closed", finalityFingerprint: null },
      };
      let stateReads = 0;
      let native;
      const record = (name, detail = null) => {
        calls.push(detail === null ? [name] : [name, detail]);
        persist({
          mappingFingerprint: mapping.mappingFingerprint,
          nonThenable: !Object.hasOwn(native, "then") && native.then === undefined,
          stateReads,
        });
      };
      native = {
        async runStartupSelfTest() {
          record("runStartupSelfTest");
          return { role: "management", mst: true, bst: false, writes: 0 };
        },
        async readManagementState() {
          stateReads += 1;
          record("readManagementState", stateReads);
          return structuredClone(state);
        },
        async readManagementAuth() {
          record("readManagementAuth");
          return structuredClone(authState.auth);
        },
        async configureManagementRoles(candidate) {
          record("configureManagementRoles", candidate);
          if (JSON.stringify(candidate) !== JSON.stringify(options.roles)) {
            throw new Error("ROLE_BINDING_DRIFT");
          }
        },
        async withManagementLocks(locks, callback) {
          record("withManagementLocks:start", locks);
          try {
            return await callback();
          } finally {
            record("withManagementLocks:end", locks);
          }
        },
      };
      for (const method of requiredMethods) {
        if (Object.hasOwn(native, method)) continue;
        native[method] = async () => {
          record("unexpected", method);
          throw new Error("UNEXPECTED_NATIVE_METHOD");
        };
      }
      persist({
        mappingFingerprint: mapping.mappingFingerprint,
        nonThenable: !Object.hasOwn(native, "then") && native.then === undefined,
        stateReads,
      });
      return native;
    }
  `);
  const roles = JSON.stringify({
    managementSid: "S-1-5-18",
    botSid: "S-1-5-19",
    recoverySid: "S-1-5-20",
    systemSid: "S-1-5-18",
  });
  try {
    const result = spawnSync(process.execPath, [
      "--import", pathToFileURL(bootstrapPath).href,
      "src/management-entrypoint.js",
      ...mappingPreconditionsArgv(mappingId),
    ], {
      cwd: fileURLToPath(new URL("../", import.meta.url)),
      encoding: "utf8",
      timeout: 30000,
      maxBuffer: 1024 * 1024,
      input: JSON.stringify({ actorSecret }),
      env: {
        ...process.env,
        GJC_MANAGEMENT_ROLE_BINDINGS: roles,
        GJC_TEST_CAPTURE_PATH: capturePath,
        GJC_TEST_FAKE_NATIVE_URL: pathToFileURL(fakeNativePath).href,
        GJC_TEST_MANAGEMENT_AUTH_URL: pathToFileURL(fileURLToPath(new URL("../src/management-auth.js", import.meta.url))).href,
        GJC_TEST_MAPPING_ENVELOPE_URL: pathToFileURL(fileURLToPath(new URL("../../shared/mapping-envelope.js", import.meta.url))).href,
        GJC_TEST_STATE_MAPPING_ID: stateMappingId,
        GJC_TEST_STORED_SECRET: storedSecret,
      },
    });
    return {
      ...result,
      capture: (() => {
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

function readEntrypointResult(result) {
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /^[^\r\n]+\n$/);
  return JSON.parse(result.stdout);
}

function recordCliObservation(t, mappingId, child) {
  t.diagnostic(JSON.stringify({
    completedAt: new Date().toISOString(),
    command: "mapping-preconditions",
    mappingId,
    exitCode: child.status,
    stdout: child.stdout,
  }));
}

test("scripted non-thenable child native reaches exact mapping-preconditions success", (t) => {
  for (const [mappingId, stateMappingId, expectedFingerprint] of [
    ["map-1", "map-1", "present"],
    ["missing-map", "map-1", null],
    ["constructor", "constructor", "present"],
  ]) {
    const child = runScriptedMappingPreconditionsEntrypoint({ mappingId, stateMappingId });
    const result = readEntrypointResult(child);
    assert.equal(child.status, EXIT.OK);
    assert.deepEqual(Object.keys(result).sort(), [
      "exitCode",
      "expectedFingerprint",
      "expectedRevision",
      "mappingId",
      "ok",
      "routeDisposition",
    ]);
    assert.deepEqual(result, {
      exitCode: EXIT.OK,
      ok: true,
      mappingId,
      expectedRevision: 12,
      expectedFingerprint: expectedFingerprint === "present" ? child.capture.mappingFingerprint : null,
      routeDisposition: "no-route",
    });
    assert.equal(child.capture.nonThenable, true);
    assert.deepEqual(child.capture.calls.map(([name]) => name), [
      "runStartupSelfTest",
      "readManagementState",
      "configureManagementRoles",
      "withManagementLocks:start",
      "readManagementState",
      "readManagementAuth",
      "withManagementLocks:end",
    ]);
    assert.deepEqual(child.capture.calls[3][1], ["mapping"]);
    assert.deepEqual(child.capture.calls[6][1], ["mapping"]);
    assert.equal(child.capture.stateReads, 2);
    recordCliObservation(t, mappingId, child);
  }
});

test("mapping-preconditions child preserves code-unit minimum and UTF-8 byte maximum", (t) => {
  const validAstralSecret = "𐐀".repeat(8);
  assert.equal(validAstralSecret.length, 16);
  for (const actorSecret of [validAstralSecret, "x".repeat(4096)]) {
    const valid = runScriptedMappingPreconditionsEntrypoint({
      actorSecret,
      storedSecret: actorSecret,
    });
    const validResult = readEntrypointResult(valid);
    assert.equal(valid.status, EXIT.OK);
    assert.equal(validResult.ok, true);
    recordCliObservation(t, "map-1", valid);
  }

  const invalidSecrets = [
    "x".repeat(15),
    `${"𐐀".repeat(7)}x`,
    "é".repeat(2049),
  ];
  assert.equal(invalidSecrets[1].length, 15);
  assert.ok(Buffer.byteLength(invalidSecrets[2], "utf8") > 4096);
  for (const actorSecret of invalidSecrets) {
    const child = runScriptedMappingPreconditionsEntrypoint({
      actorSecret,
      storedSecret: "owner-secret-is-long-enough",
    });
    const result = readEntrypointResult(child);
    assert.equal(child.status, EXIT.AUTH);
    assert.deepEqual(Object.keys(result).sort(), ["error", "exitCode", "ok", "routeDisposition"]);
    assert.deepEqual(result, {
      exitCode: EXIT.AUTH,
      ok: false,
      error: "AUTH_SECRET_INVALID",
      routeDisposition: "no-route",
    });
    assert.equal(child.stdout.includes(actorSecret), false);
    recordCliObservation(t, "map-1", child);
  }
});

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
