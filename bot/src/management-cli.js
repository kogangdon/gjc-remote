import { assertStrictText, parseStrictJsonBytes, STRICT_JSON_LIMITS } from "@gjc-remote/shared/strict-json";
import { isPrincipal } from "@gjc-remote/shared/identity";
import { ManagementRuntime, EXIT } from "./management-runtime.js";

const COMMANDS = new Set(["genesis", "mapping-validate", "mapping-snapshot", "mapping-reconcile", "mapping-revoke", "mapping-rollback", "tokens-attest", "auth-add", "auth-rotate", "auth-revoke", "recover", "status"]);
const SUCCESSOR_COMMANDS = new Set(["genesis", "mapping-reconcile", "mapping-revoke", "mapping-rollback", "tokens-attest", "recover"]);
const SECRET_FLAGS = new Set(["--actor-secret", "--target-secret", "--host-tokens", "--audit-file", "--state-path"]);
const COMMON_FLAGS = new Set(["--actor-principal", "--actor-secret-stdin"]);
const COMMAND_FLAGS = Object.freeze({
  genesis: new Set(["--target-principal", "--bot-principal", "--recovery-principal", "--management-provisioning-fingerprint", "--bot-provisioning-fingerprint", "--recovery-provisioning-fingerprint", "--idempotency-key", "--requested-reader-mode", "--reader-instance-id", "--reader-start-nonce", "--host-tokens-stdin"]),
  "mapping-validate": new Set(),
  "mapping-snapshot": new Set(),
  "mapping-reconcile": new Set(["--mapping-id", "--expected-revision", "--expected-fingerprint", "--idempotency-key"]),
  "mapping-revoke": new Set(["--mapping-id", "--expected-revision", "--expected-fingerprint", "--idempotency-key"]),
  "mapping-rollback": new Set(["--mapping-id", "--replacement-mapping-id", "--expected-revision", "--expected-fingerprint", "--prior-generation", "--idempotency-key"]),
  "tokens-attest": new Set(["--host-tokens-stdin", "--idempotency-key"]),
  "auth-add": new Set(["--target-principal", "--target-secret-stdin"]),
  "auth-rotate": new Set(["--target-principal", "--target-secret-stdin"]),
  "auth-revoke": new Set(["--target-principal"]),
  recover: new Set(["--idempotency-key"]),
  status: new Set(),
});
const flagName = (flag) => flag.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
function parsePrincipal(value, field) {
  if (typeof value !== "string") throw new Error(`USAGE_${field}_INVALID`);
  const principal = value.startsWith("uid:")
    ? { kind: "uid", value }
    : value.startsWith("sid:")
      ? { kind: "sid", value: value.slice(4) }
      : null;
  if (!isPrincipal(principal)) throw new Error(`USAGE_${field}_INVALID`);
  return principal;
}

const PROTECTED_FIELDS = new Set([
  "actorSecret",
  "targetSecret",
  "hostTokens",
  "mapping",
  "mappingId",
  "expectedFingerprint",
  "idempotencyKey",
  "routes",
]);
export function parseManagementArgs(argv) {
  const [command, ...rest] = argv;
  if (!COMMANDS.has(command)) throw new Error("USAGE_INVALID_COMMAND");
  const input = {};
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index]; const value = rest[index + 1];
    if (!flag?.startsWith("--") || value === undefined || SECRET_FLAGS.has(flag) || (!COMMON_FLAGS.has(flag) && !COMMAND_FLAGS[command].has(flag))) throw new Error("USAGE_INVALID_ARGUMENT");
    const name = flagName(flag);
    if (Object.hasOwn(input, name)) throw new Error("USAGE_DUPLICATE_ARGUMENT");
    if (flag === "--host-tokens-stdin" || flag === "--actor-secret-stdin" || flag === "--target-secret-stdin") { if (value !== "true") throw new Error("USAGE_INVALID_ARGUMENT"); input[name] = true; continue; }
    input[name] = value;
  }
  if (!input.actorPrincipal || !input.actorSecretStdin) throw new Error("USAGE_ACTOR_AUTH_REQUIRED");
  input.actorPrincipal = parsePrincipal(input.actorPrincipal, "ACTOR_PRINCIPAL");
  if (input.targetPrincipal) input.targetPrincipal = parsePrincipal(input.targetPrincipal, "TARGET_PRINCIPAL");
  if (input.botPrincipal) input.botPrincipal = parsePrincipal(input.botPrincipal, "BOT_PRINCIPAL");
  if (input.recoveryPrincipal) input.recoveryPrincipal = parsePrincipal(input.recoveryPrincipal, "RECOVERY_PRINCIPAL");
  if (input.expectedRevision !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(input.expectedRevision)) throw new Error("USAGE_EXPECTED_REVISION_INVALID");
    input.expectedRevision = Number(input.expectedRevision);
    if (!Number.isSafeInteger(input.expectedRevision)) throw new Error("USAGE_EXPECTED_REVISION_INVALID");
  }
  if (input.priorGeneration !== undefined) {
    if (!/^[1-9][0-9]*$/.test(input.priorGeneration)) throw new Error("USAGE_PRIOR_GENERATION_INVALID");
    input.priorGeneration = Number(input.priorGeneration);
    if (!Number.isSafeInteger(input.priorGeneration)) throw new Error("USAGE_PRIOR_GENERATION_INVALID");
  }
  if (SUCCESSOR_COMMANDS.has(command) && (typeof input.idempotencyKey !== "string" || input.idempotencyKey.length === 0)) throw new Error("USAGE_IDEMPOTENCY_KEY_REQUIRED");
  if (command === "genesis" && (!input.targetPrincipal || !input.botPrincipal || !input.recoveryPrincipal || !/^[a-f0-9]{64}$/.test(input.managementProvisioningFingerprint ?? "") || !/^[a-f0-9]{64}$/.test(input.botProvisioningFingerprint ?? "") || !/^[a-f0-9]{64}$/.test(input.recoveryProvisioningFingerprint ?? ""))) throw new Error("USAGE_GENESIS_ROLES_REQUIRED");
  if (command === "genesis" && input.requestedReaderMode !== undefined &&
      (input.requestedReaderMode !== "no-reader" && input.requestedReaderMode !== "handshake" ||
       (input.requestedReaderMode === "handshake" && (!input.readerInstanceId || !input.readerStartNonce)) ||
       (input.requestedReaderMode === "no-reader" && (input.readerInstanceId || input.readerStartNonce)))) throw new Error("USAGE_READER_BINDING_INVALID");
  if (["auth-add", "auth-rotate", "auth-revoke"].includes(command) && !input.targetPrincipal) throw new Error("USAGE_TARGET_REQUIRED");
  if (command === "mapping-rollback" && (input.priorGeneration === undefined || !input.replacementMappingId)) throw new Error("USAGE_ROLLBACK_TARGET_REQUIRED");
  if (command === "tokens-attest" && !input.hostTokensStdin) throw new Error("USAGE_HOST_TOKENS_STDIN_REQUIRED");
  return { command, input };
}
export async function readProtectedInput(stdin) {
  const chunks = []; for await (const chunk of stdin) chunks.push(chunk);
  const body = parseStrictJsonBytes(Buffer.concat(chunks), STRICT_JSON_LIMITS, {
    allowedValueControlCodes: new Set([0x0a]),
  });
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("USAGE_STDIN_INVALID");
  for (const [key, value] of Object.entries(body)) {
    if (key !== "hostTokens" && typeof value === "string") assertStrictText(value, `protected input ${key}`);
  }
  return body;
}
export async function runManagementCli({ argv, stdin, stdout, stderr, native }) {
  try {
    const { command, input } = parseManagementArgs(argv);
    const protectedInput = await readProtectedInput(stdin);
    if (command === "recover" && Object.keys(protectedInput).some((key) => key !== "actorSecret")) {
      throw new Error("USAGE_STDIN_FIELD_INVALID");
    }
    for (const [key, value] of Object.entries(protectedInput)) {
      if (!PROTECTED_FIELDS.has(key)) throw new Error("USAGE_STDIN_FIELD_INVALID");
      if (Object.hasOwn(input, key) && input[key] !== true) throw new Error("USAGE_DUPLICATE_ARGUMENT");
      input[key] = value;
    }
    if (typeof input.actorSecret !== "string") throw new Error("USAGE_ACTOR_SECRET_REQUIRED");
    if (input.targetSecretStdin && typeof input.targetSecret !== "string") throw new Error("USAGE_TARGET_SECRET_REQUIRED");
    if (input.hostTokensStdin && typeof input.hostTokens !== "string") throw new Error("USAGE_HOST_TOKENS_STDIN_REQUIRED");
    const result = await new ManagementRuntime({ native }).execute(command, input);
    stdout.write(`${JSON.stringify(result)}\n`); return result.exitCode;
  } catch (error) {
    const code = error?.message?.startsWith("USAGE_") ? EXIT.USAGE : EXIT.INVALID;
    stderr.write(`${JSON.stringify({ ok: false, exitCode: code, error: error?.message?.startsWith("USAGE_") ? error.message : "INPUT_INVALID" })}\n`);
    return code;
  }
}
