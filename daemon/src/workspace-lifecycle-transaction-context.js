import {
  assertStrictText,
  canonicalJsonHash,
  isHex64,
} from "@gjc-remote/shared/strict-json.js";
import {
  recoveryRecordFingerprint,
  validateManualCleanup,
} from "@gjc-remote/shared/recovery-envelope.js";

const OPERATION = "workspace_lifecycle_transaction_context";
const RESET_DELETE_OPERATIONS = new Set(["reset", "delete"]);
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);
const BINDING_AUTHORITY_FIELDS = Object.freeze([
  "authorityEpoch",
  "fenceGeneration",
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "authorityFingerprint",
]);
const CONTEXT_FIELDS = Object.freeze([
  "trustedBinding",
  "operation",
  "idempotencyFingerprint",
  "probeQuiescence",
  "prepareTerminal",
  "clearTerminalPreparation",
  "commitTerminal",
]);
const REASON = "reset-delete-terminal-publication-uncertain";
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const isPlainObject = (value) => value !== null && typeof value === "object" &&
  !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const hasExactKeys = (value, keys) => isPlainObject(value) &&
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const isPositiveSafeInteger = (value) => Number.isSafeInteger(value) && value >= 1;
const isBoundedStrictText = (value, maxBytes) => {
  try {
    return typeof value === "string" && assertStrictText(value, "text", maxBytes) === value;
  } catch {
    return false;
  }
};

function configInvalid(reason) {
  const error = new Error(`${OPERATION}: CONFIG_INVALID: ${reason}`);
  error.code = "CONFIG_INVALID";
  error.operation = OPERATION;
  error.reason = reason;
  throw error;
}

function validateTrustedBinding(binding) {
  if (!isPlainObject(binding)) configInvalid("trustedBinding must be a plain object");
  for (const field of BINDING_AUTHORITY_FIELDS) {
    if (!Object.hasOwn(binding, field)) configInvalid(`trustedBinding.${field} is required`);
  }
  if (!isBoundedStrictText(binding.hostId, 128) || binding.hostId.length === 0 || binding.hostId !== binding.hostId.trim()) {
    configInvalid("trustedBinding.hostId must be a bounded non-empty string");
  }
  if (typeof binding.mappingId !== "string" || !OPAQUE_ID.test(binding.mappingId)) {
    configInvalid("trustedBinding.mappingId must be a bounded opaque identity");
  }
  if (typeof binding.workspaceId !== "string" || !OPAQUE_ID.test(binding.workspaceId)) {
    configInvalid("trustedBinding.workspaceId must be a bounded opaque identity");
  }
  for (const field of [
    "authorityEpoch",
    "fenceGeneration",
    "mappingGeneration",
    "mappingVersion",
    "workspaceGeneration",
  ]) {
    if (!isPositiveSafeInteger(binding[field])) configInvalid(`trustedBinding.${field} must be a positive safe integer`);
  }
  if (!SOURCE_PLATFORMS.has(binding.sourcePlatform)) {
    configInvalid("trustedBinding.sourcePlatform is invalid");
  }
  if (!isHex64(binding.authorityFingerprint)) {
    configInvalid("trustedBinding.authorityFingerprint must be a SHA-256 fingerprint");
  }
}

function buildManualCleanupAuthority(binding, operation, idempotencyFingerprint) {
  const txId = canonicalJsonHash({
    kind: "reset-delete-lifecycle-transaction",
    authorityVersion: "receipt-v3",
    authorityEpoch: binding.authorityEpoch,
    fenceGeneration: binding.fenceGeneration,
    hostId: binding.hostId,
    workspaceId: binding.workspaceId,
    mappingId: binding.mappingId,
    mappingGeneration: binding.mappingGeneration,
    mappingVersion: binding.mappingVersion,
    workspaceGeneration: binding.workspaceGeneration,
    sourcePlatform: binding.sourcePlatform,
    authorityFingerprint: binding.authorityFingerprint,
    operation,
    idempotencyFingerprint,
  });
  const authority = {
    anchorFingerprint: binding.authorityFingerprint,
    fenceGeneration: binding.fenceGeneration,
    txId,
    reason: REASON,
    expectedFingerprint: null,
    observedFingerprint: null,
    expectedFloorFingerprint: null,
    observedFloorFingerprint: null,
  };
  const record = {
    version: 1,
    kind: "manual-cleanup",
    ...authority,
    routeDisposition: "no-route",
    blockedUntilOwnerAction: true,
    manualCleanupFingerprint: null,
  };
  record.manualCleanupFingerprint = recoveryRecordFingerprint(record, "manualCleanupFingerprint");
  try {
    validateManualCleanup(record);
  } catch (error) {
    configInvalid(`manual-cleanup authority is invalid: ${error?.message ?? "invalid"}`);
  }
  return Object.freeze(authority);
}

/**
 * Creates the host-held, per-call manual-cleanup authority for a reset/delete
 * transaction. The accepted binding is the only route-authority source.
 */
export function createResetDeleteLifecycleContext(input) {
  if (!hasExactKeys(input, CONTEXT_FIELDS)) {
    configInvalid(`input must carry exactly ${CONTEXT_FIELDS.join(", ")}`);
  }
  const {
    trustedBinding,
    operation,
    idempotencyFingerprint,
    probeQuiescence,
    prepareTerminal,
    clearTerminalPreparation,
    commitTerminal,
  } = input;
  validateTrustedBinding(trustedBinding);
  if (!RESET_DELETE_OPERATIONS.has(operation)) {
    configInvalid("operation must be 'reset' or 'delete'");
  }
  if (!isHex64(idempotencyFingerprint)) {
    configInvalid("idempotencyFingerprint must be a SHA-256 fingerprint");
  }
  if (typeof probeQuiescence !== "function") configInvalid("probeQuiescence must be a function");
  if (typeof prepareTerminal !== "function") configInvalid("prepareTerminal must be a function");
  if (typeof clearTerminalPreparation !== "function") {
    configInvalid("clearTerminalPreparation must be a function");
  }
  if (typeof commitTerminal !== "function") configInvalid("commitTerminal must be a function");

  return Object.freeze({
    lifecycleAuthority: buildManualCleanupAuthority(trustedBinding, operation, idempotencyFingerprint),
    probeQuiescence,
    prepareTerminal,
    clearTerminalPreparation,
    commitTerminal,
  });
}
