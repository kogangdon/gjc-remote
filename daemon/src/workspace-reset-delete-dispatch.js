// Native reset/delete dispatch. All storage and tree work is deliberately
// deferred to the fenced operation; this module only verifies host-held route
// authority and builds its per-call callbacks.
import { join as joinPath } from "node:path";
import { createWorkspaceResetDeleteOperation } from "./workspace-reset-delete-operation.js";

const OPERATION = "workspace_reset_delete_dispatch";
const RUNTIME_INCOMPATIBLE = "RUNTIME_INCOMPATIBLE";
const POINTER_KIND = "workspace-generation-pointer";
const SUPPORTED_RESET_DELETE_OPERATIONS = new Set(["reset", "delete"]);
const LIFECYCLE_AUTHORITY_KEYS = Object.freeze([
  "anchorFingerprint", "fenceGeneration", "txId", "reason",
  "expectedFingerprint", "observedFingerprint", "expectedFloorFingerprint",
  "observedFloorFingerprint",
]);
const LIFECYCLE_CONTEXT_KEYS = Object.freeze([
  "lifecycleAuthority",
  "probeQuiescence",
  "prepareTerminal",
  "clearTerminalPreparation",
  "commitTerminal",
]);
const MATERIALIZER_PLATFORM = Object.freeze(Object.assign(Object.create(null), {
  posix: "posix",
  "windows-drive": "windows",
}));
const RECEIPT_LIFECYCLE_FIELDS = Object.freeze([
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "authorityFingerprint",
]);

const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (value, keys) => isPlainObject(value) && Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const isHex64 = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
function configError(reason) {
  const error = new Error(`${OPERATION}: CONFIG_INVALID: ${reason}`);
  error.code = "CONFIG_INVALID";
  error.operation = OPERATION;
  error.reason = reason;
  return error;
}
function refuse(code, reason, cleanupState = "not_required") {
  return Object.freeze({
    ok: false,
    code,
    reason,
    cleanupState,
  });
}
function assertFn(value, name) { if (typeof value !== "function") throw configError(`${name} must be a function`); }
function assertMethods(container, methods, name) {
  for (const method of methods) if (!container || typeof container[method] !== "function") {
    throw configError(`${name}.${method} must be a function`);
  }
}
function generationSegment(generation) { return String(generation).padStart(6, "0"); }
function matchesReceiptLifecycleAuthority(message, trustedBinding) {
  // Receipt binds intentionally carry no routeFingerprint. The lifecycle
  // frame's routeFingerprint is therefore channel metadata, not destructive
  // storage authority; every field that selects the host mapping/workspace is
  // matched against the independently verified receipt binding below.
  return (
    Number.isSafeInteger(trustedBinding.authorityEpoch) &&
    trustedBinding.authorityEpoch >= 1 &&
    Number.isSafeInteger(trustedBinding.fenceGeneration) &&
    trustedBinding.fenceGeneration >= 1 &&
    RECEIPT_LIFECYCLE_FIELDS.every(
      (field) => message[field] === trustedBinding[field]
    )
  );
}

export function createLifecycleResetDeleteDispatcher(config = {}) {
  if (!isPlainObject(config)) throw configError("config must be an object");
  const { workspaceRoot, makePublisherIo, makeBackupIo, resolveManifestPaths, acquireFence, residualIo } = config;
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    throw configError("workspaceRoot must be a non-empty string");
  }
  assertFn(makePublisherIo, "makePublisherIo");
  assertFn(makeBackupIo, "makeBackupIo");
  assertFn(resolveManifestPaths, "resolveManifestPaths");
  assertFn(acquireFence, "acquireFence");
  assertMethods(residualIo, ["listResidualProcesses"], "residualIo");

  async function dispatchResetDelete({
    message, trustedBinding, trustedInventoryWorkspace, leaseCandidate, lifecycleContext, readiness,
  } = {}) {
    if (!isPlainObject(message)) return refuse(RUNTIME_INCOMPATIBLE, "missing lifecycle message");
    if (!SUPPORTED_RESET_DELETE_OPERATIONS.has(message.operation)) {
      return refuse(RUNTIME_INCOMPATIBLE, "operation is not a reset/delete operation");
    }
    if (!isPlainObject(trustedBinding)) return refuse(RUNTIME_INCOMPATIBLE, "no accepted binding for workspace");
    if (!matchesReceiptLifecycleAuthority(message, trustedBinding)) {
      return refuse(
        RUNTIME_INCOMPATIBLE,
        "lifecycle authority does not match the accepted receipt binding"
      );
    }
    if (!isPlainObject(trustedInventoryWorkspace) ||
        typeof trustedInventoryWorkspace.workDir !== "string" || trustedInventoryWorkspace.workDir.length === 0) {
      return refuse(RUNTIME_INCOMPATIBLE, "no trusted inventory workspace for source workDir");
    }
    if (trustedInventoryWorkspace.hostId !== message.hostId ||
        trustedInventoryWorkspace.workspaceId !== message.workspaceId ||
        trustedInventoryWorkspace.sourcePlatform !== message.sourcePlatform) {
      return refuse(RUNTIME_INCOMPATIBLE, "trusted inventory identity does not match the verified message");
    }
    if (!isPlainObject(readiness)) return refuse(RUNTIME_INCOMPATIBLE, "missing live readiness dimensions");
    if (leaseCandidate === null || typeof leaseCandidate !== "object") {
      return refuse(RUNTIME_INCOMPATIBLE, "missing trusted fence lease candidate");
    }
    // This is a host-held capability bundle, never reconstructed from wire data.
    if (!hasExactKeys(lifecycleContext, LIFECYCLE_CONTEXT_KEYS) ||
        !hasExactKeys(lifecycleContext.lifecycleAuthority, LIFECYCLE_AUTHORITY_KEYS) ||
        typeof lifecycleContext.probeQuiescence !== "function" ||
        typeof lifecycleContext.prepareTerminal !== "function" ||
        typeof lifecycleContext.clearTerminalPreparation !== "function" ||
        typeof lifecycleContext.commitTerminal !== "function") {
      return refuse(RUNTIME_INCOMPATIBLE, "missing or malformed lifecycle context");
    }
    const byteReaderPlatform = MATERIALIZER_PLATFORM[message.sourcePlatform];
    if (!byteReaderPlatform) {
      return refuse("CONTAINMENT_UNSUPPORTED", `source platform ${String(message.sourcePlatform)} is not serveable`);
    }

    const request = {
      operation: message.operation,
      hostId: message.hostId,
      workspaceId: message.workspaceId,
      sourcePlatform: message.sourcePlatform,
      workDir: trustedInventoryWorkspace.workDir,
      expectedWorkspaceGeneration: trustedBinding.workspaceGeneration,
      leaseCandidate,
      lifecycleContext,
      // Runs only after acquire -> quiescence -> fence-current -> live-pin.
      async prepareDirtyBackup(live) {
        if (live.kind !== POINTER_KIND) throw configError("live slot is not a generation pointer");
        const record = live.record;
        const generation = record.activeGeneration;
        if (!Number.isSafeInteger(generation) || generation < 1 ||
            !isHex64(record.rootIdentityFingerprint) || !isHex64(record.storageIdentityFingerprint) ||
            !isHex64(record.gitGenerationFingerprint)) {
          throw configError("live record is missing derivable dirty-backup identity");
        }
        const candidatePath = joinPath(workspaceRoot, message.workspaceId, "generations", generationSegment(generation));
        const relativePaths = await resolveManifestPaths(candidatePath, byteReaderPlatform);
        if (!Array.isArray(relativePaths) || relativePaths.length === 0) {
          throw configError("no trusted dirty-backup paths for the live generation");
        }
        const backupIo = makeBackupIo(candidatePath, byteReaderPlatform);
        assertMethods(backupIo, ["readBytes"], "backupIo");
        return {
          dirtyBackup: {
            hostId: message.hostId,
            workspaceId: message.workspaceId,
            workspaceGeneration: generation,
            sourcePlatform: message.sourcePlatform,
            rootIdentityFingerprint: record.rootIdentityFingerprint,
            storageIdentityFingerprint: record.storageIdentityFingerprint,
            gitGenerationFingerprint: record.gitGenerationFingerprint,
            relativePaths,
          },
          backupIo,
        };
      },
    };

    try {
      const receipt = await createWorkspaceResetDeleteOperation({
        acquireFence,
        residualIo,
        // Publisher construction and all live reads are fenced too.
        tombstoneIo: () => makePublisherIo(message.workspaceId),
      }).runResetDelete(request);
      if (receipt.disposition === "committed") {
        return Object.freeze({
          ok: true,
          receipt,
          cleanupState: "not_required",
        });
      }
      return Object.freeze({
        ok: false,
        code: RUNTIME_INCOMPATIBLE,
        reason: "reset/delete requires manual cleanup",
        receipt,
        cleanupState: "manual_required",
      });
    } catch (error) {
      return refuse(
        typeof error?.code === "string" ? error.code : RUNTIME_INCOMPATIBLE,
        typeof error?.reason === "string"
          ? error.reason
          : "reset/delete operation failed",
        "indeterminate",
      );
    }
  }
  return Object.freeze({ dispatchResetDelete });
}
