import { join as joinPath } from "node:path";

import { createWorkspaceRestoreMigrationOperation } from "./workspace-restore-migration-operation.js";

const OPERATION = "workspace_restore_migration_dispatch";
const RUNTIME_INCOMPATIBLE = "RUNTIME_INCOMPATIBLE";
const SUPPORTED_OPERATIONS = new Set(["restore", "migration"]);
const RECEIPT_FIELDS = Object.freeze([
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "authorityFingerprint",
]);

const isObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

function refuse(code, reason, cleanupState = "not_required") {
  return Object.freeze({
    ok: false,
    code,
    reason,
    cleanupState,
  });
}

function configError(reason) {
  const error = new Error(`${OPERATION}: CONFIG_INVALID: ${reason}`);
  error.code = "CONFIG_INVALID";
  error.operation = OPERATION;
  error.reason = reason;
  return error;
}

function assertFunction(value, name) {
  if (typeof value !== "function") throw configError(`${name} must be a function`);
}

function assertMethods(value, methods, name) {
  for (const method of methods) {
    assertFunction(value?.[method], `${name}.${method}`);
  }
}

function cloneJson(value) {
  if (Array.isArray(value)) return value.map(cloneJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).map((key) => [key, cloneJson(value[key])])
    );
  }
  return value;
}

function receiptMatches(message, binding) {
  return (
    Number.isSafeInteger(binding.authorityEpoch) &&
    binding.authorityEpoch > 0 &&
    Number.isSafeInteger(binding.fenceGeneration) &&
    binding.fenceGeneration > 0 &&
    RECEIPT_FIELDS.every((field) => message[field] === binding[field])
  );
}

function validRestoreContext(context, operation) {
  return (
    isObject(context) &&
    Object.isFrozen(context) &&
    typeof context.stagingPath === "string" &&
    context.stagingPath.length > 0 &&
    isObject(context.expectedAuthority) &&
    isObject(context.manifest) &&
    typeof context.manifest.manifestFingerprint === "string" &&
    isObject(context.expectedGraph) &&
    typeof context.restoredFromWorkspaceId === "string" &&
    context.restoredFromWorkspaceId.length > 0 &&
    Number.isSafeInteger(context.restoredFromGeneration) &&
    context.restoredFromGeneration >= 1 &&
    Number.isSafeInteger(context.probedAtMs) &&
    context.probedAtMs >= 0 &&
    (operation === "migration"
      ? typeof context.migrationKind === "string" && context.migrationKind.length > 0
      : context.migrationKind === undefined)
  );
}

export function createLifecycleRestoreMigrationDispatcher(config = {}) {
  if (!isObject(config)) throw configError("config must be an object");
  const {
    workspaceRoot,
    containment,
    gitVerifier,
    stagePromotion,
    makeStageReader,
    makePublisherIo,
    acquireFence,
    clock,
    maxAgeMs,
    replaySeen,
    hashIdentity,
  } = config;
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    throw configError("workspaceRoot must be a non-empty string");
  }
  assertMethods(containment, ["identifyRoot", "verifyContained"], "containment");
  assertMethods(gitVerifier, ["verifyRepositoryGraph"], "gitVerifier");
  assertMethods(stagePromotion, ["materializeAndVerify", "cleanup"], "stagePromotion");
  assertFunction(makeStageReader, "makeStageReader");
  assertFunction(makePublisherIo, "makePublisherIo");
  assertFunction(acquireFence, "acquireFence");
  assertMethods(clock, ["now"], "clock");
  assertMethods(replaySeen, ["has", "add"], "replaySeen");
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) {
    throw configError("maxAgeMs must be a safe integer >= 1 owned by daemon config");
  }
  if (hashIdentity !== undefined) assertFunction(hashIdentity, "hashIdentity");

  async function dispatchRestoreMigration({
    message,
    trustedBinding,
    trustedInventoryWorkspace,
    leaseCandidate,
    restoreContext,
    readiness,
  } = {}) {
    if (!isObject(message) || !SUPPORTED_OPERATIONS.has(message.operation)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing or unsupported lifecycle message");
    }
    if (!isObject(trustedBinding) || !receiptMatches(message, trustedBinding)) {
      return refuse(
        RUNTIME_INCOMPATIBLE,
        "lifecycle authority does not match the accepted receipt binding"
      );
    }
    if (!isObject(trustedInventoryWorkspace) ||
        typeof trustedInventoryWorkspace.workDir !== "string" ||
        trustedInventoryWorkspace.workDir.length === 0 ||
        trustedInventoryWorkspace.hostId !== trustedBinding.hostId ||
        trustedInventoryWorkspace.workspaceId !== trustedBinding.workspaceId ||
        trustedInventoryWorkspace.sourcePlatform !== trustedBinding.sourcePlatform) {
      return refuse(
        RUNTIME_INCOMPATIBLE,
        "no trusted inventory workspace for accepted binding"
      );
    }
    if (!isObject(readiness) || leaseCandidate === null ||
        typeof leaseCandidate !== "object") {
      return refuse(RUNTIME_INCOMPATIBLE, "missing trusted runtime state");
    }
    if (!["posix", "windows-drive"].includes(trustedBinding.sourcePlatform)) {
      return refuse(
        "CONTAINMENT_UNSUPPORTED",
        `source platform ${String(trustedBinding.sourcePlatform)} is not serveable`
      );
    }
    if (!validRestoreContext(restoreContext, message.operation)) {
      return refuse(
        RUNTIME_INCOMPATIBLE,
        "no sealed restore context for accepted binding"
      );
    }

    const successorGeneration = trustedBinding.workspaceGeneration + 1;
    const segment = String(successorGeneration).padStart(6, "0");
    const candidatePath = joinPath(
      workspaceRoot,
      trustedBinding.workspaceId,
      "generations",
      segment
    );
    const request = {
      operation: "restore",
      ...(message.operation === "migration"
        ? { migrationKind: restoreContext.migrationKind }
        : {}),
      hostId: trustedBinding.hostId,
      workspaceId: trustedBinding.workspaceId,
      sourcePlatform: trustedBinding.sourcePlatform,
      workspaceRoot,
      workDir: trustedInventoryWorkspace.workDir,
      expectedWorkspaceGeneration: trustedBinding.workspaceGeneration,
      generationPath: `generations/${segment}`,
      candidatePath,
      gitDir: candidatePath,
      stagingPath: restoreContext.stagingPath,
      leaseCandidate,
      expectedAuthority: cloneJson(restoreContext.expectedAuthority),
      manifest: cloneJson(restoreContext.manifest),
      restoredFromWorkspaceId: restoreContext.restoredFromWorkspaceId,
      restoredFromGeneration: restoreContext.restoredFromGeneration,
      expectedGraph: cloneJson(restoreContext.expectedGraph),
      probedAtMs: restoreContext.probedAtMs,
      readiness,
    };
    try {
      const receipt = await createWorkspaceRestoreMigrationOperation({
        containment,
        gitVerifier,
        stagePromotion,
        makeStageReader,
        makePublisherIo,
        acquireFence,
        clock,
        maxAgeMs,
        replaySeen,
        ...(hashIdentity ? { hashIdentity } : {}),
      }).runRestoreMigration(request);
      return Object.freeze({
        ok: true,
        receipt,
        cleanupState: "not_required",
      });
    } catch (error) {
      return refuse(
        typeof error?.code === "string" ? error.code : RUNTIME_INCOMPATIBLE,
        typeof error?.reason === "string"
          ? error.reason
          : "restore/migration operation failed",
        error?.cleanupError
          ? "manual_required"
          : error?.code === "WORKSPACE_MIGRATION_UNSUPPORTED"
            ? "not_required"
            : "indeterminate",
      );
    }
  }

  return Object.freeze({ dispatchRestoreMigration });
}
