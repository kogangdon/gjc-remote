import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { classifyWorkspaceLifecycleEvidence } from "@gjc-remote/shared/workspace-lifecycle-envelope.js";
import {
  validateManualCleanup,
  recoveryRecordFingerprint,
} from "@gjc-remote/shared/recovery-envelope.js";
import { assertQuiescent } from "./workspace-lease-registry.js";
import { computeDirtyBackup } from "./workspace-dirty-backup.js";
import { assertResidualProcessAbsence } from "./workspace-residual-process.js";
import {
  TOMBSTONE_STEPS,
  readLiveDisposition,
  buildTombstone,
  publishTombstone,
} from "./workspace-tombstone-publisher.js";

const OPERATION = "workspace_reset_delete";
const POINTER_KIND = "workspace-generation-pointer";
const RESET_DELETE_OPERATIONS = new Set(["reset", "delete"]);
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

function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (!['code', 'operation', 'reason', 'message'].includes(key)) error[key] = value;
    }
  }
  throw error;
}

const isPlainObject = (value) => value !== null && typeof value === "object" &&
  !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const hasExactKeys = (value, keys) => isPlainObject(value) &&
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const isNonEmptyString = (value) => typeof value === "string" && value.length > 0;

function assertMethods(container, methods, path) {
  for (const method of methods) {
    if (!container || typeof container[method] !== "function") {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `${path}.${method} must be a function`);
    }
  }
}

function buildManualCleanup(lifecycleAuthority) {
  const record = {
    version: 1,
    kind: "manual-cleanup",
    anchorFingerprint: lifecycleAuthority.anchorFingerprint,
    fenceGeneration: lifecycleAuthority.fenceGeneration,
    txId: lifecycleAuthority.txId,
    reason: lifecycleAuthority.reason,
    expectedFingerprint: lifecycleAuthority.expectedFingerprint,
    observedFingerprint: lifecycleAuthority.observedFingerprint,
    expectedFloorFingerprint: lifecycleAuthority.expectedFloorFingerprint,
    observedFloorFingerprint: lifecycleAuthority.observedFloorFingerprint,
    routeDisposition: "no-route",
    blockedUntilOwnerAction: true,
    manualCleanupFingerprint: null,
  };
  record.manualCleanupFingerprint = recoveryRecordFingerprint(record, "manualCleanupFingerprint");
  try {
    validateManualCleanup(record);
  } catch (error) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `manual-cleanup authority is invalid: ${error?.message ?? "invalid"}`);
  }
  if (classifyWorkspaceLifecycleEvidence({ manualCleanup: record }) !== "manual_cleanup") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "manual-cleanup record did not classify as manual_cleanup");
  }
  return Object.freeze(record);
}

/**
 * The destructive transition has a deliberately narrow dependency surface. The
 * tombstone IO supplier is deferred so opening the live slot happens only after
 * the exclusive lease has closed and exact transaction quiescence is proven.
 */
export function createWorkspaceResetDeleteOperation(deps = {}) {
  if (!isPlainObject(deps)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "createWorkspaceResetDeleteOperation requires a deps object");
  }
  const { acquireFence, residualIo, tombstoneIo } = deps;
  if (typeof acquireFence !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "acquireFence must be a function");
  }
  if (typeof tombstoneIo !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "tombstoneIo must be a function");
  }
  assertMethods(residualIo, ["listResidualProcesses"], "residualIo");

  function assertRequest(request) {
    if (!isPlainObject(request)) refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request must be an object");
    if (!RESET_DELETE_OPERATIONS.has(request.operation)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "operation must be 'reset' or 'delete'");
    }
    for (const key of ["hostId", "workspaceId", "sourcePlatform", "workDir"]) {
      if (!isNonEmptyString(request[key])) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.${key} must be a non-empty string`);
      }
    }
    if (request.leaseCandidate === undefined || request.leaseCandidate === null) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.leaseCandidate is required for the exclusive fence");
    }
    if (
      !Number.isSafeInteger(request.expectedWorkspaceGeneration) ||
      request.expectedWorkspaceGeneration < 1
    ) {
      refuse(
        PROTOCOL_ERROR_CODES.CONFIG_INVALID,
        "request.expectedWorkspaceGeneration must be a positive safe integer"
      );
    }
    if (typeof request.prepareDirtyBackup !== "function") {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.prepareDirtyBackup must be a function");
    }
    if (!hasExactKeys(request.lifecycleContext, LIFECYCLE_CONTEXT_KEYS)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.lifecycleContext must carry exactly lifecycleAuthority, probeQuiescence, commitTerminal");
    }
    const {
      lifecycleAuthority,
      probeQuiescence,
      prepareTerminal,
      clearTerminalPreparation,
      commitTerminal,
    } = request.lifecycleContext;
    if (!hasExactKeys(lifecycleAuthority, LIFECYCLE_AUTHORITY_KEYS)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.lifecycleContext.lifecycleAuthority must carry exactly ${LIFECYCLE_AUTHORITY_KEYS.join(", ")}`);
    }
    if (
      typeof probeQuiescence !== "function" ||
      typeof prepareTerminal !== "function" ||
      typeof clearTerminalPreparation !== "function" ||
      typeof commitTerminal !== "function"
    ) {
      refuse(
        PROTOCOL_ERROR_CODES.CONFIG_INVALID,
        "request.lifecycleContext callbacks must be functions"
      );
    }
  }

  function assertFenceCurrent(lease, checkpoint) {
    if (!lease.isCurrent()) {
      refuse(PROTOCOL_ERROR_CODES.LEASE_CONFLICT, `exclusive fence was lost before ${checkpoint}`, { checkpoint });
    }
  }

  async function runResetDelete(request) {
    assertRequest(request);
    const { operation, hostId, workspaceId, sourcePlatform, lifecycleContext } = request;
    // This validation is intentionally eager and pure: a publication ambiguity
    // can always carry a complete owner-action checkpoint.
    const manualCleanup = buildManualCleanup(lifecycleContext.lifecycleAuthority);
    const lease = acquireFence(request.leaseCandidate);
    try {
      if (!lease || typeof lease.isCurrent !== "function" || typeof lease.release !== "function") {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "acquireFence must return a lease with { isCurrent, release }");
      }

      await assertQuiescent(await lifecycleContext.probeQuiescence());
      assertFenceCurrent(lease, "live-read");

      const io = await tombstoneIo(request);
      assertMethods(io, ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"], "tombstoneIo");
      const live = await readLiveDisposition(io);
      if (live === null) {
        refuse(
          PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
          "no live record to tombstone"
        );
      }

      if (live.kind !== POINTER_KIND) {
        refuse(
          PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
          "live slot is not the accepted generation pointer"
        );
      }
      if (
        live.record.hostId !== hostId ||
        live.record.workspaceId !== workspaceId ||
        live.record.sourcePlatform !== sourcePlatform ||
        live.record.activeGeneration !== request.expectedWorkspaceGeneration
      ) {
        refuse(
          PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
          "live pointer identity differs from the accepted binding"
        );
      }

      const prepared = await request.prepareDirtyBackup(live, request);
      if (!isPlainObject(prepared) || !isPlainObject(prepared.dirtyBackup)) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "prepareDirtyBackup must return { dirtyBackup, backupIo }");
      }
      assertMethods(prepared.backupIo, ["readBytes"], "prepareDirtyBackup.backupIo");
      const backup = await computeDirtyBackup(prepared.backupIo, prepared.dirtyBackup);
      const dirtyBackupFingerprint = backup.manifestFingerprint;

      await assertResidualProcessAbsence(residualIo, {
        hostId,
        workspaceId,
        workDir: request.workDir,
        sourcePlatform,
      });
      assertFenceCurrent(lease, "publication");

      const tombstone = buildTombstone({
        hostId, workspaceId, sourcePlatform, operation,
        tombstonedGeneration: live.record.activeGeneration,
        priorKind: live.kind,
        priorPointerFingerprint: live.fingerprint,
        dirtyBackupFingerprint,
      });
      const commitManualCleanup = async (error, step, commit = true) => {
        const receipt = Object.freeze({
          operation,
          published: false,
          tombstone,
          fence: lease.fence,
          dirtyBackupFingerprint,
          disposition: "manual_cleanup",
          manualCleanup,
          cause: Object.freeze({
            code: typeof error?.code === "string" ? error.code : null,
            step,
          }),
        });
        if (commit) await lifecycleContext.commitTerminal(receipt, request);
        return receipt;
      };

      try {
        await lifecycleContext.prepareTerminal(manualCleanup, request);
      } catch (error) {
        if (error?.terminalPreparationAmbiguous === true) {
          return await commitManualCleanup(error, "prepareTerminal");
        }
        throw error;
      }
      if (!lease.isCurrent()) {
        try {
          await lifecycleContext.clearTerminalPreparation(request);
        } catch (error) {
          return await commitManualCleanup(error, "clearTerminalPreparation");
        }
        refuse(
          PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
          "exclusive fence was lost after terminal preparation",
          { checkpoint: "terminal-preparation" }
        );
      }
      let published;
      try {
        published = await publishTombstone(io, tombstone);
      } catch (error) {
        if (!TOMBSTONE_STEPS.includes(error?.step)) {
          try {
            await lifecycleContext.clearTerminalPreparation(request);
          } catch (clearError) {
            return await commitManualCleanup(
              clearError,
              "clearTerminalPreparation"
            );
          }
          throw error;
        }
        return await commitManualCleanup(error, error.step);
      }
      const receipt = Object.freeze({
        operation, published: Object.freeze({ ...published }), tombstone, fence: lease.fence,
        dirtyBackupFingerprint, disposition: "committed",
      });
      await lifecycleContext.commitTerminal(receipt, request);
      try {
        await lifecycleContext.clearTerminalPreparation(request);
      } catch (error) {
        return await commitManualCleanup(
          error,
          "clearTerminalPreparation",
          false
        );
      }
      return receipt;
    } finally {
      if (lease && typeof lease.release === "function") lease.release();
    }
  }

  return Object.freeze({ runResetDelete });
}
