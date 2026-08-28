// Reset/delete lifecycle dispatch wiring for the native workspace data plane
// (#53 Phase 2, slice S6f.4; issue #81 native-serving boundary).
//
// THIN, PURE, dependency-injected glue that turns an authenticated lifecycle
// WIRE message (shared/protocol.js MSG_TYPES.WORKSPACE_RESET_DELETE) into a
// fully derived reset/delete request and runs the already-landed pure
// orchestrator createWorkspaceResetDeleteOperation (S5e). It performs NO direct
// filesystem/subprocess I/O and does NOT read or flip the native-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false). Live enablement is the
// separate S7 boundary.
//
// Authorization model is identical to the S6f.2 create / S6f.3 refresh
// dispatchers: the 9-field lifecycle authority tuple comes ONLY from the
// ACCEPTED BIND_WORKSPACE binding (passed in as `trustedBinding`, never the
// message under test), verified strict-equal via
// verifyWorkspaceLifecycleAuthority. Trust in route/authority fingerprints is
// trust-on-first-use (issue #179).
//
// Reset/delete is DESTRUCTIVE, so the orchestrator gates it behind an EXCLUSIVE
// activity fence + workload quiescence + a dirty-backup capture + a
// residual-process absence proof before the sole live-slot mutation (a terminal
// tombstone CAS). This dispatcher's derivation obligations (all from host-held
// trusted state, never the wire message):
//   - The base being destroyed is the CURRENT live slot, read via
//     readLiveDisposition over the injected single-slot io. expected
//     .priorPointerFingerprint pins that exact record (a live POINTER's
//     pointerFingerprint, or a live TOMBSTONE's priorPointerFingerprint so the
//     A4 idempotent re-delete short-circuit matches). A null slot is refused
//     WORKSPACE_GENERATION_STALE (nothing to destroy).
//   - The dirty-backup descriptor (paths + generation identity) is derived from
//     the live POINTER record + resolveManifestPaths. On the idempotent
//     re-delete path (live already a matching tombstone) computeDirtyBackup is
//     never reached (the orchestrator A4-short-circuits first), so the
//     descriptor is shape-only there and is filled from the tombstone's own
//     real fields.
//   - The exclusive fence identity (leaseCandidate) and the manual-cleanup
//     authority (lifecycleAuthority tx-context) are host-held bind-time / serving
//     tx state; the daemon holds them and passes them in as per-call parameters.
//     The dispatcher forwards leaseCandidate opaquely to acquireFence and the
//     8-field lifecycleAuthority opaquely to the orchestrator (shape-checked).
//
// The residual-process enumerator (residualIo, S5c) is an S7 native gap
// (issue #171): the boot wiring injects an Option-A fail-closed placeholder that
// refuses (cannot certify absence -> destruction is not authorised) until the
// real native handle/pid scanner lands. Reading/writing live storage
// (makePublisherIo), enumerating the candidate manifest paths
// (resolveManifestPaths), and reading the dirty tree (makeBackupIo) are likewise
// native serving concerns; the daemon supplies them and holds a null dispatcher
// until they land, so the served branch stays inert while the gate is false.

import { join as joinPath } from "node:path";

import {
  verifyWorkspaceLifecycleAuthority,
  workspaceLifecycleAuthority,
} from "@gjc-remote/shared";

import { createWorkspaceResetDeleteOperation } from "./workspace-reset-delete-operation.js";
import { readLiveDisposition } from "./workspace-tombstone-publisher.js";

const OPERATION = "workspace_reset_delete_dispatch";

const RUNTIME_INCOMPATIBLE = "RUNTIME_INCOMPATIBLE";

const POINTER_KIND = "workspace-generation-pointer";
const TOMBSTONE_KIND = "workspace-tombstone";

const SUPPORTED_RESET_DELETE_OPERATIONS = new Set(["reset", "delete"]);

// The exact injected manual-cleanup authority sub-object the orchestrator needs
// (A6). Kept in sync with workspace-reset-delete-operation.js LIFECYCLE_AUTHORITY_KEYS.
const LIFECYCLE_AUTHORITY_KEYS = Object.freeze([
  "anchorFingerprint",
  "fenceGeneration",
  "txId",
  "reason",
  "expectedFingerprint",
  "observedFingerprint",
  "expectedFloorFingerprint",
  "observedFloorFingerprint",
]);

// Wire sourcePlatform {posix, windows-drive, windows-unc} vs materializer/
// byte-reader {posix, windows}. windows-unc is not containment-verifiable.
const MATERIALIZER_PLATFORM = Object.freeze({
  posix: "posix",
  "windows-drive": "windows",
});

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const hasExactKeys = (value, keys) =>
  isPlainObject(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

const isHex64 = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

function configError(reason) {
  const error = new Error(`${OPERATION}: CONFIG_INVALID: ${reason}`);
  error.code = "CONFIG_INVALID";
  error.operation = OPERATION;
  error.reason = reason;
  return error;
}

function refuse(code, reason) {
  return Object.freeze({ ok: false, code, reason });
}

function assertFn(value, name) {
  if (typeof value !== "function") throw configError(`${name} must be a function`);
}

function assertMethods(container, methods, name) {
  for (const method of methods) {
    if (!container || typeof container[method] !== "function") {
      throw configError(`${name}.${method} must be a function`);
    }
  }
}

function generationSegment(generation) {
  return String(generation).padStart(6, "0");
}

/**
 * Build the reset/delete lifecycle dispatcher.
 *
 * config = {
 *   workspaceRoot,          // absolute native base dir for served workspaces
 *   makePublisherIo,        // async (workspaceId) => single-slot io (S6f.1a).
 *                           //   used both as the tombstone io and to read the
 *                           //   live disposition (readLiveDisposition).
 *   makeBackupIo,           // (candidatePath, byteReaderPlatform) => { readBytes }
 *   resolveManifestPaths,   // async (candidatePath, platform) => string[] (S7 #171)
 *   acquireFence,           // (leaseCandidate) => lease  (EXCLUSIVE fence, S6f.1e)
 *   probeQuiescence,        // () => { pendingInvokes, pendingSessions } (S6f.1e)
 *   residualIo,             // { listResidualProcesses } (S7 #171 Option-A placeholder)
 * }
 */
export function createLifecycleResetDeleteDispatcher(config = {}) {
  if (!isPlainObject(config)) throw configError("config must be an object");
  const {
    workspaceRoot,
    makePublisherIo,
    makeBackupIo,
    resolveManifestPaths,
    acquireFence,
    probeQuiescence,
    residualIo,
  } = config;

  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    throw configError("workspaceRoot must be a non-empty string");
  }
  assertFn(makePublisherIo, "makePublisherIo");
  assertFn(makeBackupIo, "makeBackupIo");
  assertFn(resolveManifestPaths, "resolveManifestPaths");
  assertFn(acquireFence, "acquireFence");
  assertFn(probeQuiescence, "probeQuiescence");
  assertMethods(residualIo, ["listResidualProcesses"], "residualIo");

  /**
   * Authorize + derive + run one reset/delete. Resolves to a frozen
   * { ok:true, receipt } for a committed / already_tombstoned disposition or a
   * frozen { ok:false, code, reason } refusal (including a manual_cleanup
   * disposition, which the wire surfaces as a refusal while the operator
   * reconciles out of band). Never throws for an expected refusal.
   *
   * `trustedBinding` is the accepted BIND_WORKSPACE binding record (the sole
   * authority source). `leaseCandidate` is the adopted EXCLUSIVE-fence identity
   * and `lifecycleAuthority` is the manual-cleanup tx-context; both are host-held
   * serving state the daemon supplies per-call.
   */
  async function dispatchResetDelete({
    message,
    trustedBinding,
    trustedInventoryWorkspace,
    leaseCandidate,
    lifecycleAuthority,
    readiness,
  } = {}) {
    if (!isPlainObject(message)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing lifecycle message");
    }
    if (!SUPPORTED_RESET_DELETE_OPERATIONS.has(message.operation)) {
      return refuse(RUNTIME_INCOMPATIBLE, "operation is not a reset/delete operation");
    }

    // Guard 1: authorize the message against the trusted binding's 9-field
    // authority tuple (never the message's own claims).
    if (!isPlainObject(trustedBinding)) {
      return refuse(RUNTIME_INCOMPATIBLE, "no accepted binding for workspace");
    }
    const trusted = workspaceLifecycleAuthority(trustedBinding);
    if (!verifyWorkspaceLifecycleAuthority(message, trusted)) {
      return refuse(RUNTIME_INCOMPATIBLE, "lifecycle authority does not match the accepted binding");
    }

    // Guard 2: trusted inventory existence + identity cross-check against the
    // already-verified message (defense-in-depth).
    if (!isPlainObject(trustedInventoryWorkspace) ||
        typeof trustedInventoryWorkspace.workDir !== "string" ||
        trustedInventoryWorkspace.workDir.length === 0) {
      return refuse(RUNTIME_INCOMPATIBLE, "no trusted inventory workspace for source workDir");
    }
    if (trustedInventoryWorkspace.hostId !== message.hostId ||
        trustedInventoryWorkspace.workspaceId !== message.workspaceId ||
        trustedInventoryWorkspace.sourcePlatform !== message.sourcePlatform) {
      return refuse(RUNTIME_INCOMPATIBLE, "trusted inventory identity does not match the verified message");
    }

    if (!isPlainObject(readiness)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing live readiness dimensions");
    }

    // Guard 3: the exclusive-fence identity and the manual-cleanup authority are
    // host-held serving state; the wire message can supply neither.
    if (leaseCandidate === null || typeof leaseCandidate !== "object") {
      return refuse(RUNTIME_INCOMPATIBLE, "missing trusted fence lease candidate");
    }
    if (!hasExactKeys(lifecycleAuthority, LIFECYCLE_AUTHORITY_KEYS)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing or malformed manual-cleanup authority");
    }

    const sourcePlatform = message.sourcePlatform;
    const materializerPlatform = MATERIALIZER_PLATFORM[sourcePlatform];
    if (!materializerPlatform) {
      return refuse("CONTAINMENT_UNSUPPORTED", `source platform ${String(sourcePlatform)} is not serveable`);
    }
    const byteReaderPlatform = materializerPlatform;

    const hostId = message.hostId;
    const workspaceId = message.workspaceId;

    try {
      const tombstoneIo = await makePublisherIo(workspaceId);
      // The base being destroyed is the CURRENT live slot (host-held trusted
      // state; the wire message can never pin it). A null slot has nothing to
      // destroy.
      const live = await readLiveDisposition(tombstoneIo);
      if (live === null) {
        return refuse("WORKSPACE_GENERATION_STALE", "no live record is published to reset/delete");
      }

      let generation;
      let rootIdentityFingerprint;
      let storageIdentityFingerprint;
      let gitGenerationFingerprint;
      if (live.kind === POINTER_KIND) {
        // Normal destroy: derive the dirty-backup identity from the live pointer.
        generation = live.record.activeGeneration;
        rootIdentityFingerprint = live.record.rootIdentityFingerprint;
        storageIdentityFingerprint = live.record.storageIdentityFingerprint;
        gitGenerationFingerprint = live.record.gitGenerationFingerprint;
      } else if (live.kind === TOMBSTONE_KIND) {
        // Idempotent re-delete: the orchestrator A4-short-circuits to
        // already_tombstoned BEFORE computeDirtyBackup, so this descriptor is
        // shape-only and never consumed. Fill it from the tombstone's own real
        // fields (distinct 64-hex hashes) rather than fabricating values.
        generation = live.record.tombstonedGeneration;
        rootIdentityFingerprint = live.record.priorPointerFingerprint;
        storageIdentityFingerprint = live.record.dirtyBackupFingerprint ?? live.record.tombstoneFingerprint;
        gitGenerationFingerprint = live.record.tombstoneFingerprint;
      } else {
        return refuse(RUNTIME_INCOMPATIBLE, "live slot is an unknown record kind");
      }

      if (!Number.isSafeInteger(generation) || generation < 1 ||
          !isHex64(rootIdentityFingerprint) ||
          !isHex64(storageIdentityFingerprint) ||
          !isHex64(gitGenerationFingerprint)) {
        return refuse(RUNTIME_INCOMPATIBLE, "live record is missing derivable dirty-backup identity");
      }

      const segment = generationSegment(generation);
      const candidatePath = joinPath(workspaceRoot, workspaceId, "generations", segment);

      const relativePaths = await resolveManifestPaths(candidatePath, byteReaderPlatform);
      if (!Array.isArray(relativePaths) || relativePaths.length === 0) {
        return refuse(RUNTIME_INCOMPATIBLE, "no trusted dirty-backup paths for the live generation");
      }
      const backupIo = makeBackupIo(candidatePath, byteReaderPlatform);
      assertMethods(backupIo, ["readBytes"], "backupIo");

      const request = {
        operation: message.operation,
        hostId,
        workspaceId,
        sourcePlatform,
        leaseCandidate,
        dirtyBackup: {
          hostId,
          workspaceId,
          workspaceGeneration: generation,
          sourcePlatform,
          rootIdentityFingerprint,
          storageIdentityFingerprint,
          gitGenerationFingerprint,
          relativePaths,
        },
        expected: {
          // A live POINTER pins its own fingerprint; a live TOMBSTONE pins the
          // record it chained onto so the A4 idempotent short-circuit matches.
          priorPointerFingerprint: live.kind === POINTER_KIND
            ? live.fingerprint
            : live.record.priorPointerFingerprint,
        },
        lifecycleAuthority,
      };

      const receipt = await createWorkspaceResetDeleteOperation({
        acquireFence,
        probeQuiescence,
        backupIo,
        residualIo,
        tombstoneIo,
      }).runResetDelete(request);

      // committed / already_tombstoned are successful terminal dispositions.
      // manual_cleanup means the terminal tombstone publication began but its
      // durability is unproven; the wire surfaces it as a refusal (operator
      // reconciles out of band) while the internal receipt is preserved.
      if (receipt.disposition === "committed" || receipt.disposition === "already_tombstoned") {
        return Object.freeze({ ok: true, receipt });
      }
      return Object.freeze({
        ok: false,
        code: RUNTIME_INCOMPATIBLE,
        reason: "reset/delete requires manual cleanup",
        receipt,
      });
    } catch (error) {
      // error.code / reason are INTERNAL diagnostics only: the daemon wire
      // boundary whitelists the code against PROTOCOL_ERROR_CODES and never
      // serializes the reason (review S6f.2 F2).
      return refuse(
        typeof error?.code === "string" ? error.code : RUNTIME_INCOMPATIBLE,
        typeof error?.reason === "string" ? error.reason : "reset/delete operation failed",
      );
    }
  }

  return Object.freeze({ dispatchResetDelete });
}
