// Restore/migration lifecycle dispatch wiring for the native workspace data
// plane (#53 Phase 2, slice S6f.5; issue #81 native-serving boundary).
//
// THIN, PURE, dependency-injected glue that turns an authenticated lifecycle
// WIRE message (shared/protocol.js MSG_TYPES.WORKSPACE_RESTORE_MIGRATION) into
// a fully derived restore/migration request and runs the already-landed pure
// orchestrator createWorkspaceRestoreMigrationOperation (S5i). It performs NO
// direct filesystem/subprocess I/O and does NOT read or flip the native-serving
// gate (NATIVE_WORKSPACE_SERVING_ENABLED stays false). Live enablement is the
// separate S7 boundary.
//
// Authorization model is identical to the S6f.2 create / S6f.3 refresh /
// S6f.4 reset-delete dispatchers: the 9-field lifecycle authority tuple comes
// ONLY from the ACCEPTED BIND_WORKSPACE binding (passed in as `trustedBinding`,
// never the message under test), verified strict-equal via
// verifyWorkspaceLifecycleAuthority. Trust in route/authority fingerprints is
// trust-on-first-use (issue #179).
//
// Restore/migration promotes a QUARANTINED STAGED source onto the live slot as
// a reversible successor generation, under an EXCLUSIVE activity fence. Unlike
// refresh (which re-materializes the workspace's own tree) the staged source is
// external host-held serving state: its stagingPath, the provenance authority
// it must match, its manifest, and the restore lineage are NOT derivable from
// the thin wire message or the live pointer. The daemon holds that payload as a
// per-call `restoreContext` (the S7 serving-state gap); the dispatcher forwards
// it opaquely into the orchestrator after authorization. The dispatcher's own
// derivations (from host-held trusted state, never the wire message):
//   - The base being promoted onto is the CURRENT live pointer, read via the
//     injected publisher io (readLiveGeneration); the successor generation and
//     its candidate/git directory derive as base.activeGeneration + 1. A
//     workspace with no published live generation is refused
//     WORKSPACE_GENERATION_STALE (nothing to promote onto). The orchestrator
//     independently re-reads and CAS-guards the base (optimistic concurrency).
//   - The exclusive fence identity (leaseCandidate) is the adopted bind-time
//     fence authority; the daemon holds it and passes it in per-call.
//   - A "migration" wire operation carries its migrationKind through the
//     restoreContext; a disabled docker session-volume migration is refused by
//     the orchestrator with a fixed public code BEFORE any fence/I/O.
//
// The provenance/checksum readers (both rooted in the SAME quarantined
// stagingPath, per the orchestrator's same-quarantined-scope contract),
// makePublisherIo, containment, and gitVerifier are native serving low-level
// concerns (S7, issue #171); the daemon supplies them and holds a null
// dispatcher until they land, so the served branch stays inert while the gate
// is false.

import { join as joinPath } from "node:path";

import {
  verifyWorkspaceLifecycleAuthority,
  workspaceLifecycleAuthority,
} from "@gjc-remote/shared";

import { createWorkspaceRestoreMigrationOperation } from "./workspace-restore-migration-operation.js";
import { readLiveGeneration } from "./workspace-generation-publisher.js";

const OPERATION = "workspace_restore_migration_dispatch";

const RUNTIME_INCOMPATIBLE = "RUNTIME_INCOMPATIBLE";

const SUPPORTED_RESTORE_OPERATIONS = new Set(["restore", "migration"]);

// Wire sourcePlatform {posix, windows-drive, windows-unc} vs materializer/
// byte-reader {posix, windows}. windows-unc is not containment-verifiable.
// null-prototype map (issue #184): a wire sourcePlatform can never resolve an
// inherited Object.prototype key (constructor/__proto__) to a truthy non-string.
const MATERIALIZER_PLATFORM = Object.freeze(
  Object.assign(Object.create(null), {
    posix: "posix",
    "windows-drive": "windows",
  }),
);

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

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
 * Build the restore/migration lifecycle dispatcher.
 *
 * config = {
 *   workspaceRoot,        // absolute native base dir for served workspaces
 *   makePublisherIo,      // async (workspaceId) => publishIo (S6f.1a); also the
 *                         //   live-base read source (readLiveGeneration).
 *   containment,          // S4a { identifyRoot, verifyContained }
 *   gitVerifier,          // S4b { verifyRepositoryGraph }
 *   makeProvenanceIo,     // (stagingPath) => { readProvenanceRecord } (S5g / S7 #171)
 *   makeChecksumIo,       // (stagingPath) => { readBytes } (S4c / S7 #171)
 *   acquireFence,         // (leaseCandidate) => lease  (EXCLUSIVE fence, S6f.1e)
 *   clock,                // { now(): number } trusted monotonic ms clock
 *   maxAgeMs,             // safe int >= 1 (daemon config; freshness window)
 *   replaySeen,           // { has, add } single-use readiness seen-set
 *   hashIdentity?,        // optional (identity) => hex64
 * }
 */
export function createLifecycleRestoreMigrationDispatcher(config = {}) {
  if (!isPlainObject(config)) throw configError("config must be an object");
  const {
    workspaceRoot,
    makePublisherIo,
    containment,
    gitVerifier,
    makeProvenanceIo,
    makeChecksumIo,
    acquireFence,
    clock,
    maxAgeMs,
    replaySeen,
    hashIdentity,
  } = config;

  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    throw configError("workspaceRoot must be a non-empty string");
  }
  assertFn(makePublisherIo, "makePublisherIo");
  assertMethods(containment, ["identifyRoot", "verifyContained"], "containment");
  assertMethods(gitVerifier, ["verifyRepositoryGraph"], "gitVerifier");
  assertFn(makeProvenanceIo, "makeProvenanceIo");
  assertFn(makeChecksumIo, "makeChecksumIo");
  assertFn(acquireFence, "acquireFence");
  assertMethods(clock, ["now"], "clock");
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) {
    throw configError("maxAgeMs must be a safe integer >= 1 owned by daemon config");
  }
  assertMethods(replaySeen, ["has", "add"], "replaySeen");
  if (hashIdentity !== undefined && typeof hashIdentity !== "function") {
    throw configError("hashIdentity must be a function when provided");
  }

  // The restore payload the thin wire message cannot carry; the daemon sources
  // it from host serving state (S7 #171) and passes it per-call. Minimal
  // shape-guard here (fail-closed clarity); the orchestrator deep-validates.
  function refuseRestoreContext(restoreContext, wireOperation) {
    if (!isPlainObject(restoreContext)) {
      return "missing host-held restore context";
    }
    if (typeof restoreContext.stagingPath !== "string" || restoreContext.stagingPath.length === 0) {
      return "restore context is missing a staging path";
    }
    if (!isPlainObject(restoreContext.expectedAuthority)) {
      return "restore context is missing the expected provenance authority";
    }
    if (!isPlainObject(restoreContext.staged)) {
      return "restore context is missing the staged source descriptor";
    }
    if (!isPlainObject(restoreContext.manifest) ||
        typeof restoreContext.manifest.manifestFingerprint !== "string" ||
        restoreContext.manifest.manifestFingerprint.length === 0) {
      return "restore context is missing the staged manifest";
    }
    if (typeof restoreContext.restoredFromWorkspaceId !== "string" ||
        restoreContext.restoredFromWorkspaceId.length === 0) {
      return "restore context is missing the restore-source workspace id";
    }
    if (!Number.isSafeInteger(restoreContext.restoredFromGeneration) ||
        restoreContext.restoredFromGeneration < 1) {
      return "restore context is missing the restore-source generation";
    }
    // A "migration" wire operation must name its migration kind; a plain
    // "restore" must not (the orchestrator only accepts operation "restore" and
    // an optional migrationKind).
    if (wireOperation === "migration") {
      if (typeof restoreContext.migrationKind !== "string" || restoreContext.migrationKind.length === 0) {
        return "migration requires a non-empty migration kind";
      }
    } else if (restoreContext.migrationKind !== undefined) {
      return "a plain restore must not carry a migration kind";
    }
    return null;
  }

  /**
   * Authorize + derive + run one restore/migration. Resolves to a frozen
   * { ok:true, receipt } on success or a frozen { ok:false, code, reason }
   * refusal. Never throws for an expected refusal.
   *
   * `trustedBinding` is the accepted BIND_WORKSPACE binding (the sole authority
   * source). `leaseCandidate` is the adopted EXCLUSIVE-fence identity and
   * `restoreContext` is the host-held staged-source payload; both are host-held
   * serving state the daemon supplies per-call.
   */
  async function dispatchRestoreMigration({
    message,
    trustedBinding,
    trustedInventoryWorkspace,
    leaseCandidate,
    restoreContext,
    readiness,
  } = {}) {
    if (!isPlainObject(message)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing lifecycle message");
    }
    if (!SUPPORTED_RESTORE_OPERATIONS.has(message.operation)) {
      return refuse(RUNTIME_INCOMPATIBLE, "operation is not a restore/migration operation");
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

    // Guard 3: the exclusive-fence identity is host-held bind-time state.
    if (leaseCandidate === null || typeof leaseCandidate !== "object") {
      return refuse(RUNTIME_INCOMPATIBLE, "missing trusted fence lease candidate");
    }

    // Guard 4: the staged-source restore payload is host-held serving state.
    const restoreContextReason = refuseRestoreContext(restoreContext, message.operation);
    if (restoreContextReason !== null) {
      return refuse(RUNTIME_INCOMPATIBLE, restoreContextReason);
    }

    const sourcePlatform = message.sourcePlatform;
    const materializerPlatform = MATERIALIZER_PLATFORM[sourcePlatform];
    if (!materializerPlatform) {
      return refuse("CONTAINMENT_UNSUPPORTED", `source platform ${String(sourcePlatform)} is not serveable`);
    }

    const hostId = message.hostId;
    const workspaceId = message.workspaceId;
    const workDir = trustedInventoryWorkspace.workDir;

    try {
      const publishIo = await makePublisherIo(workspaceId);
      // The base being promoted onto is the CURRENT live pointer (host-held
      // trusted state; the wire message can never pin it). The successor
      // generation and its candidate/git dir derive from base + 1; the
      // orchestrator re-reads and CAS-guards it.
      const live = await readLiveGeneration(publishIo);
      if (!live || !Number.isSafeInteger(live.activeGeneration) || live.activeGeneration < 1 ||
          typeof live.pointerFingerprint !== "string" || live.pointerFingerprint.length === 0) {
        return refuse("WORKSPACE_GENERATION_STALE", "no live generation is published to promote onto");
      }
      const successorGeneration = live.activeGeneration + 1;
      const segment = generationSegment(successorGeneration);
      const candidatePath = joinPath(workspaceRoot, workspaceId, "generations", segment);
      const gitDir = candidatePath;
      const generationPath = `generations/${segment}`;

      const provenanceIo = makeProvenanceIo(restoreContext.stagingPath);
      assertMethods(provenanceIo, ["readProvenanceRecord"], "provenanceIo");
      const checksumIo = makeChecksumIo(restoreContext.stagingPath);
      assertMethods(checksumIo, ["readBytes"], "checksumIo");

      const deps = {
        containment,
        gitVerifier,
        provenanceIo,
        checksumIo,
        publishIo,
        acquireFence,
        clock,
        maxAgeMs,
        replaySeen,
        ...(hashIdentity ? { hashIdentity } : {}),
      };

      const probedAtMs = clock.now();
      const request = {
        // The orchestrator only accepts operation "restore"; a "migration" wire
        // op is expressed as a restore carrying its migrationKind.
        operation: "restore",
        ...(message.operation === "migration" ? { migrationKind: restoreContext.migrationKind } : {}),
        hostId,
        workspaceId,
        sourcePlatform,
        workDir,
        generationPath,
        candidatePath,
        gitDir,
        stagingPath: restoreContext.stagingPath,
        leaseCandidate,
        expected: { pointerFingerprint: live.pointerFingerprint },
        expectedAuthority: restoreContext.expectedAuthority,
        staged: restoreContext.staged,
        manifest: restoreContext.manifest,
        restoredFromWorkspaceId: restoreContext.restoredFromWorkspaceId,
        restoredFromGeneration: restoreContext.restoredFromGeneration,
        probedAtMs,
        readiness,
        ...(isPlainObject(restoreContext.expectedGraph) ? { expectedGraph: restoreContext.expectedGraph } : {}),
      };

      const receipt = await createWorkspaceRestoreMigrationOperation(deps).runRestoreMigration(request);
      return Object.freeze({ ok: true, receipt });
    } catch (error) {
      // error.code / reason are INTERNAL diagnostics only: the daemon wire
      // boundary whitelists the code against PROTOCOL_ERROR_CODES and never
      // serializes the reason (review S6f.2 F2).
      return refuse(
        typeof error?.code === "string" ? error.code : RUNTIME_INCOMPATIBLE,
        typeof error?.reason === "string" ? error.reason : "restore/migration operation failed",
      );
    }
  }

  return Object.freeze({ dispatchRestoreMigration });
}
