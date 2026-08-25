// Reset / delete lifecycle orchestrator for the native workspace data plane
// (#53 Phase 2, slice S5e).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations
// -> Reset/delete row): a destructive reset/delete is admissible ONLY when every
// one of these holds, in order:
//   1. Exclusive prompt/read fence            (S5b acquireActivity({exclusive:true}))
//   2. Workload quiescence                    (S5b assertQuiescent)
//   3. Fence still current                     (fence recheck before any capture)
//   4. Dirty backup captured + complete        (S5a computeDirtyBackup)
//   5. No residual process bound to the ws     (S5c assertResidualProcessAbsence)
//   6. Fence still current                     (fence recheck immediately pre-mutation)
//   7. Terminal tombstone published (CAS)      (S5d buildTombstone + publishTombstone)
//
// This module is the LAST slice of the reset/delete family: it COMPOSES the S5a
// dirty-backup, S5b exclusive-lease + quiescence, S5c residual-process, and S5d
// tombstone primitives verbatim (by import, an Option-C sanctioned wiring
// orchestrator) and reuses S4d's atomic single-slot linearization point through
// S5d's publisher. It performs NO direct filesystem, subprocess, or network I/O
// itself, does NOT read or flip the native-workspace-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false), and is NOT wired into
// daemon.js request dispatch. Live enablement is the separate S7 boundary.
//
// Destruction ordering guarantee: the live content is never destroyed before a
// dirty backup is durably captured and fingerprinted (step 4), no residual
// process is still bound (step 5), and the exclusive fence is still current
// immediately before the tombstone flip (step 6). The tombstone publication
// (step 7) is the SOLE live-slot mutation and is itself old-or-new atomic (S4d
// discipline via S5d). Any refusal in steps 1-3 leaves the workspace untouched.
//
// Disposition contract:
//   - "committed"          tombstone published cleanly onto the live record.
//   - "already_tombstoned" the live slot already holds a tombstone chaining onto
//                          the caller's expected base (A4 idempotent re-delete);
//                          no second CAS, no fs mutation.
//   - "manual_cleanup"     a dirty backup WAS captured (step 4) and the terminal
//                          tombstone PUBLICATION (step 7) began but its ordered
//                          io failed (writeTemp/flushTemp/replace/flushParent) --
//                          including a post-replace flushParent failure whose
//                          durability is unproven -- so the CAS may have partially
//                          executed. The operator must reconcile. The result
//                          carries a manual-cleanup record built ENTIRELY from
//                          injected `request.lifecycleAuthority` fields (A6 --
//                          never derived) that passes the shared
//                          `validateManualCleanup` and classifies as
//                          "manual_cleanup".
//
// Steps 1-6 failures (fence acquisition, quiescence, fence rechecks, backup,
// residual-process presence, stale-CAS base) are CLEAN structured rejections:
// the captured backup is non-destructive and the sole live-slot mutation never
// began, so the workspace is left exactly intact.
//
// A5 code discipline: this module reuses module-local S4/S5 codes at the module
// level and PROTOCOL_ERROR_CODES entries; it registers nothing new in
// shared/protocol.js.

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
const TOMBSTONE_KIND = "workspace-tombstone";
const RESET_DELETE_OPERATIONS = new Set(["reset", "delete"]);

// The exact injected authority sub-object S5e needs to produce a manual-cleanup
// record (A6). Every field is a source field of shared/recovery-envelope.js
// `validateManualCleanup`; version/kind/routeDisposition/blockedUntilOwnerAction
// are supplied as fixed constants and manualCleanupFingerprint is computed. S5e
// NEVER derives or defaults these -- a missing field is a fail-closed refusal.
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

/** Refuse with a structured error carrying a protocol `.code`. */
function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (!["code", "operation", "reason", "message"].includes(key)) error[key] = value;
    }
  }
  throw error;
}

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const hasExactKeys = (value, keys) =>
  isPlainObject(value) && Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

const isNonEmptyString = (value) => typeof value === "string" && value.length > 0;

function assertFn(container, name, path) {
  if (!container || typeof container[name] !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `${path}.${name} must be a function`);
  }
}

/**
 * Build a reset/delete operation bound to its injected collaborators.
 *
 * deps = {
 *   acquireFence,      // (leaseCandidate) => { fence, isCurrent(), release() }
 *                      //   the WorkspaceLeaseRegistry.acquireActivity({exclusive:true})
 *                      //   fence; throws WORKSPACE_BUSY / LEASE_CONFLICT /
 *                      //   WORKSPACE_ADMISSION_EXCEEDED on acquisition failure.
 *   probeQuiescence,   // () => { pendingInvokes, pendingSessions } | Promise<...>
 *                      //   trusted live workload counts (NOT requester-sourced).
 *   backupIo,          // S5a/S4c io: { readBytes(relPath) } reparse-safe reader
 *   residualIo,        // S5c io:     { listResidualProcesses({hostId, workspaceId}) }
 *   tombstoneIo,       // S5d io:     { readLivePointer, writeTemp, flushTemp,
 *                      //               replace, flushParent }
 * }
 */
export function createWorkspaceResetDeleteOperation(deps = {}) {
  if (!isPlainObject(deps)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "createWorkspaceResetDeleteOperation requires a deps object");
  }
  const { acquireFence, probeQuiescence, backupIo, residualIo, tombstoneIo } = deps;

  if (typeof acquireFence !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "acquireFence must be a function");
  }
  if (typeof probeQuiescence !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "probeQuiescence must be a function");
  }
  assertFn(backupIo, "readBytes", "backupIo");
  assertFn(residualIo, "listResidualProcesses", "residualIo");
  for (const method of ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"]) {
    assertFn(tombstoneIo, method, "tombstoneIo");
  }

  function assertRequest(request) {
    if (!isPlainObject(request)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request must be an object");
    }
    if (!RESET_DELETE_OPERATIONS.has(request.operation)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "operation must be 'reset' or 'delete'");
    }
    for (const key of ["hostId", "workspaceId", "sourcePlatform"]) {
      if (!isNonEmptyString(request[key])) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.${key} must be a non-empty string`);
      }
    }
    if (request.leaseCandidate === undefined || request.leaseCandidate === null) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.leaseCandidate is required for the exclusive fence");
    }
    if (!isPlainObject(request.dirtyBackup)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.dirtyBackup must be an object");
    }
    if (!isPlainObject(request.expected) || !isNonEmptyString(request.expected.priorPointerFingerprint)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.expected.priorPointerFingerprint must be a non-empty string");
    }
    // Authority for the manual-cleanup path is shape-validated up front (A6):
    // it must be fully present BEFORE any fence acquisition or mutation, so a
    // failure in steps 5-7 can always emit a complete checkpoint.
    if (!hasExactKeys(request.lifecycleAuthority, LIFECYCLE_AUTHORITY_KEYS)) {
      refuse(
        PROTOCOL_ERROR_CODES.CONFIG_INVALID,
        `request.lifecycleAuthority must carry exactly ${LIFECYCLE_AUTHORITY_KEYS.join(", ")}`,
      );
    }
  }

  // The exclusive fence must still be current at a checkpoint; a lost fence means
  // a concurrent invalidation / rebind raced this destructive operation.
  function assertFenceCurrent(lease, checkpoint) {
    if (!lease.isCurrent()) {
      refuse(PROTOCOL_ERROR_CODES.LEASE_CONFLICT, `exclusive fence was lost before ${checkpoint}`, { checkpoint });
    }
  }

  // Build a manual-cleanup record ENTIRELY from injected authority fields (A6),
  // fingerprint it with the shared recovery hash, and prove it classifies as
  // manual_cleanup through the real shared vocabulary. Never fabricates fields.
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
    // validateManualCleanup throws WORKSPACE_LIFECYCLE_ENVELOPE_INVALID on a
    // malformed injected field; surface it as a fail-closed CONFIG_INVALID so a
    // partial checkpoint is never emitted.
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
   * Run one reset/delete lifecycle transition. Resolves to a frozen result whose
   * `disposition` is "committed", "already_tombstoned", or "manual_cleanup".
   * Rejects with a structured refusal (`.code` a protocol value) for any failure
   * in steps 1-6 (fence acquisition, quiescence, fence rechecks, backup capture,
   * residual-process presence) and for a stale-CAS/malformed publish base: the
   * workspace is left intact. Only a failure of the ordered tombstone
   * publication io (step 7) is converted into a manual_cleanup disposition,
   * because the CAS may have partially executed. The exclusive fence is always
   * released.
   */
  async function runResetDelete(request) {
    assertRequest(request);
    const { operation, hostId, workspaceId, sourcePlatform } = request;

    // Build the manual-cleanup checkpoint record EAGERLY, before any fence or io
    // (A6, pure): a semantically-invalid injected authority is a fail-closed
    // CONFIG_INVALID rejection here with zero side effects, so the step-7 catch
    // can never discover a bad authority AFTER the tombstone may already be live
    // (which would lose the checkpoint and mislabel a live-slot state). The
    // frozen record is reused verbatim on the manual_cleanup path.
    const manualCleanup = buildManualCleanup(request.lifecycleAuthority);

    // Step 1 -- acquire the EXCLUSIVE prompt/read fence. Throws WORKSPACE_BUSY /
    // LEASE_CONFLICT / WORKSPACE_ADMISSION_EXCEEDED on acquisition failure (no
    // fence to release, no io touched -> zero fs mutation).
    const lease = acquireFence(request.leaseCandidate);
    let dirtyBackupFingerprint = null;
    try {
      if (!lease || typeof lease.isCurrent !== "function" || typeof lease.release !== "function") {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "acquireFence must return a lease with { isCurrent, release }");
      }

      // A4 idempotent re-delete -- if the live slot ALREADY holds a tombstone
      // chaining onto the caller's expected base, this destruction already
      // happened: short-circuit with zero CAS and zero mutation. The prior read
      // is a benign read-only probe that precedes the step-2 quiescence gate.
      // Host/workspace need not be re-checked: priorPointerFingerprint is a
      // globally-unique canonical hash, so an exact match already pins identity.
      const priorLive = await readLiveDisposition(tombstoneIo);
      if (
        priorLive !== null &&
        priorLive.kind === TOMBSTONE_KIND &&
        priorLive.record.priorPointerFingerprint === request.expected.priorPointerFingerprint
      ) {
        return Object.freeze({
          operation,
          published: false,
          tombstone: priorLive.record,
          fence: lease.fence,
          dirtyBackupFingerprint: null,
          disposition: "already_tombstoned",
        });
      }

      // Step 2 -- workload quiescence. Refuses WORKSPACE_BUSY when a prompt/read
      // is still in flight against this workspace.
      assertQuiescent(await probeQuiescence());

      // Step 3 -- the exclusive fence must still be current before we capture.
      assertFenceCurrent(lease, "dirty-backup");

      // Step 4 -- capture the dirty backup of the live tree. A partial/unreadable
      // tree aborts here (WORKSPACE_MANIFEST_*) with nothing destroyed. The
      // backup is complete-checked inside computeDirtyBackup.
      const backup = await computeDirtyBackup(backupIo, request.dirtyBackup);
      dirtyBackupFingerprint = backup.manifestFingerprint;

      // Step 5 -- no residual process may still be bound to the workspace. A
      // present process is a clean rejection (WORKSPACE_RESIDUAL_PROCESS): the
      // captured backup is non-destructive, so the live slot is untouched.
      await assertResidualProcessAbsence(residualIo, { hostId, workspaceId });

      // Step 6 -- the exclusive fence must still be current immediately before
      // the sole live-slot mutation. A lost fence is a clean LEASE_CONFLICT
      // rejection: nothing is published.
      assertFenceCurrent(lease, "publication");

      // Step 7 -- build and publish the terminal tombstone, CAS onto the exact
      // currently-live record read via the dual-kind reader. The disposed
      // generation, priorKind, and priorPointerFingerprint are all DERIVED from
      // the live record, never the requester. A null slot, a live record that
      // diverged from the caller's expected base (a concurrent generation
      // publication that raced this operation before or during it), or a stale
      // intra-publish CAS base is a clean rejection (no mutation); only a failure
      // of the ordered publication io itself is converted into manual_cleanup.
      const live = await readLiveDisposition(tombstoneIo);
      if (live === null) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "no live record to tombstone");
      }
      // Optimistic expected-base gate (mirrors S4g assertExpectedBase): the
      // requester pins the exact live record it intends to tombstone. A mismatch
      // means the generation advanced before the fence closed the window, so the
      // enumerated dirty backup describes a stale generation -- refuse rather
      // than tombstone a base the caller never saw. Clean rejection, no mutation.
      if (live.fingerprint !== request.expected.priorPointerFingerprint) {
        refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "live record diverged from the expected base before publication", {
          step: "cas",
          expectedPriorPointerFingerprint: request.expected.priorPointerFingerprint,
          liveFingerprint: live.fingerprint,
        });
      }
      const tombstonedGeneration = live.kind === POINTER_KIND
        ? live.record.activeGeneration
        : live.record.tombstonedGeneration;
      const tombstone = buildTombstone({
        hostId,
        workspaceId,
        sourcePlatform,
        operation,
        tombstonedGeneration,
        priorKind: live.kind,
        priorPointerFingerprint: live.fingerprint,
        dirtyBackupFingerprint,
      });

      let published;
      try {
        published = await publishTombstone(tombstoneIo, tombstone);
      } catch (error) {
        // Only a failure of the ordered publication io (writeTemp/flushTemp/
        // replace/flushParent) is ambiguous enough for manual_cleanup: the CAS
        // may have partially executed or a post-replace flush left durability
        // unproven. Any other throw (stale CAS base, malformed record) means no
        // mutation happened -- re-throw it as a clean rejection.
        if (!TOMBSTONE_STEPS.includes(error?.step)) throw error;
        return Object.freeze({
          operation,
          published: false,
          tombstone,
          fence: lease.fence,
          dirtyBackupFingerprint,
          disposition: "manual_cleanup",
          manualCleanup,
          cause: Object.freeze({
            code: typeof error?.code === "string" ? error.code : null,
            step: error.step,
          }),
        });
      }

      return Object.freeze({
        operation,
        published: Object.freeze({ ...published }),
        tombstone,
        fence: lease.fence,
        dirtyBackupFingerprint,
        disposition: "committed",
      });
      // Steps 1-6 failures propagate as structured rejections (workspace intact).
      // The manual-cleanup authority was already validated eagerly above, so the
      // step-7 catch only ever reuses a proven-good frozen record.
    } finally {
      if (lease && typeof lease.release === "function") lease.release();
    }
  }

  return Object.freeze({ runResetDelete });
}
