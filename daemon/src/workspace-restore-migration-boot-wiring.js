// Boot + per-connection glue for the S6f.5 workspace restore/migration
// lifecycle dispatch security core (issue #81 / #53 Phase 2).
//
// The reviewed security substance lives in workspace-restore-migration-dispatch.js.
// This module is the thin, unit-testable wiring the daemon uses to construct
// the boot-singleton restore/migration dispatcher. The adopted EXCLUSIVE-fence
// identity (leaseCandidate) is sourced by the daemon from the shared fence-
// identity module (workspace-adopted-lease-candidate.js, issue #182).
//
// The dispatcher stays null until BOTH the human-approved serving gate flips
// (S6f.7, NATIVE_WORKSPACE_SERVING_ENABLED) AND a native serving low-level deps
// bundle is available (S7, issue #171). Until then the daemon holds a null
// dispatcher and the WORKSPACE_RESTORE_MIGRATION branch fails closed with
// RUNTIME_INCOMPATIBLE, identical to the S6f.1b contract stub.

import { createLifecycleRestoreMigrationDispatcher } from "./workspace-restore-migration-dispatch.js";

/**
 * Construct the boot-singleton restore/migration dispatcher, or null when serving
 * is not eligible. Returns null unless recovery/serving is enabled, a contained
 * workspaceRoot is configured, AND a native serving low-level deps bundle
 * (makePublisherIo, containment, gitVerifier, makeProvenanceIo, makeChecksumIo,
 * acquireFence, clock, maxAgeMs, replaySeen) is supplied (the bundle is the
 * S7/#171 gap). Fail-closed: any missing precondition yields null (restore then
 * refuses RUNTIME_INCOMPATIBLE).
 */
export function resolveLifecycleRestoreMigrationDispatcher({ enabled, workspaceRoot, nativeServingDeps } = {}) {
  if (enabled !== true) return null;
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) return null;
  if (nativeServingDeps === null || typeof nativeServingDeps !== "object") return null;
  return createLifecycleRestoreMigrationDispatcher({ workspaceRoot, ...nativeServingDeps });
}
