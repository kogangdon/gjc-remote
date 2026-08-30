// Boot + per-connection glue for the S6f.4 workspace reset/delete lifecycle
// dispatch security core (issue #81 / #53 Phase 2).
//
// The reviewed security substance lives in workspace-reset-delete-dispatch.js.
// This module is the thin, unit-testable wiring the daemon uses to construct
// the boot-singleton reset/delete dispatcher. The adopted EXCLUSIVE-fence
// identity (leaseCandidate) is sourced by the daemon from the shared fence-
// identity module (workspace-adopted-lease-candidate.js, issue #182).
//
// The dispatcher stays null until BOTH the human-approved serving gate flips
// (S6f.7, NATIVE_WORKSPACE_SERVING_ENABLED) AND a native serving low-level deps
// bundle is available (S7, issue #171). Until then the daemon holds a null
// dispatcher and the WORKSPACE_RESET_DELETE branch fails closed with
// RUNTIME_INCOMPATIBLE, identical to the S6f.1b contract stub.

import { createLifecycleResetDeleteDispatcher } from "./workspace-reset-delete-dispatch.js";
import { createResidualProcessNativeIo } from "./workspace-residual-process-native-io.js";

const RESET_DELETE_DEPENDENCIES = Object.freeze([
  "makePublisherIo",
  "makeBackupIo",
  "resolveManifestPaths",
  "acquireFence",
]);

/**
 * Construct the boot-singleton reset/delete dispatcher, or null when serving is
 * not eligible. Returns null unless recovery/serving is enabled, a contained
 * workspaceRoot is configured, AND a native serving low-level deps bundle
 * (makePublisherIo, makeBackupIo, resolveManifestPaths, acquireFence,
 * residualIo) is supplied. Per-call lifecycle quiescence and terminal
 * callbacks are supplied by lifecycleContext, never the static bundle.
 * Fail-closed: any missing precondition yields null (reset/delete then refuses
 * RUNTIME_INCOMPATIBLE).
 */
export function resolveLifecycleResetDeleteDispatcher({ enabled, workspaceRoot, nativeServingDeps } = {}) {
  if (enabled !== true) return null;
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) return null;
  if (nativeServingDeps === null || typeof nativeServingDeps !== "object") return null;
  try {
    if (
      RESET_DELETE_DEPENDENCIES.some((name) => typeof nativeServingDeps[name] !== "function") ||
      typeof nativeServingDeps.residualIo?.listResidualProcesses !== "function"
    ) {
      return null;
    }
    return createLifecycleResetDeleteDispatcher({ ...nativeServingDeps, workspaceRoot });
  } catch {
    return null;
  }
}

/**
 * Select the residual-process enumeration IO for the reset/delete deps bundle
 * at the single swap seam the placeholder promises (S7.3 #171).
 *
 * Binds a verified native enumerator projection (S7.2
 * createResidualProcessEnumerator) to this host's serving identity. Missing
 * capability is rejected by the caller, which leaves reset/delete null.
 *
 * @param {object} params
 * @param {?object} params.enumerator native enumerator projection, or null/undefined.
 * @param {string} params.hostId this daemon's own bound host id.
 * @param {string} params.workspaceRoot the contained serving root.
 * @param {"posix"|"windows-drive"} params.sourcePlatform the host path format.
 */
export function resolveResidualProcessIo({ enumerator, hostId, workspaceRoot, sourcePlatform } = {}) {
  return createResidualProcessNativeIo({ enumerator, hostId, workspaceRoot, sourcePlatform });
}
