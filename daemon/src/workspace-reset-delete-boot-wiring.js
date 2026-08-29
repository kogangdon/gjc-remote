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

/**
 * Construct the boot-singleton reset/delete dispatcher, or null when serving is
 * not eligible. Returns null unless recovery/serving is enabled, a contained
 * workspaceRoot is configured, AND a native serving low-level deps bundle
 * (makePublisherIo, makeBackupIo, resolveManifestPaths, acquireFence,
 * probeQuiescence, residualIo) is supplied (the bundle is the S7/#171 gap).
 * Fail-closed: any missing precondition yields null (reset/delete then refuses
 * RUNTIME_INCOMPATIBLE).
 */
export function resolveLifecycleResetDeleteDispatcher({ enabled, workspaceRoot, nativeServingDeps } = {}) {
  if (enabled !== true) return null;
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) return null;
  if (nativeServingDeps === null || typeof nativeServingDeps !== "object") return null;
  return createLifecycleResetDeleteDispatcher({ workspaceRoot, ...nativeServingDeps });
}

/**
 * Option-A fail-closed residual-process enumerator placeholder (S7 #171).
 *
 * Certifying that NO OS process remains bound to a workspace before it is
 * destroyed requires a native handle/pid scanner that does not exist yet. Until
 * it lands (S7 #171), this placeholder REFUSES to certify absence: its
 * listResidualProcesses always throws, which assertResidualProcessAbsence
 * (S5c) wraps as a fail-closed CONFIG_INVALID refusal -- a workspace is never
 * destroyed on the basis of an unproven absence. This is only assembled into a
 * nativeServingDeps bundle, and the bundle itself stays absent (dispatcher null)
 * while the serving gate is false, so this code never executes in production
 * today; it exists so the S7 assembler swaps in the real scanner at exactly one
 * seam.
 */
export function createResidualProcessPlaceholderIo() {
  return Object.freeze({
    async listResidualProcesses() {
      const error = new Error(
        "native residual-process enumeration is not implemented (S7 #171); cannot certify absence",
      );
      error.code = "CONFIG_INVALID";
      error.reason = "residual-process enumeration unavailable";
      throw error;
    },
  });
}

/**
 * Select the residual-process enumeration IO for the reset/delete deps bundle
 * at the single swap seam the placeholder promises (S7.3 #171).
 *
 * When a verified native enumerator projection (S7.2
 * createResidualProcessEnumerator) is available, return the real native adapter
 * bound to this host's serving identity (createResidualProcessNativeIo);
 * otherwise fall back to the Option-A placeholder that refuses to certify
 * absence. The native adapter, not this selector, enforces the fail-closed
 * hostId/workspaceId/platform checks. This selector is inert while the serving
 * gate is false: the full nativeServingDeps bundle stays absent, so the
 * dispatcher is null and neither branch executes in production today.
 *
 * @param {object} params
 * @param {?object} params.enumerator native enumerator projection, or null/undefined.
 * @param {string} params.hostId this daemon's own bound host id.
 * @param {string} params.workspaceRoot the contained serving root.
 * @param {"posix"|"windows-drive"} params.sourcePlatform the host path format.
 */
export function resolveResidualProcessIo({ enumerator, hostId, workspaceRoot, sourcePlatform } = {}) {
  if (enumerator === null || enumerator === undefined) {
    return createResidualProcessPlaceholderIo();
  }
  return createResidualProcessNativeIo({ enumerator, hostId, workspaceRoot, sourcePlatform });
}
