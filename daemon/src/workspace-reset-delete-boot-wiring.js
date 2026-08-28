// Boot + per-connection glue for the S6f.4 workspace reset/delete lifecycle
// dispatch security core (issue #81 / #53 Phase 2).
//
// The reviewed security substance lives in workspace-reset-delete-dispatch.js.
// This module is the thin, unit-testable wiring the daemon uses to (1) construct
// the boot-singleton reset/delete dispatcher and (2) reconstruct the adopted
// EXCLUSIVE-fence identity (leaseCandidate) for a WORKSPACE_RESET_DELETE message
// from the trusted per-connection accepted binding.
//
// The dispatcher stays null until BOTH the human-approved serving gate flips
// (S6f.7, NATIVE_WORKSPACE_SERVING_ENABLED) AND a native serving low-level deps
// bundle is available (S7, issue #171). Until then the daemon holds a null
// dispatcher and the WORKSPACE_RESET_DELETE branch fails closed with
// RUNTIME_INCOMPATIBLE, identical to the S6f.1b contract stub.

import { createLifecycleResetDeleteDispatcher } from "./workspace-reset-delete-dispatch.js";

const HEX64 = /^[0-9a-f]{64}$/;

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

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
 * Reconstruct the adopted EXCLUSIVE-fence identity (leaseCandidate) for a
 * reset/delete from the trusted accepted-binding record. Identical shape to the
 * refresh fence identity (buildRefreshLeaseCandidate); the WorkspaceLeaseRegistry
 * (S6f.1e) matches a candidate by the full binding authority tuple plus its
 * hex64 bindingFingerprint (the value adopted at bind time). The daemon holds
 * both the binding record and the local `computeBindingFingerprint` function;
 * the wire message can never supply it.
 *
 * S7 PLACEHOLDER (issue #182): recomputing the legacy 11-field
 * `bindingFingerprint` here does NOT match a receipt-mode binding adopted as
 * V3 authority + proof.bindingFingerprint + socketGeneration. It fails CLOSED
 * (the registry refuses -> dispatcher catches -> RUNTIME_INCOMPATIBLE), which is
 * safe while serving is gated off and the dispatcher is null. When the native
 * serving path is wired (S7 #171 / before S6f.7), source leaseCandidate from the
 * actual adopted WorkspaceLeaseRegistry candidate instead.
 *
 * Fail-closed: returns null when the binding is missing/not an object, or when
 * the recomputed fingerprint is not a hex64 string (reset/delete then refuses).
 */
export function buildResetDeleteLeaseCandidate(binding, computeBindingFingerprint) {
  if (!isPlainObject(binding)) return null;
  if (typeof computeBindingFingerprint !== "function") return null;
  let bindingFingerprint;
  try {
    bindingFingerprint = computeBindingFingerprint(binding);
  } catch {
    return null;
  }
  if (typeof bindingFingerprint !== "string" || !HEX64.test(bindingFingerprint)) return null;
  return Object.freeze({ ...binding, bindingFingerprint });
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
