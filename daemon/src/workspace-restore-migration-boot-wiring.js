// Boot + per-connection glue for the S6f.5 workspace restore/migration
// lifecycle dispatch security core (issue #81 / #53 Phase 2).
//
// The reviewed security substance lives in workspace-restore-migration-dispatch.js.
// This module is the thin, unit-testable wiring the daemon uses to (1) construct
// the boot-singleton restore/migration dispatcher and (2) reconstruct the adopted
// EXCLUSIVE-fence identity (leaseCandidate) for a WORKSPACE_RESTORE_MIGRATION
// message from the trusted per-connection accepted binding.
//
// The dispatcher stays null until BOTH the human-approved serving gate flips
// (S6f.7, NATIVE_WORKSPACE_SERVING_ENABLED) AND a native serving low-level deps
// bundle is available (S7, issue #171). Until then the daemon holds a null
// dispatcher and the WORKSPACE_RESTORE_MIGRATION branch fails closed with
// RUNTIME_INCOMPATIBLE, identical to the S6f.1b contract stub.

import { createLifecycleRestoreMigrationDispatcher } from "./workspace-restore-migration-dispatch.js";

const HEX64 = /^[0-9a-f]{64}$/;

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

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

/**
 * Reconstruct the adopted EXCLUSIVE-fence identity (leaseCandidate) for a
 * restore/migration from the trusted accepted-binding record. Identical shape to
 * the reset-delete / refresh fence identity; the WorkspaceLeaseRegistry (S6f.1e)
 * matches a candidate by the full binding authority tuple plus its hex64
 * bindingFingerprint (the value adopted at bind time). The daemon holds both the
 * binding record and the local `computeBindingFingerprint` function; the wire
 * message can never supply it.
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
 * the recomputed fingerprint is not a hex64 string (restore then refuses).
 */
export function buildRestoreMigrationLeaseCandidate(binding, computeBindingFingerprint) {
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
