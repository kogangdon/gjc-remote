// Boot + per-connection glue for the S6f.3 workspace refresh lifecycle dispatch
// security core (issue #81 / #53 Phase 2).
//
// The reviewed security substance lives in workspace-refresh-dispatch.js. This
// module is the thin, unit-testable wiring the daemon uses to (1) construct the
// boot-singleton refresh dispatcher and (2) reconstruct the adopted fence
// identity (leaseCandidate) for a WORKSPACE_REFRESH message from the trusted
// per-connection accepted binding.
//
// The trusted-binding resolution and the live-readiness projection are shared
// verbatim with the create wiring (workspace-create-boot-wiring.js:
// resolveTrustedCreateBinding, projectServingReadiness); this module adds only
// the refresh-specific fence-identity reconstruction.
//
// The dispatcher stays null until BOTH the human-approved serving gate flips
// (S6f.7, NATIVE_WORKSPACE_SERVING_ENABLED) AND a native serving low-level deps
// bundle is available (S7, issue #171). Until then the daemon holds a null
// dispatcher and the WORKSPACE_REFRESH branch fails closed with
// RUNTIME_INCOMPATIBLE, identical to the S6f.1b contract stub.

import { createLifecycleRefreshDispatcher } from "./workspace-refresh-dispatch.js";

const HEX64 = /^[0-9a-f]{64}$/;

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * Construct the boot-singleton refresh dispatcher, or null when serving is not
 * eligible. Returns null unless recovery/serving is enabled, a contained
 * workspaceRoot is configured, AND a native serving low-level deps bundle
 * (containment, gitVerifier, makeManifestIo, makePublisherIo, materialize,
 * resolveManifestPaths, acquireFence, clock, maxAgeMs, replaySeen) is supplied
 * (the bundle is the S7/#171 gap). Fail-closed: any missing precondition yields
 * null (refresh then refuses RUNTIME_INCOMPATIBLE).
 */
export function resolveLifecycleRefreshDispatcher({ enabled, workspaceRoot, nativeServingDeps } = {}) {
  if (enabled !== true) return null;
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) return null;
  if (nativeServingDeps === null || typeof nativeServingDeps !== "object") return null;
  return createLifecycleRefreshDispatcher({ workspaceRoot, ...nativeServingDeps });
}

/**
 * Reconstruct the adopted fence identity (leaseCandidate) for a refresh from
 * the trusted accepted-binding record. The activity fence
 * (WorkspaceLeaseRegistry, S6f.1e) matches a candidate by the full binding
 * authority tuple plus its hex64 bindingFingerprint (the value adopted at bind
 * time). The daemon holds both: the binding record and the local
 * `computeBindingFingerprint` function. This is trusted host-held state; the
 * wire message can never supply it.
 *
 * S7 PLACEHOLDER (issue #182): recomputing the legacy 11-field
 * `bindingFingerprint` here does NOT match a receipt-mode binding adopted as
 * V3 authority + proof.bindingFingerprint + socketGeneration. It fails CLOSED
 * (the registry refuses -> dispatcher catches -> RUNTIME_INCOMPATIBLE), which
 * is safe while serving is gated off and the dispatcher is null. When the
 * native serving path is wired (S7 #171 / before S6f.7), source leaseCandidate
 * from the actual adopted WorkspaceLeaseRegistry candidate instead.
 *
 * Fail-closed: returns null when the binding is missing/not an object, or when
 * the recomputed fingerprint is not a hex64 string (refresh then refuses).
 */
export function buildRefreshLeaseCandidate(binding, computeBindingFingerprint) {
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
