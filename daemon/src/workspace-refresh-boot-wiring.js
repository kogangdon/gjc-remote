// Boot + per-connection glue for the S6f.3 workspace refresh lifecycle dispatch
// security core (issue #81 / #53 Phase 2).
//
// The reviewed security substance lives in workspace-refresh-dispatch.js. This
// This module is the thin, unit-testable wiring the daemon uses to construct
// the boot-singleton refresh dispatcher. The adopted fence identity
// (leaseCandidate) is sourced by the daemon from the shared fence-identity
// module (workspace-adopted-lease-candidate.js, issue #182).
//
// The trusted-binding resolution and the live-readiness projection are shared
// verbatim with the create wiring (workspace-create-boot-wiring.js:
// resolveTrustedCreateBinding, projectServingReadiness).
//
// The dispatcher stays null until BOTH the human-approved serving gate flips
// (S6f.7, NATIVE_WORKSPACE_SERVING_ENABLED) AND a native serving low-level deps
// bundle is available (S7, issue #171). Until then the daemon holds a null
// dispatcher and the WORKSPACE_REFRESH branch fails closed with
// RUNTIME_INCOMPATIBLE, identical to the S6f.1b contract stub.

import { createLifecycleRefreshDispatcher } from "./workspace-refresh-dispatch.js";

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
