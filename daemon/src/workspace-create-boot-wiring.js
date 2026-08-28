// Boot + per-connection glue for the S6f.2 workspace create/clone lifecycle
// dispatch security core (issue #81 / #53 Phase 2).
//
// The reviewed security substance lives in workspace-create-dispatch.js. This
// module is the thin, unit-testable wiring the daemon uses to (1) construct the
// boot-singleton create dispatcher, (2) resolve the trusted per-connection
// accepted binding for a WORKSPACE_CREATE message, and (3) project the daemon's
// live readiness status into the four-dimension shape the create orchestrator
// consumes.
//
// The dispatcher stays null until BOTH the human-approved serving gate flips
// (S6f.7, NATIVE_WORKSPACE_SERVING_ENABLED) AND a native serving low-level
// deps bundle is available (S7, issue #171). Until then the daemon holds a null
// dispatcher and the WORKSPACE_CREATE branch fails closed with
// RUNTIME_INCOMPATIBLE, identical to the S6f.1b contract stub.

import { createLifecycleCreateDispatcher } from "./workspace-create-dispatch.js";

/**
 * Construct the boot-singleton create dispatcher, or null when serving is not
 * eligible. Returns null unless recovery/serving is enabled, a contained
 * workspaceRoot is configured, AND a native serving low-level deps bundle is
 * supplied (the bundle is the S7/#171 gap). Fail-closed: any missing
 * precondition yields null (create then refuses RUNTIME_INCOMPATIBLE).
 */
export function resolveLifecycleCreateDispatcher({ enabled, workspaceRoot, nativeServingDeps } = {}) {
  if (enabled !== true) return null;
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) return null;
  if (nativeServingDeps === null || typeof nativeServingDeps !== "object") return null;
  return createLifecycleCreateDispatcher({ workspaceRoot, ...nativeServingDeps });
}

/**
 * Resolve the trusted accepted-binding record for a workspaceId from the
 * per-connection bindings Map (keyed by bindingId; each value is a bindingState
 * whose `.binding` carries the 9 authority fields). Returns the binding record
 * or null. This is the SOLE trusted authority source for the create dispatch;
 * the wire message can never supply it.
 *
 * Fail-closed on ambiguity (review S6f.2 MEDIUM): if more than one accepted
 * binding claims the same workspaceId, no single trusted tuple is unambiguous,
 * so return null (create then refuses) rather than pinning an arbitrary one.
 */
export function resolveTrustedCreateBinding(bindings, workspaceId) {
  if (!bindings || typeof bindings[Symbol.iterator] !== "function") return null;
  if (typeof workspaceId !== "string" || workspaceId.length === 0) return null;
  let match = null;
  for (const [, bindingState] of bindings) {
    const binding = bindingState?.binding;
    if (binding && binding.workspaceId === workspaceId) {
      if (match !== null) return null; // ambiguous: two bindings, one workspaceId
      match = binding;
    }
  }
  return match;
}

const SERVING_READINESS_DIMENSIONS = Object.freeze([
  "connection",
  "runtime",
  "providerAuth",
  "modelProfile",
]);

/**
 * Project the daemon's flat live readiness status into the four-dimension
 * { state, source } shape the create orchestrator consumes. source is always
 * "live" because it is the daemon's own current status at dispatch time. A
 * missing dimension projects to state "unknown" (fail-closed at the
 * orchestrator's readiness attestation).
 */
export function projectServingReadiness(status) {
  const snapshot = {};
  for (const dimension of SERVING_READINESS_DIMENSIONS) {
    const state = status && typeof status[dimension] === "string" ? status[dimension] : "unknown";
    snapshot[dimension] = { state, source: "live" };
  }
  return snapshot;
}
