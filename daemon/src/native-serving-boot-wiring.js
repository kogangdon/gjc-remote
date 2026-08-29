// Native serving bundle boot wiring (slice S6f.7d).
//
// Testable glue between the daemon boot sequence and the S6f.7d serving-deps
// assembly. Extracted from daemon.js so the pre-mortem #1 degrade-on-fault
// behavior is unit-testable (the top-level daemon script is not).
//
// Resolves the CREATE + REFRESH nativeServingDeps bundles ONLY when BOTH the
// human-approved serving gate is enabled AND boot recovery is enabled. Any
// fault - an invalid readiness config or an assembly throw - degrades serving
// to fail-closed (null bundles) with a sanitized diagnostic, so a serving
// misconfiguration never takes the daemon down or regresses any non-serving
// path. reset/delete + restore/migration are excluded (Option C-narrow) and
// are never assembled here.

import { assembleNativeServingDeps } from "./native-serving-deps.js";
import { resolveReadinessMaxAgeMs } from "./native-serving-config.js";

const INERT = Object.freeze({ create: null, refresh: null, degraded: false, diagnostic: null });

/**
 * @param {object} options
 * @param {boolean} options.gateEnabled - NATIVE_WORKSPACE_SERVING_ENABLED.
 * @param {boolean} options.recoveryEnabled - workspaceRecoveryConfig.enabled.
 * @param {string} options.workspaceRoot - contained native workspace root.
 * @param {object} options.workspaceLeases - the WorkspaceLeaseRegistry.
 * @param {Record<string,string|undefined>} [options.env]
 * @param {Function} [options.assemble] - injectable assembler (tests).
 * @param {Function} [options.resolveMaxAge] - injectable config resolver (tests).
 * @returns {{ create: object|null, refresh: object|null, degraded: boolean, diagnostic: object|null }}
 */
export function resolveNativeServingBundles({
  gateEnabled,
  recoveryEnabled,
  workspaceRoot,
  workspaceLeases,
  env = process.env,
  assemble = assembleNativeServingDeps,
  resolveMaxAge = resolveReadinessMaxAgeMs,
} = {}) {
  // Gate closed (or recovery off): serving is inert, NOT a degradation.
  if (gateEnabled !== true || recoveryEnabled !== true) {
    return INERT;
  }
  try {
    const readinessMaxAge = resolveMaxAge({ env });
    if (readinessMaxAge.ok !== true) {
      return degrade(readinessMaxAge.diagnostic);
    }
    const bundles = assemble({ workspaceRoot, workspaceLeases, maxAgeMs: readinessMaxAge.maxAgeMs });
    return Object.freeze({ create: bundles.create, refresh: bundles.refresh, degraded: false, diagnostic: null });
  } catch (error) {
    // Factory/assembly faults carry only fixed diagnostic text (no secrets):
    // surface the sanitized code + message so boot logging is actionable while
    // serving stays fail-closed.
    return degrade({
      code: typeof error?.code === "string" ? error.code : "NATIVE_SERVING_ASSEMBLY_FAILED",
      reason: typeof error?.message === "string" ? error.message : "native serving deps assembly failed",
    });
  }
}

function degrade(diagnostic) {
  return Object.freeze({ create: null, refresh: null, degraded: true, diagnostic: Object.freeze({ ...diagnostic }) });
}
