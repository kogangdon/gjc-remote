// Native serving bundle boot wiring (slice S6f.7d).
//
// Testable glue between the daemon boot sequence and the S6f.7d serving-deps
// assembly. Extracted from daemon.js so the pre-mortem #1 degrade-on-fault
// behavior is unit-testable (the top-level daemon script is not).
//
// Resolves the CREATE + REFRESH + RESET/DELETE nativeServingDeps bundles ONLY when BOTH the
// human-approved serving gate is enabled AND boot recovery is enabled. Any
// fault - an invalid readiness config or an assembly throw - degrades serving
// to fail-closed (null bundles) with a sanitized diagnostic, so a serving
// misconfiguration never takes the daemon down or regresses any non-serving
// path. A reset/delete-only native capability fault leaves CREATE/REFRESH live
// and reset/delete null; restore/migration remains intentionally null.

import { assembleNativeServingDeps } from "./native-serving-deps.js";
import { resolveReadinessMaxAgeMs } from "./native-serving-config.js";

const INERT = Object.freeze({
  create: null,
  refresh: null,
  resetDelete: null,
  restoreMigration: null,
  degraded: false,
  diagnostic: null,
});
const RESET_DELETE_KEYS = Object.freeze([
  "makePublisherIo",
  "makeBackupIo",
  "resolveManifestPaths",
  "acquireFence",
]);

/**
 * @param {object} options
 * @param {boolean} options.gateEnabled - NATIVE_WORKSPACE_SERVING_ENABLED.
 * @param {boolean} options.recoveryEnabled - workspaceRecoveryConfig.enabled.
 * @param {string} options.workspaceRoot - contained native workspace root.
 * @param {object} options.workspaceLeases - the WorkspaceLeaseRegistry.
 * @param {Record<string,string|undefined>} [options.env]
 * @param {Function} [options.assemble] - injectable assembler (tests).
 * @param {Function} [options.resolveMaxAge] - injectable config resolver (tests).
 * @param {string} options.hostId - this daemon's bound host identity.
 * @param {"posix"|"windows-drive"} options.sourcePlatform - host path format.
 * @returns {{ create: object|null, refresh: object|null, resetDelete: object|null, restoreMigration: null, degraded: boolean, diagnostic: object|null }}
 */
export function resolveNativeServingBundles({
  gateEnabled,
  recoveryEnabled,
  workspaceRoot,
  workspaceLeases,
  hostId,
  sourcePlatform,
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
    const bundles = assemble({
      workspaceRoot,
      workspaceLeases,
      maxAgeMs: readinessMaxAge.maxAgeMs,
      hostId,
      sourcePlatform,
    });
    if (bundles?.create === null || typeof bundles?.create !== "object" ||
        bundles?.refresh === null || typeof bundles?.refresh !== "object") {
      throw new Error("native serving assembler returned incomplete create/refresh bundles");
    }
    return Object.freeze({
      create: bundles.create,
      refresh: bundles.refresh,
      resetDelete: isCompleteResetDeleteBundle(bundles.resetDelete) ? bundles.resetDelete : null,
      restoreMigration: null,
      degraded: false,
      diagnostic: null,
    });
  } catch (error) {
    // Factory/assembly faults never expose error text, which may contain paths
    // or native-loader details. Preserve only a conventional machine code.
    return degrade({
      code: /^[A-Z][A-Z0-9_]*$/.test(error?.code ?? "")
        ? error.code
        : "NATIVE_SERVING_ASSEMBLY_FAILED",
      reason: "native serving deps assembly failed",
    });
  }
}

function isCompleteResetDeleteBundle(bundle) {
  return bundle !== null &&
    typeof bundle === "object" &&
    RESET_DELETE_KEYS.every((key) => typeof bundle[key] === "function") &&
    typeof bundle.residualIo?.listResidualProcesses === "function";
}

function degrade(diagnostic) {
  return Object.freeze({
    create: null,
    refresh: null,
    resetDelete: null,
    restoreMigration: null,
    degraded: true,
    diagnostic: Object.freeze({
      code: typeof diagnostic?.code === "string" ? diagnostic.code : "NATIVE_SERVING_ASSEMBLY_FAILED",
      reason: typeof diagnostic?.reason === "string" ? diagnostic.reason : "native serving deps assembly failed",
    }),
  });
}
