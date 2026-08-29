/**
 * Pure native-workspace-serving gate decision (#53/#81 slice S6f.7a).
 *
 * NOT wired into daemon.js by this slice: the NATIVE_WORKSPACE_SERVING_ENABLED
 * serving gate stays hard-disabled (false) after S6f.7a. This module only
 * shapes the boolean decision the later flip slice (S6f.7f) will consume,
 * following the landed-but-unwired precedent of workspace-lease-fence.js.
 *
 * resolveNativeServingEnabled answers exactly one question -- "is native
 * workspace serving eligible at all on this boot?" -- and is deliberately
 * fail-closed and multiplicative:
 *
 *   - (a) the operator opt-in env var GJC_NATIVE_WORKSPACE_SERVING must be the
 *     EXACT string "1". Every other value (unset, "", whitespace, "0",
 *     "false", "TRUE", "1 " with a trailing space, a non-string, etc.) reads
 *     as disabled. This uses an explicit === "1" allowlist, never a generic
 *     truthiness / Boolean() coercion, to eliminate the classic env-var
 *     fail-open bug class (pre-mortem #2).
 *   - (b) inventoryReceiptAdvertised must be the boolean literal true (the
 *     daemon's already-computed protocol-v3 + receipt-capability signal at
 *     daemon.js:155-158). A truthy-but-non-true value never enables serving.
 *
 * This boolean is NOT a per-operation switch: each resolve*Dispatcher keeps its
 * own per-operation bundle-completeness / dispatcher-null check, and the
 * per-workspace barred-workspace admission check is separate again. This gate
 * is only the outermost AND-ed term.
 */

/**
 * @param {{ env?: Record<string, unknown>, inventoryReceiptAdvertised?: unknown }} input
 * @returns {boolean} true only when the env opt-in is exactly "1" AND
 *   inventoryReceiptAdvertised is exactly boolean true; false otherwise.
 */
export function resolveNativeServingEnabled({ env, inventoryReceiptAdvertised } = {}) {
  const optIn = env == null ? undefined : env.GJC_NATIVE_WORKSPACE_SERVING;
  const envEnabled = optIn === "1";
  return envEnabled && inventoryReceiptAdvertised === true;
}
