// Trust-boundary wire sanitizers for the native-serving lifecycle dispatch
// branches (issue #184; #53 Phase 2 / #81). Pure, side-effect-free helpers
// extracted from daemon.js so they are unit-testable without booting the
// daemon (which connects to the bot on import).

import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

/**
 * Whitelist an internal dispatcher result code before it crosses the wire.
 *
 * Only a code the shared PROTOCOL_ERROR_CODES table OWNS may be serialized; a
 * bare `PROTOCOL_ERROR_CODES[code] ?? RUNTIME_INCOMPATIBLE` is unsafe because an
 * inherited Object.prototype key (e.g. "constructor", "toString") resolves to a
 * truthy Function that `??` does NOT fall back on. result.code is internal and
 * typeof-string-checked at the callsite today, so this is defense-in-depth.
 *
 * @param {unknown} code
 * @returns {string} an owned PROTOCOL_ERROR_CODES value, else RUNTIME_INCOMPATIBLE
 */
export function whitelistProtocolCode(code) {
  return typeof code === "string" && Object.hasOwn(PROTOCOL_ERROR_CODES, code)
    ? PROTOCOL_ERROR_CODES[code]
    : PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE;
}

/**
 * Format a sanitized, bounded structured log line for a manual_cleanup receipt,
 * or null when the result is not a manual_cleanup checkpoint.
 *
 * A terminal tombstone publish that crashed mid-CAS returns ok:false carrying a
 * manual_cleanup receipt: a partial-durability operator checkpoint (a dirty
 * backup WAS captured, but the tombstone's durability is unproven). The wire
 * frame stays a sanitized refusal (review F2), so without a distinct log the
 * checkpoint is indistinguishable from a routine refusal. This returns only
 * non-path, bounded fields the operator needs to reconcile the partial-CAS state
 * out of band; it never serializes raw filesystem paths or the full receipt.
 *
 * @param {{ operation?: unknown, workspaceId?: unknown }} msg
 * @param {{ ok?: boolean, receipt?: any }} result
 * @returns {string | null}
 */
export function formatManualCleanupLog(msg, result) {
  const receipt = result?.receipt;
  if (result?.ok || !receipt || receipt.disposition !== "manual_cleanup") return null;
  const mc =
    receipt.manualCleanup && typeof receipt.manualCleanup === "object"
      ? {
          txId: typeof receipt.manualCleanup.txId === "string" ? receipt.manualCleanup.txId : null,
          reason: typeof receipt.manualCleanup.reason === "string" ? receipt.manualCleanup.reason : null,
        }
      : null;
  return `daemon: workspace lifecycle manual_cleanup required: ${JSON.stringify({
    operation: typeof msg?.operation === "string" ? msg.operation : null,
    workspaceId: typeof msg?.workspaceId === "string" ? msg.workspaceId : null,
    disposition: "manual_cleanup",
    dirtyBackupFingerprint:
      typeof receipt.dirtyBackupFingerprint === "string" ? receipt.dirtyBackupFingerprint : null,
    cause:
      receipt.cause && typeof receipt.cause === "object"
        ? {
            code: typeof receipt.cause.code === "string" ? receipt.cause.code : null,
            step: typeof receipt.cause.step === "number" ? receipt.cause.step : null,
          }
        : null,
    manualCleanup: mc,
  })}`;
}
