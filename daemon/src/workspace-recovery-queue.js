// Bounded boot-recovery admission queue (slice S6c, #53 Phase 2 / G004).
//
// Pure, io-free primitive. At boot a restarted daemon may discover any number
// of workspaces whose durable state needs crash-recovery classification (S6b).
// This module is the structural proof that recovery can NEVER become an
// unbounded queue: it admits work in fixed-size batches and, above a hard total
// ceiling, refuses ALL progress rather than draining an arbitrarily large
// backlog.
//
// Two fixed ceilings (NOT caller-overridable - a configurable ceiling is not a
// ceiling):
//   MAX_RECOVERY_BATCH = 8   - most workspaces admitted per batch.
//   MAX_RECOVERY_TOTAL = 64  - most workspaces admitted across the whole boot.
//
// planRecoveryBatches(workspaceIds):
//   - workspaceIds must be an array of unique 1..256-char strings.
//   - length > MAX_RECOVERY_TOTAL  -> refuse WORKSPACE_ADMISSION_EXCEEDED with
//     ZERO workspaces processed (all-or-nothing: no partial drain, no batches).
//   - otherwise -> deterministic ordered partition into batches of at most
//     MAX_RECOVERY_BATCH, covering every id exactly once.
// The refusal-above-ceiling is the load-bearing "no unbounded queue" invariant:
// exceeding the total does not process the first 64 and drop the rest, it
// refuses everything so a human sees an explicit admission failure. Barring
// specific workspaces (INV-6 barredWorkspaceIds) is a serving-time concern
// deferred to S6f; this slice only bounds admission volume.

const OPERATION = "workspace_recovery_queue";

// Module-local literals (A5: boot-internal refusals, not wire protocol codes;
// tests assert these exact strings).
const QUEUE_INVALID = "WORKSPACE_RECOVERY_QUEUE_INVALID";
const ADMISSION_EXCEEDED = "WORKSPACE_ADMISSION_EXCEEDED";

const MAX_RECOVERY_BATCH = 8;
const MAX_RECOVERY_TOTAL = 64;

function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (!["code", "operation", "reason", "message"].includes(key)) error[key] = value;
    }
  }
  throw error;
}

const isId = (value) => typeof value === "string" && value.length > 0 && value.length <= 256;

/**
 * Partition the workspaces awaiting boot-recovery into bounded, ordered batches.
 * Refuses the ENTIRE admission (zero processed) when the total exceeds the hard
 * ceiling. Returns a frozen `{ totalAdmitted, batchCount, batches }` where
 * `batches` is a frozen array of frozen id arrays, each of length
 * 1..MAX_RECOVERY_BATCH, together covering every input id once in order.
 */
export function planRecoveryBatches(workspaceIds) {
  if (!Array.isArray(workspaceIds)) refuse(QUEUE_INVALID, "workspaceIds must be an array");
  const seen = new Set();
  for (const id of workspaceIds) {
    if (!isId(id)) refuse(QUEUE_INVALID, "every workspaceId must be a 1..256 char string");
    if (seen.has(id)) refuse(QUEUE_INVALID, `duplicate workspaceId: ${id}`);
    seen.add(id);
  }

  // Hard ceiling: refuse ALL progress above the total. No partial drain.
  if (workspaceIds.length > MAX_RECOVERY_TOTAL) {
    refuse(ADMISSION_EXCEEDED,
      `recovery admission of ${workspaceIds.length} workspaces exceeds the ${MAX_RECOVERY_TOTAL} ceiling`,
      { requested: workspaceIds.length, ceiling: MAX_RECOVERY_TOTAL, admitted: 0 });
  }

  const batches = [];
  for (let index = 0; index < workspaceIds.length; index += MAX_RECOVERY_BATCH) {
    batches.push(Object.freeze(workspaceIds.slice(index, index + MAX_RECOVERY_BATCH)));
  }
  return Object.freeze({
    totalAdmitted: workspaceIds.length,
    batchCount: batches.length,
    batches: Object.freeze(batches),
  });
}

export { MAX_RECOVERY_BATCH, MAX_RECOVERY_TOTAL, QUEUE_INVALID, ADMISSION_EXCEEDED };
