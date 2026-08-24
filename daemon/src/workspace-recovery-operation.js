// Boot crash-recovery orchestrator (slice S6d, #53 Phase 2 / G004).
//
// This is a WIRING orchestrator: it composes the S6 pure primitives (S6a
// snapshot, S6b classifier, S6c bounded queue) with the S4d generation
// publisher over an INJECTED io seam. The io is the deterministic crash-sim
// surface - every read/act is an injected async function that a test can make
// throw at a chosen step; the orchestrator itself performs no timing and no
// real filesystem work.
//
// recoverWorkspaces(deps, workspaceIds):
//   1. planRecoveryBatches(workspaceIds) (S6c) bounds admission; above the hard
//      ceiling it refuses ALL progress (WORKSPACE_ADMISSION_EXCEEDED) and this
//      orchestrator processes nothing.
//   2. For each admitted workspace, in batch order:
//        a. buildRecoverySnapshot from deps.readSnapshotInputs(workspaceId) (S6a).
//        b. classifyGenerationRecovery(snapshot) (S6b) -> one of four dispositions.
//        c. act on the disposition, and ONLY that disposition:
//           - committed             -> no action.
//           - committed-needs-flush -> re-run ONLY the idempotent io.flushParent()
//                                      (NEVER publishGeneration - its CAS would
//                                      now hard-throw). A second recovery pass over
//                                      the same durable state re-flushes idempotently.
//           - safe-replay           -> publishGeneration(io, candidatePointer) (S4d),
//                                      whose CAS precondition still holds. After it
//                                      lands, a second pass sees live==candidate and
//                                      routes to committed-needs-flush (flush, not a
//                                      second publish) - so replay is single-shot.
//           - manual_cleanup        -> take NO action; add workspaceId to
//                                      barredWorkspaceIds (operator must resolve).
//   3. A per-workspace io/validation failure is fail-closed to that ONE workspace:
//      it is barred and recovery CONTINUES for the rest (one corrupt workspace
//      never blocks boot for the others). Only a queue ceiling breach aborts all.
//
// Boot recovery makes NO WorkspaceLeaseRegistry calls: the registry starts EMPTY
// on a fresh process (F3 Option b), so this module neither imports nor touches
// it. That absence is a load-bearing invariant, asserted by the tests.
//
// barredWorkspaceIds is the set a later serving-admission gate (INV-6, S6f) must
// refuse to serve until an operator resolves them; producing it is this slice's
// job, enforcing it is S6f's.

import { buildRecoverySnapshot } from "./workspace-recovery-snapshot.js";
import { classifyGenerationRecovery } from "./workspace-generation-recovery.js";
import { planRecoveryBatches } from "./workspace-recovery-queue.js";
import { publishGeneration } from "./workspace-generation-publisher.js";

const OPERATION = "workspace_recovery_operation";
const OPERATION_INVALID = "WORKSPACE_RECOVERY_OPERATION_INVALID";

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

const isFn = (value) => typeof value === "function";

/**
 * Orchestrate boot crash-recovery for a set of workspaces. Pure control flow
 * over an injected io seam.
 *
 * @param {object} deps
 * @param {(workspaceId: string) => Promise<object>} deps.readSnapshotInputs -
 *   returns the durable recovery-snapshot fields (livePointer, priorPointer,
 *   candidatePointer, checkpoint, transaction, manualCleanup) for one workspace.
 * @param {(workspaceId: string) => object} deps.publisherIo - returns the S4d
 *   generation-publisher io (readLivePointer/writeTemp/flushTemp/replace/flushParent)
 *   for one workspace; used for safe-replay publish and committed-needs-flush flush.
 * @param {string[]} workspaceIds - workspaces awaiting recovery.
 * @returns frozen `{ admitted, batchCount, processed, barredWorkspaceIds }`.
 */
export async function recoverWorkspaces(deps, workspaceIds) {
  if (deps === null || typeof deps !== "object") refuse(OPERATION_INVALID, "deps must be an object");
  if (!isFn(deps.readSnapshotInputs)) refuse(OPERATION_INVALID, "deps.readSnapshotInputs must be a function");
  if (!isFn(deps.publisherIo)) refuse(OPERATION_INVALID, "deps.publisherIo must be a function");

  // S6c bounds admission; an over-ceiling backlog throws here with zero processed.
  const plan = planRecoveryBatches(workspaceIds);

  const processed = [];
  const barredWorkspaceIds = [];

  for (const batch of plan.batches) {
    for (const workspaceId of batch) {
      let disposition = null;
      let action = "barred";
      let failure = null;
      try {
        const inputs = await deps.readSnapshotInputs(workspaceId);
        const snapshot = buildRecoverySnapshot({ ...inputs, workspaceId });
        const classified = classifyGenerationRecovery(snapshot);
        disposition = classified.disposition;
        if (disposition === "committed") {
          action = "none";
        } else if (disposition === "committed-needs-flush") {
          await deps.publisherIo(workspaceId).flushParent();
          action = "flushed";
        } else if (disposition === "safe-replay") {
          await publishGeneration(deps.publisherIo(workspaceId), classified.candidatePointer);
          action = "republished";
        } else {
          action = "barred";
        }
      } catch (error) {
        // Fail-closed to this one workspace: bar it, keep recovering the rest.
        // Preserve the classified disposition (if we got that far) for diagnostics -
        // a safe-replay that threw mid-publish is barred as a *safe-replay* failure,
        // not silently relabeled; a pre-classify read/validate failure has no
        // disposition yet and is recorded as manual_cleanup.
        if (disposition === null) disposition = "manual_cleanup";
        action = "barred";
        failure = { code: String(error?.code ?? "unknown"), reason: String(error?.reason ?? error?.message ?? "unknown") };
      }
      if (action === "barred") barredWorkspaceIds.push(workspaceId);
      processed.push(Object.freeze(failure ? { workspaceId, disposition, action, failure: Object.freeze(failure) } : { workspaceId, disposition, action }));
    }
  }

  return Object.freeze({
    admitted: plan.totalAdmitted,
    batchCount: plan.batchCount,
    processed: Object.freeze(processed),
    barredWorkspaceIds: Object.freeze(barredWorkspaceIds),
  });
}

export { OPERATION_INVALID };
