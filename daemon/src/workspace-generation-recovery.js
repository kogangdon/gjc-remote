// Generation crash-recovery classifier (slice S6b, #53 Phase 2 / G004).
//
// Pure, io-free state machine over an S6a RecoverySnapshot. Given the durable
// on-disk state a restarted daemon observed for one workspace, it returns
// exactly ONE of four dispositions describing how (or whether) recovery may
// safely resolve a crash that interrupted an S4d generation publish:
//
//   committed            - nothing was in flight, or the op fully completed and
//                          the live pointer already reflects the committed
//                          candidate. Nothing to do.
//   committed-needs-flush - the CAS `replace` already landed (the live pointer
//                          ALREADY equals the transaction's candidate identity)
//                          but the checkpoint never advanced past prepared/
//                          applied. Resolved by re-running ONLY the idempotent
//                          io.flushParent() step (never publishGeneration, whose
//                          CAS precondition would now hard-throw), then advancing
//                          the checkpoint. This is the PM1 case pass-1 wrongly
//                          abandoned to manual_cleanup.
//   safe-replay          - the `replace` never landed (the live pointer STILL
//                          equals the pre-crash prior pointer) AND a recovered
//                          candidate pointer body is present whose self-
//                          fingerprint matches the transaction's recorded
//                          candidate identity. Only here is a fresh
//                          publishGeneration valid - its CAS precondition
//                          (priorPointerFingerprint === live) still holds.
//   manual_cleanup       - every other combination: an existing manual-cleanup
//                          record, a fingerprint mismatch, a would-be safe-replay
//                          whose candidate body is absent/mismatched, or a live
//                          pointer matching neither prior nor candidate identity.
//
// Binding discipline: this classifier compares fingerprint STRINGS carried on
// the validated snapshot; it imports no sibling operation module. The candidate
// identity is sourced from the TRANSACTION record (transaction.candidateFingerprint),
// NEVER from a checkpoint - checkpoints carry no candidate fingerprint field
// (verified schema; operationEvidenceFingerprint is null for phase 'prepared').
// The classifier is a pure return value: it recommends an action but performs
// none, invents no new protocol code, and never maps a live pointer to a
// publishGeneration that would fail its own CAS precondition.

import { validateRecoverySnapshot } from "./workspace-recovery-snapshot.js";

const DISPOSITIONS = Object.freeze(["committed", "committed-needs-flush", "safe-replay", "manual_cleanup"]);

const pointerFp = (pointer) => (pointer === null ? null : pointer.pointerFingerprint);

/**
 * Classify how boot-recovery may resolve one workspace's post-crash generation
 * state. Pure over a validated S6a RecoverySnapshot; returns a frozen
 * `{ disposition }` (safe-replay additionally carries the validated
 * `candidatePointer` to publish). Throws S6a's validator error on a malformed
 * snapshot.
 */
export function classifyGenerationRecovery(snapshot) {
  validateRecoverySnapshot(snapshot);

  // An explicit manual-cleanup record is terminal: the operation already
  // resolved to operator-action-required; recovery never second-guesses it.
  if (snapshot.manualCleanup !== null) return Object.freeze({ disposition: "manual_cleanup" });

  const { transaction, checkpoint } = snapshot;

  // Nothing was in flight (no transaction and no checkpoint): steady state,
  // nothing to recover.
  if (transaction === null && checkpoint === null) return Object.freeze({ disposition: "committed" });

  // An in-flight op requires BOTH its transaction and its checkpoint to be
  // classifiable; a half-present pair is corrupt.
  if (transaction === null || checkpoint === null) return Object.freeze({ disposition: "manual_cleanup" });

  const phase = checkpoint.phase;
  const liveFp = pointerFp(snapshot.livePointer);
  const priorFp = pointerFp(snapshot.priorPointer);
  const candidateFp = transaction.candidateFingerprint; // hex64, sourced from the transaction (F1)
  const candidateBodyFp = pointerFp(snapshot.candidatePointer);

  const replaceLanded = liveFp !== null && liveFp === candidateFp;
  const replaceNeverLanded = liveFp === priorFp; // both-null (first publication) or matching successor
  const candidateBodyMatches = candidateBodyFp !== null && candidateBodyFp === candidateFp;
  // The real S4d CAS precondition: the recovered candidate must chain onto the
  // CURRENT live pointer (its priorPointerFingerprint === liveFp), else a fresh
  // publishGeneration would hard-throw. A snapshot whose priorPointer and
  // candidate lineage disagree is inconsistent and must not be replayed.
  const candidateChainsOntoLive = snapshot.candidatePointer !== null && snapshot.candidatePointer.priorPointerFingerprint === liveFp;

  if (phase === "committed") {
    // Fully done iff the live pointer reflects the committed candidate.
    return Object.freeze({ disposition: replaceLanded ? "committed" : "manual_cleanup" });
  }

  if (phase === "prepared" || phase === "applied") {
    if (replaceLanded) {
      // Rename landed, checkpoint never advanced -> re-flush + advance, never republish.
      return Object.freeze({ disposition: "committed-needs-flush" });
    }
    if (replaceNeverLanded && candidateBodyMatches && candidateChainsOntoLive) {
      // Nothing moved, we hold the exact candidate body, and it chains onto the
      // current live pointer -> a fresh publish is CAS-valid.
      return Object.freeze({ disposition: "safe-replay", candidatePointer: snapshot.candidatePointer });
    }
    // Mismatch, or replay-eligible but no recoverable/ matching candidate body.
    return Object.freeze({ disposition: "manual_cleanup" });
  }

  // phase === "manual_cleanup" (checkpoint already terminal) or any unexpected value.
  return Object.freeze({ disposition: "manual_cleanup" });
}

export { DISPOSITIONS };
