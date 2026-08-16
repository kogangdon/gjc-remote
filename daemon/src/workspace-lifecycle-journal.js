import {
  classifyWorkspaceLifecycleEvidence,
  validateWorkspaceLifecycleCheckpoint,
  validateWorkspaceLifecycleHead,
  validateWorkspaceLifecycleTransaction,
} from "../../shared/workspace-lifecycle-envelope.js";
import { validateManualCleanup } from "../../shared/recovery-envelope.js";

const faultStages = new Set(["create", "flush", "replace", "head-cas"]);
const fault = (stage) => { const error = new Error(`WORKSPACE_LIFECYCLE_JOURNAL_FAULT: ${stage}`); error.code = "WORKSPACE_LIFECYCLE_JOURNAL_FAULT"; return error; };
const conflict = () => { const error = new Error("WORKSPACE_LIFECYCLE_JOURNAL_CONFLICT"); error.code = "WORKSPACE_LIFECYCLE_JOURNAL_CONFLICT"; return error; };

/**
 * Deterministic in-memory lifecycle-journal test port. It performs no filesystem
 * I/O and makes no host durability, recovery, takeover, or serving claim.
 */
export class DeterministicWorkspaceLifecycleJournal {
  constructor({ failures = [] } = {}) {
    this.failures = new Set(failures);
    for (const stage of this.failures) if (!faultStages.has(stage)) throw new TypeError("WORKSPACE_LIFECYCLE_JOURNAL_INVALID_FAULT");
    this.records = new Map();
    this.head = null;
    this.heads = new Map();
    this.manualCleanup = null;
  }

  #boundary(stage) { if (this.failures.delete(stage)) throw fault(stage); }

  /** Exclusively creates a transaction record in this non-durable test port. */
  create(transaction) {
    this.#boundary("create");
    validateWorkspaceLifecycleTransaction(transaction);
    if (this.records.has(transaction.txId)) throw conflict();
    this.records.set(transaction.txId, { transaction, checkpoint: null });
    return transaction;
  }

  /** Flushes the first checkpoint for its transaction in this non-durable test port. */
  flush(checkpoint) {
    this.#boundary("flush");
    const entry = this.records.get(checkpoint?.txId);
    if (!entry || entry.checkpoint !== null) throw conflict();
    validateWorkspaceLifecycleCheckpoint(checkpoint, entry.transaction);
    if (checkpoint.phase !== "prepared") throw conflict();
    entry.checkpoint = checkpoint;
    return checkpoint;
  }

  /** Replaces a checkpoint only when its supplied fingerprint matches the current record. */
  replace(checkpoint, expectedCheckpointFingerprint) {
    this.#boundary("replace");
    const entry = this.records.get(checkpoint?.txId);
    if (!entry || !entry.checkpoint || entry.checkpoint.checkpointFingerprint !== expectedCheckpointFingerprint) throw conflict();
    validateWorkspaceLifecycleCheckpoint(checkpoint, entry.transaction);
    const transition = `${entry.checkpoint.phase}:${checkpoint.phase}`;
    if (!["prepared:applied", "applied:committed", "prepared:manual_cleanup", "applied:manual_cleanup", "committed:manual_cleanup"].includes(transition)) throw conflict();
    entry.checkpoint = checkpoint;
    return checkpoint;
  }

  /** Atomically advances the in-memory head only from the supplied revision and fingerprint. */
  compareAndSetHead(head, { expectedRevision, expectedHeadFingerprint = null } = {}) {
    this.#boundary("head-cas");
    validateWorkspaceLifecycleHead(head);
    const target = [...this.records.values()].find(
      (entry) => entry.checkpoint?.checkpointFingerprint === head.currentRecordFingerprint
    );
    if (!target || target.checkpoint.phase !== "committed") throw conflict();
    if (
      target.transaction.expectedHeadRevision !== expectedRevision ||
      target.transaction.expectedHeadFingerprint !== expectedHeadFingerprint
    ) throw conflict();
    if (this.manualCleanup || (this.head?.revision ?? 0) !== expectedRevision || (this.head?.headFingerprint ?? null) !== expectedHeadFingerprint) throw conflict();
    if (head.revision !== expectedRevision + 1) throw conflict();
    if (this.head) this.heads.set(this.head.headFingerprint, this.head);
    this.head = head;
    return head;
  }

  /** Stores fingerprint-validated manual cleanup, which permanently absorbs later head writes. */
  setManualCleanup(manualCleanup) {
    validateManualCleanup(manualCleanup);
    if (this.manualCleanup) throw conflict();
    this.manualCleanup = manualCleanup;
    return manualCleanup;
  }

  /** Classifies the current in-memory evidence as a restart would, without recovery or serving. */
  classifyAfterRestart({ txId, authorityFingerprint = null } = {}) {
    const entry = this.records.get(txId);
    const predecessorHead = entry?.transaction?.expectedHeadFingerprint
      ? this.heads.get(entry.transaction.expectedHeadFingerprint) ?? null
      : null;
    return classifyWorkspaceLifecycleEvidence({ transaction: entry?.transaction ?? null, checkpoint: entry?.checkpoint ?? null, head: this.head, predecessorHead, manualCleanup: this.manualCleanup, authorityFingerprint });
  }
}
