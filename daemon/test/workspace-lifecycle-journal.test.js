import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJsonHash } from "../../shared/strict-json.js";
import { buildWorkspaceLifecycleCheckpoint, buildWorkspaceLifecycleHead, buildWorkspaceLifecycleTransaction } from "../../shared/workspace-lifecycle-envelope.js";
import { DeterministicWorkspaceLifecycleJournal } from "../src/workspace-lifecycle-journal.js";

const tx = () => buildWorkspaceLifecycleTransaction({ txId: "transaction", hostId: "host", mappingId: "mapping", mappingGeneration: 1, mappingVersion: 1, workspaceId: "workspace", workspaceGeneration: 1, sourcePlatform: "discord", routeFingerprint: "a".repeat(64), authorityFingerprint: "b".repeat(64), inventoryGeneration: 1, anchorFingerprint: "c".repeat(64), operation: "create", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64), ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 0, expectedHeadFingerprint: null, beforeFingerprint: null, candidateFingerprint: "1".repeat(64), priorFingerprint: null });
const cleanup = () => { const value = { version: 1, kind: "manual-cleanup", anchorFingerprint: "c".repeat(64), fenceGeneration: 1, txId: "transaction", reason: "owner-action", expectedFingerprint: null, observedFingerprint: null, expectedFloorFingerprint: null, observedFloorFingerprint: null, routeDisposition: "no-route", blockedUntilOwnerAction: true }; return { ...value, manualCleanupFingerprint: canonicalJsonHash(value) }; };

test("deterministic store rejects duplicate create, substitution, and stale head CAS", () => {
  const journal = new DeterministicWorkspaceLifecycleJournal();
  const transaction = tx();
  const prepared = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "prepared" });
  const applied = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "applied", operationEvidenceFingerprint: transaction.candidateFingerprint });
  const committed = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "committed", operationEvidenceFingerprint: transaction.candidateFingerprint });
  journal.create(transaction);
  assert.throws(() => journal.create(transaction), (error) => error.code === "WORKSPACE_LIFECYCLE_JOURNAL_CONFLICT");
  journal.flush(prepared);
  assert.throws(() => journal.replace(applied, "0".repeat(64)), (error) => error.code === "WORKSPACE_LIFECYCLE_JOURNAL_CONFLICT");
  journal.replace(applied, prepared.checkpointFingerprint);
  journal.replace(committed, applied.checkpointFingerprint);
  const head = buildWorkspaceLifecycleHead({ revision: 1, currentRecordFingerprint: committed.checkpointFingerprint, disposition: "committed" });
  assert.throws(() => journal.compareAndSetHead(head, { expectedRevision: 1 }), (error) => error.code === "WORKSPACE_LIFECYCLE_JOURNAL_CONFLICT");
  journal.compareAndSetHead(head, { expectedRevision: 0 });
  assert.equal(journal.classifyAfterRestart({ txId: transaction.txId, authorityFingerprint: transaction.authorityFingerprint }), "committed");
});

test("torn, malformed, missing, and authority-drift evidence is no-route", () => {
  const journal = new DeterministicWorkspaceLifecycleJournal();
  assert.equal(journal.classifyAfterRestart({ txId: "missing" }), "no-route");
  const transaction = tx();
  journal.create(transaction);
  assert.equal(journal.classifyAfterRestart({ txId: transaction.txId }), "no-route");
  const prepared = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "prepared" });
  journal.flush(prepared);
  assert.equal(journal.classifyAfterRestart({ txId: transaction.txId, authorityFingerprint: "0".repeat(64) }), "no-route");
});

test("fault boundaries are injected once and manual cleanup is absorbing", () => {
  for (const stage of ["create", "flush", "replace", "head-cas"]) {
    const journal = new DeterministicWorkspaceLifecycleJournal({ failures: [stage] });
    assert.throws(() => journal[stage === "head-cas" ? "compareAndSetHead" : stage](stage === "create" ? tx() : {}), (error) => error.code === "WORKSPACE_LIFECYCLE_JOURNAL_FAULT");
  }
  const journal = new DeterministicWorkspaceLifecycleJournal();
  journal.setManualCleanup(cleanup());
  assert.equal(journal.classifyAfterRestart({ txId: "transaction" }), "manual_cleanup");
  const head = buildWorkspaceLifecycleHead({ revision: 1, currentRecordFingerprint: "1".repeat(64), disposition: "committed" });
  assert.throws(() => journal.compareAndSetHead(head, { expectedRevision: 0 }), (error) => error.code === "WORKSPACE_LIFECYCLE_JOURNAL_CONFLICT");
});
