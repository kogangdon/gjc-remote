import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJsonHash } from "../strict-json.js";
import {
  buildWorkspaceLifecycleCheckpoint,
  buildWorkspaceLifecycleHead,
  buildWorkspaceLifecycleTransaction,
  classifyWorkspaceLifecycleEvidence,
  validateWorkspaceLifecycleCheckpoint,
  validateWorkspaceLifecycleHead,
  validateWorkspaceLifecycleTransaction,
} from "../workspace-lifecycle-envelope.js";

const hash = "a".repeat(64);
const tx = () => buildWorkspaceLifecycleTransaction({ txId: "transaction", hostId: "host", mappingId: "mapping", mappingGeneration: 2, mappingVersion: 1, workspaceId: "workspace", workspaceGeneration: 3, sourcePlatform: "discord", routeFingerprint: hash, authorityFingerprint: "b".repeat(64), inventoryGeneration: 4, anchorFingerprint: "c".repeat(64), operation: "create", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64), ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 0, expectedHeadFingerprint: null, beforeFingerprint: null, candidateFingerprint: "1".repeat(64), priorFingerprint: null });
const manualCleanup = () => { const value = { version: 1, kind: "manual-cleanup", anchorFingerprint: "c".repeat(64), fenceGeneration: 1, txId: "transaction", reason: "owner-action", expectedFingerprint: null, observedFingerprint: null, expectedFloorFingerprint: null, observedFloorFingerprint: null, routeDisposition: "no-route", blockedUntilOwnerAction: true }; return { ...value, manualCleanupFingerprint: canonicalJsonHash(value) }; };

test("transaction uses exact keys and a canonical fingerprint", () => {
  const value = tx();
  assert.equal(validateWorkspaceLifecycleTransaction(value), value);
  assert.throws(() => validateWorkspaceLifecycleTransaction({ ...value, extra: true }));
  assert.throws(() => validateWorkspaceLifecycleTransaction({ ...value, operation: "delete" }));
  assert.throws(() => buildWorkspaceLifecycleTransaction({ ...value, version: undefined, kind: undefined, transactionFingerprint: undefined, operation: "takeover" }));
});

test("checkpoints enforce legal evidence and transaction relations", () => {
  const transaction = tx();
  const prepared = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "prepared" });
  const applied = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "applied", operationEvidenceFingerprint: transaction.candidateFingerprint });
  const committed = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "committed", operationEvidenceFingerprint: transaction.candidateFingerprint });
  assert.equal(validateWorkspaceLifecycleCheckpoint(prepared, transaction), prepared);
  assert.equal(validateWorkspaceLifecycleCheckpoint(applied, transaction), applied);
  assert.equal(validateWorkspaceLifecycleCheckpoint(committed, transaction), committed);
  assert.throws(() => validateWorkspaceLifecycleCheckpoint({ ...committed, txId: "other" }, transaction));
  assert.throws(() => buildWorkspaceLifecycleCheckpoint({ transaction, phase: "applied" }));
});

test("only exact committed evidence routes and manual cleanup absorbs", () => {
  const transaction = tx();
  const committed = buildWorkspaceLifecycleCheckpoint({ transaction, phase: "committed", operationEvidenceFingerprint: transaction.candidateFingerprint });
  const head = buildWorkspaceLifecycleHead({ revision: 1, currentRecordFingerprint: committed.checkpointFingerprint, disposition: "committed" });
  assert.equal(classifyWorkspaceLifecycleEvidence({ transaction, checkpoint: committed, head, authorityFingerprint: transaction.authorityFingerprint }), "committed");
  const impossibleHead = buildWorkspaceLifecycleHead({ revision: 2, currentRecordFingerprint: committed.checkpointFingerprint, disposition: "committed" });
  assert.equal(classifyWorkspaceLifecycleEvidence({ transaction, checkpoint: committed, head: impossibleHead, authorityFingerprint: transaction.authorityFingerprint }), "no-route");
  assert.equal(classifyWorkspaceLifecycleEvidence({ transaction, checkpoint: committed, head }), "no-route");
  assert.equal(classifyWorkspaceLifecycleEvidence({ transaction, checkpoint: { ...committed, phase: "prepared" }, head }), "no-route");
  assert.equal(classifyWorkspaceLifecycleEvidence({ transaction, checkpoint: committed, head, authorityFingerprint: hash }), "no-route");
  assert.equal(classifyWorkspaceLifecycleEvidence({ manualCleanup: manualCleanup() }), "manual_cleanup");
  assert.throws(() => validateWorkspaceLifecycleHead({ ...head, disposition: "manual_cleanup" }));
});

test("non-genesis committed evidence requires the exact predecessor head", () => {
  const predecessor = buildWorkspaceLifecycleHead({
    revision: 1,
    currentRecordFingerprint: "2".repeat(64),
    disposition: "committed",
  });
  const { version, kind, transactionFingerprint, ...base } = tx();
  const transaction = buildWorkspaceLifecycleTransaction({
    ...base,
    txId: "transaction-2",
    operation: "refresh",
    expectedHeadRevision: 1,
    expectedHeadFingerprint: predecessor.headFingerprint,
    beforeFingerprint: "3".repeat(64),
    priorFingerprint: "4".repeat(64),
  });
  const committed = buildWorkspaceLifecycleCheckpoint({
    transaction,
    phase: "committed",
    operationEvidenceFingerprint: transaction.candidateFingerprint,
  });
  const head = buildWorkspaceLifecycleHead({
    revision: 2,
    currentRecordFingerprint: committed.checkpointFingerprint,
    disposition: "committed",
  });

  assert.equal(
    classifyWorkspaceLifecycleEvidence({
      transaction,
      checkpoint: committed,
      head,
      predecessorHead: predecessor,
      authorityFingerprint: transaction.authorityFingerprint,
    }),
    "committed"
  );
  assert.equal(
    classifyWorkspaceLifecycleEvidence({
      transaction,
      checkpoint: committed,
      head,
      predecessorHead: buildWorkspaceLifecycleHead({
        revision: 1,
        currentRecordFingerprint: "5".repeat(64),
        disposition: "committed",
      }),
      authorityFingerprint: transaction.authorityFingerprint,
    }),
    "no-route"
  );
});
