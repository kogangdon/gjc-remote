import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { buildGenerationPointer } from "../src/workspace-generation-publisher.js";
import {
  buildWorkspaceLifecycleTransaction,
  buildWorkspaceLifecycleCheckpoint,
} from "@gjc-remote/shared/workspace-lifecycle-envelope";
import {
  buildRecoverySnapshot,
  validateRecoverySnapshot,
  SNAPSHOT_KEYS,
  SNAPSHOT_INVALID,
} from "../src/workspace-recovery-snapshot.js";

// ---- fixtures -------------------------------------------------------------

const POINTER_BASE = {
  hostId: "host-1",
  workspaceId: "workspace-1",
  sourcePlatform: "windows-drive",
  generationPath: "generations/000001",
  rootIdentityFingerprint: "1".repeat(64),
  storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64),
  manifestFingerprint: "4".repeat(64),
};

const firstPointer = (overrides = {}) =>
  buildGenerationPointer({ ...POINTER_BASE, activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: null, ...overrides });

const successorPointer = (prior, overrides = {}) =>
  buildGenerationPointer({
    ...POINTER_BASE,
    generationPath: "generations/000002",
    activeGeneration: prior.activeGeneration + 1,
    priorGeneration: prior.activeGeneration,
    priorPointerFingerprint: prior.pointerFingerprint,
    ...overrides,
  });

const hash = "a".repeat(64);
const transaction = () =>
  buildWorkspaceLifecycleTransaction({
    txId: "transaction", hostId: "host", mappingId: "mapping", mappingGeneration: 2, mappingVersion: 1,
    workspaceId: "workspace", workspaceGeneration: 3, sourcePlatform: "discord", routeFingerprint: hash,
    authorityFingerprint: "b".repeat(64), inventoryGeneration: 4, anchorFingerprint: "c".repeat(64),
    operation: "create", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64),
    ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 0, expectedHeadFingerprint: null,
    beforeFingerprint: null, candidateFingerprint: "1".repeat(64), priorFingerprint: null,
  });

const preparedCheckpoint = (tx) => buildWorkspaceLifecycleCheckpoint({ transaction: tx, phase: "prepared" });
const committedCheckpoint = (tx) =>
  buildWorkspaceLifecycleCheckpoint({ transaction: tx, phase: "committed", operationEvidenceFingerprint: tx.candidateFingerprint });

const manualCleanup = () => {
  const value = {
    version: 1, kind: "manual-cleanup", anchorFingerprint: "c".repeat(64), fenceGeneration: 1, txId: "transaction",
    reason: "owner-action", expectedFingerprint: null, observedFingerprint: null, expectedFloorFingerprint: null,
    observedFloorFingerprint: null, routeDisposition: "no-route", blockedUntilOwnerAction: true,
  };
  return { ...value, manualCleanupFingerprint: canonicalJsonHash(value) };
};

// ---- tests ----------------------------------------------------------------

test("a fully populated snapshot (including candidatePointer) round-trips and is frozen", () => {
  const prior = firstPointer();
  const live = successorPointer(prior);
  const candidate = successorPointer(prior, { generationPath: "generations/000003" });
  const tx = transaction();
  const snapshot = buildRecoverySnapshot({
    workspaceId: "workspace-1",
    livePointer: live,
    priorPointer: prior,
    candidatePointer: candidate,
    checkpoint: committedCheckpoint(tx),
    transaction: tx,
    manualCleanup: manualCleanup(),
  });
  assert.deepEqual(Object.keys(snapshot).sort(), [...SNAPSHOT_KEYS].sort());
  assert.ok(Object.isFrozen(snapshot));
  assert.equal(snapshot.livePointer, live);
  assert.equal(snapshot.candidatePointer, candidate);
  assert.equal(validateRecoverySnapshot(snapshot), snapshot);
});

test("an all-null snapshot (only workspaceId) is valid", () => {
  const snapshot = buildRecoverySnapshot({ workspaceId: "workspace-1" });
  for (const key of SNAPSHOT_KEYS) {
    if (key !== "workspaceId") assert.equal(snapshot[key], null, `${key} defaults to null`);
  }
  assert.equal(validateRecoverySnapshot(snapshot), snapshot);
});

test("candidatePointer:null is valid and structurally distinguishable from a populated one", () => {
  const prior = firstPointer();
  const withBody = buildRecoverySnapshot({ workspaceId: "w", candidatePointer: successorPointer(prior) });
  const withoutBody = buildRecoverySnapshot({ workspaceId: "w", candidatePointer: null });
  assert.notEqual(withBody.candidatePointer, null);
  assert.equal(withoutBody.candidatePointer, null);
});

test("each field malformed throws that field's OWN validator error, unchanged", () => {
  const tx = transaction();
  // livePointer -> WORKSPACE_GENERATION_INVALID
  const badPointer = { ...firstPointer(), pointerFingerprint: "0".repeat(64) };
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", livePointer: badPointer }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID");
  // candidatePointer -> WORKSPACE_GENERATION_INVALID (same validator)
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", candidatePointer: badPointer }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID");
  // transaction -> WORKSPACE_LIFECYCLE_ENVELOPE_INVALID
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", transaction: { ...tx, operation: "takeover" } }),
    (e) => e instanceof TypeError && /WORKSPACE_LIFECYCLE_ENVELOPE_INVALID/.test(e.message));
  // checkpoint -> WORKSPACE_LIFECYCLE_ENVELOPE_INVALID
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", checkpoint: { ...committedCheckpoint(tx), phase: "bogus" } }),
    (e) => e instanceof TypeError && /WORKSPACE_LIFECYCLE_ENVELOPE_INVALID/.test(e.message));
  // manualCleanup -> RECOVERY_ENVELOPE_INVALID
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", manualCleanup: { ...manualCleanup(), kind: "nope" } }),
    (e) => e instanceof TypeError && /RECOVERY_ENVELOPE_INVALID/.test(e.message));
});

test("checkpoint/transaction relation is enforced when both are present", () => {
  const tx = transaction();
  const otherTx = buildWorkspaceLifecycleTransaction({
    txId: "transaction-2", hostId: "host", mappingId: "mapping", mappingGeneration: 2, mappingVersion: 1,
    workspaceId: "workspace", workspaceGeneration: 3, sourcePlatform: "discord", routeFingerprint: hash,
    authorityFingerprint: "b".repeat(64), inventoryGeneration: 4, anchorFingerprint: "c".repeat(64),
    operation: "create", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64),
    ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 0, expectedHeadFingerprint: null,
    beforeFingerprint: null, candidateFingerprint: "1".repeat(64), priorFingerprint: null,
  });
  // committed checkpoint of tx does NOT relate to otherTx -> relation failure
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", checkpoint: committedCheckpoint(tx), transaction: otherTx }),
    (e) => e instanceof TypeError && /WORKSPACE_LIFECYCLE_ENVELOPE_INVALID/.test(e.message));
  // prepared checkpoint relates fine
  const ok = buildRecoverySnapshot({ workspaceId: "w", checkpoint: preparedCheckpoint(tx), transaction: tx });
  assert.equal(ok.checkpoint.phase, "prepared");
});

test("a committed checkpoint with transaction:null fails its own evidence rule; malformed priorPointer throws the pointer validator", () => {
  const tx = transaction();
  // committed checkpoint carries a non-null operationEvidenceFingerprint that can
  // only be validated against its transaction; with transaction:null the shared
  // checkpoint evidence rule rejects it - recovery never accepts committed
  // evidence without its transaction.
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", checkpoint: committedCheckpoint(tx), transaction: null }),
    (e) => e instanceof TypeError && /WORKSPACE_LIFECYCLE_ENVELOPE_INVALID/.test(e.message));
  // a prepared checkpoint (null evidence) with transaction:null validates on schema alone
  const ok = buildRecoverySnapshot({ workspaceId: "w", checkpoint: preparedCheckpoint(tx), transaction: null });
  assert.equal(ok.checkpoint.phase, "prepared");
  // malformed priorPointer -> the pointer validator's own error
  const badPrior = { ...firstPointer(), activeGeneration: 999 };
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", priorPointer: badPrior }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID");
});

test("container-shape violations refuse with the local WORKSPACE_RECOVERY_SNAPSHOT_INVALID literal", () => {
  assert.throws(() => buildRecoverySnapshot(null), (e) => e.code === SNAPSHOT_INVALID && e.operation === "workspace_recovery_snapshot");
  assert.throws(() => buildRecoverySnapshot("x"), (e) => e.code === SNAPSHOT_INVALID);
  // unknown field must not be silently dropped
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "w", livePonter: null }), (e) => e.code === SNAPSHOT_INVALID && /unknown snapshot field/.test(e.reason));
  // bad workspaceId
  assert.throws(() => buildRecoverySnapshot({ workspaceId: "" }), (e) => e.code === SNAPSHOT_INVALID);
  assert.throws(() => buildRecoverySnapshot({ workspaceId: 42 }), (e) => e.code === SNAPSHOT_INVALID);
  // validateRecoverySnapshot requires the exact key set
  assert.throws(() => validateRecoverySnapshot({ workspaceId: "w" }), (e) => e.code === SNAPSHOT_INVALID);
});
