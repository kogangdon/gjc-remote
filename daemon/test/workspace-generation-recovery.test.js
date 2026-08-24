import assert from "node:assert/strict";
import test from "node:test";
import { buildGenerationPointer } from "../src/workspace-generation-publisher.js";
import {
  buildWorkspaceLifecycleTransaction,
  buildWorkspaceLifecycleCheckpoint,
} from "@gjc-remote/shared/workspace-lifecycle-envelope";
import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { buildRecoverySnapshot } from "../src/workspace-recovery-snapshot.js";
import { classifyGenerationRecovery, DISPOSITIONS } from "../src/workspace-generation-recovery.js";

// ---- pointer fixtures -----------------------------------------------------

const POINTER_BASE = {
  hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
  rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
};
const prior = buildGenerationPointer({ ...POINTER_BASE, generationPath: "generations/000001", activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: null });
const candidate = buildGenerationPointer({ ...POINTER_BASE, generationPath: "generations/000002", activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: prior.pointerFingerprint });
// A different well-formed successor whose self-fingerprint differs from `candidate`.
const otherCandidate = buildGenerationPointer({ ...POINTER_BASE, generationPath: "generations/000002", activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: prior.pointerFingerprint, manifestFingerprint: "8".repeat(64) });
// A live pointer matching neither prior nor candidate identity.
const foreign = buildGenerationPointer({ ...POINTER_BASE, generationPath: "generations/000009", activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: prior.pointerFingerprint, manifestFingerprint: "9".repeat(64) });

// ---- lifecycle fixtures ---------------------------------------------------

// A refresh (successor) transaction whose candidate identity == candidate.pointerFingerprint.
const tx = buildWorkspaceLifecycleTransaction({
  txId: "transaction", hostId: "host", mappingId: "mapping", mappingGeneration: 2, mappingVersion: 1,
  workspaceId: "workspace", workspaceGeneration: 3, sourcePlatform: "discord", routeFingerprint: "a".repeat(64),
  authorityFingerprint: "b".repeat(64), inventoryGeneration: 4, anchorFingerprint: "c".repeat(64),
  operation: "refresh", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64),
  ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 1, expectedHeadFingerprint: "7".repeat(64),
  beforeFingerprint: prior.pointerFingerprint, candidateFingerprint: candidate.pointerFingerprint, priorFingerprint: prior.pointerFingerprint,
});
const checkpointFor = (phase) => phase === "prepared"
  ? buildWorkspaceLifecycleCheckpoint({ transaction: tx, phase: "prepared" })
  : buildWorkspaceLifecycleCheckpoint({ transaction: tx, phase, operationEvidenceFingerprint: tx.candidateFingerprint });

const manualCleanupRecord = () => {
  const value = {
    version: 1, kind: "manual-cleanup", anchorFingerprint: "c".repeat(64), fenceGeneration: 1, txId: "transaction",
    reason: "owner-action", expectedFingerprint: null, observedFingerprint: null, expectedFloorFingerprint: null,
    observedFloorFingerprint: null, routeDisposition: "no-route", blockedUntilOwnerAction: true,
  };
  return { ...value, manualCleanupFingerprint: canonicalJsonHash(value) };
};

const snap = (over) => buildRecoverySnapshot({ workspaceId: "workspace-1", priorPointer: prior, transaction: tx, ...over });

// ---- exhaustive disposition sweep -----------------------------------------

const LIVE = { prior, candidate, foreign };            // replace never landed | landed | corrupt
const BODY = { matching: candidate, mismatched: otherCandidate, absent: null };

// expected[phase][live][body]
const EXPECTED = {
  prepared: {
    prior:     { matching: "safe-replay", mismatched: "manual_cleanup", absent: "manual_cleanup" },
    candidate: { matching: "committed-needs-flush", mismatched: "committed-needs-flush", absent: "committed-needs-flush" },
    foreign:   { matching: "manual_cleanup", mismatched: "manual_cleanup", absent: "manual_cleanup" },
  },
  applied: {
    prior:     { matching: "safe-replay", mismatched: "manual_cleanup", absent: "manual_cleanup" },
    candidate: { matching: "committed-needs-flush", mismatched: "committed-needs-flush", absent: "committed-needs-flush" },
    foreign:   { matching: "manual_cleanup", mismatched: "manual_cleanup", absent: "manual_cleanup" },
  },
  committed: {
    prior:     { matching: "manual_cleanup", mismatched: "manual_cleanup", absent: "manual_cleanup" },
    candidate: { matching: "committed", mismatched: "committed", absent: "committed" },
    foreign:   { matching: "manual_cleanup", mismatched: "manual_cleanup", absent: "manual_cleanup" },
  },
};

test("exhaustive crash-point x phase x candidate-availability disposition sweep", () => {
  for (const phase of ["prepared", "applied", "committed"]) {
    for (const liveKey of Object.keys(LIVE)) {
      for (const bodyKey of Object.keys(BODY)) {
        const result = classifyGenerationRecovery(snap({
          livePointer: LIVE[liveKey],
          candidatePointer: BODY[bodyKey],
          checkpoint: checkpointFor(phase),
        }));
        const expected = EXPECTED[phase][liveKey][bodyKey];
        assert.equal(result.disposition, expected, `phase=${phase} live=${liveKey} body=${bodyKey}`);
        assert.ok(DISPOSITIONS.includes(result.disposition));
        if (expected === "safe-replay") {
          assert.equal(result.candidatePointer, candidate, "safe-replay carries the recovered candidate body");
        } else {
          assert.ok(!("candidatePointer" in result), "non-safe-replay carries no candidatePointer");
        }
        assert.ok(Object.isFrozen(result));
      }
    }
  }
});

test("nothing in flight (no transaction, no checkpoint) is committed / no-op", () => {
  assert.equal(classifyGenerationRecovery(buildRecoverySnapshot({ workspaceId: "w" })).disposition, "committed");
  assert.equal(classifyGenerationRecovery(buildRecoverySnapshot({ workspaceId: "w", livePointer: candidate })).disposition, "committed");
});

test("a half-present transaction/checkpoint pair is corrupt -> manual_cleanup", () => {
  // transaction present, checkpoint absent
  assert.equal(classifyGenerationRecovery(snap({ livePointer: candidate, checkpoint: null })).disposition, "manual_cleanup");
  // checkpoint present, transaction absent
  const orphanCheckpoint = buildRecoverySnapshot({ workspaceId: "w", livePointer: prior, checkpoint: buildWorkspaceLifecycleCheckpoint({ transaction: tx, phase: "prepared" }), transaction: null });
  assert.equal(classifyGenerationRecovery(orphanCheckpoint).disposition, "manual_cleanup");
});

test("an explicit manual-cleanup record is terminal -> manual_cleanup", () => {
  const s = snap({ livePointer: candidate, checkpoint: checkpointFor("prepared"), manualCleanup: manualCleanupRecord() });
  assert.equal(classifyGenerationRecovery(s).disposition, "manual_cleanup");
});

test("candidatePointer:null in an otherwise safe-replay-eligible state forces manual_cleanup (F2 no-body rule)", () => {
  const s = snap({ livePointer: prior, candidatePointer: null, checkpoint: checkpointFor("prepared") });
  assert.equal(classifyGenerationRecovery(s).disposition, "manual_cleanup");
});

test("classifier rejects a malformed snapshot via S6a's validator (no silent pass)", () => {
  assert.throws(() => classifyGenerationRecovery({ workspaceId: "w" }), (e) => e.code === "WORKSPACE_RECOVERY_SNAPSHOT_INVALID");
});

test("first-publication crash-before-replace (null live, null prior) is safe-replay; a lost live pointer is manual_cleanup", () => {
  // First publication: no live pointer and no prior yet; a create transaction
  // whose candidate identity == the first pointer's self-fingerprint.
  const firstCand = buildGenerationPointer({ ...POINTER_BASE, generationPath: "generations/000001", activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: null });
  const txCreate = buildWorkspaceLifecycleTransaction({
    txId: "transaction", hostId: "host", mappingId: "mapping", mappingGeneration: 2, mappingVersion: 1,
    workspaceId: "workspace", workspaceGeneration: 3, sourcePlatform: "discord", routeFingerprint: "a".repeat(64),
    authorityFingerprint: "b".repeat(64), inventoryGeneration: 4, anchorFingerprint: "c".repeat(64),
    operation: "create", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64),
    ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 0, expectedHeadFingerprint: null,
    beforeFingerprint: null, candidateFingerprint: firstCand.pointerFingerprint, priorFingerprint: null,
  });
  const firstPub = buildRecoverySnapshot({
    workspaceId: "w", livePointer: null, priorPointer: null, candidatePointer: firstCand,
    checkpoint: buildWorkspaceLifecycleCheckpoint({ transaction: txCreate, phase: "prepared" }), transaction: txCreate,
  });
  const result = classifyGenerationRecovery(firstPub);
  assert.equal(result.disposition, "safe-replay");
  assert.equal(result.candidatePointer, firstCand);

  // Lost live pointer: live is null but a prior existed (successor op) -> corrupt,
  // replace neither landed nor is provably un-landed. manual_cleanup.
  const lostLive = snap({ livePointer: null, candidatePointer: candidate, checkpoint: checkpointFor("prepared") });
  assert.equal(classifyGenerationRecovery(lostLive).disposition, "manual_cleanup");
  const lostLiveCommitted = snap({ livePointer: null, candidatePointer: candidate, checkpoint: checkpointFor("committed") });
  assert.equal(classifyGenerationRecovery(lostLiveCommitted).disposition, "manual_cleanup");
});

test("safe-replay requires the candidate body to chain onto the live pointer (real CAS precondition)", () => {
  // candidate body whose priorPointerFingerprint does NOT reference the live
  // pointer -> republish would fail CAS -> manual_cleanup even though the
  // self-fingerprint would otherwise match a transaction candidate.
  const disjointPrior = buildGenerationPointer({ ...POINTER_BASE, generationPath: "generations/000050", activeGeneration: 5, priorGeneration: 4, priorPointerFingerprint: "5".repeat(64) });
  const disjointCand = buildGenerationPointer({ ...POINTER_BASE, generationPath: "generations/000051", activeGeneration: 6, priorGeneration: 5, priorPointerFingerprint: disjointPrior.pointerFingerprint });
  const txDisjoint = buildWorkspaceLifecycleTransaction({
    txId: "transaction", hostId: "host", mappingId: "mapping", mappingGeneration: 2, mappingVersion: 1,
    workspaceId: "workspace", workspaceGeneration: 3, sourcePlatform: "discord", routeFingerprint: "a".repeat(64),
    authorityFingerprint: "b".repeat(64), inventoryGeneration: 4, anchorFingerprint: "c".repeat(64),
    operation: "refresh", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64),
    ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 1, expectedHeadFingerprint: "7".repeat(64),
    beforeFingerprint: prior.pointerFingerprint, candidateFingerprint: disjointCand.pointerFingerprint, priorFingerprint: prior.pointerFingerprint,
  });
  // live == prior (replace never landed), candidate self-fp matches tx, but the
  // candidate's recorded prior is disjointPrior, not the live pointer.
  const s = buildRecoverySnapshot({
    workspaceId: "w", livePointer: prior, priorPointer: prior, candidatePointer: disjointCand,
    checkpoint: buildWorkspaceLifecycleCheckpoint({ transaction: txDisjoint, phase: "prepared" }), transaction: txDisjoint,
  });
  assert.equal(classifyGenerationRecovery(s).disposition, "manual_cleanup");
});
