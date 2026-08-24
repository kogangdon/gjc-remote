import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { buildGenerationPointer, generationPointerBytes, parseGenerationPointer } from "../src/workspace-generation-publisher.js";
import { buildWorkspaceLifecycleTransaction, buildWorkspaceLifecycleCheckpoint } from "@gjc-remote/shared/workspace-lifecycle-envelope";
import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { recoverWorkspaces, OPERATION_INVALID } from "../src/workspace-recovery-operation.js";

// ---- fixtures -------------------------------------------------------------

const BASE = {
  hostId: "host-1", workspaceId: "workspace-1", sourcePlatform: "windows-drive",
  rootIdentityFingerprint: "1".repeat(64), storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64), manifestFingerprint: "4".repeat(64),
};
const prior = buildGenerationPointer({ ...BASE, generationPath: "generations/000001", activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: null });
const candidate = buildGenerationPointer({ ...BASE, generationPath: "generations/000002", activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: prior.pointerFingerprint });
const otherCandidate = buildGenerationPointer({ ...BASE, generationPath: "generations/000002", activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: prior.pointerFingerprint, manifestFingerprint: "8".repeat(64) });
const foreign = buildGenerationPointer({ ...BASE, generationPath: "generations/000009", activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: prior.pointerFingerprint, manifestFingerprint: "9".repeat(64) });

const tx = buildWorkspaceLifecycleTransaction({
  txId: "transaction", hostId: "host", mappingId: "mapping", mappingGeneration: 2, mappingVersion: 1,
  workspaceId: "workspace", workspaceGeneration: 3, sourcePlatform: "discord", routeFingerprint: "a".repeat(64),
  authorityFingerprint: "b".repeat(64), inventoryGeneration: 4, anchorFingerprint: "c".repeat(64),
  operation: "refresh", principalFingerprint: "d".repeat(64), idempotencyFingerprint: "e".repeat(64),
  ownerFingerprint: "f".repeat(64), fenceGeneration: 1, expectedHeadRevision: 1, expectedHeadFingerprint: "7".repeat(64),
  beforeFingerprint: prior.pointerFingerprint, candidateFingerprint: candidate.pointerFingerprint, priorFingerprint: prior.pointerFingerprint,
});
const prepared = buildWorkspaceLifecycleCheckpoint({ transaction: tx, phase: "prepared" });

const manualCleanupRecord = () => {
  const value = {
    version: 1, kind: "manual-cleanup", anchorFingerprint: "c".repeat(64), fenceGeneration: 1, txId: "transaction",
    reason: "owner-action", expectedFingerprint: null, observedFingerprint: null, expectedFloorFingerprint: null,
    observedFloorFingerprint: null, routeDisposition: "no-route", blockedUntilOwnerAction: true,
  };
  return { ...value, manualCleanupFingerprint: canonicalJsonHash(value) };
};

// ---- fake io world --------------------------------------------------------

function makeWorld(spec) {
  return {
    liveBytes: spec.live === undefined || spec.live === null ? null : generationPointerBytes(spec.live),
    temp: null,
    prior: spec.prior ?? null,
    candidate: spec.candidate ?? null,
    checkpoint: spec.checkpoint ?? null,
    transaction: spec.transaction ?? null,
    manualCleanup: spec.manualCleanup ?? null,
    readThrows: spec.readThrows ?? false,
    replaceThrowsOnce: spec.replaceThrowsOnce ?? false,
    flushParentCalls: 0,
    replaceCalls: 0,
  };
}

function makeDeps(worlds) {
  return {
    readSnapshotInputs: async (id) => {
      const w = worlds.get(id);
      if (w.readThrows) throw Object.assign(new Error("io read boom"), { code: "IO_READ", reason: "boom" });
      return {
        livePointer: w.liveBytes === null ? null : parseGenerationPointer(w.liveBytes),
        priorPointer: w.prior,
        candidatePointer: w.candidate,
        checkpoint: w.checkpoint,
        transaction: w.transaction,
        manualCleanup: w.manualCleanup,
      };
    },
    publisherIo: (id) => {
      const w = worlds.get(id);
      return {
        readLivePointer: async () => w.liveBytes,
        writeTemp: async (bytes) => { w.temp = bytes; return "t"; },
        flushTemp: async () => {},
        replace: async () => {
          if (w.replaceThrowsOnce) {
            w.replaceThrowsOnce = false;
            const e = new Error("disk lost at replace");
            e.code = "EIO";
            throw e;
          }
          w.liveBytes = w.temp; w.replaceCalls += 1;
        },
        flushParent: async () => { w.flushParentCalls += 1; },
      };
    },
  };
}

// ---- tests ----------------------------------------------------------------

test("mixed batch: each disposition acts correctly and barredWorkspaceIds is exact", async () => {
  const worlds = new Map([
    ["ws-committed", makeWorld({ live: candidate })],                                            // no tx/checkpoint -> committed
    ["ws-flush", makeWorld({ live: candidate, prior, checkpoint: prepared, transaction: tx })],  // live==candidate -> committed-needs-flush
    ["ws-replay", makeWorld({ live: prior, prior, candidate, checkpoint: prepared, transaction: tx })], // live==prior -> safe-replay
    ["ws-manual", makeWorld({ live: foreign, prior, checkpoint: prepared, transaction: tx })],   // live==neither -> manual_cleanup
    ["ws-badio", makeWorld({ readThrows: true })],                                               // io failure -> barred
  ]);
  const ids = [...worlds.keys()];
  const result = await recoverWorkspaces(makeDeps(worlds), ids);

  assert.equal(result.admitted, 5);
  assert.equal(result.batchCount, 1);
  const byId = Object.fromEntries(result.processed.map((p) => [p.workspaceId, p]));
  assert.equal(byId["ws-committed"].disposition, "committed");
  assert.equal(byId["ws-committed"].action, "none");
  assert.equal(byId["ws-flush"].disposition, "committed-needs-flush");
  assert.equal(byId["ws-flush"].action, "flushed");
  assert.equal(worlds.get("ws-flush").flushParentCalls, 1);
  assert.equal(worlds.get("ws-flush").replaceCalls, 0, "committed-needs-flush must NEVER republish");
  assert.equal(byId["ws-replay"].disposition, "safe-replay");
  assert.equal(byId["ws-replay"].action, "republished");
  assert.equal(worlds.get("ws-replay").replaceCalls, 1);
  assert.equal(byId["ws-manual"].disposition, "manual_cleanup");
  assert.equal(byId["ws-badio"].action, "barred");
  assert.ok(byId["ws-badio"].failure && byId["ws-badio"].failure.code === "IO_READ");

  // barred set = exactly the manual_cleanup + failed workspaces, in order
  assert.deepEqual(result.barredWorkspaceIds, ["ws-manual", "ws-badio"]);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.barredWorkspaceIds) && Object.isFrozen(result.processed));
});

test("committed-needs-flush is idempotent across a double recovery pass", async () => {
  const worlds = new Map([["ws", makeWorld({ live: candidate, prior, checkpoint: prepared, transaction: tx })]]);
  const deps = makeDeps(worlds);
  const first = await recoverWorkspaces(deps, ["ws"]);
  const second = await recoverWorkspaces(deps, ["ws"]);
  assert.equal(first.processed[0].disposition, "committed-needs-flush");
  assert.equal(second.processed[0].disposition, "committed-needs-flush");
  // flushed once per pass, state never diverges, and NEVER a republish
  assert.equal(worlds.get("ws").flushParentCalls, 2);
  assert.equal(worlds.get("ws").replaceCalls, 0);
});

test("safe-replay is single-shot: a second pass sees live==candidate and flushes, never double-publishes", async () => {
  const worlds = new Map([["ws", makeWorld({ live: prior, prior, candidate, checkpoint: prepared, transaction: tx })]]);
  const deps = makeDeps(worlds);
  const first = await recoverWorkspaces(deps, ["ws"]);
  assert.equal(first.processed[0].disposition, "safe-replay");
  assert.equal(worlds.get("ws").replaceCalls, 1, "one publish on the first pass");
  // after the publish landed, live == candidate; a re-run classifies committed-needs-flush
  const second = await recoverWorkspaces(deps, ["ws"]);
  assert.equal(second.processed[0].disposition, "committed-needs-flush");
  assert.equal(second.processed[0].action, "flushed");
  assert.equal(worlds.get("ws").replaceCalls, 1, "NO second publish (would CAS-conflict)");
});

test("mismatched candidate body forces manual_cleanup and performs no io action", async () => {
  const worlds = new Map([["ws", makeWorld({ live: prior, prior, candidate: otherCandidate, checkpoint: prepared, transaction: tx })]]);
  const result = await recoverWorkspaces(makeDeps(worlds), ["ws"]);
  assert.equal(result.processed[0].disposition, "manual_cleanup");
  assert.deepEqual(result.barredWorkspaceIds, ["ws"]);
  assert.equal(worlds.get("ws").replaceCalls, 0);
  assert.equal(worlds.get("ws").flushParentCalls, 0);
});

test("an explicit manual-cleanup record bars the workspace without action", async () => {
  const worlds = new Map([["ws", makeWorld({ live: candidate, prior, checkpoint: prepared, transaction: tx, manualCleanup: manualCleanupRecord() })]]);
  const result = await recoverWorkspaces(makeDeps(worlds), ["ws"]);
  assert.equal(result.processed[0].disposition, "manual_cleanup");
  assert.equal(worlds.get("ws").flushParentCalls, 0);
  assert.equal(worlds.get("ws").replaceCalls, 0);
});

test("a crash DURING the safe-replay publish bars that workspace (preserving the disposition) and the next pass converges", async () => {
  const worlds = new Map([["ws", makeWorld({ live: prior, prior, candidate, checkpoint: prepared, transaction: tx, replaceThrowsOnce: true })]]);
  const deps = makeDeps(worlds);
  // pass 1: replace throws mid-publish -> publisher wraps as WORKSPACE_GENERATION_IO_FAILED;
  // orchestrator bars this one workspace but PRESERVES the safe-replay disposition for diagnostics.
  const first = await recoverWorkspaces(deps, ["ws"]);
  assert.equal(first.processed[0].disposition, "safe-replay");
  assert.equal(first.processed[0].action, "barred");
  assert.equal(first.processed[0].failure.code, "WORKSPACE_GENERATION_IO_FAILED");
  assert.deepEqual(first.barredWorkspaceIds, ["ws"]);
  assert.equal(worlds.get("ws").replaceCalls, 0, "the throwing replace did not advance the live pointer");
  // pass 2: replace no longer throws; the live pointer is still the prior, so
  // the same safe-replay is re-attempted and now converges (single publish).
  const second = await recoverWorkspaces(deps, ["ws"]);
  assert.equal(second.processed[0].disposition, "safe-replay");
  assert.equal(second.processed[0].action, "republished");
  assert.equal(worlds.get("ws").replaceCalls, 1);
  assert.deepEqual(second.barredWorkspaceIds, []);
});

test("admission ceiling breach processes nothing (no io reads)", async () => {
  let reads = 0;
  const deps = { readSnapshotInputs: async () => { reads += 1; return {}; }, publisherIo: () => ({}) };
  const ids = Array.from({ length: 65 }, (_, i) => `ws-${i}`);
  await assert.rejects(recoverWorkspaces(deps, ids), (e) => e.code === "WORKSPACE_ADMISSION_EXCEEDED");
  assert.equal(reads, 0, "zero io reads above the ceiling");
});

test("deps validation refuses with the local operation literal", async () => {
  await assert.rejects(recoverWorkspaces(null, []), (e) => e.code === OPERATION_INVALID);
  await assert.rejects(recoverWorkspaces({ publisherIo: () => ({}) }, []), (e) => e.code === OPERATION_INVALID);
  await assert.rejects(recoverWorkspaces({ readSnapshotInputs: async () => ({}) }, []), (e) => e.code === OPERATION_INVALID);
});

test("boot recovery NEVER touches the WorkspaceLeaseRegistry (registry starts empty; F3)", async () => {
  const src = await readFile(fileURLToPath(new URL("../src/workspace-recovery-operation.js", import.meta.url)), "utf8");
  // strip block and line comments so we scan only executable code (the module
  // doc legitimately explains WHY it never calls the registry)
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)\/\/[^\n]*/g, "$1");
  assert.ok(!/lease-registry/.test(code), "orchestrator must not import the lease registry");
  assert.ok(!/LeaseRegistry|leaseRegistry/.test(code), "orchestrator code must not reference any lease registry symbol");
  // structural proof: recovery completes with a deps seam exposing ONLY
  // readSnapshotInputs + publisherIo - there is nowhere for a registry call to originate
  const worlds = new Map([["ws", makeWorld({ live: candidate })]]);
  const deps = makeDeps(worlds);
  assert.deepEqual(Object.keys(deps).sort(), ["publisherIo", "readSnapshotInputs"]);
  const result = await recoverWorkspaces(deps, ["ws"]);
  assert.equal(result.processed[0].disposition, "committed");
});
