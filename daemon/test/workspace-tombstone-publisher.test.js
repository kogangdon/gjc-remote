import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { canonicalJsonBytes, canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { classifyWorkspaceLifecycleEvidence } from "@gjc-remote/shared/workspace-lifecycle-envelope.js";
import {
  buildGenerationPointer,
  generationPointerBytes,
} from "../src/workspace-generation-publisher.js";
import {
  TOMBSTONE_STEPS,
  buildTombstone,
  parseTombstone,
  publishTombstone,
  readLiveDisposition,
  readLiveTombstone,
  tombstoneBytes,
  validateTombstone,
} from "../src/workspace-tombstone-publisher.js";

const HOST = "host-a";
const WORKSPACE = "workspace-a";
const TOMBSTONE_LIMITS = { maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 256 };

// A valid S4d generation pointer to seed the live slot (generation 3 chained
// onto a prior generation 2).
function livePointer(overrides = {}) {
  return buildGenerationPointer({
    hostId: HOST,
    workspaceId: WORKSPACE,
    sourcePlatform: "posix",
    activeGeneration: 3,
    generationPath: "generations/3",
    rootIdentityFingerprint: "a".repeat(64),
    storageIdentityFingerprint: "b".repeat(64),
    gitGenerationFingerprint: "c".repeat(64),
    manifestFingerprint: "d".repeat(64),
    priorGeneration: 2,
    priorPointerFingerprint: "e".repeat(64),
    ...overrides,
  });
}

// A delete tombstone chaining onto the given live pointer.
function tombstoneFor(pointer, overrides = {}) {
  return buildTombstone({
    hostId: pointer.hostId,
    workspaceId: pointer.workspaceId,
    sourcePlatform: pointer.sourcePlatform,
    operation: "delete",
    tombstonedGeneration: pointer.activeGeneration,
    priorKind: "workspace-generation-pointer",
    priorPointerFingerprint: pointer.pointerFingerprint,
    dirtyBackupFingerprint: "f".repeat(64),
    ...overrides,
  });
}

// In-memory injected io: a single slot holding the live record bytes. `throwAt`
// names a step at which the corresponding op throws (deterministic crash-sim,
// no timing). `replace` mutates the slot ONLY when it does not throw.
function makeIo(initialBytes = null) {
  const state = { slot: initialBytes };
  const throwAt = new Set();
  return {
    state,
    throwAt,
    async readLivePointer() {
      return state.slot;
    },
    async writeTemp(bytes) {
      if (throwAt.has("writeTemp")) throw new Error("writeTemp boom");
      return { bytes };
    },
    async flushTemp() {
      if (throwAt.has("flushTemp")) throw new Error("flushTemp boom");
    },
    async replace(ref) {
      if (throwAt.has("replace")) throw new Error("replace boom");
      state.slot = ref.bytes;
    },
    async flushParent() {
      if (throwAt.has("flushParent")) throw new Error("flushParent boom");
    },
  };
}

async function expectRefusal(fn, code) {
  await assert.rejects(fn, (error) => {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
    assert.equal(error.operation, "workspace_tombstone_publish");
    return true;
  });
}

test("happy path: publish a tombstone over a live pointer and read it back", async () => {
  const pointer = livePointer();
  const io = makeIo(generationPointerBytes(pointer));
  const tombstone = tombstoneFor(pointer);

  const result = await publishTombstone(io, tombstone);
  assert.equal(result.published, true);
  assert.equal(result.operation, "delete");
  assert.equal(result.tombstonedGeneration, 3);
  assert.equal(result.tombstoneFingerprint, tombstone.tombstoneFingerprint);
  assert.equal(result.priorPointerFingerprint, pointer.pointerFingerprint);
  assert.equal(result.priorKind, "workspace-generation-pointer");

  // Read-back round-trip: the live record is now the tombstone.
  const readBack = await readLiveTombstone(io);
  assert.deepEqual(readBack, tombstone);
  const disposition = await readLiveDisposition(io);
  assert.equal(disposition.kind, "workspace-tombstone");
  assert.equal(disposition.fingerprint, tombstone.tombstoneFingerprint);
  assert.deepEqual(disposition.record, tombstone);
});

test("crash-sim: at each step the live slot is EITHER the prior pointer OR the new tombstone, never torn", async () => {
  const pointer = livePointer();
  const pointerBytes = generationPointerBytes(pointer);
  const tombstone = tombstoneFor(pointer);

  for (const step of TOMBSTONE_STEPS) {
    const io = makeIo(pointerBytes);
    io.throwAt.add(step);
    // Every injected step failure surfaces as WORKSPACE_TOMBSTONE_IO_FAILED.
    await expectRefusal(() => publishTombstone(io, tombstone), "WORKSPACE_TOMBSTONE_IO_FAILED");

    // The slot always holds ONE valid record. replace is the linearization
    // point: a throw at or before it leaves the prior pointer live; a throw
    // after it (flushParent) leaves the new tombstone live.
    const live = await readLiveDisposition(io);
    if (step === "flushParent") {
      assert.equal(live.kind, "workspace-tombstone");
      assert.equal(live.fingerprint, tombstone.tombstoneFingerprint);
    } else {
      assert.equal(live.kind, "workspace-generation-pointer");
      assert.equal(live.fingerprint, pointer.pointerFingerprint);
    }
  }
});

test("stale priorPointerFingerprint is refused WORKSPACE_GENERATION_CAS_CONFLICT with no mutation", async () => {
  const pointer = livePointer();
  const pointerBytes = generationPointerBytes(pointer);
  const io = makeIo(pointerBytes);
  const stale = tombstoneFor(pointer, { priorPointerFingerprint: "9".repeat(64) });

  await expectRefusal(() => publishTombstone(io, stale), "WORKSPACE_GENERATION_CAS_CONFLICT");
  // Slot untouched: still the original pointer.
  assert.deepEqual(io.state.slot, pointerBytes);
  const live = await readLiveDisposition(io);
  assert.equal(live.kind, "workspace-generation-pointer");
  assert.equal(live.fingerprint, pointer.pointerFingerprint);
});

test("a mismatched priorKind or tombstonedGeneration is a CAS conflict", async () => {
  const pointer = livePointer();
  const io = makeIo(generationPointerBytes(pointer));
  await expectRefusal(
    () => publishTombstone(io, tombstoneFor(pointer, { priorKind: "workspace-tombstone" })),
    "WORKSPACE_GENERATION_CAS_CONFLICT"
  );
  await expectRefusal(
    () => publishTombstone(io, tombstoneFor(pointer, { tombstonedGeneration: 2 })),
    "WORKSPACE_GENERATION_CAS_CONFLICT"
  );
});

test("cannot tombstone an empty live slot", async () => {
  const pointer = livePointer();
  const io = makeIo(null);
  await expectRefusal(() => publishTombstone(io, tombstoneFor(pointer)), "WORKSPACE_GENERATION_CAS_CONFLICT");
});

test("tombstone chains onto a prior tombstone (reset then delete of the same generation)", async () => {
  const pointer = livePointer();
  const reset = buildTombstone({
    hostId: HOST,
    workspaceId: WORKSPACE,
    sourcePlatform: "posix",
    operation: "reset",
    tombstonedGeneration: pointer.activeGeneration,
    priorKind: "workspace-generation-pointer",
    priorPointerFingerprint: pointer.pointerFingerprint,
    dirtyBackupFingerprint: null,
  });
  const io = makeIo(generationPointerBytes(pointer));
  await publishTombstone(io, reset);

  const del = buildTombstone({
    hostId: HOST,
    workspaceId: WORKSPACE,
    sourcePlatform: "posix",
    operation: "delete",
    tombstonedGeneration: pointer.activeGeneration,
    priorKind: "workspace-tombstone",
    priorPointerFingerprint: reset.tombstoneFingerprint,
    dirtyBackupFingerprint: null,
  });
  const result = await publishTombstone(io, del);
  assert.equal(result.published, true);
  assert.equal(result.priorKind, "workspace-tombstone");
  const live = await readLiveTombstone(io);
  assert.deepEqual(live, del);
});

test("readLiveDisposition dispatches on kind: pointer, tombstone, unknown, empty", async () => {
  const pointer = livePointer();
  const tombstone = tombstoneFor(pointer);

  const pointerIo = makeIo(generationPointerBytes(pointer));
  const pd = await readLiveDisposition(pointerIo);
  assert.equal(pd.kind, "workspace-generation-pointer");
  assert.equal(pd.fingerprint, pointer.pointerFingerprint);
  assert.deepEqual(pd.record, pointer);

  const tombstoneIo = makeIo(tombstoneBytes(tombstone));
  const td = await readLiveDisposition(tombstoneIo);
  assert.equal(td.kind, "workspace-tombstone");
  assert.deepEqual(td.record, tombstone);

  // readLiveTombstone returns null when the live record is a pointer.
  assert.equal(await readLiveTombstone(pointerIo), null);

  // Empty slot -> null.
  assert.equal(await readLiveDisposition(makeIo(null)), null);

  // Unknown record kind -> CONFIG_INVALID (corrupt slot).
  const unknownIo = makeIo(canonicalJsonBytes({ kind: "workspace-something-else" }, TOMBSTONE_LIMITS));
  await expectRefusal(() => readLiveDisposition(unknownIo), PROTOCOL_ERROR_CODES.CONFIG_INVALID);

  // Object with no string kind -> CONFIG_INVALID.
  const noKindIo = makeIo(canonicalJsonBytes({ foo: 1 }, TOMBSTONE_LIMITS));
  await expectRefusal(() => readLiveDisposition(noKindIo), PROTOCOL_ERROR_CODES.CONFIG_INVALID);

  // Non-object canonical JSON (array) -> CONFIG_INVALID.
  const arrayIo = makeIo(canonicalJsonBytes([1, 2, 3], TOMBSTONE_LIMITS));
  await expectRefusal(() => readLiveDisposition(arrayIo), PROTOCOL_ERROR_CODES.CONFIG_INVALID);
});

test("validate/build reject malformed tombstones", async () => {
  const pointer = livePointer();
  // Bad operation.
  assert.throws(() => tombstoneFor(pointer, { operation: "create" }), /WORKSPACE_TOMBSTONE_INVALID/);
  // Bad priorKind.
  assert.throws(() => tombstoneFor(pointer, { priorKind: "nope" }), /WORKSPACE_TOMBSTONE_INVALID/);
  // Non-hex priorPointerFingerprint.
  assert.throws(() => tombstoneFor(pointer, { priorPointerFingerprint: "short" }), /WORKSPACE_TOMBSTONE_INVALID/);
  // Non-generation tombstonedGeneration.
  assert.throws(() => tombstoneFor(pointer, { tombstonedGeneration: 0 }), /WORKSPACE_TOMBSTONE_INVALID/);
  // A tampered fingerprint fails validation on parse.
  const good = tombstoneFor(pointer);
  const tampered = { ...good, tombstonedGeneration: 4 };
  assert.throws(() => validateTombstone(tampered), /WORKSPACE_TOMBSTONE_INVALID/);
  // dirtyBackupFingerprint === null is accepted.
  const clean = tombstoneFor(pointer, { dirtyBackupFingerprint: null });
  assert.equal(clean.dirtyBackupFingerprint, null);
  // Round-trip parse of a valid tombstone.
  assert.deepEqual(parseTombstone(tombstoneBytes(good)), good);
});

test("an incomplete lifecycle checkpoint classifies as manual_cleanup via the shared classifier", () => {
  // S5e builds a manual-cleanup record when a reset/delete cannot be resolved.
  // This binds S5d/S5e to the shared vocabulary: a valid manual-cleanup record
  // classifies as manual_cleanup (an unresolved disposal requiring owner action).
  const value = {
    version: 1,
    kind: "manual-cleanup",
    anchorFingerprint: "c".repeat(64),
    fenceGeneration: 1,
    txId: "transaction",
    reason: "owner-action",
    expectedFingerprint: null,
    observedFingerprint: null,
    expectedFloorFingerprint: null,
    observedFloorFingerprint: null,
    routeDisposition: "no-route",
    blockedUntilOwnerAction: true,
  };
  const manualCleanup = { ...value, manualCleanupFingerprint: canonicalJsonHash(value) };
  assert.equal(classifyWorkspaceLifecycleEvidence({ manualCleanup }), "manual_cleanup");
  // Absent any evidence, the classifier is "no-route", never a false disposal.
  assert.equal(classifyWorkspaceLifecycleEvidence({}), "no-route");
});

test("TOMBSTONE_STEPS is the frozen 4-step protocol with replace as the linearization point", () => {
  assert.deepEqual([...TOMBSTONE_STEPS], ["writeTemp", "flushTemp", "replace", "flushParent"]);
  assert.equal(Object.isFrozen(TOMBSTONE_STEPS), true);
  assert.equal(TOMBSTONE_STEPS[2], "replace");
});


test("io/reader contract violations fail closed", async () => {
  const pointer = livePointer();
  const tombstone = tombstoneFor(pointer);

  // io missing a required method -> WORKSPACE_TOMBSTONE_INVALID before any read.
  for (const drop of ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"]) {
    const io = makeIo(generationPointerBytes(pointer));
    delete io[drop];
    await expectRefusal(() => publishTombstone(io, tombstone), "WORKSPACE_TOMBSTONE_INVALID");
  }

  // readLivePointer returns a non-Uint8Array -> WORKSPACE_TOMBSTONE_IO_FAILED.
  const badBytesIo = { ...makeIo(null), async readLivePointer() { return "not-bytes"; } };
  await expectRefusal(() => readLiveDisposition(badBytesIo), "WORKSPACE_TOMBSTONE_IO_FAILED");

  // readLivePointer rejects -> WORKSPACE_TOMBSTONE_IO_FAILED, never absence.
  const throwingIo = { ...makeIo(null), async readLivePointer() { throw new Error("scan crashed"); } };
  await expectRefusal(() => readLiveDisposition(throwingIo), "WORKSPACE_TOMBSTONE_IO_FAILED");
});

test("a host/workspace mismatch against the live record is a CAS conflict", async () => {
  const pointer = livePointer();
  const io = makeIo(generationPointerBytes(pointer));
  // A tombstone whose fingerprint is valid for a different host still fails the
  // first succession guard (host/workspace) before the fingerprint guard.
  const otherHost = livePointer({ hostId: "host-b" });
  const otherHostIo = makeIo(generationPointerBytes(otherHost));
  const forOtherHost = tombstoneFor(otherHost); // priorPointerFingerprint matches otherHost
  await expectRefusal(() => publishTombstone(io, forOtherHost), "WORKSPACE_GENERATION_CAS_CONFLICT");
  // And its intended target still accepts it (proves the tombstone itself is valid).
  const ok = await publishTombstone(otherHostIo, forOtherHost);
  assert.equal(ok.published, true);
});

test("an IO_FAILED publication step error carries its step name", async () => {
  const pointer = livePointer();
  const io = makeIo(generationPointerBytes(pointer));
  io.throwAt.add("writeTemp");
  await assert.rejects(
    () => publishTombstone(io, tombstoneFor(pointer)),
    (error) => {
      assert.equal(error.code, "WORKSPACE_TOMBSTONE_IO_FAILED");
      assert.equal(error.step, "writeTemp");
      return true;
    }
  );
});

test("an extra or missing key is rejected by validateTombstone", () => {
  const good = tombstoneFor(livePointer());
  assert.throws(() => validateTombstone({ ...good, extra: 1 }), /WORKSPACE_TOMBSTONE_INVALID/);
  const { dirtyBackupFingerprint, ...missing } = good;
  assert.throws(() => validateTombstone(missing), /WORKSPACE_TOMBSTONE_INVALID/);
});
