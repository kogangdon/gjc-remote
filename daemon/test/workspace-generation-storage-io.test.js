import assert from "node:assert/strict";
import { mkdtemp, mkdir, open, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildGenerationPointer,
  publishGeneration,
  readLiveGeneration,
} from "../src/workspace-generation-publisher.js";
import {
  createAtomicPointerIo,
  createGenerationPublisherIo,
  createTombstonePublisherIo,
  enumerateRecoverableWorkspaces,
  readSnapshotInputs,
} from "../src/workspace-generation-storage-io.js";

const HEX = (byte) => byte.toString(16).padStart(2, "0");
const hex64 = (seed) => {
  let out = "";
  for (let i = 0; i < 32; i += 1) out += HEX((seed + i) % 256);
  return out;
};

function firstPointer({ hostId = "host-1", workspaceId = "ws-1" } = {}) {
  return buildGenerationPointer({
    hostId,
    workspaceId,
    sourcePlatform: "posix",
    activeGeneration: 1,
    generationPath: "generations/1",
    rootIdentityFingerprint: hex64(1),
    storageIdentityFingerprint: hex64(2),
    gitGenerationFingerprint: hex64(3),
    manifestFingerprint: hex64(4),
    priorGeneration: null,
    priorPointerFingerprint: null,
  });
}

function successorPointer(prior, { activeGeneration = 2 } = {}) {
  return buildGenerationPointer({
    hostId: prior.hostId,
    workspaceId: prior.workspaceId,
    sourcePlatform: prior.sourcePlatform,
    activeGeneration,
    generationPath: `generations/${activeGeneration}`,
    rootIdentityFingerprint: hex64(11),
    storageIdentityFingerprint: hex64(12),
    gitGenerationFingerprint: hex64(13),
    manifestFingerprint: hex64(14),
    priorGeneration: prior.activeGeneration,
    priorPointerFingerprint: prior.pointerFingerprint,
  });
}

async function makeTmpRoot() {
  return mkdtemp(path.join(tmpdir(), "gen-storage-io-"));
}

test("round trip: createGenerationPublisherIo publishes and reads back the first generation", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const pointer = firstPointer();
    await publishGeneration(io, pointer);

    const fresh = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const live = await readLiveGeneration(fresh);
    assert.equal(live.pointerFingerprint, pointer.pointerFingerprint);
    assert.equal(live.activeGeneration, 1);

    const snapshot = await readSnapshotInputs({ workspaceRoot: root, workspaceId: "ws-1" });
    assert.notEqual(snapshot.livePointer, null);
    assert.equal(snapshot.livePointer.pointerFingerprint, pointer.pointerFingerprint);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("successor chaining: publishing generation 2 onto generation 1 flips the live pointer", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const gen1 = firstPointer();
    await publishGeneration(io, gen1);
    const gen2 = successorPointer(gen1);
    await publishGeneration(io, gen2);

    const live = await readLiveGeneration(io);
    assert.equal(live.activeGeneration, 2);
    assert.equal(live.pointerFingerprint, gen2.pointerFingerprint);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("crash injection: throwing before replace leaves the prior live value intact", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const gen1 = firstPointer();
    await publishGeneration(io, gen1);

    const gen2 = successorPointer(gen1);
    const bytes = (await import("../src/workspace-generation-publisher.js")).generationPointerBytes(gen2);
    const tempRef = await io.writeTemp(bytes);
    await io.flushTemp(tempRef);
    // Simulated SIGKILL: stop before replace().

    const live = await readLiveGeneration(io);
    assert.equal(live.pointerFingerprint, gen1.pointerFingerprint, "live pointer must remain the prior value");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("crash injection: throwing after replace leaves the new value live", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const gen1 = firstPointer();
    await publishGeneration(io, gen1);

    const gen2 = successorPointer(gen1);
    const { generationPointerBytes } = await import("../src/workspace-generation-publisher.js");
    const bytes = generationPointerBytes(gen2);
    const tempRef = await io.writeTemp(bytes);
    await io.flushTemp(tempRef);
    await io.replace(tempRef);
    // Simulated SIGKILL: stop before flushParent(). replace already committed.

    const live = await readLiveGeneration(io);
    assert.equal(live.pointerFingerprint, gen2.pointerFingerprint, "live pointer must be the new value");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("crash injection on first publication: throwing before replace leaves the slot empty (null)", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const gen1 = firstPointer();
    const { generationPointerBytes } = await import("../src/workspace-generation-publisher.js");
    const bytes = generationPointerBytes(gen1);
    const tempRef = await io.writeTemp(bytes);
    await io.flushTemp(tempRef);
    // Simulated SIGKILL before replace: no first publication ever landed.

    const live = await readLiveGeneration(io);
    assert.equal(live, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("exclusive temp create: two concurrent writeTemp calls get distinct temp paths", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const bytesA = new TextEncoder().encode("payload-a");
    const bytesB = new TextEncoder().encode("payload-b");
    const [refA, refB] = await Promise.all([io.writeTemp(bytesA), io.writeTemp(bytesB)]);
    assert.notEqual(refA.tempPath, refB.tempPath);
    await io.flushTemp(refA);
    await io.flushTemp(refB);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("exclusive temp create: a pre-existing temp file with the same name rejects with EEXIST", async () => {
  const root = await makeTmpRoot();
  try {
    const workspaceId = "ws-1";
    const genDir = path.join(root, workspaceId, "generation");
    await mkdir(genDir, { recursive: true });
    const collidingPath = path.join(genDir, "live.ptr.1.1.deadbeefcafe.tmp");
    await writeFile(collidingPath, "pre-existing");

    let sawEexist = false;
    try {
      const handle = await open(collidingPath, "wx");
      await handle.close();
    } catch (error) {
      sawEexist = error?.code === "EEXIST";
    }
    assert.equal(sawEexist, true, "the 'wx' open flag must reject an existing path with EEXIST");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("leftover-temp sweep: an orphan *.tmp from a simulated crash is removed and a later publish succeeds", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const gen1 = firstPointer();

    const { generationPointerBytes } = await import("../src/workspace-generation-publisher.js");
    const orphanRef = await io.writeTemp(generationPointerBytes(gen1));
    await io.flushTemp(orphanRef);
    // Simulated crash: orphanRef.tempPath is now abandoned on disk (never replaced).

    const genDir = path.join(root, "ws-1", "generation");
    const beforeSweep = (await readdir(genDir)).filter((name) => name.endsWith(".tmp"));
    assert.equal(beforeSweep.length, 1, "the orphan temp must exist before the sweep");

    await io.sweepLeftoverTemps();
    const afterSweep = (await readdir(genDir)).filter((name) => name.endsWith(".tmp"));
    assert.equal(afterSweep.length, 0, "sweepLeftoverTemps must remove the orphan");

    // A subsequent full publish still succeeds (writeTemp also sweeps internally).
    await publishGeneration(io, gen1);
    const live = await readLiveGeneration(io);
    assert.equal(live.pointerFingerprint, gen1.pointerFingerprint);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("same-volume rename: the temp file is created in the same directory as the live pointer", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const gen1 = firstPointer();
    const { generationPointerBytes } = await import("../src/workspace-generation-publisher.js");
    const tempRef = await io.writeTemp(generationPointerBytes(gen1));
    const pointerPath = path.join(root, "ws-1", "generation", "live.ptr");
    assert.equal(path.dirname(tempRef.tempPath), path.dirname(pointerPath));
    await io.flushTemp(tempRef);
    await io.replace(tempRef);
    await io.flushParent();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("tombstone io: createTombstonePublisherIo places live.tomb under tombstone/", async () => {
  const root = await makeTmpRoot();
  try {
    const io = await createTombstonePublisherIo({ workspaceRoot: root, workspaceId: "ws-1" });
    const live = await io.readLivePointer();
    assert.equal(live, null);
    const dirents = await readdir(path.join(root, "ws-1"));
    assert.ok(dirents.includes("tombstone"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("readSnapshotInputs: all-absent workspace returns all 6 fields null", async () => {
  const root = await makeTmpRoot();
  try {
    await mkdir(path.join(root, "ws-1"), { recursive: true });
    const snapshot = await readSnapshotInputs({ workspaceRoot: root, workspaceId: "ws-1" });
    assert.deepEqual(snapshot, {
      livePointer: null,
      priorPointer: null,
      candidatePointer: null,
      checkpoint: null,
      transaction: null,
      manualCleanup: null,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("readSnapshotInputs: each of the 6 files present returns a parsed non-null value", async () => {
  const root = await makeTmpRoot();
  try {
    const workspaceId = "ws-1";
    const genDir = path.join(root, workspaceId, "generation");
    const lifecycleDir = path.join(root, workspaceId, "lifecycle");
    await mkdir(genDir, { recursive: true });
    await mkdir(lifecycleDir, { recursive: true });

    const { generationPointerBytes } = await import("../src/workspace-generation-publisher.js");
    const live = firstPointer({ workspaceId });
    const prior = firstPointer({ workspaceId });
    const candidate = firstPointer({ workspaceId });
    await writeFile(path.join(genDir, "live.ptr"), generationPointerBytes(live));
    await writeFile(path.join(genDir, "prior.ptr"), generationPointerBytes(prior));
    await writeFile(path.join(genDir, "candidate.ptr"), generationPointerBytes(candidate));
    await writeFile(path.join(lifecycleDir, "checkpoint.json"), JSON.stringify({ marker: "checkpoint" }));
    await writeFile(path.join(lifecycleDir, "transaction.json"), JSON.stringify({ marker: "transaction" }));
    await writeFile(path.join(lifecycleDir, "manual-cleanup.json"), JSON.stringify({ marker: "manual-cleanup" }));

    const snapshot = await readSnapshotInputs({ workspaceRoot: root, workspaceId });
    assert.equal(snapshot.livePointer.pointerFingerprint, live.pointerFingerprint);
    assert.equal(snapshot.priorPointer.pointerFingerprint, prior.pointerFingerprint);
    assert.equal(snapshot.candidatePointer.pointerFingerprint, candidate.pointerFingerprint);
    assert.deepEqual(snapshot.checkpoint, { marker: "checkpoint" });
    assert.deepEqual(snapshot.transaction, { marker: "transaction" });
    assert.deepEqual(snapshot.manualCleanup, { marker: "manual-cleanup" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("readSnapshotInputs: a truncated pointer file throws rather than returning null", async () => {
  const root = await makeTmpRoot();
  try {
    const workspaceId = "ws-1";
    const genDir = path.join(root, workspaceId, "generation");
    await mkdir(genDir, { recursive: true });
    await writeFile(path.join(genDir, "live.ptr"), '{"version":1,"kind":"workspace-generation-pointer"');

    await assert.rejects(() => readSnapshotInputs({ workspaceRoot: root, workspaceId }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("readSnapshotInputs: a truncated lifecycle JSON file throws rather than returning null", async () => {
  const root = await makeTmpRoot();
  try {
    const workspaceId = "ws-1";
    const lifecycleDir = path.join(root, workspaceId, "lifecycle");
    await mkdir(lifecycleDir, { recursive: true });
    await writeFile(path.join(lifecycleDir, "checkpoint.json"), '{"partial": tru');

    await assert.rejects(() => readSnapshotInputs({ workspaceRoot: root, workspaceId }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("enumerateRecoverableWorkspaces: an absent root returns []", async () => {
  const root = await makeTmpRoot();
  const missing = path.join(root, "does-not-exist");
  await rm(root, { recursive: true, force: true });
  const result = await enumerateRecoverableWorkspaces({ workspaceRoot: missing });
  assert.deepEqual(result, []);
});

test("enumerateRecoverableWorkspaces: empty root returns []", async () => {
  const root = await makeTmpRoot();
  try {
    const result = await enumerateRecoverableWorkspaces({ workspaceRoot: root });
    assert.deepEqual(result, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("enumerateRecoverableWorkspaces: only recoverable workspaces are returned, sorted", async () => {
  const root = await makeTmpRoot();
  try {
    // ws-gen: has a generation/live.ptr -> recoverable
    await createGenerationPublisherIo({ workspaceRoot: root, workspaceId: "ws-gen" }).then(async (io) => {
      await publishGeneration(io, firstPointer({ workspaceId: "ws-gen" }));
    });
    // ws-tomb: has a tombstone/live.tomb file -> recoverable
    const tombDir = path.join(root, "ws-tomb", "tombstone");
    await mkdir(tombDir, { recursive: true });
    await writeFile(path.join(tombDir, "live.tomb"), "placeholder");
    // ws-lifecycle: has only a lifecycle/ dir -> recoverable
    await mkdir(path.join(root, "ws-lifecycle", "lifecycle"), { recursive: true });
    // ws-empty: an empty directory -> NOT recoverable
    await mkdir(path.join(root, "ws-empty"), { recursive: true });
    // a stray file at the root (not a directory) must be ignored, not throw
    await writeFile(path.join(root, "stray-file.txt"), "not a workspace");

    const result = await enumerateRecoverableWorkspaces({ workspaceRoot: root });
    assert.deepEqual(result, ["ws-gen", "ws-lifecycle", "ws-tomb"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("win32 honesty: flushParent never throws on the current platform", async () => {
  const root = await makeTmpRoot();
  try {
    const io = createAtomicPointerIo({ pointerPath: path.join(root, "live.ptr") });
    await mkdir(root, { recursive: true });
    await io.flushParent();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
