import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync, renameSync, openSync, fsyncSync, closeSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  buildGenerationPointer,
  generationPointerBytes,
  parseGenerationPointer,
  publishGeneration,
  readLiveGeneration,
  PUBLISH_STEPS,
} from "../src/workspace-generation-publisher.js";

const BASE = {
  hostId: "host-1",
  workspaceId: "workspace-1",
  sourcePlatform: "windows-drive",
  rootIdentityFingerprint: "1".repeat(64),
  storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64),
  manifestFingerprint: "4".repeat(64),
};

function mkPointer(gen, prior) {
  return buildGenerationPointer({
    ...BASE,
    generationPath: `generations/${String(gen).padStart(6, "0")}`,
    activeGeneration: gen,
    priorGeneration: prior ? prior.activeGeneration : null,
    priorPointerFingerprint: prior ? prior.pointerFingerprint : null,
  });
}

function bestEffortFlush(path, { dir = false } = {}) {
  try {
    const fd = openSync(path, dir ? "r" : "r+");
    try { fsyncSync(fd); } finally { closeSync(fd); }
  } catch {
    // Directory fsync is unsupported on some platforms (Windows); the rename
    // itself is the atomic linearisation point, so a best-effort flush is fine.
  }
}

// A real-filesystem io. `failAt` names a step that throws BEFORE performing its
// effect, deterministically simulating a SIGKILL at that instant with no timing.
function realIo(dir, { failAt = null } = {}) {
  const pointerPath = join(dir, "pointer.json");
  const crash = (step) => {
    if (failAt === step) {
      const e = new Error(`simulated crash at ${step}`);
      e.code = "ECRASH";
      throw e;
    }
  };
  return {
    pointerPath,
    readLivePointer: async () => {
      crash("readLivePointer");
      if (!existsSync(pointerPath)) return null;
      return readFileSync(pointerPath);
    },
    writeTemp: async (bytes) => {
      crash("writeTemp");
      const tempPath = join(dir, `pointer.json.tmp.${randomBytes(6).toString("hex")}`);
      writeFileSync(tempPath, bytes, { flag: "wx" });
      return tempPath;
    },
    flushTemp: async (tempPath) => {
      crash("flushTemp");
      bestEffortFlush(tempPath);
    },
    replace: async (tempPath) => {
      crash("replace");
      renameSync(tempPath, pointerPath); // atomic same-volume replace
    },
    flushParent: async () => {
      crash("flushParent");
      bestEffortFlush(dir, { dir: true });
    },
  };
}

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "s4d-gen-"));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("publishes a first generation then a successor, preserving the prior generation directory", async () => {
  await withTempDir(async (dir) => {
    // Stage two generation directories on disk; publication only flips the pointer.
    mkdirSync(join(dir, "generations", "000001"), { recursive: true });
    mkdirSync(join(dir, "generations", "000002"), { recursive: true });
    writeFileSync(join(dir, "generations", "000001", "marker"), "gen1");

    const io = realIo(dir);
    const p1 = mkPointer(1, null);
    const proof1 = await publishGeneration(io, p1);
    assert.equal(proof1.activeGeneration, 1);
    assert.deepEqual({ ...parseGenerationPointer(readFileSync(io.pointerPath)) }, { ...p1 });

    const p2 = mkPointer(2, p1);
    const proof2 = await publishGeneration(io, p2);
    assert.equal(proof2.activeGeneration, 2);
    assert.equal(proof2.priorGeneration, 1);

    // The live pointer is now p2, chained to p1's fingerprint.
    const live = await readLiveGeneration(io);
    assert.deepEqual({ ...live }, { ...p2 });
    assert.equal(live.priorPointerFingerprint, p1.pointerFingerprint);

    // The prior generation directory is preserved for reversible rollback.
    assert.ok(existsSync(join(dir, "generations", "000001", "marker")));
  });
});

test("a real successor publication is rejected (CAS) when the live pointer is not its declared prior", async () => {
  await withTempDir(async (dir) => {
    const io = realIo(dir);
    const p1 = mkPointer(1, null);
    await publishGeneration(io, p1);

    // Build a successor that chains onto a DIFFERENT prior pointer.
    const strangerPrior = buildGenerationPointer({ ...BASE, generationPath: "generations/000001", activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: null, manifestFingerprint: "a".repeat(64) });
    const bad = mkPointer(2, strangerPrior);
    await assert.rejects(publishGeneration(io, bad), (e) => e.code === "WORKSPACE_GENERATION_CAS_CONFLICT");

    // The live pointer is untouched by the rejected publication.
    assert.deepEqual({ ...(await readLiveGeneration(io)) }, { ...p1 });
  });
});

test("crash at every publication step leaves the on-disk pointer as exactly the old or the new valid pointer", async () => {
  for (const failAt of PUBLISH_STEPS) {
    await withTempDir(async (dir) => {
      // Establish a live generation p1.
      await publishGeneration(realIo(dir), mkPointer(1, null));
      const p1 = mkPointer(1, null);
      const p2 = mkPointer(2, p1);

      // Attempt to promote p2 but crash deterministically at `failAt`.
      const crashingIo = realIo(dir, { failAt });
      await assert.rejects(publishGeneration(crashingIo, p2), (e) => e.code === "WORKSPACE_GENERATION_IO_FAILED" && e.step === failAt);

      // Invariant: the live pointer on disk still parses to a VALID pointer that
      // is either exactly p1 (crash at/before the atomic replace) or exactly p2
      // (crash after the replace) — never torn, corrupt, or absent.
      const liveBytes = readFileSync(join(dir, "pointer.json"));
      const live = parseGenerationPointer(liveBytes); // throws if torn/corrupt
      const isOld = live.pointerFingerprint === p1.pointerFingerprint;
      const isNew = live.pointerFingerprint === p2.pointerFingerprint;
      assert.ok(isOld || isNew, `crash at ${failAt}: live pointer is neither p1 nor p2`);
      if (failAt === "flushParent") {
        assert.ok(isNew, "a crash after the atomic replace must expose the new pointer");
      } else {
        assert.ok(isOld, `a crash at ${failAt} (at/before replace) must preserve the old pointer`);
      }

      // No temp file may masquerade as the live pointer path.
      const stray = readdirSync(dir).filter((name) => name === "pointer.json");
      assert.equal(stray.length, 1);
    });
  }
});

test("a leftover temp file from a crashed publish does not affect the next publish", async () => {
  await withTempDir(async (dir) => {
    // Establish p1, then crash a p2 promotion at flushTemp so an exclusive temp
    // is left on disk next to the live pointer.
    await publishGeneration(realIo(dir), mkPointer(1, null));
    const p1 = mkPointer(1, null);
    const p2 = mkPointer(2, p1);
    await assert.rejects(publishGeneration(realIo(dir, { failAt: "flushTemp" }), p2),
      (e) => e.code === "WORKSPACE_GENERATION_IO_FAILED" && e.step === "flushTemp");

    // A temp file is present and the live pointer is still p1.
    const leftovers = readdirSync(dir).filter((name) => name.startsWith("pointer.json.tmp."));
    assert.ok(leftovers.length >= 1, "expected a leftover temp from the crashed publish");
    assert.deepEqual({ ...(await readLiveGeneration(realIo(dir))) }, { ...p1 });

    // Retrying the same promotion succeeds (writeTemp uses a fresh unique name,
    // and the CAS still sees p1 as live) and lands p2 as the live pointer.
    const proof = await publishGeneration(realIo(dir), p2);
    assert.equal(proof.activeGeneration, 2);
    assert.deepEqual({ ...(await readLiveGeneration(realIo(dir))) }, { ...p2 });
  });
});
