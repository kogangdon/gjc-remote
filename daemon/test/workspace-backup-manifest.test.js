import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import {
  buildWorkspaceManifest,
  validateWorkspaceManifest,
  workspaceManifestBytes,
  parseWorkspaceManifest,
  computeManifestEntries,
  verifyManifestAgainst,
} from "../src/workspace-backup-manifest.js";

const BASE = {
  hostId: "host-1",
  workspaceId: "workspace-1",
  workspaceGeneration: 3,
  sourcePlatform: "windows-drive",
  rootIdentityFingerprint: "1".repeat(64),
  storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64),
};

const sha = (buf) => createHash("sha256").update(buf).digest("hex");

function fakeIo(map) {
  return {
    readBytes: async (path) => {
      if (!map.has(path)) {
        const e = new Error(`missing ${path}`);
        e.code = "ENOENT";
        throw e;
      }
      return map.get(path);
    },
  };
}

async function expectRefusal(promiseOrFn, code) {
  try {
    await (typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn);
    assert.fail(`expected refusal ${code} but resolved`);
  } catch (error) {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.reason ?? error.message}`);
    assert.equal(error.operation, "workspace_backup_manifest");
    assert.equal(typeof error.reason, "string");
    assert.ok(error.message.startsWith("workspace_backup_manifest:"));
    return error;
  }
}

test("build produces a frozen, sorted, self-consistent manifest", () => {
  const m = buildWorkspaceManifest({
    ...BASE,
    entries: [
      { path: "b.txt", size: 6, sha256: "a".repeat(64) },
      { path: "a/c.txt", size: 5, sha256: "b".repeat(64) },
    ],
  });
  assert.equal(m.kind, "workspace-backup-manifest");
  assert.equal(m.version, 1);
  assert.equal(m.entryCount, 2);
  assert.equal(m.totalSize, 11);
  assert.deepEqual(m.entries.map((e) => e.path), ["a/c.txt", "b.txt"]); // sorted
  assert.equal(m.manifestFingerprint.length, 64);
  assert.ok(Object.isFrozen(m));
  assert.ok(Object.isFrozen(m.entries));
  assert.throws(() => { m.entries.push({}); });
  // A freshly built manifest re-validates.
  assert.equal(validateWorkspaceManifest(m), m);
});

test("fingerprint is deterministic regardless of input entry order", () => {
  const a = buildWorkspaceManifest({ ...BASE, entries: [
    { path: "z", size: 1, sha256: "1".repeat(64) },
    { path: "a", size: 2, sha256: "2".repeat(64) },
  ] });
  const b = buildWorkspaceManifest({ ...BASE, entries: [
    { path: "a", size: 2, sha256: "2".repeat(64) },
    { path: "z", size: 1, sha256: "1".repeat(64) },
  ] });
  assert.equal(a.manifestFingerprint, b.manifestFingerprint);
});

test("fingerprint changes when any hashed field changes", () => {
  const base = buildWorkspaceManifest({ ...BASE, entries: [{ path: "a", size: 1, sha256: "1".repeat(64) }] });
  const diffGen = buildWorkspaceManifest({ ...BASE, workspaceGeneration: 4, entries: [{ path: "a", size: 1, sha256: "1".repeat(64) }] });
  const diffContent = buildWorkspaceManifest({ ...BASE, entries: [{ path: "a", size: 1, sha256: "9".repeat(64) }] });
  const diffGit = buildWorkspaceManifest({ ...BASE, gitGenerationFingerprint: "4".repeat(64), entries: [{ path: "a", size: 1, sha256: "1".repeat(64) }] });
  assert.notEqual(base.manifestFingerprint, diffGen.manifestFingerprint);
  assert.notEqual(base.manifestFingerprint, diffContent.manifestFingerprint);
  assert.notEqual(base.manifestFingerprint, diffGit.manifestFingerprint);
});

test("empty entry set builds a valid manifest", () => {
  const m = buildWorkspaceManifest({ ...BASE, entries: [] });
  assert.equal(m.entryCount, 0);
  assert.equal(m.totalSize, 0);
  assert.deepEqual(m.entries, []);
  validateWorkspaceManifest(m);
});

test("bytes round-trip through parseWorkspaceManifest", () => {
  const m = buildWorkspaceManifest({ ...BASE, entries: [
    { path: "dir/file", size: 3, sha256: "c".repeat(64) },
  ] });
  const bytes = workspaceManifestBytes(m);
  const parsed = parseWorkspaceManifest(bytes);
  assert.equal(parsed.manifestFingerprint, m.manifestFingerprint);
  assert.deepEqual(parsed.entries, m.entries.map((e) => ({ ...e })));
});

test("rejects reserved/absolute/escaping entry paths", () => {
  const cases = ["/abs", "..", "a/../b", "C:\\x", "win\\sep", "a//b", "has\0nul", ""];
  for (const bad of cases) {
    assert.throws(
      () => buildWorkspaceManifest({ ...BASE, entries: [{ path: bad, size: 0, sha256: "0".repeat(64) }] }),
      (e) => e.code === "WORKSPACE_MANIFEST_PATH_REJECTED" || e.code === "WORKSPACE_MANIFEST_INVALID",
      `path ${JSON.stringify(bad)} should be rejected`,
    );
  }
});

test("rejects a bad sha256, negative size, unknown platform", () => {
  assert.throws(() => buildWorkspaceManifest({ ...BASE, entries: [{ path: "a", size: 1, sha256: "nothex" }] }),
    (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
  assert.throws(() => buildWorkspaceManifest({ ...BASE, entries: [{ path: "a", size: -1, sha256: "1".repeat(64) }] }),
    (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
  assert.throws(() => buildWorkspaceManifest({ ...BASE, sourcePlatform: "bsd", entries: [] }),
    (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
});

test("validate rejects a tampered fingerprint", () => {
  const m = { ...buildWorkspaceManifest({ ...BASE, entries: [{ path: "a", size: 1, sha256: "1".repeat(64) }] }) };
  const tampered = { ...m, manifestFingerprint: "0".repeat(64) };
  assert.throws(() => validateWorkspaceManifest(tampered), (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
});

test("validate rejects a body change that does not update the fingerprint", () => {
  const m = buildWorkspaceManifest({ ...BASE, entries: [{ path: "a", size: 1, sha256: "1".repeat(64) }] });
  const mutated = { ...m, totalSize: 999, entries: m.entries.map((e) => ({ ...e })) };
  assert.throws(() => validateWorkspaceManifest(mutated), (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
});

test("validate rejects unsorted or duplicate entries", () => {
  const good = buildWorkspaceManifest({ ...BASE, entries: [
    { path: "a", size: 1, sha256: "1".repeat(64) },
    { path: "b", size: 1, sha256: "2".repeat(64) },
  ] });
  const unsorted = { ...good, entries: [good.entries[1], good.entries[0]].map((e) => ({ ...e })) };
  unsorted.manifestFingerprint = good.manifestFingerprint;
  assert.throws(() => validateWorkspaceManifest(unsorted), (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
  const dup = { ...good, entryCount: 2, entries: [{ ...good.entries[0] }, { ...good.entries[0] }] };
  assert.throws(() => validateWorkspaceManifest(dup), (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
});

test("parse rejects non-canonical bytes", () => {
  assert.throws(() => parseWorkspaceManifest(Buffer.from("{not json")), (e) => e.code === "WORKSPACE_MANIFEST_INVALID");
});

test("computeManifestEntries reads, hashes, and sorts", async () => {
  const map = new Map([
    ["b.txt", Buffer.from("world\n")],
    ["a/c.txt", Buffer.from("hello")],
  ]);
  const entries = await computeManifestEntries(fakeIo(map), ["b.txt", "a/c.txt"]);
  assert.deepEqual(entries.map((e) => e.path), ["a/c.txt", "b.txt"]);
  assert.equal(entries[0].size, 5);
  assert.equal(entries[0].sha256, sha(Buffer.from("hello")));
});

test("computeManifestEntries refuses duplicate input paths", async () => {
  await expectRefusal(computeManifestEntries(fakeIo(new Map([["a", Buffer.from("x")]])), ["a", "a"]), "WORKSPACE_MANIFEST_INVALID");
});

test("computeManifestEntries surfaces a read failure as WORKSPACE_MANIFEST_READ_FAILED", async () => {
  await expectRefusal(computeManifestEntries(fakeIo(new Map()), ["missing"]), "WORKSPACE_MANIFEST_READ_FAILED");
});

test("computeManifestEntries refuses a reader that does not return bytes", async () => {
  const io = { readBytes: async () => "not bytes" };
  await expectRefusal(computeManifestEntries(io, ["a"]), "WORKSPACE_MANIFEST_READ_FAILED");
});

test("verifyManifestAgainst passes for matching content and reports count", async () => {
  const map = new Map([["a", Buffer.from("hello")], ["b", Buffer.from("world")]]);
  const entries = await computeManifestEntries(fakeIo(map), ["a", "b"]);
  const m = buildWorkspaceManifest({ ...BASE, entries });
  assert.deepEqual(await verifyManifestAgainst(fakeIo(map), m), { ok: true, verifiedCount: 2 });
});

test("verifyManifestAgainst fails on a content change (sha mismatch)", async () => {
  const map = new Map([["a", Buffer.from("hello")]]);
  const entries = await computeManifestEntries(fakeIo(map), ["a"]);
  const m = buildWorkspaceManifest({ ...BASE, entries });
  const tampered = new Map([["a", Buffer.from("HELLO")]]);
  const err = await expectRefusal(verifyManifestAgainst(fakeIo(tampered), m), "WORKSPACE_MANIFEST_MISMATCH");
  assert.equal(err.path, "a");
});

test("verifyManifestAgainst fails on a size change", async () => {
  const map = new Map([["a", Buffer.from("hello")]]);
  const entries = await computeManifestEntries(fakeIo(map), ["a"]);
  const m = buildWorkspaceManifest({ ...BASE, entries });
  const shorter = new Map([["a", Buffer.from("hi")]]);
  await expectRefusal(verifyManifestAgainst(fakeIo(shorter), m), "WORKSPACE_MANIFEST_MISMATCH");
});

test("verifyManifestAgainst fails when a manifested file is missing", async () => {
  const map = new Map([["a", Buffer.from("hello")]]);
  const entries = await computeManifestEntries(fakeIo(map), ["a"]);
  const m = buildWorkspaceManifest({ ...BASE, entries });
  await expectRefusal(verifyManifestAgainst(fakeIo(new Map()), m), "WORKSPACE_MANIFEST_MISMATCH");
});
