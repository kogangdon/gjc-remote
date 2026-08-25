import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import {
  computeDirtyBackup,
  assertDirtyBackupComplete,
  DIRTY_BACKUP_REQUEST_KEYS,
} from "../src/workspace-dirty-backup.js";
import { buildWorkspaceManifest } from "../src/workspace-backup-manifest.js";

const IDENTITY = {
  hostId: "host-1",
  workspaceId: "workspace-1",
  workspaceGeneration: 4,
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

async function expectRefusal(promiseOrFn, code, operation = "workspace_dirty_backup") {
  try {
    await (typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn);
    assert.fail(`expected refusal ${code} but resolved`);
  } catch (error) {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.reason ?? error.message}`);
    assert.equal(error.operation, operation);
    assert.equal(typeof error.reason, "string");
    return error;
  }
}

test("dirty backup captures the live tree and matches an independent S4c manifest", async () => {
  const map = new Map([
    ["b.txt", Buffer.from("world\n")],
    ["dir/a.txt", Buffer.from("hello")],
  ]);
  const backup = await computeDirtyBackup(fakeIo(map), {
    ...IDENTITY,
    relativePaths: ["b.txt", "dir/a.txt"],
  });

  // Frozen result exposing the manifest and its fingerprint.
  assert.ok(Object.isFrozen(backup));
  assert.equal(backup.manifest.kind, "workspace-backup-manifest");
  assert.equal(backup.manifest.entryCount, 2);
  assert.equal(backup.manifestFingerprint, backup.manifest.manifestFingerprint);
  assert.equal(backup.manifestFingerprint.length, 64);

  // The dirty backup is byte-for-byte comparable to a clean S4c manifest built
  // from the same identity + content: composing S4c verbatim, not a parallel
  // schema, means the fingerprints are identical.
  const independent = buildWorkspaceManifest({
    ...IDENTITY,
    entries: [
      { path: "b.txt", size: 6, sha256: sha(Buffer.from("world\n")) },
      { path: "dir/a.txt", size: 5, sha256: sha(Buffer.from("hello")) },
    ],
  });
  assert.equal(backup.manifestFingerprint, independent.manifestFingerprint);
});

test("a zero-path request is refused (no vacuous backup)", async () => {
  await expectRefusal(
    computeDirtyBackup(fakeIo(new Map()), { ...IDENTITY, relativePaths: [] }),
    "CONFIG_INVALID",
  );
});

test("a non-array or non-exact request is refused before any read", async () => {
  await expectRefusal(
    computeDirtyBackup(fakeIo(new Map()), { ...IDENTITY, relativePaths: "b.txt" }),
    "CONFIG_INVALID",
  );
  // Missing a required identity key.
  const { gitGenerationFingerprint, ...missing } = IDENTITY;
  await expectRefusal(
    computeDirtyBackup(fakeIo(new Map()), { ...missing, relativePaths: ["a"] }),
    "CONFIG_INVALID",
  );
  // Extra key beyond the exact set.
  await expectRefusal(
    computeDirtyBackup(fakeIo(new Map()), { ...IDENTITY, relativePaths: ["a"], extra: true }),
    "CONFIG_INVALID",
  );
});

test("a missing io.readBytes is refused", async () => {
  await expectRefusal(
    computeDirtyBackup({}, { ...IDENTITY, relativePaths: ["a"] }),
    "CONFIG_INVALID",
  );
});

test("an unreadable file aborts the backup as a composed S4c read failure", async () => {
  const map = new Map([["present", Buffer.from("x")]]);
  // 'missing' is not in the map -> S4c read failure propagates unchanged.
  await expectRefusal(
    computeDirtyBackup(fakeIo(map), { ...IDENTITY, relativePaths: ["present", "missing"] }),
    "WORKSPACE_MANIFEST_READ_FAILED",
    "workspace_backup_manifest",
  );
});

test("a duplicate requested path aborts the backup via the composed S4c refusal", async () => {
  const map = new Map([["a", Buffer.from("x")]]);
  await expectRefusal(
    computeDirtyBackup(fakeIo(map), { ...IDENTITY, relativePaths: ["a", "a"] }),
    "WORKSPACE_MANIFEST_INVALID",
    "workspace_backup_manifest",
  );
});

test("assertDirtyBackupComplete rejects a manifest that does not cover every intended path", () => {
  // A manifest built from ONE file cannot satisfy a two-path intent: this is the
  // vacuous/partial-backup guard the S4f review demanded. WORKSPACE_MANIFEST_MISMATCH.
  const partial = buildWorkspaceManifest({
    ...IDENTITY,
    entries: [{ path: "a", size: 1, sha256: sha(Buffer.from("x")) }],
  });
  const err = assertThrows(() => assertDirtyBackupComplete(partial, ["a", "b"]));
  assert.equal(err.code, "WORKSPACE_MANIFEST_MISMATCH");
  assert.equal(err.expectedCount, 2);
  assert.equal(err.actualCount, 1);

  // The exact-cover case passes and returns the manifest.
  assert.equal(assertDirtyBackupComplete(partial, ["a"]), partial);
});

test("assertDirtyBackupComplete rejects the right COUNT of the WRONG paths (set coverage, not cardinality)", () => {
  // Manifest covers {a,b}; intent is {a,c}: equal count (2==2) but 'b' is not
  // intended and 'c' is uncovered. A cardinality-only check would pass this.
  const manifest = buildWorkspaceManifest({
    ...IDENTITY,
    entries: [
      { path: "a", size: 1, sha256: sha(Buffer.from("x")) },
      { path: "b", size: 1, sha256: sha(Buffer.from("y")) },
    ],
  });
  const err = assertThrows(() => assertDirtyBackupComplete(manifest, ["a", "c"]));
  assert.equal(err.code, "WORKSPACE_MANIFEST_MISMATCH");
  assert.equal(err.unexpectedPath, "b");
});

test("assertDirtyBackupComplete refuses a duplicated intent rather than silently deduping", () => {
  const manifest = buildWorkspaceManifest({
    ...IDENTITY,
    entries: [{ path: "a", size: 1, sha256: sha(Buffer.from("x")) }],
  });
  const err = assertThrows(() => assertDirtyBackupComplete(manifest, ["a", "a"]));
  assert.equal(err.code, "CONFIG_INVALID");
});

test("assertDirtyBackupComplete refuses an empty intended path set", () => {
  const empty = buildWorkspaceManifest({ ...IDENTITY, entries: [] });
  const err = assertThrows(() => assertDirtyBackupComplete(empty, []));
  assert.equal(err.code, "CONFIG_INVALID");
});

test("DIRTY_BACKUP_REQUEST_KEYS is the frozen exact request contract", () => {
  assert.ok(Object.isFrozen(DIRTY_BACKUP_REQUEST_KEYS));
  assert.deepEqual([...DIRTY_BACKUP_REQUEST_KEYS].sort(), [
    "gitGenerationFingerprint",
    "hostId",
    "relativePaths",
    "rootIdentityFingerprint",
    "sourcePlatform",
    "storageIdentityFingerprint",
    "workspaceGeneration",
    "workspaceId",
  ]);
});

function assertThrows(fn) {
  try {
    fn();
    assert.fail("expected a refusal but nothing was thrown");
  } catch (error) {
    return error;
  }
}
