import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildWorkspaceManifest,
  computeManifestEntries,
  verifyManifestAgainst,
  workspaceManifestBytes,
  parseWorkspaceManifest,
} from "../src/workspace-backup-manifest.js";

const BASE = {
  hostId: "host-int",
  workspaceId: "workspace-int",
  workspaceGeneration: 1,
  sourcePlatform: process.platform === "win32" ? "windows-drive" : "posix",
  rootIdentityFingerprint: "1".repeat(64),
  storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64),
};

// A real filesystem-backed reader: joins the workspace-relative POSIX path onto
// the staging root using the host separator. This mirrors how the daemon will
// wire the native no-follow reader at S4f/S4g (minus reparse verification,
// which is out of this pure module's scope).
function fsIo(root) {
  return {
    readBytes: async (relPath) => readFile(join(root, ...relPath.split("/"))),
  };
}

function stage(files) {
  const root = mkdtempSync(join(tmpdir(), "s4c-manifest-"));
  for (const [rel, content] of Object.entries(files)) {
    const parts = rel.split("/");
    if (parts.length > 1) mkdirSync(join(root, ...parts.slice(0, -1)), { recursive: true });
    writeFileSync(join(root, ...parts), content);
  }
  return root;
}

test("builds and verifies a manifest against a real staged directory", async () => {
  const root = stage({
    "README.md": "# hi\n",
    "src/a.js": "export const a = 1;\n",
    "src/nested/b.js": "export const b = 2;\n",
  });
  try {
    const io = fsIo(root);
    const entries = await computeManifestEntries(io, ["README.md", "src/a.js", "src/nested/b.js"]);
    const manifest = buildWorkspaceManifest({ ...BASE, entries });
    assert.equal(manifest.entryCount, 3);
    // Serialize -> parse -> verify against the same real content.
    const parsed = parseWorkspaceManifest(workspaceManifestBytes(manifest));
    const result = await verifyManifestAgainst(io, parsed);
    assert.deepEqual(result, { ok: true, verifiedCount: 3 });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("verification fails after a real file is modified on disk", async () => {
  const root = stage({ "data.bin": Buffer.from([1, 2, 3, 4]) });
  try {
    const io = fsIo(root);
    const entries = await computeManifestEntries(io, ["data.bin"]);
    const manifest = buildWorkspaceManifest({ ...BASE, entries });
    writeFileSync(join(root, "data.bin"), Buffer.from([1, 2, 3, 9]));
    await assert.rejects(
      verifyManifestAgainst(io, manifest),
      (e) => e.code === "WORKSPACE_MANIFEST_MISMATCH" && e.path === "data.bin" && e.operation === "workspace_backup_manifest",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("verification fails after a real file is deleted", async () => {
  const root = stage({ "keep.txt": "keep\n", "gone.txt": "gone\n" });
  try {
    const io = fsIo(root);
    const entries = await computeManifestEntries(io, ["keep.txt", "gone.txt"]);
    const manifest = buildWorkspaceManifest({ ...BASE, entries });
    rmSync(join(root, "gone.txt"));
    await assert.rejects(
      verifyManifestAgainst(io, manifest),
      (e) => e.code === "WORKSPACE_MANIFEST_MISMATCH" && e.path === "gone.txt",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
