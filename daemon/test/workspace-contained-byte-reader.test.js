import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { createContainedByteReader } from "../src/workspace-contained-byte-reader.js";
import { relativeComponents } from "../src/workspace-containment.js";

async function withTempRoot(fn) {
  const root = await mkdtemp(path.join(tmpdir(), "gjc-byte-reader-"));
  try {
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("reuse proof: relativeComponents is importable from workspace-containment.js", () => {
  assert.equal(typeof relativeComponents, "function");
  assert.deepEqual(relativeComponents("/root", "/root/a/b", "posix"), ["a", "b"]);
});

test("happy path: readBytes returns the exact bytes written at a nested relative path", async () => {
  await withTempRoot(async (root) => {
    await mkdir(path.join(root, "a"), { recursive: true });
    const expected = Buffer.from("hello contained reader", "utf8");
    await writeFile(path.join(root, "a", "b.txt"), expected);

    const reader = createContainedByteReader({ root, sourcePlatform: "posix" });
    const bytes = await reader.readBytes("a/b.txt");

    assert.ok(bytes instanceof Uint8Array);
    assert.deepEqual(Buffer.from(bytes), expected);
  });
});

test("windows-style separators: a forward-slash relPath is tolerated in windows mode", async () => {
  await withTempRoot(async (root) => {
    await mkdir(path.join(root, "a"), { recursive: true });
    const expected = Buffer.from("windows mode forward slash", "utf8");
    await writeFile(path.join(root, "a", "b.txt"), expected);

    const reader = createContainedByteReader({ root, sourcePlatform: "windows" });
    const bytes = await reader.readBytes("a/b.txt");

    assert.deepEqual(Buffer.from(bytes), expected);
  });
});

test("containment refusal: absolute path outside root is refused", async () => {
  await withTempRoot(async (root) => {
    const reader = createContainedByteReader({ root, sourcePlatform: "posix" });
    await assert.rejects(
      reader.readBytes("/etc/passwd"),
      (error) => error.code === "WORKSPACE_ROOT_ESCAPE"
    );
  });
});

test("containment refusal: '..' traversal escape is refused", async () => {
  await withTempRoot(async (root) => {
    const reader = createContainedByteReader({ root, sourcePlatform: "posix" });
    await assert.rejects(
      reader.readBytes("../secret"),
      (error) => error.code === "WORKSPACE_ROOT_ESCAPE"
    );
  });
});

test("containment refusal: a lone '.' segment is refused", async () => {
  await withTempRoot(async (root) => {
    const reader = createContainedByteReader({ root, sourcePlatform: "posix" });
    await assert.rejects(
      reader.readBytes("a/./b.txt"),
      (error) => error.code === "WORKSPACE_ROOT_ESCAPE"
    );
  });
});

test("containment refusal: a NUL byte in relPath is refused", async () => {
  await withTempRoot(async (root) => {
    const reader = createContainedByteReader({ root, sourcePlatform: "posix" });
    await assert.rejects(
      reader.readBytes("a\0b.txt"),
      (error) => error.code === "WORKSPACE_ROOT_ESCAPE"
    );
  });
});

test("leaf reparse refusal: a symlink leaf is refused", async (t) => {
  await withTempRoot(async (root) => {
    await writeFile(path.join(root, "real.txt"), "real bytes");
    try {
      await symlink(path.join(root, "real.txt"), path.join(root, "link.txt"));
    } catch (error) {
      if (process.platform === "win32" && (error.code === "EPERM" || error.code === "EACCES")) {
        t.skip("symlink creation requires elevated privilege on this Windows host");
        return;
      }
      throw error;
    }

    const reader = createContainedByteReader({ root, sourcePlatform: "posix" });
    await assert.rejects(
      reader.readBytes("link.txt"),
      (error) => error.code === "WORKSPACE_ROOT_ESCAPE"
    );
  });
});

test("ENOENT propagates for a missing file rather than resolving null", async () => {
  await withTempRoot(async (root) => {
    const reader = createContainedByteReader({ root, sourcePlatform: "posix" });
    await assert.rejects(
      reader.readBytes("missing.txt"),
      (error) => error.code === "ENOENT"
    );
  });
});
