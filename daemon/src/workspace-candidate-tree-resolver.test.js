import test from "node:test";
import assert from "node:assert/strict";

import { createCandidateManifestResolver } from "./workspace-candidate-tree-resolver.js";

// Build a fake `readdir({ withFileTypes: true })` over an in-memory tree.
// `tree` maps an absolute dir path to an array of { name, kind } where kind is
// "file" | "dir" | "symlink" | "other".
function fakeReaddir(tree) {
  return async (dir) => {
    const entries = tree[dir];
    if (!entries) {
      const error = new Error(`ENOENT: ${dir}`);
      error.code = "ENOENT";
      throw error;
    }
    return entries.map(({ name, kind }) => ({
      name,
      isSymbolicLink: () => kind === "symlink",
      isDirectory: () => kind === "dir",
      isFile: () => kind === "file",
    }));
  };
}

test("empty candidate root yields an empty manifest", async () => {
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir({ "/root": [] }) });
  assert.deepEqual(await resolve("/root", "posix"), []);
});

test("nested regular files return sorted relative posix paths", async () => {
  const tree = {
    "/root": [
      { name: "b.txt", kind: "file" },
      { name: "sub", kind: "dir" },
      { name: "a.txt", kind: "file" },
    ],
    "/root/sub": [
      { name: "deep", kind: "dir" },
      { name: "c.txt", kind: "file" },
    ],
    "/root/sub/deep": [{ name: "d.txt", kind: "file" }],
  };
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir(tree) });
  assert.deepEqual(await resolve("/root", "posix"), [
    "a.txt",
    "b.txt",
    "sub/c.txt",
    "sub/deep/d.txt",
  ]);
});

test("windows platform joins relative paths with a backslash", async () => {
  const tree = {
    "C:\\root": [{ name: "sub", kind: "dir" }],
    "C:\\root\\sub": [{ name: "f.txt", kind: "file" }],
  };
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir(tree) });
  assert.deepEqual(await resolve("C:\\root", "windows"), ["sub\\f.txt"]);
});

test("symlink leaf and symlink directory are excluded, never descended", async () => {
  const tree = {
    "/root": [
      { name: "real.txt", kind: "file" },
      { name: "link.txt", kind: "symlink" },
      { name: "escaped", kind: "symlink" }, // symlinked dir: must NOT be descended
    ],
    // If the resolver wrongly descends the symlinked dir it would read this and
    // leak an out-of-tree file into the manifest.
    "/root/escaped": [{ name: "secret.txt", kind: "file" }],
  };
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir(tree) });
  assert.deepEqual(await resolve("/root", "posix"), ["real.txt"]);
});

test("non-file non-dir entries (sockets/fifos) are skipped", async () => {
  const tree = {
    "/root": [
      { name: "keep.txt", kind: "file" },
      { name: "sock", kind: "other" },
    ],
  };
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir(tree) });
  assert.deepEqual(await resolve("/root", "posix"), ["keep.txt"]);
});

test("strict restore mode rejects symlinks and unsupported entries", async () => {
  for (const kind of ["symlink", "other"]) {
    const resolve = createCandidateManifestResolver({
      readdir: fakeReaddir({
        "/root": [{ name: "unexpected", kind }],
      }),
      rejectUnsupported: true,
    });
    await assert.rejects(
      resolve("/root", "posix"),
      (error) => error.code === "WORKSPACE_MANIFEST_MISMATCH"
    );
  }
});

test("a dirent name that would escape the root is refused", async () => {
  const tree = { "/root": [{ name: "..", kind: "file" }] };
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir(tree) });
  await assert.rejects(resolve("/root", "posix"), (error) => {
    assert.equal(error.code, "WORKSPACE_ROOT_ESCAPE");
    return true;
  });
});

test("a dirent name carrying a foreign embedded separator is refused", async () => {
  // In posix containment mode relativeComponents splits on "/", so a name
  // carrying the foreign "\\" separator survives as one opaque segment that
  // the host fs could still resolve as a traversal - it must be refused.
  const tree = { "/root": [{ name: "a\\b", kind: "file" }] };
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir(tree) });
  await assert.rejects(resolve("/root", "posix"), (error) => {
    assert.equal(error.code, "WORKSPACE_ROOT_ESCAPE");
    return true;
  });
});

test("invalid candidatePath and platform fail closed with CONFIG_INVALID", async () => {
  const resolve = createCandidateManifestResolver({ readdir: fakeReaddir({}) });
  await assert.rejects(resolve("", "posix"), (e) => e.code === "CONFIG_INVALID");
  await assert.rejects(resolve("/root", "linux"), (e) => e.code === "CONFIG_INVALID");
});

test("non-function readdir injection fails closed", () => {
  assert.throws(() => createCandidateManifestResolver({ readdir: 123 }), (e) => e.code === "CONFIG_INVALID");
});

test("a dirent lacking type predicates fails closed (no fail-open symlink)", async () => {
  const badReaddir = async () => [{ name: "x.txt" }]; // missing isSymbolicLink/isDirectory/isFile
  const resolve = createCandidateManifestResolver({ readdir: badReaddir });
  await assert.rejects(resolve("/root", "posix"), (e) => e.code === "CONFIG_INVALID");
});
