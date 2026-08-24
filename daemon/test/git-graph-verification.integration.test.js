import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, rmSync, writeFileSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGitGraphVerifier } from "../src/git-graph-verification.js";

const execFileAsync = promisify(execFile);

function resolveGitPath() {
  const candidates = [
    process.env.GJC_GIT_PATH,
    process.platform === "win32" ? "C:\\Program Files\\Git\\cmd\\git.exe" : null,
    "/usr/bin/git",
    "/usr/local/bin/git",
    "/opt/homebrew/bin/git",
  ].filter((c) => typeof c === "string" && c.length > 0);
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

const GIT = resolveGitPath();
const SKIP = GIT ? false : "no git binary available on this host";

const AUTHOR_ENV = {
  GIT_AUTHOR_NAME: "S4b Test",
  GIT_AUTHOR_EMAIL: "s4b@example.invalid",
  GIT_COMMITTER_NAME: "S4b Test",
  GIT_COMMITTER_EMAIL: "s4b@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  PATH: process.env.PATH,
};

async function git(repo, args) {
  return execFileAsync(GIT, ["-C", repo, "-c", "commit.gpgsign=false", "-c", "user.name=S4b", "-c", "user.email=s4b@example.invalid", ...args], {
    env: AUTHOR_ENV,
    encoding: "utf8",
    windowsHide: true,
  });
}

async function makeHealthyRepo() {
  const dir = await mkdtemp(join(tmpdir(), "s4b-git-"));
  await git(dir, ["init", "-q", "-b", "main"]);
  writeFileSync(join(dir, "a.txt"), "hello\n");
  await git(dir, ["add", "a.txt"]);
  await git(dir, ["commit", "-q", "-m", "first"]);
  writeFileSync(join(dir, "b.txt"), "world\n");
  await git(dir, ["add", "b.txt"]);
  await git(dir, ["commit", "-q", "-m", "second"]);
  await git(dir, ["tag", "v1"]);
  return dir;
}

function looseObjectFiles(repo) {
  const objectsRoot = join(repo, ".git", "objects");
  const files = [];
  for (const shard of readdirSync(objectsRoot)) {
    if (shard.length !== 2) continue; // skip pack/info
    const shardDir = join(objectsRoot, shard);
    for (const name of readdirSync(shardDir)) {
      const full = join(shardDir, name);
      if (statSync(full).isFile()) files.push(full);
    }
  }
  return files;
}

test("verifies a real healthy repository and yields a stable generation", { skip: SKIP }, async () => {
  const repo = await makeHealthyRepo();
  try {
    const verifier = createGitGraphVerifier({ gitPath: GIT });
    const proof = await verifier.verifyRepositoryGraph(repo);
    assert.equal(proof.bare, false);
    assert.match(proof.head, /^[0-9a-f]{40}$|^[0-9a-f]{64}$/);
    assert.ok(proof.objectCount >= 6, `expected >=6 objects, got ${proof.objectCount}`);
    const names = proof.refs.map((r) => r.name);
    assert.ok(names.includes("refs/heads/main"));
    assert.ok(names.includes("refs/tags/v1"));
    assert.equal(proof.generationFingerprint.length, 64);

    // Re-verify with the observed generation as the expectation → must pass.
    const rechecked = await verifier.verifyRepositoryGraph(repo, {
      headOid: proof.head,
      generationFingerprint: proof.generationFingerprint,
      refs: proof.refs.map((r) => ({ ...r })),
    });
    assert.equal(rechecked.generationFingerprint, proof.generationFingerprint);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("refuses when the expected generation does not match", { skip: SKIP }, async () => {
  const repo = await makeHealthyRepo();
  try {
    const verifier = createGitGraphVerifier({ gitPath: GIT });
    await assert.rejects(
      verifier.verifyRepositoryGraph(repo, { headOid: "0".repeat(40) }),
      (e) => e.code === "GIT_GENERATION_MISMATCH" && e.operation === "verify_git_graph",
    );
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("refuses a directory that is not a git repository", { skip: SKIP }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "s4b-nongit-"));
  try {
    const verifier = createGitGraphVerifier({ gitPath: GIT });
    await assert.rejects(
      verifier.verifyRepositoryGraph(dir),
      (e) => e.code === "GIT_REPOSITORY_INVALID" && e.operation === "verify_git_graph",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("refuses a repository with a missing reachable object", { skip: SKIP }, async () => {
  const repo = await makeHealthyRepo();
  try {
    // Deleting a loose object breaks connectivity (rev-list --missing=error /
    // fsck both flag it). Repacking is avoided so objects stay loose.
    const loose = looseObjectFiles(repo);
    assert.ok(loose.length > 0, "expected loose objects to delete");
    unlinkSync(loose[0]);
    const verifier = createGitGraphVerifier({ gitPath: GIT });
    const err = await verifier.verifyRepositoryGraph(repo).then(
      () => { throw new Error("expected refusal"); },
      (e) => e,
    );
    assert.equal(err.operation, "verify_git_graph");
    assert.ok(
      err.code === "GIT_GRAPH_INCOMPLETE" || err.code === "GIT_OID_INTEGRITY_FAILED",
      `unexpected code ${err.code}`,
    );
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("refuses a repository with a corrupted loose object", { skip: SKIP }, async () => {
  const repo = await makeHealthyRepo();
  try {
    const loose = looseObjectFiles(repo);
    assert.ok(loose.length > 0);
    unlinkSync(loose[0]);
    writeFileSync(loose[0], Buffer.from("this is not a valid zlib git object"));
    const verifier = createGitGraphVerifier({ gitPath: GIT });
    const err = await verifier.verifyRepositoryGraph(repo).then(
      () => { throw new Error("expected refusal"); },
      (e) => e,
    );
    assert.equal(err.operation, "verify_git_graph");
    assert.ok(
      err.code === "GIT_GRAPH_INCOMPLETE" || err.code === "GIT_OID_INTEGRITY_FAILED",
      `unexpected code ${err.code}`,
    );
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("preflight succeeds against the real git binary", { skip: SKIP }, async () => {
  const verifier = createGitGraphVerifier({ gitPath: GIT });
  const version = await verifier.preflight();
  assert.match(version, /^\d+\.\d+/);
});
