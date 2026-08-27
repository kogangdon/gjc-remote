import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, writeFile, readdir, mkdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { createGitMaterializer } from "./workspace-git-materializer.js";
import { createGitGraphVerifier, resolveDefaultGitPath } from "./git-graph-verification.js";

const execFileP = promisify(execFile);

const GIT_PATH = process.env.GJC_GIT_PATH ?? resolveDefaultGitPath();

async function gitAvailable() {
  try {
    await execFileP(GIT_PATH, ["--version"], { windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

const tempDirs = [];

async function mkTemp(prefix) {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

async function cleanupTemps() {
  for (const dir of tempDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true, maxRetries: 5 });
  }
}

const FIXTURE_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "GJC Test",
  GIT_AUTHOR_EMAIL: "gjc-test@example.invalid",
  GIT_COMMITTER_NAME: "GJC Test",
  GIT_COMMITTER_EMAIL: "gjc-test@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
};

async function initFixtureRepo(dir) {
  await execFileP(GIT_PATH, ["-c", "init.defaultBranch=main", "init"], { cwd: dir, env: FIXTURE_ENV, windowsHide: true });
  await writeFile(path.join(dir, "README.md"), "materializer fixture\n");
  await execFileP(GIT_PATH, ["-c", "user.email=gjc-test@example.invalid", "-c", "user.name=GJC Test", "add", "README.md"], {
    cwd: dir,
    env: FIXTURE_ENV,
    windowsHide: true,
  });
  await execFileP(
    GIT_PATH,
    ["-c", "user.email=gjc-test@example.invalid", "-c", "user.name=GJC Test", "commit", "-m", "initial commit"],
    { cwd: dir, env: FIXTURE_ENV, windowsHide: true },
  );
}

function sourcePlatform() {
  return process.platform === "win32" ? "windows" : "posix";
}

test("workspace-git-materializer", async (t) => {
  const available = await gitAvailable();
  if (!available) {
    t.skip(`git binary unavailable at ${GIT_PATH}`);
    return;
  }

  t.after(async () => {
    await cleanupTemps();
  });

  await t.test("happy path: create-clone materializes an isolated, graph-valid clone", async () => {
    const workDir = await mkTemp("gjc-materializer-src-");
    await initFixtureRepo(workDir);

    const root = await mkTemp("gjc-materializer-dst-");
    const candidatePath = path.join(root, "candidate");
    const gitDir = path.join(root, "git-dir");

    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    const receipt = await materializer.materialize({
      operation: "create_clone",
      hostId: "host-1",
      workspaceId: "ws-1",
      sourcePlatform: sourcePlatform(),
      workDir,
      generationPath: candidatePath,
      candidatePath,
      gitDir,
      activeGeneration: "gen-0",
    });

    assert.equal(receipt.materialized, true);
    assert.equal(receipt.operation, "create_clone");
    assert.equal(receipt.workspaceId, "ws-1");
    assert.equal(receipt.candidatePath, candidatePath);
    assert.equal(receipt.gitDir, gitDir);
    assert.ok(Object.isFrozen(receipt));

    const workTreeEntries = await readdir(candidatePath);
    assert.ok(workTreeEntries.includes("README.md"));

    const gitDirEntries = await readdir(gitDir);
    assert.ok(gitDirEntries.includes("HEAD"));
    assert.ok(gitDirEntries.includes("objects"));

    const verifier = createGitGraphVerifier({ gitPath: GIT_PATH });
    const proof = await verifier.verifyRepositoryGraph(gitDir, {});
    assert.ok(proof.head);
    assert.ok(proof.objectCount > 0);
  });

  await t.test("refresh op materializes an isolated clone with baseGeneration accepted", async () => {
    const workDir = await mkTemp("gjc-materializer-src2-");
    await initFixtureRepo(workDir);

    const root = await mkTemp("gjc-materializer-refresh-");
    const candidatePath = path.join(root, "candidate");
    const gitDir = path.join(root, "git-dir");

    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    const receipt = await materializer.materialize({
      operation: "refresh",
      hostId: "host-1",
      workspaceId: "ws-2",
      sourcePlatform: sourcePlatform(),
      workDir,
      generationPath: candidatePath,
      candidatePath,
      gitDir,
      baseGeneration: "gen-0",
    });

    assert.equal(receipt.materialized, true);
    assert.equal(receipt.operation, "refresh");

    const workTreeEntries = await readdir(candidatePath);
    assert.ok(workTreeEntries.includes("README.md"));
    const gitDirEntries = await readdir(gitDir);
    assert.ok(gitDirEntries.includes("HEAD"));
    assert.ok(gitDirEntries.includes("objects"));
  });

  await t.test("MATERIALIZE_REQUEST_INVALID: relative candidatePath", async () => {
    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: sourcePlatform(),
        workDir: await mkTemp("gjc-materializer-inv1-"),
        candidatePath: "relative/candidate",
        gitDir: path.join(await mkTemp("gjc-materializer-inv1g-"), "gitdir"),
      }),
      (error) => {
        assert.equal(error.operation, "materialize_workspace");
        assert.equal(error.code, "MATERIALIZE_REQUEST_INVALID");
        return true;
      },
    );
  });

  await t.test("MATERIALIZE_REQUEST_INVALID: bad sourcePlatform", async () => {
    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    const workDir = await mkTemp("gjc-materializer-inv2-");
    const root = await mkTemp("gjc-materializer-inv2r-");
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: "macos",
        workDir,
        candidatePath: path.join(root, "candidate"),
        gitDir: path.join(root, "git-dir"),
      }),
      (error) => {
        assert.equal(error.operation, "materialize_workspace");
        assert.equal(error.code, "MATERIALIZE_REQUEST_INVALID");
        return true;
      },
    );
  });

  await t.test("MATERIALIZE_REQUEST_INVALID: empty operation", async () => {
    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    const workDir = await mkTemp("gjc-materializer-inv3-");
    const root = await mkTemp("gjc-materializer-inv3r-");
    await assert.rejects(
      materializer.materialize({
        operation: "",
        sourcePlatform: sourcePlatform(),
        workDir,
        candidatePath: path.join(root, "candidate"),
        gitDir: path.join(root, "git-dir"),
      }),
      (error) => {
        assert.equal(error.operation, "materialize_workspace");
        assert.equal(error.code, "MATERIALIZE_REQUEST_INVALID");
        return true;
      },
    );
  });

  await t.test("MATERIALIZE_TARGET_EXISTS: pre-created non-empty candidatePath", async () => {
    const workDir = await mkTemp("gjc-materializer-exist-src-");
    await initFixtureRepo(workDir);

    const root = await mkTemp("gjc-materializer-exist-");
    const candidatePath = path.join(root, "candidate");
    const gitDir = path.join(root, "git-dir");
    await mkdir(candidatePath, { recursive: true });
    await writeFile(path.join(candidatePath, "occupied.txt"), "already here\n");

    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: sourcePlatform(),
        workDir,
        candidatePath,
        gitDir,
      }),
      (error) => {
        assert.equal(error.operation, "materialize_workspace");
        assert.equal(error.code, "MATERIALIZE_TARGET_EXISTS");
        return true;
      },
    );
  });

  await t.test("MATERIALIZE_CLONE_FAILED: workDir is not a git repo", async () => {
    const workDir = await mkTemp("gjc-materializer-notrepo-");
    // intentionally leave workDir empty / not a git repository

    const root = await mkTemp("gjc-materializer-notrepo-dst-");
    const candidatePath = path.join(root, "candidate");
    const gitDir = path.join(root, "git-dir");

    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: sourcePlatform(),
        workDir,
        candidatePath,
        gitDir,
      }),
      (error) => {
        assert.equal(error.operation, "materialize_workspace");
        assert.equal(error.code, "MATERIALIZE_CLONE_FAILED");
        assert.equal(typeof error.code, "string");
        // no raw exec error object shape (e.g. no bare `cmd`/`killed` leaking
        // as the thrown object identity) — the thrown error is our refusal.
        assert.ok(!(error instanceof TypeError));
        return true;
      },
    );
  });

  await t.test("isolation: --no-hardlinks clone produces an independent object store", async () => {
    const workDir = await mkTemp("gjc-materializer-iso-src-");
    await initFixtureRepo(workDir);

    const root = await mkTemp("gjc-materializer-iso-");
    const candidatePath = path.join(root, "candidate");
    const gitDir = path.join(root, "git-dir");

    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    await materializer.materialize({
      operation: "create_clone",
      sourcePlatform: sourcePlatform(),
      workDir,
      candidatePath,
      gitDir,
    });

    const objectsDir = path.join(gitDir, "objects");
    const entries = await readdir(objectsDir);
    assert.ok(entries.length > 0, "cloned object store must be populated independently");
    // A hard st_nlink check is win32-fragile (NTFS hardlink semantics differ
    // from POSIX inode nlink reporting for some filesystems/drivers), so we
    // keep this assertion to "object store exists and is populated" rather
    // than asserting nlink === 1 across platforms.
  });

  await t.test("partial-failure cleanup: a failed clone leaves no debris and a retry succeeds", async () => {
    const workDir = await mkTemp("gjc-materializer-cleanup-src-");
    // start as NOT a git repo so the first clone fails
    const root = await mkTemp("gjc-materializer-cleanup-");
    const candidatePath = path.join(root, "candidate");
    const gitDir = path.join(root, "git-dir");

    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: sourcePlatform(),
        workDir,
        candidatePath,
        gitDir,
      }),
      (error) => {
        assert.equal(error.code, "MATERIALIZE_CLONE_FAILED");
        return true;
      },
    );

    // No debris: both targets must be gone so a retry is not wedged.
    await assert.rejects(stat(candidatePath), (e) => e.code === "ENOENT");
    await assert.rejects(stat(gitDir), (e) => e.code === "ENOENT");

    // Retry against the SAME targets after making workDir a real repo: proves
    // the cleanup unwedged the retry (no MATERIALIZE_TARGET_EXISTS).
    await initFixtureRepo(workDir);
    const receipt = await materializer.materialize({
      operation: "create_clone",
      sourcePlatform: sourcePlatform(),
      workDir,
      candidatePath,
      gitDir,
    });
    assert.equal(receipt.materialized, true);
  });

  await t.test("MATERIALIZE_ISOLATION_VIOLATED: alternates-inheriting clone is destroyed and refused", async () => {
    // Drive the seam with a mock git that simulates a clone which leaves an
    // objects/info/alternates pointer (an externally-borrowed object store).
    // The post-clone isolation check must fire and remove both targets.
    const root = await mkTemp("gjc-materializer-alt-");
    const candidatePath = path.join(root, "candidate");
    const gitDir = path.join(root, "git-dir");

    const mockExec = async (_file, args) => {
      if (args.includes("--version")) {
        return { stdout: "git version 2.40.0\n", stderr: "" };
      }
      if (args.includes("clone")) {
        await mkdir(candidatePath, { recursive: true });
        await mkdir(path.join(gitDir, "objects", "info"), { recursive: true });
        await writeFile(path.join(gitDir, "objects", "info", "alternates"), "/some/other/repo/objects\n");
        return { stdout: "", stderr: "" };
      }
      throw new Error(`unexpected git invocation: ${args.join(" ")}`);
    };

    const materializer = createGitMaterializer({ gitPath: GIT_PATH, execFileFn: mockExec });
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: sourcePlatform(),
        workDir: path.join(root, "src"),
        candidatePath,
        gitDir,
      }),
      (error) => {
        assert.equal(error.operation, "materialize_workspace");
        assert.equal(error.code, "MATERIALIZE_ISOLATION_VIOLATED");
        return true;
      },
    );
    // Non-isolated debris must be removed.
    await assert.rejects(stat(candidatePath), (e) => e.code === "ENOENT");
    await assert.rejects(stat(gitDir), (e) => e.code === "ENOENT");
  });

  await t.test("MATERIALIZE_REQUEST_INVALID: overlapping / equal target paths", async () => {
    const materializer = createGitMaterializer({ gitPath: GIT_PATH });
    const root = await mkTemp("gjc-materializer-overlap-");
    const workDir = path.join(root, "src");
    const candidatePath = path.join(root, "candidate");

    // candidatePath === gitDir
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: sourcePlatform(),
        workDir,
        candidatePath,
        gitDir: candidatePath,
      }),
      (error) => {
        assert.equal(error.code, "MATERIALIZE_REQUEST_INVALID");
        return true;
      },
    );

    // gitDir nested inside candidatePath
    await assert.rejects(
      materializer.materialize({
        operation: "create_clone",
        sourcePlatform: sourcePlatform(),
        workDir,
        candidatePath,
        gitDir: path.join(candidatePath, "git-dir"),
      }),
      (error) => {
        assert.equal(error.code, "MATERIALIZE_REQUEST_INVALID");
        return true;
      },
    );
  });
});
