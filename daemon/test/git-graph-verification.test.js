import assert from "node:assert/strict";
import test from "node:test";
import { createGitGraphVerifier } from "../src/git-graph-verification.js";

const REPO = process.platform === "win32" ? "C:\\ws\\proj" : "/srv/ws/proj";
const GITPATH = process.platform === "win32" ? "C:\\Program Files\\Git\\cmd\\git.exe" : "/usr/bin/git";

const OID_A = "a".repeat(40);
const OID_B = "b".repeat(40);
const OID_HEAD = "c".repeat(40);

// Identify the git subcommand from a full arg vector that may be prefixed with
// `-C <repo>` and a run of `-c key=val` hardening pairs.
function subcommandOf(args) {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === "-C" || a === "-c") {
      i += 1; // skip its value
      continue;
    }
    if (a.startsWith("-")) return a; // e.g. --version
    return a; // rev-parse / fsck / rev-list / for-each-ref
  }
  return null;
}

function hasRepo(args) {
  return args[0] === "-C";
}

function fail(exitCode, stderr, stdout = "") {
  const err = new Error("simulated non-zero exit");
  err.code = exitCode;
  err.stderr = stderr;
  err.stdout = stdout;
  return err;
}

// Configurable fake mirroring promisify(execFile) resolution/rejection shape.
function makeGit(overrides = {}) {
  const cfg = {
    version: "git version 2.55.0.windows.5",
    bare: false,
    gitDir: process.platform === "win32" ? "C:\\ws\\proj\\.git" : "/srv/ws/proj/.git",
    fsck: () => ({ stdout: "", stderr: "" }),
    revList: () => ({ stdout: `${OID_HEAD}\n${OID_A} tree\n${OID_B} blob path\n`, stderr: "" }),
    refs: () => ({ stdout: `${OID_HEAD} refs/heads/main\n${OID_A} refs/tags/v1\n`, stderr: "" }),
    head: () => ({ stdout: `${OID_HEAD}\n`, stderr: "" }),
    ...overrides,
  };
  const calls = [];
  async function execFileFn(file, args, opts) {
    calls.push({ file, args, opts });
    const sub = subcommandOf(args);
    if (sub === "--version") return { stdout: cfg.version, stderr: "" };
    if (sub === "rev-parse") {
      if (args.includes("HEAD")) {
        const r = cfg.head();
        if (r instanceof Error) throw r;
        return r;
      }
      const r = typeof cfg.revParse === "function"
        ? cfg.revParse()
        : { stdout: `${cfg.bare}\n${cfg.gitDir}\n`, stderr: "" };
      if (r instanceof Error) throw r;
      return r;
    }
    if (sub === "fsck") {
      const r = cfg.fsck();
      if (r instanceof Error) throw r;
      return r;
    }
    if (sub === "rev-list") {
      const r = cfg.revList();
      if (r instanceof Error) throw r;
      return r;
    }
    if (sub === "for-each-ref") {
      const r = cfg.refs();
      if (r instanceof Error) throw r;
      return r;
    }
    throw new Error(`unexpected subcommand: ${sub} (${args.join(" ")})`);
  }
  return { execFileFn, calls, cfg };
}

async function expectRefusal(promise, code) {
  try {
    await promise;
    assert.fail(`expected refusal ${code} but resolved`);
  } catch (error) {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.reason ?? error.message}`);
    assert.equal(error.operation, "verify_git_graph");
    assert.equal(typeof error.reason, "string");
    assert.ok(error.reason.length > 0);
    // No raw git/exec object leaked as the thrown error.
    assert.ok(error.message.startsWith("verify_git_graph:"));
    return error;
  }
}

test("verifyRepositoryGraph returns a frozen proof on a healthy repo", async () => {
  const { execFileFn } = makeGit();
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  const proof = await verifier.verifyRepositoryGraph(REPO);
  assert.equal(proof.gitVersion, "2.55.0");
  assert.equal(proof.bare, false);
  assert.equal(proof.head, OID_HEAD);
  assert.equal(proof.objectCount, 3);
  assert.deepEqual(proof.refs.map((r) => r.name), ["refs/heads/main", "refs/tags/v1"]);
  assert.equal(typeof proof.generationFingerprint, "string");
  assert.equal(proof.generationFingerprint.length, 64);
  assert.ok(Object.isFrozen(proof));
  assert.ok(Object.isFrozen(proof.refs));
  assert.throws(() => { proof.refs.push({}); });
});

test("generation fingerprint is deterministic for the same head+refs", async () => {
  const a = makeGit();
  const b = makeGit();
  const va = createGitGraphVerifier({ execFileFn: a.execFileFn, gitPath: GITPATH });
  const vb = createGitGraphVerifier({ execFileFn: b.execFileFn, gitPath: GITPATH });
  const pa = await va.verifyRepositoryGraph(REPO);
  const pb = await vb.verifyRepositoryGraph(REPO);
  assert.equal(pa.generationFingerprint, pb.generationFingerprint);
});

test("fingerprint changes when a ref oid changes", async () => {
  const base = makeGit();
  const moved = makeGit({ refs: () => ({ stdout: `${OID_B} refs/heads/main\n${OID_A} refs/tags/v1\n`, stderr: "" }) });
  const p1 = await createGitGraphVerifier({ execFileFn: base.execFileFn, gitPath: GITPATH }).verifyRepositoryGraph(REPO);
  const p2 = await createGitGraphVerifier({ execFileFn: moved.execFileFn, gitPath: GITPATH }).verifyRepositoryGraph(REPO);
  assert.notEqual(p1.generationFingerprint, p2.generationFingerprint);
});

test("construction refuses a non-absolute git path", () => {
  assert.throws(
    () => createGitGraphVerifier({ execFileFn: makeGit().execFileFn, gitPath: "git" }),
    (e) => e.code === "GIT_PREFLIGHT_FAILED",
  );
});

test("refuses a non-absolute repository path", async () => {
  const { execFileFn } = makeGit();
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(verifier.verifyRepositoryGraph("relative/repo"), "GIT_REPOSITORY_INVALID");
});

test("preflight refuses a git older than the floor", async () => {
  const { execFileFn } = makeGit({ version: "git version 2.10.0" });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_PREFLIGHT_FAILED");
});

test("preflight refuses when the git binary cannot spawn", async () => {
  const spawnErr = new Error("spawn ENOENT");
  spawnErr.code = "ENOENT";
  const { execFileFn } = makeGit({ version: spawnErr });
  // version is a value; convert to a throwing fake by wrapping:
  const throwing = {
    async execFileFn(file, args) {
      if (subcommandOf(args) === "--version") throw spawnErr;
      throw new Error("unreached");
    },
  };
  void execFileFn;
  const verifier = createGitGraphVerifier({ execFileFn: throwing.execFileFn, gitPath: GITPATH });
  await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_PREFLIGHT_FAILED");
});

test("refuses a path that is not a git repository", async () => {
  const { execFileFn } = makeGit({ revParse: () => fail(128, "fatal: not a git repository") });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_REPOSITORY_INVALID");
});

test("fsck missing-object failure maps to GIT_GRAPH_INCOMPLETE", async () => {
  const { execFileFn } = makeGit({ fsck: () => fail(1, "missing blob 1234567: broken link") });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  const err = await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_GRAPH_INCOMPLETE");
  assert.ok(String(err.stderr).includes("missing"));
});

test("fsck hash-integrity failure maps to GIT_OID_INTEGRITY_FAILED", async () => {
  const { execFileFn } = makeGit({ fsck: () => fail(1, "error: sha1 mismatch for object deadbeef") });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_OID_INTEGRITY_FAILED");
});

test("rev-list --missing=error failure maps to GIT_GRAPH_INCOMPLETE", async () => {
  const { execFileFn } = makeGit({ revList: () => fail(128, "fatal: missing object") });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_GRAPH_INCOMPLETE");
});

test("a killed (timed-out) subprocess maps to GIT_VERIFICATION_TIMEOUT", async () => {
  const killed = new Error("timeout");
  killed.killed = true;
  killed.signal = "SIGTERM";
  const { execFileFn } = makeGit({ fsck: () => killed });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH, timeoutMs: 5 });
  await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_VERIFICATION_TIMEOUT");
});

test("a non-OID ref target is refused as GIT_REPOSITORY_INVALID", async () => {
  const { execFileFn } = makeGit({ refs: () => ({ stdout: "notanoid refs/heads/main\n", stderr: "" }) });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(verifier.verifyRepositoryGraph(REPO), "GIT_REPOSITORY_INVALID");
});

test("an unborn HEAD yields head=null and still succeeds", async () => {
  const { execFileFn } = makeGit({
    head: () => fail(1, "fatal: needed a single revision"),
    refs: () => ({ stdout: "", stderr: "" }),
    revList: () => ({ stdout: "", stderr: "" }),
  });
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  const proof = await verifier.verifyRepositoryGraph(REPO);
  assert.equal(proof.head, null);
  assert.equal(proof.objectCount, 0);
  assert.deepEqual(proof.refs, []);
});

test("expected headOid mismatch is refused as GIT_GENERATION_MISMATCH", async () => {
  const { execFileFn } = makeGit();
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(
    verifier.verifyRepositoryGraph(REPO, { headOid: OID_A }),
    "GIT_GENERATION_MISMATCH",
  );
});

test("expected generationFingerprint mismatch is refused", async () => {
  const { execFileFn } = makeGit();
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(
    verifier.verifyRepositoryGraph(REPO, { generationFingerprint: "0".repeat(64) }),
    "GIT_GENERATION_MISMATCH",
  );
});

test("expected ref-set mismatch is refused", async () => {
  const { execFileFn } = makeGit();
  const verifier = createGitGraphVerifier({ execFileFn, gitPath: GITPATH });
  await expectRefusal(
    verifier.verifyRepositoryGraph(REPO, { refs: [{ name: "refs/heads/main", oid: OID_A }] }),
    "GIT_GENERATION_MISMATCH",
  );
});

test("a matching expected generation passes", async () => {
  const probe = makeGit();
  const proof = await createGitGraphVerifier({ execFileFn: probe.execFileFn, gitPath: GITPATH })
    .verifyRepositoryGraph(REPO);
  const verify = makeGit();
  const rechecked = await createGitGraphVerifier({ execFileFn: verify.execFileFn, gitPath: GITPATH })
    .verifyRepositoryGraph(REPO, {
      headOid: proof.head,
      generationFingerprint: proof.generationFingerprint,
      refs: proof.refs.map((r) => ({ ...r })),
    });
  assert.equal(rechecked.generationFingerprint, proof.generationFingerprint);
});

test("every invocation is env-scrubbed and hardened", async () => {
  const probe = makeGit();
  const verifier = createGitGraphVerifier({ execFileFn: probe.execFileFn, gitPath: GITPATH });
  await verifier.verifyRepositoryGraph(REPO);
  assert.ok(probe.calls.length >= 5);
  for (const call of probe.calls) {
    assert.equal(call.file, GITPATH);
    assert.equal(call.opts.windowsHide, true);
    assert.equal(call.opts.env.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(call.opts.env.GIT_TERMINAL_PROMPT, "0");
    assert.equal(call.opts.env.GIT_ALLOW_PROTOCOL, "");
    // The caller's ambient PATH is never inherited wholesale.
    assert.ok(!("USERPROFILE" in call.opts.env));
    // Hardening config is present on every call.
    assert.ok(call.args.includes("core.protectNTFS=true"));
    assert.ok(call.args.includes("core.hooksPath="));
  }
});
