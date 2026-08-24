// Git graph / ref / OID all-reachable verification for the native workspace
// data plane (#53 Phase 2, slice S4b).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations):
// "Full connectivity/ref/OID/all-reachable verification is required at every
//  create/clone and refresh generation publication."
//
// This module is a PURE, dependency-injected primitive. It does NOT wire into
// the daemon and does NOT flip the native-workspace-serving gate — that gate
// stays disabled (daemon.js NATIVE_WORKSPACE_SERVING_ENABLED = false). The
// create/clone (S4f) and refresh (S4g) wiring slices consume this verifier
// after S4a containment has already proven the repository path is a
// reparse-free, contained directory.
//
// Design decisions (recorded in the ultragoal ledger for slice S4):
//   * git is invoked as the SYSTEM git binary via child_process.execFile,
//     absolute-path pinned, version-preflighted fail-closed, and env-scrubbed
//     (GIT_CONFIG_NOSYSTEM + global/system config redirected to the null
//     device, HOME redirected, GIT_* cleared, hooks and credential helpers
//     disabled, core.symlinks=false, core.protectNTFS=true). isomorphic-git was
//     rejected: fsck-grade connectivity + OID hash integrity is exactly what a
//     mature git delivers and is expensive to reproduce correctly.
//   * All subcommands are strictly READ-ONLY and strictly LOCAL (fsck,
//     rev-list, for-each-ref, rev-parse) — none touch the network.
//   * Concurrency: each verification runs its subcommands SEQUENTIALLY, so one
//     verification holds at most one live subprocess. The host-wide git
//     subprocess cap (#33, cap 4) is enforced by the daemon at the S4f/S4g
//     wiring seam, not here.
//
// Every refusal is a deterministic, module-owned structured error
// { code, operation: "verify_git_graph", reason } — a raw git/exec error object
// is never allowed to escape.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

// git accepts the platform null device as a config path and reads it as empty;
// os.devNull (\\.\nul on Windows) is NOT accepted by git ("Invalid argument"),
// so we use the config-safe spelling explicitly.
const NULL_CONFIG = process.platform === "win32" ? "NUL" : "/dev/null";

const OPERATION = "verify_git_graph";

// Minimum git that supports the flags relied on here (--missing=error on
// rev-list is 2.16+, --no-dangling on fsck is 1.7+; we floor conservatively at
// 2.20 which every currently supported git satisfies).
const MIN_GIT_MAJOR = 2;
const MIN_GIT_MINOR = 20;

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_BUFFER = 64 * 1024 * 1024; // 64 MiB of object-name output

const OID_RE = /^[0-9a-f]{40}$|^[0-9a-f]{64}$/; // sha1 or sha256 object names

function isRefusal(error) {
  return error != null && error.operation === OPERATION && typeof error.code === "string";
}

function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (key !== "code" && key !== "operation" && key !== "reason" && key !== "message") {
        error[key] = value;
      }
    }
  }
  throw error;
}

// Build the scrubbed environment once. Redirecting global/system config to the
// OS null device is the modern robust way to guarantee no ambient git config
// (aliases, hooksPath, includeIf, credential helpers) influences verification.
function buildScrubbedEnv(gitPath) {
  // GIT_CONFIG_GLOBAL overrides ~/.gitconfig AND ~/.config/git/config (and thus
  // XDG), so pointing it plus GIT_CONFIG_SYSTEM at the null device, together
  // with GIT_CONFIG_NOSYSTEM=1, fully neutralises ambient config without any
  // HOME redirect (an invalid HOME breaks git on some platforms).
  const env = {
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: NULL_CONFIG,
    GIT_CONFIG_SYSTEM: NULL_CONFIG,
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PROTOCOL_FROM_USER: "0",
    GIT_ALLOW_PROTOCOL: "",
    LANG: "C",
    LC_ALL: "C",
  };
  // git.exe on Windows is self-locating, but keeping the git install directory
  // on PATH lets it find its bundled helpers deterministically. We deliberately
  // do NOT inherit the caller's PATH.
  const sep = process.platform === "win32" ? ";" : ":";
  const gitDir = gitPath.replace(/[\\/][^\\/]*$/, "");
  env.PATH = gitDir;
  env.Path = gitDir; // Windows env var casing safety
  void sep;
  return env;
}

// Config overrides applied to every invocation. These harden the process
// against hostile repository config and reparse tricks.
const HARDENING_CONFIG = [
  "-c", "core.hooksPath=",
  "-c", "core.fsmonitor=false",
  "-c", "core.symlinks=false",
  "-c", "core.protectNTFS=true",
  "-c", "core.protectHFS=true",
  "-c", "credential.helper=",
  "-c", "gc.auto=0",
  "-c", "advice.detachedHead=false",
];

function resolveDefaultGitPath() {
  const fromEnv = process.env.GJC_GIT_PATH;
  if (fromEnv && fromEnv.trim().length > 0) return fromEnv.trim();
  if (process.platform === "win32") return "C:\\Program Files\\Git\\cmd\\git.exe";
  return "/usr/bin/git";
}

/**
 * @param {object} [deps]
 * @param {(file:string,args:string[],opts:object)=>Promise<{stdout:string,stderr:string}>} [deps.execFileFn]
 * @param {string} [deps.gitPath] absolute path to the git binary
 * @param {number} [deps.timeoutMs]
 * @param {number} [deps.maxBuffer]
 */
export function createGitGraphVerifier(deps = {}) {
  const execFileFn = deps.execFileFn ?? promisify(execFile);
  const gitPath = deps.gitPath ?? resolveDefaultGitPath();
  const timeoutMs = Number.isInteger(deps.timeoutMs) && deps.timeoutMs > 0 ? deps.timeoutMs : DEFAULT_TIMEOUT_MS;
  const maxBuffer = Number.isInteger(deps.maxBuffer) && deps.maxBuffer > 0 ? deps.maxBuffer : DEFAULT_MAX_BUFFER;

  if (typeof gitPath !== "string" || gitPath.length === 0 || !isAbsolute(gitPath)) {
    // Fail closed at construction: an unpinned/relative git path is a PATH
    // hijack vector and is never acceptable for a security primitive.
    refuse("GIT_PREFLIGHT_FAILED", "git binary path must be a non-empty absolute path");
  }

  const scrubbedEnv = buildScrubbedEnv(gitPath);
  let preflightVersion = null;

  async function run(repoPath, args) {
    const fullArgs = repoPath === null
      ? [...HARDENING_CONFIG, ...args]
      : ["-C", repoPath, ...HARDENING_CONFIG, ...args];
    try {
      const { stdout, stderr } = await execFileFn(gitPath, fullArgs, {
        env: scrubbedEnv,
        timeout: timeoutMs,
        maxBuffer,
        windowsHide: true,
        encoding: "utf8",
      });
      return { stdout: String(stdout ?? ""), stderr: String(stderr ?? ""), exitCode: 0 };
    } catch (error) {
      if (isRefusal(error)) throw error;
      if (error && (error.killed === true || error.signal === "SIGTERM")) {
        refuse("GIT_VERIFICATION_TIMEOUT", `git ${args[0]} exceeded ${timeoutMs}ms`, {
          stderr: truncate(error.stderr),
        });
      }
      // Non-zero exit: surface exit code + captured streams, but let callers
      // classify (fsck failure vs invalid repo) via the returned shape.
      const err = new Error("git non-zero exit");
      err.exitCode = typeof error?.code === "number" ? error.code : null;
      err.stdout = String(error?.stdout ?? "");
      err.stderr = String(error?.stderr ?? "");
      err.spawnFailed = typeof error?.code === "string"; // e.g. ENOENT/EACCES
      err.spawnCode = err.spawnFailed ? error.code : null;
      throw err;
    }
  }

  async function preflight() {
    if (preflightVersion !== null) return preflightVersion;
    let out;
    try {
      out = await run(null, ["--version"]);
    } catch (error) {
      if (isRefusal(error)) throw error;
      if (error?.spawnFailed) {
        refuse("GIT_PREFLIGHT_FAILED", `git binary is not executable: ${error.spawnCode}`);
      }
      refuse("GIT_PREFLIGHT_FAILED", "git --version failed", { stderr: truncate(error?.stderr) });
    }
    const match = /git version (\d+)\.(\d+)(?:\.(\d+))?/.exec(out.stdout);
    if (!match) {
      refuse("GIT_PREFLIGHT_FAILED", `unrecognized git version output: ${truncate(out.stdout, 80)}`);
    }
    const major = Number(match[1]);
    const minor = Number(match[2]);
    if (major < MIN_GIT_MAJOR || (major === MIN_GIT_MAJOR && minor < MIN_GIT_MINOR)) {
      refuse(
        "GIT_PREFLIGHT_FAILED",
        `git ${major}.${minor} is below the required ${MIN_GIT_MAJOR}.${MIN_GIT_MINOR}`,
      );
    }
    preflightVersion = `${major}.${minor}${match[3] ? `.${match[3]}` : ""}`;
    return preflightVersion;
  }

  async function assertRepository(repoPath) {
    let out;
    try {
      out = await run(repoPath, ["rev-parse", "--is-bare-repository", "--absolute-git-dir"]);
    } catch (error) {
      if (isRefusal(error)) throw error;
      if (error?.spawnFailed) {
        refuse("GIT_PREFLIGHT_FAILED", `git binary is not executable: ${error.spawnCode}`);
      }
      refuse("GIT_REPOSITORY_INVALID", "path is not a git repository", {
        stderr: truncate(error?.stderr),
      });
    }
    const lines = out.stdout.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
    const gitDir = lines[1] ?? null;
    if (!gitDir) {
      refuse("GIT_REPOSITORY_INVALID", "git rev-parse did not report an absolute git dir");
    }
    return { bare: lines[0] === "true", gitDir };
  }

  // fsck --full --strict is the authoritative connectivity + OID hash-integrity
  // + ref-validity proof. --no-dangling suppresses non-fatal dangling notices
  // (dangling objects are unreachable but present, not corruption).
  async function assertGraphIntegrity(repoPath) {
    try {
      await run(repoPath, ["fsck", "--full", "--strict", "--no-progress", "--no-dangling"]);
    } catch (error) {
      if (isRefusal(error)) throw error;
      if (error?.spawnFailed) {
        refuse("GIT_PREFLIGHT_FAILED", `git binary is not executable: ${error.spawnCode}`);
      }
      const stderr = String(error?.stderr ?? "");
      const code = /\bmissing\b|\bbroken\b|\bunable to read\b/i.test(stderr)
        ? "GIT_GRAPH_INCOMPLETE"
        : "GIT_OID_INTEGRITY_FAILED";
      refuse(code, "git fsck reported a corrupt or incomplete object graph", {
        exitCode: error?.exitCode ?? null,
        stderr: truncate(stderr),
      });
    }
  }

  // rev-list --all --objects with the default --missing=error re-proves that
  // every object reachable from every ref is present, and yields the object
  // count. This is redundant with fsck's connectivity pass by design (defense
  // in depth) and additionally enumerates the reachable object set.
  async function countReachableObjects(repoPath) {
    let out;
    try {
      out = await run(repoPath, ["rev-list", "--all", "--objects", "--missing=error"]);
    } catch (error) {
      if (isRefusal(error)) throw error;
      refuse("GIT_GRAPH_INCOMPLETE", "reachable-object enumeration failed", {
        exitCode: error?.exitCode ?? null,
        stderr: truncate(error?.stderr),
      });
    }
    let count = 0;
    for (const line of out.stdout.split("\n")) {
      if (line.length > 0) count += 1;
    }
    return count;
  }

  async function readRefs(repoPath) {
    let out;
    try {
      out = await run(repoPath, ["for-each-ref", "--format=%(objectname) %(refname)"]);
    } catch (error) {
      if (isRefusal(error)) throw error;
      refuse("GIT_REPOSITORY_INVALID", "unable to enumerate refs", {
        stderr: truncate(error?.stderr),
      });
    }
    const refs = [];
    for (const raw of out.stdout.split("\n")) {
      const line = raw.trim();
      if (line.length === 0) continue;
      const spaceAt = line.indexOf(" ");
      if (spaceAt <= 0) {
        refuse("GIT_REPOSITORY_INVALID", `malformed ref line: ${truncate(line, 80)}`);
      }
      const oid = line.slice(0, spaceAt);
      const name = line.slice(spaceAt + 1);
      if (!OID_RE.test(oid)) {
        refuse("GIT_REPOSITORY_INVALID", `ref ${name} has a non-OID target: ${truncate(oid, 80)}`);
      }
      refs.push({ name, oid });
    }
    refs.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    return refs;
  }

  async function readHead(repoPath) {
    try {
      const out = await run(repoPath, ["rev-parse", "--verify", "--quiet", "HEAD"]);
      const oid = out.stdout.trim();
      return oid.length > 0 && OID_RE.test(oid) ? oid : null;
    } catch (error) {
      if (isRefusal(error)) throw error;
      // Unborn HEAD (fresh repo with no commit) is a legitimate empty state.
      return null;
    }
  }

  function generationFingerprint(head, refs) {
    const hash = createHash("sha256");
    hash.update(`head\0${head ?? ""}\n`);
    for (const ref of refs) {
      hash.update(`${ref.name}\0${ref.oid}\n`);
    }
    return hash.digest("hex");
  }

  /**
   * Prove the git object graph at `repoPath` is complete and internally
   * consistent, returning a frozen generation proof. Throws a structured
   * refusal on any failure.
   *
   * @param {string} repoPath  containment-verified absolute repository path
   * @param {object} [expected]
   * @param {string} [expected.headOid]  required HEAD oid (refresh generation check)
   * @param {Array<{name:string,oid:string}>} [expected.refs]  required exact ref set
   * @param {string} [expected.generationFingerprint]  required generation fingerprint
   * @returns {Promise<Readonly<{gitVersion:string,bare:boolean,head:(string|null),refs:ReadonlyArray<{name:string,oid:string}>,objectCount:number,generationFingerprint:string}>>}
   */
  async function verifyRepositoryGraph(repoPath, expected = {}) {
    if (typeof repoPath !== "string" || repoPath.length === 0 || !isAbsolute(repoPath)) {
      refuse("GIT_REPOSITORY_INVALID", "repository path must be a non-empty absolute path");
    }

    const gitVersion = await preflight();
    const { bare } = await assertRepository(repoPath);
    await assertGraphIntegrity(repoPath);
    const objectCount = await countReachableObjects(repoPath);
    const refs = await readRefs(repoPath);
    const head = await readHead(repoPath);
    const fingerprint = generationFingerprint(head, refs);

    if (expected && typeof expected === "object") {
      if (typeof expected.headOid === "string" && expected.headOid !== head) {
        refuse("GIT_GENERATION_MISMATCH", "HEAD oid does not match the expected generation", {
          expectedHeadOid: expected.headOid,
          actualHeadOid: head,
        });
      }
      if (typeof expected.generationFingerprint === "string" && expected.generationFingerprint !== fingerprint) {
        refuse("GIT_GENERATION_MISMATCH", "generation fingerprint does not match the expected generation", {
          expectedGenerationFingerprint: expected.generationFingerprint,
          actualGenerationFingerprint: fingerprint,
        });
      }
      if (Array.isArray(expected.refs)) {
        const want = expected.refs
          .map((r) => `${r.name}\0${r.oid}`)
          .sort()
          .join("\n");
        const have = refs.map((r) => `${r.name}\0${r.oid}`).join("\n");
        if (want !== have) {
          refuse("GIT_GENERATION_MISMATCH", "ref set does not match the expected generation");
        }
      }
    }

    return Object.freeze({
      gitVersion,
      bare,
      head,
      refs: Object.freeze(refs.map((r) => Object.freeze({ ...r }))),
      objectCount,
      generationFingerprint: fingerprint,
    });
  }

  return Object.freeze({ verifyRepositoryGraph, preflight, gitPath });
}

function truncate(value, max = 4000) {
  const str = String(value ?? "");
  return str.length > max ? `${str.slice(0, max)}…` : str;
}
