// Git data-plane materializer for the native workspace serving primitive
// (#53 Phase 2, slice S6f.1d).
//
// This module is a PURE, dependency-injected primitive. It does NOT wire into
// the daemon and does NOT flip the native-workspace-serving gate — that gate
// stays disabled (daemon.js NATIVE_WORKSPACE_SERVING_ENABLED = false). The
// create/refresh workspace orchestrators (a later wiring slice) inject this
// factory to materialize a candidate generation directory before it is
// verified (see ./git-graph-verification.js) and published.
//
// Clone strategy — read this before touching the clone args:
//   git clone --local --no-hardlinks --separate-git-dir=<gitDir> -- <workDir> <candidatePath>
//   * --no-hardlinks gives each generation a FULLY ISOLATED object store: no
//     cross-generation corruption can occur via objects shared by hardlink
//     with any other generation's object store.
//   * --local keeps the clone strictly offline (no network transport is ever
//     invoked here).
//   * --separate-git-dir honors the caller's explicit two-path model: the
//     working tree lands at candidatePath, the git dir lands at gitDir.
//   Both the create-clone request and the refresh request produce a
//   VERIFIED ISOLATED CLONE of workDir's CURRENT state at the moment this
//   runs — the daemon is responsible for updating workDir out-of-band before
//   a refresh; this seam merely snapshots whatever is there right now.
//   `baseGeneration` (refresh) and `activeGeneration` (create-clone) are
//   accepted on the request and MAY be surfaced in the returned receipt, but
//   they do NOT change the git action performed by this foundation
//   primitive: there is no refresh-specific fetch/merge/incremental-update
//   here. Any such refinement (e.g. reusing baseGeneration's objects, or a
//   fetch+reset flow instead of a fresh clone) is explicitly DEFERRED to the
//   S6f.3 wiring slice, which has the full orchestration context needed to
//   decide whether that optimization is safe.
//
// Hardening posture mirrors ./git-graph-verification.js exactly: git is
// invoked as the SYSTEM git binary via child_process.execFile, absolute-path
// pinned, version-preflighted fail-closed (floor 2.32), and env-scrubbed. A
// raw git/exec/child_process error object is never allowed to escape this
// module — every failure path throws a structured refusal.
//
// Refusal codes:
//   MATERIALIZE_REQUEST_INVALID, MATERIALIZE_PREFLIGHT_FAILED,
//   MATERIALIZE_TARGET_EXISTS, MATERIALIZE_TIMEOUT,
//   MATERIALIZE_OUTPUT_OVERFLOW, MATERIALIZE_CLONE_FAILED,
//   MATERIALIZE_ISOLATION_VIOLATED
//
// Recovery contract: this seam is all-or-nothing. If the clone fails partway
// (timeout / disk-full / non-zero exit) OR the materialised repo fails the
// post-clone isolation check, the module best-effort removes both partial
// targets (candidatePath and gitDir) before throwing, so a retry never trips
// MATERIALIZE_TARGET_EXISTS on the module's own aborted debris. Only a
// fully-verified, isolated clone is left behind on success.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { isAbsolute, resolve as resolvePath, relative as relativePath, join as joinPath } from "node:path";
import { stat, readdir, rm } from "node:fs/promises";

import {
  resolveDefaultGitPath,
  buildScrubbedEnv,
  HARDENING_CONFIG,
  MIN_GIT_MAJOR,
  MIN_GIT_MINOR,
} from "./git-graph-verification.js";

const OPERATION = "materialize_workspace";

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_BUFFER = 64 * 1024 * 1024; // 64 MiB

const VALID_SOURCE_PLATFORMS = new Set(["posix", "windows"]);

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

function truncate(value, max = 4000) {
  const str = String(value ?? "");
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

function isNonEmptyAbsolutePath(value) {
  return typeof value === "string" && value.length > 0 && isAbsolute(value);
}

function validateRequest(request) {
  if (request === null || typeof request !== "object") {
    refuse("MATERIALIZE_REQUEST_INVALID", "request must be an object");
  }
  const { operation, workDir, candidatePath, gitDir, sourcePlatform } = request;
  if (typeof operation !== "string" || operation.length === 0) {
    refuse("MATERIALIZE_REQUEST_INVALID", "operation must be a non-empty string");
  }
  if (!isNonEmptyAbsolutePath(workDir)) {
    refuse("MATERIALIZE_REQUEST_INVALID", "workDir must be a non-empty absolute path");
  }
  if (!isNonEmptyAbsolutePath(candidatePath)) {
    refuse("MATERIALIZE_REQUEST_INVALID", "candidatePath must be a non-empty absolute path");
  }
  if (!isNonEmptyAbsolutePath(gitDir)) {
    refuse("MATERIALIZE_REQUEST_INVALID", "gitDir must be a non-empty absolute path");
  }
  if (!VALID_SOURCE_PLATFORMS.has(sourcePlatform)) {
    refuse("MATERIALIZE_REQUEST_INVALID", "sourcePlatform must be 'posix' or 'windows'");
  }
  // Distinctness / non-overlap: the three paths address three disjoint
  // filesystem locations. Equality or nesting between any two would let the
  // clone read and write the same subtree (or clone into the source), which
  // must fail loudly at the request boundary rather than late as an opaque
  // MATERIALIZE_CLONE_FAILED.
  const pairs = [
    ["workDir", workDir, "candidatePath", candidatePath],
    ["workDir", workDir, "gitDir", gitDir],
    ["candidatePath", candidatePath, "gitDir", gitDir],
  ];
  for (const [aName, aPath, bName, bPath] of pairs) {
    if (pathOverlaps(aPath, bPath)) {
      refuse(
        "MATERIALIZE_REQUEST_INVALID",
        `${aName} and ${bName} must be distinct, non-overlapping paths`,
      );
    }
  }
}

// True when a and b are equal or one contains the other (after normalization).
// A path is "inside" another when the relative path from parent to child is
// neither empty (equal), absolute (different root/drive), nor escapes via "..".
function pathOverlaps(a, b) {
  const ra = resolvePath(a);
  const rb = resolvePath(b);
  if (ra === rb) return true;
  const relAB = relativePath(ra, rb);
  if (relAB !== "" && !relAB.startsWith("..") && !isAbsolute(relAB)) return true;
  const relBA = relativePath(rb, ra);
  if (relBA !== "" && !relBA.startsWith("..") && !isAbsolute(relBA)) return true;
  return false;
}

async function pathExistsNonEmpty(targetPath) {
  let info;
  try {
    info = await stat(targetPath);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    // Any other stat failure (EACCES, ENOTDIR, ...) is treated as "exists" in
    // the conservative sense: we cannot prove it is safe to clobber.
    return true;
  }
  if (info.isFile()) return true;
  if (info.isDirectory()) {
    const entries = await readdir(targetPath);
    return entries.length > 0;
  }
  return true; // symlink / other special file: conservatively treat as occupied
}

// Best-effort removal of both materialisation targets after a failed or
// non-isolated clone. Never throws: cleanup failures must not mask the
// original refusal, and a leftover on an unremovable path is surfaced later
// as MATERIALIZE_TARGET_EXISTS rather than crashing here.
async function cleanupTargets(candidatePath, gitDir) {
  for (const target of [candidatePath, gitDir]) {
    try {
      await rm(target, { recursive: true, force: true });
    } catch {
      // swallow: best-effort only
    }
  }
}

/**
 * @param {object} [deps]
 * @param {(file:string,args:string[],opts:object)=>Promise<{stdout:string,stderr:string}>} [deps.execFileFn]
 * @param {string} [deps.gitPath] absolute path to the git binary
 * @param {number} [deps.timeoutMs]
 * @param {number} [deps.maxBuffer]
 */
export function createGitMaterializer(deps = {}) {
  const execFileFn = deps.execFileFn ?? promisify(execFile);
  const gitPath = deps.gitPath ?? resolveDefaultGitPath();
  const timeoutMs = Number.isInteger(deps.timeoutMs) && deps.timeoutMs > 0 ? deps.timeoutMs : DEFAULT_TIMEOUT_MS;
  const maxBuffer = Number.isInteger(deps.maxBuffer) && deps.maxBuffer > 0 ? deps.maxBuffer : DEFAULT_MAX_BUFFER;

  if (typeof gitPath !== "string" || gitPath.length === 0 || !isAbsolute(gitPath)) {
    // Fail closed at construction: an unpinned/relative git path is a PATH
    // hijack vector and is never acceptable for a security primitive.
    refuse("MATERIALIZE_PREFLIGHT_FAILED", "git binary path must be a non-empty absolute path");
  }

  // buildScrubbedEnv() disallows all git network protocols (GIT_ALLOW_PROTOCOL="")
  // as the graph verifier only ever reads an already-local repository. This
  // materializer's sole action is a --local clone of a local working
  // directory, which git's transport layer still classifies under the "file"
  // protocol allowlist even with --local — so the file protocol must be
  // permitted here while every other protocol (http, ssh, git, ...) stays
  // blocked, preserving the "never touches the network" guarantee.
  const scrubbedEnv = { ...buildScrubbedEnv(gitPath), GIT_ALLOW_PROTOCOL: "file" };
  let preflightVersion = null;

  async function run(args) {
    const fullArgs = [...HARDENING_CONFIG, ...args];
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
        refuse("MATERIALIZE_TIMEOUT", `git ${args[0]} exceeded ${timeoutMs}ms`, {
          stderr: truncate(error.stderr),
        });
      }
      if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
        refuse("MATERIALIZE_OUTPUT_OVERFLOW", `git ${args[0]} output exceeded ${maxBuffer} bytes`);
      }
      if (typeof error?.code === "string") {
        // Spawn failure (ENOENT/EACCES/...): the binary itself could not run.
        refuse("MATERIALIZE_PREFLIGHT_FAILED", `git binary is not executable: ${error.code}`);
      }
      refuse("MATERIALIZE_CLONE_FAILED", `git ${args[0]} exited non-zero`, {
        exitCode: typeof error?.code === "number" ? error.code : null,
        stderr: truncate(error?.stderr),
      });
    }
  }

  async function preflight() {
    if (preflightVersion !== null) return preflightVersion;
    const out = await run(["--version"]);
    const match = /git version (\d+)\.(\d+)(?:\.(\d+))?/.exec(out.stdout);
    if (!match) {
      refuse("MATERIALIZE_PREFLIGHT_FAILED", `unrecognized git version output: ${truncate(out.stdout, 80)}`);
    }
    const major = Number(match[1]);
    const minor = Number(match[2]);
    if (major < MIN_GIT_MAJOR || (major === MIN_GIT_MAJOR && minor < MIN_GIT_MINOR)) {
      refuse(
        "MATERIALIZE_PREFLIGHT_FAILED",
        `git ${major}.${minor} is below the required ${MIN_GIT_MAJOR}.${MIN_GIT_MINOR}`,
      );
    }
    preflightVersion = `${major}.${minor}${match[3] ? `.${match[3]}` : ""}`;
    return preflightVersion;
  }

  async function materialize(request) {
    try {
      validateRequest(request);
    } catch (error) {
      if (isRefusal(error)) throw error;
      throw error;
    }

    const { operation, workspaceId, workDir, candidatePath, gitDir } = request;

    await preflight();

    if (await pathExistsNonEmpty(candidatePath)) {
      refuse("MATERIALIZE_TARGET_EXISTS", `candidatePath already exists: ${candidatePath}`);
    }
    if (await pathExistsNonEmpty(gitDir)) {
      refuse("MATERIALIZE_TARGET_EXISTS", `gitDir already exists: ${gitDir}`);
    }

    await run([
      "clone",
      "--local",
      "--no-hardlinks",
      `--separate-git-dir=${gitDir}`,
      "--",
      workDir,
      candidatePath,
    ]).catch(async (error) => {
      // Partial-failure cleanup: a mid-clone abort can leave a partial working
      // tree and/or git dir. Remove both so a retry is not permanently wedged
      // on this module's own debris, then rethrow the structured refusal.
      await cleanupTargets(candidatePath, gitDir);
      throw error;
    });

    // Isolation enforcement: --local --no-hardlinks copies objects but does NOT
    // defeat objects/info/alternates inheritance. A source repo that borrows
    // objects would yield a clone that silently depends on an external object
    // store while fsck/rev-list still pass — breaking the FULL-ISOLATION
    // guarantee this seam promises. If the alternates pointer is present, the
    // materialised repo is NOT self-contained: destroy it and refuse.
    const alternatesPath = joinPath(gitDir, "objects", "info", "alternates");
    let alternatesPresent = false;
    try {
      await stat(alternatesPath);
      alternatesPresent = true;
    } catch (error) {
      if (error?.code !== "ENOENT") {
        // Cannot prove absence: fail closed (treat as a violation).
        alternatesPresent = true;
      }
    }
    if (alternatesPresent) {
      await cleanupTargets(candidatePath, gitDir);
      refuse(
        "MATERIALIZE_ISOLATION_VIOLATED",
        "materialised repository inherits an external object store (objects/info/alternates present)",
      );
    }

    return Object.freeze({
      operation,
      workspaceId,
      candidatePath,
      gitDir,
      materialized: true,
    });
  }

  return Object.freeze({ materialize, preflight, gitPath });
}
