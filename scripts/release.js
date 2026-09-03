#!/usr/bin/env node
// Release helper for the gjc-remote monorepo.
//
// Bumps every workspace `version` field in lockstep, syncs bun.lock, promotes
// the CHANGELOG.md `[Unreleased]` section, and (unless --no-verify) runs the
// full test suite before creating the release commit. Only when the test
// gate actually ran does it also create an annotated `vX.Y.Z` tag; pushing
// that tag triggers `.github/workflows/release.yml`, which re-runs the suite
// on CI and prepares a draft GitHub Release. Publishing remains blocked until
// the issue #55 evidence packet passes its protected promotion gate. Every
// staged file this script checks is
// re-read from the git index (not the working tree) right before the
// commit, so the whitelist and content checks below apply to exactly what
// will be committed, not to whatever happens to be on disk.
//
// Usage:
//   node scripts/release.js <version> [--push] [--no-verify]
//     <version>     target semver, e.g. 0.2.0 (a leading "v" is stripped)
//     --push        also push the release commit + tag to origin
//     --no-verify   skip the local `npm test` gate; the release commit is
//                   still created for local inspection, but no `vX.Y.Z` tag
//                   is created, so this can never leave behind a tag that
//                   triggers the release workflow with the test gate
//                   skipped (rejected together with --push for the same
//                   reason: a release that reaches origin must never skip
//                   the local test gate)
//
// npm publishing is intentionally NOT part of this flow yet; it is gated on the
// npm org + NPM_TOKEN being provisioned (see release.yml).

import { execSync } from "node:child_process";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const PKG_FILES = [
  "package.json",
  "bot/package.json",
  "daemon/package.json",
  "shared/package.json",
];
export const CHANGELOG_FILE = "CHANGELOG.md";
export const ALLOWED_STAGED_PATHS = [...PKG_FILES, "bun.lock", CHANGELOG_FILE];
export const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function fail(msg) {
  console.error(`release: ${msg}`);
  process.exit(1);
}
function run(cmd) {
  execSync(cmd, { cwd: ROOT, stdio: "inherit" });
}
function capture(cmd) {
  return execSync(cmd, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function core(v) {
  return v.split("-")[0].split(".").map((n) => Number.parseInt(n, 10));
}
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
// Returns >0 if a>b, <0 if a<b, 0 if equal cores (prerelease ignored).
export function cmpCore(a, b) {
  const [aa, bb] = [core(a), core(b)];
  for (let i = 0; i < 3; i += 1) {
    if (aa[i] !== bb[i]) return aa[i] - bb[i];
  }
  return 0;
}

// --- Flag exclusivity -------------------------------------------------------
//
// A release that reaches origin must never skip the local test gate, so
// --no-verify and --push are mutually exclusive. --no-verify alone never
// creates a `vX.Y.Z` tag (see main()) -- it only produces a local commit for
// inspection, so it can't leave behind a tag that later gets pushed by hand.
export function checkFlagExclusivity(skipVerify, doPush) {
  if (skipVerify && doPush) {
    return "--no-verify cannot be combined with --push; a release that reaches origin must run the local test gate. Drop --push for a local dry run, or drop --no-verify to push for real.";
  }
  return null;
}

// --- CLI argument wiring -----------------------------------------------------
//
// Pure argv -> `{ version, doPush, skipVerify }` | `{ error }` parsing, kept
// separate from main() so the flag/positional wiring (unknown-flag
// rejection, --push/--no-verify exclusivity, version regex) is unit-testable
// without spawning a process or touching git/the filesystem -- main() calls
// process.exit() on failure, which a normal unit test can't safely exercise.
export function parseCliArgs(argv) {
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const positional = argv.filter((a) => !a.startsWith("--"));
  const doPush = flags.delete("--push");
  const skipVerify = flags.delete("--no-verify");
  if (flags.size > 0) {
    return { error: `unknown flag(s): ${[...flags].join(", ")}` };
  }
  if (positional.length !== 1) {
    return { error: "usage: node scripts/release.js <version> [--push] [--no-verify]" };
  }

  const exclusivityError = checkFlagExclusivity(skipVerify, doPush);
  if (exclusivityError) return { error: exclusivityError };

  const version = positional[0].replace(/^v/, "");
  if (!SEMVER.test(version)) return { error: `invalid semver: ${positional[0]}` };

  return { version, doPush, skipVerify };
}

// --- Staged-diff whitelist ---------------------------------------------------
//
// After staging the version bump, the staged change must touch only the
// paths this script is allowed to touch, and each staged package.json must
// have changed nothing but its "version" key. Both checks are pure functions
// over data the caller supplies, so they're testable without git mutations.
// The caller is responsible for sourcing that data from the git index (see
// readStagedJson/readStagedText in main()), not from the working tree, so
// the check applies to what will actually be committed.

// Returns the subset of `stagedFiles` that are not in `allowedPaths`.
export function findDisallowedPaths(stagedFiles, allowedPaths = ALLOWED_STAGED_PATHS) {
  const allowed = new Set(allowedPaths);
  return stagedFiles.filter((f) => !allowed.has(f));
}

// Compares parsed-JSON `before`/`after` package.json contents and returns the
// list of top-level keys that changed other than "version". An empty result
// with `before.version === after.version` means nothing changed at all,
// which the caller should also treat as an error (see main flow below).
export function findUnexpectedPackageJsonKeys(before, after) {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const changed = [];
  for (const key of keys) {
    if (key === "version") continue;
    if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) changed.push(key);
  }
  return changed;
}

// bun.lock stores each workspace as `"version": "X.Y.Z",` inside a JSON5-ish
// block. This does NOT parse or fully understand bun.lock's format: it only
// checks the *shape* of each added/removed line in the staged unified diff.
// What it verifies: every added or removed line matches a bare
// `"version": "...",` field, and every *added* line's value equals the
// target release version. What it does NOT verify: which workspace a
// version field belongs to, that every expected workspace's version line
// actually changed, or anything about lines that were not part of the diff.
// A change that hides an unrelated edit inside an already-changed line, or
// that reformats a version line without changing its value, is out of scope
// for this check.
const LOCK_VERSION_LINE_RE = /^"version":\s*"([^"]*)"\s*,?\s*$/;
export function findUnexpectedLockfileDiffLines(diffText, version) {
  const unexpected = [];
  for (const line of diffText.split("\n")) {
    if (line.startsWith("+++") || line.startsWith("---")) continue;
    if (!line.startsWith("+") && !line.startsWith("-")) continue;
    const trimmed = line.slice(1).trim();
    const match = LOCK_VERSION_LINE_RE.exec(trimmed);
    if (!match) {
      unexpected.push(line);
      continue;
    }
    if (line.startsWith("+") && match[1] !== version) unexpected.push(line);
  }
  return unexpected;
}

// --- Changelog promotion -----------------------------------------------------
//
// Moves everything under "## [Unreleased]" into a new "## [X.Y.Z] - DATE"
// section and leaves a fresh empty [Unreleased] behind. Pure string-in,
// string-out so it's testable without touching disk. Returns
// `{ error }` on failure or `{ text }` with the promoted changelog text.
export function promoteChangelog(text, version, date) {
  const dupRe = new RegExp(`^## \\[${escapeRegExp(version)}\\]`, "m");
  if (dupRe.test(text)) {
    return {
      error: `${CHANGELOG_FILE} already has a "## [${version}]" section; refusing to create a duplicate release heading`,
    };
  }

  const headingRe = /^## \[Unreleased\]\s*$/m;
  const match = headingRe.exec(text);
  if (!match) return { error: `${CHANGELOG_FILE} has no "## [Unreleased]" heading` };

  const sectionStart = match.index;
  const afterHeading = match.index + match[0].length;
  const rest = text.slice(afterHeading);
  const nextHeadingMatch = /^## \[/m.exec(rest);
  const sectionEnd = nextHeadingMatch ? afterHeading + nextHeadingMatch.index : text.length;

  const body = text.slice(afterHeading, sectionEnd).trim();
  if (!body) {
    return {
      error: `${CHANGELOG_FILE} "[Unreleased]" section is empty; add release notes before releasing`,
    };
  }

  const before = text.slice(0, sectionStart);
  const after = text.slice(sectionEnd);
  const promoted = `## [Unreleased]\n\n## [${version}] - ${date}\n\n${body}\n\n`;
  return { text: before + promoted + after };
}

export function todayIso(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

const isMain = (() => {
  if (!process.argv[1]) return false;
  try {
    return fileURLToPath(import.meta.url) === resolve(process.argv[1]);
  } catch {
    return false;
  }
})();

if (isMain) {
  main();
}

function main() {
  const parsed = parseCliArgs(process.argv.slice(2));
  if (parsed.error) fail(parsed.error);
  const { version, doPush, skipVerify } = parsed;

  // Preconditions: clean tree, on main, monotonic version, tag free.
  if (capture("git status --porcelain")) {
    fail("working tree is not clean; commit or stash first");
  }
  const branch = capture("git rev-parse --abbrev-ref HEAD");
  if (branch !== "main") fail(`must run on main (current branch: ${branch})`);

  // Refuse a symlinked (or otherwise non-regular) path this script is about
  // to write to: if PKG_FILES/CHANGELOG_FILE resolve through a symlink, this
  // script would write the target file while git stages the unchanged link
  // blob, so the whitelist checks below would pass on a release that never
  // actually shipped the bump.
  for (const rel of [...PKG_FILES, CHANGELOG_FILE]) {
    const p = join(ROOT, rel);
    let st;
    try {
      st = lstatSync(p);
    } catch {
      fail(`${rel} does not exist`);
      return;
    }
    if (!st.isFile()) {
      fail(
        `${rel} is not a regular file (symlink or other special file); refusing to bump a path git may stage differently from what this script wrote`
      );
    }
  }

  const rootPkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const current = rootPkg.version;
  if (version === current || cmpCore(version, current) < 0) {
    fail(`new version ${version} must be greater than current ${current}`);
  }
  if (capture(`git tag --list "v${version}"`)) {
    fail(`tag v${version} already exists`);
  }

  // Fail fast on a missing/empty/duplicate changelog entry before mutating
  // anything.
  const changelogPath = join(ROOT, CHANGELOG_FILE);
  const changelogBefore = readFileSync(changelogPath, "utf8");
  const promoted = promoteChangelog(changelogBefore, version, todayIso());
  if (promoted.error) fail(promoted.error);

  console.log(`Releasing v${version} (from ${current})`);

  // Validate every package.json bump before writing any of them, so a
  // failure partway through never leaves some files bumped and others not.
  const beforeByFile = new Map();
  const nextByFile = new Map();
  for (const rel of PKG_FILES) {
    const p = join(ROOT, rel);
    const txt = readFileSync(p, "utf8");
    beforeByFile.set(rel, JSON.parse(txt));
    const next = txt.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`);
    if (next === txt) fail(`could not update "version" in ${rel}`);
    nextByFile.set(rel, next);
  }
  for (const [rel, next] of nextByFile) {
    writeFileSync(join(ROOT, rel), next);
    console.log(`  bumped ${rel}`);
  }

  writeFileSync(changelogPath, promoted.text);
  console.log(`  promoted ${CHANGELOG_FILE} [Unreleased] -> [${version}]`);

  console.log("Syncing bun.lock...");
  run("bun install");

  if (!skipVerify) {
    console.log("Running test suite...");
    run("npm test");
  }

  run(`git add ${PKG_FILES.join(" ")} bun.lock ${CHANGELOG_FILE}`);

  // Everything from here on reads from the git index (not the working
  // tree), so it validates exactly what is about to be committed.
  const stagedFiles = capture("git diff --cached --name-only")
    .split("\n")
    .filter(Boolean);
  const disallowed = findDisallowedPaths(stagedFiles, ALLOWED_STAGED_PATHS);
  if (disallowed.length > 0) {
    fail(`staged change touches disallowed path(s): ${disallowed.join(", ")}`);
  }
  for (const rel of PKG_FILES) {
    const after = JSON.parse(capture(`git show :${rel}`));
    const before = beforeByFile.get(rel);
    const unexpected = findUnexpectedPackageJsonKeys(before, after);
    if (unexpected.length > 0) {
      fail(`staged ${rel} changed key(s) other than "version": ${unexpected.join(", ")}`);
    }
    if (before.version === after.version) {
      fail(`staged ${rel} "version" did not change`);
    }
  }

  const stagedChangelog = capture(`git show :${CHANGELOG_FILE}`);
  if (stagedChangelog.trim() !== promoted.text.trim()) {
    fail(
      `staged ${CHANGELOG_FILE} does not match the expected promotion (new [${version}] section plus an emptied [Unreleased]); refusing to commit an unexpected changelog structure`
    );
  }

  const lockDiff = capture("git diff --cached -- bun.lock");
  const badLockLines = findUnexpectedLockfileDiffLines(lockDiff, version);
  if (badLockLines.length > 0) {
    fail(
      `staged bun.lock has line(s) that are not a "version" field bump to ${version}: ${badLockLines.join(" | ")}`
    );
  }

  // --no-verify here is git's own hook-skip flag, not this script's
  // --no-verify (the npm-test gate handled above). Pre-commit hooks run
  // between the whitelist checks above and the commit itself and could
  // stage more changes than we just validated; this script's own checks are
  // the real gate, so hook trust would just reintroduce that race.
  run(`git commit --no-verify -m "chore(release): v${version}"`);

  if (skipVerify) {
    console.log(
      `\nDry run: --no-verify skipped the local test gate, so no v${version} tag was created.`
    );
    // The release commit already exists locally, so a bare re-run would fail the
    // monotonic-version precondition. Name the undo step instead of implying the
    // re-run works from here.
    console.log(
      `The release commit was made locally on ${branch}. Undo it with \`git reset --hard HEAD~1\`, then re-run without --no-verify to run the test suite and tag for real.`
    );
    return;
  }

  run(`git tag -a v${version} -m "v${version}"`);
  console.log(`\nCreated release commit + tag v${version}.`);

  if (doPush) {
    run(`git push origin ${branch}`);
    run(`git push origin v${version}`);
    console.log("Pushed commit + tag; the release workflow will run on GitHub.");
  } else {
    console.log(`Next: git push origin ${branch} && git push origin v${version}`);
  }
}
