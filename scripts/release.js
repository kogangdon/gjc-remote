#!/usr/bin/env node
// Release helper for the gjc-remote monorepo.
//
// Bumps every workspace `version` field in lockstep, syncs bun.lock, promotes
// the CHANGELOG.md `[Unreleased]` section, runs the full test suite, then
// creates the release commit and an annotated `vX.Y.Z` tag. Pushing that tag
// triggers `.github/workflows/release.yml`, which re-runs the suite on CI and
// cuts the GitHub Release.
//
// Usage:
//   node scripts/release.js <version> [--push] [--no-verify]
//     <version>     target semver, e.g. 0.2.0 (a leading "v" is stripped)
//     --push        also push the release commit + tag to origin
//     --no-verify   skip the local `npm test` gate before committing
//                   (rejected together with --push: a release that reaches
//                   origin must never skip the local test gate)
//
// npm publishing is intentionally NOT part of this flow yet; it is gated on the
// npm org + NPM_TOKEN being provisioned (see release.yml).

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
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
// --no-verify and --push are mutually exclusive. --no-verify remains usable
// on its own for a local dry run that never leaves the machine.
export function checkFlagExclusivity(skipVerify, doPush) {
  if (skipVerify && doPush) {
    return "--no-verify cannot be combined with --push; a release that reaches origin must run the local test gate. Drop --push for a local dry run, or drop --no-verify to push for real.";
  }
  return null;
}

// --- Staged-diff whitelist ---------------------------------------------------
//
// After staging the version bump, the staged change must touch only the
// paths this script is allowed to touch, and each staged package.json must
// have changed nothing but its "version" key. Both checks are pure functions
// over data the caller supplies, so they're testable without git mutations.

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

// --- Changelog promotion -----------------------------------------------------
//
// Moves everything under "## [Unreleased]" into a new "## [X.Y.Z] - DATE"
// section and leaves a fresh empty [Unreleased] behind. Pure string-in,
// string-out so it's testable without touching disk. Returns
// `{ error }` on failure or `{ text }` with the promoted changelog text.
export function promoteChangelog(text, version, date) {
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
  const args = process.argv.slice(2);
  const flags = new Set(args.filter((a) => a.startsWith("--")));
  const positional = args.filter((a) => !a.startsWith("--"));
  const doPush = flags.delete("--push");
  const skipVerify = flags.delete("--no-verify");
  if (flags.size > 0) fail(`unknown flag(s): ${[...flags].join(", ")}`);
  if (positional.length !== 1) {
    fail("usage: node scripts/release.js <version> [--push] [--no-verify]");
  }

  const exclusivityError = checkFlagExclusivity(skipVerify, doPush);
  if (exclusivityError) fail(exclusivityError);

  const version = positional[0].replace(/^v/, "");
  if (!SEMVER.test(version)) fail(`invalid semver: ${positional[0]}`);

  // Preconditions: clean tree, on main, monotonic version, tag free.
  if (capture("git status --porcelain")) {
    fail("working tree is not clean; commit or stash first");
  }
  const branch = capture("git rev-parse --abbrev-ref HEAD");
  if (branch !== "main") fail(`must run on main (current branch: ${branch})`);

  const rootPkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const current = rootPkg.version;
  if (version === current || cmpCore(version, current) < 0) {
    fail(`new version ${version} must be greater than current ${current}`);
  }
  if (capture(`git tag --list "v${version}"`)) {
    fail(`tag v${version} already exists`);
  }

  // Fail fast on a missing/empty changelog entry before mutating anything.
  const changelogPath = join(ROOT, CHANGELOG_FILE);
  const changelogBefore = readFileSync(changelogPath, "utf8");
  const promoted = promoteChangelog(changelogBefore, version, todayIso());
  if (promoted.error) fail(promoted.error);

  console.log(`Releasing v${version} (from ${current})`);
  const beforeByFile = new Map();
  for (const rel of PKG_FILES) {
    const p = join(ROOT, rel);
    const txt = readFileSync(p, "utf8");
    beforeByFile.set(rel, JSON.parse(txt));
    const next = txt.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`);
    if (next === txt) fail(`could not update "version" in ${rel}`);
    writeFileSync(p, next);
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

  const stagedFiles = capture("git diff --cached --name-only")
    .split("\n")
    .filter(Boolean);
  const disallowed = findDisallowedPaths(stagedFiles, ALLOWED_STAGED_PATHS);
  if (disallowed.length > 0) {
    fail(`staged change touches disallowed path(s): ${disallowed.join(", ")}`);
  }
  for (const rel of PKG_FILES) {
    const after = JSON.parse(readFileSync(join(ROOT, rel), "utf8"));
    const before = beforeByFile.get(rel);
    const unexpected = findUnexpectedPackageJsonKeys(before, after);
    if (unexpected.length > 0) {
      fail(`staged ${rel} changed key(s) other than "version": ${unexpected.join(", ")}`);
    }
    if (before.version === after.version) {
      fail(`staged ${rel} "version" did not change`);
    }
  }

  run(`git commit -m "chore(release): v${version}"`);
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
