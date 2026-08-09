#!/usr/bin/env node
// Fails if any released "## [X.Y.Z]" heading, or the "### Prior releases"
// block (the only record of v0.2.0-v0.2.4, which predate this changelog),
// present in CHANGELOG.md at the comparison ref is missing from the working
// tree's CHANGELOG.md. This protects released history: a change can add
// [Unreleased] notes or a new version section, but it can never erase a
// heading or the pre-changelog history record that already shipped.
//
// Usage:
//   node scripts/changelog-history-guard.mjs [--base <ref>] [--mode pr|push]
//
// --mode pr (default) diffs against a merge-base with the target branch,
// which is what a pull-request run needs: HEAD (the PR branch) and
// origin/main (the target) share a common ancestor that predates the PR's
// own commits, so the merge-base is a real "before this change" snapshot.
//
// --mode push is for a run that is already sitting *on* main (the CI "push"
// trigger, i.e. a direct-to-main release commit): at that point origin/main
// already points at HEAD itself, so `git merge-base HEAD origin/main`
// degenerates to HEAD and a pr-mode guard would compare the working tree
// against itself -- a structural no-op that can never fail. --mode push
// instead resolves the comparison ref to the most recent tag reachable from
// HEAD~1, falling back to HEAD~1 itself when no tag is reachable, which is
// an actual "before this commit" snapshot.
//
// With no --base and --mode pr, the ref is resolved automatically:
//   - "origin/main" if already resolvable (or fetchable), which is what CI
//     (running against the PR branch) and most local clones want.
//   - falls back to the local "main" branch otherwise.

import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const CHANGELOG_FILE = "CHANGELOG.md";
const HEADING_RE = /^## \[(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]/gm;
const PRIOR_RELEASES_HEADING = "### Prior releases";
const PRIOR_RELEASES_RE = /^### Prior releases\s*$/m;

// Returns the set of released version headings ("## [X.Y.Z]") found in a
// CHANGELOG.md text. Pure string-in, set-out so it's testable without git.
export function extractReleaseHeadings(text) {
  const out = new Set();
  let match;
  const re = new RegExp(HEADING_RE);
  while ((match = re.exec(text)) !== null) {
    out.add(match[1]);
  }
  return out;
}

// Returns whether `text` contains the "### Prior releases" heading that
// records history predating the changelog itself.
export function hasPriorReleasesSection(text) {
  return PRIOR_RELEASES_RE.test(text);
}

// Returns the protected items present in `baseText` but absent from
// `workingText`: released version headings ("X.Y.Z") plus, if it was
// removed, the literal string PRIOR_RELEASES_HEADING. Sorted (version
// headings first) for stable output. Pure, testable without git.
export function findRemovedHeadings(baseText, workingText) {
  const base = extractReleaseHeadings(baseText);
  const working = extractReleaseHeadings(workingText);
  const removed = [...base].filter((v) => !working.has(v)).sort();
  if (hasPriorReleasesSection(baseText) && !hasPriorReleasesSection(workingText)) {
    removed.push(PRIOR_RELEASES_HEADING);
  }
  return removed;
}

function describeRemoved(item) {
  return item === PRIOR_RELEASES_HEADING ? `the "${PRIOR_RELEASES_HEADING}" block` : `[${item}]`;
}

function fail(msg) {
  console.error(`changelog-history-guard: ${msg}`);
  process.exit(1);
}
function capture(cmd) {
  return execSync(cmd, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function defaultRefExists(ref) {
  try {
    execSync(`git rev-parse --verify ${ref}`, { cwd: ROOT, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
function defaultFetchOriginMain() {
  execSync("git fetch origin main --quiet", { cwd: ROOT, stdio: "ignore" });
}
function defaultDescribePreviousTag() {
  return execSync("git describe --tags --abbrev=0 HEAD~1", {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

// Resolves the ref to diff released headings against in "pr" mode: prefers
// "origin/main" (fetching it first if the local clone doesn't have it yet,
// as in a shallow CI checkout), and falls back to a local "main" branch.
// `refExists`/`fetchOriginMain` are injectable so this is testable without
// running real git commands or hitting the network.
export function resolveBaseRef({
  refExists = defaultRefExists,
  fetchOriginMain = defaultFetchOriginMain,
} = {}) {
  const tried = [];
  if (refExists("origin/main")) return "origin/main";
  tried.push("origin/main (not present locally)");

  try {
    fetchOriginMain();
  } catch {
    // Offline, no "origin" remote, or fetch refused; fall through.
  }
  if (refExists("origin/main")) return "origin/main";
  tried.push("origin/main (fetch failed)");

  if (refExists("main")) return "main";
  tried.push("main (not present locally)");

  throw new Error(
    `could not resolve a base ref to diff against (tried: ${tried.join(", ")}); pass one explicitly with --base <ref>`
  );
}

// Resolves the ref to diff released headings against in "push" mode: the
// most recent tag reachable from HEAD~1, or HEAD~1 itself if none is
// reachable. Used instead of resolveBaseRef() when HEAD is already on main
// (see the module doc comment for why origin/main is unusable there).
// Injectable for the same reason as resolveBaseRef().
export function resolvePushBaseRef({
  refExists = defaultRefExists,
  describePreviousTag = defaultDescribePreviousTag,
} = {}) {
  try {
    const tag = describePreviousTag();
    if (tag) return tag;
  } catch {
    // No tag reachable from HEAD~1; fall through to the previous commit.
  }
  if (refExists("HEAD~1")) return "HEAD~1";
  throw new Error(
    "could not resolve a previous commit or tag to diff against in --mode push; this is likely the repository's first commit"
  );
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
  const baseIdx = args.indexOf("--base");
  const explicitBase = baseIdx >= 0 ? args[baseIdx + 1] : null;
  const modeIdx = args.indexOf("--mode");
  const mode = modeIdx >= 0 ? args[modeIdx + 1] : "pr";
  if (mode !== "pr" && mode !== "push") {
    fail(`invalid --mode "${mode}"; expected "pr" or "push"`);
    return;
  }

  let baseRef;
  try {
    baseRef = explicitBase ?? (mode === "push" ? resolvePushBaseRef() : resolveBaseRef());
  } catch (err) {
    fail(err.message);
    return;
  }

  let mergeBase;
  try {
    mergeBase = capture(`git merge-base HEAD ${baseRef}`);
  } catch {
    fail(`could not compute merge-base between HEAD and ${baseRef}`);
    return;
  }

  let baseText = "";
  try {
    baseText = capture(`git show ${mergeBase}:${CHANGELOG_FILE}`);
  } catch {
    // CHANGELOG.md did not exist at the merge base; nothing to protect.
    baseText = "";
  }

  const workingPath = join(ROOT, CHANGELOG_FILE);
  const workingText = existsSync(workingPath) ? readFileSync(workingPath, "utf8") : "";

  const removed = findRemovedHeadings(baseText, workingText);
  if (removed.length > 0) {
    fail(
      `${CHANGELOG_FILE} is missing released history present at ${baseRef} ` +
        `(merge-base ${mergeBase.slice(0, 8)}): ${removed.map(describeRemoved).join(", ")}. ` +
        "Released history must never be removed."
    );
    return;
  }

  console.log(
    `changelog-history-guard: OK (mode ${mode}, base ${baseRef} @ ${mergeBase.slice(0, 8)}, no released history removed)`
  );
}
