#!/usr/bin/env node
// Fails if any released "## [X.Y.Z]" heading present in CHANGELOG.md at the
// merge base is missing from the working tree's CHANGELOG.md. This protects
// released history: a pull request can add [Unreleased] notes or a new
// version section, but it can never erase a heading that already shipped.
//
// Usage:
//   node scripts/changelog-history-guard.mjs [--base <ref>]
//
// With no --base, the ref is resolved automatically:
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

// Returns the version headings present in `baseText` but absent from
// `workingText`, sorted for stable output. Pure, testable without git.
export function findRemovedHeadings(baseText, workingText) {
  const base = extractReleaseHeadings(baseText);
  const working = extractReleaseHeadings(workingText);
  return [...base].filter((v) => !working.has(v)).sort();
}

function fail(msg) {
  console.error(`changelog-history-guard: ${msg}`);
  process.exit(1);
}
function capture(cmd) {
  return execSync(cmd, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function refExists(ref) {
  try {
    execSync(`git rev-parse --verify ${ref}`, { cwd: ROOT, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Resolves the ref to diff released headings against: prefers
// "origin/main" (fetching it first if the local clone doesn't have it yet,
// as in a shallow CI checkout), and falls back to a local "main" branch.
export function resolveBaseRef() {
  const tried = [];
  if (refExists("origin/main")) return "origin/main";
  tried.push("origin/main (not present locally)");

  try {
    execSync("git fetch origin main --quiet", { cwd: ROOT, stdio: "ignore" });
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

  let baseRef;
  try {
    baseRef = explicitBase ?? resolveBaseRef();
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
      `${CHANGELOG_FILE} is missing released version heading(s) present at ${baseRef} ` +
        `(merge-base ${mergeBase.slice(0, 8)}): ${removed.map((v) => `[${v}]`).join(", ")}. ` +
        "Released history must never be removed."
    );
    return;
  }

  console.log(
    `changelog-history-guard: OK (base ${baseRef} @ ${mergeBase.slice(0, 8)}, no released headings removed)`
  );
}
