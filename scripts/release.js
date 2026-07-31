#!/usr/bin/env node
// Release helper for the gjc-remote monorepo.
//
// Bumps every workspace `version` field in lockstep, syncs bun.lock, runs the
// full test suite, then creates the release commit and an annotated `vX.Y.Z`
// tag. Pushing that tag triggers `.github/workflows/release.yml`, which re-runs
// the suite on CI and cuts the GitHub Release.
//
// Usage:
//   node scripts/release.js <version> [--push] [--no-verify]
//     <version>     target semver, e.g. 0.2.0 (a leading "v" is stripped)
//     --push        also push the release commit + tag to origin
//     --no-verify   skip the local `npm test` gate before committing
//
// npm publishing is intentionally NOT part of this flow yet; it is gated on the
// npm org + NPM_TOKEN being provisioned (see release.yml).

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PKG_FILES = [
  "package.json",
  "bot/package.json",
  "daemon/package.json",
  "shared/package.json",
];
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

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
function cmpCore(a, b) {
  const [aa, bb] = [core(a), core(b)];
  for (let i = 0; i < 3; i += 1) {
    if (aa[i] !== bb[i]) return aa[i] - bb[i];
  }
  return 0;
}

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const positional = args.filter((a) => !a.startsWith("--"));
const doPush = flags.delete("--push");
const skipVerify = flags.delete("--no-verify");
if (flags.size > 0) fail(`unknown flag(s): ${[...flags].join(", ")}`);
if (positional.length !== 1) {
  fail("usage: node scripts/release.js <version> [--push] [--no-verify]");
}

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

console.log(`Releasing v${version} (from ${current})`);
for (const rel of PKG_FILES) {
  const p = join(ROOT, rel);
  const txt = readFileSync(p, "utf8");
  const next = txt.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`);
  if (next === txt) fail(`could not update "version" in ${rel}`);
  writeFileSync(p, next);
  console.log(`  bumped ${rel}`);
}

console.log("Syncing bun.lock...");
run("bun install");

if (!skipVerify) {
  console.log("Running test suite...");
  run("npm test");
}

run(`git add ${PKG_FILES.join(" ")} bun.lock`);
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
