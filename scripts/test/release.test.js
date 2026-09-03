import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  ALLOWED_STAGED_PATHS,
  checkFlagExclusivity,
  cmpCore,
  findDisallowedPaths,
  findUnexpectedLockfileDiffLines,
  findUnexpectedPackageJsonKeys,
  parseCliArgs,
  promoteChangelog,
} from "../release.js";

test("tag workflow creates only a draft release", async () => {
  const workflow = (
    await readFile(new URL("../../.github/workflows/release.yml", import.meta.url), "utf8")
  ).replaceAll("\r\n", "\n");
  assert.equal(workflow.match(/\bgh release create\b/g)?.length, 1);
  assert.match(workflow, /name: Create draft GitHub Release/);
  const command = workflow.match(
    /run: >-\n((?: {10}.+\n)+)/,
  )?.[1];
  assert.ok(command);
  assert.match(command, /gh release create "\$GITHUB_REF_NAME"/);
  assert.match(command, /--draft/);
  assert.doesNotMatch(
    workflow,
    /\bgh release edit\b/,
  );
});

// --- --no-verify / --push exclusivity ---------------------------------------

test("checkFlagExclusivity rejects --no-verify combined with --push", () => {
  const msg = checkFlagExclusivity(true, true);
  assert.match(msg, /--no-verify/);
  assert.match(msg, /--push/);
});

test("checkFlagExclusivity allows --no-verify without --push (local dry run)", () => {
  assert.equal(checkFlagExclusivity(true, false), null);
});

test("checkFlagExclusivity allows --push without --no-verify", () => {
  assert.equal(checkFlagExclusivity(false, true), null);
});

test("checkFlagExclusivity allows neither flag", () => {
  assert.equal(checkFlagExclusivity(false, false), null);
});

// --- staged-diff whitelist ----------------------------------------------------

test("findDisallowedPaths is empty when every staged file is allowed", () => {
  const staged = ["package.json", "bot/package.json", "bun.lock", "CHANGELOG.md"];
  assert.deepEqual(findDisallowedPaths(staged, ALLOWED_STAGED_PATHS), []);
});

test("findDisallowedPaths flags any path outside the whitelist", () => {
  const staged = ["package.json", "bot/src/bot.js"];
  assert.deepEqual(findDisallowedPaths(staged, ALLOWED_STAGED_PATHS), ["bot/src/bot.js"]);
});

test("findUnexpectedPackageJsonKeys is empty when only version changed", () => {
  const before = { name: "x", version: "0.2.0", private: true };
  const after = { name: "x", version: "0.3.0", private: true };
  assert.deepEqual(findUnexpectedPackageJsonKeys(before, after), []);
});

test("findUnexpectedPackageJsonKeys reports keys that changed besides version", () => {
  const before = { name: "x", version: "0.2.0", dependencies: { a: "1" } };
  const after = { name: "x", version: "0.3.0", dependencies: { a: "2" } };
  assert.deepEqual(findUnexpectedPackageJsonKeys(before, after), ["dependencies"]);
});

test("findUnexpectedPackageJsonKeys reports an added key", () => {
  const before = { name: "x", version: "0.2.0" };
  const after = { name: "x", version: "0.3.0", engines: { node: ">=26" } };
  assert.deepEqual(findUnexpectedPackageJsonKeys(before, after), ["engines"]);
});

// --- cmpCore -------------------------------------------------------------------

test("cmpCore orders by numeric core, ignoring prerelease", () => {
  assert.ok(cmpCore("0.3.0", "0.2.4") > 0);
  assert.ok(cmpCore("0.2.4", "0.3.0") < 0);
  assert.equal(cmpCore("0.3.0", "0.3.0"), 0);
  assert.equal(cmpCore("0.3.0-rc.1", "0.3.0"), 0);
});

// --- changelog promotion --------------------------------------------------------

const SAMPLE_CHANGELOG = `# Changelog

## [Unreleased]

### Added

- New thing.

## [0.2.4] - 2026-07-01

- Old thing.
`;

test("promoteChangelog moves Unreleased content into a new dated section", () => {
  const result = promoteChangelog(SAMPLE_CHANGELOG, "0.3.0", "2026-08-09");
  assert.equal(result.error, undefined);
  assert.match(result.text, /## \[Unreleased\]\n\n## \[0\.3\.0\] - 2026-08-09/);
  assert.match(result.text, /### Added\n\n- New thing\./);
  // Old release section is preserved, unchanged.
  assert.match(result.text, /## \[0\.2\.4\] - 2026-07-01\n\n- Old thing\./);
});

test("promoteChangelog leaves a fresh, empty Unreleased section behind", () => {
  const result = promoteChangelog(SAMPLE_CHANGELOG, "0.3.0", "2026-08-09");
  const unreleasedIdx = result.text.indexOf("## [Unreleased]");
  const nextHeadingIdx = result.text.indexOf("## [0.3.0]");
  const between = result.text.slice(unreleasedIdx + "## [Unreleased]".length, nextHeadingIdx).trim();
  assert.equal(between, "");
});

test("promoteChangelog fails when Unreleased has no content", () => {
  const empty = "# Changelog\n\n## [Unreleased]\n\n## [0.2.4] - 2026-07-01\n\n- Old thing.\n";
  const result = promoteChangelog(empty, "0.3.0", "2026-08-09");
  assert.match(result.error, /empty/);
  assert.equal(result.text, undefined);
});

test("promoteChangelog fails when there is no Unreleased heading at all", () => {
  const noHeading = "# Changelog\n\n## [0.2.4] - 2026-07-01\n\n- Old thing.\n";
  const result = promoteChangelog(noHeading, "0.3.0", "2026-08-09");
  assert.match(result.error, /no "## \[Unreleased\]" heading/);
});

test("promoteChangelog handles Unreleased as the only/last section", () => {
  const onlySection = "# Changelog\n\n## [Unreleased]\n\n- Only thing.\n";
  const result = promoteChangelog(onlySection, "0.1.0", "2026-08-09");
  assert.equal(result.error, undefined);
  assert.match(result.text, /## \[Unreleased\]\n\n## \[0\.1\.0\] - 2026-08-09\n\n- Only thing\./);
});
// --- promoteChangelog: duplicate release section ------------------------------

test("promoteChangelog refuses a duplicate release heading", () => {
  const withHandWritten = `# Changelog

## [Unreleased]

### Added

- New thing.

## [0.3.0] - 2026-08-09

- Hand-written section already here.

## [0.2.4] - 2026-07-01

- Old thing.
`;
  const result = promoteChangelog(withHandWritten, "0.3.0", "2026-08-10");
  assert.match(result.error, /already has a "## \[0\.3\.0\]" section/);
  assert.equal(result.text, undefined);
});

test("promoteChangelog allows a version that doesn't already exist", () => {
  const result = promoteChangelog(SAMPLE_CHANGELOG, "0.3.0", "2026-08-09");
  assert.equal(result.error, undefined);
});

// --- findUnexpectedLockfileDiffLines ------------------------------------------

test("findUnexpectedLockfileDiffLines is empty for a clean version-only diff", () => {
  const diff = [
    "diff --git a/bun.lock b/bun.lock",
    "--- a/bun.lock",
    "+++ b/bun.lock",
    "@@ -8,7 +8,7 @@",
    '-      "version": "0.2.4",',
    '+      "version": "0.3.0",',
  ].join("\n");
  assert.deepEqual(findUnexpectedLockfileDiffLines(diff, "0.3.0"), []);
});

test("findUnexpectedLockfileDiffLines flags an added line that isn't a version bump", () => {
  const diff = [
    "--- a/bun.lock",
    "+++ b/bun.lock",
    '-      "version": "0.2.4",',
    '+      "version": "0.3.0",',
    '+      "private": true,',
  ].join("\n");
  const flagged = findUnexpectedLockfileDiffLines(diff, "0.3.0");
  assert.equal(flagged.length, 1);
  assert.match(flagged[0], /"private": true/);
});

test("findUnexpectedLockfileDiffLines flags an added version line with the wrong value", () => {
  const diff = ['+      "version": "9.9.9",'].join("\n");
  const flagged = findUnexpectedLockfileDiffLines(diff, "0.3.0");
  assert.equal(flagged.length, 1);
});

test("findUnexpectedLockfileDiffLines ignores +++/--- file headers", () => {
  const diff = ["--- a/bun.lock", "+++ b/bun.lock"].join("\n");
  assert.deepEqual(findUnexpectedLockfileDiffLines(diff, "0.3.0"), []);
});

// --- parseCliArgs: CLI wiring --------------------------------------------------

test("parseCliArgs accepts a bare version and strips a leading 'v'", () => {
  const result = parseCliArgs(["v0.3.1"]);
  assert.deepEqual(result, { version: "0.3.1", doPush: false, skipVerify: false });
});

test("parseCliArgs recognizes --push and --no-verify regardless of order", () => {
  assert.deepEqual(parseCliArgs(["--push", "0.3.1"]), {
    version: "0.3.1",
    doPush: true,
    skipVerify: false,
  });
  assert.deepEqual(parseCliArgs(["0.3.1", "--no-verify"]), {
    version: "0.3.1",
    doPush: false,
    skipVerify: true,
  });
});

test("parseCliArgs rejects an unknown flag", () => {
  const result = parseCliArgs(["0.3.1", "--force"]);
  assert.match(result.error, /unknown flag\(s\): --force/);
});

test("parseCliArgs rejects zero positional arguments", () => {
  const result = parseCliArgs([]);
  assert.match(result.error, /usage: node scripts\/release\.js/);
});

test("parseCliArgs rejects more than one positional argument", () => {
  const result = parseCliArgs(["0.3.1", "0.3.2"]);
  assert.match(result.error, /usage: node scripts\/release\.js/);
});

test("parseCliArgs rejects --no-verify combined with --push", () => {
  const result = parseCliArgs(["0.3.1", "--no-verify", "--push"]);
  assert.match(result.error, /--no-verify.*--push/s);
});

test("parseCliArgs rejects an invalid semver", () => {
  const result = parseCliArgs(["not-a-version"]);
  assert.match(result.error, /invalid semver: not-a-version/);
});

test("parseCliArgs treats a repeated flag as a single flag (Set semantics)", () => {
  const result = parseCliArgs(["0.3.1", "--push", "--push"]);
  assert.deepEqual(result, { version: "0.3.1", doPush: true, skipVerify: false });
});
