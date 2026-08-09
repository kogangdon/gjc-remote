import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ALLOWED_STAGED_PATHS,
  checkFlagExclusivity,
  cmpCore,
  findDisallowedPaths,
  findUnexpectedPackageJsonKeys,
  promoteChangelog,
} from "../release.js";

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
