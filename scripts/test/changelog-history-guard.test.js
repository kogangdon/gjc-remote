import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extractReleaseHeadings,
  findRemovedHeadings,
} from "../changelog-history-guard.mjs";

const CHANGELOG = `# Changelog

## [Unreleased]

## [0.3.0] - 2026-08-09

### Added

- Thing.

## [0.2.4] - 2026-07-01

- Older thing.
`;

test("extractReleaseHeadings finds every released version heading, not Unreleased", () => {
  const headings = extractReleaseHeadings(CHANGELOG);
  assert.deepEqual([...headings].sort(), ["0.2.4", "0.3.0"]);
});

test("extractReleaseHeadings returns an empty set for text with no headings", () => {
  assert.deepEqual([...extractReleaseHeadings("# Changelog\n\nnothing here\n")], []);
});

test("findRemovedHeadings passes when nothing changed", () => {
  assert.deepEqual(findRemovedHeadings(CHANGELOG, CHANGELOG), []);
});

test("findRemovedHeadings allows an added heading", () => {
  const withNewRelease = CHANGELOG.replace(
    "## [Unreleased]",
    "## [Unreleased]\n\n## [0.3.1] - 2026-08-10\n\n- New stuff."
  );
  assert.deepEqual(findRemovedHeadings(CHANGELOG, withNewRelease), []);
});

test("findRemovedHeadings detects a removed release heading", () => {
  const withoutOldRelease = CHANGELOG.replace(
    /## \[0\.2\.4\][\s\S]*$/,
    ""
  );
  assert.deepEqual(findRemovedHeadings(CHANGELOG, withoutOldRelease), ["0.2.4"]);
});

test("findRemovedHeadings detects every removed heading when the whole file is gone", () => {
  assert.deepEqual(findRemovedHeadings(CHANGELOG, ""), ["0.2.4", "0.3.0"]);
});
