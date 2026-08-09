import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extractReleaseHeadings,
  findRemovedHeadings,
  hasPriorReleasesSection,
  resolveBaseRef,
  resolvePushBaseRef,
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
// --- "### Prior releases" block protection -------------------------------------

const CHANGELOG_WITH_PRIOR_RELEASES = `${CHANGELOG}
### Prior releases

Releases before 0.3.0 (v0.2.0-v0.2.4) predate this changelog.
`;

test("hasPriorReleasesSection detects the heading", () => {
  assert.equal(hasPriorReleasesSection(CHANGELOG_WITH_PRIOR_RELEASES), true);
  assert.equal(hasPriorReleasesSection(CHANGELOG), false);
});

test("findRemovedHeadings flags a removed '### Prior releases' block", () => {
  const withoutPriorReleases = CHANGELOG_WITH_PRIOR_RELEASES.replace(
    /### Prior releases[\s\S]*$/,
    ""
  );
  assert.deepEqual(
    findRemovedHeadings(CHANGELOG_WITH_PRIOR_RELEASES, withoutPriorReleases),
    ["### Prior releases"]
  );
});

test("findRemovedHeadings allows '### Prior releases' when it never existed at base", () => {
  assert.deepEqual(findRemovedHeadings(CHANGELOG, CHANGELOG), []);
});

test("findRemovedHeadings combines removed version headings and a removed prior-releases block", () => {
  const gutted = CHANGELOG_WITH_PRIOR_RELEASES.replace(/## \[0\.2\.4\][\s\S]*$/, "");
  assert.deepEqual(findRemovedHeadings(CHANGELOG_WITH_PRIOR_RELEASES, gutted), [
    "0.2.4",
    "### Prior releases",
  ]);
});

// --- resolveBaseRef (pr mode) ---------------------------------------------------

test("resolveBaseRef prefers origin/main when it already exists locally", () => {
  const ref = resolveBaseRef({
    refExists: (r) => r === "origin/main",
    fetchOriginMain: () => {
      throw new Error("should not fetch when origin/main already resolves");
    },
  });
  assert.equal(ref, "origin/main");
});

test("resolveBaseRef fetches origin/main when it's missing, then re-checks", () => {
  let fetched = false;
  let checks = 0;
  const ref = resolveBaseRef({
    refExists: (r) => {
      checks += 1;
      if (r !== "origin/main") return false;
      return fetched;
    },
    fetchOriginMain: () => {
      fetched = true;
    },
  });
  assert.equal(ref, "origin/main");
  assert.ok(checks >= 2);
});

test("resolveBaseRef falls back to local main when origin/main never resolves", () => {
  const ref = resolveBaseRef({
    refExists: (r) => r === "main",
    fetchOriginMain: () => {
      throw new Error("offline");
    },
  });
  assert.equal(ref, "main");
});

test("resolveBaseRef throws with a diagnostic listing every ref it tried", () => {
  assert.throws(
    () =>
      resolveBaseRef({
        refExists: () => false,
        fetchOriginMain: () => {
          throw new Error("offline");
        },
      }),
    /origin\/main.*main.*--base/s
  );
});

// --- resolvePushBaseRef (push mode) ---------------------------------------------

test("resolvePushBaseRef prefers the previous tag reachable from HEAD~1", () => {
  const ref = resolvePushBaseRef({
    describePreviousTag: () => "v0.2.4",
    refExists: () => {
      throw new Error("should not need to check HEAD~1 when a tag resolves");
    },
  });
  assert.equal(ref, "v0.2.4");
});

test("resolvePushBaseRef falls back to HEAD~1 when no tag is reachable", () => {
  const ref = resolvePushBaseRef({
    describePreviousTag: () => {
      throw new Error("no tag reachable from HEAD~1");
    },
    refExists: (r) => r === "HEAD~1",
  });
  assert.equal(ref, "HEAD~1");
});

test("resolvePushBaseRef throws when there is no previous commit or tag", () => {
  assert.throws(
    () =>
      resolvePushBaseRef({
        describePreviousTag: () => {
          throw new Error("no tag");
        },
        refExists: () => false,
      }),
    /could not resolve a previous commit or tag/
  );
});
