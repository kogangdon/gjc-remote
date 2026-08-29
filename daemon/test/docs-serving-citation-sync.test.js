import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// S6f.0 docs-sync guard: the two Phase 2 verification/implementation docs cite the
// `NATIVE_WORKSPACE_SERVING_ENABLED` serving-gate definition by an absolute
// daemon/src/daemon.js:<line> reference. Those citations silently drift whenever the
// file shifts (this exact drift produced the stale :199 reference S6f.0 reconciled).
// This test derives the real definition line from source and fails CI on any doc
// citation that references the gate const but points at the wrong line.

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const daemonSrc = join(repoRoot, "daemon", "src", "daemon.js");
const docPaths = [
  join(repoRoot, "docs", "daemon-workspace-verification.md"),
  join(repoRoot, "docs", "daemon-workspace-implementation-phases.md"),
];

const GATE_CONST = "NATIVE_WORKSPACE_SERVING_ENABLED";
// S6f.7f: the gate is now an env-gated resolveNativeServingEnabled(...) call, not
// a `= false` literal. Anchor on the `const <GATE_CONST> =` definition prefix so
// the docs-sync guard survives the RHS flip and any future RHS reshaping.
const GATE_DEFINITION_PREFIX = `const ${GATE_CONST} =`;

function gateDefinitionLine() {
  const lines = readFileSync(daemonSrc, "utf8").split(/\r?\n/);
  const matches = lines
    .map((line, i) => (line.trim().startsWith(GATE_DEFINITION_PREFIX) ? i : -1))
    .filter((i) => i !== -1);
  assert.notEqual(
    matches.length,
    0,
    `serving-gate definition "${GATE_DEFINITION_PREFIX} ..." not found in daemon/src/daemon.js`,
  );
  assert.equal(
    matches.length,
    1,
    `expected exactly one "${GATE_DEFINITION_PREFIX} ..." definition line in daemon/src/daemon.js, found ${matches.length}`,
  );
  return matches[0] + 1;
}

test("docs cite the current NATIVE_WORKSPACE_SERVING_ENABLED definition line", () => {
  const gateLine = gateDefinitionLine();
  const citation = /daemon\/src\/daemon\.js:(\d+)/g;
  let assertedCitations = 0;

  for (const docPath of docPaths) {
    const lines = readFileSync(docPath, "utf8").split(/\r?\n/);
    for (const line of lines) {
      if (!line.includes(GATE_CONST)) continue;
      citation.lastIndex = 0;
      let match;
      while ((match = citation.exec(line)) !== null) {
        assertedCitations += 1;
        assert.equal(
          Number(match[1]),
          gateLine,
          `${docPath}: citation daemon/src/daemon.js:${match[1]} sits on a ${GATE_CONST} line ` +
            `but the real definition is at line ${gateLine}; update the doc citation.`,
        );
      }
    }
  }

  // Guard the guard: if the citation phrasing ever moves off the const line, this test
  // would silently pass without checking anything. Require at least one real citation.
  assert.ok(
    assertedCitations >= 2,
    `expected at least 2 gate-line citations across the Phase 2 docs, found ${assertedCitations}; ` +
      `the docs-sync guard is no longer covering the ${GATE_CONST} citations.`,
  );
});
