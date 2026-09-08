import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { GJC_SKILLS } from "../src/skills.js";

test("Discord skill commands match the installed SDK bundled catalog", () => {
  const result = spawnSync("bun", [
    "-e",
    'import { DEFAULT_GJC_DEFINITION_NAMES } from "@gajae-code/coding-agent/defaults/gjc-defaults"; console.log(JSON.stringify(DEFAULT_GJC_DEFINITION_NAMES));',
  ], {
    cwd: fileURLToPath(new URL("../../daemon/", import.meta.url)),
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const names = GJC_SKILLS.map(({ name }) => name);
  assert.equal(new Set(names).size, names.length);
  assert.deepEqual(names.toSorted(), JSON.parse(result.stdout).toSorted());
  for (const { description } of GJC_SKILLS) {
    assert.ok(description.length > 0 && description.length <= 100);
  }
});
