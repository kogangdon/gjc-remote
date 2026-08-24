import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  REMOVED_DEV_FLAGS,
  detectRemovedDevFlags,
  assertNoRemovedDevFlags,
} from "../src/workspace-removed-flags.js";

const NAMES = REMOVED_DEV_FLAGS.map((f) => f.name);

test("the two retired flags and their distinct gates are the registry", () => {
  assert.deepEqual([...NAMES].sort(), ["GJC_DEV_CONNECTIVITY_PROBE", "GJC_DEV_NATIVE_SINGLE_WRITER_LOCK"]);
  const gates = REMOVED_DEV_FLAGS.map((f) => f.gate).sort();
  assert.deepEqual(gates, ["FINAL_LEASE_FENCE_TESTS_PASS", "FULL_GRAPH_PUBLICATION_TESTS_PASS"]);
  // registry and its entries are frozen
  assert.ok(Object.isFrozen(REMOVED_DEV_FLAGS));
  for (const f of REMOVED_DEV_FLAGS) assert.ok(Object.isFrozen(f));
});

test("a clean environment produces no violations and does not exit", () => {
  assert.deepEqual(detectRemovedDevFlags({}), []);
  let exited = false;
  const n = assertNoRemovedDevFlags({ HOST_ID: "x" }, { logError: () => {}, exit: () => { exited = true; } });
  assert.equal(n, 0);
  assert.equal(exited, false);
});

test("presence-based rejection: each flag at any value (1, 0, empty) is a violation with per-gate unique evidence", () => {
  for (const flag of REMOVED_DEV_FLAGS) {
    for (const value of ["1", "0", "", "anything"]) {
      const found = detectRemovedDevFlags({ [flag.name]: value });
      assert.equal(found.length, 1, `${flag.name}=${JSON.stringify(value)} must be rejected`);
      assert.equal(found[0].name, flag.name);
      assert.equal(found[0].gate, flag.gate);
      // per-gate unique evidence: message names both the flag and its distinct retired gate
      assert.match(found[0].message, new RegExp(flag.name));
      assert.match(found[0].message, new RegExp(flag.gate));
    }
  }
});

test("both flags present are both reported, in registry order, and the guard exits(1) once", () => {
  const env = { GJC_DEV_CONNECTIVITY_PROBE: "0", GJC_DEV_NATIVE_SINGLE_WRITER_LOCK: "1" };
  const found = detectRemovedDevFlags(env);
  assert.deepEqual(found.map((v) => v.name), NAMES); // registry order
  const messages = [];
  let exitCode = null;
  let exitCalls = 0;
  const n = assertNoRemovedDevFlags(env, { logError: (m) => messages.push(m), exit: (c) => { exitCode = c; exitCalls += 1; } });
  assert.equal(n, 2);
  assert.equal(exitCalls, 1);
  assert.equal(exitCode, 1);
  assert.equal(messages.length, 2, "one unique diagnostic per removed flag");
  // the two messages are distinct (per-gate unique evidence, not interchangeable)
  assert.notEqual(messages[0], messages[1]);
});

test("the two flag names do not appear in daemon/.env.example", async () => {
  const env = await readFile(fileURLToPath(new URL("../.env.example", import.meta.url)), "utf8");
  for (const name of NAMES) {
    assert.ok(!env.includes(name), `${name} must be absent from .env.example`);
  }
});
