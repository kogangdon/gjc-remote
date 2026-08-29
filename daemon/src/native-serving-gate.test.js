import test from "node:test";
import assert from "node:assert/strict";
import { resolveNativeServingEnabled } from "./native-serving-gate.js";

// Slice S6f.7a: the pure gate-decision function. It is fail-closed and
// multiplicative -- serving is eligible only when the env opt-in is EXACTLY
// "1" AND inventoryReceiptAdvertised is EXACTLY boolean true.

function gate(rawEnvValue, inventoryReceiptAdvertised) {
  const env = rawEnvValue === undefined ? {} : { GJC_NATIVE_WORKSPACE_SERVING: rawEnvValue };
  return resolveNativeServingEnabled({ env, inventoryReceiptAdvertised });
}

test("enabled only for the exact string \"1\" with inventory receipt advertised", () => {
  assert.equal(gate("1", true), true);
});

test("env opt-in fails closed for every non-\"1\" value (pre-mortem #2 matrix)", () => {
  // Each of these MUST read as disabled even when inventory is advertised.
  const disabledValues = [
    undefined, // unset
    "", // empty
    " ", // whitespace
    "  ", // more whitespace
    "0",
    "false",
    "true",
    "TRUE",
    "1 ", // trailing space
    " 1", // leading space
    "01",
    "10",
    "yes",
    "on",
    "enabled",
  ];
  for (const value of disabledValues) {
    assert.equal(gate(value, true), false, `env value ${JSON.stringify(value)} must fail closed`);
  }
});

test("a non-string env value never enables serving (=== \"1\" is strict)", () => {
  // process.env values are strings, but guard the strict-equality contract.
  for (const value of [1, 1n, true, {}, ["1"], Symbol("1")]) {
    assert.equal(
      resolveNativeServingEnabled({ env: { GJC_NATIVE_WORKSPACE_SERVING: value }, inventoryReceiptAdvertised: true }),
      false,
      `non-string env value ${String(value)} must fail closed`,
    );
  }
});

test("inventoryReceiptAdvertised must be exactly boolean true", () => {
  assert.equal(gate("1", true), true);
  // Falsy, missing, and truthy-but-non-true values all fail closed.
  for (const advertised of [false, undefined, null, 0, "", "true", 1, {}, "1"]) {
    assert.equal(gate("1", advertised), false, `advertised ${JSON.stringify(advertised)} must fail closed`);
  }
});

test("both terms are required (AND, not OR)", () => {
  assert.equal(gate("1", false), false); // env on, inventory off
  assert.equal(gate("0", true), false); // env off, inventory on
  assert.equal(gate("0", false), false); // both off
  assert.equal(gate("1", true), true); // both on
});

test("missing or malformed input objects fail closed rather than throw", () => {
  assert.equal(resolveNativeServingEnabled(), false);
  assert.equal(resolveNativeServingEnabled({}), false);
  assert.equal(resolveNativeServingEnabled({ env: undefined, inventoryReceiptAdvertised: true }), false);
  assert.equal(resolveNativeServingEnabled({ env: null, inventoryReceiptAdvertised: true }), false);
  assert.equal(
    resolveNativeServingEnabled({ env: {}, inventoryReceiptAdvertised: true }),
    false,
    "env object without the opt-in key must fail closed",
  );
});
