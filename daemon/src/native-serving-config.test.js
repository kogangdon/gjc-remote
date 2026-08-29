import test from "node:test";
import assert from "node:assert/strict";

import {
  resolveReadinessMaxAgeMs,
  READINESS_MAX_AGE_ENV,
  DEFAULT_MAX_AGE_MS,
  MIN_MAX_AGE_MS,
  MAX_MAX_AGE_MS,
} from "./native-serving-config.js";

test("unset / empty env resolves to the default", () => {
  assert.deepEqual(resolveReadinessMaxAgeMs({ env: {} }), { ok: true, maxAgeMs: DEFAULT_MAX_AGE_MS });
  assert.deepEqual(resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: "" } }), {
    ok: true,
    maxAgeMs: DEFAULT_MAX_AGE_MS,
  });
});

test("a valid in-range integer is accepted verbatim", () => {
  assert.deepEqual(resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: "45000" } }), {
    ok: true,
    maxAgeMs: 45000,
  });
});

test("the minimum and maximum bounds are inclusive", () => {
  assert.deepEqual(resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: String(MIN_MAX_AGE_MS) } }), {
    ok: true,
    maxAgeMs: MIN_MAX_AGE_MS,
  });
  assert.deepEqual(resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: String(MAX_MAX_AGE_MS) } }), {
    ok: true,
    maxAgeMs: MAX_MAX_AGE_MS,
  });
});

test("just-below-min and just-above-max fail closed", () => {
  const below = resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: String(MIN_MAX_AGE_MS - 1) } });
  const above = resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: String(MAX_MAX_AGE_MS + 1) } });
  assert.equal(below.ok, false);
  assert.equal(below.diagnostic.code, "NATIVE_SERVING_CONFIG_INVALID");
  assert.equal(below.diagnostic.env, READINESS_MAX_AGE_ENV);
  assert.equal(above.ok, false);
});

test("non-integer / signed / decimal / unit forms fail closed", () => {
  for (const bad of ["abc", "-5000", "+5000", "1.5", "5000ms", "0x10", "1e4", " 5000 x", "NaN", "Infinity"]) {
    const result = resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: bad } });
    assert.equal(result.ok, false, `expected ${bad} to fail`);
    assert.equal(result.diagnostic.code, "NATIVE_SERVING_CONFIG_INVALID");
  }
});

test("surrounding whitespace around a valid integer is tolerated", () => {
  assert.deepEqual(resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: "  20000  " } }), {
    ok: true,
    maxAgeMs: 20000,
  });
});

test("an unsafe-integer magnitude fails closed before range check", () => {
  const huge = "9".repeat(20); // 10^20-ish, above MAX and beyond safe integer
  const result = resolveReadinessMaxAgeMs({ env: { [READINESS_MAX_AGE_ENV]: huge } });
  assert.equal(result.ok, false);
});
