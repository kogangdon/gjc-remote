import test from "node:test";
import assert from "node:assert/strict";

import { resolveNativeServingBundles } from "./native-serving-boot-wiring.js";

const okBundles = () => ({ create: { __c: 1 }, refresh: { __r: 1 } });
const baseArgs = {
  gateEnabled: true,
  recoveryEnabled: true,
  workspaceRoot: "/ws/root",
  workspaceLeases: { acquireActivity() {} },
  env: {},
};

test("gate closed -> inert bundles, not a degradation", () => {
  const result = resolveNativeServingBundles({ ...baseArgs, gateEnabled: false, assemble: okBundles });
  assert.deepEqual(result, { create: null, refresh: null, degraded: false, diagnostic: null });
});

test("recovery disabled -> inert bundles, not a degradation", () => {
  const result = resolveNativeServingBundles({ ...baseArgs, recoveryEnabled: false, assemble: okBundles });
  assert.equal(result.degraded, false);
  assert.equal(result.create, null);
});

test("gate + recovery on with valid config -> assembled bundles", () => {
  let assembleArgs;
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: true, maxAgeMs: 30000 }),
    assemble: (args) => {
      assembleArgs = args;
      return okBundles();
    },
  });
  assert.equal(result.degraded, false);
  assert.deepEqual(result.create, { __c: 1 });
  assert.deepEqual(result.refresh, { __r: 1 });
  assert.deepEqual(assembleArgs, { workspaceRoot: "/ws/root", workspaceLeases: baseArgs.workspaceLeases, maxAgeMs: 30000 });
});

test("invalid readiness config -> degrade to null bundles with the config diagnostic", () => {
  const diagnostic = { code: "NATIVE_SERVING_CONFIG_INVALID", env: "GJC_...", reason: "out of range" };
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: false, diagnostic }),
    assemble: () => {
      throw new Error("assemble must not be called when config is invalid");
    },
  });
  assert.equal(result.degraded, true);
  assert.equal(result.create, null);
  assert.equal(result.refresh, null);
  assert.equal(result.diagnostic.code, "NATIVE_SERVING_CONFIG_INVALID");
  assert.equal(result.diagnostic.reason, "out of range");
});

test("assembly throw -> degrade to null bundles with sanitized code+reason", () => {
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: true, maxAgeMs: 30000 }),
    assemble: () => {
      throw Object.assign(new Error("native low-level unavailable"), { code: "NATIVE_ADDON_MISSING" });
    },
  });
  assert.equal(result.degraded, true);
  assert.equal(result.create, null);
  assert.equal(result.diagnostic.code, "NATIVE_ADDON_MISSING");
  assert.equal(result.diagnostic.reason, "native low-level unavailable");
});

test("assembly throw without a code -> generic fail-closed code", () => {
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: true, maxAgeMs: 30000 }),
    assemble: () => {
      throw new Error("boom");
    },
  });
  assert.equal(result.degraded, true);
  assert.equal(result.diagnostic.code, "NATIVE_SERVING_ASSEMBLY_FAILED");
});

test("the returned result and diagnostic are frozen", () => {
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: false, diagnostic: { code: "X" } }),
    assemble: okBundles,
  });
  assert.throws(() => {
    result.create = {};
  }, TypeError);
  assert.throws(() => {
    result.diagnostic.code = "Y";
  }, TypeError);
});
