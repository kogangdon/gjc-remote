import test from "node:test";
import assert from "node:assert/strict";

import { resolveNativeServingBundles } from "./native-serving-boot-wiring.js";

const okBundles = () => ({
  create: { __c: 1 },
  refresh: { __r: 1 },
  resetDelete: {
    __d: 1,
    makePublisherIo() {},
    makeBackupIo() {},
    resolveManifestPaths() {},
    acquireFence() {},
    residualIo: { listResidualProcesses() {} },
  },
  restoreMigration: restoreMigrationBundle(),
});
function restoreMigrationBundle(overrides = {}) {
  return Object.freeze({
    containment: { identifyRoot() {}, verifyContained() {} },
    gitVerifier: { verifyRepositoryGraph() {} },
    stagePromotion: { materializeAndVerify() {}, cleanup() {} },
    makeStageReader() {},
    makePublisherIo() {},
    acquireFence() {},
    clock: { now() { return 1; } },
    maxAgeMs: 30_000,
    replaySeen: { has() {}, add() {} },
    ...overrides,
  });
}
const baseArgs = {
  gateEnabled: true,
  recoveryEnabled: true,
  workspaceRoot: "/ws/root",
  workspaceLeases: { acquireActivity() {} },
  hostId: "host-1",
  sourcePlatform: "posix",
  env: {},
};

test("gate closed -> inert bundles, not a degradation", () => {
  const result = resolveNativeServingBundles({ ...baseArgs, gateEnabled: false, assemble: okBundles });
  assert.deepEqual(result, {
    create: null,
    refresh: null,
    resetDelete: null,
    restoreMigration: null,
    degraded: false,
    diagnostic: null,
  });
});

test("recovery disabled -> inert bundles, not a degradation", () => {
  const result = resolveNativeServingBundles({ ...baseArgs, recoveryEnabled: false, assemble: okBundles });
  assert.equal(result.degraded, false);
  assert.equal(result.create, null);
  assert.equal(result.resetDelete, null);
  assert.equal(result.restoreMigration, null);
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
  assert.equal(result.resetDelete.__d, 1);
  assert.ok(result.restoreMigration);
  assert.deepEqual(assembleArgs, {
    workspaceRoot: "/ws/root",
    workspaceLeases: baseArgs.workspaceLeases,
    maxAgeMs: 30000,
    hostId: "host-1",
    sourcePlatform: "posix",
  });
});

test("invalid readiness config -> sanitized degradation with null bundles", () => {
  const diagnostic = { code: "NATIVE_SERVING_CONFIG_INVALID", env: "GJC_...", reason: "out of range", secret: "nope" };
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
  assert.equal(result.resetDelete, null);
  assert.equal(result.restoreMigration, null);
  assert.equal(result.diagnostic.code, "NATIVE_SERVING_CONFIG_INVALID");
  assert.equal(result.diagnostic.reason, "out of range");
  assert.equal("secret" in result.diagnostic, false);
});

test("assembly throw -> degrades with a sanitized code and no raw error text", () => {
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: true, maxAgeMs: 30000 }),
    assemble: () => {
      throw Object.assign(new Error("native low-level unavailable"), { code: "NATIVE_ADDON_MISSING" });
    },
  });
  assert.equal(result.degraded, true);
  assert.equal(result.create, null);
  assert.equal(result.refresh, null);
  assert.equal(result.resetDelete, null);
  assert.equal(result.diagnostic.code, "NATIVE_ADDON_MISSING");
  assert.equal(result.diagnostic.reason, "native serving deps assembly failed");
});

test("an unavailable reset/delete bundle leaves create and refresh serving", () => {
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: true, maxAgeMs: 30000 }),
    assemble: () => ({ create: { __c: 1 }, refresh: { __r: 1 }, resetDelete: null }),
  });
  assert.equal(result.degraded, false);
  assert.deepEqual(result.create, { __c: 1 });
  assert.deepEqual(result.refresh, { __r: 1 });
  assert.equal(result.resetDelete, null);
});

test("an incomplete reset/delete bundle stays inert without regressing create or refresh", () => {
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: true, maxAgeMs: 30000 }),
    assemble: () => ({
      create: { __c: 1 },
      refresh: { __r: 1 },
      resetDelete: { makePublisherIo() {} },
    }),
  });
  assert.equal(result.degraded, false);
  assert.deepEqual(result.create, { __c: 1 });
  assert.deepEqual(result.refresh, { __r: 1 });
  assert.equal(result.resetDelete, null);
});

test("a malformed restore-only bundle stays inert without degrading other operations", () => {
  const result = resolveNativeServingBundles({
    ...baseArgs,
    resolveMaxAge: () => ({ ok: true, maxAgeMs: 30000 }),
    assemble: () => ({
      create: { __c: 1 },
      refresh: { __r: 1 },
      resetDelete: null,
      restoreMigration: { makePublisherIo() {} },
    }),
  });
  assert.equal(result.degraded, false);
  assert.deepEqual(result.create, { __c: 1 });
  assert.deepEqual(result.refresh, { __r: 1 });
  assert.equal(result.restoreMigration, null);
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
