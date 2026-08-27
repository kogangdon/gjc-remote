// WIRING slice S6f.1 (#53/#81): tests for workspace-recovery-boot-wiring.js.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  resolveWorkspaceRecoveryConfig,
  runBootRecovery,
} from "./workspace-recovery-boot-wiring.js";

test("resolveWorkspaceRecoveryConfig: unset env -> disabled", () => {
  const result = resolveWorkspaceRecoveryConfig({ env: {} });
  assert.deepEqual(result, { ok: true, enabled: false, workspaceRoot: null });
});

test("resolveWorkspaceRecoveryConfig: empty/whitespace -> disabled", () => {
  assert.deepEqual(
    resolveWorkspaceRecoveryConfig({ env: { GJC_NATIVE_WORKSPACE_ROOT: "" } }),
    { ok: true, enabled: false, workspaceRoot: null }
  );
  assert.deepEqual(
    resolveWorkspaceRecoveryConfig({ env: { GJC_NATIVE_WORKSPACE_ROOT: "   " } }),
    { ok: true, enabled: false, workspaceRoot: null }
  );
});

test("resolveWorkspaceRecoveryConfig: non-string -> fail closed, path-free", () => {
  const result = resolveWorkspaceRecoveryConfig({ env: { GJC_NATIVE_WORKSPACE_ROOT: 12345 } });
  assert.equal(result.ok, false);
  assert.equal(result.diagnostic.code, "WORKSPACE_RECOVERY_ROOT_INVALID");
  assert.ok(!JSON.stringify(result.diagnostic).includes("12345"));
});

test("resolveWorkspaceRecoveryConfig: relative path -> fail closed, path-free", () => {
  const result = resolveWorkspaceRecoveryConfig({ env: { GJC_NATIVE_WORKSPACE_ROOT: "workspaces" } });
  assert.equal(result.ok, false);
  assert.equal(result.diagnostic.code, "WORKSPACE_RECOVERY_ROOT_INVALID");
  assert.ok(!JSON.stringify(result.diagnostic).includes("workspaces"));
});

test("resolveWorkspaceRecoveryConfig: absolute path -> enabled", () => {
  const absolute = path.resolve(process.cwd(), "some-workspace-root");
  const result = resolveWorkspaceRecoveryConfig({ env: { GJC_NATIVE_WORKSPACE_ROOT: `  ${absolute}  ` } });
  assert.deepEqual(result, { ok: true, enabled: true, workspaceRoot: absolute });
});

test("runBootRecovery: workspaceRoot missing -> throws WORKSPACE_RECOVERY_BOOT_CONFIG_INVALID", async () => {
  await assert.rejects(
    () => runBootRecovery({}),
    (error) => {
      assert.equal(error.code, "WORKSPACE_RECOVERY_BOOT_CONFIG_INVALID");
      assert.equal(error.operation, "workspace_recovery_boot_wiring");
      return true;
    }
  );
});

test("runBootRecovery: happy path wires enumerate -> ioMap -> recover", async () => {
  const sentinelA = { id: "sentinel-a" };
  const sentinelB = { id: "sentinel-b" };
  const frozenResult = Object.freeze({
    admitted: 2,
    batchCount: 1,
    processed: Object.freeze([]),
    barredWorkspaceIds: Object.freeze(["b"]),
  });

  const readInputsCalls = [];
  const createPublisherIoCalls = [];
  let capturedRecoveryDeps;

  const deps = {
    enumerate: async ({ workspaceRoot }) => {
      assert.equal(workspaceRoot, "/fake/root");
      return ["a", "b"];
    },
    createPublisherIo: async ({ workspaceRoot, workspaceId }) => {
      createPublisherIoCalls.push({ workspaceRoot, workspaceId });
      return workspaceId === "a" ? sentinelA : sentinelB;
    },
    readInputs: async (args) => {
      readInputsCalls.push(args);
      return { workspaceId: args.workspaceId };
    },
    recover: async (recoveryDeps, workspaceIds) => {
      capturedRecoveryDeps = recoveryDeps;
      assert.deepEqual(workspaceIds, ["a", "b"]);
      // Assert publisherIo is SYNC and returns the pre-built sentinel.
      const ioA = recoveryDeps.publisherIo("a");
      const ioB = recoveryDeps.publisherIo("b");
      assert.equal(ioA, sentinelA);
      assert.equal(ioB, sentinelB);
      assert.ok(!(ioA instanceof Promise));
      assert.ok(!(ioB instanceof Promise));
      await recoveryDeps.readSnapshotInputs("a");
      return frozenResult;
    },
  };

  const result = await runBootRecovery({ workspaceRoot: "/fake/root", deps });

  assert.equal(result, frozenResult);
  assert.deepEqual(result.barredWorkspaceIds, ["b"]);
  assert.deepEqual(createPublisherIoCalls, [
    { workspaceRoot: "/fake/root", workspaceId: "a" },
    { workspaceRoot: "/fake/root", workspaceId: "b" },
  ]);
  assert.deepEqual(readInputsCalls, [{ workspaceRoot: "/fake/root", workspaceId: "a" }]);
  assert.ok(capturedRecoveryDeps);
});

test("runBootRecovery: queue-ceiling breach propagates unchanged", async () => {
  const ceilingError = new Error("workspace_recovery_queue: WORKSPACE_ADMISSION_EXCEEDED");
  ceilingError.code = "WORKSPACE_ADMISSION_EXCEEDED";

  const deps = {
    enumerate: async () => ["a"],
    createPublisherIo: async () => ({}),
    readInputs: async () => ({}),
    recover: async () => {
      throw ceilingError;
    },
  };

  await assert.rejects(
    () => runBootRecovery({ workspaceRoot: "/fake/root", deps }),
    (error) => {
      assert.equal(error, ceilingError);
      assert.equal(error.code, "WORKSPACE_ADMISSION_EXCEEDED");
      return true;
    }
  );
});

test("runBootRecovery: createPublisherIo rejects for one id -> fails closed", async () => {
  const deps = {
    enumerate: async () => ["a", "b"],
    createPublisherIo: async ({ workspaceId }) => {
      if (workspaceId === "b") throw new Error("boom");
      return {};
    },
    readInputs: async () => ({}),
    recover: async () => {
      throw new Error("recover must not be reached");
    },
  };

  await assert.rejects(() => runBootRecovery({ workspaceRoot: "/fake/root", deps }), /boom/);
});

test("runBootRecovery: real-fs empty root -> no barred workspaces", async (t) => {
  let tempDir;
  try {
    tempDir = await mkdtemp(path.join(os.tmpdir(), "gjc-recovery-boot-"));
    const result = await runBootRecovery({ workspaceRoot: tempDir });
    assert.deepEqual(result.barredWorkspaceIds, []);
    assert.deepEqual(result.processed, []);
    assert.equal(result.admitted, 0);
  } finally {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  }
});
