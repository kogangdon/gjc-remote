import assert from "node:assert/strict";
import test from "node:test";

import {
  buildWorkspaceInventory,
  workspaceInventoryBytes,
} from "@gjc-remote/shared/workspace-inventory";
import { createWorkspaceInventoryProvider } from "../src/workspace-inventory-provider.js";

const builtInventoryDocument = buildWorkspaceInventory({
  hostId: "provider-test-host",
  inventoryGeneration: 1,
  workspaces: [],
});
const inventoryDocument = Object.freeze({
  ...builtInventoryDocument,
  workspaces: Object.freeze(
    builtInventoryDocument.workspaces.map((workspace) =>
      Object.freeze({ ...workspace }))),
});
const inventory = workspaceInventoryBytes(inventoryDocument).toString("utf8");

function nativeResult(result) {
  return Object.freeze({
    selfTest: async () => {},
    readAccepted: async () => result,
  });
}

function nativeError(error) {
  return Object.freeze({
    selfTest: async () => {},
    readAccepted: async () => { throw error; },
  });
}

function nativePresent() {
  return Object.freeze({
    status: "present",
    inventory: inventoryDocument,
    proof: Object.freeze({
      source: "native",
      inventoryGeneration: 1,
      inventoryFingerprint: inventoryDocument.inventoryFingerprint,
      commitFingerprint: "c".repeat(64),
      floorFingerprint: "d".repeat(64),
    }),
  });
}

test("raw inventory and status are rejected outside explicit test injection", () => {
  for (const options of [
    { serializedTestInventory: inventory },
    { testStatus: "stale" },
    { testEpochMismatch: true },
    { testInjectionEnabled: "true" },
    { testEpochMismatch: 1, testInjectionEnabled: true },
    { testStatus: 1, testInjectionEnabled: true },
  ]) {
    assert.throws(
      () => createWorkspaceInventoryProvider(options),
      (error) => error?.code === "CONFIG_INVALID"
    );
  }
});

test("legacy test injection remains explicit and proof-bearing", async () => {
  const provider = createWorkspaceInventoryProvider({
    testInjectionEnabled: true,
    serializedTestInventory: inventory,
  });
  assert.equal(provider.receiptCapable, true);
  const result = await provider.read();
  assert.equal(result.status, "present");
  assert.equal(result.inventory.inventoryGeneration, 1);
  assert.deepEqual(result.proof, { source: "test-injection" });
});

test("native Reader and serialized or status test injection are exclusive before reads", () => {
  let calls = 0;
  const reader = Object.freeze({
    selfTest: async () => {},
    readAccepted: async () => { calls += 1; },
  });
  for (const options of [
    { testInjectionEnabled: true },
    { serializedTestInventory: inventory, testInjectionEnabled: true },
    { testStatus: "stale", testInjectionEnabled: true },
    { testEpochMismatch: true, testInjectionEnabled: true },
  ]) {
    assert.throws(
      () => createWorkspaceInventoryProvider({ reader, ...options }),
      (error) => error?.code === "CONFIG_INVALID"
    );
  }
  assert.equal(calls, 0);
});

test("default production boundary remains exact missing and not receipt capable", async () => {
  const provider = createWorkspaceInventoryProvider();
  assert.equal(provider.receiptCapable, false);
  assert.deepEqual(await provider.read(), { status: "missing" });
});

test("native Reader provider is receipt capable and preserves floor epochs", async () => {
  const provider = createWorkspaceInventoryProvider({ reader: nativeResult(nativePresent()) });
  assert.equal(provider.receiptCapable, true);
  const first = await provider.read();
  const second = await provider.read();
  assert.deepEqual(first, {
    status: "present",
    inventory: inventoryDocument,
    epoch: 1,
    proof: {
      source: "native",
      inventoryGeneration: 1,
      inventoryFingerprint: inventoryDocument.inventoryFingerprint,
      commitFingerprint: "c".repeat(64),
      floorFingerprint: "d".repeat(64),
    },
  });
  assert.deepEqual(second, first);
});

test("native Reader maps missing and known errors", async () => {
  const missing = createWorkspaceInventoryProvider({
    reader: nativeResult(Object.freeze({ status: "missing" })),
  });
  assert.deepEqual(await missing.read(), { status: "missing", epoch: 1 });
  const error = Object.assign(new Error("stale"), {
    code: "INVENTORY_STALE",
    operation: "read_inventory",
    writes: 0,
    ambiguous: false,
  });
  const failed = createWorkspaceInventoryProvider({
    reader: nativeError(error),
  });
  assert.deepEqual(await failed.read(), {
    status: "stale",
    code: "INVENTORY_STALE",
    epoch: 1,
  });
});

test("native Reader rejects malformed, accessor, and proxy inputs deterministically", () => {
  for (const reader of [
    {},
    Object.freeze(Object.defineProperties({}, {
      selfTest: { enumerable: true, value: async () => {} },
      readAccepted: { enumerable: true, get: () => async () => {} },
    })),
    new Proxy(Object.freeze({
      selfTest: async () => {},
      readAccepted: async () => {},
    }), { getOwnPropertyDescriptor() { throw new Error("trap"); } }),
  ]) {
    assert.throws(
      () => createWorkspaceInventoryProvider({ reader }),
      (error) => error?.code === "CONFIG_INVALID"
    );
  }
  for (const options of [
    { nativeReader: nativeResult(nativePresent()) },
    Object.defineProperty({}, "reader", {
      enumerable: true,
      get: () => nativeResult(nativePresent()),
    }),
    new Proxy({}, {
      ownKeys() { throw new Error("trap"); },
    }),
  ]) {
    assert.throws(
      () => createWorkspaceInventoryProvider(options),
      (error) => error?.code === "CONFIG_INVALID",
    );
  }
});

test("authority-bearing v1 inventory is not accepted as a fallback", () => {
  assert.throws(
    () => createWorkspaceInventoryProvider({
      testInjectionEnabled: true,
      serializedTestInventory: JSON.stringify({
        version: 1,
        inventoryGeneration: 1,
        workspaces: [],
      }),
    }),
    /WORKSPACE_INVENTORY_INVALID/,
  );
});
