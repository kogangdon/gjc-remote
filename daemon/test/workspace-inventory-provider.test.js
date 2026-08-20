import assert from "node:assert/strict";
import test from "node:test";

import {
  buildWorkspaceInventory,
  workspaceInventoryBytes,
} from "@gjc-remote/shared/workspace-inventory";
import { createWorkspaceInventoryProvider } from "../src/workspace-inventory-provider.js";

const inventory = workspaceInventoryBytes(buildWorkspaceInventory({
  hostId: "provider-test-host",
  inventoryGeneration: 1,
  workspaces: [],
})).toString("utf8");

test("raw inventory is rejected outside explicit test injection", () => {
  assert.throws(
    () =>
      createWorkspaceInventoryProvider({
        serializedTestInventory: inventory,
      }),
    (error) => error?.code === "CONFIG_INVALID"
  );
});

test("test inventory provider returns parsed proof-bearing evidence", async () => {
  const provider = createWorkspaceInventoryProvider({
    testInjectionEnabled: true,
    serializedTestInventory: inventory,
  });

  const result = await provider.read();
  assert.equal(result.status, "present");
  assert.equal(result.inventory.inventoryGeneration, 1);
  assert.deepEqual(result.proof, { source: "test-injection" });
});

test("production provider boundary remains missing without native evidence", async () => {
  const provider = createWorkspaceInventoryProvider();
  assert.deepEqual(await provider.read(), { status: "missing" });
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
