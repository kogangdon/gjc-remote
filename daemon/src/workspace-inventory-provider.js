import { parseWorkspaceInventory } from "./workspace-inventory.js";

export function createWorkspaceInventoryProvider({
  testInjectionEnabled = false,
  serializedTestInventory = undefined,
} = {}) {
  if (serializedTestInventory !== undefined && !testInjectionEnabled) {
    const error = new Error(
      "GJC_WORKSPACE_INVENTORY requires GJC_READINESS_TEST_INJECTION=1"
    );
    error.code = "CONFIG_INVALID";
    throw error;
  }
  const inventory =
    serializedTestInventory === undefined
      ? undefined
      : parseWorkspaceInventory(serializedTestInventory);
  return Object.freeze({
    async read() {
      return inventory === undefined
        ? Object.freeze({ status: "missing" })
        : Object.freeze({
            status: "present",
            inventory,
            proof: Object.freeze({ source: "test-injection" }),
          });
    },
  });
}
