import { parseWorkspaceInventory } from "./workspace-inventory.js";

export function createWorkspaceInventoryProvider({
  testInjectionEnabled = false,
  serializedTestInventory = undefined,
  testStatus = undefined,
  testEpochMismatch = false,
} = {}) {
  if (serializedTestInventory !== undefined && !testInjectionEnabled) {
    const error = new Error(
      "GJC_WORKSPACE_INVENTORY requires GJC_READINESS_TEST_INJECTION=1"
    );
    error.code = "CONFIG_INVALID";
    throw error;
  }
  const inventory = serializedTestInventory === undefined
    ? undefined
    : parseWorkspaceInventory(serializedTestInventory);
  // Test injection is the sole provider in this phase.  An epoch is included
  // in every read so callers can reject a snapshot that changes mid-receipt.
  const epoch = 1;
  const status = testInjectionEnabled && typeof testStatus === "string"
    ? testStatus.trim().toLowerCase()
    : undefined;
  const statusCodes = Object.freeze({
    invalid: "INVENTORY_INVALID",
    access_denied: "INVENTORY_ACCESS_DENIED",
    stale: "INVENTORY_STALE",
    manual_cleanup: "INVENTORY_MANUAL_CLEANUP",
    io_failed: "INVENTORY_IO_FAILED",
    root_escape: "WORKSPACE_ROOT_ESCAPE",
    containment_unsupported: "CONTAINMENT_UNSUPPORTED",
  });
  let reads = 0;
  return Object.freeze({
    receiptCapable: testInjectionEnabled && inventory !== undefined,
    async read() {
      reads += 1;
      if (status && status !== "present") {
        return Object.freeze({
          status,
          epoch: testEpochMismatch ? reads : epoch,
          code: status === "missing" || status === "transient"
            ? undefined
            : statusCodes[status] ?? "INVENTORY_INVALID",
        });
      }
      return inventory === undefined
        ? Object.freeze({ status: "missing" })
        : Object.freeze({
            status: "present",
            inventory,
            epoch: testEpochMismatch ? reads : epoch,
            proof: Object.freeze({ source: "test-injection" }),
          });
    },
  });
}
