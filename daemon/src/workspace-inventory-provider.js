import { createInventoryFloor } from "./inventory-floor.js";
import { parseWorkspaceInventory } from "./workspace-inventory.js";

const STATUS_CODES = Object.freeze({
  invalid: "INVENTORY_INVALID",
  access_denied: "INVENTORY_ACCESS_DENIED",
  stale: "INVENTORY_STALE",
  manual_cleanup: "INVENTORY_MANUAL_CLEANUP",
  io_failed: "INVENTORY_IO_FAILED",
  root_escape: "WORKSPACE_ROOT_ESCAPE",
  containment_unsupported: "CONTAINMENT_UNSUPPORTED",
});
const PROVIDER_OPTION_KEYS = Object.freeze([
  "reader",
  "testInjectionEnabled",
  "serializedTestInventory",
  "testStatus",
  "testEpochMismatch",
]);

function configError(message) {
  const error = new Error(message);
  error.code = "CONFIG_INVALID";
  return error;
}

function providerOptions(options) {
  try {
    if (options === null || typeof options !== "object" ||
        Array.isArray(options) ||
        Object.getPrototypeOf(options) !== Object.prototype) {
      throw configError("inventory provider options are invalid");
    }
    const own = Reflect.ownKeys(options);
    if (own.some((key) => typeof key !== "string" ||
        !PROVIDER_OPTION_KEYS.includes(key))) {
      throw configError("inventory provider options are invalid");
    }
    const descriptors = Object.getOwnPropertyDescriptors(options);
    const result = {};
    for (const key of own) {
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.enumerable !== true ||
          descriptor.get !== undefined || descriptor.set !== undefined ||
          !Object.hasOwn(descriptor, "value")) {
        throw configError("inventory provider options are invalid");
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error?.code === "CONFIG_INVALID") throw error;
    throw configError("inventory provider options are invalid");
  }
}

export function createWorkspaceInventoryProvider(options = {}) {
  const {
    reader = undefined,
    testInjectionEnabled = false,
    serializedTestInventory = undefined,
    testStatus = undefined,
    testEpochMismatch = false,
  } = providerOptions(options);
  if (typeof testInjectionEnabled !== "boolean" ||
      typeof testEpochMismatch !== "boolean" ||
      (testStatus !== undefined && typeof testStatus !== "string")) {
    throw configError("inventory provider test controls are invalid");
  }
  const hasTestInjection = serializedTestInventory !== undefined ||
    testStatus !== undefined || testEpochMismatch !== false;
  if ((hasTestInjection || testEpochMismatch !== false) && !testInjectionEnabled) {
    throw configError(
      "GJC_WORKSPACE_INVENTORY requires GJC_READINESS_TEST_INJECTION=1"
    );
  }
  if (reader !== undefined && (testInjectionEnabled || hasTestInjection)) {
    throw configError("native Reader cannot be combined with test inventory injection");
  }
  if (reader !== undefined) {
    const floor = createInventoryFloor({ reader });
    return Object.freeze({
      receiptCapable: true,
      read: floor.read,
    });
  }

  const inventory = serializedTestInventory === undefined
    ? undefined
    : parseWorkspaceInventory(serializedTestInventory);
  const epoch = 1;
  const status = testInjectionEnabled && typeof testStatus === "string"
    ? testStatus.trim().toLowerCase()
    : undefined;
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
            : STATUS_CODES[status] ?? "INVENTORY_INVALID",
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
