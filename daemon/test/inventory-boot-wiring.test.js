import test from "node:test";
import assert from "node:assert/strict";

import { resolveInventoryProviderConfig } from "../src/inventory-boot-wiring.js";
import { createWorkspaceInventoryProvider } from "../src/workspace-inventory-provider.js";
import { inventoryConfigDiagnostic } from "../src/inventory-config.js";

const stubReader = () =>
  Object.freeze({
    selfTest: async () => Object.freeze({ role: "daemon", contractVersion: 4, writes: 0 }),
    readAccepted: async () => {
      throw new Error("must not read");
    },
  });

const configInvalidError = () => {
  const error = new Error("Inventory configuration is invalid.");
  Object.defineProperties(error, {
    code: { value: "CONFIG_INVALID", enumerable: true },
    operation: { value: "initialize_inventory_config", enumerable: true },
    writes: { value: 0, enumerable: true },
    ambiguous: { value: false, enumerable: true },
  });
  return error;
};

const nativeRefusedError = () => {
  const error = new Error("native control refused");
  Object.defineProperties(error, {
    code: { value: "ERR_NATIVE_CONTROL_REFUSED", enumerable: true },
    operation: { value: "load_native_control", enumerable: true },
    writes: { value: 0, enumerable: true },
    ambiguous: { value: false, enumerable: true },
  });
  return error;
};

test("test-injection enabled short-circuits to legacy options in verify mode (factory never called)", async () => {
  let calls = 0;
  const result = await resolveInventoryProviderConfig(
    {
      testInjectionEnabled: true,
      nativeInventoryMode: "verify",
      hostId: "H1",
      platform: "linux",
      env: {
        GJC_WORKSPACE_INVENTORY: "{}",
        GJC_WORKSPACE_INVENTORY_TEST_STATUS: "present",
        GJC_WORKSPACE_INVENTORY_TEST_EPOCH_MISMATCH: "1",
      },
    },
    {
      initializeInventoryConfig: async () => {
        calls += 1;
        throw new Error("factory must not run");
      },
      inventoryConfigDiagnostic,
    },
  );
  assert.equal(calls, 0);
  assert.equal(result.ok, true);
  assert.deepEqual(result.providerOptions, {
    testInjectionEnabled: true,
    serializedTestInventory: "{}",
    testStatus: "present",
    testEpochMismatch: true,
  });
});

test("off mode returns legacy options and never calls the factory", async () => {
  let calls = 0;
  const result = await resolveInventoryProviderConfig(
    {
      testInjectionEnabled: false,
      nativeInventoryMode: "off",
      hostId: "H1",
      platform: "linux",
      env: {},
    },
    {
      initializeInventoryConfig: async () => {
        calls += 1;
        throw new Error("factory must not run");
      },
      inventoryConfigDiagnostic,
    },
  );
  assert.equal(calls, 0);
  assert.equal(result.ok, true);
  assert.deepEqual(result.providerOptions, {
    testInjectionEnabled: false,
    serializedTestInventory: undefined,
    testStatus: undefined,
    testEpochMismatch: false,
  });
});

test("off mode preserves the fail-closed misconfig guard (stray GJC_WORKSPACE_INVENTORY without injection)", async () => {
  const result = await resolveInventoryProviderConfig(
    {
      testInjectionEnabled: false,
      nativeInventoryMode: "off",
      hostId: "H1",
      platform: "linux",
      env: { GJC_WORKSPACE_INVENTORY: '{"stray":true}' },
    },
    {
      initializeInventoryConfig: async () => {
        throw new Error("factory must not run");
      },
      inventoryConfigDiagnostic,
    },
  );
  assert.equal(result.ok, true);
  // The legacy options carry the stray inventory forward so the real provider fails closed.
  assert.equal(result.providerOptions.serializedTestInventory, '{"stray":true}');
  assert.equal(result.providerOptions.testInjectionEnabled, false);
  assert.throws(
    () => createWorkspaceInventoryProvider(result.providerOptions),
    (error) => error.code === "CONFIG_INVALID" &&
      /requires GJC_READINESS_TEST_INJECTION=1/.test(error.message),
  );
});

test("verify mode with a self-tested reader yields receiptCapable provider options", async () => {
  const reader = stubReader();
  let receivedEnvMode;
  const result = await resolveInventoryProviderConfig(
    {
      testInjectionEnabled: false,
      nativeInventoryMode: "verify",
      hostId: "H1",
      platform: "linux",
      env: { GJC_INVENTORY_ROLE_BINDINGS: "roles" },
    },
    {
      initializeInventoryConfig: async ({ env }) => {
        receivedEnvMode = env.GJC_NATIVE_INVENTORY_MODE;
        return Object.freeze({ mode: "verify", reader, selfTest: {} });
      },
      inventoryConfigDiagnostic,
    },
  );
  assert.equal(receivedEnvMode, "verify");
  assert.equal(result.ok, true);
  assert.equal(result.providerOptions.reader, reader);
  // Fed into the real provider, a reader yields a receipt-capable provider.
  const provider = createWorkspaceInventoryProvider(result.providerOptions);
  assert.equal(provider.receiptCapable, true);
});

test("verify mode maps a CONFIG_INVALID throw to a structured diagnostic and ok:false", async () => {
  const result = await resolveInventoryProviderConfig(
    {
      testInjectionEnabled: false,
      nativeInventoryMode: "verify",
      hostId: "H1",
      platform: "linux",
      env: {},
    },
    {
      initializeInventoryConfig: async () => {
        throw configInvalidError();
      },
      inventoryConfigDiagnostic,
    },
  );
  assert.equal(result.ok, false);
  assert.deepEqual(result.diagnostic, {
    code: "CONFIG_INVALID",
    operation: "initialize_inventory_config",
    writes: 0,
    ambiguous: false,
  });
  assert.equal(Object.isFrozen(result.diagnostic), true);
  // Diagnostic is path-free and secret-free (only the four structured keys).
  assert.deepEqual(Object.keys(result.diagnostic).sort(), [
    "ambiguous",
    "code",
    "operation",
    "writes",
  ]);
});

test("verify mode maps a native-control refusal to its structured diagnostic and ok:false", async () => {
  const result = await resolveInventoryProviderConfig(
    {
      testInjectionEnabled: false,
      nativeInventoryMode: "verify",
      hostId: "H1",
      platform: "linux",
      env: {},
    },
    {
      initializeInventoryConfig: async () => {
        throw nativeRefusedError();
      },
      inventoryConfigDiagnostic,
    },
  );
  assert.equal(result.ok, false);
  assert.deepEqual(result.diagnostic, {
    code: "ERR_NATIVE_CONTROL_REFUSED",
    operation: "load_native_control",
    writes: 0,
    ambiguous: false,
  });
});

test("verify mode threads the caller's normalized mode into the config env override", async () => {
  let receivedEnv;
  await resolveInventoryProviderConfig(
    {
      testInjectionEnabled: false,
      nativeInventoryMode: "verify",
      hostId: "H1",
      platform: "linux",
      // Raw env carries a non-canonical casing that must NOT reach the exact-match config.
      env: { GJC_NATIVE_INVENTORY_MODE: "Verify", GJC_INVENTORY_ROLE_BINDINGS: "roles" },
    },
    {
      initializeInventoryConfig: async ({ env }) => {
        receivedEnv = env;
        return Object.freeze({ mode: "verify", reader: stubReader(), selfTest: {} });
      },
      inventoryConfigDiagnostic,
    },
  );
  assert.equal(receivedEnv.GJC_NATIVE_INVENTORY_MODE, "verify");
  // Other env keys are preserved.
  assert.equal(receivedEnv.GJC_INVENTORY_ROLE_BINDINGS, "roles");
});
