import {
  initializeInventoryConfig as defaultInitializeInventoryConfig,
  inventoryConfigDiagnostic as defaultInventoryConfigDiagnostic,
} from "./inventory-config.js";

// Pure, side-effect-free resolver for the daemon boot inventory-provider options.
//
// Precedence (single source of truth for the mutual-exclusion invariant):
//   1. test injection enabled (any mode)          -> legacy test-injection provider options
//   2. test injection disabled AND mode 'verify'  -> production native reader (self-tested)
//   3. otherwise (off / unset, injection disabled) -> legacy provider options (misconfig guard preserved)
//
// The production native reader path is reachable ONLY in case 2, so a production
// reader and test-injected inventory can never be attempted together. Case 3
// forwards the exact same legacy options as `main` (including
// `serializedTestInventory`) so a stray GJC_WORKSPACE_INVENTORY without
// GJC_READINESS_TEST_INJECTION=1 still fails closed in the provider.
//
// Returns `{ ok: true, providerOptions }` for cases 1/3 and for a successful
// verify self-test, or `{ ok: false, diagnostic }` (a structured, path-free,
// secret-free object) when verify configuration/self-test fails. This function
// never calls process.exit — the caller owns termination.
export async function resolveInventoryProviderConfig(
  { testInjectionEnabled, nativeInventoryMode, hostId, platform, env = process.env },
  {
    initializeInventoryConfig = defaultInitializeInventoryConfig,
    inventoryConfigDiagnostic = defaultInventoryConfigDiagnostic,
  } = {},
) {
  if (testInjectionEnabled !== true && nativeInventoryMode === "verify") {
    try {
      const config = await initializeInventoryConfig({
        env: { ...env, GJC_NATIVE_INVENTORY_MODE: nativeInventoryMode },
        hostId,
        platform,
      });
      return { ok: true, providerOptions: { reader: config.reader } };
    } catch (error) {
      return { ok: false, diagnostic: inventoryConfigDiagnostic(error) };
    }
  }

  return {
    ok: true,
    providerOptions: {
      testInjectionEnabled: testInjectionEnabled === true,
      serializedTestInventory: env.GJC_WORKSPACE_INVENTORY,
      testStatus: env.GJC_WORKSPACE_INVENTORY_TEST_STATUS,
      testEpochMismatch: env.GJC_WORKSPACE_INVENTORY_TEST_EPOCH_MISMATCH === "1",
    },
  };
}
