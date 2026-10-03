import { loadVerifiedAddon } from "./index.js";
import { provisionInventoryBasesAdapter } from "./inventory.js";

export {
  buildManifest,
  createContainmentLowLevel,
  createInventoryPublisher,
  createInventoryReader,
  createManagementNative,
  createResidualProcessEnumerator,
  createServiceNative,
  validateBuildManifest,
} from "./index.js";
export { createServiceStartupObserver } from "./service-startup-observer.js";
export { createSelfProcessObserver } from "./service-native.js";

export async function provisionInventoryBases(options) {
  return provisionInventoryBasesAdapter(() => loadVerifiedAddon(), options);
}
