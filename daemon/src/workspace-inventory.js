import {
  parseWorkspaceInventory as parseWorkspaceInventoryV2,
} from "@gjc-remote/shared/workspace-inventory";

function freezeInventory(inventory) {
  return Object.freeze({
    ...inventory,
    workspaces: Object.freeze(
      inventory.workspaces.map((workspace) => Object.freeze({ ...workspace })),
    ),
  });
}

export function parseWorkspaceInventory(value) {
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array
    ? Buffer.from(value)
    : Buffer.from(`${value ?? ""}`, "utf8");
  try {
    return freezeInventory(parseWorkspaceInventoryV2(bytes));
  } catch (cause) {
    throw new TypeError("WORKSPACE_INVENTORY_INVALID", { cause });
  }
}

export function findWorkspaceInventory(inventory, binding) {
  if (!inventory || !binding ||
      inventory.inventoryGeneration !== binding.inventoryGeneration) {
    return undefined;
  }
  return inventory.workspaces.find((workspace) =>
    workspace.hostId === binding.hostId &&
    workspace.workspaceId === binding.workspaceId &&
    workspace.sourcePlatform === binding.sourcePlatform
  );
}
