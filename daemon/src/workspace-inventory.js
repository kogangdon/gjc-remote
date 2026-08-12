import { isMappingId, isMappingGeneration, isMappingVersion, isReadinessWorkspaceGeneration, isWorkspaceId } from "@gjc-remote/shared";
import { isFullyQualifiedRouteWorkDir } from "@gjc-remote/shared/work-dir.js";
import { parseStrictJsonBytes } from "@gjc-remote/shared/strict-json.js";

const MAX_INVENTORY_BYTES = 1024 * 1024;
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);
const HEX64 = /^[0-9a-f]{64}$/;
const INVENTORY_KEYS = ["version", "inventoryGeneration", "workspaces"];
const WORKSPACE_KEYS = [
  "hostId", "mappingId", "mappingGeneration", "workspaceGeneration", "mappingVersion",
  "workspaceId", "sourcePlatform", "workDir", "routeFingerprint", "authorityFingerprint",
];

function exact(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function validHostId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && value.trim() === value;
}

function validateWorkspace(record) {
  if (!exact(record, WORKSPACE_KEYS) || !validHostId(record.hostId) ||
      !isMappingId(record.mappingId) || !isMappingGeneration(record.mappingGeneration) ||
      !isReadinessWorkspaceGeneration(record.workspaceGeneration) ||
      !isMappingVersion(record.mappingVersion) || !isWorkspaceId(record.workspaceId) ||
      !SOURCE_PLATFORMS.has(record.sourcePlatform) ||
      !isFullyQualifiedRouteWorkDir(record.workDir) ||
      !HEX64.test(record.routeFingerprint) || !HEX64.test(record.authorityFingerprint)) {
    throw new TypeError("WORKSPACE_INVENTORY_INVALID");
  }
  return Object.freeze({ ...record });
}

export function parseWorkspaceInventory(value) {
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array
    ? Buffer.from(value)
    : Buffer.from(`${value ?? ""}`, "utf8");
  if (bytes.length === 0 || bytes.length > MAX_INVENTORY_BYTES) {
    throw new TypeError("WORKSPACE_INVENTORY_INVALID");
  }
  const parsed = parseStrictJsonBytes(bytes);
  if (!exact(parsed, INVENTORY_KEYS) || parsed.version !== 1 ||
      !Number.isSafeInteger(parsed.inventoryGeneration) || parsed.inventoryGeneration < 1 ||
      !Array.isArray(parsed.workspaces) || parsed.workspaces.length > 64) {
    throw new TypeError("WORKSPACE_INVENTORY_INVALID");
  }
  const workspaces = parsed.workspaces.map(validateWorkspace);
  const ids = new Set(workspaces.map((workspace) => workspace.workspaceId));
  if (ids.size !== workspaces.length) throw new TypeError("WORKSPACE_INVENTORY_INVALID");
  return Object.freeze({
    version: parsed.version,
    inventoryGeneration: parsed.inventoryGeneration,
    workspaces: Object.freeze(workspaces),
  });
}

export function findWorkspaceInventory(inventory, binding) {
  if (!inventory || !binding) return undefined;
  return inventory.workspaces.find((workspace) =>
    workspace.hostId === binding.hostId &&
    workspace.mappingId === binding.mappingId &&
    workspace.mappingGeneration === binding.mappingGeneration &&
    workspace.workspaceGeneration === binding.workspaceGeneration &&
    workspace.mappingVersion === binding.mappingVersion &&
    workspace.workspaceId === binding.workspaceId &&
    workspace.sourcePlatform === binding.sourcePlatform &&
    workspace.routeFingerprint === binding.routeFingerprint &&
    workspace.authorityFingerprint === binding.authorityFingerprint &&
    inventory.inventoryGeneration === binding.inventoryGeneration
  );
}
