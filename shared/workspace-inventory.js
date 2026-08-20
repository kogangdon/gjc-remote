import { createHash } from "node:crypto";
import {
  STRICT_JSON_LIMITS,
  assertStrictText,
  canonicalJsonBytes,
  canonicalJsonHash,
  isHex64,
  parseCanonicalJsonBytes,
  utf8Compare,
} from "./strict-json.js";

export const WORKSPACE_INVENTORY_VERSION = 2;
export const WORKSPACE_INVENTORY_LIMITS = Object.freeze({
  ...STRICT_JSON_LIMITS,
  maxHostIdBytes: 128,
  maxWorkspaceIdBytes: 128,
  maxWorkDirBytes: 4096,
  maxWorkspaces: 64,
  maxGeneration: Number.MAX_SAFE_INTEGER,
});

const TOP_LEVEL_KEYS = Object.freeze([
  "version",
  "hostId",
  "inventoryGeneration",
  "inventoryFingerprint",
  "workspaces",
]);
const PREIMAGE_KEYS = Object.freeze([
  "version",
  "hostId",
  "inventoryGeneration",
  "workspaces",
]);
const WORKSPACE_KEYS = Object.freeze([
  "hostId",
  "workspaceId",
  "sourcePlatform",
  "workDir",
  "rootIdentityFingerprint",
  "storageIdentityFingerprint",
]);
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);
const WORKSPACE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function fail(message) {
  throw new TypeError(`WORKSPACE_INVENTORY_INVALID: ${message}`);
}

function isPlainObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value, keys) {
  return isPlainObject(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function strictText(value, name, maxBytes) {
  try {
    if (typeof value !== "string" || value.length === 0) return false;
    return assertStrictText(value, name, maxBytes) === value;
  } catch {
    return false;
  }
}

function validateWorkspace(workspace, hostId) {
  if (!hasExactKeys(workspace, WORKSPACE_KEYS)) fail("workspace keys");
  if (workspace.hostId !== hostId) fail("workspace hostId");
  if (!WORKSPACE_ID_PATTERN.test(workspace.workspaceId) ||
      Buffer.byteLength(workspace.workspaceId, "utf8") > WORKSPACE_INVENTORY_LIMITS.maxWorkspaceIdBytes) {
    fail("workspaceId");
  }
  if (!SOURCE_PLATFORMS.has(workspace.sourcePlatform)) fail("sourcePlatform");
  if (!strictText(workspace.workDir, "workDir", WORKSPACE_INVENTORY_LIMITS.maxWorkDirBytes)) {
    fail("workDir");
  }
  if (!isHex64(workspace.rootIdentityFingerprint)) fail("rootIdentityFingerprint");
  if (!isHex64(workspace.storageIdentityFingerprint)) fail("storageIdentityFingerprint");
  return workspace;
}

function validatePreimage(inventory, keys) {
  if (!hasExactKeys(inventory, keys)) fail("top-level keys");
  if (inventory.version !== WORKSPACE_INVENTORY_VERSION) fail("version");
  if (!strictText(inventory.hostId, "hostId", WORKSPACE_INVENTORY_LIMITS.maxHostIdBytes)) {
    fail("hostId");
  }
  if (!Number.isSafeInteger(inventory.inventoryGeneration) ||
      inventory.inventoryGeneration < 1 ||
      inventory.inventoryGeneration > WORKSPACE_INVENTORY_LIMITS.maxGeneration) {
    fail("inventoryGeneration");
  }
  if (!Array.isArray(inventory.workspaces) ||
      inventory.workspaces.length > WORKSPACE_INVENTORY_LIMITS.maxWorkspaces) {
    fail("workspaces");
  }

  let previousWorkspaceId = null;
  for (const workspace of inventory.workspaces) {
    validateWorkspace(workspace, inventory.hostId);
    if (previousWorkspaceId !== null &&
        utf8Compare(previousWorkspaceId, workspace.workspaceId) >= 0) {
      fail("workspaces must be unique and sorted");
    }
    previousWorkspaceId = workspace.workspaceId;
  }
  return inventory;
}

function assertDocumentByteLimit(inventory) {
  const bytes = canonicalJsonBytes(inventory, WORKSPACE_INVENTORY_LIMITS);
  if (bytes.length < 1 || bytes.length > WORKSPACE_INVENTORY_LIMITS.maxBytes) {
    fail("document byte limit");
  }
  return bytes;
}

export function workspaceInventoryFingerprint(inventory) {
  const hasFingerprint = isPlainObject(inventory) &&
    Object.hasOwn(inventory, "inventoryFingerprint");
  validatePreimage(inventory, hasFingerprint ? TOP_LEVEL_KEYS : PREIMAGE_KEYS);
  const {
    inventoryFingerprint: _inventoryFingerprint,
    ...preimage
  } = inventory;
  return canonicalJsonHash(preimage, WORKSPACE_INVENTORY_LIMITS);
}

export function validateWorkspaceInventory(inventory) {
  validatePreimage(inventory, TOP_LEVEL_KEYS);
  if (!isHex64(inventory.inventoryFingerprint)) fail("inventoryFingerprint");
  if (workspaceInventoryFingerprint(inventory) !== inventory.inventoryFingerprint) {
    fail("inventory fingerprint");
  }
  assertDocumentByteLimit(inventory);
  return inventory;
}

export function buildWorkspaceInventory({
  hostId,
  inventoryGeneration,
  workspaces,
}) {
  if (!Array.isArray(workspaces)) fail("workspaces");
  const sortedWorkspaces = workspaces.map((workspace) => {
    validateWorkspace(workspace, hostId);
    return { ...workspace };
  }).sort((left, right) => utf8Compare(left.workspaceId, right.workspaceId));
  const inventory = {
    version: WORKSPACE_INVENTORY_VERSION,
    hostId,
    inventoryGeneration,
    workspaces: sortedWorkspaces,
  };
  inventory.inventoryFingerprint = workspaceInventoryFingerprint(inventory);
  return validateWorkspaceInventory(inventory);
}

export function workspaceInventoryBytes(inventory) {
  validateWorkspaceInventory(inventory);
  return assertDocumentByteLimit(inventory);
}

export function parseWorkspaceInventory(bytes) {
  const inventory = parseCanonicalJsonBytes(bytes, WORKSPACE_INVENTORY_LIMITS);
  return validateWorkspaceInventory(inventory);
}

export function workspaceInventoryHostKey(hostId) {
  if (!strictText(hostId, "hostId", WORKSPACE_INVENTORY_LIMITS.maxHostIdBytes)) {
    fail("hostId");
  }
  return createHash("sha256").update(Buffer.from(hostId, "utf8")).digest("hex");
}
