import {
  assertStrictText,
  canonicalJsonHash,
  isHex64,
} from "./strict-json.js";

export const WORKSPACE_AUTHORITY_DESCRIPTOR_KEYS = Object.freeze([
  "authorityEpoch",
  "fenceGeneration",
  "hostId",
  "mappingId",
  "mappingGeneration",
  "workspaceGeneration",
  "mappingVersion",
  "sourcePlatform",
  "workspaceId",
  "authorityFingerprint",
]);

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);

function fail(message) {
  throw new TypeError(`WORKSPACE_BINDING_INVALID: ${message}`);
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

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

function isOpaqueId(value) {
  return typeof value === "string" && OPAQUE_ID.test(value);
}

function isExactHostId(value) {
  try {
    return typeof value === "string" &&
      value.length > 0 &&
      value === value.trim() &&
      assertStrictText(value, "hostId", 128) === value;
  } catch {
    return false;
  }
}

export function validateWorkspaceAuthorityDescriptor(descriptor) {
  if (!hasExactKeys(descriptor, WORKSPACE_AUTHORITY_DESCRIPTOR_KEYS)) {
    fail("authority descriptor keys");
  }
  if (!isPositiveSafeInteger(descriptor.authorityEpoch)) fail("authorityEpoch");
  if (!isPositiveSafeInteger(descriptor.fenceGeneration)) fail("fenceGeneration");
  if (!isExactHostId(descriptor.hostId)) fail("hostId");
  if (!isOpaqueId(descriptor.mappingId)) fail("mappingId");
  if (!isPositiveSafeInteger(descriptor.mappingGeneration)) fail("mappingGeneration");
  if (!isPositiveSafeInteger(descriptor.workspaceGeneration)) fail("workspaceGeneration");
  if (!isPositiveSafeInteger(descriptor.mappingVersion)) fail("mappingVersion");
  if (!SOURCE_PLATFORMS.has(descriptor.sourcePlatform)) fail("sourcePlatform");
  if (!isOpaqueId(descriptor.workspaceId)) fail("workspaceId");
  if (!isHex64(descriptor.authorityFingerprint)) fail("authorityFingerprint");
  return descriptor;
}

export function isWorkspaceAuthorityDescriptor(descriptor) {
  try {
    validateWorkspaceAuthorityDescriptor(descriptor);
    return true;
  } catch {
    return false;
  }
}

export function workspaceBindingFingerprint({
  authority,
  inventoryGeneration,
  inventoryFingerprint,
}) {
  validateWorkspaceAuthorityDescriptor(authority);
  if (!isPositiveSafeInteger(inventoryGeneration)) fail("inventoryGeneration");
  if (!isHex64(inventoryFingerprint)) fail("inventoryFingerprint");
  return canonicalJsonHash({
    schemaVersion: 1,
    authority,
    inventory: {
      inventoryGeneration,
      inventoryFingerprint,
    },
  });
}
