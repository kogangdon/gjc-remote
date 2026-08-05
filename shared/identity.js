import { assertStrictText, canonicalJsonHash, isHex64 } from "./strict-json.js";

const ANCHOR_KEYS = ["anchorVersion", "configPathFingerprint", "parentIdentity", "targetRelativeName", "controlRootRelativeName"];

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value, keys) {
  return isPlainObject(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function isCanonicalPrincipal(value) {
  if (value.kind === "uid") {
    if (!/^uid:(0|[1-9][0-9]{0,9})$/.test(value.value)) return false;
    return BigInt(value.value.slice(4)) <= 4294967295n;
  }
  return value.kind === "sid" && /^S-(?:0|[1-9][0-9]*)-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*))+$/.test(value.value);
}

export function isOpaqueIdentity(value) {
  try { return typeof value === "string" && value.length > 0 && assertStrictText(value, "identity", 4096) === value; } catch { return false; }
}

export function isPrincipal(value) {
  return hasExactKeys(value, ["kind", "value"]) && isOpaqueIdentity(value.value) && isCanonicalPrincipal(value);
}

export function isProvisioningSource(value) {
  if (!hasExactKeys(value, ["kind", "fingerprint"])) return false;
  return typeof value.kind === "string" && value.kind.length > 0 && isHex64(value.fingerprint);
}

export function isAclFingerprint(value) { return isHex64(value); }

export function isManagementAnchor(value) {
  return hasExactKeys(value, ANCHOR_KEYS) &&
    value.anchorVersion === 1 &&
    isHex64(value.configPathFingerprint) &&
    isOpaqueIdentity(value.parentIdentity) &&
    value.targetRelativeName === "channels.json" &&
    value.controlRootRelativeName === ".gjc-remote-control";
}

export function managementAnchorFingerprint(anchor) {
  if (!isManagementAnchor(anchor)) throw new TypeError("invalid management anchor");
  return canonicalJsonHash(anchor);
}

export function isIdentityAclBinding(value) {
  return hasExactKeys(value, ["identity", "aclFingerprint"]) && isOpaqueIdentity(value.identity) && isAclFingerprint(value.aclFingerprint);
}
