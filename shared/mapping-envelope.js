import { createHash } from "node:crypto";
import { canonicalJsonHash, isHex64, parseStrictJsonBytes, assertStrictText, utf8Compare } from "./strict-json.js";
import { isFullyQualifiedRouteWorkDir } from "./work-dir.js";
import { isManagementAnchor, isOpaqueIdentity } from "./identity.js";

const MAX_HOST_TOKENS_BYTES = 1024 * 1024;
const HEX_OR_NULL = (value) => value === null || isHex64(value);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const positiveFence = (value) => Number.isSafeInteger(value) && value >= 1;
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return object(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)); }
function validText(value, max) { try { return typeof value === "string" && value.length > 0 && assertStrictText(value, "text", max) === value; } catch { return false; } }
function hashWithout(value, field) { const copy = { ...value }; delete copy[field]; return canonicalJsonHash(copy); }
function bytes(value, name) { if (typeof value === "string") return Buffer.from(value, "utf8"); if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value); throw new TypeError(`${name} must be bytes`); }

export function parseManagedHostTokens(input) {
  const raw = bytes(input, "HOST_TOKENS");
  if (raw.length > MAX_HOST_TOKENS_BYTES) throw new RangeError("HOST_TOKENS exceeds 1 MiB");
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) throw new SyntaxError("HOST_TOKENS must not contain a BOM");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(raw); } catch { throw new SyntaxError("HOST_TOKENS is not valid UTF-8"); }
  if (text === "") throw new SyntaxError("HOST_TOKENS requires at least one entry");
  if (text.includes("\r")) throw new SyntaxError("HOST_TOKENS must use LF only");
  const entries = text.endsWith("\n") ? text.slice(0, -1).split("\n") : text.split("\n");
  const tokens = new Map();
  for (const entry of entries) {
    const separator = entry.indexOf("=");
    if (separator <= 0) throw new SyntaxError("HOST_TOKENS entries require hostId=token");
    const hostId = entry.slice(0, separator);
    const token = entry.slice(separator + 1);
    if (Buffer.byteLength(hostId, "utf8") > 128 || hostId.length > 128 || !validText(hostId, 128) || hostId.includes("=") || /^\s|\s$/u.test(hostId)) throw new SyntaxError("invalid managed host ID");
    if (Buffer.byteLength(token, "utf8") > 4096 || token.length === 0 || /[\0\n\r]/u.test(token)) throw new SyntaxError("invalid managed host token");
    try { assertStrictText(token, "managed host token", 4096); } catch { throw new SyntaxError("invalid managed host token"); }
    if (tokens.has(hostId)) throw new SyntaxError("duplicate managed host ID");
    tokens.set(hostId, token);
  }
  return tokens;
}

export function managedHostSetFingerprint(tokensOrInput) {
  const hostIds = tokensOrInput instanceof Map ? [...tokensOrInput.keys()] : [...parseManagedHostTokens(tokensOrInput).keys()];
  hostIds.sort(utf8Compare);
  const json = `{"encoding":"utf-8","hostIds":[${hostIds.map(JSON.stringify).join(",")}],"schemaVersion":1}`;
  return createHash("sha256").update(Buffer.from(json, "utf8")).digest("hex");
}

const CONTROL_ROOT_KEYS = ["version", "kind", "managementStamp", "anchor", "anchorFingerprint", "fenceGeneration", "sourceKind", "wrapperKind", "wrapperRelativeName", "targetRelativeName", "controlRootRelativeName", "readerVersionFloorFingerprint", "wrapperFingerprint", "controlRootFingerprint"];
export function isControlRoot(value) {
  if (!exact(value, CONTROL_ROOT_KEYS)) return false;
  const source = value.sourceKind;
  const subordinate = source === "managed-v1" ? ["managed-v1-wrapper", "managed-v1-wrapper.json"] : source === "legacy-retained" ? ["legacy-retained-wrapper", "legacy-retained.json"] : null;
  return value.version === 1 && value.kind === "management-control-root" && value.managementStamp === "gjc-management-control/v1" &&
    isManagementAnchor(value.anchor) && value.anchorFingerprint === canonicalJsonHash(value.anchor) && positiveFence(value.fenceGeneration) && subordinate !== null &&
    value.wrapperKind === subordinate[0] && value.wrapperRelativeName === subordinate[1] && value.targetRelativeName === "channels.json" &&
    value.controlRootRelativeName === ".gjc-remote-control" && isHex64(value.readerVersionFloorFingerprint) && isHex64(value.wrapperFingerprint) &&
    isHex64(value.controlRootFingerprint) && value.controlRootFingerprint === hashWithout(value, "controlRootFingerprint");
}

const RETAINED_KEYS = ["version", "kind", "sourceKind", "managementStamp", "anchorFingerprint", "fenceGeneration", "targetRelativeName", "targetState", "rawTargetByteFingerprint", "rawTargetByteLength", "targetIdentity", "targetAclFingerprint", "readerVersion", "legacyRetention", "dispatchClass", "routeDisposition", "retentionTxId", "retentionSequence", "previousWrapperFingerprint", "wrapperFingerprint"];
const MANAGED_KEYS = ["version", "kind", "sourceKind", "managementStamp", "anchorFingerprint", "fenceGeneration", "targetRelativeName", "targetState", "targetIdentity", "targetAclFingerprint", "semanticStateFingerprint", "readerVersion", "dispatchClass", "routeDisposition", "wrapperSequence", "previousWrapperFingerprint", "wrapperFingerprint"];

export function isLegacyRetainedWrapper(value) {
  return exact(value, RETAINED_KEYS) && value.version === 1 && value.kind === "legacy-retained-wrapper" && value.sourceKind === "legacy-retained" && value.managementStamp === "gjc-management-envelope/v1" &&
    isHex64(value.anchorFingerprint) && positiveFence(value.fenceGeneration) && value.targetRelativeName === "channels.json" && value.targetState === "legacy-unmigrated" && isHex64(value.rawTargetByteFingerprint) && Number.isSafeInteger(value.rawTargetByteLength) && value.rawTargetByteLength >= 0 && isOpaqueIdentity(value.targetIdentity) && isHex64(value.targetAclFingerprint) && value.readerVersion === null && value.legacyRetention === "exact" && value.dispatchClass === "workspace-only" && value.routeDisposition === "no-route" && typeof value.retentionTxId === "string" && UUID.test(value.retentionTxId) && value.retentionSequence === 1 && HEX_OR_NULL(value.previousWrapperFingerprint) && isHex64(value.wrapperFingerprint) && value.wrapperFingerprint === hashWithout(value, "wrapperFingerprint");
}

export function isManagedV1Wrapper(value) {
  const state = value?.targetState;
  const validSequence = Number.isSafeInteger(value?.wrapperSequence) && value.wrapperSequence >= 1 &&
    ((value.wrapperSequence === 1 && value.previousWrapperFingerprint === null) ||
     (value.wrapperSequence > 1 && isHex64(value.previousWrapperFingerprint)));
  return exact(value, MANAGED_KEYS) && value.version === 1 && value.kind === "managed-v1-wrapper" && value.sourceKind === "managed-v1" && value.managementStamp === "gjc-management-envelope/v1" &&
    isHex64(value.anchorFingerprint) && positiveFence(value.fenceGeneration) && value.targetRelativeName === "channels.json" && (state === "genesis-empty" || state === "managed-empty" || state === "managed") && (state !== "genesis-empty" || value.fenceGeneration === 1) && isOpaqueIdentity(value.targetIdentity) && isHex64(value.targetAclFingerprint) && HEX_OR_NULL(value.semanticStateFingerprint) && (value.readerVersion === null || value.readerVersion === 2) && value.dispatchClass === "workspace-only" && value.routeDisposition === "no-route" && validSequence && isHex64(value.wrapperFingerprint) && value.wrapperFingerprint === hashWithout(value, "wrapperFingerprint");
}

export function validateManagementEnvelope(controlRoot, wrapper, context = {}) {
  if (!isControlRoot(controlRoot)) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
  const validWrapper = controlRoot.sourceKind === "legacy-retained" ? isLegacyRetainedWrapper(wrapper) : isManagedV1Wrapper(wrapper);
  if (!validWrapper || wrapper.wrapperFingerprint !== controlRoot.wrapperFingerprint || wrapper.anchorFingerprint !== controlRoot.anchorFingerprint || wrapper.fenceGeneration !== controlRoot.fenceGeneration) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
  if (context.targetIdentity === undefined || context.targetAclFingerprint === undefined || wrapper.targetIdentity !== context.targetIdentity || wrapper.targetAclFingerprint !== context.targetAclFingerprint) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
  if (controlRoot.sourceKind === "legacy-retained") {
    if (context.targetBytes === undefined) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
    const target = bytes(context.targetBytes, "target");
    if (wrapper.rawTargetByteLength !== target.length || wrapper.rawTargetByteFingerprint !== createHash("sha256").update(target).digest("hex")) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
  }
  return { ok: true, sourceKind: controlRoot.sourceKind, dispatchClass: "workspace-only", routeDisposition: controlRoot.sourceKind === "legacy-retained" ? "no-route" : wrapper.routeDisposition, controlRoot, wrapper };
}

export function classifyMappingEnvelope({ controlRootBytes, wrapperBytes, targetBytes, targetIdentity, targetAclFingerprint, parseLegacyV0 }) {
  if (controlRootBytes !== undefined && controlRootBytes !== null) {
    try {
      const root = parseStrictJsonBytes(bytes(controlRootBytes, "control root"));
      if (wrapperBytes === undefined || wrapperBytes === null) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
      return validateManagementEnvelope(root, parseStrictJsonBytes(bytes(wrapperBytes, "wrapper")), { targetBytes, targetIdentity, targetAclFingerprint });
    } catch { return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" }; }
  }
  if (typeof parseLegacyV0 !== "function") return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
  try {
    const target = parseStrictJsonBytes(bytes(targetBytes, "target"));
    if (object(target) && Object.hasOwn(target, "managementStamp")) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
    const legacy = parseLegacyV0(target);
    if (legacy === false || legacy === undefined || legacy === null) return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" };
    return { ok: true, sourceKind: "legacy-v0", dispatchClass: "workspace-only", routeDisposition: "workspace-only", target: legacy };
  } catch { return { ok: false, code: "MANAGEMENT_ENVELOPE_INVALID" }; }
}

export const parseManagedHostTokensV1 = parseManagedHostTokens;
export const classifyMapping = classifyMappingEnvelope;
const MANAGED_CHANNEL_KEYS = [
  "version", "managementStamp", "revision", "authorityEpoch", "fenceGeneration",
  "mappingGeneration", "tokenConfigGeneration",
  "tokenConfigHostSetFingerprint", "targetState", "dispatchClass",
  "mappings", "routes", "configFingerprint",
];
const MAPPING_KEYS = [
  "mappingId", "hostId", "fenceGeneration", "mappingGeneration", "mappingVersion",
  "sourcePlatform", "workspaceId", "workDir", "sourceRoot",
  "containerRoot", "volumeIdentity", "casePolicy", "immutableDefault",
  "mappingFingerprint",
];
const ROUTE_KEYS = [
  "channelId", "hostId", "mappingId", "fenceGeneration", "mappingGeneration",
  "mappingVersion", "sourcePlatform", "workspaceId", "workDir",
  "routeFingerprint",
];
const OPAQUE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DISCORD_ID = /^[0-9]{1,20}$/;

function exactHostId(value) {
  return typeof value === "string" && value.length <= 128 &&
    Buffer.byteLength(value, "utf8") <= 128 && validText(value, 128) &&
    value === value.trim();
}

function canonicalPosixRoot(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.includes("\\")) return false;
  if (value !== "/" && value.endsWith("/")) return false;
  return !value.split("/").some((segment, index) => index > 0 && (segment === "" || segment === "." || segment === ".."));
}

function canonicalWindowsDriveRoot(value) {
  if (typeof value !== "string" || !/^[A-Z]:\\/.test(value) || value.includes("/")) return false;
  const tail = value.slice(3);
  return tail === "" || !tail.split("\\").some((segment) => segment === "." || segment === ".." || segment === "");
}

function canonicalWindowsUncRoot(value) {
  if (typeof value !== "string" || !/^\\\\[^\\]+\\[^\\]+(?:\\.*)?$/.test(value) || value.includes("/")) return false;
  return !value.slice(2).split("\\").some((segment) => segment === "" || segment === "." || segment === "..");
}

function validMappingLocation(mapping) {
  if (!["posix", "windows-drive", "windows-unc"].includes(mapping.sourcePlatform)) return false;
  if (!["sensitive", "insensitive"].includes(mapping.casePolicy)) return false;
  if (!validText(mapping.volumeIdentity, 512)) return false;
  if (mapping.containerRoot !== null && !canonicalPosixRoot(mapping.containerRoot)) return false;
  if (mapping.sourcePlatform === "posix" && !canonicalPosixRoot(mapping.sourceRoot)) return false;
  if (mapping.sourcePlatform === "windows-drive" && !canonicalWindowsDriveRoot(mapping.sourceRoot)) return false;
  if (mapping.sourcePlatform === "windows-unc" && !canonicalWindowsUncRoot(mapping.sourceRoot)) return false;
  if (mapping.sourcePlatform !== "posix" && mapping.casePolicy !== "insensitive") return false;
  return true;
}

export function validateManagedMappingRecord(mapping) {
  if (!exact(mapping, MAPPING_KEYS) || !OPAQUE_TOKEN.test(mapping.mappingId) ||
      !exactHostId(mapping.hostId) || !positiveFence(mapping.fenceGeneration) || !Number.isSafeInteger(mapping.mappingGeneration) ||
      mapping.mappingGeneration < 1 || mapping.mappingVersion !== 1 ||
      !validMappingLocation(mapping) || typeof mapping.immutableDefault !== "boolean" ||
      !isHex64(mapping.mappingFingerprint)) throw new TypeError("MANAGED_MAPPING_INVALID");
  const workspace = mapping.workspaceId !== null;
  const legacy = mapping.workDir !== null;
  if (workspace === legacy) throw new TypeError("MANAGED_MAPPING_INVALID");
  if (workspace && !OPAQUE_TOKEN.test(mapping.workspaceId)) throw new TypeError("MANAGED_MAPPING_INVALID");
  if (legacy && (!validText(mapping.workDir, 4096) || !isFullyQualifiedRouteWorkDir(mapping.workDir))) throw new TypeError("MANAGED_MAPPING_INVALID");
  if (hashWithout(mapping, "mappingFingerprint") !== mapping.mappingFingerprint) throw new TypeError("MANAGED_MAPPING_INVALID");
  return mapping;
}

export function validateManagedRouteRecord(route, mapping) {
  if (!exact(route, ROUTE_KEYS) || !DISCORD_ID.test(route.channelId) ||
      !isHex64(route.routeFingerprint)) throw new TypeError("MANAGED_ROUTE_INVALID");
  validateManagedMappingRecord(mapping);
  for (const key of ["hostId", "mappingId", "fenceGeneration", "mappingGeneration", "mappingVersion", "sourcePlatform", "workspaceId", "workDir"]) {
    if (route[key] !== mapping[key]) throw new TypeError("MANAGED_ROUTE_INVALID");
  }
  if (hashWithout(route, "routeFingerprint") !== route.routeFingerprint) throw new TypeError("MANAGED_ROUTE_INVALID");
  return route;
}

export function validateManagedChannelsV2(value) {
  if (!exact(value, MANAGED_CHANNEL_KEYS) || value.version !== 2 ||
      value.managementStamp !== "gjc-management-channels/v2" ||
      value.dispatchClass !== "workspace-only" ||
      !positiveFence(value.fenceGeneration) ||
      !Number.isSafeInteger(value.mappingGeneration) || value.mappingGeneration < 0 ||
      !Number.isSafeInteger(value.tokenConfigGeneration) || value.tokenConfigGeneration < 1 ||
      !isHex64(value.tokenConfigHostSetFingerprint) ||
      !["genesis-empty", "managed-empty", "managed"].includes(value.targetState) ||
      !object(value.mappings) || !object(value.routes) || !isHex64(value.configFingerprint)) {
    throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  }
  const empty = value.targetState === "genesis-empty";
  if (empty && value.fenceGeneration !== 1) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  if (empty !== (value.revision === null && value.authorityEpoch === null)) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  if (!empty && (!Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !Number.isSafeInteger(value.authorityEpoch) || value.authorityEpoch < 1)) {
    throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  }
  if (empty && (value.mappingGeneration !== 0 || Object.keys(value.mappings).length !== 0 ||
      Object.keys(value.routes).length !== 0)) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");

  let maximumGeneration = 0;
  for (const [mappingId, mapping] of Object.entries(value.mappings)) {
    if (mappingId !== mapping.mappingId) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
    validateManagedMappingRecord(mapping);
    if (mapping.fenceGeneration !== value.fenceGeneration) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
    maximumGeneration = Math.max(maximumGeneration, mapping.mappingGeneration);
  }
  for (const [channelId, route] of Object.entries(value.routes)) {
    if (channelId !== route.channelId || !Object.hasOwn(value.mappings, route.mappingId)) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
    validateManagedRouteRecord(route, value.mappings[route.mappingId]);
    if (route.fenceGeneration !== value.fenceGeneration) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  }
  if (maximumGeneration > value.mappingGeneration) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  if (value.targetState === "managed-empty" && Object.keys(value.routes).length !== 0) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  if (value.targetState === "managed" && Object.keys(value.routes).length === 0) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  if (hashWithout(value, "configFingerprint") !== value.configFingerprint) throw new TypeError("MANAGED_CHANNELS_V2_INVALID");
  return value;
}

export function createGenesisEmptyChannels({
  tokenConfigGeneration,
  tokenConfigHostSetFingerprint,
  fenceGeneration,
}) {
  const value = {
    version: 2,
    managementStamp: "gjc-management-channels/v2",
    revision: null,
    authorityEpoch: null,
    fenceGeneration,
    mappingGeneration: 0,
    tokenConfigGeneration,
    tokenConfigHostSetFingerprint,
    targetState: "genesis-empty",
    dispatchClass: "workspace-only",
    mappings: {},
    routes: {},
    configFingerprint: null,
  };
  value.configFingerprint = hashWithout(value, "configFingerprint");
  return validateManagedChannelsV2(value);
}

export function fingerprintManagedMappingRecord(record) {
  const value = { ...record, mappingFingerprint: null };
  value.mappingFingerprint = hashWithout(value, "mappingFingerprint");
  return validateManagedMappingRecord(value);
}

export function fingerprintManagedRouteRecord(record, mapping) {
  const value = { ...record, routeFingerprint: null };
  value.routeFingerprint = hashWithout(value, "routeFingerprint");
  return validateManagedRouteRecord(value, mapping);
}
