import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
function sourceIdentity(stat) {
  return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`;
}

function sameLegacyFence(left, right) {
  return left?.generation === right?.generation &&
    left?.targetIdentity === right?.targetIdentity &&
    left?.controlDirectoryIdentity === right?.controlDirectoryIdentity &&
    left?.controlRootIdentity === right?.controlRootIdentity &&
    left?.bootstrapBlockerIdentity === right?.bootstrapBlockerIdentity;
}
export function createManagedAuthoritySelection() {
  let observed = false;
  return Object.freeze({
    observe(snapshot) {
      if (!snapshot || typeof snapshot !== "object") return observed;
      if (snapshot.managementMarkerPresent === true ||
          snapshot.managedHistoryMarkerPresent === true ||
          snapshot.managedSidecarPresent === true ||
          snapshot.bootstrapBlockerPresent === true ||
          snapshot.genesisProbePresent === true ||
          snapshot.nativeVerified === true ||
          (snapshot.controlRootBytes !== undefined && snapshot.controlRootBytes !== null)) {
        observed = true;
      }
      return observed;
    },
    get observed() {
      return observed;
    },
  });
}

function lstatOrAbsent(path, fs) {
  try {
    return fs.lstatSync(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export function readLegacyV0SourceSnapshot({
  targetPath,
  controlDirectoryPath,
  controlRootPath,
  managedHistoryMarkerPath,
  bootstrapBlockerPath,
  fs = { lstatSync, readFileSync },
}) {
  const beforeControlDirectory = lstatOrAbsent(controlDirectoryPath, fs);
  const beforeControlRoot = lstatOrAbsent(controlRootPath, fs);
  const beforeManagedHistoryMarker = managedHistoryMarkerPath
    ? lstatOrAbsent(managedHistoryMarkerPath, fs)
    : null;
  const beforeBootstrapBlocker = bootstrapBlockerPath
    ? lstatOrAbsent(bootstrapBlockerPath, fs)
    : null;
  if (beforeControlDirectory || beforeControlRoot || beforeManagedHistoryMarker || beforeBootstrapBlocker) {
    return {
      legacyV0Verified: false,
      managementMarkerPresent: true,
      managedHistoryMarkerPresent: Boolean(beforeManagedHistoryMarker),
      ...(bootstrapBlockerPath ? { bootstrapBlockerPresent: Boolean(beforeBootstrapBlocker) } : {}),
      controlRootBytes: null,
      targetBytes: Buffer.alloc(0),
    };
  }

  const beforeTarget = fs.lstatSync(targetPath);
  if (!beforeTarget.isFile() || beforeTarget.isSymbolicLink()) {
    throw new Error("legacy mapping source is ambiguous");
  }
  const targetBytes = Buffer.from(fs.readFileSync(targetPath));
  const afterTarget = fs.lstatSync(targetPath);
  const afterControlDirectory = lstatOrAbsent(controlDirectoryPath, fs);
  const afterControlRoot = lstatOrAbsent(controlRootPath, fs);
  const afterManagedHistoryMarker = managedHistoryMarkerPath
    ? lstatOrAbsent(managedHistoryMarkerPath, fs)
    : null;
  const afterBootstrapBlocker = bootstrapBlockerPath
    ? lstatOrAbsent(bootstrapBlockerPath, fs)
    : null;
  if (afterControlDirectory || afterControlRoot || afterManagedHistoryMarker || afterBootstrapBlocker ||
      sourceIdentity(beforeTarget) !== sourceIdentity(afterTarget)) {
    throw new Error("legacy mapping source changed while loading");
  }

  const legacyFence = {
    generation: createHash("sha256").update(targetBytes).digest("hex"),
    targetIdentity: sourceIdentity(afterTarget),
    controlDirectoryIdentity: null,
    controlRootIdentity: null,
    ...(bootstrapBlockerPath ? { bootstrapBlockerIdentity: null } : {}),
  };
  return {
    legacyV0Verified: true,
    controlRootAbsent: true,
    controlRootBytes: null,
    managementMarkerPresent: false,
    managedHistoryMarkerPresent: false,
    ...(bootstrapBlockerPath ? { bootstrapBlockerPresent: false } : {}),
    targetBytes,
    legacyFence,
  };
}

export function verifyLegacyV0SourceFence(options, expectedFence) {
  try {
    const current = readLegacyV0SourceSnapshot(options);
    return current.legacyV0Verified === true && sameLegacyFence(current.legacyFence, expectedFence);
  } catch {
    return false;
  }
}

import { isFullyQualifiedRouteWorkDir } from "@gjc-remote/shared/work-dir.js";
import { classifyMappingEnvelope, parseManagedHostTokens } from "@gjc-remote/shared/mapping-envelope";


function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireTrimmedString(value, setting) {
  if (typeof value !== "string") {
    throw new TypeError(`${setting} must be a string`);
  }

  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${setting} must not be empty`);
  }
  return normalized;
}
export function parseProvisionedManagementRoleBindings(raw) {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    throw new Error("GJC_MANAGEMENT_ROLE_BINDINGS is required for managed authority");
  }
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("GJC_MANAGEMENT_ROLE_BINDINGS must be JSON");
  }
  if (!isPlainObject(value)) throw new TypeError("GJC_MANAGEMENT_ROLE_BINDINGS must be a plain object");
  const keys = ["managementSid", "botSid", "recoverySid", "systemSid"];
  if (Reflect.ownKeys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) {
    throw new Error("GJC_MANAGEMENT_ROLE_BINDINGS must contain exactly managementSid, botSid, recoverySid, and systemSid");
  }
  const bindings = Object.fromEntries(keys.map((key) => [key, requireTrimmedString(value[key], `GJC_MANAGEMENT_ROLE_BINDINGS ${key}`)]));
  if (new Set([bindings.managementSid, bindings.botSid, bindings.recoverySid]).size !== 3) {
    throw new Error("GJC_MANAGEMENT_ROLE_BINDINGS management, bot, and recovery roles must differ");
  }
  return Object.freeze(bindings);
}

export function parseChannelMap(raw) {
  if (!isPlainObject(raw)) {
    throw new TypeError("CHANNEL_MAP must be a plain object");
  }

  const channelMap = {};
  for (const channelId of Reflect.ownKeys(raw)) {
    if (typeof channelId !== "string") {
      throw new Error("CHANNEL_MAP route keys must be decimal Discord IDs");
    }
    const route = raw[channelId];
    if (channelId === "_comment") {
      if (typeof route !== "string") {
        throw new TypeError("CHANNEL_MAP _comment must be a string");
      }
      continue;
    }

    if (!/^[0-9]+$/.test(channelId)) {
      throw new Error(`CHANNEL_MAP route key "${channelId}" must be a decimal Discord ID`);
    }
    if (!isPlainObject(route)) {
      throw new TypeError(`CHANNEL_MAP route "${channelId}" must be a plain object`);
    }

    const keys = Reflect.ownKeys(route);
    if (
      keys.length !== 2 ||
      !keys.includes("hostId") ||
      !keys.includes("workDir")
    ) {
      throw new Error(`CHANNEL_MAP route "${channelId}" must contain exactly hostId and workDir`);
    }

    const hostId = requireTrimmedString(
      route.hostId,
      `CHANNEL_MAP route "${channelId}" hostId`
    );
    const workDir = requireTrimmedString(
      route.workDir,
      `CHANNEL_MAP route "${channelId}" workDir`
    );
    if (!isFullyQualifiedRouteWorkDir(workDir)) {
      throw new Error(`CHANNEL_MAP route "${channelId}" workDir must be fully qualified`);
    }

    channelMap[channelId] = { hostId, workDir };
  }

  return channelMap;
}

export function parseHostTokens(raw) {
  if (typeof raw !== "string") {
    throw new TypeError("HOST_TOKENS must be a string");
  }
  if (raw.trim().length === 0) {
    return new Map();
  }

  const hostTokens = new Map();
  const entries = raw.split(",");
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    const colonIndex = entry.indexOf(":");
    if (colonIndex === -1) {
      throw new Error(`HOST_TOKENS entry ${index + 1} is malformed`);
    }

    const hostId = entry.slice(0, colonIndex).trim();
    const token = entry.slice(colonIndex + 1).trim();
    if (hostId.length === 0) {
      throw new Error(`HOST_TOKENS entry ${index + 1} has an empty host ID`);
    }
    if (token.length === 0) {
      throw new Error(`HOST_TOKENS entry ${index + 1} has an empty token`);
    }
    if (hostTokens.has(hostId)) {
      throw new Error(`HOST_TOKENS entry ${index + 1} has a duplicate host ID`);
    }

    hostTokens.set(hostId, token);
  }

  return hostTokens;
}

export function parseHostTokensForAuthority(raw, managedAuthorityPresent) {
  return managedAuthorityPresent ? parseManagedHostTokens(raw) : parseHostTokens(raw);
}

export function parseAllowedUsers(raw) {
  if (typeof raw !== "string") {
    throw new TypeError("GJC_BOT_ALLOWED_USERS must be a string");
  }
  if (raw.trim().length === 0) {
    return [];
  }

  const allowedUsers = [];
  const seen = new Set();
  const entries = raw.split(",");
  for (let index = 0; index < entries.length; index++) {
    const userId = entries[index].trim();
    if (userId.length === 0) {
      throw new Error(`GJC_BOT_ALLOWED_USERS entry ${index + 1} must not be empty`);
    }
    if (!/^[0-9]+$/.test(userId)) {
      throw new Error(`GJC_BOT_ALLOWED_USERS entry ${index + 1} must be a decimal Discord ID`);
    }
    if (!seen.has(userId)) {
      seen.add(userId);
      allowedUsers.push(userId);
    }
  }

  return allowedUsers;
}

export function validateChannelHosts(channelMap, hostTokens) {
  if (!(hostTokens instanceof Map)) {
    throw new TypeError("HOST_TOKENS must be parsed before validating CHANNEL_MAP");
  }

  for (const [channelId, route] of Object.entries(channelMap)) {
    if (!hostTokens.has(route.hostId)) {
      throw new Error(`CHANNEL_MAP route "${channelId}" references unknown hostId "${route.hostId}"`);
    }
  }
}

export function loadChannelMapState({ current, readText, validate = () => {} }) {
  try {
    const next = parseChannelMap(JSON.parse(readText()));
    validate(next);
    return { ok: true, map: next };
  } catch (error) {
    return { ok: false, map: current, error };
  }
}
export async function loadManagedChannelMapState({
  current,
  readSnapshot,
  validate = () => {},
  parseLegacyV0 = parseChannelMap,
  authoritySelection = createManagedAuthoritySelection(),
}) {
  let snapshot;
  try {
    snapshot = await readSnapshot();
    if (!snapshot || typeof snapshot !== "object") {
      throw new TypeError("managed mapping snapshot is unavailable");
    }
  } catch (error) {
    return { ok: false, map: current, error };
  }

  const controlRootAbsent = snapshot.controlRootAbsent === true;
  const managementMarkerPresent = authoritySelection.observe(snapshot);
  if (controlRootAbsent && !managementMarkerPresent) {
    try {
      if (snapshot.legacyV0Verified !== true || !snapshot.legacyFence) {
        return unavailableState("WORKSPACE_MAPPING_UNAVAILABLE");
      }
      const next = parseLegacyV0(JSON.parse(Buffer.from(snapshot.targetBytes).toString("utf8")));
      validate(next);
      return {
        ok: true,
        map: next,
        classification: {
          sourceKind: "legacy-v0",
          dispatchClass: "workspace-only",
          routeDisposition: "workspace-only",
          legacyFence: snapshot.legacyFence,
        },
      };
    } catch (error) {
      return { ok: false, map: current, error };
    }
  }

  if (controlRootAbsent || snapshot.nativeVerified !== true) {
    return unavailableState("MANAGED_NATIVE_UNAVAILABLE");
  }

  try {
    const classification = classifyMappingEnvelope({
      controlRootBytes: snapshot.controlRootBytes,
      wrapperBytes: snapshot.wrapperBytes,
      targetBytes: snapshot.targetBytes,
      targetIdentity: snapshot.targetIdentity,
      targetAclFingerprint: snapshot.targetAclFingerprint,
      parseLegacyV0,
    });
    if (!classification.ok) return unavailableState("WORKSPACE_MAPPING_UNAVAILABLE");

    return {
      ok: true,
      map: {},
      classification: {
        sourceKind: classification.sourceKind,
        dispatchClass: classification.dispatchClass,
        routeDisposition: classification.routeDisposition,
      },
    };
  } catch {
    return unavailableState("WORKSPACE_MAPPING_UNAVAILABLE");
  }
}

function unavailableState(code) {
  return {
    ok: false,
    map: {},
    classification: { sourceKind: "unavailable", dispatchClass: "workspace-only", routeDisposition: "no-route", code },
    error: new Error(code),
  };
}
