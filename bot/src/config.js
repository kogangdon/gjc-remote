import path from "node:path";

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
    if (!path.posix.isAbsolute(workDir) && !path.win32.isAbsolute(workDir)) {
      throw new Error(`CHANNEL_MAP route "${channelId}" workDir must be absolute`);
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
