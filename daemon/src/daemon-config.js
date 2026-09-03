import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { V0_LIMITS } from "@gjc-remote/shared";

const OPERATION = "resolve_daemon_connection_config";
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
const TOKEN_FILE_MAX_BYTES = V0_LIMITS.TOKEN * 4 + 2;
const BOT_WS_URL_MAX_LENGTH = 4096;

export class DaemonConfigError extends Error {
  constructor() {
    super("Daemon connection configuration is invalid.");
    Object.defineProperties(this, {
      name: { value: "DaemonConfigError" },
      code: { value: "CONFIG_INVALID", enumerable: true },
      operation: { value: OPERATION, enumerable: true },
    });
  }
}

function invalidConfig() {
  return new DaemonConfigError();
}

function isValidProtocolValue(value, limit, { allowEmpty = false } = {}) {
  return (
    typeof value === "string" &&
    value.length <= limit &&
    (allowEmpty || value.length > 0) &&
    !CONTROL_CHARACTERS.test(value)
  );
}

function stripSingleTerminalLineEnding(value) {
  if (value.endsWith("\r\n")) return value.slice(0, -2);
  if (value.endsWith("\n")) return value.slice(0, -1);
  return value;
}

function asBytes(value) {
  if (value instanceof Uint8Array) return value;
  return null;
}

async function readTokenFile(readFile, tokenFile) {
  if (typeof readFile !== "function") throw invalidConfig();

  let bytes;
  try {
    // The injected reader must honor this cap rather than reading an unbounded
    // secret and truncating it after the fact.
    bytes = asBytes(await readFile(tokenFile, TOKEN_FILE_MAX_BYTES));
  } catch {
    throw invalidConfig();
  }
  if (bytes === null || bytes.byteLength > TOKEN_FILE_MAX_BYTES) {
    throw invalidConfig();
  }

  let token;
  try {
    token = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw invalidConfig();
  }
  token = stripSingleTerminalLineEnding(token);

  if (
    token !== token.trim() ||
    !isValidProtocolValue(token, V0_LIMITS.TOKEN)
  ) {
    throw invalidConfig();
  }
  return token;
}

export async function readBoundedRegularFile(file, maxBytes) {
  let handle;
  try {
    handle = await open(
      file,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
    );
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > maxBytes) throw invalidConfig();

    const bytes = Buffer.alloc(maxBytes + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > maxBytes) throw invalidConfig();
    return bytes.subarray(0, offset);
  } finally {
    await handle?.close();
  }
}

/**
 * Resolve the daemon's connection credentials without coupling them to
 * workspace mapping or native-serving configuration.
 *
 * `readFile(path, maxBytes)` is an injected bounded byte reader. It must return
 * a Uint8Array (Buffer is accepted) containing no more than `maxBytes` bytes.
 */
export async function resolveDaemonConnectionConfig({
  env,
  readFile = readBoundedRegularFile,
}) {
  if (env === null || typeof env !== "object") throw invalidConfig();

  const hostId = env.HOST_ID;
  const botWsUrl = env.BOT_WS_URL;
  const hostLabel = env.HOST_LABEL;
  const hasEnvironmentToken = env.HOST_TOKEN !== undefined;
  const hasTokenFile = env.HOST_TOKEN_FILE !== undefined;

  if (
    !isValidProtocolValue(hostId, V0_LIMITS.HOST_ID) ||
    !isValidProtocolValue(botWsUrl, BOT_WS_URL_MAX_LENGTH) ||
    (hostLabel !== undefined &&
      !isValidProtocolValue(hostLabel, V0_LIMITS.LABEL, { allowEmpty: true })) ||
    hasEnvironmentToken === hasTokenFile
  ) {
    throw invalidConfig();
  }
  try {
    const parsed = new URL(botWsUrl);
    if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
      throw invalidConfig();
    }
  } catch {
    throw invalidConfig();
  }

  let token;
  if (hasEnvironmentToken) {
    token = env.HOST_TOKEN;
    if (!isValidProtocolValue(token, V0_LIMITS.TOKEN)) throw invalidConfig();
  } else {
    const tokenFile = env.HOST_TOKEN_FILE;
    if (typeof tokenFile !== "string" || !isAbsolute(tokenFile)) {
      throw invalidConfig();
    }
    token = await readTokenFile(readFile, tokenFile);
  }

  return Object.freeze({ hostId, token, hostLabel, botWsUrl });
}
