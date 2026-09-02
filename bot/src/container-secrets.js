import { readFileSync as fsReadFileSync } from "node:fs";

const SECRET_LIMITS = Object.freeze({
  DISCORD_TOKEN: 64 * 1024,
  HOST_TOKENS: 1024 * 1024,
});

function fail(name, reason) {
  throw new Error(`${name} secret configuration is invalid: ${reason}`);
}

function readSecretFile(name, path, readFileSync) {
  if (typeof path !== "string" || path.length === 0) {
    fail(name, `${name}_FILE must be a non-empty path`);
  }
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch {
    fail(name, `${name}_FILE could not be read`);
  }
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > SECRET_LIMITS[name]) {
    fail(name, `${name}_FILE exceeds its byte limit`);
  }
  let value;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(name, `${name}_FILE must contain valid UTF-8`);
  }
  if (name === "DISCORD_TOKEN") value = value.replace(/\r?\n$/, "");
  if (value.trim().length === 0 || value.includes("\0") || value.includes("\r")) {
    fail(name, `${name}_FILE contains invalid text`);
  }
  if (name === "DISCORD_TOKEN" && value.includes("\n")) {
    fail(name, `${name}_FILE must contain exactly one non-empty line`);
  }
  return value;
}

function resolveSecret(env, name, readFileSync) {
  const direct = env?.[name];
  const file = env?.[`${name}_FILE`];
  if (direct !== undefined && direct !== "" && file !== undefined && file !== "") {
    fail(name, `set only one of ${name} or ${name}_FILE`);
  }
  if (file !== undefined && file !== "") {
    return readSecretFile(name, file, readFileSync);
  }
  return direct;
}

export function resolveBotSecrets({
  env = process.env,
  readFileSync = fsReadFileSync,
} = {}) {
  if (env === null || typeof env !== "object") {
    throw new TypeError("bot secret environment must be an object");
  }
  if (typeof readFileSync !== "function") {
    throw new TypeError("readFileSync must be a function");
  }
  return Object.freeze({
    DISCORD_TOKEN: resolveSecret(env, "DISCORD_TOKEN", readFileSync),
    HOST_TOKENS: resolveSecret(env, "HOST_TOKENS", readFileSync),
  });
}
