const ENV_NAME = "GJC_RESTORE_CONTEXTS_JSON";
const MAX_BYTES = 1024 * 1024;

function diagnostic(reason) {
  return Object.freeze({
    code: "RESTORE_CONTEXT_CONFIG_INVALID",
    env: ENV_NAME,
    reason,
  });
}

export function resolveRestoreContextClaims({ env = process.env } = {}) {
  const raw = env?.[ENV_NAME];
  if (raw === undefined || raw === "") {
    return Object.freeze({
      ok: true,
      enabled: false,
      claims: Object.freeze([]),
      diagnostic: null,
    });
  }
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_BYTES) {
    return Object.freeze({
      ok: false,
      enabled: false,
      claims: Object.freeze([]),
      diagnostic: diagnostic("value must be UTF-8 JSON no larger than 1 MiB"),
    });
  }
  let claims;
  try {
    claims = JSON.parse(raw);
  } catch {
    return Object.freeze({
      ok: false,
      enabled: false,
      claims: Object.freeze([]),
      diagnostic: diagnostic("value must be valid JSON"),
    });
  }
  if (!Array.isArray(claims) || claims.length < 1 || claims.length > 64) {
    return Object.freeze({
      ok: false,
      enabled: false,
      claims: Object.freeze([]),
      diagnostic: diagnostic("value must be an array containing 1 to 64 claims"),
    });
  }
  return Object.freeze({
    ok: true,
    enabled: true,
    claims,
    diagnostic: null,
  });
}

export { ENV_NAME as RESTORE_CONTEXTS_ENV };
