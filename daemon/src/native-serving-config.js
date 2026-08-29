// Native serving readiness freshness config (slice S6f.7d).
//
// Resolves and BOUNDS the readiness-attestation freshness window
// (`maxAgeMs`) the create/refresh serving orchestrators enforce on
// `probedAtMs` and that the S6f.7b replay window uses for eviction. This is a
// daemon-config value (never requester-sourced), so per AGENTS.md it MUST be
// validated, bounded, and covered by tests for invalid / minimum / maximum
// values.
//
// Env var: GJC_NATIVE_WORKSPACE_READINESS_MAX_AGE_MS
//   - unset / empty  -> DEFAULT_MAX_AGE_MS
//   - a base-10 integer within [MIN_MAX_AGE_MS, MAX_MAX_AGE_MS] -> that value
//   - anything else (non-integer, sign, out of range, overflow) -> fail closed
//     with a sanitized diagnostic (the daemon degrades serving to fail-closed
//     rather than serving with an unbounded/misconfigured freshness window).
//
// Pure and dependency-injected (env is passed in); never wires into daemon.js
// directly - the S6f.7d daemon glue calls it while assembling serving deps.

export const READINESS_MAX_AGE_ENV = "GJC_NATIVE_WORKSPACE_READINESS_MAX_AGE_MS";
export const DEFAULT_MAX_AGE_MS = 30_000;
export const MIN_MAX_AGE_MS = 1_000;
export const MAX_MAX_AGE_MS = 3_600_000;

/**
 * @param {{ env?: Record<string, string | undefined> }} [options]
 * @returns {{ ok: true, maxAgeMs: number } | { ok: false, diagnostic: object }}
 */
export function resolveReadinessMaxAgeMs({ env = process.env } = {}) {
  const raw = env?.[READINESS_MAX_AGE_ENV];
  if (raw === undefined || raw === null || raw === "") {
    return { ok: true, maxAgeMs: DEFAULT_MAX_AGE_MS };
  }
  if (typeof raw !== "string") {
    return fail("must be a string value");
  }
  const trimmed = raw.trim();
  // Strict base-10 non-negative integer: no signs, decimals, whitespace,
  // hex, or exponent forms that Number() would silently accept.
  if (!/^[0-9]+$/.test(trimmed)) {
    return fail("must be a base-10 integer with no sign, decimal, or unit suffix");
  }
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value)) {
    return fail("exceeds the safe integer range");
  }
  if (value < MIN_MAX_AGE_MS || value > MAX_MAX_AGE_MS) {
    return fail(`must be within [${MIN_MAX_AGE_MS}, ${MAX_MAX_AGE_MS}] ms`);
  }
  return { ok: true, maxAgeMs: value };
}

function fail(reason) {
  return {
    ok: false,
    diagnostic: {
      code: "NATIVE_SERVING_CONFIG_INVALID",
      env: READINESS_MAX_AGE_ENV,
      reason,
    },
  };
}
