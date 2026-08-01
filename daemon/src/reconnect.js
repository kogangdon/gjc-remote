const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30_000;
const REGISTER_DENIED_RETRY_MS = 300_000;
const REGISTER_DENIED_RETRY_DEFAULT_MS = REGISTER_DENIED_RETRY_MS;
const REGISTER_DENIED_RETRY_MIN_MS = 1000;
// setTimeout clamps larger values to a one millisecond timeout. Keep the
// configured retry below that boundary so an invalid large value cannot turn
// into a hot reconnect loop.
const TIMER_MAX_MS = 2_147_483_647;

/**
 * Parse and validate the fixed retry used after registration denial.
 *
 * Undefined means that the documented five-minute default should be used.
 * Every configured value must be an integer in the range accepted by
 * setTimeout and at least one second, so malformed test configuration cannot
 * create a hot loop.
 *
 * @param {unknown} value
 * @returns {number}
 */
function parseRegisterDeniedRetryMs(value) {
  if (value === undefined) return REGISTER_DENIED_RETRY_DEFAULT_MS;

  const text = typeof value === "string" ? value.trim() : value;
  if (text === "") {
    throw new RangeError(
      `GJC_REGISTER_DENIED_RETRY_MS must be at least ${REGISTER_DENIED_RETRY_MIN_MS}ms`
    );
  }

  const retryMs = typeof text === "number" ? text : Number(text);
  if (
    !Number.isFinite(retryMs) ||
    !Number.isSafeInteger(retryMs) ||
    retryMs < REGISTER_DENIED_RETRY_MIN_MS ||
    retryMs > TIMER_MAX_MS
  ) {
    throw new RangeError(
      `GJC_REGISTER_DENIED_RETRY_MS must be a safe integer between ` +
        `${REGISTER_DENIED_RETRY_MIN_MS}ms and ${TIMER_MAX_MS}ms`
    );
  }
  return retryMs;
}

/**
 * Equal-jitter exponential backoff.
 *
 * Returns the delay to wait before the next reconnect attempt and the base to
 * carry into the following attempt. The delay is drawn from `[base/2, base]`,
 * which keeps a bounded schedule while spreading many daemons' reconnects so a
 * shared bot restart does not trigger a synchronized thundering herd.
 *
 * @param {number} base current backoff base in milliseconds
 * @param {{ max?: number, random?: () => number }} [options]
 * @returns {{ delay: number, nextBase: number }}
 */
function nextReconnect(
  base,
  { max = RECONNECT_MAX_MS, random = Math.random } = {}
) {
  // Clamp the incoming base to the ceiling first, so the drawn delay itself is
  // always bounded by `max` (not just the base carried into the next attempt).
  const capped = Math.min(
    Number.isFinite(base) && base > 0 ? base : RECONNECT_BASE_MS,
    max
  );
  const half = capped / 2;
  const sample = Number(random());
  const jitter = Number.isFinite(sample)
    ? Math.min(1, Math.max(0, sample))
    : 0;
  const delay = Math.round(half + jitter * half);
  const nextBase = Math.min(capped * 2, max);
  return { delay, nextBase };
}

export {
  RECONNECT_BASE_MS,
  RECONNECT_MAX_MS,
  REGISTER_DENIED_RETRY_MS,
  REGISTER_DENIED_RETRY_DEFAULT_MS,
  REGISTER_DENIED_RETRY_MIN_MS,
  TIMER_MAX_MS,
  parseRegisterDeniedRetryMs,
  nextReconnect,
};
