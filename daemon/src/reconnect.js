const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30_000;

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
  const capped = Math.min(base, max);
  const half = capped / 2;
  const delay = Math.round(half + random() * half);
  const nextBase = Math.min(capped * 2, max);
  return { delay, nextBase };
}

export { RECONNECT_BASE_MS, RECONNECT_MAX_MS, nextReconnect };
