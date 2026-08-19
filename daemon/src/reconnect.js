const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30_000;
const REGISTER_DENIED_RETRY_MS = 300_000;
const REGISTER_DENIED_RETRY_DEFAULT_MS = REGISTER_DENIED_RETRY_MS;
const REGISTER_DENIED_RETRY_MIN_MS = 1000;
const SHUTDOWN_TIMEOUT_DEFAULT_MS = 15_000;
const SHUTDOWN_TIMEOUT_MIN_MS = 1000;
// setTimeout clamps larger values to a one millisecond timeout. Keep the
// configured retry below that boundary so an invalid large value cannot turn
// into a hot reconnect loop.
const TIMER_MAX_MS = 2_147_483_647;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
const URL_CREDENTIALS = /:\/\/[^/\s@]+@/g;
const MAX_SANITIZED_ERROR_LENGTH = 500;

function stringifyErrorMessage(value) {
  try {
    if (value instanceof Error) return String(value.message);
    return String(value);
  } catch {
    return "";
  }
}

/**
 * Convert an arbitrary thrown value into a bounded, single-line diagnostic.
 * Only the message is used for Error instances; stack traces and raw objects
 * never reach logs.
 *
 * @param {unknown} value
 * @param {Iterable<unknown>} [sensitiveValues]
 * @returns {string}
 */
function sanitizeErrorMessage(value, sensitiveValues = []) {
  let message = stringifyErrorMessage(value);
  for (const secret of sensitiveValues) {
    if (typeof secret !== "string" || secret.length === 0) continue;
    message = message.split(secret).join("[redacted]");
  }
  message = message
    .replace(URL_CREDENTIALS, "://[redacted]@")
    .replace(CONTROL_CHARACTERS, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (message.length === 0) message = "unknown error";
  return message.slice(0, MAX_SANITIZED_ERROR_LENGTH);
}

/**
 * Parse and validate a millisecond duration supplied via environment variable.
 *
 * Undefined means the documented default should be used. Every configured
 * value must be an integer in the range accepted by setTimeout and at least
 * `minMs`, so malformed configuration can neither create a hot loop
 * (setTimeout clamps out-of-range values to ~1ms) nor an unbounded wait.
 *
 * @param {unknown} value
 * @param {{ envName: string, defaultMs: number, minMs: number }} bounds
 * @returns {number}
 */
function parseBoundedTimeoutMs(value, { envName, defaultMs, minMs }) {
  if (value === undefined) return defaultMs;

  const text = typeof value === "string" ? value.trim() : value;
  if (text === "") {
    throw new RangeError(`${envName} must be at least ${minMs}ms`);
  }

  const ms = typeof text === "number" ? text : Number(text);
  if (
    !Number.isFinite(ms) ||
    !Number.isSafeInteger(ms) ||
    ms < minMs ||
    ms > TIMER_MAX_MS
  ) {
    throw new RangeError(
      `${envName} must be a safe integer between ${minMs}ms and ${TIMER_MAX_MS}ms`
    );
  }
  return ms;
}

/**
 * Parse and validate the fixed retry used after registration denial.
 *
 * @param {unknown} value
 * @returns {number}
 */
function parseRegisterDeniedRetryMs(value) {
  return parseBoundedTimeoutMs(value, {
    envName: "GJC_REGISTER_DENIED_RETRY_MS",
    defaultMs: REGISTER_DENIED_RETRY_DEFAULT_MS,
    minMs: REGISTER_DENIED_RETRY_MIN_MS,
  });
}

/**
 * Parse and validate the daemon's overall shutdown deadline. The deadline
 * must stay below any supervisor stop timeout so the daemon's clean exit
 * never races the supervisor's kill.
 *
 * @param {unknown} value
 * @returns {number}
 */
function parseShutdownTimeoutMs(value) {
  return parseBoundedTimeoutMs(value, {
    envName: "GJC_SHUTDOWN_TIMEOUT_MS",
    defaultMs: SHUTDOWN_TIMEOUT_DEFAULT_MS,
    minMs: SHUTDOWN_TIMEOUT_MIN_MS,
  });
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
function createReconnectScheduler({
  deniedRetryMs = REGISTER_DENIED_RETRY_DEFAULT_MS,
  onReconnect = () => {},
  logger = console.log,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  random = Math.random,
} = {}) {
  let reconnectDelay = RECONNECT_BASE_MS;
  let timer = null;
  let registrationDenied = false;

  function clear() {
    if (timer !== null) {
      clearTimeoutFn(timer);
      timer = null;
    }
  }

  function scheduleNormal() {
    if (timer !== null) return;
    const { delay, nextBase } = nextReconnect(reconnectDelay, { random });
    reconnectDelay = nextBase;
    logger(`daemon: disconnected from bot, retrying in ${delay}ms`);
    timer = setTimeoutFn(() => {
      timer = null;
      onReconnect();
    }, delay);
  }

  function scheduleDenied() {
    if (timer !== null) return;
    logger(`daemon: registration denied, retrying in ${deniedRetryMs}ms`);
    timer = setTimeoutFn(() => {
      timer = null;
      onReconnect();
    }, deniedRetryMs);
  }

  return {
    clear,
    markDenied() {
      registrationDenied = true;
    },
    markAccepted() {
      registrationDenied = false;
      reconnectDelay = RECONNECT_BASE_MS;
      clear();
    },
    scheduleNormal,
    scheduleDenied,
    onClose({ deniedForConnection = false } = {}) {
      if (registrationDenied) {
        if (!deniedForConnection) scheduleDenied();
        return;
      }
      scheduleNormal();
    },
    isDenied() {
      return registrationDenied;
    },
    hasTimer() {
      return timer !== null;
    },
  };
}

export {
  RECONNECT_BASE_MS,
  RECONNECT_MAX_MS,
  REGISTER_DENIED_RETRY_MS,
  REGISTER_DENIED_RETRY_DEFAULT_MS,
  REGISTER_DENIED_RETRY_MIN_MS,
  SHUTDOWN_TIMEOUT_DEFAULT_MS,
  SHUTDOWN_TIMEOUT_MIN_MS,
  TIMER_MAX_MS,
  parseRegisterDeniedRetryMs,
  parseShutdownTimeoutMs,
  nextReconnect,
  createReconnectScheduler,
  sanitizeErrorMessage,
};
