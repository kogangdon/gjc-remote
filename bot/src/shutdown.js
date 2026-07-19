const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10_000;

/**
 * Awaits a teardown step, but never blocks longer than `timeoutMs`.
 *
 * A step that rejects is logged; a step that hangs (never settles) is abandoned
 * after the timeout so a stuck dependency cannot wedge the shutdown sequence.
 */
async function settleStep(label, run, { timeoutMs, logError }) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      logError(`bot: ${label} shutdown timed out after ${timeoutMs}ms`);
      resolve();
    }, timeoutMs);
    if (timer && typeof timer.unref === "function") timer.unref();
  });
  try {
    await Promise.race([Promise.resolve().then(run), timeout]);
  } catch (error) {
    logError(`bot: ${label} shutdown failed`, error);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Builds a graceful-shutdown handler that tears services down in a safe order.
 *
 * The registry is closed first so in-flight invokes settle and connected
 * daemons observe a clean socket close, then the Discord gateway connection is
 * destroyed. The handler is idempotent (repeated signals are ignored) and always
 * reaches `exit(0)`: each step is bounded by `timeoutMs`, so a step that throws
 * or hangs cannot wedge the process.
 *
 * @param {{
 *   registry: { close: () => Promise<unknown> },
 *   client: { destroy: () => Promise<unknown> | unknown },
 *   log?: (message: string) => void,
 *   logError?: (message: string, error?: unknown) => void,
 *   exit?: (code: number) => void,
 *   timeoutMs?: number,
 * }} deps
 * @returns {(signal: string) => Promise<void>}
 */
function createShutdown({
  registry,
  client,
  log = console.log,
  logError = console.error,
  exit = process.exit,
  timeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS,
}) {
  let shuttingDown = false;
  return async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`bot: received ${signal}, shutting down`);
    await settleStep("host registry", () => registry.close(), {
      timeoutMs,
      logError,
    });
    await settleStep("Discord client", () => client.destroy(), {
      timeoutMs,
      logError,
    });
    exit(0);
  };
}

export { createShutdown, DEFAULT_SHUTDOWN_TIMEOUT_MS };
