/**
 * Builds a graceful-shutdown handler that tears services down in a safe order.
 *
 * The registry is closed first so in-flight invokes settle and connected
 * daemons observe a clean socket close, then the Discord gateway connection is
 * destroyed. The handler is idempotent (repeated signals are ignored) and always
 * reaches `exit(0)` even if a teardown step throws, so a stuck dependency cannot
 * wedge the process.
 *
 * @param {{
 *   registry: { close: () => Promise<unknown> },
 *   client: { destroy: () => Promise<unknown> | unknown },
 *   log?: (message: string) => void,
 *   logError?: (message: string, error: unknown) => void,
 *   exit?: (code: number) => void,
 * }} deps
 * @returns {(signal: string) => Promise<void>}
 */
function createShutdown({
  registry,
  client,
  log = console.log,
  logError = console.error,
  exit = process.exit,
}) {
  let shuttingDown = false;
  return async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`bot: received ${signal}, shutting down`);
    try {
      await registry.close();
    } catch (error) {
      logError("bot: host registry shutdown failed", error);
    }
    try {
      await client.destroy();
    } catch (error) {
      logError("bot: Discord client shutdown failed", error);
    }
    exit(0);
  };
}

export { createShutdown };
