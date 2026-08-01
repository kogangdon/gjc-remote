// daemon/test-fixtures/shutdown-hang.mjs
//
// Spawned by lifecycle.test.js. Boots daemon.js with the session pool's
// shutdown patched to never settle, proving the shutdown deadline
// (GJC_SHUTDOWN_TIMEOUT_MS) unblocks the process instead of hanging forever.

if (process.env.GJC_LIFECYCLE_FIXTURE !== "1") {
  console.error("fixture: spawned by lifecycle.test.js only");
  process.exit(0);
}

const { SessionPool } = await import("../src/session-pool.js");
SessionPool.prototype.shutdown = () => new Promise(() => {});

const signalHandlers = new Map();
const originalProcessOn = process.on;
process.on = function captureSignalHandler(event, handler) {
  if (event === "SIGTERM" || event === "SIGINT") {
    signalHandlers.set(event, handler);
    return this;
  }
  return originalProcessOn.call(this, event, handler);
};

await import("../src/daemon.js");
process.on = originalProcessOn;

setTimeout(() => signalHandlers.get("SIGTERM")(), 100);
