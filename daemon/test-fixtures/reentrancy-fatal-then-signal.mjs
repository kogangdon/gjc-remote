// daemon/test-fixtures/reentrancy-fatal-then-signal.mjs
//
// Spawned by lifecycle.test.js. A fatal event starts shutdown first; a
// signal lands while disposal is still in flight. The shutdown latch must
// not re-enter and the fatal's non-zero exit must win — a late signal cannot
// launder a crash into a clean stop.

if (process.env.GJC_LIFECYCLE_FIXTURE !== "1") {
  console.error("fixture: spawned by lifecycle.test.js only");
  process.exit(0);
}

const { SessionPool } = await import("../src/session-pool.js");
SessionPool.prototype.shutdown = () => {
  console.log("POOL_SHUTDOWN_CALLED");
  return new Promise((resolve) => setTimeout(resolve, 200));
};

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

setTimeout(() => {
  throw new Error("early fatal");
}, 0);
setTimeout(() => signalHandlers.get("SIGTERM")(), 50);
