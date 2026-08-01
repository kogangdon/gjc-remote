// daemon/test-fixtures/reentrancy-signal-then-fatal.mjs
//
// Spawned by lifecycle.test.js. A signal starts shutdown first; a fatal
// event lands while disposal is still in flight. The shutdown latch must not
// re-enter and the signal's exit 0 must win (first-initiator-wins).

if (process.env.GJC_LIFECYCLE_FIXTURE !== "1") {
  console.error("fixture: spawned by lifecycle.test.js only");
  process.exit(0);
}

const { SessionPool } = await import("../src/session-pool.js");
SessionPool.prototype.shutdown = () => {
  // Marker counted by the test; the 200ms window keeps shutdown "in
  // progress" long enough for the second trigger to land inside it.
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

signalHandlers.get("SIGTERM")();
setTimeout(() => {
  throw new Error("late fatal");
}, 50);
