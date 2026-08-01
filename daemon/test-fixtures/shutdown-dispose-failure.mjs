// daemon/test-fixtures/shutdown-dispose-failure.mjs
//
// Spawned by lifecycle.test.js. Boots daemon.js with the session pool's
// shutdown patched to always fail, then drives the SIGTERM path to prove a
// disposal failure cannot turn an operator stop into a crash exit.

// Guard: this file is a child-process entry, not a test. Bare `node --test`
// discovers every .mjs under a directory named `test`, so the fixtures live
// outside it; this guard is insurance against future runner pattern changes.
if (process.env.GJC_LIFECYCLE_FIXTURE !== "1") {
  console.error("fixture: spawned by lifecycle.test.js only");
  process.exit(0);
}

// Import the exact class daemon.js will import (same ESM module instance),
// so patching the prototype here also patches the pool the daemon creates.
const { SessionPool } = await import("../src/session-pool.js");
SessionPool.prototype.shutdown = () =>
  Promise.reject(new Error("injected dispose failure"));

// Capture the SIGTERM/SIGINT handlers daemon.js registers so the "signal"
// can be delivered by direct invocation — deterministic on Windows too,
// where real SIGTERM delivery is not emulated as a catchable signal.
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

// Reproduce the operator stopping the service.
setTimeout(() => signalHandlers.get("SIGTERM")(), 100);
