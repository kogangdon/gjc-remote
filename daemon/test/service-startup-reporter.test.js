import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";
import {
  serviceDaemonTargetFingerprint,
  validateServiceStartupObservationEvent,
} from "@gjc-remote/shared/service-startup-observation";
import { createDaemonServiceStartupReporter } from "../src/service-startup-reporter.js";

const h = (label) => createHash("sha256").update(label).digest("hex");
const context = Object.freeze({
  component: "daemon", serviceKey: `prod-1-${h("key")}`, processEpochFingerprint: h("epoch"),
  effectiveConfigFingerprint: h("config"), configSourceIdentityFingerprint: h("source"),
});
const binding = { ...context };

function sink() {
  const writable = new EventEmitter();
  writable.lines = [];
  writable.write = (bytes, callback) => {
    writable.lines.push(Buffer.from(bytes).toString("utf8"));
    queueMicrotask(() => callback());
    return true;
  };
  return writable;
}

test("daemon target fingerprint strips URL userinfo and fragment but binds host and URL", () => {
  const base = serviceDaemonTargetFingerprint({ botWsUrl: "wss://bot.example:8443/ws?x=1", hostId: "prod-1" });
  assert.equal(serviceDaemonTargetFingerprint({ botWsUrl: "wss://u:p@bot.example:8443/ws?x=1#f", hostId: "prod-1" }), base);
  assert.notEqual(serviceDaemonTargetFingerprint({ botWsUrl: "wss://bot.example:8443/ws?x=2", hostId: "prod-1" }), base);
  assert.notEqual(serviceDaemonTargetFingerprint({ botWsUrl: "wss://bot.example:8443/ws?x=1", hostId: "prod-2" }), base);
  for (const botWsUrl of ["https://bot.example/", "not a url", 1]) {
    assert.throws(() => serviceDaemonTargetFingerprint({ botWsUrl, hostId: "prod-1" }), { code: "SERVICE_STARTUP_OBSERVATION_INVALID" });
  }
  assert.throws(() => serviceDaemonTargetFingerprint({ botWsUrl: "ws://bot/", hostId: "" }), { code: "SERVICE_STARTUP_OBSERVATION_INVALID" });
});

test("daemon reporter emits exact-target registration generations and ignores stale transports", async () => {
  const writable = sink();
  const reporter = createDaemonServiceStartupReporter({
    context, botWsUrl: "ws://127.0.0.1:9000/", hostId: "prod-1", writable, onFailure: assert.fail,
  });
  const first = reporter.registrationAttempted();
  reporter.registrationDenied(first);
  reporter.connectionClosed(first);
  const second = reporter.registrationAttempted();
  reporter.registrationAccepted(first);
  reporter.connectionClosed(first);
  reporter.registrationAccepted(second);
  reporter.registrationAccepted(second);
  reporter.registrationDenied(second);
  reporter.connectionClosed(null);
  await reporter.flush();
  const events = writable.lines.map((line) =>
    validateServiceStartupObservationEvent(JSON.parse(line), { binding, expectedState: reporter.expectedState }));
  assert.deepEqual(events.map(({ state }) => [state.registration, state.connectionGeneration, state.attemptedGeneration, state.acceptedGeneration]), [
    ["attempted", 1, 1, null],
    ["denied", 1, 1, null],
    ["disconnected", 1, 1, null],
    ["attempted", 2, 2, null],
    ["accepted", 2, 2, 2],
  ]);
  assert.equal(events[4].state.targetFingerprint,
    serviceDaemonTargetFingerprint({ botWsUrl: "ws://127.0.0.1:9000/", hostId: "prod-1" }));
});

test("daemon reporter refuses non-daemon contexts", () => {
  assert.throws(() => createDaemonServiceStartupReporter({
    context: { ...context, component: "bot" }, botWsUrl: "ws://h/", hostId: "prod-1", writable: sink(), onFailure() {},
  }), TypeError);
  assert.throws(() => createDaemonServiceStartupReporter({
    context, botWsUrl: "ws://h/", hostId: "prod-1", writable: sink(),
  }), TypeError);
});
