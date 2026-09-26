import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";
import { managedHostSetFingerprint } from "@gjc-remote/shared/mapping-envelope";
import { validateServiceStartupObservationEvent } from "@gjc-remote/shared/service-startup-observation";
import { createBotServiceStartupReporter } from "../src/service-startup-reporter.js";

const h = (label) => createHash("sha256").update(label).digest("hex");
const context = Object.freeze({
  schemaVersion: 1, component: "bot", serviceKey: "bot", processEpochFingerprint: h("epoch"),
  effectiveConfigFingerprint: h("config"), configSourceIdentityFingerprint: h("source"),
  launchFingerprint: h("launch"), runtimePolicyFingerprint: h("policy"),
  bootstrapClosureFingerprint: h("closure"), scopeFingerprint: h("scope"),
});

function sink({ fail = false } = {}) {
  const writable = new EventEmitter();
  writable.lines = [];
  writable.write = (bytes, callback) => {
    writable.lines.push(Buffer.from(bytes).toString("utf8"));
    queueMicrotask(() => callback(fail ? new Error("EPIPE") : undefined));
    return true;
  };
  return writable;
}

function fakeRegistry() {
  const registry = { listener: "closed", ids: [] };
  registry.getServiceStartupSnapshot = () => ({ listener: registry.listener, connectedHostIds: [...registry.ids] });
  return registry;
}

test("bot reporter emits bound, deduplicated listener/Discord/exact-host transitions", async () => {
  const tokensByHostId = new Map([["prod-1", "a"], ["prod-2", "b"]]);
  const writable = sink();
  const reporter = createBotServiceStartupReporter({ context, tokensByHostId, writable, onFailure: assert.fail });
  const registry = fakeRegistry();
  reporter.attachRegistry(registry);
  registry.listener = "listening";
  reporter.report();
  reporter.report();
  reporter.setDiscord("connected");
  registry.ids = ["prod-1", "intruder"];
  reporter.report();
  registry.ids = ["prod-2", "prod-1"];
  reporter.report();
  await reporter.flush();
  const binding = {
    component: "bot", serviceKey: "bot", processEpochFingerprint: h("epoch"),
    effectiveConfigFingerprint: h("config"), configSourceIdentityFingerprint: h("source"),
  };
  const events = writable.lines.map((line) => {
    assert.equal(line.endsWith("\n"), true);
    return validateServiceStartupObservationEvent(JSON.parse(line), { binding, expectedState: reporter.expectedState });
  });
  assert.deepEqual(events.map((event) => event.sequence), [1, 2, 3, 4, 5]);
  assert.deepEqual(events.map(({ state }) => [state.listener, state.discord, state.connectedHostCount]), [
    ["closed", "disconnected", 0],
    ["listening", "disconnected", 0],
    ["listening", "connected", 0],
    ["listening", "connected", 1],
    ["listening", "connected", 2],
  ]);
  assert.equal(events[4].state.connectedHostSetFingerprint, managedHostSetFingerprint(tokensByHostId));
  assert.equal(events[3].state.connectedHostSetFingerprint, managedHostSetFingerprint(new Map([["prod-1", true]])));
  assert.equal(reporter.expectedState.expectedHostCount, 2);
  assert.equal(writable.lines.join("").includes("\"a\""), false);
});

test("bot reporter reports a failed writable once and stops emitting", async () => {
  const failures = [];
  const writable = sink({ fail: true });
  const reporter = createBotServiceStartupReporter({
    context, tokensByHostId: new Map(), writable, onFailure: (error) => failures.push(error.code),
  });
  reporter.attachRegistry(fakeRegistry());
  reporter.setDiscord("connected");
  await new Promise((resolve) => setImmediate(resolve));
  reporter.setDiscord("disconnected");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(failures, ["SERVICE_STARTUP_OBSERVATION_EMITTER_FAILED"]);
});

test("bot reporter refuses non-bot contexts and invalid options", () => {
  assert.throws(() => createBotServiceStartupReporter({
    context: { ...context, component: "daemon" }, tokensByHostId: new Map(), writable: sink(), onFailure() {},
  }), TypeError);
  assert.throws(() => createBotServiceStartupReporter({
    context, tokensByHostId: {}, writable: sink(), onFailure() {},
  }), TypeError);
  const reporter = createBotServiceStartupReporter({ context, tokensByHostId: new Map(), writable: sink(), onFailure() {} });
  assert.throws(() => reporter.setDiscord("ready"), TypeError);
  assert.throws(() => reporter.attachRegistry({}), TypeError);
});
