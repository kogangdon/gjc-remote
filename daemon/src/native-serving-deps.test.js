import test from "node:test";
import assert from "node:assert/strict";

import { assembleNativeServingDeps } from "./native-serving-deps.js";
import { createReadinessReplayWindow } from "./workspace-readiness-replay-window.js";

function fakeFactories(spy = {}) {
  const marker = (name) => ({ __marker: name });
  return {
    makeContainmentLowLevel: () => marker("lowLevel"),
    makeContainment: (arg) => {
      spy.containmentArg = arg;
      return { identifyRoot() {}, verifyContained() {}, __marker: "containment" };
    },
    makeGitVerifier: () => ({ verifyRepositoryGraph() {}, __marker: "gitVerifier" }),
    makeMaterializer: () => ({ materialize: marker("materialize"), preflight() {}, gitPath: "/git" }),
    makeByteReader: (arg) => {
      spy.byteReaderArg = arg;
      return { readBytes() {}, __marker: "byteReader" };
    },
    makePublisher: (arg) => {
      spy.publisherArg = arg;
      return { __marker: "publisher" };
    },
    makeManifestResolver: () => marker("resolveManifestPaths"),
    makeReplayWindow: (arg) => {
      spy.replayArg = arg;
      return { has() {}, add() {}, __marker: "replaySeen" };
    },
    makeActivityFence: (registry) => {
      spy.fenceRegistry = registry;
      return marker("acquireFence");
    },
  };
}

const baseArgs = () => ({
  workspaceRoot: "/ws/root",
  workspaceLeases: { acquireActivity() {} },
  maxAgeMs: 30000,
});

test("create bundle carries exactly the create dispatcher deps", () => {
  const spy = {};
  const { create } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories(spy) });
  assert.deepEqual(Object.keys(create).sort(), [
    "clock",
    "containment",
    "gitVerifier",
    "makeManifestIo",
    "makePublisherIo",
    "materialize",
    "maxAgeMs",
    "replaySeen",
    "resolveManifestPaths",
  ]);
  assert.equal(create.maxAgeMs, 30000);
  assert.equal(create.materialize.__marker, "materialize");
  assert.equal(create.containment.__marker, "containment");
  assert.equal(create.resolveManifestPaths.__marker, "resolveManifestPaths");
  assert.equal(typeof create.clock.now, "function");
  // no acquireFence on the create bundle
  assert.equal("acquireFence" in create, false);
});

test("refresh bundle is create + a non-exclusive activity fence", () => {
  const spy = {};
  const { create, refresh } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories(spy) });
  assert.equal(refresh.acquireFence.__marker, "acquireFence");
  // the activity fence is bound to the passed lease registry
  assert.ok(spy.fenceRegistry && typeof spy.fenceRegistry.acquireActivity === "function");
  // every create key is preserved on refresh
  for (const key of Object.keys(create)) {
    assert.equal(refresh[key], create[key], `refresh.${key} must equal create.${key}`);
  }
});

test("the SAME replaySeen instance is shared across create and refresh (caveat C1)", () => {
  const { create, refresh } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories({}) });
  assert.equal(create.replaySeen, refresh.replaySeen);
  assert.equal(create.replaySeen.__marker, "replaySeen");
});

test("C1 cross-op: a fingerprint burned via the create bundle is already seen via refresh", () => {
  // Use the REAL replay window so the shared-instance guarantee is behavioral,
  // not just referential: burning through one bundle must block the other.
  const { create, refresh } = assembleNativeServingDeps({
    ...baseArgs(),
    factories: { ...fakeFactories({}), makeReplayWindow: createReadinessReplayWindow },
  });
  assert.equal(create.replaySeen, refresh.replaySeen);
  assert.equal(refresh.replaySeen.has("fp-x"), false);
  create.replaySeen.add("fp-x"); // create burns it
  assert.equal(refresh.replaySeen.has("fp-x"), true); // refresh sees it as replayed
});

test("containment is built from the verified native low-level, replay window from clock+maxAgeMs", () => {
  const spy = {};
  const clock = { now: () => 42 };
  assembleNativeServingDeps({ ...baseArgs(), clock, factories: fakeFactories(spy) });
  assert.equal(spy.containmentArg.lowLevel.__marker, "lowLevel");
  assert.deepEqual(spy.replayArg, { maxAgeMs: 30000, clock });
});

test("makeManifestIo roots the byte reader at the candidate + source platform", () => {
  const spy = {};
  const { create } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories(spy) });
  const io = create.makeManifestIo("/ws/root/id/generations/g1", "windows");
  assert.equal(io.__marker, "byteReader");
  assert.deepEqual(spy.byteReaderArg, { root: "/ws/root/id/generations/g1", sourcePlatform: "windows" });
});

test("makePublisherIo binds the publisher to workspaceRoot + workspaceId", () => {
  const spy = {};
  const { create } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories(spy) });
  const io = create.makePublisherIo("ws-42");
  assert.equal(io.__marker, "publisher");
  assert.deepEqual(spy.publisherArg, { workspaceRoot: "/ws/root", workspaceId: "ws-42" });
});

test("invalid inputs fail closed", () => {
  const f = fakeFactories({});
  assert.throws(() => assembleNativeServingDeps({ ...baseArgs(), workspaceRoot: "", factories: f }), TypeError);
  assert.throws(() => assembleNativeServingDeps({ ...baseArgs(), workspaceLeases: null, factories: f }), TypeError);
  assert.throws(() => assembleNativeServingDeps({ ...baseArgs(), maxAgeMs: 0, factories: f }), TypeError);
  assert.throws(() => assembleNativeServingDeps({ ...baseArgs(), maxAgeMs: 1.5, factories: f }), TypeError);
  assert.throws(() => assembleNativeServingDeps({ ...baseArgs(), clock: {}, factories: f }), TypeError);
});

test("returned bundles are frozen", () => {
  const { create, refresh } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories({}) });
  assert.throws(() => {
    create.maxAgeMs = 1;
  }, TypeError);
  assert.throws(() => {
    refresh.acquireFence = null;
  }, TypeError);
});
