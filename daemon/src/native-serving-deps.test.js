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
    makeManifestResolver: () => {
      const resolveManifestPaths = async () => [];
      resolveManifestPaths.__marker = "resolveManifestPaths";
      return resolveManifestPaths;
    },
    makeReplayWindow: (arg) => {
      spy.replayArg = arg;
      return { has() {}, add() {}, __marker: "replaySeen" };
    },
    makeActivityFence: (registry) => {
      spy.fenceRegistry = registry;
      const acquireFence = () => marker("lease");
      acquireFence.__marker = "acquireFence";
      return acquireFence;
    },
    makeExclusiveFence: (registry) => {
      spy.exclusiveFenceRegistry = registry;
      const acquireFence = () => marker("exclusiveLease");
      acquireFence.__marker = "acquireExclusiveFence";
      return acquireFence;
    },
    makeResidualEnumerator: () => {
      spy.residualEnumerator = {
        enumerate_workspace_process_holders() {
          return [];
        },
        __marker: "residualEnumerator",
      };
      return spy.residualEnumerator;
    },
    makeResidualIo: (arg) => {
      spy.residualIoArg = arg;
      return { listResidualProcesses() {}, __marker: "residualIo" };
    },
  };
}

const baseArgs = () => ({
  workspaceRoot: "/ws/root",
  workspaceLeases: { acquireActivity() {} },
  maxAgeMs: 30000,
  hostId: "host-1",
  sourcePlatform: "posix",
  runtimePlatform: "linux",
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

test("reset/delete bundle is frozen and carries only its static dependencies", () => {
  const spy = {};
  const { create, resetDelete } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories(spy) });
  assert.ok(Object.isFrozen(resetDelete));
  assert.deepEqual(Object.keys(resetDelete).sort(), [
    "acquireFence",
    "makeBackupIo",
    "makePublisherIo",
    "residualIo",
    "resolveManifestPaths",
  ]);
  assert.equal(resetDelete.makeBackupIo, create.makeManifestIo);
  assert.equal(resetDelete.residualIo.__marker, "residualIo");
  assert.equal("probeQuiescence" in resetDelete, false);
});

test("reset/delete uses an exclusive fence and a real residual-process adapter", () => {
  const spy = {};
  const args = baseArgs();
  const { resetDelete } = assembleNativeServingDeps({ ...args, factories: fakeFactories(spy) });
  assert.equal(resetDelete.acquireFence.__marker, "acquireExclusiveFence");
  assert.equal(spy.exclusiveFenceRegistry, args.workspaceLeases);
  assert.deepEqual(spy.residualIoArg, {
    enumerator: spy.residualEnumerator,
    hostId: "host-1",
    workspaceRoot: "/ws/root",
    sourcePlatform: "posix",
  });
});

test("reset/delete backup IO is deferred and backed by the contained byte reader", () => {
  const spy = {};
  const { resetDelete } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories(spy) });
  assert.equal(spy.byteReaderArg, undefined);
  const io = resetDelete.makeBackupIo("/ws/root/ws/generations/1", "posix");
  assert.equal(io.__marker, "byteReader");
  assert.deepEqual(spy.byteReaderArg, {
    root: "/ws/root/ws/generations/1",
    sourcePlatform: "posix",
  });
});

test("a missing or refusing residual capability leaves only reset/delete inert", () => {
  for (const factories of [
    { ...fakeFactories({}), makeResidualEnumerator: () => null },
    { ...fakeFactories({}), makeResidualEnumerator: () => { throw new Error("native capability refused"); } },
  ]) {
    const bundles = assembleNativeServingDeps({ ...baseArgs(), factories });
    assert.equal(bundles.resetDelete, null);
    assert.ok(bundles.create);
    assert.ok(bundles.refresh);
  }
});

test("non-Linux runtimes leave only reset/delete inert", () => {
  for (const runtimePlatform of ["win32", "darwin"]) {
    const bundles = assembleNativeServingDeps({
      ...baseArgs(),
      runtimePlatform,
      factories: fakeFactories({}),
    });
    assert.equal(bundles.resetDelete, null);
    assert.ok(bundles.create);
    assert.ok(bundles.refresh);
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
  const { create, refresh, resetDelete } = assembleNativeServingDeps({ ...baseArgs(), factories: fakeFactories({}) });
  assert.throws(() => {
    create.maxAgeMs = 1;
  }, TypeError);
  assert.throws(() => {
    refresh.acquireFence = null;
  }, TypeError);
  assert.throws(() => {
    resetDelete.acquireFence = null;
  }, TypeError);
});
