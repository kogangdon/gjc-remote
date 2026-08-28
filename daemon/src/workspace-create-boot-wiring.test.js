import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveLifecycleCreateDispatcher,
  resolveTrustedCreateBinding,
  projectServingReadiness,
} from "../src/workspace-create-boot-wiring.js";

// A minimal-but-complete native serving deps bundle: exactly the create
// orchestrator dependency set that workspace-create-dispatch.js's factory
// validates. Fakes only; no fs/git/subprocess.
function nativeServingDeps() {
  return {
    containment: {
      identifyRoot: async () => ({ rootIdentity: {}, storageIdentity: {} }),
      verifyContained: async () => ({ identity: {}, rootIdentity: {} }),
    },
    gitVerifier: { verifyRepositoryGraph: async () => ({}) },
    makeManifestIo: () => ({ readBytes: async () => Buffer.from("x") }),
    makePublisherIo: async () => ({
      readLivePointer: async () => null,
      writeTemp: async () => "t",
      flushTemp: async () => {},
      replace: async () => {},
      flushParent: async () => {},
    }),
    materialize: async () => {},
    resolveManifestPaths: async () => ["a.txt"],
    clock: { now: () => 1 },
    maxAgeMs: 5_000,
    replaySeen: { has: () => false, add: () => {} },
  };
}

// --- resolveLifecycleCreateDispatcher: fail-closed unless every gate is met ---

test("resolveLifecycleCreateDispatcher: disabled serving returns null", () => {
  assert.equal(
    resolveLifecycleCreateDispatcher({ enabled: false, workspaceRoot: "/srv/ws", nativeServingDeps: nativeServingDeps() }),
    null,
  );
});

test("resolveLifecycleCreateDispatcher: missing workspaceRoot returns null", () => {
  assert.equal(
    resolveLifecycleCreateDispatcher({ enabled: true, workspaceRoot: "", nativeServingDeps: nativeServingDeps() }),
    null,
  );
});

test("resolveLifecycleCreateDispatcher: absent native deps bundle returns null", () => {
  assert.equal(resolveLifecycleCreateDispatcher({ enabled: true, workspaceRoot: "/srv/ws" }), null);
  assert.equal(
    resolveLifecycleCreateDispatcher({ enabled: true, workspaceRoot: "/srv/ws", nativeServingDeps: null }),
    null,
  );
});

test("resolveLifecycleCreateDispatcher: fully eligible constructs a dispatcher", () => {
  const dispatcher = resolveLifecycleCreateDispatcher({
    enabled: true,
    workspaceRoot: "/srv/ws",
    nativeServingDeps: nativeServingDeps(),
  });
  assert.ok(dispatcher);
  assert.equal(typeof dispatcher.dispatchCreate, "function");
});

// --- resolveTrustedCreateBinding: the sole trusted authority source ---

function bindingsMap(entries) {
  return new Map(entries.map(({ bindingId, workspaceId }) => [
    bindingId,
    { binding: { bindingId, workspaceId, hostId: "host-1" } },
  ]));
}

test("resolveTrustedCreateBinding: returns the binding whose workspaceId matches", () => {
  const bindings = bindingsMap([
    { bindingId: "b1", workspaceId: "workspace-1" },
    { bindingId: "b2", workspaceId: "workspace-2" },
  ]);
  const found = resolveTrustedCreateBinding(bindings, "workspace-2");
  assert.equal(found.bindingId, "b2");
  assert.equal(found.workspaceId, "workspace-2");
});

test("resolveTrustedCreateBinding: unknown workspaceId returns null", () => {
  const bindings = bindingsMap([{ bindingId: "b1", workspaceId: "workspace-1" }]);
  assert.equal(resolveTrustedCreateBinding(bindings, "workspace-9"), null);
});

test("resolveTrustedCreateBinding: rejects a non-iterable bindings container", () => {
  assert.equal(resolveTrustedCreateBinding(null, "workspace-1"), null);
  assert.equal(resolveTrustedCreateBinding({}, "workspace-1"), null);
});

test("resolveTrustedCreateBinding: rejects an empty workspaceId", () => {
  const bindings = bindingsMap([{ bindingId: "b1", workspaceId: "workspace-1" }]);
  assert.equal(resolveTrustedCreateBinding(bindings, ""), null);
});

// --- projectServingReadiness: four dimensions, live source, fail-closed ---

test("projectServingReadiness: maps each live status dimension", () => {
  const snapshot = projectServingReadiness({
    connection: "online",
    runtime: "ready",
    providerAuth: "configured",
    modelProfile: "ready",
    workspace: "present",
  });
  assert.deepEqual(snapshot, {
    connection: { state: "online", source: "live" },
    runtime: { state: "ready", source: "live" },
    providerAuth: { state: "configured", source: "live" },
    modelProfile: { state: "ready", source: "live" },
  });
});

test("projectServingReadiness: a missing dimension projects to unknown", () => {
  const snapshot = projectServingReadiness({ connection: "online" });
  assert.equal(snapshot.runtime.state, "unknown");
  assert.equal(snapshot.runtime.source, "live");
  assert.equal(snapshot.connection.state, "online");
});

test("projectServingReadiness: a nullish status yields all-unknown", () => {
  const snapshot = projectServingReadiness(undefined);
  for (const dim of ["connection", "runtime", "providerAuth", "modelProfile"]) {
    assert.equal(snapshot[dim].state, "unknown");
  }
});
