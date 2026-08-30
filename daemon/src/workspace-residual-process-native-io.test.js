import assert from "node:assert/strict";
import test from "node:test";
import { posix } from "node:path";

import { createResidualProcessNativeIo } from "../src/workspace-residual-process-native-io.js";
import { assertResidualProcessAbsence } from "../src/workspace-residual-process.js";

// A fake native enumerator projection that records its (workDir, sourcePlatform)
// call and returns a configurable holder set (or throws a native-style refusal).
function fakeEnumerator(behavior = { returns: [] }) {
  const calls = [];
  return {
    calls,
    enumerate_workspace_process_holders(workDir, sourcePlatform) {
      calls.push({ workDir, sourcePlatform });
      if (behavior.throws) throw behavior.throws;
      return behavior.returns;
    },
  };
}

const identity = { hostId: "host-A", workspaceRoot: "/srv/ws", sourcePlatform: "posix" };
const scope = (overrides = {}) => ({
  hostId: "host-A",
  workspaceId: "ws-42",
  workDir: posix.join("/srv/ws", "ws-42"),
  sourcePlatform: "posix",
  ...overrides,
});

test("rejects a constructor without a usable native enumerator", () => {
  for (const enumerator of [undefined, null, {}, { enumerate_workspace_process_holders: true }]) {
    assert.throws(
      () => createResidualProcessNativeIo({ ...identity, enumerator }),
      (e) => e.code === "CONFIG_INVALID",
    );
  }
});

test("rejects a constructor with a bad hostId, workspaceRoot, or sourcePlatform", () => {
  const enumerator = fakeEnumerator();
  assert.throws(() => createResidualProcessNativeIo({ ...identity, enumerator, hostId: "" }), (e) => e.code === "CONFIG_INVALID");
  assert.throws(() => createResidualProcessNativeIo({ ...identity, enumerator, workspaceRoot: "" }), (e) => e.code === "CONFIG_INVALID");
  assert.throws(() => createResidualProcessNativeIo({ ...identity, enumerator, sourcePlatform: "windows-unc" }), (e) => e.code === "CONFIG_INVALID");
  assert.throws(() => createResidualProcessNativeIo({ ...identity, enumerator, sourcePlatform: "linux" }), (e) => e.code === "CONFIG_INVALID");
});

test("scans the exact trusted inventory workDir and host source platform", async () => {
  const enumerator = fakeEnumerator({ returns: [] });
  const io = createResidualProcessNativeIo({ ...identity, enumerator });
  const result = await io.listResidualProcesses(scope());
  assert.deepEqual(result, []);
  assert.deepEqual(enumerator.calls, [{
    workDir: posix.join("/srv/ws", "ws-42"),
    sourcePlatform: "posix",
  }]);
});

test("passes the native holder set through unchanged", async () => {
  const holders = [{ pid: 100 }, { pid: 2048 }];
  const enumerator = fakeEnumerator({ returns: holders });
  const io = createResidualProcessNativeIo({ ...identity, enumerator });
  assert.deepEqual(await io.listResidualProcesses(scope()), holders);
});

test("refuses a request for a different host without scanning", async () => {
  const enumerator = fakeEnumerator();
  const io = createResidualProcessNativeIo({ ...identity, enumerator });
  await assert.rejects(
    () => io.listResidualProcesses(scope({ hostId: "host-B" })),
    (e) => e.code === "CONFIG_INVALID",
  );
  assert.equal(enumerator.calls.length, 0);
});

test("refuses a traversing or non-segment workspaceId without scanning", async () => {
  const enumerator = fakeEnumerator();
  const io = createResidualProcessNativeIo({ ...identity, enumerator });
  for (const workspaceId of ["..", ".", "../other", "a/b", "a\\b", "/x", "C:evil", "ws:stream", "ws.", "ws ", "with\0nul", ""]) {
    await assert.rejects(
      () => io.listResidualProcesses(scope({ workspaceId })),
      (e) => e.code === "CONFIG_INVALID",
      workspaceId,
    );
  }
  assert.equal(enumerator.calls.length, 0);
});

test("refuses a non-object request", async () => {
  const io = createResidualProcessNativeIo({ ...identity, enumerator: fakeEnumerator() });
  for (const request of [null, undefined, "x", 5]) {
    await assert.rejects(() => io.listResidualProcesses(request), (e) => e.code === "CONFIG_INVALID");
  }
});

test("native refusals propagate unwrapped and become fail-closed CONFIG_INVALID through the guard", async () => {
  const unsupported = new Error("scan unsupported");
  unsupported.code = "CONTAINMENT_UNSUPPORTED";
  const enumerator = fakeEnumerator({ throws: unsupported });
  const io = createResidualProcessNativeIo({ ...identity, enumerator });
  // Raw: the native error propagates unchanged.
  await assert.rejects(
    () => io.listResidualProcesses(scope()),
    (e) => e.code === "CONTAINMENT_UNSUPPORTED",
  );
  // Through the S5c guard: an unreadable scan is CONFIG_INVALID (never absent).
  await assert.rejects(
    () => assertResidualProcessAbsence(io, scope()),
    (e) => e.code === "CONFIG_INVALID",
  );
});

test("integrates with assertResidualProcessAbsence: empty certifies absence, non-empty blocks destruction", async () => {
  const absentIo = createResidualProcessNativeIo({ ...identity, enumerator: fakeEnumerator({ returns: [] }) });
  assert.deepEqual(await assertResidualProcessAbsence(absentIo, scope()), { absent: true });

  const heldIo = createResidualProcessNativeIo({ ...identity, enumerator: fakeEnumerator({ returns: [{ pid: 7 }] }) });
  await assert.rejects(
    () => assertResidualProcessAbsence(heldIo, scope()),
    (e) => e.code === "WORKSPACE_RESIDUAL_PROCESS",
  );
});

test("the adapter surface is frozen", () => {
  const io = createResidualProcessNativeIo({ ...identity, enumerator: fakeEnumerator() });
  assert.equal(Object.isFrozen(io), true);
});
