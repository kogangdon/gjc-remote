import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import {
  assertResidualProcessAbsence,
  RESIDUAL_PROCESS_REQUEST_KEYS,
} from "../src/workspace-residual-process.js";

const REQUEST = Object.freeze({ hostId: "host-a", workspaceId: "workspace-a" });

// Injected enumerator that returns a fixed result (array or otherwise), and
// records the exact scope it was queried with so tests can prove the guard
// forwards { hostId, workspaceId } unchanged.
function fakeIo(result) {
  const calls = [];
  return {
    calls,
    async listResidualProcesses(scope) {
      calls.push(scope);
      if (typeof result === "function") return result();
      return result;
    },
  };
}

async function expectRefusal(fn, code) {
  await assert.rejects(fn, (error) => {
    assert.equal(error.code, code, `expected code ${code}, got ${error.code}`);
    assert.equal(error.operation, "workspace_residual_process");
    return true;
  });
}

test("an empty residual-process list certifies absence with a frozen certificate", async () => {
  const io = fakeIo([]);
  const result = await assertResidualProcessAbsence(io, REQUEST);
  assert.deepEqual(result, { absent: true });
  assert.equal(Object.isFrozen(result), true);
  // The enumerator was scoped to exactly the requested host + workspace.
  assert.deepEqual(io.calls, [{ hostId: "host-a", workspaceId: "workspace-a" }]);
});

test("a non-empty residual-process list refuses WORKSPACE_RESIDUAL_PROCESS with pid context", async () => {
  const io = fakeIo([{ pid: 4321, name: "gjc" }, { pid: 99 }]);
  await assert.rejects(
    () => assertResidualProcessAbsence(io, REQUEST),
    (error) => {
      assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_RESIDUAL_PROCESS);
      assert.equal(error.operation, "workspace_residual_process");
      assert.equal(error.residualCount, 2);
      assert.deepEqual(error.pids, [4321, 99]);
      assert.equal(Object.isFrozen(error.pids), true);
      return true;
    }
  );
});

test("a non-array enumerator return is a contract violation refused CONFIG_INVALID", async () => {
  for (const bad of [null, undefined, {}, "processes", 3]) {
    const io = fakeIo(bad);
    await expectRefusal(
      () => assertResidualProcessAbsence(io, REQUEST),
      PROTOCOL_ERROR_CODES.CONFIG_INVALID
    );
  }
});

test("a malformed descriptor (missing/invalid pid) is refused CONFIG_INVALID, not absence", async () => {
  for (const bad of [
    [{ name: "no-pid" }],
    [{ pid: 0 }],
    [{ pid: -1 }],
    [{ pid: 1.5 }],
    [{ pid: "12" }],
    [null],
    [42],
    [{ pid: 10 }, { name: "second-is-bad" }],
  ]) {
    const io = fakeIo(bad);
    await expectRefusal(
      () => assertResidualProcessAbsence(io, REQUEST),
      PROTOCOL_ERROR_CODES.CONFIG_INVALID
    );
  }
});

test("a missing or non-function enumerator is refused CONFIG_INVALID before any query", async () => {
  for (const io of [null, undefined, {}, { listResidualProcesses: 5 }]) {
    await expectRefusal(
      () => assertResidualProcessAbsence(io, REQUEST),
      PROTOCOL_ERROR_CODES.CONFIG_INVALID
    );
  }
});

test("a request missing, extending, or mistyping identity is refused CONFIG_INVALID", async () => {
  const io = fakeIo([]);
  const bads = [
    undefined,
    {},
    { hostId: "host-a" },
    { workspaceId: "workspace-a" },
    { hostId: "host-a", workspaceId: "workspace-a", extra: 1 },
    { hostId: "", workspaceId: "workspace-a" },
    { hostId: "host-a", workspaceId: "" },
    { hostId: 1, workspaceId: "workspace-a" },
  ];
  for (const request of bads) {
    await expectRefusal(
      () => assertResidualProcessAbsence(io, request),
      PROTOCOL_ERROR_CODES.CONFIG_INVALID
    );
  }
  // None of the refusals consulted the enumerator except the well-formed ones;
  // the malformed-identity refusals must fail closed BEFORE the scan. Only the
  // requests that passed identity validation (none here) would call it.
  assert.deepEqual(io.calls, []);
});

test("the request key set is exactly hostId + workspaceId", () => {
  assert.deepEqual([...RESIDUAL_PROCESS_REQUEST_KEYS], ["hostId", "workspaceId"]);
  assert.equal(Object.isFrozen(RESIDUAL_PROCESS_REQUEST_KEYS), true);
});


test("a rejecting enumerator is wrapped fail-closed as CONFIG_INVALID, never absence", async () => {
  const io = {
    async listResidualProcesses() {
      throw new Error("native handle scan crashed");
    },
  };
  await assert.rejects(
    () => assertResidualProcessAbsence(io, REQUEST),
    (error) => {
      assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
      assert.equal(error.operation, "workspace_residual_process");
      // The raw enumerator failure is preserved as cause for diagnosis.
      assert.equal(error.cause instanceof Error, true);
      assert.match(error.cause.message, /native handle scan crashed/);
      return true;
    }
  );
});
