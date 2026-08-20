import assert from "node:assert/strict";
import { test } from "node:test";
import {
  WORKSPACE_INVENTORY_LIMITS,
  buildWorkspaceInventory,
  parseWorkspaceInventory,
  validateWorkspaceInventory,
  workspaceInventoryBytes,
  workspaceInventoryFingerprint,
  workspaceInventoryHostKey,
} from "../workspace-inventory.js";

const ROOT = "1".repeat(64);
const STORAGE = "2".repeat(64);

function workspace(overrides = {}) {
  return {
    hostId: "host-1",
    workspaceId: "workspace-1",
    sourcePlatform: "posix",
    workDir: "/srv/작업/프로젝트",
    rootIdentityFingerprint: ROOT,
    storageIdentityFingerprint: STORAGE,
    ...overrides,
  };
}

function inventory(overrides = {}) {
  return buildWorkspaceInventory({
    hostId: "host-1",
    inventoryGeneration: 1,
    workspaces: [workspace()],
    ...overrides,
  });
}

test("builds the exact canonical inventory and stable fingerprints", () => {
  const value = inventory();
  assert.equal(
    workspaceInventoryBytes(value).toString("utf8"),
    "{\"hostId\":\"host-1\",\"inventoryFingerprint\":\"9bef5a3fd61ddd23edc5e7005ab797494ca413adabe443f4afee5e80b3c0eb36\",\"inventoryGeneration\":1,\"version\":2,\"workspaces\":[{\"hostId\":\"host-1\",\"rootIdentityFingerprint\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"sourcePlatform\":\"posix\",\"storageIdentityFingerprint\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"workDir\":\"/srv/작업/프로젝트\",\"workspaceId\":\"workspace-1\"}]}",
  );
  assert.equal(value.inventoryFingerprint, "9bef5a3fd61ddd23edc5e7005ab797494ca413adabe443f4afee5e80b3c0eb36");
  assert.equal(workspaceInventoryFingerprint(value), value.inventoryFingerprint);
  assert.equal(
    workspaceInventoryHostKey("host-1"),
    "4a1796ac493525ff45c4e74eef19d7a30d2bfff7e693ef67e2a7e8efe62a98ef",
  );
});

test("sorts records by workspaceId UTF-8 bytes without mutating input", () => {
  const workspaces = [
    workspace({ workspaceId: "z" }),
    workspace({ workspaceId: "A" }),
    workspace({ workspaceId: "a" }),
  ];
  const value = inventory({ workspaces });
  assert.deepEqual(value.workspaces.map(({ workspaceId }) => workspaceId), ["A", "a", "z"]);
  assert.deepEqual(workspaces.map(({ workspaceId }) => workspaceId), ["z", "A", "a"]);
});

test("round-trips only canonical UTF-8 bytes", () => {
  const value = inventory();
  assert.deepEqual(parseWorkspaceInventory(workspaceInventoryBytes(value)), value);
  assert.throws(
    () => parseWorkspaceInventory(Buffer.from(` ${workspaceInventoryBytes(value)}`)),
    /JSON is not canonically encoded/,
  );
  assert.throws(
    () => parseWorkspaceInventory(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), workspaceInventoryBytes(value)])),
    /must not contain a BOM/,
  );
  assert.throws(
    () => parseWorkspaceInventory(Buffer.from([0xff])),
    /not valid UTF-8/,
  );
});

test("rejects duplicate JSON keys before schema validation", () => {
  assert.throws(
    () => parseWorkspaceInventory(Buffer.from(
      "{\"hostId\":\"host-1\",\"hostId\":\"host-2\",\"inventoryFingerprint\":\"" +
      "0".repeat(64) +
      "\",\"inventoryGeneration\":1,\"version\":2,\"workspaces\":[]}",
    )),
    /duplicate object key/,
  );
});

test("rejects unknown, missing, unsorted, duplicate, and foreign records", () => {
  const value = inventory({
    workspaces: [
      workspace({ workspaceId: "a" }),
      workspace({ workspaceId: "b" }),
    ],
  });
  assert.throws(
    () => validateWorkspaceInventory({ ...value, unexpected: true }),
    /top-level keys/,
  );
  const { inventoryFingerprint: _fingerprint, ...missing } = value;
  assert.throws(() => validateWorkspaceInventory(missing), /top-level keys/);
  assert.throws(
    () => workspaceInventoryFingerprint({ ...missing, workspaces: [...missing.workspaces].reverse() }),
    /unique and sorted/,
  );
  assert.throws(
    () => inventory({ workspaces: [workspace(), workspace()] }),
    /unique and sorted/,
  );
  assert.throws(
    () => inventory({ workspaces: [workspace({ hostId: "host-2" })] }),
    /workspace hostId/,
  );
  assert.throws(
    () => inventory({ workspaces: [{ ...workspace(), unexpected: true }] }),
    /workspace keys/,
  );
});

test("rejects invalid identifiers, platforms, paths, generations, and fingerprints", () => {
  for (const hostId of ["", "x".repeat(129), "가".repeat(43), "host\n1", "\ud800"]) {
    assert.throws(() => inventory({ hostId, workspaces: [] }), /hostId/);
  }
  for (const workspaceId of ["", "-bad", "bad/path", "é", "x".repeat(129)]) {
    assert.throws(
      () => inventory({ workspaces: [workspace({ workspaceId })] }),
      /workspaceId/,
    );
  }
  assert.throws(
    () => inventory({ workspaces: [workspace({ sourcePlatform: "darwin" })] }),
    /sourcePlatform/,
  );
  for (const workDir of ["", "x".repeat(4097), "가".repeat(1366), "bad\u0000path", "\udfff"]) {
    assert.throws(
      () => inventory({ workspaces: [workspace({ workDir })] }),
      /workDir/,
    );
  }
  for (const inventoryGeneration of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => inventory({ inventoryGeneration }), /inventoryGeneration/);
  }
  assert.throws(
    () => inventory({ workspaces: [workspace({ rootIdentityFingerprint: "A".repeat(64) })] }),
    /rootIdentityFingerprint/,
  );
  assert.throws(
    () => inventory({ workspaces: [workspace({ storageIdentityFingerprint: "0".repeat(63) })] }),
    /storageIdentityFingerprint/,
  );
});

test("accepts all platforms, empty inventory, maximum generation, and 64 records", () => {
  for (const sourcePlatform of ["posix", "windows-drive", "windows-unc"]) {
    assert.equal(
      inventory({ workspaces: [workspace({ sourcePlatform })] }).workspaces[0].sourcePlatform,
      sourcePlatform,
    );
  }
  assert.deepEqual(inventory({ workspaces: [] }).workspaces, []);
  assert.equal(
    inventory({ inventoryGeneration: Number.MAX_SAFE_INTEGER }).inventoryGeneration,
    Number.MAX_SAFE_INTEGER,
  );
  assert.equal(
    inventory({ hostId: "é".repeat(64), workspaces: [] }).hostId,
    "é".repeat(64),
  );
  assert.equal(
    inventory({ workspaces: [workspace({ workDir: "é".repeat(2048) })] }).workspaces[0].workDir,
    "é".repeat(2048),
  );
  const workspaces = Array.from(
    { length: WORKSPACE_INVENTORY_LIMITS.maxWorkspaces },
    (_, index) => workspace({ workspaceId: `workspace-${String(index).padStart(2, "0")}` }),
  );
  assert.equal(inventory({ workspaces }).workspaces.length, 64);
  assert.throws(
    () => inventory({ workspaces: [...workspaces, workspace({ workspaceId: "workspace-64" })] }),
    /workspaces/,
  );
});

test("preserves non-ASCII bytes without Unicode normalization", () => {
  const composed = inventory({ workspaces: [workspace({ workDir: "/srv/café" })] });
  const decomposed = inventory({ workspaces: [workspace({ workDir: "/srv/cafe\u0301" })] });
  assert.notEqual(composed.inventoryFingerprint, decomposed.inventoryFingerprint);
  assert.equal(parseWorkspaceInventory(workspaceInventoryBytes(composed)).workspaces[0].workDir, "/srv/café");
  assert.equal(parseWorkspaceInventory(workspaceInventoryBytes(decomposed)).workspaces[0].workDir, "/srv/cafe\u0301");
});

test("rejects altered fingerprints and oversized documents", () => {
  const value = inventory();
  assert.throws(
    () => validateWorkspaceInventory({ ...value, inventoryFingerprint: "0".repeat(64) }),
    /inventory fingerprint/,
  );
  assert.throws(
    () => parseWorkspaceInventory(Buffer.alloc(WORKSPACE_INVENTORY_LIMITS.maxBytes + 1, 0x20)),
    /byte limit/,
  );
});
