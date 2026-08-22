import assert from "node:assert/strict";
import test from "node:test";
import { buildWorkspaceInventory } from "@gjc-remote/shared/workspace-inventory";

import {
  captureInventoryReader,
  createInventoryFloor,
} from "../src/inventory-floor.js";

function accepted({
  inventoryGeneration = 1,
  variant = "empty",
  commitFingerprint = "c".repeat(64),
  floorFingerprint = "d".repeat(64),
} = {}) {
  const built = buildWorkspaceInventory({
    hostId: "provider-test-host",
    inventoryGeneration,
    workspaces: variant === "empty" ? [] : [{
      hostId: "provider-test-host",
      workspaceId: "workspace",
      sourcePlatform: "posix",
      workDir: "/workspace",
      rootIdentityFingerprint: "a".repeat(64),
      storageIdentityFingerprint: "b".repeat(64),
    }],
  });
  const inventory = Object.freeze({
    ...built,
    workspaces: Object.freeze(
      built.workspaces.map((workspace) => Object.freeze({ ...workspace }))),
  });
  return Object.freeze({
    status: "present",
    inventory,
    proof: Object.freeze({
      source: "native",
      inventoryGeneration,
      inventoryFingerprint: inventory.inventoryFingerprint,
      commitFingerprint,
      floorFingerprint,
    }),
  });
}

function reader(values) {
  let index = 0;
  return Object.freeze({
    selfTest: async () => Object.freeze({
      role: "daemon",
      contractVersion: 4,
      writes: 0,
    }),
    readAccepted: async () => {
      const value = values[Math.min(index++, values.length - 1)];
      if (value instanceof Error) throw value;
      return value;
    },
  });
}

function nativeError(code) {
  return Object.assign(new Error(code), {
    code,
    operation: "read_inventory",
    writes: 0,
    ambiguous: false,
  });
}

test("normalizes exact frozen native missing and present snapshots", async () => {
  const floor = createInventoryFloor({ reader: reader([
    Object.freeze({ status: "missing" }),
    accepted(),
  ]) });
  const missing = await floor.read();
  const present = await floor.read();
  assert.deepEqual(missing, { status: "missing", epoch: 1 });
  assert.deepEqual(present, {
    status: "present",
    inventory: accepted().inventory,
    epoch: 2,
    proof: {
      source: "native",
      inventoryGeneration: 1,
      inventoryFingerprint: accepted().inventory.inventoryFingerprint,
      commitFingerprint: "c".repeat(64),
      floorFingerprint: "d".repeat(64),
    },
  });
  assert.equal(Object.isFrozen(missing), true);
  assert.equal(Object.isFrozen(present), true);
  assert.equal(Object.isFrozen(present.proof), true);
});

test("retains the epoch only for an identical native state key", async () => {
  const floor = createInventoryFloor({ reader: reader([
    accepted(), accepted(),
    accepted({ inventoryGeneration: 2 }),
    accepted({ inventoryGeneration: 2, variant: "one" }),
    accepted({ inventoryGeneration: 2, variant: "one", commitFingerprint: "e".repeat(64) }),
    accepted({ inventoryGeneration: 2, variant: "one", commitFingerprint: "e".repeat(64), floorFingerprint: "f".repeat(64) }),
    Object.freeze({ status: "missing" }),
  ]) });
  const epochs = [];
  for (let index = 0; index < 7; index += 1) epochs.push((await floor.read()).epoch);
  assert.deepEqual(epochs, [1, 1, 2, 3, 4, 5, 6]);
});

test("serializes concurrent Reader calls", async () => {
  let active = 0;
  let maximum = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const floor = createInventoryFloor({ reader: Object.freeze({
    selfTest: async () => {},
    readAccepted: async () => {
      active += 1;
      maximum = Math.max(maximum, active);
      await gate;
      active -= 1;
      return Object.freeze({ status: "missing" });
    },
  }) });
  const first = floor.read();
  const second = floor.read();
  await Promise.resolve();
  assert.equal(maximum, 1);
  release();
  await Promise.all([first, second]);
  assert.equal(maximum, 1);
});

test("maps every known native error without retaining a prior present snapshot", async () => {
  const cases = [
    ["INVENTORY_PENDING", { status: "transient", epoch: 2 }],
    ["INVENTORY_INVALID", { status: "invalid", code: "INVENTORY_INVALID", epoch: 3 }],
    ["INVENTORY_ACCESS_DENIED", { status: "access_denied", code: "INVENTORY_ACCESS_DENIED", epoch: 4 }],
    ["INVENTORY_STALE", { status: "stale", code: "INVENTORY_STALE", epoch: 5 }],
    ["INVENTORY_MANUAL_CLEANUP", { status: "manual_cleanup", code: "INVENTORY_MANUAL_CLEANUP", epoch: 6 }],
    ["WORKSPACE_ROOT_ESCAPE", { status: "root_escape", code: "WORKSPACE_ROOT_ESCAPE", epoch: 7 }],
    ["CONTAINMENT_UNSUPPORTED", { status: "containment_unsupported", code: "CONTAINMENT_UNSUPPORTED", epoch: 8 }],
    ["INVENTORY_IO_FAILED", { status: "io_failed", code: "INVENTORY_IO_FAILED", epoch: 9 }],
  ];
  const values = [accepted(), ...cases.map(([code]) => {
    return nativeError(code);
  })];
  const floor = createInventoryFloor({ reader: reader(values) });
  assert.equal((await floor.read()).status, "present");
  for (const [, expected] of cases) assert.deepEqual(await floor.read(), expected);
});

test("retains identical failures and increments on recovery", async () => {
  const stale = nativeError("INVENTORY_STALE");
  const floor = createInventoryFloor({ reader: reader([
    accepted(), stale, stale, accepted(),
  ]) });
  assert.deepEqual(
    [await floor.read(), await floor.read(), await floor.read(), await floor.read()]
      .map((result) => result.epoch),
    [1, 2, 2, 3]
  );
});

test("unknown Reader errors throw and malformed results fail closed", async () => {
  const unknown = new Error("unexpected");
  const floor = createInventoryFloor({ reader: reader([accepted(), unknown]) });
  assert.equal((await floor.read()).status, "present");
  await assert.rejects(floor.read(), (error) => error === unknown);
  const malformedNative = new Error("malformed native envelope");
  malformedNative.code = "INVENTORY_STALE";
  await assert.rejects(
    createInventoryFloor({ reader: reader([malformedNative]) }).read(),
    (error) => error === malformedNative,
  );
  const malformed = createInventoryFloor({ reader: reader([Object.freeze({ status: "present" })]) });
  await assert.rejects(malformed.read(), (error) => error?.code === "CONFIG_INVALID");
  const missingWithSymbol = Object.freeze({
    status: "missing",
    [Symbol("extra")]: true,
  });
  await assert.rejects(
    createInventoryFloor({ reader: reader([missingWithSymbol]) }).read(),
    (error) => error?.code === "CONFIG_INVALID",
  );
  const hiddenResult = accepted();
  const hiddenProof = Object.freeze(Object.defineProperty(
    { ...hiddenResult.proof }, "hidden", { value: true },
  ));
  const presentWithHiddenProof = Object.freeze({
    status: "present",
    inventory: hiddenResult.inventory,
    proof: hiddenProof,
  });
  await assert.rejects(
    createInventoryFloor({ reader: reader([presentWithHiddenProof]) }).read(),
    (error) => error?.code === "CONFIG_INVALID",
  );
  const valid = accepted();
  const presentWithMutableInventory = Object.freeze({
    status: "present",
    inventory: { ...valid.inventory },
    proof: valid.proof,
  });
  await assert.rejects(
    createInventoryFloor({
      reader: reader([presentWithMutableInventory]),
    }).read(),
    (error) => error?.code === "CONFIG_INVALID",
  );
  const hiddenStatus = Object.freeze(Object.defineProperty({}, "status", {
    enumerable: false,
    value: "missing",
  }));
  const nullPrototype = Object.assign(Object.create(null), {
    status: "missing",
  });
  Object.freeze(nullPrototype);
  for (const value of [hiddenStatus, nullPrototype]) {
    await assert.rejects(
      createInventoryFloor({ reader: reader([value]) }).read(),
      (error) => error?.code === "CONFIG_INVALID",
    );
  }
});

test("test-only forced increments fail closed at the safe integer limit", async () => {
  const floor = createInventoryFloor({
    reader: reader([Object.freeze({ status: "missing" })]),
    testEpochMismatch: Number.MAX_SAFE_INTEGER,
  });
  assert.equal((await floor.read()).epoch, Number.MAX_SAFE_INTEGER);
  await assert.rejects(floor.read(), (error) => error?.code === "INVENTORY_INVALID");
});

test("each floor instance starts a fresh epoch namespace", async () => {
  const nativeReader = reader([Object.freeze({ status: "missing" })]);
  assert.equal((await createInventoryFloor({ reader: nativeReader }).read()).epoch, 1);
  assert.equal((await createInventoryFloor({ reader: nativeReader }).read()).epoch, 1);
});

test("Reader capture requires an own data descriptor", () => {
  assert.throws(
    () => captureInventoryReader(Object.create({ readAccepted: async () => {} })),
    (error) => error?.code === "CONFIG_INVALID"
  );
  assert.throws(
    () => captureInventoryReader(Object.freeze(Object.defineProperties({}, {
      selfTest: { enumerable: true, value: async () => {} },
      readAccepted: { enumerable: true, get: () => async () => {} },
    }))),
    (error) => error?.code === "CONFIG_INVALID"
  );
  assert.throws(
    () => captureInventoryReader(new Proxy(Object.freeze({
      selfTest: async () => {},
      readAccepted: async () => {},
    }), {
      getOwnPropertyDescriptor() { throw new Error("trap"); },
    })),
    (error) => error?.code === "CONFIG_INVALID"
  );
});
