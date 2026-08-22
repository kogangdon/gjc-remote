import { workspaceInventoryBytes } from "@gjc-remote/shared/workspace-inventory";
import { parseWorkspaceInventory } from "./workspace-inventory.js";

const MAX_EPOCH = Number.MAX_SAFE_INTEGER;

const NATIVE_ERROR_CODES = new Map([
  ["INVENTORY_PENDING", Object.freeze({ status: "transient" })],
  ["INVENTORY_INVALID", Object.freeze({ status: "invalid", code: "INVENTORY_INVALID" })],
  ["INVENTORY_ACCESS_DENIED", Object.freeze({ status: "access_denied", code: "INVENTORY_ACCESS_DENIED" })],
  ["INVENTORY_STALE", Object.freeze({ status: "stale", code: "INVENTORY_STALE" })],
  ["INVENTORY_MANUAL_CLEANUP", Object.freeze({ status: "manual_cleanup", code: "INVENTORY_MANUAL_CLEANUP" })],
  ["WORKSPACE_ROOT_ESCAPE", Object.freeze({ status: "root_escape", code: "WORKSPACE_ROOT_ESCAPE" })],
  ["CONTAINMENT_UNSUPPORTED", Object.freeze({ status: "containment_unsupported", code: "CONTAINMENT_UNSUPPORTED" })],
  ["INVENTORY_IO_FAILED", Object.freeze({ status: "io_failed", code: "INVENTORY_IO_FAILED" })],
]);

function invalidReader() {
  const error = new TypeError("NATIVE_INVENTORY_READER_INVALID");
  error.code = "CONFIG_INVALID";
  return error;
}

function ownData(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor && Object.hasOwn(descriptor, "value") ? descriptor.value : undefined;
}

function exactDataKeys(object, keys) {
  if (object === null || typeof object !== "object" ||
      Array.isArray(object) || Object.getPrototypeOf(object) !== Object.prototype ||
      !Object.isFrozen(object)) {
    return false;
  }
  const actual = Reflect.ownKeys(object);
  return actual.length === keys.length &&
    actual.every((key) => typeof key === "string" && keys.includes(key)) &&
    keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(object, key);
      return descriptor?.enumerable === true && descriptor.get === undefined &&
        descriptor.set === undefined && Object.hasOwn(descriptor, "value");
    });
}

function frozenDataObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      !Object.isFrozen(value)) return false;
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length ||
      own.some((key) => typeof key !== "string" || !keys.includes(key))) {
    return false;
  }
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && descriptor.get === undefined &&
      descriptor.set === undefined && Object.hasOwn(descriptor, "value");
  });
}

function exactFrozenInventory(value) {
  if (!frozenDataObject(value, [
    "version",
    "hostId",
    "inventoryGeneration",
    "inventoryFingerprint",
    "workspaces",
  ])) return false;
  const workspaces = ownData(value, "workspaces");
  if (!Array.isArray(workspaces) || !Object.isFrozen(workspaces)) {
    return false;
  }
  const descriptors = Object.getOwnPropertyDescriptors(workspaces);
  const length = descriptors.length?.value;
  const own = Reflect.ownKeys(workspaces);
  if (!Number.isSafeInteger(length) || length < 0 ||
      own.length !== length + 1 ||
      !Object.hasOwn(descriptors, "length")) return false;
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.enumerable !== true ||
        descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, "value")) return false;
  }
  return workspaces.every((workspace) => frozenDataObject(workspace, [
    "hostId",
    "workspaceId",
    "sourcePlatform",
    "workDir",
    "rootIdentityFingerprint",
    "storageIdentityFingerprint",
  ]));
}

function normalizeReaderResult(result) {
  try {
    if (exactDataKeys(result, ["status"]) && ownData(result, "status") === "missing") {
      return Object.freeze({ status: "missing" });
    }
    if (!exactDataKeys(result, ["status", "inventory", "proof"]) ||
        ownData(result, "status") !== "present") {
      throw invalidReader();
    }
    const readerInventory = ownData(result, "inventory");
    if (!exactFrozenInventory(readerInventory)) throw invalidReader();
    const inventory = parseWorkspaceInventory(
      workspaceInventoryBytes(readerInventory));
    const proof = ownData(result, "proof");
    if (!exactDataKeys(proof, [
      "source",
      "inventoryGeneration",
      "inventoryFingerprint",
      "commitFingerprint",
      "floorFingerprint",
    ]) || ownData(proof, "source") !== "native" ||
        !Number.isSafeInteger(ownData(proof, "inventoryGeneration")) ||
        ownData(proof, "inventoryGeneration") < 1 ||
        ["inventoryFingerprint", "commitFingerprint", "floorFingerprint"].some((key) =>
          typeof ownData(proof, key) !== "string" ||
          !/^[0-9a-f]{64}$/.test(ownData(proof, key))) ||
        inventory.inventoryGeneration !== ownData(proof, "inventoryGeneration") ||
        inventory.inventoryFingerprint !== ownData(proof, "inventoryFingerprint")) {
      throw invalidReader();
    }
    return Object.freeze({
      status: "present",
      inventory,
      proof: Object.freeze({
        source: "native",
        inventoryGeneration: ownData(proof, "inventoryGeneration"),
        inventoryFingerprint: ownData(proof, "inventoryFingerprint"),
        commitFingerprint: ownData(proof, "commitFingerprint"),
        floorFingerprint: ownData(proof, "floorFingerprint"),
      }),
    });
  } catch (error) {
    if (error?.code === "CONFIG_INVALID") throw error;
    throw invalidReader();
  }
}

function nativeErrorResult(error) {
  try {
    if (!error || typeof error !== "object" ||
        Object.getOwnPropertySymbols(error).length !== 0 ||
        Object.keys(error).sort().join("\u0000") !==
          ["ambiguous", "code", "operation", "writes"].join("\u0000")) {
      return undefined;
    }
    const code = ownData(error, "code");
    const operation = ownData(error, "operation");
    const writes = ownData(error, "writes");
    const ambiguous = ownData(error, "ambiguous");
    if (typeof code !== "string" || typeof operation !== "string" ||
        !Number.isSafeInteger(writes) || writes < 0 ||
        typeof ambiguous !== "boolean") return undefined;
    return NATIVE_ERROR_CODES.get(code);
  } catch {
    return undefined;
  }
}

function snapshot(result, epoch) {
  return Object.freeze({ ...result, epoch });
}

function stateKey(result) {
  return result.status === "present"
    ? [
        result.status,
        result.proof.inventoryGeneration,
        result.proof.inventoryFingerprint,
        result.proof.commitFingerprint,
        result.proof.floorFingerprint,
      ].join("\u0000")
    : [result.status, result.code ?? ""].join("\u0000");
}

export function captureInventoryReader(reader) {
  try {
    if (!exactDataKeys(reader, ["selfTest", "readAccepted"]) ||
        typeof ownData(reader, "selfTest") !== "function") {
      throw invalidReader();
    }
    const descriptor = Object.getOwnPropertyDescriptor(reader, "readAccepted");
    if (!descriptor || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") {
      throw invalidReader();
    }
    return descriptor.value;
  } catch (error) {
    if (error?.code === "CONFIG_INVALID") throw error;
    throw invalidReader();
  }
}

export function createInventoryFloor({ reader, testEpochMismatch = false } = {}) {
  const readAccepted = captureInventoryReader(reader);
  const forceEpochMismatch = testEpochMismatch === true ||
    (Number.isSafeInteger(testEpochMismatch) && testEpochMismatch > 1);
  let epoch = Number.isSafeInteger(testEpochMismatch) && testEpochMismatch > 1
    ? testEpochMismatch
    : 1;
  let priorKey;
  let queued = Promise.resolve();

  const readOne = async () => {
    let state;
    try {
      state = normalizeReaderResult(await readAccepted());
    } catch (error) {
      const mapped = nativeErrorResult(error);
      if (!mapped) throw error;
      state = mapped;
    }
    const key = stateKey(state);
    if (priorKey !== undefined && (priorKey !== key || forceEpochMismatch)) {
      if (epoch === MAX_EPOCH) {
        const error = new RangeError("INVENTORY_EPOCH_OVERFLOW");
        error.code = "INVENTORY_INVALID";
        throw error;
      }
      epoch += 1;
    }
    priorKey = key;
    return snapshot(state, epoch);
  };

  return Object.freeze({
    async read() {
      const current = queued.then(readOne);
      queued = current.catch(() => undefined);
      return current;
    },
  });
}
