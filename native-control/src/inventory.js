import { isPrincipal } from '@gjc-remote/shared/identity';
import { STRICT_JSON_LIMITS } from '@gjc-remote/shared/strict-json';
import { parseWorkspaceInventory, workspaceInventoryHostKey } from '@gjc-remote/shared/workspace-inventory';
import { createInventoryPublisherTransaction } from './inventory-publisher.js';
import {
  buildFloor, exact, floorBytes, hash, leaf, objectIdentity, parseCommit,
  parseFloor, readEnvelope, sameBytes, uint64,
} from './inventory-state.js';

const FACTORY_KEYS = Object.freeze(['hostId', 'roles']);
const ROLE_KEYS = Object.freeze(['management', 'bot', 'recovery', 'daemon', 'system']);
const PRINCIPAL_KEYS = Object.freeze(['kind', 'value']);
const getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const getPrototypeOf = Object.getPrototypeOf;
const ownKeys = Reflect.ownKeys;
const localErrors = new WeakSet();

function localError(code, operation, writes = 0, ambiguous = false) {
  const error = new Error('inventory operation failed');
  Object.defineProperties(error, {
    code: { value: code, enumerable: true },
    operation: { value: operation, enumerable: true },
    writes: { value: writes, enumerable: true },
    ambiguous: { value: ambiguous, enumerable: true },
  });
  localErrors.add(error);
  return error;
}

function isLocalError(value) {
  return value !== null &&
    (typeof value === 'object' || typeof value === 'function') &&
    localErrors.has(value);
}

function addWrites(total, amount) {
  if (!Number.isSafeInteger(amount) || amount < 0 ||
      total > Number.MAX_SAFE_INTEGER - amount) {
    throw localError('INVENTORY_IO_FAILED', 'read_inventory', total, true);
  }
  return total + amount;
}

function invalid() {
  throw localError('INVENTORY_INVALID', 'resolve_native_state_root');
}

function exactDataValues(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        getPrototypeOf(value) !== Object.prototype) return null;
    const names = ownKeys(value);
    if (names.length !== keys.length || names.some((name) => typeof name !== 'string') ||
        !keys.every((key) => names.includes(key))) return null;
    const descriptors = getOwnPropertyDescriptors(value);
    const values = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.enumerable !== true || descriptor.get !== undefined ||
          descriptor.set !== undefined || !Object.hasOwn(descriptor, 'value')) return null;
      values[key] = descriptor.value;
    }
    return values;
  } catch {
    return null;
  }
}

function isWindowsSidShape(value) {
  const fields = value.split('-');
  if (fields.length < 4 || fields.length > 18 ||
      fields[0] !== 'S' || fields[1] !== '1') return false;
  const decimal = /^(0|[1-9][0-9]*)$/;
  if (!fields.slice(2).every((field) => decimal.test(field))) return false;
  try {
    if (BigInt(fields[2]) > 281474976710655n) return false;
    return fields.slice(3).every((field) => BigInt(field) <= 4294967295n);
  } catch {
    return false;
  }
}

function principalSnapshot(value) {
  const values = exactDataValues(value, PRINCIPAL_KEYS);
  if (!values) return null;
  if (typeof values.value !== 'string' ||
      Buffer.byteLength(values.value, 'utf8') > 4096 ||
      (values.kind === 'sid' && !isWindowsSidShape(values.value))) return null;
  const principal = { kind: values.kind, value: values.value };
  try {
    return isPrincipal(principal) ? Object.freeze(principal) : null;
  } catch {
    return null;
  }
}

function validateOptions(options) {
  const values = exactDataValues(options, FACTORY_KEYS);
  if (!values) invalid();
  const roleValues = exactDataValues(values.roles, ROLE_KEYS);
  if (!roleValues) invalid();
  const principals = ROLE_KEYS.map((key) => principalSnapshot(roleValues[key]));
  if (principals.some((principal) => principal === null)) invalid();
  const kind = principals[0].kind;
  const requiredKind = process.platform === 'win32' ? 'sid' :
    process.platform === 'linux' ? 'uid' : null;
  if (!principals.every((principal) => principal.kind === kind) ||
      kind !== requiredKind ||
      new Set(principals.map((principal) => principal.value)).size !== principals.length ||
      (kind === 'sid' ? principals[4].value !== 'S-1-5-18' : principals[4].value !== 'uid:0')) invalid();
  let hostKey;
  try {
    hostKey = workspaceInventoryHostKey(values.hostId);
  } catch {
    invalid();
  }
  return Object.freeze({
    hostId: values.hostId,
    hostKey,
    roles: Object.freeze(
      Object.fromEntries(ROLE_KEYS.map((key, index) => [key, principals[index]]))),
  });
}

function requireLowLevel(lowLevel, publisher) {
  if (lowLevel === null || typeof lowLevel !== 'object' ||
      Array.isArray(lowLevel)) invalid();
  const names = publisher ? [
    'resolve_native_state_root',
    'verify_inventory_acl',
    'read_workspace_root_facts',
    'ensure_inventory_directory',
    'acquire_inventory_fence',
    'read_inventory_object',
    'publish_inventory_object_atomic',
  ] : [
    'resolve_native_state_root',
    'verify_inventory_acl',
    'read_workspace_root_facts',
    'acquire_inventory_fence',
    'read_inventory_object',
    'publish_inventory_object_atomic',
  ];
  let descriptors;
  try {
    descriptors = getOwnPropertyDescriptors(lowLevel);
  } catch {
    invalid();
  }
  const captured = {};
  for (const name of names) {
    const descriptor = descriptors[name];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') invalid();
    captured[name] = descriptor.value;
  }
  // Capture each verified data property once so later object mutation cannot
  // alter an adapter transaction.
  return Object.freeze(captured);
}

async function verifyAcl(lowLevel, path, roles, profile, expectedActor) {
  if (await lowLevel.verify_inventory_acl(path, roles, profile, expectedActor) !== true) {
    throw localError('INVENTORY_ACCESS_DENIED', 'verify_inventory_acl');
  }
}

function requireResolvedRoot(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw localError('INVENTORY_IO_FAILED', 'resolve_native_state_root');
  }
  return value;
}

function fenceValue(value) {
  const result = exact(value, ['release', 'writes']);
  return result && typeof result.release === 'function' &&
    Number.isSafeInteger(result.writes) && result.writes >= 0 ? result : null;
}

function factsMatch(workspace, value) {
  const result = exact(value, ['sourcePlatform', 'workDir', 'rootIdentity', 'storageIdentity']);
  if (!result || result.sourcePlatform !== workspace.sourcePlatform ||
      result.workDir !== workspace.workDir || !objectIdentityLike(result.rootIdentity, workspace.sourcePlatform, true) ||
      !objectIdentityLike(result.storageIdentity, workspace.sourcePlatform, false)) return false;
  return hash(result.rootIdentity) === workspace.rootIdentityFingerprint &&
    hash(result.storageIdentity) === workspace.storageIdentityFingerprint;
}

function objectIdentityLike(value, platform, root) {
  if (platform === 'posix') {
    const names = root ? ['kind', 'device', 'inode'] : ['kind', 'device'];
    const item = exact(value, names);
    return !!item && item.kind === (root ? 'posix-root-v1' : 'posix-storage-v1') &&
      uint64(item.device) && (!root || uint64(item.inode));
  }
  if (platform === 'windows-drive') {
    const names = root ? ['kind', 'volumeSerial', 'fileId'] : ['kind', 'volumeGuid', 'volumeSerial', 'fileSystem'];
    const item = exact(value, names);
    return !!item && item.kind === (root ? 'win32-root-v1' : 'windows-drive-storage-v1') &&
      (root ? /^[a-f0-9]{16}$/.test(item.volumeSerial) && /^[a-f0-9]{32}$/.test(item.fileId) :
        /^\\\\\?\\VOLUME\{[0-9A-F-]{36}\}\\$/.test(item.volumeGuid) && /^[0-9A-F]{8}$/.test(item.volumeSerial) && /^[A-Z0-9._-]{1,32}$/.test(item.fileSystem));
  }
  return false;
}

function checkedPublication(value) {
  const result = exact(value, ['writes', 'identity']);
  return result && Number.isSafeInteger(result.writes) && result.writes >= 0 &&
    objectIdentity(result.identity) ? result : null;
}

function requirePublication(value, expectedWrites) {
  const result = checkedPublication(value);
  if (result && result.writes === expectedWrites) return result;
  const writes = Number.isSafeInteger(value?.writes) && value.writes >= 0
    ? value.writes : 0;
  throw localError(
    'INVENTORY_IO_FAILED', 'publish_inventory_object_atomic', writes, true);
}

function frozenInventory(value) {
  return Object.freeze({
    ...value,
    workspaces: Object.freeze(
      value.workspaces.map((workspace) => Object.freeze({ ...workspace }))),
  });
}

async function createAdapter(loadLowLevel, options, role) {
  const validated = validateOptions(options);
  if (typeof loadLowLevel !== 'function') invalid();
  const publisher = role === 'management';
  const lowLevel = requireLowLevel(await loadLowLevel(), publisher);
  if (!publisher) return createReaderAdapter(lowLevel, validated);
  const inventoryRoot = requireResolvedRoot(
    await lowLevel.resolve_native_state_root(validated.hostKey, 'inventory'));
  const selfTest = async () => {
    await verifyAcl(lowLevel, inventoryRoot, validated.roles, 'inventory-directory', role);
    return Object.freeze({ role, contractVersion: 4, writes: 0 });
  };
  await selfTest();
  const publish = createInventoryPublisherTransaction({
    lowLevel,
    hostId: validated.hostId,
    roles: validated.roles,
    inventoryRoot,
  });
  return Object.freeze({ selfTest, publish });
}

async function createReaderAdapter(lowLevel, validated) {
  const roots = async () => {
    const inventoryRoot = requireResolvedRoot(await lowLevel.resolve_native_state_root(validated.hostKey, 'inventory'));
    const readerRoot = requireResolvedRoot(await lowLevel.resolve_native_state_root(validated.hostKey, 'reader'));
    await verifyAcl(lowLevel, inventoryRoot, validated.roles, 'inventory-directory', 'daemon');
    await verifyAcl(lowLevel, readerRoot, validated.roles, 'reader-directory', 'daemon');
    return { inventoryRoot, readerRoot };
  };
  const selfTest = async () => {
    await roots();
    return Object.freeze({ role: 'daemon', contractVersion: 4, writes: 0 });
  };
  const readAccepted = async () => {
    let fence; let body; let bodyExact = false; let outcome;
    let releaseError; let writes = 0; let returnedFloorIdentity;
    try {
      const { inventoryRoot, readerRoot } = await roots();
      const paths = {
        marker: leaf(inventoryRoot, 'inventory-manual-cleanup.v1.json'),
        inventory: leaf(inventoryRoot, 'workspace-inventory.v2.json'),
        commit: leaf(inventoryRoot, 'inventory-commit.v1.json'),
        fence: leaf(inventoryRoot, 'inventory-publication.lock'),
        floor: leaf(readerRoot, 'inventory-floor.v1.json'),
      };
      const read = (path, profile) => lowLevel.read_inventory_object(path, STRICT_JSON_LIMITS.maxBytes, validated.roles, profile);
      const acquired = await lowLevel.acquire_inventory_fence(
        paths.fence, validated.roles);
      const checkedFence = fenceValue(acquired);
      fence = checkedFence && {
        ...checkedFence,
        release: checkedFence.release.bind(acquired),
      };
      if (!fence) throw localError('INVENTORY_IO_FAILED', 'acquire_inventory_fence', 0, true);
      if (fence.writes !== 0) {
        throw localError(
          'INVENTORY_IO_FAILED', 'acquire_inventory_fence',
          fence.writes, true);
      }
      const fencedInventoryRoot = requireResolvedRoot(
        await lowLevel.resolve_native_state_root(
          validated.hostKey, 'inventory'));
      const fencedReaderRoot = requireResolvedRoot(
        await lowLevel.resolve_native_state_root(validated.hostKey, 'reader'));
      if (fencedInventoryRoot !== inventoryRoot ||
          fencedReaderRoot !== readerRoot) {
        throw localError('INVENTORY_STALE', 'read_inventory');
      }
      await verifyAcl(
        lowLevel, fencedInventoryRoot, validated.roles,
        'inventory-directory', 'daemon');
      await verifyAcl(
        lowLevel, fencedReaderRoot, validated.roles,
        'reader-directory', 'daemon');
      const rawMarker = await read(paths.marker, 'inventory-manual-cleanup');
      if (rawMarker !== null) {
        throw localError(
          'INVENTORY_MANUAL_CLEANUP', 'read_inventory', 0,
          rawMarker === undefined);
      }
      const inventory = readEnvelope(await read(paths.inventory, 'inventory-file'), parseWorkspaceInventory);
      const commit = readEnvelope(await read(paths.commit, 'inventory-commit'), (bytes) => parseCommit(bytes, validated.hostId));
      const priorFloor = readEnvelope(await read(paths.floor, 'inventory-floor'), (bytes) => parseFloor(bytes, validated.hostId));
      if (inventory === undefined || commit === undefined ||
          priorFloor === undefined) {
        throw localError('INVENTORY_INVALID', 'read_inventory');
      }
      if (!inventory && !commit) {
        if (priorFloor) throw localError('INVENTORY_STALE', 'read_inventory');
        const finalMarker = await read(
          paths.marker, 'inventory-manual-cleanup');
        const finalInventory = await read(paths.inventory, 'inventory-file');
        const finalCommit = await read(paths.commit, 'inventory-commit');
        const finalFloor = await read(paths.floor, 'inventory-floor');
        if (finalMarker !== null || finalInventory !== null ||
            finalCommit !== null || finalFloor !== null) {
          throw localError(
            'INVENTORY_MANUAL_CLEANUP', 'read_inventory', 0, true);
        }
        outcome = Object.freeze({ status: 'missing' });
      } else {
        if (!inventory || !commit) {
          throw localError('INVENTORY_MANUAL_CLEANUP', 'read_inventory');
        }
        const current = inventory.document;
        if (current.hostId !== validated.hostId) {
          throw localError('INVENTORY_INVALID', 'read_inventory');
        }
        if (commit.document.inventoryGeneration !== current.inventoryGeneration ||
            commit.document.inventoryFingerprint !== current.inventoryFingerprint ||
            commit.document.inventoryObjectIdentityFingerprint !== hash(inventory.identity)) {
          throw localError('INVENTORY_MANUAL_CLEANUP', 'read_inventory');
        }
        await verifyAcl(lowLevel, paths.inventory, validated.roles, 'inventory-file', 'daemon');
        await verifyAcl(lowLevel, paths.commit, validated.roles, 'inventory-commit', 'daemon');
        for (const workspace of current.workspaces) {
          if (!factsMatch(workspace, await lowLevel.read_workspace_root_facts(workspace.workDir, workspace.sourcePlatform))) {
            throw localError('INVENTORY_STALE', 'read_inventory');
          }
        }
        const expectedFloor = buildFloor({
          hostId: validated.hostId,
          inventoryGeneration: current.inventoryGeneration,
          inventoryFingerprint: current.inventoryFingerprint,
        });
        const expectedFloorBytes = floorBytes(expectedFloor);
        if (!priorFloor) {
          if (current.inventoryGeneration !== 1) {
            throw localError('INVENTORY_STALE', 'read_inventory');
          }
        } else if (priorFloor.document.inventoryGeneration === current.inventoryGeneration &&
            priorFloor.document.inventoryFingerprint === current.inventoryFingerprint) {
          // Exact floor replay is a read-only success.
        } else if (priorFloor.document.inventoryGeneration === current.inventoryGeneration - 1 &&
            priorFloor.document.inventoryFingerprint !== current.inventoryFingerprint) {
          const published = requirePublication(await lowLevel.publish_inventory_object_atomic(
            paths.floor, '.inventory-floor.', expectedFloorBytes,
            priorFloor.identity, validated.roles, 'inventory-floor'), 5);
          writes += published.writes; returnedFloorIdentity = published.identity;
        } else throw localError('INVENTORY_STALE', 'read_inventory');
        if (priorFloor) {
          await verifyAcl(lowLevel, paths.floor, validated.roles, 'inventory-floor', 'daemon');
        }
        if (!priorFloor) {
          const published = requirePublication(await lowLevel.publish_inventory_object_atomic(
            paths.floor, '.inventory-floor.', expectedFloorBytes, null,
            validated.roles, 'inventory-floor'), 4);
          writes += published.writes; returnedFloorIdentity = published.identity;
        }
        if (writes) {
          const publishedFloor = readEnvelope(await read(paths.floor, 'inventory-floor'), (bytes) => parseFloor(bytes, validated.hostId));
          if (!publishedFloor || !sameBytes(publishedFloor.bytes, expectedFloorBytes) ||
              publishedFloor.document.floorFingerprint !== expectedFloor.floorFingerprint ||
              hash(publishedFloor.identity) !== hash(returnedFloorIdentity)) {
            throw localError(
              'INVENTORY_MANUAL_CLEANUP', 'read_inventory_object', writes, true);
          }
          await verifyAcl(lowLevel, paths.floor, validated.roles, 'inventory-floor', 'daemon');
        }
        const marker = await read(paths.marker, 'inventory-manual-cleanup');
        const finalInventory = readEnvelope(
          await read(paths.inventory, 'inventory-file'), parseWorkspaceInventory);
        const finalCommit = readEnvelope(
          await read(paths.commit, 'inventory-commit'),
          (bytes) => parseCommit(bytes, validated.hostId));
        const finalFloor = readEnvelope(
          await read(paths.floor, 'inventory-floor'),
          (bytes) => parseFloor(bytes, validated.hostId));
        const expectedFloorIdentity = writes
          ? returnedFloorIdentity : priorFloor.identity;
        if (marker !== null || !finalInventory || !finalCommit || !finalFloor ||
            !sameBytes(finalInventory.bytes, inventory.bytes) ||
            !sameBytes(finalCommit.bytes, commit.bytes) ||
            !sameBytes(finalFloor.bytes, expectedFloorBytes) ||
            hash(finalInventory.identity) !== hash(inventory.identity) ||
            hash(finalCommit.identity) !== hash(commit.identity) ||
            hash(finalFloor.identity) !== hash(expectedFloorIdentity)) {
          throw localError(
            'INVENTORY_MANUAL_CLEANUP', 'read_inventory', writes, true);
        }
        await verifyAcl(
          lowLevel, paths.inventory, validated.roles,
          'inventory-file', 'daemon');
        await verifyAcl(
          lowLevel, paths.commit, validated.roles,
          'inventory-commit', 'daemon');
        await verifyAcl(
          lowLevel, paths.floor, validated.roles,
          'inventory-floor', 'daemon');
        for (const workspace of current.workspaces) {
          if (!factsMatch(
            workspace,
            await lowLevel.read_workspace_root_facts(
              workspace.workDir, workspace.sourcePlatform))) {
            throw localError(
              'INVENTORY_MANUAL_CLEANUP', 'read_inventory',
              writes, writes > 0);
          }
        }
        outcome = Object.freeze({
          status: 'present',
          inventory: frozenInventory(current),
          proof: Object.freeze({
            source: 'native', inventoryGeneration: current.inventoryGeneration,
            inventoryFingerprint: current.inventoryFingerprint, commitFingerprint: commit.document.commitFingerprint,
            floorFingerprint: expectedFloor.floorFingerprint,
          }),
        });
      }
    } catch (caught) {
      if (isLocalError(caught)) {
        if (Number.isSafeInteger(caught.writes) && caught.writes >= 0) {
          writes = Math.max(writes, caught.writes);
        }
      } else {
        const prefix = writes;
        const amount = Number.isSafeInteger(caught?.writes) &&
          caught.writes >= 0 ? caught.writes : null;
        if (amount === null) {
          body = localError(
            caught?.code || 'INVENTORY_IO_FAILED',
            caught?.operation || 'read_inventory', writes,
            caught?.ambiguous === true);
        } else {
          try {
            writes = addWrites(writes, amount);
            bodyExact = prefix === 0;
          } catch (overflow) {
            body = overflow;
          }
        }
      }
      body ??= caught;
    } finally {
      if (fence) {
        try { await fence.release(); } catch (caught) { releaseError = caught; }
      }
    }
    if (releaseError) {
      if (body) throw localError('INVENTORY_MANUAL_CLEANUP', 'release_inventory_fence', writes, true);
      throw localError('INVENTORY_IO_FAILED', 'release_inventory_fence', writes, true);
    }
    if (body) {
      if ((isLocalError(body) || bodyExact) && body.writes === writes) {
        throw body;
      }
      throw localError(
        body?.code || 'INVENTORY_IO_FAILED',
        body?.operation || 'read_inventory', writes,
        body?.ambiguous === true);
    }
    return outcome;
  };
  await selfTest();
  return Object.freeze({ selfTest, readAccepted });
}

export function createInventoryPublisherAdapter(loadLowLevel, options) {
  return createAdapter(loadLowLevel, options, 'management');
}

export function createInventoryReaderAdapter(loadLowLevel, options) {
  return createAdapter(loadLowLevel, options, 'daemon');
}
