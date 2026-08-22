import { randomBytes } from 'node:crypto';
import {
  STRICT_JSON_LIMITS, assertStrictText, canonicalJsonBytes, canonicalJsonHash, isHex64,
  parseCanonicalJsonBytes,
} from '@gjc-remote/shared/strict-json';
import {
  buildWorkspaceInventory, parseWorkspaceInventory, workspaceInventoryHostKey,
} from '@gjc-remote/shared/workspace-inventory';

const MAX = Number.MAX_SAFE_INTEGER;
const objectPrototype = Object.prototype;
const candidateKeys = ['expectedInventoryGeneration', 'workspaces'];
const workspaceKeys = ['workspaceId', 'sourcePlatform', 'workDir'];
const commitKeys = ['version', 'hostId', 'inventoryGeneration', 'inventoryFingerprint', 'inventoryObjectIdentityFingerprint', 'publicationNonce', 'commitFingerprint'];
const floorKeys = ['version', 'hostId', 'inventoryGeneration', 'inventoryFingerprint', 'floorFingerprint'];

function failure(code, operation, writes = 0, ambiguous = false) {
  const value = new Error('inventory operation failed');
  Object.defineProperties(value, {
    code: { value: code, enumerable: true }, operation: { value: operation, enumerable: true },
    writes: { value: writes, enumerable: true }, ambiguous: { value: ambiguous, enumerable: true },
  });
  return value;
}
function exact(value, names) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== objectPrototype) return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== names.length || own.some((name) => typeof name !== 'string') || !names.every((name) => own.includes(name))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value); const result = {};
    for (const name of names) {
      const descriptor = descriptors[name];
      if (!descriptor || !descriptor.enumerable || descriptor.get || descriptor.set || !Object.hasOwn(descriptor, 'value')) return null;
      result[name] = descriptor.value;
    }
    return result;
  } catch { return null; }
}
function arraySnapshot(value, maxLength) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const own = Reflect.ownKeys(value);
    const length = descriptors.length?.value;
    if (!Number.isSafeInteger(length) || length < 0) return null;
    if (own.some((name) => typeof name !== 'string') ||
        own.length !== length + 1 || !Object.hasOwn(descriptors, 'length') ||
        length > maxLength) return null;
    const result = [];
    for (let index = 0; index < length; index++) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true ||
          descriptor.get !== undefined || descriptor.set !== undefined ||
          !Object.hasOwn(descriptor, 'value')) return null;
      result.push(descriptor.value);
    }
    return result;
  } catch {
    return null;
  }
}
function fenceValue(value) {
  try {
    if (!value || typeof value !== 'object') return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== 2 || !own.includes('release') || !own.includes('writes')) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const name of ['release', 'writes']) {
      const descriptor = descriptors[name];
      if (!descriptor || !descriptor.enumerable || descriptor.get || descriptor.set || !Object.hasOwn(descriptor, 'value')) return null;
    }
    return typeof descriptors.release.value === 'function' && Number.isSafeInteger(descriptors.writes.value) && descriptors.writes.value >= 0 ? descriptors : null;
  } catch { return null; }
}
function text(value, max) {
  try {
    return typeof value === 'string' && value.length > 0 &&
      assertStrictText(value, 'inventory text', max) === value;
  } catch {
    return false;
  }
}
function leaf(root, name) { return `${root}${root.endsWith('/') || root.endsWith('\\') ? '' : process.platform === 'win32' ? '\\' : '/'}${name}`; }
function sameBytes(left, right) { return Buffer.isBuffer(left) && left.equals(right); }
function hash(value) { return canonicalJsonHash(value, STRICT_JSON_LIMITS); }
function documentFingerprint(value, name) { const { [name]: ignored, ...preimage } = value; return canonicalJsonHash(preimage, STRICT_JSON_LIMITS); }
function uint64(value) { return typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && (() => { try { return BigInt(value) <= 18446744073709551615n; } catch { return false; } })(); }
function uid(value) {
  if (typeof value !== 'string' || !/^uid:(0|[1-9][0-9]*)$/.test(value)) return false;
  try { return BigInt(value.slice(4)) <= 4294967295n; } catch { return false; }
}
function sid(value) {
  if (typeof value !== 'string') return false;
  const fields = value.split('-');
  if (fields.length < 4 || fields.length > 18 ||
      fields[0] !== 'S' || fields[1] !== '1' ||
      !fields.slice(2).every((field) => /^(0|[1-9][0-9]*)$/.test(field))) return false;
  try {
    return BigInt(fields[2]) <= 281474976710655n &&
      fields.slice(3).every((field) => BigInt(field) <= 4294967295n);
  } catch {
    return false;
  }
}
function objectIdentity(value) {
  const posix = exact(value, ['device', 'inode', 'mode', 'owner']);
  if (posix && uint64(posix.device) && uint64(posix.inode) && Number.isInteger(posix.mode) && posix.mode >= 0 && posix.mode <= 0xffffffff && uid(posix.owner)) return posix;
  const windows = exact(value, ['volumeSerial', 'fileId', 'attributes', 'owner']);
  if (windows && /^[a-f0-9]{16}$/.test(windows.volumeSerial) && /^[a-f0-9]{32}$/.test(windows.fileId) && Number.isInteger(windows.attributes) && windows.attributes >= 0 && windows.attributes <= 0xffffffff && sid(windows.owner)) return windows;
  return null;
}
function candidate(input) {
  const value = exact(input, candidateKeys);
  const workspaces = value ? arraySnapshot(value.workspaces, 64) : null;
  if (!value || !Number.isSafeInteger(value.expectedInventoryGeneration) ||
      value.expectedInventoryGeneration < 0 || !workspaces) {
    throw failure('INVENTORY_INVALID', 'publish_inventory');
  }
  const seen = new Set(); const rows = [];
  for (const item of workspaces) {
    const row = exact(item, workspaceKeys);
    if (!row || typeof row.workspaceId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(row.workspaceId) || Buffer.byteLength(row.workspaceId, 'utf8') > 128 || seen.has(row.workspaceId) || !['posix', 'windows-drive', 'windows-unc'].includes(row.sourcePlatform) || !text(row.workDir, 4096)) throw failure('INVENTORY_INVALID', 'publish_inventory');
    seen.add(row.workspaceId); rows.push(Object.freeze({ ...row }));
  }
  return Object.freeze({ expectedInventoryGeneration: value.expectedInventoryGeneration, workspaces: Object.freeze(rows) });
}
function validDocument(value, names, fingerprintName, hostId) {
  const result = exact(value, names);
  return result && result.version === 1 && result.hostId === hostId && isHex64(result[fingerprintName]) && documentFingerprint(result, fingerprintName) === result[fingerprintName] ? result : null;
}
function parseCommit(bytes, hostId) {
  const result = validDocument(parseCanonicalJsonBytes(bytes, STRICT_JSON_LIMITS), commitKeys, 'commitFingerprint', hostId);
  return result && Number.isSafeInteger(result.inventoryGeneration) && result.inventoryGeneration >= 1 && isHex64(result.inventoryFingerprint) && isHex64(result.inventoryObjectIdentityFingerprint) && /^[a-f0-9]{32}$/.test(result.publicationNonce) ? result : null;
}
function parseFloor(bytes, hostId) {
  const result = validDocument(parseCanonicalJsonBytes(bytes, STRICT_JSON_LIMITS), floorKeys, 'floorFingerprint', hostId);
  return result && Number.isSafeInteger(result.inventoryGeneration) && result.inventoryGeneration >= 1 && isHex64(result.inventoryFingerprint) ? result : null;
}
function readEnvelope(value, parser) {
  if (value === null) return null;
  const envelope = exact(value, ['bytes', 'identity']);
  if (!envelope || !Buffer.isBuffer(envelope.bytes) || !objectIdentity(envelope.identity)) return undefined;
  try { const document = parser(envelope.bytes); return document ? { bytes: envelope.bytes, identity: envelope.identity, document } : undefined; } catch { return undefined; }
}
function add(total, amount) {
  if (!Number.isSafeInteger(amount) || amount < 0 || total > MAX - amount) throw failure('INVENTORY_IO_FAILED', 'publish_inventory', total, true);
  return total + amount;
}
function nativeFailure(caught, total) {
  const amount = caught && Number.isSafeInteger(caught.writes) && caught.writes >= 0 ? caught.writes : null;
  const writes = amount === null ? total : add(total, amount);
  if (total === 0 && amount !== null) return caught;
  return failure(caught?.code || 'INVENTORY_IO_FAILED', caught?.operation || 'publish_inventory', writes, caught?.ambiguous === true);
}
function publishResult(value, operation) {
  const result = exact(value, ['writes', 'identity']);
  return result && Number.isSafeInteger(result.writes) && result.writes >= 0 && objectIdentity(result.identity) ? result : (() => { throw failure('INVENTORY_IO_FAILED', operation, 0, true); })();
}
function facts(workspace, value) {
  const result = exact(value, ['sourcePlatform', 'workDir', 'rootIdentity', 'storageIdentity']);
  if (!result || result.sourcePlatform !== workspace.sourcePlatform || !text(result.workDir, 4096)) return null;
  const root = workspace.sourcePlatform === 'posix'
    ? exact(result.rootIdentity, ['kind', 'device', 'inode'])
    : exact(result.rootIdentity, ['kind', 'volumeSerial', 'fileId']);
  const storage = workspace.sourcePlatform === 'posix'
    ? exact(result.storageIdentity, ['kind', 'device'])
    : workspace.sourcePlatform === 'windows-drive'
      ? exact(result.storageIdentity, ['kind', 'volumeGuid', 'volumeSerial', 'fileSystem']) : null;
  if (!root || !storage || (workspace.sourcePlatform === 'posix' && (root.kind !== 'posix-root-v1' || storage.kind !== 'posix-storage-v1' || !uint64(root.device) || !uint64(root.inode) || !uint64(storage.device))) || (workspace.sourcePlatform === 'windows-drive' && (root.kind !== 'win32-root-v1' || storage.kind !== 'windows-drive-storage-v1' || !/^[a-f0-9]{16}$/.test(root.volumeSerial) || !/^[a-f0-9]{32}$/.test(root.fileId) || !/^\\\\\?\\VOLUME\{[0-9A-F-]{36}\}\\$/.test(storage.volumeGuid) || !/^[0-9A-F]{8}$/.test(storage.volumeSerial) || !/^[A-Z0-9._-]{1,32}$/.test(storage.fileSystem)))) return null;
  return Object.freeze({ workDir: result.workDir, root: Object.freeze(root), storage: Object.freeze(storage) });
}
function relation(inventory, commit, floor) {
  if (!inventory && !commit && !floor) return 'genesis';
  if (!inventory || !commit) return 'invalid-object';
  const current = inventory.document;
  if (commit.document.inventoryGeneration !== current.inventoryGeneration || commit.document.inventoryFingerprint !== current.inventoryFingerprint || commit.document.inventoryObjectIdentityFingerprint !== hash(inventory.identity)) return 'invalid-object';
  if (!floor) return current.inventoryGeneration === 1 ? 'pending' : 'invalid-object';
  if (floor.document.inventoryGeneration === current.inventoryGeneration && floor.document.inventoryFingerprint === current.inventoryFingerprint) return 'accepted';
  if (floor.document.inventoryGeneration === current.inventoryGeneration - 1 && floor.document.inventoryFingerprint !== current.inventoryFingerprint) return 'pending';
  return 'floor-conflict';
}
function marker(hostId, reason, inventory, commit, floor) {
  const result = { version: 1, hostId, reason, inventoryGeneration: inventory?.document.inventoryGeneration ?? null, inventoryFingerprint: inventory?.document.inventoryFingerprint ?? null, commitFingerprint: commit?.document.commitFingerprint ?? null, floorFingerprint: floor?.document.floorFingerprint ?? null, routeDisposition: 'no-route', blockedUntilOwnerAction: true };
  result.manualCleanupFingerprint = documentFingerprint(result, 'manualCleanupFingerprint'); return result;
}
function commit(hostId, inventory, identity, previousNonce) {
  let publicationNonce; do { publicationNonce = randomBytes(16).toString('hex'); } while (publicationNonce === previousNonce);
  const result = { version: 1, hostId, inventoryGeneration: inventory.inventoryGeneration, inventoryFingerprint: inventory.inventoryFingerprint, inventoryObjectIdentityFingerprint: hash(identity), publicationNonce };
  result.commitFingerprint = documentFingerprint(result, 'commitFingerprint'); return result;
}

export function createInventoryPublisherTransaction({ lowLevel, hostId, roles, inventoryRoot, checkpoint = async () => {} }) {
  return async (input) => {
    const requested = candidate(input);
    const paths = { inventory: leaf(inventoryRoot, 'workspace-inventory.v2.json'), commit: leaf(inventoryRoot, 'inventory-commit.v1.json'), marker: leaf(inventoryRoot, 'inventory-manual-cleanup.v1.json'), fence: leaf(inventoryRoot, 'inventory-publication.lock') };
    let fence; let releaseFence; let writes = 0; let committed = false; let inventoryPublished = false;
    let markerRequired = false; let outcome; let bodyError;
    let stateInventory; let stateCommit; let stateFloor;
    const read = async (path, profile) => lowLevel.read_inventory_object(path, STRICT_JSON_LIMITS.maxBytes, roles, profile);
    const publish = async (path, prefix, bytes, expected, profile) => {
      try { const result = publishResult(await lowLevel.publish_inventory_object_atomic(path, prefix, bytes, expected, roles, profile), 'publish_inventory_object_atomic'); writes = add(writes, result.writes); return result; }
      catch (caught) {
        const native = nativeFailure(caught, writes);
        if (Number.isSafeInteger(native?.writes) && native.writes >= writes) writes = native.writes;
        throw native;
      }
    };
    const mark = async (reason, inventory, currentCommit, floor) => {
      const result = marker(hostId, reason, inventory, currentCommit, floor);
      try {
        await publish(paths.marker, '.inventory-manual-cleanup.',
          canonicalJsonBytes(result, STRICT_JSON_LIMITS), null,
          'inventory-manual-cleanup');
      } catch {
        throw failure('INVENTORY_MANUAL_CLEANUP', 'publish_inventory', writes, true);
      }
    };
    try {
      if (await lowLevel.verify_inventory_acl(
          inventoryRoot, roles, 'inventory-directory', 'management') !== true) {
        throw failure('INVENTORY_ACCESS_DENIED', 'verify_inventory_acl', writes);
      }
      fence = await lowLevel.acquire_inventory_fence(paths.fence, roles);
      const checkedFence = fenceValue(fence);
      if (!checkedFence) throw failure('INVENTORY_IO_FAILED', 'acquire_inventory_fence', writes, true);
      releaseFence = checkedFence.release.value.bind(fence);
      writes = add(writes, checkedFence.writes.value); await checkpoint('fence-acquired');
      const readerRoot = await lowLevel.resolve_native_state_root(workspaceInventoryHostKey(hostId), 'reader');
      if (typeof readerRoot !== 'string' || !readerRoot) throw failure('INVENTORY_IO_FAILED', 'resolve_native_state_root', writes);
      const rawMarker = await read(paths.marker, 'inventory-manual-cleanup');
      if (rawMarker !== null) throw failure('INVENTORY_MANUAL_CLEANUP', 'publish_inventory', writes, rawMarker === undefined);
      const rawInventory = await read(paths.inventory, 'inventory-file');
      const rawCommit = await read(paths.commit, 'inventory-commit');
      const rawFloor = await read(leaf(readerRoot, 'inventory-floor.v1.json'), 'inventory-floor');
      const inventory = stateInventory = readEnvelope(rawInventory, parseWorkspaceInventory);
      const currentCommit = stateCommit = readEnvelope(rawCommit, (bytes) => parseCommit(bytes, hostId));
      const floor = stateFloor = readEnvelope(rawFloor, (bytes) => parseFloor(bytes, hostId));
      await checkpoint('state-read');
      const state = inventory === undefined || currentCommit === undefined ||
        floor === undefined || (inventory && inventory.document.hostId !== hostId)
        ? 'invalid-object' : relation(inventory, currentCommit, floor);
      if (state === 'invalid-object' || state === 'floor-conflict') {
        await mark(state, inventory, currentCommit, floor);
        throw failure('INVENTORY_MANUAL_CLEANUP', 'publish_inventory', writes);
      }
      const generation = inventory?.document.inventoryGeneration ?? 0;
      if (requested.expectedInventoryGeneration !== generation) throw failure('INVENTORY_STALE', 'publish_inventory', writes);
      const observed = [];
      for (const workspace of requested.workspaces) {
        const value = facts(workspace, await lowLevel.read_workspace_root_facts(workspace.workDir, workspace.sourcePlatform));
        if (!value) throw failure('INVENTORY_IO_FAILED', 'read_workspace_root_facts', writes);
        observed.push(value);
      }
      const records = observed.map((value, index) => ({ hostId, workspaceId: requested.workspaces[index].workspaceId, sourcePlatform: requested.workspaces[index].sourcePlatform, workDir: value.workDir, rootIdentityFingerprint: hash(value.root), storageIdentityFingerprint: hash(value.storage) }));
      const sameGeneration = inventory
        ? buildWorkspaceInventory({ hostId, inventoryGeneration: generation, workspaces: records })
        : null;
      const unchanged = inventory &&
        sameGeneration.inventoryFingerprint === inventory.document.inventoryFingerprint;
      await checkpoint('facts-built');
      if (unchanged) { outcome = Object.freeze({ status: 'unchanged', inventoryGeneration: generation, inventoryFingerprint: inventory.document.inventoryFingerprint, commitFingerprint: currentCommit.document.commitFingerprint, writes }); }
      else {
        if (state === 'pending') throw failure('INVENTORY_PENDING', 'publish_inventory', writes);
        if (generation === MAX) { await mark('floor-conflict', inventory, currentCommit, floor); throw failure('INVENTORY_MANUAL_CLEANUP', 'publish_inventory', writes); }
        const next = buildWorkspaceInventory({ hostId, inventoryGeneration: generation + 1, workspaces: records });
        const inventoryBytes = canonicalJsonBytes(next, STRICT_JSON_LIMITS);
        let inventoryPublication;
        try {
          inventoryPublication = await publish(paths.inventory, '.workspace-inventory.', inventoryBytes,
            inventory?.identity ?? null, 'inventory-file');
          inventoryPublished = true;
        } catch (caught) {
          markerRequired = caught?.ambiguous === true;
          throw caught;
        }
        await checkpoint('inventory-published');
        const reopened = readEnvelope(await read(paths.inventory, 'inventory-file'), parseWorkspaceInventory);
        if (!reopened || !sameBytes(reopened.bytes, inventoryBytes) ||
            reopened.document.inventoryFingerprint !== next.inventoryFingerprint ||
            hash(reopened.identity) !== hash(inventoryPublication.identity)) {
          throw failure('INVENTORY_IO_FAILED', 'read_inventory_object', writes, false);
        }
        stateInventory = reopened;
        if (await lowLevel.verify_inventory_acl(paths.inventory, roles, 'inventory-file', 'management') !== true) throw failure('INVENTORY_ACCESS_DENIED', 'verify_inventory_acl', writes, false);
        for (let index = 0; index < requested.workspaces.length; index++) {
          const again = facts(requested.workspaces[index], await lowLevel.read_workspace_root_facts(requested.workspaces[index].workDir, requested.workspaces[index].sourcePlatform));
          const before = observed[index];
          if (!again || again.workDir !== before.workDir || hash(again.root) !== hash(before.root) || hash(again.storage) !== hash(before.storage)) throw failure('INVENTORY_IO_FAILED', 'read_workspace_root_facts', writes, false);
        }
        await checkpoint('inventory-verified');
        const nextCommit = commit(hostId, next, reopened.identity, currentCommit?.document.publicationNonce);
        const commitBytes = canonicalJsonBytes(nextCommit, STRICT_JSON_LIMITS);
        const commitPublication = await publish(
          paths.commit, '.inventory-commit.', commitBytes,
          currentCommit?.identity ?? null, 'inventory-commit');
        await checkpoint('commit-published');
        const reopenedCommit = readEnvelope(await read(paths.commit, 'inventory-commit'), (bytes) => parseCommit(bytes, hostId));
        if (!reopenedCommit || !sameBytes(reopenedCommit.bytes, commitBytes) ||
            reopenedCommit.document.commitFingerprint !== nextCommit.commitFingerprint ||
            reopenedCommit.document.inventoryObjectIdentityFingerprint !== hash(reopened.identity) ||
            hash(reopenedCommit.identity) !== hash(commitPublication.identity)) {
          throw failure('INVENTORY_IO_FAILED', 'read_inventory_object', writes, false);
        }
        stateCommit = reopenedCommit;
        if (await lowLevel.verify_inventory_acl(paths.commit, roles, 'inventory-commit', 'management') !== true) throw failure('INVENTORY_ACCESS_DENIED', 'verify_inventory_acl', writes, false);
        committed = true;
        outcome = Object.freeze({ status: 'published', inventoryGeneration: next.inventoryGeneration, inventoryFingerprint: next.inventoryFingerprint, commitFingerprint: nextCommit.commitFingerprint, writes });
        try { await checkpoint('commit-verified'); } catch {}
      }
    } catch (caught) {
      // Commit verification is the linearization point.  Checkpoints are
      // diagnostics, not a way to retract a verified positive publication.
      if (committed) bodyError = undefined;
      else bodyError = caught;
      if (fence && (inventoryPublished || markerRequired) && !committed) {
        try {
          const existing = await read(paths.marker, 'inventory-manual-cleanup');
          if (existing === null) await mark(caught?.ambiguous === true ? 'publication-ambiguous' : caught?.operation === 'read_workspace_root_facts' || caught?.operation === 'read_inventory_object' || caught?.operation === 'verify_inventory_acl' ? 'post-publication-verification-failed' : 'partial-publication', stateInventory, stateCommit, stateFloor);
          bodyError = failure(
            'INVENTORY_MANUAL_CLEANUP', 'publish_inventory', writes,
            caught?.ambiguous === true);
        } catch (markerError) { bodyError = failure('INVENTORY_MANUAL_CLEANUP', 'publish_inventory', writes, true); }
      }
    }
    if (fence) {
      let releaseError;
      try { await checkpoint('before-release'); } catch (caught) { if (!committed && !bodyError) bodyError = caught; }
      try {
        if (releaseFence) await releaseFence();
        else throw failure('INVENTORY_IO_FAILED', 'release_inventory_fence', writes, true);
      } catch (caught) { releaseError = caught; }
      if (releaseError) {
        if (bodyError) throw failure('INVENTORY_MANUAL_CLEANUP', 'release_inventory_fence', writes, true);
        throw failure('INVENTORY_IO_FAILED', 'release_inventory_fence', writes, true);
      }
    }
    if (bodyError) {
      if (writes > 0 && bodyError.writes !== writes) throw failure(bodyError.code || 'INVENTORY_IO_FAILED', bodyError.operation || 'publish_inventory', writes, bodyError.ambiguous === true);
      throw bodyError;
    }
    return outcome;
  };
}
