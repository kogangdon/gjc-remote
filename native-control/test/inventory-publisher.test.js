import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createInventoryPublisherTransaction } from '../src/inventory-publisher.js';
import { buildWorkspaceInventory, parseWorkspaceInventory } from '../../shared/workspace-inventory.js';
import { STRICT_JSON_LIMITS, canonicalJsonBytes, canonicalJsonHash, parseCanonicalJsonBytes } from '../../shared/strict-json.js';

const hostId = 'owned-host';
const roles = Object.freeze({});
const rootIdentity = Object.freeze({ kind: 'posix-root-v1', device: '2', inode: '3' });
const storageIdentity = Object.freeze({ kind: 'posix-storage-v1', device: '2' });

function model({ fenceWrites = 0, checkpoint, mutateFacts, publishFailure, releaseFailure, publishIdentityMismatch } = {}) {
  const objects = new Map(); const calls = []; let sequence = 0; let released = 0;
  const identity = () => ({ device: '1', inode: String(++sequence), mode: 33152, owner: 'uid:1001' });
  const lowLevel = {
    verify_inventory_acl: async (...args) => { calls.push(['acl', ...args]); return true; },
    resolve_native_state_root: async (...args) => { calls.push(['root', ...args]); return '/reader'; },
    acquire_inventory_fence: async (...args) => { calls.push(['fence', ...args]); return Object.freeze({ writes: fenceWrites, release: async () => { released++; calls.push(['release']); if (releaseFailure) throw releaseFailure; } }); },
    read_inventory_object: async (path, ...args) => { calls.push(['read', path, ...args]); return objects.get(path) ?? null; },
    read_workspace_root_facts: async (workDir, sourcePlatform) => {
      calls.push(['facts', workDir, sourcePlatform]);
      return mutateFacts?.(calls.filter(([kind]) => kind === 'facts').length, workDir, sourcePlatform) ?? { sourcePlatform, workDir: `/canonical${workDir}`, rootIdentity, storageIdentity };
    },
    publish_inventory_object_atomic: async (path, prefix, bytes, expectedIdentity, ...args) => {
      calls.push(['publish', path, prefix, expectedIdentity, ...args]);
      if (publishFailure) await publishFailure(path);
      const prior = objects.get(path) ?? null;
      assert.equal(expectedIdentity, prior?.identity ?? null, 'CAS predecessor');
      const value = { bytes: Buffer.from(bytes), identity: identity() }; objects.set(path, value);
      return {
        writes: prior ? 5 : 4,
        identity: publishIdentityMismatch?.(path, value.identity) ?? value.identity,
      };
    },
  };
  const publisher = createInventoryPublisherTransaction({ hostId, roles, inventoryRoot: '/inventory', lowLevel, checkpoint });
  return { publisher, calls, objects, released: () => released, lowLevel };
}
function input(workspaces = [{ workspaceId: 'one', sourcePlatform: 'posix', workDir: '/work' }], generation = 0) { return { expectedInventoryGeneration: generation, workspaces }; }
function paths(state) { return [...state.objects.keys()]; }
function basename(path) { return path.split(/[\\/]/).at(-1); }
function objectPath(name) { return `/inventory${process.platform === 'win32' ? '\\' : '/'}${name}`; }
function readerPath(name) { return `/reader${process.platform === 'win32' ? '\\' : '/'}${name}`; }
function identity(inode = '99') { return { device: '1', inode, mode: 33152, owner: 'uid:1001' }; }
function fingerprint(document, field) {
  const { [field]: ignored, ...preimage } = document;
  return canonicalJsonHash(preimage, STRICT_JSON_LIMITS);
}
function putDocument(state, path, document, inode) {
  state.objects.set(path, { bytes: canonicalJsonBytes(document, STRICT_JSON_LIMITS), identity: identity(inode) });
}
function acceptedFloor(state) {
  const inventoryEnvelope = state.objects.get(objectPath('workspace-inventory.v2.json'));
  const inventory = parseWorkspaceInventory(inventoryEnvelope.bytes);
  const floor = { version: 1, hostId, inventoryGeneration: inventory.inventoryGeneration, inventoryFingerprint: inventory.inventoryFingerprint };
  floor.floorFingerprint = fingerprint(floor, 'floorFingerprint');
  putDocument(state, readerPath('inventory-floor.v1.json'), floor, '98');
}
function seedAcceptedState(state, generation, floorGeneration = generation) {
  const inventoryIdentity = identity('51');
  const inventory = buildWorkspaceInventory({
    hostId,
    inventoryGeneration: generation,
    workspaces: [{
      hostId,
      workspaceId: 'one',
      sourcePlatform: 'posix',
      workDir: '/canonical/work',
      rootIdentityFingerprint: canonicalJsonHash(rootIdentity, STRICT_JSON_LIMITS),
      storageIdentityFingerprint: canonicalJsonHash(storageIdentity, STRICT_JSON_LIMITS),
    }],
  });
  state.objects.set(objectPath('workspace-inventory.v2.json'), {
    bytes: canonicalJsonBytes(inventory, STRICT_JSON_LIMITS),
    identity: inventoryIdentity,
  });
  const commit = {
    version: 1,
    hostId,
    inventoryGeneration: generation,
    inventoryFingerprint: inventory.inventoryFingerprint,
    inventoryObjectIdentityFingerprint: canonicalJsonHash(inventoryIdentity, STRICT_JSON_LIMITS),
    publicationNonce: '1'.repeat(32),
  };
  commit.commitFingerprint = fingerprint(commit, 'commitFingerprint');
  putDocument(state, objectPath('inventory-commit.v1.json'), commit, '52');
  if (floorGeneration !== null) {
    const floor = {
      version: 1,
      hostId,
      inventoryGeneration: floorGeneration,
      inventoryFingerprint: floorGeneration === generation
        ? inventory.inventoryFingerprint : '2'.repeat(64),
    };
    floor.floorFingerprint = fingerprint(floor, 'floorFingerprint');
    putDocument(state, readerPath('inventory-floor.v1.json'), floor, '53');
  }
  return inventory;
}

test('orders marker, inventory, commit, floor reads and publishes genesis with exact writes', async () => {
  const state = model({ fenceWrites: 3 });
  const result = await state.publisher(input());
  assert.deepEqual(result.status, 'published'); assert.equal(result.inventoryGeneration, 1); assert.equal(result.writes, 11);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(state.calls.filter(([kind]) => kind === 'read').map(([, path]) => basename(path)), [
    'inventory-manual-cleanup.v1.json', 'workspace-inventory.v2.json', 'inventory-commit.v1.json', 'inventory-floor.v1.json',
    'workspace-inventory.v2.json', 'inventory-commit.v1.json',
  ]);
  assert.deepEqual(state.calls.filter(([kind]) => kind === 'publish').map(([, path]) => basename(path)), ['workspace-inventory.v2.json', 'inventory-commit.v1.json']);
  assert.equal(state.released(), 1);
});

test('a present marker short-circuits later reads and writes', async () => {
  const state = model();
  state.objects.set(objectPath('inventory-manual-cleanup.v1.json'), { bytes: Buffer.from('{}'), identity: { device: '1', inode: '1', mode: 33152, owner: 'uid:1001' } });
  await assert.rejects(state.publisher(input()), (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' && error.writes === 0);
  assert.equal(state.calls.filter(([kind]) => kind === 'read').length, 1);
  assert.equal(state.calls.some(([kind]) => kind === 'publish'), false);
});

test('reordered equivalent candidate is unchanged with no object writes', async () => {
  const state = model();
  const first = await state.publisher(input([{ workspaceId: 'b', sourcePlatform: 'posix', workDir: '/b' }, { workspaceId: 'a', sourcePlatform: 'posix', workDir: '/a' }]));
  const writes = state.calls.filter(([kind]) => kind === 'publish').length;
  const result = await state.publisher(input([{ workspaceId: 'a', sourcePlatform: 'posix', workDir: '/a' }, { workspaceId: 'b', sourcePlatform: 'posix', workDir: '/b' }], first.inventoryGeneration));
  assert.equal(result.status, 'unchanged'); assert.equal(result.writes, 0);
  assert.equal(state.calls.filter(([kind]) => kind === 'publish').length, writes);
});

test('a first-generation snapshot without a floor is pending for semantic changes', async () => {
  const state = model();
  const first = await state.publisher(input());
  const writes = state.calls.filter(([kind]) => kind === 'publish').length;
  await assert.rejects(
    state.publisher(input([{ workspaceId: 'two', sourcePlatform: 'posix', workDir: '/other' }], first.inventoryGeneration)),
    (error) => error.code === 'INVENTORY_PENDING' && error.writes === 0,
  );
  assert.equal(state.calls.filter(([kind]) => kind === 'publish').length, writes);
});

test('an accepted floor permits exact replacement writes', async () => {
  const state = model();
  const first = await state.publisher(input());
  acceptedFloor(state);
  const result = await state.publisher(input([
    { workspaceId: 'two', sourcePlatform: 'posix', workDir: '/other' },
  ], first.inventoryGeneration));
  assert.equal(result.status, 'published');
  assert.equal(result.inventoryGeneration, 2);
  assert.equal(result.writes, 10);
});

test('a same-generation floor fingerprint conflict writes an absorbing marker', async () => {
  const state = model();
  const first = await state.publisher(input());
  const floor = { version: 1, hostId, inventoryGeneration: first.inventoryGeneration, inventoryFingerprint: '0'.repeat(64) };
  floor.floorFingerprint = fingerprint(floor, 'floorFingerprint');
  putDocument(state, readerPath('inventory-floor.v1.json'), floor, '97');
  await assert.rejects(state.publisher(input([], first.inventoryGeneration)),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' && error.writes === 4);
  const marker = parseCanonicalJsonBytes(
    state.objects.get(objectPath('inventory-manual-cleanup.v1.json')).bytes,
    STRICT_JSON_LIMITS,
  );
  assert.equal(marker.reason, 'floor-conflict');
});

test('an exact predecessor floor keeps generation N pending', async () => {
  const state = model();
  seedAcceptedState(state, 2, 1);
  await assert.rejects(state.publisher(input([], 2)),
    (error) => error.code === 'INVENTORY_PENDING' && error.writes === 0);
  assert.equal(state.calls.some(([kind]) => kind === 'publish'), false);
});

test('generation exhaustion writes an absorbing no-route marker before building MAX plus one', async () => {
  const state = model();
  seedAcceptedState(state, Number.MAX_SAFE_INTEGER);
  await assert.rejects(state.publisher(input([], Number.MAX_SAFE_INTEGER)),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' && error.writes === 4);
  const marker = parseCanonicalJsonBytes(
    state.objects.get(objectPath('inventory-manual-cleanup.v1.json')).bytes,
    STRICT_JSON_LIMITS,
  );
  assert.equal(marker.reason, 'floor-conflict');
  assert.equal(marker.inventoryGeneration, Number.MAX_SAFE_INTEGER);
});

test('partial durable state writes an invalid-object marker', async () => {
  const state = model();
  const inventory = buildWorkspaceInventory({ hostId, inventoryGeneration: 1, workspaces: [] });
  putDocument(state, objectPath('workspace-inventory.v2.json'), inventory, '54');
  await assert.rejects(state.publisher(input([], 1)),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' && error.writes === 4);
  const marker = parseCanonicalJsonBytes(
    state.objects.get(objectPath('inventory-manual-cleanup.v1.json')).bytes,
    STRICT_JSON_LIMITS,
  );
  assert.equal(marker.reason, 'invalid-object');
});

test('marker publication failure remains absorbing and includes native writes', async () => {
  const native = Object.assign(new Error('marker'), {
    code: 'INVENTORY_IO_FAILED',
    operation: 'publish_inventory_object_atomic',
    writes: 2,
    ambiguous: false,
  });
  const state = model({
    fenceWrites: 3,
    publishFailure: async (path) => {
      if (path.endsWith('inventory-manual-cleanup.v1.json')) throw native;
    },
  });
  const inventory = buildWorkspaceInventory({ hostId, inventoryGeneration: 1, workspaces: [] });
  putDocument(state, objectPath('workspace-inventory.v2.json'), inventory, '55');
  await assert.rejects(state.publisher(input([], 1)),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.operation === 'publish_inventory' && error.writes === 5 &&
      error.ambiguous === true);
});

test('stale CAS and invalid candidates leave storage unchanged', async () => {
  const state = model();
  await assert.rejects(state.publisher(input([], 1)), (error) => error.code === 'INVENTORY_STALE' && error.writes === 0);
  const accessor = { expectedInventoryGeneration: 0, workspaces: [] };
  Object.defineProperty(accessor, 'workspaces', { enumerable: true, get() { return []; } });
  await assert.rejects(state.publisher(accessor), (error) => error.code === 'INVENTORY_INVALID');
  await assert.rejects(state.publisher(new Proxy(input(), { ownKeys() { throw new Error('trap'); } })), (error) => error.code === 'INVENTORY_INVALID');
  const proxiedWorkspaces = new Proxy([], {
    ownKeys() { throw new Error('trap'); },
  });
  await assert.rejects(state.publisher({
    expectedInventoryGeneration: 0,
    workspaces: proxiedWorkspaces,
  }), (error) => error.code === 'INVENTORY_INVALID');
  await assert.rejects(state.publisher(input([
    { workspaceId: 'bad', sourcePlatform: 'posix', workDir: '/bad\ud800' },
  ])), (error) => error.code === 'INVENTORY_INVALID');
  assert.deepEqual(paths(state), []);
});

test('foreign-host inventory and noncanonical identities become absorbing state', async () => {
  const state = model();
  const foreign = buildWorkspaceInventory({
    hostId: 'foreign-host',
    inventoryGeneration: 1,
    workspaces: [],
  });
  const badIdentity = {
    device: '1',
    inode: '56',
    mode: 33152,
    owner: 'uid:4294967296',
  };
  state.objects.set(objectPath('workspace-inventory.v2.json'), {
    bytes: canonicalJsonBytes(foreign, STRICT_JSON_LIMITS),
    identity: badIdentity,
  });
  await assert.rejects(state.publisher(input([], 1)),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.ambiguous === false && error.writes === 4);
  assert.ok(state.objects.has(objectPath('inventory-manual-cleanup.v1.json')));

  const foreignState = model();
  const inventoryIdentity = identity('57');
  foreignState.objects.set(objectPath('workspace-inventory.v2.json'), {
    bytes: canonicalJsonBytes(foreign, STRICT_JSON_LIMITS),
    identity: inventoryIdentity,
  });
  const commit = {
    version: 1,
    hostId,
    inventoryGeneration: 1,
    inventoryFingerprint: foreign.inventoryFingerprint,
    inventoryObjectIdentityFingerprint: canonicalJsonHash(
      inventoryIdentity, STRICT_JSON_LIMITS),
    publicationNonce: '3'.repeat(32),
  };
  commit.commitFingerprint = fingerprint(commit, 'commitFingerprint');
  putDocument(foreignState, objectPath('inventory-commit.v1.json'), commit, '58');
  const floor = {
    version: 1,
    hostId,
    inventoryGeneration: 1,
    inventoryFingerprint: foreign.inventoryFingerprint,
  };
  floor.floorFingerprint = fingerprint(floor, 'floorFingerprint');
  putDocument(foreignState, readerPath('inventory-floor.v1.json'), floor, '59');
  await assert.rejects(foreignState.publisher(input([], 1)),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.ambiguous === false && error.writes === 4);
});

test('paired Unicode workspace paths remain valid UTF-8 input', async () => {
  const state = model();
  const result = await state.publisher(input([
    { workspaceId: 'unicode', sourcePlatform: 'posix', workDir: '/작업/😀' },
  ]));
  assert.equal(result.status, 'published');
});

test('post-inventory workspace mutation produces a verified manual-cleanup marker', async () => {
  const state = model({ mutateFacts: (count, workDir, sourcePlatform) => ({ sourcePlatform, workDir: count === 2 ? '/changed' : `/canonical${workDir}`, rootIdentity, storageIdentity }) });
  await assert.rejects(state.publisher(input()), (error) =>
    error.code === 'INVENTORY_MANUAL_CLEANUP' && error.writes === 8 &&
    error.ambiguous === false);
  assert.ok(paths(state).some((path) => path.endsWith('inventory-manual-cleanup.v1.json')));
  assert.equal(state.released(), 1);
});

test('a before-release diagnostic failure still releases and cannot overturn a verified commit', async () => {
  const state = model({ checkpoint: async (name) => { if (name === 'before-release') throw new Error('diagnostic'); } });
  const result = await state.publisher(input());
  assert.equal(result.status, 'published'); assert.equal(state.released(), 1);
});

test('native publication failure includes its reported writes once', async () => {
  const native = Object.assign(new Error('native'), { code: 'INVENTORY_IO_FAILED', operation: 'publish_inventory_object_atomic', writes: 2, ambiguous: false });
  const state = model({ publishFailure: async (path) => { if (path.endsWith('workspace-inventory.v2.json')) throw native; } });
  await assert.rejects(state.publisher(input()), (error) => error === native);
  assert.equal(state.released(), 1);
});

test('native failure writes aggregate once with earlier fence writes', async () => {
  const native = Object.assign(new Error('native'), { code: 'INVENTORY_IO_FAILED', operation: 'publish_inventory_object_atomic', writes: 2, ambiguous: false });
  const state = model({ fenceWrites: 3, publishFailure: async (path) => { if (path.endsWith('workspace-inventory.v2.json')) throw native; } });
  await assert.rejects(state.publisher(input()),
    (error) => error !== native && error.code === native.code && error.writes === 5 && error.ambiguous === false);
});

test('ambiguous inventory publication records evidence and retains every write', async () => {
  const native = Object.assign(new Error('native'), { code: 'INVENTORY_MANUAL_CLEANUP', operation: 'publish_inventory_object_atomic', writes: 2, ambiguous: true });
  const state = model({ publishFailure: async (path) => { if (path.endsWith('workspace-inventory.v2.json')) throw native; } });
  await assert.rejects(state.publisher(input()),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' && error.writes === 6 && error.ambiguous === true);
  const marker = parseCanonicalJsonBytes(
    state.objects.get(objectPath('inventory-manual-cleanup.v1.json')).bytes,
    STRICT_JSON_LIMITS,
  );
  assert.equal(marker.reason, 'publication-ambiguous');
});

test('reopened inventory must match the native publication identity', async () => {
  const state = model({
    publishIdentityMismatch: (path, publishedIdentity) =>
      path.endsWith('workspace-inventory.v2.json')
        ? { ...publishedIdentity, inode: '999' } : publishedIdentity,
  });
  await assert.rejects(state.publisher(input()),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.writes === 8 && error.ambiguous === false);
  assert.ok(state.objects.has(objectPath('inventory-manual-cleanup.v1.json')));
});

test('commit publication failure records partial state with exact writes', async () => {
  const native = Object.assign(new Error('commit'), {
    code: 'INVENTORY_IO_FAILED',
    operation: 'publish_inventory_object_atomic',
    writes: 2,
    ambiguous: false,
  });
  const state = model({
    publishFailure: async (path) => {
      if (path.endsWith('inventory-commit.v1.json')) throw native;
    },
  });
  await assert.rejects(state.publisher(input()),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.writes === 10 && error.ambiguous === false);
  const marker = parseCanonicalJsonBytes(
    state.objects.get(objectPath('inventory-manual-cleanup.v1.json')).bytes,
    STRICT_JSON_LIMITS,
  );
  assert.equal(marker.reason, 'partial-publication');
});

test('reopened commit must match the native publication identity', async () => {
  const state = model({
    publishIdentityMismatch: (path, publishedIdentity) =>
      path.endsWith('inventory-commit.v1.json')
        ? { ...publishedIdentity, inode: '999' } : publishedIdentity,
  });
  await assert.rejects(state.publisher(input()),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.writes === 12 && error.ambiguous === false);
});

test('a post-commit diagnostic cannot retract a positive commit', async () => {
  const state = model({ checkpoint: async (name) => { if (name === 'commit-verified') throw new Error('diagnostic'); } });
  const result = await state.publisher(input());
  assert.equal(result.status, 'published');
  assert.equal(state.released(), 1);
});

test('body and release failure returns manual-cleanup ambiguity', async () => {
  const releaseFailure = Object.assign(new Error('release'), { code: 'INVENTORY_IO_FAILED' });
  const state = model({ releaseFailure });
  await assert.rejects(state.publisher(input([], 1)),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.operation === 'release_inventory_fence' && error.ambiguous === true);
  assert.equal(state.released(), 1);
});

test('fresh management ACL denial occurs before fence acquisition', async () => {
  const state = model();
  state.lowLevel.verify_inventory_acl = async () => false;
  await assert.rejects(state.publisher(input()),
    (error) => error.code === 'INVENTORY_ACCESS_DENIED' && error.writes === 0);
  assert.equal(state.calls.some(([kind]) => kind === 'fence'), false);
});

test('release uses the capability captured before fence mutation', async () => {
  let original = 0;
  let substituted = 0;
  const fence = {
    writes: 0,
    release: async () => { original++; },
  };
  const state = model({
    checkpoint: async (name) => {
      if (name === 'fence-acquired') {
        fence.release = async () => { substituted++; };
      }
    },
  });
  state.lowLevel.acquire_inventory_fence = async () => fence;
  const result = await state.publisher(input());
  assert.equal(result.status, 'published');
  assert.equal(original, 1);
  assert.equal(substituted, 0);
});

test('two publishers serialize through an asynchronous fence', async () => {
  let held = false; let release; let acquired = 0; let released = 0;
  const gate = new Promise((resolve) => { release = resolve; });
  const first = model(); const second = model();
  for (const state of [first, second]) state.lowLevel.acquire_inventory_fence = async () => {
    while (held) await gate;
    held = true;
    acquired++;
    return Object.freeze({ writes: 0, release: async () => { released++; held = false; release(); } });
  };
  const one = first.publisher(input());
  await Promise.resolve();
  const two = second.publisher(input());
  await Promise.all([one, two]);
  assert.equal(acquired, 2);
  assert.equal(released, 2);
});

test('a D-like holder of the shared fence blocks all M state reads', async () => {
  let releaseHolder;
  const holder = new Promise((resolve) => { releaseHolder = resolve; });
  let held = true;
  const state = model();
  state.lowLevel.acquire_inventory_fence = async () => {
    if (held) await holder;
    held = true;
    return {
      writes: 0,
      release: async () => { held = false; },
    };
  };
  const pending = state.publisher(input());
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(state.calls.some(([kind]) => kind === 'read'), false);
  held = false;
  releaseHolder();
  const result = await pending;
  assert.equal(result.status, 'published');
});

test('Windows drive facts use the frozen native fingerprint schema', async () => {
  const state = model();
  state.lowLevel.read_workspace_root_facts = async (workDir, sourcePlatform) => ({
    sourcePlatform,
    workDir: `C:\\canonical${workDir}`,
    rootIdentity: {
      kind: 'win32-root-v1',
      volumeSerial: '0011223344556677',
      fileId: '00112233445566778899aabbccddeeff',
    },
    storageIdentity: {
      kind: 'windows-drive-storage-v1',
      volumeGuid: '\\\\?\\Volume{12345678-1234-1234-1234-123456789ABC}\\',
      volumeSerial: '89ABCDEF',
      fileSystem: 'NTFS',
    },
  });
  const result = await state.publisher(input([{
    workspaceId: 'windows',
    sourcePlatform: 'windows-drive',
    workDir: '\\workspace',
  }]));
  assert.equal(result.status, 'published');
});

test('CLI rejects malformed input and redacts malformed role bindings', () => {
  const entrypoint = fileURLToPath(new URL('../src/inventory-entrypoint.js', import.meta.url));
  const missingCommand = spawnSync(process.execPath, [entrypoint], {
    input: '',
    encoding: 'utf8',
    env: { ...process.env, GJC_INVENTORY_ROLE_BINDINGS: '{}' },
  });
  assert.notEqual(missingCommand.status, 0);
  assert.deepEqual(Object.keys(JSON.parse(missingCommand.stderr)).sort(),
    ['ambiguous', 'code', 'operation', 'status', 'writes']);

  const secret = 'do-not-render-this-principal';
  const malformedRoles = spawnSync(process.execPath, [entrypoint, 'publish'], {
    input: JSON.stringify({ hostId, expectedInventoryGeneration: 0, workspaces: [] }),
    encoding: 'utf8',
    env: { ...process.env, GJC_INVENTORY_ROLE_BINDINGS: secret },
  });
  assert.notEqual(malformedRoles.status, 0);
  assert.equal(malformedRoles.stdout, '');
  assert.equal(malformedRoles.stderr.includes(secret), false);
  assert.equal(JSON.parse(malformedRoles.stderr).code, 'INVENTORY_INVALID');

  const malformedInputs = [
    '\ufeff{}',
    '{"hostId":"owned-host","hostId":"other","expectedInventoryGeneration":0,"workspaces":[]}',
    '{"hostId":"owned-host","expectedInventoryGeneration":0,"workspaces":[]} trailing',
    ' '.repeat(1024 * 1024 + 1),
  ];
  for (const malformed of malformedInputs) {
    const result = spawnSync(process.execPath, [entrypoint, 'publish'], {
      input: malformed,
      encoding: 'utf8',
      env: { ...process.env, GJC_INVENTORY_ROLE_BINDINGS: '{}' },
    });
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).code, 'INVENTORY_INVALID');
  }
});
