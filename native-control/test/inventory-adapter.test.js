import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJsonBytes,
  canonicalJsonHash,
  STRICT_JSON_LIMITS,
} from '@gjc-remote/shared/strict-json';
import { buildWorkspaceInventory } from '@gjc-remote/shared/workspace-inventory';
import {
  createInventoryPublisherAdapter,
  createInventoryReaderAdapter,
} from '../src/inventory.js';
import { documentFingerprint } from '../src/inventory-state.js';
import * as publicApi from '../src/public.js';

const hostId = 'owned-host';
const hostKey = '53adf929ced7346019d88ec53d76cda70c485f8ef9348a392cf38ae382055b7d';
const roles = Object.freeze(process.platform === 'win32' ? {
  management: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1001' }),
  bot: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1002' }),
  recovery: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1003' }),
  daemon: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1004' }),
  system: Object.freeze({ kind: 'sid', value: 'S-1-5-18' }),
} : {
  management: Object.freeze({ kind: 'uid', value: 'uid:1001' }),
  bot: Object.freeze({ kind: 'uid', value: 'uid:1002' }),
  recovery: Object.freeze({ kind: 'uid', value: 'uid:1003' }),
  daemon: Object.freeze({ kind: 'uid', value: 'uid:1004' }),
  system: Object.freeze({ kind: 'uid', value: 'uid:0' }),
});

function nativeError(code = 'INVENTORY_ACCESS_DENIED', operation = 'verify_inventory_acl') {
  const error = new Error('inventory operation failed');
  Object.assign(error, { code, operation, writes: 0, ambiguous: false });
  return error;
}

function fixture() {
  const calls = [];
  const forbidden = () => assert.fail('adapter attempted mutation or object I/O');
  const lowLevel = {
    resolve_native_state_root: async (key, kind) => {
      calls.push(['root', key, kind]);
      return `/managed/${kind}/${key}`;
    },
    verify_inventory_acl: async (path, suppliedRoles, profile, expectedActor) => {
      calls.push(['acl', path, suppliedRoles, profile, expectedActor]);
      return true;
    },
    current_os_principal: forbidden,
    read_workspace_root_facts: forbidden,
    ensure_inventory_directory: forbidden,
    acquire_inventory_fence: forbidden,
    read_inventory_object: forbidden,
    publish_inventory_object_atomic: forbidden,
  };
  return { lowLevel, calls };
}

test('publisher rejects an incomplete low-level capability surface', async () => {
  const state = fixture();
  delete state.lowLevel.publish_inventory_object_atomic;
  await assert.rejects(
    createInventoryPublisherAdapter(() => state.lowLevel, { hostId, roles }),
    (error) => assertBoundedError(error, 'INVENTORY_INVALID', 'resolve_native_state_root'),
  );
  assert.deepEqual(state.calls, []);
});

test('publisher rejects accessor capabilities without invoking them', async () => {
  const state = fixture();
  let getterCalls = 0;
  Object.defineProperty(state.lowLevel, 'read_workspace_root_facts', {
    enumerable: true,
    configurable: true,
    get() {
      getterCalls++;
      return async () => {};
    },
  });
  await assert.rejects(
    createInventoryPublisherAdapter(() => state.lowLevel, { hostId, roles }),
    (error) => assertBoundedError(error, 'INVENTORY_INVALID', 'resolve_native_state_root'),
  );
  assert.equal(getterCalls, 0);
  assert.deepEqual(state.calls, []);
});

function assertBoundedError(error, code, operation) {
  assert.equal(error.message, 'inventory operation failed');
  assert.ok(Buffer.byteLength(error.message, 'utf8') <= 160);
  assert.deepEqual(Object.keys(error), ['code', 'operation', 'writes', 'ambiguous']);
  assert.deepEqual(
    { code: error.code, operation: error.operation, writes: error.writes, ambiguous: error.ambiguous },
    { code, operation, writes: 0, ambiguous: false },
  );
  assert.doesNotMatch(error.message, /owned-host|uid:|managed/i);
  return true;
}

async function rejectsInvalid(options, create = createInventoryPublisherAdapter) {
  let loaded = false;
  await assert.rejects(
    create(() => { loaded = true; return fixture().lowLevel; }, options),
    (error) => assertBoundedError(error, 'INVENTORY_INVALID', 'resolve_native_state_root'),
  );
  assert.equal(loaded, false, 'input rejection must precede addon loading');
}

test('publisher factory returns an actor-bound frozen selfTest and publish', async () => {
  const state = fixture();
  const publisher = await createInventoryPublisherAdapter(() => state.lowLevel, { hostId, roles });
  assert.deepEqual(Object.keys(publisher), ['selfTest', 'publish']);
  assert.equal(Object.isFrozen(publisher), true);
  assert.equal(typeof publisher.publish, 'function');
  assert.deepEqual(state.calls.map(([kind, path,, profile, actor]) => [kind, path, profile, actor]), [
    ['root', hostKey, undefined, undefined],
    ['acl', `/managed/inventory/${hostKey}`, 'inventory-directory', 'management'],
  ]);
  const result = await publisher.selfTest();
  assert.deepEqual(result, { role: 'management', contractVersion: 4, writes: 0 });
  assert.deepEqual(Object.keys(result), ['role', 'contractVersion', 'writes']);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(state.calls.at(-1)[4], 'management');
});

test('reader factory and every selfTest bind D while verifying both roots', async () => {
  const state = fixture();
  const reader = await createInventoryReaderAdapter(() => state.lowLevel, { hostId, roles });
  assert.deepEqual(Object.keys(reader), ['selfTest', 'readAccepted']);
  assert.equal(Object.isFrozen(reader), true);
  assert.equal(typeof reader.readAccepted, 'function');
  assert.deepEqual(state.calls.map(([kind, path, rootKind, profile, actor]) =>
    [kind, path, rootKind, profile, actor]), [
    ['root', hostKey, 'inventory', undefined, undefined],
    ['root', hostKey, 'reader', undefined, undefined],
    ['acl', `/managed/inventory/${hostKey}`, roles, 'inventory-directory', 'daemon'],
    ['acl', `/managed/reader/${hostKey}`, roles, 'reader-directory', 'daemon'],
  ]);
  const result = await reader.selfTest();
  assert.deepEqual(result, { role: 'daemon', contractVersion: 4, writes: 0 });
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(state.calls.slice(-2).map((call) => call[4]), ['daemon', 'daemon']);
});

test('factory selfTest fails closed on absent or false ACL evidence', async () => {
  const absentState = fixture();
  const expected = nativeError();
  absentState.lowLevel.verify_inventory_acl = async () => { throw expected; };
  await assert.rejects(
    createInventoryPublisherAdapter(() => absentState.lowLevel, { hostId, roles }),
    (error) => error === expected,
  );

  const falseState = fixture();
  falseState.lowLevel.verify_inventory_acl = async () => false;
  await assert.rejects(
    createInventoryPublisherAdapter(() => falseState.lowLevel, { hostId, roles }),
    (error) => assertBoundedError(error, 'INVENTORY_ACCESS_DENIED', 'verify_inventory_acl'),
  );
});

test('native errors from roots and verification preserve exact identity and fields', async () => {
  const rootState = fixture();
  const rootError = nativeError('INVENTORY_IO_FAILED', 'resolve_native_state_root');
  rootState.lowLevel.resolve_native_state_root = async () => { throw rootError; };
  await assert.rejects(
    createInventoryPublisherAdapter(() => rootState.lowLevel, { hostId, roles }),
    (error) => error === rootError,
  );
});

test('factory rejects missing or malformed resolved roots before ACL verification', async () => {
  for (const invalidRoot of [undefined, null, '', Buffer.from('/managed/inventory')]) {
    const state = fixture();
    state.lowLevel.resolve_native_state_root = async () => invalidRoot;
    await assert.rejects(
      createInventoryPublisherAdapter(() => state.lowLevel, { hostId, roles }),
      (error) => assertBoundedError(error, 'INVENTORY_IO_FAILED', 'resolve_native_state_root'),
    );
    assert.equal(state.calls.some(([kind]) => kind === 'acl'), false);
  }

  const readerState = fixture();
  readerState.lowLevel.resolve_native_state_root = async (key, kind) => {
    readerState.calls.push(['root', key, kind]);
    return kind === 'inventory' ? `/managed/inventory/${key}` : undefined;
  };
  await assert.rejects(
    createInventoryReaderAdapter(() => readerState.lowLevel, { hostId, roles }),
    (error) => assertBoundedError(error, 'INVENTORY_IO_FAILED', 'resolve_native_state_root'),
  );
  assert.equal(readerState.calls.some(([kind]) => kind === 'acl'), false);
});

test('validated role snapshots do not observe later input mutation', async () => {
  const mutableRoles = Object.fromEntries(
    Object.entries(roles).map(([key, value]) => [key, { ...value }]));
  const state = fixture();
  const publisher = await createInventoryPublisherAdapter(
    () => state.lowLevel, { hostId, roles: mutableRoles });
  mutableRoles.management.value = mutableRoles.daemon.value;
  mutableRoles.daemon = mutableRoles.management;
  await publisher.selfTest();
  const supplied = state.calls.at(-1)[2];
  assert.equal(supplied.management.value, roles.management.value);
  assert.equal(supplied.daemon.value, roles.daemon.value);
  assert.equal(Object.isFrozen(supplied), true);
  assert.equal(Object.isFrozen(supplied.management), true);
});

test('factory validation rejects malformed options before addon loading', async () => {
  await rejectsInvalid(undefined);
  await rejectsInvalid({ hostId });
  await rejectsInvalid({ hostId, roles, extra: true });
  await rejectsInvalid({ hostId: '', roles });
  await rejectsInvalid({ hostId: 'x'.repeat(129), roles });
  await rejectsInvalid({ hostId: 'bad\u0000host', roles });
  await rejectsInvalid(Object.assign(Object.create(null), { hostId, roles }));
  await rejectsInvalid(Object.assign({ hostId, roles }, { [Symbol('extra')]: true }));
  const accessor = {};
  Object.defineProperties(accessor, {
    hostId: { enumerable: true, get: () => hostId },
    roles: { enumerable: true, value: roles },
  });
  await rejectsInvalid(accessor);
  await rejectsInvalid(new Proxy({}, { ownKeys() { throw new Error('trap'); } }));
});

test('role validation rejects malformed, duplicate, mixed-kind, and non-system bindings', async () => {
  const wrongKindRoles = process.platform === 'win32' ? {
    management: { kind: 'uid', value: 'uid:1001' },
    bot: { kind: 'uid', value: 'uid:1002' },
    recovery: { kind: 'uid', value: 'uid:1003' },
    daemon: { kind: 'uid', value: 'uid:1004' },
    system: { kind: 'uid', value: 'uid:0' },
  } : {
    management: { kind: 'sid', value: 'S-1-5-21-100-1001' },
    bot: { kind: 'sid', value: 'S-1-5-21-100-1002' },
    recovery: { kind: 'sid', value: 'S-1-5-21-100-1003' },
    daemon: { kind: 'sid', value: 'S-1-5-21-100-1004' },
    system: { kind: 'sid', value: 'S-1-5-18' },
  };
  const variants = [
    { ...roles, daemon: roles.management },
    wrongKindRoles,
    { ...roles, system: { kind: roles.system.kind, value:
      roles.system.kind === 'sid' ? 'S-1-5-19' : 'uid:1' } },
    { ...roles, bot: { kind: roles.bot.kind, value:
      roles.bot.kind === 'sid' ? 's-1-5-21-100' : 'uid:01' } },
    { ...roles, extra: { kind: roles.bot.kind, value:
      roles.bot.kind === 'sid' ? 'S-1-5-21-100-9' : 'uid:9' } },
    Object.assign(Object.create(null), roles),
  ];
  if (process.platform === 'win32') {
    variants.push({
      ...roles,
      management: {
        kind: 'sid',
        value: `S-1-5-${'1-'.repeat(2_100)}1`,
      },
    });
    for (const value of [
      `S-1-5-${Array.from({ length: 16 }, () => '1').join('-')}`,
      'S-1-281474976710656-1',
      'S-1-5-4294967296',
      'S-2-5-1',
    ]) {
      variants.push({ ...roles, management: { kind: 'sid', value } });
    }
  }
  for (const invalidRoles of variants) await rejectsInvalid({ hostId, roles: invalidRoles });
  const principalAccessor = { ...roles };
  Object.defineProperty(principalAccessor, 'bot', {
    enumerable: true,
    value: Object.defineProperties({}, {
      kind: { enumerable: true, value: roles.bot.kind },
      value: { enumerable: true, get: () => roles.bot.value },
    }),
  });
  await rejectsInvalid({ hostId, roles: principalAccessor });
});

const readerRootIdentity = Object.freeze({
  kind: 'posix-root-v1',
  device: '7',
  inode: '11',
});
const readerStorageIdentity = Object.freeze({
  kind: 'posix-storage-v1',
  device: '7',
});

function readerPath(root, name) {
  const separator = process.platform === 'win32' ? '\\' : '/';
  return `${root}${separator}${name}`;
}

function readerObjectIdentity(inode) {
  return {
    device: '7',
    inode: String(inode),
    mode: 33152,
    owner: 'uid:1001',
  };
}

function floorDocument(generation, fingerprint) {
  const document = {
    version: 1,
    hostId,
    inventoryGeneration: generation,
    inventoryFingerprint: fingerprint,
  };
  document.floorFingerprint = documentFingerprint(document, 'floorFingerprint');
  return document;
}

function commitDocument(inventory, identity) {
  const document = {
    version: 1,
    hostId,
    inventoryGeneration: inventory.inventoryGeneration,
    inventoryFingerprint: inventory.inventoryFingerprint,
    inventoryObjectIdentityFingerprint: canonicalJsonHash(
      identity, STRICT_JSON_LIMITS),
    publicationNonce: 'a'.repeat(32),
  };
  document.commitFingerprint = documentFingerprint(
    document, 'commitFingerprint');
  return document;
}

function createReaderModel({
  generation = 1,
  floor = 'absent',
  factsMismatch = false,
  releaseError = null,
  acquireError = null,
  publishError = null,
  returnedIdentityMismatch = false,
  floorAclDenied = false,
  factsMismatchAfter = null,
  finalInventoryDrift = false,
} = {}) {
  const inventoryRoot = '/managed/inventory';
  const readerRoot = '/managed/reader';
  const inventoryIdentity = readerObjectIdentity(20);
  const record = {
    hostId,
    workspaceId: 'workspace',
    sourcePlatform: 'posix',
    workDir: '/canonical/workspace',
    rootIdentityFingerprint: canonicalJsonHash(
      readerRootIdentity, STRICT_JSON_LIMITS),
    storageIdentityFingerprint: canonicalJsonHash(
      readerStorageIdentity, STRICT_JSON_LIMITS),
  };
  const inventory = buildWorkspaceInventory({
    hostId,
    inventoryGeneration: generation,
    workspaces: [record],
  });
  const commit = commitDocument(inventory, inventoryIdentity);
  const objects = new Map([
    [readerPath(inventoryRoot, 'workspace-inventory.v2.json'), {
      bytes: canonicalJsonBytes(inventory, STRICT_JSON_LIMITS),
      identity: inventoryIdentity,
    }],
    [readerPath(inventoryRoot, 'inventory-commit.v1.json'), {
      bytes: canonicalJsonBytes(commit, STRICT_JSON_LIMITS),
      identity: readerObjectIdentity(21),
    }],
  ]);
  if (floor !== 'absent') {
    const acceptedGeneration = floor === 'exact' ? generation : generation - 1;
    const acceptedFingerprint = floor === 'exact'
      ? inventory.inventoryFingerprint : 'b'.repeat(64);
    objects.set(readerPath(readerRoot, 'inventory-floor.v1.json'), {
      bytes: canonicalJsonBytes(
        floorDocument(acceptedGeneration, acceptedFingerprint),
        STRICT_JSON_LIMITS,
      ),
      identity: readerObjectIdentity(22),
    });
  }
  const calls = [];
  const readCounts = new Map();
  let factsReads = 0;
  let released = 0;
  let currentReleaseError = releaseError;
  let identitySequence = 30;
  const lowLevel = {
    resolve_native_state_root: async (_key, kind) => {
      calls.push(['root', kind]);
      return kind === 'inventory' ? inventoryRoot : readerRoot;
    },
    verify_inventory_acl: async (path, _roles, profile, actor) => {
      calls.push(['acl', path, profile, actor]);
      return !(floorAclDenied && profile === 'inventory-floor');
    },
    read_workspace_root_facts: async (workDir, sourcePlatform) => {
      calls.push(['facts', workDir]);
      factsReads += 1;
      const mismatch = factsMismatch ||
        (Number.isInteger(factsMismatchAfter) &&
          factsReads >= factsMismatchAfter);
      return {
        sourcePlatform,
        workDir,
        rootIdentity: mismatch
          ? { ...readerRootIdentity, inode: '12' } : readerRootIdentity,
        storageIdentity: readerStorageIdentity,
      };
    },
    acquire_inventory_fence: async (path) => {
      calls.push(['fence', path]);
      if (acquireError) throw acquireError;
      return {
        writes: 0,
        release: async () => {
          released += 1;
          calls.push(['release']);
          if (currentReleaseError) throw currentReleaseError;
        },
      };
    },
    read_inventory_object: async (path, _maxBytes, _roles, profile) => {
      calls.push(['read', path, profile]);
      const count = (readCounts.get(path) ?? 0) + 1;
      readCounts.set(path, count);
      if (finalInventoryDrift &&
          path.endsWith('workspace-inventory.v2.json') && count >= 2) {
        return {
          bytes: canonicalJsonBytes(inventory, STRICT_JSON_LIMITS),
          identity: readerObjectIdentity(999),
        };
      }
      return objects.get(path) ?? null;
    },
    publish_inventory_object_atomic: async (
      path, prefix, bytes, expectedIdentity, _roles, profile,
    ) => {
      calls.push(['publish', path, prefix, expectedIdentity, profile]);
      if (publishError) throw publishError;
      const prior = objects.get(path);
      const identity = readerObjectIdentity(identitySequence++);
      objects.set(path, { bytes: Buffer.from(bytes), identity });
      return {
        writes: prior ? 5 : 4,
        identity: returnedIdentityMismatch
          ? { ...identity, inode: '999' } : identity,
      };
    },
  };
  return {
    inventory,
    commit,
    objects,
    calls,
    lowLevel,
    released: () => released,
    setReleaseError: (value) => { currentReleaseError = value; },
    readCounts,
    inventoryRoot,
    readerRoot,
  };
}

async function createModeledReader(state) {
  const reader = await createInventoryReaderAdapter(
    () => state.lowLevel, { hostId, roles });
  state.calls.length = 0;
  return reader;
}

test('Reader returns missing only after the locked marker-first state read', async () => {
  const state = createReaderModel();
  state.objects.clear();
  const reader = await createModeledReader(state);
  const result = await reader.readAccepted();
  assert.deepEqual(result, { status: 'missing' });
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(
    state.calls.filter(([kind]) => kind === 'root')
      .map(([, rootKind]) => rootKind),
    ['inventory', 'reader', 'inventory', 'reader'],
  );
  assert.deepEqual(
    state.calls.filter(([kind]) => kind === 'read')
      .map(([, path]) => path.split(/[\\/]/).at(-1)),
    [
      'inventory-manual-cleanup.v1.json',
      'workspace-inventory.v2.json',
      'inventory-commit.v1.json',
      'inventory-floor.v1.json',
      'inventory-manual-cleanup.v1.json',
      'workspace-inventory.v2.json',
      'inventory-commit.v1.json',
      'inventory-floor.v1.json',
    ],
  );
  assert.equal(state.released(), 1);
});

test('Reader rejects missing or replay state that drifts on the final pass', async () => {
  const missing = createReaderModel({ finalInventoryDrift: true });
  missing.objects.clear();
  await assert.rejects(
    (await createModeledReader(missing)).readAccepted(),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.operation === 'read_inventory' &&
      error.writes === 0 && error.ambiguous === true,
  );

  const replay = createReaderModel({
    floor: 'exact',
    finalInventoryDrift: true,
  });
  await assert.rejects(
    (await createModeledReader(replay)).readAccepted(),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.writes === 0 && error.ambiguous === true,
  );
});

test('Reader creates, replays, and advances the D floor with exact proof', async () => {
  const genesis = createReaderModel();
  const reader = await createModeledReader(genesis);
  const first = await reader.readAccepted();
  assert.deepEqual(Object.keys(first), ['status', 'inventory', 'proof']);
  assert.strictEqual(first.inventory.inventoryFingerprint,
    genesis.inventory.inventoryFingerprint);
  assert.equal(Object.isFrozen(first.inventory), true);
  assert.equal(Object.isFrozen(first.inventory.workspaces), true);
  assert.equal(Object.isFrozen(first.inventory.workspaces[0]), true);
  assert.deepEqual(Object.keys(first.proof), [
    'source',
    'inventoryGeneration',
    'inventoryFingerprint',
    'commitFingerprint',
    'floorFingerprint',
  ]);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.proof), true);
  assert.equal(
    genesis.calls.filter(([kind]) => kind === 'publish').at(0)[4],
    'inventory-floor',
  );
  assert.equal(
    genesis.calls.filter(([kind]) => kind === 'publish').length, 1);
  genesis.calls.length = 0;
  const replay = await reader.readAccepted();
  assert.equal(replay.proof.floorFingerprint, first.proof.floorFingerprint);
  assert.equal(
    genesis.calls.some(([kind]) => kind === 'publish'), false);

  const advance = createReaderModel({ generation: 2, floor: 'previous' });
  const advanced = await (await createModeledReader(advance)).readAccepted();
  assert.equal(advanced.inventory.inventoryGeneration, 2);
  assert.equal(
    advance.calls.filter(([kind]) => kind === 'publish').at(0)[4],
    'inventory-floor',
  );
});

test('dual Readers serialize through the shared fence and publish one floor', async () => {
  const state = createReaderModel();
  let tail = Promise.resolve();
  let maximum = 0;
  let active = 0;
  state.lowLevel.acquire_inventory_fence = async (path) => {
    state.calls.push(['fence', path]);
    const previous = tail;
    let unlock;
    tail = new Promise((resolve) => { unlock = resolve; });
    await previous;
    active += 1;
    maximum = Math.max(maximum, active);
    return {
      writes: 0,
      release: async () => {
        active -= 1;
        unlock();
      },
    };
  };
  const reader = await createModeledReader(state);
  const results = await Promise.all([
    reader.readAccepted(),
    reader.readAccepted(),
  ]);
  assert.deepEqual(results.map(({ status }) => status), ['present', 'present']);
  assert.equal(maximum, 1);
  assert.equal(
    state.calls.filter(([kind]) => kind === 'publish').length, 1);
});

test('Reader rejects every rollback, jump, partial, and marker state', async () => {
  const cases = [];
  const generationTwo = createReaderModel({ generation: 2 });
  cases.push([generationTwo, 'INVENTORY_STALE']);

  const rollback = createReaderModel({ generation: 1, floor: 'exact' });
  const rollbackFloor = floorDocument(2, 'c'.repeat(64));
  rollback.objects.set(
    readerPath(rollback.readerRoot, 'inventory-floor.v1.json'),
    {
      bytes: canonicalJsonBytes(rollbackFloor, STRICT_JSON_LIMITS),
      identity: readerObjectIdentity(40),
    },
  );
  cases.push([rollback, 'INVENTORY_STALE']);

  const partial = createReaderModel();
  partial.objects.delete(
    readerPath(partial.inventoryRoot, 'inventory-commit.v1.json'));
  cases.push([partial, 'INVENTORY_MANUAL_CLEANUP']);

  const commitOnly = createReaderModel();
  commitOnly.objects.delete(
    readerPath(commitOnly.inventoryRoot, 'workspace-inventory.v2.json'));
  cases.push([commitOnly, 'INVENTORY_MANUAL_CLEANUP']);

  const inventoryWithFloor = createReaderModel({ floor: 'exact' });
  inventoryWithFloor.objects.delete(
    readerPath(inventoryWithFloor.inventoryRoot, 'inventory-commit.v1.json'));
  cases.push([inventoryWithFloor, 'INVENTORY_MANUAL_CLEANUP']);

  const commitWithFloor = createReaderModel({ floor: 'exact' });
  commitWithFloor.objects.delete(
    readerPath(commitWithFloor.inventoryRoot, 'workspace-inventory.v2.json'));
  cases.push([commitWithFloor, 'INVENTORY_MANUAL_CLEANUP']);

  const floorOnly = createReaderModel({ floor: 'exact' });
  floorOnly.objects.delete(
    readerPath(floorOnly.inventoryRoot, 'workspace-inventory.v2.json'));
  floorOnly.objects.delete(
    readerPath(floorOnly.inventoryRoot, 'inventory-commit.v1.json'));
  cases.push([floorOnly, 'INVENTORY_STALE']);

  const marker = createReaderModel();
  marker.objects.set(
    readerPath(marker.inventoryRoot, 'inventory-manual-cleanup.v1.json'),
    { bytes: Buffer.from('{}'), identity: readerObjectIdentity(41) },
  );
  cases.push([marker, 'INVENTORY_MANUAL_CLEANUP']);

  const malformed = createReaderModel();
  malformed.objects.get(
    readerPath(malformed.inventoryRoot, 'inventory-commit.v1.json'),
  ).bytes = Buffer.from('{}');
  cases.push([malformed, 'INVENTORY_INVALID']);

  for (const [state, code] of cases) {
    const reader = await createModeledReader(state);
    await assert.rejects(reader.readAccepted(),
      (error) => error.code === code && error.writes === 0);
    assert.equal(state.released(), 1);
  }
});

test('Reader preserves native fence errors and rejects stale workspace facts', async () => {
  const native = Object.assign(new Error('native'), {
    code: 'INVENTORY_STALE',
    operation: 'acquire_inventory_fence',
    writes: 0,
    ambiguous: false,
  });
  const absentFence = createReaderModel({ acquireError: native });
  await assert.rejects(
    (await createModeledReader(absentFence)).readAccepted(),
    (error) => error === native,
  );
  const pending = Object.assign(new Error('pending'), {
    code: 'INVENTORY_PENDING',
    operation: 'acquire_inventory_fence',
    writes: 0,
    ambiguous: false,
  });
  await assert.rejects(
    (await createModeledReader(
      createReaderModel({ acquireError: pending }))).readAccepted(),
    (error) => error === pending,
  );

  const staleFacts = createReaderModel({ factsMismatch: true });
  await assert.rejects(
    (await createModeledReader(staleFacts)).readAccepted(),
    (error) => error.code === 'INVENTORY_STALE' &&
      error.operation === 'read_inventory' && error.writes === 0,
  );

  const secondPass = createReaderModel({ factsMismatchAfter: 2 });
  await assert.rejects(
    (await createModeledReader(secondPass)).readAccepted(),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.operation === 'read_inventory' &&
      error.writes === 4 && error.ambiguous === true,
  );
});

test('Reader retains a verified floor but fails closed on identity or release errors', async () => {
  const mismatch = createReaderModel({ returnedIdentityMismatch: true });
  await assert.rejects(
    (await createModeledReader(mismatch)).readAccepted(),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.writes === 4 && error.ambiguous === true,
  );

  const releaseError = Object.assign(new Error('release'), {
    code: 'INVENTORY_IO_FAILED',
    operation: 'release_inventory_fence',
    writes: 0,
    ambiguous: true,
  });
  const release = createReaderModel({ releaseError });
  await assert.rejects(
    (await createModeledReader(release)).readAccepted(),
    (error) => error.code === 'INVENTORY_IO_FAILED' &&
      error.operation === 'release_inventory_fence' &&
      error.writes === 4 && error.ambiguous === true,
  );
  assert.ok(release.objects.has(
    readerPath(release.readerRoot, 'inventory-floor.v1.json')));
  release.setReleaseError(null);
  release.calls.length = 0;
  const recovered = await (await createModeledReader(release)).readAccepted();
  assert.equal(recovered.status, 'present');
  assert.equal(release.calls.some(([kind]) => kind === 'publish'), false);

  const acl = createReaderModel({ floorAclDenied: true });
  await assert.rejects(
    (await createModeledReader(acl)).readAccepted(),
    (error) => error.code === 'INVENTORY_ACCESS_DENIED' &&
      error.operation === 'verify_inventory_acl' &&
      error.writes === 4,
  );

  const partialPublish = Object.assign(new Error('partial publish'), {
    code: 'INVENTORY_IO_FAILED',
    operation: 'publish_inventory_object_atomic',
    writes: 2,
    ambiguous: true,
  });
  const dualFailure = createReaderModel({
    publishError: partialPublish,
    releaseError,
  });
  await assert.rejects(
    (await createModeledReader(dualFailure)).readAccepted(),
    (error) => error.code === 'INVENTORY_MANUAL_CLEANUP' &&
      error.operation === 'release_inventory_fence' &&
      error.writes === 2 && error.ambiguous === true,
  );
});

test('public module exposes only management plus staged inventory factories', () => {
  assert.deepEqual(Object.keys(publicApi).sort(), [
    'buildManifest',
    'createInventoryPublisher',
    'createInventoryReader',
    'createManagementNative',
    'validateBuildManifest',
  ]);
  assert.equal(typeof publicApi.createInventoryPublisher, 'function');
  assert.equal(typeof publicApi.createInventoryReader, 'function');
  assert.equal('createInventoryPublisherAdapter' in publicApi, false);
  assert.equal('createInventoryReaderAdapter' in publicApi, false);
});
