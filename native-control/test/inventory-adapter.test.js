import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createInventoryPublisherAdapter,
  createInventoryReaderAdapter,
} from '../src/inventory.js';
import * as publicApi from '../src/public.js';

const hostId = 'owned-host';
const hostKey = '53adf929ced7346019d88ec53d76cda70c485f8ef9348a392cf38ae382055b7d';
const roles = Object.freeze({
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
    ensure_inventory_directory: forbidden,
    acquire_inventory_fence: forbidden,
    read_inventory_object: forbidden,
    publish_inventory_object_atomic: forbidden,
  };
  return { lowLevel, calls };
}

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

test('publisher factory returns only an actor-bound frozen selfTest', async () => {
  const state = fixture();
  const publisher = await createInventoryPublisherAdapter(() => state.lowLevel, { hostId, roles });
  assert.deepEqual(Object.keys(publisher), ['selfTest']);
  assert.equal(Object.isFrozen(publisher), true);
  assert.equal('publish' in publisher, false);
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
  assert.deepEqual(Object.keys(reader), ['selfTest']);
  assert.equal(Object.isFrozen(reader), true);
  assert.equal('readAccepted' in reader, false);
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
  assert.equal(supplied.management.value, 'uid:1001');
  assert.equal(supplied.daemon.value, 'uid:1004');
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
  const variants = [
    { ...roles, daemon: roles.management },
    { ...roles, daemon: { kind: 'sid', value: 'S-1-5-21-100' } },
    { ...roles, system: { kind: 'uid', value: 'uid:1' } },
    { ...roles, bot: { kind: 'uid', value: 'uid:01' } },
    { ...roles, extra: { kind: 'uid', value: 'uid:9' } },
    Object.assign(Object.create(null), roles),
  ];
  for (const invalidRoles of variants) await rejectsInvalid({ hostId, roles: invalidRoles });
  const principalAccessor = { ...roles };
  Object.defineProperty(principalAccessor, 'bot', {
    enumerable: true,
    value: Object.defineProperties({}, {
      kind: { enumerable: true, value: 'uid' },
      value: { enumerable: true, get: () => 'uid:1002' },
    }),
  });
  await rejectsInvalid({ hostId, roles: principalAccessor });
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
