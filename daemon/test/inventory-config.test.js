import test from 'node:test';
import assert from 'node:assert/strict';
import { initializeInventoryConfig, inventoryConfigDiagnostic } from '../src/inventory-config.js';

const linuxRoles = Object.freeze({
  management: { kind: 'uid', value: 'uid:1001' },
  bot: { kind: 'uid', value: 'uid:1002' },
  recovery: { kind: 'uid', value: 'uid:1003' },
  daemon: { kind: 'uid', value: 'uid:1004' },
  system: { kind: 'uid', value: 'uid:0' },
});
const windowsRoles = Object.freeze({
  management: { kind: 'sid', value: 'S-1-5-21-1001' },
  bot: { kind: 'sid', value: 'S-1-5-21-1002' },
  recovery: { kind: 'sid', value: 'S-1-5-21-1003' },
  daemon: { kind: 'sid', value: 'S-1-5-21-1004' },
  system: { kind: 'sid', value: 'S-1-5-18' },
});
const rolesJson = (roles = linuxRoles) => JSON.stringify(roles);
const verifyEnv = (roles = linuxRoles) => ({
  GJC_NATIVE_INVENTORY_MODE: 'verify', GJC_INVENTORY_ROLE_BINDINGS: rolesJson(roles),
});
const reader = () => Object.freeze({
  selfTest: async () => Object.freeze({ role: 'daemon', contractVersion: 4, writes: 0 }),
  readAccepted: async () => { throw new Error('must not read'); },
});

test('off is inert for absent mode and malformed inputs', async () => {
  const inaccessibleRoles = { GJC_NATIVE_INVENTORY_MODE: 'off' };
  Object.defineProperty(inaccessibleRoles, 'GJC_INVENTORY_ROLE_BINDINGS', {
    get() { throw new Error('roles must remain unread'); },
  });
  for (const env of [
    {},
    { GJC_NATIVE_INVENTORY_MODE: 'off', GJC_INVENTORY_ROLE_BINDINGS: '{' },
    inaccessibleRoles,
  ]) {
    let calls = 0;
    const result = await initializeInventoryConfig({ env, platform: 'unsupported' }, {
      createInventoryReader: () => { calls += 1; throw new Error('factory'); },
    });
    assert.deepEqual(result, { mode: 'off' });
    assert.equal(Object.isFrozen(result), true);
    assert.equal(calls, 0);
  }
});

test('mode must be exact lowercase off or verify', async () => {
  for (const mode of ['', ' off', 'off ', 'OFF', 'verify ', ' Verify', null]) {
    await assert.rejects(
      initializeInventoryConfig({ env: { GJC_NATIVE_INVENTORY_MODE: mode }, platform: 'linux' }),
      (error) => error.code === 'CONFIG_INVALID' && error.operation === 'initialize_inventory_config'
    );
  }
});

test('verify rejects invalid roles before the factory', async () => {
  const invalid = [
    '{}',
    '{"management":{"kind":"uid","value":"uid:1001"},"management":{"kind":"uid","value":"uid:1005"},"bot":{"kind":"uid","value":"uid:1002"},"recovery":{"kind":"uid","value":"uid:1003"},"daemon":{"kind":"uid","value":"uid:1004"},"system":{"kind":"uid","value":"uid:0"}}',
    '{"management":{"kind":"uid","value":"uid:1"},"bot":{"kind":"uid","value":"uid:2"},"recovery":{"kind":"uid","value":"uid:3"},"daemon":{"kind":"uid","value":"uid:4"},"system":{"kind":"uid","value":"uid:0"},"extra":true}',
    rolesJson({ ...linuxRoles, bot: linuxRoles.management }),
    rolesJson({ ...linuxRoles, bot: windowsRoles.bot }),
    rolesJson({ ...linuxRoles, management: { kind: 'uid', value: 'uid:01' } }),
    rolesJson({ ...linuxRoles, management: { kind: 'uid', value: 'uid:4294967296' } }),
    rolesJson({ ...linuxRoles, system: { kind: 'uid', value: 'uid:1' } }),
    rolesJson({ ...windowsRoles, system: { kind: 'sid', value: 'S-1-5-018' } }),
    rolesJson({ ...windowsRoles, management: { kind: 'sid', value: 'S-1-281474976710656-1' } }),
  ];
  for (const bindings of invalid) {
    let calls = 0;
    await assert.rejects(initializeInventoryConfig({
      env: { GJC_NATIVE_INVENTORY_MODE: 'verify', GJC_INVENTORY_ROLE_BINDINGS: bindings }, platform: 'linux',
    }, { createInventoryReader: () => { calls += 1; } }), /Inventory configuration is invalid/);
    assert.equal(calls, 0);
  }
});

test('windows accepts only canonical bounded SID roles', async () => {
  let received;
  await initializeInventoryConfig({ env: verifyEnv(windowsRoles), hostId: 'host-a', platform: 'win32' }, {
    createInventoryReader: async (options) => {
      received = options;
      return reader();
    },
  });
  assert.deepEqual(received.roles, windowsRoles);
  assert.equal(Object.isFrozen(received.roles.system), true);
});

test('windows rejects malformed, noncanonical, and oversized SIDs before the factory', async () => {
  for (const management of [
    { kind: 'sid', value: 's-1-5-21-1001' },
    { kind: 'sid', value: 'S-1-281474976710656-1' },
    { kind: 'sid', value: 'S-1-5-21-4294967296' },
  ]) {
    let calls = 0;
    await assert.rejects(initializeInventoryConfig({
      env: verifyEnv({ ...windowsRoles, management }), platform: 'win32',
    }, { createInventoryReader: () => { calls += 1; } }), /Inventory configuration is invalid/);
    assert.equal(calls, 0);
  }
  let calls = 0;
  await assert.rejects(initializeInventoryConfig({
    env: verifyEnv({
      ...windowsRoles,
      system: { kind: 'sid', value: 'S-1-5-19' },
    }),
    platform: 'win32',
  }, { createInventoryReader: () => { calls += 1; } }), /Inventory configuration is invalid/);
  assert.equal(calls, 0);
});

test('verify rejects unsupported platforms and test injection before factory', async () => {
  for (const [platform, env] of [
    ['darwin', verifyEnv()],
    ['linux', { ...verifyEnv(), GJC_READINESS_TEST_INJECTION: '1' }],
  ]) {
    let calls = 0;
    await assert.rejects(initializeInventoryConfig({ env, platform }, {
      createInventoryReader: () => { calls += 1; },
    }), /Inventory configuration is invalid/);
    assert.equal(calls, 0);
  }
});

test('verify gives the factory one frozen exact argument and never reads', async () => {
  let calls = 0;
  let reads = 0;
  const receiver = {};
  const result = await initializeInventoryConfig({ env: verifyEnv(), hostId: 'host-a', platform: 'linux' }, {
    createInventoryReader: async (options) => {
      calls += 1;
      assert.deepEqual(Object.keys(options), ['hostId', 'roles']);
      assert.equal(Object.isFrozen(options), true);
      assert.equal(Object.isFrozen(options.roles), true);
      assert.equal(options.hostId, 'host-a');
      Object.assign(receiver, {
        selfTest() {
          assert.equal(this, receiver);
          return Object.freeze({ role: 'daemon', contractVersion: 4, writes: 0 });
        },
        readAccepted: async () => { reads += 1; },
      });
      return Object.freeze(receiver);
    },
  });
  assert.equal(calls, 1);
  assert.equal(reads, 0);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.selfTest), true);
});

test('reader and self-test shapes must be frozen exact data objects', async () => {
  const proxy = new Proxy(Object.freeze({
    selfTest: async () => Object.freeze({ role: 'daemon', contractVersion: 4, writes: 0 }),
    readAccepted() {},
  }), {
    ownKeys() { throw new Error('proxy trap'); },
  });
  const readers = [
    { selfTest: async () => ({}), readAccepted() {} },
    Object.freeze({ selfTest: async () => ({ role: 'daemon', contractVersion: 4, writes: 0 }), readAccepted() {} }),
    Object.freeze({ get selfTest() { return async () => ({}); }, readAccepted() {} }),
    Object.freeze({ selfTest: async () => Object.freeze({ role: 'daemon', contractVersion: 3, writes: 0 }), readAccepted() {} }),
    proxy,
  ];
  for (const candidate of readers) {
    await assert.rejects(initializeInventoryConfig({ env: verifyEnv(), platform: 'linux' }, {
      createInventoryReader: async () => candidate,
    }), /Inventory configuration is invalid/);
  }
});

test('factory and self-test failures propagate without fallback', async () => {
  const factoryFailure = new Error('factory sentinel');
  await assert.rejects(initializeInventoryConfig({ env: verifyEnv(), platform: 'linux' }, {
    createInventoryReader: async () => { throw factoryFailure; },
  }), (error) => error === factoryFailure);
  const selfTestFailure = new Error('self test sentinel');
  await assert.rejects(initializeInventoryConfig({ env: verifyEnv(), platform: 'linux' }, {
    createInventoryReader: async () => Object.freeze({
      selfTest: async () => { throw selfTestFailure; }, readAccepted() {},
    }),
  }), (error) => error === selfTestFailure);
  assert.equal(await initializeInventoryConfig({
    env: verifyEnv(), platform: 'linux',
  }, {
    createInventoryReader: async () => { throw 'primitive factory failure'; },
  }).catch((error) => error), 'primitive factory failure');
  assert.equal(await initializeInventoryConfig({
    env: verifyEnv(), platform: 'linux',
  }, {
    createInventoryReader: async () => Object.freeze({
      selfTest: async () => { throw 17; }, readAccepted() {},
    }),
  }).catch((error) => error), 17);
});

test('hostile environment access fails with a bounded config error', async () => {
  const env = new Proxy({}, {
    get() { throw new Error('HOST_ROLE_PATH_SECRET'); },
  });
  await assert.rejects(
    initializeInventoryConfig({ env, platform: 'linux' }),
    (error) => error.code === 'CONFIG_INVALID' &&
      error.operation === 'initialize_inventory_config' &&
      error.writes === 0 && error.ambiguous === false &&
      error.message.includes('HOST_ROLE_PATH_SECRET') === false,
  );
});

test('diagnostics are frozen and do not disclose secrets', () => {
  const secret = 'UID_SID_PATH_BYTES_SECRET';
  const cases = [
    new Error(secret),
    { code: 'CONFIG_INVALID', operation: 'initialize_inventory_config', message: secret },
    { code: 'ERR_NATIVE_CONTROL_REFUSED', operation: 'load_native_control', writes: 0, reason: secret },
    { code: 'INVENTORY_ACCESS_DENIED', operation: 'verify_inventory_acl', writes: 0, ambiguous: false, roles: secret },
  ];
  for (const error of cases) {
    const diagnostic = inventoryConfigDiagnostic(error);
    assert.equal(Object.isFrozen(diagnostic), true);
    assert.deepEqual(Object.keys(diagnostic), ['code', 'operation', 'writes', 'ambiguous']);
    assert.equal(JSON.stringify(diagnostic).includes(secret), false);
  }
  assert.deepEqual(inventoryConfigDiagnostic({ code: 'unknown', operation: secret }), {
    code: 'INVENTORY_IO_FAILED', operation: 'initialize_inventory_config', writes: 0, ambiguous: true,
  });
  assert.deepEqual(inventoryConfigDiagnostic({
    code: 'CONFIG_INVALID', operation: 'initialize_inventory_config',
    writes: 1, ambiguous: false,
  }), {
    code: 'INVENTORY_IO_FAILED', operation: 'initialize_inventory_config', writes: 0, ambiguous: true,
  });
  assert.deepEqual(inventoryConfigDiagnostic(new Proxy({}, {
    get() { throw new Error(secret); },
  })), {
    code: 'INVENTORY_IO_FAILED', operation: 'initialize_inventory_config', writes: 0, ambiguous: true,
  });
});
