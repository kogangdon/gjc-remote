import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { validateServiceRoles } from '@gjc-remote/shared/service-lifecycle-envelope';
import {
  capabilities,
  capabilitySignatures,
  contractRevision,
  serviceCapabilities,
} from '../src/capabilities.js';
import {
  validateBuildManifestMetadata,
  validateNativeAddonContract,
  validateNativePackageContract,
} from '../src/native-provenance.js';
import { createSelfProcessObserverFactory, createServiceNativeFactory } from '../src/service-native.js';
import * as publicApi from '../src/public.js';

const ROLE_KEYS = ['management', 'bot', 'recovery', 'daemon', 'system'];
const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('public self observation rejects caller authority before loading native code', () => {
  assert.equal(typeof publicApi.createSelfProcessObserver, 'function');
  assert.equal(publicApi.createSelfProcessObserver.length, 0);
  assert.equal(Object.hasOwn(publicApi, 'observeSelfProcessEpoch'), false);
  assert.equal(Object.hasOwn(publicApi, 'createSelfProcessObserverFactory'), false);
  assert.equal(Object.hasOwn(publicApi, 'createServiceBootstrapNative'), false);
  assert.equal(Object.hasOwn(publicApi, 'readSelfServiceConfig'), false);
  let accessed = false;
  const suppliedAuthority = new Proxy({}, {
    get() { accessed = true; throw new Error('must not inspect supplied authority'); },
    ownKeys() { accessed = true; throw new Error('must not inspect supplied authority'); },
  });
  for (const value of [undefined, null, 123, 'C:/another/process.exe', suppliedAuthority]) {
    assertServiceInvalid(() => publicApi.createSelfProcessObserver(value), 'create_self_process_observer');
  }
  assert.equal(accessed, false);
});

test('source ABI accepts only native contract v5 revision 1 and N-API 8', () => {
  assert.equal(packageJson.version, '2.0.0');
  assert.equal(contractRevision, 1);
  assert.deepEqual(publicApi.buildManifest, {
    contractVersion: 5,
    contractRevision: 1,
    napi: 8,
    capabilities,
    capabilitySignatures,
  });
  assert.deepEqual(packageJson.nativeControlContract, {
    version: 5,
    revision: 1,
    napi: 8,
    platforms: ['linux-x64', 'linux-arm64', 'win32-x64'],
  });
  assert.equal(validateNativePackageContract(packageJson), true);
  for (const [version, revision, napi] of [[4, 4, 8], [5, 4, 8], [5, 1, 7]]) {
    const incompatible = structuredClone(packageJson);
    incompatible.nativeControlContract = {
      ...incompatible.nativeControlContract,
      version,
      revision,
      napi,
    };
    assert.equal(validateNativePackageContract(incompatible), false);
  }
  const staleSourceVersion = structuredClone(packageJson);
  staleSourceVersion.version = '1.0.0';
  assert.equal(validateNativePackageContract(staleSourceVersion), false);

  const addonContract = {
    contractVersion: 5,
    contractRevision: 1,
    napi: 8,
    capabilities,
    capabilitySignatures,
  };
  assert.equal(validateNativeAddonContract(addonContract), true);
  assert.equal(validateNativeAddonContract({ ...addonContract, contractVersion: 4 }), false);
  assert.equal(validateNativeAddonContract({ ...addonContract, contractRevision: 4 }), false);
  const manifest = {
    contractVersion: 5,
    contractRevision: 1,
    package: packageJson.name,
    version: packageJson.version,
    napi: 8,
    platform: 'linux',
    arch: 'x64',
    addon: 'native_control.node',
    sha256: 'a'.repeat(64),
    capabilities,
    capabilitySignatures,
  };
  assert.equal(validateBuildManifestMetadata(manifest, packageJson, 'linux', 'x64'), true);
  assert.equal(validateBuildManifestMetadata({ ...manifest, contractVersion: 4 }, packageJson, 'linux', 'x64'), false);
  assert.equal(validateBuildManifestMetadata({ ...manifest, contractRevision: 4 }, packageJson, 'linux', 'x64'), false);
  assert.equal(validateBuildManifestMetadata(manifest, staleSourceVersion, 'linux', 'x64'), false);
});

test('self observer captures only its read-only method and preserves native receipts and errors', () => {
  let loads = 0;
  let calls = 0;
  let failure;
  const receipt = Object.freeze({ processEpochFingerprint: 'a'.repeat(64), writes: 0 });
  const backend = {
    observeSelfProcessEpoch() { calls += 1; if (failure) throw failure; return receipt; },
    get readSelfServiceConfig() { assert.fail('self observer must not capture config access'); },
    get createServiceNative() { assert.fail('self observer must not capture management access'); },
  };
  const create = createSelfProcessObserverFactory(() => { loads += 1; return backend; });
  assertServiceInvalid(() => create(undefined), 'create_self_process_observer');
  assert.equal(loads, 0);
  const observer = create();
  assert.equal(loads, 1);
  assert.equal(Object.isFrozen(observer), true);
  assert.deepEqual(Reflect.ownKeys(observer), ['observeSelfProcessEpoch']);
  assert.equal(observer.observeSelfProcessEpoch.length, 0);
  assertServiceInvalid(() => observer.observeSelfProcessEpoch(123), 'observe_self_process_epoch');
  assert.equal(calls, 0);
  backend.observeSelfProcessEpoch = () => assert.fail('must retain the verified function');
  assert.equal(observer.observeSelfProcessEpoch(), receipt);
  failure = Object.assign(new Error('native refusal'), { code: 'SERVICE_STALE', writes: 0 });
  assert.throws(() => observer.observeSelfProcessEpoch(), (error) => error === failure);
  assert.equal(calls, 2);
  assert.equal(loads, 1);
});

test('self observer refuses missing and accessor-backed methods without evaluating them', () => {
  let accessed = false;
  for (const backend of [null, {}, { observeSelfProcessEpoch: 1 }, {
    get observeSelfProcessEpoch() { accessed = true; return () => ({}); },
  }]) {
    assertServiceInvalid(
      () => createSelfProcessObserverFactory(() => backend)(),
      'create_self_process_observer',
    );
  }
  assert.equal(accessed, false);
});

function validRoles() {
  if (process.platform === 'win32') {
    return {
      management: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1001' },
      bot: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1002' },
      recovery: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1003' },
      daemon: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1004' },
      system: { kind: 'sid', value: 'S-1-5-18' },
    };
  }
  return {
    management: { kind: 'uid', value: 'uid:1001' },
    bot: { kind: 'uid', value: 'uid:1002' },
    recovery: { kind: 'uid', value: 'uid:1003' },
    daemon: { kind: 'uid', value: 'uid:1004' },
    system: { kind: 'uid', value: 'uid:0' },
  };
}

function cloneRoles(roles = validRoles()) {
  return Object.fromEntries(ROLE_KEYS.map((role) => [role, { ...roles[role] }]));
}

function fakeAddon(overrides = {}) {
  const calls = [];
  const addon = {};
  for (const name of serviceCapabilities) {
    addon[name] = (...args) => {
      const result = Object.freeze({ capability: name, sequence: calls.length });
      calls.push({ name, args, result });
      return result;
    };
  }
  Object.assign(addon, {
    open_verified_parent: () => 'management authority',
    publish_inventory_object_atomic: () => 'inventory authority',
    enumerate_workspace_process_holders: () => 'serving authority',
    native_control_contract: () => 'raw addon contract',
  }, overrides);
  return { addon, calls };
}

function publicArguments(name) {
  return capabilitySignatures[name]
    .filter((parameter) => parameter !== 'roles')
    .map((parameter, index) => ({ capability: name, parameter, index }));
}

function assertServiceInvalid(invoke, operation = 'create_service_native') {
  assert.throws(invoke, (error) => {
    assert.equal(error.code, 'SERVICE_INVALID');
    assert.equal(error.operation, operation);
    assert.equal(error.writes, 0);
    assert.equal(error.ambiguous, false);
    return true;
  });
}

function assertFactoryRefusal(invoke, capability) {
  assert.throws(invoke, (error) => {
    assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
    assert.equal(error.operation, 'create_service_native');
    assert.equal(error.reason, `verified addon is missing native capability: ${capability}`);
    assert.equal(error.writes, 0);
    return true;
  });
}

test('public factory exposes no loader, path, trust, platform, or root override', () => {
  assert.equal(typeof publicApi.createServiceNative, 'function');
  assert.equal(publicApi.createServiceNative.length, 1);
  assert.equal('createServiceNativeFactory' in publicApi, false);
  assert.equal('serviceCapabilities' in publicApi, false);

  const roles = validRoles();
  for (const [key, value] of [
    ['loadAddon', () => ({})],
    ['addonPath', 'unverified.node'],
    ['manifestPath', 'unverified.json'],
    ['sidecarPath', 'unverified.sig'],
    ['trustedKeysPath', 'caller-trust.json'],
    ['devKeysPath', 'caller-dev-trust.json'],
    ['warn', () => {}],
    ['platform', process.platform],
    ['root', 'caller-root'],
  ]) {
    assertServiceInvalid(() => publicApi.createServiceNative({ roles, [key]: value }));
  }
  assertServiceInvalid(() => publicApi.createServiceNative({ roles }, () => ({})));
});

test('validates an exact five-role platform tuple before invoking the loader', () => {
  let getterCalls = 0;
  const accessorRoles = cloneRoles();
  Object.defineProperty(accessorRoles, 'management', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return validRoles().management;
    },
  });
  const accessorOptions = {};
  Object.defineProperty(accessorOptions, 'roles', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return validRoles();
    },
  });

  const missingRole = cloneRoles();
  delete missingRole.daemon;
  const extraRole = { ...cloneRoles(), operator: cloneRoles().management };
  const duplicateRole = cloneRoles();
  duplicateRole.bot.value = duplicateRole.management.value;
  const wrongSystem = cloneRoles();
  wrongSystem.system.value = process.platform === 'win32'
    ? 'S-1-5-21-111111111-222222222-333333333-1005'
    : 'uid:1005';
  const wrongKind = Object.fromEntries(ROLE_KEYS.map((role, index) => [role,
    process.platform === 'win32'
      ? { kind: 'uid', value: `uid:${index}` }
      : { kind: 'sid', value: role === 'system' ? 'S-1-5-18' : `S-1-5-21-1-2-3-${index + 1}` },
  ]));
  const principalExtra = cloneRoles();
  principalExtra.bot.extra = true;
  const principalPrototype = cloneRoles();
  principalPrototype.bot = Object.assign(Object.create(null), principalPrototype.bot);
  const symbolRole = cloneRoles();
  symbolRole[Symbol('authority')] = true;
  const nonCanonical = cloneRoles();
  nonCanonical.management.value = process.platform === 'win32' ? 'S-1-05-21-1' : 'uid:01';
  const canonicalPolicyFailures = [
    duplicateRole,
    wrongSystem,
    wrongKind,
    nonCanonical,
  ];
  for (const roles of canonicalPolicyFailures) {
    assert.throws(
      () => validateServiceRoles(roles, process.platform),
      /SERVICE_LIFECYCLE_ENVELOPE_INVALID/,
    );
  }

  const invalidInputs = [
    undefined,
    null,
    {},
    { roles: validRoles(), extra: true },
    Object.assign(Object.create(null), { roles: validRoles() }),
    accessorOptions,
    { roles: missingRole },
    { roles: extraRole },
    { roles: Object.assign(Object.create(null), validRoles()) },
    { roles: accessorRoles },
    { roles: duplicateRole },
    { roles: wrongSystem },
    { roles: wrongKind },
    { roles: principalExtra },
    { roles: principalPrototype },
    { roles: symbolRole },
    { roles: nonCanonical },
  ];

  for (const options of invalidInputs) {
    let loads = 0;
    const createServiceNative = createServiceNativeFactory(() => {
      loads += 1;
      return fakeAddon().addon;
    });
    assertServiceInvalid(() => createServiceNative(options));
    assert.equal(loads, 0);
  }
  assert.equal(getterCalls, 0, 'accessor-backed authority input must not be evaluated');

  let loads = 0;
  const createServiceNative = createServiceNativeFactory(() => {
    loads += 1;
    return fakeAddon().addon;
  });
  assertServiceInvalid(() => createServiceNative());
  assertServiceInvalid(() => createServiceNative({ roles: validRoles() }, undefined));
  assert.equal(loads, 0);
});

test('applies the native Win32 SID bounds after canonical shared role validation', () => {
  if (process.platform !== 'win32') {
    const roles = validRoles();
    assert.equal(validateServiceRoles(roles, process.platform), roles);
    return;
  }
  const roles = validRoles();
  roles.management.value = 'S-1-281474976710656-21-1';
  assert.equal(validateServiceRoles(roles, process.platform), roles,
    'the canonical policy deliberately does not duplicate native SID representation bounds');

  let loads = 0;
  const createServiceNative = createServiceNativeFactory(() => {
    loads += 1;
    return fakeAddon().addon;
  });
  assertServiceInvalid(() => createServiceNative({ roles }));
  assert.equal(loads, 0);
});

test('projects exactly the declared frozen service-capability surface', () => {
  const { addon } = fakeAddon();
  const loaderArguments = [];
  const createServiceNative = createServiceNativeFactory((...args) => {
    loaderArguments.push(args);
    return addon;
  });
  const facade = createServiceNative({ roles: validRoles() });

  assert.deepEqual(Object.keys(facade), serviceCapabilities);
  assert.deepEqual(Reflect.ownKeys(facade), serviceCapabilities);
  assert.equal(Object.isFrozen(facade), true);
  assert.deepEqual(loaderArguments, [[]]);
  for (const name of serviceCapabilities) assert.equal(typeof facade[name], 'function');
  for (const withheld of [
    'open_verified_parent',
    'publish_inventory_object_atomic',
    'enumerate_workspace_process_holders',
    'native_control_contract',
    'addon',
    'dispatch',
    'invoke',
  ]) assert.equal(facade[withheld], undefined, withheld);
  assert.throws(() => {
    facade.open_verified_parent = () => 'injected';
  }, TypeError);
});

test('all signatures remove only roles and inject the immutable snapshot at its exact native position', () => {
  const inputRoles = validRoles();
  const expectedRoles = structuredClone(inputRoles);
  const { addon, calls } = fakeAddon();
  const facade = createServiceNativeFactory(() => addon)({ roles: inputRoles });
  const roleCalls = [];
  const roleCapabilities = serviceCapabilities
    .filter((name) => capabilitySignatures[name].includes('roles'));
  assert.ok(roleCapabilities.length > 0);

  for (const name of serviceCapabilities) {
    const signature = capabilitySignatures[name];
    const args = publicArguments(name);
    assert.equal(facade[name].length, args.length, `${name} reflected arity`);
    assert.equal(facade[name].name, name, `${name} reflected name`);
    const result = facade[name](...args);
    const call = calls.at(-1);
    assert.equal(result, call.result, `${name} result identity`);
    assert.equal(call.name, name);
    assert.equal(call.args.length, signature.length, `${name} native arity`);
    let publicIndex = 0;
    for (let nativeIndex = 0; nativeIndex < signature.length; nativeIndex += 1) {
      if (signature[nativeIndex] === 'roles') {
        roleCalls.push(call.args[nativeIndex]);
      } else {
        assert.equal(call.args[nativeIndex], args[publicIndex],
          `${name} argument ${signature[nativeIndex]} identity`);
        publicIndex += 1;
      }
    }
  }

  assert.equal(roleCalls.length, roleCapabilities.length);
  assert.ok(roleCalls.every((roles) => roles === roleCalls[0]));
  assert.notEqual(roleCalls[0], inputRoles);
  assert.deepEqual(roleCalls[0], expectedRoles);
  assert.equal(Object.isFrozen(roleCalls[0]), true);
  for (const role of ROLE_KEYS) {
    assert.notEqual(roleCalls[0][role], inputRoles[role]);
    assert.equal(Object.isFrozen(roleCalls[0][role]), true);
  }
  assert.equal(facade.plan_win32_service_resource.length, 5);
  assert.deepEqual(capabilitySignatures.plan_win32_service_resource, [
    'name', 'serviceRole', 'launch', 'applicationManifestFingerprint', 'phase', 'roles',
  ]);
  assert.equal(facade.create_win32_service_disabled.length, 4);
  assert.deepEqual(capabilitySignatures.create_win32_service_disabled, [
    'name', 'serviceRole', 'launch', 'servicePassword', 'roles',
  ]);
  assert.equal(facade.configure_win32_service_launch.length, 4);
  assert.deepEqual(capabilitySignatures.configure_win32_service_launch, [
    'serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint', 'launch',
  ]);

  const callerRoles = validRoles();
  facade.open_win32_service('GJCRemoteBot', 'bot', callerRoles);
  const substitution = calls.at(-1).args;
  assert.notEqual(substitution[2], callerRoles);
  assert.equal(substitution[2], roleCalls[0]);
  assert.equal(substitution[3], callerRoles,
    'a roles-shaped public value remains in the access slot and cannot replace captured authority');
});

test('caller mutation cannot change captured role authority', () => {
  const roles = validRoles();
  const expected = structuredClone(roles);
  const { addon, calls } = fakeAddon();
  const facade = createServiceNativeFactory(() => addon)({ roles });

  roles.management.value = roles.bot.value;
  roles.bot = roles.system;
  roles.daemon.kind = process.platform === 'win32' ? 'uid' : 'sid';
  delete roles.recovery;

  facade.open_service_root('service-state', 'read-existing');
  const captured = calls.at(-1).args[1];
  assert.deepEqual(captured, expected);
  assert.equal(Object.isFrozen(captured), true);
  assert.throws(() => {
    captured.management.value = captured.bot.value;
  }, TypeError);
  assert.deepEqual(captured, expected);
});

test('every method rejects missing and extra positional arguments before native invocation', () => {
  const { addon, calls } = fakeAddon();
  const facade = createServiceNativeFactory(() => addon)({ roles: validRoles() });

  for (const name of serviceCapabilities) {
    const args = publicArguments(name);
    const before = calls.length;
    if (args.length > 0) {
      assertServiceInvalid(() => facade[name](...args.slice(0, -1)), name);
      assert.equal(calls.length, before, `${name} missing argument must not invoke native code`);
    }
    assertServiceInvalid(() => facade[name](...args, { callerAuthority: true }), name);
    assert.equal(calls.length, before, `${name} extra argument must not invoke native code`);
  }
});

test('fails closed for every missing capability and for non-functions without evaluating accessors', () => {
  for (const missing of serviceCapabilities) {
    const { addon } = fakeAddon();
    delete addon[missing];
    assertFactoryRefusal(
      () => createServiceNativeFactory(() => addon)({ roles: validRoles() }),
      missing,
    );
  }

  const nonFunction = fakeAddon().addon;
  nonFunction.query_win32_service = Object.freeze({ callable: false });
  assertFactoryRefusal(
    () => createServiceNativeFactory(() => nonFunction)({ roles: validRoles() }),
    'query_win32_service',
  );

  let getterCalls = 0;
  const accessor = fakeAddon().addon;
  Object.defineProperty(accessor, 'read_boot_id', {
    enumerable: true,
    configurable: true,
    get() {
      getterCalls += 1;
      return () => 'untrusted getter';
    },
  });
  assertFactoryRefusal(
    () => createServiceNativeFactory(() => accessor)({ roles: validRoles() }),
    'read_boot_id',
  );
  assert.equal(getterCalls, 0);
});

test('captures native function references once', () => {
  const { addon } = fakeAddon();
  let originalCalls = 0;
  let replacementCalls = 0;
  addon.read_boot_id = () => {
    originalCalls += 1;
    return 'original';
  };
  const facade = createServiceNativeFactory(() => addon)({ roles: validRoles() });
  addon.read_boot_id = () => {
    replacementCalls += 1;
    return 'replacement';
  };

  assert.equal(facade.read_boot_id(), 'original');
  assert.equal(originalCalls, 1);
  assert.equal(replacementCalls, 0);
});

test('preserves opaque handles, bytes, receipts, native errors, and write accounting by identity', () => {
  const rootHandle = { opaque: Symbol('root') };
  const lockHandle = { opaque: Symbol('lock') };
  const expectedIdentity = { device: '7', inode: '9' };
  const bytes = Buffer.from('native bytes');
  const readBytes = Buffer.from('native read result');
  const receipt = Object.freeze({ writes: 5, identity: expectedIdentity });
  const nativeError = new Error('native publication reconciliation required');
  nativeError.code = 'SERVICE_MANUAL_CLEANUP';
  nativeError.operation = 'remove_service_object_exact';
  nativeError.writes = 7;
  nativeError.ambiguous = true;
  const observed = {};
  const { addon } = fakeAddon({
    open_service_root: (rootKind, roles, access) => {
      observed.root = { rootKind, roles, access };
      return rootHandle;
    },
    close_service_handle: (handle) => {
      observed.closed = handle;
      return undefined;
    },
    publish_service_file_atomic: (...args) => {
      observed.publish = args;
      return receipt;
    },
    read_service_file: (...args) => {
      observed.read = args;
      return readBytes;
    },
    remove_service_object_exact: () => {
      throw nativeError;
    },
  });
  const facade = createServiceNativeFactory(() => addon)({ roles: validRoles() });

  const opened = facade.open_service_root('service-state', 'read-existing');
  assert.equal(opened, rootHandle);
  assert.equal(observed.root.roles.management.value, validRoles().management.value);
  assert.equal(facade.close_service_handle(opened), undefined);
  assert.equal(observed.closed, rootHandle);

  const published = facade.publish_service_file_atomic(
    rootHandle, 'state.json', bytes, expectedIdentity, lockHandle,
  );
  assert.equal(published, receipt);
  assert.equal(observed.publish[0], rootHandle);
  assert.equal(observed.publish[2], bytes);
  assert.equal(observed.publish[3], expectedIdentity);
  assert.equal(observed.publish[4], lockHandle);
  assert.equal(facade.read_service_file(rootHandle, 'state.json', 4096), readBytes);
  assert.equal(observed.read[0], rootHandle);

  let caught;
  try {
    facade.remove_service_object_exact(rootHandle, 'state.json', expectedIdentity, lockHandle);
  } catch (error) {
    caught = error;
  }
  assert.equal(caught, nativeError);
  assert.equal(caught.writes, 7);
  assert.equal(caught.ambiguous, true);
});
