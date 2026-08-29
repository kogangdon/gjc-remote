import test from 'node:test';
import assert from 'node:assert/strict';

import { createResidualProcessEnumerator } from '../src/index.js';
import * as publicApi from '../src/public.js';

// A fake fully-verified addon exposing far more than the residual-process
// surface, used to prove createResidualProcessEnumerator withholds everything
// except the single read-only enumeration capability and passes arguments
// through positionally.
function fakeAddon(overrides = {}) {
  const calls = [];
  const record = (name, ret) => (...args) => {
    calls.push({ name, args });
    return ret === undefined ? { name, args } : ret;
  };
  const addon = {
    enumerate_workspace_process_holders: record('enumerate_workspace_process_holders', [{ pid: 4321 }]),
    // Capabilities that MUST NOT be reachable through the enumerator surface.
    remove_verified_file: record('remove_verified_file'),
    publish_inventory_object_atomic: record('publish_inventory_object_atomic'),
    read_workspace_root_facts: record('read_workspace_root_facts'),
    ...overrides,
  };
  return { addon, calls };
}

test('public API re-exports createResidualProcessEnumerator', () => {
  assert.equal(publicApi.createResidualProcessEnumerator, createResidualProcessEnumerator);
});

test('projects exactly the enumerate capability and nothing else', () => {
  const { addon } = fakeAddon();
  const enumerator = createResidualProcessEnumerator({ loadAddon: () => addon });
  assert.deepEqual(Object.keys(enumerator), ['enumerate_workspace_process_holders']);
  assert.equal(enumerator.remove_verified_file, undefined);
  assert.equal(enumerator.publish_inventory_object_atomic, undefined);
  assert.equal(enumerator.read_workspace_root_facts, undefined);
});

test('surface is frozen and cannot be widened after construction', () => {
  const { addon } = fakeAddon();
  const enumerator = createResidualProcessEnumerator({ loadAddon: () => addon });
  assert.equal(Object.isFrozen(enumerator), true);
  assert.throws(() => {
    'use strict';
    enumerator.remove_verified_file = () => 'injected';
  }, TypeError);
});

test('enumerate_workspace_process_holders passes (workDir, sourcePlatform) through positionally and returns the holder set', () => {
  const { addon, calls } = fakeAddon();
  const enumerator = createResidualProcessEnumerator({ loadAddon: () => addon });
  const result = enumerator.enumerate_workspace_process_holders('/srv/ws', 'posix');
  assert.deepEqual(result, [{ pid: 4321 }]);
  assert.deepEqual(calls.at(-1), { name: 'enumerate_workspace_process_holders', args: ['/srv/ws', 'posix'] });
});

test('native throws propagate unwrapped through the projection', () => {
  const boom = () => {
    const error = new Error('residual scan failed');
    error.code = 'ERR_NATIVE_CONTROL_REFUSED';
    throw error;
  };
  const { addon } = fakeAddon({ enumerate_workspace_process_holders: boom });
  const enumerator = createResidualProcessEnumerator({ loadAddon: () => addon });
  assert.throws(() => enumerator.enumerate_workspace_process_holders('/srv/ws', 'posix'), {
    code: 'ERR_NATIVE_CONTROL_REFUSED',
    message: 'residual scan failed',
  });
});

test('fails closed when the verified addon is missing the enumerate capability', () => {
  const { addon } = fakeAddon();
  delete addon.enumerate_workspace_process_holders;
  assert.throws(() => createResidualProcessEnumerator({ loadAddon: () => addon }), {
    code: 'ERR_NATIVE_CONTROL_REFUSED',
    operation: 'create_residual_process_enumerator',
    reason: 'verified addon is missing native capability: enumerate_workspace_process_holders',
  });
});

test('fails closed when the enumerate capability is present but not a function', () => {
  const { addon } = fakeAddon({ enumerate_workspace_process_holders: true });
  assert.throws(() => createResidualProcessEnumerator({ loadAddon: () => addon }), {
    code: 'ERR_NATIVE_CONTROL_REFUSED',
    operation: 'create_residual_process_enumerator',
  });
});
