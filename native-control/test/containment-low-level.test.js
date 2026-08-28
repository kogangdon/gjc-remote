import test from 'node:test';
import assert from 'node:assert/strict';

import { createContainmentLowLevel } from '../src/index.js';
import * as publicApi from '../src/public.js';

// A fake fully-verified addon exposing far more than the containment surface,
// used to prove createContainmentLowLevel withholds everything except the three
// read-only identity capabilities and passes arguments through positionally.
function fakeAddon(overrides = {}) {
  const calls = [];
  const record = (name) => (...args) => {
    calls.push({ name, args });
    return { name, args };
  };
  const addon = {
    read_workspace_root_facts: record('read_workspace_root_facts'),
    read_identity: record('read_identity'),
    path_exists_no_follow: record('path_exists_no_follow'),
    // Capabilities that MUST NOT be reachable through the containment surface.
    remove_verified_file: record('remove_verified_file'),
    publish_inventory_object_atomic: record('publish_inventory_object_atomic'),
    set_exact_role_acl: record('set_exact_role_acl'),
    ...overrides,
  };
  return { addon, calls };
}

test('public API re-exports createContainmentLowLevel', () => {
  assert.equal(publicApi.createContainmentLowLevel, createContainmentLowLevel);
});

test('projects exactly the three containment capabilities and nothing else', () => {
  const { addon } = fakeAddon();
  const lowLevel = createContainmentLowLevel({ loadAddon: () => addon });
  assert.deepEqual(
    Object.keys(lowLevel).sort(),
    ['path_exists_no_follow', 'read_identity', 'read_workspace_root_facts'],
  );
  // No management/inventory mutation capability leaks through.
  assert.equal(lowLevel.remove_verified_file, undefined);
  assert.equal(lowLevel.publish_inventory_object_atomic, undefined);
  assert.equal(lowLevel.set_exact_role_acl, undefined);
});

test('surface is frozen and cannot be widened after construction', () => {
  const { addon } = fakeAddon();
  const lowLevel = createContainmentLowLevel({ loadAddon: () => addon });
  assert.equal(Object.isFrozen(lowLevel), true);
  assert.throws(() => {
    'use strict';
    lowLevel.remove_verified_file = () => 'injected';
  }, TypeError);
});

test('read_workspace_root_facts passes (path, sourcePlatform) through positionally', () => {
  const { addon, calls } = fakeAddon();
  const lowLevel = createContainmentLowLevel({ loadAddon: () => addon });
  const result = lowLevel.read_workspace_root_facts('/srv/ws', 'posix');
  assert.deepEqual(result, { name: 'read_workspace_root_facts', args: ['/srv/ws', 'posix'] });
  assert.deepEqual(calls.at(-1), { name: 'read_workspace_root_facts', args: ['/srv/ws', 'posix'] });
});

test('read_identity passes (path) through positionally', () => {
  const { addon, calls } = fakeAddon();
  const lowLevel = createContainmentLowLevel({ loadAddon: () => addon });
  const result = lowLevel.read_identity('/srv/ws/leaf');
  assert.deepEqual(result, { name: 'read_identity', args: ['/srv/ws/leaf'] });
  assert.deepEqual(calls.at(-1), { name: 'read_identity', args: ['/srv/ws/leaf'] });
});

test('path_exists_no_follow passes (path) through positionally', () => {
  const { addon, calls } = fakeAddon();
  const lowLevel = createContainmentLowLevel({ loadAddon: () => addon });
  const result = lowLevel.path_exists_no_follow('/srv/ws/leaf');
  assert.deepEqual(result, { name: 'path_exists_no_follow', args: ['/srv/ws/leaf'] });
  assert.deepEqual(calls.at(-1), { name: 'path_exists_no_follow', args: ['/srv/ws/leaf'] });
});

test('native throws propagate unwrapped through the projection', () => {
  const boom = () => {
    const error = new Error('reparse point encountered');
    error.code = 'ERR_NATIVE_CONTROL_REFUSED';
    throw error;
  };
  const { addon } = fakeAddon({ read_identity: boom });
  const lowLevel = createContainmentLowLevel({ loadAddon: () => addon });
  assert.throws(() => lowLevel.read_identity('/srv/ws/junction'), {
    code: 'ERR_NATIVE_CONTROL_REFUSED',
    message: 'reparse point encountered',
  });
});

test('fails closed when the verified addon is missing a containment capability', () => {
  for (const missing of ['read_workspace_root_facts', 'read_identity', 'path_exists_no_follow']) {
    const { addon } = fakeAddon();
    delete addon[missing];
    assert.throws(() => createContainmentLowLevel({ loadAddon: () => addon }), {
      code: 'ERR_NATIVE_CONTROL_REFUSED',
      operation: 'create_containment_low_level',
      reason: `verified addon is missing native capability: ${missing}`,
    });
  }
});

test('fails closed when a required capability is present but not a function', () => {
  const { addon } = fakeAddon({ path_exists_no_follow: true });
  assert.throws(() => createContainmentLowLevel({ loadAddon: () => addon }), {
    code: 'ERR_NATIVE_CONTROL_REFUSED',
    operation: 'create_containment_low_level',
  });
});
