import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { capabilitySignatures, serviceCapabilities } from '../src/capabilities.js';
import { createServiceNativeFactory } from '../src/service-native.js';

const require = createRequire(import.meta.url);
const addonPath = fileURLToPath(new URL('../build/Release/native_control.node', import.meta.url));
const addonSourcePath = fileURLToPath(new URL('../src/addon.cc', import.meta.url));
const source = readFileSync(addonSourcePath, 'utf8');

const observationSignatures = {
  plan_service_artifact_location: ['rootKind', 'artifactFingerprint', 'relativePath', 'roles'],
  resolve_service_artifact_location: ['directoryHandle', 'relativePath', 'expectedFileSha256'],
  open_service_external_root: ['absolutePath', 'profile', 'roles'],
  read_service_external_object: ['externalRootHandle', 'relativePath', 'mode', 'maxBytes'],
};

function nativeBlock(name) {
  const start = source.indexOf(`napi_value ${name}(`);
  assert.notEqual(start, -1, `${name} implementation exists`);
  const end = source.indexOf('\nnapi_value ', start + 1);
  return source.slice(start, end === -1 ? source.length : end);
}

function testRoles() {
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

function facadeFixture() {
  const calls = new Map();
  const addon = Object.fromEntries(serviceCapabilities.map((name) => [
    name,
    (...args) => {
      calls.set(name, args);
      return Object.freeze({ name });
    },
  ]));
  const roles = testRoles();
  return {
    calls,
    roles,
    facade: createServiceNativeFactory(() => addon)({ roles }),
  };
}

test('observation capabilities expose closed positional signatures through the role-bound facade', () => {
  assert.deepEqual(
    Object.fromEntries(Object.keys(observationSignatures).map((name) => [
      name,
      capabilitySignatures[name],
    ])),
    observationSignatures,
  );
  assert.deepEqual(
    serviceCapabilities.filter((name) => Object.hasOwn(observationSignatures, name)),
    Object.keys(observationSignatures),
  );

  const { calls, roles, facade } = facadeFixture();
  const directoryHandle = Object.freeze({ nativeHandle: 'directory' });
  const externalRootHandle = Object.freeze({ nativeHandle: 'external-root' });
  facade.plan_service_artifact_location('releases', 'a'.repeat(64), 'bin/worker.exe');
  facade.resolve_service_artifact_location(directoryHandle, 'bin/worker.exe', 'b'.repeat(64));
  facade.open_service_external_root('C:\\scope\\config', 'config');
  facade.read_service_external_object(externalRootHandle, 'daemon.env', 'bytes', 262144);
  const projectedRoles = calls.get('plan_service_artifact_location')[3];

  assert.deepEqual(calls.get('plan_service_artifact_location'), [
    'releases', 'a'.repeat(64), 'bin/worker.exe', projectedRoles,
  ]);
  assert.deepEqual(calls.get('resolve_service_artifact_location'), [
    directoryHandle, 'bin/worker.exe', 'b'.repeat(64),
  ]);
  assert.deepEqual(calls.get('open_service_external_root'), [
    'C:\\scope\\config', 'config', projectedRoles,
  ]);
  assert.deepEqual(calls.get('read_service_external_object'), [
    externalRootHandle, 'daemon.env', 'bytes', 262144,
  ]);
  assert.deepEqual(projectedRoles, roles);
  assert.notEqual(projectedRoles, roles);
  assert.equal(calls.get('open_service_external_root')[2], projectedRoles);
  assert.equal(facade.plan_service_artifact_location.length, 3);
  assert.equal(facade.resolve_service_artifact_location.length, 3);
  assert.equal(facade.open_service_external_root.length, 2);
  assert.equal(facade.read_service_external_object.length, 4);
});

test('native source binds identities, absence, role ACL profiles, and bounded read modes', () => {
  const plan = nativeBlock('PlanServiceArtifactLocation');
  const resolve = nativeBlock('ResolveServiceArtifactLocation');
  const openRoot = nativeBlock('OpenServiceExternalRoot');
  const readObject = nativeBlock('ReadServiceExternalObject');
  const externalProfileParser = source.slice(
    source.indexOf('bool ParseServiceExternalProfile('),
    source.indexOf('ServiceAclProfile ServiceExternalDirectoryProfile('),
  );
  const ownerPolicy = source.slice(
    source.indexOf('size_t ServiceProfileOwner('),
    source.indexOf('uint8_t ServiceRoleMode(', source.indexOf('size_t ServiceProfileOwner(')),
  );
  const identityProfileParser = source.slice(
    source.indexOf('bool ParseServiceAclProfile('),
    source.indexOf('bool ServiceProfileDirectory(', source.indexOf('bool ParseServiceAclProfile(')),
  );
  const roleModes = source.slice(
    source.indexOf('uint8_t ServiceRoleMode('),
    source.indexOf('#ifdef _WIN32\nbool ServiceActorAuthorized', source.indexOf('uint8_t ServiceRoleMode(')),
  );

  for (const field of [
    'schemaVersion', 'rootKind', 'artifactFingerprint', 'relativePath',
    'absoluteRoot', 'absolutePath', 'anchorIdentityFingerprint',
    'missingSegments', 'existingDirectoryIdentity', 'intentFingerprint', 'writes',
  ]) assert.equal(plan.includes(`"${field}"`), true, `LocationIntent field ${field}`);
  for (const field of [
    'schemaVersion', 'publishedPath', 'absolutePath', 'directoryIdentity',
    'fileIdentity', 'fileSha256', 'writes',
  ]) assert.equal(resolve.includes(`"${field}"`), true, `PublishedLocation field ${field}`);
  for (const field of ['handle', 'profile', 'absolutePath', 'rootIdentity', 'absence', 'writes']) {
    assert.equal(openRoot.includes(`"${field}"`), true, `ExternalRoot field ${field}`);
  }
  for (const field of ['kind', 'identity', 'absence', 'bytes', 'entries', 'writes']) {
    assert.equal(readObject.includes(`"${field}"`), true, `ExternalObservation field ${field}`);
  }

  for (const profile of [
    'service-external-anchor-directory',
    'service-bot-config-directory', 'service-bot-config-file',
    'service-daemon-config-directory', 'service-daemon-config-file',
    'service-sdk-install-directory', 'service-sdk-install-file',
    'service-bot-retained-directory', 'service-bot-retained-file',
    'service-daemon-retained-directory', 'service-daemon-retained-file',
  ]) assert.equal(source.includes(profile), true, `role-fenced identity profile ${profile}`);
  for (const profile of [
    'service-external-anchor-directory',
    'service-bot-config-directory', 'service-bot-config-file',
    'service-daemon-config-directory', 'service-daemon-config-file',
    'service-sdk-install-directory', 'service-sdk-install-file',
    'service-bot-retained-directory', 'service-bot-retained-file',
    'service-daemon-retained-directory', 'service-daemon-retained-file',
  ]) assert.equal(identityProfileParser.includes(`text == "${profile}"`), true);
  for (const profile of ['config', 'retained-state', 'sdk-install']) {
    assert.equal(externalProfileParser.includes(`text == "${profile}"`), true);
  }
  for (const profile of [
    'bot-config', 'daemon-config',
    'bot-retained-state', 'daemon-retained-state',
  ]) assert.equal(externalProfileParser.includes(profile), false);

  assert.match(plan, /ServiceObservationFixedRootIdentity/);
  assert.match(plan, /ServiceWindowsNotFound/);
  assert.match(plan, /artifact_fingerprint \+ "\/" \+ relative_path/);
  assert.match(resolve, /HashRetainedServiceArtifact/);
  assert.match(resolve, /NumberOfLinks != 1/);
  assert.match(resolve, /RevalidateServiceStoreHandle/);
  assert.match(openRoot, /ServiceActorAuthorized\(roles\)/);
  assert.match(openRoot, /ServiceObservationAbsenceValue/);
  assert.match(openRoot, /external_policy = inferred_policy/);
  assert.match(openRoot, /RevalidateServiceExternalRoot/);
  assert.match(readObject, /ServiceActorAuthorized\(external_root->roles\)/);
  assert.match(readObject, /ServiceObservationAbsenceValue/);
  assert.match(readObject, /ServiceObservationDirectorySnapshot/);
  assert.match(readObject, /ServiceSetString\(env, result, "kind", "file"\)/);
  assert.match(readObject, /1024ULL \* 1024ULL/);
  assert.match(readObject, /256ULL \* 1024ULL/);
  assert.match(readObject, /16ULL \* 1024ULL/);
  assert.match(readObject, /ReadFile\(file, &byte, 1/);
  assert.match(source, /FILE_ATTRIBUTE_REPARSE_POINT/);
  assert.match(source, /VerifyWindowsServiceFileAcl\(handle, roles, profile\)/);
  assert.match(source, /ServiceStoreHandleKind::ExternalRoot/);
  assert.match(source, /for \(HANDLE ancestor : handle->external_ancestors\)/);
  assert.match(source, /CloseServiceStoreNative\(handle\)/);
  assert.match(source, /void ServiceObservationError[\s\S]*?"writes"/);
  assert.match(roleModes, /role == 2 \|\| role == 4 \|\| role == workload/);
  assert.match(roleModes, /role == 0 \|\| role == workload/);
  assert.match(ownerPolicy, /BotRetainedDirectory[\s\S]*?BotRetainedFile\) return 1/);
  assert.match(ownerPolicy, /DaemonRetainedDirectory[\s\S]*?DaemonRetainedFile\) return 3/);
  assert.match(readObject, /external_observed_entries/);
  assert.match(readObject, /external_observed_name_bytes/);
});

test('native malformed handle/profile tuples fail before observation and report zero writes', (context) => {
  if (!existsSync(addonPath)) {
    context.skip('native addon is not built in this source-only check');
    return;
  }
  const addon = require(addonPath);
  const contract = addon.native_control_contract();
  for (const capability of Object.keys(observationSignatures)) {
    assert.equal(contract.capabilities.includes(capability), true, capability);
  }

  for (const invoke of [
    () => addon.plan_service_artifact_location('unsupported', 'a'.repeat(64), 'entry.exe', {}),
    () => addon.resolve_service_artifact_location({}, 'entry.exe', 'a'.repeat(64)),
    () => addon.open_service_external_root('C:\\scope\\missing', 'unsupported-profile', {}),
    () => addon.read_service_external_object({}, 'entry.env', 'bytes', 1024),
  ]) {
    assert.throws(invoke, (error) => {
      assert.equal(error.code, 'SERVICE_INVALID');
      assert.equal(error.writes, 0);
      assert.equal(error.ambiguous, false);
      return true;
    });
  }
  for (const profile of [
    'bot-config', 'daemon-config',
    'bot-retained-state', 'daemon-retained-state',
  ]) {
    assert.throws(
      () => addon.open_service_external_root('C:\\scope\\missing', profile, {}),
      (error) => error.code === 'SERVICE_INVALID' && error.writes === 0,
    );
  }
});

test('every Windows access check receives a descriptor with owner, group and DACL', () => {
  // AuthzAccessCheck (ERROR_INVALID_PARAMETER) and AccessCheck
  // (ERROR_INVALID_SECURITY_DESCR) reject owner-less or group-less
  // descriptors, which silently denied every bootstrap-anchor traversal proof
  // and every service self-observation.
  const functionStart = /^(?:static )?(?:bool|napi_value|[A-Za-z_][\w:<>]*) [A-Za-z_]\w*\([^;]*?\)\s*\{/gm;
  const starts = [...source.matchAll(functionStart)].map((match) => match.index);
  const calls = [...source.matchAll(/\b(?:Authz)?AccessCheck\(/g)];
  const functions = new Set();
  for (const call of calls) {
    const start = starts.filter((offset) => offset < call.index).at(-1);
    assert.notEqual(start, undefined, `enclosing function for access check at offset ${call.index}`);
    functions.add(start);
    const body = source.slice(start, call.index);
    const argsEnd = source.indexOf(';', call.index);
    const args = source.slice(call.index, argsEnd);
    const descriptor = call[0].startsWith('Authz')
      ? args.split(',')[4].trim()
      : args.slice(call[0].length).split(',')[0].trim();
    const queries = [...body.matchAll(/GetSecurityInfo\(([^;]*?)&(\w+)\)/g)]
      .filter((query) => query[2] === descriptor);
    assert.equal(queries.length, 1, `one GetSecurityInfo fills ${descriptor} before access check at offset ${call.index}`);
    for (const flag of ['OWNER_SECURITY_INFORMATION', 'GROUP_SECURITY_INFORMATION', 'DACL_SECURITY_INFORMATION']) {
      assert.ok(queries[0][1].includes(flag), `${flag} requested for access check at offset ${call.index}`);
    }
  }
  assert.equal(calls.length, 4, 'all Windows access-check calls are covered');
  assert.equal(functions.size, 3, 'all Windows access-check functions are covered');
});
