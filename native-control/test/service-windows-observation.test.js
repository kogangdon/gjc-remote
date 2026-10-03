import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { capabilitySignatures, serviceCapabilities } from '../src/capabilities.js';
import { createServiceNativeFactory } from '../src/service-native.js';
import { createServiceObservationDirectoryFixture } from '../test-fixtures/service-observation-directory.mjs';

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

function nativeFunctionBlock(signature) {
  const start = source.indexOf(signature);
  assert.notEqual(start, -1, `${signature} implementation exists`);
  const end = source.indexOf('\n}', start);
  assert.notEqual(end, -1, `${signature} implementation ends`);
  return source.slice(start, end + 2);
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
  addon.read_win32_boot_clock = () => {
    calls.set('read_win32_boot_clock', []);
    return Object.freeze({ name: 'read_win32_boot_clock' });
  };
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
  assert.deepEqual(facade.read_win32_boot_clock(), { name: 'read_win32_boot_clock' });
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
  assert.deepEqual(calls.get('read_win32_boot_clock'), []);
  assert.deepEqual(projectedRoles, roles);
  assert.notEqual(projectedRoles, roles);
  assert.equal(calls.get('open_service_external_root')[2], projectedRoles);
  assert.equal(facade.plan_service_artifact_location.length, 3);
  assert.equal(facade.resolve_service_artifact_location.length, 3);
  assert.equal(facade.open_service_external_root.length, 2);
  assert.equal(facade.read_service_external_object.length, 4);
  assert.equal(facade.read_win32_boot_clock.length, 0);
});

function nativeObservationRoles(addon) {
  const current = addon.current_os_principal();
  const system = 'S-1-5-18';
  assert.equal(current?.kind, 'sid');
  const result = spawnSync('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    'Get-LocalUser | ForEach-Object { $_.SID.Value }',
  ], { encoding: 'utf8', timeout: 10_000, windowsHide: true });
  assert.equal(result.error, undefined, 'read-only local user enumeration must run');
  assert.equal(result.status, 0, 'read-only local user enumeration must succeed');
  const candidates = [...new Set(result.stdout.split(/\r?\n/).map((value) => value.trim()))]
    .filter((value) => /^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/.test(value))
    .filter((value) => value !== current.value && value !== system);
  assert.ok(
    candidates.length >= (current.value === system ? 4 : 3),
    'the temporary native fixture requires three distinct existing user SIDs besides management and SYSTEM',
  );
  const management = current.value === system ? candidates.shift() : current.value;
  return {
    management: { kind: 'sid', value: management },
    bot: { kind: 'sid', value: candidates[0] },
    recovery: { kind: 'sid', value: candidates[1] },
    daemon: { kind: 'sid', value: candidates[2] },
    system: { kind: 'sid', value: system },
  };
}

test('Windows service and inventory roots share the OS installation drive without ProgramData fallback', () => {
  const systemDriveResolver = nativeFunctionBlock('bool ResolveWindowsSystemDriveRoot(');
  const serviceRoot = nativeFunctionBlock('bool ResolveServiceStoreRoot(');
  const baseContainer = nativeFunctionBlock('bool ResolveServiceBaseContainer(');
  const shawlParent = nativeFunctionBlock('ShawlParentState PrepareShawlServiceParent(');
  const observationRoot = nativeFunctionBlock('bool ServiceObservationFixedRootIdentity(');

  assert.match(systemDriveResolver, /GetSystemWindowsDirectoryW\s*\(/);
  assert.ok(systemDriveResolver.includes('windows_path.size() < 2'),
    'the documented drive-root installation result X: is accepted');
  assert.ok(systemDriveResolver.includes("(windows_path.size() > 2 && windows_path[2] != L'\\\\')"),
    'a non-root result must be absolute rather than drive-relative');
  assert.ok(systemDriveResolver.includes("windows_path[0] - L'a' + L'A'"),
    'lowercase API drive letters are normalized before publication');
  assert.ok(systemDriveResolver.includes('std::string(1, static_cast<char>(drive)) + ":\\\\"'),
    'the returned drive root has exactly one trailing separator');
  assert.doesNotMatch(systemDriveResolver, /FOLDERID_ProgramData|SHGetKnownFolderPath|GetEnvironmentVariable|_wgetenv|std::getenv/);
  for (const [name, block] of [
    ['ResolveServiceStoreRoot', serviceRoot],
    ['ResolveServiceBaseContainer', baseContainer],
    ['PrepareShawlServiceParent', shawlParent],
    ['ServiceObservationFixedRootIdentity', observationRoot],
  ]) {
    assert.match(block, /ResolveWindowsSystemDriveRoot\s*\(/, `${name} uses the system-drive resolver`);
    assert.doesNotMatch(block, /FOLDERID_ProgramData|SHGetKnownFolderPath/, `${name} does not derive its root from ProgramData`);
  }

  const absentStart = observationRoot.indexOf(
    'if (base_state == ServiceContainerState::Absent) {',
  );
  const absentEnd = observationRoot.indexOf(
    '\n  if (base_state != ServiceContainerState::Ready)', absentStart,
  );
  assert.notEqual(absentStart, -1, 'fixed-root absence branch exists');
  assert.notEqual(absentEnd, -1, 'fixed-root absence branch ends');
  const absentBranch = observationRoot.slice(absentStart, absentEnd);
  assert.match(absentBranch, /ResolveWindowsSystemDriveRoot\s*\(/);
  assert.doesNotMatch(absentBranch, /FOLDERID_ProgramData|SHGetKnownFolderPath/);

  assert.match(baseContainer, /spec->name = "gjc-remote"/);
  assert.match(baseContainer, /spec->identity = "system-drive-gjc-remote"/);
  assert.match(serviceRoot, /const std::string base_path = system_drive_root \+ "gjc-remote";/);
  assert.match(shawlParent, /const std::string base_path = system_drive_root \+ "gjc-remote";/);
  assert.match(serviceRoot, /root_kind == "control" \? "service-control" : root_kind/);
  assert.match(serviceRoot, /\*name = "shawl"/);

  const inventoryFunctions = [
    nativeFunctionBlock('bool InventoryPath('),
    nativeFunctionBlock('napi_value ResolveInventoryStateRootWindows('),
    nativeFunctionBlock('bool VerifyInventoryBaseWindows('),
    nativeFunctionBlock('bool OpenInventoryParentBoundWindows('),
  ];
  const inventoryBase = nativeFunctionBlock('bool ResolveWindowsInventoryBasePath(');
  assert.match(inventoryBase, /ResolveWindowsSystemDriveRoot\s*\(/);
  assert.match(inventoryBase, /system_drive_root \+ "gjc-remote"/);
  assert.match(inventoryBase, /native-reader/);
  assert.match(inventoryBase, /\\native/);
  for (const block of inventoryFunctions) {
    assert.match(block, /ResolveWindowsInventoryBasePath\s*\(/);
    assert.doesNotMatch(block, /FOLDERID_ProgramData|SHGetKnownFolderPath/);
  }
  assert.equal(
    [...source.matchAll(/FOLDERID_ProgramData/g)].length,
    0,
    'no native state root falls back to ProgramData',
  );
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

test('directory snapshots finish enumeration before byte-order sorting and refuse non-EOF errors', () => {
  const snapshot = nativeFunctionBlock('bool ServiceObservationDirectorySnapshot(');
  const eof = snapshot.indexOf('if (GetLastError() == ERROR_NO_MORE_FILES) break;');
  const sort = snapshot.indexOf('std::sort(entries->begin(), entries->end()');
  assert.notEqual(eof, -1, 'only ERROR_NO_MORE_FILES terminates enumeration successfully');
  assert.match(snapshot.slice(eof), /^if \(GetLastError\(\) == ERROR_NO_MORE_FILES\) break;\s*return false;/);
  assert.ok(sort > eof, 'the sorted result is produced only after enumeration completes');
});

test('native Windows SDK directory snapshots complete mixed-case enumeration, sort names, and fail closed on invalid children', (context) => {
  if (process.platform !== 'win32') {
    context.skip('native external directory snapshots require Windows');
    return;
  }
  if (!existsSync(addonPath)) {
    context.skip('native addon is not built in this source-only check');
    return;
  }

  const addon = require(addonPath);
  const roles = nativeObservationRoles(addon);
  const fixture = createServiceObservationDirectoryFixture(roles);
  let handle;
  try {
    const opened = addon.open_service_external_root(fixture.root, 'sdk-install', roles);
    assert.equal(opened.writes, 0);
    assert.equal(opened.profile, 'sdk-install');
    handle = opened.handle;

    const snapshot = addon.read_service_external_object(handle, '', 'directory', 0);
    assert.equal(snapshot.kind, 'directory');
    assert.equal(snapshot.writes, 0);
    assert.deepEqual(
      snapshot.entries.map(({ name, kind }) => [name, kind]),
      [
        ['CHANGELOG.md', 'file'],
        ['LICENSE', 'file'],
        ['build', 'directory'],
        ['index.js', 'file'],
      ],
    );

    writeFileSync(join(fixture.root, 'invalid-acl.txt'), 'untrusted child\n');
    assert.throws(
      () => addon.read_service_external_object(handle, '', 'directory', 0),
      (error) => error.code === 'SERVICE_STALE' && error.writes === 0,
      'an invalid child must refuse the entire snapshot rather than expose a partial listing',
    );
  } finally {
    if (handle !== undefined) addon.close_service_handle(handle);
    fixture.cleanup();
  }
});

test('planned Win32 launch mode is confined to planning while mutation callers retain materialized-file checks', () => {
  const capture = nativeFunctionBlock('bool CaptureWin32ServiceLaunch(');
  const plan = nativeBlock('PlanWin32ServiceResource');
  const create = nativeBlock('CreateWin32ServiceDisabled');
  const configure = nativeBlock('ConfigureWin32ServiceLaunch');
  assert.match(capture, /Win32ServiceLaunchValidation validation =\s*Win32ServiceLaunchValidation::Materialized/);
  assert.match(plan, /Win32ServiceLaunchValidation::PlannedArtifacts/);

  const materializedStart = capture.indexOf('const bool materialized_artifacts_valid =');
  const runtimeStart = capture.indexOf('const bool runtime_valid =');
  assert.ok(materializedStart > runtimeStart, 'runtime file proof stays outside planned-artifact bypass');
  const materialized = capture.slice(materializedStart, capture.indexOf('if (!runtime_valid', materializedStart));
  for (const artifact of ['supervisor_path', 'entrypoint_path', 'bootstrap_path']) {
    assert.match(materialized, new RegExp(`ReadWindowsFileSha256\\(launch->${artifact}`));
    assert.match(materialized, new RegExp(`VerifyWindowsPathServiceAcl\\(launch->${artifact}`));
  }
  const runtime = capture.slice(runtimeStart, materializedStart);
  assert.match(runtime, /ReadWindowsFileSha256\(launch->runtime_path/);
  assert.match(runtime, /VerifyWindowsPathServiceAcl\(launch->runtime_path/);
  for (const check of [
    'VerifyWindowsDirectoryNoFollow(launch->working_directory)',
    'VerifyWindowsDirectoryNoFollow(launch->home_directory)',
    'VerifyWin32ConfigSourceLaunch',
    'VerifyWindowsPathServiceAcl(launch->channels_config',
    'VerifyWin32RuntimeConfigLaunch',
    'launch->sdk_profile_path',
  ]) assert.ok(capture.includes(check), `${check} remains enforced in planned mode`);

  for (const [name, body] of [['create', create], ['configure', configure]]) {
    const call = body.match(/CaptureWin32ServiceLaunch\([\s\S]*?\);/);
    assert.ok(call, `${name} path captures the launch`);
    assert.doesNotMatch(call[0], /PlannedArtifacts/, `${name} uses materialized validation`);
  }
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
