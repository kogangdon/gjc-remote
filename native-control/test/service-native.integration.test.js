import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  capabilities,
  capabilitySignatures,
  contractRevision,
  validateBuildManifest,
} from '../src/index.js';

const require = createRequire(import.meta.url);
const addonPath = fileURLToPath(new URL('../build/Release/native_control.node', import.meta.url));
const manifestPath = fileURLToPath(new URL('../build/Release/native-control.manifest.json', import.meta.url));
const packagePath = fileURLToPath(new URL('../package.json', import.meta.url));
const addonSourcePath = fileURLToPath(new URL('../src/addon.cc', import.meta.url));

const serviceCapabilities = [
  'set_exact_service_acl',
  'verify_exact_service_acl',
  'read_file_facts_no_follow',
  'read_boot_id',
  'read_process_facts',
  'enumerate_process_tree',
  'read_linux_service_cgroup',
  'terminate_linux_service_cgroup',
  'open_win32_service',
  'close_win32_service',
  'query_win32_service',
  'create_win32_service_disabled',
  'protect_win32_service',
  'set_win32_service_marker',
  'configure_win32_service_launch',
  'set_win32_service_start_type',
  'set_win32_service_failure_actions',
  'set_win32_service_failure_actions_flag',
  'start_win32_service',
  'stop_win32_service',
  'delete_win32_service',
  'terminate_win32_service_tree',
  'open_service_root',
  'open_service_directory',
  'acquire_service_lock',
  'close_service_handle',
  'read_service_file',
  'publish_service_file_atomic',
  'remove_service_object_exact',
  'list_service_directory',
  'publish_service_directory_no_replace',
  'open_linux_service_scope',
  'read_linux_service_object',
  'publish_linux_service_object',
  'remove_linux_service_object',
  'begin_service_artifact_write',
  'write_service_artifact_chunk',
  'finish_service_artifact_write',
  'open_service_artifact_reader',
  'read_service_artifact_chunk',
  'remove_service_artifact_file_exact',
  'seal_service_directory',
  'open_service_artifact_source',
];

const serviceSignatures = {
  set_exact_service_acl: ['path', 'roles', 'profile'],
  verify_exact_service_acl: ['path', 'roles', 'profile'],
  read_file_facts_no_follow: ['path', 'maxBytes'],
  read_boot_id: [],
  read_process_facts: ['pid'],
  enumerate_process_tree: ['rootPid', 'rootStartTime', 'rootExecutable', 'rootOwner'],
  read_linux_service_cgroup: ['cgroupPath'],
  terminate_linux_service_cgroup: ['cgroupPath', 'expectedDevice', 'expectedInode', 'expectedTreeFingerprint'],
  open_win32_service: ['name', 'serviceRole', 'roles', 'access'],
  close_win32_service: ['serviceHandle'],
  query_win32_service: ['serviceHandle'],
  create_win32_service_disabled: ['name', 'serviceRole', 'supervisorPath', 'supervisorSha256', 'workingDirectory', 'homeDirectory', 'runtimePath', 'runtimeSha256', 'entrypointPath', 'entrypointSha256', 'logDirectory', 'logAs', 'logCmdAs', 'channelsConfig', 'servicePassword', 'roles'],
  protect_win32_service: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint', 'transitionMarker'],
  set_win32_service_marker: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint', 'transitionMarker'],
  configure_win32_service_launch: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint', 'supervisorPath', 'supervisorSha256', 'workingDirectory', 'homeDirectory', 'runtimePath', 'runtimeSha256', 'entrypointPath', 'entrypointSha256', 'logDirectory', 'logAs', 'logCmdAs', 'channelsConfig'],
  set_win32_service_start_type: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint', 'startType'],
  set_win32_service_failure_actions: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint', 'failurePolicy'],
  set_win32_service_failure_actions_flag: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint', 'enabled'],
  start_win32_service: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint'],
  stop_win32_service: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint'],
  delete_win32_service: ['serviceHandle', 'expectedConfigFingerprint', 'expectedRuntimeFingerprint'],
  terminate_win32_service_tree: ['serviceHandle', 'expectedConfigFingerprint', 'rootPid', 'rootStartTime', 'rootExecutable', 'rootOwner', 'expectedTreeFingerprint'],
  open_service_root: ['rootKind', 'roles', 'access'],
  open_service_directory: ['parentHandle', 'name', 'access', 'expectedIdentity', 'lockHandle'],
  acquire_service_lock: ['controlRootHandle', 'scope', 'serviceKey', 'mode'],
  close_service_handle: ['handle'],
  read_service_file: ['parentHandle', 'name', 'maxBytes'],
  publish_service_file_atomic: ['parentHandle', 'name', 'bytes', 'expected', 'lockHandle'],
  remove_service_object_exact: ['parentHandle', 'name', 'expected', 'lockHandle'],
  list_service_directory: ['directoryHandle', 'maxEntries', 'lockHandle'],
  publish_service_directory_no_replace: ['sourceDirectoryHandle', 'destinationParentHandle', 'name', 'expectedSourceIdentity', 'artifactLockHandle'],
  open_linux_service_scope: ['roles', 'serviceKey', 'access'],
  read_linux_service_object: ['scopeHandle', 'objectKind'],
  publish_linux_service_object: ['scopeHandle', 'objectKind', 'bytes', 'expected', 'lockHandle'],
  remove_linux_service_object: ['scopeHandle', 'objectKind', 'expected', 'lockHandle'],
  begin_service_artifact_write: ['parentHandle', 'name', 'expectedSize', 'expectedSha256', 'artifactLockHandle'],
  write_service_artifact_chunk: ['writerHandle', 'expectedOffset', 'bytes'],
  finish_service_artifact_write: ['writerHandle', 'finalProfile'],
  open_service_artifact_reader: ['parentHandle', 'name', 'maxBytes', 'expectedFacts', 'artifactLockHandle'],
  read_service_artifact_chunk: ['readerHandle', 'expectedOffset', 'maxBytes'],
  remove_service_artifact_file_exact: ['parentHandle', 'name', 'expectedFacts', 'artifactLockHandle'],
  seal_service_directory: ['directoryHandle', 'expectedIdentity', 'artifactLockHandle'],
  open_service_artifact_source: ['path', 'maxBytes', 'expectedFacts', 'roles'],
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function loadCurrentAddon() {
  assert.equal(existsSync(addonPath), true, 'revision-4 native_control.node must be built before this gate');
  assert.equal(existsSync(manifestPath), true, 'revision-4 native-control.manifest.json must be built before this gate');
  const addonBytes = readFileSync(addonPath);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
  assert.equal(
    validateBuildManifest(manifest, packageJson, addonBytes),
    true,
    'the present addon must positively validate as the current revision-4 platform tuple',
  );
  return { addon: require(addonPath), addonBytes, manifest, packageJson };
}

test('revision 4 declares one exact service-native ABI without replacing retained capabilities', () => {
  const packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
  assert.equal(contractRevision, 4);
  assert.equal(packageJson.nativeControlContract.revision, 4);
  assert.equal(serviceCapabilities.length, 43);
  assert.deepEqual(capabilities.slice(-serviceCapabilities.length), serviceCapabilities);
  assert.deepEqual(
    Object.fromEntries(serviceCapabilities.map((name) => [name, capabilitySignatures[name]])),
    serviceSignatures,
  );
  assert.equal(new Set(capabilities).size, capabilities.length);
  assert.deepEqual(Object.keys(capabilitySignatures), capabilities);
});

test('current revision-4 addon and manifest agree exactly and reject revision/table drift', () => {
  const { addon, addonBytes, manifest, packageJson } = loadCurrentAddon();
  const contract = addon.native_control_contract();
  assert.deepEqual(contract, {
    contractVersion: 4,
    contractRevision: 4,
    napi: 8,
    capabilities,
    capabilitySignatures,
  });
  for (const name of serviceCapabilities) assert.equal(typeof addon[name], 'function', name);

  assert.equal(validateBuildManifest({ ...manifest, contractRevision: 3 }, packageJson, addonBytes), false);
  assert.equal(validateBuildManifest({ ...manifest, contractRevision: 5 }, packageJson, addonBytes), false);
  const capabilityDrift = structuredClone(manifest);
  capabilityDrift.capabilities.pop();
  assert.equal(validateBuildManifest(capabilityDrift, packageJson, addonBytes), false);
  const signatureDrift = structuredClone(manifest);
  signatureDrift.capabilitySignatures.start_win32_service = ['serviceHandle'];
  assert.equal(validateBuildManifest(signatureDrift, packageJson, addonBytes), false);
});

test('native read-only service facts bind current file bytes, boot, PID start, executable, owner, and tree', () => {
  const { addon, addonBytes } = loadCurrentAddon();
  const file = addon.read_file_facts_no_follow(addonPath, addonBytes.length);
  assert.equal(file.size, addonBytes.length);
  assert.equal(file.sha256, sha256(addonBytes));
  assert.match(file.securitySha256, /^[0-9a-f]{64}$/);
  assert.match(file.owner, process.platform === 'win32' ? /^S-1-/ : /^uid:[0-9]+$/);
  assert.equal(addon.read_file_facts_no_follow(`${addonPath}.absent`, 1), null);
  assert.throws(
    () => addon.read_file_facts_no_follow(addonPath, -1),
    (error) => error.code === 'SERVICE_INVALID' && error.writes === 0,
  );
  assert.throws(
    () => addon.verify_exact_service_acl(addonPath, {}, 'service-release-file'),
    (error) => error.code === 'SERVICE_INVALID' && error.writes === 0,
  );

  assert.match(addon.read_boot_id(), process.platform === 'win32'
    ? /^win32:[1-9][0-9]+$/
    : /^linux:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  const processFacts = addon.read_process_facts(process.pid);
  assert.equal(processFacts.pid, process.pid);
  assert.match(processFacts.startTime, /^[1-9][0-9]*$/);
  assert.equal(processFacts.executable.length > 0, true);
  assert.match(processFacts.owner, process.platform === 'win32' ? /^S-1-/ : /^uid:[0-9]+$/);

  const tree = addon.enumerate_process_tree(
    processFacts.pid,
    processFacts.startTime,
    processFacts.executable,
    processFacts.owner,
  );
  assert.match(tree.treeFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(tree.processCount, tree.processes.length);
  assert.equal(tree.processes[0].pid, processFacts.pid);
  assert.equal(tree.processes[0].startTime, processFacts.startTime);
  assert.equal(tree.processes[0].executable, processFacts.executable);
  assert.equal(tree.processes[0].owner, processFacts.owner);
  assert.equal(tree.processes[0].depth, 0);
});

test('native provider SHA-256 agrees with independent Node crypto boundary vectors', () => {
  const { addon } = loadCurrentAddon();
  const directory = mkdtempSync(join(tmpdir(), 'gjc-service-native-sha-'));
  try {
    for (const length of [0, 55, 56, 63, 64, 65, 4097]) {
      const bytes = Buffer.allocUnsafe(length);
      for (let index = 0; index < bytes.length; ++index) {
        bytes[index] = (index * 131 + length) & 0xff;
      }
      const path = join(directory, `${length}.bin`);
      writeFileSync(path, bytes);
      const facts = addon.read_file_facts_no_follow(path, length);
      assert.equal(facts.size, length);
      assert.equal(facts.sha256, sha256(bytes), `SHA-256 length ${length}`);
      assert.notEqual(facts.sha256, '', `SHA-256 length ${length} must not accept an empty provider result`);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('platform-specific mutation primitives fail closed off-platform without touching services or processes', () => {
  const { addon } = loadCurrentAddon();
  const fingerprint = '0'.repeat(64);
  if (process.platform === 'win32') {
    assert.throws(
      () => addon.read_linux_service_cgroup('/sys/fs/cgroup/system.slice/gjc-remote-bot.service'),
      (error) => error.code === 'SERVICE_UNSUPPORTED' && error.writes === 0,
    );
    assert.throws(
      () => addon.terminate_linux_service_cgroup('/sys/fs/cgroup/system.slice/gjc-remote-bot.service', '1', '1', fingerprint),
      (error) => error.code === 'SERVICE_UNSUPPORTED' && error.writes === 0,
    );
  } else {
    assert.throws(
      () => addon.open_win32_service('GJCRemoteBot', 'bot', {}, 'query'),
      (error) => error.code === 'SERVICE_UNSUPPORTED' && error.writes === 0,
    );
    assert.throws(
      () => addon.terminate_win32_service_tree(null, fingerprint, process.pid, '1', '/not-used', 'uid:0', fingerprint),
      (error) => error.code === 'SERVICE_UNSUPPORTED' && error.writes === 0,
    );
  }
});

test('native service namespace rejects non-canonical names before any resource open', () => {
  const { addon } = loadCurrentAddon();
  const digest = 'a'.repeat(64);
  if (process.platform === 'win32') {
    let rolesRead = false;
    const unreadableRoles = new Proxy({}, {
      getPrototypeOf() {
        rolesRead = true;
        throw new Error('roles must not be inspected for an invalid service name');
      },
    });
    const invalid = [
      ['gjc-remote-bot', 'bot'],
      ['GJCRemoteBot-extra', 'bot'],
      [`GJCRemoteDaemon-host-${'a'.repeat(63)}`, 'daemon'],
      [`GJCRemoteDaemon-${'a'.repeat(33)}-${digest}`, 'daemon'],
      [`GJCRemoteDaemon-Host-${digest}`, 'daemon'],
      [`GJCRemoteDaemon-host_${digest}`, 'daemon'],
    ];
    for (const [name, role] of invalid) {
      rolesRead = false;
      assert.throws(
        () => addon.open_win32_service(name, role, unreadableRoles, 'query'),
        (error) => error.code === 'SERVICE_INVALID' && error.writes === 0,
        name,
      );
      assert.equal(rolesRead, false, `${name} must refuse before role or SCM access`);
    }
  } else {
    const root = '/sys/fs/cgroup/system.slice/';
    for (const name of [
      `gjc-remote-daemon@host-${'a'.repeat(63)}.service`,
      `gjc-remote-daemon@${'a'.repeat(33)}-${digest}.service`,
      `gjc-remote-daemon@Host-${digest}.service`,
      `gjc-remote-daemon@host_${digest}.service`,
    ]) {
      assert.throws(
        () => addon.read_linux_service_cgroup(root + name),
        (error) => error.code === 'SERVICE_INVALID' && error.writes === 0,
        name,
      );
    }
  }
});

test('Windows start request keeps START_PENDING with PID zero distinct from a proven wrapper epoch', () => {
  const source = readFileSync(addonSourcePath, 'utf8');
  const begin = source.indexOf('napi_value StartWin32Service');
  const end = source.indexOf('napi_value StopWin32Service', begin);
  assert.notEqual(begin, -1);
  assert.notEqual(end, -1);
  const implementation = source.slice(begin, end);
  assert.match(
    implementation,
    /after\.state != SERVICE_START_PENDING &&\s*!\(after\.state == SERVICE_RUNNING && after\.process_id != 0\)/,
  );
  assert.match(implementation, /"startRequested", true/);
  assert.doesNotMatch(implementation, /wrapperEpochObserved/);
  assert.doesNotMatch(implementation, /\|\|\s*after\.process_id == 0/);
});

test('Windows open distinguishes deletion pending from genuine absence and access denial', () => {
  const source = readFileSync(addonSourcePath, 'utf8');
  const begin = source.indexOf('napi_value OpenWin32Service');
  const end = source.indexOf('napi_value CloseWin32Service', begin);
  assert.notEqual(begin, -1);
  assert.notEqual(end, -1);
  const implementation = source.slice(begin, end);
  assert.match(implementation, /error == ERROR_SERVICE_DOES_NOT_EXIST/);
  assert.match(
    implementation,
    /error == ERROR_SERVICE_MARKED_FOR_DELETE\s*\?\s*"SERVICE_PENDING"\s*:\s*"SERVICE_ACCESS_DENIED"/,
  );
});

test('Windows create derives its service account only from the selected canonical role SID', () => {
  const source = readFileSync(addonSourcePath, 'utf8');
  const resolverBegin = source.indexOf('bool ResolveWin32ServiceAccountName');
  const resolverEnd = source.indexOf('bool BuildWin32ServiceObjectAcl', resolverBegin);
  const createBegin = source.indexOf('napi_value CreateWin32ServiceDisabled');
  const createEnd = source.indexOf('napi_value ProtectWin32Service', createBegin);
  assert.notEqual(resolverBegin, -1);
  assert.notEqual(resolverEnd, -1);
  assert.notEqual(createBegin, -1);
  assert.notEqual(createEnd, -1);
  const resolver = source.slice(resolverBegin, resolverEnd);
  const create = source.slice(createBegin, createEnd);

  assert.match(resolver, /kMaximumAccountUnits = 4096/);
  assert.match(resolver, /LookupAccountSidW\(/);
  assert.match(resolver, /use == SidTypeUser/);
  assert.match(resolver, /Win32ServiceAccountMatches\(account_utf8, expected_sid\)/);
  assert.match(create, /InventoryArgs\(env, info, 16, args\)/);
  assert.match(create, /role == "bot" \? roles\.bot : roles\.daemon/);
  assert.match(create, /ResolveWin32ServiceAccountName\(selected_sid, &account\)/);
  assert.match(create, /empty_dependencies, account\.c_str\(\),/);
  assert.doesNotMatch(create, /accountName/);
  assert.doesNotMatch(create, /InventoryString\(env, args\[14\], &account\)/);
});

test('Windows canonical role parsing bounds LookupAccountSid sizes before allocation', () => {
  const source = readFileSync(addonSourcePath, 'utf8');
  const begin = source.indexOf('bool CanonicalUserSid');
  const end = source.indexOf('bool InventoryRole', begin);
  assert.notEqual(begin, -1);
  assert.notEqual(end, -1);
  const parser = source.slice(begin, end);
  assert.match(parser, /kMaximumAccountUnits = 4096/);
  assert.match(parser, /first_error == ERROR_INSUFFICIENT_BUFFER/);
  assert.match(parser, /name <= kMaximumAccountUnits/);
  assert.match(parser, /domain <= kMaximumAccountUnits/);
  assert.match(parser, /static_cast<uint64_t>\(name\) \+ domain \+ 1 <=/);
  assert.ok(
    parser.indexOf('name <= kMaximumAccountUnits') <
      parser.indexOf('std::vector<wchar_t> n'),
    'reported principal sizes must be bounded before allocation',
  );
  assert.match(parser, /use == SidTypeUser/);
  assert.match(parser, /ConvertSidToStringSidW/);
});
