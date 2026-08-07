import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const release = join(root, 'build', 'Release');
const addon = join(release, 'native_control.node');
const manifestPath = join(release, 'native-control.manifest.json');
const capabilities = [
  'open_verified_parent', 'open_no_follow', 'read_identity', 'read_acl', 'path_exists_no_follow',
  'set_exact_role_acl', 'verify_exact_role_acl', 'read_verified_bytes', 'create_exclusive_temp', 'flush_file',
  'flush_directory_or_volume', 'replace_existing_atomic', 'create_absent_exclusive',
  'ensure_control_directory', 'acquire_native_lock', 'current_os_principal',
  'principal_access_check', 'remove_verified_file', 'open_verified_parent_handle',
  'open_verified_object_handle', 'read_handle_identity', 'read_handle_bytes',
  'write_handle_bytes', 'remove_verified_handle', 'verify_role_sid_not_group',
];
const capabilitySignatures = {
  open_verified_parent: ['path'], open_no_follow: ['path'], read_identity: ['path'], read_acl: ['path'], path_exists_no_follow: ['path'],
  set_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  verify_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  read_verified_bytes: ['path'], create_exclusive_temp: ['parent', 'prefix', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  flush_file: ['path'], flush_directory_or_volume: ['path'],
  replace_existing_atomic: ['source', 'destination', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  create_absent_exclusive: ['path', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  ensure_control_directory: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  acquire_native_lock: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  current_os_principal: [], principal_access_check: ['path', 'kind', 'principal', 'mode', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'], remove_verified_file: ['path', 'expectedBytes'],
  open_verified_parent_handle: ['path'], open_verified_object_handle: ['parentHandle', 'name'],
  read_handle_identity: ['handle'], read_handle_bytes: ['handle'],
  write_handle_bytes: ['handle', 'bytes'], remove_verified_handle: ['handle', 'expectedBytes'],
  verify_role_sid_not_group: ['sid'],
};

function fail(message) {
  process.stderr.write(`native-control verification failed: ${message}\n`);
  process.exitCode = 1;
}
if (JSON.stringify(packageJson.nativeControlContract) !== JSON.stringify({
  version: 3, napi: 8, platforms: ['linux-x64', 'linux-arm64', 'win32-x64'],
})) fail('package native capability contract is invalid');

if (!['linux-x64', 'linux-arm64', 'win32-x64'].includes(`${process.platform}-${process.arch}`)) {
  fail(`unsupported native-control platform: ${process.platform}-${process.arch}`);
} else if (!existsSync(addon)) {
  fail('native_control.node is missing');
} else {
  const expected = {
    contractVersion: 3,
    package: packageJson.name,
    version: packageJson.version,
    napi: 8,
    platform: process.platform,
    arch: process.arch,
    addon: 'native_control.node',
    sha256: createHash('sha256').update(readFileSync(addon)).digest('hex'),
    capabilities,
    capabilitySignatures,
  };
  let loaded;
  try { loaded = require(addon); } catch { fail('native_control.node could not be loaded'); }
  if (loaded) {
    for (const name of capabilities) if (typeof loaded[name] !== 'function') fail(`native capability ${name} is missing`);
    let contract;
    try { contract = loaded.native_control_contract(); } catch { fail('native capability contract is missing or unreadable'); }
    if (!contract || JSON.stringify(contract) !== JSON.stringify({ contractVersion: 3, napi: 8, capabilities, capabilitySignatures })) fail('native capability contract does not match the expected function signatures');
  }
  if (process.argv.includes('--write-manifest')) {
    if (!loaded || process.exitCode) process.exitCode = 1;
    else writeFileSync(manifestPath, `${JSON.stringify(expected, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  } else if (!existsSync(manifestPath)) {
    fail('native-control.manifest.json is missing');
  } else {
    let actual;
    try { actual = JSON.parse(readFileSync(manifestPath, 'utf8')); } catch { fail('manifest is not valid JSON'); process.exit(); }
    for (const [key, value] of Object.entries(expected)) {
      if (JSON.stringify(actual[key]) !== JSON.stringify(value)) fail(`manifest ${key} does not match the local addon`);
    }
  }
}
