import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { lstatSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonicalJsonHash } from '@gjc-remote/shared/strict-json';
import { verifyManifestSignature } from '../src/native-provenance.js';
import {
  capabilitySignatures,
  selfObservationCapabilities,
  serviceCapabilities,
} from '../src/capabilities.js';

const nativeRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const addonPath = join(nativeRoot, 'build', 'Release', 'native_control.node');
const baselineManifestPath = join(
  nativeRoot, 'build', 'Release', 'native-control.manifest.json',
);
const baselineSignaturePath = `${baselineManifestPath}.sig`;
const baselineTrustPath = join(nativeRoot, 'release-keys', 'trusted.json');
const immutableAbi1Sha256 =
  '7570ea932439048e803c670332bb2fdf58f7c4f88f81b652c2c93c8b00bd488e';
const addonSourcePath = join(nativeRoot, 'src', 'addon.cc');
const nativeSource = readFileSync(addonSourcePath, 'utf8');
const require = createRequire(import.meta.url);
function hasAddonOutput() {
  try {
    const status = lstatSync(addonPath);
    assert.equal(status.isFile() && !status.isSymbolicLink(), true,
      'present native addon output must be a regular file');
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}
const addonOutputPresent = hasAddonOutput();
const addon = process.platform === 'win32' && process.arch === 'x64' &&
    addonOutputPresent
  ? require(addonPath)
  : null;
const contractDescriptor = addon &&
  Object.getOwnPropertyDescriptor(addon, 'native_control_contract');
const addonContract = typeof contractDescriptor?.value === 'function'
  ? Reflect.apply(contractDescriptor.value, addon, [])
  : null;
const hasSelfObserver = addon !== null &&
  typeof addon.read_win32_boot_clock === 'function' &&
  typeof addon.observe_self_process_epoch === 'function' &&
  typeof addon.read_self_service_config === 'function';

function isImmutableAbi1Baseline() {
  if (!addon || hasSelfObserver) return false;
  const addonBytes = readFileSync(addonPath);
  const digest = createHash('sha256').update(addonBytes).digest('hex');
  if (digest !== immutableAbi1Sha256) return false;
  const manifestBytes = readFileSync(baselineManifestPath);
  const signatureBytes = readFileSync(baselineSignaturePath);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const signature = JSON.parse(signatureBytes.toString('utf8'));
  const trusted = JSON.parse(readFileSync(baselineTrustPath, 'utf8'));
  const verified = verifyManifestSignature(
    manifestBytes, signature, trusted,
  );
  if (!verified.ok || verified.keyId !== 'prod-2026-08-r2' ||
      manifest.package !== '@gjc-remote/native-control' ||
      manifest.version !== '1.0.0' || manifest.contractVersion !== 4 ||
      manifest.contractRevision !== 4 || manifest.napi !== 8 ||
      manifest.platform !== 'win32' || manifest.arch !== 'x64' ||
      manifest.addon !== 'native_control.node' ||
      manifest.sha256 !== immutableAbi1Sha256 || digest !== manifest.sha256) {
    return false;
  }
  assert.deepEqual(addonContract, {
    contractVersion: manifest.contractVersion,
    contractRevision: manifest.contractRevision,
    napi: manifest.napi,
    capabilities: manifest.capabilities,
    capabilitySignatures: manifest.capabilitySignatures,
  });
  return true;
}

const immutableAbi1Baseline = isImmutableAbi1Baseline();

function requireSelfObserver(t) {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('self-observer runtime checks require Win32 x64');
    return null;
  }
  if (!addonOutputPresent) {
    t.skip('self-observer runtime prerequisite is unrun: native addon output is absent');
    return null;
  }
  assert.notEqual(addon, null, 'present Win32 x64 addon must load without error');
  assert.notEqual(addonContract, null,
    'present native addon must export a callable contract');
  if (immutableAbi1Baseline) {
    t.skip('self-observer runtime prerequisite is unrun: immutable signed native-control 1.0.0 ABI1 baseline lacks Task 1.2 exports');
    return null;
  }
  assert.equal(hasSelfObserver, true,
    'non-baseline native addon must export all Task 1.2 self-observer methods');
  return addon;
}

test('self-observation APIs reject all caller-supplied arguments', (t) => {
  const native = requireSelfObserver(t);
  if (!native) return;
  for (const [name, operation] of [
    ['read_win32_boot_clock', native.read_win32_boot_clock],
    ['observe_self_process_epoch', native.observe_self_process_epoch],
    ['read_self_service_config', native.read_self_service_config],
  ]) {
    assert.throws(() => operation('unexpected'), (error) => {
      assert.equal(error.code, 'SERVICE_INVALID');
      assert.equal(error.operation, name);
      assert.equal(error.writes, 0);
      assert.equal(error.ambiguous, false);
      assert.equal(error.reason, 'invalid-input');
      return true;
    });
  }
});

test('Win32 boot clock and self epoch return only their immutable hash receipts', (t) => {
  const native = requireSelfObserver(t);
  if (!native) return;
  const clock = native.read_win32_boot_clock();
  assert.deepEqual(Object.keys(clock).sort(), [
    'bootFingerprint', 'schemaVersion', 'tickMs', 'writes',
  ]);
  assert.equal(clock.schemaVersion, 1);
  assert.equal(Number.isSafeInteger(clock.tickMs), true);
  assert.equal(clock.tickMs >= 0, true);
  assert.match(clock.bootFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(clock.writes, 0);

  const first = native.observe_self_process_epoch();
  const second = native.observe_self_process_epoch();
  assert.deepEqual(Object.keys(first).sort(), [
    'processEpochFingerprint', 'writes',
  ]);
  assert.match(first.processEpochFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(first.processEpochFingerprint, second.processEpochFingerprint);
  assert.equal(first.writes, 0);
});

test('physical security identity and self-process epoch match approved fixed vectors', () => {
  const identity = {
    attributes: 32,
    fileId: '000102030405060708090a0b0c0d0e0f',
    kind: 'gjc-remote/win32-physical-security-identity/v1',
    owner: 'S-1-5-18',
    securitySha256: 'b'.repeat(64),
    volumeSerial: '0123456789abcdef',
  };
  const executableIdentityFingerprint = canonicalJsonHash(identity);
  assert.equal(executableIdentityFingerprint,
    'ca00bab810fa821d583bcb0ac53619adbb70d867ae9cefb52381bdbdc1593ddd');
  const physicalStart = nativeSource.indexOf(
    'bool ServiceSelfWin32PhysicalSecurityIdentityFingerprint(',
  );
  const physicalEnd = nativeSource.indexOf(
    'bool ServiceSelfWindowsBootFingerprint(', physicalStart,
  );
  const physicalImplementation = nativeSource.slice(
    physicalStart, physicalEnd,
  );
  assert.notEqual(physicalStart, -1);
  assert.notEqual(physicalEnd, -1);
  assert.match(physicalImplementation,
    /ServiceSelfLowerHex\(identity\.volume_serial, 16\)/);
  assert.match(physicalImplementation,
    /ServiceSelfLowerHex\(identity\.file_id, 32\)/);
  assert.match(physicalImplementation,
    /ServiceSelfCanonicalWindowsSid\(identity\.owner\)/);
  assert.match(physicalImplementation,
    /ValidServiceFingerprint\(identity\.security_sha256\)/);
  assert.match(physicalImplementation,
    /gjc-remote\/win32-physical-security-identity\/v1/);
  assert.match(physicalImplementation,
    /\\"attributes\\":.*\\"fileId\\":.*\\"kind\\":\\"gjc-remote\/win32-physical-security-identity\/v1\\",.*\\"owner\\":.*\\"securitySha256\\":.*\\"volumeSerial\\":/s);
  assert.doesNotMatch(physicalImplementation, /ServiceProfileText|profile/);

  const epoch = {
    kind: 'gjc-remote/windows-self-epoch/v1',
    bootId: 'win32:133485408000000000',
    pid: 12345,
    creationTime: '133485408012345678',
    executableIdentityFingerprint,
  };
  assert.equal(canonicalJsonHash(epoch),
    'ec6ee0a4de02294e4e43dedd95b3a264276d579417fd0abf824ef3170805aa21');
  const start = nativeSource.indexOf('napi_value ObserveSelfProcessEpoch(');
  const end = nativeSource.indexOf('napi_value ReadSelfServiceConfig(', start);
  const implementation = nativeSource.slice(start, end);
  assert.match(implementation, /\{\\"bootId\\":\\"/);
  assert.match(implementation, /\\"creationTime\\":\\"/);
  assert.match(implementation, /\\"executableIdentityFingerprint\\":\\"/);
  assert.match(implementation, /gjc-remote\/windows-self-epoch\/v1/);
  assert.match(implementation, /\\"pid\\":/);
});

test('self config source is fixed, bounded, ACL-checked, and identity-rechecked', () => {
  const start = nativeSource.indexOf('napi_value ReadSelfServiceConfig(');
  const end = nativeSource.indexOf(
    'napi_value ReadServiceArtifactChunk(', start,
  );
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const implementation = nativeSource.slice(start, end);
  assert.match(implementation, /InventoryArgs\(env, info, 0, args\)/);
  assert.match(implementation, /L"\.env"/);
  assert.match(implementation, /L"runtime-config"/);
  assert.match(implementation, /L"\.bunfig\.toml"/);
  assert.match(implementation, /256ULL \* 1024ULL/);
  assert.match(implementation, /1024ULL \* 1024ULL/);
  assert.match(nativeSource, /ServiceSelfDenyCurrentWriteAccess\(file, false\)/);
  assert.match(nativeSource, /ServiceSelfDenyCurrentWriteAccess\(next, true\)/);
  assert.match(implementation, /ServiceSelfDirectoryChainStable/);
  assert.match(implementation, /sourceIdentityFingerprint/);
  assert.match(implementation, /fileSha256/);
  assert.doesNotMatch(implementation, /InventoryRolesArg|absolutePath|roles/);
  assert.match(nativeSource, /standard->NumberOfLinks != 1/);
});

test('ancestor AccessCheck permits only append/add-subdirectory among writes', () => {
  const strictStart = nativeSource.indexOf(
    'bool ServiceSelfDenyCurrentWriteAccess(HANDLE object, bool directory) {',
  );
  const strictEnd = nativeSource.indexOf(
    'bool ServiceSelfDenyCurrentAncestorTakeoverAccess(HANDLE object) {',
    strictStart,
  );
  const ancestorEnd = nativeSource.indexOf(
    'bool ServiceSelfCaptureFileIdentity(', strictEnd,
  );
  const chainStart = nativeSource.indexOf(
    'bool ServiceSelfOpenDirectoryChain(',
  );
  const chainEnd = nativeSource.indexOf(
    'bool ServiceSelfDirectoryChainStable(', chainStart,
  );
  const strictCheck = nativeSource.slice(strictStart, strictEnd);
  const ancestorCheck = nativeSource.slice(strictEnd, ancestorEnd);
  const chain = nativeSource.slice(chainStart, chainEnd);
  assert.notEqual(strictStart, -1);
  assert.notEqual(strictEnd, -1);
  assert.notEqual(ancestorEnd, -1);
  assert.match(strictCheck, /FILE_APPEND_DATA/);
  assert.match(strictCheck, /FILE_WRITE_EA/);
  for (const right of [
    'FILE_WRITE_DATA', 'FILE_WRITE_EA', 'FILE_WRITE_ATTRIBUTES',
    'DELETE', 'FILE_DELETE_CHILD', 'WRITE_DAC', 'WRITE_OWNER',
  ]) assert.match(ancestorCheck, new RegExp(right));
  assert.doesNotMatch(ancestorCheck, /FILE_APPEND_DATA/);
  assert.match(chain, /ServiceSelfDenyCurrentAncestorTakeoverAccess\(current\)/);
  assert.match(chain, /ServiceSelfDenyCurrentWriteAccess\(next, true\)/);
});

test('self-observation capabilities are role-free and excluded from the service facade', () => {
  const names = [
    'read_win32_boot_clock',
    'observe_self_process_epoch',
    'read_self_service_config',
  ];
  assert.deepEqual(selfObservationCapabilities, names);
  for (const name of names) {
    assert.deepEqual(capabilitySignatures[name], []);
    assert.equal(serviceCapabilities.includes(name), false);
  }
});
