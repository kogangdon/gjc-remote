import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import Module from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import test from 'node:test';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';
import {
  capabilities,
  capabilitySignatures,
  contractRevision,
} from '../src/capabilities.js';

const nativeRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sharedRoot = join(nativeRoot, '..', 'shared');
const bootstrapSource = readFileSync(
  join(nativeRoot, 'src', 'service-bootstrap-native.js'), 'utf8',
);
const addonFixtureBytes = Buffer.from('isolated native test image');

function pinnedManifest(addonBytes) {
  return {
    contractVersion: 5,
    contractRevision,
    package: '@gjc-remote/native-control',
    version: JSON.parse(readFileSync(join(nativeRoot, 'package.json'), 'utf8')).version,
    napi: 8,
    platform: process.platform,
    arch: process.arch,
    addon: 'native_control.node',
    sha256: createHash('sha256').update(addonBytes).digest('hex'),
    capabilities,
    capabilitySignatures,
  };
}

async function createHarness(t) {
  const installation = await createPinnedDeploymentInstallation({
    keyIds: ['bootstrap-fixture'],
    includeNativeProvenance: true,
  });
  t.after(() => installation.dispose());
  const root = mkdtempSync(join(tmpdir(), 'gjc-bootstrap-native-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const packageRoot = join(root, 'native-control');
  const sourceRoot = join(packageRoot, 'src');
  const releaseRoot = join(packageRoot, 'build', 'Release');
  const releaseKeysRoot = join(packageRoot, 'release-keys');
  const sharedPackageRoot = join(root, 'node_modules', '@gjc-remote', 'shared');
  mkdirSync(sourceRoot, { recursive: true });
  mkdirSync(releaseRoot, { recursive: true });
  mkdirSync(releaseKeysRoot, { recursive: true });
  mkdirSync(sharedPackageRoot, { recursive: true });
  for (const name of [
    'service-bootstrap-native.js',
    'native-provenance.js',
    'capabilities.js',
  ]) {
    copyFileSync(join(nativeRoot, 'src', name), join(sourceRoot, name));
  }
  copyFileSync(join(nativeRoot, 'package.json'), join(packageRoot, 'package.json'));
  copyFileSync(join(sharedRoot, 'strict-json.js'),
    join(sharedPackageRoot, 'strict-json.js'));
  writeFileSync(join(sharedPackageRoot, 'package.json'), JSON.stringify({
    name: '@gjc-remote/shared',
    type: 'module',
    exports: { './strict-json': './strict-json.js' },
  }));

  const trustedPath = join(releaseKeysRoot, 'trusted.json');
  writeFileSync(trustedPath, installation.bundledNativeTrustBytes);
  writeFileSync(join(releaseKeysRoot, 'local-dev.json'), '{ malformed decoy');

  const manifestBytes = Buffer.from(JSON.stringify(pinnedManifest(addonFixtureBytes)));
  const signatureBytes = installation.signNativeManifest(manifestBytes);
  const manifestPath = join(releaseRoot, 'native-control.manifest.json');
  const signaturePath = `${manifestPath}.sig`;
  const addonPath = join(releaseRoot, 'native_control.node');
  writeFileSync(manifestPath, manifestBytes);
  writeFileSync(signaturePath, signatureBytes);
  writeFileSync(addonPath, addonFixtureBytes);

  const addonContract = {
    contractVersion: 5,
    contractRevision,
    napi: 8,
    capabilities,
    capabilitySignatures,
  };
  const calls = [];
  const nativeAddon = Object.create(null);
  Object.defineProperties(nativeAddon, {
    native_control_contract: {
      value: () => addonContract,
      enumerable: true,
    },
    read_self_service_config: {
      value: () => (calls.push('config'), { schemaVersion: 1 }),
      enumerable: true,
    },
    observe_self_process_epoch: {
      value: () => (calls.push('epoch'), { writes: 0 }),
      enumerable: true,
    },
    forbidden_host_capability: {
      value: () => { throw new Error('must not be projected'); },
      enumerable: true,
    },
  });
  for (const name of capabilities) {
    if (Object.hasOwn(nativeAddon, name)) continue;
    Object.defineProperty(nativeAddon, name, {
      value: () => assert.fail(`bootstrap must not invoke ${name}`),
      enumerable: true,
      configurable: true,
    });
  }
  const previousNativeLoader = Module._extensions['.node'];
  let nativeLoads = 0;
  Module._extensions['.node'] = (module, filename) => {
    if (filename !== addonPath) throw new Error('unexpected native path');
    nativeLoads += 1;
    module.exports = nativeAddon;
  };
  let restored = false;
  const restore = () => {
    if (restored) return;
    restored = true;
    if (previousNativeLoader) Module._extensions['.node'] = previousNativeLoader;
    else delete Module._extensions['.node'];
  };
  t.after(restore);

  return {
    addonPath,
    calls,
    manifestPath,
    nativeAddon,
    nativeLoads: () => nativeLoads,
    packagePath: join(packageRoot, 'package.json'),
    restore,
    signaturePath,
    trustedPath,
    moduleUrl: pathToFileURL(
      join(sourceRoot, 'service-bootstrap-native.js'),
    ).href,
    installation,
  };
}

async function importHarness(harness) {
  return import(harness.moduleUrl);
}

function assertRefused(action) {
  assert.throws(action, (error) => {
    assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
    assert.equal(error.operation, 'create_service_bootstrap_native');
    assert.equal(error.reason, 'production-native-addon-unverified');
    assert.equal(error.writes, 0);
    assert.equal(error.ambiguous, false);
    assert.equal(/(?:[A-Za-z]:\\|\/tmp\/|\.env)/.test(error.message), false);
    return true;
  });
}

test('bootstrap loader is fixed-input and verifies signed metadata and addon bytes before require', () => {
  const start = bootstrapSource.indexOf('function loadProductionAddon()');
  const end = bootstrapSource.indexOf(
    'export function createServiceBootstrapNative()', start,
  );
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const loader = bootstrapSource.slice(start, end);
  const verifier = loader.indexOf('verifyPinnedNativeBuildManifest({');
  const addonHash = loader.indexOf(
    'receipt.addonSha256 !== nativeFingerprint(addon.bytes)',
  );
  const requireAddon = loader.indexOf('requireFromPackage(addonPath)');
  assert.notEqual(verifier, -1);
  assert.notEqual(addonHash, -1);
  assert.notEqual(requireAddon, -1);
  assert.equal(verifier < addonHash && addonHash < requireAddon, true);
  assert.match(bootstrapSource, /readStableBytes\(trustPath, trustLimit\)/);
  assert.doesNotMatch(bootstrapSource, /process\.env|process\.cwd|local-dev\.json|NODE_OPTIONS|BUN_OPTIONS/);
  assert.match(bootstrapSource,
    /export function createServiceBootstrapNative\(\)\s*\{\s*if \(arguments\.length !== 0\) refuse\(\);/);
});

test('production bootstrap loader exposes only verified self-observation methods', async (t) => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('production-strict bootstrap native loader is Win32 x64 only');
    return;
  }
  const harness = await createHarness(t);
  const { createServiceBootstrapNative } = await importHarness(harness);
  assert.equal(createServiceBootstrapNative.length, 0);
  const projection = createServiceBootstrapNative();
  assert.deepEqual(Object.keys(projection).sort(), [
    'observeSelfProcessEpoch', 'readSelfServiceConfig',
  ]);
  assert.equal(Object.isFrozen(projection), true);
  assert.deepEqual(projection.readSelfServiceConfig(), { schemaVersion: 1 });
  assert.deepEqual(projection.observeSelfProcessEpoch(), { writes: 0 });
  assert.deepEqual(harness.calls, ['config', 'epoch']);
  assert.equal(harness.nativeLoads(), 1);
  assertRefused(() => createServiceBootstrapNative(() => harness));
  assert.equal(harness.nativeLoads(), 1);
});

test('production bootstrap loader refuses signed native 1.0.0 contract-4 metadata before addon load', async (t) => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('production-strict bootstrap native loader is Win32 x64 only');
    return;
  }
  const harness = await createHarness(t);
  const legacyPackage = JSON.parse(readFileSync(harness.packagePath, 'utf8'));
  legacyPackage.version = '1.0.0';
  legacyPackage.nativeControlContract = {
    version: 4,
    revision: 4,
    napi: 8,
    platforms: ['linux-x64', 'linux-arm64', 'win32-x64'],
  };
  writeFileSync(harness.packagePath, JSON.stringify(legacyPackage));
  const legacyManifestBytes = Buffer.from(JSON.stringify({
    contractVersion: 4,
    contractRevision: 4,
    package: legacyPackage.name,
    version: legacyPackage.version,
    napi: 8,
    platform: process.platform,
    arch: process.arch,
    addon: 'native_control.node',
    sha256: createHash('sha256').update(addonFixtureBytes).digest('hex'),
    capabilities,
    capabilitySignatures,
  }));
  writeFileSync(harness.manifestPath, legacyManifestBytes);
  writeFileSync(harness.signaturePath, harness.installation.signNativeManifest(legacyManifestBytes));

  const { createServiceBootstrapNative } = await importHarness(harness);
  assertRefused(() => createServiceBootstrapNative());
  assert.equal(harness.nativeLoads(), 0);
});

test('bootstrap loader rejects incomplete and accessor-backed addon exports', async (t) => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('production-strict bootstrap native loader is Win32 x64 only');
    return;
  }
  const harness = await createHarness(t);
  const { createServiceBootstrapNative } = await importHarness(harness);
  assert.equal(delete harness.nativeAddon.read_boot_id, true);
  assertRefused(() => createServiceBootstrapNative());
  let getterCalls = 0;
  Object.defineProperty(harness.nativeAddon, 'read_boot_id', {
    get() { getterCalls += 1; return () => 'untrusted'; },
    enumerable: true,
    configurable: true,
  });
  assertRefused(() => createServiceBootstrapNative());
  assert.equal(getterCalls, 0);
  assert.deepEqual(harness.calls, []);
});

test('production bootstrap loader refuses empty pins despite a local-dev decoy', async (t) => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('production-strict bootstrap native loader is Win32 x64 only');
    return;
  }
  const harness = await createHarness(t);
  writeFileSync(harness.trustedPath, JSON.stringify({ version: 1, keys: [] }));
  const { createServiceBootstrapNative } = await importHarness(harness);
  assertRefused(() => createServiceBootstrapNative());
  assert.equal(harness.nativeLoads(), 0);
});

test('production bootstrap loader refuses dirty production pins before native load', async (t) => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('production-strict bootstrap native loader is Win32 x64 only');
    return;
  }
  const harness = await createHarness(t);
  const impostor = await createPinnedDeploymentInstallation({
    keyIds: ['foreign-bootstrap-fixture'],
    includeNativeProvenance: true,
  });
  t.after(() => impostor.dispose());
  writeFileSync(harness.trustedPath, impostor.bundledNativeTrustBytes);
  const { createServiceBootstrapNative } = await importHarness(harness);
  assertRefused(() => createServiceBootstrapNative());
  assert.equal(harness.nativeLoads(), 0);
});

test('tampered signed-addon bytes are refused before require can execute them', async (t) => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('production-strict bootstrap native loader is Win32 x64 only');
    return;
  }
  const harness = await createHarness(t);
  writeFileSync(harness.addonPath, Buffer.from('tampered executable fixture'));
  const { createServiceBootstrapNative } = await importHarness(harness);
  assertRefused(() => createServiceBootstrapNative());
  assert.equal(harness.nativeLoads(), 0);
});

test('invalid manifest signature cannot trigger native preload execution', async (t) => {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    t.skip('production-strict bootstrap native loader is Win32 x64 only');
    return;
  }
  const harness = await createHarness(t);
  const signature = JSON.parse(readFileSync(harness.signaturePath, 'utf8'));
  writeFileSync(harness.signaturePath, JSON.stringify({
    ...signature,
    signature: Buffer.alloc(64, 0).toString('base64'),
  }));
  const { createServiceBootstrapNative } = await importHarness(harness);
  assertRefused(() => createServiceBootstrapNative());
  assert.equal(harness.nativeLoads(), 0);
});
