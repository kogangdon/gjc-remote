import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { basename, dirname, join, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import {
  capabilities,
  capabilitySignatures,
  contractRevision,
} from '../src/capabilities.js';
import {
  createPinnedDeploymentInstallation,
} from '../test-fixtures/pinned-deployment-installation.mjs';

// This suite never invokes Bun, Git, a registry, native code, or a service.
// Its addon/manifest are inert synthetic bytes used only to reach and prove the
// harness's final source-membership fence through the exact fixture modules.
const require = createRequire(import.meta.url);
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fsPromises = require('node:fs/promises');
const originalSpawn = childProcess.spawn;
const originalGenerateKeyPairSync = crypto.generateKeyPairSync;
const originalMkdir = fsPromises.mkdir;
const originalMkdtemp = fsPromises.mkdtemp;
const originalRealpath = fsPromises.realpath;
const productRoot = fileURLToPath(new URL('../..', import.meta.url));
const ACKNOWLEDGEMENT_FLAG = '--acknowledge-real-bun-fixture-build';

function copyRegular(source, destination, mode = undefined) {
  const stat = lstatSync(source);
  assert.equal(stat.isFile(), true, `expected regular source file: ${source}`);
  assert.equal(stat.isSymbolicLink(), false, `refuse source link: ${source}`);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination);
  chmodSync(destination, mode ?? ((stat.mode & 0o111) === 0 ? 0o644 : 0o755));
}

function excludedSourcePath(relativePath) {
  return /(?:^|[\\/])tests?(?:[\\/]|$)/i.test(relativePath) ||
    /\.(?:test|spec)\.[^./\\]+$/i.test(relativePath);
}

function copySourceDirectory(source, destination, relativePath = '') {
  const stat = lstatSync(source);
  assert.equal(stat.isDirectory(), true, `expected source directory: ${source}`);
  assert.equal(stat.isSymbolicLink(), false, `refuse source directory link: ${source}`);
  mkdirSync(destination, { recursive: true });
  const entries = readdirSync(source, { withFileTypes: true })
    .sort((left, right) => Buffer.compare(
      Buffer.from(left.name, 'utf8'),
      Buffer.from(right.name, 'utf8'),
    ));
  for (const entry of entries) {
    const nextRelative = relativePath.length === 0
      ? entry.name
      : `${relativePath}/${entry.name}`;
    const sourcePath = join(source, entry.name);
    const destinationPath = join(destination, entry.name);
    assert.equal(entry.isSymbolicLink(), false, `refuse source link: ${sourcePath}`);
    assert.equal(
      entry.isDirectory() || entry.isFile(),
      true,
      `refuse special source entry: ${sourcePath}`,
    );
    if (excludedSourcePath(nextRelative)) continue;
    if (entry.isDirectory()) {
      copySourceDirectory(sourcePath, destinationPath, nextRelative);
    } else {
      copyRegular(sourcePath, destinationPath);
    }
  }
}

function fixtureRootFor(installation) {
  const builderPath = fileURLToPath(installation.releaseBuilderUrl);
  return dirname(dirname(dirname(builderPath)));
}

function populateExactSyntheticSource(root) {
  for (const name of ['package.json', 'bun.lock']) {
    copyRegular(join(productRoot, name), join(root, name), 0o644);
  }
  copyRegular(
    join(productRoot, 'deploy', 'native', 'release-contract.json'),
    join(root, 'deploy', 'native', 'release-contract.json'),
    0o644,
  );
  for (const workspace of ['bot', 'daemon', 'native-control']) {
    copyRegular(
      join(productRoot, workspace, 'package.json'),
      join(root, workspace, 'package.json'),
      0o644,
    );
    copySourceDirectory(
      join(productRoot, workspace, 'src'),
      join(root, workspace, 'src'),
    );
  }
  copyRegular(
    join(productRoot, 'shared', 'package.json'),
    join(root, 'shared', 'package.json'),
    0o644,
  );
  for (const entry of readdirSync(join(productRoot, 'shared'), {
    withFileTypes: true,
  }).sort((left, right) => Buffer.compare(
    Buffer.from(left.name, 'utf8'),
    Buffer.from(right.name, 'utf8'),
  ))) {
    if (!entry.name.endsWith('.js')) continue;
    assert.equal(entry.isFile(), true);
    assert.equal(entry.isSymbolicLink(), false);
    copyRegular(
      join(productRoot, 'shared', entry.name),
      join(root, 'shared', entry.name),
    );
  }

  const fixtureDirectory = join(root, 'native-control', 'test-fixtures');
  mkdirSync(fixtureDirectory, { recursive: true });
  copyRegular(
    join(productRoot, 'native-control', 'test-fixtures',
      'pinned-deployment-installation.mjs'),
    join(fixtureDirectory, 'pinned-deployment-installation.mjs'),
    0o644,
  );
  copyRegular(
    join(productRoot, 'native-control', 'test-fixtures',
      'service-release-real-bun.mjs'),
    join(fixtureDirectory, 'service-release-real-bun.mjs'),
    0o644,
  );

  // Model the current production-input disposition: deployment pins absent.
  // The enclosing exact-source fixture retains independent native public pins.
  for (const deploymentTrustName of ['application-trusted.json', 'shawl-trusted.json']) {
    const deploymentTrust = join(
      root,
      'native-control',
      'deployment-keys',
      deploymentTrustName,
    );
    assert.equal(existsSync(deploymentTrust), true);
    unlinkSync(deploymentTrust);
  }

  const addonBytes = Buffer.from(
    'synthetic inert addon bytes; never loaded or executed\n',
    'utf8',
  );
  const manifestBytes = canonicalJsonBytes({
    contractVersion: 5,
    contractRevision,
    package: '@gjc-remote/native-control',
    version: '2.0.0',
    napi: 8,
    platform: process.platform,
    arch: process.arch,
    addon: 'native_control.node',
    sha256: createHash('sha256').update(addonBytes).digest('hex'),
    capabilities,
    capabilitySignatures,
  });
  const releaseDirectory = join(root, 'native-control', 'build', 'Release');
  mkdirSync(releaseDirectory, { recursive: true });
  writeFileSync(join(releaseDirectory, 'native_control.node'), addonBytes, {
    mode: 0o755,
  });
  writeFileSync(
    join(releaseDirectory, 'native-control.manifest.json'),
    manifestBytes,
    { mode: 0o644 },
  );
  return join(fixtureDirectory, 'service-release-real-bun.mjs');
}

function installNoProcessBoundary(t, sourceRoot) {
  const ownedRoots = [];
  let spawnCalls = 0;
  let keyGenerationCalls = 0;
  let realpathCalls = 0;
  let mkdirCalls = 0;
  let mkdtempCalls = 0;
  let injected = false;

  const spawnMock = t.mock.method(childProcess, 'spawn', () => {
    spawnCalls += 1;
    throw new Error('MODELED_PROCESS_BOUNDARY_REFUSED');
  });
  const keyMock = t.mock.method(crypto, 'generateKeyPairSync', (...args) => {
    keyGenerationCalls += 1;
    return Reflect.apply(originalGenerateKeyPairSync, crypto, args);
  });
  const realpathMock = t.mock.method(fsPromises, 'realpath', async (...args) => {
    realpathCalls += 1;
    return Reflect.apply(originalRealpath, fsPromises, args);
  });
  const mkdtempMock = t.mock.method(fsPromises, 'mkdtemp', async (...args) => {
    mkdtempCalls += 1;
    const created = await Reflect.apply(originalMkdtemp, fsPromises, args);
    if (String(args[0]).includes('gjc-real-bun-release-fixture-')) {
      ownedRoots.push(resolve(created));
    }
    return created;
  });
  const mkdirMock = t.mock.method(fsPromises, 'mkdir', async (...args) => {
    mkdirCalls += 1;
    const [path, options] = args;
    if (!injected && typeof path === 'string' &&
        basename(path) === 'source' && options?.recursive === false &&
        dirname(path).includes('gjc-real-bun-release-fixture-')) {
      injected = true;
      const latePath = join(sourceRoot, 'bot', 'src', 'late-eligible.js');
      assert.equal(existsSync(latePath), false);
      writeFileSync(
        latePath,
        'export const lateEligible = true;\n',
        { mode: 0o644 },
      );
      const error = new Error('MODELED_POST_CAPTURE_SOURCE_CHANGE');
      error.code = 'EACCES';
      throw error;
    }
    return Reflect.apply(originalMkdir, fsPromises, args);
  });
  syncBuiltinESMExports();

  return {
    snapshot() {
      return Object.freeze({
        spawnCalls,
        keyGenerationCalls,
        realpathCalls,
        mkdirCalls,
        mkdtempCalls,
        ownedRootCount: ownedRoots.length,
      });
    },
    get injected() { return injected; },
    get ownedRoots() { return [...ownedRoots]; },
    restore() {
      mkdirMock.mock.restore();
      mkdtempMock.mock.restore();
      realpathMock.mock.restore();
      keyMock.mock.restore();
      spawnMock.mock.restore();
      syncBuiltinESMExports();
      assert.equal(childProcess.spawn, originalSpawn);
    },
  };
}

function errorCode(expected) {
  return (error) => {
    assert.equal(error?.name, 'RealBunFixtureError');
    assert.equal(error?.code, expected);
    assert.equal(error?.message, expected);
    assert.equal(error?.cause, undefined);
    assert.ok(Buffer.byteLength(error.message, 'utf8') < 128);
    return true;
  };
}

test('real-Bun evidence harness refuses no acknowledgement and detects newly eligible selected source membership', async (t) => {
  assert.equal(
    ['win32:x64', 'linux:x64', 'linux:arm64'].includes(
      `${process.platform}:${process.arch}`,
    ),
    true,
    'the source-fence fixture requires a supported host tuple',
  );
  const installation = await createPinnedDeploymentInstallation({
    keyIds: ['deployment-test'],
    includeReleaseBuilder: true,
  });
  let boundary = null;
  try {
    const root = fixtureRootFor(installation);
    const harnessPath = populateExactSyntheticSource(root);
    boundary = installNoProcessBoundary(t, root);
    const harness = await import(
      `${pathToFileURL(harnessPath).href}?source-membership=${Date.now()}`
    );
    assert.equal(
      typeof harness.runServiceReleaseRealBunEvidence,
      'function',
    );

    const beforeAcknowledgement = boundary.snapshot();
    await assert.rejects(
      harness.runServiceReleaseRealBunEvidence(),
      errorCode(
        'SERVICE_RELEASE_REAL_BUN_FIXTURE_ACKNOWLEDGEMENT_REQUIRED',
      ),
    );
    assert.deepEqual(boundary.snapshot(), beforeAcknowledgement);

    await assert.rejects(
      harness.runServiceReleaseRealBunEvidence([ACKNOWLEDGEMENT_FLAG]),
      errorCode('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED'),
    );
    assert.equal(boundary.injected, true);
    assert.equal(boundary.snapshot().spawnCalls, 0);
    assert.ok(
      boundary.snapshot().keyGenerationCalls > 0,
      'the exact helper was reached only after explicit acknowledgement',
    );
    assert.equal(
      existsSync(join(root, 'bot', 'src', 'late-eligible.js')),
      true,
      'the membership change is confined to the owned synthetic source',
    );
    assert.ok(boundary.ownedRoots.length > 0);
    for (const ownedRoot of boundary.ownedRoots) {
      assert.equal(
        existsSync(ownedRoot),
        false,
        'the identity-validated harness root is cleaned after refusal',
      );
    }
  } finally {
    boundary?.restore();
    installation.dispose();
  }
});
