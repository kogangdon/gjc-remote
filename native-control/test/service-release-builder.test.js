import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { readFile, realpath } from 'node:fs/promises';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, sep } from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { canonicalJsonBytes, parseCanonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import { applicationDeploymentManifestFingerprint } from '@gjc-remote/shared/deployment-envelope';
import { capabilities, capabilitySignatures, contractRevision } from '../src/capabilities.js';
import { consumeApplicationArchive, inspectApplicationArchive } from '../src/service-archive.js';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';

const require = createRequire(import.meta.url);
const childProcess = require('node:child_process');
const fsPromises = require('node:fs/promises');
const originalSpawn = childProcess.spawn;
const execFileSync = childProcess.execFileSync;
const spawnSync = childProcess.spawnSync;
const FIXED_REMOTE = 'https://github.com/kogangdon/gjc-remote.git';
const POSITIVE_PLATFORM = process.platform === 'win32' ? 'win32' : 'linux';
const POSITIVE_ARCHITECTURE = process.platform === 'win32'
  ? 'x64'
  : process.arch === 'arm64' ? 'arm64' : 'x64';
const OTHER_PLATFORM = POSITIVE_PLATFORM === 'win32' ? 'linux' : 'win32';
const OTHER_ARCHITECTURE = POSITIVE_ARCHITECTURE === 'arm64' ? 'x64' : 'arm64';
const TARGET_SUFFIX = `${POSITIVE_PLATFORM}-${POSITIVE_ARCHITECTURE}`;
const ARCHIVE_NAME = `gjc-remote-service-0.4.0-rc.1-${TARGET_SUFFIX}.tar.gz`;
const MANIFEST_NAME = `gjc-remote-service-${TARGET_SUFFIX}.manifest.json`;
const SDK_INTEGRITY = 'sha512-rqhs7FELytNw0zfumqroc5EaVrtEUccGGp4YNpFbycF89o+Q+dzWWof1uRVnZvS+GLzCKR9psWZiDEacJzXY7A==';
const SDK_SOURCE_CONTRACT_DOMAIN = 'gjc-remote/sdk-external-state-source/v1';
const SDK_ROOT_IDENTITY = '@gajae-code/coding-agent@0.16.7';
const SDK_SOURCES = Object.freeze({
  settings: Object.freeze({
    path: 'src/config/settings.ts',
    bytes: Buffer.from('export const settingsContract = 1;\n'),
  }),
  model: Object.freeze({
    path: 'src/config/model-registry.ts',
    bytes: Buffer.from('export const modelContract = 1;\n'),
  }),
  auth: Object.freeze({
    path: 'src/session/auth-storage.ts',
    bytes: Buffer.from('export const authContract = 1;\n'),
  }),
  session: Object.freeze({
    path: 'src/session/session-manager.ts',
    bytes: Buffer.from('export const CURRENT_SESSION_VERSION = 5;\n'),
  }),
});
const LONG_UTF8_RESOURCE = `resources/${'검증'.repeat(40)}.dat`;
const fakeSri = (byte) => `sha512-${Buffer.alloc(64, byte).toString('base64')}`;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function expectedSdkSourceFingerprint(domain, closureFingerprint) {
  const source = SDK_SOURCES[domain];
  return createHash('sha256')
    .update(`${SDK_SOURCE_CONTRACT_DOMAIN}/${domain}`, 'utf8')
    .update(Buffer.from([0]))
    .update(canonicalJsonBytes({
      rootIdentity: SDK_ROOT_IDENTITY,
      sourcePath: source.path,
      sourceSha256: sha256(source.bytes),
      closureFingerprint,
    }))
    .digest('hex');
}

function write(path, bytes, mode = 0o644) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes, { mode });
  chmodSync(path, mode);
}

function writeJson(path, value) {
  write(path, `${JSON.stringify(value, null, 2)}\n`);
}

function writeMarkerCommand(root, name, markerPath) {
  const commandPath = join(
    root,
    process.platform === 'win32' ? `${name}.cmd` : name,
  );
  if (process.platform === 'win32') {
    write(
      commandPath,
      `@echo off\r\n> ${JSON.stringify(markerPath)} echo executed\r\nexit /b 1\r\n`,
      0o755,
    );
  } else {
    write(
      commandPath,
      `#!/bin/sh\nprintf executed > ${JSON.stringify(markerPath)}\nexit 1\n`,
      0o755,
    );
  }
  return commandPath;
}

function packageModels({
  caseNativeAlias = false,
  caseNativePackage = caseNativeAlias,
  sdkOptionalPeer = false,
  debugSynthesis = false,
  edgeSpecifier = null,
  edgeLockPackages = [],
  targetPlatform = POSITIVE_PLATFORM,
  targetArchitecture = POSITIVE_ARCHITECTURE,
} = {}) {
  const models = {
    bot: {
      name: '@gjc-remote/bot', version: '0.4.0-rc.1', private: true, type: 'module',
      dependencies: {
        '@gjc-remote/native-control': '*',
        '@gjc-remote/shared': '0.4.0-rc.1',
        'fixture-consumer': '1.0.0',
      },
    },
    daemon: {
      name: '@gjc-remote/daemon', version: '0.4.0-rc.1', private: true, type: 'module',
      dependencies: {
        '@gajae-code/coding-agent': '0.16.7',
        '@gjc-remote/native-control': '*',
        '@gjc-remote/shared': '0.4.0-rc.1',
      },
    },
    native: {
      name: '@gjc-remote/native-control', version: '1.0.0', private: true, type: 'module',
      nativeControlContract: {
        version: 4,
        revision: 4,
        napi: 8,
        platforms: ['linux-x64', 'linux-arm64', 'win32-x64'],
      },
      dependencies: { '@gjc-remote/shared': '0.4.0-rc.1', tar: '7.5.22' },
    },
    shared: { name: '@gjc-remote/shared', version: '0.4.0-rc.1', private: true, type: 'module' },
    consumer: {
      name: 'fixture-consumer', version: '1.0.0', type: 'module',
      dependencies: { '@gjc-remote/native-control': '*' },
      optionalDependencies: { 'fixture-target': '1.0.0' },
    },
    target: {
      name: 'fixture-target', version: '1.0.0', type: 'module',
      os: [targetPlatform], cpu: [targetArchitecture],
    },
    sdk: {
      name: '@gajae-code/coding-agent', version: '0.16.7', type: 'module',
      dependencies: { 'fixture-sdk-leaf': '1.0.0' },
      ...(sdkOptionalPeer ? {
        peerDependencies: { 'fixture-optional-peer': '^1.0.0' },
        peerDependenciesMeta: {
          'fixture-optional-peer': { optional: true },
        },
      } : {}),
    },
    sdkLeaf: { name: 'fixture-sdk-leaf', version: '1.0.0', type: 'module' },
    optionalPeer: {
      name: 'fixture-optional-peer',
      version: '1.0.0',
      type: 'module',
    },
    tar: { name: 'tar', version: '7.5.22', type: 'module' },
  };
  if (caseNativeAlias) {
    models.consumer.dependencies['@GJC-REMOTE/native-control'] = '1.0.0';
  }
  if (edgeSpecifier !== null) {
    models.consumer.dependencies['fixture-edge'] = edgeSpecifier;
    models.edgeLockPackages = edgeLockPackages.length > 0
      ? edgeLockPackages.map((record) => ({ ...record }))
      : [{ name: 'fixture-edge', version: '1.0.0' }];
  }
  if (caseNativePackage) {
    models.caseNative = {
      name: '@GJC-REMOTE/native-control',
      version: '1.0.0',
      type: 'module',
    };
  }
  if (debugSynthesis) {
    models.consumer.dependencies['fixture-debug'] = '1.0.0';
    // Mirrors Bun's real lock normalization: the published package.json ships
    // only peerDependenciesMeta; the frozen lock carries the registry's
    // peerDependencies plus optionalPeers (observed with debug@4.4.3).
    models.debug = {
      name: 'fixture-debug', version: '1.0.0', type: 'module',
      peerDependenciesMeta: { 'fixture-peer-optional': { optional: true } },
    };
    models.debugLock = {
      peerDependencies: { 'fixture-peer-optional': '*' },
      optionalPeers: ['fixture-peer-optional'],
    };
  }
  return models;
}

function bunLock(models = packageModels(), {
  sdkIntegrity = SDK_INTEGRITY,
} = {}) {
  const lock = {
    lockfileVersion: 1,
    configVersion: 0,
    workspaces: {
      '': {
        name: 'gjc-remote',
        version: '0.4.0-rc.1',
        devDependencies: { 'jsonc-parser': '3.3.1' },
      },
      bot: { name: models.bot.name, version: models.bot.version, dependencies: models.bot.dependencies },
      daemon: { name: models.daemon.name, version: models.daemon.version, dependencies: models.daemon.dependencies },
      'native-control': { name: models.native.name, version: models.native.version, dependencies: models.native.dependencies },
      shared: { name: models.shared.name, version: models.shared.version },
    },
    packages: {
      '@gjc-remote/bot': ['@gjc-remote/bot@workspace:bot'],
      '@gjc-remote/daemon': ['@gjc-remote/daemon@workspace:daemon'],
      '@gjc-remote/native-control': ['@gjc-remote/native-control@workspace:native-control'],
      '@gjc-remote/shared': ['@gjc-remote/shared@workspace:shared'],
      '@gajae-code/coding-agent': [
        '@gajae-code/coding-agent@0.16.7', '',
        {
          dependencies: models.sdk.dependencies,
          ...(models.sdk.peerDependencies ? {
            peerDependencies: models.sdk.peerDependencies,
            optionalPeers: ['fixture-optional-peer'],
          } : {}),
        }, sdkIntegrity,
      ],
      'fixture-consumer': [
        'fixture-consumer@1.0.0', '',
        { dependencies: models.consumer.dependencies, optionalDependencies: models.consumer.optionalDependencies }, fakeSri(1),
      ],
      'fixture-sdk-leaf': ['fixture-sdk-leaf@1.0.0', '', {}, fakeSri(2)],
      ...(models.sdk.peerDependencies ? {
        'fixture-optional-peer': [
          'fixture-optional-peer@1.0.0', '', {}, fakeSri(6),
        ],
      } : {}),
      'fixture-target': [
        'fixture-target@1.0.0', '',
        { os: models.target.os[0], cpu: models.target.cpu[0] }, fakeSri(3),
      ],
      tar: ['tar@7.5.22', '', {}, fakeSri(4)],
      ...(models.debug ? {
        'fixture-debug': ['fixture-debug@1.0.0', '', { ...models.debugLock }, fakeSri(7)],
      } : {}),
      ...(models.caseNative ? {
        '@GJC-REMOTE/native-control': [
          '@GJC-REMOTE/native-control@1.0.0', '', {}, fakeSri(5),
        ],
      } : {}),
      ...Object.fromEntries((models.edgeLockPackages ?? []).map(
        ({ key = null, name, version }, index) => [
          key ?? (index === 0 ? name : `${name}@${version}#${index}`),
          [`${name}@${version}`, '', {}, fakeSri(10 + index)],
        ],
      )),
    },
  };
  const json = JSON.stringify(lock, null, 2);
  return Buffer.from(`// Bun text lock fixture: comments and the final trailing comma are intentional.\n${json.replace(/\n}$/, ',\n}\n')}`);
}

function git(source, args, env = {}) {
  return execFileSync('git', args, {
    cwd: source,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Service Release Fixture',
      GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Service Release Fixture',
      GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function createSourceRepository(root, installation, {
  mutablePath = false,
  commitAfterTag = false,
  models = packageModels(),
  lockBytes = bunLock(models),
  nativeTrustBytes = installation.bundledNativeTrustBytes,
  applicationTrustBytes = installation.bundledApplicationTrustBytes,
  shawlTrustBytes = installation.bundledShawlTrustBytes,
  mutateSource,
} = {}) {
  const source = join(root, 'source');
  mkdirSync(source, { recursive: true });
  writeJson(join(source, 'package.json'), {
    name: 'gjc-remote', version: '0.4.0-rc.1', private: true, type: 'module',
    workspaces: ['bot', 'daemon', 'native-control', 'shared'],
    devDependencies: { 'jsonc-parser': '3.3.1' },
  });
  write(join(source, 'bun.lock'), lockBytes);
  writeJson(join(source, 'bot/package.json'), models.bot);
  write(join(source, 'bot/src/bot.js'), 'export const botFixture = true;\n');
  writeJson(join(source, 'daemon/package.json'), models.daemon);
  write(join(source, 'daemon/src/daemon.js'), 'export const daemonFixture = true;\n');
  writeJson(join(source, 'native-control/package.json'), models.native);
  write(join(source, 'native-control/src/public.js'), 'export const nativeFixture = true;\n');
  write(join(source, 'native-control/release-keys/trusted.json'), nativeTrustBytes);
  write(
    join(source, 'native-control/deployment-keys/application-trusted.json'),
    applicationTrustBytes,
  );
  write(
    join(source, 'native-control/deployment-keys/shawl-trusted.json'),
    shawlTrustBytes,
  );
  writeJson(join(source, 'shared/package.json'), models.shared);
  write(join(source, 'shared/protocol.js'), 'export const PROTOCOL_VERSION = 3;\n');
  write(join(source, 'shared/resource.js'), 'export const resource = "complete";\n');
  write(join(source, 'bot/test/not-production.test.js'), 'throw new Error("must not ship");\n');
  write(join(source, 'native-control/src/not-production.test.js'), 'throw new Error("must not ship");\n');
  write(join(source, 'native-control/README.md'), 'not a selected production root\n');
  if (mutablePath) write(join(source, 'bot/src/.env/secret'), 'must-not-ship\n');
  mutateSource?.({ source, models });

  git(source, ['init', '--initial-branch=main']);
  git(source, ['remote', 'add', 'origin', FIXED_REMOTE]);
  git(source, ['add', '--all']);
  git(source, ['commit', '--no-gpg-sign', '-m', 'fixture release source'], {
    GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z',
    GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z',
  });
  git(source, ['tag', 'v0.4.0-rc.1']);
  if (commitAfterTag) {
    write(join(source, 'shared/later.js'), 'export const later = true;\n');
    git(source, ['add', '--all']);
    git(source, ['commit', '--no-gpg-sign', '-m', 'commit after release tag'], {
      GIT_AUTHOR_DATE: '2026-01-02T00:00:00Z',
      GIT_COMMITTER_DATE: '2026-01-02T00:00:00Z',
    });
  }
  return { source, models };
}

function createNativeInputs(root, installation, packageJson, {
  addonBytes = Buffer.from('signed native addon fixture\n'),
  writtenAddonBytes = addonBytes,
  emptySignature = false,
  platform = POSITIVE_PLATFORM,
  architecture = POSITIVE_ARCHITECTURE,
  manifestOverrides = {},
  mutateSignature,
} = {}) {
  const nativeRoot = join(root, 'native-input');
  mkdirSync(nativeRoot, { recursive: true });
  const manifest = {
    contractVersion: 4,
    contractRevision,
    package: packageJson.name,
    version: packageJson.version,
    napi: 8,
    platform,
    arch: architecture,
    addon: 'native_control.node',
    sha256: sha256(addonBytes),
    capabilities,
    capabilitySignatures,
    ...manifestOverrides,
  };
  const manifestBytes = canonicalJsonBytes(manifest, {
    maxBytes: 1024 * 1024, maxDepth: 32, maxNodes: 100_000,
  });
  let signatureBytes = emptySignature
    ? Buffer.alloc(0)
    : installation.signNativeManifest(manifestBytes);
  if (mutateSignature) signatureBytes = mutateSignature(signatureBytes);
  write(join(nativeRoot, 'native_control.node'), writtenAddonBytes, 0o755);
  write(join(nativeRoot, 'native-control.manifest.json'), manifestBytes);
  write(join(nativeRoot, 'native-control.manifest.json.sig'), signatureBytes);
  return {
    nativeAddonPath: join(nativeRoot, 'native_control.node'),
    nativeManifestPath: join(nativeRoot, 'native-control.manifest.json'),
    nativeSignaturePath: join(nativeRoot, 'native-control.manifest.json.sig'),
  };
}

function linkWorkspace(source, destination) {
  mkdirSync(dirname(destination), { recursive: true });
  symlinkSync(source, destination, process.platform === 'win32' ? 'junction' : 'dir');
}

function materializeModeledProduction(cwd, {
  sdkVersion = '0.16.7',
  sdkSchemaVersion = 2,
  transcriptVersion = 5,
  sdkLeafBytes = 'SDK transitive closure resource\n',
  missingSdkSource = null,
  sdkOptionalPeer = false,
  includeSdkOptionalPeer = false,
  sdkOptionalPeerBytes = 'SDK optional peer resource\n',
  edgeSpecifier = null,
  edgeLockPackages = [],
  installedEdgeName = 'fixture-edge',
  installedEdgeVersion = '1.0.0',
  nestedEdge = false,
  escapeLink = false,
  cycleLink = false,
  aliasDecoy = false,
  aliasMarkerFile = false,
  caseNativeAlias = false,
  caseOnlyRootAlias = false,
  consumerVersion = '1.0.0',
  dependencyCredentials = false,
  debugSynthesis = false,
  omitConsumer = false,
  omitSdkLeaf = false,
  omitTar = false,
  omitTarget = false,
  targetPlatform = POSITIVE_PLATFORM,
  targetArchitecture = POSITIVE_ARCHITECTURE,
} = {}) {
  const models = packageModels({
    caseNativeAlias,
    caseNativePackage: caseOnlyRootAlias || caseNativeAlias,
    sdkOptionalPeer,
    debugSynthesis,
    edgeSpecifier,
    edgeLockPackages,
    targetPlatform,
    targetArchitecture,
  });
  const modules = join(cwd, 'node_modules');
  mkdirSync(modules, { recursive: true });
  if (aliasMarkerFile) {
    write(join(modules, '@gjc-remote/native-control'), 'not a package directory\n');
  } else if (caseOnlyRootAlias) {
    const caseAlias = join(modules, '@GJC-REMOTE/native-control');
    writeJson(join(caseAlias, 'package.json'), models.caseNative);
    write(join(caseAlias, 'index.js'), 'export const caseOnlyAlias = true;\n');
  } else {
    linkWorkspace(join(cwd, 'native-control'), join(modules, '@gjc-remote/native-control'));
  }
  linkWorkspace(join(cwd, 'shared'), join(modules, '@gjc-remote/shared'));
  writeJson(
    join(cwd, 'native-control/node_modules/dependency-only-shadow/package.json'),
    { name: 'dependency-only-shadow', version: '1.0.0' },
  );
  write(
    join(cwd, 'native-control/node_modules/dependency-only-shadow/foreign.js'),
    'export const shadow = true;\n',
  );

  const consumer = join(modules, 'fixture-consumer');
  if (!omitConsumer) {
    writeJson(join(consumer, 'package.json'), {
      ...models.consumer,
      version: consumerVersion,
    });
    write(join(consumer, 'index.js'), 'export const consumer = true;\n');
    write(join(consumer, 'resources/complete.dat'), 'consumer complete production resource\n');
    write(join(consumer, LONG_UTF8_RESOURCE), 'portable long UTF-8 path\n');
    if (dependencyCredentials) {
      write(
        join(consumer, 'lib/credentials/state.js'),
        'export const providerCredentialsState = true;\n',
      );
    }
    const nestedNative = join(consumer, 'node_modules/@gjc-remote/native-control');
    if (aliasDecoy) {
      writeJson(join(nestedNative, 'package.json'), models.native);
      write(join(nestedNative, 'src/public.js'), 'export const decoy = true;\n');
    } else if (!caseNativeAlias) {
      linkWorkspace(join(cwd, 'native-control'), nestedNative);
    }
    if (caseNativeAlias) {
      const caseAlias = join(consumer, 'node_modules/@GJC-REMOTE/native-control');
      writeJson(join(caseAlias, 'package.json'), models.caseNative);
      write(join(caseAlias, 'index.js'), 'export const caseAlias = true;\n');
    }
    if (escapeLink) {
      const outside = join(dirname(cwd), 'outside-link-target');
      mkdirSync(outside, { recursive: true });
      write(join(outside, 'secret.txt'), 'outside\n');
      symlinkSync(outside, join(consumer, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
    }
    if (cycleLink) {
      symlinkSync(consumer, join(consumer, 'cycle'), process.platform === 'win32' ? 'junction' : 'dir');
    }
  }

  if (!omitTarget) {
    const target = join(modules, 'fixture-target');
    writeJson(join(target, 'package.json'), models.target);
    write(join(target, 'target.js'), `export const target = "${targetPlatform}-${targetArchitecture}";\n`);
  }

  const sdk = join(modules, '@gajae-code/coding-agent');
  writeJson(join(sdk, 'package.json'), { ...models.sdk, version: sdkVersion });
  for (const [domain, source] of Object.entries(SDK_SOURCES)) {
    if (domain !== 'session' && missingSdkSource !== domain) {
      write(join(sdk, source.path), source.bytes);
    }
  }
  write(join(sdk, 'src/config/config-schema-version.ts'), `export const CONFIG_SCHEMA_VERSION = ${sdkSchemaVersion};\n`);
  write(join(sdk, 'src/session/session-manager.ts'), `export const CURRENT_SESSION_VERSION = ${transcriptVersion};\n`);
  write(join(sdk, 'resources/complete.dat'), 'entire SDK package artifact is retained\n');

  if (!omitSdkLeaf) {
    const leaf = join(modules, 'fixture-sdk-leaf');
    writeJson(join(leaf, 'package.json'), models.sdkLeaf);
    write(join(leaf, 'resource.txt'), sdkLeafBytes);
  }
  if (includeSdkOptionalPeer) {
    const peer = join(modules, 'fixture-optional-peer');
    writeJson(join(peer, 'package.json'), models.optionalPeer);
    write(join(peer, 'resource.txt'), sdkOptionalPeerBytes);
  }
  if (edgeSpecifier !== null) {
    const edge = nestedEdge
      ? join(consumer, 'node_modules', 'fixture-edge')
      : join(modules, 'fixture-edge');
    writeJson(join(edge, 'package.json'), {
      name: installedEdgeName,
      version: installedEdgeVersion,
      type: 'module',
    });
    write(join(edge, 'index.js'), 'export const edge = true;\n');
  }

  if (!omitTar) {
    const tar = join(modules, 'tar');
    writeJson(join(tar, 'package.json'), models.tar);
    write(join(tar, 'index.js'), 'export const tarFixture = true;\n');
  }
  if (models.debug) {
    const debug = join(modules, 'fixture-debug');
    writeJson(join(debug, 'package.json'), models.debug);
    write(join(debug, 'index.js'), 'export const debugFixture = true;\n');
  }
}

function installModeledBunBoundary(t, options = {}) {
  const calls = [];
  const mocked = t.mock.method(childProcess, 'spawn', (command, args, spawnOptions) => {
    if (command !== 'bun') return originalSpawn(command, args, spawnOptions);
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => {
      queueMicrotask(() => child.emit('close', null, 'SIGKILL'));
      return true;
    };
    calls.push({ args: [...args], cwd: spawnOptions.cwd, env: { ...spawnOptions.env } });
    queueMicrotask(() => {
      try {
        if (args.length === 1 && args[0] === '--version') {
          child.stdout.end('1.4.2\n');
        } else {
          materializeModeledProduction(spawnOptions.cwd, options);
          child.stdout.end('modeled Bun production materialization\n');
        }
        child.stderr.end();
        child.emit('close', 0, null);
      } catch (error) {
        child.stderr.end('modeled materialization failure\n');
        child.stdout.end();
        child.emit('close', 1, null);
      }
    });
    return child;
  });
  syncBuiltinESMExports();
  return {
    evidenceScope: 'modeled-external-bun-process-no-network-or-sri-proof',
    calls,
    restore() {
      mocked.mock.restore();
      syncBuiltinESMExports();
    },
  };
}

function installFsPromisesBoundary(t, {
  beforeLstat = () => {},
  observeOpen = () => {},
} = {}) {
  const originalLstat = fsPromises.lstat;
  const originalOpen = fsPromises.open;
  const lstatMock = t.mock.method(
    fsPromises,
    'lstat',
    async (...args) => {
      beforeLstat(...args);
      return Reflect.apply(originalLstat, fsPromises, args);
    },
  );
  const openMock = t.mock.method(
    fsPromises,
    'open',
    async (...args) => {
      observeOpen(...args);
      return Reflect.apply(originalOpen, fsPromises, args);
    },
  );
  syncBuiltinESMExports();
  return {
    restore() {
      openMock.mock.restore();
      lstatMock.mock.restore();
      syncBuiltinESMExports();
    },
  };
}

async function inputFor(
  root,
  source,
  native,
  outputName = 'candidate-a',
  {
    platform = POSITIVE_PLATFORM,
    architecture = POSITIVE_ARCHITECTURE,
  } = {},
) {
  return {
    sourceRoot: await realpath(source),
    outputDirectory: join(await realpath(root), outputName),
    platform,
    architecture,
    releaseSequence: 11,
    signingKeyId: 'future-deployment-key',
    nativeAddonPath: await realpath(native.nativeAddonPath),
    nativeManifestPath: await realpath(native.nativeManifestPath),
    nativeSignaturePath: await realpath(native.nativeSignaturePath),
  };
}

async function refuses(action, code) {
  await assert.rejects(action, (error) => {
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.equal(error.writes, 0);
    assert.ok(error.message.length < 128);
    return true;
  });
}

async function* fileChunks(path) {
  const bytes = await readFile(path);
  for (let offset = 0; offset < bytes.length; offset += 97) yield bytes.subarray(offset, offset + 97);
}

async function createFixture(t, options = {}) {
  const boundary = installModeledBunBoundary(t, options);
  let installation;
  try {
    installation = await createPinnedDeploymentInstallation({
      keyIds: ['future-deployment-key'],
      includeReleaseBuilder: true,
    });
  } catch (error) {
    boundary.restore();
    throw error;
  }
  return {
    boundary,
    installation,
    dispose() {
      try {
        installation.dispose();
      } finally {
        boundary.restore();
      }
    },
  };
}

test('release contract is closed and Bun JSONC parsing rejects every error and duplicate property', async (t) => {
  const fixture = await createFixture(t);
  try {
    const nativeTrust = JSON.parse(
      fixture.installation.bundledNativeTrustBytes,
    );
    const applicationTrust = JSON.parse(
      fixture.installation.bundledApplicationTrustBytes,
    );
    const shawlTrust = JSON.parse(
      fixture.installation.bundledShawlTrustBytes,
    );
    assert.equal(nativeTrust.keys.length > 0, true);
    assert.equal(applicationTrust.keys.length > 0, true);
    assert.equal(shawlTrust.keys.length > 0, true);
    for (const deploymentTrust of [applicationTrust, shawlTrust]) {
      assert.equal(
        nativeTrust.keys.some((nativeKey) => deploymentTrust.keys.some(
          (deploymentKey) => deploymentKey.keyId === nativeKey.keyId ||
            deploymentKey.publicKeyPem === nativeKey.publicKeyPem,
        )),
        false,
        'synthetic deployment and native trust authorities must remain disjoint',
      );
    }
    assert.deepEqual(
      Object.keys(fixture.installation.releaseBuilder).sort(),
      [
        'buildUnsignedServiceRelease',
        'loadServiceReleaseContract',
        'parseBunProductionLock',
        'runServiceReleaseCli',
        'verifyUnsignedServiceRelease',
      ],
    );
    const contract = await fixture.installation.releaseBuilder.loadServiceReleaseContract();
    assert.equal(fixture.installation.releaseBuilder.buildUnsignedServiceRelease.length, 1);
    assert.equal(contract.repository, 'kogangdon/gjc-remote');
    assert.equal(contract.releaseVersion, '0.4.0-rc.1');
    assert.equal(contract.releaseTag, 'v0.4.0-rc.1');
    assert.equal(contract.sdk.packageVersion, '0.16.7');
    assert.equal(contract.sdk.configSchemaVersion, 2);
    assert.equal(contract.sdk.transcriptVersion, 5);
    assert.deepEqual(contract.sdk.sourceRoots, Object.fromEntries(
      Object.entries(SDK_SOURCES).map(([domain, source]) => [domain, source.path]),
    ));
    assert.equal(contract.sdk.sourceContractDomain, SDK_SOURCE_CONTRACT_DOMAIN);
    assert.equal(contract.sdk.closureDomain, 'gjc-remote/sdk-production-closure/v1');
    const botFormats = new Map(contract.formatRegistry.bot.formats.map(
      (record) => [record.formatId, record],
    ));
    for (const kind of ['authority-epoch-floor', 'fence-generation-floor']) {
      assert.deepEqual(botFormats.get(`floor:${kind}@1`), {
        formatId: `floor:${kind}@1`,
        marker: { version: 1, kind },
        source: 'bot/src/managed-authority-reader.js',
      });
    }
    assert.deepEqual(botFormats.get('reader-state:readerVersion/2'), {
      formatId: 'reader-state:readerVersion/2',
      marker: { readerVersion: 2 },
      source: 'shared/genesis-envelope.js',
    });
    assert.equal(botFormats.has('genesis:genesis-parent-mutation-proof@1'), false);
    assert.deepEqual(
      botFormats.get('genesis:genesis-authority-request@1')?.marker,
      { version: 1, kind: 'genesis-authority-request', sequence: 1 },
    );
    assert.deepEqual(
      botFormats.get('genesis:genesis-authority-receipt@1')?.marker,
      { version: 1, kind: 'genesis-authority-receipt', sequence: 2 },
    );
    assert.equal(
      botFormats.get('genesis:genesis-authority-request@1')?.source,
      'shared/genesis-envelope.js',
    );
    assert.equal(
      botFormats.get('genesis:genesis-authority-receipt@1')?.source,
      'shared/genesis-envelope.js',
    );
    assert.deepEqual(contract.producer.archive, {
      format: 'posix-ustar', gzipLevel: 6, gzipOperatingSystem: 255,
      mtimeSeconds: 0, terminalZeroBlocks: 2, paxType: 'local',
      paxKeys: ['SCHILY.nlink', 'mtime', 'path', 'size'],
    });
    assert.equal(Object.isFrozen(contract), true);

    const valid = bunLock();
    const parsed = fixture.installation.releaseBuilder.parseBunProductionLock(valid);
    assert.equal(parsed.sha256, sha256(valid));
    assert.equal(parsed.names.get('@gajae-code/coding-agent')[0].integrity, SDK_INTEGRITY);

    const duplicate = Buffer.from(valid.toString('utf8').replace(
      '"lockfileVersion": 1,',
      '"lockfileVersion": 1,\n  "lockfileVersion": 1,',
    ));
    assert.throws(
      () => fixture.installation.releaseBuilder.parseBunProductionLock(duplicate),
      { code: 'SERVICE_RELEASE_LOCK_INVALID', writes: 0 },
    );
    const malformed = Buffer.from(valid.toString('utf8').replace('"configVersion": 0', '"configVersion": 0 garbage'));
    assert.throws(
      () => fixture.installation.releaseBuilder.parseBunProductionLock(malformed),
      { code: 'SERVICE_RELEASE_LOCK_INVALID', writes: 0 },
    );
    assert.throws(
      () => fixture.installation.releaseBuilder.parseBunProductionLock(Buffer.alloc(16 * 1024 * 1024 + 1)),
      { code: 'SERVICE_RELEASE_LOCK_INVALID', writes: 0 },
    );
    for (const invalid of [
      '{}',
      Buffer.alloc(0),
      Buffer.from([0xff]),
      Buffer.from('/* unterminated'),
      Buffer.from('{"lockfileVersion":1} trailing'),
      Buffer.from(valid.toString('utf8').replace('"configVersion": 0', '"configVersion":')),
    ]) {
      assert.throws(
        () => fixture.installation.releaseBuilder.parseBunProductionLock(invalid),
        { code: 'SERVICE_RELEASE_LOCK_INVALID', writes: 0 },
      );
    }
    for (const name of ['__proto__', 'constructor', 'prototype']) {
      const prototypeName = Buffer.from(valid.toString('utf8').replace(
        '"fixture-sdk-leaf@1.0.0",\n      "",\n      {},',
        `"fixture-sdk-leaf@1.0.0",\n      "",\n      {"${name}": true},`,
      ));
      assert.notDeepEqual(prototypeName, valid);
      assert.throws(
        () => fixture.installation.releaseBuilder
          .parseBunProductionLock(prototypeName),
        { code: 'SERVICE_RELEASE_LOCK_INVALID', writes: 0 },
      );
    }
    await refuses(
      fixture.installation.releaseBuilder.runServiceReleaseCli(['build']),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
    await refuses(
      fixture.installation.releaseBuilder.runServiceReleaseCli([]),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
    for (const invocation of [
      {
        args: [
          '--input-type=module',
          '-e',
          `await import(${JSON.stringify(fixture.installation.releaseBuilderUrl)}); process.stdout.write("IMPORT_OK\\n");`,
        ],
      },
      {
        args: ['--input-type=module', '-'],
        input: `await import(${JSON.stringify(fixture.installation.releaseBuilderUrl)}); process.stdout.write("IMPORT_OK\\n");`,
      },
    ]) {
      const imported = spawnSync(process.execPath, invocation.args, {
        input: invocation.input,
        encoding: 'utf8',
        windowsHide: true,
      });
      assert.equal(imported.status, 0);
      assert.equal(imported.signal, null);
      assert.equal(imported.stdout, 'IMPORT_OK\n');
      assert.equal(imported.stderr, '');
    }
  } finally {
    fixture.dispose();
  }
});

test('two clean modeled Bun-boundary builds are byte-identical and round-trip the real archive parser', async (t) => {
  // Only child_process.spawn at the external Bun boundary is modeled. Git,
  // signatures, filesystem traversal, tar/gzip, parser and crypto are real.
  // This test makes no registry, SRI-download or real-Bun evidence claim.
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-builder-test-'));
  const fixture = await createFixture(t);
  try {
    const firstRoot = join(root, 'first');
    const secondRoot = join(root, 'second');
    const sourceFixture = createSourceRepository(
      firstRoot,
      fixture.installation,
    );
    const independentSource = createSourceRepository(
      secondRoot,
      fixture.installation,
    );
    const native = createNativeInputs(
      firstRoot,
      fixture.installation,
      sourceFixture.models.native,
    );
    const independentNative = createNativeInputs(
      secondRoot,
      fixture.installation,
      independentSource.models.native,
    );
    const firstInput = await inputFor(firstRoot, sourceFixture.source, native, 'candidate-a');
    const secondInput = await inputFor(
      secondRoot,
      independentSource.source,
      independentNative,
      'candidate-b',
    );
    const first = await fixture.installation.releaseBuilder.buildUnsignedServiceRelease(firstInput);
    const second = await fixture.installation.releaseBuilder.buildUnsignedServiceRelease(secondInput);

    assert.equal(first.unsigned, true);
    assert.equal(first.signatureGenerated, false);
    assert.equal(first.sdkClosurePackageCount, 2);
    assert.equal(first.producerEvidence.kind, 'real-external-bun-process');
    assert.equal(first.producerEvidence.integrityAuthority, 'fresh-bun-frozen-lockfile-registry-sri');
    assert.equal(fixture.boundary.evidenceScope, 'modeled-external-bun-process-no-network-or-sri-proof');
    assert.equal(first.source.repository, 'kogangdon/gjc-remote');
    assert.equal(first.source.tag, 'v0.4.0-rc.1');
    assert.equal(first.source.commit, git(sourceFixture.source, ['rev-parse', 'HEAD^{commit}']));
    assert.equal(first.source.tree, git(sourceFixture.source, ['rev-parse', 'HEAD^{tree}']));
    assert.equal(first.source.commit, git(independentSource.source, ['rev-parse', 'HEAD^{commit}']));
    assert.equal(first.source.tree, git(independentSource.source, ['rev-parse', 'HEAD^{tree}']));
    assert.equal(first.nativeAddonSha256, sha256(Buffer.from('signed native addon fixture\n')));
    assert.equal(
      first.nativeManifestFingerprint,
      sha256(readFileSync(native.nativeManifestPath)),
    );
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(first.source), true);
    assert.equal(Object.isFrozen(first.sdkExternalStateContract), true);
    assert.equal(Object.isFrozen(first.sdkExternalStateContract.sourceContracts), true);
    assert.deepEqual(
      {
        packageName: first.sdkExternalStateContract.packageName,
        packageVersion: first.sdkExternalStateContract.packageVersion,
        lockIntegrity: first.sdkExternalStateContract.lockIntegrity,
        configSchemaVersion: first.sdkExternalStateContract.configSchemaVersion,
      },
      {
        packageName: '@gajae-code/coding-agent',
        packageVersion: '0.16.7',
        lockIntegrity: SDK_INTEGRITY,
        configSchemaVersion: 2,
      },
    );
    assert.deepEqual(
      first.sdkExternalStateContract.sourceContracts,
      Object.fromEntries(Object.keys(SDK_SOURCES).map((domain) => [
        domain,
        expectedSdkSourceFingerprint(domain, first.sdkClosureFingerprint),
      ])),
    );
    assert.equal(
      new Set(Object.values(first.sdkExternalStateContract.sourceContracts)).size,
      Object.keys(SDK_SOURCES).length,
      'the four source roots must remain independently domain-separated',
    );

    const names = readdirSync(firstInput.outputDirectory).sort();
    assert.deepEqual(names, [
      ARCHIVE_NAME,
      MANIFEST_NAME,
    ]);
    assert.deepEqual(
      readFileSync(join(firstInput.outputDirectory, names[0])),
      readFileSync(join(secondInput.outputDirectory, names[0])),
    );
    assert.deepEqual(
      readFileSync(join(firstInput.outputDirectory, names[1])),
      readFileSync(join(secondInput.outputDirectory, names[1])),
    );
    assert.deepEqual(first, second);

    const manifest = parseCanonicalJsonBytes(readFileSync(join(firstInput.outputDirectory, names[1])), {
      maxBytes: 1024 * 1024, maxDepth: 32, maxNodes: 10_000,
    });
    assert.equal(manifest.source.bunLockSha256, sha256(bunLock()));
    assert.equal(manifest.nativeControl.manifestFingerprint, first.nativeManifestFingerprint);
    assert.equal(
      manifest.compatibility.roles.daemon.sdkExternalStateContractFingerprint,
      first.sdkExternalStateContract.sdkExternalStateContractFingerprint,
    );
    const inspection = await inspectApplicationArchive({
      chunks: fileChunks(join(firstInput.outputDirectory, names[0])), manifest,
    });
    let inventoryBytes;
    let archivedLockBytes;
    await consumeApplicationArchive({
      chunks: fileChunks(join(firstInput.outputDirectory, names[0])),
      manifest,
      inspection,
      async onFile(record, byteChunks) {
        const parts = [];
        for await (const bytes of byteChunks) {
          if (record.path === 'bundle-files.json' || record.path === 'bun.lock') {
            parts.push(Buffer.from(bytes));
          }
        }
        if (record.path === 'bundle-files.json') inventoryBytes = Buffer.concat(parts);
        if (record.path === 'bun.lock') archivedLockBytes = Buffer.concat(parts);
      },
    });
    assert.deepEqual(archivedLockBytes, bunLock());
    assert.equal(sha256(archivedLockBytes), first.source.bunLockSha256);
    assert.equal(sha256(archivedLockBytes), manifest.source.bunLockSha256);
    const inventory = parseCanonicalJsonBytes(inventoryBytes, {
      maxBytes: 32 * 1024 * 1024, maxDepth: 16, maxNodes: 600_032,
    });
    assert.equal(inventory.payloadEntries.some((record) => record.path === 'bundle-files.json'), false);
    assert.equal(inventory.payloadEntryCount, inventory.payloadEntries.length);
    assert.equal(inventory.treeFingerprint, manifest.inventory.treeFingerprint);
    assert.equal(sha256(inventoryBytes), manifest.inventory.sha256);
    const secondManifest = parseCanonicalJsonBytes(
      readFileSync(join(secondInput.outputDirectory, names[1])),
      { maxBytes: 1024 * 1024, maxDepth: 32, maxNodes: 10_000 },
    );
    const secondInspection = await inspectApplicationArchive({
      chunks: fileChunks(join(secondInput.outputDirectory, names[0])),
      manifest: secondManifest,
    });
    let independentInventoryBytes;
    await consumeApplicationArchive({
      chunks: fileChunks(join(secondInput.outputDirectory, names[0])),
      manifest: secondManifest,
      inspection: secondInspection,
      async onFile(record, byteChunks) {
        const parts = [];
        for await (const bytes of byteChunks) {
          if (record.path === 'bundle-files.json') parts.push(Buffer.from(bytes));
        }
        if (record.path === 'bundle-files.json') {
          independentInventoryBytes = Buffer.concat(parts);
        }
      },
    });
    assert.deepEqual(independentInventoryBytes, inventoryBytes);
    const paths = new Set(inspection.files.map((record) => record.path));
    assert.ok(
      Buffer.byteLength(`node_modules/fixture-consumer/${LONG_UTF8_RESOURCE}`, 'utf8') > 100,
      'portable long UTF-8 fixture must require extended tar path handling',
    );
    for (const path of [
      'package.json',
      'bun.lock',
      'bot/package.json',
      'bot/src/bot.js',
      'daemon/package.json',
      'daemon/src/daemon.js',
      'native-control/package.json',
      'native-control/deployment-keys/application-trusted.json',
      'native-control/deployment-keys/shawl-trusted.json',
      'native-control/release-keys/trusted.json',
      'native-control/src/public.js',
      'shared/package.json',
      'shared/protocol.js',
      'shared/resource.js',
      ...Object.values(SDK_SOURCES).map(
        (source) => `node_modules/@gajae-code/coding-agent/${source.path}`,
      ),
      'node_modules/@gajae-code/coding-agent/src/config/config-schema-version.ts',
      'node_modules/@gajae-code/coding-agent/resources/complete.dat',
      'node_modules/fixture-sdk-leaf/resource.txt',
      'node_modules/fixture-consumer/resources/complete.dat',
      `node_modules/fixture-consumer/${LONG_UTF8_RESOURCE}`,
      'node_modules/fixture-target/target.js',
      'node_modules/tar/index.js',
      'node_modules/@gjc-remote/native-control/build/Release/native_control.node',
      'node_modules/fixture-consumer/node_modules/@gjc-remote/native-control/build/Release/native_control.node',
    ]) assert.equal(paths.has(path), true, path);
    assert.equal([...paths].some((path) => path.startsWith('node_modules/jsonc-parser/')), false);
    assert.equal([...paths].some((path) => path.split('/').includes('.bin')), false);
    assert.equal([...paths].some((path) =>
      path.split('/').some((segment) => [
        '.env', '.git', '.gjc', '.gjc-remote-session', '.cache', 'credentials', 'logs', 'sessions',
      ].includes(segment))), false);
    for (const excluded of [
      'bot/test/not-production.test.js',
      'native-control/src/not-production.test.js',
      'native-control/README.md',
      'native-control/node_modules/dependency-only-shadow/package.json',
      'native-control/node_modules/dependency-only-shadow/foreign.js',
    ]) assert.equal(paths.has(excluded), false, excluded);
    assert.equal([...paths].some((path) =>
      path.includes('/@gjc-remote/native-control/node_modules/')), false);
    const byPath = new Map(inspection.files.map((record) => [record.path, record]));
    for (const [path, trustBytes] of [
      [
        'native-control/deployment-keys/application-trusted.json',
        fixture.installation.bundledApplicationTrustBytes,
      ],
      [
        'native-control/deployment-keys/shawl-trusted.json',
        fixture.installation.bundledShawlTrustBytes,
      ],
    ]) {
      const deploymentTrustRecord = byPath.get(path);
      assert.deepEqual(
        {
          size: deploymentTrustRecord.size,
          sha256: deploymentTrustRecord.sha256,
        },
        {
          size: trustBytes.length,
          sha256: sha256(trustBytes),
        },
      );
    }
    const rootAddon = byPath.get('native-control/build/Release/native_control.node');
    const nativeRootRecords = inspection.files.filter((record) =>
      record.path.startsWith('native-control/') &&
      !record.path.startsWith('native-control/node_modules/'));
    for (const aliasRoot of [
      'node_modules/@gjc-remote/native-control',
      'node_modules/fixture-consumer/node_modules/@gjc-remote/native-control',
    ]) {
      for (const rootRecord of nativeRootRecords) {
        const relativePath = rootRecord.path.slice('native-control/'.length);
        const alias = byPath.get(`${aliasRoot}/${relativePath}`);
        assert.ok(alias, `${aliasRoot}/${relativePath}`);
        assert.deepEqual(
          {
            size: alias.size,
            sha256: alias.sha256,
            executablePolicy: alias.executablePolicy,
          },
          {
            size: rootRecord.size,
            sha256: rootRecord.sha256,
            executablePolicy: rootRecord.executablePolicy,
          },
        );
      }
    }
    assert.equal(rootAddon.executablePolicy, 'required');
    assert.equal(inspection.files[0].path, 'bundle-files.json');

    const verification = await fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({
      candidateDirectory: firstInput.outputDirectory,
    });
    assert.equal(verification.manifestFingerprint, first.manifestFingerprint);
    assert.equal(verification.signatureGenerated, false);
    assert.equal(Object.isFrozen(verification), true);
    const cliVerification = await fixture.installation.releaseBuilder.runServiceReleaseCli([
      'verify', '--candidate', firstInput.outputDirectory,
    ]);
    assert.deepEqual(cliVerification, verification);
    assert.equal(fixture.boundary.calls.length, 4);
    for (const call of fixture.boundary.calls.filter((entry) => entry.args[0] === 'install')) {
      assert.deepEqual(call.args.slice(0, 6), [
        'install', '--production', '--frozen-lockfile', '--ignore-scripts', '--backend=copyfile', '--linker=hoisted',
      ]);
      assert.ok(call.args.some((value) => value.startsWith('--cache-dir=')));
      assert.ok(call.args.includes('--registry=https://registry.npmjs.org'));
      assert.ok(call.args.includes(`--os=${POSITIVE_PLATFORM}`));
      assert.ok(call.args.includes(`--cpu=${POSITIVE_ARCHITECTURE}`));
      for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'NODE_OPTIONS', 'NPM_TOKEN', 'npm_config_proxy']) {
        assert.equal(Object.hasOwn(call.env, name), false);
      }
    }
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('integrity-pinned dependency paths may contain host-state-named segments', async (t) => {
  // Real dependency tarballs legitimately ship directories like
  // lib/credentials (observed in @anthropic-ai/sdk). The host-state segment
  // ban protects workspace source selection only; dependency bytes are
  // bound by the frozen lockfile SRI, not by name policy.
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-dep-names-'));
  const fixture = await createFixture(t, { dependencyCredentials: true });
  try {
    const sourceFixture = createSourceRepository(root, fixture.installation);
    const native = createNativeInputs(root, fixture.installation, sourceFixture.models.native);
    const input = await inputFor(root, sourceFixture.source, native);
    const built = await fixture.installation.releaseBuilder.buildUnsignedServiceRelease(input);
    assert.equal(built.unsigned, true);
    const names = readdirSync(input.outputDirectory).sort();
    assert.deepEqual(names, [ARCHIVE_NAME, MANIFEST_NAME]);
    const manifest = parseCanonicalJsonBytes(readFileSync(join(input.outputDirectory, names[1])), {
      maxBytes: 1024 * 1024, maxDepth: 32, maxNodes: 10_000,
    });
    const inspection = await inspectApplicationArchive({
      chunks: fileChunks(join(input.outputDirectory, names[0])), manifest,
    });
    assert.equal(
      inspection.files.some((record) =>
        record.path === 'node_modules/fixture-consumer/lib/credentials/state.js'),
      true,
    );
    const verification = await fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({
      candidateDirectory: input.outputDirectory,
    });
    assert.equal(verification.manifestFingerprint, built.manifestFingerprint);
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('lock-synthesized peer metadata is authoritative and cross-checked', async (t) => {
  // Real Bun locks carry registry-resolved peerDependencies/optionalPeers that
  // the published package.json omits (observed with debug@4.4.3). The builder
  // must accept that exact shape and still reject inconsistent lock metadata.
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-peer-synth-'));
  const fixture = await createFixture(t, { debugSynthesis: true });
  try {
    const models = packageModels({ debugSynthesis: true });
    const sourceFixture = createSourceRepository(root, fixture.installation, { models });
    const native = createNativeInputs(root, fixture.installation, models.native);
    const input = await inputFor(root, sourceFixture.source, native);
    const built = await fixture.installation.releaseBuilder.buildUnsignedServiceRelease(input);
    assert.equal(built.unsigned, true);
    const names = readdirSync(input.outputDirectory).sort();
    const manifest = parseCanonicalJsonBytes(readFileSync(join(input.outputDirectory, names[1])), {
      maxBytes: 1024 * 1024, maxDepth: 32, maxNodes: 10_000,
    });
    const inspection = await inspectApplicationArchive({
      chunks: fileChunks(join(input.outputDirectory, names[0])), manifest,
    });
    assert.equal(
      inspection.files.some((record) => record.path === 'node_modules/fixture-debug/index.js'),
      true,
    );
    assert.equal(
      inspection.files.some((record) => record.path.startsWith('node_modules/fixture-peer-optional/')),
      false,
      'absent optional peers remain absent without failing the build',
    );
    const verification = await fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({
      candidateDirectory: input.outputDirectory,
    });
    assert.equal(verification.manifestFingerprint, built.manifestFingerprint);

    const inconsistentRoot = join(root, 'inconsistent');
    mkdirSync(inconsistentRoot, { recursive: true });
    const inconsistentModels = packageModels({ debugSynthesis: true });
    inconsistentModels.debugLock = {};
    const inconsistentSource = createSourceRepository(
      inconsistentRoot,
      fixture.installation,
      { models: inconsistentModels },
    );
    const inconsistentNative = createNativeInputs(
      inconsistentRoot,
      fixture.installation,
      inconsistentModels.native,
    );
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(
        await inputFor(inconsistentRoot, inconsistentSource.source, inconsistentNative, 'candidate-c'),
      ),
      'SERVICE_RELEASE_LOCK_INVALID',
    );
    assert.equal(existsSync(join(inconsistentRoot, 'candidate-c')), false);
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('source repository identity, tag, clean tree, mutable paths and preserved output fail closed before publication', async (t) => {
  const fixture = await createFixture(t);
  const roots = [];
  try {
    const dirtyRoot = mkdtempSync(join(tmpdir(), 'gjc-release-dirty-'));
    roots.push(dirtyRoot);
    const dirty = createSourceRepository(dirtyRoot, fixture.installation);
    const dirtyNative = createNativeInputs(dirtyRoot, fixture.installation, dirty.models.native);
    write(join(dirty.source, 'untracked.txt'), 'dirty\n');
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(await inputFor(dirtyRoot, dirty.source, dirtyNative)),
      'SERVICE_RELEASE_SOURCE_DIRTY',
    );

    const tagRoot = mkdtempSync(join(tmpdir(), 'gjc-release-tag-'));
    roots.push(tagRoot);
    const wrongTag = createSourceRepository(tagRoot, fixture.installation, { commitAfterTag: true });
    const tagNative = createNativeInputs(tagRoot, fixture.installation, wrongTag.models.native);
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(await inputFor(tagRoot, wrongTag.source, tagNative)),
      'SERVICE_RELEASE_SOURCE_INVALID',
    );

    const repositoryRoot = mkdtempSync(join(tmpdir(), 'gjc-release-repository-'));
    roots.push(repositoryRoot);
    const wrongRepository = createSourceRepository(repositoryRoot, fixture.installation);
    git(wrongRepository.source, ['remote', 'set-url', 'origin', 'https://github.com/example/not-gjc-remote.git']);
    const repositoryNative = createNativeInputs(repositoryRoot, fixture.installation, wrongRepository.models.native);
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(
        await inputFor(repositoryRoot, wrongRepository.source, repositoryNative),
      ),
      'SERVICE_RELEASE_SOURCE_INVALID',
    );

    const mutableRoot = mkdtempSync(join(tmpdir(), 'gjc-release-mutable-'));
    roots.push(mutableRoot);
    const mutable = createSourceRepository(mutableRoot, fixture.installation, { mutablePath: true });
    const mutableNative = createNativeInputs(mutableRoot, fixture.installation, mutable.models.native);
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(await inputFor(mutableRoot, mutable.source, mutableNative)),
      'SERVICE_RELEASE_PATH_INVALID',
    );

    const outputRoot = mkdtempSync(join(tmpdir(), 'gjc-release-output-'));
    roots.push(outputRoot);
    const outputSource = createSourceRepository(outputRoot, fixture.installation);
    const outputNative = createNativeInputs(outputRoot, fixture.installation, outputSource.models.native);
    const input = await inputFor(outputRoot, outputSource.source, outputNative);
    mkdirSync(input.outputDirectory);
    write(join(input.outputDirectory, 'user-output.txt'), 'preserve me\n');
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(input),
      'SERVICE_RELEASE_OUTPUT_INVALID',
    );
    assert.equal(readFileSync(join(input.outputDirectory, 'user-output.txt'), 'utf8'), 'preserve me\n');
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease({
        ...input,
        callerMaterializer: () => {},
      }),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(
        Object.assign(Object.create(null), input),
      ),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
    let inputGetterCalls = 0;
    const accessorInput = { ...input };
    Object.defineProperty(accessorInput, 'signingKeyId', {
      enumerable: true,
      get() {
        inputGetterCalls += 1;
        return 'caller-key';
      },
    });
    await refuses(
      fixture.installation.releaseBuilder
        .buildUnsignedServiceRelease(accessorInput),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
    assert.equal(inputGetterCalls, 0);

    const unsupported = {
      ...input,
      outputDirectory: join(await realpath(outputRoot), 'unsupported'),
      platform: 'win32',
      architecture: 'arm64',
    };
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease(unsupported),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
    await refuses(
      fixture.installation.releaseBuilder.buildUnsignedServiceRelease({
        ...input,
        outputDirectory: join(await realpath(outputSource.source), 'release-output'),
      }),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
  } finally {
    fixture.dispose();
    for (const root of roots) rmSync(root, { recursive: true, force: true });
  }
});

test('repository fsmonitor and replacement objects cannot alter captured Git identity', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-git-hardening-'));
  const fixture = await createFixture(t);
  try {
    const source = createSourceRepository(root, fixture.installation);
    const originalCommit = git(source.source, ['rev-parse', 'HEAD^{commit}']);
    const originalTree = git(source.source, ['rev-parse', 'HEAD^{tree}']);
    const marker = join(root, 'fsmonitor-executed');
    const fsmonitor = writeMarkerCommand(
      root,
      'hostile-fsmonitor',
      marker,
    );

    write(
      join(source.source, 'shared/replacement-only.js'),
      'export const replacementOnly = true;\n',
    );
    git(source.source, ['add', 'shared/replacement-only.js']);
    const replacementTree = git(source.source, ['write-tree']);
    const replacementCommit = git(source.source, [
      'commit-tree',
      replacementTree,
      '-p',
      originalCommit,
      '-m',
      'hostile replacement commit',
    ], {
      GIT_AUTHOR_DATE: '2026-01-03T00:00:00Z',
      GIT_COMMITTER_DATE: '2026-01-03T00:00:00Z',
    });
    git(source.source, ['reset', '--hard', originalCommit]);
    git(source.source, ['replace', originalCommit, replacementCommit]);
    assert.notEqual(replacementTree, originalTree);
    // Arm the hostile fsmonitor only after fixture setup: the harness's own
    // (unhardened) add/write-tree/reset would otherwise execute the hook on
    // Linux and forge the marker the builder is being judged by.
    git(source.source, ['config', 'core.fsmonitor', fsmonitor]);
    assert.equal(existsSync(marker), false);

    const native = createNativeInputs(
      root,
      fixture.installation,
      source.models.native,
    );
    const input = await inputFor(root, source.source, native);
    const receipt = await fixture.installation.releaseBuilder
      .buildUnsignedServiceRelease(input);

    assert.equal(receipt.source.commit, originalCommit);
    assert.equal(receipt.source.tree, originalTree);
    assert.notEqual(receipt.source.tree, replacementTree);
    assert.equal(existsSync(marker), false);
    assert.equal(fixture.boundary.calls.length, 2);
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('executable clean and process filters refuse before status or filter execution', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-git-filter-'));
  const fixture = await createFixture(t);
  try {
    const source = createSourceRepository(root, fixture.installation, {
      mutateSource({ source: sourceRoot }) {
        write(
          join(sourceRoot, '.gitattributes'),
          'bot/src/bot.js filter=hostile\n',
        );
      },
    });
    const marker = join(root, 'filter-executed');
    const command = writeMarkerCommand(root, 'hostile-filter', marker);
    git(source.source, ['config', 'filter.hostile.clean', command]);
    git(source.source, ['config', 'filter.hostile.process', command]);
    const native = createNativeInputs(
      root,
      fixture.installation,
      source.models.native,
    );
    const input = await inputFor(root, source.source, native);

    await refuses(
      fixture.installation.releaseBuilder
        .buildUnsignedServiceRelease(input),
      'SERVICE_RELEASE_GIT_INVALID',
    );
    assert.equal(existsSync(marker), false);
    assert.equal(existsSync(input.outputDirectory), false);
    assert.equal(fixture.boundary.calls.length, 0);
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('producer-target mismatch refuses before Bun or candidate writes', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-cross-target-'));
  const fixture = await createFixture(t);
  try {
    const source = createSourceRepository(root, fixture.installation);
    const target = process.platform === 'win32'
      ? { platform: 'linux', architecture: 'x64' }
      : { platform: 'darwin', architecture: 'x64' };
    const native = createNativeInputs(
      root,
      fixture.installation,
      source.models.native,
      target,
    );
    const input = await inputFor(
      root,
      source.source,
      native,
      'candidate-cross-target',
      target,
    );

    await refuses(
      fixture.installation.releaseBuilder
        .buildUnsignedServiceRelease(input),
      process.platform === 'win32'
        ? 'SERVICE_RELEASE_PRODUCER_FAILED'
        : 'SERVICE_RELEASE_INPUT_INVALID',
    );
    assert.equal(fixture.boundary.calls.length, 0);
    assert.equal(existsSync(input.outputDirectory), false);
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('budget admission sizes remain copy-time maxima before destination creation', async (t) => {
  await t.test('Git-selected source growth refuses before material destination open', async (t) => {
    const root = mkdtempSync(join(tmpdir(), 'gjc-release-source-growth-'));
    const fixture = await createFixture(t);
    let boundary;
    try {
      const source = createSourceRepository(root, fixture.installation);
      const native = createNativeInputs(
        root,
        fixture.installation,
        source.models.native,
      );
      const input = await inputFor(root, source.source, native);
      // The builder walks the canonical (realpath) source root, so compare
      // against the canonical spelling: GitHub's Windows runner TEMP is not
      // spelled the way realpath returns it.
      const growingPath = join(input.sourceRoot, 'bot', 'src', 'bot.js');
      let observations = 0;
      let destinationOpens = 0;
      boundary = installFsPromisesBoundary(t, {
        beforeLstat(path) {
          if (String(path) !== growingPath) return;
          observations += 1;
          if (observations === 2) {
            writeFileSync(
              growingPath,
              Buffer.concat([readFileSync(growingPath), Buffer.from('x')]),
            );
          }
        },
        observeOpen(path) {
          const value = String(path);
          if (value !== growingPath &&
              value.endsWith(join('bot', 'src', 'bot.js'))) {
            destinationOpens += 1;
          }
        },
      });

      await refuses(
        fixture.installation.releaseBuilder
          .buildUnsignedServiceRelease(input),
        'SERVICE_RELEASE_FILE_INVALID',
      );
      assert.equal(observations, 2);
      assert.equal(destinationOpens, 0);
      assert.equal(fixture.boundary.calls.length, 0);
      assert.equal(existsSync(input.outputDirectory), false);
    } finally {
      boundary?.restore();
      fixture.dispose();
      rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('native addon growth refuses before material destination open', async (t) => {
    const root = mkdtempSync(join(tmpdir(), 'gjc-release-native-growth-'));
    const fixture = await createFixture(t);
    let boundary;
    try {
      const source = createSourceRepository(root, fixture.installation);
      const native = createNativeInputs(
        root,
        fixture.installation,
        source.models.native,
      );
      const input = await inputFor(root, source.source, native);
      const nativeAddonPath = input.nativeAddonPath;
      let observations = 0;
      let destinationOpens = 0;
      boundary = installFsPromisesBoundary(t, {
        beforeLstat(path) {
          if (String(path) !== nativeAddonPath) return;
          observations += 1;
          if (observations === 2) {
            writeFileSync(
              nativeAddonPath,
              Buffer.concat([
                readFileSync(nativeAddonPath),
                Buffer.from('x'),
              ]),
            );
          }
        },
        observeOpen(path) {
          const value = String(path);
          if (value !== nativeAddonPath &&
              value.endsWith('native_control.node')) {
            destinationOpens += 1;
          }
        },
      });

      await refuses(
        fixture.installation.releaseBuilder
          .buildUnsignedServiceRelease(input),
        'SERVICE_RELEASE_FILE_INVALID',
      );
      assert.equal(observations, 2);
      assert.equal(destinationOpens, 0);
      assert.equal(fixture.boundary.calls.length, 0);
      assert.equal(existsSync(input.outputDirectory), false);
    } finally {
      boundary?.restore();
      fixture.dispose();
      rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('discovered package growth refuses before payload destination open', async (t) => {
    const root = mkdtempSync(join(tmpdir(), 'gjc-release-payload-growth-'));
    const fixture = await createFixture(t);
    let boundary;
    try {
      const source = createSourceRepository(root, fixture.installation);
      const native = createNativeInputs(
        root,
        fixture.installation,
        source.models.native,
      );
      const input = await inputFor(root, source.source, native);
      const suffix = join(
        'node_modules',
        'fixture-sdk-leaf',
        'resource.txt',
      );
      let grownPath = null;
      let destinationOpens = 0;
      boundary = installFsPromisesBoundary(t, {
        beforeLstat(path) {
          const value = String(path);
          if (grownPath !== null || !value.includes(`${sep}material${sep}`) ||
              !value.endsWith(suffix)) return;
          grownPath = value;
          writeFileSync(
            value,
            Buffer.concat([readFileSync(value), Buffer.from('x')]),
          );
        },
        observeOpen(path) {
          const value = String(path);
          if (value.includes(`${sep}payload${sep}`) &&
              value.endsWith(suffix)) destinationOpens += 1;
        },
      });

      await refuses(
        fixture.installation.releaseBuilder
          .buildUnsignedServiceRelease(input),
        'SERVICE_RELEASE_FILE_INVALID',
      );
      assert.notEqual(grownPath, null);
      assert.equal(destinationOpens, 0);
      assert.equal(fixture.boundary.calls.length, 2);
      assert.equal(existsSync(input.outputDirectory), false);
    } finally {
      boundary?.restore();
      fixture.dispose();
      rmSync(root, { recursive: true, force: true });
    }
  });
});

test('replacement of a newly created output directory is preserved on refusal', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-output-replace-'));
  const fixture = await createFixture(t);
  let boundary;
  try {
    const source = createSourceRepository(root, fixture.installation);
    const native = createNativeInputs(
      root,
      fixture.installation,
      source.models.native,
    );
    const input = await inputFor(root, source.source, native);
    const displaced = join(root, 'displaced-builder-output');
    const replacementMarker = join(
      input.outputDirectory,
      'replacement-owner.txt',
    );
    let outputLstats = 0;
    let replacementInstalled = false;
    let builderOutputOpens = 0;
    boundary = installFsPromisesBoundary(t, {
      beforeLstat(path) {
        if (String(path) !== input.outputDirectory) return;
        outputLstats += 1;
        if (outputLstats !== 3) return;
        renameSync(input.outputDirectory, displaced);
        mkdirSync(input.outputDirectory);
        writeFileSync(replacementMarker, 'replacement owner\n');
        replacementInstalled = true;
      },
      observeOpen(path) {
        const value = String(path);
        if (value === input.outputDirectory ||
            value.startsWith(`${input.outputDirectory}${sep}`)) {
          builderOutputOpens += 1;
        }
      },
    });

    await refuses(
      fixture.installation.releaseBuilder
        .buildUnsignedServiceRelease(input),
      'SERVICE_RELEASE_OUTPUT_INVALID',
    );
    assert.equal(replacementInstalled, true);
    assert.equal(builderOutputOpens, 0);
    assert.equal(
      readFileSync(replacementMarker, 'utf8'),
      'replacement owner\n',
    );
    assert.deepEqual(
      readdirSync(input.outputDirectory),
      ['replacement-owner.txt'],
    );
    assert.deepEqual(readdirSync(displaced), []);
    assert.equal(existsSync(join(displaced, ARCHIVE_NAME)), false);
    assert.equal(existsSync(join(displaced, MANIFEST_NAME)), false);
    assert.equal(fixture.boundary.calls.length, 2);
  } finally {
    boundary?.restore();
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('dependency, SDK, native provenance and materialized-link tampering are rejected', async (t) => {
  const caseOnlyModels = packageModels({ caseNativePackage: true });
  const edgeModels = (edgeSpecifier, edgeLockPackages) =>
    packageModels({ edgeSpecifier, edgeLockPackages });
  const prereleaseEdgePackages = [{
    key: 'fixture-edge',
    name: 'fixture-edge',
    version: '1.1.0-beta.1',
  }];
  const prereleaseEdgeModels = edgeModels(
    '^1.0.0',
    prereleaseEdgePackages,
  );
  const foreignNamePackages = [
    { key: 'fixture-edge', name: 'fixture-edge', version: '1.0.0' },
    { key: 'fixture-foreign', name: 'fixture-foreign', version: '1.0.0' },
  ];
  const foreignNameModels = edgeModels('^1.0.0', foreignNamePackages);
  const fileSourcePackages = [{
    key: 'fixture-edge',
    name: 'fixture-edge',
    version: '1.0.0',
  }];
  const fileSourceModels = edgeModels(
    'file:../fixture-edge',
    fileSourcePackages,
  );
  const nestedEdgePackages = [
    { key: 'fixture-edge', name: 'fixture-edge', version: '1.0.0' },
    {
      key: 'fixture-consumer/fixture-edge',
      name: 'fixture-edge',
      version: '2.0.0',
    },
  ];
  const nestedEdgeModels = edgeModels(
    '>=1.0.0 <3.0.0',
    nestedEdgePackages,
  );
  const cases = [
    ['missing required production dependency', { omitConsumer: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['missing workspace production dependency marker', { aliasMarkerFile: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['missing SDK transitive dependency', { omitSdkLeaf: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['missing non-SDK transitive dependency', { omitTar: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['foreign installed dependency version', { consumerVersion: '2.0.0' }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['wrong installed SDK version', { sdkVersion: '0.16.5' }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['incompatible dependency prerelease does not satisfy a stable range', {
      edgeSpecifier: '^1.0.0',
      edgeLockPackages: prereleaseEdgePackages,
      installedEdgeVersion: '1.1.0-beta.1',
    }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID', {
      models: prereleaseEdgeModels,
      lockBytes: bunLock(prereleaseEdgeModels),
    }],
    ['resolved dependency package name must equal its declared edge', {
      edgeSpecifier: '^1.0.0',
      edgeLockPackages: foreignNamePackages,
      installedEdgeName: 'fixture-foreign',
    }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID', {
      models: foreignNameModels,
      lockBytes: bunLock(foreignNameModels),
    }],
    ['non-registry dependency source is not a semver range', {
      edgeSpecifier: 'file:../fixture-edge',
      edgeLockPackages: fileSourcePackages,
    }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID', {
      models: fileSourceModels,
      lockBytes: bunLock(fileSourceModels),
    }],
    ['nested resolution cannot borrow a globally locked compatible version', {
      edgeSpecifier: '>=1.0.0 <3.0.0',
      edgeLockPackages: nestedEdgePackages,
      installedEdgeVersion: '1.0.0',
      nestedEdge: true,
    }, {}, 'SERVICE_RELEASE_LOCK_INVALID', {
      models: nestedEdgeModels,
      lockBytes: bunLock(nestedEdgeModels),
    }],
    ['wrong SDK lock SRI', {}, {}, 'SERVICE_RELEASE_SDK_INVALID', {
      lockBytes: bunLock(packageModels(), { sdkIntegrity: fakeSri(9) }),
    }],
    ['wrong SDK configuration schema marker', { sdkSchemaVersion: 3 }, {}, 'SERVICE_RELEASE_SDK_INVALID'],
    ['wrong SDK transcript marker', { transcriptVersion: 4 }, {}, 'SERVICE_RELEASE_SDK_INVALID'],
    ['missing audited SDK source root', { missingSdkSource: 'auth' }, {}, 'SERVICE_RELEASE_SDK_INVALID'],
    ['native workspace dependency-only shadow', { aliasDecoy: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['missing applicable target optional dependency', { omitTarget: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['materialized link escape', { escapeLink: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['materialized link cycle', { cycleLink: true }, {}, 'SERVICE_RELEASE_CLOSURE_INVALID'],
    ['native addon differs from signed digest', {}, {
      writtenAddonBytes: Buffer.from('tampered addon\n'),
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest package drift', {}, {
      manifestOverrides: { package: '@foreign/native-control' },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest package-version drift', {}, {
      manifestOverrides: { version: '9.9.9' },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest contract drift', {}, {
      manifestOverrides: { contractRevision: contractRevision + 1 },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest N-API drift', {}, {
      manifestOverrides: { napi: 7 },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest capability drift', {}, {
      manifestOverrides: { capabilities: capabilities.slice(1) },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest signature-table drift', {}, {
      manifestOverrides: {
        capabilitySignatures: {
          ...capabilitySignatures,
          read_boot_id: ['authority'],
        },
      },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest digest syntax drift', {}, {
      manifestOverrides: { sha256: 'A'.repeat(64) },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest tuple drift', {}, {
      platform: OTHER_PLATFORM,
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['native manifest architecture drift', {}, {
      architecture: OTHER_ARCHITECTURE,
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['bundled native trust differs from installed pins', {}, {},
      'SERVICE_RELEASE_NATIVE_INVALID', {
        mutateTrust(bytes) {
          const store = JSON.parse(bytes);
          store.keys[0].keyId = 'foreign-native-key';
          return Buffer.from(JSON.stringify(store));
        },
      }],
    ['missing native signature bytes', {}, {
      emptySignature: true,
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['tampered native signature bytes', {}, {
      mutateSignature(bytes) {
        const sidecar = JSON.parse(bytes);
        sidecar.signature = `${sidecar.signature[0] === 'A' ? 'B' : 'A'}${sidecar.signature.slice(1)}`;
        return canonicalJsonBytes(sidecar);
      },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['foreign native signing key', {}, {
      mutateSignature(bytes) {
        const sidecar = JSON.parse(bytes);
        sidecar.keyId = 'foreign-native-key';
        return canonicalJsonBytes(sidecar);
      },
    }, 'SERVICE_RELEASE_NATIVE_INVALID'],
    ['Windows target refuses case-variant native alias', {
      caseOnlyRootAlias: true,
    }, {
      // Native tuple must match the win32/x64 target regardless of host
      // architecture so the refusal comes from the closure walk.
      platform: 'win32',
      architecture: 'x64',
    }, 'SERVICE_RELEASE_CLOSURE_INVALID', {
      models: caseOnlyModels,
      lockBytes: bunLock(caseOnlyModels),
    }, {
      platform: 'win32',
      architecture: 'x64',
    }],
  ];
  for (const [
    name,
    boundaryOptions,
    nativeOptions,
    code,
    sourceOptions = {},
    target = {},
  ] of cases) {
    await t.test(name, async (t) => {
      const root = mkdtempSync(join(tmpdir(), 'gjc-release-tamper-'));
      const fixture = await createFixture(t, boundaryOptions);
      try {
        const { mutateTrust, ...repositoryOptions } = sourceOptions;
        const nativeTrustBytes = mutateTrust
          ? mutateTrust(fixture.installation.bundledNativeTrustBytes)
          : fixture.installation.bundledNativeTrustBytes;
        const source = createSourceRepository(
          root,
          fixture.installation,
          { ...repositoryOptions, nativeTrustBytes },
        );
        const native = createNativeInputs(root, fixture.installation, source.models.native, nativeOptions);
        const buildInput = await inputFor(
          root,
          source.source,
          native,
          'candidate-a',
          target,
        );
        await refuses(
          fixture.installation.releaseBuilder
            .buildUnsignedServiceRelease(buildInput),
          code,
        );
        assert.equal(existsSync(buildInput.outputDirectory), false);
      } finally {
        fixture.dispose();
        rmSync(root, { recursive: true, force: true });
      }
    });
  }
});

test('modeled closure binds non-root SDK bytes and excludes a non-applicable optional target', async (t) => {
  // These are modeled package trees behind the mocked Bun process. Their
  // fingerprints prove builder closure sensitivity, not registry/TLS/SRI
  // materialization integrity.
  const buildModeled = async (name, boundaryOptions, sourceModels = packageModels()) => {
    const root = mkdtempSync(join(tmpdir(), `gjc-release-${name}-`));
    const fixture = await createFixture(t, boundaryOptions);
    try {
      const source = createSourceRepository(
        root,
        fixture.installation,
        { models: sourceModels, lockBytes: bunLock(sourceModels) },
      );
      const native = createNativeInputs(
        root,
        fixture.installation,
        source.models.native,
      );
      const input = await inputFor(root, source.source, native);
      const receipt = await fixture.installation.releaseBuilder
        .buildUnsignedServiceRelease(input);
      const manifest = parseCanonicalJsonBytes(
        readFileSync(join(
          input.outputDirectory,
          MANIFEST_NAME,
        )),
        { maxBytes: 1024 * 1024, maxDepth: 32, maxNodes: 10_000 },
      );
      const inspection = await inspectApplicationArchive({
        chunks: fileChunks(join(
          input.outputDirectory,
          ARCHIVE_NAME,
        )),
        manifest,
      });
      return {
        receipt,
        paths: new Set(inspection.files.map((record) => record.path)),
      };
    } finally {
      fixture.dispose();
      rmSync(root, { recursive: true, force: true });
    }
  };

  const baseline = await buildModeled('sdk-leaf-a', {});
  const changed = await buildModeled('sdk-leaf-b', {
    sdkLeafBytes: 'tampered SDK transitive closure resource\n',
  });
  assert.notEqual(
    baseline.receipt.sdkClosureFingerprint,
    changed.receipt.sdkClosureFingerprint,
  );
  assert.notEqual(
    baseline.receipt.sdkExternalStateContract.sdkExternalStateContractFingerprint,
    changed.receipt.sdkExternalStateContract.sdkExternalStateContractFingerprint,
  );
  for (const domain of Object.keys(SDK_SOURCES)) {
    assert.notEqual(
      baseline.receipt.sdkExternalStateContract.sourceContracts[domain],
      changed.receipt.sdkExternalStateContract.sourceContracts[domain],
      `${domain} must bind the SDK-reachable transitive closure`,
    );
  }

  const nonApplicableTargetModels = packageModels({
    targetPlatform: OTHER_PLATFORM,
    targetArchitecture: 'x64',
  });
  const nonApplicable = await buildModeled(
    'non-applicable-optional',
    {
      omitTarget: true,
      targetPlatform: OTHER_PLATFORM,
      targetArchitecture: 'x64',
    },
    nonApplicableTargetModels,
  );
  assert.equal(
    nonApplicable.paths.has('node_modules/fixture-target/package.json'),
    false,
  );
  assert.equal(
    nonApplicable.paths.has('node_modules/fixture-sdk-leaf/resource.txt'),
    true,
  );

  const optionalPeerModels = packageModels({ sdkOptionalPeer: true });
  const optionalPeerAbsent = await buildModeled(
    'optional-peer-absent',
    { sdkOptionalPeer: true, includeSdkOptionalPeer: false },
    optionalPeerModels,
  );
  assert.equal(optionalPeerAbsent.receipt.sdkClosurePackageCount, 2);
  assert.equal(
    optionalPeerAbsent.paths.has(
      'node_modules/fixture-optional-peer/package.json',
    ),
    false,
  );
  const optionalPeerPresent = await buildModeled(
    'optional-peer-present',
    { sdkOptionalPeer: true, includeSdkOptionalPeer: true },
    optionalPeerModels,
  );
  assert.equal(optionalPeerPresent.receipt.sdkClosurePackageCount, 3);
  assert.equal(
    optionalPeerPresent.paths.has(
      'node_modules/fixture-optional-peer/resource.txt',
    ),
    true,
  );
  assert.notEqual(
    optionalPeerPresent.receipt.sdkClosureFingerprint,
    optionalPeerAbsent.receipt.sdkClosureFingerprint,
  );
  for (const domain of Object.keys(SDK_SOURCES)) {
    assert.notEqual(
      optionalPeerPresent.receipt.sdkExternalStateContract
        .sourceContracts[domain],
      optionalPeerAbsent.receipt.sdkExternalStateContract
        .sourceContracts[domain],
      `${domain} must bind a present compatible optional SDK peer`,
    );
  }
});

test('candidate verification recomputes SDK-reachable closure after non-root byte tamper', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-sdk-hybrid-'));
  const boundaryOptions = {
    sdkLeafBytes: 'baseline SDK transitive closure resource\n',
  };
  const fixture = await createFixture(t, boundaryOptions);
  try {
    const source = createSourceRepository(
      root,
      fixture.installation,
    );
    const native = createNativeInputs(
      root,
      fixture.installation,
      source.models.native,
    );
    const baselineInput = await inputFor(
      root,
      source.source,
      native,
      'candidate-sdk-baseline',
    );
    const baselineReceipt = await fixture.installation.releaseBuilder
      .buildUnsignedServiceRelease(baselineInput);
    const baselineManifest = parseCanonicalJsonBytes(readFileSync(join(
      baselineInput.outputDirectory,
      MANIFEST_NAME,
    )));

    boundaryOptions.sdkLeafBytes = 'tampered SDK transitive closure resource\n';
    const changedInput = await inputFor(
      root,
      source.source,
      native,
      'candidate-sdk-changed',
    );
    const changedReceipt = await fixture.installation.releaseBuilder
      .buildUnsignedServiceRelease(changedInput);
    const changedManifest = parseCanonicalJsonBytes(readFileSync(join(
      changedInput.outputDirectory,
      MANIFEST_NAME,
    )));
    assert.notEqual(
      baselineReceipt.sdkClosureFingerprint,
      changedReceipt.sdkClosureFingerprint,
    );

    const hybridDirectory = join(root, 'candidate-sdk-hybrid');
    mkdirSync(hybridDirectory);
    write(
      join(
        hybridDirectory,
        ARCHIVE_NAME,
      ),
      readFileSync(join(
        changedInput.outputDirectory,
        ARCHIVE_NAME,
      )),
    );
    const hybridManifest = structuredClone(changedManifest);
    hybridManifest.compatibility = structuredClone(
      baselineManifest.compatibility,
    );
    hybridManifest.manifestFingerprint = null;
    hybridManifest.manifestFingerprint =
      applicationDeploymentManifestFingerprint(hybridManifest);
    write(
      join(
        hybridDirectory,
        MANIFEST_NAME,
      ),
      canonicalJsonBytes(hybridManifest),
    );

    await refuses(
      fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({
        candidateDirectory: await realpath(hybridDirectory),
      }),
      'SERVICE_RELEASE_SDK_INVALID',
    );
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('candidate verification rejects archive corruption and extra assets without trusting unsigned metadata', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-release-candidate-'));
  const fixture = await createFixture(t);
  try {
    const source = createSourceRepository(root, fixture.installation);
    const native = createNativeInputs(root, fixture.installation, source.models.native);
    const input = await inputFor(root, source.source, native);
    await fixture.installation.releaseBuilder.buildUnsignedServiceRelease(input);
    await refuses(
      fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({
        candidateDirectory: input.outputDirectory,
        trustOverride: Buffer.alloc(0),
      }),
      'SERVICE_RELEASE_INPUT_INVALID',
    );
    const archivePath = join(input.outputDirectory, ARCHIVE_NAME);
    const archive = readFileSync(archivePath);
    archive[Math.floor(archive.length / 2)] ^= 1;
    writeFileSync(archivePath, archive);
    await refuses(
      fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({ candidateDirectory: input.outputDirectory }),
      'SERVICE_RELEASE_ARCHIVE_INVALID',
    );

    const second = await inputFor(root, source.source, native, 'candidate-extra');
    await fixture.installation.releaseBuilder.buildUnsignedServiceRelease(second);
    write(join(second.outputDirectory, 'unexpected.sig'), 'not signed\n');
    await refuses(
      fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({ candidateDirectory: second.outputDirectory }),
      'SERVICE_RELEASE_CANDIDATE_INVALID',
    );

    const third = await inputFor(root, source.source, native, 'candidate-metadata');
    await fixture.installation.releaseBuilder.buildUnsignedServiceRelease(third);
    const manifestPath = join(
      third.outputDirectory,
      MANIFEST_NAME,
    );
    const manifestBytes = readFileSync(manifestPath);
    const changedManifest = Buffer.from(manifestBytes.toString('utf8').replace(
      '"releaseSequence":11',
      '"releaseSequence":12',
    ));
    assert.notDeepEqual(changedManifest, manifestBytes);
    writeFileSync(manifestPath, changedManifest);
    await refuses(
      fixture.installation.releaseBuilder.verifyUnsignedServiceRelease({
        candidateDirectory: third.outputDirectory,
      }),
      'SERVICE_RELEASE_CANDIDATE_INVALID',
    );
  } finally {
    fixture.dispose();
    rmSync(root, { recursive: true, force: true });
  }
});

test('root package exposes only explicit unsigned build and verify commands while retaining jsonc-parser pin', () => {
  const rootPackage = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.equal(rootPackage.devDependencies['jsonc-parser'], '3.3.1');
  assert.equal(rootPackage.devDependencies.yaml, '2.8.1');
  assert.equal(rootPackage.scripts['build:service-release'], 'node native-control/scripts/build-service-release.mjs build');
  assert.equal(rootPackage.scripts['verify:service-release'], 'node native-control/scripts/build-service-release.mjs verify');
  assert.equal(Object.keys(rootPackage.scripts).some((name) => /sign|publish|deploy/.test(name)), false);
});
