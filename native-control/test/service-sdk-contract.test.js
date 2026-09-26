import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { DEPLOYMENT_ENVELOPE_LIMITS } from '@gjc-remote/shared/deployment-envelope';
import {
  assertSdkExternalStateContract,
  deriveSdkExternalStateContract,
  SDK_EXTERNAL_STATE_REQUIREMENTS,
} from '../src/service-sdk-contract.js';
import {
  bunPackageRootForPath,
  parseBunProductionLock,
  resolveBunProductionClosure,
} from '../src/service-production-closure.js';

const ROOT_IDENTITY = `${SDK_EXTERNAL_STATE_REQUIREMENTS.packageName}@${SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion}`;
const TRANSITIVE_IDENTITY = 'fixture-transitive@1.2.3';
const TRANSITIVE_INTEGRITY = `sha512-${Buffer.alloc(64, 0x32).toString('base64')}`;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

function file(path, bytes) {
  return {
    path,
    size: bytes.byteLength,
    sha256: hash(bytes),
    executablePolicy: 'forbidden',
  };
}

function syntheticInstallation({
  configSchemaSource = 'export const CONFIG_SCHEMA_VERSION = 2;\n',
  sessionManagerSource = 'export const CURRENT_SESSION_VERSION = 5;\n',
  transitiveBytes = 'nonsecret synthetic SDK dependency source\n',
  rootIdentity = ROOT_IDENTITY,
  rootIntegrity = SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity,
  omitSourceRoot = null,
  omitTransitive = false,
  includeUnreachable = false,
  mismatchConfigSource = false,
} = {}) {
  const configBytes = Buffer.from(configSchemaSource);
  const sessionBytes = Buffer.from(sessionManagerSource);
  const sourceBytes = {
    [SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots.settings]: Buffer.from('synthetic settings source\n'),
    [SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots.model]: Buffer.from('synthetic model source\n'),
    [SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots.auth]: Buffer.from('synthetic auth source\n'),
    [SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots.session]: sessionBytes,
    'src/config/config-schema-version.ts': configBytes,
  };
  const rootFiles = Object.entries(sourceBytes)
    .filter(([path]) => path !== omitSourceRoot)
    .map(([path, bytes]) => file(path, bytes));
  const root = {
    identity: rootIdentity,
    integrity: rootIntegrity,
    files: rootFiles,
    edges: [{ kind: 'dependency', name: 'fixture-transitive', targetIdentity: TRANSITIVE_IDENTITY }],
  };
  const bytes = Buffer.from(transitiveBytes);
  const transitive = {
    identity: TRANSITIVE_IDENTITY,
    integrity: TRANSITIVE_INTEGRITY,
    files: [file('index.js', bytes)],
    edges: [],
  };
  const packages = [root];
  if (!omitTransitive) packages.push(transitive);
  if (includeUnreachable) {
    packages.push({
      identity: 'fixture-unreachable@1.0.0',
      integrity: `sha512-${Buffer.alloc(64, 0x33).toString('base64')}`,
      files: [file('index.js', Buffer.from('unreachable package\n'))],
      edges: [],
    });
  }
  return {
    packages,
    configSchemaVersionSource: mismatchConfigSource
      ? Buffer.from('export const CONFIG_SCHEMA_VERSION = 2;\n// changed after hashing\n')
      : configBytes,
    sessionManagerSource: sessionBytes,
  };
}

function derive(input = syntheticInstallation()) {
  return deriveSdkExternalStateContract(input);
}

function invalid(action) {
  assert.throws(action, {
    name: 'TypeError',
    message: 'SDK_EXTERNAL_STATE_CONTRACT_INVALID',
  });
}

function productionInvalid(action, code) {
  assert.throws(action, { name: 'TypeError', code });
}

function packageSri(byte) {
  return `sha512-${Buffer.alloc(64, byte).toString('base64')}`;
}

function productionGraphFixture({
  optionalPeer = false,
  installOptionalPeer = optionalPeer,
  optionalTarget = false,
  nestedLeaf = false,
  corruptSdkEdge = false,
} = {}) {
  const daemonDependencies = {
    [SDK_EXTERNAL_STATE_REQUIREMENTS.packageName]: SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion,
  };
  const botDependencies = nestedLeaf ? { 'fixture-sdk-leaf': '1.5.0' } : {};
  const sdkDependencies = { 'fixture-sdk-leaf': nestedLeaf ? '^1.0.0' : '1.0.0' };
  const sdkOptionalDependencies = optionalTarget ? { 'fixture-linux-only': '1.0.0' } : undefined;
  const sdkPeerDependencies = optionalPeer ? { 'fixture-optional-peer': '^1.0.0' } : undefined;
  const sdk = {
    name: SDK_EXTERNAL_STATE_REQUIREMENTS.packageName,
    version: SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion,
    dependencies: sdkDependencies,
    ...(sdkOptionalDependencies ? { optionalDependencies: sdkOptionalDependencies } : {}),
    ...(sdkPeerDependencies ? {
      peerDependencies: sdkPeerDependencies,
      peerDependenciesMeta: { 'fixture-optional-peer': { optional: true } },
    } : {}),
  };
  const workspaces = {
    '': { name: 'gjc-remote', version: '0.4.0-rc.2' },
    bot: { name: '@gjc-remote/bot', version: '0.4.0-rc.2', dependencies: botDependencies },
    daemon: { name: '@gjc-remote/daemon', version: '0.4.0-rc.2', dependencies: daemonDependencies },
    'native-control': { name: '@gjc-remote/native-control', version: '1.0.0', dependencies: {} },
    shared: { name: '@gjc-remote/shared', version: '0.4.0-rc.2' },
  };
  const packages = {
    '@gjc-remote/bot': ['@gjc-remote/bot@workspace:bot'],
    '@gjc-remote/daemon': ['@gjc-remote/daemon@workspace:daemon'],
    '@gjc-remote/native-control': ['@gjc-remote/native-control@workspace:native-control'],
    '@gjc-remote/shared': ['@gjc-remote/shared@workspace:shared'],
    [SDK_EXTERNAL_STATE_REQUIREMENTS.packageName]: [
      `${ROOT_IDENTITY}`, '', {
        dependencies: corruptSdkEdge ? { 'fixture-sdk-leaf': '2.0.0' } : sdkDependencies,
        ...(sdkOptionalDependencies ? { optionalDependencies: sdkOptionalDependencies } : {}),
        ...(sdkPeerDependencies ? {
          peerDependencies: sdkPeerDependencies,
          optionalPeers: ['fixture-optional-peer'],
        } : {}),
      }, SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity,
    ],
    'fixture-sdk-leaf': [
      `fixture-sdk-leaf@${nestedLeaf ? '1.5.0' : '1.0.0'}`, '', {}, packageSri(41),
    ],
    ...(nestedLeaf ? {
      '@gajae-code/coding-agent/fixture-sdk-leaf': [
        'fixture-sdk-leaf@1.2.0', '', {}, packageSri(42),
      ],
    } : {}),
    ...(installOptionalPeer ? {
      'fixture-optional-peer': ['fixture-optional-peer@1.0.0', '', {}, packageSri(43)],
    } : {}),
    ...(optionalTarget ? {
      'fixture-linux-only': [
        'fixture-linux-only@1.0.0', '', { os: 'linux', cpu: 'x64' }, packageSri(44),
      ],
    } : {}),
  };
  if (optionalTarget) {
    packages[SDK_EXTERNAL_STATE_REQUIREMENTS.packageName][2].optionalDependencies = sdkOptionalDependencies;
  }
  const lockBytes = Buffer.from(JSON.stringify({ lockfileVersion: 1, configVersion: 0, workspaces, packages }));
  const lock = parseBunProductionLock(lockBytes);
  const contract = {
    sourceWorkspaces: [
      { path: 'bot', packageName: '@gjc-remote/bot', packageVersion: '0.4.0-rc.2' },
      { path: 'daemon', packageName: '@gjc-remote/daemon', packageVersion: '0.4.0-rc.2' },
      { path: 'native-control', packageName: '@gjc-remote/native-control', packageVersion: '1.0.0' },
      { path: 'shared', packageName: '@gjc-remote/shared', packageVersion: '0.4.0-rc.2' },
    ],
  };
  const packageData = new Map();
  for (const [root, packageJson] of Object.entries({
    bot: { name: '@gjc-remote/bot', version: '0.4.0-rc.2', dependencies: botDependencies },
    daemon: { name: '@gjc-remote/daemon', version: '0.4.0-rc.2', dependencies: daemonDependencies },
    'native-control': { name: '@gjc-remote/native-control', version: '1.0.0', dependencies: {} },
    shared: { name: '@gjc-remote/shared', version: '0.4.0-rc.2' },
    'node_modules/@gajae-code/coding-agent': sdk,
    ...(nestedLeaf ? {
      'node_modules/@gajae-code/coding-agent/node_modules/fixture-sdk-leaf': {
        name: 'fixture-sdk-leaf', version: '1.2.0',
      },
      'node_modules/fixture-sdk-leaf': { name: 'fixture-sdk-leaf', version: '1.5.0' },
    } : {
      'node_modules/fixture-sdk-leaf': { name: 'fixture-sdk-leaf', version: '1.0.0' },
    }),
    ...(installOptionalPeer ? {
      'node_modules/fixture-optional-peer': { name: 'fixture-optional-peer', version: '1.0.0' },
    } : {}),
  })) {
    packageData.set(root, {
      realRoot: root,
      packageBytes: Buffer.from(JSON.stringify(packageJson)),
    });
  }
  const result = resolveBunProductionClosure({
    lock,
    contract,
    platform: 'win32',
    architecture: 'x64',
    packageRoots: new Set(packageData.keys()),
    readPackageRoot: async (root) => packageData.get(root) ?? null,
  });
  return { lockBytes, lock, result, packageData, sdk };
}

test('derives and exactly matches a bounded pinned SDK installation closure', () => {
  const installation = syntheticInstallation();
  const result = derive(installation);

  assert.equal(result.sdkContract.packageName, '@gajae-code/coding-agent');
  assert.equal(result.sdkContract.packageVersion, '0.16.7');
  assert.equal(result.sdkContract.lockIntegrity, SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity);
  assert.equal(result.sdkContract.configSchemaVersion, 2);
  assert.equal(result.packageCount, 2);
  assert.match(result.closureFingerprint, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(result.sdkContract.sourceContracts), ['settings', 'model', 'auth', 'session']);
  assert.equal(Object.isFrozen(result.sdkContract), true);
  assert.equal(Object.isFrozen(result.sdkContract.sourceContracts), true);

  const matched = assertSdkExternalStateContract({
    ...installation,
    sdkExternalStateContractFingerprint: result.sdkContract.sdkExternalStateContractFingerprint,
  });
  assert.deepEqual(matched, result);
});

test('tampered transitive bytes change provenance and fail comparison with the signed contract', () => {
  const signed = derive();
  const tampered = syntheticInstallation({ transitiveBytes: 'tampered synthetic SDK dependency source\n' });
  const observed = derive(tampered);

  assert.notEqual(observed.closureFingerprint, signed.closureFingerprint);
  assert.notEqual(
    observed.sdkContract.sdkExternalStateContractFingerprint,
    signed.sdkContract.sdkExternalStateContractFingerprint,
  );
  invalid(() => assertSdkExternalStateContract({
    ...tampered,
    sdkExternalStateContractFingerprint: signed.sdkContract.sdkExternalStateContractFingerprint,
  }));
});

test('missing declared source roots and mismatched version-source bytes fail closed', () => {
  invalid(() => derive(syntheticInstallation({ omitSourceRoot: 'src/config/settings.ts' })));
  invalid(() => derive(syntheticInstallation({ mismatchConfigSource: true })));
});

test('SDK package, integrity, schema, and transcript version changes are rejected', () => {
  invalid(() => derive(syntheticInstallation({
    rootIdentity: '@gajae-code/coding-agent@0.16.8',
  })));
  invalid(() => derive(syntheticInstallation({
    rootIntegrity: `sha512-${Buffer.alloc(64, 0x34).toString('base64')}`,
  })));
  invalid(() => derive(syntheticInstallation({
    configSchemaSource: 'export const CONFIG_SCHEMA_VERSION = 3;\n',
  })));
  invalid(() => derive(syntheticInstallation({
    sessionManagerSource: 'export const CURRENT_SESSION_VERSION = 6;\n',
  })));
});

test('incomplete and overinclusive package closures are rejected', () => {
  invalid(() => derive(syntheticInstallation({ omitTransitive: true })));
  invalid(() => derive(syntheticInstallation({ includeUnreachable: true })));
});

test('package-count bounds are enforced before closure traversal', () => {
  const installation = syntheticInstallation();
  invalid(() => deriveSdkExternalStateContract({
    ...installation,
    packages: new Array(DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries + 1),
  }));
});

test('closed own-data input schemas reject getters and extra properties before evaluation', () => {
  let getterReads = 0;
  const topLevelGetter = syntheticInstallation();
  Object.defineProperty(topLevelGetter, 'packages', {
    enumerable: true,
    get() {
      getterReads += 1;
      return syntheticInstallation().packages;
    },
  });
  invalid(() => derive(topLevelGetter));

  const packageGetter = syntheticInstallation();
  Object.defineProperty(packageGetter.packages[0], 'identity', {
    enumerable: true,
    get() {
      getterReads += 1;
      return ROOT_IDENTITY;
    },
  });
  invalid(() => derive(packageGetter));

  for (const key of ['files', 'edges']) {
    const installation = syntheticInstallation();
    const values = installation.packages[0][key];
    Object.defineProperty(values, '0', {
      enumerable: true,
      get() {
        getterReads += 1;
        return values[0];
      },
    });
    invalid(() => derive(installation));
  }

  const fileGetter = syntheticInstallation();
  Object.defineProperty(fileGetter.packages[0].files[0], 'path', {
    enumerable: true,
    get() {
      getterReads += 1;
      return 'src/config/settings.ts';
    },
  });
  invalid(() => derive(fileGetter));

  const edgeGetter = syntheticInstallation();
  Object.defineProperty(edgeGetter.packages[0].edges[0], 'targetIdentity', {
    enumerable: true,
    get() {
      getterReads += 1;
      return TRANSITIVE_IDENTITY;
    },
  });
  invalid(() => derive(edgeGetter));

  const hiddenProperty = syntheticInstallation();
  Object.defineProperty(hiddenProperty.packages[0], 'ignored', { value: true });
  invalid(() => derive(hiddenProperty));

  const hiddenArrayProperty = syntheticInstallation();
  Object.defineProperty(hiddenArrayProperty.packages[0].files, 'ignored', { value: true });
  invalid(() => derive(hiddenArrayProperty));

  const symbolicProperty = syntheticInstallation();
  Object.defineProperty(symbolicProperty.packages[0].files, Symbol('extra'), { value: true });
  invalid(() => derive(symbolicProperty));

  const foreignArray = syntheticInstallation();
  Object.setPrototypeOf(foreignArray.packages[0].edges, Object.create(Array.prototype));
  invalid(() => derive(foreignArray));

  const foreignRecord = syntheticInstallation();
  Object.setPrototypeOf(foreignRecord.packages[0], null);
  invalid(() => derive(foreignRecord));

  const signed = derive().sdkContract;
  const signedFingerprintGetter = syntheticInstallation();
  Object.defineProperty(signedFingerprintGetter, 'sdkExternalStateContractFingerprint', {
    enumerable: true,
    get() {
      getterReads += 1;
      return signed.sdkExternalStateContractFingerprint;
    },
  });
  invalid(() => assertSdkExternalStateContract(signedFingerprintGetter));
  assert.equal(getterReads, 0);
});

test('canonical package and aggregate closure encodings stay within the byte budget', () => {
  const makeLargeFiles = (prefix, count) => Array.from({ length: count }, (_, index) => ({
    path: `${String(index).padStart(4, '0')}/${prefix}${'a'.repeat(3980)}`,
    size: 0,
    sha256: '0'.repeat(64),
    executablePolicy: 'forbidden',
  }));

  const packageOverflow = syntheticInstallation();
  packageOverflow.packages[0].files.push(...makeLargeFiles('p', 8500));
  invalid(() => derive(packageOverflow));

  const aggregateOverflow = syntheticInstallation({ omitTransitive: true });
  const root = aggregateOverflow.packages[0];
  root.edges = [];
  const largePackages = Array.from({ length: 4 }, (_, index) => {
    const identity = `fixture-large-${index}@1.0.0`;
    root.edges.push({ kind: 'dependency', name: `fixture-large-${index}`, targetIdentity: identity });
    return {
      identity,
      integrity: `sha512-${Buffer.alloc(64, index + 1).toString('base64')}`,
      files: makeLargeFiles(`g${index}`, 2100),
      edges: [],
    };
  });
  aggregateOverflow.packages.push(...largePackages);
  for (const record of aggregateOverflow.packages) {
    assert.ok(Buffer.byteLength(JSON.stringify(record)) < DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes);
  }
  assert.ok(Buffer.byteLength(JSON.stringify({ packages: aggregateOverflow.packages })) >
    DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes);
  invalid(() => derive(aggregateOverflow));
});

test('version source bytes must agree with their declared closure size', () => {
  const installation = syntheticInstallation();
  installation.packages[0].files.find(
    (entry) => entry.path === 'src/config/config-schema-version.ts',
  ).size += 1;
  invalid(() => derive(installation));
});

test('shared Bun parser and resolver preserve the builder SDK SRI and package edge graph', async () => {
  const fixture = productionGraphFixture();
  assert.equal(fixture.lock.sha256, hash(fixture.lockBytes));
  fixture.lock.identities.clear();
  fixture.lock.names.clear();
  fixture.lock.workspaces.clear();
  const { nodes } = await fixture.result;
  const daemon = nodes.get('workspace:daemon');
  const sdkEdge = daemon.edges.find((edge) => edge.name === SDK_EXTERNAL_STATE_REQUIREMENTS.packageName);
  const sdk = nodes.get(sdkEdge.targetKey);
  assert.equal(sdk.identity, ROOT_IDENTITY);
  assert.equal(sdk.integrity, SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity);
  assert.deepEqual(sdk.edges.map(({ kind, name, targetIdentity }) => ({ kind, name, targetIdentity })), [{
    kind: 'dependency',
    name: 'fixture-sdk-leaf',
    targetIdentity: 'fixture-sdk-leaf@1.0.0',
  }]);
});

test('shared Bun parser rejects corrupt JSONC, invalid SRI, and lock/package edge disagreement', async () => {
  productionInvalid(
    () => parseBunProductionLock(Buffer.from('{"lockfileVersion":1, broken')),
    'SERVICE_PRODUCTION_LOCK_INVALID',
  );
  const fixture = productionGraphFixture();
  const badSri = JSON.parse(fixture.lockBytes.toString('utf8'));
  badSri.packages[SDK_EXTERNAL_STATE_REQUIREMENTS.packageName][3] = 'sha512-not-a-64-byte-integrity';
  productionInvalid(
    () => parseBunProductionLock(Buffer.from(JSON.stringify(badSri))),
    'SERVICE_PRODUCTION_LOCK_INVALID',
  );

  const mismatched = productionGraphFixture({ corruptSdkEdge: true });
  await assert.rejects(mismatched.result, { code: 'SERVICE_PRODUCTION_LOCK_INVALID' });
});

test('shared resolver selects nested hoisted identity before the root package candidate', async () => {
  const fixture = productionGraphFixture({ nestedLeaf: true });
  const { nodes } = await fixture.result;
  const sdk = nodes.get(nodes.get('workspace:daemon').edges[0].targetKey);
  const leaf = nodes.get(sdk.edges[0].targetKey);
  assert.equal(leaf.root, 'node_modules/@gajae-code/coding-agent/node_modules/fixture-sdk-leaf');
  assert.equal(leaf.identity, 'fixture-sdk-leaf@1.2.0');
  assert.equal(nodes.get('location:node_modules/fixture-sdk-leaf').identity, 'fixture-sdk-leaf@1.5.0');
});

test('shared resolver preserves optional-peer absence and target-filtered optional dependency rules', async () => {
  const fixture = productionGraphFixture({
    optionalPeer: true,
    installOptionalPeer: false,
    optionalTarget: true,
  });
  const { nodes } = await fixture.result;
  const sdk = nodes.get(nodes.get('workspace:daemon').edges[0].targetKey);
  assert.deepEqual(sdk.edges.map(({ kind, name }) => ({ kind, name })), [
    { kind: 'dependency', name: 'fixture-sdk-leaf' },
  ]);
});

test('shared resolver includes an installed optional peer with its lock-authenticated identity', async () => {
  const fixture = productionGraphFixture({ optionalPeer: true });
  const { nodes } = await fixture.result;
  const sdk = nodes.get(nodes.get('workspace:daemon').edges[0].targetKey);
  assert.ok(sdk.edges.some((edge) =>
    edge.kind === 'optional-peer' && edge.targetIdentity === 'fixture-optional-peer@1.0.0'));
});

test('inventory package-root extraction handles workspaces, scoped roots, and nested hoisted roots', () => {
  assert.equal(bunPackageRootForPath('daemon/package.json'), 'daemon');
  assert.equal(bunPackageRootForPath('node_modules/@scope/package/package.json'),
    'node_modules/@scope/package');
  assert.equal(bunPackageRootForPath(
    'node_modules/outer/node_modules/@scope/package/package.json',
  ), 'node_modules/outer/node_modules/@scope/package');
  assert.equal(bunPackageRootForPath('node_modules/package/src/index.js'), null);
  assert.equal(bunPackageRootForPath('node_modules/../package/package.json'), null);
});

test('production-closure adapter rejects getters without evaluating them and refuses listed metadata absence', async () => {
  const fixture = productionGraphFixture();
  await fixture.result;
  const roots = new Set(fixture.packageData.keys());
  let getterReads = 0;
  const withGetter = resolveBunProductionClosure({
    lock: fixture.lock,
    contract: {
      sourceWorkspaces: [
        { path: 'bot', packageName: '@gjc-remote/bot', packageVersion: '0.4.0-rc.2' },
        { path: 'daemon', packageName: '@gjc-remote/daemon', packageVersion: '0.4.0-rc.2' },
        { path: 'native-control', packageName: '@gjc-remote/native-control', packageVersion: '1.0.0' },
        { path: 'shared', packageName: '@gjc-remote/shared', packageVersion: '0.4.0-rc.2' },
      ],
    },
    platform: 'win32',
    architecture: 'x64',
    packageRoots: roots,
    readPackageRoot: async (root) => {
      const facts = fixture.packageData.get(root);
      if (root !== 'node_modules/@gajae-code/coding-agent') return facts ?? null;
      const result = { realRoot: facts.realRoot };
      Object.defineProperty(result, 'packageBytes', {
        enumerable: true,
        get() {
          getterReads += 1;
          return facts.packageBytes;
        },
      });
      return result;
    },
  });
  await assert.rejects(withGetter, { code: 'SERVICE_PRODUCTION_CLOSURE_INVALID' });
  assert.equal(getterReads, 0);

  const missingListedPackage = resolveBunProductionClosure({
    lock: fixture.lock,
    contract: {
      sourceWorkspaces: [
        { path: 'bot', packageName: '@gjc-remote/bot', packageVersion: '0.4.0-rc.2' },
        { path: 'daemon', packageName: '@gjc-remote/daemon', packageVersion: '0.4.0-rc.2' },
        { path: 'native-control', packageName: '@gjc-remote/native-control', packageVersion: '1.0.0' },
        { path: 'shared', packageName: '@gjc-remote/shared', packageVersion: '0.4.0-rc.2' },
      ],
    },
    platform: 'win32',
    architecture: 'x64',
    packageRoots: roots,
    readPackageRoot: async (root) => root === 'node_modules/@gajae-code/coding-agent'
      ? null : fixture.packageData.get(root) ?? null,
  });
  await assert.rejects(missingListedPackage, { code: 'SERVICE_PRODUCTION_CLOSURE_INVALID' });
});
