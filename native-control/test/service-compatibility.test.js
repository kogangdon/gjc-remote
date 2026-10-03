import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  APPLICATION_DEPLOYMENT_REPOSITORY,
  buildApplicationDeploymentManifest,
  buildBundleInventory,
  buildDeploymentCompatibility,
} from '@gjc-remote/shared/deployment-envelope';
import { canonicalJsonBytes, canonicalJsonHash } from '@gjc-remote/shared/strict-json';
import {
  serviceNativeIdentityFingerprint,
  serviceRolesFingerprint,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { createGenesisEmptyChannels } from '@gjc-remote/shared/mapping-envelope';
import {
  createServiceCompatibilityObserverForTest,
  createSdkPackageRootReaderForTest,
  SERVICE_COMPATIBILITY_LIMITS,
} from '../src/service-compatibility.js';
import { SDK_EXTERNAL_STATE_REQUIREMENTS } from '../src/service-sdk-contract.js';
import {
  parseBunProductionLock,
  resolveBunProductionClosure,
  SERVICE_PRODUCTION_WORKSPACES,
} from '../src/service-production-closure.js';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const hex = (character) => character.repeat(64);

const roles = Object.freeze({
  management: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1001' }),
  bot: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1002' }),
  recovery: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1003' }),
  daemon: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1004' }),
  system: Object.freeze({ kind: 'sid', value: 'S-1-5-18' }),
});

function candidateManifest() {
  const inventory = buildBundleInventory({
    payloadEntries: [
      { path: 'bot/src/bot.js', size: 3, sha256: hex('1'), executablePolicy: 'forbidden' },
      { path: 'daemon/src/daemon.js', size: 5, sha256: hex('2'), executablePolicy: 'forbidden' },
      { path: 'native-control/build/Release/native-control.manifest.json', size: 7, sha256: hex('3'), executablePolicy: 'forbidden' },
    ],
  }, { platform: 'win32' });
  const inventoryBytes = canonicalJsonBytes(inventory, {
    maxBytes: 32 * 1024 * 1024,
    maxDepth: 16,
    maxNodes: 600_032,
  });
  const compatibility = buildDeploymentCompatibility({
    bot: {
      domains: [{
        domain: 'bot-mapping-reader',
        readableFormats: ['channels:gjc-management-channels/v2'],
        writableFormats: ['channels:gjc-management-channels/v2'],
      }],
    },
    daemon: {
      domains: [
        { domain: 'daemon-app-session', readableFormats: ['sdk-session:transcript@5'], writableFormats: ['sdk-session:transcript@5'] },
        { domain: 'workspace-lifecycle', readableFormats: ['workspace:workspace-lifecycle-head@1'], writableFormats: ['workspace:workspace-lifecycle-head@1'] },
      ],
      sdkExternalStateContractFingerprint: hex('9'),
    },
  });
  return buildApplicationDeploymentManifest({
    signingKeyId: 'deployment-test',
    releaseId: 'v1.2.3',
    releaseVersion: '1.2.3',
    releaseSequence: 7,
    source: {
      repository: APPLICATION_DEPLOYMENT_REPOSITORY,
      tag: 'v1.2.3',
      commit: '1'.repeat(40),
      tree: '2'.repeat(40),
      bunLockSha256: hex('3'),
    },
    target: { platform: 'win32', architecture: 'x64' },
    archive: {
      name: 'gjc-remote-service-1.2.3-win32-x64.tar.gz',
      mediaType: 'application/gzip',
      byteLength: 4096,
      sha256: hex('4'),
      entryCount: inventory.payloadEntryCount + 1,
    },
    inventory: {
      path: 'bundle-files.json',
      byteLength: inventoryBytes.byteLength,
      sha256: hash(inventoryBytes),
      payloadEntryCount: inventory.payloadEntryCount,
      unpackedPayloadBytes: inventory.unpackedPayloadBytes,
      treeFingerprint: inventory.treeFingerprint,
    },
    entrypoints: { bot: 'bot/src/bot.js', daemon: 'daemon/src/daemon.js' },
    runtimes: { node: { minimumVersion: '26.0.0' }, bun: { minimumVersion: '1.4.0' } },
    nativeControl: {
      manifestPath: 'native-control/build/Release/native-control.manifest.json',
      manifestFingerprint: hex('5'),
      contractVersion: 5,
      contractRevision: 2,
    },
    wireCapabilities: ['gate_presentation_v1', 'terminal_disposition_v1'],
    compatibility,
  });
}

function binding(candidate = candidateManifest()) {
  return {
    candidate,
    component: 'bot',
    serviceKey: 'bot',
    roles,
    workingDirectory: 'C:\\service',
    channelsConfig: 'C:\\service\\channels.json',
  };
}

function nativeIdentity(profile, id = '00000000000000000000000000000001', owner = roles.management.value) {
  return {
    profile,
    kind: 'win32-service-object-v1',
    volumeSerial: '0000000000000001',
    fileId: id,
    attributes: 0,
    owner,
    securitySha256: hex('a'),
  };
}

function daemonBinding(candidate = candidateManifest()) {
  return {
    candidate,
    component: 'daemon',
    serviceKey: `daemon-host-${'d'.repeat(64)}`,
    roles,
    workingDirectory: 'C:\\service',
    channelsConfig: null,
  };
}

function daemonSdkObserver({
  profileEntryCount = 0,
  installationEntryCount = 0,
  installationListing = undefined,
  includeSidecars = false,
  omitSignature = false,
  foreignManifest = false,
} = {}) {
  const binding = daemonBinding();
  const installationRoot = 'C:\\sdk-install';
  const profileRoot = 'C:\\sdk-profile';
  const configIdentity = nativeIdentity('service-daemon-config-directory');
  const catalogIdentity = nativeIdentity('service-daemon-config-file', '00000000000000000000000000000002');
  const profileIdentity = nativeIdentity('service-sdk-install-directory', '00000000000000000000000000000003');
  const installationIdentity = nativeIdentity('service-sdk-install-directory', '00000000000000000000000000000004');
  const sdkContractFingerprint = hex('9');
  const stateIdentityAttestationFields = {
    schemaVersion: 1,
    profileIdentityFingerprint: serviceNativeIdentityFingerprint(
      profileIdentity, 'win32', 'service-sdk-install-directory'),
    sdkExternalStateContractFingerprint: sdkContractFingerprint,
    guarantee: 'operator-attested-identity',
  };
  const sdk = {
    installationRoot,
    profileRoot,
    packageVersion: SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion,
    lockIntegrity: SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity,
    sdkExternalStateContractFingerprint: sdkContractFingerprint,
    provenanceManifestPath: 'application.manifest.json',
    provenanceSignaturePath: 'application.manifest.json.sig',
    stateIdentityAttestation: {
      ...stateIdentityAttestationFields,
      attestationFingerprint: canonicalJsonHash(stateIdentityAttestationFields),
    },
  };
  const catalogFields = {
    schemaVersion: 1,
    kind: 'windows-service-state-scope',
    serviceKey: binding.serviceKey,
    rolesFingerprint: serviceRolesFingerprint(roles, 'win32'),
    workDirs: [],
    nativeWorkspaceRoots: [],
    sdk,
  };
  const catalog = Buffer.from(JSON.stringify({
    ...catalogFields,
    scopeFingerprint: canonicalJsonHash(catalogFields),
  }));
  const directoryEntries = (count, identityOffset) => Array.from({ length: count }, (_, index) => ({
    name: `entry-${String(index).padStart(5, '0')}.js`,
    kind: 'file',
    identity: nativeIdentity('service-sdk-install-file', (identityOffset + index).toString(16).padStart(32, '0')),
  }));
  const profileEntries = directoryEntries(profileEntryCount, 100);
  const sidecarContents = new Map();
  const sidecarEntries = includeSidecars ? [
    {
      name: sdk.provenanceManifestPath,
      kind: 'file',
      identity: nativeIdentity('service-sdk-install-file', '00000000000000000000000000000005'),
      bytes: canonicalJsonBytes(candidateManifest()),
    },
    ...(!omitSignature ? [{
      name: sdk.provenanceSignaturePath,
      kind: 'file',
      identity: nativeIdentity('service-sdk-install-file', '00000000000000000000000000000006'),
      bytes: Buffer.from('{}'),
    }] : []),
  ] : [];
  for (const entry of sidecarEntries) sidecarContents.set(entry.name, entry);
  const installationEntries = installationListing ?? [
    ...directoryEntries(installationEntryCount, 10_000),
    ...sidecarEntries.map(({ name, kind, identity }) => ({ name, kind, identity })),
  ].sort((left, right) => Buffer.compare(Buffer.from(left.name, 'utf8'), Buffer.from(right.name, 'utf8')));
  const installationByName = new Map(installationEntries
    .filter((entry) => entry !== null)
    .map((entry) => [entry.name, entry]));
  let installationChildReads = 0;
  const sidecarByteReads = [];
  const fileObservation = (identity, bytes) => ({
    kind: 'file', identity, absence: null, bytes, entries: null, writes: 0,
  });
  const directoryObservation = (identity, entries) => ({
    kind: 'directory', identity, absence: null, bytes: null, entries, writes: 0,
  });
  const native = {
    open_service_external_root(absolutePath, profile) {
      const rootIdentity = absolutePath === 'C:\\service' && profile === 'config' ? configIdentity :
        absolutePath === profileRoot && profile === 'sdk-install' ? profileIdentity :
          absolutePath === installationRoot && profile === 'sdk-install' ? installationIdentity : null;
      if (rootIdentity === null) throw new Error(`unexpected root ${absolutePath}:${profile}`);
      return { handle: { absolutePath }, profile, absolutePath, rootIdentity, absence: null, writes: 0 };
    },
    read_service_external_object(handle, relativePath, mode) {
      if (handle.absolutePath === 'C:\\service' && relativePath === 'service-authority.json' && mode === 'bytes') {
        return fileObservation(catalogIdentity, catalog);
      }
      if (handle.absolutePath === profileRoot && relativePath === '' && mode === 'directory') {
        return directoryObservation(profileIdentity, profileEntries);
      }
      if (handle.absolutePath === installationRoot && relativePath === '' && mode === 'directory') {
        return directoryObservation(installationIdentity, installationEntries);
      }
      if (handle.absolutePath === installationRoot) {
        const sidecar = sidecarContents.get(relativePath);
        if (mode === 'bytes' && sidecar) {
          sidecarByteReads.push(relativePath);
          const identity = foreignManifest && relativePath === sdk.provenanceManifestPath
            ? nativeIdentity('service-sdk-install-file', '00000000000000000000000000000007')
            : sidecar.identity;
          return fileObservation(identity, sidecar.bytes);
        }
      }
      if (handle.absolutePath === installationRoot && mode === 'facts') {
        installationChildReads += 1;
        const entry = installationByName.get(relativePath);
        if (entry) return fileObservation(entry.identity, null);
      }
      throw new Error(`unexpected native object ${handle.absolutePath}:${relativePath}:${mode}`);
    },
    read_file_facts_no_follow(absolutePath) {
      const relativePath = absolutePath.slice(installationRoot.length + 1);
      const sidecar = sidecarContents.get(relativePath);
      if (!sidecar) throw new Error(`unexpected SDK facts path ${absolutePath}`);
      return {
        kind: 'win32-file-v1',
        volumeSerial: sidecar.identity.volumeSerial,
        fileId: sidecar.identity.fileId,
        size: sidecar.bytes.byteLength,
        sha256: hash(sidecar.bytes),
        attributes: sidecar.identity.attributes,
        owner: sidecar.identity.owner,
        securitySha256: sidecar.identity.securitySha256,
      };
    },
    close_service_handle() {
      return { writes: 0 };
    },
  };
  return {
    observer: createServiceCompatibilityObserverForTest({ binding, native }),
    get installationChildReads() { return installationChildReads; },
    sidecarByteReads,
  };
}

test('SDK package-root callback supplies the exact facts accepted by the production closure resolver', async () => {
  const packageNames = {
    bot: '@gjc-remote/bot',
    daemon: '@gjc-remote/daemon',
    'native-control': '@gjc-remote/native-control',
    shared: '@gjc-remote/shared',
  };
  const sourceWorkspaces = SERVICE_PRODUCTION_WORKSPACES.map((root) => ({
    path: root,
    packageName: packageNames[root],
    packageVersion: '1.0.0',
  }));
  const workspaces = Object.fromEntries([
    ['', { name: 'gjc-remote', version: '1.0.0' }],
    ...sourceWorkspaces.map(({ path, packageName, packageVersion }) => [
      path, { name: packageName, version: packageVersion },
    ]),
  ]);
  const packages = Object.fromEntries(sourceWorkspaces.map(({ path, packageName }) => [
    packageName, [`${packageName}@workspace:${path}`],
  ]));
  const lock = parseBunProductionLock(Buffer.from(JSON.stringify({
    lockfileVersion: 1,
    configVersion: 0,
    workspaces,
    packages,
  })));
  const packageBytes = new Map(sourceWorkspaces.map(({ path, packageName, packageVersion }) => [
    path, Buffer.from(JSON.stringify({ name: packageName, version: packageVersion })),
  ]));
  const readRoots = [];
  const readPackageRoot = createSdkPackageRootReaderForTest({
    packageRoots: new Set(SERVICE_PRODUCTION_WORKSPACES),
    rootEntries: new Map([...packageBytes].map(([root, bytes]) => [root, { size: bytes.byteLength }])),
    treeByPath: new Map(SERVICE_PRODUCTION_WORKSPACES.map((root) => [root, {
      kind: 'directory',
      identityFingerprint: hash(root),
    }])),
    readPackageFile(root, entry) {
      readRoots.push(root);
      const bytes = packageBytes.get(root);
      assert.equal(entry.size, bytes.byteLength);
      return { bytes };
    },
  });

  const closure = await resolveBunProductionClosure({
    lock,
    contract: { sourceWorkspaces },
    platform: 'win32',
    architecture: 'x64',
    packageRoots: new Set(SERVICE_PRODUCTION_WORKSPACES),
    readPackageRoot,
  });

  assert.deepEqual(closure.admittedRoots, new Set(SERVICE_PRODUCTION_WORKSPACES));
  assert.deepEqual(readRoots, SERVICE_PRODUCTION_WORKSPACES);
  assert.equal(closure.nodes.size, SERVICE_PRODUCTION_WORKSPACES.length);
  for (const node of closure.nodes.values()) {
    assert.deepEqual(node.packageBytes, packageBytes.get(node.root));
  }
});

test('bounded listing hashes preserve canonical digests for small existing inventories', () => {
  const listing = [{ path: 'src/daemon.js', kind: 'file', identityFingerprint: hex('a') }];
  assert.equal(
    canonicalJsonHash(listing, {
      maxDepth: 2,
      maxNodes: SERVICE_COMPATIBILITY_LIMITS.inventoryEntries * 4 + 1,
    }),
    canonicalJsonHash(listing),
  );
});

test('large SDK profile and installation listings pass the compatibility inventory hashing boundary', async () => {
  // Each mapped entry contains its object plus three values: 3,000 entries
  // exceed strict-json's default 10,000-node limit without nearing inventory caps.
  for (const [label, options, expectedChildReads] of [
    ['profile', { profileEntryCount: 3_000 }, 0],
    ['installation', { installationEntryCount: 3_000 }, 3_000],
  ]) {
    const fixture = daemonSdkObserver(options);
    await assert.rejects(() => fixture.observer.assertFirstInstall(), {
      code: 'SERVICE_COMPATIBILITY_SDK_FILE_NOT_IN_INSTALLATION',
      writes: 0,
    }, label);
    assert.equal(fixture.installationChildReads, expectedChildReads, label);
  }
});

test('present SDK provenance sidecars are read from the authenticated installation tree before signature validation', async () => {
  const fixture = daemonSdkObserver({ includeSidecars: true });
  await assert.rejects(() => fixture.observer.assertFirstInstall(), {
    code: 'DEPLOYMENT_MANIFEST_INVALID',
    writes: 0,
  });
  assert.deepEqual(fixture.sidecarByteReads, [
    'application.manifest.json',
    'application.manifest.json.sig',
  ]);
});

test('missing or foreign SDK provenance files remain a refusal', async () => {
  const missing = daemonSdkObserver({ includeSidecars: true, omitSignature: true });
  await assert.rejects(() => missing.observer.assertFirstInstall(), {
    code: 'SERVICE_COMPATIBILITY_SDK_FILE_NOT_IN_INSTALLATION',
    writes: 0,
  });
  assert.deepEqual(missing.sidecarByteReads, ['application.manifest.json']);

  const foreign = daemonSdkObserver({ includeSidecars: true, foreignManifest: true });
  await assert.rejects(() => foreign.observer.assertFirstInstall(), {
    code: 'SERVICE_COMPATIBILITY_SDK_FILE_PROFILE_DRIFT',
    writes: 0,
  });
  assert.deepEqual(foreign.sidecarByteReads, ['application.manifest.json']);
});

test('SDK directory inventories above the compatibility limit refuse before hashing entries', async () => {
  const fixture = daemonSdkObserver({ installationListing: Array(100_001).fill(null) });
  await assert.rejects(() => fixture.observer.assertFirstInstall(), {
    code: 'SERVICE_COMPATIBILITY_INVENTORY_INCOMPLETE',
    writes: 0,
  });
  assert.equal(fixture.installationChildReads, 0);
});

test('missing required native root is a refusal, not an empty compatibility receipt', async () => {
  let closeCount = 0;
  let readCount = 0;
  const native = {
    open_service_external_root(absolutePath, profile) {
      return {
        handle: {},
        profile,
        absolutePath,
        rootIdentity: null,
        absence: {
          parentIdentity: nativeIdentity('service-external-anchor-directory'),
          missingSegments: ['service'],
        },
        writes: 0,
      };
    },
    read_service_external_object() {
      readCount += 1;
      throw new Error('unexpected read after absent required root');
    },
    close_service_handle() {
      closeCount += 1;
    },
  };
  const observer = createServiceCompatibilityObserverForTest({ binding: binding(), native });

  await assert.rejects(() => observer.assertFirstInstall(), { code: 'SERVICE_COMPATIBILITY_ROOT_ABSENT', writes: 0 });
  assert.equal(closeCount, 1);
  assert.equal(readCount, 0);
});

test('native read denial remains a refusal and the opened root handle is closed', async () => {
  let closeCount = 0;
  let readCount = 0;
  const native = {
    open_service_external_root(absolutePath, profile) {
      return {
        handle: {},
        profile,
        absolutePath,
        rootIdentity: nativeIdentity('service-bot-config-directory'),
        absence: null,
        writes: 0,
      };
    },
    read_service_external_object() {
      readCount += 1;
      throw Object.assign(new Error('access denied'), { code: 'SERVICE_ACCESS_DENIED', writes: 0 });
    },
    close_service_handle() {
      closeCount += 1;
    },
  };
  const observer = createServiceCompatibilityObserverForTest({ binding: binding(), native });

  await assert.rejects(() => observer.assertFirstInstall(), { code: 'SERVICE_ACCESS_DENIED', writes: 0 });
  assert.equal(closeCount, 1);
  assert.equal(readCount, 1);
});

test('fake native observations cannot mint a first-install evidence receipt', async () => {
  const configIdentity = nativeIdentity('service-bot-config-directory');
  const catalogFields = {
    schemaVersion: 1,
    kind: 'windows-service-state-scope',
    serviceKey: 'bot',
    rolesFingerprint: serviceRolesFingerprint(roles, 'win32'),
    workDirs: [],
    nativeWorkspaceRoots: [],
    sdk: null,
  };
  const catalog = Buffer.from(JSON.stringify({
    ...catalogFields,
    scopeFingerprint: canonicalJsonHash(catalogFields),
  }));
  const channels = Buffer.from(JSON.stringify(createGenesisEmptyChannels({
    tokenConfigGeneration: 1,
    tokenConfigHostSetFingerprint: hex('b'),
    fenceGeneration: 1,
  })));
  let closeCount = 0;
  const native = {
    open_service_external_root(absolutePath, profile) {
      if (absolutePath === 'C:\\service' && profile === 'config') {
        return { handle: { absolutePath }, profile, absolutePath, rootIdentity: configIdentity, absence: null, writes: 0 };
      }
      if (absolutePath === 'C:\\service\\.gjc-remote-control' && profile === 'retained-state') {
        return {
          handle: { absolutePath },
          profile,
          absolutePath,
          rootIdentity: null,
          absence: { parentIdentity: configIdentity, missingSegments: ['.gjc-remote-control'] },
          writes: 0,
        };
      }
      throw new Error('unexpected external root');
    },
    read_service_external_object(handle, relativePath, mode) {
      const absent = (name) => ({
        kind: 'absent',
        identity: null,
        absence: { parentIdentity: configIdentity, missingSegments: [name] },
        bytes: null,
        entries: null,
        writes: 0,
      });
      const file = (id, bytes) => ({
        kind: 'file',
        identity: nativeIdentity('service-bot-config-file', id),
        absence: null,
        bytes,
        entries: null,
        writes: 0,
      });
      if (handle.absolutePath !== 'C:\\service') throw new Error('unexpected native handle');
      if (relativePath === 'service-authority.json' && mode === 'bytes') {
        return file('00000000000000000000000000000002', catalog);
      }
      if (relativePath === 'channels.json' && mode === 'bytes') {
        return file('00000000000000000000000000000003', channels);
      }
      if (mode === 'facts' && [
        '.channels.json.managed-history.json',
        '.channels.json.genesis-bootstrap-blocker',
      ].includes(relativePath)) return absent(relativePath);
      throw new Error(`unexpected native object ${relativePath}:${mode}`);
    },
    close_service_handle() {
      closeCount += 1;
      return { writes: 0 };
    },
  };
  const observer = createServiceCompatibilityObserverForTest({ binding: binding(), native });

  await assert.rejects(() => observer.assertFirstInstall(), { code: 'SERVICE_COMPATIBILITY_RECEIPT_PROVENANCE', writes: 0 });
  assert.equal(closeCount, 4);
  // Update reuses the captured evidence and cannot bypass receipt provenance.
  await assert.rejects(() => observer.assertUpdate({ current: {}, expectedScopeFingerprint: 'a'.repeat(64) }),
    { code: 'SERVICE_COMPATIBILITY_RECEIPT_PROVENANCE', writes: 0 });
  await assert.rejects(() => observer.assertUpdate({ current: {} }), { code: 'SERVICE_COMPATIBILITY_BINDING', writes: 0 });
  assert.equal(closeCount, 4, 'update does not re-open native roots');
});
