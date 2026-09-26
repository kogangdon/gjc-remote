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
import { serviceRolesFingerprint } from '@gjc-remote/shared/service-lifecycle-envelope';
import { createGenesisEmptyChannels } from '@gjc-remote/shared/mapping-envelope';
import { createServiceCompatibilityObserverForTest } from '../src/service-compatibility.js';

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
      contractRevision: 1,
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
