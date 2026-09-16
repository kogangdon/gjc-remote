import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import {
  buildApplicationDeploymentManifest,
  buildDeploymentCompatibility,
  buildShawlDeploymentManifest,
  deploymentSignaturePreimage,
  DEPLOYMENT_SIGNATURE_DOMAINS,
  SHAWL_UPSTREAM,
} from '@gjc-remote/shared/deployment-envelope';
import { assertPinnedDeploymentManifest, readDeploymentInputFile, verifyDeploymentProvenance, verifyPinnedDeploymentProvenance } from '../src/deployment-provenance.js';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';

// Ephemeral keys are confined to this pure verifier fixture; no production files are written.
const applicationKey = generateKeyPairSync('ed25519');
const shawlKey = generateKeyPairSync('ed25519');
const nativeKey = generateKeyPairSync('ed25519');
const wrongKey = generateKeyPairSync('ed25519');
const pem = (key) => key.publicKey.export({ type: 'spki', format: 'pem' });
const keyEntry = (key, keyId) => ({ keyId, algorithm: 'ed25519', publicKeyPem: pem(key) });
const trustBytes = (entries) => Buffer.from(JSON.stringify({ version: 1, keys: entries }));
const applicationEntry = keyEntry(applicationKey, 'application-test');
const shawlEntry = keyEntry(shawlKey, 'shawl-test');
const nativeEntry = keyEntry(nativeKey, 'native-test');

function fixture({ key = shawlKey, signingKeyId = shawlEntry.keyId } = {}) {
  const manifest = buildShawlDeploymentManifest({
    signingKeyId,
    releaseSequence: 1,
    target: { platform: 'win32', architecture: 'x64' },
    upstream: {
      repository: SHAWL_UPSTREAM.repository,
      tag: SHAWL_UPSTREAM.tag,
      commit: SHAWL_UPSTREAM.commit,
      assetId: 42,
      assetName: 'shawl-v1.9.0-win64.zip',
      zipSha256: '1'.repeat(64),
    },
    executable: { name: 'shawl.exe', byteLength: 100, sha256: '2'.repeat(64), version: '1.9.0', versionOutput: 'shawl 1.9.0', authenticode: 'unsigned' },
    projectAsset: { repository: 'kogangdon/gjc-remote', tag: 'v0.3.1', name: 'gjc-remote-shawl-win32-x64.exe' },
  });
  const sidecar = {
    schemaVersion: 1,
    kind: 'shawl-deployment-signature',
    domain: DEPLOYMENT_SIGNATURE_DOMAINS.shawl,
    keyId: signingKeyId,
    algorithm: 'ed25519',
    manifestFingerprint: manifest.manifestFingerprint,
    signature: sign(null, deploymentSignaturePreimage('shawl', manifest), key.privateKey).toString('base64'),
  };
  return {
    purpose: 'shawl',
    manifestBytes: canonicalJsonBytes(manifest),
    signatureBytes: canonicalJsonBytes(sidecar),
    applicationTrustBytes: trustBytes([applicationEntry]),
    shawlTrustBytes: trustBytes([shawlEntry]),
    nativeTrustBytes: trustBytes([nativeEntry]),
    platform: 'win32',
    architecture: 'x64',
  };
}

function refuses(input, code) {
  assert.throws(() => verifyDeploymentProvenance(input), (error) => {
    assert.equal(error.code, code);
    assert.equal(error.writes, 0);
    assert.equal(error.message, code);
    return true;
  });
}

function modifySignature(input, change) {
  const sidecar = JSON.parse(input.signatureBytes);
  change(sidecar);
  return { ...input, signatureBytes: canonicalJsonBytes(sidecar) };
}

test('dedicated deployment key verifies domain-bound Shawl attestation, not native provenance', () => {
  const result = verifyDeploymentProvenance(fixture());
  assert.equal(result.manifest.executable.authenticode, 'unsigned');
  assert.equal(result.signingKeyId, shawlEntry.keyId);
  assert.match(result.signingKeyFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(result.nativeAddonProvenance, 'independent-verification-required');
});

test('application signature binds its exact tuple and cannot certify another platform', () => {
  const hash = 'a'.repeat(64);
  const manifest = buildApplicationDeploymentManifest({
    signingKeyId: applicationEntry.keyId,
    releaseId: 'v1.2.3',
    releaseVersion: '1.2.3',
    releaseSequence: 1,
    source: { repository: 'kogangdon/gjc-remote', tag: 'v1.2.3', commit: 'a'.repeat(40), tree: 'b'.repeat(40), bunLockSha256: hash },
    target: { platform: 'linux', architecture: 'x64' },
    archive: { name: 'gjc-remote-service-1.2.3-linux-x64.tar.gz', mediaType: 'application/gzip', byteLength: 100, sha256: hash, entryCount: 4 },
    inventory: { path: 'bundle-files.json', byteLength: 100, sha256: hash, payloadEntryCount: 3, unpackedPayloadBytes: 100, treeFingerprint: hash },
    entrypoints: { bot: 'bot/src/bot.js', daemon: 'daemon/src/daemon.js' },
    runtimes: { node: { minimumVersion: '26.0.0' }, bun: { minimumVersion: '1.4.0' } },
    nativeControl: { manifestPath: 'native-control/build/Release/native-control.manifest.json', manifestFingerprint: hash, contractVersion: 4, contractRevision: 4 },
    wireCapabilities: ['gate_presentation_v1'],
    compatibility: buildDeploymentCompatibility({
      bot: { domains: [{ domain: 'bot-mapping-reader', readableFormats: ['mapping-v1'], writableFormats: ['mapping-v1'] }] },
      daemon: {
        domains: [
          { domain: 'daemon-app-session', readableFormats: ['session-v1'], writableFormats: ['session-v1'] },
          { domain: 'workspace-lifecycle', readableFormats: ['workspace-v1'], writableFormats: ['workspace-v1'] },
        ],
        sdkExternalStateContractFingerprint: hash,
      },
    }),
  });
  const sidecar = {
    schemaVersion: 1, kind: 'application-deployment-signature',
    domain: DEPLOYMENT_SIGNATURE_DOMAINS.application,
    keyId: applicationEntry.keyId, algorithm: 'ed25519',
    manifestFingerprint: manifest.manifestFingerprint,
    signature: sign(null, deploymentSignaturePreimage('application', manifest), applicationKey.privateKey).toString('base64'),
  };
  const input = {
    ...fixture(), purpose: 'application', platform: 'linux',
    manifestBytes: canonicalJsonBytes(manifest), signatureBytes: canonicalJsonBytes(sidecar),
  };
  const result = verifyDeploymentProvenance(input);
  assert.equal(result.manifestFingerprint, manifest.manifestFingerprint);
  assert.throws(() => { result.manifest.target.platform = 'win32'; }, TypeError);
  assert.throws(() => { result.manifest.payloadEntries[0].sha256 = 'b'.repeat(64); }, TypeError);
  assert.throws(() => result.manifest.payloadEntries.pop(), TypeError);
  assert.deepEqual(result.manifest, manifest);
  refuses({ ...input, architecture: 'arm64' }, 'DEPLOYMENT_TARGET_INVALID');
  refuses({ ...input, purpose: 'shawl', platform: 'win32' }, 'DEPLOYMENT_MANIFEST_INVALID');
});

test('application and Shawl verification use only their purpose-specific roots', () => {
  const input = fixture();
  refuses({ ...input, shawlTrustBytes: undefined }, 'DEPLOYMENT_TRUST_INVALID');
  assert.equal(verifyDeploymentProvenance({ ...input, applicationTrustBytes: undefined }).signingKeyId, shawlEntry.keyId);
  refuses({ ...input, shawlTrustBytes: input.applicationTrustBytes }, 'DEPLOYMENT_SIGNING_KEY_UNKNOWN');
});

test('native key ID and native SPKI reuse each fail independently before signature acceptance', () => {
  const input = fixture();
  refuses({ ...input, nativeTrustBytes: trustBytes([keyEntry(nativeKey, shawlEntry.keyId)]) }, 'DEPLOYMENT_TRUST_DOMAIN_COLLISION');
  refuses({ ...input, nativeTrustBytes: trustBytes([keyEntry(shawlKey, 'different-native-id')]) }, 'DEPLOYMENT_TRUST_DOMAIN_COLLISION');
});

test('all trust entries are checked, including unused colliding keys', () => {
  const input = fixture();
  refuses({ ...input, shawlTrustBytes: trustBytes([shawlEntry, keyEntry(nativeKey, 'unused-key')]) }, 'DEPLOYMENT_TRUST_DOMAIN_COLLISION');
});

test('unknown signing key, wrong key and altered signature fail closed', () => {
  refuses(fixture({ signingKeyId: 'untrusted' }), 'DEPLOYMENT_SIGNING_KEY_UNKNOWN');
  refuses(fixture({ key: wrongKey }), 'DEPLOYMENT_SIGNATURE_INVALID');
  refuses(modifySignature(fixture(), (sidecar) => { sidecar.signature = Buffer.alloc(64).toString('base64'); }), 'DEPLOYMENT_SIGNATURE_INVALID');
});

test('application-domain and raw-native signature replays cannot verify as Shawl', () => {
  const input = fixture();
  refuses(modifySignature(input, (sidecar) => { sidecar.domain = DEPLOYMENT_SIGNATURE_DOMAINS.application; }), 'DEPLOYMENT_MANIFEST_INVALID');
  const replay = modifySignature(input, (sidecar) => {
    sidecar.signature = sign(null, input.manifestBytes, shawlKey.privateKey).toString('base64');
  });
  refuses(replay, 'DEPLOYMENT_SIGNATURE_INVALID');
});

test('noncanonical JSON, tampered manifest and malformed sidecar encoding are refused', () => {
  const input = fixture();
  refuses({ ...input, manifestBytes: Buffer.concat([input.manifestBytes, Buffer.from('\n')]) }, 'DEPLOYMENT_MANIFEST_INVALID');
  refuses({ ...input, signatureBytes: Buffer.concat([input.signatureBytes, Buffer.from('\n')]) }, 'DEPLOYMENT_MANIFEST_INVALID');
  const manifest = JSON.parse(input.manifestBytes);
  manifest.releaseSequence = 2;
  refuses({ ...input, manifestBytes: canonicalJsonBytes(manifest) }, 'DEPLOYMENT_MANIFEST_INVALID');
  refuses(modifySignature(input, (sidecar) => { sidecar.signature += '='; }), 'DEPLOYMENT_MANIFEST_INVALID');
  refuses(modifySignature(input, (sidecar) => { sidecar.extra = true; }), 'DEPLOYMENT_MANIFEST_INVALID');
});

test('wrong platform, unsupported tuple and unknown purpose are refused', () => {
  const input = fixture();
  for (const delta of [{ platform: 'linux' }, { architecture: 'arm64' }, { purpose: 'native' }]) {
    refuses({ ...input, ...delta }, 'DEPLOYMENT_TARGET_INVALID');
  }
});

test('empty, missing, malformed, duplicate and wrong-algorithm trust stores cannot bootstrap', () => {
  const input = fixture();
  const invalid = [
    undefined,
    Buffer.from('{'),
    trustBytes([]),
    trustBytes([applicationEntry, applicationEntry]),
    trustBytes([applicationEntry, { ...applicationEntry, keyId: 'same-spki-other-id' }]),
    trustBytes([{ ...applicationEntry, algorithm: 'p256' }]),
    trustBytes([{ ...applicationEntry, publicKeyPem: 'not-a-key' }]),
    trustBytes([{ ...applicationEntry, privateKeyPem: 'forbidden' }]),
    Buffer.alloc(64 * 1024 + 1),
  ];
  for (const shawlTrustBytes of invalid) refuses({ ...input, shawlTrustBytes }, 'DEPLOYMENT_TRUST_INVALID');
  refuses({ ...input, nativeTrustBytes: trustBytes([]) }, 'DEPLOYMENT_TRUST_INVALID');
  refuses({ ...input, nativeTrustBytes: undefined }, 'DEPLOYMENT_TRUST_INVALID');
});

test('manifest and signature byte limits reject oversized input', () => {
  const input = fixture();
  refuses({ ...input, manifestBytes: Buffer.alloc(1024 * 1024 + 1) }, 'DEPLOYMENT_MANIFEST_INVALID');
  refuses({ ...input, signatureBytes: Buffer.alloc(16 * 1024 + 1) }, 'DEPLOYMENT_MANIFEST_INVALID');
});

test('trust key-count and byte limits accept their maxima and reject overflow', () => {
  const input = fixture();
  const entries = [shawlEntry];
  for (let index = 1; index < 32; index += 1) {
    entries.push(keyEntry(generateKeyPairSync('ed25519'), `shawl-test-${index}`));
  }
  const encoded = trustBytes(entries);
  const maximum = Buffer.concat([encoded, Buffer.alloc(64 * 1024 - encoded.length, 32)]);
  assert.equal(verifyDeploymentProvenance({ ...input, shawlTrustBytes: maximum }).signingKeyId, shawlEntry.keyId);
  refuses({ ...input, shawlTrustBytes: Buffer.concat([maximum, Buffer.from(' ')]) }, 'DEPLOYMENT_TRUST_INVALID');
  entries.push(keyEntry(generateKeyPairSync('ed25519'), 'shawl-test-overflow'));
  refuses({ ...input, shawlTrustBytes: trustBytes(entries) }, 'DEPLOYMENT_TRUST_INVALID');
});

test('explicit-trust receipts and caller objects never acquire pinned authority', () => {
  const receipt = verifyDeploymentProvenance(fixture());
  for (const value of [receipt, receipt.manifest, { ...receipt.manifest }, null, undefined]) {
    assert.throws(
      () => assertPinnedDeploymentManifest(value, 'shawl'),
      { code: 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED', writes: 0 },
    );
  }
  assert.throws(
    () => assertPinnedDeploymentManifest(undefined, undefined),
    { code: 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED', writes: 0 },
  );
});

test('pinned manifest brands bind exact objects, purposes and isolated installation instances', async () => {
  const installation = await createPinnedDeploymentInstallation({ keyIds: ['shawl-test'] });
  let other;
  try {
    other = await createPinnedDeploymentInstallation({ keyIds: ['shawl-test'] });
    const manifest = installation.verifyManifest(JSON.parse(fixture().manifestBytes));
    assert.equal(installation.provenance.assertPinnedDeploymentManifest(manifest, 'shawl'), manifest);
    assert.equal(Object.isFrozen(manifest), true);
    assert.equal(Object.isFrozen(manifest.executable), true);
    assert.throws(() => { manifest.executable.sha256 = '0'.repeat(64); }, TypeError);
    for (const [check, value, purpose] of [
      [installation.provenance.assertPinnedDeploymentManifest, manifest, 'application'],
      [installation.provenance.assertPinnedDeploymentManifest, { ...manifest }, 'shawl'],
      [installation.provenance.assertPinnedDeploymentManifest, JSON.parse(JSON.stringify(manifest)), 'shawl'],
      [installation.provenance.assertPinnedDeploymentManifest, installation.provenance.verifyDeploymentProvenance(fixture()).manifest, 'shawl'],
      [other.provenance.assertPinnedDeploymentManifest, manifest, 'shawl'],
      [assertPinnedDeploymentManifest, manifest, 'shawl'],
    ]) {
      assert.throws(
        () => check(value, purpose),
        { code: 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED', writes: 0 },
      );
    }
  } finally {
    other?.dispose();
    installation.dispose();
  }
});

test('installed verifier rejects caller-supplied trust rather than overriding pinned roots', () => {
  assert.throws(() => verifyPinnedDeploymentProvenance(fixture()), { code: 'DEPLOYMENT_INPUT_INVALID', writes: 0 });
});

test('read-only verifier input enforces byte bounds and regular-file identity', () => {
  const root = mkdtempSync(join(tmpdir(), 'deployment-provenance-'));
  try {
    const path = join(root, 'input.json');
    writeFileSync(path, 'a');
    assert.deepEqual(readDeploymentInputFile(path, 1), Buffer.from('a'));
    for (const bound of [0, -1, 1.5, NaN, Infinity, 1024 * 1024 + 1]) {
      assert.throws(() => readDeploymentInputFile(path, bound), { code: 'DEPLOYMENT_FILE_INVALID', writes: 0 });
    }
    assert.throws(() => readDeploymentInputFile(root, 1), { code: 'DEPLOYMENT_FILE_INVALID' });
    assert.throws(() => readDeploymentInputFile('relative.json', 1), { code: 'DEPLOYMENT_FILE_INVALID' });
    writeFileSync(path, Buffer.alloc(1024 * 1024, 97));
    assert.equal(readDeploymentInputFile(path, 1024 * 1024).length, 1024 * 1024);
    assert.throws(() => readDeploymentInputFile(path, 1024 * 1024 - 1), { code: 'DEPLOYMENT_FILE_INVALID' });
    writeFileSync(path, Buffer.alloc(1024 * 1024 + 1));
    assert.throws(() => readDeploymentInputFile(path, 1024 * 1024), { code: 'DEPLOYMENT_FILE_INVALID' });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('manifest verification command rejects malformed arguments and redacts file paths', () => {
  const script = fileURLToPath(new URL('../scripts/verify-deployment-manifest.mjs', import.meta.url));
  const invoke = (args) => {
    const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    return JSON.parse(result.stderr);
  };
  assert.equal(invoke([]).code, 'DEPLOYMENT_ARGUMENTS_INVALID');
  assert.equal(invoke([
    '--purpose', 'shawl', '--purpose', 'application', '--platform', 'win32',
    '--architecture', 'x64', '--signature', 'ignored',
  ]).code, 'DEPLOYMENT_ARGUMENTS_INVALID');
  const root = mkdtempSync(join(tmpdir(), 'deployment-cli-'));
  try {
    const privatePath = join(root, 'private-input-must-not-appear.json');
    const receipt = invoke([
      '--purpose', 'shawl', '--manifest', privatePath, '--signature', privatePath,
      '--platform', 'win32', '--architecture', 'x64',
    ]);
    assert.deepEqual(receipt, {
      schemaVersion: 1, kind: 'deployment-provenance-refusal', code: 'DEPLOYMENT_FILE_INVALID', writes: 0,
    });
    assert.equal(JSON.stringify(receipt).includes(root), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
