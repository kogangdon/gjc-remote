import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  buildApplicationDeploymentManifest,
  buildDeploymentCompatibility,
  buildShawlDeploymentManifest,
  SHAWL_UPSTREAM,
} from '@gjc-remote/shared/deployment-envelope';
import { canonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import { verifyDeploymentProvenance } from '../src/deployment-provenance.js';

const script = fileURLToPath(new URL('../scripts/sign-deployment-manifest.mjs', import.meta.url));
const openssl = process.platform === 'win32' ? 'openssl.exe' : 'openssl';
const hash = 'a'.repeat(64);

function keyEntry(key, keyId) {
  return {
    keyId,
    algorithm: 'ed25519',
    publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function trustBytes(entries) {
  return Buffer.from(JSON.stringify({ version: 1, keys: entries }));
}

function runSigner(args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', windowsHide: true });
}

function applicationManifest(keyId) {
  return buildApplicationDeploymentManifest({
    signingKeyId: keyId,
    releaseId: 'v1.2.3',
    releaseVersion: '1.2.3',
    releaseSequence: 1,
    source: {
      repository: 'kogangdon/gjc-remote', tag: 'v1.2.3', commit: 'a'.repeat(40), tree: 'b'.repeat(40), bunLockSha256: hash,
    },
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
}

function shawlManifest(keyId) {
  return buildShawlDeploymentManifest({
    signingKeyId: keyId,
    releaseSequence: 1,
    target: { platform: 'win32', architecture: 'x64' },
    upstream: {
      repository: SHAWL_UPSTREAM.repository,
      tag: SHAWL_UPSTREAM.tag,
      commit: SHAWL_UPSTREAM.commit,
      assetId: 42,
      assetName: 'shawl-v1.9.0-win64.zip',
      zipSha256: hash,
    },
    executable: { name: 'shawl.exe', byteLength: 100, sha256: hash, version: '1.9.0', versionOutput: 'shawl 1.9.0', authenticode: 'unsigned' },
    projectAsset: { repository: 'kogangdon/gjc-remote', tag: 'v0.3.1', name: 'gjc-remote-shawl-win32-x64.exe' },
  });
}

test('offline signer creates application and Shawl sidecars accepted by purpose-specific verification', () => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-sign-'));
  try {
    const applicationKey = generateKeyPairSync('ed25519');
    const shawlKey = generateKeyPairSync('ed25519');
    const nativeKey = generateKeyPairSync('ed25519');
    const applicationEntry = keyEntry(applicationKey, 'application-test');
    const shawlEntry = keyEntry(shawlKey, 'shawl-test');
    const nativeEntry = keyEntry(nativeKey, 'native-test');
    const application = applicationManifest(applicationEntry.keyId);
    const shawl = shawlManifest(shawlEntry.keyId);
    const applicationManifestPath = join(root, 'application.manifest.json');
    const shawlManifestPath = join(root, 'shawl.manifest.json');
    const applicationKeyPath = join(root, 'application-key.pem');
    const shawlKeyPath = join(root, 'shawl-key.pem');
    const applicationSignaturePath = join(root, 'application.manifest.json.sig');
    const shawlSignaturePath = join(root, 'shawl.manifest.json.sig');
    writeFileSync(applicationManifestPath, canonicalJsonBytes(application));
    writeFileSync(shawlManifestPath, canonicalJsonBytes(shawl));
    writeFileSync(applicationKeyPath, applicationKey.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(shawlKeyPath, shawlKey.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });

    for (const [purpose, manifestPath, keyPath, keyId, outputPath] of [
      ['application', applicationManifestPath, applicationKeyPath, applicationEntry.keyId, applicationSignaturePath],
      ['shawl', shawlManifestPath, shawlKeyPath, shawlEntry.keyId, shawlSignaturePath],
    ]) {
      const run = runSigner([
        '--purpose', purpose,
        '--manifest', manifestPath,
        '--key', keyPath,
        '--key-id', keyId,
        '--output', outputPath,
        '--openssl', openssl,
      ]);
      assert.equal(run.status, 0, run.stderr);
      const receipt = JSON.parse(run.stdout);
      assert.deepEqual({ purpose: receipt.purpose, keyId: receipt.keyId, signaturePath: receipt.signaturePath, writes: receipt.writes }, { purpose, keyId, signaturePath: outputPath, writes: 1 });
      if (process.platform !== 'win32') assert.equal(statSync(outputPath).mode & 0o777, 0o600);
    }

    const common = {
      applicationTrustBytes: trustBytes([applicationEntry]),
      shawlTrustBytes: trustBytes([shawlEntry]),
      nativeTrustBytes: trustBytes([nativeEntry]),
    };
    const applicationResult = verifyDeploymentProvenance({
      ...common, purpose: 'application', platform: 'linux', architecture: 'x64',
      manifestBytes: readFileSync(applicationManifestPath), signatureBytes: readFileSync(applicationSignaturePath),
    });
    const shawlResult = verifyDeploymentProvenance({
      ...common, purpose: 'shawl', platform: 'win32', architecture: 'x64',
      manifestBytes: readFileSync(shawlManifestPath), signatureBytes: readFileSync(shawlSignaturePath),
    });
    assert.equal(applicationResult.signingKeyId, applicationEntry.keyId);
    assert.equal(shawlResult.signingKeyId, shawlEntry.keyId);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('signer rejects malformed arguments and signing failures without writing a sidecar', () => {
  const root = mkdtempSync(join(tmpdir(), 'gjc-sign-fail-'));
  try {
    const manifest = shawlManifest('shawl-test');
    const manifestPath = join(root, 'manifest.json');
    const keyPath = join(root, 'key.pem');
    const outputPath = join(root, 'output.sig');
    writeFileSync(manifestPath, canonicalJsonBytes(manifest));
    writeFileSync(keyPath, 'not a private key', { mode: 0o600 });
    const invalidArguments = [
      ['--purpose', 'shawl', '--manifest', 'relative.json', '--key', keyPath, '--key-id', 'shawl-test', '--output', outputPath, '--openssl', openssl],
      ['--purpose', 'shawl', '--manifest', manifestPath, '--key', keyPath, '--key-id', 'shawl-test', '--output', outputPath, '--openssl', openssl, '--unknown', 'value'],
      ['--purpose', 'shawl', '--purpose', 'application', '--manifest', manifestPath, '--key', keyPath, '--key-id', 'shawl-test', '--output', outputPath, '--openssl', openssl],
    ];
    for (const args of invalidArguments) {
      const invalid = runSigner(args);
      assert.notEqual(invalid.status, 0);
      assert.equal(JSON.parse(invalid.stderr).writes, 0);
      assert.doesNotMatch(invalid.stderr, /relative\.json/);
    }
    const failed = runSigner(['--purpose', 'shawl', '--manifest', manifestPath, '--key', keyPath, '--key-id', 'shawl-test', '--output', outputPath, '--openssl', openssl]);
    assert.notEqual(failed.status, 0);
    assert.equal(JSON.parse(failed.stderr).writes, 0);
    assert.equal(failed.stdout, '');
    assert.equal(existsSync(outputPath), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
