import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  buildManifest,
} from '../../native-control/src/index.js';
import {
  assertTargetMatchesRuntime,
  installSignatureSidecarIfAbsent,
  parseArguments,
  parseSignatureMap,
  parseSignaturesJson,
  probeNativeTampering,
  SUPPORTED_TARGETS,
  verifyNativePreflight,
  writeReceiptExclusive,
} from '../verify-signed-native.mjs';

const repositoryPackageBytes = readFileSync(
  new URL('../../native-control/package.json', import.meta.url),
);
const repositoryPackage = JSON.parse(repositoryPackageBytes.toString('utf8'));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function fixture() {
  const addonBytes = Buffer.from('synthetic native addon fixture');
  const platform = 'linux';
  const architecture = 'x64';
  const manifest = {
    ...buildManifest,
    package: repositoryPackage.name,
    version: repositoryPackage.version,
    platform,
    arch: architecture,
    addon: 'native_control.node',
    sha256: sha256(addonBytes),
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const sidecar = Object.freeze({
    keyId: 'test-fixture-ed25519',
    algorithm: 'ed25519',
    signature: sign(null, manifestBytes, privateKey).toString('base64'),
  });
  const sidecarBytes = Buffer.from(`${JSON.stringify(sidecar)}\n`, 'utf8');
  const trustedStoreBytes = Buffer.from(JSON.stringify({
    version: 1,
    keys: [{
      keyId: sidecar.keyId,
      algorithm: sidecar.algorithm,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    }],
  }), 'utf8');
  return {
    addonBytes,
    manifest,
    manifestBytes,
    packageBytes: repositoryPackageBytes,
    sidecar,
    sidecarBytes,
    trustedStoreBytes,
    platform,
    architecture,
    input: {
      addonBytes,
      manifestBytes,
      packageBytes: repositoryPackageBytes,
      sidecarBytes,
      trustedStoreBytes,
      platform,
      architecture,
    },
  };
}

function withTemporaryDirectory(run) {
  const directory = mkdtempSync(join(tmpdir(), 'verify-signed-native-'));
  try {
    run(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('argument and runtime checks reject unsupported tuples and malformed source commits', () => {
  assert.throws(() => parseArguments([
    '--input-dir', 'input', '--target', 'linux-mips',
    '--source-commit', 'a'.repeat(40), '--output', 'receipt.json',
  ]), { code: 'NATIVE_VERIFY_TARGET_INVALID' });
  assert.throws(() => parseArguments([
    '--input-dir', 'input', '--target', 'linux-x64',
    '--source-commit', 'A'.repeat(40), '--output', 'receipt.json',
  ]), { code: 'NATIVE_VERIFY_SOURCE_COMMIT_INVALID' });
  assert.throws(() => assertTargetMatchesRuntime('linux-arm64', 'linux', 'x64'), {
    code: 'NATIVE_VERIFY_RUNTIME_MISMATCH',
  });
  assert.deepEqual(
    assertTargetMatchesRuntime('win32-x64', 'win32', 'x64'),
    SUPPORTED_TARGETS['win32-x64'],
  );
});

test('signature maps require the exact supported target set and valid sidecars', () => {
  const sidecar = { keyId: 'fixture-key', algorithm: 'ed25519', signature: 'AQ==' };
  const complete = Object.fromEntries(
    Object.keys(SUPPORTED_TARGETS).map((target) => [target, sidecar]),
  );
  const parsed = parseSignatureMap(Buffer.from(JSON.stringify(complete)));
  assert.deepEqual(Object.keys(parsed).sort(), Object.keys(SUPPORTED_TARGETS).sort());
  assert.equal(parsed['linux-arm64'].keyId, 'fixture-key');
  assert.deepEqual(
    parseSignaturesJson(JSON.stringify(complete)),
    parsed,
  );

  for (const invalid of [
    { 'linux-x64': sidecar, 'linux-arm64': sidecar },
    { ...complete, 'darwin-arm64': sidecar },
    { ...complete, 'win32-x64': { ...sidecar, signature: 'not base64!' } },
  ]) {
    assert.throws(() => parseSignatureMap(Buffer.from(JSON.stringify(invalid))), {
      code: 'NATIVE_VERIFY_SIGNATURE_MAP_INVALID',
    });
  }
  assert.throws(() => parseSignatureMap(Buffer.from('{"linux-x64":{},"linux-x64":{}}')), {
    code: 'NATIVE_VERIFY_SIGNATURE_MAP_INVALID',
  });
  assert.throws(() => parseSignaturesJson(JSON.stringify({
    ...complete,
    'win32-x64': { ...sidecar, privateKeyPem: 'forbidden' },
  })), { code: 'NATIVE_VERIFY_SIGNATURE_MAP_INVALID' });
  assert.throws(() => parseSignaturesJson(JSON.stringify(Object.fromEntries(
    Object.keys(SUPPORTED_TARGETS).map((target) => [target, {
      ...sidecar,
      signature: 'A'.repeat(16 * 1024 + 4),
    }]),
  ))), { code: 'NATIVE_VERIFY_SIGNATURE_MAP_INVALID' });
  assert.throws(() => parseSignaturesJson(' '.repeat(64 * 1024 + 1)), {
    code: 'NATIVE_VERIFY_SIGNATURE_MAP_INVALID',
  });
});

test('pure preflight verifies synthetic signed bytes against the repository package contract', () => {
  const value = fixture();
  const result = verifyNativePreflight(value.input);
  assert.equal(result.keyId, value.sidecar.keyId);
  assert.equal(result.algorithm, 'ed25519');
  assert.equal(result.addonSha256, sha256(value.addonBytes));
  assert.equal(result.manifestSha256, sha256(value.manifestBytes));
  assert.equal(result.manifest.package, repositoryPackage.name);
  assert.deepEqual(result.manifest.capabilities, buildManifest.capabilities);
});

test('pure preflight rejects missing inputs, addon hash changes, and native package contract drift', () => {
  const value = fixture();
  assert.throws(() => verifyNativePreflight({ ...value.input, addonBytes: undefined }), {
    code: 'NATIVE_VERIFY_INPUT_INVALID',
  });
  assert.throws(() => verifyNativePreflight({
    ...value.input,
    manifestBytes: Buffer.from('{'),
  }), { code: 'NATIVE_VERIFY_MANIFEST_INVALID' });

  const changedAddon = Buffer.from(value.addonBytes);
  changedAddon[0] ^= 1;
  assert.throws(() => verifyNativePreflight({ ...value.input, addonBytes: changedAddon }), {
    code: 'NATIVE_VERIFY_MANIFEST_INVALID',
  });

  const changedPackage = JSON.parse(repositoryPackageBytes.toString('utf8'));
  changedPackage.nativeControlContract.revision += 1;
  assert.throws(() => verifyNativePreflight({
    ...value.input,
    packageBytes: Buffer.from(JSON.stringify(changedPackage)),
  }), { code: 'NATIVE_VERIFY_PACKAGE_INVALID' });
});

test('pure preflight rejects byte-changed manifests, invalid signatures, and unknown keys', () => {
  const value = fixture();
  const changedManifest = Buffer.from(value.manifestBytes);
  changedManifest[changedManifest.length - 1] = 0x20;
  assert.throws(() => verifyNativePreflight({
    ...value.input,
    manifestBytes: changedManifest,
  }), { code: 'NATIVE_VERIFY_SIGNATURE_INVALID' });

  const changedSignature = Buffer.from(value.sidecar.signature);
  changedSignature[0] = changedSignature[0] === 0x41 ? 0x42 : 0x41;
  const badSidecar = Buffer.from(JSON.stringify({
    ...value.sidecar,
    signature: changedSignature.toString(),
  }));
  assert.throws(() => verifyNativePreflight({ ...value.input, sidecarBytes: badSidecar }), {
    code: 'NATIVE_VERIFY_SIGNATURE_INVALID',
  });

  const unknownKeySidecar = Buffer.from(JSON.stringify({
    ...value.sidecar,
    keyId: 'unknown-fixture-key',
  }));
  assert.throws(() => verifyNativePreflight({ ...value.input, sidecarBytes: unknownKeySidecar }), {
    code: 'NATIVE_VERIFY_SIGNING_KEY_UNKNOWN',
  });
});

test('in-memory one-byte tamper probes reject addon, manifest, and signature changes', () => {
  const probes = probeNativeTampering(fixture().input);
  for (const probe of Object.values(probes)) {
    assert.equal(probe.rejected, true);
    assert.equal(probe.changedBytes, 1);
  }
});

test('tamper probes refuse an invalid baseline instead of reporting false rejection evidence', () => {
  const value = fixture();
  const addonBytes = Buffer.from(value.input.addonBytes);
  addonBytes[0] ^= 1;
  assert.throws(() => probeNativeTampering({ ...value.input, addonBytes }), {
    code: 'NATIVE_VERIFY_MANIFEST_INVALID',
  });
});

test('sidecar installation is exclusive, accepts semantic equality, and preserves conflicts', () => {
  const value = fixture();
  withTemporaryDirectory((directory) => {
    const initial = Buffer.from(`${JSON.stringify(value.sidecar, null, 2)}\n`);
    const first = installSignatureSidecarIfAbsent(directory, initial, value.sidecar);
    assert.equal(first.created, true);

    const sidecarPath = join(directory, 'native-control.manifest.json.sig');
    const saved = readFileSync(sidecarPath);
    const sameDifferentEncoding = Buffer.from(JSON.stringify(value.sidecar));
    const second = installSignatureSidecarIfAbsent(directory, sameDifferentEncoding, value.sidecar);
    assert.equal(second.created, false);
    assert.deepEqual(second.bytes, saved);

    const conflict = {
      ...value.sidecar,
      keyId: 'different-fixture-key',
    };
    assert.throws(() => installSignatureSidecarIfAbsent(
      directory,
      Buffer.from(JSON.stringify(conflict)),
      conflict,
    ), { code: 'NATIVE_VERIFY_SIGNATURE_CONFLICT' });
    assert.deepEqual(readFileSync(sidecarPath), saved);
  });
});

test('receipt output uses exclusive creation and leaves an existing receipt unchanged', () => {
  withTemporaryDirectory((directory) => {
    const output = join(directory, 'receipt.json');
    const receipt = { status: 'verified', sourceCommit: 'b'.repeat(40) };
    writeReceiptExclusive(output, receipt);
    const saved = readFileSync(output);
    assert.deepEqual(JSON.parse(saved.toString('utf8')), receipt);
    assert.throws(() => writeReceiptExclusive(output, { status: 'replacement' }), {
      code: 'NATIVE_VERIFY_OUTPUT_EXISTS',
    });
    assert.deepEqual(readFileSync(output), saved);
  });
});
