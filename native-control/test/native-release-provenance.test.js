import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs, { readFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import test from 'node:test';

import {
  capabilities,
  capabilitySignatures,
  contractRevision,
} from '../src/capabilities.js';
import {
  validateBuildManifest,
  validateBuildManifestMetadata,
  verifyPinnedNativeBuildManifest,
} from '../src/native-provenance.js';
import * as indexApi from '../src/index.js';
import * as publicApi from '../src/public.js';
import {
  createPinnedDeploymentInstallation,
} from '../test-fixtures/pinned-deployment-installation.mjs';

const packageBytes = readFileSync(
  new URL('../package.json', import.meta.url),
);
const packageJson = JSON.parse(packageBytes);
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const typedArrayFill = Uint8Array.prototype.fill;
const typedArraySet = Uint8Array.prototype.set;

function sharedBufferCopy(bytes) {
  const copy = Buffer.from(new SharedArrayBuffer(bytes.byteLength));
  Reflect.apply(typedArraySet, copy, [bytes]);
  return copy;
}

function overwriteBytes(target, source) {
  Reflect.apply(typedArraySet, target, [source]);
}

function overwriteWithZeroes(target) {
  Reflect.apply(typedArrayFill, target, [0]);
}

function manifestFor(
  platform = process.platform,
  architecture = process.arch,
  overrides = {},
) {
  return {
    contractVersion: 4,
    contractRevision,
    package: packageJson.name,
    version: packageJson.version,
    napi: 8,
    platform,
    arch: architecture,
    addon: 'native_control.node',
    sha256: 'a'.repeat(64),
    capabilities,
    capabilitySignatures,
    ...overrides,
  };
}

function manifestBytes(manifest) {
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

function signedInput(installation, {
  manifest = manifestFor(),
  manifestRaw = manifestBytes(manifest),
  packageRaw = packageBytes,
  bundledTrustBytes = installation.bundledNativeTrustBytes,
  platform = process.platform,
  architecture = process.arch,
} = {}) {
  return {
    manifestBytes: manifestRaw,
    signatureBytes: installation.signNativeManifest(manifestRaw),
    packageBytes: packageRaw,
    bundledTrustBytes,
    platform,
    architecture,
  };
}

async function withNativeInstallation(run) {
  const installation = await createPinnedDeploymentInstallation({
    keyIds: ['deployment-test'],
    includeNativeProvenance: true,
  });
  try {
    return await run(installation);
  } finally {
    installation.dispose();
  }
}

function assertFailure(invoke, code) {
  assert.throws(invoke, (error) => {
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.equal(error.operation, 'verify_pinned_native_build_manifest');
    assert.equal(error.writes, 0);
    assert.equal('path' in error, false);
    assert.equal('reason' in error, false);
    assert.equal('cause' in error, false);
    return true;
  });
}

test('metadata-only validation is exact while validateBuildManifest still binds actual addon bytes', () => {
  const addonBytes = Buffer.from('streamed native addon bytes');
  const manifest = manifestFor('linux', 'x64', {
    sha256: digest(addonBytes),
  });

  assert.equal(
    validateBuildManifestMetadata(manifest, packageJson, 'linux', 'x64'),
    true,
  );
  assert.equal(
    validateBuildManifest(manifest, packageJson, addonBytes, 'linux', 'x64'),
    true,
  );
  assert.equal(
    validateBuildManifest(
      manifest,
      packageJson,
      Buffer.from('different native addon bytes'),
      'linux',
      'x64',
    ),
    false,
  );
  assert.equal(
    validateBuildManifestMetadata(
      { ...manifest, sha256: manifest.sha256.toUpperCase() },
      packageJson,
      'linux',
      'x64',
    ),
    false,
  );
  assert.equal(
    validateBuildManifestMetadata(
      { ...manifest, extraAuthority: true },
      packageJson,
      'linux',
      'x64',
    ),
    false,
  );
});

test('pinned metadata verifier remains private and returns an explicit frozen non-binary receipt', async () => {
  await withNativeInstallation(async (installation) => {
    assert.equal(installation.store, null);
    assert.equal(installation.transport, null);
    assert.equal(installation.offline, null);
    assert.equal(typeof installation.nativeProvenance.verifyPinnedNativeBuildManifest, 'function');
    assert.equal(typeof installation.signNativeManifest, 'function');
    assert.equal('verifyPinnedNativeBuildManifest' in indexApi, false);
    assert.equal('validateBuildManifestMetadata' in indexApi, false);
    assert.equal('verifyPinnedNativeBuildManifest' in publicApi, false);

    const input = signedInput(installation);
    const sidecar = JSON.parse(input.signatureBytes);
    const receipt = installation.nativeProvenance
      .verifyPinnedNativeBuildManifest(input);
    const { signingKeyFingerprint, ...metadata } = receipt;

    assert.deepEqual(metadata, {
      manifestFingerprint: digest(input.manifestBytes),
      addonSha256: 'a'.repeat(64),
      platform: process.platform,
      architecture: process.arch,
      contractVersion: 4,
      contractRevision,
      napi: 8,
      signingKeyId: sidecar.keyId,
      signatureAlgorithm: 'ed25519',
      addonBytesVerification: 'required',
      addonLoadVerification: 'required',
      addonExportVerification: 'required',
    });
    assert.match(signingKeyFingerprint, /^[0-9a-f]{64}$/);
    assert.equal(Object.isFrozen(receipt), true);
    assert.throws(() => {
      receipt.addonBytesVerification = 'verified';
    }, TypeError);

    assertFailure(
      () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
        ...input,
        addonBytes: Buffer.from('not accepted by this metadata-only API'),
      }),
      'NATIVE_PROVENANCE_INPUT_INVALID',
    );
    for (const [name, value] of [
      ['trustedKeysPath', 'caller-trust.json'],
      ['devKeysPath', 'caller-dev.json'],
      ['nativeTrustBytes', input.bundledTrustBytes],
    ]) {
      assertFailure(
        () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
          ...input,
          [name]: value,
        }),
        'NATIVE_PROVENANCE_INPUT_INVALID',
      );
    }
    const wrongPrototype = Object.assign(Object.create(null), input);
    assertFailure(
      () => installation.nativeProvenance
        .verifyPinnedNativeBuildManifest(wrongPrototype),
      'NATIVE_PROVENANCE_INPUT_INVALID',
    );
    let accessorReads = 0;
    const accessorInput = { ...input };
    Object.defineProperty(accessorInput, 'bundledTrustBytes', {
      enumerable: true,
      get() {
        accessorReads += 1;
        return input.bundledTrustBytes;
      },
    });
    assertFailure(
      () => installation.nativeProvenance
        .verifyPinnedNativeBuildManifest(accessorInput),
      'NATIVE_PROVENANCE_INPUT_INVALID',
    );
    assert.equal(accessorReads, 0);
  });
});

test('snapshots all shared byte inputs before installed-trust I/O', async (t) => {
  await withNativeInstallation(async (installation) => {
    const original = signedInput(installation);
    const expectedManifestFingerprint = digest(original.manifestBytes);
    const expectedAddonSha256 = JSON.parse(original.manifestBytes).sha256;
    const input = {
      ...original,
      manifestBytes: sharedBufferCopy(original.manifestBytes),
      signatureBytes: sharedBufferCopy(original.signatureBytes),
      packageBytes: sharedBufferCopy(original.packageBytes),
      bundledTrustBytes: sharedBufferCopy(original.bundledTrustBytes),
    };
    const byteInputs = [
      input.manifestBytes,
      input.signatureBytes,
      input.packageBytes,
      input.bundledTrustBytes,
    ];
    const originalLstatSync = fs.lstatSync;
    let mutated = false;
    t.mock.method(fs, 'lstatSync', (...args) => {
      if (!mutated) {
        mutated = true;
        for (const bytes of byteInputs) overwriteWithZeroes(bytes);
      }
      return Reflect.apply(originalLstatSync, fs, args);
    });
    syncBuiltinESMExports();

    let receipt;
    try {
      receipt = installation.nativeProvenance
        .verifyPinnedNativeBuildManifest(input);
    } finally {
      t.mock.restoreAll();
      syncBuiltinESMExports();
    }

    assert.equal(mutated, true);
    assert.equal(receipt.manifestFingerprint, expectedManifestFingerprint);
    assert.equal(receipt.addonSha256, expectedAddonSha256);
    assert.ok(byteInputs.every((bytes) =>
      Reflect.apply(Uint8Array.prototype.every, bytes, [
        (value) => value === 0,
      ])));
  });
});

test('cannot authenticate parse-time manifest B with signature-time manifest A', async (t) => {
  await withNativeInstallation(async (installation) => {
    const manifestA = manifestBytes(manifestFor(
      process.platform,
      process.arch,
      { sha256: 'a'.repeat(64) },
    ));
    const manifestB = manifestBytes(manifestFor(
      process.platform,
      process.arch,
      { sha256: 'b'.repeat(64) },
    ));
    assert.equal(manifestA.byteLength, manifestB.byteLength);
    const input = signedInput(installation, {
      manifestRaw: manifestA,
    });
    input.manifestBytes = sharedBufferCopy(manifestB);

    const originalLstatSync = fs.lstatSync;
    let switched = false;
    t.mock.method(fs, 'lstatSync', (...args) => {
      if (!switched) {
        switched = true;
        overwriteBytes(input.manifestBytes, manifestA);
      }
      return Reflect.apply(originalLstatSync, fs, args);
    });
    syncBuiltinESMExports();

    try {
      assertFailure(
        () => installation.nativeProvenance
          .verifyPinnedNativeBuildManifest(input),
        'NATIVE_PROVENANCE_SIGNATURE_INVALID',
      );
    } finally {
      t.mock.restoreAll();
      syncBuiltinESMExports();
    }

    assert.equal(switched, true);
    assert.deepEqual(Buffer.from(input.manifestBytes), manifestA);
  });
});

test('bypasses caller-owned Buffer metadata accessors without invoking them', async () => {
  await withNativeInstallation(async (installation) => {
    const input = signedInput(installation);
    const expectedManifestFingerprint = digest(input.manifestBytes);
    let accessorCalls = 0;
    for (const field of [
      'manifestBytes',
      'signatureBytes',
      'packageBytes',
      'bundledTrustBytes',
    ]) {
      for (const property of ['length', 'byteLength', 'buffer']) {
        Object.defineProperty(input[field], property, {
          configurable: true,
          get() {
            accessorCalls += 1;
            throw new Error(`private ${field}.${property} getter`);
          },
        });
      }
    }

    const receipt = installation.nativeProvenance
      .verifyPinnedNativeBuildManifest(input);
    assert.equal(receipt.manifestFingerprint, expectedManifestFingerprint);
    assert.equal(accessorCalls, 0);
  });
});

test('redacts byte-inspection failures as invalid input', async () => {
  await withNativeInstallation(async (installation) => {
    const input = signedInput(installation);
    input.manifestBytes = new Proxy(input.manifestBytes, {
      getPrototypeOf() {
        throw new Error('private proxy inspection failure');
      },
    });
    assertFailure(
      () => installation.nativeProvenance
        .verifyPinnedNativeBuildManifest(input),
      'NATIVE_PROVENANCE_INPUT_INVALID',
    );
  });
});

test('manifest fingerprint covers the original signed bytes, including harmless JSON whitespace', async () => {
  await withNativeInstallation(async (installation) => {
    const manifest = manifestFor();
    const compact = Buffer.from(JSON.stringify(manifest), 'utf8');
    const spaced = Buffer.from(`${JSON.stringify(manifest)}\n`, 'utf8');
    const compactReceipt = installation.nativeProvenance
      .verifyPinnedNativeBuildManifest(signedInput(installation, {
        manifest,
        manifestRaw: compact,
      }));
    const spacedReceipt = installation.nativeProvenance
      .verifyPinnedNativeBuildManifest(signedInput(installation, {
        manifest,
        manifestRaw: spaced,
      }));

    assert.equal(compactReceipt.manifestFingerprint, digest(compact));
    assert.equal(spacedReceipt.manifestFingerprint, digest(spaced));
    assert.notEqual(
      compactReceipt.manifestFingerprint,
      spacedReceipt.manifestFingerprint,
    );
  });
});

test('raw signed-manifest byte tampering fails signature verification', async () => {
  await withNativeInstallation(async (installation) => {
    const input = signedInput(installation);
    assertFailure(
      () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
        ...input,
        manifestBytes: Buffer.concat([input.manifestBytes, Buffer.from(' ')]),
      }),
      'NATIVE_PROVENANCE_SIGNATURE_INVALID',
    );
  });
});

test('malformed signed manifest bytes fail strict parsing without leaking parser detail', async () => {
  await withNativeInstallation(async (installation) => {
    for (const manifestRaw of [
      Buffer.from('{"contractVersion":4,"contractVersion":4}', 'utf8'),
      Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
      Buffer.from([0xff]),
    ]) {
      assertFailure(
        () => installation.nativeProvenance
          .verifyPinnedNativeBuildManifest(signedInput(installation, {
            manifestRaw,
          })),
        'NATIVE_PROVENANCE_MANIFEST_INVALID',
      );
    }
  });
});

test('signed manifest field, ABI, and capability-table drift is rejected', async () => {
  await withNativeInstallation(async (installation) => {
    const cases = [
      ['contract version', { contractVersion: 3 }],
      ['contract revision', { contractRevision: contractRevision + 1 }],
      ['N-API version', { napi: 7 }],
      ['package name', { package: '@foreign/native-control' }],
      ['package version', { version: '999.0.0' }],
      ['addon name', { addon: 'foreign.node' }],
      ['short addon digest', { sha256: 'a'.repeat(63) }],
      ['uppercase addon digest', { sha256: 'A'.repeat(64) }],
      ['capability list', { capabilities: capabilities.slice(1) }],
      ['capability signature table', {
        capabilitySignatures: {
          ...capabilitySignatures,
          read_boot_id: ['authority'],
        },
      }],
      ['extra manifest authority', { trustPath: 'caller-trust.json' }],
    ];
    for (const [, overrides] of cases) {
      const input = signedInput(installation, {
        manifest: manifestFor(process.platform, process.arch, overrides),
      });
      assertFailure(
        () => installation.nativeProvenance
          .verifyPinnedNativeBuildManifest(input),
        'NATIVE_PROVENANCE_MANIFEST_INVALID',
      );
    }
  });
});

test('requested and signed platform tuples must be current and approved', async () => {
  await withNativeInstallation(async (installation) => {
    const current = signedInput(installation);
    assertFailure(
      () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
        ...current,
        platform: 'darwin',
        architecture: 'arm64',
      }),
      'NATIVE_PROVENANCE_TARGET_INVALID',
    );

    const otherPlatform = process.platform === 'win32' ? 'linux' : 'win32';
    const mismatch = signedInput(installation, {
      manifest: manifestFor(otherPlatform, 'x64'),
      platform: process.platform,
      architecture: process.arch,
    });
    assertFailure(
      () => installation.nativeProvenance
        .verifyPinnedNativeBuildManifest(mismatch),
      'NATIVE_PROVENANCE_TARGET_INVALID',
    );
  });
});

test('package bytes must be strict JSON with the exact current native contract', async () => {
  await withNativeInstallation(async (installation) => {
    const contractCases = [
      {
        ...packageJson,
        name: '@foreign/native-control',
      },
      { ...packageJson, nativeControlContract: {
        ...packageJson.nativeControlContract,
        revision: contractRevision + 1,
      } },
      { ...packageJson, nativeControlContract: {
        ...packageJson.nativeControlContract,
        napi: 7,
      } },
      { ...packageJson, nativeControlContract: {
        ...packageJson.nativeControlContract,
        platforms: [...packageJson.nativeControlContract.platforms].reverse(),
      } },
      { ...packageJson, nativeControlContract: {
        ...packageJson.nativeControlContract,
        trustOverride: true,
      } },
    ];
    for (const drifted of contractCases) {
      const matchingManifest = manifestFor(process.platform, process.arch, {
        package: drifted.name,
        version: drifted.version,
      });
      const input = signedInput(installation, {
        manifest: matchingManifest,
        packageRaw: Buffer.from(JSON.stringify(drifted), 'utf8'),
      });
      assertFailure(
        () => installation.nativeProvenance
          .verifyPinnedNativeBuildManifest(input),
        'NATIVE_PROVENANCE_MANIFEST_INVALID',
      );
    }

    for (const packageRaw of [
      Buffer.from('{"name":"first","name":"second"}', 'utf8'),
      Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
      Buffer.from([0xff]),
    ]) {
      const input = signedInput(installation, { packageRaw });
      assertFailure(
        () => installation.nativeProvenance
          .verifyPinnedNativeBuildManifest(input),
        'NATIVE_PROVENANCE_MANIFEST_INVALID',
      );
    }
  });
});

test('signature format, signature bytes, algorithm, and signing key tamper fail closed', async () => {
  await withNativeInstallation(async (installation) => {
    const input = signedInput(installation);
    const sidecar = JSON.parse(input.signatureBytes);
    const invoke = (changed) => installation.nativeProvenance
      .verifyPinnedNativeBuildManifest({
        ...input,
        signatureBytes: Buffer.from(JSON.stringify(changed), 'utf8'),
      });

    const tamperedSignature = `${sidecar.signature[0] === 'A' ? 'B' : 'A'}${sidecar.signature.slice(1)}`;
    assertFailure(
      () => invoke({ ...sidecar, signature: tamperedSignature }),
      'NATIVE_PROVENANCE_SIGNATURE_INVALID',
    );
    assertFailure(
      () => invoke({ ...sidecar, algorithm: 'p256' }),
      'NATIVE_PROVENANCE_SIGNATURE_INVALID',
    );
    assertFailure(
      () => invoke({ ...sidecar, keyId: 'foreign-native-key' }),
      'NATIVE_PROVENANCE_SIGNING_KEY_UNKNOWN',
    );
    assertFailure(
      () => invoke({ ...sidecar, trustPath: 'caller-trust.json' }),
      'NATIVE_PROVENANCE_SIGNATURE_INVALID',
    );
    assertFailure(
      () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
        ...input,
        signatureBytes: Buffer.from('{"keyId":"a","keyId":"b"}', 'utf8'),
      }),
      'NATIVE_PROVENANCE_SIGNATURE_INVALID',
    );
  });
});

test('bundled native trust must normalize to the complete installed pin identities', async () => {
  const installation = await createPinnedDeploymentInstallation({
    keyIds: ['deployment-test'],
    includeNativeProvenance: true,
  });
  const foreign = await createPinnedDeploymentInstallation({
    keyIds: ['other-deployment-test'],
    includeNativeProvenance: true,
  });
  try {
    const input = signedInput(installation);
    const installed = JSON.parse(
      installation.bundledNativeTrustBytes.toString('utf8'),
    );
    const foreignStore = JSON.parse(
      foreign.bundledNativeTrustBytes.toString('utf8'),
    );

    const reformatted = Buffer.from(JSON.stringify(installed, null, 2));
    const accepted = installation.nativeProvenance
      .verifyPinnedNativeBuildManifest({
        ...input,
        bundledTrustBytes: reformatted,
      });
    assert.equal(accepted.signingKeyId, installed.keys[0].keyId);

    for (const bundledTrustBytes of [
      Buffer.from(JSON.stringify({ version: 1, keys: [] })),
      foreign.bundledNativeTrustBytes,
      Buffer.from(JSON.stringify({
        version: 1,
        keys: [{
          ...installed.keys[0],
          keyId: 'fixture-dev-only-key',
        }],
      })),
      Buffer.from(JSON.stringify({
        version: 1,
        keys: [
          ...installed.keys,
          {
            ...foreignStore.keys[0],
            keyId: 'foreign-addon-key',
          },
        ],
      })),
    ]) {
      assertFailure(
        () => installation.nativeProvenance
          .verifyPinnedNativeBuildManifest({
            ...input,
            bundledTrustBytes,
          }),
        'NATIVE_PROVENANCE_TRUST_INVALID',
      );
    }
  } finally {
    foreign.dispose();
    installation.dispose();
  }
});

test('production pinned verifier rejects genuine signatures from fixture-only native authority', async () => {
  await withNativeInstallation(async (installation) => {
    const input = signedInput(installation);
    const fixtureReceipt = installation.nativeProvenance
      .verifyPinnedNativeBuildManifest(input);
    assert.equal(fixtureReceipt.manifestFingerprint, digest(input.manifestBytes));
    assertFailure(
      () => verifyPinnedNativeBuildManifest(input),
      'NATIVE_PROVENANCE_TRUST_INVALID',
    );
  });
});

test('all byte inputs are nonempty and bounded before parsing or trust access', async () => {
  await withNativeInstallation(async (installation) => {
    const input = signedInput(installation);
    for (const [field, maximum] of [
      ['manifestBytes', 1024 * 1024],
      ['packageBytes', 1024 * 1024],
      ['signatureBytes', 16 * 1024],
      ['bundledTrustBytes', 64 * 1024],
    ]) {
      assertFailure(
        () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
          ...input,
          [field]: Buffer.alloc(0),
        }),
        'NATIVE_PROVENANCE_INPUT_INVALID',
      );
      assertFailure(
        () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
          ...input,
          [field]: Buffer.alloc(maximum + 1, 0x20),
        }),
        'NATIVE_PROVENANCE_INPUT_INVALID',
      );
    }
    assertFailure(
      () => installation.nativeProvenance.verifyPinnedNativeBuildManifest({
        ...input,
        manifestBytes: new Uint8Array(input.manifestBytes),
      }),
      'NATIVE_PROVENANCE_INPUT_INVALID',
    );
  });
});

test('trust unavailability is redacted and never exposes the module-relative source path', async () => {
  const installation = await createPinnedDeploymentInstallation({
    keyIds: ['deployment-test'],
    includeNativeProvenance: true,
  });
  const input = signedInput(installation);
  const verifier = installation.nativeProvenance.verifyPinnedNativeBuildManifest;
  installation.dispose();

  assertFailure(
    () => verifier(input),
    'NATIVE_PROVENANCE_TRUST_UNAVAILABLE',
  );
});
