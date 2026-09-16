import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { Buffer } from 'node:buffer';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson,
  isHex64,
  parseStrictJsonBytes,
} from '@gjc-remote/shared/strict-json';
import {
  capabilities,
  capabilitySignatures,
  contractRevision,
} from './capabilities.js';

export const approvedNativePlatforms = Object.freeze([
  'linux-x64',
  'linux-arm64',
  'win32-x64',
]);

const nativeTrustPath = fileURLToPath(
  new URL('../release-keys/trusted.json', import.meta.url),
);
const nativePackageName = '@gjc-remote/native-control';
const supportedSignatureAlgorithms = new Set(['ed25519', 'p256']);
const manifestLimits = Object.freeze({
  maxBytes: 1024 * 1024,
  maxDepth: 64,
  maxNodes: 100_000,
});
const packageLimits = manifestLimits;
const signatureLimits = Object.freeze({
  maxBytes: 16 * 1024,
  maxDepth: 8,
  maxNodes: 64,
});
const trustLimits = Object.freeze({
  maxBytes: 64 * 1024,
  maxDepth: 8,
  maxNodes: 512,
});
const keyIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const getPrototypeOf = Object.getPrototypeOf;
const ownKeys = Reflect.ownKeys;
const reflectApply = Reflect.apply;
const bufferAlloc = Buffer.alloc;
const bufferIsBuffer = Buffer.isBuffer;
const typedArrayPrototype = getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
).get;
const typedArraySet = Uint8Array.prototype.set;

export class TrustStoreError extends Error {}
class DuplicateTrustKeyError extends TrustStoreError {}
class MalformedTrustStoreError extends TrustStoreError {}
class PinnedTrustUnavailableError extends Error {}
class PinnedTrustInvalidError extends Error {}

export const nativeFingerprint = (value) =>
  createHash('sha256').update(value).digest('hex');

export function sameNativeMetadata(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    getPrototypeOf(value) === Object.prototype;
}

function exact(value, keys) {
  return plain(value) && ownKeys(value).length === keys.length &&
    ownKeys(value).every((key) => typeof key === 'string') &&
    keys.every((key) => Object.hasOwn(value, key));
}

function exactDataValues(value, keys) {
  try {
    if (!exact(value, keys)) return null;
    const descriptors = getOwnPropertyDescriptors(value);
    const values = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.enumerable !== true ||
          descriptor.get !== undefined || descriptor.set !== undefined ||
          !Object.hasOwn(descriptor, 'value')) return null;
      values[key] = descriptor.value;
    }
    return values;
  } catch {
    return null;
  }
}

// Retains the loader's established bootstrap/dev trust-store behavior. The
// pinned metadata verifier below uses a stricter, nonempty production policy.
export function normalizeTrustStore({ present, value }) {
  if (!present) throw new MalformedTrustStoreError('trust store file is unreadable');
  if (value === undefined) throw new MalformedTrustStoreError('trust store is not valid JSON');
  if (!value || getPrototypeOf(value) !== Object.prototype ||
      value.version !== 1 || !Array.isArray(value.keys)) {
    throw new MalformedTrustStoreError(
      'trust store has an unexpected shape (expected { version: 1, keys: [] })',
    );
  }
  const keys = value.keys.map((key, index) => {
    if (!key || getPrototypeOf(key) !== Object.prototype ||
        typeof key.keyId !== 'string' || key.keyId.length === 0 ||
        !supportedSignatureAlgorithms.has(key.algorithm) ||
        typeof key.publicKeyPem !== 'string' || key.publicKeyPem.length === 0) {
      throw new MalformedTrustStoreError(
        `trust store keys[${index}] is missing required fields`,
      );
    }
    return key;
  });
  const seenKeyIds = new Set();
  for (const key of keys) {
    if (seenKeyIds.has(key.keyId)) {
      throw new DuplicateTrustKeyError(
        `duplicate keyId in trust store: ${key.keyId}`,
      );
    }
    seenKeyIds.add(key.keyId);
  }
  return keys;
}

// Pure verifier for the existing native sidecar format. The signature preimage
// is the exact raw manifest byte sequence supplied by the caller.
export function verifyManifestSignature(manifestBytes, sidecar, trustStore) {
  if (!Buffer.isBuffer(manifestBytes)) {
    return { ok: false, reason: 'manifest bytes are not a buffer' };
  }
  if (!sidecar || getPrototypeOf(sidecar) !== Object.prototype) {
    return { ok: false, reason: 'signature sidecar is missing or malformed' };
  }
  const { keyId, algorithm, signature } = sidecar;
  if (typeof keyId !== 'string' || !keyId ||
      typeof algorithm !== 'string' ||
      !supportedSignatureAlgorithms.has(algorithm) ||
      typeof signature !== 'string' || !signature) {
    return { ok: false, reason: 'signature sidecar is missing or malformed' };
  }
  const keys = Array.isArray(trustStore?.keys) ? trustStore.keys : [];
  const pinned = keys.find((key) => key && key.keyId === keyId);
  if (!pinned) return { ok: false, reason: `unknown signing keyId: ${keyId}` };
  if (pinned.algorithm !== algorithm) {
    return {
      ok: false,
      reason: 'signature algorithm does not match the pinned key',
    };
  }
  let publicKey;
  let signatureBytes;
  try {
    publicKey = createPublicKey(pinned.publicKeyPem);
    signatureBytes = Buffer.from(signature, 'base64');
  } catch {
    return {
      ok: false,
      reason: 'pinned public key or signature is not decodable',
    };
  }
  try {
    if (algorithm === 'ed25519') {
      if (publicKey.asymmetricKeyType !== 'ed25519') {
        return { ok: false, reason: 'pinned key is not an ed25519 key' };
      }
      if (!cryptoVerify(null, manifestBytes, publicKey, signatureBytes)) {
        return { ok: false, reason: 'signature verification failed' };
      }
    } else {
      if (publicKey.asymmetricKeyType !== 'ec' ||
          publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
        return { ok: false, reason: 'pinned key is not a P-256 key' };
      }
      if (!cryptoVerify('sha256', manifestBytes, publicKey, signatureBytes)) {
        return { ok: false, reason: 'signature verification failed' };
      }
    }
  } catch {
    return { ok: false, reason: 'signature verification threw an error' };
  }
  return { ok: true, keyId, algorithm };
}

export function validateNativePackageContract(packageJson) {
  if (!plain(packageJson)) return false;
  try {
    return sameNativeMetadata(packageJson.nativeControlContract, {
      version: 4,
      revision: contractRevision,
      napi: 8,
      platforms: approvedNativePlatforms,
    });
  } catch {
    return false;
  }
}

// Validates signed metadata without claiming that the named addon bytes were
// observed. Callers that possess addon bytes must additionally hash them.
export function validateBuildManifestMetadata(
  manifest,
  packageJson,
  platform = process.platform,
  architecture = process.arch,
) {
  if (!plain(manifest) || !plain(packageJson) || !isHex64(manifest.sha256)) {
    return false;
  }
  const expected = {
    contractVersion: 4,
    contractRevision,
    package: packageJson.name,
    version: packageJson.version,
    napi: 8,
    platform,
    arch: architecture,
    addon: 'native_control.node',
    sha256: manifest.sha256,
    capabilities,
    capabilitySignatures,
  };
  try {
    return approvedNativePlatforms.includes(`${platform}-${architecture}`) &&
      sameNativeMetadata(Object.keys(manifest).sort(), Object.keys(expected).sort()) &&
      Object.keys(expected).every((key) =>
        sameNativeMetadata(manifest[key], expected[key]));
  } catch {
    return false;
  }
}

// Existing byte-verifying API: metadata validity alone is never sufficient.
export function validateBuildManifest(
  manifest,
  packageJson,
  addonBytes,
  platform = process.platform,
  architecture = process.arch,
) {
  if (!Buffer.isBuffer(addonBytes)) return false;
  try {
    return validateBuildManifestMetadata(
      manifest,
      packageJson,
      platform,
      architecture,
    ) && manifest.sha256 === nativeFingerprint(addonBytes);
  } catch {
    return false;
  }
}

export function validateNativeAddonContract(contract) {
  try {
    return contract?.contractVersion === 4 &&
      contract.contractRevision === contractRevision &&
      contract.napi === 8 &&
      sameNativeMetadata(contract.capabilities, capabilities) &&
      sameNativeMetadata(contract.capabilitySignatures, capabilitySignatures);
  } catch {
    return false;
  }
}

function provenanceError(code) {
  const error = new Error(code);
  error.code = code;
  error.operation = 'verify_pinned_native_build_manifest';
  error.writes = 0;
  throw error;
}

function readPinnedTrustBytes() {
  let descriptor;
  try {
    const named = lstatSync(nativeTrustPath, { bigint: true });
    if (!named.isFile()) throw new PinnedTrustUnavailableError();
    if (named.size === 0n || named.size > BigInt(trustLimits.maxBytes)) {
      throw new PinnedTrustInvalidError();
    }
    const flags = process.platform === 'win32'
      ? constants.O_RDONLY
      : constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
    descriptor = openSync(nativeTrustPath, flags);
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.dev !== named.dev || before.ino !== named.ino ||
        before.size !== named.size) throw new PinnedTrustUnavailableError();
    const bytes = Buffer.alloc(trustLimits.maxBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(
        descriptor,
        bytes,
        length,
        bytes.length - length,
        null,
      );
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    const finalNamed = lstatSync(nativeTrustPath, { bigint: true });
    if (length > trustLimits.maxBytes || BigInt(length) !== before.size) {
      throw new PinnedTrustInvalidError();
    }
    if ([after, finalNamed].some((stat) => !stat.isFile() ||
        stat.dev !== before.dev || stat.ino !== before.ino ||
        stat.size !== before.size || stat.mtimeNs !== before.mtimeNs ||
        stat.ctimeNs !== before.ctimeNs)) {
      throw new PinnedTrustUnavailableError();
    }
    return bytes.subarray(0, length);
  } catch (error) {
    if (error instanceof PinnedTrustInvalidError) throw error;
    throw new PinnedTrustUnavailableError();
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        throw new PinnedTrustUnavailableError();
      }
    }
  }
}

function parsePinnedTrust(bytes) {
  let store;
  try {
    store = parseStrictJsonBytes(bytes, trustLimits, {
      allowedValueControlCodes: new Set([10, 13]),
    });
  } catch {
    throw new PinnedTrustInvalidError();
  }
  if (!exact(store, ['version', 'keys']) || store.version !== 1 ||
      !Array.isArray(store.keys) || store.keys.length === 0 ||
      store.keys.length > 32) throw new PinnedTrustInvalidError();
  const ids = new Set();
  const fingerprints = new Set();
  const keys = [];
  for (const entry of store.keys) {
    if (!exact(entry, ['keyId', 'algorithm', 'publicKeyPem']) ||
        typeof entry.keyId !== 'string' || !keyIdPattern.test(entry.keyId) ||
        ids.has(entry.keyId) ||
        !supportedSignatureAlgorithms.has(entry.algorithm) ||
        typeof entry.publicKeyPem !== 'string' ||
        Buffer.byteLength(entry.publicKeyPem, 'utf8') > 16 * 1024 ||
        !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/.test(
          entry.publicKeyPem,
        )) throw new PinnedTrustInvalidError();
    let publicKey;
    let spkiFingerprint;
    try {
      publicKey = createPublicKey(entry.publicKeyPem);
      if ((entry.algorithm === 'ed25519' &&
          publicKey.asymmetricKeyType !== 'ed25519') ||
          (entry.algorithm === 'p256' &&
          (publicKey.asymmetricKeyType !== 'ec' ||
            publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1'))) {
        throw new PinnedTrustInvalidError();
      }
      spkiFingerprint = nativeFingerprint(
        publicKey.export({ type: 'spki', format: 'der' }),
      );
    } catch {
      throw new PinnedTrustInvalidError();
    }
    if (fingerprints.has(spkiFingerprint)) throw new PinnedTrustInvalidError();
    ids.add(entry.keyId);
    fingerprints.add(spkiFingerprint);
    keys.push(Object.freeze({
      keyId: entry.keyId,
      algorithm: entry.algorithm,
      publicKeyPem: entry.publicKeyPem,
      spkiFingerprint,
    }));
  }
  return Object.freeze(keys);
}

function pinnedTrustIdentities(keys) {
  const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
  return Object.freeze(keys.map((key) => Object.freeze({
    keyId: key.keyId,
    algorithm: key.algorithm,
    spkiFingerprint: key.spkiFingerprint,
  })).sort((left, right) =>
    compare(left.keyId, right.keyId) ||
    compare(left.algorithm, right.algorithm) ||
    compare(left.spkiFingerprint, right.spkiFingerprint)));
}

function snapshotInputBytes(value, maximumBytes) {
  try {
    if (!reflectApply(bufferIsBuffer, Buffer, [value])) return null;
    const byteLength = reflectApply(typedArrayByteLength, value, []);
    if (!Number.isSafeInteger(byteLength) || byteLength < 1 ||
        byteLength > maximumBytes) return null;
    const snapshot = reflectApply(bufferAlloc, Buffer, [byteLength]);
    reflectApply(typedArraySet, snapshot, [value]);
    return snapshot;
  } catch {
    return null;
  }
}

function parseNativeSidecar(bytes) {
  let sidecar;
  try {
    sidecar = parseStrictJsonBytes(bytes, signatureLimits);
  } catch {
    provenanceError('NATIVE_PROVENANCE_SIGNATURE_INVALID');
  }
  if (!exact(sidecar, ['keyId', 'algorithm', 'signature']) ||
      typeof sidecar.keyId !== 'string' || !keyIdPattern.test(sidecar.keyId) ||
      !supportedSignatureAlgorithms.has(sidecar.algorithm) ||
      typeof sidecar.signature !== 'string' || sidecar.signature.length === 0 ||
      !base64Pattern.test(sidecar.signature)) {
    provenanceError('NATIVE_PROVENANCE_SIGNATURE_INVALID');
  }
  return sidecar;
}

// Verifies authority over exact native build metadata only. Acquisition must
// stream and hash the actual addon, match that digest before immutable
// publication, and use the normal loader/startup export verification before
// activation. Cross-target code is never executed by this metadata verifier.
export function verifyPinnedNativeBuildManifest(input) {
  const values = exactDataValues(input, [
    'manifestBytes',
    'signatureBytes',
    'packageBytes',
    'bundledTrustBytes',
    'platform',
    'architecture',
  ]);
  if (!values || typeof values.platform !== 'string' ||
      typeof values.architecture !== 'string') {
    provenanceError('NATIVE_PROVENANCE_INPUT_INVALID');
  }
  const bytes = Object.freeze({
    manifest: snapshotInputBytes(
      values.manifestBytes,
      manifestLimits.maxBytes,
    ),
    signature: snapshotInputBytes(
      values.signatureBytes,
      signatureLimits.maxBytes,
    ),
    package: snapshotInputBytes(
      values.packageBytes,
      packageLimits.maxBytes,
    ),
    bundledTrust: snapshotInputBytes(
      values.bundledTrustBytes,
      trustLimits.maxBytes,
    ),
  });
  if (Object.values(bytes).some((value) => value === null)) {
    provenanceError('NATIVE_PROVENANCE_INPUT_INVALID');
  }
  if (!approvedNativePlatforms.includes(
    `${values.platform}-${values.architecture}`,
  )) provenanceError('NATIVE_PROVENANCE_TARGET_INVALID');

  let manifest;
  let packageJson;
  try {
    manifest = parseStrictJsonBytes(bytes.manifest, manifestLimits);
    packageJson = parseStrictJsonBytes(bytes.package, packageLimits);
  } catch {
    provenanceError('NATIVE_PROVENANCE_MANIFEST_INVALID');
  }
  if (manifest?.platform !== values.platform ||
      manifest?.arch !== values.architecture) {
    provenanceError('NATIVE_PROVENANCE_TARGET_INVALID');
  }
  if (packageJson?.name !== nativePackageName ||
      typeof packageJson?.version !== 'string' ||
      packageJson.version.length === 0 ||
      !validateNativePackageContract(packageJson) ||
      !validateBuildManifestMetadata(
        manifest,
        packageJson,
        values.platform,
        values.architecture,
      )) provenanceError('NATIVE_PROVENANCE_MANIFEST_INVALID');

  const sidecar = parseNativeSidecar(bytes.signature);
  let keys;
  let bundledKeys;
  try {
    keys = parsePinnedTrust(readPinnedTrustBytes());
    bundledKeys = parsePinnedTrust(bytes.bundledTrust);
  } catch (error) {
    provenanceError(error instanceof PinnedTrustInvalidError
      ? 'NATIVE_PROVENANCE_TRUST_INVALID'
      : 'NATIVE_PROVENANCE_TRUST_UNAVAILABLE');
  }
  if (!sameNativeMetadata(
    pinnedTrustIdentities(keys),
    pinnedTrustIdentities(bundledKeys),
  )) provenanceError('NATIVE_PROVENANCE_TRUST_INVALID');
  const key = keys.find((candidate) => candidate.keyId === sidecar.keyId);
  if (!key) provenanceError('NATIVE_PROVENANCE_SIGNING_KEY_UNKNOWN');
  const result = verifyManifestSignature(
    bytes.manifest,
    sidecar,
    { version: 1, keys },
  );
  if (!result.ok) provenanceError('NATIVE_PROVENANCE_SIGNATURE_INVALID');

  return Object.freeze({
    manifestFingerprint: nativeFingerprint(bytes.manifest),
    addonSha256: manifest.sha256,
    platform: values.platform,
    architecture: values.architecture,
    contractVersion: manifest.contractVersion,
    contractRevision: manifest.contractRevision,
    napi: manifest.napi,
    signingKeyId: key.keyId,
    signingKeyFingerprint: key.spkiFingerprint,
    signatureAlgorithm: result.algorithm,
    addonBytesVerification: 'required',
    addonLoadVerification: 'required',
    addonExportVerification: 'required',
  });
}
