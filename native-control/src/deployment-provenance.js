import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCanonicalJsonBytes, parseStrictJsonBytes } from '@gjc-remote/shared/strict-json';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  deploymentSignaturePreimage,
  validateApplicationDeploymentManifest,
  validateDeploymentSignature,
  validateShawlDeploymentManifest,
} from '@gjc-remote/shared/deployment-envelope';

const applicationTrustPath = fileURLToPath(new URL('../deployment-keys/application-trusted.json', import.meta.url));
const shawlTrustPath = fileURLToPath(new URL('../deployment-keys/shawl-trusted.json', import.meta.url));
const nativeTrustPath = fileURLToPath(new URL('../release-keys/trusted.json', import.meta.url));
const trustLimits = Object.freeze({ maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 512 });
const manifestLimits = Object.freeze({ maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, maxDepth: 32, maxNodes: 100_000 });
const signatureLimits = Object.freeze({ maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes, maxDepth: 8, maxNodes: 64 });
const pinnedManifests = new WeakMap();
const keyIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const plain = (value) => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function refuse(code) {
  const error = new Error(code);
  error.code = code;
  error.operation = 'verify_deployment_provenance';
  error.writes = 0;
  throw error;
}

// Bounded read-only byte acquisition for the verifier. This is not a retained
// native ownership proof and must not authorize extraction or service mutation.
export function readDeploymentInputFile(path, maximumBytes) {
  if (typeof path !== 'string' || !isAbsolute(path) || Buffer.byteLength(path) > 4096 ||
      /[\p{Cc}\p{Cs}\u2028\u2029]/u.test(path) || !Number.isSafeInteger(maximumBytes) ||
      maximumBytes < 1 || maximumBytes > DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes) refuse('DEPLOYMENT_FILE_INVALID');
  let fd;
  try {
    const named = lstatSync(path, { bigint: true });
    if (!named.isFile() || named.size > BigInt(maximumBytes)) refuse('DEPLOYMENT_FILE_INVALID');
    const flags = process.platform === 'win32'
      ? constants.O_RDONLY
      : constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
    fd = openSync(path, flags);
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.dev !== named.dev || before.ino !== named.ino || before.size > BigInt(maximumBytes)) {
      refuse('DEPLOYMENT_FILE_INVALID');
    }
    const bytes = Buffer.alloc(maximumBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const finalNamed = lstatSync(path, { bigint: true });
    if (length > maximumBytes || BigInt(length) !== before.size ||
        [after, finalNamed].some((stat) => !stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino ||
          stat.size !== before.size || stat.mtimeNs !== before.mtimeNs || stat.ctimeNs !== before.ctimeNs)) {
      refuse('DEPLOYMENT_FILE_INVALID');
    }
    return bytes.subarray(0, length);
  } catch {
    refuse('DEPLOYMENT_FILE_INVALID');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function parseTrust(bytes, deployment) {
  let store;
  try {
    // PEM values contain line endings; every other field is separately bounded below.
    store = parseStrictJsonBytes(bytes, trustLimits, { allowedValueControlCodes: new Set([10, 13]) });
  } catch {
    refuse('DEPLOYMENT_TRUST_INVALID');
  }
  if (!exact(store, ['version', 'keys']) || store.version !== 1 || !Array.isArray(store.keys) ||
      store.keys.length === 0 || store.keys.length > 32) refuse('DEPLOYMENT_TRUST_INVALID');
  const ids = new Set();
  const fingerprints = new Set();
  return store.keys.map((entry) => {
    if (!exact(entry, ['keyId', 'algorithm', 'publicKeyPem']) || typeof entry.keyId !== 'string' ||
        !keyIdPattern.test(entry.keyId) || ids.has(entry.keyId) ||
        (deployment ? entry.algorithm !== 'ed25519' : !['ed25519', 'p256'].includes(entry.algorithm)) ||
        typeof entry.publicKeyPem !== 'string' || Buffer.byteLength(entry.publicKeyPem) > 16 * 1024 ||
        !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/.test(entry.publicKeyPem)) {
      refuse('DEPLOYMENT_TRUST_INVALID');
    }
    let publicKey;
    let spkiFingerprint;
    try {
      publicKey = createPublicKey(entry.publicKeyPem);
      if ((entry.algorithm === 'ed25519' && publicKey.asymmetricKeyType !== 'ed25519') ||
          (entry.algorithm === 'p256' && (publicKey.asymmetricKeyType !== 'ec' ||
            publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1'))) refuse('DEPLOYMENT_TRUST_INVALID');
      spkiFingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
    } catch {
      refuse('DEPLOYMENT_TRUST_INVALID');
    }
    if (fingerprints.has(spkiFingerprint)) refuse('DEPLOYMENT_TRUST_INVALID');
    ids.add(entry.keyId);
    fingerprints.add(spkiFingerprint);
    return { keyId: entry.keyId, algorithm: entry.algorithm, publicKey, spkiFingerprint };
  });
}

function freezeVerifiedManifest(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeVerifiedManifest(child);
    Object.freeze(value);
  }
  return value;
}

// Pure verifier: explicit purpose-specific trust bytes support release tooling
// and isolated fixtures. Only the root selected by purpose is parsed; the
// installed acquisition path supplies that root from its module-relative file.
// Installed acquisition must use verifyPinnedDeploymentProvenance, not caller trust.
export function verifyDeploymentProvenance({ purpose, manifestBytes, signatureBytes, applicationTrustBytes, shawlTrustBytes, nativeTrustBytes, platform, architecture }) {
  if (!['application', 'shawl'].includes(purpose) ||
      !['linux:x64', 'linux:arm64', 'win32:x64'].includes(`${platform}:${architecture}`) ||
      (purpose === 'shawl' && platform !== 'win32')) refuse('DEPLOYMENT_TARGET_INVALID');
  const deploymentTrustBytes = purpose === 'application' ? applicationTrustBytes : shawlTrustBytes;
  const deploymentKeys = parseTrust(deploymentTrustBytes, true);
  const nativeKeys = parseTrust(nativeTrustBytes, false);
  const nativeIds = new Set(nativeKeys.map((entry) => entry.keyId));
  const nativeFingerprints = new Set(nativeKeys.map((entry) => entry.spkiFingerprint));
  if (deploymentKeys.some((entry) => nativeIds.has(entry.keyId) || nativeFingerprints.has(entry.spkiFingerprint))) {
    refuse('DEPLOYMENT_TRUST_DOMAIN_COLLISION');
  }
  let manifest;
  let signature;
  let preimage;
  try {
    manifest = parseCanonicalJsonBytes(manifestBytes, manifestLimits);
    if (purpose === 'application') validateApplicationDeploymentManifest(manifest);
    else validateShawlDeploymentManifest(manifest);
    signature = parseCanonicalJsonBytes(signatureBytes, signatureLimits);
    validateDeploymentSignature(signature, purpose, manifest);
    preimage = deploymentSignaturePreimage(purpose, manifest);
  } catch {
    refuse('DEPLOYMENT_MANIFEST_INVALID');
  }
  if (manifest.target.platform !== platform || manifest.target.architecture !== architecture) refuse('DEPLOYMENT_TARGET_INVALID');
  const key = deploymentKeys.find((entry) => entry.keyId === signature.keyId);
  if (!key) refuse('DEPLOYMENT_SIGNING_KEY_UNKNOWN');
  let valid = false;
  try {
    valid = verify(null, preimage, key.publicKey, Buffer.from(signature.signature, 'base64'));
  } catch {
    refuse('DEPLOYMENT_SIGNATURE_INVALID');
  }
  if (!valid) refuse('DEPLOYMENT_SIGNATURE_INVALID');
  return Object.freeze({
    manifest: freezeVerifiedManifest(manifest),
    manifestFingerprint: manifest.manifestFingerprint,
    signingKeyId: key.keyId,
    signingKeyFingerprint: key.spkiFingerprint,
    purpose,
    nativeAddonProvenance: 'independent-verification-required',
  });
}

// The brand belongs to this installed module instance, not to serialized fields,
// explicit-trust tooling receipts, or a caller-provided verification callback.
export function assertPinnedDeploymentManifest(manifest, purpose) {
  if (!['application', 'shawl'].includes(purpose) || pinnedManifests.get(manifest) !== purpose) {
    refuse('DEPLOYMENT_PINNED_PROVENANCE_REQUIRED');
  }
  return manifest;
}

// Trust roots are module-relative, never supplied by a service request or environment.
// Application and Shawl each read only their own purpose-specific root.
// Missing production material is an explicit gate; no bootstrap/dev-key fallback exists.
export function verifyPinnedDeploymentProvenance(input) {
  if (!exact(input, ['purpose', 'manifestBytes', 'signatureBytes', 'platform', 'architecture'])) {
    refuse('DEPLOYMENT_INPUT_INVALID');
  }
  let deploymentTrustBytes;
  let nativeTrustBytes;
  try {
    const trustPath = input.purpose === 'application' ? applicationTrustPath : shawlTrustPath;
    deploymentTrustBytes = readDeploymentInputFile(trustPath, trustLimits.maxBytes);
    nativeTrustBytes = readDeploymentInputFile(nativeTrustPath, trustLimits.maxBytes);
  } catch {
    refuse('DEPLOYMENT_TRUST_UNAVAILABLE');
  }
  const verified = verifyDeploymentProvenance({
    ...input,
    ...(input.purpose === 'application'
      ? { applicationTrustBytes: deploymentTrustBytes }
      : { shawlTrustBytes: deploymentTrustBytes }),
    nativeTrustBytes,
  });
  pinnedManifests.set(verified.manifest, verified.purpose);
  return verified;
}
