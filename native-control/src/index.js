import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '@gjc-remote/shared/strict-json';
import { createAdapter } from './adapter.js';
import { capabilities, capabilitySignatures } from './capabilities.js';
export { capabilities, capabilitySignatures };

const require = createRequire(import.meta.url);
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const releaseDirectory = join(packageRoot, 'build', 'Release');
const addonPath = join(releaseDirectory, 'native_control.node');
const manifestPath = join(releaseDirectory, 'native-control.manifest.json');
const releaseKeysDirectory = join(packageRoot, 'release-keys');
const trustedKeysPath = join(releaseKeysDirectory, 'trusted.json');
const devKeysPath = join(releaseKeysDirectory, 'local-dev.json');
const approvedPlatforms = Object.freeze(['linux-x64', 'linux-arm64', 'win32-x64']);
const supportedSignatureAlgorithms = new Set(['ed25519', 'p256']);
const refused = (operation, reason) => { const error = new Error(`${operation} refused: ${reason}`); error.code = 'ERR_NATIVE_CONTROL_REFUSED'; error.operation = operation; error.reason = reason; error.writes = 0; throw error; };
const fingerprint = (value) => createHash('sha256').update(value).digest('hex');
const same = (left, right) => canonicalJson(left) === canonicalJson(right);
const defaultWarn = (message) => { console.warn(`[native-control] ${message}`); };

function readJsonFileSafe(path) {
  let raw;
  try { raw = readFileSync(path, 'utf8'); } catch { return { present: false, value: undefined }; }
  try { return { present: true, value: JSON.parse(raw) }; } catch { return { present: true, value: undefined }; }
}

function normalizeTrustStore(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || value.version !== 1 || !Array.isArray(value.keys)) return [];
  return value.keys.filter((key) => key && Object.getPrototypeOf(key) === Object.prototype &&
    typeof key.keyId === 'string' && key.keyId.length > 0 &&
    supportedSignatureAlgorithms.has(key.algorithm) &&
    typeof key.publicKeyPem === 'string' && key.publicKeyPem.length > 0);
}

// Pure and independently testable: given the exact manifest bytes that were signed, the parsed
// signature sidecar, and a trust store of pinned public keys, decide whether the signature proves
// provenance. Never touches the filesystem so tests can exercise every branch with synthetic input.
export function verifyManifestSignature(manifestBytes, sidecar, trustStore) {
  if (!Buffer.isBuffer(manifestBytes)) return { ok: false, reason: 'manifest bytes are not a buffer' };
  if (!sidecar || Object.getPrototypeOf(sidecar) !== Object.prototype) {
    return { ok: false, reason: 'signature sidecar is missing or malformed' };
  }
  const { keyId, algorithm, signature } = sidecar;
  if (typeof keyId !== 'string' || !keyId ||
    typeof algorithm !== 'string' || !supportedSignatureAlgorithms.has(algorithm) ||
    typeof signature !== 'string' || !signature) {
    return { ok: false, reason: 'signature sidecar is missing or malformed' };
  }
  const keys = Array.isArray(trustStore?.keys) ? trustStore.keys : [];
  const pinned = keys.find((key) => key && key.keyId === keyId);
  if (!pinned) return { ok: false, reason: `unknown signing keyId: ${keyId}` };
  if (pinned.algorithm !== algorithm) return { ok: false, reason: 'signature algorithm does not match the pinned key' };
  let publicKey; let signatureBytes;
  try {
    publicKey = createPublicKey(pinned.publicKeyPem);
    signatureBytes = Buffer.from(signature, 'base64');
  } catch { return { ok: false, reason: 'pinned public key or signature is not decodable' }; }
  try {
    if (algorithm === 'ed25519') {
      if (publicKey.asymmetricKeyType !== 'ed25519') return { ok: false, reason: 'pinned key is not an ed25519 key' };
      if (!cryptoVerify(null, manifestBytes, publicKey, signatureBytes)) return { ok: false, reason: 'signature verification failed' };
    } else {
      if (publicKey.asymmetricKeyType !== 'ec' || publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
        return { ok: false, reason: 'pinned key is not a P-256 key' };
      }
      if (!cryptoVerify('sha256', manifestBytes, publicKey, signatureBytes)) return { ok: false, reason: 'signature verification failed' };
    }
  } catch { return { ok: false, reason: 'signature verification threw an error' }; }
  return { ok: true, keyId, algorithm };
}

export function validateBuildManifest(manifest, packageJson, addonBytes, platform = process.platform, arch = process.arch) {
  if (!manifest || Object.getPrototypeOf(manifest) !== Object.prototype || !packageJson || Object.getPrototypeOf(packageJson) !== Object.prototype || !Buffer.isBuffer(addonBytes)) return false;
  const expected = {
    contractVersion: 3, package: packageJson.name, version: packageJson.version, napi: 8,
    platform, arch, addon: 'native_control.node', sha256: fingerprint(addonBytes),
    capabilities, capabilitySignatures,
  };
  try {
    return approvedPlatforms.includes(`${platform}-${arch}`) &&
      Object.keys(expected).every((key) => same(manifest[key], expected[key]));
  } catch { return false; }
}

export function loadVerifiedAddon({
  manifestPath: manifestFilePath = manifestPath,
  addonPath: addonFilePath = addonPath,
  packageJsonPath: packageJsonFilePath = join(packageRoot, 'package.json'),
  sidecarPath: sidecarFilePath = `${manifestFilePath}.sig`,
  trustedKeysPath: trustedKeysFilePath = trustedKeysPath,
  devKeysPath: devKeysFilePath = devKeysPath,
  warn = defaultWarn,
} = {}) {
  let manifest; let manifestBytes; let packageJson; let addonBytes;
  try {
    manifestBytes = readFileSync(manifestFilePath);
    manifest = JSON.parse(manifestBytes.toString('utf8'));
    packageJson = JSON.parse(readFileSync(packageJsonFilePath, 'utf8'));
    addonBytes = readFileSync(addonFilePath);
  } catch { refused('load_native_control', 'verified build manifest or native addon is missing, invalid, or unreadable'); }
  try {
    if (!same(packageJson.nativeControlContract, { version: 3, napi: 8, platforms: approvedPlatforms })) {
      refused('load_native_control', 'package native capability contract is invalid');
    }
  } catch { refused('load_native_control', 'package native capability contract is invalid'); }
  const expected = {
    contractVersion: 3, package: packageJson.name, version: packageJson.version, napi: 8,
    platform: process.platform, arch: process.arch, addon: 'native_control.node', sha256: fingerprint(addonBytes),
    capabilities, capabilitySignatures,
  };
  if (!validateBuildManifest(manifest, packageJson, addonBytes)) {
    refused('load_native_control', 'build manifest verification failed');
  }
  {
    const trustedKeys = normalizeTrustStore(readJsonFileSafe(trustedKeysFilePath).value);
    const devFile = readJsonFileSafe(devKeysFilePath);
    const devKeys = devFile.present ? normalizeTrustStore(devFile.value) : [];
    if (trustedKeys.length + devKeys.length > 0) {
      const sidecarFile = readJsonFileSafe(sidecarFilePath);
      if (!sidecarFile.present) refused('load_native_control', 'addon provenance signature sidecar is missing');
      if (sidecarFile.value === undefined) refused('load_native_control', 'addon provenance signature sidecar is malformed');
      const result = verifyManifestSignature(manifestBytes, sidecarFile.value, { version: 1, keys: [...trustedKeys, ...devKeys] });
      if (!result.ok) refused('load_native_control', `addon provenance verification failed: ${result.reason}`);
      const usedTrusted = trustedKeys.some((key) => key.keyId === result.keyId);
      if (!usedTrusted) {
        warn(`native-control addon provenance verified with development key "${result.keyId}" from release-keys/local-dev.json — do not use development keys for production builds`);
      }
    } else {
      warn('native-control addon provenance is UNVERIFIED: no release signing keys are pinned in release-keys/trusted.json');
    }
  }
  let addon;
  try { addon = require(addonFilePath); } catch { refused('load_native_control', 'verified native addon could not be loaded'); }
  for (const name of capabilities) if (typeof addon[name] !== 'function') refused('load_native_control', `missing native capability: ${name}`);
  let contract;
  try { contract = addon.native_control_contract(); } catch { refused('load_native_control', 'native capability contract is unreadable'); }
  let validContract = false;
  try {
    validContract = contract?.contractVersion === expected.contractVersion && contract.napi === expected.napi &&
      same(contract.capabilities, capabilities) && same(contract.capabilitySignatures, capabilitySignatures);
  } catch {}
  if (!validContract) refused('load_native_control', 'native capability contract verification failed');
  return addon;
}
export const buildManifest = Object.freeze({ contractVersion: 3, napi: 8, capabilities, capabilitySignatures });

export async function createManagementNative({ configPath, roles } = {}) { return createAdapter({ lowLevel: loadVerifiedAddon(), configPath, arbitraryPrincipalProbe: true, roles }); }
