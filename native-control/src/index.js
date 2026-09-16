import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAdapter } from './adapter.js';
import { capabilities, capabilitySignatures, contractRevision, inventoryCapabilities } from './capabilities.js';
import {
  createInventoryPublisherAdapter,
  createInventoryReaderAdapter,
} from './inventory.js';
import {
  normalizeTrustStore,
  TrustStoreError,
  validateBuildManifest,
  validateNativeAddonContract,
  validateNativePackageContract,
  verifyManifestSignature,
} from './native-provenance.js';
import { createServiceNativeFactory } from './service-native.js';
export { capabilities, capabilitySignatures, contractRevision, inventoryCapabilities };
export { validateBuildManifest, verifyManifestSignature };

const require = createRequire(import.meta.url);
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const releaseDirectory = join(packageRoot, 'build', 'Release');
const addonPath = join(releaseDirectory, 'native_control.node');
const manifestPath = join(releaseDirectory, 'native-control.manifest.json');
const releaseKeysDirectory = join(packageRoot, 'release-keys');
const trustedKeysPath = join(releaseKeysDirectory, 'trusted.json');
const devKeysPath = join(releaseKeysDirectory, 'local-dev.json');
const refused = (operation, reason) => { const error = new Error(`${operation} refused: ${reason}`); error.code = 'ERR_NATIVE_CONTROL_REFUSED'; error.operation = operation; error.reason = reason; error.writes = 0; throw error; };
const defaultWarn = (message) => { console.warn(`[native-control] ${message}`); };

function readJsonFileSafe(path) {
  let raw;
  try { raw = readFileSync(path, 'utf8'); } catch { return { present: false, value: undefined }; }
  try { return { present: true, value: JSON.parse(raw) }; } catch { return { present: true, value: undefined }; }
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
  if (!validateNativePackageContract(packageJson)) {
    refused('load_native_control', 'package native capability contract is invalid');
  }
  if (!validateBuildManifest(manifest, packageJson, addonBytes)) {
    refused('load_native_control', 'build manifest verification failed');
  }
  {
    let trustedKeys; let devKeys;
    try {
      trustedKeys = normalizeTrustStore(readJsonFileSafe(trustedKeysFilePath));
      const devFile = readJsonFileSafe(devKeysFilePath);
      devKeys = devFile.present ? normalizeTrustStore(devFile) : [];
    } catch (error) {
      if (error instanceof TrustStoreError) refused('load_native_control', `trust store is invalid: ${error.message}`);
      throw error;
    }
    // A dev key from the gitignored local-dev.json trust file is honoured only in the bootstrap
    // state where zero production keys are pinned in trusted.json. As soon as one production key is
    // pinned, dev keys are dropped entirely — never merged, never used to shadow, never a fallback —
    // so a dev-signed artifact fails closed with "unknown signing keyId" instead of loading.
    const effectiveKeys = trustedKeys.length > 0 ? trustedKeys : devKeys;
    if (effectiveKeys.length > 0) {
      const sidecarFile = readJsonFileSafe(sidecarFilePath);
      if (!sidecarFile.present) refused('load_native_control', 'addon provenance signature sidecar is missing');
      if (sidecarFile.value === undefined) refused('load_native_control', 'addon provenance signature sidecar is malformed');
      const result = verifyManifestSignature(manifestBytes, sidecarFile.value, { version: 1, keys: effectiveKeys });
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
  if (!validateNativeAddonContract(contract)) {
    refused('load_native_control', 'native capability contract verification failed');
  }
  return addon;
}
export const buildManifest = Object.freeze({
  contractVersion: 4, contractRevision, napi: 8, capabilities, capabilitySignatures,
});

export const createServiceNative = createServiceNativeFactory(loadVerifiedAddon);
export async function createManagementNative({ configPath, roles } = {}) { return createAdapter({ lowLevel: loadVerifiedAddon(), configPath, arbitraryPrincipalProbe: true, roles }); }
export function createInventoryPublisher(options) {
  return createInventoryPublisherAdapter(() => loadVerifiedAddon(), options);
}
export function createInventoryReader(options) {
  return createInventoryReaderAdapter(() => loadVerifiedAddon(), options);
}

// Least-privilege workspace-serving containment surface (slice S7.1). Exposes
// ONLY the three read-only, no-follow identity capabilities that
// createWorkspaceContainment consumes - read_workspace_root_facts (canonical
// reparse-free root identity), read_identity (no-follow leaf identity), and
// path_exists_no_follow. None of these take an auth/role/profile argument, so
// the projection is a thin positional passthrough over the fully verified
// addon. Every management and inventory mutation capability is deliberately
// withheld: a serving-path caller can prove workspace root/leaf identity but
// can reach no capability that writes, ACLs, or publishes. The result is frozen
// so the surface cannot be widened after construction.
const CONTAINMENT_LOW_LEVEL_CAPABILITIES = Object.freeze([
  'read_workspace_root_facts',
  'read_identity',
  'path_exists_no_follow',
]);
export function createContainmentLowLevel({ loadAddon = loadVerifiedAddon } = {}) {
  const addon = loadAddon();
  for (const name of CONTAINMENT_LOW_LEVEL_CAPABILITIES) {
    if (typeof addon?.[name] !== 'function') {
      refused('create_containment_low_level', `verified addon is missing native capability: ${name}`);
    }
  }
  return Object.freeze({
    read_workspace_root_facts: (path, sourcePlatform) => addon.read_workspace_root_facts(path, sourcePlatform),
    read_identity: (path) => addon.read_identity(path),
    path_exists_no_follow: (path) => addon.path_exists_no_follow(path),
  });
}

// Least-privilege residual-process enumerator surface (slice S7.2). Exposes ONLY
// enumerate_workspace_process_holders(workDir, sourcePlatform) -> [{ pid }], the
// read-only scan that proves whether any process still holds a workspace open
// before a reset/delete generation teardown. Like the containment surface it is
// a thin positional passthrough over the fully verified addon with every other
// capability withheld and the result frozen, so a teardown caller can read the
// residual-holder set but reach no capability that signals, writes, or
// destroys. The scan is Linux-only in this slice; on other platforms the native
// capability throws (Windows handle-scan is slice S7.2b).
export function createResidualProcessEnumerator({ loadAddon = loadVerifiedAddon } = {}) {
  const addon = loadAddon();
  if (typeof addon?.enumerate_workspace_process_holders !== 'function') {
    refused('create_residual_process_enumerator', 'verified addon is missing native capability: enumerate_workspace_process_holders');
  }
  return Object.freeze({
    enumerate_workspace_process_holders: (workDir, sourcePlatform) =>
      addon.enumerate_workspace_process_holders(workDir, sourcePlatform),
  });
}
