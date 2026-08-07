import { createHash } from 'node:crypto';
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
const approvedPlatforms = Object.freeze(['linux-x64', 'linux-arm64', 'win32-x64']);
const refused = (operation, reason) => { const error = new Error(`${operation} refused: ${reason}`); error.code = 'ERR_NATIVE_CONTROL_REFUSED'; error.operation = operation; error.reason = reason; error.writes = 0; throw error; };
const fingerprint = (value) => createHash('sha256').update(value).digest('hex');
const same = (left, right) => canonicalJson(left) === canonicalJson(right);
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

function loadVerifiedAddon() {
  let manifest; let packageJson; let addonBytes;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    packageJson = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
    addonBytes = readFileSync(addonPath);
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
  let addon;
  try { addon = require(addonPath); } catch { refused('load_native_control', 'verified native addon could not be loaded'); }
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
