import { createHash, createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyManifestSignature } from '../src/index.js';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const release = join(root, 'build', 'Release');
const addon = join(release, 'native_control.node');
const manifestPath = join(release, 'native-control.manifest.json');
const sidecarPath = `${manifestPath}.sig`;
const trustedKeysPath = join(root, 'release-keys', 'trusted.json');
const capabilities = [
  'open_verified_parent', 'open_no_follow', 'read_identity', 'read_acl', 'path_exists_no_follow',
  'set_exact_role_acl', 'verify_exact_role_acl', 'read_verified_bytes', 'create_exclusive_temp', 'flush_file',
  'flush_directory_or_volume', 'replace_existing_atomic', 'create_absent_exclusive',
  'ensure_control_directory', 'acquire_native_lock', 'current_os_principal',
  'principal_access_check', 'remove_verified_file', 'open_verified_parent_handle',
  'open_verified_object_handle', 'read_handle_identity', 'read_handle_bytes',
  'write_handle_bytes', 'remove_verified_handle', 'verify_role_sid_not_group',
];
const capabilitySignatures = {
  open_verified_parent: ['path'], open_no_follow: ['path'], read_identity: ['path'], read_acl: ['path'], path_exists_no_follow: ['path'],
  set_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  verify_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  read_verified_bytes: ['path'], create_exclusive_temp: ['parent', 'prefix', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  flush_file: ['path'], flush_directory_or_volume: ['path'],
  replace_existing_atomic: ['source', 'destination', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  create_absent_exclusive: ['path', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  ensure_control_directory: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  acquire_native_lock: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  current_os_principal: [], principal_access_check: ['path', 'kind', 'principal', 'mode', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'], remove_verified_file: ['path', 'expectedBytes'],
  open_verified_parent_handle: ['path'], open_verified_object_handle: ['parentHandle', 'name'],
  read_handle_identity: ['handle'], read_handle_bytes: ['handle'],
  write_handle_bytes: ['handle', 'bytes'], remove_verified_handle: ['handle', 'expectedBytes'],
  verify_role_sid_not_group: ['sid'],
};

function fail(message) {
  process.stderr.write(`native-control verification failed: ${message}\n`);
  process.exitCode = 1;
}

function flagValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

// Produces build/Release/native-control.manifest.json.sig next to the freshly written manifest.
// Two custody models are supported so the private key never has to touch this tooling:
//   --sign-key <pem path>            sign locally with a PEM-encoded ed25519 or P-256 private key
//   --signature <raw sig file> --key-id <id> --algorithm <ed25519|p256>
//                                     accept a signature produced elsewhere (cloud KMS, PIV/hardware
//                                     token, ...): this script only base64-wraps the given bytes.
function writeSignatureSidecar(manifestBytes) {
  const signKeyPath = flagValue('--sign-key');
  const externalSignaturePath = flagValue('--signature');
  if (!signKeyPath && !externalSignaturePath) return;
  if (signKeyPath && externalSignaturePath) {
    fail('--sign-key and --signature are mutually exclusive');
    return;
  }
  if (signKeyPath) {
    const keyId = flagValue('--key-id');
    if (!keyId) { fail('--sign-key requires --key-id'); return; }
    let privateKey;
    try { privateKey = createPrivateKey(readFileSync(signKeyPath)); } catch { fail(`--sign-key file is not a readable private key: ${signKeyPath}`); return; }
    let algorithm; let signature;
    try {
      if (privateKey.asymmetricKeyType === 'ed25519') {
        algorithm = 'ed25519';
        signature = cryptoSign(null, manifestBytes, privateKey);
      } else if (privateKey.asymmetricKeyType === 'ec' && privateKey.asymmetricKeyDetails?.namedCurve === 'prime256v1') {
        algorithm = 'p256';
        signature = cryptoSign('sha256', manifestBytes, privateKey);
      } else {
        fail(`--sign-key must be an ed25519 or P-256 private key, got: ${privateKey.asymmetricKeyType}`);
        return;
      }
    } catch { fail('signing the manifest with --sign-key failed'); return; }
    writeFileSync(sidecarPath, `${JSON.stringify({ keyId, algorithm, signature: signature.toString('base64') }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    return;
  }
  const keyId = flagValue('--key-id');
  const algorithm = flagValue('--algorithm');
  if (!keyId || !algorithm) { fail('--signature requires both --key-id and --algorithm'); return; }
  if (algorithm !== 'ed25519' && algorithm !== 'p256') { fail(`--algorithm must be "ed25519" or "p256", got: ${algorithm}`); return; }
  let signature;
  try { signature = readFileSync(externalSignaturePath); } catch { fail(`--signature file is not readable: ${externalSignaturePath}`); return; }
  writeFileSync(sidecarPath, `${JSON.stringify({ keyId, algorithm, signature: signature.toString('base64') }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

function readJsonFileSafe(path) {
  let raw;
  try { raw = readFileSync(path, 'utf8'); } catch { return { present: false, value: undefined }; }
  try { return { present: true, value: JSON.parse(raw) }; } catch { return { present: true, value: undefined }; }
}

class DuplicateTrustKeyError extends Error {}

function normalizeTrustStore(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || value.version !== 1 || !Array.isArray(value.keys)) return [];
  const keys = value.keys.filter((key) => key && typeof key.keyId === 'string' && key.keyId &&
    (key.algorithm === 'ed25519' || key.algorithm === 'p256') && typeof key.publicKeyPem === 'string' && key.publicKeyPem);
  const seenKeyIds = new Set();
  for (const key of keys) {
    if (seenKeyIds.has(key.keyId)) throw new DuplicateTrustKeyError(`duplicate keyId in trust store: ${key.keyId}`);
    seenKeyIds.add(key.keyId);
  }
  return keys;
}

// --require-signature fails the build when the sidecar ends up absent, malformed, or does not verify
// strictly against the committed trusted.json trust root. A development key from local-dev.json is
// deliberately never consulted here: --require-signature is the release gate, so it must never be
// satisfiable by a key that only proves a local development build.
// Exported (with injectable paths) so tests can exercise this decision directly without running the
// whole build pipeline as a subprocess, the same pattern loadVerifiedAddon uses in src/index.js.
export function evaluateRequiredSignature(manifestBytes, { sidecarPath: sidecarFilePath = sidecarPath, trustedKeysPath: trustedKeysFilePath = trustedKeysPath } = {}) {
  const sidecarFile = readJsonFileSafe(sidecarFilePath);
  if (!sidecarFile.present) return { ok: false, reason: 'the signature sidecar is missing' };
  if (sidecarFile.value === undefined) return { ok: false, reason: 'the signature sidecar is malformed' };
  let trustedKeys;
  try { trustedKeys = normalizeTrustStore(readJsonFileSafe(trustedKeysFilePath).value); }
  catch (error) { return { ok: false, reason: `the trust store is invalid: ${error.message}` }; }
  const result = verifyManifestSignature(manifestBytes, sidecarFile.value, { version: 1, keys: trustedKeys });
  if (!result.ok) return { ok: false, reason: `signature verification failed: ${result.reason}` };
  return { ok: true, keyId: result.keyId, algorithm: result.algorithm };
}

function enforceRequiredSignature(manifestBytes) {
  if (!process.argv.includes('--require-signature')) return;
  const result = evaluateRequiredSignature(manifestBytes);
  if (!result.ok) fail(`--require-signature was set but ${result.reason}`);
}

const isMainModule = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMainModule) {

if (JSON.stringify(packageJson.nativeControlContract) !== JSON.stringify({
  version: 3, napi: 8, platforms: ['linux-x64', 'linux-arm64', 'win32-x64'],
})) fail('package native capability contract is invalid');

if (!['linux-x64', 'linux-arm64', 'win32-x64'].includes(`${process.platform}-${process.arch}`)) {
  fail(`unsupported native-control platform: ${process.platform}-${process.arch}`);
} else if (!existsSync(addon)) {
  fail('native_control.node is missing');
} else {
  const expected = {
    contractVersion: 3,
    package: packageJson.name,
    version: packageJson.version,
    napi: 8,
    platform: process.platform,
    arch: process.arch,
    addon: 'native_control.node',
    sha256: createHash('sha256').update(readFileSync(addon)).digest('hex'),
    capabilities,
    capabilitySignatures,
  };
  let loaded;
  try { loaded = require(addon); } catch { fail('native_control.node could not be loaded'); }
  if (loaded) {
    for (const name of capabilities) if (typeof loaded[name] !== 'function') fail(`native capability ${name} is missing`);
    let contract;
    try { contract = loaded.native_control_contract(); } catch { fail('native capability contract is missing or unreadable'); }
    if (!contract || JSON.stringify(contract) !== JSON.stringify({ contractVersion: 3, napi: 8, capabilities, capabilitySignatures })) fail('native capability contract does not match the expected function signatures');
  }
  if (process.argv.includes('--write-manifest')) {
    if (!loaded || process.exitCode) process.exitCode = 1;
    else {
      const manifestBytes = Buffer.from(`${JSON.stringify(expected, null, 2)}\n`, 'utf8');
      // Regenerating the manifest invalidates any existing sidecar: a signature is over the exact
      // prior manifest bytes, so once those bytes change the old sidecar is stale and must never be
      // left on disk where it could be mistaken for still valid. Delete it before writing the new
      // manifest so a rebuild that is not immediately re-signed fails closed (missing sidecar) rather
      // than silently keeping a signature for a manifest that no longer exists. Rebuild-then-resign
      // order: run `--write-manifest` to regenerate the manifest and drop the stale sidecar, then
      // re-run with `--sign-key`/`--signature` (optionally `--require-signature`) to produce a fresh
      // sidecar over the new manifest bytes.
      try { rmSync(sidecarPath, { force: true }); } catch {}
      writeFileSync(manifestPath, manifestBytes, { encoding: 'utf8', mode: 0o600 });
      writeSignatureSidecar(manifestBytes);
      if (!process.exitCode) enforceRequiredSignature(manifestBytes);
    }
  } else if (!existsSync(manifestPath)) {
    fail('native-control.manifest.json is missing');
  } else {
    let actual;
    let manifestBytes;
    try { manifestBytes = readFileSync(manifestPath); actual = JSON.parse(manifestBytes.toString('utf8')); } catch { fail('manifest is not valid JSON'); process.exit(); }
    for (const [key, value] of Object.entries(expected)) {
      if (JSON.stringify(actual[key]) !== JSON.stringify(value)) fail(`manifest ${key} does not match the local addon`);
    }
    writeSignatureSidecar(manifestBytes);
    if (!process.exitCode) enforceRequiredSignature(manifestBytes);
  }
}
}
