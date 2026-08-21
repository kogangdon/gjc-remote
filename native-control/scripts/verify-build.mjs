import { createHash, createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
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
  'resolve_native_state_root', 'read_workspace_root_facts', 'ensure_inventory_directory',
  'verify_inventory_acl', 'acquire_inventory_fence', 'read_inventory_object',
  'publish_inventory_object_atomic',
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
  resolve_native_state_root: ['hostKey', 'rootKind'],
  read_workspace_root_facts: ['path', 'sourcePlatform'],
  ensure_inventory_directory: ['path', 'roles', 'profile'],
  verify_inventory_acl: ['path', 'roles', 'profile', 'expectedActor'],
  acquire_inventory_fence: ['path', 'roles'],
  read_inventory_object: ['path', 'maxBytes', 'roles', 'profile'],
  publish_inventory_object_atomic: ['path', 'tempPrefix', 'bytes', 'expectedIdentity', 'roles', 'profile'],
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
    return { keyId, algorithm };
  }
  const keyId = flagValue('--key-id');
  const algorithm = flagValue('--algorithm');
  if (!keyId || !algorithm) { fail('--signature requires both --key-id and --algorithm'); return; }
  if (algorithm !== 'ed25519' && algorithm !== 'p256') { fail(`--algorithm must be "ed25519" or "p256", got: ${algorithm}`); return; }
  let signature;
  try { signature = readFileSync(externalSignaturePath); } catch { fail(`--signature file is not readable: ${externalSignaturePath}`); return; }
  writeFileSync(sidecarPath, `${JSON.stringify({ keyId, algorithm, signature: signature.toString('base64') }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  return { keyId, algorithm };
}

function readJsonFileSafe(path) {
  let raw;
  try { raw = readFileSync(path, 'utf8'); } catch { return { present: false, value: undefined }; }
  try { return { present: true, value: JSON.parse(raw) }; } catch { return { present: true, value: undefined }; }
}

class TrustStoreError extends Error {}
class DuplicateTrustKeyError extends TrustStoreError {}
class MalformedTrustStoreError extends TrustStoreError {}

// Takes the raw { present, value } shape from readJsonFileSafe so an unreadable file (ENOENT,
// permission denied) and an unparseable/wrong-shaped one both fail closed instead of silently
// collapsing into the same result as the legitimate zero-key bootstrap state. Only a file that is
// actually present, valid JSON, and shaped exactly like { version: 1, keys: [] } is bootstrap; a
// keys entry that is missing a required field is a malformed trust store too, not a silently
// dropped key, so it throws instead of being filtered out.
function normalizeTrustStore({ present, value }) {
  if (!present) throw new MalformedTrustStoreError('trust store file is unreadable');
  if (value === undefined) throw new MalformedTrustStoreError('trust store is not valid JSON');
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || value.version !== 1 || !Array.isArray(value.keys)) {
    throw new MalformedTrustStoreError('trust store has an unexpected shape (expected { version: 1, keys: [] })');
  }
  const keys = value.keys.map((key, index) => {
    if (!key || Object.getPrototypeOf(key) !== Object.prototype ||
      typeof key.keyId !== 'string' || key.keyId.length === 0 ||
      (key.algorithm !== 'ed25519' && key.algorithm !== 'p256') ||
      typeof key.publicKeyPem !== 'string' || key.publicKeyPem.length === 0) {
      throw new MalformedTrustStoreError(`trust store keys[${index}] is missing required fields`);
    }
    return key;
  });
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
  try { trustedKeys = normalizeTrustStore(readJsonFileSafe(trustedKeysFilePath)); }
  catch (error) { return { ok: false, reason: `the trust store is invalid: ${error.message}` }; }
  const result = verifyManifestSignature(manifestBytes, sidecarFile.value, { version: 1, keys: trustedKeys });
  if (!result.ok) return { ok: false, reason: `signature verification failed: ${result.reason}` };
  return { ok: true, keyId: result.keyId, algorithm: result.algorithm };
}

function enforceRequiredSignature(manifestBytes) {
  if (!process.argv.includes('--require-signature')) return undefined;
  const result = evaluateRequiredSignature(manifestBytes);
  if (!result.ok) { fail(`--require-signature was set but ${result.reason}`); return undefined; }
  return { keyId: result.keyId, algorithm: result.algorithm };
}

// Success receipt helpers: printed only from the very end of the isMainModule block, and only
// when process.exitCode is still unset, so a receipt can never appear alongside (or instead of)
// a fail() message. Signature phrasing must stay strictly honest about what actually ran this
// invocation: "signed" only when a sidecar was just written, "verified" only when
// --require-signature actually checked it against trusted.json, and an explicit zero-keys-pinned
// line when no production key exists to verify against at all.
function describeSignatureOutcome(signInfo, verifyInfo) {
  if (signInfo && verifyInfo) {
    return `signed sidecar with keyId "${signInfo.keyId}" (${signInfo.algorithm}); verified against pinned keyId "${verifyInfo.keyId}" (${verifyInfo.algorithm})`;
  }
  if (verifyInfo) return `verified against pinned keyId "${verifyInfo.keyId}" (${verifyInfo.algorithm})`;
  if (signInfo) return `signed sidecar with keyId "${signInfo.keyId}" (${signInfo.algorithm}); not verified this run (no --require-signature)`;
  // A corrupt trust store must never be reported as the benign zero-key bootstrap
  // state: the load path refuses it, so the receipt says so too.
  let pinnedCount = 0;
  try {
    pinnedCount = normalizeTrustStore(readJsonFileSafe(trustedKeysPath)).length;
  } catch (error) {
    return `addon provenance UNVERIFIABLE — ${error.message}`;
  }
  if (pinnedCount === 0) return 'addon provenance UNVERIFIED — zero keys are pinned in trusted.json';
  return `not verified this run (no --require-signature); ${pinnedCount} key${pinnedCount === 1 ? '' : 's'} pinned in trusted.json`;
}

function printSuccessReceipt({ manifestRewritten, addonSha256, signInfo, verifyInfo }) {
  if (process.exitCode) return;
  const lines = [
    'native-control build verified',
    `  platform: ${process.platform}-${process.arch}`,
    `  addon sha256: ${addonSha256.slice(0, 12)}\u2026`,
    '  contract: v4',
    `  manifest rewritten: ${manifestRewritten ? 'yes' : 'no'}`,
    `  signature: ${describeSignatureOutcome(signInfo, verifyInfo)}`,
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

// Resolve both sides through realpath so a symlinked or junctioned script path cannot
// make this file look like an imported module and silently skip the entire
// verification pipeline (including --require-signature). Ambiguity fails safe by
// RUNNING the checks: the only caller that must skip them is an in-process test
// importing this module, whose argv[1] is a different real path.
const isMainModule = (() => {
  const entry = process.argv[1];
  if (!entry) return true;
  const selfPath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(entry) === realpathSync(selfPath);
  } catch {
    // Ambiguity must run the checks, never skip them: an in-process test import
    // always has a resolvable argv[1] that differs from this file, so the only
    // callers reaching this branch are unusual invocations we refuse to trust.
    return true;
  }
})();
if (isMainModule) {

if (JSON.stringify(packageJson.nativeControlContract) !== JSON.stringify({
  version: 4, revision: 1, napi: 8, platforms: ['linux-x64', 'linux-arm64', 'win32-x64'],
})) fail('package native capability contract is invalid');

if (!['linux-x64', 'linux-arm64', 'win32-x64'].includes(`${process.platform}-${process.arch}`)) {
  fail(`unsupported native-control platform: ${process.platform}-${process.arch}`);
} else if (!existsSync(addon)) {
  fail('native_control.node is missing');
} else {
  const expected = {
    contractVersion: 4,
    contractRevision: 1,
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
    if (!contract || JSON.stringify(contract) !== JSON.stringify({ contractVersion: 4, contractRevision: 1, napi: 8, capabilities, capabilitySignatures })) fail('native capability contract does not match the expected function signatures');
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
      const signInfo = writeSignatureSidecar(manifestBytes);
      const verifyInfo = process.exitCode ? undefined : enforceRequiredSignature(manifestBytes);
      printSuccessReceipt({ manifestRewritten: true, addonSha256: expected.sha256, signInfo, verifyInfo });
    }
  } else if (!existsSync(manifestPath)) {
    fail('native-control.manifest.json is missing');
  } else {
    let actual;
    let manifestBytes;
    try { manifestBytes = readFileSync(manifestPath); actual = JSON.parse(manifestBytes.toString('utf8')); } catch { fail('manifest is not valid JSON'); process.exit(); }
    if (JSON.stringify(Object.keys(actual).sort()) !== JSON.stringify(Object.keys(expected).sort())) {
      fail('manifest keys do not match the exact local contract');
    }
    for (const [key, value] of Object.entries(expected)) {
      if (JSON.stringify(actual[key]) !== JSON.stringify(value)) fail(`manifest ${key} does not match the local addon`);
    }
    const signInfo = writeSignatureSidecar(manifestBytes);
    const verifyInfo = process.exitCode ? undefined : enforceRequiredSignature(manifestBytes);
    printSuccessReceipt({ manifestRewritten: false, addonSha256: expected.sha256, signInfo, verifyInfo });
  }
}
}
