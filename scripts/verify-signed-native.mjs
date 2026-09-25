import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseStrictJson,
  parseStrictJsonBytes,
} from '@gjc-remote/shared/strict-json';
import {
  capabilities,
  loadVerifiedAddon,
} from '../native-control/src/index.js';
import {
  validateBuildManifest,
  validateNativePackageContract,
  verifyManifestSignature,
  verifyPinnedNativeBuildManifest,
} from '../native-control/src/native-provenance.js';

const scriptPath = fileURLToPath(import.meta.url);
const projectRoot = dirname(dirname(scriptPath));
const nativeRoot = join(projectRoot, 'native-control');
const packagePath = join(nativeRoot, 'package.json');
const trustPath = join(nativeRoot, 'release-keys', 'trusted.json');
const devTrustPath = join(nativeRoot, 'release-keys', 'local-dev.json');

export const SUPPORTED_TARGETS = Object.freeze({
  'linux-x64': Object.freeze({ platform: 'linux', architecture: 'x64' }),
  'linux-arm64': Object.freeze({ platform: 'linux', architecture: 'arm64' }),
  'win32-x64': Object.freeze({ platform: 'win32', architecture: 'x64' }),
});

const LIMITS = Object.freeze({
  addonBytes: 512 * 1024 * 1024,
  manifestBytes: 1024 * 1024,
  packageBytes: 1024 * 1024,
  sidecarBytes: 16 * 1024,
  signaturesFileBytes: 64 * 1024,
  trustBytes: 64 * 1024,
});
const MANIFEST_JSON_LIMITS = Object.freeze({
  maxBytes: LIMITS.manifestBytes,
  maxDepth: 64,
  maxNodes: 100_000,
});
const PACKAGE_JSON_LIMITS = MANIFEST_JSON_LIMITS;
const SIDECAR_JSON_LIMITS = Object.freeze({ maxBytes: LIMITS.sidecarBytes, maxDepth: 8, maxNodes: 64 });
const SIGNATURE_MAP_JSON_LIMITS = Object.freeze({ maxBytes: LIMITS.signaturesFileBytes, maxDepth: 8, maxNodes: 256 });
const TRUST_JSON_LIMITS = Object.freeze({ maxBytes: LIMITS.trustBytes, maxDepth: 8, maxNodes: 512 });
const SIGNING_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SUPPORTED_FLAGS = new Set([
  '--input-dir', '--target', '--source-commit', '--output', '--signatures-file',
]);

function failure(code, message = code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function fail(code, message) {
  throw failure(code, message);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function sameSidecar(left, right) {
  return left.keyId === right.keyId && left.algorithm === right.algorithm &&
    left.signature === right.signature;
}

function validateSidecar(value, code = 'NATIVE_VERIFY_SIGNATURE_INVALID') {
  if (!isPlainObject(value) || Object.keys(value).length !== 3 ||
      !Object.hasOwn(value, 'keyId') || !Object.hasOwn(value, 'algorithm') ||
      !Object.hasOwn(value, 'signature') ||
      typeof value.keyId !== 'string' || !SIGNING_KEY_ID.test(value.keyId) ||
      (value.algorithm !== 'ed25519' && value.algorithm !== 'p256') ||
      typeof value.signature !== 'string' || value.signature.length === 0 ||
      value.signature.length > LIMITS.sidecarBytes ||
      !BASE64.test(value.signature)) {
    fail(code, 'signature sidecar must contain exactly keyId, algorithm, and a base64 signature');
  }
  const sidecar = Object.freeze({
    keyId: value.keyId,
    algorithm: value.algorithm,
    signature: value.signature,
  });
  if (Buffer.byteLength(`${JSON.stringify(sidecar)}\n`, 'utf8') > LIMITS.sidecarBytes) {
    fail(code, 'signature sidecar exceeds its byte limit');
  }
  return sidecar;
}

function parseSidecarBytes(bytes) {
  let value;
  try {
    value = parseStrictJsonBytes(bytes, SIDECAR_JSON_LIMITS);
  } catch {
    fail('NATIVE_VERIFY_SIGNATURE_INVALID', 'signature sidecar is malformed');
  }
  return validateSidecar(value);
}

function serializeSidecar(sidecar) {
  return Buffer.from(`${JSON.stringify(sidecar)}\n`, 'utf8');
}

export function parseArguments(argv) {
  if (!Array.isArray(argv)) fail('NATIVE_VERIFY_ARGUMENTS_INVALID', 'arguments must be an array');
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!SUPPORTED_FLAGS.has(flag) || values.has(flag)) {
      fail('NATIVE_VERIFY_ARGUMENTS_INVALID', `unknown or repeated option: ${String(flag)}`);
    }
    const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) {
      fail('NATIVE_VERIFY_ARGUMENTS_INVALID', `missing value for ${flag}`);
    }
    values.set(flag, value);
    index += 1;
  }
  for (const required of ['--input-dir', '--target', '--source-commit', '--output']) {
    if (!values.has(required)) fail('NATIVE_VERIFY_ARGUMENTS_INVALID', `missing required option: ${required}`);
  }
  const target = values.get('--target');
  if (!Object.hasOwn(SUPPORTED_TARGETS, target)) {
    fail('NATIVE_VERIFY_TARGET_INVALID', 'target must be linux-x64, linux-arm64, or win32-x64');
  }
  const sourceCommit = values.get('--source-commit');
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
    fail('NATIVE_VERIFY_SOURCE_COMMIT_INVALID', 'source commit must be 40 lowercase hexadecimal characters');
  }
  const parsed = {
    inputDir: values.get('--input-dir'),
    target,
    sourceCommit,
    output: values.get('--output'),
  };
  if (values.has('--signatures-file')) parsed.signaturesFile = values.get('--signatures-file');
  return Object.freeze(parsed);
}

export function assertTargetMatchesRuntime(target, platform, architecture) {
  const expected = SUPPORTED_TARGETS[target];
  if (!expected) fail('NATIVE_VERIFY_TARGET_INVALID', 'unsupported native target');
  if (expected.platform !== platform || expected.architecture !== architecture) {
    fail('NATIVE_VERIFY_RUNTIME_MISMATCH', 'the current runtime does not match the requested native target');
  }
  return expected;
}

function validateSignatureMap(value) {
  if (!isPlainObject(value)) {
    fail('NATIVE_VERIFY_SIGNATURE_MAP_INVALID', 'signature map must be a JSON object');
  }
  const names = Object.keys(SUPPORTED_TARGETS).sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== names.length || actual.some((name, index) => name !== names[index])) {
    fail('NATIVE_VERIFY_SIGNATURE_MAP_INVALID', 'signature map must contain exactly all supported targets');
  }
  const result = {};
  for (const target of names) {
    result[target] = validateSidecar(value[target], 'NATIVE_VERIFY_SIGNATURE_MAP_INVALID');
  }
  return Object.freeze(result);
}

export function parseSignatureMap(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > LIMITS.signaturesFileBytes) {
    fail('NATIVE_VERIFY_SIGNATURE_MAP_INVALID', 'signature map is missing or exceeds its byte limit');
  }
  let value;
  try {
    value = parseStrictJsonBytes(bytes, SIGNATURE_MAP_JSON_LIMITS);
  } catch {
    fail('NATIVE_VERIFY_SIGNATURE_MAP_INVALID', 'signature map is malformed');
  }
  return validateSignatureMap(value);
}

export function parseSignaturesJson(text) {
  if (typeof text !== 'string' || text.length === 0 ||
      Buffer.byteLength(text, 'utf8') > LIMITS.signaturesFileBytes) {
    fail('NATIVE_VERIFY_SIGNATURE_MAP_INVALID', 'signature JSON text is missing or exceeds its byte limit');
  }
  let value;
  try {
    value = parseStrictJson(text, SIGNATURE_MAP_JSON_LIMITS);
  } catch {
    fail('NATIVE_VERIFY_SIGNATURE_MAP_INVALID', 'signature JSON text is malformed');
  }
  return validateSignatureMap(value);
}

function boundedBytes(value, maximum, label) {
  if (!Buffer.isBuffer(value) || value.length < 1 || value.length > maximum) {
    fail('NATIVE_VERIFY_INPUT_INVALID', `${label} is missing or exceeds its byte limit`);
  }
  try {
    return Buffer.from(value);
  } catch {
    fail('NATIVE_VERIFY_INPUT_INVALID', `${label} could not be copied`);
  }
}

function parseTrustBytes(bytes) {
  let trustStore;
  try {
    trustStore = parseStrictJsonBytes(bytes, TRUST_JSON_LIMITS, {
      allowedValueControlCodes: new Set([0x0a, 0x0d]),
    });
  } catch {
    fail('NATIVE_VERIFY_TRUST_INVALID', 'trusted keys are malformed');
  }
  if (!isPlainObject(trustStore) || trustStore.version !== 1 ||
      !Array.isArray(trustStore.keys) || trustStore.keys.length === 0) {
    fail('NATIVE_VERIFY_TRUST_INVALID', 'trusted keys have an invalid shape');
  }
  return trustStore;
}

/**
 * Pure byte-level preflight. The supplied trust bytes are explicit so tests
 * can use synthetic Ed25519 fixtures. The production CLI first passes the same
 * manifest, package, sidecar, and trust bytes through verifyPinnedNativeBuildManifest,
 * which binds them to native-control/release-keys/trusted.json.
 */
export function verifyNativePreflight(input) {
  if (!isPlainObject(input)) fail('NATIVE_VERIFY_INPUT_INVALID', 'preflight input must be an object');
  const {
    manifestBytes,
    addonBytes,
    sidecarBytes,
    packageBytes,
    trustedStoreBytes,
    platform,
    architecture,
  } = input;
  const manifestRaw = boundedBytes(manifestBytes, LIMITS.manifestBytes, 'manifest');
  const addonRaw = boundedBytes(addonBytes, LIMITS.addonBytes, 'native addon');
  const sidecarRaw = boundedBytes(sidecarBytes, LIMITS.sidecarBytes, 'signature sidecar');
  const packageRaw = boundedBytes(packageBytes, LIMITS.packageBytes, 'native package');
  const trustRaw = boundedBytes(trustedStoreBytes, LIMITS.trustBytes, 'trusted keys');
  if (typeof platform !== 'string' || typeof architecture !== 'string' ||
      !Object.values(SUPPORTED_TARGETS).some((target) =>
        target.platform === platform && target.architecture === architecture)) {
    fail('NATIVE_VERIFY_TARGET_INVALID', 'native target is not supported');
  }

  let manifest;
  let packageJson;
  try {
    manifest = parseStrictJsonBytes(manifestRaw, MANIFEST_JSON_LIMITS);
    packageJson = parseStrictJsonBytes(packageRaw, PACKAGE_JSON_LIMITS);
  } catch {
    fail('NATIVE_VERIFY_MANIFEST_INVALID', 'manifest or package metadata is malformed');
  }
  if (!isPlainObject(packageJson) || packageJson.name !== '@gjc-remote/native-control' ||
      !validateNativePackageContract(packageJson)) {
    fail('NATIVE_VERIFY_PACKAGE_INVALID', 'repository native package contract is invalid');
  }
  if (manifest?.platform !== platform || manifest?.arch !== architecture) {
    fail('NATIVE_VERIFY_TARGET_INVALID', 'manifest target does not match the requested target');
  }
  let validBuild;
  try {
    validBuild = validateBuildManifest(manifest, packageJson, addonRaw, platform, architecture);
  } catch {
    validBuild = false;
  }
  if (!validBuild) fail('NATIVE_VERIFY_MANIFEST_INVALID', 'manifest contract or addon hash is invalid');

  const sidecar = parseSidecarBytes(sidecarRaw);
  const trustStore = parseTrustBytes(trustRaw);
  let signatureResult;
  try {
    signatureResult = verifyManifestSignature(manifestRaw, sidecar, trustStore);
  } catch {
    fail('NATIVE_VERIFY_SIGNATURE_INVALID', 'signature verification failed');
  }
  if (!signatureResult.ok) {
    const code = signatureResult.reason?.startsWith('unknown signing keyId:')
      ? 'NATIVE_VERIFY_SIGNING_KEY_UNKNOWN'
      : 'NATIVE_VERIFY_SIGNATURE_INVALID';
    fail(code, signatureResult.reason ?? 'signature verification failed');
  }
  return Object.freeze({
    manifest,
    sidecar,
    keyId: signatureResult.keyId,
    algorithm: signatureResult.algorithm,
    addonSha256: createHash('sha256').update(addonRaw).digest('hex'),
    manifestSha256: createHash('sha256').update(manifestRaw).digest('hex'),
    sidecarSha256: createHash('sha256').update(sidecarRaw).digest('hex'),
  });
}

function fileIdentityMatches(left, right) {
  return left.dev === right.dev && left.ino === right.ino &&
    left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

function readBoundedRegularFile(path, maximumBytes, label) {
  let descriptor;
  try {
    const named = lstatSync(path, { bigint: true });
    if (!named.isFile() || named.size < 1n || named.size > BigInt(maximumBytes)) {
      fail('NATIVE_VERIFY_INPUT_INVALID', `${label} is not a bounded regular file`);
    }
    const noFollow = process.platform === 'win32'
      ? 0
      : (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || !fileIdentityMatches(named, before)) {
      fail('NATIVE_VERIFY_INPUT_INVALID', `${label} changed while opening`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    const finalNamed = lstatSync(path, { bigint: true });
    if (offset !== bytes.length || !fileIdentityMatches(before, after) ||
        !fileIdentityMatches(before, finalNamed)) {
      fail('NATIVE_VERIFY_INPUT_INVALID', `${label} changed while reading`);
    }
    return bytes;
  } catch (error) {
    if (error?.code?.startsWith('NATIVE_VERIFY_')) throw error;
    fail('NATIVE_VERIFY_INPUT_INVALID', `${label} is missing or unreadable`);
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        fail('NATIVE_VERIFY_INPUT_INVALID', `${label} could not be closed safely`);
      }
    }
  }
}

function readOptionalBoundedRegularFile(path, maximumBytes, label) {
  try {
    lstatSync(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    fail('NATIVE_VERIFY_INPUT_INVALID', `${label} cannot be inspected`);
  }
  return readBoundedRegularFile(path, maximumBytes, label);
}

function requireInputDirectory(path) {
  try {
    const stat = lstatSync(path);
    if (!stat.isDirectory()) fail('NATIVE_VERIFY_INPUT_INVALID', 'input path must be a non-symlink directory');
  } catch (error) {
    if (error?.code?.startsWith('NATIVE_VERIFY_')) throw error;
    fail('NATIVE_VERIFY_INPUT_INVALID', 'input directory is missing or unreadable');
  }
}

function semanticallyEqualSidecars(leftBytes, right) {
  return sameSidecar(parseSidecarBytes(leftBytes), right);
}

export function installSignatureSidecarIfAbsent(inputDir, candidateBytes, expectedSidecar) {
  const directory = resolve(inputDir);
  requireInputDirectory(directory);
  const candidate = boundedBytes(candidateBytes, LIMITS.sidecarBytes, 'candidate signature sidecar');
  const expected = validateSidecar(expectedSidecar);
  if (!semanticallyEqualSidecars(candidate, expected)) {
    fail('NATIVE_VERIFY_SIGNATURE_INVALID', 'candidate sidecar does not match the verified signature');
  }
  const sidecarPath = join(directory, 'native-control.manifest.json.sig');
  const existing = readOptionalBoundedRegularFile(sidecarPath, LIMITS.sidecarBytes, 'existing signature sidecar');
  if (existing !== null) {
    if (!semanticallyEqualSidecars(existing, expected)) {
      fail('NATIVE_VERIFY_SIGNATURE_CONFLICT', 'existing signature sidecar differs from the verified signature');
    }
    return Object.freeze({ bytes: existing, created: false });
  }
  try {
    writeFileSync(sidecarPath, candidate, { flag: 'wx', mode: 0o600 });
    return Object.freeze({ bytes: candidate, created: true });
  } catch (error) {
    if (error?.code !== 'EEXIST') {
      fail('NATIVE_VERIFY_SIDECAR_WRITE_FAILED', 'signature sidecar could not be created exclusively');
    }
    const raced = readBoundedRegularFile(sidecarPath, LIMITS.sidecarBytes, 'existing signature sidecar');
    if (!semanticallyEqualSidecars(raced, expected)) {
      fail('NATIVE_VERIFY_SIGNATURE_CONFLICT', 'concurrent signature sidecar differs from the verified signature');
    }
    return Object.freeze({ bytes: raced, created: false });
  }
}

export function writeReceiptExclusive(outputPath, receipt) {
  const bytes = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  try {
    writeFileSync(outputPath, bytes, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error?.code === 'EEXIST') fail('NATIVE_VERIFY_OUTPUT_EXISTS', 'receipt output already exists');
    fail('NATIVE_VERIFY_OUTPUT_WRITE_FAILED', 'receipt output could not be created exclusively');
  }
}

function makeTamperProbe(name, input, mutate) {
  const field = name === 'addonByteChange' ? 'addonBytes' :
    name === 'manifestByteChange' ? 'manifestBytes' : 'sidecarBytes';
  const original = input[field];
  const changed = mutate(original);
  if (!Buffer.isBuffer(original) || !Buffer.isBuffer(changed) ||
      changed.length !== original.length || changed.equals(original)) {
    fail('NATIVE_VERIFY_PROBE_FAILED', `${name} tamper probe did not change exactly one byte`);
  }
  const candidate = { ...input, [field]: changed };
  try {
    verifyNativePreflight(candidate);
  } catch (error) {
    return Object.freeze({ rejected: true, changedBytes: 1, rejectionCode: error.code ?? 'ERROR' });
  }
  fail('NATIVE_VERIFY_PROBE_FAILED', `${name} tamper probe was accepted`);
}

function tamperProbes(preflightInput) {
  verifyNativePreflight(preflightInput);
  return Object.freeze({
    addonByteChange: makeTamperProbe('addonByteChange', preflightInput, (bytes) => {
      const changed = Buffer.from(bytes);
      changed[0] ^= 1;
      return changed;
    }),
    manifestByteChange: makeTamperProbe('manifestByteChange', preflightInput, (bytes) => {
      const changed = Buffer.from(bytes);
      const last = changed.length - 1;
      if (changed[last] === 0x0a) changed[last] = 0x20;
      else changed[0] = changed[0] === 0x7b ? 0x5b : changed[0] ^ 1;
      return changed;
    }),
    signatureByteChange: makeTamperProbe('signatureByteChange', preflightInput, (bytes) => {
      const changed = Buffer.from(bytes);
      const keyMarker = Buffer.from('"signature"', 'utf8');
      const keyIndex = changed.indexOf(keyMarker);
      const colon = changed.indexOf(0x3a, keyIndex + keyMarker.length);
      const quote = changed.indexOf(0x22, colon + 1);
      const character = quote + 1;
      if (keyIndex < 0 || colon < 0 || quote < 0 || character >= changed.length) {
        fail('NATIVE_VERIFY_PROBE_FAILED', 'signature field could not be located for tamper probe');
      }
      changed[character] = changed[character] === 0x41 ? 0x42 : 0x41;
      return changed;
    }),
  });
}

export function probeNativeTampering(preflightInput) {
  return tamperProbes(preflightInput);
}

function assertOutputDoesNotAliasInputs(options, paths) {
  const outputPath = resolve(options.output);
  for (const path of paths) {
    if (path && outputPath === resolve(path)) {
      fail('NATIVE_VERIFY_ARGUMENTS_INVALID', 'receipt output must not replace an input or signature sidecar');
    }
  }
}

function runtimeReceipt() {
  const bunVersion = typeof globalThis.Bun?.version === 'string'
    ? globalThis.Bun.version
    : null;
  return Object.freeze({
    name: bunVersion === null ? 'node' : 'bun',
    version: bunVersion ?? process.version,
    nodeVersion: process.version,
    bunVersion,
  });
}

function verifyPinned(manifestBytes, signatureBytes, packageBytes, trustedStoreBytes, target) {
  return verifyPinnedNativeBuildManifest({
    manifestBytes,
    signatureBytes,
    packageBytes,
    bundledTrustBytes: trustedStoreBytes,
    platform: target.platform,
    architecture: target.architecture,
  });
}

export function runVerification(rawOptions) {
  const options = Array.isArray(rawOptions)
    ? parseArguments(rawOptions)
    : rawOptions;
  if (!options || !Object.hasOwn(SUPPORTED_TARGETS, options.target) ||
      !/^[0-9a-f]{40}$/.test(options.sourceCommit ?? '')) {
    fail('NATIVE_VERIFY_ARGUMENTS_INVALID', 'verification options are invalid');
  }
  const target = assertTargetMatchesRuntime(options.target, process.platform, process.arch);
  const inputDir = resolve(options.inputDir);
  const output = resolve(options.output);
  requireInputDirectory(inputDir);
  const addonPath = join(inputDir, 'native_control.node');
  const manifestPath = join(inputDir, 'native-control.manifest.json');
  const sidecarPath = `${manifestPath}.sig`;
  const signaturesPath = options.signaturesFile ? resolve(options.signaturesFile) : null;
  assertOutputDoesNotAliasInputs(options, [
    addonPath, manifestPath, sidecarPath, signaturesPath, packagePath, trustPath,
  ]);

  const addonBytes = readBoundedRegularFile(addonPath, LIMITS.addonBytes, 'native addon');
  const manifestBytes = readBoundedRegularFile(manifestPath, LIMITS.manifestBytes, 'native manifest');
  const packageBytes = readBoundedRegularFile(packagePath, LIMITS.packageBytes, 'native package');
  const trustedStoreBytes = readBoundedRegularFile(trustPath, LIMITS.trustBytes, 'pinned native trust store');
  const targetSignatureMap = signaturesPath === null
    ? null
    : parseSignatureMap(readBoundedRegularFile(signaturesPath, LIMITS.signaturesFileBytes, 'signature map'));

  let signatureBytes;
  let signature;
  if (targetSignatureMap !== null) {
    signature = targetSignatureMap[options.target];
    signatureBytes = serializeSidecar(signature);
  } else {
    signatureBytes = readOptionalBoundedRegularFile(sidecarPath, LIMITS.sidecarBytes, 'native signature sidecar');
    if (signatureBytes === null) {
      fail('NATIVE_VERIFY_SIGNATURE_INVALID', 'native signature sidecar is missing and no signature map was supplied');
    }
    signature = parseSidecarBytes(signatureBytes);
  }

  // This production verifier reads the repository-pinned trust root itself and
  // requires the bundled trust bytes to have the same complete pin identities.
  const pinned = verifyPinned(manifestBytes, signatureBytes, packageBytes, trustedStoreBytes, target);
  const preflightInput = {
    manifestBytes,
    addonBytes,
    sidecarBytes: signatureBytes,
    packageBytes,
    trustedStoreBytes,
    platform: target.platform,
    architecture: target.architecture,
  };
  const verified = verifyNativePreflight(preflightInput);

  let installedSidecar = false;
  if (targetSignatureMap !== null) {
    const installed = installSignatureSidecarIfAbsent(inputDir, signatureBytes, signature);
    signatureBytes = installed.bytes;
    installedSidecar = installed.created;
    preflightInput.sidecarBytes = signatureBytes;
    verifyNativePreflight(preflightInput);
  }

  const probes = tamperProbes(preflightInput);
  const warnings = [];
  loadVerifiedAddon({
    manifestPath,
    addonPath,
    packageJsonPath: packagePath,
    sidecarPath,
    trustedKeysPath: trustPath,
    devKeysPath: devTrustPath,
    warn: (message) => warnings.push(String(message)),
  });
  if (warnings.length !== 0) {
    fail('NATIVE_VERIFY_LOADER_WARNING', 'verified addon loader emitted a warning');
  }

  const receipt = Object.freeze({
    schemaVersion: 1,
    kind: 'signed-native-verification',
    status: 'verified',
    target: options.target,
    platform: target.platform,
    architecture: target.architecture,
    runtime: runtimeReceipt(),
    sourceCommit: options.sourceCommit,
    hashes: Object.freeze({
      addonSha256: verified.addonSha256,
      manifestSha256: verified.manifestSha256,
      sidecarSha256: createHash('sha256').update(signatureBytes).digest('hex'),
    }),
    signing: Object.freeze({ keyId: pinned.signingKeyId, algorithm: pinned.signatureAlgorithm }),
    capabilityCount: capabilities.length,
    probes,
    sidecarInstalled: installedSidecar,
    limits: LIMITS,
    limitations: Object.freeze([
      'sourceCommit is a caller-supplied label; it is not embedded in or authenticated by the addon.',
      'Only the current host target is loaded; this does not execute or prove another target artifact.',
      'Production signature authority is the repository-pinned native-control/release-keys/trusted.json.',
      'Verification describes the bytes and loader contract observed during this run, not future filesystem state.',
      'This verifier neither builds artifacts nor signs them and makes no service or deployment API calls.',
    ]),
  });
  writeReceiptExclusive(output, receipt);
  return receipt;
}

function isMainModule() {
  return typeof process.argv[1] === 'string' && resolve(process.argv[1]) === scriptPath;
}

if (isMainModule()) {
  try {
    const receipt = runVerification(parseArguments(process.argv.slice(2)));
    process.stdout.write(`verified ${receipt.target} signed native artifact\n`);
  } catch (error) {
    process.stderr.write(`signed native verification failed: ${error.code ?? 'ERROR'}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
