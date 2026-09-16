import { spawnSync } from 'node:child_process';
import { chmodSync, closeSync, constants, fsyncSync, fstatSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmdirSync, unlinkSync, writeSync } from 'node:fs';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  DEPLOYMENT_SIGNATURE_DOMAINS,
  deploymentSignaturePreimage,
  validateApplicationDeploymentManifest,
  validateDeploymentSignature,
  validateShawlDeploymentManifest,
} from '@gjc-remote/shared/deployment-envelope';
import { canonicalJsonBytes, parseCanonicalJsonBytes } from '@gjc-remote/shared/strict-json';

const MANIFEST_LIMITS = Object.freeze({ maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, maxDepth: 32, maxNodes: 100_000 });
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const FLAGS = Object.freeze(['--purpose', '--manifest', '--key', '--key-id', '--output', '--openssl']);
const PATH_MAX_BYTES = 4096;
const OPENSSL_COMMAND = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

class SigningError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
    this.writes = 0;
  }
}

function fail(code) {
  throw new SigningError(code);
}

function parseArguments(args) {
  if (args.length !== FLAGS.length * 2) fail('DEPLOYMENT_ARGUMENTS_INVALID');
  const options = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!FLAGS.includes(flag) || options.has(flag) || typeof value !== 'string' || value.length === 0 || value.startsWith('--')) {
      fail('DEPLOYMENT_ARGUMENTS_INVALID');
    }
    options.set(flag, value);
  }
  const purpose = options.get('--purpose');
  if (!['application', 'shawl'].includes(purpose)) fail('DEPLOYMENT_ARGUMENTS_INVALID');
  return {
    purpose,
    manifest: absolutePath(options.get('--manifest')),
    key: absolutePath(options.get('--key')),
    keyId: keyId(options.get('--key-id')),
    output: absolutePath(options.get('--output')),
    openssl: opensslCommand(options.get('--openssl')),
  };
}

function safeText(value, maximum = PATH_MAX_BYTES) {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > maximum ||
      /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value) || /[\uD800-\uDFFF]/u.test(value)) {
    fail('DEPLOYMENT_ARGUMENTS_INVALID');
  }
  return value;
}

function absolutePath(value) {
  value = safeText(value);
  if (!isAbsolute(value) || resolve(value) !== value) fail('DEPLOYMENT_ARGUMENTS_INVALID');
  return value;
}

function opensslCommand(value) {
  value = safeText(value);
  if (isAbsolute(value)) return absolutePath(value);
  if (!OPENSSL_COMMAND.test(value) || value.includes('..')) fail('DEPLOYMENT_ARGUMENTS_INVALID');
  return value;
}

function keyId(value) {
  value = safeText(value, DEPLOYMENT_ENVELOPE_LIMITS.keyIdBytes);
  if (!KEY_ID.test(value)) fail('DEPLOYMENT_ARGUMENTS_INVALID');
  return value;
}

function readBoundedFile(path, maximum) {
  let fd;
  try {
    const named = lstatSync(path, { bigint: true });
    if (!named.isFile() || named.size > BigInt(maximum)) fail('DEPLOYMENT_FILE_INVALID');
    const flags = process.platform === 'win32' ? constants.O_RDONLY : constants.O_RDONLY | constants.O_NOFOLLOW;
    fd = openSync(path, flags);
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.dev !== named.dev || before.ino !== named.ino || before.size > BigInt(maximum)) {
      fail('DEPLOYMENT_FILE_INVALID');
    }
    const bytes = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const finalNamed = lstatSync(path, { bigint: true });
    if (length > maximum || BigInt(length) !== before.size ||
        [after, finalNamed].some((stat) => !stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino ||
          stat.size !== before.size || stat.mtimeNs !== before.mtimeNs || stat.ctimeNs !== before.ctimeNs)) {
      fail('DEPLOYMENT_FILE_INVALID');
    }
    return bytes.subarray(0, length);
  } catch (error) {
    if (error instanceof SigningError) throw error;
    fail('DEPLOYMENT_FILE_INVALID');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function parseManifest(bytes, purpose) {
  let manifest;
  try {
    manifest = parseCanonicalJsonBytes(bytes, MANIFEST_LIMITS);
    if (purpose === 'application') validateApplicationDeploymentManifest(manifest);
    else validateShawlDeploymentManifest(manifest);
  } catch {
    fail('DEPLOYMENT_MANIFEST_INVALID');
  }
  return manifest;
}

function openSSLOnce(command, key, preimage, preimagePath = undefined) {
  let result;
  try {
    result = spawnSync(command, [
      'pkeyutl', '-sign', '-rawin', '-inkey', key,
      ...(preimagePath === undefined ? [] : ['-in', preimagePath]),
    ], {
      input: preimagePath === undefined ? preimage : undefined,
      encoding: null,
      maxBuffer: 128 * 1024,
      windowsHide: true,
      shell: false,
    });
  } catch {
    return null;
  }
  return result.error || result.status !== 0 || result.signal !== null || !Buffer.isBuffer(result.stdout)
    ? null
    : result.stdout;
}

function invokeOpenSSL(command, key, preimage) {
  // OpenSSL's Ed25519 pkeyutl implementation requires a seekable input on
  // some platforms. Try the pipe first, then use a private 0600 temporary
  // file only when the platform/tool cannot consume stdin.
  let signature = openSSLOnce(command, key, preimage);
  if (signature !== null && signature.length === 64) return signature;
  let directory;
  let preimagePath;
  let fd;
  try {
    directory = `${tmpdir()}/gjc-deployment-sign-${process.pid}-${Date.now()}`;
    // The directory is intentionally private; avoid recursive cleanup APIs so
    // only this invocation's preimage can be removed.
    mkdirSync(directory, { mode: 0o700 });
    preimagePath = `${directory}/preimage`;
    fd = openSync(preimagePath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    let written = 0;
    while (written < preimage.length) written += writeSync(fd, preimage, written, preimage.length - written);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    signature = openSSLOnce(command, key, undefined, preimagePath);
  } catch {
    signature = null;
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (preimagePath !== undefined) {
      try { unlinkSync(preimagePath); } catch { /* best effort cleanup */ }
    }
    if (directory !== undefined) {
      try { rmdirSync(directory); } catch { /* best effort cleanup */ }
    }
  }
  if (signature === null || signature.length !== 64) fail('DEPLOYMENT_SIGNATURE_INVALID');
  return signature;
}

function writeAtomic(path, bytes) {
  let outputFacts;
  try { outputFacts = lstatSync(path); } catch (error) { if (error.code !== 'ENOENT') fail('DEPLOYMENT_OUTPUT_INVALID'); }
  if (outputFacts && !outputFacts.isFile()) fail('DEPLOYMENT_OUTPUT_INVALID');
  const parent = dirname(path);
  let parentFacts;
  try { parentFacts = lstatSync(parent); } catch { fail('DEPLOYMENT_OUTPUT_INVALID'); }
  if (!parentFacts.isDirectory()) fail('DEPLOYMENT_OUTPUT_INVALID');
  let tempPath;
  let fd;
  try {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      tempPath = `${parent}/.${basename(path)}.tmp-${process.pid}-${Date.now()}-${attempt}`;
      try {
        fd = openSync(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
        break;
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
    if (fd === undefined) throw new Error('temporary output unavailable');
    let written = 0;
    while (written < bytes.length) written += writeSync(fd, bytes, written, bytes.length - written);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    chmodSync(tempPath, 0o600);
    try {
      renameSync(tempPath, path);
    } catch (error) {
      // Windows does not replace an existing file with rename. Remove only the
      // previously validated regular output, then complete the same-dir move.
      if (error.code !== 'EEXIST' && error.code !== 'EPERM') throw error;
      if (outputFacts) unlinkSync(path);
      renameSync(tempPath, path);
    }
    tempPath = undefined;
  } catch {
    fail('DEPLOYMENT_OUTPUT_INVALID');
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (tempPath !== undefined) {
      try { unlinkSync(tempPath); } catch { /* best effort cleanup */ }
    }
  }
}

function run() {
  const options = parseArguments(process.argv.slice(2));
  if (options.manifest === options.output || options.key === options.output) fail('DEPLOYMENT_ARGUMENTS_INVALID');
  const manifestBytes = readBoundedFile(options.manifest, DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes);
  const manifest = parseManifest(manifestBytes, options.purpose);
  if (manifest.signingKeyId !== options.keyId) fail('DEPLOYMENT_SIGNING_KEY_INVALID');
  const preimage = deploymentSignaturePreimage(options.purpose, manifest);
  const signatureBytes = invokeOpenSSL(options.openssl, options.key, preimage);
  const sidecar = {
    schemaVersion: 1,
    kind: `${options.purpose}-deployment-signature`,
    domain: DEPLOYMENT_SIGNATURE_DOMAINS[options.purpose],
    keyId: options.keyId,
    algorithm: 'ed25519',
    manifestFingerprint: manifest.manifestFingerprint,
    signature: signatureBytes.toString('base64'),
  };
  try { validateDeploymentSignature(sidecar, options.purpose, manifest); } catch { fail('DEPLOYMENT_SIGNATURE_INVALID'); }
  writeAtomic(options.output, canonicalJsonBytes(sidecar));
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    kind: 'deployment-signing-receipt',
    purpose: options.purpose,
    keyId: options.keyId,
    manifestFingerprint: manifest.manifestFingerprint,
    signaturePath: options.output,
    writes: 1,
  })}\n`);
}

try {
  run();
} catch (error) {
  const code = error instanceof SigningError && /^[A-Z0-9_]+$/.test(error.code)
    ? error.code
    : 'DEPLOYMENT_SIGNING_FAILED';
  process.stderr.write(`${JSON.stringify({ schemaVersion: 1, kind: 'deployment-signing-refusal', code, writes: 0 })}\n`);
  process.exitCode = 1;
}
