import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  validateApplicationDeploymentManifest,
  validateSdkExternalStateContract,
} from '@gjc-remote/shared/deployment-envelope';
import {
  canonicalJsonBytes,
  canonicalJsonHash,
  parseCanonicalJsonBytes,
  parseStrictJsonBytes,
  utf8Compare,
} from '@gjc-remote/shared/strict-json';
import {
  validateBuildManifestMetadata,
  verifyPinnedNativeBuildManifest,
} from '../src/native-provenance.js';
import { verifyPinnedDeploymentProvenance } from '../src/deployment-provenance.js';
import { createPinnedDeploymentInstallation } from './pinned-deployment-installation.mjs';

const ACKNOWLEDGEMENT_FLAG = '--acknowledge-real-bun-fixture-build';
const FIXED_REMOTE = 'https://github.com/kogangdon/gjc-remote.git';
const FIXTURE_SIGNING_KEY_ID = 'deployment-test';
const PROCESS_TIMEOUT_MS = 60_000;
const PROCESS_OUTPUT_BYTES = 64 * 1024;
const REPORT_BYTES = 64 * 1024;
const COPY_CHUNK_BYTES = 64 * 1024;
const PACKAGE_BYTES = 1024 * 1024;
const LOCK_BYTES = 16 * 1024 * 1024;
const SOURCE_FILE_BYTES = 256 * 1024 * 1024;
const NATIVE_SIGNATURE_BYTES = 16 * 1024;
const TRUST_BYTES = 64 * 1024;
const NATIVE_ADDON_BYTES = 2 * 1024 * 1024 * 1024;
const HOST_TARGETS = new Set(['linux:arm64', 'linux:x64', 'win32:x64']);
const FORBIDDEN_SOURCE_SEGMENTS = new Set([
  '.cache',
  '.env',
  '.git',
  '.gjc',
  '.gjc-remote-session',
  'credentials',
  'home',
  'log',
  'logs',
  'node_modules',
  'session',
  'sessions',
]);
const BUILD_RECEIPT_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'unsigned',
  'signatureGenerated',
  'manifestFingerprint',
  'archiveSha256',
  'treeFingerprint',
  'sdkExternalStateContract',
  'sdkClosureFingerprint',
  'sdkClosurePackageCount',
  'nativeManifestFingerprint',
  'nativeAddonSha256',
  'source',
  'target',
  'producerEvidence',
  'limits',
  'payloadEntryCount',
  'unpackedPayloadBytes',
]);
const VERIFICATION_RECEIPT_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'unsigned',
  'signatureGenerated',
  'manifestFingerprint',
  'archiveSha256',
  'treeFingerprint',
  'sdkExternalStateContractFingerprint',
  'platform',
  'architecture',
  'entryCount',
]);
const PRODUCER_EVIDENCE_KEYS = Object.freeze([
  'kind',
  'version',
  'versionStdoutSha256',
  'versionStderrSha256',
  'installStdoutSha256',
  'installStderrSha256',
  'installArguments',
  'environmentPolicy',
  'integrityAuthority',
]);
const SAFE_FAILURE_CODES = new Set([
  'DEPLOYMENT_SIGNATURE_INVALID',
  'DEPLOYMENT_SIGNING_KEY_UNKNOWN',
  'DEPLOYMENT_TRUST_INVALID',
  'DEPLOYMENT_TRUST_UNAVAILABLE',
  'NATIVE_PROVENANCE_TRUST_INVALID',
  'SERVICE_RELEASE_ARCHIVE_INVALID',
  'SERVICE_RELEASE_CANDIDATE_INVALID',
  'SERVICE_RELEASE_CLOSURE_INVALID',
  'SERVICE_RELEASE_CONTRACT_INVALID',
  'SERVICE_RELEASE_FILE_INVALID',
  'SERVICE_RELEASE_GIT_INVALID',
  'SERVICE_RELEASE_INPUT_INVALID',
  'SERVICE_RELEASE_LOCK_INVALID',
  'SERVICE_RELEASE_NATIVE_INVALID',
  'SERVICE_RELEASE_OUTPUT_INVALID',
  'SERVICE_RELEASE_PATH_INVALID',
  'SERVICE_RELEASE_PRODUCER_FAILED',
  'SERVICE_RELEASE_SDK_INVALID',
  'SERVICE_RELEASE_SOURCE_DIRTY',
  'SERVICE_RELEASE_SOURCE_INVALID',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_ACKNOWLEDGEMENT_REQUIRED',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_CLEANUP_FAILED',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_FAILED',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_TARGET_UNSUPPORTED',
  'SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED',
]);

class RealBunFixtureError extends Error {
  constructor(code) {
    super(code);
    Object.defineProperties(this, {
      name: { value: 'RealBunFixtureError' },
      code: { value: code, enumerable: true },
    });
  }
}

function fail(code) {
  throw new RealBunFixtureError(code);
}

function exact(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) return false;
  const own = Reflect.ownKeys(value);
  return own.length === keys.length &&
    own.every((key) => typeof key === 'string') &&
    keys.every((key) => Object.hasOwn(value, key));
}

function ownData(value, key) {
  if (value === null ||
      (typeof value !== 'object' && typeof value !== 'function')) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && descriptor.get === undefined &&
      descriptor.set === undefined && Object.hasOwn(descriptor, 'value')
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function safeFailureCode(error) {
  const code = ownData(error, 'code');
  return typeof code === 'string' && SAFE_FAILURE_CODES.has(code)
    ? code
    : 'SERVICE_RELEASE_REAL_BUN_FIXTURE_FAILED';
}

function hex64(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function sameJson(left, right) {
  try {
    return canonicalJsonHash(left) === canonicalJsonHash(right);
  } catch {
    return false;
  }
}

function within(root, path) {
  const value = relative(root, path);
  return value !== '' && value !== '..' && !value.startsWith(`..${sep}`) &&
    !isAbsolute(value);
}

function sourceMode(stat) {
  return (Number(stat.mode) & 0o111) === 0 ? 0o644 : 0o755;
}

function sameStableFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino &&
    left.size === right.size && left.mode === right.mode &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function readOnlyFlags() {
  return fsConstants.O_RDONLY | (process.platform === 'win32'
    ? 0
    : (fsConstants.O_NOFOLLOW ?? 0));
}

async function stableRegularFacts(path, maximumBytes, code) {
  let handle;
  try {
    const named = await lstat(path, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.size < 0n ||
        named.size > BigInt(maximumBytes)) fail(code);
    handle = await open(path, readOnlyFlags());
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || !sameStableFile(named, before)) fail(code);
    const sha256 = createHash('sha256');
    const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
    let offset = 0;
    while (offset < Number(before.size)) {
      const length = Math.min(buffer.length, Number(before.size) - offset);
      const result = await handle.read(buffer, 0, length, offset);
      if (result.bytesRead < 1) fail(code);
      sha256.update(buffer.subarray(0, result.bytesRead));
      offset += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const finalNamed = await lstat(path, { bigint: true });
    if (!sameStableFile(before, after) || !sameStableFile(before, finalNamed)) {
      fail(code);
    }
    return Object.freeze({
      size: Number(before.size),
      sha256: sha256.digest('hex'),
      mode: sourceMode(before),
      device: String(before.dev),
      inode: String(before.ino),
      mtimeNs: String(before.mtimeNs),
      ctimeNs: String(before.ctimeNs),
    });
  } catch (error) {
    if (error instanceof RealBunFixtureError) throw error;
    fail(code);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { fail(code); }
    }
  }
}

async function readBoundedRegular(path, maximumBytes, code) {
  let handle;
  try {
    const named = await lstat(path, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.size < 1n ||
        named.size > BigInt(maximumBytes)) fail(code);
    handle = await open(path, readOnlyFlags());
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || !sameStableFile(named, before)) fail(code);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead < 1) fail(code);
      offset += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameStableFile(before, after)) fail(code);
    return bytes;
  } catch (error) {
    if (error instanceof RealBunFixtureError) throw error;
    fail(code);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { fail(code); }
    }
  }
}

async function writeExclusive(path, bytes, mode, code) {
  let handle;
  try {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    handle = await open(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
      mode,
    );
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.write(bytes, offset, bytes.length - offset, offset);
      if (result.bytesWritten < 1) fail(code);
      offset += result.bytesWritten;
    }
    await handle.sync();
    await handle.chmod(mode);
  } catch (error) {
    if (error instanceof RealBunFixtureError) throw error;
    fail(code);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { fail(code); }
    }
  }
}

async function replaceOwnedRegular(path, bytes, ownedRoot) {
  let handle;
  try {
    if (!within(ownedRoot, path)) fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
    const named = await lstat(path, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink()) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
    }
    handle = await open(path, 'r+');
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.dev !== named.dev || opened.ino !== named.ino) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
    }
    await handle.truncate(0);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.write(bytes, offset, bytes.length - offset, offset);
      if (result.bytesWritten < 1) {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
      }
      offset += result.bytesWritten;
    }
    await handle.sync();
    await handle.chmod(0o644);
  } catch (error) {
    if (error instanceof RealBunFixtureError) throw error;
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
  } finally {
    if (handle) {
      try { await handle.close(); } catch {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
      }
    }
  }
}

async function installTemporaryTrust(
  path,
  bytes,
  ownedRoot,
  original,
) {
  if (!original || typeof original.present !== 'boolean') {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
  }
  if (original.present) {
    await replaceOwnedRegular(path, bytes, ownedRoot);
    return;
  }
  if (!within(ownedRoot, path)) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
  }
  await writeExclusive(
    path,
    bytes,
    0o644,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID',
  );
}

async function copyStableRegular(source, destination, expected, maximumBytes) {
  let input;
  let output;
  try {
    const named = await lstat(source, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.size < 0n ||
        named.size > BigInt(maximumBytes)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    input = await open(source, readOnlyFlags());
    const before = await input.stat({ bigint: true });
    if (!before.isFile() || !sameStableFile(named, before)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    output = await open(
      destination,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
      expected.mode,
    );
    const sha256 = createHash('sha256');
    const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
    let offset = 0;
    while (offset < Number(before.size)) {
      const length = Math.min(buffer.length, Number(before.size) - offset);
      const read = await input.read(buffer, 0, length, offset);
      if (read.bytesRead < 1) fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
      const chunk = buffer.subarray(0, read.bytesRead);
      sha256.update(chunk);
      let written = 0;
      while (written < chunk.length) {
        const result = await output.write(
          chunk,
          written,
          chunk.length - written,
          offset + written,
        );
        if (result.bytesWritten < 1) {
          fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
        }
        written += result.bytesWritten;
      }
      offset += read.bytesRead;
    }
    const after = await input.stat({ bigint: true });
    if (!sameStableFile(before, after) || Number(before.size) !== expected.size ||
        sha256.digest('hex') !== expected.sha256) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED');
    }
    await output.sync();
    await output.chmod(expected.mode);
  } catch (error) {
    if (error instanceof RealBunFixtureError) throw error;
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
  } finally {
    if (input) {
      try { await input.close(); } catch {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
      }
    }
    if (output) {
      try { await output.close(); } catch {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
      }
    }
  }
}

function validateContractShape(contract, platform, architecture) {
  const workspaces = new Map([
    ['bot', ['package.json', 'src']],
    ['daemon', ['package.json', 'src']],
    ['native-control', [
      'deployment-keys/application-trusted.json',
      'deployment-keys/shawl-trusted.json',
      'package.json',
      'release-keys/trusted.json',
      'src',
    ]],
    ['shared', ['package.json', '*.js']],
  ]);
  if (!exact(contract, [
    'schemaVersion',
    'kind',
    'limits',
    'repository',
    'releaseVersion',
    'releaseTag',
    'producer',
    'targets',
    'sourceWorkspaces',
    'sourceRootFiles',
    'excludedSegments',
    'entrypoints',
    'runtimes',
    'nativeControl',
    'wireCapabilities',
    'sdk',
    'formatRegistry',
  ]) || contract.schemaVersion !== 1 ||
      contract.kind !== 'gjc-remote-application-release-contract' ||
      contract.repository !== 'kogangdon/gjc-remote' ||
      contract.releaseTag !== `v${contract.releaseVersion}` ||
      contract.producer?.bunVersion !== '1.4.2' ||
      !Array.isArray(contract.sourceWorkspaces) ||
      contract.sourceWorkspaces.length !== workspaces.size ||
      JSON.stringify(contract.sourceRootFiles) !==
        JSON.stringify(['bun.lock', 'package.json']) ||
      !Array.isArray(contract.targets) ||
      !contract.targets.some((target) => target.platform === platform &&
        target.architecture === architecture) ||
      contract.nativeControl?.addonPath !==
        'native-control/build/Release/native_control.node' ||
      contract.nativeControl?.manifestPath !==
        'native-control/build/Release/native-control.manifest.json' ||
      contract.nativeControl?.signaturePath !==
        'native-control/build/Release/native-control.manifest.json.sig' ||
      contract.nativeControl?.applicationTrustPath !==
        'native-control/deployment-keys/application-trusted.json' ||
      contract.nativeControl?.shawlTrustPath !==
        'native-control/deployment-keys/shawl-trusted.json' ||
      contract.nativeControl?.trustPath !==
        'native-control/release-keys/trusted.json') {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID');
  }
  const seen = new Set();
  for (const workspace of contract.sourceWorkspaces) {
    const roots = workspaces.get(workspace?.path);
    if (!roots || seen.has(workspace.path) ||
        JSON.stringify(workspace.productionRoots) !== JSON.stringify(roots)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID');
    }
    seen.add(workspace.path);
  }
  const excluded = new Set(contract.excludedSegments?.map((value) =>
    typeof value === 'string' ? value.toLowerCase() : null));
  for (const segment of [
    '.cache', '.env', '.git', '.gjc', '.gjc-remote-session',
    'credentials', 'logs', 'sessions',
  ]) {
    if (!excluded.has(segment)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID');
    }
  }
  return contract;
}

function excludedRelativeSource(path) {
  return /(?:^|\/)tests?(?:\/|$)/i.test(path) ||
    /\.(?:test|spec)\.[^./]+$/i.test(path);
}

function forbiddenSegment(name) {
  const folded = name.toLowerCase();
  return FORBIDDEN_SOURCE_SEGMENTS.has(folded) ||
    folded.startsWith('.env.');
}

async function assertDirectory(path, repositoryRoot) {
  try {
    const named = await lstat(path);
    if (!named.isDirectory() || named.isSymbolicLink()) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    const canonical = await realpath(path);
    if ((canonical !== repositoryRoot && !within(repositoryRoot, canonical)) ||
        canonical !== resolve(path)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
  } catch (error) {
    if (error instanceof RealBunFixtureError) throw error;
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
  }
}

async function collectSourceInputs(repositoryRoot, contract) {
  const records = new Map();
  const add = (
    logicalPath,
    maximumBytes = SOURCE_FILE_BYTES,
    allowAbsent = false,
  ) => {
    if (typeof logicalPath !== 'string' || logicalPath.length === 0 ||
        logicalPath.includes('\\') || logicalPath.startsWith('/') ||
        logicalPath.split('/').some((segment) => segment.length === 0 ||
          segment === '.' || segment === '..' || forbiddenSegment(segment)) ||
        records.has(logicalPath)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    const absolutePath = resolve(repositoryRoot, ...logicalPath.split('/'));
    if (!within(repositoryRoot, absolutePath)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    records.set(logicalPath, Object.freeze({
      logicalPath,
      absolutePath,
      maximumBytes,
      allowAbsent,
    }));
  };

  const walkSource = async (workspacePath, localDirectory) => {
    const absoluteDirectory = resolve(
      repositoryRoot,
      workspacePath,
      ...localDirectory.split('/'),
    );
    await assertDirectory(absoluteDirectory, repositoryRoot);
    let entries;
    try {
      entries = await readdir(absoluteDirectory, { withFileTypes: true });
    } catch {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    entries.sort((left, right) => utf8Compare(left.name, right.name));
    for (const entry of entries) {
      const localPath = `${localDirectory}/${entry.name}`;
      const logicalPath = `${workspacePath}/${localPath}`;
      if (entry.isSymbolicLink() ||
          (!entry.isDirectory() && !entry.isFile())) {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
      }
      if (forbiddenSegment(entry.name) || excludedRelativeSource(localPath)) continue;
      if (entry.isDirectory()) {
        await walkSource(workspacePath, localPath);
      } else if (entry.isFile()) {
        add(logicalPath);
      }
    }
  };

  add('package.json', PACKAGE_BYTES);
  add('bun.lock', LOCK_BYTES);
  for (const workspace of contract.sourceWorkspaces) {
    for (const root of workspace.productionRoots) {
      if (root === 'src') {
        await walkSource(workspace.path, root);
      } else if (root === '*.js') {
        const directory = resolve(repositoryRoot, workspace.path);
        await assertDirectory(directory, repositoryRoot);
        let entries;
        try {
          entries = await readdir(directory, { withFileTypes: true });
        } catch {
          fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
        }
        entries.sort((left, right) => utf8Compare(left.name, right.name));
        for (const entry of entries) {
          if (!entry.name.endsWith('.js')) continue;
          if (!entry.isFile() || entry.isSymbolicLink() ||
              forbiddenSegment(entry.name)) {
            fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
          }
          add(`${workspace.path}/${entry.name}`);
        }
      } else {
        add(
          `${workspace.path}/${root}`,
          root === 'package.json'
            ? PACKAGE_BYTES
            : root === 'release-keys/trusted.json' ||
                root === 'deployment-keys/application-trusted.json' ||
                root === 'deployment-keys/shawl-trusted.json'
              ? TRUST_BYTES
              : SOURCE_FILE_BYTES,
          root === 'deployment-keys/application-trusted.json' ||
            root === 'deployment-keys/shawl-trusted.json',
        );
      }
    }
  }
  add('deploy/native/release-contract.json', PACKAGE_BYTES);
  return [...records.values()].sort((left, right) =>
    utf8Compare(left.logicalPath, right.logicalPath));
}

function sameSelectedSourceMembership(left, right) {
  return left.length === right.length && left.every((record, index) => {
    const candidate = right[index];
    return candidate !== undefined &&
      record.logicalPath === candidate.logicalPath &&
      record.absolutePath === candidate.absolutePath &&
      record.maximumBytes === candidate.maximumBytes &&
      record.allowAbsent === candidate.allowAbsent;
  });
}

async function captureSourceState(records) {
  const values = [];
  let totalBytes = 0;
  for (const record of records) {
    if (record.allowAbsent) {
      try {
        await lstat(record.absolutePath);
      } catch (error) {
        if (ownData(error, 'code') === 'ENOENT') {
          let canonicalParent;
          try {
            canonicalParent = await realpath(dirname(record.absolutePath));
          } catch {
            fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
          }
          if (canonicalParent !== dirname(record.absolutePath)) {
            fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
          }
          values.push(Object.freeze({
            logicalPath: record.logicalPath,
            present: false,
          }));
          continue;
        }
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
      }
    }
    let canonicalPath;
    try {
      canonicalPath = await realpath(record.absolutePath);
    } catch {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    if (canonicalPath !== record.absolutePath) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    const facts = await stableRegularFacts(
      record.absolutePath,
      record.maximumBytes,
      'SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID',
    );
    totalBytes += facts.size;
    if (!Number.isSafeInteger(totalBytes)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
    values.push(Object.freeze({
      logicalPath: record.logicalPath,
      present: true,
      ...facts,
    }));
  }
  return Object.freeze({
    values: Object.freeze(values),
    fileCount: values.length,
    totalBytes,
    contentFingerprint: canonicalJsonHash(values.map((value) => ({
      path: value.logicalPath,
      present: value.present,
      ...(value.present ? {
        size: value.size,
        sha256: value.sha256,
        mode: value.mode,
      } : {}),
    }))),
    stableFingerprint: canonicalJsonHash(values),
  });
}

function sameSourceState(left, right) {
  return left.fileCount === right.fileCount &&
    left.totalBytes === right.totalBytes &&
    left.contentFingerprint === right.contentFingerprint &&
    left.stableFingerprint === right.stableFingerprint;
}

function assertOnlyFixtureTrustChanged(
  originalState,
  syntheticState,
  nativeTrustPath,
  fixtureNativeTrustBytes,
  applicationTrustPath,
  fixtureApplicationTrustBytes,
  shawlTrustPath,
  fixtureShawlTrustBytes,
) {
  const original = new Map(originalState.values
    .filter((value) => !value.logicalPath.startsWith('@host-native/'))
    .map((value) => [value.logicalPath, value]));
  const synthetic = new Map(syntheticState.values.map((value) =>
    [value.logicalPath, value]));
  const expectedTrust = new Map([
    [nativeTrustPath, fixtureNativeTrustBytes],
    [applicationTrustPath, fixtureApplicationTrustBytes],
    [shawlTrustPath, fixtureShawlTrustBytes],
  ]);
  if (synthetic.size !== original.size ||
      [...expectedTrust].some(([path, bytes]) => {
        const copied = synthetic.get(path);
        const originalValue = original.get(path);
        const digest = createHash('sha256').update(bytes).digest('hex');
        return !originalValue || !copied || copied.present !== true ||
          copied.size !== bytes.length || copied.sha256 !== digest ||
          copied.mode !== 0o644 ||
          (originalValue.present === true &&
            originalValue.sha256 === digest);
      })) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
  }
  for (const [path, copied] of synthetic) {
    if (expectedTrust.has(path)) continue;
    const source = original.get(path);
    if (!source || source.present !== true || copied.present !== true ||
        copied.size !== source.size ||
        copied.sha256 !== source.sha256 || copied.mode !== source.mode) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED');
    }
  }
}

async function copySourceSnapshot(records, state, destinationRoot) {
  const byPath = new Map(state.values.map((value) => [value.logicalPath, value]));
  for (const record of records) {
    const destination = resolve(
      destinationRoot,
      ...record.logicalPath.split('/'),
    );
    if (!within(destinationRoot, destination)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
    }
    const expected = byPath.get(record.logicalPath);
    if (!expected) fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED');
    if (expected.present === false) continue;
    await copyStableRegular(
      record.absolutePath,
      destination,
      expected,
      record.maximumBytes,
    );
  }
}

function isolatedProcessEnvironment(home) {
  const allowed = [
    'COMSPEC',
    'PATH',
    'PATHEXT',
    'SYSTEMDRIVE',
    'SYSTEMROOT',
    'TEMP',
    'TMP',
    'WINDIR',
  ];
  const environment = {};
  for (const name of allowed) {
    if (typeof process.env[name] === 'string') environment[name] = process.env[name];
  }
  return {
    ...environment,
    CI: '1',
    HOME: home,
    USERPROFILE: home,
    XDG_CACHE_HOME: join(home, 'cache'),
    XDG_CONFIG_HOME: join(home, 'config'),
    XDG_DATA_HOME: join(home, 'data'),
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: join(home, 'gitconfig'),
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    LANG: 'C',
    LC_ALL: 'C',
  };
}

async function runSyntheticGit(sourceRoot, gitHome, hooksDirectory, args, extraEnvironment = {}) {
  const configuration = [
    '-c', `core.hooksPath=${hooksDirectory}`,
    '-c', 'core.fsmonitor=false',
    '-c', 'core.autocrlf=false',
    '-c', 'commit.gpgSign=false',
    '-c', 'tag.gpgSign=false',
    '-c', 'credential.helper=',
  ];
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let timer;
    let stdoutLength = 0;
    let stderrLength = 0;
    const stdout = [];
    const child = spawn('git', [...configuration, ...args], {
      cwd: sourceRoot,
      env: { ...isolatedProcessEnvironment(gitHome), ...extraEnvironment },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) rejectPromise(error);
      else resolvePromise(value);
    };
    child.stdout.on('data', (value) => {
      const bytes = Buffer.from(value);
      stdoutLength += bytes.length;
      if (stdoutLength > PROCESS_OUTPUT_BYTES) {
        child.kill('SIGKILL');
        finish(new RealBunFixtureError('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED'));
        return;
      }
      stdout.push(bytes);
    });
    child.stderr.on('data', (value) => {
      stderrLength += Buffer.byteLength(value);
      if (stderrLength > PROCESS_OUTPUT_BYTES) {
        child.kill('SIGKILL');
        finish(new RealBunFixtureError('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED'));
      }
    });
    child.once('error', () => {
      finish(new RealBunFixtureError('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED'));
    });
    child.once('close', (code, signal) => {
      if (code !== 0 || signal !== null) {
        finish(new RealBunFixtureError('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED'));
      } else {
        finish(null, Buffer.concat(stdout, stdoutLength));
      }
    });
    timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new RealBunFixtureError('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED'));
    }, PROCESS_TIMEOUT_MS);
    timer.unref?.();
  });
}

function oneLine(bytes, pattern) {
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
  } catch {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED');
  }
  if (!pattern.test(value) || value.includes('\n') || value.includes('\r')) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED');
  }
  return value;
}

async function initializeSyntheticRepository(sourceRoot, contract, ownedRoot) {
  const gitHome = join(ownedRoot, 'synthetic-git-home');
  const hooksDirectory = join(gitHome, 'hooks-disabled');
  await mkdir(hooksDirectory, { recursive: true, mode: 0o700 });
  await writeExclusive(
    join(gitHome, 'gitconfig'),
    Buffer.alloc(0),
    0o600,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED',
  );
  for (const name of ['attributes', 'excludes']) {
    await writeExclusive(
      join(gitHome, name),
      Buffer.alloc(0),
      0o600,
      'SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED',
    );
  }
  await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
    'init',
    '--quiet',
    '--object-format=sha1',
    '--initial-branch=synthetic-fixture',
  ]);
  for (const [key, value] of [
    ['core.autocrlf', 'false'],
    ['core.fsmonitor', 'false'],
    ['core.filemode', process.platform === 'win32' ? 'false' : 'true'],
    ['core.hooksPath', hooksDirectory],
    ['core.attributesFile', join(gitHome, 'attributes')],
    ['core.excludesFile', join(gitHome, 'excludes')],
    ['commit.gpgSign', 'false'],
    ['tag.gpgSign', 'false'],
    ['credential.helper', ''],
    ['user.name', 'GJC synthetic fixture'],
    ['user.email', 'synthetic-fixture@invalid.example'],
  ]) {
    await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
      'config', '--local', key, value,
    ]);
  }
  await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
    'remote', 'add', 'origin', FIXED_REMOTE,
  ]);
  await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
    'add', '--force', '--all', '--', '.',
  ]);
  const commitEnvironment = {
    GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
    GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z',
  };
  await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
    'commit',
    '--quiet',
    '--no-gpg-sign',
    '--message',
    'Synthetic current-source snapshot for fixture evidence; not upstream provenance',
  ], commitEnvironment);
  await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
    'tag', '--no-sign', contract.releaseTag,
  ]);
  const status = await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
    'status', '--porcelain=v1', '-z', '--untracked-files=all',
  ]);
  if (status.length !== 0) fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED');
  const commit = oneLine(
    await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
      'rev-parse', '--verify', 'HEAD^{commit}',
    ]),
    /^[0-9a-f]{40}$/,
  );
  const tree = oneLine(
    await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
      'rev-parse', '--verify', 'HEAD^{tree}',
    ]),
    /^[0-9a-f]{40}$/,
  );
  const tagCommit = oneLine(
    await runSyntheticGit(sourceRoot, gitHome, hooksDirectory, [
      'rev-parse', '--verify', `${contract.releaseTag}^{commit}`,
    ]),
    /^[0-9a-f]{40}$/,
  );
  if (tagCommit !== commit) fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_GIT_FAILED');
  return Object.freeze({ commit, tree });
}

function assertExactKeys(value, keys, code) {
  if (!exact(value, keys)) fail(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (keys.some((key) => descriptors[key]?.get !== undefined ||
      descriptors[key]?.set !== undefined ||
      !Object.hasOwn(descriptors[key] ?? {}, 'value'))) fail(code);
}

function validateProducerEvidence(producer, contract) {
  assertExactKeys(
    producer,
    PRODUCER_EVIDENCE_KEYS,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED',
  );
  if (producer.kind !== 'real-external-bun-process' ||
      producer.version !== '1.4.2' ||
      producer.environmentPolicy !== 'isolated-no-auth-proxy-hooks' ||
      producer.integrityAuthority !==
        'fresh-bun-frozen-lockfile-registry-sri' ||
      !sameJson(producer.installArguments, contract.producer.installArguments) ||
      !producer.installArguments.includes('--frozen-lockfile') ||
      !producer.installArguments.includes('--ignore-scripts') ||
      !producer.installArguments.includes(
        '--registry=https://registry.npmjs.org',
      ) ||
      !producer.installArguments.includes('--cache-dir=<fresh-cache>') ||
      ![
        'versionStdoutSha256',
        'versionStderrSha256',
        'installStdoutSha256',
        'installStderrSha256',
      ].every((key) => hex64(producer[key]))) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
  }
}

async function outputFileFacts(path, maximumBytes) {
  return stableRegularFacts(
    path,
    maximumBytes,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID',
  );
}

async function verifyBuild({
  build,
  verification,
  outputDirectory,
  contract,
  target,
  syntheticGit,
  nativeFacts,
  lockSha256,
}) {
  assertExactKeys(
    build,
    BUILD_RECEIPT_KEYS,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED',
  );
  assertExactKeys(
    verification,
    VERIFICATION_RECEIPT_KEYS,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED',
  );
  assertExactKeys(
    build.source,
    ['repository', 'tag', 'commit', 'tree', 'bunLockSha256'],
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED',
  );
  assertExactKeys(
    build.target,
    ['platform', 'architecture'],
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED',
  );
  const manifestName =
    `gjc-remote-service-${target.platform}-${target.architecture}.manifest.json`;
  const archiveName =
    `gjc-remote-service-${contract.releaseVersion}-${target.platform}-${target.architecture}.tar.gz`;
  let entries;
  try {
    entries = await readdir(outputDirectory, { withFileTypes: true });
  } catch {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
  }
  entries.sort((left, right) => utf8Compare(left.name, right.name));
  if (entries.length !== 2 || entries.some((entry) =>
    !entry.isFile() || entry.isSymbolicLink()) ||
      entries[0].name !== archiveName || entries[1].name !== manifestName) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
  }
  const manifestPath = join(outputDirectory, manifestName);
  const archivePath = join(outputDirectory, archiveName);
  const manifestBytes = await readBoundedRegular(
    manifestPath,
    contract.limits.manifestBytes,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID',
  );
  let manifest;
  try {
    manifest = parseCanonicalJsonBytes(manifestBytes, {
      maxBytes: contract.limits.manifestBytes,
      maxDepth: 32,
      maxNodes: 10_000,
    });
    validateApplicationDeploymentManifest(manifest);
    validateSdkExternalStateContract(build.sdkExternalStateContract);
  } catch {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
  }
  const manifestFacts = await outputFileFacts(
    manifestPath,
    contract.limits.manifestBytes,
  );
  const archiveFacts = await outputFileFacts(
    archivePath,
    contract.limits.archiveBytes,
  );
  validateProducerEvidence(build.producerEvidence, contract);
  if (build.schemaVersion !== 1 ||
      build.kind !== 'unsigned-service-release-build-receipt' ||
      build.unsigned !== true || build.signatureGenerated !== false ||
      verification.schemaVersion !== 1 ||
      verification.kind !== 'unsigned-service-release-verification-receipt' ||
      verification.unsigned !== true ||
      verification.signatureGenerated !== false ||
      build.manifestFingerprint !== manifest.manifestFingerprint ||
      verification.manifestFingerprint !== manifest.manifestFingerprint ||
      build.archiveSha256 !== archiveFacts.sha256 ||
      verification.archiveSha256 !== archiveFacts.sha256 ||
      manifest.archive.sha256 !== archiveFacts.sha256 ||
      manifest.archive.byteLength !== archiveFacts.size ||
      build.treeFingerprint !== manifest.inventory.treeFingerprint ||
      verification.treeFingerprint !== manifest.inventory.treeFingerprint ||
      build.payloadEntryCount !== manifest.inventory.payloadEntryCount ||
      build.unpackedPayloadBytes !== manifest.inventory.unpackedPayloadBytes ||
      verification.entryCount !== manifest.archive.entryCount ||
      manifest.archive.entryCount !== manifest.inventory.payloadEntryCount + 1 ||
      build.nativeManifestFingerprint !== nativeFacts.manifest.sha256 ||
      build.nativeAddonSha256 !== nativeFacts.addon.sha256 ||
      manifest.nativeControl.manifestFingerprint !== nativeFacts.manifest.sha256 ||
      build.sdkExternalStateContract.sdkExternalStateContractFingerprint !==
        manifest.compatibility.roles.daemon.sdkExternalStateContractFingerprint ||
      verification.sdkExternalStateContractFingerprint !==
        build.sdkExternalStateContract.sdkExternalStateContractFingerprint ||
      !hex64(build.sdkClosureFingerprint) ||
      !Number.isSafeInteger(build.sdkClosurePackageCount) ||
      build.sdkClosurePackageCount < 1 ||
      !sameJson(build.target, target) ||
      verification.platform !== target.platform ||
      verification.architecture !== target.architecture ||
      !sameJson(build.limits, contract.limits) ||
      build.source.repository !== contract.repository ||
      build.source.tag !== contract.releaseTag ||
      build.source.commit !== syntheticGit.commit ||
      build.source.tree !== syntheticGit.tree ||
      build.source.bunLockSha256 !== lockSha256 ||
      manifest.releaseVersion !== contract.releaseVersion ||
      manifest.releaseId !== contract.releaseTag ||
      manifest.releaseSequence !== 1 ||
      !sameJson(manifest.target, target) ||
      manifest.source.commit !== syntheticGit.commit ||
      manifest.source.tree !== syntheticGit.tree ||
      manifest.source.bunLockSha256 !== lockSha256 ||
      manifest.signingKeyId !== FIXTURE_SIGNING_KEY_ID) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
  }
  return Object.freeze({
    manifest,
    manifestFacts,
    archiveFacts,
    summary: Object.freeze({
      manifestFingerprint: build.manifestFingerprint,
      manifestFileSha256: manifestFacts.sha256,
      archiveSha256: archiveFacts.sha256,
      archiveByteLength: archiveFacts.size,
      treeFingerprint: build.treeFingerprint,
      nativeManifestFingerprint: build.nativeManifestFingerprint,
      nativeAddonSha256: build.nativeAddonSha256,
      sdkExternalStateContractFingerprint:
        build.sdkExternalStateContract.sdkExternalStateContractFingerprint,
      sdkClosureFingerprint: build.sdkClosureFingerprint,
      sdkClosurePackageCount: build.sdkClosurePackageCount,
      payloadEntryCount: build.payloadEntryCount,
      unpackedPayloadBytes: build.unpackedPayloadBytes,
      verificationEntryCount: verification.entryCount,
      producerOutputDigests: Object.freeze({
        versionStdoutSha256: build.producerEvidence.versionStdoutSha256,
        versionStderrSha256: build.producerEvidence.versionStderrSha256,
        installStdoutSha256: build.producerEvidence.installStdoutSha256,
        installStderrSha256: build.producerEvidence.installStderrSha256,
      }),
    }),
  });
}

function assertBuildsMatch(first, second) {
  const fields = [
    'manifestFingerprint',
    'archiveSha256',
    'treeFingerprint',
    'nativeManifestFingerprint',
    'nativeAddonSha256',
    'sdkExternalStateContractFingerprint',
    'sdkClosureFingerprint',
    'sdkClosurePackageCount',
    'payloadEntryCount',
    'unpackedPayloadBytes',
    'verificationEntryCount',
  ];
  if (first.manifestFacts.size !== second.manifestFacts.size ||
      first.manifestFacts.sha256 !== second.manifestFacts.sha256 ||
      first.archiveFacts.size !== second.archiveFacts.size ||
      first.archiveFacts.sha256 !== second.archiveFacts.sha256 ||
      fields.some((field) => first.summary[field] !== second.summary[field])) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
  }
}

async function ownedDirectoryIdentity(path) {
  try {
    const named = await lstat(path, { bigint: true });
    if (!named.isDirectory() || named.isSymbolicLink()) return null;
    const canonical = await realpath(path);
    if (canonical !== resolve(path)) return null;
    return Object.freeze({
      path: canonical,
      device: String(named.dev),
      inode: String(named.ino),
    });
  } catch {
    return null;
  }
}

async function removeExactOwnedRoot(identity) {
  if (!identity) return false;
  const current = await ownedDirectoryIdentity(identity.path);
  if (!current || current.path !== identity.path ||
      current.device !== identity.device || current.inode !== identity.inode) {
    return false;
  }
  try {
    await rm(identity.path, { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
}

async function createOwnedRoot() {
  let created;
  let identity = null;
  try {
    // mkdtemp echoes the TEMP spelling it was given; the identity must be
    // captured on the canonical spelling or a differently-spelled TEMP
    // (GitHub's Windows runner) makes every later exact-path check fail.
    created = await realpath(
      await mkdtemp(join(tmpdir(), 'gjc-real-bun-release-fixture-')),
    );
    identity = await ownedDirectoryIdentity(created);
    if (identity === null) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
    }
    await chmod(identity.path, 0o700);
    const revalidated = await ownedDirectoryIdentity(identity.path);
    if (revalidated === null ||
        revalidated.device !== identity.device ||
        revalidated.inode !== identity.inode) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
    }
    return revalidated;
  } catch (error) {
    if (created) {
      if (identity === null ||
          !(await removeExactOwnedRoot(identity))) {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CLEANUP_FAILED');
      }
    }
    if (error instanceof RealBunFixtureError) throw error;
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID');
  }
}

function successReport({
  target,
  contract,
  originalState,
  syntheticState,
  syntheticGit,
  originalApplicationTrust,
  originalShawlTrust,
  productionNativeRejectedCode,
  productionDeploymentAuthority,
  builds,
}) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'service-release-real-bun-fixture-evidence',
    result: 'passed',
    evidenceScope: Object.freeze({
      producer: 'real-bun-1.4.2-frozen-production-install',
      dependencyAuthority:
        'fresh-per-build-cache-and-home-with-registry-sri',
      registry: 'https://registry.npmjs.org',
      installScripts: 'disabled',
      nativeAuthority: 'ephemeral-isolated-fixture-key-only',
      nativeInput: 'existing-host-addon-and-exact-existing-manifest-bytes',
      nativeByteVerification:
        'stable-streamed-sha256-matched-signed-manifest-no-addon-buffer',
      nativeMetadataVerification:
        'production-metadata-shape-plus-fixture-pinned-signature',
      syntheticTrustResources: Object.freeze({
        native: 'temporary-fixture-public-pins',
        application: 'temporary-fixture-public-pins',
        shawl: 'temporary-fixture-public-pins',
        productionFilesMutated: false,
      }),
      gitAuthority: 'synthetic-current-source-snapshot-only',
      productionNativeAuthorityRejected: true,
      productionNativeAuthorityRejectionCode:
        productionNativeRejectedCode,
      deploymentAuthority: 'ephemeral-isolated-fixture-key-only',
      originalProductionDeploymentPins: Object.freeze({
        application: originalApplicationTrust.present ? 'present' : 'absent',
        shawl: originalShawlTrust.present ? 'present' : 'absent',
      }),
      productionDeploymentFixtureAuthorityRejection:
        productionDeploymentAuthority,
    }),
    target,
    contract: Object.freeze({
      releaseVersion: contract.releaseVersion,
      releaseTag: contract.releaseTag,
      bunVersion: contract.producer.bunVersion,
      contractFingerprint: canonicalJsonHash(contract),
    }),
    bounds: Object.freeze({
      reportBytes: REPORT_BYTES,
      syntheticGitProcessOutputBytes: PROCESS_OUTPUT_BYTES,
      syntheticGitProcessTimeoutMs: PROCESS_TIMEOUT_MS,
      releaseContract: Object.freeze({ ...contract.limits }),
    }),
    originalSource: Object.freeze({
      fileCount: originalState.fileCount,
      totalBytes: originalState.totalBytes,
      contentFingerprint: originalState.contentFingerprint,
      stableFingerprint: originalState.stableFingerprint,
      applicationTrustInput: Object.freeze({
        path: contract.nativeControl.applicationTrustPath,
        originalDisposition:
          originalApplicationTrust.present ? 'present' : 'absent',
        synthesizedOnlyInsideOwnedFixture:
          originalApplicationTrust.present === false,
      }),
      shawlTrustInput: Object.freeze({
        path: contract.nativeControl.shawlTrustPath,
        originalDisposition:
          originalShawlTrust.present ? 'present' : 'absent',
        synthesizedOnlyInsideOwnedFixture:
          originalShawlTrust.present === false,
      }),
      unchangedAfterFixtureOperations: true,
    }),
    syntheticGit: Object.freeze({
      classification: 'synthetic-snapshot-not-upstream-provenance',
      commit: syntheticGit.commit,
      tree: syntheticGit.tree,
      tag: contract.releaseTag,
      originLabel: FIXED_REMOTE,
      sourceContentFingerprint: syntheticState.contentFingerprint,
      cleanBeforeAndAfterEachBuilderCall: true,
    }),
    buildCount: 2,
    deterministicOutputs: Object.freeze({
      manifestSizeAndSha256Match: true,
      archiveSizeAndSha256Match: true,
      eachVerifiedByActualUnsignedReleaseVerifier: true,
    }),
    builds: Object.freeze(builds.map((build, index) => Object.freeze({
      ordinal: index + 1,
      ...build.summary,
    }))),
    limitations: Object.freeze({
      productionRelease: 'not-created-or-signed',
      productionGitProvenance: 'not-established',
      fixtureNativeAuthority: 'not-accepted-by-production-verifier',
      fixtureDeploymentAuthority:
        productionDeploymentAuthority.fixtureAuthorityRejectionTested
          ? 'rejected-by-present-production-pins'
          : 'not-tested-against-production-pins-because-pins-were-absent',
      nativeAddonExecution: 'not-performed',
      nativeAddonLoadOrExportProof: 'not-provided',
      hostServiceMutation: 'not-performed',
      releasePublicationOrNetworkUpload: 'not-performed',
      registryTransport:
        'successful-real-Bun-process-evidence-not-independent-TLS-attestation',
    }),
  });
}

export async function runServiceReleaseRealBunEvidence(argv) {
  let acknowledged = false;
  try {
    const descriptor = Array.isArray(argv)
      ? Object.getOwnPropertyDescriptor(argv, '0')
      : null;
    acknowledged = argv.length === 1 && descriptor?.get === undefined &&
      descriptor?.set === undefined &&
      Object.hasOwn(descriptor ?? {}, 'value') &&
      descriptor.value === ACKNOWLEDGEMENT_FLAG;
  } catch {
    acknowledged = false;
  }
  if (!acknowledged) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_ACKNOWLEDGEMENT_REQUIRED');
  }

  const target = Object.freeze({
    platform: process.platform,
    architecture: process.arch,
  });
  if (!HOST_TARGETS.has(`${target.platform}:${target.architecture}`)) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_TARGET_UNSUPPORTED');
  }

  let repositoryRoot;
  let contractPath;
  let nativeAddonPath;
  let nativeManifestPath;
  let nativePackagePath;
  try {
    repositoryRoot = await realpath(fileURLToPath(new URL('../..', import.meta.url)));
    contractPath = await realpath(join(repositoryRoot, 'deploy', 'native', 'release-contract.json'));
    nativeAddonPath = await realpath(join(
      repositoryRoot,
      'native-control',
      'build',
      'Release',
      'native_control.node',
    ));
    nativeManifestPath = await realpath(join(
      repositoryRoot,
      'native-control',
      'build',
      'Release',
      'native-control.manifest.json',
    ));
    nativePackagePath = await realpath(join(repositoryRoot, 'native-control', 'package.json'));
  } catch {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
  }
  for (const path of [
    contractPath,
    nativeAddonPath,
    nativeManifestPath,
    nativePackagePath,
  ]) {
    if (path !== resolve(path) || !within(repositoryRoot, path)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
    }
  }

  const contractBytes = await readBoundedRegular(
    contractPath,
    PACKAGE_BYTES,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID',
  );
  let contract;
  try {
    contract = validateContractShape(
      parseStrictJsonBytes(contractBytes, {
        maxBytes: PACKAGE_BYTES,
        maxDepth: 64,
        maxNodes: 100_000,
      }),
      target.platform,
      target.architecture,
    );
  } catch (error) {
    if (error instanceof RealBunFixtureError) throw error;
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID');
  }

  const sourceRecords = await collectSourceInputs(repositoryRoot, contract);
  const nativeAddonRecord = Object.freeze({
    logicalPath: '@host-native/addon',
    absolutePath: nativeAddonPath,
    maximumBytes: NATIVE_ADDON_BYTES,
  });
  const nativeManifestRecord = Object.freeze({
    logicalPath: '@host-native/manifest',
    absolutePath: nativeManifestPath,
    maximumBytes: PACKAGE_BYTES,
  });
  const originalRecords = Object.freeze([
    ...sourceRecords,
    nativeAddonRecord,
    nativeManifestRecord,
  ]);
  const originalState = await captureSourceState(originalRecords);
  const nativeManifestBytes = await readBoundedRegular(
    nativeManifestPath,
    PACKAGE_BYTES,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID',
  );
  const nativePackageBytes = await readBoundedRegular(
    nativePackagePath,
    PACKAGE_BYTES,
    'SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID',
  );
  let nativeManifest;
  let nativePackage;
  try {
    nativeManifest = parseStrictJsonBytes(nativeManifestBytes, {
      maxBytes: PACKAGE_BYTES,
      maxDepth: 64,
      maxNodes: 100_000,
    });
    nativePackage = parseStrictJsonBytes(nativePackageBytes, {
      maxBytes: PACKAGE_BYTES,
      maxDepth: 32,
      maxNodes: 100_000,
    });
  } catch {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
  }
  const nativeFacts = Object.freeze({
    addon: originalState.values.find((value) =>
      value.logicalPath === nativeAddonRecord.logicalPath),
    manifest: originalState.values.find((value) =>
      value.logicalPath === nativeManifestRecord.logicalPath),
  });
  if (!nativeFacts.addon || nativeFacts.addon.present !== true ||
      !nativeFacts.manifest || nativeFacts.manifest.present !== true ||
      nativeManifest.platform !== target.platform ||
      nativeManifest.arch !== target.architecture ||
      nativeManifest.contractVersion !== contract.nativeControl.contractVersion ||
      nativeManifest.contractRevision !== contract.nativeControl.contractRevision ||
      nativeManifest.napi !== contract.nativeControl.napi ||
      nativeManifest.sha256 !== nativeFacts.addon.sha256 ||
      nativeFacts.manifest.sha256 !== createHash('sha256')
        .update(nativeManifestBytes).digest('hex') ||
      !validateBuildManifestMetadata(
        nativeManifest,
        nativePackage,
        target.platform,
        target.architecture,
      )) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
  }

  const lockState = originalState.values.find((value) =>
    value.logicalPath === 'bun.lock');
  const originalApplicationTrust = originalState.values.find((value) =>
    value.logicalPath === contract.nativeControl.applicationTrustPath);
  const originalShawlTrust = originalState.values.find((value) =>
    value.logicalPath === contract.nativeControl.shawlTrustPath);
  const originalNativeTrust = originalState.values.find((value) =>
    value.logicalPath === contract.nativeControl.trustPath);
  if (!lockState || lockState.present !== true ||
      !originalApplicationTrust || !originalShawlTrust ||
      !originalNativeTrust || originalNativeTrust.present !== true) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID');
  }

  let ownedRoot = null;
  let fixture = null;
  let result = null;
  let primaryFailure = null;
  try {
    ownedRoot = await createOwnedRoot();
    const ownedRootPath = ownedRoot.path;
    fixture = await createPinnedDeploymentInstallation({
      keyIds: [FIXTURE_SIGNING_KEY_ID],
      includeReleaseBuilder: true,
    });
    if (!fixture.releaseBuilder || !fixture.nativeProvenance ||
        typeof fixture.releaseBuilderUrl !== 'string' ||
        typeof fixture.signNativeManifest !== 'function' ||
        !Buffer.isBuffer(fixture.bundledNativeTrustBytes) ||
        !Buffer.isBuffer(fixture.bundledApplicationTrustBytes) ||
        !Buffer.isBuffer(fixture.bundledShawlTrustBytes)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
    }
    const fixtureNativeTrustBytes = fixture.bundledNativeTrustBytes;
    const fixtureApplicationTrustBytes = fixture.bundledApplicationTrustBytes;
    const fixtureShawlTrustBytes = fixture.bundledShawlTrustBytes;
    if (fixtureNativeTrustBytes.length < 1 ||
        fixtureNativeTrustBytes.length > TRUST_BYTES ||
        fixtureApplicationTrustBytes.length < 1 ||
        fixtureApplicationTrustBytes.length > TRUST_BYTES ||
        fixtureShawlTrustBytes.length < 1 ||
        fixtureShawlTrustBytes.length > TRUST_BYTES ||
        fixtureNativeTrustBytes.equals(fixtureApplicationTrustBytes) ||
        fixtureNativeTrustBytes.equals(fixtureShawlTrustBytes) ||
        fixtureApplicationTrustBytes.equals(fixtureShawlTrustBytes)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
    }
    try {
      if (new URL(fixture.releaseBuilderUrl).protocol !== 'file:') {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID');
      }
    } catch (error) {
      if (error instanceof RealBunFixtureError) throw error;
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID');
    }
    const fixtureContract = await fixture.releaseBuilder.loadServiceReleaseContract();
    if (!sameJson(fixtureContract, contract)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_CONTRACT_INVALID');
    }
    fixture.releaseBuilder.parseBunProductionLock(
      await readBoundedRegular(
        join(repositoryRoot, 'bun.lock'),
        LOCK_BYTES,
        'SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_INVALID',
      ),
    );

    const nativeSignatureBytes = fixture.signNativeManifest(nativeManifestBytes);
    if (!Buffer.isBuffer(nativeSignatureBytes) ||
        nativeSignatureBytes.length < 1 ||
        nativeSignatureBytes.length > NATIVE_SIGNATURE_BYTES) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
    }
    const fixtureNativeReceipt =
      fixture.nativeProvenance.verifyPinnedNativeBuildManifest({
        manifestBytes: nativeManifestBytes,
        signatureBytes: nativeSignatureBytes,
        packageBytes: nativePackageBytes,
        bundledTrustBytes: fixtureNativeTrustBytes,
        platform: target.platform,
        architecture: target.architecture,
      });
    if (fixtureNativeReceipt.manifestFingerprint !==
        nativeFacts.manifest.sha256 ||
        fixtureNativeReceipt.addonSha256 !== nativeFacts.addon.sha256 ||
        fixtureNativeReceipt.platform !== target.platform ||
        fixtureNativeReceipt.architecture !== target.architecture ||
        fixtureNativeReceipt.contractVersion !==
          contract.nativeControl.contractVersion ||
        fixtureNativeReceipt.contractRevision !==
          contract.nativeControl.contractRevision ||
        fixtureNativeReceipt.napi !== contract.nativeControl.napi ||
        fixtureNativeReceipt.addonBytesVerification !== 'required' ||
        fixtureNativeReceipt.addonLoadVerification !== 'required' ||
        fixtureNativeReceipt.addonExportVerification !== 'required') {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
    }
    let productionNativeRejectedCode = null;
    try {
      verifyPinnedNativeBuildManifest({
        manifestBytes: nativeManifestBytes,
        signatureBytes: nativeSignatureBytes,
        packageBytes: nativePackageBytes,
        bundledTrustBytes: fixtureNativeTrustBytes,
        platform: target.platform,
        architecture: target.architecture,
      });
    } catch (error) {
      productionNativeRejectedCode = ownData(error, 'code');
    }
    if (productionNativeRejectedCode !==
        'NATIVE_PROVENANCE_TRUST_INVALID') {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_NATIVE_INVALID');
    }

    const syntheticSource = join(ownedRootPath, 'source');
    await mkdir(syntheticSource, { recursive: false, mode: 0o700 });
    const canonicalSyntheticSource = await realpath(syntheticSource);
    await copySourceSnapshot(
      sourceRecords,
      originalState,
      canonicalSyntheticSource,
    );
    const temporaryNativeTrustPath = join(
      canonicalSyntheticSource,
      ...contract.nativeControl.trustPath.split('/'),
    );
    const temporaryApplicationTrustPath = join(
      canonicalSyntheticSource,
      ...contract.nativeControl.applicationTrustPath.split('/'),
    );
    const temporaryShawlTrustPath = join(
      canonicalSyntheticSource,
      ...contract.nativeControl.shawlTrustPath.split('/'),
    );
    await installTemporaryTrust(
      temporaryNativeTrustPath,
      fixtureNativeTrustBytes,
      ownedRootPath,
      originalNativeTrust,
    );
    await installTemporaryTrust(
      temporaryApplicationTrustPath,
      fixtureApplicationTrustBytes,
      ownedRootPath,
      originalApplicationTrust,
    );
    await installTemporaryTrust(
      temporaryShawlTrustPath,
      fixtureShawlTrustBytes,
      ownedRootPath,
      originalShawlTrust,
    );
    const signaturePath = join(
      ownedRootPath,
      'native-input',
      'native-control.manifest.json.sig',
    );
    await writeExclusive(
      signaturePath,
      nativeSignatureBytes,
      0o600,
      'SERVICE_RELEASE_REAL_BUN_FIXTURE_OUTPUT_INVALID',
    );
    const canonicalSignaturePath = await realpath(signaturePath);

    const syntheticRecords = sourceRecords.map((record) => Object.freeze({
      ...record,
      absolutePath: join(
        canonicalSyntheticSource,
        ...record.logicalPath.split('/'),
      ),
    }));
    const syntheticState = await captureSourceState(syntheticRecords);
    assertOnlyFixtureTrustChanged(
      originalState,
      syntheticState,
      contract.nativeControl.trustPath,
      fixtureNativeTrustBytes,
      contract.nativeControl.applicationTrustPath,
      fixtureApplicationTrustBytes,
      contract.nativeControl.shawlTrustPath,
      fixtureShawlTrustBytes,
    );
    const syntheticGit = await initializeSyntheticRepository(
      canonicalSyntheticSource,
      contract,
      ownedRootPath,
    );

    const outputs = [
      join(ownedRootPath, 'candidate-one'),
      join(ownedRootPath, 'candidate-two'),
    ];
    const builds = [];
    for (const outputDirectory of outputs) {
      const build = await fixture.releaseBuilder.buildUnsignedServiceRelease({
        sourceRoot: canonicalSyntheticSource,
        outputDirectory,
        platform: target.platform,
        architecture: target.architecture,
        releaseSequence: 1,
        signingKeyId: FIXTURE_SIGNING_KEY_ID,
        nativeAddonPath,
        nativeManifestPath,
        nativeSignaturePath: canonicalSignaturePath,
      });
      const verification = await fixture.releaseBuilder.verifyUnsignedServiceRelease({
        candidateDirectory: outputDirectory,
      });
      builds.push(await verifyBuild({
        build,
        verification,
        outputDirectory,
        contract,
        target,
        syntheticGit,
        nativeFacts,
        lockSha256: lockState.sha256,
      }));
    }
    assertBuildsMatch(builds[0], builds[1]);
    const signedDeployment = fixture.signManifest(builds[0].manifest);
    if (!Buffer.isBuffer(signedDeployment.manifestBytes) ||
        !Buffer.isBuffer(signedDeployment.signatureBytes) ||
        signedDeployment.manifestBytes.length !==
          builds[0].manifestFacts.size ||
        createHash('sha256').update(signedDeployment.manifestBytes)
          .digest('hex') !== builds[0].manifestFacts.sha256) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
    }
    const fixtureDeploymentReceipt =
      fixture.provenance.verifyPinnedDeploymentProvenance({
        purpose: 'application',
        manifestBytes: signedDeployment.manifestBytes,
        signatureBytes: signedDeployment.signatureBytes,
        platform: target.platform,
        architecture: target.architecture,
      });
    if (fixtureDeploymentReceipt.manifestFingerprint !==
        builds[0].manifest.manifestFingerprint ||
        fixtureDeploymentReceipt.signingKeyId !==
          FIXTURE_SIGNING_KEY_ID) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
    }
    let productionDeploymentRejectedCode = null;
    try {
      verifyPinnedDeploymentProvenance({
        purpose: 'application',
        manifestBytes: signedDeployment.manifestBytes,
        signatureBytes: signedDeployment.signatureBytes,
        platform: target.platform,
        architecture: target.architecture,
      });
    } catch (error) {
      productionDeploymentRejectedCode = ownData(error, 'code');
    }
    let productionDeploymentAuthority;
    if (originalApplicationTrust.present === false) {
      if (productionDeploymentRejectedCode !==
          'DEPLOYMENT_TRUST_UNAVAILABLE') {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
      }
      productionDeploymentAuthority = Object.freeze({
        originalPins: 'absent',
        fixtureAuthorityRejectionTested: false,
        observedCode: productionDeploymentRejectedCode,
        conclusion:
          'production-verifier-unavailable-no-authority-rejection-claimed',
      });
    } else {
      if (![
        'DEPLOYMENT_SIGNING_KEY_UNKNOWN',
        'DEPLOYMENT_SIGNATURE_INVALID',
      ].includes(productionDeploymentRejectedCode)) {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_VERIFICATION_FAILED');
      }
      productionDeploymentAuthority = Object.freeze({
        originalPins: 'present',
        fixtureAuthorityRejectionTested: true,
        observedCode: productionDeploymentRejectedCode,
        conclusion: 'fixture-authority-rejected-by-production-verifier',
      });
    }
    const finalSyntheticState = await captureSourceState(syntheticRecords);
    if (!sameSourceState(syntheticState, finalSyntheticState)) {
      fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED');
    }
    result = successReport({
      target,
      contract,
      originalState,
      syntheticState,
      syntheticGit,
      originalApplicationTrust,
      originalShawlTrust,
      productionNativeRejectedCode,
      productionDeploymentAuthority,
      builds,
    });
  } catch (error) {
    primaryFailure = new RealBunFixtureError(safeFailureCode(error));
  } finally {
    try {
      const finalSourceRecords = await collectSourceInputs(
        repositoryRoot,
        contract,
      );
      if (!sameSelectedSourceMembership(
        sourceRecords,
        finalSourceRecords,
      )) {
        fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED');
      }
      const finalOriginalState = await captureSourceState([
        ...finalSourceRecords,
        nativeAddonRecord,
        nativeManifestRecord,
      ]);
      if (!sameSourceState(originalState, finalOriginalState)) {
        primaryFailure = new RealBunFixtureError(
          'SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED',
        );
        result = null;
      }
    } catch {
      primaryFailure = new RealBunFixtureError(
        'SERVICE_RELEASE_REAL_BUN_FIXTURE_SOURCE_CHANGED',
      );
      result = null;
    }
    let cleanupFailed = false;
    if (fixture !== null) {
      try { fixture.dispose(); } catch { cleanupFailed = true; }
    }
    if (ownedRoot !== null &&
        !(await removeExactOwnedRoot(ownedRoot))) {
      cleanupFailed = true;
    }
    if (cleanupFailed) {
      primaryFailure = new RealBunFixtureError(
        'SERVICE_RELEASE_REAL_BUN_FIXTURE_CLEANUP_FAILED',
      );
      result = null;
    }
  }
  if (primaryFailure !== null) throw primaryFailure;
  if (result === null) fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_FAILED');
  return result;
}

function boundedReport(value) {
  const bytes = canonicalJsonBytes(value, {
    maxBytes: REPORT_BYTES,
    maxDepth: 32,
    maxNodes: 10_000,
  });
  if (bytes.length > REPORT_BYTES) {
    fail('SERVICE_RELEASE_REAL_BUN_FIXTURE_FAILED');
  }
  return bytes;
}

const invokedPath = process.argv[1] === undefined
  ? null
  : pathToFileURL(resolve(process.argv[1])).href;
if (invokedPath === import.meta.url) {
  try {
    const report = await runServiceReleaseRealBunEvidence(process.argv.slice(2));
    process.stdout.write(Buffer.concat([boundedReport(report), Buffer.from('\n')]));
  } catch (error) {
    const code = safeFailureCode(error);
    const failure = Object.freeze({
      schemaVersion: 1,
      kind: 'service-release-real-bun-fixture-evidence',
      result: code ===
        'SERVICE_RELEASE_REAL_BUN_FIXTURE_ACKNOWLEDGEMENT_REQUIRED'
        ? 'refused'
        : 'failed',
      code,
      productionRelease: 'not-created-or-signed',
      privateMaterialReported: false,
    });
    process.stderr.write(Buffer.concat([boundedReport(failure), Buffer.from('\n')]));
    process.exitCode = 1;
  }
}
