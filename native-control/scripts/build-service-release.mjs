import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants as fsConstants, realpathSync } from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  opendir,
  readFile,
  realpath,
  rm,
  stat,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { create as createTar } from 'tar';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  buildApplicationDeploymentManifest,
  buildBundleInventory,
  buildDeploymentCompatibility,
  bundleTreeFingerprint,
  validateApplicationDeploymentManifest,
  WINDOWS_SERVICE_BOOTSTRAP_EXTERNAL_BUN_CONFIG,
  WINDOWS_SERVICE_BOOTSTRAP_RUNTIME_POLICIES,
  windowsServiceBootstrapClosureFingerprint,
} from '@gjc-remote/shared/deployment-envelope';
import { DEPLOYMENT_FORMAT_REGISTRY } from '@gjc-remote/shared/deployment-format-registry';
import {
  canonicalJsonBytes,
  canonicalJsonHash,
  assertStrictText,
  parseCanonicalJsonBytes,
  parseStrictJsonBytes,
  utf8Compare,
} from '@gjc-remote/shared/strict-json';
import { verifyPinnedNativeBuildManifest } from '../src/native-provenance.js';
import { SERVICE_BOOTSTRAP_STATIC_CLOSURE } from '../src/service-bootstrap-policy.js';
import {
  deriveSdkExternalStateContract,
  SDK_EXTERNAL_STATE_REQUIREMENTS,
} from '../src/service-sdk-contract.js';
import {
  collectBunPackageClosure,
  bunPackageRootForPath,
  parseBunProductionLock as parseProductionLock,
  resolveBunProductionClosure,
  SERVICE_PRODUCTION_WORKSPACES,
} from '../src/service-production-closure.js';
import { consumeApplicationArchive, inspectApplicationArchive } from '../src/service-archive.js';

const CONTRACT_PATH = fileURLToPath(new URL('../../deploy/native/release-contract.json', import.meta.url));
const INVENTORY_PATH = 'bundle-files.json';
const PACKAGE_LIMIT = 1024 * 1024;
const TRUST_LIMIT = 64 * 1024;
const NATIVE_SIGNATURE_LIMIT = 16 * 1024;
const LOCK_LIMIT = 16 * 1024 * 1024;
const PROCESS_OUTPUT_LIMIT = 1024 * 1024;
const PROCESS_TIMEOUT_MS = 10 * 60_000;
const SOURCE_FILE_LIMIT = 256 * 1024 * 1024;
const CHUNK_BYTES = 64 * 1024;
const REGISTRY = 'https://registry.npmjs.org';
const FIXED_REMOTE = 'https://github.com/kogangdon/gjc-remote.git';
const MUTABLE_SEGMENTS = new Set([
  '.cache', '.env', '.git', '.gjc', '.gjc-remote-session',
  'credentials', 'logs', 'sessions',
]);
const SOURCE_WORKSPACES = SERVICE_PRODUCTION_WORKSPACES;
const NATIVE_ALIAS = 'node_modules/@gjc-remote/native-control';
const SDK_ROOTS = Object.keys(SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots);
const TARGETS = new Set(['linux:arm64', 'linux:x64', 'win32:x64']);
const CODES = Object.freeze({
  input: 'SERVICE_RELEASE_INPUT_INVALID',
  contract: 'SERVICE_RELEASE_CONTRACT_INVALID',
  source: 'SERVICE_RELEASE_SOURCE_INVALID',
  dirty: 'SERVICE_RELEASE_SOURCE_DIRTY',
  git: 'SERVICE_RELEASE_GIT_INVALID',
  path: 'SERVICE_RELEASE_PATH_INVALID',
  file: 'SERVICE_RELEASE_FILE_INVALID',
  lock: 'SERVICE_RELEASE_LOCK_INVALID',
  producer: 'SERVICE_RELEASE_PRODUCER_FAILED',
  closure: 'SERVICE_RELEASE_CLOSURE_INVALID',
  sdk: 'SERVICE_RELEASE_SDK_INVALID',
  native: 'SERVICE_RELEASE_NATIVE_INVALID',
  output: 'SERVICE_RELEASE_OUTPUT_INVALID',
  archive: 'SERVICE_RELEASE_ARCHIVE_INVALID',
  candidate: 'SERVICE_RELEASE_CANDIDATE_INVALID',
});

class ServiceReleaseError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ServiceReleaseError';
    this.code = code;
    this.writes = 0;
  }
}

function fail(code) {
  throw new ServiceReleaseError(code);
}

function bounded(error, fallback) {
  return error instanceof ServiceReleaseError ? error : new ServiceReleaseError(fallback);
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value, keys) {
  return plain(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function hashBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function payloadBudget() {
  let entries = 0;
  let bytes = 0;
  return Object.freeze({
    admit(size, code = CODES.output) {
      if (!Number.isSafeInteger(size) || size < 0 ||
          size > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes) fail(code);
      const nextEntries = entries + 1;
      const nextBytes = bytes + size;
      if (!Number.isSafeInteger(nextBytes) ||
          nextEntries > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries ||
          nextBytes > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes) {
        fail(code);
      }
      entries = nextEntries;
      bytes = nextBytes;
      return Object.freeze({ entries, bytes });
    },
    snapshot() {
      return Object.freeze({ entries, bytes });
    },
  });
}

async function admitRegularFile(path, maximum, budget, code) {
  try {
    const facts = await lstat(path, { bigint: true });
    if (!facts.isFile() || facts.size < 0n ||
        facts.size > BigInt(maximum) ||
        facts.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(code);
    budget.admit(Number(facts.size), code);
    return Number(facts.size);
  } catch (error) {
    throw bounded(error, code);
  }
}

function comparePath(left, right) {
  return utf8Compare(left, right);
}

function inside(root, path) {
  const rel = relative(root, path);
  return rel !== '' && !rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel);
}

function sameOrInside(root, path) {
  return resolve(root) === resolve(path) || inside(resolve(root), resolve(path));
}

function exactAbsolutePath(value) {
  return typeof value === 'string' && value.length > 0 && isAbsolute(value) && resolve(value) === value;
}

function readOnlyNoFollowFlags() {
  return process.platform === 'win32'
    ? fsConstants.O_RDONLY
    : fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
}

function assertBundlePath(path, platform) {
  try {
    bundleTreeFingerprint([{
      path,
      size: 0,
      sha256: '0'.repeat(64),
      executablePolicy: 'forbidden',
    }], { platform });
  } catch {
    fail(CODES.path);
  }
}

function assertNoMutableSegments(path) {
  if (path.split('/').some((part) => MUTABLE_SEGMENTS.has(part.toLowerCase()))) fail(CODES.path);
}

async function readRegularBytes(path, maximum, code = CODES.file) {
  let handle;
  try {
    const named = await lstat(path, { bigint: true });
    if (!named.isFile() || named.size < 0n || named.size > BigInt(maximum)) fail(code);
    handle = await open(path, readOnlyNoFollowFlags());
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.dev !== named.dev || before.ino !== named.ino ||
        before.size !== named.size || before.mtimeNs !== named.mtimeNs || before.ctimeNs !== named.ctimeNs) fail(code);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) fail(code);
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
        after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) fail(code);
    return bytes;
  } catch (error) {
    throw bounded(error, code);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { fail(code); }
    }
  }
}

async function writeExclusive(path, bytes, mode = 0o600) {
  let handle;
  try {
    handle = await open(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, mode);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset);
      if (bytesWritten === 0) fail(CODES.output);
      offset += bytesWritten;
    }
    await handle.sync();
  } catch (error) {
    throw bounded(error, CODES.output);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { fail(CODES.output); }
    }
  }
}

async function copyRegularFile(source, destination, {
  maximum = DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes,
  mode = 0o644,
  expectedGitBlob = null,
} = {}) {
  let input;
  let output;
  try {
    const named = await lstat(source, { bigint: true });
    if (!named.isFile() || named.size < 0n || named.size > BigInt(maximum)) fail(CODES.file);
    input = await open(source, readOnlyNoFollowFlags());
    const before = await input.stat({ bigint: true });
    if (!before.isFile() || before.dev !== named.dev || before.ino !== named.ino || before.size !== named.size ||
        before.mtimeNs !== named.mtimeNs || before.ctimeNs !== named.ctimeNs) fail(CODES.file);
    await mkdir(dirname(destination), { recursive: true, mode: 0o755 });
    output = await open(destination, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, mode);
    const sha256 = createHash('sha256');
    const git = expectedGitBlob === null ? null : createHash('sha1').update(`blob ${before.size}\0`);
    const buffer = Buffer.allocUnsafe(Math.min(CHUNK_BYTES, Math.max(1, Number(before.size))));
    let position = 0;
    while (position < Number(before.size)) {
      const length = Math.min(buffer.length, Number(before.size) - position);
      const { bytesRead } = await input.read(buffer, 0, length, position);
      if (bytesRead === 0) fail(CODES.file);
      const chunk = buffer.subarray(0, bytesRead);
      sha256.update(chunk);
      git?.update(chunk);
      let written = 0;
      while (written < bytesRead) {
        const result = await output.write(chunk, written, bytesRead - written, position + written);
        if (result.bytesWritten === 0) fail(CODES.output);
        written += result.bytesWritten;
      }
      position += bytesRead;
    }
    const after = await input.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
        after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) fail(CODES.file);
    if (git && git.digest('hex') !== expectedGitBlob) fail(CODES.source);
    await output.sync();
    await output.chmod(mode);
    return Object.freeze({ size: Number(before.size), sha256: sha256.digest('hex') });
  } catch (error) {
    throw bounded(error, error instanceof ServiceReleaseError ? error.code : CODES.file);
  } finally {
    if (input) {
      try { await input.close(); } catch { fail(CODES.file); }
    }
    if (output) {
      try { await output.close(); } catch { fail(CODES.output); }
    }
  }
}

function isolatedBaseEnvironment(home) {
  const allowed = ['COMSPEC', 'PATH', 'PATHEXT', 'SYSTEMDRIVE', 'SYSTEMROOT', 'TEMP', 'TMP', 'WINDIR'];
  const env = {};
  for (const name of allowed) if (typeof process.env[name] === 'string') env[name] = process.env[name];
  return {
    ...env,
    CI: '1',
    HOME: home,
    USERPROFILE: home,
    XDG_CACHE_HOME: join(home, 'cache'),
    XDG_CONFIG_HOME: join(home, 'config'),
    XDG_DATA_HOME: join(home, 'data'),
    LANG: 'C',
    LC_ALL: 'C',
    GIT_TERMINAL_PROMPT: '0',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: join(home, 'gitconfig'),
    NPM_CONFIG_USERCONFIG: join(home, 'npmrc'),
    npm_config_userconfig: join(home, 'npmrc'),
    npm_config_registry: REGISTRY,
  };
}

async function runCapturedProcess({
  command,
  args,
  cwd,
  env,
  timeoutMs = PROCESS_TIMEOUT_MS,
  maximumOutputBytes = PROCESS_OUTPUT_LIMIT,
}) {
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let timer;
    let stdoutLength = 0;
    let stderrLength = 0;
    const stdout = [];
    const stderr = [];
    const child = spawn(command, args, {
      cwd,
      env,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) rejectPromise(error);
      else resolvePromise(result);
    };
    const collect = (target, chunk, isStdout) => {
      const bytes = Buffer.from(chunk);
      if (isStdout) stdoutLength += bytes.length;
      else stderrLength += bytes.length;
      if (stdoutLength > maximumOutputBytes || stderrLength > maximumOutputBytes) {
        child.kill('SIGKILL');
        finish(new ServiceReleaseError(CODES.producer));
        return;
      }
      target.push(bytes);
    };
    child.stdout.on('data', (chunk) => collect(stdout, chunk, true));
    child.stderr.on('data', (chunk) => collect(stderr, chunk, false));
    child.on('error', () => finish(new ServiceReleaseError(CODES.producer)));
    child.on('close', (code, signal) => finish(null, Object.freeze({
      code,
      signal,
      stdout: Buffer.concat(stdout, stdoutLength),
      stderr: Buffer.concat(stderr, stderrLength),
    })));
    timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new ServiceReleaseError(CODES.producer));
    }, timeoutMs);
    timer.unref?.();
  });
}

async function runGit(sourceRoot, gitHome, args, maximum = PROCESS_OUTPUT_LIMIT) {
  const result = await runCapturedProcess({
    command: 'git',
    args: [
      '--no-replace-objects',
      '-c', 'core.fsmonitor=false',
      '-c', `core.hooksPath=${join(gitHome, 'hooks-disabled')}`,
      ...args,
    ],
    cwd: sourceRoot,
    env: {
      ...isolatedBaseEnvironment(gitHome),
      GIT_NO_REPLACE_OBJECTS: '1',
    },
    maximumOutputBytes: maximum,
  });
  if (result.code !== 0 || result.signal !== null ||
      result.stdout.length > maximum) fail(CODES.git);
  return result.stdout;
}

async function assertNoExecutableGitFilters(sourceRoot, gitHome) {
  const result = await runCapturedProcess({
    command: 'git',
    args: [
      '--no-replace-objects',
      '-c', 'core.fsmonitor=false',
      '-c', `core.hooksPath=${join(gitHome, 'hooks-disabled')}`,
      'config',
      '--includes',
      '--name-only',
      '--null',
      '--get-regexp',
      '^filter\\..*\\.(clean|process)$',
    ],
    cwd: sourceRoot,
    env: {
      ...isolatedBaseEnvironment(gitHome),
      GIT_NO_REPLACE_OBJECTS: '1',
    },
    maximumOutputBytes: PROCESS_OUTPUT_LIMIT,
  });
  if (result.signal !== null || ![0, 1].includes(result.code) ||
      result.stderr.length !== 0 ||
      (result.code === 0 && result.stdout.length !== 0) ||
      (result.code === 1 && result.stdout.length !== 0)) fail(CODES.git);
}

function oneLine(bytes, pattern, code = CODES.git) {
  const value = bytes.toString('utf8').replace(/\r?\n$/, '');
  if (!pattern.test(value)) fail(code);
  return value;
}

function parseContract(bytes) {
  let contract;
  try {
    contract = parseStrictJsonBytes(bytes, { maxBytes: PACKAGE_LIMIT, maxDepth: 32, maxNodes: 10_000 });
  } catch {
    fail(CODES.contract);
  }
  const keys = [
    'schemaVersion', 'kind', 'limits', 'repository', 'releaseVersion', 'releaseTag', 'producer',
    'targets', 'sourceWorkspaces', 'sourceRootFiles', 'excludedSegments',
    'entrypoints', 'runtimes', 'nativeControl',
    'wireCapabilities', 'sdk',
  ];
  if (!exact(contract, keys) || contract.schemaVersion !== 1 ||
      contract.kind !== 'gjc-remote-application-release-contract' ||
      contract.repository !== 'kogangdon/gjc-remote' || contract.releaseVersion !== '0.4.0-rc.4' ||
      contract.releaseTag !== 'v0.4.0-rc.4' || !exact(contract.entrypoints, ['bot', 'daemon']) ||
      contract.entrypoints.bot !== 'bot/src/bot.js' || contract.entrypoints.daemon !== 'daemon/src/daemon.js' ||
      !exact(contract.runtimes, ['node', 'bun']) || contract.runtimes.node?.minimumVersion !== '26.0.0' ||
      contract.runtimes.bun?.minimumVersion !== '1.4.0') fail(CODES.contract);
  const limitKeys = [
    'manifestBytes', 'signatureBytes', 'archiveBytes', 'unpackedPayloadBytes',
    'inventoryBytes', 'payloadEntries', 'pathBytes', 'pathSegments', 'lockBytes',
    'packageMetadataBytes', 'producerOutputBytes', 'producerTimeoutMs',
  ];
  if (!exact(contract.limits, limitKeys) ||
      canonicalJsonHash(contract.limits) !== canonicalJsonHash({
        manifestBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
        signatureBytes: DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes,
        archiveBytes: DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes,
        unpackedPayloadBytes: DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes,
        inventoryBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
        payloadEntries: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries,
        pathBytes: DEPLOYMENT_ENVELOPE_LIMITS.pathBytes,
        pathSegments: DEPLOYMENT_ENVELOPE_LIMITS.pathSegments,
        lockBytes: LOCK_LIMIT,
        packageMetadataBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
        producerOutputBytes: PROCESS_OUTPUT_LIMIT,
        producerTimeoutMs: PROCESS_TIMEOUT_MS,
      })) fail(CODES.contract);
  if (!exact(contract.producer, [
    'bunVersion', 'executableModeAuthority', 'installArguments', 'archive',
  ]) ||
      contract.producer.bunVersion !== '1.4.2' ||
      canonicalJsonHash(contract.producer.executableModeAuthority) !==
        canonicalJsonHash({
          gitExecutableBlobs: 'required',
          packageBins: 'required',
          nativeAddon: 'required',
          otherMaterializedFiles: 'producer-filesystem-mode',
          windowsProducerToLinuxTarget: 'refused-before-writes-or-network',
        }) ||
      JSON.stringify(contract.producer.installArguments) !== JSON.stringify([
        'install', '--production', '--frozen-lockfile', '--ignore-scripts', '--backend=copyfile',
        '--linker=hoisted', '--cache-dir=<fresh-cache>', `--registry=${REGISTRY}`,
        '--os=<target-platform>', '--cpu=<target-architecture>',
      ]) || !exact(contract.producer.archive, [
        'format', 'gzipLevel', 'gzipOperatingSystem', 'mtimeSeconds', 'terminalZeroBlocks', 'paxType', 'paxKeys',
      ]) || contract.producer.archive.format !== 'posix-ustar' || contract.producer.archive.gzipLevel !== 6 ||
      contract.producer.archive.gzipOperatingSystem !== 255 || contract.producer.archive.mtimeSeconds !== 0 ||
      contract.producer.archive.terminalZeroBlocks !== 2 || contract.producer.archive.paxType !== 'local' ||
      JSON.stringify(contract.producer.archive.paxKeys) !== JSON.stringify(['SCHILY.nlink', 'mtime', 'path', 'size'])) fail(CODES.contract);
  if (!Array.isArray(contract.targets) || contract.targets.length !== TARGETS.size ||
      new Set(contract.targets.map((target) => `${target?.platform}:${target?.architecture}`)).size !== TARGETS.size ||
      contract.targets.some((target) => !exact(target, ['platform', 'architecture']) ||
        !TARGETS.has(`${target.platform}:${target.architecture}`))) fail(CODES.contract);
  if (!Array.isArray(contract.sourceWorkspaces) || contract.sourceWorkspaces.length !== SOURCE_WORKSPACES.length ||
      contract.sourceWorkspaces.some((workspace, index) => !exact(workspace, [
        'path', 'packageName', 'packageVersion', 'productionRoots',
      ]) || workspace.path !== SOURCE_WORKSPACES[index] || !Array.isArray(workspace.productionRoots))) fail(CODES.contract);
  const expectedWorkspace = [
    ['bot', '@gjc-remote/bot', '0.4.0-rc.4', ['package.json', 'src']],
    ['daemon', '@gjc-remote/daemon', '0.4.0-rc.4', ['package.json', 'src']],
    ['native-control', '@gjc-remote/native-control', '2.0.0', [
      'deployment-keys/application-trusted.json',
      'deployment-keys/shawl-trusted.json', 'package.json',
      'release-keys/trusted.json', 'src',
    ]],
    ['shared', '@gjc-remote/shared', '0.4.0-rc.4', ['package.json', '*.js']],
  ];
  if (contract.sourceWorkspaces.some((workspace, index) =>
    workspace.path !== expectedWorkspace[index][0] || workspace.packageName !== expectedWorkspace[index][1] ||
    workspace.packageVersion !== expectedWorkspace[index][2] ||
    JSON.stringify(workspace.productionRoots) !== JSON.stringify(expectedWorkspace[index][3]))) fail(CODES.contract);
  if (JSON.stringify(contract.sourceRootFiles) !== JSON.stringify(['bun.lock', 'package.json']) ||
      JSON.stringify(contract.excludedSegments) !== JSON.stringify([...MUTABLE_SEGMENTS])) fail(CODES.contract);
  const nativeKeys = [
    'packageName', 'packageVersion', 'manifestPath', 'signaturePath', 'addonPath',
    'applicationTrustPath', 'shawlTrustPath', 'trustPath',
    'contractVersion', 'contractRevision', 'napi', 'executablePolicy',
  ];
  if (!exact(contract.nativeControl, nativeKeys) || contract.nativeControl.packageName !== '@gjc-remote/native-control' ||
      contract.nativeControl.packageVersion !== '2.0.0' ||
      contract.nativeControl.manifestPath !== 'native-control/build/Release/native-control.manifest.json' ||
      contract.nativeControl.signaturePath !== 'native-control/build/Release/native-control.manifest.json.sig' ||
      contract.nativeControl.addonPath !== 'native-control/build/Release/native_control.node' ||
      contract.nativeControl.applicationTrustPath !== 'native-control/deployment-keys/application-trusted.json' ||
      contract.nativeControl.shawlTrustPath !== 'native-control/deployment-keys/shawl-trusted.json' ||
      contract.nativeControl.trustPath !== 'native-control/release-keys/trusted.json' ||
      contract.nativeControl.contractVersion !== 5 || contract.nativeControl.contractRevision !== 1 ||
      contract.nativeControl.napi !== 8 || contract.nativeControl.executablePolicy !== 'required') fail(CODES.contract);
  if (!Array.isArray(contract.wireCapabilities) || contract.wireCapabilities.length === 0 ||
      contract.wireCapabilities.some((value, index) => typeof value !== 'string' ||
        (index > 0 && utf8Compare(contract.wireCapabilities[index - 1], value) >= 0)) ||
      JSON.stringify(contract.wireCapabilities) !== JSON.stringify([
        'gate_presentation_v1', 'heartbeat', 'invoke', 'invoke_cancellation_v1',
        'set_model', 'terminal_disposition_v1', 'workspace_bind_authority_verification_v1',
        'workspace_inventory_receipt_v2', 'workspace_readiness_v2',
      ])) fail(CODES.contract);
  if (!exact(contract.sdk, [
    'packageName', 'packageVersion', 'lockIntegrity', 'configSchemaVersion', 'transcriptVersion',
    'sourceRoots', 'sourceContractDomain', 'closureDomain',
  ]) || contract.sdk.packageName !== SDK_EXTERNAL_STATE_REQUIREMENTS.packageName ||
      contract.sdk.packageVersion !== SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion ||
      contract.sdk.lockIntegrity !== SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity ||
      contract.sdk.configSchemaVersion !== SDK_EXTERNAL_STATE_REQUIREMENTS.configSchemaVersion ||
      contract.sdk.transcriptVersion !== SDK_EXTERNAL_STATE_REQUIREMENTS.transcriptVersion ||
      !exact(contract.sdk.sourceRoots, SDK_ROOTS) ||
      canonicalJsonHash(contract.sdk.sourceRoots) !== canonicalJsonHash(SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots) ||
      contract.sdk.sourceContractDomain !== SDK_EXTERNAL_STATE_REQUIREMENTS.sourceContractDomain ||
      contract.sdk.closureDomain !== SDK_EXTERNAL_STATE_REQUIREMENTS.closureDomain) fail(CODES.contract);
  const formatRegistry = DEPLOYMENT_FORMAT_REGISTRY;
  if (!exact(formatRegistry, ['bot', 'daemonAppSession', 'workspaceLifecycle'])) fail(CODES.contract);
  for (const [name, expectedDomain] of [
    ['bot', 'bot-mapping-reader'], ['daemonAppSession', 'daemon-app-session'], ['workspaceLifecycle', 'workspace-lifecycle'],
  ]) {
    const domain = formatRegistry[name];
    if (!exact(domain, ['domain', 'formats']) || domain.domain !== expectedDomain || !Array.isArray(domain.formats) ||
        domain.formats.length === 0 || domain.formats.length > 256) fail(CODES.contract);
    const ids = new Set();
    for (const record of domain.formats) {
      if (!exact(record, ['formatId', 'marker', 'source']) || typeof record.formatId !== 'string' ||
          !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/.test(record.formatId) || ids.has(record.formatId) ||
          !plain(record.marker) || Object.keys(record.marker).length === 0 || typeof record.source !== 'string' ||
          record.source.length === 0) fail(CODES.contract);
      ids.add(record.formatId);
    }
  }
  return deepFreeze({ ...contract, formatRegistry });
}

export async function loadServiceReleaseContract() {
  return parseContract(await readRegularBytes(CONTRACT_PATH, PACKAGE_LIMIT, CODES.contract));
}

export function parseBunProductionLock(bytes) {
  try {
    return parseProductionLock(bytes);
  } catch {
    fail(CODES.lock);
  }
}

async function inspectGitSource(sourceRoot, contract, scratch) {
  const gitHome = join(scratch, 'git-home');
  await mkdir(join(gitHome, 'hooks-disabled'), { recursive: true });
  await writeExclusive(join(gitHome, 'gitconfig'), Buffer.alloc(0));
  await writeExclusive(join(gitHome, 'npmrc'), Buffer.alloc(0));
  const top = oneLine(await runGit(sourceRoot, gitHome, ['rev-parse', '--show-toplevel']), /.+/);
  let canonicalTop;
  let canonicalRequested;
  try {
    [canonicalTop, canonicalRequested] = await Promise.all([realpath(top), realpath(sourceRoot)]);
  } catch {
    fail(CODES.source);
  }
  if (canonicalTop !== canonicalRequested || canonicalRequested !== sourceRoot) fail(CODES.source);
  await assertNoExecutableGitFilters(sourceRoot, gitHome);
  if (oneLine(await runGit(sourceRoot, gitHome, ['rev-parse', '--show-object-format']), /^sha1$/) !== 'sha1') fail(CODES.git);
  if ((await runGit(sourceRoot, gitHome, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])).length !== 0) fail(CODES.dirty);
  const commit = oneLine(await runGit(sourceRoot, gitHome, ['rev-parse', '--verify', 'HEAD^{commit}']), /^[0-9a-f]{40}$/);
  const tree = oneLine(await runGit(sourceRoot, gitHome, ['rev-parse', '--verify', 'HEAD^{tree}']), /^[0-9a-f]{40}$/);
  const tagCommit = oneLine(await runGit(sourceRoot, gitHome, ['rev-parse', '--verify', `${contract.releaseTag}^{commit}`]), /^[0-9a-f]{40}$/);
  if (tagCommit !== commit) fail(CODES.source);
  const remote = oneLine(await runGit(sourceRoot, gitHome, ['remote', 'get-url', 'origin']), /.+/);
  if (remote !== FIXED_REMOTE) fail(CODES.source);
  const listed = await runGit(sourceRoot, gitHome, [
    'ls-tree', '-rz', '--full-tree', 'HEAD', '--', 'package.json', 'bun.lock', ...SOURCE_WORKSPACES,
  ], 16 * 1024 * 1024);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const files = [];
  for (const raw of listed.subarray(0, listed.length - (listed.at(-1) === 0 ? 1 : 0)).toString('binary').split('\0')) {
    if (raw.length === 0) continue;
    const bytes = Buffer.from(raw, 'binary');
    let decoded;
    try { decoded = decoder.decode(bytes); } catch { fail(CODES.source); }
    const match = /^(100644|100755|120000|160000) (blob|commit) ([0-9a-f]{40})\t(.+)$/.exec(decoded);
    if (!match) fail(CODES.source);
    files.push(Object.freeze({ mode: match[1], type: match[2], hash: match[3], path: match[4] }));
    if (files.length > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries) {
      fail(CODES.source);
    }
  }
  const byPath = new Map(files.map((file) => [file.path, file]));
  if (!byPath.has('package.json') || !byPath.has('bun.lock')) fail(CODES.source);
  return Object.freeze({ gitHome, commit, tree, files, byPath });
}

function selectedSourcePath(path, contract) {
  for (const workspace of contract.sourceWorkspaces) {
    const prefix = `${workspace.path}/`;
    if (!path.startsWith(prefix)) continue;
    const local = path.slice(prefix.length);
    if (local === 'package.json') return true;
    if (workspace.path === 'shared') return !local.includes('/') && local.endsWith('.js');
    if (workspace.path === 'native-control' &&
        ['deployment-keys/application-trusted.json',
          'deployment-keys/shawl-trusted.json',
          'release-keys/trusted.json'].includes(local)) return true;
    if (!local.startsWith('src/')) return false;
    return !/(?:^|\/)test(?:s)?(?:\/|$)/i.test(local) && !/\.(?:test|spec)\.[^.]+$/i.test(local);
  }
  return false;
}

async function copyGitSources(
  sourceRoot,
  materialRoot,
  git,
  contract,
  platform,
  budget,
) {
  const selected = git.files.filter((file) => selectedSourcePath(file.path, contract));
  const required = new Set(contract.sourceWorkspaces.map((workspace) => `${workspace.path}/package.json`));
  required.add(contract.entrypoints.bot);
  required.add(contract.entrypoints.daemon);
  required.add(contract.nativeControl.applicationTrustPath);
  required.add(contract.nativeControl.shawlTrustPath);
  required.add(contract.nativeControl.trustPath);
  for (const path of required) if (!selected.some((file) => file.path === path)) fail(CODES.source);
  const records = [];
  for (const file of selected.sort((left, right) => comparePath(left.path, right.path))) {
    if (file.type !== 'blob' || !['100644', '100755'].includes(file.mode)) fail(CODES.source);
    assertNoMutableSegments(file.path);
    assertBundlePath(file.path, platform);
    const source = join(sourceRoot, ...file.path.split('/'));
    const admittedSize = await admitRegularFile(source, SOURCE_FILE_LIMIT, budget, CODES.source);
    const copied = await copyRegularFile(source, join(materialRoot, ...file.path.split('/')), {
      maximum: admittedSize,
      mode: file.mode === '100755' ? 0o755 : 0o644,
      expectedGitBlob: file.hash,
    });
    records.push(Object.freeze({
      path: file.path,
      source: join(materialRoot, ...file.path.split('/')),
      executablePolicy: file.mode === '100755' ? 'required' : 'forbidden',
      ...copied,
    }));
  }
  for (const controlPath of contract.sourceRootFiles) {
    const file = git.byPath.get(controlPath);
    if (!file || file.type !== 'blob' || file.mode !== '100644') fail(CODES.source);
    const destination = join(materialRoot, controlPath);
    const maximum = controlPath === 'bun.lock' ? LOCK_LIMIT : PACKAGE_LIMIT;
    const source = join(sourceRoot, controlPath);
    const admittedSize = await admitRegularFile(source, maximum, budget, CODES.source);
    const copied = await copyRegularFile(source, destination, {
      maximum: admittedSize,
      expectedGitBlob: file.hash,
    });
    records.push(Object.freeze({
      path: controlPath,
      source: destination,
      executablePolicy: 'forbidden',
      ...copied,
    }));
  }
  return records;
}

async function revalidateGitSource(sourceRoot, git, contract) {
  await assertNoExecutableGitFilters(sourceRoot, git.gitHome);
  if ((await runGit(sourceRoot, git.gitHome, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])).length !== 0) fail(CODES.dirty);
  const commit = oneLine(await runGit(sourceRoot, git.gitHome, ['rev-parse', '--verify', 'HEAD^{commit}']), /^[0-9a-f]{40}$/);
  const tree = oneLine(await runGit(sourceRoot, git.gitHome, ['rev-parse', '--verify', 'HEAD^{tree}']), /^[0-9a-f]{40}$/);
  const tag = oneLine(await runGit(sourceRoot, git.gitHome, ['rev-parse', '--verify', `${contract.releaseTag}^{commit}`]), /^[0-9a-f]{40}$/);
  const remote = oneLine(await runGit(sourceRoot, git.gitHome, ['remote', 'get-url', 'origin']), /.+/);
  if (commit !== git.commit || tree !== git.tree || tag !== git.commit ||
      remote !== FIXED_REMOTE) fail(CODES.source);
}

function parsePackage(bytes, code = CODES.closure) {
  try {
    const value = parseStrictJsonBytes(bytes, { maxBytes: PACKAGE_LIMIT, maxDepth: 32, maxNodes: 100_000 });
    if (!plain(value) || typeof value.name !== 'string' || typeof value.version !== 'string') fail(code);
    return value;
  } catch (error) {
    throw bounded(error, code);
  }
}

async function packageRootFacts(materialRoot, logicalRoot) {
  let realRoot;
  let facts;
  try {
    realRoot = await realpath(logicalRoot);
    if (!sameOrInside(materialRoot, realRoot)) fail(CODES.closure);
    facts = await stat(realRoot, { bigint: true });
  } catch (error) {
    throw bounded(error, CODES.closure);
  }
  if (!facts.isDirectory()) fail(CODES.closure);
  const packageBytes = await readRegularBytes(join(realRoot, 'package.json'), PACKAGE_LIMIT, CODES.closure);
  return { realRoot, packageBytes };
}

function packageBinTargets(packageJson) {
  const values = typeof packageJson.bin === 'string' ? [packageJson.bin]
    : plain(packageJson.bin) ? Object.values(packageJson.bin) : packageJson.bin === undefined ? [] : null;
  if (values === null || values.some((value) => typeof value !== 'string')) fail(CODES.closure);
  const targets = new Set();
  for (const value of values) {
    const normalized = value.replace(/^\.\//, '');
    if (normalized.length === 0 || normalized.includes('\\') || normalized.startsWith('/') ||
        normalized.split('/').some((part) => part === '' || part === '.' || part === '..')) fail(CODES.closure);
    targets.add(normalized);
  }
  return targets;
}

async function walkPackageFiles({ materialRoot, realRoot, outputPrefix, ownerKey, packageJson }, addSpec) {
  const bins = packageBinTargets(packageJson);
  const discovery = { nodes: 0 };
  const walk = async (physicalDirectory, relativeDirectory, ancestors) => {
    let canonical;
    try { canonical = await realpath(physicalDirectory); } catch { fail(CODES.closure); }
    if (!sameOrInside(materialRoot, canonical) || ancestors.has(canonical)) fail(CODES.closure);
    const nextAncestors = new Set(ancestors).add(canonical);
    let directory;
    try { directory = await opendir(physicalDirectory); } catch { fail(CODES.closure); }
    for await (const entry of directory) {
      discovery.nodes += 1;
      if (discovery.nodes > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries) {
        fail(CODES.closure);
      }
      if (relativeDirectory === '' && entry.name === 'node_modules') continue;
      const local = relativeDirectory === '' ? entry.name : `${relativeDirectory}/${entry.name}`;
      const output = `${outputPrefix}/${local}`;
      let physical = join(physicalDirectory, entry.name);
      let kind = entry;
      if (entry.isSymbolicLink()) {
        try {
          physical = await realpath(physical);
          if (!sameOrInside(materialRoot, physical)) fail(CODES.closure);
          const target = await stat(physical);
          kind = {
            isDirectory: () => target.isDirectory(),
            isFile: () => target.isFile(),
            isSymbolicLink: () => false,
          };
        } catch (error) {
          throw bounded(error, CODES.closure);
        }
      }
      if (kind.isDirectory()) {
        await walk(physical, local, nextAncestors);
      } else if (kind.isFile()) {
        const fileStat = await stat(physical);
        if (!Number.isSafeInteger(fileStat.size) || fileStat.size < 0 ||
            fileStat.size > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes) {
          fail(CODES.closure);
        }
        addSpec({
          path: output,
          source: physical,
          size: fileStat.size,
          executablePolicy: bins.has(local) || (fileStat.mode & 0o111) !== 0 ? 'required' : 'forbidden',
          ownerKey,
          packageRelativePath: local,
        });
      } else {
        fail(CODES.closure);
      }
    }
  };
  await walk(realRoot, '', new Set());
}

async function readDirectoryBounded(path, maximumEntries, code) {
  const entries = [];
  try {
    const directory = await opendir(path);
    for await (const entry of directory) {
      if (entries.length >= maximumEntries) fail(code);
      entries.push(entry);
    }
    return entries;
  } catch (error) {
    throw bounded(error, code);
  }
}

async function buildProductionClosure({ materialRoot, lock, contract, platform, architecture, sourceRecords, addSpec }) {
  const factsByRoot = new Map();
  const readPackageRoot = async (packageRoot) => {
    const existing = factsByRoot.get(packageRoot);
    if (existing) return existing;
    const logicalRoot = join(materialRoot, ...packageRoot.split('/'));
    try {
      await lstat(logicalRoot);
    } catch (error) {
      if (error?.code === 'ENOENT') return null;
      fail(CODES.closure);
    }
    const facts = await packageRootFacts(materialRoot, logicalRoot);
    factsByRoot.set(packageRoot, facts);
    return facts;
  };
  let nodes;
  try {
    ({ nodes } = await resolveBunProductionClosure({
      lock,
      contract,
      platform,
      architecture,
      readPackageRoot,
      requireWorkspaceRealRoot: true,
    }));
  } catch (error) {
    fail(error?.code === 'SERVICE_PRODUCTION_LOCK_INVALID' ? CODES.lock : CODES.closure);
  }
  const sourceByWorkspace = new Map(SOURCE_WORKSPACES.map((workspace) => [workspace, []]));
  for (const record of sourceRecords) sourceByWorkspace.get(record.path.split('/')[0])?.push(record);
  for (const node of nodes.values()) {
    if (node.workspace !== null && node.key !== `workspace:${node.workspace}`) {
      for (const source of sourceByWorkspace.get(node.workspace)) {
        const local = source.path.slice(node.workspace.length + 1);
        addSpec({
          path: `${node.root}/${local}`,
          source: source.source,
          executablePolicy: source.executablePolicy,
          size: source.size,
          sha256: source.sha256,
          ownerKey: node.key,
          packageRelativePath: local,
        });
      }
    } else if (node.workspace === null) {
      await walkPackageFiles({
        materialRoot,
        realRoot: node.realRoot,
        outputPrefix: node.root,
        ownerKey: node.key,
        packageJson: node.packageJson,
      }, addSpec);
    }
  }
  if (![...nodes.values()].some((node) => node.root === NATIVE_ALIAS)) fail(CODES.closure);
  return { nodes };
}

async function sdkContractFor({ nodes, recordsByOwner, contract, readRecordBytes }) {
  const daemon = nodes.get('workspace:daemon');
  const sdkEdge = daemon?.edges.find((edge) => edge.name === contract.sdk.packageName && edge.kind === 'dependency');
  if (!sdkEdge) fail(CODES.sdk);
  const root = nodes.get(sdkEdge.targetKey);
  if (!root || root.identity !== `${contract.sdk.packageName}@${contract.sdk.packageVersion}` ||
      root.integrity !== contract.sdk.lockIntegrity) fail(CODES.sdk);
  let sdkClosure;
  try {
    sdkClosure = collectBunPackageClosure({
      nodes,
      rootKey: root.key,
      recordsByOwner,
      requireExternal: true,
    });
  } catch {
    fail(CODES.sdk);
  }
  const rootRecords = sdkClosure.recordsByOwner.get(root.key) ?? [];
  const configRecord = rootRecords.find((record) => record.packageRelativePath === 'src/config/config-schema-version.ts');
  const sessionRecord = rootRecords.find((record) => record.packageRelativePath === 'src/session/session-manager.ts');
  if (!configRecord || !sessionRecord) fail(CODES.sdk);
  const [configBytes, sessionBytes] = await Promise.all([
    readRecordBytes(configRecord),
    readRecordBytes(sessionRecord),
  ]);
  let provenance;
  try {
    provenance = deriveSdkExternalStateContract({
      packages: sdkClosure.packages,
      configSchemaVersionSource: configBytes,
      sessionManagerSource: sessionBytes,
    });
  } catch {
    fail(CODES.sdk);
  }
  return Object.freeze(provenance);
}

function compatibilityFor(contract, sdkFingerprint) {
  const ids = (domain) => [...domain.formats.map((record) => record.formatId)].sort(comparePath);
  return buildDeploymentCompatibility({
    bot: {
      domains: [{
        domain: contract.formatRegistry.bot.domain,
        readableFormats: ids(contract.formatRegistry.bot),
        writableFormats: ids(contract.formatRegistry.bot),
      }],
    },
    daemon: {
      domains: [
        {
          domain: contract.formatRegistry.daemonAppSession.domain,
          readableFormats: ids(contract.formatRegistry.daemonAppSession),
          writableFormats: ids(contract.formatRegistry.daemonAppSession),
        },
        {
          domain: contract.formatRegistry.workspaceLifecycle.domain,
          readableFormats: ids(contract.formatRegistry.workspaceLifecycle),
          writableFormats: ids(contract.formatRegistry.workspaceLifecycle),
        },
      ],
      sdkExternalStateContractFingerprint: sdkFingerprint,
    },
  });
}

async function defaultBunProcess(specification) {
  const versionResult = await runCapturedProcess({
    command: 'bun', args: ['--version'], cwd: specification.cwd, env: specification.env,
  });
  if (versionResult.code !== 0 || versionResult.signal !== null) fail(CODES.producer);
  const version = oneLine(versionResult.stdout, /^1\.4\.2$/, CODES.producer);
  const install = await runCapturedProcess({
    command: 'bun', args: specification.installArguments, cwd: specification.cwd, env: specification.env,
  });
  if (install.code !== 0 || install.signal !== null) fail(CODES.producer);
  return Object.freeze({
    kind: 'real-external-bun-process',
    version,
    versionStdoutSha256: hashBytes(versionResult.stdout),
    versionStderrSha256: hashBytes(versionResult.stderr),
    installStdoutSha256: hashBytes(install.stdout),
    installStderrSha256: hashBytes(install.stderr),
  });
}

async function materializeWithBun({ materialRoot, scratch, platform, architecture, contract }) {
  const cache = join(scratch, 'bun-cache');
  const home = join(scratch, 'bun-home');
  await mkdir(cache, { recursive: false });
  await mkdir(home, { recursive: false });
  await writeExclusive(join(home, 'npmrc'), Buffer.alloc(0));
  const installArguments = [
    'install', '--production', '--frozen-lockfile', '--ignore-scripts', '--backend=copyfile',
    '--linker=hoisted', `--cache-dir=${cache}`, `--registry=${REGISTRY}`, `--os=${platform}`, `--cpu=${architecture}`,
  ];
  const specification = deepFreeze({
    cwd: materialRoot,
    cacheDirectory: cache,
    homeDirectory: home,
    installArguments,
    env: isolatedBaseEnvironment(home),
    expectedBunVersion: contract.producer.bunVersion,
    target: { platform, architecture },
  });
  let evidence;
  try { evidence = await defaultBunProcess(specification); } catch (error) { throw bounded(error, CODES.producer); }
  if (!plain(evidence) || evidence.kind !== 'real-external-bun-process' ||
      evidence.version !== contract.producer.bunVersion ||
      !['versionStdoutSha256', 'versionStderrSha256', 'installStdoutSha256', 'installStderrSha256']
        .every((key) => /^[0-9a-f]{64}$/.test(evidence[key]))) fail(CODES.producer);
  return deepFreeze({
    ...evidence,
    installArguments: contract.producer.installArguments,
    environmentPolicy: 'isolated-no-auth-proxy-hooks',
    integrityAuthority: 'fresh-bun-frozen-lockfile-registry-sri',
  });
}

function validateBuildInput(input) {
  const keys = [
    'sourceRoot', 'outputDirectory', 'platform', 'architecture', 'releaseSequence', 'signingKeyId',
    'nativeAddonPath', 'nativeManifestPath', 'nativeSignaturePath',
  ];
  try {
    if (!exact(input, keys)) fail(CODES.input);
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => descriptors[key]?.get !== undefined ||
        descriptors[key]?.set !== undefined || !Object.hasOwn(descriptors[key] ?? {}, 'value'))) fail(CODES.input);
    const value = Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
    if (![value.sourceRoot, value.outputDirectory, value.nativeAddonPath,
      value.nativeManifestPath, value.nativeSignaturePath].every(exactAbsolutePath) ||
        !TARGETS.has(`${value.platform}:${value.architecture}`) ||
        !Number.isSafeInteger(value.releaseSequence) || value.releaseSequence < 1 ||
        typeof value.signingKeyId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.signingKeyId) ||
        sameOrInside(value.sourceRoot, value.outputDirectory) ||
        sameOrInside(value.outputDirectory, value.sourceRoot)) fail(CODES.input);
    return Object.freeze(value);
  } catch (error) {
    throw bounded(error, CODES.input);
  }
}

async function prepareOutputDirectory(path) {
  try {
    const parent = dirname(path);
    const parentFacts = await lstat(parent);
    const canonicalParent = await realpath(parent);
    if (!parentFacts.isDirectory() || parentFacts.isSymbolicLink() || canonicalParent !== parent) fail(CODES.output);
  } catch (error) {
    throw bounded(error, CODES.output);
  }
  try {
    await lstat(path);
    fail(CODES.output);
  } catch (error) {
    if (error instanceof ServiceReleaseError) throw error;
    if (error?.code !== 'ENOENT') fail(CODES.output);
  }
  try {
    await mkdir(path, { recursive: false, mode: 0o700 });
    const named = await lstat(path, { bigint: true });
    const canonical = await realpath(path);
    if (!named.isDirectory() || canonical !== path) fail(CODES.output);
    return Object.freeze({ dev: named.dev, ino: named.ino });
  } catch (error) {
    throw bounded(error, CODES.output);
  }
}

async function outputDirectoryMatches(path, identity) {
  try {
    const named = await lstat(path, { bigint: true });
    return named.isDirectory() && await realpath(path) === path &&
      named.dev === identity.dev && named.ino === identity.ino;
  } catch {
    return false;
  }
}

async function assertOutputDirectory(path, identity) {
  if (!await outputDirectoryMatches(path, identity)) fail(CODES.output);
}

async function verifyNativeInputs({
  input,
  materialRoot,
  contract,
  sourceRecords,
  budget,
}) {
  const manifestBytes = await readRegularBytes(input.nativeManifestPath, PACKAGE_LIMIT, CODES.native);
  const signatureBytes = await readRegularBytes(input.nativeSignaturePath, NATIVE_SIGNATURE_LIMIT, CODES.native);
  const packageBytes = await readRegularBytes(join(materialRoot, 'native-control', 'package.json'), PACKAGE_LIMIT, CODES.native);
  const trustBytes = await readRegularBytes(join(materialRoot, ...contract.nativeControl.trustPath.split('/')), TRUST_LIMIT, CODES.native);
  let receipt;
  try {
    receipt = verifyPinnedNativeBuildManifest({
      manifestBytes,
      signatureBytes,
      packageBytes,
      bundledTrustBytes: trustBytes,
      platform: input.platform,
      architecture: input.architecture,
    });
  } catch {
    fail(CODES.native);
  }
  const injected = [
    [contract.nativeControl.manifestPath, input.nativeManifestPath, 'forbidden'],
    [contract.nativeControl.signaturePath, input.nativeSignaturePath, 'forbidden'],
    [contract.nativeControl.addonPath, input.nativeAddonPath, contract.nativeControl.executablePolicy],
  ];
  for (const [path, source, policy] of injected) {
    assertBundlePath(path, input.platform);
    const destination = join(materialRoot, ...path.split('/'));
    const maximum = path === contract.nativeControl.addonPath
      ? DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes
      : PACKAGE_LIMIT;
    const admittedSize = await admitRegularFile(source, maximum, budget, CODES.native);
    const copied = await copyRegularFile(source, destination, {
      maximum: admittedSize,
      mode: policy === 'required' ? 0o755 : 0o644,
    });
    sourceRecords.push(Object.freeze({ path, source: destination, executablePolicy: policy, ...copied }));
    if (path === contract.nativeControl.addonPath && copied.sha256 !== receipt.addonSha256) fail(CODES.native);
  }
  return Object.freeze({ receipt });
}

async function materializePayload({ payloadRoot, specs, platform }) {
  const records = [];
  const recordsByOwner = new Map();
  const copyBudget = payloadBudget();
  for (const spec of [...specs.values()].sort((left, right) => comparePath(left.path, right.path))) {
    if (spec.ownerKey === undefined) assertNoMutableSegments(spec.path);
    assertBundlePath(spec.path, platform);
    copyBudget.admit(spec.size, CODES.output);
    const mode = spec.executablePolicy === 'required' ? 0o755 : 0o644;
    const copied = await copyRegularFile(spec.source, join(payloadRoot, ...spec.path.split('/')), {
      maximum: spec.size,
      mode,
    });
    if ((spec.size !== undefined && copied.size !== spec.size) ||
        (spec.sha256 !== undefined && copied.sha256 !== spec.sha256)) fail(CODES.source);
    const record = Object.freeze({
      path: spec.path,
      size: copied.size,
      sha256: copied.sha256,
      executablePolicy: spec.executablePolicy,
      ...(spec.packageRelativePath === undefined ? {} : { packageRelativePath: spec.packageRelativePath }),
      ...(spec.bytes === undefined ? {} : { bytes: spec.bytes }),
    });
    records.push(record);
    if (spec.ownerKey) {
      if (!recordsByOwner.has(spec.ownerKey)) recordsByOwner.set(spec.ownerKey, []);
      recordsByOwner.get(spec.ownerKey).push(record);
    }
  }
  const copied = copyBudget.snapshot();
  if (records.length !== copied.entries ||
      records.reduce((total, record) => total + record.size, 0) !== copied.bytes) {
    fail(CODES.output);
  }
  return { records, recordsByOwner };
}

async function writeArchive(payloadRoot, inventory, archivePath, contract) {
  let handle;
  const sha = createHash('sha256');
  const modes = new Map([
    [INVENTORY_PATH, 0o644],
    ...inventory.payloadEntries.map((record) => [
      record.path,
      record.executablePolicy === 'required' ? 0o755 : 0o644,
    ]),
  ]);
  let length = 0;
  try {
    handle = await open(archivePath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const archive = createTar({
      cwd: payloadRoot,
      gzip: { portable: true, level: contract.producer.archive.gzipLevel },
      portable: true,
      noMtime: true,
      strict: true,
      onWriteEntry(entry) {
        const mode = modes.get(entry.path);
        if (mode === undefined || entry.type !== 'File' || !entry.stat?.isFile()) {
          entry.destroy(new ServiceReleaseError(CODES.archive));
          return;
        }
        entry.stat.mode = (entry.stat.mode & ~0o7777) | mode;
      },
    }, [...modes.keys()]);
    let position = 0;
    for await (const value of archive) {
      const bytes = Buffer.from(value);
      length += bytes.length;
      if (!Number.isSafeInteger(length) || length > DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes) fail(CODES.archive);
      sha.update(bytes);
      let offset = 0;
      while (offset < bytes.length) {
        const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, position + offset);
        if (bytesWritten === 0) fail(CODES.archive);
        offset += bytesWritten;
      }
      position += bytes.length;
    }
    await handle.sync();
    if (length === 0) fail(CODES.archive);
    return Object.freeze({ byteLength: length, sha256: sha.digest('hex') });
  } catch (error) {
    throw bounded(error, CODES.archive);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { fail(CODES.archive); }
    }
  }
}

async function* fileChunks(path) {
  let handle;
  try {
    const named = await lstat(path, { bigint: true });
    if (!named.isFile() || named.size <= 0n ||
        named.size > BigInt(DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes)) fail(CODES.candidate);
    handle = await open(path, readOnlyNoFollowFlags());
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.dev !== named.dev || before.ino !== named.ino ||
        before.size !== named.size || before.mtimeNs !== named.mtimeNs ||
        before.ctimeNs !== named.ctimeNs) fail(CODES.candidate);
    const buffer = Buffer.allocUnsafe(CHUNK_BYTES);
    let position = 0;
    while (position < Number(before.size)) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, Number(before.size) - position),
        position,
      );
      if (bytesRead === 0) fail(CODES.candidate);
      position += bytesRead;
      yield Buffer.from(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino ||
        after.size !== before.size || after.mtimeNs !== before.mtimeNs ||
        after.ctimeNs !== before.ctimeNs) fail(CODES.candidate);
  } catch (error) {
    throw bounded(error, CODES.candidate);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { fail(CODES.candidate); }
    }
  }
}

function expectedCompatibility(contract, fingerprint) {
  return compatibilityFor(contract, fingerprint);
}

function archiveOwnRecords(inspection, root) {
  const prefix = `${root}/`;
  return inspection.files
    .filter((record) => {
      if (!record.path.startsWith(prefix)) return false;
      const local = record.path.slice(prefix.length);
      return local.length > 0 && local !== 'node_modules' &&
        !local.startsWith('node_modules/') && !local.includes('/node_modules/');
    })
    .map((record) => Object.freeze({
      ...record,
      packageRelativePath: record.path.slice(prefix.length),
    }));
}

async function buildArchiveClosure({ inspection, packageBytesByRoot, lock, contract, platform, architecture }) {
  let closure;
  try {
    closure = await resolveBunProductionClosure({
      lock,
      contract,
      platform,
      architecture,
      packageRoots: new Set(packageBytesByRoot.keys()),
      readPackageRoot: async (root) => {
        const packageBytes = packageBytesByRoot.get(root);
        if (!packageBytes) return null;
        return { realRoot: root, packageBytes };
      },
    });
  } catch (error) {
    fail(error?.code === 'SERVICE_PRODUCTION_LOCK_INVALID' ? CODES.lock : CODES.closure);
  }
  const { nodes, admittedRoots } = closure;
  const recordsByOwner = new Map([...nodes.values()].map((node) =>
    [node.key, archiveOwnRecords(inspection, node.root)]));
  for (const root of packageBytesByRoot.keys()) if (!admittedRoots.has(root)) fail(CODES.closure);
  const ownedPaths = new Set(['package.json', 'bun.lock']);
  for (const records of recordsByOwner.values()) {
    for (const record of records) {
      if (ownedPaths.has(record.path)) fail(CODES.closure);
      ownedPaths.add(record.path);
    }
  }
  for (const record of inspection.files) {
    if (record.path !== INVENTORY_PATH && !ownedPaths.has(record.path)) fail(CODES.closure);
  }
  return { nodes, recordsByOwner };
}

async function captureCandidateEvidence({ archivePath, manifest, inspection, contract }) {
  const wanted = new Map([
    [contract.nativeControl.manifestPath, { maximum: PACKAGE_LIMIT, chunks: [], size: 0, code: CODES.native }],
    [contract.nativeControl.signaturePath, { maximum: NATIVE_SIGNATURE_LIMIT, chunks: [], size: 0, code: CODES.native }],
    ['package.json', { maximum: PACKAGE_LIMIT, chunks: [], size: 0, code: CODES.closure }],
    ['native-control/package.json', { maximum: PACKAGE_LIMIT, chunks: [], size: 0, code: CODES.native }],
    [contract.nativeControl.applicationTrustPath, { maximum: TRUST_LIMIT, chunks: [], size: 0, code: CODES.candidate }],
    [contract.nativeControl.shawlTrustPath, { maximum: TRUST_LIMIT, chunks: [], size: 0, code: CODES.candidate }],
    [contract.nativeControl.trustPath, { maximum: TRUST_LIMIT, chunks: [], size: 0, code: CODES.native }],
    ['bun.lock', { maximum: LOCK_LIMIT, chunks: [], size: 0, code: CODES.lock }],
  ]);
  const sdkContentSuffixes = [
    '/src/config/config-schema-version.ts',
    '/src/session/session-manager.ts',
  ];
  for (const record of inspection.files) {
    if (bunPackageRootForPath(record.path) !== null && !wanted.has(record.path)) {
      wanted.set(record.path, { maximum: PACKAGE_LIMIT, chunks: [], size: 0, code: CODES.closure });
    }
    if (sdkContentSuffixes.some((suffix) => record.path.endsWith(suffix)) &&
        !wanted.has(record.path)) {
      wanted.set(record.path, { maximum: SOURCE_FILE_LIMIT, chunks: [], size: 0, code: CODES.sdk });
    }
  }
  let capturedBytes = 0;
  const addonHash = createHash('sha256');
  let addonBytes = 0;
  await consumeApplicationArchive({
    chunks: fileChunks(archivePath),
    manifest,
    inspection,
    async onFile(record, byteChunks) {
      const capture = wanted.get(record.path);
      for await (const bytes of byteChunks) {
        if (capture) {
          capture.size += bytes.length;
          capturedBytes += bytes.length;
          if (capture.size > capture.maximum) fail(capture.code);
          if (capturedBytes > contract.limits.packageMetadataBytes) fail(CODES.closure);
          capture.chunks.push(Buffer.from(bytes));
        }
        if (record.path === contract.nativeControl.addonPath) {
          addonBytes += bytes.length;
          addonHash.update(bytes);
        }
      }
    },
  });
  for (const capture of wanted.values()) if (capture.size === 0) fail(capture.code);
  const values = new Map([...wanted].map(([path, capture]) =>
    [path, Buffer.concat(capture.chunks, capture.size)]));
  let receipt;
  try {
    receipt = verifyPinnedNativeBuildManifest({
      manifestBytes: values.get(contract.nativeControl.manifestPath),
      signatureBytes: values.get(contract.nativeControl.signaturePath),
      packageBytes: values.get('native-control/package.json'),
      bundledTrustBytes: values.get(contract.nativeControl.trustPath),
      platform: manifest.target.platform,
      architecture: manifest.target.architecture,
    });
  } catch {
    fail(CODES.native);
  }
  if (addonBytes === 0 || addonHash.digest('hex') !== receipt.addonSha256 ||
      receipt.manifestFingerprint !== manifest.nativeControl.manifestFingerprint) fail(CODES.native);
  return Object.freeze({ values });
}

// Signed Windows service guard metadata: the static closure of the guard as
// the release runtime resolves it (package aliases under root node_modules),
// never the source-tree paths. Component-local aliases would shadow the
// declared guard for one entrypoint, so they are refused.
export function windowsServiceBootstrapMetadata(payloadEntries) {
  const byPath = new Map(payloadEntries.map((entry) => [entry.path, entry]));
  for (const entry of payloadEntries) {
    if (/^(?:bot|daemon)\/(?:src\/)?node_modules\/(?:@gjc-remote\/(?:native-control|shared)|dotenv)\//.test(entry.path)) fail(CODES.native);
  }
  const guardDirectory = `${NATIVE_ALIAS}/src`;
  const resolvePackage = (name) => {
    const segments = guardDirectory.split('/');
    for (let length = segments.length; length >= 0; length -= 1) {
      if (length > 0 && segments[length - 1] === 'node_modules') continue;
      const base = [...segments.slice(0, length), 'node_modules', name].join('/');
      if (byPath.has(`${base}/package.json`)) return base;
    }
    fail(CODES.native);
  };
  const roots = [
    ['native-control/', `${NATIVE_ALIAS}/`],
    ['shared/', `${resolvePackage('@gjc-remote/shared')}/`],
    ['node_modules/dotenv/', `${resolvePackage('dotenv')}/`],
  ];
  const staticClosure = SERVICE_BOOTSTRAP_STATIC_CLOSURE.map((sourcePath) => {
    const root = roots.find(([prefix]) => sourcePath.startsWith(prefix));
    if (!root) fail(CODES.native);
    const relativePath = `${root[1]}${sourcePath.slice(root[0].length)}`;
    const record = byPath.get(relativePath);
    if (!record) fail(CODES.native);
    return { relativePath, sha256: record.sha256 };
  }).sort((left, right) => utf8Compare(left.relativePath, right.relativePath));
  return {
    schemaVersion: 1,
    guardPath: `${guardDirectory}/service-bootstrap.js`,
    staticClosure,
    staticClosureFingerprint: windowsServiceBootstrapClosureFingerprint(staticClosure),
    runtimePolicies: {
      bot: { ...WINDOWS_SERVICE_BOOTSTRAP_RUNTIME_POLICIES.bot },
      daemon: { ...WINDOWS_SERVICE_BOOTSTRAP_RUNTIME_POLICIES.daemon },
    },
    externalBunConfig: { ...WINDOWS_SERVICE_BOOTSTRAP_EXTERNAL_BUN_CONFIG },
  };
}

function verifyNativeAliases(inspection, platform) {
  const byPath = new Map(inspection.files.map((record) => [record.path, record]));
  const root = new Map();
  for (const record of inspection.files) {
    if (!record.path.startsWith('native-control/')) continue;
    const relativePath = record.path.slice('native-control/'.length);
    if (relativePath.length === 0 || relativePath === 'node_modules' ||
        relativePath.startsWith('node_modules/')) continue;
    root.set(relativePath, record);
  }
  const aliasSegments = ['node_modules', '@gjc-remote', 'native-control'];
  const foldedMarker = aliasSegments.map((segment) => segment.toLowerCase().toUpperCase());
  const aliases = new Map();
  for (const record of inspection.files) {
    const segments = record.path.split('/');
    for (let index = 0; index <= segments.length - aliasSegments.length; index += 1) {
      const candidate = segments.slice(index, index + aliasSegments.length);
      const exactAlias = candidate.every((segment, offset) => segment === aliasSegments[offset]);
      if (platform === 'win32') {
        const foldedAlias = candidate.every((segment, offset) =>
          segment.toLowerCase().toUpperCase() === foldedMarker[offset]);
        if (foldedAlias && !exactAlias) fail(CODES.native);
      }
      if (!exactAlias) continue;
      const prefix = segments.slice(0, index + aliasSegments.length).join('/');
      aliases.set(prefix, aliases.get(prefix) ?? 0);
      const relativeSegments = segments.slice(index + aliasSegments.length);
      if (relativeSegments.length === 0) fail(CODES.native);
      if (relativeSegments[0] === 'node_modules') continue;
      const relativePath = relativeSegments.join('/');
      const rootRecord = root.get(relativePath);
      if (!rootRecord || record.size !== rootRecord.size ||
          record.sha256 !== rootRecord.sha256 ||
          record.executablePolicy !== rootRecord.executablePolicy) fail(CODES.native);
      aliases.set(prefix, aliases.get(prefix) + 1);
    }
  }
  if (root.size === 0 || !aliases.has(NATIVE_ALIAS)) fail(CODES.native);
  for (const count of aliases.values()) if (count !== root.size) fail(CODES.native);
  const addon = byPath.get('native-control/build/Release/native_control.node');
  if (!addon || addon.executablePolicy !== 'required') fail(CODES.native);
}

function candidateAssetNames(contract, platform, architecture) {
  return Object.freeze({
    manifest: `gjc-remote-service-${platform}-${architecture}.manifest.json`,
    archive: `gjc-remote-service-${contract.releaseVersion}-${platform}-${architecture}.tar.gz`,
  });
}

export async function verifyUnsignedServiceRelease(input = {}) {
  let candidateDirectory;
  try {
    if (!exact(input, ['candidateDirectory'])) fail(CODES.input);
    const descriptor = Object.getOwnPropertyDescriptor(input, 'candidateDirectory');
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, 'value') || !exactAbsolutePath(descriptor.value)) fail(CODES.input);
    candidateDirectory = descriptor.value;
  } catch (error) {
    throw bounded(error, CODES.input);
  }
  const contract = await loadServiceReleaseContract();
  let entries;
  try {
    const rootFacts = await lstat(candidateDirectory);
    if (!rootFacts.isDirectory() || rootFacts.isSymbolicLink() ||
        await realpath(candidateDirectory) !== candidateDirectory) fail(CODES.candidate);
    entries = await readDirectoryBounded(candidateDirectory, 2, CODES.candidate);
  } catch (error) {
    throw bounded(error, CODES.candidate);
  }
  if (entries.length !== 2 || entries.some((entry) => !entry.isFile() || entry.isSymbolicLink())) fail(CODES.candidate);
  const manifestEntry = entries.find((entry) => /^gjc-remote-service-(linux-(?:x64|arm64)|win32-x64)\.manifest\.json$/.test(entry.name));
  if (!manifestEntry) fail(CODES.candidate);
  const manifestPath = join(candidateDirectory, manifestEntry.name);
  let manifest;
  try {
    const bytes = await readRegularBytes(manifestPath, DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, CODES.candidate);
    manifest = parseCanonicalJsonBytes(bytes, { maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, maxDepth: 32, maxNodes: 10_000 });
    validateApplicationDeploymentManifest(manifest);
  } catch (error) {
    throw bounded(error, CODES.candidate);
  }
  if (manifest.releaseVersion !== contract.releaseVersion || manifest.releaseId !== contract.releaseTag ||
      manifest.source.repository !== contract.repository || !TARGETS.has(`${manifest.target.platform}:${manifest.target.architecture}`) ||
      canonicalJsonHash(manifest.entrypoints) !== canonicalJsonHash(contract.entrypoints) ||
      canonicalJsonHash(manifest.runtimes) !== canonicalJsonHash(contract.runtimes) ||
      manifest.nativeControl.manifestPath !== contract.nativeControl.manifestPath ||
      manifest.nativeControl.contractVersion !== contract.nativeControl.contractVersion ||
      manifest.nativeControl.contractRevision !== contract.nativeControl.contractRevision ||
      canonicalJsonHash(manifest.wireCapabilities) !== canonicalJsonHash(contract.wireCapabilities)) fail(CODES.candidate);
  const expected = candidateAssetNames(contract, manifest.target.platform, manifest.target.architecture);
  if (manifestEntry.name !== expected.manifest || manifest.archive.name !== expected.archive ||
      !entries.some((entry) => entry.name === expected.archive)) fail(CODES.candidate);
  const archivePath = join(candidateDirectory, expected.archive);
  const expectedCompat = expectedCompatibility(contract, manifest.compatibility.roles.daemon.sdkExternalStateContractFingerprint);
  if (canonicalJsonHash(expectedCompat) !== canonicalJsonHash(manifest.compatibility)) fail(CODES.candidate);
  let inspection;
  try {
    inspection = await inspectApplicationArchive({ chunks: fileChunks(archivePath), manifest });
    verifyNativeAliases(inspection, manifest.target.platform);
    const evidence = await captureCandidateEvidence({ archivePath, manifest, inspection, contract });
    const lockBytes = evidence.values.get('bun.lock');
    if (hashBytes(lockBytes) !== manifest.source.bunLockSha256) fail(CODES.lock);
    const lock = parseBunProductionLock(lockBytes);
    const packageBytesByRoot = new Map();
    for (const [path, bytes] of evidence.values) {
      const root = bunPackageRootForPath(path);
      if (root !== null) packageBytesByRoot.set(root, bytes);
    }
    const closure = await buildArchiveClosure({
      inspection,
      packageBytesByRoot,
      lock,
      contract,
      platform: manifest.target.platform,
      architecture: manifest.target.architecture,
    });
    const sdk = await sdkContractFor({
      nodes: closure.nodes,
      recordsByOwner: closure.recordsByOwner,
      contract,
      readRecordBytes(record) {
        const bytes = evidence.values.get(record.path);
        if (!bytes) fail(CODES.sdk);
        return bytes;
      },
    });
    if (sdk.sdkContract.sdkExternalStateContractFingerprint !==
        manifest.compatibility.roles.daemon.sdkExternalStateContractFingerprint) fail(CODES.sdk);
    const rootPackage = parsePackage(evidence.values.get('package.json'), CODES.candidate);
    if (rootPackage.name !== 'gjc-remote' || rootPackage.version !== contract.releaseVersion ||
        JSON.stringify(rootPackage.workspaces) !== JSON.stringify(SOURCE_WORKSPACES)) fail(CODES.candidate);
    const finalEntries = await readDirectoryBounded(
      candidateDirectory,
      2,
      CODES.candidate,
    );
    if (finalEntries.length !== 2 || finalEntries.some((entry) =>
      !entry.isFile() || entry.isSymbolicLink() ||
      ![expected.manifest, expected.archive].includes(entry.name))) fail(CODES.candidate);
  } catch (error) {
    throw bounded(error, error instanceof ServiceReleaseError ? error.code : CODES.archive);
  }
  return deepFreeze({
    schemaVersion: 1,
    kind: 'unsigned-service-release-verification-receipt',
    unsigned: true,
    signatureGenerated: false,
    manifestFingerprint: manifest.manifestFingerprint,
    archiveSha256: manifest.archive.sha256,
    treeFingerprint: manifest.inventory.treeFingerprint,
    sdkExternalStateContractFingerprint: manifest.compatibility.roles.daemon.sdkExternalStateContractFingerprint,
    platform: manifest.target.platform,
    architecture: manifest.target.architecture,
    entryCount: inspection.entryCount,
  });
}

export async function buildUnsignedServiceRelease(input) {
  input = validateBuildInput(input);
  // NTFS/Bun materialization does not retain authoritative POSIX mode bits for
  // non-bin package helpers. Refuse before creating scratch/output state or
  // invoking Git/Bun rather than emitting host-dependent Linux policy.
  if (process.platform === 'win32' && input.platform === 'linux') {
    fail(CODES.producer);
  }
  try {
    for (const path of [
      input.sourceRoot,
      input.nativeAddonPath,
      input.nativeManifestPath,
      input.nativeSignaturePath,
    ]) {
      if (await realpath(path) !== path) fail(CODES.path);
    }
  } catch (error) {
    throw bounded(error, CODES.path);
  }
  const contract = await loadServiceReleaseContract();
  let scratchCreated;
  let scratch;
  try {
    scratchCreated = await mkdtemp(join(tmpdir(), 'gjc-service-release-build-'));
    scratch = await realpath(scratchCreated);
  } catch {
    if (scratchCreated) {
      try { await rm(scratchCreated, { recursive: true, force: true }); } catch { /* private temporary material only */ }
    }
    fail(CODES.output);
  }
  const materialRoot = join(scratch, 'material');
  const payloadRoot = join(scratch, 'payload');
  let outputIdentity = null;
  try {
    await mkdir(materialRoot, { recursive: false, mode: 0o700 });
    await mkdir(payloadRoot, { recursive: false, mode: 0o700 });
    const git = await inspectGitSource(input.sourceRoot, contract, scratch);
    const rootPackageBytes = await readRegularBytes(join(input.sourceRoot, 'package.json'), PACKAGE_LIMIT, CODES.source);
    const rootPackage = parsePackage(rootPackageBytes, CODES.source);
    if (rootPackage.name !== 'gjc-remote' || rootPackage.version !== contract.releaseVersion ||
        JSON.stringify(rootPackage.workspaces) !== JSON.stringify(SOURCE_WORKSPACES)) fail(CODES.source);
    const materialBudget = payloadBudget();
    const sourceRecords = await copyGitSources(
      input.sourceRoot,
      materialRoot,
      git,
      contract,
      input.platform,
      materialBudget,
    );
    const lockBytes = await readRegularBytes(join(materialRoot, 'bun.lock'), LOCK_LIMIT, CODES.lock);
    const lock = parseBunProductionLock(lockBytes);
    const native = await verifyNativeInputs({
      input,
      materialRoot,
      contract,
      sourceRecords,
      budget: materialBudget,
    });
    const producerEvidence = await materializeWithBun({
      materialRoot,
      scratch,
      platform: input.platform,
      architecture: input.architecture,
      contract,
    });
    const postInstallLockBytes = await readRegularBytes(
      join(materialRoot, 'bun.lock'),
      LOCK_LIMIT,
      CODES.producer,
    );
    if (!postInstallLockBytes.equals(lockBytes)) fail(CODES.producer);

    const specs = new Map();
    const discoveryBudget = payloadBudget();
    const addSpec = (spec) => {
      if (spec.path === INVENTORY_PATH || specs.has(spec.path) ||
          !Number.isSafeInteger(spec.size) || spec.size < 0) {
        fail(CODES.closure);
      }
      discoveryBudget.admit(spec.size, CODES.closure);
      specs.set(spec.path, spec);
    };
    for (const source of sourceRecords) addSpec({ ...source });
    const closure = await buildProductionClosure({
      materialRoot, lock, contract, platform: input.platform, architecture: input.architecture,
      sourceRecords, addSpec,
    });
    const materialized = await materializePayload({ payloadRoot, specs, platform: input.platform });
    const sdk = await sdkContractFor({
      nodes: closure.nodes,
      recordsByOwner: materialized.recordsByOwner,
      contract,
      readRecordBytes: (record) =>
        readRegularBytes(join(payloadRoot, ...record.path.split('/')), SOURCE_FILE_LIMIT, CODES.sdk),
    });
    const inventory = buildBundleInventory({
      payloadEntries: materialized.records.map(({ path, size, sha256, executablePolicy }) => ({
        path, size, sha256, executablePolicy,
      })),
    }, { platform: input.platform });
    const inventoryBytes = canonicalJsonBytes(inventory, {
      maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
      maxDepth: 16,
      maxNodes: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries * 6 + 32,
    });
    await writeExclusive(join(payloadRoot, INVENTORY_PATH), inventoryBytes, 0o644);

    await revalidateGitSource(input.sourceRoot, git, contract);
    outputIdentity = await prepareOutputDirectory(input.outputDirectory);
    const names = candidateAssetNames(contract, input.platform, input.architecture);
    const archivePath = join(input.outputDirectory, names.archive);
    await assertOutputDirectory(input.outputDirectory, outputIdentity);
    const archive = await writeArchive(
      payloadRoot,
      inventory,
      archivePath,
      contract,
    );
    await assertOutputDirectory(input.outputDirectory, outputIdentity);
    const compatibility = compatibilityFor(contract, sdk.sdkContract.sdkExternalStateContractFingerprint);
    const manifest = buildApplicationDeploymentManifest({
      signingKeyId: input.signingKeyId,
      releaseId: contract.releaseTag,
      releaseVersion: contract.releaseVersion,
      releaseSequence: input.releaseSequence,
      source: {
        repository: contract.repository,
        tag: contract.releaseTag,
        commit: git.commit,
        tree: git.tree,
        bunLockSha256: lock.sha256,
      },
      target: { platform: input.platform, architecture: input.architecture },
      archive: {
        name: names.archive,
        mediaType: 'application/gzip',
        byteLength: archive.byteLength,
        sha256: archive.sha256,
        entryCount: inventory.payloadEntryCount + 1,
      },
      inventory: {
        path: INVENTORY_PATH,
        byteLength: inventoryBytes.length,
        sha256: hashBytes(inventoryBytes),
        payloadEntryCount: inventory.payloadEntryCount,
        unpackedPayloadBytes: inventory.unpackedPayloadBytes,
        treeFingerprint: inventory.treeFingerprint,
      },
      entrypoints: contract.entrypoints,
      runtimes: contract.runtimes,
      nativeControl: {
        manifestPath: contract.nativeControl.manifestPath,
        manifestFingerprint: native.receipt.manifestFingerprint,
        contractVersion: native.receipt.contractVersion,
        contractRevision: native.receipt.contractRevision,
      },
      wireCapabilities: contract.wireCapabilities,
      compatibility,
      ...(input.platform === 'win32'
        ? { windowsServiceBootstrap: windowsServiceBootstrapMetadata(inventory.payloadEntries) }
        : {}),
    });
    await assertOutputDirectory(input.outputDirectory, outputIdentity);
    await writeExclusive(join(input.outputDirectory, names.manifest), canonicalJsonBytes(manifest, {
      maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, maxDepth: 32, maxNodes: 10_000,
    }), 0o600);
    await assertOutputDirectory(input.outputDirectory, outputIdentity);
    const verification = await verifyUnsignedServiceRelease({ candidateDirectory: input.outputDirectory });
    await assertOutputDirectory(input.outputDirectory, outputIdentity);
    if (verification.manifestFingerprint !== manifest.manifestFingerprint ||
        verification.archiveSha256 !== manifest.archive.sha256 ||
        verification.treeFingerprint !== manifest.inventory.treeFingerprint) {
      fail(CODES.output);
    }
    await revalidateGitSource(input.sourceRoot, git, contract);
    return deepFreeze({
      schemaVersion: 1,
      kind: 'unsigned-service-release-build-receipt',
      unsigned: true,
      signatureGenerated: false,
      manifestFingerprint: verification.manifestFingerprint,
      archiveSha256: verification.archiveSha256,
      treeFingerprint: verification.treeFingerprint,
      sdkExternalStateContract: sdk.sdkContract,
      sdkClosureFingerprint: sdk.closureFingerprint,
      sdkClosurePackageCount: sdk.packageCount,
      nativeManifestFingerprint: native.receipt.manifestFingerprint,
      nativeAddonSha256: native.receipt.addonSha256,
      source: { repository: contract.repository, tag: contract.releaseTag, commit: git.commit, tree: git.tree, bunLockSha256: lock.sha256 },
      target: { platform: input.platform, architecture: input.architecture },
      producerEvidence,
      limits: contract.limits,
      payloadEntryCount: inventory.payloadEntryCount,
      unpackedPayloadBytes: inventory.unpackedPayloadBytes,
    });
  } catch (error) {
    if (outputIdentity !== null &&
        await outputDirectoryMatches(input.outputDirectory, outputIdentity)) {
      try {
        await rm(input.outputDirectory, { recursive: true, force: true });
      } catch {
        throw new ServiceReleaseError(CODES.output);
      }
    }
    throw bounded(error, CODES.output);
  } finally {
    try {
      await rm(scratch, { recursive: true, force: true });
    } catch {
      throw new ServiceReleaseError(CODES.output);
    }
  }
}

function parseCli(argv) {
  if (!Array.isArray(argv) || argv.length === 0) fail(CODES.input);
  const command = argv[0];
  const expected = command === 'build'
    ? ['--source', '--output', '--platform', '--architecture', '--release-sequence', '--signing-key-id', '--native-addon', '--native-manifest', '--native-signature']
    : command === 'verify' ? ['--candidate'] : null;
  if (!expected || argv.length !== 1 + expected.length * 2) fail(CODES.input);
  const values = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!expected.includes(flag) || values.has(flag) || typeof value !== 'string' || value.length === 0 || value.startsWith('--')) fail(CODES.input);
    values.set(flag, value);
  }
  if (values.size !== expected.length) fail(CODES.input);
  if (command === 'verify') return { command, input: { candidateDirectory: values.get('--candidate') } };
  const sequenceText = values.get('--release-sequence');
  if (!/^[1-9][0-9]*$/.test(sequenceText)) fail(CODES.input);
  return {
    command,
    input: {
      sourceRoot: values.get('--source'),
      outputDirectory: values.get('--output'),
      platform: values.get('--platform'),
      architecture: values.get('--architecture'),
      releaseSequence: Number(sequenceText),
      signingKeyId: values.get('--signing-key-id'),
      nativeAddonPath: values.get('--native-addon'),
      nativeManifestPath: values.get('--native-manifest'),
      nativeSignaturePath: values.get('--native-signature'),
    },
  };
}

export async function runServiceReleaseCli(argv = process.argv.slice(2)) {
  const parsed = parseCli(argv);
  return parsed.command === 'build'
    ? buildUnsignedServiceRelease(parsed.input)
    : verifyUnsignedServiceRelease(parsed.input);
}

const isMain = (() => {
  if (!process.argv[1] || process.argv[1] === '-') return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return true;
  }
})();

if (isMain) {
  try {
    const receipt = await runServiceReleaseCli();
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    const refusal = bounded(error, CODES.output);
    process.stderr.write(`${JSON.stringify({
      schemaVersion: 1,
      kind: 'unsigned-service-release-refusal',
      code: refusal.code,
      writes: 0,
    })}\n`);
    process.exitCode = 1;
  }
}
