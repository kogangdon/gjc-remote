import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test, { after } from 'node:test';
import { gzipSync } from 'node:zlib';
import { Header } from 'tar';
import {
  APPLICATION_BUNDLE_INVENTORY_PATH,
  SHAWL_UPSTREAM,
  buildApplicationDeploymentManifest,
  buildBundleInventory,
  buildDeploymentCompatibility,
  buildShawlDeploymentManifest,
} from '@gjc-remote/shared/deployment-envelope';
import {
  buildServiceCandidateProof,
  buildServiceFinalProof,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceTransaction,
  buildServiceTransitionProof,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import {
  canonicalJsonBytes,
  canonicalJsonHash,
  parseCanonicalJsonBytes,
} from '@gjc-remote/shared/strict-json';
import {
  capabilities,
  capabilitySignatures,
  contractRevision,
} from '../src/capabilities.js';
import * as publicApi from '../src/public.js';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';

// These tests compose the genuine isolated deployment/native signature verifiers,
// real tar parser, and real offline source with modeled read-only native, session,
// and artifact-access boundaries. They are not evidence for a real service store,
// native artifact root, filesystem ACL/durability, network, TLS, or host mutation.
const installation = await createPinnedDeploymentInstallation({
  keyIds: ['deployment-test'],
  includeAcquisition: true,
});
after(() => installation.dispose());

const BLOCK_BYTES = 512;
const TAR_END = Buffer.alloc(BLOCK_BYTES * 2);
const INVENTORY_LIMITS = Object.freeze({
  maxBytes: 32 * 1024 * 1024,
  maxDepth: 16,
  maxNodes: 600_032,
});
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function compatibility() {
  return buildDeploymentCompatibility({
    bot: {
      domains: [{
        domain: 'bot-mapping-reader',
        readableFormats: ['mapping-v1'],
        writableFormats: ['mapping-v1'],
      }],
    },
    daemon: {
      domains: [
        {
          domain: 'daemon-app-session',
          readableFormats: ['session-v1'],
          writableFormats: ['session-v1'],
        },
        {
          domain: 'workspace-lifecycle',
          readableFormats: ['workspace-v1'],
          writableFormats: ['workspace-v1'],
        },
      ],
      sdkExternalStateContractFingerprint: '9'.repeat(64),
    },
  });
}

function tarHeader(path, size, executablePolicy) {
  const header = new Header({
    path,
    mode: executablePolicy === 'required' ? 0o755 : 0o644,
    uid: 0,
    gid: 0,
    size,
    mtime: new Date(0),
    type: 'File',
    linkpath: '',
    uname: '',
    gname: '',
    devmaj: 0,
    devmin: 0,
  });
  header.encode();
  return Buffer.from(header.block);
}

function tarEntry(record) {
  const padding = Buffer.alloc((BLOCK_BYTES - (record.bytes.length % BLOCK_BYTES)) % BLOCK_BYTES);
  return Buffer.concat([
    tarHeader(record.path, record.bytes.length, record.executablePolicy),
    record.bytes,
    padding,
  ]);
}

function portableGzip(bytes) {
  const archive = Buffer.from(gzipSync(bytes, { level: 6 }));
  archive[9] = 255;
  return archive;
}

function nativePackageBytes() {
  return canonicalJsonBytes({
    name: '@gjc-remote/native-control',
    version: '1.0.0',
    nativeControlContract: {
      version: 4,
      revision: contractRevision,
      napi: 8,
      platforms: ['linux-x64', 'linux-arm64', 'win32-x64'],
    },
  });
}

function nativeManifestBytes(addonBytes, platform, architecture, claimedAddon = addonBytes) {
  return canonicalJsonBytes({
    contractVersion: 4,
    contractRevision,
    package: '@gjc-remote/native-control',
    version: '1.0.0',
    napi: 8,
    platform,
    arch: architecture,
    addon: 'native_control.node',
    sha256: sha256(claimedAddon),
    capabilities,
    capabilitySignatures,
  });
}

function releasePaths(platform) {
  const root = platform === 'win32' ? 'C:\\modeled-acquisition' : '/modeled-acquisition';
  const join = (name) => platform === 'win32' ? `${root}\\${name}` : `${root}/${name}`;
  return Object.freeze({
    applicationManifestPath: join('application.manifest.json'),
    applicationSignaturePath: join('application.manifest.json.sig'),
    applicationArchivePath: join('application.tar.gz'),
    shawlManifestPath: platform === 'win32' ? join('shawl.manifest.json') : null,
    shawlSignaturePath: platform === 'win32' ? join('shawl.manifest.json.sig') : null,
    shawlExecutablePath: platform === 'win32' ? join('shawl.exe') : null,
  });
}

function buildRelease({
  platform = 'linux',
  architecture = 'x64',
  omit = [],
  invalidArchive = false,
  nativeAddonMismatch = false,
  bundledTrustMismatch = false,
  addonExecutablePolicy = 'required',
  omitPrimaryAlias = false,
  corruptPrimaryAlias = false,
  corruptNestedAlias = false,
  extraPrimaryAliasFile = false,
  windowsFoldedPrimaryAlias = false,
  aliasMarkerFile = false,
  nodeModulesOnlyShadowAlias = false,
  applicationSequence = 7,
  shawlSequence = 3,
} = {}) {
  const releaseVersion = '1.2.3';
  const addonBytes = Buffer.from(`modeled-${platform}-${architecture}-native-addon`);
  const claimedAddon = nativeAddonMismatch
    ? Buffer.from(`different-${platform}-${architecture}-native-addon`)
    : addonBytes;
  const manifestBytes = nativeManifestBytes(
    addonBytes,
    platform,
    architecture,
    claimedAddon,
  );
  const signatureBytes = installation.signNativeManifest(manifestBytes);
  let bundledTrustBytes = Buffer.from(installation.bundledNativeTrustBytes);
  if (bundledTrustMismatch) {
    bundledTrustBytes = Buffer.from(
      bundledTrustBytes.toString('utf8').replace('fixture-native-key', 'different-native-id'),
    );
  }
  const nativeRoot = [
    {
      path: 'native-control/package.json',
      bytes: nativePackageBytes(),
      executablePolicy: 'forbidden',
    },
    {
      path: 'native-control/build/Release/native-control.manifest.json',
      bytes: manifestBytes,
      executablePolicy: 'forbidden',
    },
    {
      path: 'native-control/build/Release/native-control.manifest.json.sig',
      bytes: signatureBytes,
      executablePolicy: 'forbidden',
    },
    {
      path: 'native-control/build/Release/native_control.node',
      bytes: addonBytes,
      executablePolicy: addonExecutablePolicy,
    },
    {
      path: 'native-control/release-keys/trusted.json',
      bytes: bundledTrustBytes,
      executablePolicy: 'forbidden',
    },
  ];
  const primaryPrefix = windowsFoldedPrimaryAlias
    ? 'Node_Modules/@gjc-remote/native-control'
    : 'node_modules/@gjc-remote/native-control';
  const aliasRecord = (prefix, record) => {
    const relative = record.path.slice('native-control/'.length);
    const corrupt =
      ((corruptPrimaryAlias && prefix === primaryPrefix) ||
        (corruptNestedAlias && prefix.startsWith('daemon/'))) &&
      relative === 'package.json';
    return {
      path: `${prefix}/${relative}`,
      bytes: corrupt
        ? Buffer.concat([record.bytes, Buffer.from(' ')])
        : Buffer.from(record.bytes),
      executablePolicy: record.executablePolicy,
    };
  };
  const payload = [
    {
      path: 'bot/src/bot.js',
      bytes: Buffer.from('export const bot = true;\n'),
      executablePolicy: 'required',
    },
    {
      path: 'daemon/src/daemon.js',
      bytes: Buffer.from('export const daemon = true;\n'),
      executablePolicy: 'required',
    },
    ...nativeRoot,
    ...(!omitPrimaryAlias
      ? nativeRoot.map((record) => aliasRecord(primaryPrefix, record))
      : []),
    ...(extraPrimaryAliasFile ? [{
      path: `${primaryPrefix}/extra-runtime-file.js`,
      bytes: Buffer.from('extra primary alias file\n'),
      executablePolicy: 'forbidden',
    }] : []),
    ...nativeRoot.map((record) => aliasRecord(
      'daemon/node_modules/@gjc-remote/native-control',
      record,
    )),
    {
      path: 'native-control/node_modules/modeled-dependency/index.js',
      bytes: Buffer.from('root nested dependency is outside alias equality\n'),
      executablePolicy: 'forbidden',
    },
    {
      path: `${primaryPrefix}/node_modules/modeled-dependency/index.js`,
      bytes: Buffer.from('primary nested dependency may differ\n'),
      executablePolicy: 'forbidden',
    },
    {
      path: 'daemon/node_modules/@gjc-remote/native-control/node_modules/modeled-dependency/index.js',
      bytes: Buffer.from('nested alias dependency may differ\n'),
      executablePolicy: 'forbidden',
    },
    ...(aliasMarkerFile ? [{
      path: 'shadow-marker/node_modules/@gjc-remote/native-control',
      bytes: Buffer.from('alias marker is a regular file\n'),
      executablePolicy: 'forbidden',
    }] : []),
    ...(nodeModulesOnlyShadowAlias ? [{
      path: 'shadow-node-modules/node_modules/@gjc-remote/native-control/node_modules/decoy/index.js',
      bytes: Buffer.from('node_modules-only shadow alias\n'),
      executablePolicy: 'forbidden',
    }] : []),
  ].filter((record) => !omit.includes(record.path));
  const inventory = buildBundleInventory({
    payloadEntries: payload.map((record) => ({
      path: record.path,
      size: record.bytes.length,
      sha256: sha256(record.bytes),
      executablePolicy: record.executablePolicy,
    })),
  }, { platform });
  const inventoryBytes = canonicalJsonBytes(inventory, INVENTORY_LIMITS);
  const inventoryRecord = {
    path: APPLICATION_BUNDLE_INVENTORY_PATH,
    bytes: inventoryBytes,
    executablePolicy: 'forbidden',
  };
  const tarBytes = Buffer.concat([
    tarEntry(inventoryRecord),
    ...payload.map(tarEntry),
    TAR_END,
  ]);
  const archiveBytes = invalidArchive
    ? portableGzip(Buffer.from('not a tar archive'))
    : portableGzip(tarBytes);
  const application = buildApplicationDeploymentManifest({
    signingKeyId: 'deployment-test',
    releaseId: `v${releaseVersion}`,
    releaseVersion,
    releaseSequence: applicationSequence,
    source: {
      repository: 'kogangdon/gjc-remote',
      tag: `v${releaseVersion}`,
      commit: 'a'.repeat(40),
      tree: 'b'.repeat(40),
      bunLockSha256: 'c'.repeat(64),
    },
    target: { platform, architecture },
    archive: {
      name: `gjc-remote-service-${releaseVersion}-${platform}-${architecture}.tar.gz`,
      mediaType: 'application/gzip',
      byteLength: archiveBytes.length,
      sha256: sha256(archiveBytes),
      entryCount: inventory.payloadEntryCount + 1,
    },
    inventory: {
      path: APPLICATION_BUNDLE_INVENTORY_PATH,
      byteLength: inventoryBytes.length,
      sha256: sha256(inventoryBytes),
      payloadEntryCount: inventory.payloadEntryCount,
      unpackedPayloadBytes: inventory.unpackedPayloadBytes,
      treeFingerprint: inventory.treeFingerprint,
    },
    entrypoints: {
      bot: 'bot/src/bot.js',
      daemon: 'daemon/src/daemon.js',
    },
    runtimes: {
      node: { minimumVersion: '26.0.0' },
      bun: { minimumVersion: '1.4.0' },
    },
    nativeControl: {
      manifestPath: 'native-control/build/Release/native-control.manifest.json',
      manifestFingerprint: sha256(manifestBytes),
      contractVersion: 4,
      contractRevision,
    },
    wireCapabilities: ['gate_presentation_v1'],
    compatibility: compatibility(),
  });
  const signedApplication = installation.signManifest(application);

  const shawlBytes = platform === 'win32'
    ? Buffer.from('modeled Shawl 1.9.0 executable')
    : null;
  const shawl = platform === 'win32' ? buildShawlDeploymentManifest({
    signingKeyId: 'deployment-test',
    releaseSequence: shawlSequence,
    target: { platform: 'win32', architecture: 'x64' },
    upstream: {
      repository: SHAWL_UPSTREAM.repository,
      tag: SHAWL_UPSTREAM.tag,
      commit: SHAWL_UPSTREAM.commit,
      assetId: 410957225,
      assetName: 'shawl-v1.9.0-win64.zip',
      zipSha256: 'd'.repeat(64),
    },
    executable: {
      name: 'shawl.exe',
      byteLength: shawlBytes.length,
      sha256: sha256(shawlBytes),
      version: SHAWL_UPSTREAM.version,
      versionOutput: `shawl ${SHAWL_UPSTREAM.version}`,
      authenticode: 'unsigned',
    },
    projectAsset: {
      repository: 'kogangdon/gjc-remote',
      tag: `v${releaseVersion}`,
      name: 'gjc-remote-shawl-win32-x64.exe',
    },
  }) : null;
  const signedShawl = shawl === null ? null : installation.signManifest(shawl);
  const paths = releasePaths(platform);
  const files = new Map([
    [paths.applicationManifestPath, signedApplication.manifestBytes],
    [paths.applicationSignaturePath, signedApplication.signatureBytes],
    [paths.applicationArchivePath, archiveBytes],
  ]);
  if (platform === 'win32') {
    files.set(paths.shawlManifestPath, signedShawl.manifestBytes);
    files.set(paths.shawlSignaturePath, signedShawl.signatureBytes);
    files.set(paths.shawlExecutablePath, shawlBytes);
  }
  const source = platform === 'win32' ? {
    kind: 'offline',
    applicationManifestPath: paths.applicationManifestPath,
    applicationSignaturePath: paths.applicationSignaturePath,
    applicationArchivePath: paths.applicationArchivePath,
    shawlManifestPath: paths.shawlManifestPath,
    shawlSignaturePath: paths.shawlSignaturePath,
    shawlExecutablePath: paths.shawlExecutablePath,
  } : {
    kind: 'offline',
    applicationManifestPath: paths.applicationManifestPath,
    applicationSignaturePath: paths.applicationSignaturePath,
    applicationArchivePath: paths.applicationArchivePath,
  };
  return {
    platform,
    architecture,
    application,
    shawl,
    source,
    paths,
    files,
    payload,
    archiveBytes,
    shawlBytes,
  };
}

function modeledFileFacts(path, bytes, platform, ordinal) {
  if (platform === 'linux') {
    return {
      kind: 'linux-file-v1',
      device: '1',
      inode: String(ordinal + 1),
      size: bytes.length,
      sha256: sha256(bytes),
      mode: 0o600,
      owner: 'uid:1000',
      securitySha256: '1'.repeat(64),
    };
  }
  return {
    kind: 'win32-file-v1',
    volumeSerial: '1'.repeat(16),
    fileId: sha256(Buffer.from(`${ordinal}:${path}`)).slice(0, 32),
    size: bytes.length,
    sha256: sha256(bytes),
    attributes: 32,
    owner: 'S-1-5-21-1-2-3-1000',
    securitySha256: '2'.repeat(64),
  };
}

function modeledOfflineNative(release, {
  chunkBytes = 37,
  closeFailurePath = null,
  closeFailures = 0,
  closeFailureCode = 'SERVICE_IO_FAILED',
  closeFailureAmbiguous = false,
  onReadChunk = null,
} = {}) {
  const handles = new Set();
  const opened = [];
  const closed = [];
  const closeAttempts = [];
  let remainingCloseFailures = closeFailures;
  let ordinal = 0;
  const native = {
    open_service_artifact_source(path, maximum, expected) {
      assert.equal(expected, null);
      opened.push(path);
      const bytes = release.files.get(path);
      if (bytes === undefined) return null;
      assert.ok(bytes.length <= maximum);
      const handle = { path, bytes, closed: false };
      handles.add(handle);
      return {
        handle,
        facts: modeledFileFacts(path, bytes, release.platform, ordinal++),
        writes: 0,
      };
    },
    read_service_artifact_chunk(handle, offset, maximum) {
      if (!handles.has(handle) || handle.closed) {
        const error = new Error('MODELED_PRIVATE_CLOSED_HANDLE');
        error.code = 'SERVICE_STALE';
        error.writes = 0;
        throw error;
      }
      assert.ok(maximum <= 1024 * 1024);
      onReadChunk?.(handle, offset);
      const bytes = Buffer.from(handle.bytes.subarray(
        offset,
        Math.min(handle.bytes.length, offset + Math.min(maximum, chunkBytes)),
      ));
      const nextOffset = offset + bytes.length;
      return Object.freeze({
        bytes,
        nextOffset,
        eof: nextOffset === handle.bytes.length,
        writes: 0,
      });
    },
    close_service_handle(handle) {
      closeAttempts.push(handle.path);
      if (handle.path === closeFailurePath && remainingCloseFailures > 0) {
        remainingCloseFailures -= 1;
        const error = new Error('MODELED_PRIVATE_CLOSE_FAILURE');
        error.code = closeFailureCode;
        error.writes = 0;
        error.ambiguous = closeFailureAmbiguous;
        throw error;
      }
      if (!handles.delete(handle)) {
        const error = new Error('MODELED_PRIVATE_DUPLICATE_CLOSE');
        error.code = 'SERVICE_STALE';
        error.writes = 0;
        throw error;
      }
      handle.closed = true;
      closed.push(handle.path);
      return Object.freeze({ writes: 0 });
    },
  };
  return {
    native,
    handles,
    opened,
    closed,
    closeAttempts,
    get remainingCloseFailures() { return remainingCloseFailures; },
  };
}

function sameJson(left, right) {
  return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
}

function collectChunks(chunks) {
  return (async () => {
    const parts = [];
    let length = 0;
    for await (const value of chunks) {
      const bytes = Buffer.from(value);
      parts.push(bytes);
      length += bytes.length;
    }
    return Buffer.concat(parts, length);
  })();
}

function sessionError(state, code, ambiguous = false) {
  const error = new Error('MODELED_PRIVATE_SESSION_ERROR');
  error.code = code;
  error.writes = state.writes;
  error.ambiguous = ambiguous;
  return error;
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function modeledSession(release, prepared, {
  initialWrites = 2,
  cloneRetainResult = false,
  stageGate = null,
  failAccessClose = false,
  accessCloseFailures = 0,
  accessCloseFailureCode = 'SERVICE_IO_FAILED',
  accessCloseFailureAmbiguous = false,
  retainFailure = null,
  failWritePath = null,
  failPublish = false,
} = {}) {
  let remainingAccessCloseFailures = accessCloseFailures;
  const state = {
    writes: initialWrites,
    journal: prepared,
    log: [],
    retained: new Set(),
    reserved: new Set(),
    borrowed: 0,
    sessionCloseCalls: 0,
    manifestAuthorities: [],
    afterAccessOpened: null,
  };
  const expectedManifest = (purpose) => purpose === 'application'
    ? release.application
    : release.shawl;
  const candidateFingerprint = (transaction, purpose) => purpose === 'application'
    ? transaction.candidate.applicationManifestFingerprint
    : transaction.candidate.shawlManifestFingerprint;
  const assertTransaction = (transaction, phase) => {
    if (!sameJson(transaction, state.journal) || transaction.phase !== phase) {
      throw sessionError(state, 'SERVICE_PENDING');
    }
  };
  const retainDeploymentEnvelope = (input) => {
    if (retainFailure !== null) throw retainFailure;
    assertTransaction(input.transaction, 'prepared');
    const expected = expectedManifest(input.purpose);
    if (candidateFingerprint(input.transaction, input.purpose) !== expected.manifestFingerprint) {
      throw sessionError(state, 'SERVICE_SCOPE_MISMATCH');
    }
    const verified = installation.provenance.verifyPinnedDeploymentProvenance({
      purpose: input.purpose,
      manifestBytes: input.manifestBytes,
      signatureBytes: input.signatureBytes,
      platform: release.platform,
      architecture: release.architecture,
    });
    state.log.push(`retain:${input.purpose}`);
    state.retained.add(input.purpose);
    state.writes += 1;
    if (!cloneRetainResult) return verified;
    return Object.freeze({
      ...verified,
      manifest: structuredClone(verified.manifest),
    });
  };
  const reservePurpose = (purpose, input) => {
    assertTransaction(input.transaction, 'prepared');
    installation.provenance.assertPinnedDeploymentManifest(input.manifest, purpose);
    if (!state.retained.has(purpose) ||
        !sameJson(input.manifest, expectedManifest(purpose))) {
      throw sessionError(state, 'SERVICE_SCOPE_MISMATCH');
    }
    state.log.push(`reserve:${purpose}`);
    state.manifestAuthorities.push({ step: 'reserve', purpose, manifest: input.manifest });
    state.reserved.add(purpose);
    state.writes += 1;
    return Object.freeze({
      purpose,
      sequence: input.manifest.releaseSequence,
      currentSequence: input.currentSequence,
      modeledFloor: true,
    });
  };

  function makeAccess(purpose, manifest, transaction) {
    let closed = false;
    let staged = null;
    let expected = null;
    const written = new Map();
    const expectedAsset = purpose === 'application'
      ? manifest.archive
      : manifest.executable;
    const ensureOpen = () => {
      if (closed) throw sessionError(state, 'SERVICE_STALE');
    };
    const access = {
      async stageAsset(chunks) {
        ensureOpen();
        state.log.push(`stage:${purpose}:start`);
        if (stageGate !== null) {
          stageGate.entered.resolve();
          await stageGate.release.promise;
          ensureOpen();
        }
        const bytes = await collectChunks(chunks);
        ensureOpen();
        if (bytes.length !== expectedAsset.byteLength || sha256(bytes) !== expectedAsset.sha256) {
          throw sessionError(state, 'SERVICE_MANUAL_CLEANUP', true);
        }
        staged = bytes;
        state.writes += 1;
        state.log.push(`stage:${purpose}:done`);
        return Object.freeze({ facts: Object.freeze({ size: bytes.length, sha256: sha256(bytes) }) });
      },
      openStagedAsset() {
        ensureOpen();
        if (staged === null) throw sessionError(state, 'SERVICE_PENDING');
        state.log.push(`reader:${purpose}:open`);
        let readerClosed = false;
        let claimed = false;
        const chunks = Object.freeze({
          [Symbol.asyncIterator]() {
            if (readerClosed || claimed) throw sessionError(state, 'SERVICE_STALE');
            claimed = true;
            let offset = 0;
            return Object.freeze({
              async next() {
                if (readerClosed) throw sessionError(state, 'SERVICE_STALE');
                if (offset === staged.length) return { done: true, value: undefined };
                const bytes = staged.subarray(offset, Math.min(staged.length, offset + 41));
                offset += bytes.length;
                return { done: false, value: bytes };
              },
              async return() {
                readerClosed = true;
                return { done: true, value: undefined };
              },
              [Symbol.asyncIterator]() { return this; },
            });
          },
        });
        return Object.freeze({
          facts: Object.freeze({ size: staged.length, sha256: sha256(staged) }),
          chunks,
          close() {
            if (readerClosed) return;
            readerClosed = true;
            state.log.push(`reader:${purpose}:close`);
          },
        });
      },
      prepareCandidate(inventoryBytes) {
        ensureOpen();
        state.log.push(`prepare:${purpose}`);
        if (purpose === 'application') {
          const inventory = parseCanonicalJsonBytes(inventoryBytes, INVENTORY_LIMITS);
          expected = new Map([[APPLICATION_BUNDLE_INVENTORY_PATH, {
            size: manifest.inventory.byteLength,
            sha256: manifest.inventory.sha256,
          }]]);
          for (const record of inventory.payloadEntries) expected.set(record.path, record);
        } else {
          assert.equal(inventoryBytes, null);
          expected = new Map([['shawl.exe', {
            size: manifest.executable.byteLength,
            sha256: manifest.executable.sha256,
          }]]);
        }
        state.writes += 1;
      },
      async writeCandidateFile(path, chunks) {
        ensureOpen();
        const record = expected?.get(path);
        if (!record) throw sessionError(state, 'SERVICE_SCOPE_MISMATCH');
        if (path === failWritePath) {
          state.writes += 1;
          throw sessionError(state, 'SERVICE_MANUAL_CLEANUP', true);
        }
        const bytes = await collectChunks(chunks);
        ensureOpen();
        if (bytes.length !== record.size || sha256(bytes) !== record.sha256) {
          throw sessionError(state, 'SERVICE_MANUAL_CLEANUP', true);
        }
        written.set(path, bytes);
        state.log.push(`write:${purpose}:${path}`);
        state.writes += 1;
        return Object.freeze({ path, size: bytes.length, sha256: sha256(bytes) });
      },
      publishCandidate() {
        ensureOpen();
        if (failPublish) {
          state.writes += 1;
          throw sessionError(state, 'SERVICE_MANUAL_CLEANUP', true);
        }
        if (expected === null || written.size !== expected.size ||
            [...expected.keys()].some((path) => !written.has(path))) {
          throw sessionError(state, 'SERVICE_PENDING');
        }
        const publication = Object.freeze({
          purpose,
          manifestFingerprint: manifest.manifestFingerprint,
          bindingFingerprint: sha256(Buffer.from(`${purpose}:${manifest.manifestFingerprint}`)),
        });
        state.log.push(`publish:${purpose}`);
        state.writes += 1;
        return publication;
      },
      close() {
        if (closed) return;
        state.log.push(`access:${purpose}:close`);
        if (failAccessClose) throw sessionError(state, 'SERVICE_MANUAL_CLEANUP', true);
        if (remainingAccessCloseFailures > 0) {
          remainingAccessCloseFailures -= 1;
          throw sessionError(
            state,
            accessCloseFailureCode,
            accessCloseFailureAmbiguous,
          );
        }
        closed = true;
        state.borrowed -= 1;
      },
    };
    return Object.freeze(access);
  }

  const openArtifactAccess = (input) => {
    state.log.push(`access:${input.purpose}:attempt`);
    assertTransaction(input.transaction, 'sequence-reserved');
    installation.provenance.assertPinnedDeploymentManifest(input.manifest, input.purpose);
    if (!state.reserved.has(input.purpose) ||
        !sameJson(input.manifest, expectedManifest(input.purpose))) {
      throw sessionError(state, 'SERVICE_SCOPE_MISMATCH');
    }
    state.log.push(`root:${input.purpose}`);
    state.manifestAuthorities.push({
      step: 'access',
      purpose: input.purpose,
      manifest: input.manifest,
    });
    state.writes += 1;
    state.borrowed += 1;
    const access = makeAccess(input.purpose, input.manifest, input.transaction);
    state.afterAccessOpened?.();
    return access;
  };
  const commitPurpose = (purpose, input) => {
    assertTransaction(input.transaction, 'sequence-reserved');
    if (state.borrowed !== 0) throw sessionError(state, 'SERVICE_PENDING');
    if (!sameJson(input.manifest, expectedManifest(purpose)) ||
        input.publication.purpose !== purpose) {
      throw sessionError(state, 'SERVICE_STALE');
    }
    state.log.push(`commit:${purpose}`);
    state.manifestAuthorities.push({ step: 'commit', purpose, manifest: input.manifest });
    state.writes += 1;
    return Object.freeze({ purpose, committed: true, sequence: input.manifest.releaseSequence });
  };

  const session = {
    component: prepared.component,
    serviceKey: prepared.serviceKey,
    platform: release.platform,
    architecture: release.architecture,
    retainDeploymentEnvelope,
    reserveApplicationSequence: (input) => reservePurpose('application', input),
    openArtifactAccess,
    commitApplicationSequence: (input) => commitPurpose('application', input),
    close() {
      if (state.borrowed !== 0) throw sessionError(state, 'SERVICE_PENDING');
      state.sessionCloseCalls += 1;
    },
  };
  if (release.platform === 'win32') {
    session.reserveShawlSequence = (input) => reservePurpose('shawl', input);
    session.commitShawlSequence = (input) => commitPurpose('shawl', input);
  }
  Object.defineProperty(session, 'writes', {
    enumerable: true,
    get: () => state.writes,
  });
  Object.freeze(session);
  const controls = Object.freeze({
    state,
    appendSequenceReserved(transaction) {
      if (transaction.phase !== 'sequence-reserved' || transaction.substep !== 'observed') {
        throw new TypeError('Modeled sequence journal phase');
      }
      state.journal = transaction;
      state.log.push('journal:sequence-reserved');
      state.writes += 1;
    },
  });
  return { session, controls };
}

function transactionFor(release, {
  candidateApplicationFingerprint = release.application.manifestFingerprint,
  phase = 'prepared',
  substep = 'none',
  previousJournalFingerprint = null,
} = {}) {
  const platform = release.platform;
  const old = buildServiceOldProof({
    disposition: 'absent',
    manifestFingerprint: null,
    resourceProof: null,
    applicationManifestFingerprint: null,
    shawlManifestFingerprint: null,
    serviceGeneration: 0,
    activation: 'disabled-not-startable',
  }, platform);
  const candidate = buildServiceCandidateProof({
    disposition: 'release',
    applicationManifestFingerprint: candidateApplicationFingerprint,
    shawlManifestFingerprint: release.shawl?.manifestFingerprint ?? null,
    releaseSequence: release.application.releaseSequence,
    releaseTreeFingerprint: release.application.inventory.treeFingerprint,
    compatibilityFingerprint: canonicalJsonHash(release.application.compatibility),
  }, platform);
  const transition = buildServiceTransitionProof({
    oldFingerprint: old.oldFingerprint,
    candidateFingerprint: candidate.candidateFingerprint,
    expectedBeforeResourceFingerprint: null,
    expectedAfterResourceFingerprint: '3'.repeat(64),
    platformResourceFingerprint: '4'.repeat(64),
    platformState: buildServicePlatformState(platform, 'trial'),
  }, platform);
  const final = buildServiceFinalProof({
    disposition: 'stable',
    manifestFingerprint: '5'.repeat(64),
    resourceProof: '6'.repeat(64),
    applicationManifestFingerprint: candidate.applicationManifestFingerprint,
    shawlManifestFingerprint: candidate.shawlManifestFingerprint,
    serviceGeneration: 1,
    activation: 'enabled',
  }, platform);
  return buildServiceTransaction({
    transactionId: 'acquisition-tx',
    transactionNonce: '7'.repeat(32),
    operation: 'install',
    component: 'bot',
    serviceKey: 'bot',
    platform,
    architecture: release.architecture,
    serviceGeneration: 1,
    old,
    candidate,
    transition,
    final,
    phase,
    substep,
    previousJournalFingerprint,
  });
}

function sequenceReserved(prepared) {
  return buildServiceTransaction({
    ...prepared,
    phase: 'sequence-reserved',
    substep: 'observed',
    previousJournalFingerprint: prepared.transactionFingerprint,
  });
}

function createHarness(release, sessionOptions = {}, offlineOptions = {}) {
  const prepared = transactionFor(release);
  const modeled = modeledSession(release, prepared, sessionOptions);
  const offline = modeledOfflineNative(release, offlineOptions);
  const acquisition = installation.acquisition.createServiceAcquisition({
    session: modeled.session,
    native: offline.native,
    source: release.source,
  });
  return {
    acquisition,
    prepared,
    reserved: sequenceReserved(prepared),
    session: modeled,
    offline,
  };
}

function sessionWithWrites(session, getter) {
  const copy = {};
  for (const [key, descriptor] of Object.entries(
    Object.getOwnPropertyDescriptors(session),
  )) {
    if (key !== 'writes') Object.defineProperty(copy, key, descriptor);
  }
  Object.defineProperty(copy, 'writes', {
    enumerable: true,
    get: getter,
  });
  return Object.freeze(copy);
}

function acquisitionError(code, operation, writes = undefined, ambiguous = false) {
  return (error) => {
    assert.equal(error?.name, 'ServiceAcquisitionError');
    assert.equal(error?.code, code);
    assert.equal(error?.operation, operation);
    if (writes !== undefined) assert.equal(error?.writes, writes);
    else assert.ok(Number.isSafeInteger(error?.writes) && error.writes >= 0);
    assert.equal(error?.ambiguous, ambiguous);
    assert.equal(error?.message, code);
    assert.equal(error?.cause, undefined);
    assert.ok(Buffer.byteLength(error.message, 'utf8') < 128);
    assert.doesNotMatch(error.message, /modeled|private|token|https?:/i);
    return true;
  };
}

async function reserveAndJournal(harness) {
  await harness.acquisition.readManifests();
  const receipt = harness.acquisition.reserve({
    transaction: harness.prepared,
    currentApplicationSequence: 0,
    currentShawlSequence: harness.prepared.platform === 'win32' ? 0 : null,
  });
  harness.session.controls.appendSequenceReserved(harness.reserved);
  return receipt;
}

test('acquisition stays private, frozen, closed-input-only, and captures only the fixed session/native source contracts', async () => {
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(Object.hasOwn(publicApi, 'createServiceAcquisition'), false);
  assert.equal(Object.hasOwn(packageJson.exports, './service-acquisition'), false);

  const release = buildRelease();
  const harness = createHarness(release);
  assert.equal(Object.isFrozen(harness.acquisition), true);
  assert.deepEqual(Object.keys(harness.acquisition), ['readManifests', 'reserve', 'publish', 'close']);
  await assert.rejects(
    harness.acquisition.close('extra'),
    acquisitionError('SERVICE_ACQUISITION_INVALID', 'close_service_acquisition', 2),
  );
  await harness.acquisition.close();
  assert.equal(harness.session.controls.state.sessionCloseCalls, 0);

  const { session } = modeledSession(release, transactionFor(release));
  const offline = modeledOfflineNative(release);
  for (const invoke of [
    () => installation.acquisition.createServiceAcquisition(),
    () => installation.acquisition.createServiceAcquisition({ session, native: offline.native, source: release.source }, null),
    () => installation.acquisition.createServiceAcquisition({ session, native: offline.native, source: release.source, extra: true }),
    () => installation.acquisition.createServiceAcquisition({ session, native: null, source: release.source }),
    () => installation.acquisition.createServiceAcquisition({ session, native: offline.native, source: { ...release.source, extra: true } }),
    () => installation.acquisition.createServiceAcquisition({
      session,
      native: offline.native,
      source: Object.defineProperty({ ...release.source }, 'kind', {
        enumerable: true,
        get: () => 'offline',
      }),
    }),
    () => installation.acquisition.createServiceAcquisition({
      session,
      native: offline.native,
      source: { kind: 'github-release', tag: 'v1.2.3' },
    }),
  ]) {
    assert.throws(invoke, acquisitionError('SERVICE_ACQUISITION_INVALID', 'create_service_acquisition'));
  }

  const online = installation.acquisition.createServiceAcquisition({
    session,
    native: null,
    source: { kind: 'github-release', tag: 'v1.2.3' },
  });
  await online.close();
});

test('factory and runtime diagnostics use a descriptor-safe closed code set', async (t) => {
  const release = buildRelease();
  const prepared = transactionFor(release);
  const modeled = modeledSession(release, prepared);

  await t.test('an offline native prototype trap cannot forward a private-looking code', () => {
    const privateError = new Error('MODELED_PRIVATE_TOKEN');
    privateError.code = 'SERVICE_PRIVATE_TOKEN_ABC';
    privateError.ambiguous = true;
    const hostileNative = new Proxy({}, {
      getPrototypeOf() { throw privateError; },
    });
    assert.throws(
      () => installation.acquisition.createServiceAcquisition({
        session: modeled.session,
        native: hostileNative,
        source: release.source,
      }),
      acquisitionError(
        'SERVICE_ACQUISITION_INVALID',
        'create_service_acquisition',
        2,
      ),
    );

    const getterError = new Error('MODELED_PRIVATE_TOKEN');
    Object.defineProperties(getterError, {
      code: {
        enumerable: true,
        get() { throw new Error('MODELED_PRIVATE_FACTORY_CODE_GETTER'); },
      },
      ambiguous: {
        enumerable: true,
        get() { throw new Error('MODELED_PRIVATE_FACTORY_AMBIGUITY_GETTER'); },
      },
    });
    const getterNative = new Proxy({}, {
      getPrototypeOf() { throw getterError; },
    });
    assert.throws(
      () => installation.acquisition.createServiceAcquisition({
        session: modeled.session,
        native: getterNative,
        source: release.source,
      }),
      acquisitionError(
        'SERVICE_ACQUISITION_INVALID',
        'create_service_acquisition',
        2,
      ),
    );
  });

  await t.test('throwing exception-field getters cannot escape normalization', async () => {
    const exotic = new Error('MODELED_PRIVATE_EXCEPTION');
    Object.defineProperties(exotic, {
      code: {
        enumerable: true,
        get() { throw new Error('MODELED_PRIVATE_CODE_GETTER'); },
      },
      ambiguous: {
        enumerable: true,
        get() { throw new Error('MODELED_PRIVATE_AMBIGUITY_GETTER'); },
      },
    });
    const harness = createHarness(release, { retainFailure: exotic });
    await harness.acquisition.readManifests();
    assert.throws(() => harness.acquisition.reserve({
      transaction: harness.prepared,
      currentApplicationSequence: 0,
      currentShawlSequence: null,
    }), acquisitionError(
      'SERVICE_ACQUISITION_FAILED',
      'reserve_service_acquisition',
      2,
      false,
    ));
    await harness.acquisition.close();
  });

  await t.test('an unknown matching runtime code is replaced by the fixed fallback', async () => {
    const unknown = new Error('MODELED_PRIVATE_RUNTIME');
    unknown.code = 'SERVICE_PRIVATE_TOKEN_ABC';
    unknown.ambiguous = true;
    const harness = createHarness(release, { retainFailure: unknown });
    await harness.acquisition.readManifests();
    assert.throws(() => harness.acquisition.reserve({
      transaction: harness.prepared,
      currentApplicationSequence: 0,
      currentShawlSequence: null,
    }), acquisitionError(
      'SERVICE_ACQUISITION_FAILED',
      'reserve_service_acquisition',
      2,
      false,
    ));
    await harness.acquisition.close();
  });
});

test('invalid initial session write counters always refuse with the last valid count of zero', () => {
  const release = buildRelease();
  const prepared = transactionFor(release);
  const modeled = modeledSession(release, prepared);
  const offline = modeledOfflineNative(release);
  const values = [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '2', null];
  for (const value of values) {
    const invalidSession = sessionWithWrites(modeled.session, () => value);
    assert.throws(
      () => installation.acquisition.createServiceAcquisition({
        session: invalidSession,
        native: offline.native,
        source: release.source,
      }),
      acquisitionError(
        'SERVICE_ACQUISITION_INVALID',
        'create_service_acquisition',
        0,
      ),
    );
  }
  const throwingSession = sessionWithWrites(modeled.session, () => {
    const error = new Error('MODELED_PRIVATE_WRITES_GETTER');
    error.code = 'SERVICE_PRIVATE_TOKEN_ABC';
    throw error;
  });
  assert.throws(
    () => installation.acquisition.createServiceAcquisition({
      session: throwingSession,
      native: offline.native,
      source: release.source,
    }),
    acquisitionError(
      'SERVICE_ACQUISITION_INVALID',
      'create_service_acquisition',
      0,
    ),
  );
});

test('modeled composition: Linux keeps its original brand despite a cloned retain receipt and orders commit after access close', async () => {
  const release = buildRelease();
  const harness = createHarness(release, { cloneRetainResult: true });
  const read = await harness.acquisition.readManifests();
  assert.equal(Object.isFrozen(read), true);
  assert.equal(read.application.kind, 'application-deployment-manifest');
  assert.equal(read.shawl, null);
  assert.equal(Object.isFrozen(read.application), true);
  assert.equal(
    installation.provenance.assertPinnedDeploymentManifest(
      read.application,
      'application',
    ),
    read.application,
  );
  assert.throws(
    () => installation.provenance.assertPinnedDeploymentManifest(
      structuredClone(read.application),
      'application',
    ),
    { code: 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED', writes: 0 },
  );
  assert.deepEqual(harness.offline.opened, [
    release.paths.applicationManifestPath,
    release.paths.applicationSignaturePath,
  ]);
  assert.deepEqual(harness.session.controls.state.log, []);
  release.files.get(release.paths.applicationManifestPath).fill(0);
  release.files.get(release.paths.applicationSignaturePath).fill(0);

  const reserve = harness.acquisition.reserve({
    transaction: harness.prepared,
    currentApplicationSequence: 0,
    currentShawlSequence: null,
  });
  assert.equal(Object.isFrozen(reserve), true);
  assert.equal(reserve.application.purpose, 'application');
  assert.equal(reserve.shawl, null);
  assert.deepEqual(harness.session.controls.state.log, [
    'retain:application',
    'reserve:application',
  ]);
  assert.equal(harness.offline.opened.includes(release.paths.applicationArchivePath), false);
  assert.equal(harness.session.controls.state.log.some((entry) => entry.startsWith('root:')), false);
  assert.throws(() => harness.acquisition.reserve({
    transaction: harness.prepared,
    currentApplicationSequence: 0,
    currentShawlSequence: null,
  }), acquisitionError(
    'SERVICE_ACQUISITION_STATE_INVALID',
    'reserve_service_acquisition',
    harness.session.controls.state.writes,
  ));

  harness.session.controls.appendSequenceReserved(harness.reserved);
  const published = await harness.acquisition.publish({ transaction: harness.reserved });
  assert.equal(Object.isFrozen(published), true);
  assert.equal(Object.isFrozen(published.application), true);
  assert.equal(published.application.manifest, read.application);
  assert.equal(published.shawl, null);
  assert.equal(published.application.nativeMetadata.manifestFingerprint, release.application.nativeControl.manifestFingerprint);
  assert.equal(published.application.nativeMetadata.addonBytesVerification, 'required');
  assert.equal(published.application.nativeMetadata.addonLoadVerification, 'required');
  assert.equal(published.application.nativeMetadata.addonExportVerification, 'required');
  assert.ok(harness.session.controls.state.manifestAuthorities
    .filter(({ purpose }) => purpose === 'application')
    .every(({ manifest }) => manifest === read.application));
  const log = harness.session.controls.state.log;
  assert.ok(log.indexOf('journal:sequence-reserved') < log.indexOf('root:application'));
  assert.ok(log.indexOf('root:application') < log.indexOf('stage:application:start'));
  assert.ok(log.indexOf('publish:application') < log.indexOf('access:application:close'));
  assert.ok(log.indexOf('access:application:close') < log.indexOf('commit:application'));
  assert.ok(log.includes(`write:application:${APPLICATION_BUNDLE_INVENTORY_PATH}`));
  assert.ok(log.includes('write:application:native-control/build/Release/native_control.node'));
  assert.ok(log.includes(
    'write:application:node_modules/@gjc-remote/native-control/build/Release/native_control.node',
  ));
  assert.ok(log.includes(
    'write:application:daemon/node_modules/@gjc-remote/native-control/build/Release/native_control.node',
  ));
  assert.equal(harness.session.controls.state.borrowed, 0);
  assert.equal(harness.offline.handles.size, 0);
  const roots = log.filter((entry) => entry.startsWith('root:')).length;
  await assert.rejects(
    harness.acquisition.publish({ transaction: harness.reserved }),
    acquisitionError(
      'SERVICE_ACQUISITION_STATE_INVALID',
      'publish_service_acquisition',
      harness.session.controls.state.writes,
    ),
  );
  assert.equal(
    log.filter((entry) => entry.startsWith('root:')).length,
    roots,
  );
  await harness.acquisition.close();
  assert.equal(harness.session.controls.state.sessionCloseCalls, 0);
});

test('modeled composition: Windows retains both envelopes before either floor and publishes application then Shawl', async () => {
  const release = buildRelease({ platform: 'win32' });
  const harness = createHarness(release);
  const read = await harness.acquisition.readManifests();
  assert.equal(read.application.kind, 'application-deployment-manifest');
  assert.equal(read.shawl.kind, 'shawl-deployment-manifest');
  assert.equal(
    installation.provenance.assertPinnedDeploymentManifest(read.shawl, 'shawl'),
    read.shawl,
  );
  assert.deepEqual(harness.offline.opened, [
    release.paths.applicationManifestPath,
    release.paths.applicationSignaturePath,
    release.paths.shawlManifestPath,
    release.paths.shawlSignaturePath,
  ]);
  const reserve = harness.acquisition.reserve({
    transaction: harness.prepared,
    currentApplicationSequence: 1,
    currentShawlSequence: 1,
  });
  assert.equal(reserve.application.purpose, 'application');
  assert.equal(reserve.shawl.purpose, 'shawl');
  assert.deepEqual(harness.session.controls.state.log, [
    'retain:application',
    'retain:shawl',
    'reserve:application',
    'reserve:shawl',
  ]);
  harness.session.controls.appendSequenceReserved(harness.reserved);
  const published = await harness.acquisition.publish({ transaction: harness.reserved });
  assert.equal(published.application.manifest, read.application);
  assert.equal(published.shawl.manifest, read.shawl);
  assert.equal(published.shawl.publication.purpose, 'shawl');
  const log = harness.session.controls.state.log;
  assert.ok(log.indexOf('commit:application') < log.indexOf('root:shawl'));
  assert.ok(log.indexOf('publish:shawl') < log.indexOf('access:shawl:close'));
  assert.ok(log.indexOf('access:shawl:close') < log.indexOf('commit:shawl'));
  assert.equal(harness.session.controls.state.borrowed, 0);
  assert.equal(harness.offline.handles.size, 0);
  await harness.acquisition.close();
});

test('asset bodies and staging roots remain inaccessible before both reservation and the sequence-reserved journal', async (t) => {
  await t.test('before reserve', async () => {
    const release = buildRelease();
    const harness = createHarness(release);
    await harness.acquisition.readManifests();
    await assert.rejects(
      harness.acquisition.publish({ transaction: harness.reserved }),
      acquisitionError('SERVICE_ACQUISITION_STATE_INVALID', 'publish_service_acquisition', 2),
    );
    assert.equal(harness.offline.opened.includes(release.paths.applicationArchivePath), false);
    assert.equal(harness.session.controls.state.log.some((entry) => entry.startsWith('root:')), false);
    await harness.acquisition.close();
  });

  await t.test('floor reserved but journal not advanced', async () => {
    const release = buildRelease();
    const harness = createHarness(release);
    await harness.acquisition.readManifests();
    harness.acquisition.reserve({
      transaction: harness.prepared,
      currentApplicationSequence: 0,
      currentShawlSequence: null,
    });
    const writes = harness.session.controls.state.writes;
    await assert.rejects(
      harness.acquisition.publish({ transaction: harness.reserved }),
      acquisitionError('SERVICE_PENDING', 'publish_service_acquisition', writes),
    );
    assert.equal(harness.offline.opened.includes(release.paths.applicationArchivePath), false);
    assert.equal(harness.session.controls.state.log.includes('root:application'), false);
    await harness.acquisition.close();
  });
});

test('genuine isolated signature failures and transaction identity forks refuse before artifact requests', async (t) => {
  await t.test('wrong-purpose signature', async () => {
    const release = buildRelease({ platform: 'win32' });
    release.files.set(
      release.paths.applicationSignaturePath,
      release.files.get(release.paths.shawlSignaturePath),
    );
    const harness = createHarness(release);
    await assert.rejects(
      harness.acquisition.readManifests(),
      acquisitionError(
        'DEPLOYMENT_MANIFEST_INVALID',
        'read_service_acquisition_manifests',
        2,
      ),
    );
    assert.equal(harness.session.controls.state.log.length, 0);
    assert.equal(harness.offline.handles.size, 0);
    await harness.acquisition.close();
  });

  await t.test('tampered signature', async () => {
    const release = buildRelease();
    const signature = JSON.parse(
      release.files.get(release.paths.applicationSignaturePath).toString('utf8'),
    );
    signature.signature = Buffer.alloc(64).toString('base64');
    release.files.set(release.paths.applicationSignaturePath, canonicalJsonBytes(signature));
    const harness = createHarness(release, { initialWrites: 5 });
    await assert.rejects(
      harness.acquisition.readManifests(),
      acquisitionError('DEPLOYMENT_SIGNATURE_INVALID', 'read_service_acquisition_manifests', 5),
    );
    assert.equal(harness.session.controls.state.log.length, 0);
    assert.equal(harness.offline.handles.size, 0);
    await harness.acquisition.close();
  });

  await t.test('foreign same-key-id signature', async () => {
    const foreign = await createPinnedDeploymentInstallation({ keyIds: ['deployment-test'] });
    try {
      const release = buildRelease();
      release.files.set(
        release.paths.applicationSignaturePath,
        foreign.signManifest(release.application).signatureBytes,
      );
      const harness = createHarness(release);
      await assert.rejects(
        harness.acquisition.readManifests(),
        acquisitionError('DEPLOYMENT_SIGNATURE_INVALID', 'read_service_acquisition_manifests', 2),
      );
      assert.equal(harness.session.controls.state.log.length, 0);
      await harness.acquisition.close();
    } finally {
      foreign.dispose();
    }
  });

  await t.test('candidate fingerprint fork', async () => {
    const release = buildRelease();
    const prepared = transactionFor(release, {
      candidateApplicationFingerprint: '0'.repeat(64),
    });
    const modeled = modeledSession(release, prepared);
    const offline = modeledOfflineNative(release);
    const acquisition = installation.acquisition.createServiceAcquisition({
      session: modeled.session,
      native: offline.native,
      source: release.source,
    });
    await acquisition.readManifests();
    await assert.rejects(async () => acquisition.reserve({
      transaction: prepared,
      currentApplicationSequence: 0,
      currentShawlSequence: null,
    }), acquisitionError('SERVICE_SCOPE_MISMATCH', 'reserve_service_acquisition', 2));
    assert.equal(offline.opened.includes(release.paths.applicationArchivePath), false);
    await acquisition.close();
  });
});

test('archive, native digest, bundled trust and missing native metadata all fail before immutable publication', async (t) => {
  const cases = [
    ['signed archive digest mismatch', {}, 'DEPLOYMENT_SOURCE_IDENTITY_MISMATCH', (release) => {
      const corrupted = Buffer.from(release.archiveBytes);
      corrupted[corrupted.length - 1] ^= 1;
      release.files.set(release.paths.applicationArchivePath, corrupted);
    }],
    ['invalid archive', { invalidArchive: true }, /^SERVICE_ARCHIVE_/, null],
    ['native addon digest mismatch', { nativeAddonMismatch: true }, 'SERVICE_ACQUISITION_NATIVE_AUTHORITY_INVALID', null],
    ['native addon lacks executable policy', {
      addonExecutablePolicy: 'forbidden',
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['missing primary runtime alias', {
      omitPrimaryAlias: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['primary runtime alias is missing a root file', {
      omit: [
        'node_modules/@gjc-remote/native-control/build/Release/native-control.manifest.json.sig',
      ],
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['primary runtime alias has an extra file', {
      extraPrimaryAliasFile: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['primary runtime alias differs from root native subtree', {
      corruptPrimaryAlias: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['nested runtime alias differs from root native subtree', {
      corruptNestedAlias: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['Windows folded noncanonical runtime alias', {
      platform: 'win32',
      windowsFoldedPrimaryAlias: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['Linux alias marker regular file', {
      aliasMarkerFile: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['Windows alias marker regular file', {
      platform: 'win32',
      aliasMarkerFile: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['Linux node_modules-only shadow alias', {
      nodeModulesOnlyShadowAlias: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['Windows node_modules-only shadow alias', {
      platform: 'win32',
      nodeModulesOnlyShadowAlias: true,
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
    ['bundled native trust mismatch', { bundledTrustMismatch: true }, 'NATIVE_PROVENANCE_TRUST_INVALID', null],
    ['missing native signature', {
      omit: ['native-control/build/Release/native-control.manifest.json.sig'],
    }, 'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID', null],
  ];
  for (const [name, releaseOptions, expectedCode, mutate] of cases) {
    await t.test(name, async () => {
      const release = buildRelease(releaseOptions);
      mutate?.(release);
      const harness = createHarness(release);
      await reserveAndJournal(harness);
      const beforePublishWrites = harness.session.controls.state.writes;
      await assert.rejects(
        harness.acquisition.publish({ transaction: harness.reserved }),
        (error) => {
          if (expectedCode instanceof RegExp) assert.match(error.code, expectedCode);
          else assert.equal(error.code, expectedCode);
          assert.equal(error.operation, 'publish_service_acquisition');
          assert.equal(error.writes, harness.session.controls.state.writes);
          assert.ok(error.writes >= beforePublishWrites);
          assert.equal(error.cause, undefined);
          return true;
        },
      );
      assert.equal(
        harness.session.controls.state.log.some((entry) => entry.startsWith('publish:')),
        false,
      );
      assert.equal(
        harness.session.controls.state.log.some((entry) => entry.startsWith('commit:')),
        false,
      );
      assert.equal(harness.session.controls.state.borrowed, 0);
      assert.equal(harness.offline.handles.size, 0);
      await harness.acquisition.close();
    });
  }
});

test('errors retain cumulative session writes and preserve manual-cleanup ambiguity without double counting', async (t) => {
  await t.test('pure parser error after retained/floor/journal writes', async () => {
    const release = buildRelease({ invalidArchive: true });
    const harness = createHarness(release, { initialWrites: 4 });
    await reserveAndJournal(harness);
    const priorWrites = harness.session.controls.state.writes;
    await assert.rejects(
      harness.acquisition.publish({ transaction: harness.reserved }),
      (error) => {
        assert.match(error.code, /^SERVICE_ARCHIVE_/);
        assert.equal(error.writes, harness.session.controls.state.writes);
        assert.ok(error.writes > priorWrites);
        assert.equal(error.ambiguous, false);
        return true;
      },
    );
    await harness.acquisition.close();
  });

  await t.test('manual cleanup from candidate publication dominates and remains exact', async () => {
    const release = buildRelease();
    const harness = createHarness(release, { failPublish: true });
    await reserveAndJournal(harness);
    await assert.rejects(
      harness.acquisition.publish({ transaction: harness.reserved }),
      (error) => {
        assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
        assert.equal(error.operation, 'publish_service_acquisition');
        assert.equal(error.writes, harness.session.controls.state.writes);
        assert.equal(error.ambiguous, true);
        assert.equal(error.cause, undefined);
        return true;
      },
    );
    assert.equal(harness.session.controls.state.log.includes('commit:application'), false);
    await harness.acquisition.close();
  });

  await t.test('manual cleanup from a pass-two file write survives parser wrapping', async () => {
    const release = buildRelease();
    const harness = createHarness(release, {
      failWritePath: 'daemon/src/daemon.js',
    });
    await reserveAndJournal(harness);
    await assert.rejects(
      harness.acquisition.publish({ transaction: harness.reserved }),
      acquisitionError(
        'SERVICE_MANUAL_CLEANUP',
        'publish_service_acquisition',
        undefined,
        true,
      ),
    );
    assert.equal(harness.session.controls.state.log.includes('publish:application'), false);
    assert.equal(harness.session.controls.state.log.includes('commit:application'), false);
    await harness.acquisition.close();
  });

  await t.test('access close failure blocks sequence commit', async () => {
    const release = buildRelease();
    const harness = createHarness(release, { failAccessClose: true });
    await reserveAndJournal(harness);
    await assert.rejects(
      harness.acquisition.publish({ transaction: harness.reserved }),
      acquisitionError(
        'SERVICE_MANUAL_CLEANUP',
        'publish_service_acquisition',
        undefined,
        true,
      ),
    );
    assert.equal(harness.session.controls.state.log.includes('commit:application'), false);
    await assert.rejects(
      harness.acquisition.close(),
      acquisitionError('SERVICE_MANUAL_CLEANUP', 'close_service_acquisition', undefined, true),
    );
  });
});

test('synchronous close failures are retried instead of being cached permanently', async (t) => {
  await t.test('artifact access close fails once, then cleanup releases the borrow', async () => {
    const release = buildRelease();
    const harness = createHarness(release, {
      accessCloseFailures: 1,
      accessCloseFailureCode: 'SERVICE_IO_FAILED',
    });
    await reserveAndJournal(harness);
    await assert.rejects(
      harness.acquisition.publish({ transaction: harness.reserved }),
      acquisitionError(
        'SERVICE_IO_FAILED',
        'publish_service_acquisition',
      ),
    );
    assert.equal(
      harness.session.controls.state.log.filter((entry) =>
        entry === 'access:application:close').length,
      2,
    );
    assert.equal(harness.session.controls.state.borrowed, 0);
    assert.doesNotThrow(() => harness.session.session.close());
    await harness.acquisition.close();
  });

  await t.test('offline source close fails once during bootstrap, then retries its native closer', async () => {
    const release = buildRelease();
    const prepared = transactionFor(release);
    const modeled = modeledSession(release, prepared);
    let acquisition;
    let closing;
    let triggered = false;
    const offline = modeledOfflineNative(release, {
      chunkBytes: 1,
      closeFailurePath: release.paths.applicationManifestPath,
      closeFailures: 1,
      onReadChunk() {
        if (triggered) return;
        triggered = true;
        closing = acquisition.close();
      },
    });
    acquisition = installation.acquisition.createServiceAcquisition({
      session: modeled.session,
      native: offline.native,
      source: release.source,
    });
    await assert.rejects(
      acquisition.readManifests(),
      acquisitionError(
        'SERVICE_ACQUISITION_CLOSED',
        'read_service_acquisition_manifests',
        2,
      ),
    );
    await closing;
    assert.equal(offline.remainingCloseFailures, 0);
    assert.ok(
      offline.closeAttempts.filter((path) =>
        path === release.paths.applicationManifestPath).length >= 2,
    );
    assert.equal(offline.handles.size, 0);
    assert.equal(modeled.controls.state.sessionCloseCalls, 0);
    await acquisition.close();
  });
});

test('early close cancels the source stream, unwinds reader/access ownership, and never closes the caller session', async () => {
  const gate = { entered: deferred(), release: deferred() };
  const release = buildRelease();
  const harness = createHarness(release, { stageGate: gate });
  await reserveAndJournal(harness);
  const publishing = harness.acquisition.publish({ transaction: harness.reserved });
  await gate.entered.promise;
  const closing = harness.acquisition.close();
  gate.release.resolve();
  await assert.rejects(
    publishing,
    acquisitionError('SERVICE_ACQUISITION_CLOSED', 'publish_service_acquisition'),
  );
  await closing;
  assert.equal(harness.offline.handles.size, 0);
  assert.equal(harness.session.controls.state.borrowed, 0);
  assert.equal(harness.session.controls.state.log.includes('publish:application'), false);
  assert.equal(harness.session.controls.state.log.includes('commit:application'), false);
  assert.equal(harness.session.controls.state.sessionCloseCalls, 0);
});

test('fixed acquisition deadline closes the offline source and forbids later work without a clock injection seam', async (t) => {
  const timers = [];
  t.mock.method(globalThis, 'setTimeout', (callback, milliseconds) => {
    const timer = {
      callback,
      milliseconds,
      cleared: false,
      unrefCalled: false,
      unref() { this.unrefCalled = true; return this; },
    };
    timers.push(timer);
    return timer;
  });
  t.mock.method(globalThis, 'clearTimeout', (timer) => { timer.cleared = true; });
  const release = buildRelease();
  const harness = createHarness(release);
  assert.equal(timers.length, 1);
  assert.equal(timers[0].milliseconds, 10 * 60_000);
  assert.equal(timers[0].unrefCalled, true);
  await harness.acquisition.readManifests();
  timers[0].callback();
  await Promise.resolve();
  assert.throws(
    () => harness.acquisition.reserve({
      transaction: harness.prepared,
      currentApplicationSequence: 0,
      currentShawlSequence: null,
    }),
    acquisitionError(
      'SERVICE_ACQUISITION_DEADLINE_EXCEEDED',
      'reserve_service_acquisition',
      2,
    ),
  );
  assert.equal(harness.offline.opened.includes(release.paths.applicationArchivePath), false);
  assert.equal(harness.session.controls.state.sessionCloseCalls, 0);
  await harness.acquisition.close();
});

test('deadline crossing inside openArtifactAccess closes the acquired borrow before rejecting', async (t) => {
  const timers = [];
  t.mock.method(globalThis, 'setTimeout', (callback, milliseconds) => {
    const timer = {
      callback,
      milliseconds,
      cleared: false,
      unref() { return this; },
    };
    timers.push(timer);
    return timer;
  });
  t.mock.method(globalThis, 'clearTimeout', (timer) => { timer.cleared = true; });
  const release = buildRelease();
  const harness = createHarness(release);
  await reserveAndJournal(harness);
  assert.equal(timers.length, 1);
  harness.session.controls.state.afterAccessOpened = () => timers[0].callback();
  await assert.rejects(
    harness.acquisition.publish({ transaction: harness.reserved }),
    (error) => {
      assert.equal(error.code, 'SERVICE_ACQUISITION_DEADLINE_EXCEEDED');
      assert.equal(error.operation, 'publish_service_acquisition');
      assert.equal(error.writes, harness.session.controls.state.writes);
      assert.equal(error.ambiguous, false);
      return true;
    },
  );
  assert.equal(harness.session.controls.state.borrowed, 0);
  assert.equal(harness.offline.handles.size, 0);
  assert.equal(
    harness.session.controls.state.log.includes('stage:application:start'),
    false,
  );
  assert.doesNotThrow(() => harness.session.session.close());
  assert.equal(harness.session.controls.state.sessionCloseCalls, 1);
  await harness.acquisition.close();
  assert.equal(harness.session.controls.state.sessionCloseCalls, 1);
});

test('phase, tuple, one-use and closed-state guards fail before new source or root activity', async (t) => {
  await t.test('read rejects a reentrant operation without opening a second source', async () => {
    const release = buildRelease();
    const harness = createHarness(release);
    const first = harness.acquisition.readManifests();
    await assert.rejects(
      harness.acquisition.readManifests(),
      acquisitionError('SERVICE_PENDING', 'read_service_acquisition_manifests', 2),
    );
    await first;
    assert.deepEqual(harness.offline.opened, [
      release.paths.applicationManifestPath,
      release.paths.applicationSignaturePath,
    ]);
    assert.equal(harness.offline.handles.size, 0);
    await harness.acquisition.close();
  });

  await t.test('reserve requires prepared/none and platform-specific Shawl sequence shape', async () => {
    const release = buildRelease();
    const harness = createHarness(release);
    await harness.acquisition.readManifests();
    assert.throws(() => harness.acquisition.reserve({
      transaction: harness.reserved,
      currentApplicationSequence: 0,
      currentShawlSequence: null,
    }), acquisitionError('SERVICE_ACQUISITION_TRANSACTION_MISMATCH', 'reserve_service_acquisition', 2));
    assert.throws(() => harness.acquisition.reserve({
      transaction: harness.prepared,
      currentApplicationSequence: -1,
      currentShawlSequence: null,
    }), acquisitionError('SERVICE_ACQUISITION_INVALID', 'reserve_service_acquisition', 2));
    assert.throws(() => harness.acquisition.reserve({
      transaction: harness.prepared,
      currentApplicationSequence: 0,
      currentShawlSequence: 0,
    }), acquisitionError('SERVICE_ACQUISITION_INVALID', 'reserve_service_acquisition', 2));
    assert.equal(harness.session.controls.state.log.length, 0);
    await harness.acquisition.close();

    const windowsRelease = buildRelease({ platform: 'win32' });
    const windows = createHarness(windowsRelease);
    await windows.acquisition.readManifests();
    assert.throws(() => windows.acquisition.reserve({
      transaction: windows.prepared,
      currentApplicationSequence: 0,
      currentShawlSequence: null,
    }), acquisitionError('SERVICE_ACQUISITION_INVALID', 'reserve_service_acquisition', 2));
    assert.equal(windows.session.controls.state.log.length, 0);
    await windows.acquisition.close();
  });

  await t.test('publish requires the exact reserved transaction identity and observed journal phase', async () => {
    const release = buildRelease();
    const harness = createHarness(release);
    await reserveAndJournal(harness);
    const different = buildServiceTransaction({
      ...harness.reserved,
      transactionId: 'different-tx',
      transactionNonce: '8'.repeat(32),
    });
    await assert.rejects(
      harness.acquisition.publish({ transaction: different }),
      acquisitionError('SERVICE_ACQUISITION_TRANSACTION_MISMATCH', 'publish_service_acquisition'),
    );
    assert.equal(harness.session.controls.state.log.includes('root:application'), false);
    await harness.acquisition.close();
  });

  await t.test('read is single-use and close is idempotent', async () => {
    const release = buildRelease();
    const harness = createHarness(release);
    await harness.acquisition.readManifests();
    await assert.rejects(
      harness.acquisition.readManifests(),
      acquisitionError('SERVICE_ACQUISITION_STATE_INVALID', 'read_service_acquisition_manifests', 2),
    );
    const opened = harness.offline.opened.length;
    await harness.acquisition.close();
    await harness.acquisition.close();
    await assert.rejects(
      harness.acquisition.readManifests(),
      acquisitionError('SERVICE_ACQUISITION_CLOSED', 'read_service_acquisition_manifests', 2),
    );
    assert.equal(harness.offline.opened.length, opened);
    assert.equal(harness.session.controls.state.sessionCloseCalls, 0);
  });
});
