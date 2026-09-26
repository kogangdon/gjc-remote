import { createHash } from 'node:crypto';
import {
  canonicalJsonBytes,
  canonicalJsonHash,
  parseCanonicalJsonBytes,
  utf8Compare,
} from '@gjc-remote/shared/strict-json';
import {
  APPLICATION_BUNDLE_INVENTORY_PATH,
  DEPLOYMENT_ENVELOPE_LIMITS,
  validateApplicationDeploymentManifest,
  validateBundleInventory,
  validateShawlDeploymentManifest,
} from '@gjc-remote/shared/deployment-envelope';

const ARTIFACT_MAX_BYTES = 2 * 1024 * 1024 * 1024;
const ARTIFACT_CHUNK_BYTES = 1024 * 1024;
const MARKER_LIMITS = Object.freeze({
  maxBytes: 1024 * 1024,
  maxDepth: 64,
  maxNodes: 100_000,
});
const INVENTORY_LIMITS = Object.freeze({
  maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
  maxDepth: 16,
  maxNodes: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries * 6 + 32,
});
const ACCESS_KEYS = Object.freeze([
  'bridge',
  'purpose',
  'manifest',
  'transaction',
  'transactionIdentity',
  'roles',
  'rolesFingerprint',
  'platform',
  'architecture',
  'component',
  'serviceKey',
  'onClose',
]);
const BRIDGE_KEYS = Object.freeze([
  'bootstrapRoot',
  'openRoot',
  'openDirectory',
  'adoptHandle',
  'disownHandle',
  'readFile',
  'publishFile',
  'listDirectory',
  'beginWrite',
  'writeChunk',
  'finishWrite',
  'openReader',
  'readChunk',
  'removeFile',
  'removeObject',
  'sealDirectory',
  'publishDirectory',
  'closeHandle',
  'observePublication',
  'fail',
]);
const LOGICAL_TRANSACTION_KEYS = Object.freeze([
  'transactionId',
  'transactionNonce',
  'operation',
  'component',
  'serviceKey',
  'platform',
  'architecture',
  'serviceGeneration',
  'old',
  'candidate',
  'transition',
  'final',
]);
const MARKER_KEYS = Object.freeze([
  'schemaVersion',
  'kind',
  'purpose',
  'component',
  'serviceKey',
  'platform',
  'architecture',
  'transactionIdentity',
  'transaction',
  'candidate',
  'asset',
  'roles',
  'rolesFingerprint',
  'stagingRootBindingFingerprint',
  'stagingRootIdentity',
  'scratchIdentity',
  'markerFingerprint',
]);
const OPERATIONS = Object.freeze({
  open: 'open_service_artifact_access',
  stage: 'stage_service_asset',
  openAsset: 'open_staged_service_asset',
  readAsset: 'read_staged_service_asset',
  prepare: 'prepare_service_candidate',
  write: 'write_service_candidate_file',
  publish: 'publish_service_candidate',
  close: 'close_service_artifact_access',
});
const ARTIFACT_FAILURE_CODES = new Set([
  'SERVICE_ACCESS_DENIED',
  'SERVICE_ALREADY_EXISTS',
  'SERVICE_CRYPTO_UNAVAILABLE',
  'SERVICE_INVALID',
  'SERVICE_IO_FAILED',
  'SERVICE_MANUAL_CLEANUP',
  'SERVICE_PENDING',
  'SERVICE_SCOPE_MISMATCH',
  'SERVICE_STALE',
  'SERVICE_TOMBSTONED',
  'SERVICE_UNSUPPORTED',
]);

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value, keys) {
  if (!plain(value)) return false;
  const own = Reflect.ownKeys(value);
  return own.length === keys.length && own.every((key) => typeof key === 'string') &&
    keys.every((key) => Object.hasOwn(value, key));
}

function dataValues(value, keys) {
  if (!plain(value)) return null;
  try {
    const own = Reflect.ownKeys(value);
    if (own.length !== keys.length || own.some((key) => typeof key !== 'string')) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.enumerable !== true || descriptor.get !== undefined ||
          descriptor.set !== undefined || !Object.hasOwn(descriptor, 'value')) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

function capturedFailure(value) {
  if (value === null ||
      (typeof value !== 'object' && typeof value !== 'function')) {
    return null;
  }
  try {
    const code = Object.getOwnPropertyDescriptor(value, 'code');
    const ambiguous = Object.getOwnPropertyDescriptor(value, 'ambiguous');
    if (!code || code.get !== undefined || code.set !== undefined ||
        typeof code.value !== 'string' ||
        !ARTIFACT_FAILURE_CODES.has(code.value)) {
      return null;
    }
    return Object.freeze({
      code: code.value,
      ambiguous: ambiguous?.get === undefined &&
        ambiguous?.set === undefined &&
        ambiguous?.value === true,
    });
  } catch {
    return null;
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function cloneJson(value, limits = MARKER_LIMITS) {
  return deepFreeze(parseCanonicalJsonBytes(canonicalJsonBytes(value, limits), limits));
}

function isHex64(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function copyBytes(value, maximum) {
  try {
    if (!isBytes(value) || value.byteLength > maximum) return null;
    const bytes = Buffer.from(value);
    return bytes.length <= maximum ? bytes : null;
  } catch {
    return null;
  }
}

function iteratorFor(chunks) {
  if (isBytes(chunks)) {
    let done = false;
    return {
      async next() {
        if (done) return { done: true, value: undefined };
        done = true;
        return { done: false, value: chunks };
      },
      async return() {
        done = true;
        return { done: true, value: undefined };
      },
    };
  }
  try {
    if (chunks === null || chunks === undefined) return null;
    const asyncIterator = chunks[Symbol.asyncIterator];
    if (typeof asyncIterator === 'function') {
      const iterator = Reflect.apply(asyncIterator, chunks, []);
      return iterator && typeof iterator.next === 'function' ? iterator : null;
    }
    const syncIterator = chunks[Symbol.iterator];
    if (typeof syncIterator !== 'function') return null;
    const iterator = Reflect.apply(syncIterator, chunks, []);
    if (!iterator || typeof iterator.next !== 'function') return null;
    return {
      async next() { return iterator.next(); },
      async return() {
        return typeof iterator.return === 'function'
          ? iterator.return()
          : { done: true, value: undefined };
      },
    };
  } catch {
    return null;
  }
}

function markerFingerprint(marker) {
  const { markerFingerprint: ignored, ...preimage } = marker;
  return canonicalJsonHash(preimage, MARKER_LIMITS);
}

function safeScratchName(serviceKey, transactionNonce, purpose) {
  const name = `${serviceKey}-${transactionNonce}-${purpose}`;
  return name.length <= 255 && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)
    ? name
    : null;
}

function relativeSegments(path) {
  if (typeof path !== 'string' || Buffer.byteLength(path, 'utf8') >
      DEPLOYMENT_ENVELOPE_LIMITS.pathBytes || path.startsWith('/') ||
      path.startsWith('\\') || path.includes('\\') || /^[A-Za-z]:/.test(path)) {
    return null;
  }
  const segments = path.split('/');
  if (segments.length === 0 || segments.length > DEPLOYMENT_ENVELOPE_LIMITS.pathSegments ||
      segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..' ||
        Buffer.byteLength(segment, 'utf8') > 255 ||
        segment.startsWith('.gjc-service-'))) {
    return null;
  }
  return segments;
}

function directExpected(expected, prefix) {
  const children = new Map();
  const start = prefix.length === 0 ? 0 : prefix.length + 1;
  for (const [path, record] of expected) {
    if (prefix.length !== 0 && !path.startsWith(`${prefix}/`)) continue;
    const suffix = path.slice(start);
    if (suffix.length === 0) continue;
    const slash = suffix.indexOf('/');
    const name = slash === -1 ? suffix : suffix.slice(0, slash);
    const kind = slash === -1 ? 'file' : 'directory';
    const prior = children.get(name);
    if (prior && prior.kind !== kind) return null;
    children.set(name, kind === 'file' ? { kind, record } : { kind });
  }
  return children;
}

function compareFacts(left, right) {
  try {
    return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
  } catch {
    return false;
  }
}


function expectedAssetFor(purpose, manifest) {
  const expectation = Object.freeze({
    size: purpose === 'application'
      ? manifest.archive.byteLength
      : manifest.executable.byteLength,
    sha256: purpose === 'application'
      ? manifest.archive.sha256
      : manifest.executable.sha256,
  });
  if (!Number.isSafeInteger(expectation.size) || expectation.size < 1 ||
      expectation.size > ARTIFACT_MAX_BYTES || !isHex64(expectation.sha256)) {
    return null;
  }
  return expectation;
}

function scratchMarker({
  purpose,
  manifest,
  transaction,
  transactionIdentity,
  roles,
  rolesFingerprint,
  platform,
  architecture,
  component,
  serviceKey,
  stagingRootBinding,
  scratchIdentity,
}) {
  const logicalTransaction = Object.fromEntries(
    LOGICAL_TRANSACTION_KEYS.map((key) => [key, transaction[key]]),
  );
  if (canonicalJsonHash(logicalTransaction, MARKER_LIMITS) !==
      transactionIdentity) {
    return null;
  }
  const asset = expectedAssetFor(purpose, manifest);
  if (asset === null) return null;
  const marker = {
    schemaVersion: 1,
    kind: 'service-artifact-transaction-marker',
    purpose,
    component,
    serviceKey,
    platform,
    architecture,
    transactionIdentity,
    transaction: logicalTransaction,
    candidate: transaction.candidate,
    asset,
    roles,
    rolesFingerprint,
    stagingRootBindingFingerprint: stagingRootBinding.bindingFingerprint,
    stagingRootIdentity: stagingRootBinding.identity,
    scratchIdentity,
    markerFingerprint: null,
  };
  marker.markerFingerprint = markerFingerprint(marker);
  return cloneJson(marker);
}
function factsMatchIdentity(facts, identity) {
  if (!plain(facts) || !plain(identity) || facts.owner !== identity.owner ||
      facts.securitySha256 !== identity.securitySha256) return false;
  if (facts.kind === 'linux-file-v1' && identity.kind === 'linux-service-object-v1') {
    return facts.device === identity.device && facts.inode === identity.inode &&
      facts.mode === identity.mode;
  }
  if (facts.kind === 'win32-file-v1' && identity.kind === 'win32-service-object-v1') {
    return facts.volumeSerial === identity.volumeSerial && facts.fileId === identity.fileId &&
      facts.attributes === identity.attributes;
  }
  return false;
}

class ArtifactAccessState {
  constructor(values) {
    this.bridge = values.bridge;
    this.purpose = values.purpose;
    this.manifestAuthority = values.manifest;
    this.manifest = cloneJson(values.manifest, {
      maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
      maxDepth: 32,
      maxNodes: 100_000,
    });
    this.transaction = cloneJson(values.transaction);
    this.transactionIdentity = values.transactionIdentity;
    this.roles = cloneJson(values.roles);
    this.rolesFingerprint = values.rolesFingerprint;
    this.platform = values.platform;
    this.architecture = values.architecture;
    this.component = values.component;
    this.serviceKey = values.serviceKey;
    this.onClose = values.onClose;
    this.closed = false;
    this.poisoned = false;
    this.busy = false;
    this.readers = new Set();
    this.writer = null;
    this.stagingRoot = null;
    this.scratch = null;
    this.candidate = null;
    this.destinationRoot = null;
    this.assetFacts = null;
    this.expected = null;
    this.inventoryBytes = null;
    this.inventory = null;
    this.written = new Set();
    this.candidateDirectories = new Map();
    this.candidateSealed = false;
    this.published = false;
    this.assetName = this.purpose === 'application' ? 'archive' : 'raw-shawl';
    this.publicationName = this.purpose === 'application'
      ? this.manifest.archive.sha256
      : this.manifest.executable.sha256;
    this.expectedAsset = expectedAssetFor(this.purpose, this.manifest);
    if (this.expectedAsset === null ||
        this.expectedAsset.sha256 !== this.publicationName) {
      this.fail('SERVICE_INVALID', OPERATIONS.open);
    }
    this.scratchName = safeScratchName(
      this.serviceKey,
      this.transaction.transactionNonce,
      this.purpose,
    );
    if (this.scratchName === null) this.fail('SERVICE_INVALID', OPERATIONS.open);
    try {
      this.openScratch();
    } catch (error) {
      try { this.close(); } catch {}
      throw error;
    }
  }

  fail(code, operation, ambiguous = false) {
    return this.bridge.fail(code, operation, ambiguous);
  }

  failCaptured(error, operation, fallback = 'SERVICE_IO_FAILED') {
    const captured = capturedFailure(error);
    this.fail(
      captured?.code ?? fallback,
      operation,
      captured?.ambiguous === true,
    );
  }

  ensureOpen(operation) {
    if (this.closed) this.fail('SERVICE_STALE', operation);
    if (this.poisoned) this.fail('SERVICE_MANUAL_CLEANUP', operation, true);
  }

  markManual(operation) {
    this.poisoned = true;
    this.fail('SERVICE_MANUAL_CLEANUP', operation, true);
  }

  async runAsync(operation, callback, poisonOnManual = false) {
    this.ensureOpen(operation);
    if (this.busy) this.fail('SERVICE_PENDING', operation);
    this.busy = true;
    try {
      return await callback();
    } catch (error) {
      if (poisonOnManual && error?.code === 'SERVICE_MANUAL_CLEANUP') {
        this.poisoned = true;
      }
      throw error;
    } finally {
      this.busy = false;
    }
  }

  runSync(operation, callback, poisonOnManual = false) {
    this.ensureOpen(operation);
    if (this.busy) this.fail('SERVICE_PENDING', operation);
    this.busy = true;
    try {
      return callback();
    } catch (error) {
      if (poisonOnManual && error?.code === 'SERVICE_MANUAL_CLEANUP') {
        this.poisoned = true;
      }
      throw error;
    } finally {
      this.busy = false;
    }
  }

  openOrCreateRoot(rootKind, operation) {
    return this.bridge.bootstrapRoot(rootKind, operation);
  }

  openScratch() {
    const operation = OPERATIONS.open;
    this.stagingRoot = this.openOrCreateRoot('staging', operation);
    const entries = this.bridge.listDirectory(this.stagingRoot.handle, operation);
    const entry = entries.entries.find(({ name }) => name === this.scratchName) ?? null;
    let created = false;
    if (entry === null) {
      this.scratch = this.bridge.openDirectory(
        this.stagingRoot.handle,
        this.scratchName,
        'create-new',
        null,
        operation,
      );
      created = true;
    } else {
      if (entry.identity.profile !== 'service-staging-directory') {
        this.markManual(operation);
      }
      this.scratch = this.bridge.openDirectory(
        this.stagingRoot.handle,
        this.scratchName,
        'write-existing',
        entry.identity,
        operation,
      );
    }
    const marker = this.buildMarker();
    const markerBytes = canonicalJsonBytes(marker, MARKER_LIMITS);
    const existing = this.bridge.readFile(
      this.scratch.handle,
      'transaction.json',
      MARKER_LIMITS.maxBytes,
      operation,
    );
    if (created) {
      if (existing !== null) this.markManual(operation);
      this.bridge.publishFile(
        this.scratch.handle,
        'transaction.json',
        markerBytes,
        null,
        operation,
      );
    } else {
      if (existing === null || !existing.bytes.equals(markerBytes)) {
        this.markManual(operation);
      }
      let parsed;
      try {
        parsed = parseCanonicalJsonBytes(existing.bytes, MARKER_LIMITS);
      } catch {
        this.markManual(operation);
      }
      if (!exact(parsed, MARKER_KEYS) || markerFingerprint(parsed) !== parsed.markerFingerprint ||
          !canonicalJsonBytes(parsed, MARKER_LIMITS).equals(markerBytes)) {
        this.markManual(operation);
      }
    }
    const scratchEntries = this.bridge.listDirectory(this.scratch.handle, operation).entries;
    const allowed = new Set(['transaction.json', this.assetName, 'candidate']);
    if (scratchEntries.some(({ name, identity }) =>
      !allowed.has(name) ||
      (name === 'transaction.json' && identity.profile !== 'service-staging-file') ||
      (name === this.assetName && identity.profile !== 'service-staging-file') ||
      (name === 'candidate' &&
       !['service-staging-directory', 'service-release-directory'].includes(identity.profile)))) {
      this.markManual(operation);
    }
  }

  buildMarker() {
    const marker = scratchMarker({
      purpose: this.purpose,
      manifest: this.manifest,
      transaction: this.transaction,
      transactionIdentity: this.transactionIdentity,
      roles: this.roles,
      rolesFingerprint: this.rolesFingerprint,
      platform: this.platform,
      architecture: this.architecture,
      component: this.component,
      serviceKey: this.serviceKey,
      stagingRootBinding: this.stagingRoot.rootBinding,
      scratchIdentity: this.scratch.identity,
    });
    if (marker === null) this.fail('SERVICE_INVALID', OPERATIONS.open);
    return marker;
  }

  findEntry(parent, name, operation) {
    return this.bridge.listDirectory(parent, operation).entries.find(
      (entry) => entry.name === name,
    ) ?? null;
  }

  closeNative(handle, operation) {
    if (handle !== null && handle !== undefined) this.bridge.closeHandle(handle, operation);
  }

  exactFile(
    parent,
    name,
    expected,
    expectedProfile,
    operation,
    retainedFacts = null,
    knownEntry = null,
  ) {
    const entry = knownEntry ?? this.findEntry(parent, name, operation);
    if (entry === null) return null;
    if (entry.identity.profile !== expectedProfile) this.markManual(operation);
    let opened;
    try {
      opened = this.bridge.openReader(
        parent,
        name,
        expected.size,
        retainedFacts,
        operation,
      );
    } catch (error) {
      if (error?.code === 'SERVICE_STALE') this.markManual(operation);
      throw error;
    }
    if (opened === null || opened.facts.size !== expected.size ||
        opened.facts.sha256 !== expected.sha256 ||
        !factsMatchIdentity(opened.facts, entry.identity)) {
      if (opened !== null) this.closeNative(opened.handle, operation);
      this.markManual(operation);
    }
    this.closeNative(opened.handle, operation);
    return deepFreeze(cloneJson(opened.facts));
  }

  async consumeExactChunks(chunks, expected, operation) {
    const iterator = iteratorFor(chunks);
    if (iterator === null) this.fail('SERVICE_INVALID', operation);
    return this.consumeExactIterator(iterator, expected, operation);
  }

  async consumeExactIterator(iterator, expected, operation) {
    const hash = createHash('sha256');
    let offset = 0;
    let emptyChunks = 0;
    try {
      for (;;) {
        const result = await iterator.next();
        if (!plain(result) || typeof result.done !== 'boolean') {
          this.fail('SERVICE_INVALID', operation);
        }
        if (result.done) break;
        const bytes = copyBytes(result.value, ARTIFACT_CHUNK_BYTES);
        if (bytes === null) this.fail('SERVICE_INVALID', operation);
        if (bytes.length === 0) {
          emptyChunks += 1;
          if (expected.size !== 0 || emptyChunks > 1) {
            this.fail('SERVICE_INVALID', operation);
          }
          continue;
        }
        if (offset > expected.size - bytes.length) {
          this.fail('SERVICE_SCOPE_MISMATCH', operation);
        }
        offset += bytes.length;
        hash.update(bytes);
      }
    } catch (error) {
      try {
        if (typeof iterator.return === 'function') await iterator.return();
      } catch {}
      this.failCaptured(error, operation);
    }
    if (offset !== expected.size || hash.digest('hex') !== expected.sha256) {
      this.fail('SERVICE_SCOPE_MISMATCH', operation);
    }
  }

  async preflightIterator(iterator, expected, operation) {
    let first;
    try {
      first = await iterator.next();
    } catch (error) {
      this.failCaptured(error, operation);
    }
    if (!plain(first) || typeof first.done !== 'boolean') {
      this.fail('SERVICE_INVALID', operation);
    }
    let bytes = null;
    if (first.done) {
      if (expected.size !== 0) this.fail('SERVICE_SCOPE_MISMATCH', operation);
    } else {
      bytes = copyBytes(first.value, ARTIFACT_CHUNK_BYTES);
      if (bytes === null || (bytes.length === 0 && expected.size !== 0)) {
        this.fail('SERVICE_INVALID', operation);
      }
      if (bytes.length > expected.size) {
        this.fail('SERVICE_SCOPE_MISMATCH', operation);
      }
    }
    let pending = true;
    return {
      async next() {
        if (pending) {
          pending = false;
          return first.done
            ? { done: true, value: undefined }
            : { done: false, value: bytes };
        }
        return iterator.next();
      },
      async return() {
        pending = false;
        return typeof iterator.return === 'function'
          ? iterator.return()
          : { done: true, value: undefined };
      },
    };
  }

  async writeStream(parent, name, expected, profile, chunks, operation, preparedIterator = null) {
    const iterator = preparedIterator ?? iteratorFor(chunks);
    if (iterator === null) this.fail('SERVICE_INVALID', operation);
    let first;
    try {
      first = await iterator.next();
    } catch (error) {
      this.failCaptured(error, operation);
    }
    if (!plain(first) || typeof first.done !== 'boolean') {
      this.fail('SERVICE_INVALID', operation);
    }
    let firstBytes = null;
    if (first.done) {
      if (expected.size !== 0) this.fail('SERVICE_SCOPE_MISMATCH', operation);
    } else {
      firstBytes = copyBytes(first.value, ARTIFACT_CHUNK_BYTES);
      if (firstBytes === null || (firstBytes.length === 0 && expected.size !== 0)) {
        this.fail('SERVICE_INVALID', operation);
      }
      if (firstBytes.length > expected.size) {
        this.fail('SERVICE_SCOPE_MISMATCH', operation);
      }
    }
    let offset = 0;
    let emptyChunks = firstBytes?.length === 0 ? 1 : 0;
    try {
      const begun = this.bridge.beginWrite(
        parent,
        name,
        expected.size,
        expected.sha256,
        operation,
      );
      this.writer = begun.handle;
      if (firstBytes !== null && firstBytes.length !== 0) {
        const written = this.bridge.writeChunk(
          this.writer,
          offset,
          firstBytes,
          operation,
        );
        offset = written.nextOffset;
      }
      let sourceDone = first.done;
      while (!sourceDone) {
        const result = await iterator.next();
        if (!plain(result) || typeof result.done !== 'boolean') {
          this.markManual(operation);
        }
        if (result.done) {
          sourceDone = true;
          break;
        }
        const bytes = copyBytes(result.value, ARTIFACT_CHUNK_BYTES);
        if (bytes === null) this.markManual(operation);
        if (bytes.length === 0) {
          emptyChunks += 1;
          if (expected.size !== 0 || emptyChunks > 1) this.markManual(operation);
          continue;
        }
        if (offset > expected.size - bytes.length) this.markManual(operation);
        const written = this.bridge.writeChunk(
          this.writer,
          offset,
          bytes,
          operation,
        );
        offset = written.nextOffset;
      }
      const finished = this.bridge.finishWrite(this.writer, profile, operation);
      this.writer = null;
      if (finished.facts.size !== expected.size ||
          finished.facts.sha256 !== expected.sha256) {
        this.markManual(operation);
      }
      return deepFreeze(cloneJson(finished.facts));
    } catch {
      try {
        if (typeof iterator.return === 'function') await iterator.return();
      } catch {}
      if (this.writer !== null) {
        try { this.closeNative(this.writer, operation); } catch {}
        this.writer = null;
      }
      this.poisoned = true;
      this.fail('SERVICE_MANUAL_CLEANUP', operation, true);
    }
  }

  async stageAsset(chunks) {
    const operation = OPERATIONS.stage;
    this.ensureOpen(operation);
    const existing = this.exactFile(
      this.scratch.handle,
      this.assetName,
      this.expectedAsset,
      'service-staging-file',
      operation,
      this.assetFacts,
    );
    if (existing !== null) {
      await this.consumeExactChunks(chunks, this.expectedAsset, operation);
      this.assetFacts = existing;
      return Object.freeze({ facts: existing });
    }
    this.assetFacts = await this.writeStream(
      this.scratch.handle,
      this.assetName,
      this.expectedAsset,
      'service-staging-file',
      chunks,
      operation,
    );
    return Object.freeze({ facts: this.assetFacts });
  }

  openStagedAsset() {
    const operation = OPERATIONS.openAsset;
    this.ensureOpen(operation);
    const facts = this.exactFile(
      this.scratch.handle,
      this.assetName,
      this.expectedAsset,
      'service-staging-file',
      operation,
      this.assetFacts,
    );
    if (facts === null) this.fail('SERVICE_STALE', operation);
    this.assetFacts = facts;
    let opened;
    try {
      opened = this.bridge.openReader(
        this.scratch.handle,
        this.assetName,
        this.expectedAsset.size,
        facts,
        operation,
      );
    } catch (error) {
      if (error?.code === 'SERVICE_STALE') this.markManual(operation);
      throw error;
    }
    if (opened === null || !compareFacts(opened.facts, facts)) {
      if (opened !== null) this.closeNative(opened.handle, operation);
      this.markManual(operation);
    }
    const reader = this.readerObject(opened.handle, facts);
    this.readers.add(reader.state);
    return reader.public;
  }

  readerObject(handle, facts) {
    const state = {
      handle,
      facts,
      offset: 0,
      complete: false,
      closed: false,
      started: false,
    };
    const owner = this;
    const closeReader = () => {
      if (state.closed) return;
      owner.closeNative(state.handle, OPERATIONS.readAsset);
      state.closed = true;
      owner.readers.delete(state);
    };
    const throwReadFailure = (error) => {
      owner.poisoned = true;
      if (typeof error?.code === 'string' &&
          /^SERVICE_[A-Z_]+$/.test(error.code)) {
        owner.fail(
          error.code,
          OPERATIONS.readAsset,
          error.ambiguous === true,
        );
      }
      owner.fail('SERVICE_IO_FAILED', OPERATIONS.readAsset, true);
    };
    const chunks = Object.freeze({
      [Symbol.asyncIterator]() {
        if (state.closed || owner.closed || state.started) {
          owner.fail('SERVICE_STALE', OPERATIONS.readAsset);
        }
        state.started = true;
        return Object.freeze({
          async next() {
            if (owner.closed) owner.fail('SERVICE_STALE', OPERATIONS.readAsset);
            if (state.complete) {
              return Object.freeze({ done: true, value: undefined });
            }
            if (state.closed) owner.fail('SERVICE_STALE', OPERATIONS.readAsset);
            let result;
            try {
              result = owner.bridge.readChunk(
                state.handle,
                state.offset,
                ARTIFACT_CHUNK_BYTES,
                OPERATIONS.readAsset,
              );
            } catch (error) {
              try {
                closeReader();
              } catch (closeError) {
                throwReadFailure(closeError);
              }
              throwReadFailure(error);
            }
            state.offset = result.nextOffset;
            if (result.eof) {
              try {
                closeReader();
              } catch (error) {
                throwReadFailure(error);
              }
              state.complete = true;
            }
            return Object.freeze({ done: false, value: result.bytes });
          },
          async return() {
            if (state.complete) {
              return Object.freeze({ done: true, value: undefined });
            }
            try {
              closeReader();
            } catch (error) {
              throwReadFailure(error);
            }
            owner.fail('SERVICE_PENDING', OPERATIONS.readAsset);
          },
          async throw() {
            if (!state.complete) {
              try {
                closeReader();
              } catch (error) {
                throwReadFailure(error);
              }
            }
            owner.fail('SERVICE_PENDING', OPERATIONS.readAsset);
          },
          [Symbol.asyncIterator]() { return this; },
        });
      },
    });
    const close = function close() {
      if (arguments.length !== 0) owner.fail('SERVICE_INVALID', OPERATIONS.readAsset);
      if (state.closed) return;
      closeReader();
    };
    return {
      state,
      public: Object.freeze({ facts, chunks, close }),
    };
  }

  expectedInventory(inventoryBytes, operation) {
    const bytes = copyBytes(inventoryBytes, DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes);
    if (bytes === null || bytes.length !== this.manifest.inventory.byteLength ||
        createHash('sha256').update(bytes).digest('hex') !== this.manifest.inventory.sha256) {
      this.fail('SERVICE_INVALID', operation);
    }
    let inventory;
    try {
      inventory = parseCanonicalJsonBytes(bytes, INVENTORY_LIMITS);
      validateBundleInventory(inventory, { platform: this.platform });
      validateApplicationDeploymentManifest(this.manifest, inventory);
    } catch {
      this.fail('SERVICE_INVALID', operation);
    }
    if (inventory.payloadEntryCount !== this.manifest.inventory.payloadEntryCount ||
        inventory.unpackedPayloadBytes !== this.manifest.inventory.unpackedPayloadBytes ||
        inventory.treeFingerprint !== this.manifest.inventory.treeFingerprint) {
      this.fail('SERVICE_SCOPE_MISMATCH', operation);
    }
    const expected = new Map();
    expected.set(APPLICATION_BUNDLE_INVENTORY_PATH, Object.freeze({
      path: APPLICATION_BUNDLE_INVENTORY_PATH,
      size: bytes.length,
      sha256: this.manifest.inventory.sha256,
      profile: 'service-release-file',
    }));
    for (const entry of inventory.payloadEntries) {
      expected.set(entry.path, Object.freeze({
        path: entry.path,
        size: entry.size,
        sha256: entry.sha256,
        profile: entry.executablePolicy === 'required'
          ? 'service-release-executable'
          : 'service-release-file',
      }));
    }
    if ([...expected.keys()].some((path) => relativeSegments(path) === null)) {
      this.fail('SERVICE_SCOPE_MISMATCH', operation);
    }
    return { bytes, expected, inventory };
  }

  prepareCandidate(inventoryBytes) {
    const operation = OPERATIONS.prepare;
    this.ensureOpen(operation);
    if (this.expected !== null) this.fail('SERVICE_PENDING', operation);
    if (this.assetFacts === null) {
      const facts = this.exactFile(
        this.scratch.handle,
        this.assetName,
        this.expectedAsset,
        'service-staging-file',
        operation,
      );
      if (facts === null) this.fail('SERVICE_STALE', operation);
      this.assetFacts = facts;
    }
    if (this.purpose === 'application') {
      const prepared = this.expectedInventory(inventoryBytes, operation);
      this.inventoryBytes = prepared.bytes;
      this.inventory = prepared.inventory;
      this.expected = prepared.expected;
    } else {
      if (inventoryBytes !== null) this.fail('SERVICE_INVALID', operation);
      this.expected = new Map([['shawl.exe', Object.freeze({
        path: 'shawl.exe',
        size: this.manifest.executable.byteLength,
        sha256: this.manifest.executable.sha256,
        profile: 'service-release-executable',
      })]]);
    }
    const entry = this.findEntry(this.scratch.handle, 'candidate', operation);
    if (entry === null) {
      this.candidate = this.bridge.openDirectory(
        this.scratch.handle,
        'candidate',
        'create-new',
        null,
        operation,
      );
      if (this.purpose === 'application') {
        const record = this.expected.get(APPLICATION_BUNDLE_INVENTORY_PATH);
        try {
          const begun = this.bridge.beginWrite(
            this.candidate.handle,
            APPLICATION_BUNDLE_INVENTORY_PATH,
            record.size,
            record.sha256,
            operation,
          );
          this.writer = begun.handle;
          let offset = 0;
          while (offset < this.inventoryBytes.length) {
            const bytes = this.inventoryBytes.subarray(
              offset,
              Math.min(offset + ARTIFACT_CHUNK_BYTES, this.inventoryBytes.length),
            );
            const written = this.bridge.writeChunk(
              this.writer,
              offset,
              bytes,
              operation,
            );
            offset = written.nextOffset;
          }
          if (offset !== record.size) this.markManual(operation);
          const finished = this.bridge.finishWrite(
            this.writer,
            record.profile,
            operation,
          );
          this.writer = null;
          if (finished.facts.size !== record.size || finished.facts.sha256 !== record.sha256) {
            this.markManual(operation);
          }
          this.written.add(APPLICATION_BUNDLE_INVENTORY_PATH);
        } catch {
          if (this.writer !== null) {
            try { this.closeNative(this.writer, operation); } catch {}
            this.writer = null;
          }
          this.poisoned = true;
          this.fail('SERVICE_MANUAL_CLEANUP', operation, true);
        }
      }
    } else if (entry.identity.profile === 'service-release-directory') {
      this.candidate = this.bridge.openDirectory(
        this.scratch.handle,
        'candidate',
        'write-existing',
        entry.identity,
        operation,
      );
      this.verifyTree(this.candidate.handle, '', true, operation);
      this.candidateSealed = true;
      for (const path of this.expected.keys()) this.written.add(path);
    } else {
      this.markManual(operation);
    }
    this.inventoryBytes = null;
    return Object.freeze({
      purpose: this.purpose,
      expectedFileCount: this.expected.size,
    });
  }

  openParentForPath(segments, operation) {
    const handles = [];
    let parent = this.candidate.handle;
    let prefix = '';
    let createFailed = false;
    try {
      for (const name of segments.slice(0, -1)) {
        prefix = prefix.length === 0 ? name : `${prefix}/${name}`;
        const identity = this.candidateDirectories.get(prefix) ?? null;
        let opened;
        if (identity === null) {
          try {
            opened = this.bridge.openDirectory(
              parent,
              name,
              'create-new',
              null,
              operation,
            );
          } catch (error) {
            createFailed = true;
            throw error;
          }
          handles.push(opened);
          this.candidateDirectories.set(prefix, opened.identity);
        } else {
          opened = this.bridge.openDirectory(
            parent,
            name,
            'write-existing',
            identity,
            operation,
          );
          handles.push(opened);
        }
        parent = opened.handle;
      }
      return { parent, handles };
    } catch (error) {
      let cleanupFailed = false;
      for (let index = handles.length - 1; index >= 0; index -= 1) {
        try {
          this.closeNative(handles[index].handle, operation);
        } catch {
          cleanupFailed = true;
        }
      }
      if (cleanupFailed || createFailed) this.markManual(operation);
      this.failCaptured(error, operation);
    }
  }

  async writeCandidateFile(path, chunks) {
    const operation = OPERATIONS.write;
    this.ensureOpen(operation);
    if (this.expected === null || this.candidate === null) {
      this.fail('SERVICE_PENDING', operation);
    }
    const segments = relativeSegments(path);
    const expected = segments === null ? null : this.expected.get(path);
    if (expected === undefined || expected === null) this.fail('SERVICE_INVALID', operation);
    const iterator = iteratorFor(chunks);
    if (iterator === null) this.fail('SERVICE_INVALID', operation);
    if (this.candidateSealed || this.written.has(path)) {
      await this.consumeExactIterator(iterator, expected, operation);
      this.verifyExpectedPath(path, expected, operation);
      this.written.add(path);
      return Object.freeze({ path, size: expected.size, sha256: expected.sha256 });
    }
    const prefetchedIterator = await this.preflightIterator(
      iterator,
      expected,
      operation,
    );
    let opened;
    try {
      opened = this.openParentForPath(segments, operation);
    } catch (error) {
      try { await prefetchedIterator.return(); } catch {}
      throw error;
    }
    try {
      await this.writeStream(
        opened.parent,
        segments.at(-1),
        expected,
        expected.profile,
        chunks,
        operation,
        prefetchedIterator,
      );
      this.written.add(path);
      return Object.freeze({ path, size: expected.size, sha256: expected.sha256 });
    } catch (error) {
      try { await prefetchedIterator.return(); } catch {}
      throw error;
    } finally {
      for (let index = opened.handles.length - 1; index >= 0; index -= 1) {
        this.closeNative(opened.handles[index].handle, operation);
      }
    }
  }

  verifyExpectedPath(path, expected, operation) {
    const segments = relativeSegments(path);
    let parent = this.candidate.handle;
    const handles = [];
    try {
      for (const name of segments.slice(0, -1)) {
        const entry = this.findEntry(parent, name, operation);
        if (entry === null || !['service-staging-directory', 'service-release-directory']
          .includes(entry.identity.profile)) this.markManual(operation);
        const opened = this.bridge.openDirectory(
          parent,
          name,
          'read-existing',
          entry.identity,
          operation,
        );
        handles.push(opened);
        parent = opened.handle;
      }
      if (this.exactFile(
        parent,
        segments.at(-1),
        expected,
        expected.profile,
        operation,
      ) === null) this.markManual(operation);
    } finally {
      for (let index = handles.length - 1; index >= 0; index -= 1) {
        this.closeNative(handles[index].handle, operation);
      }
    }
  }

  verifyTree(directory, prefix, sealed, operation) {
    const direct = directExpected(this.expected, prefix);
    if (direct === null) this.markManual(operation);
    const listing = this.bridge.listDirectory(directory, operation);
    if (listing.entries.length !== direct.size) this.markManual(operation);
    const observed = listing.entries.map(({ name }) => name);
    const names = [...direct.keys()].sort(utf8Compare);
    if (observed.some((name, index) => name !== names[index])) this.markManual(operation);
    for (const entry of listing.entries) {
      const expected = direct.get(entry.name);
      if (expected.kind === 'file') {
        if (entry.identity.profile !== expected.record.profile ||
            this.exactFile(
              directory,
              entry.name,
              expected.record,
              expected.record.profile,
              operation,
              null,
              entry,
            ) === null) this.markManual(operation);
        continue;
      }
      const requiredProfile = sealed
        ? 'service-release-directory'
        : 'service-staging-directory';
      if (entry.identity.profile !== requiredProfile) this.markManual(operation);
      const child = this.bridge.openDirectory(
        directory,
        entry.name,
        'read-existing',
        entry.identity,
        operation,
      );
      try {
        const childPrefix = prefix.length === 0
          ? entry.name
          : `${prefix}/${entry.name}`;
        this.verifyTree(child.handle, childPrefix, sealed, operation);
      } finally {
        this.closeNative(child.handle, operation);
      }
    }
  }

  sealTree(directory, identity, prefix, operation) {
    const direct = directExpected(this.expected, prefix);
    const listing = this.bridge.listDirectory(directory, operation);
    if (direct === null || listing.entries.length !== direct.size) this.markManual(operation);
    const observed = listing.entries.map(({ name }) => name);
    const names = [...direct.keys()].sort(utf8Compare);
    if (observed.some((name, index) => name !== names[index])) this.markManual(operation);
    for (const entry of listing.entries) {
      const expected = direct.get(entry.name);
      if (expected.kind === 'file') {
        if (entry.identity.profile !== expected.record.profile ||
            this.exactFile(
              directory,
              entry.name,
              expected.record,
              expected.record.profile,
              operation,
              null,
              entry,
            ) === null) this.markManual(operation);
        continue;
      }
      if (entry.identity.profile !== 'service-staging-directory') this.markManual(operation);
      const child = this.bridge.openDirectory(
        directory,
        entry.name,
        'write-existing',
        entry.identity,
        operation,
      );
      try {
        const childPrefix = prefix.length === 0
          ? entry.name
          : `${prefix}/${entry.name}`;
        this.sealTree(child.handle, child.identity, childPrefix, operation);
      } finally {
        this.closeNative(child.handle, operation);
      }
    }
    const relisted = this.bridge.listDirectory(directory, operation);
    if (relisted.entries.length !== direct.size ||
        relisted.entries.some((entry, index) => entry.name !== names[index])) {
      this.markManual(operation);
    }
    for (const entry of relisted.entries) {
      const expected = direct.get(entry.name);
      const profile = expected.kind === 'directory'
        ? 'service-release-directory'
        : expected.record.profile;
      if (entry.identity.profile !== profile) this.markManual(operation);
    }
    return this.bridge.sealDirectory(directory, identity, operation).identity;
  }

  openDestination(operation, create) {
    if (this.destinationRoot !== null) return this.destinationRoot;
    const rootKind = this.purpose === 'application' ? 'releases' : 'shawl';
    this.destinationRoot = create
      ? this.bridge.bootstrapRoot(rootKind, operation)
      : this.bridge.openRoot(rootKind, 'write-existing', operation);
    return this.destinationRoot;
  }

  observeExistingTarget(destination, operation, disposition) {
    const entry = this.findEntry(destination.handle, this.publicationName, operation);
    if (entry === null) return null;
    if (entry.identity.profile !== 'service-release-directory') this.markManual(operation);
    const target = this.bridge.openDirectory(
      destination.handle,
      this.publicationName,
      'read-existing',
      entry.identity,
      operation,
    );
    try {
      this.verifyTree(target.handle, '', true, operation);
      return this.bridge.observePublication(
        this.purpose,
        this.manifestAuthority,
        target.identity,
        operation,
        disposition,
        this.inventory,
      );
    } finally {
      this.closeNative(target.handle, operation);
    }
  }

  publishCandidate() {
    const operation = OPERATIONS.publish;
    this.ensureOpen(operation);
    if (this.expected === null) this.fail('SERVICE_PENDING', operation);
    if (this.published) {
      const observed = this.observeExistingTarget(
        this.destinationRoot,
        operation,
        'published',
      );
      if (observed === null) this.markManual(operation);
      return observed;
    }
    if (this.candidate === null) this.fail('SERVICE_PENDING', operation);
    const complete = this.written.size === this.expected.size &&
      [...this.expected.keys()].every((path) => this.written.has(path));
    if (!complete) {
      this.fail('SERVICE_PENDING', operation);
    }
    const destination = this.openDestination(operation, true);
    const reused = this.observeExistingTarget(destination, operation, 'reused');
    if (reused !== null) {
      this.published = true;
      return reused;
    }
    if (destination === null) this.markManual(operation);
    if (!this.candidateSealed) {
      this.verifyTree(this.candidate.handle, '', false, operation);
      const identity = this.sealTree(
        this.candidate.handle,
        this.candidate.identity,
        '',
        operation,
      );
      this.candidate = Object.freeze({ ...this.candidate, identity });
      this.candidateSealed = true;
    }
    this.verifyTree(this.candidate.handle, '', true, operation);
    const published = this.bridge.publishDirectory(
      this.candidate.handle,
      destination.handle,
      this.publicationName,
      this.candidate.identity,
      operation,
    );
    this.candidate = Object.freeze({ ...this.candidate, identity: published.identity });
    this.verifyTree(this.candidate.handle, '', true, operation);
    this.closeNative(this.candidate.handle, operation);
    this.candidate = null;
    const observed = this.observeExistingTarget(destination, operation, 'published');
    if (observed === null) this.markManual(operation);
    this.published = true;
    return observed;
  }

  close() {
    if (this.closed) return;
    if (this.busy) this.fail('SERVICE_PENDING', OPERATIONS.close);
    let first = null;
    for (const reader of [...this.readers]) {
      try {
        this.closeNative(reader.handle, OPERATIONS.close);
        reader.closed = true;
        this.readers.delete(reader);
      } catch (error) {
        first ??= error;
      }
    }
    if (this.writer !== null) {
      try {
        this.closeNative(this.writer, OPERATIONS.close);
        this.writer = null;
      } catch (error) {
        first ??= error;
      }
    }
    for (const property of ['candidate', 'destinationRoot', 'scratch', 'stagingRoot']) {
      const retained = this[property];
      if (retained === null) continue;
      try {
        this.closeNative(retained.handle, OPERATIONS.close);
        this[property] = null;
      } catch (error) {
        first ??= error;
      }
    }
    if (first !== null) throw first;
    this.closed = true;
    this.inventoryBytes = null;
    this.inventory = null;
    this.expected = null;
    this.candidateDirectories.clear();
    this.onClose();
  }
}

const COLLECTION_KEYS = Object.freeze([
  'bridge',
  'purpose',
  'manifest',
  'artifact',
  'platform',
  'expectedRootBindingFingerprint',
  'expectedRootIdentity',
  'phase',
  'advancePhase',
]);
const COLLECTION_PHASES = new Set([
  'payload-removing',
  'inventory-removing',
  'root-removing',
]);
const COLLECTION_OPERATIONS = Object.freeze({
  inspect: 'inspect_published_service_artifact',
  collect: 'collect_published_service_artifact',
});

class RetainedArtifactChildren {
  constructor(bridge, operation) {
    this.bridge = bridge;
    this.operation = operation;
    this.ownedHandles = [];
  }

  fail(code = 'SERVICE_MANUAL_CLEANUP', ambiguous = true) {
    this.bridge.fail(code, this.operation, ambiguous);
  }

  releaseState() {}

  retain(opened) {
    this.bridge.adoptHandle(opened.handle, this.operation);
    this.ownedHandles.push(opened.handle);
    return opened;
  }

  release(handle) {
    this.bridge.disownHandle(handle, this.operation);
    this.bridge.closeHandle(handle, this.operation);
    const index = this.ownedHandles.lastIndexOf(handle);
    if (index !== -1) this.ownedHandles.splice(index, 1);
    this.releaseState(handle);
  }

  close() {
    let failure = null;
    for (const handle of [...this.ownedHandles].reverse()) {
      if (!this.ownedHandles.includes(handle)) continue;
      try {
        this.release(handle);
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure !== null) throw failure;
  }

  async closeAfter(callback) {
    try {
      const result = await callback();
      this.close();
      return result;
    } catch (error) {
      try {
        this.close();
      } catch {}
      throw error;
    }
  }
}

class PublishedArtifactCollector extends RetainedArtifactChildren {
  constructor(values) {
    const operation = values.phase === null
      ? COLLECTION_OPERATIONS.inspect
      : COLLECTION_OPERATIONS.collect;
    super(values.bridge, operation);
    this.purpose = values.purpose;
    this.manifest = values.manifest;
    this.artifact = values.artifact;
    this.platform = values.platform;
    this.expectedRootBindingFingerprint =
      values.expectedRootBindingFingerprint;
    this.expectedRootIdentity = values.expectedRootIdentity;
    this.phase = values.phase;
    this.advancePhase = values.advancePhase;
    this.root = null;
    this.target = null;
  }

  releaseState(handle) {
    if (this.root?.handle === handle) this.root = null;
    if (this.target?.handle === handle) this.target = null;
  }
  openTarget() {
    const root = this.bridge.openRoot(
      this.artifact.rootKind,
      'write-existing',
      this.operation,
    );
    if (root === null) this.fail('SERVICE_STALE', false);
    this.root = this.retain(root);
    if (this.expectedRootBindingFingerprint !== null &&
        (this.root.rootBinding.bindingFingerprint !==
          this.expectedRootBindingFingerprint ||
         !compareFacts(
           this.root.rootBinding.identity,
           this.expectedRootIdentity,
         ))) {
      this.fail();
    }
    const entry = this.bridge.listDirectory(
      this.root.handle,
      this.operation,
    ).entries.find(({ name }) =>
      name === this.artifact.artifactFingerprint) ?? null;
    if (entry === null) {
      if (this.phase === 'root-removing') return false;
      this.fail('SERVICE_STALE', false);
    }
    if (!compareFacts(entry.identity, this.artifact.directoryIdentity) ||
        entry.identity.profile !== 'service-release-directory') {
      this.fail();
    }
    try {
      const target = this.bridge.openDirectory(
        this.root.handle,
        this.artifact.artifactFingerprint,
        'write-existing',
        this.artifact.directoryIdentity,
        this.operation,
      );
      this.target = this.retain(target);
    } catch {
      this.fail();
    }
    return true;
  }

  async readFile(directory, entry, expected, collectBytes = false) {
    if (entry.identity.profile !== expected.profile) this.fail();
    let opened;
    try {
      opened = this.bridge.openReader(
        directory,
        entry.name,
        expected.size,
        null,
        this.operation,
      );
      if (opened !== null) this.retain(opened);
    } catch {
      this.fail();
    }
    if (opened === null ||
        opened.facts.size !== expected.size ||
        opened.facts.sha256 !== expected.sha256 ||
        !factsMatchIdentity(opened.facts, entry.identity)) {
      if (opened !== null) {
        try {
          this.release(opened.handle);
        } catch {}
      }
      this.fail();
    }
    const parts = [];
    let offset = 0;
    let eof = false;
    try {
      while (!eof) {
        const result = this.bridge.readChunk(
          opened.handle,
          offset,
          ARTIFACT_CHUNK_BYTES,
          this.operation,
        );
        offset = result.nextOffset;
        eof = result.eof;
        if (collectBytes && result.bytes.length !== 0) {
          parts.push(result.bytes);
        }
      }
      if (offset !== expected.size) this.fail();
    } catch {
      try {
        this.release(opened.handle);
      } catch {}
      this.fail();
    }
    this.release(opened.handle);
    return Object.freeze({
      facts: deepFreeze(cloneJson(opened.facts)),
      bytes: collectBytes ? Buffer.concat(parts, expected.size) : null,
    });
  }

  async applicationExpected() {
    const listing = this.bridge.listDirectory(
      this.target.handle,
      this.operation,
    );
    const entry = listing.entries.find(({ name }) =>
      name === APPLICATION_BUNDLE_INVENTORY_PATH) ?? null;
    if (entry === null) this.fail('SERVICE_STALE', false);
    const expectedInventory = Object.freeze({
      size: this.manifest.inventory.byteLength,
      sha256: this.manifest.inventory.sha256,
      profile: 'service-release-file',
    });
    const read = await this.readFile(
      this.target.handle,
      entry,
      expectedInventory,
      true,
    );
    let inventory;
    try {
      inventory = parseCanonicalJsonBytes(read.bytes, INVENTORY_LIMITS);
      validateBundleInventory(inventory, { platform: this.platform });
      validateApplicationDeploymentManifest(this.manifest, inventory);
    } catch {
      this.fail();
    }
    const expected = new Map([[
      APPLICATION_BUNDLE_INVENTORY_PATH,
      Object.freeze({
        path: APPLICATION_BUNDLE_INVENTORY_PATH,
        ...expectedInventory,
      }),
    ]]);
    for (const record of inventory.payloadEntries) {
      expected.set(record.path, Object.freeze({
        path: record.path,
        size: record.size,
        sha256: record.sha256,
        profile: record.executablePolicy === 'required'
          ? 'service-release-executable'
          : 'service-release-file',
      }));
    }
    return expected;
  }

  expectedShawl() {
    try {
      validateShawlDeploymentManifest(this.manifest);
    } catch {
      this.fail();
    }
    return new Map([['shawl.exe', Object.freeze({
      path: 'shawl.exe',
      size: this.manifest.executable.byteLength,
      sha256: this.manifest.executable.sha256,
      profile: 'service-release-executable',
    })]]);
  }

  async expected() {
    return this.purpose === 'application'
      ? this.applicationExpected()
      : this.expectedShawl();
  }

  async visitDirectory(
    directory,
    prefix,
    expected,
    { allowMissing, removePayload },
  ) {
    const direct = directExpected(expected, prefix);
    if (direct === null) this.fail();
    const listing = this.bridge.listDirectory(directory, this.operation);
    const entries = new Map(listing.entries.map((entry) => [entry.name, entry]));
    if (listing.entries.some((entry) => !direct.has(entry.name)) ||
        (!allowMissing && entries.size !== direct.size)) {
      this.fail();
    }
    for (const [name, descriptor] of direct) {
      const entry = entries.get(name);
      if (entry === undefined) {
        if (!allowMissing) this.fail('SERVICE_STALE', false);
        continue;
      }
      const path = prefix.length === 0 ? name : `${prefix}/${name}`;
      if (descriptor.kind === 'file') {
        const read = await this.readFile(
          directory,
          entry,
          descriptor.record,
        );
        if (removePayload &&
            path !== APPLICATION_BUNDLE_INVENTORY_PATH) {
          this.bridge.removeFile(
            directory,
            name,
            read.facts,
            this.operation,
          );
        }
        continue;
      }
      if (entry.identity.profile !== 'service-release-directory') {
        this.fail();
      }
      let child;
      try {
        child = this.retain(this.bridge.openDirectory(
          directory,
          name,
          'write-existing',
          entry.identity,
          this.operation,
        ));
      } catch {
        this.fail();
      }
      try {
        await this.visitDirectory(
          child.handle,
          path,
          expected,
          { allowMissing, removePayload },
        );
      } finally {
        this.release(child.handle);
      }
      if (removePayload) {
        this.bridge.removeObject(
          directory,
          name,
          entry.identity,
          this.operation,
        );
      }
    }
  }

  assertRootContents(names) {
    const listing = this.bridge.listDirectory(
      this.target.handle,
      this.operation,
    );
    const expected = [...names].sort(utf8Compare);
    if (listing.entries.length !== expected.length ||
        listing.entries.some((entry, index) =>
          entry.name !== expected[index])) {
      this.fail();
    }
    return listing;
  }

  async inspect() {
    return this.closeAfter(async () => {
      if (!this.openTarget()) this.fail('SERVICE_STALE', false);
      const expected = await this.expected();
      await this.visitDirectory(
        this.target.handle,
        '',
        expected,
        { allowMissing: false, removePayload: false },
      );
      return Object.freeze({
        artifactRootBindingFingerprint:
          this.root.rootBinding.bindingFingerprint,
        artifactRootIdentity: deepFreeze(
          cloneJson(this.root.rootBinding.identity),
        ),
      });
    });
  }

  async collect() {
    return this.closeAfter(async () => {
      const present = this.openTarget();
      if (!present) return Object.freeze({ targetAbsent: true });
      if (this.phase === 'payload-removing') {
        const expected = await this.expected();
        await this.visitDirectory(
          this.target.handle,
          '',
          expected,
          { allowMissing: true, removePayload: false },
        );
        await this.visitDirectory(
          this.target.handle,
          '',
          expected,
          { allowMissing: true, removePayload: true },
        );
        this.assertRootContents(
          this.purpose === 'application'
            ? [APPLICATION_BUNDLE_INVENTORY_PATH]
            : [],
        );
        this.advancePhase('inventory-removing');
        this.phase = 'inventory-removing';
      }
      if (this.phase === 'inventory-removing') {
        const listing = this.bridge.listDirectory(
          this.target.handle,
          this.operation,
        );
        if (listing.entries.some((entry) =>
          entry.name !== APPLICATION_BUNDLE_INVENTORY_PATH) ||
            (this.purpose === 'shawl' && listing.entries.length !== 0) ||
            listing.entries.length > 1) {
          this.fail();
        }
        if (this.purpose === 'application') {
          const entry = listing.entries[0] ?? null;
          if (entry !== null) {
            const expectedInventory = Object.freeze({
              size: this.manifest.inventory.byteLength,
              sha256: this.manifest.inventory.sha256,
              profile: 'service-release-file',
            });
            const read = await this.readFile(
              this.target.handle,
              entry,
              expectedInventory,
              true,
            );
            try {
              const inventory = parseCanonicalJsonBytes(
                read.bytes,
                INVENTORY_LIMITS,
              );
              validateBundleInventory(inventory, {
                platform: this.platform,
              });
              validateApplicationDeploymentManifest(
                this.manifest,
                inventory,
              );
            } catch {
              this.fail();
            }
            this.bridge.removeFile(
              this.target.handle,
              APPLICATION_BUNDLE_INVENTORY_PATH,
              read.facts,
              this.operation,
            );
          }
        }
        this.assertRootContents([]);
        this.advancePhase('root-removing');
        this.phase = 'root-removing';
      }
      if (this.phase !== 'root-removing') this.fail('SERVICE_INVALID', false);
      this.assertRootContents([]);
      const targetIdentity = this.target.identity;
      this.release(this.target.handle);
      this.bridge.removeObject(
        this.root.handle,
        this.artifact.artifactFingerprint,
        targetIdentity,
        this.operation,
      );
      return Object.freeze({ targetAbsent: true });
    });
  }
}

function collectionValues(input) {
  const values = dataValues(input, COLLECTION_KEYS);
  const bridgeValues = values === null
    ? null
    : dataValues(values.bridge, BRIDGE_KEYS);
  if (values === null || bridgeValues === null ||
      BRIDGE_KEYS.some((key) => typeof bridgeValues[key] !== 'function') ||
      !['application', 'shawl'].includes(values.purpose) ||
      !plain(values.manifest) || !plain(values.artifact) ||
      !['linux', 'win32'].includes(values.platform) ||
      (values.expectedRootBindingFingerprint !== null &&
       !isHex64(values.expectedRootBindingFingerprint)) ||
      (values.expectedRootBindingFingerprint === null) !==
       (values.expectedRootIdentity === null) ||
      (values.phase !== null && !COLLECTION_PHASES.has(values.phase)) ||
      typeof values.advancePhase !== 'function') {
    if (bridgeValues !== null && typeof bridgeValues.fail === 'function') {
      bridgeValues.fail(
        'SERVICE_INVALID',
        COLLECTION_OPERATIONS.inspect,
        false,
      );
    }
    throw new TypeError('Invalid private service artifact collection');
  }
  const expectedKind = values.purpose === 'application'
    ? 'application-deployment-manifest'
    : 'shawl-deployment-manifest';
  const expectedRoot = values.purpose === 'application'
    ? 'releases'
    : 'shawl';
  const expectedDigest = values.purpose === 'application'
    ? values.manifest.archive?.sha256
    : values.manifest.executable?.sha256;
  if (values.manifest.kind !== expectedKind ||
      values.manifest.target?.platform !== values.platform ||
      values.artifact.artifactKind !== values.purpose ||
      values.artifact.rootKind !== expectedRoot ||
      values.artifact.artifactFingerprint !== expectedDigest ||
      values.artifact.manifestFingerprint !==
        values.manifest.manifestFingerprint) {
    bridgeValues.fail(
      'SERVICE_SCOPE_MISMATCH',
      values.phase === null
        ? COLLECTION_OPERATIONS.inspect
        : COLLECTION_OPERATIONS.collect,
      false,
    );
  }
  values.bridge = Object.freeze(Object.fromEntries(
    BRIDGE_KEYS.map((key) => [key, bridgeValues[key]]),
  ));
  return values;
}

export function createServicePublishedArtifactCollectorInternal(input) {
  const values = collectionValues(input);
  const inspect = values.phase === null;
  if (inspect !==
      (values.expectedRootBindingFingerprint === null)) {
    values.bridge.fail(
      'SERVICE_INVALID',
      inspect
        ? COLLECTION_OPERATIONS.inspect
        : COLLECTION_OPERATIONS.collect,
      false,
    );
  }
  const state = new PublishedArtifactCollector(values);
  let active = false;
  const run = async (method) => {
    if (active) state.fail('SERVICE_PENDING', false);
    active = true;
    try {
      return await state[method]();
    } finally {
      active = false;
    }
  };
  return Object.freeze({
    inspect() {
      if (arguments.length !== 0 || !inspect) {
        state.fail('SERVICE_INVALID', false);
      }
      return run('inspect');
    },
    collect() {
      if (arguments.length !== 0 || inspect) {
        state.fail('SERVICE_INVALID', false);
      }
      return run('collect');
    },
    retryClose() {
      if (arguments.length !== 0) {
        state.fail('SERVICE_INVALID', false);
      }
      if (active) state.fail('SERVICE_PENDING', false);
      state.close();
      return Object.freeze({ released: true });
    },
  });
}

const SCRATCH_COLLECTOR_KEYS = Object.freeze([
  'bridge',
  'purpose',
  'manifest',
  'transaction',
  'transactionIdentity',
  'roles',
  'rolesFingerprint',
  'platform',
  'architecture',
  'component',
  'serviceKey',
  'authority',
  'inspectArchive',
  'phase',
  'advancePhase',
]);
const SCRATCH_AUTHORITY_KEYS = Object.freeze([
  'stagingRootBindingFingerprint',
  'stagingRootIdentity',
  'scratchName',
  'scratchIdentity',
  'markerFingerprint',
  'markerFacts',
  'assetName',
  'assetSize',
  'assetSha256',
  'assetFacts',
  'candidateIdentity',
]);
const SCRATCH_OPERATIONS = Object.freeze({
  capture: 'capture_scratch_artifact_authority',
  collect: 'collect_scratch_artifact_space',
});
const SCRATCH_APPLICATION_PHASES = Object.freeze([
  'candidate-payload-removing',
  'candidate-inventory-removing',
  'candidate-root-removing',
  'asset-removing',
  'marker-removing',
  'scratch-root-removing',
]);
const SCRATCH_SHAWL_PHASES = Object.freeze(
  SCRATCH_APPLICATION_PHASES.filter(
    (phase) => phase !== 'candidate-inventory-removing',
  ),
);
const SCRATCH_DIRECTORY_PROFILES = new Set([
  'service-staging-directory',
  'service-release-directory',
]);
const SCRATCH_FILE_PROFILES = new Set([
  'service-staging-file',
  'service-release-file',
  'service-release-executable',
]);

class ScratchArtifactCollector extends RetainedArtifactChildren {
  constructor(values) {
    const operation = values.phase === null
      ? SCRATCH_OPERATIONS.capture
      : SCRATCH_OPERATIONS.collect;
    super(values.bridge, operation);
    this.purpose = values.purpose;
    this.manifest = values.manifest;
    this.platform = values.platform;
    this.phase = values.phase;
    this.advancePhase = values.advancePhase;
    this.inspectArchive = values.inspectArchive;
    this.authority = values.authority;
    this.captureInput = values.phase === null
      ? Object.freeze({
        transaction: values.transaction,
        transactionIdentity: values.transactionIdentity,
        roles: values.roles,
        rolesFingerprint: values.rolesFingerprint,
        architecture: values.architecture,
        component: values.component,
        serviceKey: values.serviceKey,
      })
      : null;
    this.phases = this.purpose === 'shawl'
      ? SCRATCH_SHAWL_PHASES
      : SCRATCH_APPLICATION_PHASES;
    this.assetName = this.purpose === 'application' ? 'archive' : 'raw-shawl';
    this.assetExpect = values.phase === null
      ? expectedAssetFor(this.purpose, this.manifest)
      : Object.freeze({
        size: this.authority.assetSize,
        sha256: this.authority.assetSha256,
      });
    this.scratchName = values.phase === null
      ? safeScratchName(
        values.serviceKey,
        values.transaction.transactionNonce,
        this.purpose,
      )
      : this.authority.scratchName;
    this.root = null;
    this.scratch = null;
    this.candidate = null;
    this.markerFacts = null;
    this.observedAssetFacts = null;
  }

  releaseState(handle) {
    if (this.root?.handle === handle) this.root = null;
    if (this.scratch?.handle === handle) this.scratch = null;
    if (this.candidate?.handle === handle) this.candidate = null;
  }

  phaseIndex(phase = this.phase) {
    return this.phases.indexOf(phase);
  }

  advance() {
    const index = this.phaseIndex();
    if (index === -1 || index + 1 >= this.phases.length) {
      this.fail('SERVICE_INVALID', false);
    }
    const next = this.phases[index + 1];
    this.advancePhase(next);
    this.phase = next;
  }

  verifyMarkerBytes(bytes, facts) {
    let parsed;
    try {
      parsed = parseCanonicalJsonBytes(bytes, MARKER_LIMITS);
    } catch {
      this.fail();
    }
    if (!exact(parsed, MARKER_KEYS) ||
        markerFingerprint(parsed) !== parsed.markerFingerprint ||
        parsed.markerFingerprint !== this.authority.markerFingerprint ||
        !compareFacts(facts, this.authority.markerFacts)) {
      this.fail();
    }
    return parsed;
  }
  observeFileFacts(parent, entry, maximum) {
    let opened;
    try {
      opened = this.bridge.openReader(
        parent,
        entry.name,
        maximum,
        null,
        this.operation,
      );
    } catch {
      this.fail();
    }
    if (opened === null) this.fail('SERVICE_STALE', false);
    this.retain(opened);
    try {
      if (!factsMatchIdentity(opened.facts, entry.identity)) this.fail();
      return deepFreeze(cloneJson(opened.facts));
    } finally {
      this.release(opened.handle);
    }
  }

  async capture() {
    return this.closeAfter(async () => {
      const root = this.bridge.openRoot(
        'staging',
        'write-existing',
        this.operation,
      );
      if (root === null) return null;
      this.root = this.retain(root);
      const entry = this.bridge.listDirectory(
        this.root.handle,
        this.operation,
      ).entries.find(({ name }) => name === this.scratchName) ?? null;
      if (entry === null) return null;
      if (entry.identity.profile !== 'service-staging-directory') this.fail();
      this.scratch = this.retain(this.bridge.openDirectory(
        this.root.handle,
        this.scratchName,
        'write-existing',
        entry.identity,
        this.operation,
      ));
      const markerBytes = this.bridge.readFile(
        this.scratch.handle,
        'transaction.json',
        MARKER_LIMITS.maxBytes,
        this.operation,
      );
      if (markerBytes === null) this.fail();
      let parsed;
      try {
        parsed = parseCanonicalJsonBytes(markerBytes.bytes, MARKER_LIMITS);
      } catch {
        this.fail();
      }
      if (!exact(parsed, MARKER_KEYS) ||
          markerFingerprint(parsed) !== parsed.markerFingerprint) {
        this.fail();
      }
      const expected = scratchMarker({
        purpose: this.purpose,
        manifest: this.manifest,
        transaction: this.captureInput.transaction,
        transactionIdentity: this.captureInput.transactionIdentity,
        roles: this.captureInput.roles,
        rolesFingerprint: this.captureInput.rolesFingerprint,
        platform: this.platform,
        architecture: this.captureInput.architecture,
        component: this.captureInput.component,
        serviceKey: this.captureInput.serviceKey,
        stagingRootBinding: this.root.rootBinding,
        scratchIdentity: this.scratch.identity,
      });
      if (expected === null) this.fail('SERVICE_INVALID', false);
      if (!canonicalJsonBytes(expected, MARKER_LIMITS)
        .equals(markerBytes.bytes)) {
        this.fail();
      }
      const entries = this.bridge.listDirectory(
        this.scratch.handle,
        this.operation,
      ).entries;
      const allowed = new Set(['transaction.json', this.assetName, 'candidate']);
      const markerEntry = entries.find(({ name }) =>
        name === 'transaction.json');
      if (markerEntry === undefined ||
          markerEntry.identity.profile !== 'service-staging-file' ||
          entries.some((candidateEntry) => !allowed.has(candidateEntry.name))) {
        this.fail();
      }
      const assetEntry = entries.find(({ name }) =>
        name === this.assetName) ?? null;
      let assetFacts = null;
      if (assetEntry !== null) {
        if (assetEntry.identity.profile !== 'service-staging-file') {
          this.fail();
        }
        assetFacts = this.observeFileFacts(
          this.scratch.handle,
          assetEntry,
          this.assetExpect.size,
        );
      }
      const candidateEntry = entries.find(({ name }) =>
        name === 'candidate') ?? null;
      let candidateIdentity = null;
      if (candidateEntry !== null) {
        if (!SCRATCH_DIRECTORY_PROFILES.has(candidateEntry.identity.profile)) {
          this.fail();
        }
        candidateIdentity = deepFreeze(cloneJson(candidateEntry.identity));
      }
      return Object.freeze({
        stagingRootBindingFingerprint:
          this.root.rootBinding.bindingFingerprint,
        stagingRootIdentity: deepFreeze(
          cloneJson(this.root.rootBinding.identity),
        ),
        scratchName: this.scratchName,
        scratchIdentity: deepFreeze(cloneJson(this.scratch.identity)),
        markerFingerprint: parsed.markerFingerprint,
        markerFacts: deepFreeze(cloneJson(markerBytes.facts)),
        assetName: this.assetName,
        assetSize: this.assetExpect.size,
        assetSha256: this.assetExpect.sha256,
        assetFacts,
        candidateIdentity,
      });
    });
  }

  openScratch() {
    const root = this.bridge.openRoot(
      'staging',
      'write-existing',
      this.operation,
    );
    if (root === null) this.fail();
    this.root = this.retain(root);
    if (this.root.rootBinding.bindingFingerprint !==
          this.authority.stagingRootBindingFingerprint ||
        !compareFacts(
          this.root.rootBinding.identity,
          this.authority.stagingRootIdentity,
        )) {
      this.fail();
    }
    const entry = this.bridge.listDirectory(
      this.root.handle,
      this.operation,
    ).entries.find(({ name }) => name === this.scratchName) ?? null;
    if (entry === null) {
      if (this.phase === 'scratch-root-removing') return false;
      this.fail('SERVICE_STALE', false);
    }
    if (entry.identity.profile !== 'service-staging-directory' ||
        !compareFacts(entry.identity, this.authority.scratchIdentity)) {
      this.fail();
    }
    try {
      this.scratch = this.retain(this.bridge.openDirectory(
        this.root.handle,
        this.scratchName,
        'write-existing',
        entry.identity,
        this.operation,
      ));
    } catch {
      this.fail();
    }
    return true;
  }

  validateTopLevel() {
    const entries = this.bridge.listDirectory(
      this.scratch.handle,
      this.operation,
    ).entries;
    const index = this.phaseIndex();
    const markerIndex = this.phaseIndex('marker-removing');
    const assetIndex = this.phaseIndex('asset-removing');
    const candidateIndex = this.phaseIndex('candidate-root-removing');
    const names = new Set(entries.map((entry) => entry.name));
    for (const name of names) {
      if (name !== 'transaction.json' && name !== this.assetName &&
          name !== 'candidate') {
        this.fail();
      }
    }
    const markerEntry = entries.find(({ name }) =>
      name === 'transaction.json') ?? null;
    if (markerEntry === null) {
      if (index < markerIndex) this.fail();
    } else if (index > markerIndex) {
      this.fail();
    } else {
      if (markerEntry.identity.profile !== 'service-staging-file') {
        this.fail();
      }
      const marker = this.bridge.readFile(
        this.scratch.handle,
        'transaction.json',
        MARKER_LIMITS.maxBytes,
        this.operation,
      );
      if (marker === null) this.fail('SERVICE_STALE', false);
      this.verifyMarkerBytes(
        marker.bytes,
        marker.facts,
      );
      this.markerFacts = deepFreeze(cloneJson(marker.facts));
    }
    const assetEntry = entries.find(({ name }) =>
      name === this.assetName) ?? null;
    this.observedAssetFacts = null;
    if (assetEntry === null) {
      if (this.authority.assetFacts !== null && index < assetIndex) {
        this.fail();
      }
    } else if (index > assetIndex) {
      this.fail();
    } else {
      if (this.authority.assetFacts === null ||
          assetEntry.identity.profile !== 'service-staging-file') {
        this.fail();
      }
      const facts = this.observeFileFacts(
        this.scratch.handle,
        assetEntry,
        this.authority.assetSize,
      );
      if (!compareFacts(facts, this.authority.assetFacts)) this.fail();
      this.observedAssetFacts = facts;
    }
    const candidateEntry = entries.find(({ name }) =>
      name === 'candidate') ?? null;
    if (candidateEntry === null) {
      if (this.authority.candidateIdentity !== null &&
          index < candidateIndex) {
        this.fail('SERVICE_STALE', false);
      }
    } else if (index > candidateIndex) {
      this.fail();
    } else {
      if (this.authority.candidateIdentity === null ||
          !SCRATCH_DIRECTORY_PROFILES.has(candidateEntry.identity.profile) ||
          !compareFacts(
            candidateEntry.identity,
            this.authority.candidateIdentity,
          )) {
        this.fail();
      }
      try {
        if (this.candidate === null) {
          this.candidate = this.retain(this.bridge.openDirectory(
            this.scratch.handle,
            'candidate',
            'write-existing',
            candidateEntry.identity,
            this.operation,
          ));
        }
      } catch {
        this.fail();
      }
    }
  }

  assetChunks() {
    const outer = this;
    let used = false;
    return Object.freeze({
      [Symbol.asyncIterator]() {
        let reader = null;
        let offset = 0;
        let complete = false;
        if (used) outer.fail('SERVICE_INVALID', false);
        used = true;
        return Object.freeze({
          async next() {
            if (complete) return Object.freeze({ done: true, value: undefined });
            if (reader === null) {
              let opened;
              try {
                opened = outer.bridge.openReader(
                  outer.scratch.handle,
                  outer.assetName,
                  outer.authority.assetSize,
                  null,
                  outer.operation,
                );
              } catch {
                outer.fail();
              }
              if (opened === null) outer.fail('SERVICE_STALE', false);
              reader = outer.retain(opened);
            }
            const chunk = outer.bridge.readChunk(
              reader.handle,
              offset,
              ARTIFACT_CHUNK_BYTES,
              outer.operation,
            );
            offset = chunk.nextOffset;
            if (chunk.eof) {
              complete = true;
              const finished = reader;
              reader = null;
              outer.release(finished.handle);
            }
            return Object.freeze({ done: false, value: chunk.bytes });
          },
          async return() {
            if (reader !== null) {
              const abandoned = reader;
              reader = null;
              outer.release(abandoned.handle);
            }
            complete = true;
            return Object.freeze({ done: true, value: undefined });
          },
          [Symbol.asyncIterator]() {
            return this;
          },
        });
      },
    });
  }

  async authenticatedClosure() {
    if (this.purpose === 'shawl') {
      return new Map([['shawl.exe', Object.freeze({
        path: 'shawl.exe',
        size: this.manifest.executable.byteLength,
        sha256: this.manifest.executable.sha256,
        profile: 'service-release-executable',
      })]]);
    }
    if (this.observedAssetFacts === null ||
        this.observedAssetFacts.size !== this.authority.assetSize ||
        this.observedAssetFacts.sha256 !== this.authority.assetSha256) {
      this.fail();
    }
    let inspection;
    try {
      inspection = await this.inspectArchive(this.assetChunks());
    } catch {
      this.fail();
    }
    if (!plain(inspection) ||
        inspection.manifestFingerprint !==
          this.manifest.manifestFingerprint ||
        inspection.archiveSha256 !== this.authority.assetSha256 ||
        inspection.treeFingerprint !== this.manifest.inventory.treeFingerprint ||
        !Array.isArray(inspection.files)) {
      this.fail();
    }
    let inventorySeen = false;
    const expected = new Map();
    for (const file of inspection.files) {
      if (!plain(file) || relativeSegments(file.path) === null ||
          !Number.isSafeInteger(file.size) || !isHex64(file.sha256) ||
          !['forbidden', 'required'].includes(file.executablePolicy) ||
          expected.has(file.path)) {
        this.fail();
      }
      if (file.path === APPLICATION_BUNDLE_INVENTORY_PATH) {
        if (inventorySeen ||
            file.size !== this.manifest.inventory.byteLength ||
            file.sha256 !== this.manifest.inventory.sha256 ||
            file.executablePolicy !== 'forbidden') {
          this.fail();
        }
        inventorySeen = true;
      }
      expected.set(file.path, Object.freeze({
        path: file.path,
        size: file.size,
        sha256: file.sha256,
        profile: file.executablePolicy === 'required'
          ? 'service-release-executable'
          : 'service-release-file',
      }));
    }
    if (!inventorySeen) this.fail();
    return expected;
  }

  observeCandidateFile(directory, entry, record) {
    if (!SCRATCH_FILE_PROFILES.has(entry.identity.profile)) this.fail();
    const facts = this.observeFileFacts(directory, entry, record.size);
    if (entry.identity.profile === 'service-staging-file') return facts;
    if (entry.identity.profile !== record.profile ||
        facts.size !== record.size || facts.sha256 !== record.sha256) {
      this.fail();
    }
    return facts;
  }

  async visitScratchTree(directory, prefix, expected, removePayload) {
    const direct = directExpected(expected, prefix);
    if (direct === null) this.fail();
    const listing = this.bridge.listDirectory(directory, this.operation);
    const entries = new Map(listing.entries.map((entry) => [entry.name, entry]));
    if (listing.entries.some((entry) => !direct.has(entry.name))) {
      this.fail();
    }
    for (const [name, descriptor] of direct) {
      const entry = entries.get(name);
      if (entry === undefined) continue;
      const path = prefix.length === 0 ? name : `${prefix}/${name}`;
      if (descriptor.kind === 'file') {
        if (removePayload && this.purpose === 'application' &&
            path === APPLICATION_BUNDLE_INVENTORY_PATH) {
          continue;
        }
        const observed = this.observeCandidateFile(
          directory,
          entry,
          descriptor.record,
        );
        if (removePayload) {
          this.bridge.removeFile(
            directory,
            name,
            observed,
            this.operation,
          );
        }
        continue;
      }
      if (!SCRATCH_DIRECTORY_PROFILES.has(entry.identity.profile)) {
        this.fail();
      }
      let child;
      try {
        child = this.retain(this.bridge.openDirectory(
          directory,
          name,
          'write-existing',
          entry.identity,
          this.operation,
        ));
      } catch {
        this.fail();
      }
      try {
        await this.visitScratchTree(
          child.handle,
          path,
          expected,
          removePayload,
        );
      } finally {
        this.release(child.handle);
      }
      if (removePayload) {
        this.bridge.removeObject(
          directory,
          name,
          entry.identity,
          this.operation,
        );
      }
    }
  }

  async removeCandidatePayload() {
    const listing = this.bridge.listDirectory(
      this.candidate.handle,
      this.operation,
    );
    if (listing.entries.length !== 0) {
      const expected = await this.authenticatedClosure();
      await this.visitScratchTree(
        this.candidate.handle,
        '',
        expected,
        false,
      );
      await this.visitScratchTree(
        this.candidate.handle,
        '',
        expected,
        true,
      );
    }
    const remaining = this.bridge.listDirectory(
      this.candidate.handle,
      this.operation,
    ).entries.map((entry) => entry.name);
    const allowed = this.purpose === 'application'
      ? [APPLICATION_BUNDLE_INVENTORY_PATH]
      : [];
    if (remaining.length !== allowed.length ||
        remaining.some((name, index) => name !== allowed[index])) {
      this.fail();
    }
    this.advance();
  }

  async removeCandidateInventory() {
    const listing = this.bridge.listDirectory(
      this.candidate.handle,
      this.operation,
    );
    if (listing.entries.length > 1 ||
        listing.entries.some((entry) =>
          entry.name !== APPLICATION_BUNDLE_INVENTORY_PATH)) {
      this.fail();
    }
    const entry = listing.entries[0] ?? null;
    if (entry !== null) {
      if (!SCRATCH_FILE_PROFILES.has(entry.identity.profile) ||
          entry.identity.profile === 'service-release-executable') {
        this.fail();
      }
      const facts = this.observeFileFacts(
        this.candidate.handle,
        entry,
        this.manifest.inventory.byteLength,
      );
      if (entry.identity.profile === 'service-release-file' &&
          (facts.size !== this.manifest.inventory.byteLength ||
           facts.sha256 !== this.manifest.inventory.sha256)) {
        this.fail();
      }
      this.bridge.removeFile(
        this.candidate.handle,
        entry.name,
        facts,
        this.operation,
      );
    }
    if (this.bridge.listDirectory(this.candidate.handle, this.operation)
        .entries.length !== 0) {
      this.fail();
    }
    this.advance();
  }

  removeCandidateRoot() {
    if (this.candidate === null) {
      this.advance();
      return;
    }
    if (this.bridge.listDirectory(this.candidate.handle, this.operation)
        .entries.length !== 0) {
      this.fail();
    }
    const identity = this.candidate.identity;
    this.release(this.candidate.handle);
    this.candidate = null;
    this.bridge.removeObject(
      this.scratch.handle,
      'candidate',
      identity,
      this.operation,
    );
    this.advance();
  }

  removeAsset() {
    if (this.observedAssetFacts !== null) {
      this.bridge.removeFile(
        this.scratch.handle,
        this.assetName,
        this.observedAssetFacts,
        this.operation,
      );
    }
    this.advance();
  }

  removeMarker() {
    if (this.markerFacts !== null) {
      this.bridge.removeFile(
        this.scratch.handle,
        'transaction.json',
        this.markerFacts,
        this.operation,
      );
    }
    this.advance();
  }

  removeScratchRoot() {
    if (this.bridge.listDirectory(this.scratch.handle, this.operation)
        .entries.length !== 0) {
      this.fail();
    }
    const identity = this.scratch.identity;
    this.release(this.scratch.handle);
    this.scratch = null;
    this.bridge.removeObject(
      this.root.handle,
      this.scratchName,
      identity,
      this.operation,
    );
  }

  async collect() {
    return this.closeAfter(async () => {
      if (!this.openScratch()) {
        return Object.freeze({ targetAbsent: true });
      }
      for (;;) {
        this.validateTopLevel();
        if (this.phase === 'candidate-payload-removing') {
          await this.removeCandidatePayload();
          continue;
        }
        if (this.phase === 'candidate-inventory-removing') {
          await this.removeCandidateInventory();
          continue;
        }
        if (this.phase === 'candidate-root-removing') {
          this.removeCandidateRoot();
          continue;
        }
        if (this.phase === 'asset-removing') {
          this.removeAsset();
          continue;
        }
        if (this.phase === 'marker-removing') {
          this.removeMarker();
          continue;
        }
        if (this.phase !== 'scratch-root-removing') {
          this.fail('SERVICE_INVALID', false);
        }
        this.removeScratchRoot();
        return Object.freeze({ targetAbsent: true });
      }
    });
  }
}

function scratchCollectorValues(input) {
  const values = dataValues(input, SCRATCH_COLLECTOR_KEYS);
  const bridgeValues = values === null
    ? null
    : dataValues(values.bridge, BRIDGE_KEYS);
  const capture = values !== null && values.phase === null;
  const valid =
    values !== null && bridgeValues !== null &&
    BRIDGE_KEYS.every((key) => typeof bridgeValues[key] === 'function') &&
    ['application', 'shawl'].includes(values.purpose) &&
    plain(values.manifest) &&
    ['linux', 'win32'].includes(values.platform) &&
    (values.purpose !== 'shawl' || values.platform === 'win32') &&
    typeof values.advancePhase === 'function' &&
    (capture
      ? values.authority === null &&
        plain(values.transaction) &&
        isHex64(values.transactionIdentity) &&
        plain(values.roles) &&
        isHex64(values.rolesFingerprint) &&
        ['x64', 'arm64'].includes(values.architecture) &&
        typeof values.component === 'string' &&
        typeof values.serviceKey === 'string' &&
        values.inspectArchive === null
      : values.authority !== null &&
        plain(values.authority) &&
        exact(values.authority, SCRATCH_AUTHORITY_KEYS) &&
        isHex64(values.authority.stagingRootBindingFingerprint) &&
        isHex64(values.authority.markerFingerprint) &&
        typeof values.authority.scratchName === 'string' &&
        typeof values.authority.assetName === 'string' &&
        Number.isSafeInteger(values.authority.assetSize) &&
        isHex64(values.authority.assetSha256) &&
        (values.purpose !== 'application' ||
          typeof values.inspectArchive === 'function'));
  if (!valid) {
    if (bridgeValues !== null && typeof bridgeValues.fail === 'function') {
      bridgeValues.fail(
        'SERVICE_INVALID',
        capture ? SCRATCH_OPERATIONS.capture : SCRATCH_OPERATIONS.collect,
        false,
      );
    }
    throw new TypeError('Invalid private scratch artifact collector');
  }
  values.bridge = Object.freeze(Object.fromEntries(
    BRIDGE_KEYS.map((key) => [key, bridgeValues[key]]),
  ));
  return values;
}

export function createScratchArtifactCollectorInternal(input) {
  const values = scratchCollectorValues(input);
  const capture = values.phase === null;
  const state = new ScratchArtifactCollector(values);
  let active = false;
  const run = async (method) => {
    if (active) state.fail('SERVICE_PENDING', false);
    active = true;
    try {
      return await state[method]();
    } finally {
      active = false;
    }
  };
  return Object.freeze({
    capture() {
      if (arguments.length !== 0 || !capture) {
        state.fail('SERVICE_INVALID', false);
      }
      return run('capture');
    },
    collect() {
      if (arguments.length !== 0 || capture) {
        state.fail('SERVICE_INVALID', false);
      }
      return run('collect');
    },
    retryClose() {
      if (arguments.length !== 0) {
        state.fail('SERVICE_INVALID', false);
      }
      if (active) state.fail('SERVICE_PENDING', false);
      state.close();
      return Object.freeze({ released: true });
    },
  });
}

// Private store assembly seam. The package entrypoint does not export it;
// ServiceStore supplies the captured, fence-bound bridge only after pinned
// provenance and exact active-transaction admission.
export function createServiceArtifactAccessInternal(input) {
  const values = dataValues(input, ACCESS_KEYS);
  const bridgeValues = values === null
    ? null
    : dataValues(values.bridge, BRIDGE_KEYS);
  if (values === null || !['application', 'shawl'].includes(values.purpose) ||
      bridgeValues === null ||
      BRIDGE_KEYS.some((key) => typeof bridgeValues[key] !== 'function') ||
      !plain(values.manifest) || !plain(values.transaction) ||
      !isHex64(values.transactionIdentity) || !plain(values.roles) ||
      !isHex64(values.rolesFingerprint) || typeof values.onClose !== 'function' ||
      values.transaction.component !== values.component ||
      values.transaction.serviceKey !== values.serviceKey ||
      values.transaction.platform !== values.platform ||
      values.transaction.architecture !== values.architecture) {
    if (bridgeValues !== null && typeof bridgeValues.fail === 'function') {
      bridgeValues.fail('SERVICE_INVALID', OPERATIONS.open, false);
    }
    throw new TypeError('Invalid private service artifact access');
  }
  values.bridge = Object.freeze(Object.fromEntries(
    BRIDGE_KEYS.map((key) => [key, bridgeValues[key]]),
  ));
  let state;
  try {
    state = new ArtifactAccessState(values);
  } catch (error) {
    try { state?.close(); } catch {}
    throw error;
  }
  return Object.freeze({
    async stageAsset(chunks) {
      if (arguments.length !== 1) state.fail('SERVICE_INVALID', OPERATIONS.stage);
      return state.runAsync(
        OPERATIONS.stage,
        () => state.stageAsset(chunks),
        true,
      );
    },
    openStagedAsset() {
      if (arguments.length !== 0) state.fail('SERVICE_INVALID', OPERATIONS.openAsset);
      return state.runSync(
        OPERATIONS.openAsset,
        () => state.openStagedAsset(),
        true,
      );
    },
    prepareCandidate(inventoryBytes) {
      if (arguments.length !== 1) state.fail('SERVICE_INVALID', OPERATIONS.prepare);
      return state.runSync(
        OPERATIONS.prepare,
        () => state.prepareCandidate(inventoryBytes),
        true,
      );
    },
    async writeCandidateFile(path, chunks) {
      if (arguments.length !== 2) state.fail('SERVICE_INVALID', OPERATIONS.write);
      return state.runAsync(
        OPERATIONS.write,
        () => state.writeCandidateFile(path, chunks),
        true,
      );
    },
    publishCandidate() {
      if (arguments.length !== 0) state.fail('SERVICE_INVALID', OPERATIONS.publish);
      return state.runSync(
        OPERATIONS.publish,
        () => state.publishCandidate(),
        true,
      );
    },
    close() {
      if (arguments.length !== 0) state.fail('SERVICE_INVALID', OPERATIONS.close);
      return state.close();
    },
  });
}
