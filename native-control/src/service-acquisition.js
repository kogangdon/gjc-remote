import {
  APPLICATION_BUNDLE_INVENTORY_PATH,
  DEPLOYMENT_ENVELOPE_LIMITS,
  REQUIRED_NATIVE_CONTROL_CONTRACT,
  buildBundleInventory,
  validateDeploymentSource,
} from '@gjc-remote/shared/deployment-envelope';
import {
  SERVICE_LIFECYCLE_LIMITS,
  validateServiceKey,
  validateServiceTransaction,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import {
  canonicalJsonBytes,
  canonicalJsonHash,
  parseCanonicalJsonBytes,
} from '@gjc-remote/shared/strict-json';
import {
  consumeApplicationArchive,
  inspectApplicationArchive,
} from './service-archive.js';
import { verifyPinnedDeploymentProvenance } from './deployment-provenance.js';
import { verifyPinnedNativeBuildManifest } from './native-provenance.js';
import { createOfflineDeploymentSource } from './service-offline-source.js';
import { createGithubReleaseTransport } from './service-transport.js';

const SOURCE_LIMITS = Object.freeze({
  maxBytes: 64 * 1024,
  maxDepth: 8,
  maxNodes: 128,
});
const TRANSACTION_LIMITS = Object.freeze({
  maxBytes: SERVICE_LIFECYCLE_LIMITS.protectedRecordBytes,
  maxDepth: 64,
  maxNodes: 100_000,
});
const INVENTORY_LIMITS = Object.freeze({
  maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
  maxDepth: 16,
  maxNodes: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries * 6 + 32,
});
const NATIVE_ADDON_PATH = 'native-control/build/Release/native_control.node';
const PRIMARY_NATIVE_ALIAS = 'node_modules/@gjc-remote/native-control';
const NATIVE_ALIAS_SEGMENTS = Object.freeze([
  'node_modules',
  '@gjc-remote',
  'native-control',
]);
const NATIVE_METADATA = Object.freeze(new Map([
  ['native-control/package.json', 1024 * 1024],
  ['native-control/build/Release/native-control.manifest.json', 1024 * 1024],
  ['native-control/build/Release/native-control.manifest.json.sig', 16 * 1024],
  ['native-control/release-keys/trusted.json', 64 * 1024],
]));
const SESSION_METHODS = Object.freeze([
  'retainDeploymentEnvelope',
  'reserveApplicationSequence',
  'openArtifactAccess',
  'commitApplicationSequence',
]);
const WINDOWS_SESSION_METHODS = Object.freeze([
  'reserveShawlSequence',
  'commitShawlSequence',
]);
const ERROR_CODES = new Set([
  'DEPLOYMENT_FILE_INVALID',
  'DEPLOYMENT_INPUT_INVALID',
  'DEPLOYMENT_MANIFEST_INVALID',
  'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED',
  'DEPLOYMENT_SIGNATURE_INVALID',
  'DEPLOYMENT_SIGNING_KEY_UNKNOWN',
  'DEPLOYMENT_SOURCE_ALREADY_CONSUMED',
  'DEPLOYMENT_SOURCE_CLOSED',
  'DEPLOYMENT_SOURCE_HASH_INVALID',
  'DEPLOYMENT_SOURCE_IDENTITY_MISMATCH',
  'DEPLOYMENT_SOURCE_INCOMPLETE',
  'DEPLOYMENT_SOURCE_INVALID',
  'DEPLOYMENT_SOURCE_MISSING',
  'DEPLOYMENT_SOURCE_NATIVE_FAILED',
  'DEPLOYMENT_SOURCE_NATIVE_INVALID',
  'DEPLOYMENT_SOURCE_NATIVE_WRITES',
  'DEPLOYMENT_SOURCE_PINNED_PROVENANCE_REQUIRED',
  'DEPLOYMENT_SOURCE_TARGET_MISMATCH',
  'DEPLOYMENT_TARGET_INVALID',
  'DEPLOYMENT_TRUST_DOMAIN_COLLISION',
  'DEPLOYMENT_TRUST_INVALID',
  'DEPLOYMENT_TRUST_UNAVAILABLE',
  'NATIVE_PROVENANCE_INPUT_INVALID',
  'NATIVE_PROVENANCE_MANIFEST_INVALID',
  'NATIVE_PROVENANCE_SIGNATURE_INVALID',
  'NATIVE_PROVENANCE_SIGNING_KEY_UNKNOWN',
  'NATIVE_PROVENANCE_TARGET_INVALID',
  'NATIVE_PROVENANCE_TRUST_INVALID',
  'NATIVE_PROVENANCE_TRUST_UNAVAILABLE',
  'RELEASE_SEQUENCE_CONFLICT',
  'RELEASE_SEQUENCE_DOWNGRADE',
  'RELEASE_SEQUENCE_NOT_ADVANCING',
  'RELEASE_SEQUENCE_RESERVED',
  'SERVICE_ACCESS_DENIED',
  'SERVICE_ACQUISITION_ALREADY_CONSUMED',
  'SERVICE_ACQUISITION_CLOSED',
  'SERVICE_ACQUISITION_DEADLINE_EXCEEDED',
  'SERVICE_ACQUISITION_FAILED',
  'SERVICE_ACQUISITION_INCOMPLETE',
  'SERVICE_ACQUISITION_INVALID',
  'SERVICE_ACQUISITION_NATIVE_AUTHORITY_INVALID',
  'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
  'SERVICE_ACQUISITION_SOURCE_MISMATCH',
  'SERVICE_ACQUISITION_STATE_INVALID',
  'SERVICE_ACQUISITION_TRANSACTION_MISMATCH',
  'SERVICE_ALREADY_EXISTS',
  'SERVICE_ARCHIVE_CONSUMER_FAILED',
  'SERVICE_ARCHIVE_CONSUMER_INCOMPLETE',
  'SERVICE_ARCHIVE_DECOMPRESSION_LIMIT',
  'SERVICE_ARCHIVE_ENTRY_INVALID',
  'SERVICE_ARCHIVE_GZIP_INVALID',
  'SERVICE_ARCHIVE_HASH_INVALID',
  'SERVICE_ARCHIVE_HEADER_INVALID',
  'SERVICE_ARCHIVE_INPUT_INVALID',
  'SERVICE_ARCHIVE_INSPECTION_INVALID',
  'SERVICE_ARCHIVE_INVENTORY_INVALID',
  'SERVICE_ARCHIVE_MANIFEST_INVALID',
  'SERVICE_ARCHIVE_PATH_INVALID',
  'SERVICE_ARCHIVE_PAX_INVALID',
  'SERVICE_ARCHIVE_PAYLOAD_INVALID',
  'SERVICE_ARCHIVE_SIZE_INVALID',
  'SERVICE_ARCHIVE_TAR_INVALID',
  'SERVICE_CRYPTO_UNAVAILABLE',
  'SERVICE_INVALID',
  'SERVICE_IO_FAILED',
  'SERVICE_MANUAL_CLEANUP',
  'SERVICE_NOT_PENDING',
  'SERVICE_PENDING',
  'SERVICE_REFERENCED',
  'SERVICE_SCOPE_MISMATCH',
  'SERVICE_STALE',
  'SERVICE_STORE_ABSENT',
  'SERVICE_TOMBSTONED',
  'SERVICE_TRANSPORT_ALREADY_CONSUMED',
  'SERVICE_TRANSPORT_CLOSED',
  'SERVICE_TRANSPORT_CONNECT_TIMEOUT',
  'SERVICE_TRANSPORT_DEADLINE_EXCEEDED',
  'SERVICE_TRANSPORT_HASH_INVALID',
  'SERVICE_TRANSPORT_IDLE_TIMEOUT',
  'SERVICE_TRANSPORT_INCOMPLETE',
  'SERVICE_TRANSPORT_INVALID',
  'SERVICE_TRANSPORT_MANIFEST_MISMATCH',
  'SERVICE_TRANSPORT_NETWORK_FAILED',
  'SERVICE_TRANSPORT_REDIRECT_INVALID',
  'SERVICE_TRANSPORT_REDIRECT_LIMIT',
  'SERVICE_TRANSPORT_RESPONSE_INVALID',
  'SERVICE_TRANSPORT_SIZE_INVALID',
  'SERVICE_UNSUPPORTED',
]);

const OPERATIONS = Object.freeze({
  create: 'create_service_acquisition',
  read: 'read_service_acquisition_manifests',
  reserve: 'reserve_service_acquisition',
  publish: 'publish_service_acquisition',
  close: 'close_service_acquisition',
});

class ServiceAcquisitionError extends Error {
  constructor(code, operation, writes, ambiguous = false) {
    super(code);
    Object.defineProperties(this, {
      name: { value: 'ServiceAcquisitionError' },
      code: { value: code, enumerable: true },
      operation: { value: operation, enumerable: true },
      writes: { value: writes, enumerable: true },
      ambiguous: { value: ambiguous, enumerable: true },
    });
  }
}

function acquisitionFailure(code, operation, writes, ambiguous = false) {
  return new ServiceAcquisitionError(code, operation, writes, ambiguous);
}

function exactDataValues(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) return null;
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

function dataProperty(value, key) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && descriptor.enumerable === true && descriptor.get === undefined &&
      descriptor.set === undefined && Object.hasOwn(descriptor, 'value')
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function snapshot(value, limits) {
  return parseCanonicalJsonBytes(canonicalJsonBytes(value, limits), limits);
}

function transactionIdentity(transaction) {
  return canonicalJsonHash({
    transactionId: transaction.transactionId,
    transactionNonce: transaction.transactionNonce,
    operation: transaction.operation,
    component: transaction.component,
    serviceKey: transaction.serviceKey,
    platform: transaction.platform,
    architecture: transaction.architecture,
    serviceGeneration: transaction.serviceGeneration,
    old: transaction.old,
    candidate: transaction.candidate,
    transition: transaction.transition,
    final: transaction.final,
  });
}

function exceptionData(error, field) {
  if (error === null ||
      (typeof error !== 'object' && typeof error !== 'function')) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, field);
    return descriptor && descriptor.get === undefined &&
      descriptor.set === undefined && Object.hasOwn(descriptor, 'value')
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function captureFailure(error, fallback = 'SERVICE_ACQUISITION_FAILED') {
  const candidate = exceptionData(error, 'code');
  const recognized = typeof candidate === 'string' &&
    ERROR_CODES.has(candidate);
  return Object.freeze({
    code: recognized ? candidate : fallback,
    ambiguous: recognized && exceptionData(error, 'ambiguous') === true,
  });
}

function dominantFailure(primary, cleanup) {
  const left = primary === null || primary === undefined
    ? null
    : captureFailure(primary);
  const right = cleanup === null || cleanup === undefined
    ? null
    : captureFailure(cleanup);
  if (right?.code === 'SERVICE_MANUAL_CLEANUP' || right?.ambiguous === true) return right;
  if (left?.code === 'SERVICE_MANUAL_CLEANUP' || left?.ambiguous === true) return left;
  return left ?? right;
}

function asyncIterator(chunks) {
  try {
    if (chunks === null || typeof chunks !== 'object' ||
        typeof chunks[Symbol.asyncIterator] !== 'function') return null;
    const iterator = chunks[Symbol.asyncIterator]();
    return iterator !== null && typeof iterator === 'object' &&
      typeof iterator.next === 'function' ? iterator : null;
  } catch {
    return null;
  }
}

function closeMethod(resource) {
  return dataProperty(resource, 'close');
}

export function createServiceAcquisition(options) {
  const input = exactDataValues(options, ['session', 'native', 'source']);
  if (arguments.length !== 1 || input === null) {
    throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', OPERATIONS.create, 0);
  }

  let session;
  let sourceDescription;
  let sourceAdapter;
  let observedWrites = 0;
  try {
    const suppliedSession = input.session;
    if (suppliedSession === null || typeof suppliedSession !== 'object' ||
        Array.isArray(suppliedSession) || Object.getPrototypeOf(suppliedSession) !== Object.prototype) {
      throw new TypeError('session');
    }
    const component = dataProperty(suppliedSession, 'component');
    const serviceKey = dataProperty(suppliedSession, 'serviceKey');
    const platform = dataProperty(suppliedSession, 'platform');
    const architecture = dataProperty(suppliedSession, 'architecture');
    validateServiceKey(serviceKey, component);
    if (!['linux:x64', 'linux:arm64', 'win32:x64'].includes(`${platform}:${architecture}`)) {
      throw new TypeError('tuple');
    }
    const writesDescriptor = Object.getOwnPropertyDescriptor(suppliedSession, 'writes');
    if (!writesDescriptor || writesDescriptor.enumerable !== true ||
        typeof writesDescriptor.get !== 'function' || writesDescriptor.set !== undefined) {
      throw new TypeError('writes');
    }
    const getWrites = writesDescriptor.get.bind(suppliedSession);
    const initialWrites = getWrites();
    if (!Number.isSafeInteger(initialWrites) || initialWrites < 0) {
      throw new TypeError('writes');
    }
    observedWrites = initialWrites;
    const methods = Object.create(null);
    for (const name of [
      ...SESSION_METHODS,
      ...(platform === 'win32' ? WINDOWS_SESSION_METHODS : []),
    ]) {
      const method = dataProperty(suppliedSession, name);
      if (typeof method !== 'function') throw new TypeError('session method');
      methods[name] = method.bind(suppliedSession);
    }
    session = Object.freeze({
      component,
      serviceKey,
      platform,
      architecture,
      getWrites,
      methods: Object.freeze(methods),
    });

    const sourceKind = dataProperty(input.source, 'kind');
    const sourceKeys = sourceKind === 'github-release'
      ? ['kind', 'tag']
      : platform === 'win32'
        ? [
          'kind',
          'applicationManifestPath',
          'applicationSignaturePath',
          'applicationArchivePath',
          'shawlManifestPath',
          'shawlSignaturePath',
          'shawlExecutablePath',
        ]
        : [
          'kind',
          'applicationManifestPath',
          'applicationSignaturePath',
          'applicationArchivePath',
        ];
    const sourceValues = exactDataValues(input.source, sourceKeys);
    if (sourceValues === null) throw new TypeError('source');
    sourceDescription = snapshot(
      Object.fromEntries(sourceKeys.map((key) => [key, sourceValues[key]])),
      SOURCE_LIMITS,
    );
    validateDeploymentSource(sourceDescription, { platform, architecture });
    if (sourceDescription.kind === 'github-release') {
      if (input.native !== null) throw new TypeError('online native');
      sourceAdapter = createGithubReleaseTransport({
        tag: sourceDescription.tag,
        platform,
        architecture,
      });
    } else {
      if (input.native === null || typeof input.native !== 'object' ||
          Array.isArray(input.native) ||
          Object.getPrototypeOf(input.native) !== Object.prototype) {
        throw new TypeError('offline native');
      }
      sourceAdapter = createOfflineDeploymentSource({
        native: input.native,
        source: sourceDescription,
        platform,
        architecture,
      });
    }
  } catch (error) {
    try { sourceAdapter?.close?.(); } catch {}
    const captured = captureFailure(error, 'SERVICE_ACQUISITION_INVALID');
    throw acquisitionFailure(
      captured.code,
      OPERATIONS.create,
      observedWrites,
      captured.ambiguous,
    );
  }

  let phase = 'initial';
  let busy = false;
  let activeTask = null;
  let terminalCode = null;
  let deadlineTimer = null;
  let cleanupFailure = null;
  let sourceClosed = false;
  let sourceClosing = null;
  let manifests = null;
  let reservedIdentity = null;
  const activeResources = [];
  const createdAt = Date.now();

  function currentWrites() {
    try {
      const value = session.getWrites();
      if (!Number.isSafeInteger(value) || value < observedWrites) {
        return observedWrites;
      }
      observedWrites = value;
    } catch {
      // Preserve the last valid cumulative count. The operation itself will
      // still fail through its authoritative session method or cleanup path.
    }
    return observedWrites;
  }

  function normalize(error, operation, fallback = 'SERVICE_ACQUISITION_FAILED') {
    const captured = captureFailure(error, fallback);
    return acquisitionFailure(
      captured.code,
      operation,
      currentWrites(),
      captured.ambiguous,
    );
  }

  function rememberCleanupFailure(error) {
    const captured = captureFailure(error);
    if (captured.code === 'SERVICE_MANUAL_CLEANUP' ||
        captured.ambiguous === true) {
      cleanupFailure = dominantFailure(cleanupFailure, captured);
    }
  }

  function checkDeadline(operation) {
    if (terminalCode !== null) {
      throw acquisitionFailure(terminalCode, operation, currentWrites());
    }
    const elapsed = Date.now() - createdAt;
    if (!Number.isFinite(elapsed) || elapsed < 0 ||
        elapsed >= DEPLOYMENT_ENVELOPE_LIMITS.acquisitionTimeoutMs) {
      expire();
      throw acquisitionFailure(
        'SERVICE_ACQUISITION_DEADLINE_EXCEEDED',
        operation,
        currentWrites(),
      );
    }
  }

  function registerResource(resource, operation) {
    const close = closeMethod(resource);
    if (typeof close !== 'function') {
      throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
    }
    const entry = {
      resource,
      close: close.bind(resource),
      closed: false,
      closing: null,
    };
    activeResources.push(entry);
    return entry;
  }

  async function closeEntry(entry) {
    if (entry.closed) return null;
    if (entry.closing !== null) return entry.closing;
    const closing = Promise.resolve()
      .then(() => entry.close())
      .then(() => {
        entry.closed = true;
        const index = activeResources.indexOf(entry);
        if (index !== -1) activeResources.splice(index, 1);
        currentWrites();
        return null;
      }, (error) => {
        currentWrites();
        return error;
      })
      .finally(() => {
        if (entry.closing === closing) entry.closing = null;
      });
    entry.closing = closing;
    return closing;
  }

  async function cleanupResources() {
    let first = null;
    for (const entry of [...activeResources].reverse()) {
      const error = await closeEntry(entry);
      first = dominantFailure(first, error);
    }
    if (first !== null) rememberCleanupFailure(first);
    return first;
  }

  async function closeSource() {
    if (sourceClosed) return null;
    if (sourceClosing !== null) return sourceClosing;
    const closing = Promise.resolve()
      .then(() => {
        const close = closeMethod(sourceAdapter);
        if (typeof close !== 'function') throw new TypeError('source close');
        return close.call(sourceAdapter);
      })
      .then(() => {
        sourceClosed = true;
        return null;
      }, (error) => {
        rememberCleanupFailure(error);
        return error;
      })
      .finally(() => {
        if (sourceClosing === closing) sourceClosing = null;
      });
    sourceClosing = closing;
    return closing;
  }

  function expire() {
    if (terminalCode !== null) return;
    terminalCode = 'SERVICE_ACQUISITION_DEADLINE_EXCEEDED';
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
    deadlineTimer = null;
    Promise.resolve()
      .then(cleanupResources)
      .then(closeSource)
      .catch(rememberCleanupFailure);
  }

  deadlineTimer = setTimeout(expire, DEPLOYMENT_ENVELOPE_LIMITS.acquisitionTimeoutMs);
  deadlineTimer.unref?.();

  function invokeSession(name, argument, operation) {
    checkDeadline(operation);
    try {
      const result = session.methods[name](argument);
      currentWrites();
      checkDeadline(operation);
      return result;
    } catch (error) {
      currentWrites();
      throw error;
    }
  }

  function validateTransaction(value, expectedPhase, expectedSubstep, operation) {
    let transaction;
    try {
      transaction = snapshot(value, TRANSACTION_LIMITS);
      validateServiceTransaction(transaction);
    } catch {
      throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
    }
    if (transaction.component !== session.component ||
        transaction.serviceKey !== session.serviceKey ||
        transaction.platform !== session.platform ||
        transaction.architecture !== session.architecture ||
        !['install', 'update'].includes(transaction.operation) ||
        transaction.phase !== expectedPhase ||
        transaction.substep !== expectedSubstep) {
      throw acquisitionFailure('SERVICE_ACQUISITION_TRANSACTION_MISMATCH', operation, currentWrites());
    }
    return transaction;
  }

  function deadlineChunks(chunks, operation) {
    let claimed = false;
    return Object.freeze({
      [Symbol.asyncIterator]() {
        if (claimed) {
          throw acquisitionFailure('SERVICE_ACQUISITION_ALREADY_CONSUMED', operation, currentWrites());
        }
        claimed = true;
        const iterator = asyncIterator(chunks);
        if (iterator === null) {
          throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
        }
        let ended = false;
        return Object.freeze({
          async next(value) {
            checkDeadline(operation);
            const result = await iterator.next(value);
            checkDeadline(operation);
            if (result === null || typeof result !== 'object' || typeof result.done !== 'boolean') {
              throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
            }
            ended = result.done;
            return result;
          },
          async return(value) {
            if (ended) return Object.freeze({ done: true, value: undefined });
            ended = true;
            if (typeof iterator.return === 'function') return iterator.return(value);
            throw acquisitionFailure(
              'SERVICE_ACQUISITION_INCOMPLETE',
              operation,
              currentWrites(),
            );
          },
          async throw(error) {
            ended = true;
            if (typeof iterator.throw === 'function') return iterator.throw(error);
            if (typeof iterator.return === 'function') await iterator.return();
            throw acquisitionFailure(
              'SERVICE_ACQUISITION_INCOMPLETE',
              operation,
              currentWrites(),
            );
          },
          [Symbol.asyncIterator]() { return this; },
        });
      },
    });
  }

  async function failAndClose(error, operation) {
    const resourceError = await cleanupResources();
    const sourceError = await closeSource();
    phase = 'failed';
    const primary = terminalCode === null
      ? error
      : acquisitionFailure(terminalCode, operation, currentWrites());
    const dominant = dominantFailure(
      dominantFailure(primary, resourceError),
      dominantFailure(sourceError, cleanupFailure),
    );
    throw normalize(dominant, operation);
  }

  function runAsync(operation, callback) {
    try {
      checkDeadline(operation);
    } catch (error) {
      return Promise.reject(error);
    }
    if (busy) {
      return Promise.reject(acquisitionFailure('SERVICE_PENDING', operation, currentWrites()));
    }
    busy = true;
    let task;
    task = (async () => {
      try {
        const result = await callback();
        checkDeadline(operation);
        const cleanup = await cleanupResources();
        if (cleanup !== null) throw cleanup;
        checkDeadline(operation);
        return result;
      } catch (error) {
        return failAndClose(error, operation);
      } finally {
        busy = false;
        if (activeTask === task) activeTask = null;
      }
    })();
    activeTask = task;
    return task;
  }

  async function verifiedBootstrap(purpose, operation) {
    checkDeadline(operation);
    const bootstrap = await sourceAdapter.readBootstrap(purpose);
    checkDeadline(operation);
    const values = exactDataValues(bootstrap, ['manifestBytes', 'signatureBytes']);
    if (values === null || !Buffer.isBuffer(values.manifestBytes) ||
        !Buffer.isBuffer(values.signatureBytes) || values.manifestBytes.length === 0 ||
        values.manifestBytes.length > DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes ||
        values.signatureBytes.length === 0 ||
        values.signatureBytes.length > DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes) {
      throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
    }
    const manifestBytes = Buffer.from(values.manifestBytes);
    const signatureBytes = Buffer.from(values.signatureBytes);
    const verified = verifyPinnedDeploymentProvenance({
      purpose,
      manifestBytes,
      signatureBytes,
      platform: session.platform,
      architecture: session.architecture,
    });
    checkDeadline(operation);
    if (sourceDescription.kind === 'github-release') {
      const signedTag = purpose === 'application'
        ? verified.manifest.source.tag
        : verified.manifest.projectAsset.tag;
      if (signedTag !== sourceDescription.tag) {
        throw acquisitionFailure(
          'SERVICE_ACQUISITION_SOURCE_MISMATCH',
          operation,
          currentWrites(),
        );
      }
    }
    return Object.freeze({
      manifest: verified.manifest,
      manifestBytes,
      signatureBytes,
    });
  }

  function readManifests() {
    const operation = OPERATIONS.read;
    if (arguments.length !== 0) {
      return Promise.reject(acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites()));
    }
    return runAsync(operation, async () => {
      if (phase !== 'initial') {
        throw acquisitionFailure('SERVICE_ACQUISITION_STATE_INVALID', operation, currentWrites());
      }
      phase = 'reading';
      const application = await verifiedBootstrap('application', operation);
      const shawl = session.platform === 'win32'
        ? await verifiedBootstrap('shawl', operation)
        : null;
      manifests = Object.freeze({ application, shawl });
      phase = 'manifests-read';
      return Object.freeze({
        application: application.manifest,
        shawl: shawl?.manifest ?? null,
      });
    });
  }

  function reserve(inputValue) {
    const operation = OPERATIONS.reserve;
    checkDeadline(operation);
    if (busy) throw acquisitionFailure('SERVICE_PENDING', operation, currentWrites());
    const input = exactDataValues(inputValue, [
      'transaction',
      'currentApplicationSequence',
      'currentShawlSequence',
    ]);
    if (arguments.length !== 1 || input === null ||
        !Number.isSafeInteger(input.currentApplicationSequence) ||
        input.currentApplicationSequence < 0 ||
        (session.platform === 'linux'
          ? input.currentShawlSequence !== null
          : !Number.isSafeInteger(input.currentShawlSequence) ||
            input.currentShawlSequence < 0)) {
      throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
    }
    if (phase !== 'manifests-read' || manifests === null) {
      throw acquisitionFailure('SERVICE_ACQUISITION_STATE_INVALID', operation, currentWrites());
    }
    busy = true;
    phase = 'reserving';
    try {
      const transaction = validateTransaction(input.transaction, 'prepared', 'none', operation);
      invokeSession('retainDeploymentEnvelope', {
        purpose: 'application',
        manifestBytes: manifests.application.manifestBytes,
        signatureBytes: manifests.application.signatureBytes,
        transaction,
      }, operation);
      if (session.platform === 'win32') {
        invokeSession('retainDeploymentEnvelope', {
          purpose: 'shawl',
          manifestBytes: manifests.shawl.manifestBytes,
          signatureBytes: manifests.shawl.signatureBytes,
          transaction,
        }, operation);
      }
      const application = invokeSession('reserveApplicationSequence', {
        manifest: manifests.application.manifest,
        transaction,
        currentSequence: input.currentApplicationSequence,
      }, operation);
      const shawl = session.platform === 'win32'
        ? invokeSession('reserveShawlSequence', {
          manifest: manifests.shawl.manifest,
          transaction,
          currentSequence: input.currentShawlSequence,
        }, operation)
        : null;
      reservedIdentity = transactionIdentity(transaction);
      phase = 'reserved';
      return Object.freeze({ application, shawl });
    } catch (error) {
      phase = 'failed';
      const closeResult = closeSource();
      closeResult.catch(rememberCleanupFailure);
      throw normalize(dominantFailure(error, cleanupFailure), operation);
    } finally {
      busy = false;
    }
  }

  function nativeFiles(inspection, operation) {
    const records = new Map(inspection.files.map((record) => [record.path, record]));
    // The signed root metadata is authoritative only when every package path
    // Node may resolve exposes that same native-control subtree. Nested package
    // dependencies are separate closures and are deliberately excluded.
    const rootPrefix = 'native-control/';
    const root = new Map();
    for (const record of inspection.files) {
      if (!record.path.startsWith(rootPrefix)) continue;
      const relative = record.path.slice(rootPrefix.length);
      if (relative.length === 0 || relative === 'node_modules' ||
          relative.startsWith('node_modules/')) continue;
      root.set(relative, record);
    }
    const aliases = new Map();
    const foldedMarker = NATIVE_ALIAS_SEGMENTS.map((segment) =>
      segment.toLowerCase().toUpperCase());
    for (const record of inspection.files) {
      const segments = record.path.split('/');
      for (let index = 0;
        index <= segments.length - NATIVE_ALIAS_SEGMENTS.length;
        index += 1) {
        const candidate = segments.slice(
          index,
          index + NATIVE_ALIAS_SEGMENTS.length,
        );
        const exactAlias = candidate.every((segment, offset) =>
          segment === NATIVE_ALIAS_SEGMENTS[offset]);
        if (session.platform === 'win32') {
          const foldedAlias = candidate.every((segment, offset) =>
            segment.toLowerCase().toUpperCase() === foldedMarker[offset]);
          if (foldedAlias && !exactAlias) {
            throw acquisitionFailure(
              'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
              operation,
              currentWrites(),
            );
          }
        }
        if (!exactAlias) continue;
        const prefix = segments.slice(
          0,
          index + NATIVE_ALIAS_SEGMENTS.length,
        ).join('/');
        aliases.set(prefix, aliases.get(prefix) ?? 0);
        const relativeSegments = segments.slice(
          index + NATIVE_ALIAS_SEGMENTS.length,
        );
        if (relativeSegments.length === 0) {
          throw acquisitionFailure(
            'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
            operation,
            currentWrites(),
          );
        }
        if (relativeSegments[0] === 'node_modules') continue;
        const relative = relativeSegments.join('/');
        const rootRecord = root.get(relative);
        if (rootRecord === undefined ||
            record.size !== rootRecord.size ||
            record.sha256 !== rootRecord.sha256 ||
            record.executablePolicy !== rootRecord.executablePolicy) {
          throw acquisitionFailure(
            'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
            operation,
            currentWrites(),
          );
        }
        aliases.set(prefix, aliases.get(prefix) + 1);
      }
    }
    if (root.size === 0 || !aliases.has(PRIMARY_NATIVE_ALIAS)) {
      throw acquisitionFailure(
        'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
        operation,
        currentWrites(),
      );
    }
    for (const count of aliases.values()) {
      if (count !== root.size) {
        throw acquisitionFailure(
          'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
          operation,
          currentWrites(),
        );
      }
    }
    const addon = records.get(NATIVE_ADDON_PATH);
    if (!addon || addon.size < 1 || addon.executablePolicy !== 'required') {
      throw acquisitionFailure(
        'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
        operation,
        currentWrites(),
      );
    }
    const metadata = new Map();
    for (const [path, maximum] of NATIVE_METADATA) {
      const record = records.get(path);
      if (!record || record.size < 1 || record.size > maximum ||
          record.executablePolicy !== 'forbidden') {
        throw acquisitionFailure(
          'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
          operation,
          currentWrites(),
        );
      }
      metadata.set(path, {
        record,
        bytes: Buffer.allocUnsafe(record.size),
        offset: 0,
      });
    }
    return Object.freeze({ addon, metadata });
  }

  function teeMetadata(chunks, capture, operation) {
    return Object.freeze({
      async *[Symbol.asyncIterator]() {
        for await (const value of deadlineChunks(chunks, operation)) {
          if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
            throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
          }
          const bytes = Buffer.isBuffer(value)
            ? value
            : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
          const next = capture.offset + bytes.length;
          if (!Number.isSafeInteger(next) || next > capture.bytes.length) {
            throw acquisitionFailure(
              'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
              operation,
              currentWrites(),
            );
          }
          bytes.copy(capture.bytes, capture.offset);
          capture.offset = next;
          yield bytes;
        }
        if (capture.offset !== capture.bytes.length) {
          throw acquisitionFailure(
            'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
            operation,
            currentWrites(),
          );
        }
      },
    });
  }

  async function openSourceAsset(purpose, operation) {
    checkDeadline(operation);
    const manifest = purpose === 'application'
      ? manifests.application.manifest
      : manifests.shawl.manifest;
    const asset = await (purpose === 'application'
      ? sourceAdapter.openApplication(manifest)
      : sourceAdapter.openShawl(manifest));
    const entry = registerResource(asset, operation);
    const values = exactDataValues(asset, ['chunks', 'close']) ??
      exactDataValues(asset, ['facts', 'chunks', 'close']);
    if (values === null || typeof values.close !== 'function') {
      throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
    }
    checkDeadline(operation);
    return { asset, chunks: values.chunks, entry };
  }

  function openAccess(purpose, transaction, operation) {
    const manifest = purpose === 'application'
      ? manifests.application.manifest
      : manifests.shawl.manifest;
    checkDeadline(operation);
    let access;
    try {
      access = session.methods.openArtifactAccess({
        purpose,
        manifest,
        transaction,
      });
    } catch (error) {
      currentWrites();
      throw error;
    }
    const entry = registerResource(access, operation);
    currentWrites();
    checkDeadline(operation);
    return { access, entry };
  }

  async function closeRequired(entry, operation) {
    const error = await closeEntry(entry);
    if (error !== null) throw normalize(error, operation);
    checkDeadline(operation);
  }

  async function publishApplication(transaction, operation) {
    const manifest = manifests.application.manifest;
    const { access, entry: accessEntry } = openAccess('application', transaction, operation);
    const source = await openSourceAsset('application', operation);
    await access.stageAsset(deadlineChunks(source.chunks, operation));
    await closeRequired(source.entry, operation);

    const inspectionReader = access.openStagedAsset();
    const inspectionEntry = registerResource(inspectionReader, operation);
    const inspection = await inspectApplicationArchive({
      manifest,
      chunks: deadlineChunks(inspectionReader.chunks, operation),
    });
    await closeRequired(inspectionEntry, operation);
    checkDeadline(operation);

    const native = nativeFiles(inspection, operation);
    const inventory = buildBundleInventory({
      payloadEntries: inspection.files
        .filter((record) => record.path !== APPLICATION_BUNDLE_INVENTORY_PATH)
        .map((record) => ({
          path: record.path,
          size: record.size,
          sha256: record.sha256,
          executablePolicy: record.executablePolicy,
        })),
    }, { platform: session.platform });
    const inventoryBytes = canonicalJsonBytes(inventory, INVENTORY_LIMITS);
    checkDeadline(operation);
    access.prepareCandidate(inventoryBytes);
    checkDeadline(operation);

    const consumeReader = access.openStagedAsset();
    const consumeEntry = registerResource(consumeReader, operation);
    let callbackFailure = null;
    try {
      await consumeApplicationArchive({
        manifest,
        inspection,
        chunks: deadlineChunks(consumeReader.chunks, operation),
        onFile: async (record, chunks) => {
          try {
            checkDeadline(operation);
            const capture = native.metadata.get(record.path);
            await access.writeCandidateFile(
              record.path,
              capture === undefined
                ? deadlineChunks(chunks, operation)
                : teeMetadata(chunks, capture, operation),
            );
            checkDeadline(operation);
          } catch (error) {
            callbackFailure = error;
            throw error;
          }
        },
      });
    } catch (error) {
      throw callbackFailure ?? error;
    }
    await closeRequired(consumeEntry, operation);

    for (const capture of native.metadata.values()) {
      if (capture.offset !== capture.bytes.length) {
        throw acquisitionFailure(
          'SERVICE_ACQUISITION_NATIVE_METADATA_INVALID',
          operation,
          currentWrites(),
        );
      }
    }
    checkDeadline(operation);
    const nativeMetadata = verifyPinnedNativeBuildManifest({
      packageBytes: native.metadata.get('native-control/package.json').bytes,
      manifestBytes: native.metadata.get(
        'native-control/build/Release/native-control.manifest.json',
      ).bytes,
      signatureBytes: native.metadata.get(
        'native-control/build/Release/native-control.manifest.json.sig',
      ).bytes,
      bundledTrustBytes: native.metadata.get(
        'native-control/release-keys/trusted.json',
      ).bytes,
      platform: session.platform,
      architecture: session.architecture,
    });
    checkDeadline(operation);
    if (nativeMetadata.manifestFingerprint !== manifest.nativeControl.manifestFingerprint ||
        nativeMetadata.addonSha256 !== native.addon.sha256 ||
        nativeMetadata.platform !== session.platform ||
        nativeMetadata.architecture !== session.architecture ||
        nativeMetadata.contractVersion !== REQUIRED_NATIVE_CONTROL_CONTRACT.version ||
        nativeMetadata.contractRevision !== REQUIRED_NATIVE_CONTROL_CONTRACT.revision ||
        nativeMetadata.contractVersion !== manifest.nativeControl.contractVersion ||
        nativeMetadata.contractRevision !== manifest.nativeControl.contractRevision ||
        nativeMetadata.napi !== 8 ||
        nativeMetadata.addonBytesVerification !== 'required' ||
        nativeMetadata.addonLoadVerification !== 'required' ||
        nativeMetadata.addonExportVerification !== 'required') {
      throw acquisitionFailure(
        'SERVICE_ACQUISITION_NATIVE_AUTHORITY_INVALID',
        operation,
        currentWrites(),
      );
    }

    const publication = access.publishCandidate();
    checkDeadline(operation);
    await closeRequired(accessEntry, operation);
    invokeSession('commitApplicationSequence', {
      manifest,
      transaction,
      publication,
    }, operation);
    return Object.freeze({ manifest, publication, nativeMetadata });
  }

  async function publishShawl(transaction, operation) {
    const manifest = manifests.shawl.manifest;
    const { access, entry: accessEntry } = openAccess('shawl', transaction, operation);
    const source = await openSourceAsset('shawl', operation);
    await access.stageAsset(deadlineChunks(source.chunks, operation));
    await closeRequired(source.entry, operation);
    access.prepareCandidate(null);
    checkDeadline(operation);
    const reader = access.openStagedAsset();
    const readerEntry = registerResource(reader, operation);
    await access.writeCandidateFile(
      'shawl.exe',
      deadlineChunks(reader.chunks, operation),
    );
    await closeRequired(readerEntry, operation);
    const publication = access.publishCandidate();
    checkDeadline(operation);
    await closeRequired(accessEntry, operation);
    invokeSession('commitShawlSequence', {
      manifest,
      transaction,
      publication,
    }, operation);
    return Object.freeze({ manifest, publication });
  }

  function publish(inputValue) {
    const operation = OPERATIONS.publish;
    if (arguments.length !== 1) {
      return Promise.reject(acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites()));
    }
    const input = exactDataValues(inputValue, ['transaction']);
    if (input === null) {
      return Promise.reject(acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites()));
    }
    return runAsync(operation, async () => {
      if (phase !== 'reserved' || manifests === null || reservedIdentity === null) {
        throw acquisitionFailure('SERVICE_ACQUISITION_STATE_INVALID', operation, currentWrites());
      }
      const transaction = validateTransaction(
        input.transaction,
        'sequence-reserved',
        'observed',
        operation,
      );
      if (transactionIdentity(transaction) !== reservedIdentity) {
        throw acquisitionFailure(
          'SERVICE_ACQUISITION_TRANSACTION_MISMATCH',
          operation,
          currentWrites(),
        );
      }
      phase = 'publishing';
      const application = await publishApplication(transaction, operation);
      const shawl = session.platform === 'win32'
        ? await publishShawl(transaction, operation)
        : null;
      phase = 'published';
      return Object.freeze({ application, shawl });
    });
  }

  async function close() {
    const operation = OPERATIONS.close;
    if (arguments.length !== 0) {
      throw acquisitionFailure('SERVICE_ACQUISITION_INVALID', operation, currentWrites());
    }
    if (terminalCode === null) terminalCode = 'SERVICE_ACQUISITION_CLOSED';
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
    deadlineTimer = null;
    const firstCleanup = await cleanupResources();
    const sourceError = await closeSource();
    if (activeTask !== null) {
      try { await activeTask; } catch {}
    }
    const secondCleanup = await cleanupResources();
    const secondSourceError = await closeSource();
    const unresolvedFirstCleanup = activeResources.length === 0
      ? null
      : firstCleanup;
    const unresolvedSourceError = sourceClosed ? null : sourceError;
    const dominant = dominantFailure(
      dominantFailure(unresolvedFirstCleanup, unresolvedSourceError),
      dominantFailure(
        dominantFailure(secondCleanup, secondSourceError),
        cleanupFailure,
      ),
    );
    if (dominant !== null) throw normalize(dominant, operation);
  }

  return Object.freeze({ readManifests, reserve, publish, close });
}
