import {
  canonicalJson,
  canonicalJsonBytes,
  canonicalJsonHash,
  isHex64,
  parseCanonicalJsonBytes,
  utf8Compare,
} from '@gjc-remote/shared/strict-json';
import {
  SERVICE_LIFECYCLE_LIMITS,
  buildServiceArtifactCleanup,
  buildServiceArtifactScratchCleanup,
  buildServiceArtifactBinding,
  buildServiceFloorHistoryIntent,
  buildServiceFloorHistoryState,
  buildServiceFloorWitness,
  buildServiceJournalHead,
  buildServiceSequenceFloor,
  buildServiceStoreRegistration,
  buildServiceStoreRegistrationIncarnation,
  buildServiceZeroReferenceObservation,
  serviceKeyForTarget,
  serviceArtifactPhysicalTargetFingerprint,
  serviceNativeIdentityFingerprint,
  serviceRolesFingerprint,
  validateServiceArtifactBinding,
  validateServiceArtifactCleanup,
  validateServiceArtifactFileFacts,
  validateServiceCandidateProof,
  validateServiceControlRootBinding,
  validateServiceFinalProof,
  validateServiceFloorWitness,
  validateServiceFloorHistoryIntent,
  validateServiceFloorHistoryState,
  validateServiceJournalHead,
  validateServiceKey,
  validateServiceManifest,
  validateServiceManualCleanup,
  validateServiceNativeIdentity,
  validateServiceOldProof,
  validateServiceReferenceRecord,
  validateServiceResourceProof,
  validateServiceRoles,
  validateServiceSequenceFloor,
  validateServiceStartupProof,
  validateServiceStoreRegistration,
  validateServiceStoreRegistrationIncarnation,
  validateServiceTarget,
  validateServiceTombstone,
  validateServiceTransaction,
  validateServiceTransitionProof,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { createHash } from 'node:crypto';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  validateApplicationDeploymentManifest,
  validateShawlDeploymentManifest,
} from '@gjc-remote/shared/deployment-envelope';
import {
  assertPinnedDeploymentManifest,
  verifyPinnedDeploymentProvenance,
} from './deployment-provenance.js';
import {
  createServicePublishedArtifactCollectorInternal,
  createServiceArtifactAccessInternal,
  createScratchArtifactCollectorInternal,
} from './service-artifacts.js';
import { inspectApplicationArchive } from './service-archive.js';

export const SERVICE_STORE_LIMITS = Object.freeze({
  recordBytes: 16 * 1024 * 1024,
  directoryEntries: 100_000,
  jsonDepth: 64,
  jsonNodes: 500_000,
});

export const SERVICE_STORE_LAYOUT = Object.freeze({
  registration: 'store-registration.json',
  historyDirectory: 'history',
  registrationIncarnation: 'registration-incarnation.json',
  floorHistoryIntent: 'intent.json',
  floorHistoryState: 'state.json',
  manifestFiles: Object.freeze({ current: 'current.json', previous: 'previous.json' }),
  resourceFiles: Object.freeze({ current: 'current-resource.json', previous: 'previous-resource.json' }),
  startup: 'startup.json',
  journalHead: 'head.json',
  tombstone: 'current.json',
  manualCleanup: 'current.json',
  artifactCleanup: 'artifact-cleanup.json',
});

const METADATA_NATIVE = Object.freeze([
  'open_service_root',
  'open_service_directory',
  'acquire_service_lock',
  'close_service_handle',
  'read_service_file',
  'publish_service_file_atomic',
  'remove_service_object_exact',
  'list_service_directory',
  'publish_service_directory_no_replace',
]);
const ARTIFACT_NATIVE = Object.freeze([
  'begin_service_artifact_write',
  'write_service_artifact_chunk',
  'finish_service_artifact_write',
  'open_service_artifact_reader',
  'read_service_artifact_chunk',
  'remove_service_artifact_file_exact',
  'seal_service_directory',
  'open_service_artifact_source',
]);
const REQUIRED_NATIVE = Object.freeze([
  ...METADATA_NATIVE,
  ...ARTIFACT_NATIVE,
]);
const OPTIONAL_NATIVE = Object.freeze([
  'open_linux_service_scope',
  'read_linux_service_object',
]);
const ROLE_KEYS = Object.freeze(['management', 'bot', 'recovery', 'daemon', 'system']);
const OPEN_NAMESPACES = Object.freeze(['transaction', 'manifest', 'reference', 'tombstone', 'floor', 'manual']);
const SERVICE_DIRECT = Object.freeze(['transaction', 'manifest', 'tombstone', 'manual']);
const MANIFEST_FILE_SET = new Set(['current.json', 'previous.json', 'current-resource.json', 'previous-resource.json', 'startup.json']);
const SINGLE_FILE_SET = new Set(['current.json']);
const MANUAL_FILE_SET = new Set([
  SERVICE_STORE_LAYOUT.manualCleanup,
  SERVICE_STORE_LAYOUT.artifactCleanup,
]);
const JOURNAL_ENTRY = /^entry-([0-9]{16})\.json$/;
const RETAINED_DEPLOYMENT_ENVELOPE = /^deployment-(application|shawl)-([0-9a-f]{64})\.json$/;
const RETAINED_DEPLOYMENT_ERROR_CODES = new Set([
  'SERVICE_ACCESS_DENIED',
  'SERVICE_ALREADY_EXISTS',
  'SERVICE_INVALID',
  'SERVICE_IO_FAILED',
  'SERVICE_MANUAL_CLEANUP',
  'SERVICE_PENDING',
  'SERVICE_SCOPE_MISMATCH',
  'SERVICE_STALE',
  'SERVICE_TOMBSTONED',
  'DEPLOYMENT_INPUT_INVALID',
  'DEPLOYMENT_MANIFEST_INVALID',
  'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED',
  'DEPLOYMENT_SIGNATURE_INVALID',
  'DEPLOYMENT_SIGNING_KEY_UNKNOWN',
  'DEPLOYMENT_TARGET_INVALID',
  'DEPLOYMENT_TRUST_DOMAIN_COLLISION',
  'DEPLOYMENT_TRUST_INVALID',
  'DEPLOYMENT_TRUST_UNAVAILABLE',
]);
const ARTIFACT_CLEANUP_ERROR_CODES = new Set([
  ...RETAINED_DEPLOYMENT_ERROR_CODES,
  'SERVICE_CRYPTO_UNAVAILABLE',
  'SERVICE_REFERENCED',
  'SERVICE_UNSUPPORTED',
]);
const NONCE = /^[0-9a-f]{32}$/;
const TUPLES = new Set(['linux:x64', 'linux:arm64', 'win32:x64']);
const ARTIFACT_CHUNK_BYTES = 1024 * 1024;
const ARTIFACT_DIRECTORY_ENTRIES =
  DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries + 1;
const JSON_LIMITS = Object.freeze({
  maxBytes: SERVICE_STORE_LIMITS.recordBytes,
  maxDepth: SERVICE_STORE_LIMITS.jsonDepth,
  maxNodes: SERVICE_STORE_LIMITS.jsonNodes,
});
const receiptBindings = new WeakMap();
const publicationBindings = new WeakMap();
const driverLockBindings = new WeakMap();

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value, keys) {
  if (!plain(value)) return false;
  const own = Reflect.ownKeys(value);
  return own.length === keys.length && own.every((key) => typeof key === 'string') && keys.every((key) => Object.hasOwn(value, key));
}

function dataValues(value, keys) {
  if (!plain(value)) return null;
  let descriptors;
  try {
    if (Reflect.ownKeys(value).length !== keys.length) return null;
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true || descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, 'value')) return null;
    result[key] = descriptor.value;
  }
  return result;
}

function throwStore(code, operation, writes = 0, ambiguous = false, cause = undefined) {
  const error = new Error(`${operation} failed`, cause === undefined ? undefined : { cause });
  Object.defineProperties(error, {
    name: { value: 'ServiceStoreError' },
    code: { value: code, enumerable: true },
    operation: { value: operation, enumerable: true },
    writes: { value: writes, enumerable: true },
    ambiguous: { value: ambiguous, enumerable: true },
  });
  throw error;
}

function throwRetainedDeploymentFailure(error, operation, writes) {
  throwStore(
    RETAINED_DEPLOYMENT_ERROR_CODES.has(error?.code)
      ? error.code
      : 'SERVICE_IO_FAILED',
    operation,
    writes,
    error?.ambiguous === true,
  );
}

function validWrites(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function freezeJson(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Array.isArray(value) ? value : Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}

function cloneJson(value) {
  return freezeJson(parseCanonicalJsonBytes(canonicalJsonBytes(value, JSON_LIMITS), JSON_LIMITS));
}

function sameJson(left, right) {
  try { return canonicalJson(left, JSON_LIMITS) === canonicalJson(right, JSON_LIMITS); } catch { return false; }
}

function captureNative(native) {
  if (native === null || (typeof native !== 'object' && typeof native !== 'function')) {
    throwStore('SERVICE_INVALID', 'create_service_store');
  }
  let descriptors;
  try { descriptors = Object.getOwnPropertyDescriptors(native); } catch { throwStore('SERVICE_INVALID', 'create_service_store'); }
  const captured = Object.create(null);
  for (const name of REQUIRED_NATIVE) {
    const descriptor = descriptors[name];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
      throwStore('SERVICE_INVALID', 'create_service_store');
    }
    captured[name] = descriptor.value;
  }
  for (const name of OPTIONAL_NATIVE) {
    const descriptor = descriptors[name];
    if (descriptor && descriptor.get === undefined && descriptor.set === undefined &&
        Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function') {
      captured[name] = descriptor.value;
    }
  }
  return Object.freeze(captured);
}

function scopesFor(platform, architecture) {
  return Object.freeze([
    `application:${platform}:${architecture}`,
    ...(platform === 'win32' ? ['shawl:win32:x64'] : []),
  ]);
}

function floorName(scope) {
  return `${scope.replaceAll(':', '-')}.json`;
}

function floorWitnessName(scope) {
  return `${scope.replaceAll(':', '-')}.witness.json`;
}

function floorHistoryName(scope, revision, action = null, transactionFingerprint = null, serviceKey = null) {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throwStore('SERVICE_INVALID', 'floor_history_name');
  }
  const value = String(revision).padStart(16, '0');
  if (value.length !== 16) throwStore('SERVICE_INVALID', 'floor_history_name');
  const prefix = `${scope.replaceAll(':', '-')}-r${value}`;
  if (revision === 0) {
    if (action !== null || transactionFingerprint !== null || serviceKey !== null) {
      throwStore('SERVICE_INVALID', 'floor_history_name');
    }
    return `${prefix}-bootstrap`;
  }
  if (!['reserve', 'commit', 'abandon'].includes(action) ||
      !isHex64(transactionFingerprint)) {
    throwStore('SERVICE_INVALID', 'floor_history_name');
  }
  try { validateServiceKey(serviceKey); } catch {
    throwStore('SERVICE_INVALID', 'floor_history_name');
  }
  return `${prefix}-${action}-${transactionFingerprint}-${serviceKey}`;
}

function parseFloorHistoryName(scope, name) {
  const prefix = `${scope.replaceAll(':', '-')}-r`;
  if (typeof name !== 'string' || !name.startsWith(prefix)) return null;
  const suffix = name.slice(prefix.length);
  const revisionText = suffix.slice(0, 16);
  if (!/^[0-9]{16}$/.test(revisionText)) return null;
  const revision = Number(revisionText);
  if (!Number.isSafeInteger(revision) || revision < 0) return null;
  if (revision === 0) {
    return suffix === `${revisionText}-bootstrap`
      ? Object.freeze({ revision, action: null, transactionFingerprint: null, serviceKey: null })
      : null;
  }
  const tail = suffix.slice(17);
  const first = tail.indexOf('-');
  if (first < 0) return null;
  const action = tail.slice(0, first);
  const transactionFingerprint = tail.slice(first + 1, first + 65);
  const serviceKey = tail.slice(first + 66);
  if (tail[first + 65] !== '-' || !['reserve', 'commit', 'abandon'].includes(action) ||
      !isHex64(transactionFingerprint)) return null;
  try { validateServiceKey(serviceKey); } catch { return null; }
  return Object.freeze({ revision, action, transactionFingerprint, serviceKey });
}

function floorPairState(floor, witness) {
  if (witness.state === 'stable' &&
      witness.currentFloorFingerprint === floor.floorFingerprint &&
      witness.intendedFloorFingerprint === null &&
      witness.revision === floor.revision &&
      floor.historyEntryIdentityFingerprint === witness.historyEntryIdentityFingerprint &&
      floor.previousHistoryStateFingerprint === witness.previousHistoryStateFingerprint) {
    return 'stable';
  }
  if (witness.state !== 'intent') return null;
  if (witness.currentFloorFingerprint === floor.floorFingerprint &&
      witness.revision === floor.revision + 1) {
    return 'before';
  }
  if (witness.intendedFloorFingerprint !== floor.floorFingerprint ||
      witness.revision !== floor.revision ||
      floor.historyEntryIdentityFingerprint !== witness.historyEntryIdentityFingerprint ||
      floor.previousHistoryStateFingerprint !== witness.previousHistoryStateFingerprint) {
    return null;
  }
  if (witness.action === 'reserve') {
    const reservation = floor.activeReservation;
    if (!reservation ||
        reservation.transactionId !== witness.transactionId ||
        reservation.transactionNonce !== witness.transactionNonce ||
        reservation.transactionFingerprint !== witness.transactionFingerprint) return null;
  } else if (witness.action === 'commit') {
    if (floor.activeReservation !== null ||
        floor.committedTransactionId !== witness.transactionId ||
        floor.committedTransactionNonce !== witness.transactionNonce ||
        floor.committedTransactionFingerprint !== witness.transactionFingerprint) return null;
  } else if (witness.action === 'abandon' && floor.activeReservation !== null) {
    return null;
  }
  return 'after';
}

function floorTransitionFields(floor) {
  return {
    scope: floor.scope,
    revision: floor.revision,
    highestReservedSequence: floor.highestReservedSequence,
    highestReservedManifestFingerprint: floor.highestReservedManifestFingerprint,
    committedSequence: floor.committedSequence,
    committedManifestFingerprint: floor.committedManifestFingerprint,
    committedPublicationFingerprint: floor.committedPublicationFingerprint,
    committedTransactionId: floor.committedTransactionId,
    committedTransactionNonce: floor.committedTransactionNonce,
    committedTransactionFingerprint: floor.committedTransactionFingerprint,
    activeReservation: floor.activeReservation,
  };
}

function journalName(sequence) {
  if (!Number.isSafeInteger(sequence) || sequence < 1) throwStore('SERVICE_INVALID', 'journal_name');
  const value = String(sequence).padStart(16, '0');
  if (value.length !== 16) throwStore('SERVICE_INVALID', 'journal_name');
  return `entry-${value}.json`;
}

function retainedDeploymentEnvelopeName(purpose, manifestFingerprint) {
  if (!['application', 'shawl'].includes(purpose) ||
      !isHex64(manifestFingerprint)) {
    throwStore('SERVICE_INVALID', 'retained_deployment_envelope_name');
  }
  return `deployment-${purpose}-${manifestFingerprint}.json`;
}

function parseRetainedDeploymentEnvelopeName(name) {
  if (typeof name !== 'string') return null;
  const match = RETAINED_DEPLOYMENT_ENVELOPE.exec(name);
  return match === null
    ? null
    : Object.freeze({ purpose: match[1], manifestFingerprint: match[2] });
}

function boundedByteCopy(value, maximumBytes) {
  try {
    if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) ||
        value.byteLength < 1 || value.byteLength > maximumBytes) {
      return null;
    }
    const bytes = Buffer.from(value);
    return bytes.length >= 1 && bytes.length <= maximumBytes ? bytes : null;
  } catch {
    return null;
  }
}

function decodeCanonicalBase64(value, maximumBytes) {
  if (typeof value !== 'string' || value.length === 0 ||
      value.length > 4 * Math.ceil(maximumBytes / 3)) {
    throw new TypeError('retained deployment envelope bytes');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.length > maximumBytes ||
      bytes.toString('base64') !== value) {
    throw new TypeError('retained deployment envelope base64');
  }
  return bytes;
}

function validateRetainedDeploymentEnvelope(value) {
  if (!exact(value, [
    'schemaVersion',
    'kind',
    'serviceKey',
    'component',
    'platform',
    'architecture',
    'purpose',
    'manifestFingerprint',
    'manifestBase64',
    'signatureBase64',
  ]) ||
      value.schemaVersion !== 1 ||
      value.kind !== 'retained-deployment-envelope' ||
      !['application', 'shawl'].includes(value.purpose) ||
      !TUPLES.has(`${value.platform}:${value.architecture}`) ||
      (value.purpose === 'shawl' && value.platform !== 'win32') ||
      !isHex64(value.manifestFingerprint)) {
    throw new TypeError('retained deployment envelope');
  }
  validateServiceKey(value.serviceKey, value.component);
  decodeCanonicalBase64(
    value.manifestBase64,
    DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
  );
  decodeCanonicalBase64(
    value.signatureBase64,
    DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes,
  );
  return value;
}

class Calls {
  constructor(native) {
    this.native = native;
    this.writes = 0;
    this.handleOwner = null;
  }

  invoke(name, ...args) {
    let value;
    try { value = Reflect.apply(this.native[name], undefined, args); }
    catch (error) {
      const writes = validWrites(error?.writes) ? error.writes : 0;
      this.writes += writes;
      throwStore(
        typeof error?.code === 'string' ? error.code : 'SERVICE_IO_FAILED',
        typeof error?.operation === 'string' ? error.operation : name,
        this.writes,
        error?.ambiguous === true || !validWrites(error?.writes),
        error,
      );
    }
    if (name === 'close_service_handle' &&
        this.handleOwner !== null) {
      const handle = args[0];
      const index = this.handleOwner.handles.lastIndexOf(handle);
      if (index !== -1) this.handleOwner.handles.splice(index, 1);
    }
    if (this.handleOwner !== null && value !== null &&
        typeof value === 'object') {
      let descriptor;
      try {
        descriptor = Object.getOwnPropertyDescriptor(value, 'handle');
      } catch {}
      if (descriptor?.get === undefined &&
          descriptor?.set === undefined &&
          descriptor?.value !== null &&
          descriptor?.value !== undefined &&
          !this.handleOwner.handles.includes(descriptor.value)) {
        this.handleOwner.handles.push(descriptor.value);
      }

    }
    if (value !== null && typeof value === 'object' && Object.hasOwn(value, 'writes')) {
      if (!validWrites(value.writes)) throwStore('SERVICE_INVALID', name, this.writes, this.writes > 0);
      this.writes += value.writes;
    }
    return value;
  }

  adoptHandle(handle) {
    if (this.handleOwner === null) return;
    if (!this.handleOwner.handles.includes(handle)) {
      this.error(
        'SERVICE_MANUAL_CLEANUP',
        'adopt_service_handle_owner',
        true,
      );
    }
  }

  disownHandle(handle) {
    if (this.handleOwner === null) return;
    const index = this.handleOwner.handles.lastIndexOf(handle);
    if (index !== -1) this.handleOwner.handles.splice(index, 1);
  }

  beginHandleOwner() {
    if (this.handleOwner !== null) {
      this.error('SERVICE_PENDING', 'begin_service_handle_owner');
    }
    const owner = { handles: [] };
    this.handleOwner = owner;
    return owner;
  }

  retryHandleOwner(owner) {
    if (this.handleOwner !== owner) {
      this.error(
        'SERVICE_MANUAL_CLEANUP',
        'retry_service_handle_owner',
        true,
      );
    }
    let failure = null;
    for (const handle of [...owner.handles].reverse()) {
      try {
        this.invoke('close_service_handle', handle);
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure !== null) throw failure;
  }

  releaseHandleOwner(owner) {
    if (this.handleOwner !== owner || owner.handles.length !== 0) {
      this.error(
        'SERVICE_MANUAL_CLEANUP',
        'release_service_handle_owner',
        true,
      );
    }
    this.handleOwner = null;
  }


  invalid(operation, ambiguous = false, cause = undefined) {
    throwStore('SERVICE_INVALID', operation, this.writes, ambiguous, cause);
  }

  error(code, operation, ambiguous = false, cause = undefined) {
    throwStore(code, operation, this.writes, ambiguous, cause);
  }

  validate(operation, validator) {
    try { return validator(); }
    catch (error) {
      if (error?.name === 'ServiceStoreError') throw error;
      this.invalid(operation, this.writes > 0, error);
    }
  }
}

function validateRootResult(calls, result, platform, rootKind, expectedOwner) {
  return calls.validate('open_service_root', () => {
    if (!exact(result, ['handle', 'rootBinding', 'writes']) || result.handle === null || !validWrites(result.writes) ||
        !plain(result.rootBinding) || result.rootBinding.rootKind !== rootKind) throw new TypeError('root result');
    if (rootKind === 'control') validateServiceControlRootBinding(result.rootBinding, platform);
    else {
      if (!exact(result.rootBinding, ['schemaVersion', 'rootKind', 'rootPath', 'rootNonce', 'rolesFingerprint', 'identity', 'directoryIdentities', 'bindingFingerprint']) ||
          result.rootBinding.schemaVersion !== 1 || typeof result.rootBinding.rootNonce !== 'string' ||
          !NONCE.test(result.rootBinding.rootNonce) ||
          !isHex64(result.rootBinding.rolesFingerprint) || !isHex64(result.rootBinding.bindingFingerprint) ||
          typeof result.rootBinding.rootPath !== 'string' || result.rootBinding.rootPath.length === 0 ||
          !plain(result.rootBinding.directoryIdentities) || Object.keys(result.rootBinding.directoryIdentities).length !== 0) {
        throw new TypeError('artifact root binding');
      }
      validateServiceNativeIdentity(
        result.rootBinding.identity,
        platform,
        rootKind === 'staging' ? 'service-staging-directory' : 'service-release-directory',
      );
    }
    if (result.rootBinding.identity.owner !== expectedOwner) throw new TypeError('root owner');
    return result;
  });
}

function validateOwnedRootResult(calls, result, platform, rootKind, expectedOwner) {
  try {
    return validateRootResult(calls, result, platform, rootKind, expectedOwner);
  } catch (error) {
    if (plain(result) && Object.hasOwn(result, 'handle') && result.handle !== null) {
      throwAfterCleanup(calls, error, () => calls.invoke('close_service_handle', result.handle));
    }
    throw error;
  }
}

function validateDirectoryResult(calls, result, platform) {
  return calls.validate('open_service_directory', () => {
    if (!exact(result, ['handle', 'identity', 'writes']) || result.handle === null || !validWrites(result.writes)) {
      throw new TypeError('directory result');
    }
    validateServiceNativeIdentity(result.identity, platform);
    return result;
  });
}

function validateOwnedDirectoryResult(calls, result, platform) {
  try {
    return validateDirectoryResult(calls, result, platform);
  } catch (error) {
    if (plain(result) && Object.hasOwn(result, 'handle') && result.handle !== null) {
      throwAfterCleanup(calls, error, () => calls.invoke('close_service_handle', result.handle));
    }
    throw error;
  }
}

function validateLockResult(calls, result, platform) {
  return calls.validate('acquire_service_lock', () => {
    if (!exact(result, ['handle', 'identity', 'writes']) || result.handle === null || !validWrites(result.writes)) {
      throw new TypeError('lock result');
    }
    validateServiceNativeIdentity(result.identity, platform, 'service-control-file');
    return result;
  });
}

function validateOwnedLockResult(calls, result, platform) {
  try {
    return validateLockResult(calls, result, platform);
  } catch (error) {
    if (plain(result) && Object.hasOwn(result, 'handle') && result.handle !== null) {
      throwAfterCleanup(calls, error, () => calls.invoke('close_service_handle', result.handle));
    }
    throw error;
  }
}

function validateReadResult(calls, result) {
  return calls.validate('read_service_file', () => {
    if (result === null) return null;
    if (!exact(result, ['bytes', 'facts', 'writes']) || !Buffer.isBuffer(result.bytes) || !plain(result.facts) || result.writes !== 0) {
      throw new TypeError('read result');
    }
    return result;
  });
}

function validateWriteResult(calls, result, operation) {
  return calls.validate(operation, () => {
    if (!exact(result, ['facts', 'writes']) || !plain(result.facts) || !validWrites(result.writes) || result.writes < 1) {
      throw new TypeError('write result');
    }
    return result;
  });
}

function validateListResult(calls, result, platform) {
  return calls.validate('list_service_directory', () => {
    if (!exact(result, ['directoryIdentity', 'entries', 'writes']) || result.writes !== 0 ||
        !Array.isArray(result.entries) || result.entries.length > SERVICE_STORE_LIMITS.directoryEntries) {
      throw new TypeError('list entries');
    }
    validateServiceNativeIdentity(result.directoryIdentity, platform, 'service-control-directory');
    let previous = null;
    for (const entry of result.entries) {
      if (!exact(entry, ['name', 'identity']) || typeof entry.name !== 'string' || entry.name.length === 0) {
        throw new TypeError('list entry');
      }
      validateServiceNativeIdentity(entry.identity, platform);
      if (previous !== null && utf8Compare(previous, entry.name) >= 0) throw new TypeError('list ordering');
      previous = entry.name;
    }
    return result;
  });
}

function validateArtifactListResult(calls, result, platform, expectedIdentity) {
  return calls.validate('list_service_directory', () => {
    if (!exact(result, ['directoryIdentity', 'entries', 'writes']) ||
        result.writes !== 0 || !Array.isArray(result.entries) ||
        result.entries.length > ARTIFACT_DIRECTORY_ENTRIES) {
      throw new TypeError('artifact list result');
    }
    validateServiceNativeIdentity(result.directoryIdentity, platform);
    if (!sameJson(result.directoryIdentity, expectedIdentity)) {
      throw new TypeError('artifact directory identity');
    }
    let previous = null;
    for (const entry of result.entries) {
      if (!exact(entry, ['name', 'identity']) ||
          typeof entry.name !== 'string' || entry.name.length === 0 ||
          Buffer.byteLength(entry.name, 'utf8') > 255) {
        throw new TypeError('artifact list entry');
      }
      validateServiceNativeIdentity(entry.identity, platform);
      if (previous !== null && utf8Compare(previous, entry.name) >= 0) {
        throw new TypeError('artifact list ordering');
      }
      previous = entry.name;
    }
    return result;
  });
}

function parseRecord(calls, bytes, validator, operation) {
  try {
    const value = parseCanonicalJsonBytes(bytes, JSON_LIMITS);
    validator(value);
    return cloneJson(value);
  } catch (error) {
    calls.error('SERVICE_MANUAL_CLEANUP', operation, true, error);
  }
}

function closeReverse(calls, handles) {
  let first;
  for (let index = handles.length - 1; index >= 0; index -= 1) {
    if (handles[index] === undefined || handles[index] === null) continue;
    try { calls.invoke('close_service_handle', handles[index]); } catch (error) { first ??= error; }
  }
  if (first) throw first;
}

function throwAfterCleanup(calls, original, cleanup) {
  let cleanupError;
  try { cleanup(); } catch (error) { cleanupError = error; }
  if (cleanupError) {
    throwStore(
      'SERVICE_MANUAL_CLEANUP',
      'close_service_store_after_failure',
      Math.max(
        calls.writes,
        validWrites(original?.writes) ? original.writes : 0,
        validWrites(cleanupError?.writes) ? cleanupError.writes : 0,
      ),
      true,
      new AggregateError([original, cleanupError], 'service store operation and cleanup both failed'),
    );
  }
  throw original;
}

function acquire(calls, root, platform, scope, serviceKey, mode, expectedIdentity = undefined) {
  const value = validateOwnedLockResult(
    calls,
    calls.invoke('acquire_service_lock', root, scope, serviceKey, mode),
    platform,
  );
  if ((mode === 'shared-existing' && value.writes !== 0) ||
      (expectedIdentity !== undefined && (!sameJson(value.identity, expectedIdentity) || value.writes !== 0))) {
    try {
      calls.error('SERVICE_MANUAL_CLEANUP', 'acquire_service_lock', true);
    } catch (error) {
      throwAfterCleanup(calls, error, () => calls.invoke('close_service_handle', value.handle));
    }
  }
  return value;
}

function readRegistration(calls, root, rootBinding, platform, architecture, roles, rolesFingerprint) {
  let directory;
  let history;
  try {
    directory = validateOwnedDirectoryResult(calls, calls.invoke(
      'open_service_directory', root, 'floor', 'read-existing', rootBinding.directoryIdentities.floor, null,
    ), platform);
    if (directory.writes !== 0) calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
    const raw = validateReadResult(calls, calls.invoke(
      'read_service_file', directory.handle, SERVICE_STORE_LAYOUT.registration, SERVICE_STORE_LIMITS.recordBytes,
    ));
    if (raw === null) calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
    const registration = parseRecord(calls, raw.bytes, validateServiceStoreRegistration, 'open_service_store');
    if (registration.platform !== platform || registration.architecture !== architecture ||
        registration.serviceRolesFingerprint !== rolesFingerprint ||
        !sameJson(registration.roles, roles) ||
        !sameJson(registration.rootBinding, rootBinding) ||
        registration.historyRootIdentity.owner !== roles.management.value) {
      calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
    }
    history = validateOwnedDirectoryResult(calls, calls.invoke(
      'open_service_directory',
      directory.handle,
      SERVICE_STORE_LAYOUT.historyDirectory,
      'read-existing',
      registration.historyRootIdentity,
      null,
    ), platform);
    if (history.writes !== 0) calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
    const incarnationRaw = validateReadResult(calls, calls.invoke(
      'read_service_file',
      history.handle,
      SERVICE_STORE_LAYOUT.registrationIncarnation,
      SERVICE_STORE_LIMITS.recordBytes,
    ));
    if (incarnationRaw === null) calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
    const incarnation = parseRecord(
      calls,
      incarnationRaw.bytes,
      validateServiceStoreRegistrationIncarnation,
      'open_service_store',
    );
    if (incarnation.platform !== platform || incarnation.architecture !== architecture ||
        incarnation.rootBindingFingerprint !== rootBinding.bindingFingerprint ||
        incarnation.historyRootIdentityFingerprint !== registration.historyRootIdentityFingerprint ||
        incarnation.registrationFingerprint !== registration.registrationFingerprint ||
        incarnation.registrationRecordSha256 !== canonicalJsonHash(registration) ||
        incarnation.registrationFileFacts.owner !== roles.management.value ||
        !sameJson(incarnation.registrationFileFacts, raw.facts)) {
      calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
    }
    calls.invoke('close_service_handle', history.handle);
    history = undefined;
    calls.invoke('close_service_handle', directory.handle);
    directory = undefined;
    return Object.freeze({
      value: registration,
      facts: calls.validate('open_service_store', () => cloneJson(raw.facts)),
      bytes: Buffer.from(raw.bytes),
      incarnation: cloneJson(incarnation),
      incarnationFacts: calls.validate('open_service_store', () => cloneJson(incarnationRaw.facts)),
      incarnationBytes: Buffer.from(incarnationRaw.bytes),
    });
  } finally {
    if (history?.handle) {
      try { calls.invoke('close_service_handle', history.handle); } catch {}
    }
    if (directory?.handle) {
      try { calls.invoke('close_service_handle', directory.handle); } catch {}
    }
  }
}

function preflightGlobalLocks(calls, root, platform) {
  const handles = [];
  try {
    const artifact = acquire(calls, root, platform, 'artifact', null, 'shared-existing');
    handles.push(artifact.handle);
    const shared = acquire(calls, root, platform, 'shared-template', null, 'shared-existing');
    handles.push(shared.handle);
    const identities = Object.freeze({ artifact: cloneJson(artifact.identity), shared: cloneJson(shared.identity) });
    closeReverse(calls, handles);
    handles.length = 0;
    return identities;
  } finally {
    if (handles.length > 0) {
      try { closeReverse(calls, handles); } catch {}
    }
  }
}

function findEntry(listing, name) {
  return listing.entries.find((entry) => entry.name === name) ?? null;
}

function referenceServiceKey(name) {
  if (typeof name !== 'string' || !name.endsWith('.json')) return null;
  const serviceKey = name.slice(0, -5);
  try { return validateServiceKey(serviceKey); } catch { return null; }
}

function sameReferenceArtifacts(left, right) {
  if (left === null || right === null) return left === right;
  return left.artifacts.length === right.artifacts.length &&
    left.artifacts.every((artifact, index) =>
      artifact.bindingFingerprint === right.artifacts[index].bindingFingerprint);
}

function artifactPhysicalRelation(left, right) {
  if (left.artifactKind === 'shared-template' || right.artifactKind === 'shared-template') {
    return 'different';
  }
  const sameTargetName = left.rootKind === right.rootKind &&
    left.artifactFingerprint === right.artifactFingerprint;
  const sameIdentity = left.directoryIdentityFingerprint ===
      right.directoryIdentityFingerprint &&
    sameJson(left.directoryIdentity, right.directoryIdentity);
  if (sameTargetName && sameIdentity) return 'same';
  if (sameTargetName || sameIdentity) return 'ambiguous';
  return 'different';
}

function metadataExists(calls, namespaces, artifactLock, serviceKey, platform) {
  for (const name of SERVICE_DIRECT) {
    const listing = validateListResult(calls, calls.invoke(
      'list_service_directory', namespaces[name], SERVICE_STORE_LIMITS.directoryEntries, artifactLock,
    ), platform);
    if (findEntry(listing, serviceKey)) return true;
  }
  const references = validateListResult(calls, calls.invoke(
    'list_service_directory', namespaces.reference, SERVICE_STORE_LIMITS.directoryEntries, artifactLock,
  ), platform);
  return findEntry(references, `${serviceKey}.json`) !== null;
}

function globalFloorPending(calls, floorDirectory, historyDirectory, artifactLock, scopes, registration, rootBinding, platform, architecture) {
  const expectedNames = new Set([
    SERVICE_STORE_LAYOUT.registration,
    SERVICE_STORE_LAYOUT.historyDirectory,
    ...scopes.flatMap((scope) => [floorName(scope), floorWitnessName(scope)]),
  ]);
  const listing = validateListResult(calls, calls.invoke(
    'list_service_directory', floorDirectory, SERVICE_STORE_LIMITS.directoryEntries, artifactLock,
  ), platform);
  if (listing.entries.length !== expectedNames.size ||
      listing.entries.some((entry) => !expectedNames.has(entry.name))) {
    calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
  }
  let pending = false;
  const historyListing = validateListResult(calls, calls.invoke(
    'list_service_directory',
    historyDirectory,
    SERVICE_STORE_LIMITS.directoryEntries,
    artifactLock,
  ), platform);
  for (const scope of scopes) {
    const floorRaw = validateReadResult(calls, calls.invoke(
      'read_service_file', floorDirectory, floorName(scope), SERVICE_STORE_LIMITS.recordBytes,
    ));
    const witnessRaw = validateReadResult(calls, calls.invoke(
      'read_service_file', floorDirectory, floorWitnessName(scope), SERVICE_STORE_LIMITS.recordBytes,
    ));
    if (!floorRaw || !witnessRaw) calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
    const floor = parseRecord(calls, floorRaw.bytes, validateServiceSequenceFloor, 'read_sequence_floor');
    const witness = parseRecord(calls, witnessRaw.bytes, validateServiceFloorWitness, 'read_sequence_floor');
    if (floor.scope !== scope || witness.scope !== scope || witness.platform !== platform ||
        witness.architecture !== architecture ||
        witness.rootBindingFingerprint !== rootBinding.bindingFingerprint) {
      calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
    }
    const state = floorPairState(floor, witness);
    if (state === null) calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
    if (state !== 'stable' || floor.activeReservation !== null) pending = true;
    const historyEntries = historyListing.entries
      .map((entry) => ({ entry, descriptor: parseFloorHistoryName(scope, entry.name) }))
      .filter(({ descriptor }) => descriptor !== null)
      .sort((left, right) => left.descriptor.revision - right.descriptor.revision);
    if (historyEntries.length === 0 ||
        historyEntries.some(({ descriptor }, index) => descriptor.revision !== index)) {
      calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
    }
    const latest = historyEntries.at(-1);
    if (latest.descriptor.revision < floor.revision ||
        latest.descriptor.revision > floor.revision + 1) {
      calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
    }
    let historyHandle;
    try {
      historyHandle = validateOwnedDirectoryResult(calls, calls.invoke(
        'open_service_directory',
        historyDirectory,
        latest.entry.name,
        'read-existing',
        latest.entry.identity,
        artifactLock,
      ), platform);
      if (historyHandle.writes !== 0) {
        calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
      }
      const historyFiles = validateListResult(calls, calls.invoke(
        'list_service_directory',
        historyHandle.handle,
        SERVICE_STORE_LIMITS.directoryEntries,
        artifactLock,
      ), platform);
      const hasState = historyFiles.entries.some(({ name }) =>
        name === SERVICE_STORE_LAYOUT.floorHistoryState);
      if (latest.descriptor.revision !== floor.revision || !hasState) pending = true;
      if (hasState) {
        const stateRaw = validateReadResult(calls, calls.invoke(
          'read_service_file',
          historyHandle.handle,
          SERVICE_STORE_LAYOUT.floorHistoryState,
          SERVICE_STORE_LIMITS.recordBytes,
        ));
        if (stateRaw === null) calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
        const historyState = parseRecord(
          calls,
          stateRaw.bytes,
          validateServiceFloorHistoryState,
          'read_sequence_floor',
        );
        if (historyState.scope !== scope ||
            historyState.revision !== latest.descriptor.revision ||
            historyState.platform !== platform ||
            historyState.architecture !== architecture ||
            historyState.rootBindingFingerprint !== rootBinding.bindingFingerprint ||
            historyState.registrationFingerprint !== registration.registrationFingerprint ||
            !sameJson(historyState.historyEntryIdentity, latest.entry.identity) ||
            historyState.historyEntryIdentity.owner !== rootBinding.identity.owner ||
            historyState.floorFileFacts.owner !== rootBinding.identity.owner ||
            historyState.witnessFileFacts.owner !== rootBinding.identity.owner ||
            historyState.floorFingerprint !== floor.floorFingerprint ||
            historyState.witnessFingerprint !== witness.witnessFingerprint ||
            historyState.floorRecordSha256 !== canonicalJsonHash(floor) ||
            historyState.witnessRecordSha256 !== canonicalJsonHash(witness) ||
            !sameJson(historyState.floorFileFacts, floorRaw.facts) ||
            !sameJson(historyState.witnessFileFacts, witnessRaw.facts)) {
          calls.error('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', true);
        }
      }
      calls.invoke('close_service_handle', historyHandle.handle);
      historyHandle = undefined;
    } finally {
      if (historyHandle?.handle) {
        try { calls.invoke('close_service_handle', historyHandle.handle); } catch {}
      }
    }
  }
  return pending;
}

function optionsSnapshot(options) {
  const values = dataValues(options, ['native', 'roles', 'target', 'platform', 'architecture']);
  if (!values || !TUPLES.has(`${values.platform}:${values.architecture}`)) {
    throwStore('SERVICE_INVALID', 'create_service_store');
  }
  const targetHead = dataValues(values.target, ['component']);
  const targetValues = targetHead?.component === 'bot'
    ? targetHead
    : dataValues(values.target, ['component', 'hostId']);
  const roleValues = dataValues(values.roles, ROLE_KEYS);
  if (!targetValues || !roleValues) throwStore('SERVICE_INVALID', 'create_service_store');
  const target = Object.fromEntries(Object.entries(targetValues));
  const roles = {};
  for (const role of ROLE_KEYS) {
    const principal = dataValues(roleValues[role], ['kind', 'value']);
    if (!principal) throwStore('SERVICE_INVALID', 'create_service_store');
    roles[role] = Object.fromEntries(Object.entries(principal));
  }
  try {
    validateServiceTarget(target);
    validateServiceRoles(roles, values.platform);
  } catch (error) {
    throwStore('SERVICE_INVALID', 'create_service_store', 0, false, error);
  }
  return {
    native: captureNative(values.native),
    roles: cloneJson(roles),
    platform: values.platform,
    architecture: values.architecture,
    component: target.component,
    serviceKey: serviceKeyForTarget(target),
  };
}

export function createServiceStore(options) {
  const config = optionsSnapshot(options);
  const scopes = scopesFor(config.platform, config.architecture);
  const rolesFingerprint = serviceRolesFingerprint(config.roles, config.platform);

  function openExisting(mode) {
    const calls = new Calls(config.native);
    const rawRoot = calls.invoke('open_service_root', 'control', mode === 'read-only' ? 'read-existing' : 'write-existing');
    if (rawRoot === null) {
      if (mode === 'read-only') return null;
      calls.error('SERVICE_STORE_ABSENT', 'open_service_store');
    }
    const rootResult = validateOwnedRootResult(
      calls, rawRoot, config.platform, 'control', config.roles.management.value,
    );
    const cleanup = [rootResult.handle];
    let session;
    try {
      if (rootResult.writes !== 0) calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
      const registrationSnapshot = readRegistration(
        calls,
        rootResult.handle,
        rootResult.rootBinding,
        config.platform,
        config.architecture,
        config.roles,
        rolesFingerprint,
      );
      let artifact;
      let shared;
      if (mode === 'read-only') {
        artifact = acquire(calls, rootResult.handle, config.platform, 'artifact', null, 'shared-existing');
        cleanup.push(artifact.handle);
        shared = acquire(calls, rootResult.handle, config.platform, 'shared-template', null, 'shared-existing');
        cleanup.push(shared.handle);
      } else {
        const identities = preflightGlobalLocks(calls, rootResult.handle, config.platform);
        artifact = acquire(calls, rootResult.handle, config.platform, 'artifact', null, 'exclusive', identities.artifact);
        cleanup.push(artifact.handle);
        shared = acquire(calls, rootResult.handle, config.platform, 'shared-template', null, 'exclusive', identities.shared);
        cleanup.push(shared.handle);
      }
      const namespaces = Object.create(null);
      for (const name of OPEN_NAMESPACES) {
        const opened = validateOwnedDirectoryResult(calls, calls.invoke(
          'open_service_directory', rootResult.handle, name,
          mode === 'read-only' ? 'read-existing' : 'write-existing',
          rootResult.rootBinding.directoryIdentities[name], artifact.handle,
        ), config.platform);
        cleanup.push(opened.handle);
        if (opened.writes !== 0) calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
        namespaces[name] = opened;
      }
      const history = validateOwnedDirectoryResult(calls, calls.invoke(
        'open_service_directory',
        namespaces.floor.handle,
        SERVICE_STORE_LAYOUT.historyDirectory,
        mode === 'read-only' ? 'read-existing' : 'write-existing',
        registrationSnapshot.value.historyRootIdentity,
        artifact.handle,
      ), config.platform);
      cleanup.push(history.handle);
      if (history.writes !== 0) calls.error('SERVICE_MANUAL_CLEANUP', 'open_service_store', true);
      const hasMetadata = metadataExists(calls, Object.fromEntries(
        Object.entries(namespaces).map(([name, value]) => [name, value.handle]),
      ), artifact.handle, config.serviceKey, config.platform);
      const hasPendingGlobalFloor = !hasMetadata && globalFloorPending(
        calls,
        namespaces.floor.handle,
        history.handle,
        artifact.handle,
        scopes,
        registrationSnapshot.value,
        rootResult.rootBinding,
        config.platform,
        config.architecture,
      );
      if (mode === 'mutation' && hasPendingGlobalFloor) {
        calls.error('SERVICE_PENDING', 'open_service_store');
      }
      let service;
      if (mode === 'read-only') {
        service = acquire(calls, rootResult.handle, config.platform, 'service-key', config.serviceKey, 'shared-existing');
      } else if (hasMetadata || mode === 'recovery') {
        const observed = acquire(calls, rootResult.handle, config.platform, 'service-key', config.serviceKey, 'shared-existing');
        cleanup.push(observed.handle);
        calls.invoke('close_service_handle', observed.handle);
        cleanup.pop();
        service = acquire(calls, rootResult.handle, config.platform, 'service-key', config.serviceKey, 'exclusive', observed.identity);
      } else {
        service = acquire(calls, rootResult.handle, config.platform, 'service-key', config.serviceKey, 'exclusive');
      }
      cleanup.push(service.handle);
      session = new Session({
        calls,
        mode,
        config,
        scopes,
        rolesFingerprint,
        rootResult,
        artifact,
        shared,
        service,
        namespaces,
        history,
        registrationSnapshot,
      });
      session.initialize();
      cleanup.length = 0;
      if (mode === 'mutation' && session.blocked()) {
        const code = session.blockCode();
        session.close();
        throwStore(code, 'open_service_store', calls.writes);
      }
      if (mode === 'recovery') session.assertRecoveryAdmission();
      return session.publicApi();
    } catch (error) {
      if (session) {
        throwAfterCleanup(calls, error, () => session.close());
      } else {
        throwAfterCleanup(calls, error, () => closeReverse(calls, cleanup));
      }
    }
  }

  function bootstrap() {
    const calls = new Calls(config.native);
    const rawRoot = calls.invoke('open_service_root', 'control', 'create-new');
    if (rawRoot === null) calls.error('SERVICE_IO_FAILED', 'bootstrap_service_store');
    const rootResult = validateOwnedRootResult(
      calls, rawRoot, config.platform, 'control', config.roles.management.value,
    );
    const cleanup = [rootResult.handle];
    let session;
    try {
      if (rootResult.writes < 1) calls.error('SERVICE_MANUAL_CLEANUP', 'bootstrap_service_store', true);
      const artifact = acquire(calls, rootResult.handle, config.platform, 'artifact', null, 'exclusive');
      cleanup.push(artifact.handle);
      const shared = acquire(calls, rootResult.handle, config.platform, 'shared-template', null, 'exclusive');
      cleanup.push(shared.handle);
      const service = acquire(calls, rootResult.handle, config.platform, 'service-key', config.serviceKey, 'exclusive');
      cleanup.push(service.handle);
      const namespaces = Object.create(null);
      for (const name of OPEN_NAMESPACES) {
        const opened = validateOwnedDirectoryResult(calls, calls.invoke(
          'open_service_directory', rootResult.handle, name, 'write-existing',
          rootResult.rootBinding.directoryIdentities[name], artifact.handle,
        ), config.platform);
        cleanup.push(opened.handle);
        if (opened.writes !== 0) calls.error('SERVICE_MANUAL_CLEANUP', 'bootstrap_service_store', true);
        namespaces[name] = opened;
      }
      const history = validateOwnedDirectoryResult(calls, calls.invoke(
        'open_service_directory',
        namespaces.floor.handle,
        SERVICE_STORE_LAYOUT.historyDirectory,
        'create-new',
        null,
        artifact.handle,
      ), config.platform);
      cleanup.push(history.handle);
      if (history.writes < 1) calls.error('SERVICE_MANUAL_CLEANUP', 'bootstrap_service_store', true);
      session = new Session({
        calls,
        mode: 'mutation',
        config,
        scopes,
        rolesFingerprint,
        rootResult,
        artifact,
        shared,
        service,
        namespaces,
        history,
      });
      session.bootstrap();
      session.initialize();
      cleanup.length = 0;
      return session.publicApi();
    } catch (error) {
      if (session) {
        throwAfterCleanup(calls, error, () => session.close());
      } else {
        throwAfterCleanup(calls, error, () => closeReverse(calls, cleanup));
      }
    }
  }

  return Object.freeze({
    component: config.component,
    serviceKey: config.serviceKey,
    platform: config.platform,
    architecture: config.architecture,
    bootstrap,
    openReadOnly: () => openExisting('read-only'),
    openMutation: () => openExisting('mutation'),
    openRecovery: () => openExisting('recovery'),
  });
}

class Session {
  #calls;
  #mode;
  #config;
  #scopes;
  #rolesFingerprint;
  #root;
  #artifact;
  #shared;
  #service;
  #namespaces;
  #history;
  #serviceDirectories = new Map();
  #historyDirectories = new Map();
  #floors = new Map();
  #token = Object.freeze({});
  #closed = false;
  #tombstone;
  #manual;
  #journal;
  #references;
  #observedPublications = new Map();
  #observedSharedTemplateBindings = new Set();
  #driverLockHandoff;
  #provisionalMetadata = null;
  #metadataPairMutation = false;
  #registrationSnapshot;
  #registration;
  #globalRecoveryBinding;
  #recoveryBinding;
  #artifactAccesses = 0;
  #artifactCleanup;
  #cleanupMetadataMutation = false;
  #artifactCollectionActive = false;
  #artifactCleanupUncertain = false;
  #artifactCollectorOwner = null;

  constructor({ calls, mode, config, scopes, rolesFingerprint, rootResult, artifact, shared, service, namespaces, history, registrationSnapshot = null }) {
    this.#calls = calls;
    this.#mode = mode;
    this.#config = config;
    this.#scopes = scopes;
    this.#rolesFingerprint = rolesFingerprint;
    this.#root = rootResult;
    this.#artifact = artifact;
    this.#shared = shared;
    this.#service = service;
    this.#namespaces = namespaces;
    this.#history = history;
    this.#registrationSnapshot = registrationSnapshot;
    // The handles are never exposed through a general store API.  This
    // capability is handed only to a driver created for this session and is
    // branded so a caller cannot manufacture an equivalent authority object.
    this.#driverLockHandoff = Object.freeze({
      artifact: this.#artifact.handle,
      sharedTemplate: this.#shared.handle,
      serviceKey: this.#service.handle,
    });
    driverLockBindings.set(this.#driverLockHandoff, { token: this.#token });
  }

  publicApi() {
    const self = this;
    return Object.freeze({
      component: this.#config.component,
      serviceKey: this.#config.serviceKey,
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      get writes() { return self.#calls.writes; },
      handoffDriverLocks: () => self.handoffDriverLocks(),
      close: () => self.close(),
      readManifest: (slot) => self.readManifest(slot),
      publishManifest: (slot, value, expected) => self.publishManifest(slot, value, expected),
      removeManifest: (slot, expected) => self.removeManifest(slot, expected),
      readResourceProof: (slot) => self.readResourceProof(slot),
      publishResourceProof: (slot, value, expected) => self.publishResourceProof(slot, value, expected),
      removeResourceProof: (slot, expected) => self.removeResourceProof(slot, expected),
      readStartupProof: () => self.readStartupProof(),
      publishStartupProof: (value, expected) => self.publishStartupProof(value, expected),
      removeStartupProof: (expected) => self.removeStartupProof(expected),
      readJournal: () => self.readJournal(),
      appendJournal: (value) => self.appendJournal(value),
      retainDeploymentEnvelope: (input) => self.retainDeploymentEnvelope(input),
      readRetainedDeploymentEnvelope: (input) => self.readRetainedDeploymentEnvelope(input),
      openArtifactAccess: (input) => self.openArtifactAccess(input),
      readTombstone: () => self.readTombstone(),
      publishTombstone: (value, expected) => self.publishTombstone(value, expected),
      readManualCleanup: () => self.readManualCleanup(),
      publishManualCleanup: (value, expected) => self.publishManualCleanup(value, expected),
      clearManualCleanup: (expected, oldProof) => self.clearManualCleanup(expected, oldProof),
      readReferences: () => self.readReferences(),
      readSiblingReferences: () => self.readSiblingReferences(),
      readPublicationReceipt: (input) => self.readPublicationReceipt(input),
      publishReferences: (value, expected) => self.publishReferences(value, expected),
      observeZeroReferences: (artifact) => self.observeZeroReferences(artifact),
      collectPublishedArtifact: (...args) =>
        self.collectPublishedArtifact(args),
      recoverPublishedArtifactCollection: (...args) =>
        self.recoverPublishedArtifactCollection(args),
      collectScratchArtifacts: (...args) =>
        self.collectScratchArtifacts(args),
      recoverScratchArtifactCollection: (...args) =>
        self.recoverScratchArtifactCollection(args),
      observeApplicationPublication: (manifest, identity) => self.observeApplicationPublication(manifest, identity),
      observeShawlPublication: (manifest, identity) => self.observeShawlPublication(manifest, identity),
      createSharedTemplateBinding: (...args) => self.createSharedTemplateBinding(...args),
      readApplicationFloor: () => self.readFloor(`application:${self.#config.platform}:${self.#config.architecture}`),
      assertFloorCas: (input) => self.assertFloorCas(input),
      acceptProvisionalMetadata: (input) => self.acceptProvisionalMetadata(input),
      publishCurrentMetadata: (input) => self.publishCurrentMetadata(input),
      reserveApplicationSequence: (input) => self.reserveApplicationSequence(input),
      commitApplicationSequence: (input) => self.commitApplicationSequence(input),
      abandonApplicationSequence: (input) => self.abandonApplicationSequence(input),
      assertApplicationRollback: (input) => self.assertApplicationRollback(input),
      readShawlFloor: () => self.readShawlFloor(),
      reserveShawlSequence: (input) => self.reserveShawlSequence(input),
      commitShawlSequence: (input) => self.commitShawlSequence(input),
      abandonShawlSequence: (input) => self.abandonShawlSequence(input),
      assertShawlRollback: (input) => self.assertShawlRollback(input),
    });
  }

  #ensureOpen(operation) {
    if (this.#closed) throwStore('SERVICE_STALE', operation, this.#calls.writes);
  }

  #ensureWritable(operation) {
    this.#ensureOpen(operation);
    if (this.#mode === 'read-only') throwStore('SERVICE_ACCESS_DENIED', operation, this.#calls.writes);
    if (this.#artifactAccesses !== 0 &&
        !this.#cleanupMetadataMutation) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (this.#artifactCleanup?.present &&
        !this.#cleanupMetadataMutation) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (this.#artifactCleanupUncertain &&
        !this.#cleanupMetadataMutation) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    if (this.#manual?.present && operation !== 'clear_manual_cleanup') {
      throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes);
    }
  }

  #assertPinnedManifest(manifest, purpose) {
    try {
      return assertPinnedDeploymentManifest(manifest, purpose);
    } catch (error) {
      const deploymentCode = typeof error?.code === 'string' &&
        /^DEPLOYMENT_[A-Z_]+$/.test(error.code);
      throwStore(
        deploymentCode ? error.code : 'SERVICE_IO_FAILED',
        'verify_deployment_provenance',
        this.#calls.writes,
        !deploymentCode || error?.ambiguous === true,
      );
    }
  }

  #scope(value, operation) {
    if (value.component !== this.#config.component || value.serviceKey !== this.#config.serviceKey ||
        value.platform !== this.#config.platform || value.architecture !== this.#config.architecture) {
      throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    }
  }

  #scopeRoles(value, operation) {
    if (value.rolesFingerprint !== this.#rolesFingerprint || !sameJson(value.roles, this.#config.roles)) {
      throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    }
  }

  #snapshot(value, validator, operation) {
    try {
      const snapshot = cloneJson(value);
      validator(snapshot);
      return snapshot;
    } catch (error) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes, false, error);
    }
  }

  #list(handle, lock = this.#artifact.handle) {
    this.#ensureOpen('list_service_directory');
    return validateListResult(this.#calls, this.#calls.invoke(
      'list_service_directory', handle, SERVICE_STORE_LIMITS.directoryEntries, lock,
    ), this.#config.platform);
  }

  #makeReceipt(logical, value, native) {
    const receipt = Object.freeze({ present: value !== null, value });
    receiptBindings.set(receipt, { token: this.#token, logical, native, consumed: false });
    return receipt;
  }

  #boundReceipt(receipt, logical, operation) {
    const binding = receiptBindings.get(receipt);
    if (!binding || binding.token !== this.#token || binding.logical !== logical || binding.consumed) {
      throwStore('SERVICE_STALE', operation, this.#calls.writes);
    }
    return binding;
  }

  #consume(receipt) {
    receiptBindings.get(receipt).consumed = true;
  }

  #read(handle, name, validator, logical) {
    this.#ensureOpen(logical);
    const raw = validateReadResult(this.#calls, this.#calls.invoke(
      'read_service_file', handle, name, SERVICE_STORE_LIMITS.recordBytes,
    ));
    if (raw === null) return this.#makeReceipt(logical, null, null);
    const value = parseRecord(this.#calls, raw.bytes, validator, logical);
    return this.#makeReceipt(logical, value, {
      facts: this.#calls.validate(logical, () => cloneJson(raw.facts)),
      bytes: Buffer.from(raw.bytes),
    });
  }

  #publish(handle, name, value, validator, expected, logical, lock = this.#service.handle) {
    this.#ensureWritable(logical);
    const prior = this.#boundReceipt(expected, logical, logical);
    let bytes;
    let frozen;
    try {
      frozen = cloneJson(value);
      validator(frozen);
      bytes = canonicalJsonBytes(frozen, JSON_LIMITS);
    } catch (error) {
      throwStore('SERVICE_INVALID', logical, this.#calls.writes, false, error);
    }
    const nativeExpected = prior.native === null ? null : { facts: prior.native.facts, bytes: Buffer.from(prior.native.bytes) };
    const result = validateWriteResult(this.#calls, this.#calls.invoke(
      'publish_service_file_atomic', handle, name, bytes, nativeExpected, lock,
    ), 'publish_service_file_atomic');
    this.#consume(expected);
    return this.#makeReceipt(logical, frozen, {
      facts: this.#calls.validate(logical, () => cloneJson(result.facts)),
      bytes: Buffer.from(bytes),
    });
  }

  #remove(handle, name, expected, logical, lock = this.#service.handle, authorizationOperation = logical) {
    this.#ensureWritable(authorizationOperation);
    const prior = this.#boundReceipt(expected, logical, logical);
    if (prior.native === null) throwStore('SERVICE_STALE', logical, this.#calls.writes);
    const result = this.#calls.invoke(
      'remove_service_object_exact', handle, name,
      { facts: prior.native.facts, bytes: Buffer.from(prior.native.bytes) }, lock,
    );
    if (!exact(result, ['removed', 'writes']) || result.removed !== true || !validWrites(result.writes) || result.writes < 1) {
      throwStore('SERVICE_INVALID', logical, this.#calls.writes, true);
    }
    this.#consume(expected);
    return this.#makeReceipt(logical, null, null);
  }

  #namespaceEntries(name) {
    return this.#list(this.#namespaces[name].handle).entries;
  }

  #serviceDirectory(namespace, create = false) {
    const cached = this.#serviceDirectories.get(namespace);
    if (cached) return cached;
    const parent = this.#namespaces[namespace].handle;
    const entry = findEntry(this.#list(parent), this.#config.serviceKey);
    if (!entry && !create) return null;
    if (!entry) this.#ensureWritable(`open_${namespace}_directory`);
    const opened = validateOwnedDirectoryResult(this.#calls, this.#calls.invoke(
      'open_service_directory', parent, this.#config.serviceKey,
      this.#mode === 'read-only' ? 'read-existing' : entry ? 'write-existing' : 'create-new',
      entry?.identity ?? null, this.#service.handle,
    ), this.#config.platform);
    if (entry ? opened.writes !== 0 : opened.writes < 1) {
      let error;
      try {
        this.#calls.error('SERVICE_MANUAL_CLEANUP', `open_${namespace}_directory`, true);
      } catch (caught) {
        error = caught;
      }
      throwAfterCleanup(
        this.#calls,
        error,
        () => this.#calls.invoke('close_service_handle', opened.handle),
      );
    }
    const value = Object.freeze({ handle: opened.handle, identity: cloneJson(opened.identity) });
    this.#calls.disownHandle(opened.handle);
    this.#serviceDirectories.set(namespace, value);
    return value;
  }

  #readService(namespace, name, validator, logical) {
    const directory = this.#serviceDirectory(namespace, false);
    return directory ? this.#read(directory.handle, name, validator, logical) : this.#makeReceipt(logical, null, null);
  }

  #publishService(namespace, name, value, validator, expected, logical) {
    return this.#publish(this.#serviceDirectory(namespace, true).handle, name, value, validator, expected, logical);
  }

  #historyDirectory(scope, revision, create = false, descriptor = null) {
    const name = floorHistoryName(
      scope,
      revision,
      descriptor?.action ?? null,
      descriptor?.transactionFingerprint ?? null,
      descriptor?.serviceKey ?? null,
    );
    const cached = this.#historyDirectories.get(name);
    if (cached) return cached;
    const entry = findEntry(this.#list(this.#history.handle, this.#artifact.handle), name);
    if (!entry && !create) return null;
    if (!entry) this.#ensureWritable('open_floor_history_directory');
    const opened = validateOwnedDirectoryResult(this.#calls, this.#calls.invoke(
      'open_service_directory',
      this.#history.handle,
      name,
      entry ? (this.#mode === 'read-only' ? 'read-existing' : 'write-existing') : 'create-new',
      entry?.identity ?? null,
      this.#artifact.handle,
    ), this.#config.platform);
    if (entry ? opened.writes !== 0 : opened.writes < 1) {
      let error;
      try {
        this.#calls.error('SERVICE_MANUAL_CLEANUP', 'open_floor_history_directory', true);
      } catch (caught) {
        error = caught;
      }
      throwAfterCleanup(
        this.#calls,
        error,
        () => this.#calls.invoke('close_service_handle', opened.handle),
      );
    }
    const value = Object.freeze({
      handle: opened.handle,
      identity: cloneJson(opened.identity),
    });
    this.#calls.disownHandle(opened.handle);
    this.#historyDirectories.set(name, value);
    return value;
  }

  #releaseHistoryDirectory(directory) {
    if (!directory) return;
    for (const [name, value] of this.#historyDirectories) {
      if (value === directory) {
        this.#calls.invoke('close_service_handle', value.handle);
        this.#historyDirectories.delete(name);
        return;
      }
    }
  }

  #receiptNative(receipt, logical, operation) {
    const binding = this.#boundReceipt(receipt, logical, operation);
    if (binding.native === null) throwStore('SERVICE_STALE', operation, this.#calls.writes);
    return binding.native;
  }

  bootstrap() {
    this.#ensureWritable('bootstrap_service_store');
    const registration = buildServiceStoreRegistration({
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      roles: this.#config.roles,
      serviceRolesFingerprint: this.#rolesFingerprint,
      rootBinding: cloneJson(this.#root.rootBinding),
      historyRootIdentity: cloneJson(this.#history.identity),
      historyRootIdentityFingerprint: serviceNativeIdentityFingerprint(
        this.#history.identity,
        this.#config.platform,
        'service-control-directory',
      ),
    });
    const registrationReceipt = this.#publish(
      this.#namespaces.floor.handle,
      SERVICE_STORE_LAYOUT.registration,
      registration,
      validateServiceStoreRegistration,
      this.#makeReceipt('store-registration', null, null),
      'store-registration',
      this.#artifact.handle,
    );
    const registrationNative = this.#receiptNative(
      registrationReceipt,
      'store-registration',
      'bootstrap_service_store',
    );
    const incarnation = buildServiceStoreRegistrationIncarnation({
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      rootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
      historyRootIdentityFingerprint: registration.historyRootIdentityFingerprint,
      registrationFingerprint: registration.registrationFingerprint,
      registrationRecordSha256: canonicalJsonHash(registration),
      registrationFileFacts: cloneJson(registrationNative.facts),
    });
    this.#publish(
      this.#history.handle,
      SERVICE_STORE_LAYOUT.registrationIncarnation,
      incarnation,
      validateServiceStoreRegistrationIncarnation,
      this.#makeReceipt('registration-incarnation', null, null),
      'registration-incarnation',
      this.#artifact.handle,
    );
    for (const scope of this.#scopes) {
      const historyDirectory = this.#historyDirectory(scope, 0, true);
      const historyEntryIdentityFingerprint = serviceNativeIdentityFingerprint(
        historyDirectory.identity,
        this.#config.platform,
        'service-control-directory',
      );
      const floor = buildServiceSequenceFloor({
        scope,
        revision: 0,
        historyEntryIdentityFingerprint,
        previousHistoryStateFingerprint: null,
        highestReservedSequence: 0,
        highestReservedManifestFingerprint: null,
        committedSequence: 0,
        committedManifestFingerprint: null,
        committedPublicationFingerprint: null,
        committedTransactionId: null,
        committedTransactionNonce: null,
        committedTransactionFingerprint: null,
        activeReservation: null,
      });
      const floorReceipt = this.#publish(
        this.#namespaces.floor.handle, floorName(scope), floor, validateServiceSequenceFloor,
        this.#makeReceipt(`floor:${scope}`, null, null), `floor:${scope}`, this.#artifact.handle,
      );
      const witness = buildServiceFloorWitness({
        scope,
        platform: this.#config.platform,
        architecture: this.#config.architecture,
        rootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
        revision: 0,
        historyEntryIdentityFingerprint,
        previousHistoryStateFingerprint: null,
        state: 'stable',
        action: null,
        component: null,
        serviceKey: null,
        currentFloorFingerprint: floor.floorFingerprint,
        intendedFloorFingerprint: null,
        transactionId: null,
        transactionNonce: null,
        transactionFingerprint: null,
      });
      const witnessReceipt = this.#publish(
        this.#namespaces.floor.handle, floorWitnessName(scope), witness, validateServiceFloorWitness,
        this.#makeReceipt(`floor-witness:${scope}`, null, null), `floor-witness:${scope}`, this.#artifact.handle,
      );
      const floorNative = this.#receiptNative(floorReceipt, `floor:${scope}`, 'bootstrap_service_store');
      const witnessNative = this.#receiptNative(
        witnessReceipt,
        `floor-witness:${scope}`,
        'bootstrap_service_store',
      );
      const state = buildServiceFloorHistoryState({
        scope,
        platform: this.#config.platform,
        architecture: this.#config.architecture,
        rootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
        registrationFingerprint: registration.registrationFingerprint,
        revision: 0,
        action: null,
        component: null,
        serviceKey: null,
        transactionId: null,
        transactionNonce: null,
        transactionFingerprint: null,
        historyEntryIdentity: cloneJson(historyDirectory.identity),
        historyEntryIdentityFingerprint,
        previousHistoryStateFingerprint: null,
        intentFingerprint: null,
        floorFingerprint: floor.floorFingerprint,
        witnessFingerprint: witness.witnessFingerprint,
        floorRecordSha256: canonicalJsonHash(floor),
        witnessRecordSha256: canonicalJsonHash(witness),
        floorFileFacts: cloneJson(floorNative.facts),
        witnessFileFacts: cloneJson(witnessNative.facts),
      });
      const stateReceipt = this.#publish(
        historyDirectory.handle,
        SERVICE_STORE_LAYOUT.floorHistoryState,
        state,
        validateServiceFloorHistoryState,
        this.#makeReceipt(`floor-history-state:${scope}:0`, null, null),
        `floor-history-state:${scope}:0`,
        this.#artifact.handle,
      );
      this.#floors.set(scope, {
        floor: floorReceipt,
        witness: witnessReceipt,
        historyDirectory,
        historyState: stateReceipt,
        historyIntent: null,
      });
    }
  }

  initialize() {
    this.#ensureOpen('initialize_service_store');
    this.#validateNamespaces();
    const registration = this.#read(
      this.#namespaces.floor.handle, SERVICE_STORE_LAYOUT.registration,
      validateServiceStoreRegistration, 'store-registration',
    );
    if (!registration.present || registration.value.platform !== this.#config.platform ||
        registration.value.architecture !== this.#config.architecture ||
        registration.value.serviceRolesFingerprint !== this.#rolesFingerprint ||
        !sameJson(registration.value.roles, this.#config.roles) ||
        !sameJson(registration.value.rootBinding, this.#root.rootBinding) ||
        !sameJson(registration.value.historyRootIdentity, this.#history.identity)) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'initialize_service_store', this.#calls.writes, true);
    }
    const incarnation = this.#read(
      this.#history.handle,
      SERVICE_STORE_LAYOUT.registrationIncarnation,
      validateServiceStoreRegistrationIncarnation,
      'registration-incarnation',
    );
    const registrationNative = this.#receiptNative(
      registration,
      'store-registration',
      'initialize_service_store',
    );
    if (!incarnation.present ||
        incarnation.value.platform !== this.#config.platform ||
        incarnation.value.architecture !== this.#config.architecture ||
        incarnation.value.rootBindingFingerprint !== this.#root.rootBinding.bindingFingerprint ||
        incarnation.value.historyRootIdentityFingerprint !== registration.value.historyRootIdentityFingerprint ||
        incarnation.value.registrationFingerprint !== registration.value.registrationFingerprint ||
        incarnation.value.registrationRecordSha256 !== canonicalJsonHash(registration.value) ||
        incarnation.value.registrationFileFacts.owner !== this.#config.roles.management.value ||
        !sameJson(incarnation.value.registrationFileFacts, registrationNative.facts)) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'initialize_service_store', this.#calls.writes, true);
    }
    if (this.#registrationSnapshot) {
      const live = this.#boundReceipt(registration, 'store-registration', 'initialize_service_store').native;
      const incarnationLive = this.#boundReceipt(
        incarnation,
        'registration-incarnation',
        'initialize_service_store',
      ).native;
      if (!live || !sameJson(live.facts, this.#registrationSnapshot.facts) ||
          !live.bytes.equals(this.#registrationSnapshot.bytes) ||
          !incarnationLive ||
          !sameJson(incarnationLive.facts, this.#registrationSnapshot.incarnationFacts) ||
          !incarnationLive.bytes.equals(this.#registrationSnapshot.incarnationBytes)) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'initialize_service_store', this.#calls.writes, true);
      }
    }
    this.#registration = registration.value;
    for (const scope of this.#scopes) this.#loadFloor(scope);
    this.#tombstone = this.readTombstone();
    this.#manual = this.readManualCleanup();
    this.#artifactCleanup = this.#readArtifactCleanup();
    this.#validateServiceFiles();
    this.#journal = this.#validateServiceRecords();
    if (this.#artifactCleanup.present) {
      const record = this.#artifactCleanup.value;
      const transaction = this.#retainedTransactionByFingerprint(
        record.transactionFingerprint,
      );
      try {
        if (transaction === null) {
          throw new TypeError('missing cleanup transaction');
        }
        if (record.scope === 'scratch') {
          this.#validateCleanupRecordJournal(
            record,
            transaction,
            'validate_artifact_cleanup',
          );
          const retained = this.#assertScratchCleanupProvenance(
            record,
            'validate_artifact_cleanup',
          );
          if (transaction.phase !== 'committed') {
            this.#assertFloorAbandonEvidence(
              record.purpose,
              transaction,
              record.releaseSequence,
              record.manifestFingerprint,
              'validate_artifact_cleanup',
            );
          }
        } else {
          this.#assertArtifactCleanupTransaction(
            transaction,
            'validate_artifact_cleanup',
          );
        }
      } catch (error) {
        if (error?.name === 'ServiceStoreError' &&
            error.code === 'SERVICE_PENDING') {
          throw error;
        }
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          'validate_artifact_cleanup',
          this.#calls.writes,
          true,
        );
      }
    }
    this.#deriveRecoveryBinding();
  }

  #validateNamespaces() {
    for (const namespace of SERVICE_DIRECT) {
      for (const entry of this.#namespaceEntries(namespace)) {
        try { validateServiceKey(entry.name); } catch (error) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_namespace', this.#calls.writes, true, error);
        }
      }
    }
    for (const entry of this.#namespaceEntries('reference')) {
      if (referenceServiceKey(entry.name) === null) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_namespace', this.#calls.writes, true);
      }
    }
    const expected = new Set([
      SERVICE_STORE_LAYOUT.registration,
      SERVICE_STORE_LAYOUT.historyDirectory,
      ...this.#scopes.flatMap((scope) => [floorName(scope), floorWitnessName(scope)]),
    ]);
    const actual = this.#namespaceEntries('floor').map((entry) => entry.name);
    if (actual.length !== expected.size || actual.some((name) => !expected.has(name))) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_floor_namespace', this.#calls.writes, true);
    }
    for (const entry of this.#list(this.#history.handle, this.#artifact.handle).entries) {
      const revision = this.#scopes.find((scope) =>
        parseFloorHistoryName(scope, entry.name) !== null);
      if (entry.name === SERVICE_STORE_LAYOUT.registrationIncarnation) {
        if (entry.identity.profile !== 'service-control-file') {
          throwStore('SERVICE_MANUAL_CLEANUP', 'validate_floor_history', this.#calls.writes, true);
        }
      } else if (revision === undefined || entry.identity.profile !== 'service-control-directory') {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_floor_history', this.#calls.writes, true);
      }
    }
  }

  #validateServiceFiles() {
    const manifest = this.#serviceDirectory('manifest', false);
    if (manifest) {
      for (const entry of this.#list(manifest.handle, this.#service.handle).entries) {
        if (MANIFEST_FILE_SET.has(entry.name)) continue;
        const parsed = parseRetainedDeploymentEnvelopeName(entry.name);
        if (parsed === null) {
          throwStore(
            'SERVICE_MANUAL_CLEANUP',
            'validate_manifest_records',
            this.#calls.writes,
            true,
          );
        }
        let receipt;
        try {
          receipt = this.#read(
            manifest.handle,
            entry.name,
            validateRetainedDeploymentEnvelope,
            `retained-deployment-envelope:${parsed.purpose}`,
          );
        } catch {
          throwStore(
            'SERVICE_MANUAL_CLEANUP',
            'validate_manifest_records',
            this.#calls.writes,
            true,
          );
        }
        if (!receipt.present ||
            receipt.value.component !== this.#config.component ||
            receipt.value.serviceKey !== this.#config.serviceKey ||
            receipt.value.platform !== this.#config.platform ||
            receipt.value.architecture !== this.#config.architecture ||
            receipt.value.purpose !== parsed.purpose ||
            receipt.value.manifestFingerprint !== parsed.manifestFingerprint) {
          throwStore(
            'SERVICE_MANUAL_CLEANUP',
            'validate_manifest_records',
            this.#calls.writes,
            true,
          );
        }
      }
    }
    for (const [namespace, allowed] of [['tombstone', SINGLE_FILE_SET], ['manual', MANUAL_FILE_SET]]) {
      const directory = this.#serviceDirectory(namespace, false);
      if (directory && this.#list(directory.handle, this.#service.handle).entries.some((entry) => !allowed.has(entry.name))) {
        throwStore('SERVICE_MANUAL_CLEANUP', `validate_${namespace}_records`, this.#calls.writes, true);
      }
    }
    const transaction = this.#serviceDirectory('transaction', false);
    if (transaction && this.#list(transaction.handle, this.#service.handle).entries.some(
      (entry) => entry.name !== SERVICE_STORE_LAYOUT.journalHead && !JOURNAL_ENTRY.test(entry.name),
    )) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_transaction_records', this.#calls.writes, true);
    }
  }

  #referenceSlotMatchesProof(slot, proof, transaction = null) {
    if (slot === null || slot.serviceGeneration !== proof.serviceGeneration) return false;
    if (transaction &&
        (slot.transactionId !== transaction.transactionId ||
         slot.transactionNonce !== transaction.transactionNonce)) return false;
    const application = slot.artifacts.find(({ artifactKind }) => artifactKind === 'application');
    const shawl = slot.artifacts.find(({ artifactKind }) => artifactKind === 'shawl');
    return application?.manifestFingerprint === proof.applicationManifestFingerprint &&
      (this.#config.platform === 'win32'
        ? shawl?.manifestFingerprint === proof.shawlManifestFingerprint
        : shawl === undefined && proof.shawlManifestFingerprint === null);
  }

  #validateCommittedMetadata({
    currentManifest,
    previousManifest,
    currentResource,
    previousResource,
    references,
    journal,
    transaction,
  }) {
    if (transaction.final.disposition === 'absent') {
      const emptyReferences = references.present &&
        references.value.current === null && references.value.previous === null &&
         references.value.provisional === null &&
         references.value.serviceGeneration === transaction.serviceGeneration;
      if (currentManifest.present || previousManifest.present ||
          currentResource.present || previousResource.present ||
          !emptyReferences || !this.#tombstone.present ||
          this.#tombstone.value.serviceGeneration !== transaction.serviceGeneration ||
          this.#tombstone.value.resourceProof !== transaction.old.resourceProof ||
          this.#tombstone.value.currentManifestFingerprint !== transaction.old.manifestFingerprint ||
          !journal.entries.some((entry) =>
            entry.transactionId === this.#tombstone.value.transactionId &&
            entry.transactionFingerprint === this.#tombstone.value.transactionFingerprint)) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_committed_service_records', this.#calls.writes, true);
      }
      return;
    }
    if (!currentManifest.present || !currentResource.present || !references.present ||
        currentManifest.value.manifestFingerprint !== transaction.final.manifestFingerprint ||
        currentManifest.value.resourceProof !== transaction.final.resourceProof ||
        currentManifest.value.applicationManifestFingerprint !==
          transaction.final.applicationManifestFingerprint ||
        currentManifest.value.shawlManifestFingerprint !== transaction.final.shawlManifestFingerprint ||
        currentManifest.value.serviceGeneration !== transaction.final.serviceGeneration ||
        currentResource.value.resourceProof !== transaction.final.resourceProof ||
        currentResource.value.applicationManifestFingerprint !==
          transaction.final.applicationManifestFingerprint ||
        currentResource.value.shawlManifestFingerprint !== transaction.final.shawlManifestFingerprint ||
        currentResource.value.serviceGeneration !== transaction.final.serviceGeneration ||
        currentResource.value.operation !== transaction.operation ||
        currentResource.value.transactionId !== transaction.transactionId ||
        currentResource.value.transactionNonce !== transaction.transactionNonce ||
        references.value.serviceGeneration !== transaction.final.serviceGeneration ||
        references.value.provisional !== null ||
        !this.#referenceSlotMatchesProof(
          references.value.current,
          transaction.final,
          transaction,
        ) ||
        this.#tombstone.present) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_committed_service_records', this.#calls.writes, true);
    }
    if (transaction.old.disposition === 'absent') {
      if (previousManifest.present || previousResource.present ||
          references.value.previous !== null ||
          currentManifest.value.predecessorManifestFingerprint !== null ||
          currentResource.value.predecessorResourceProof !== null) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_committed_service_records', this.#calls.writes, true);
      }
      return;
    }
    const firstCurrentIndex = journal.entries.findIndex((entry) =>
      entry.transactionId === transaction.transactionId &&
      entry.transactionNonce === transaction.transactionNonce);
    const predecessor = journal.entries.slice(0, firstCurrentIndex).findLast((entry) =>
      entry.phase === 'committed');
    if (!predecessor || !previousManifest.present || !previousResource.present ||
        previousManifest.value.manifestFingerprint !== transaction.old.manifestFingerprint ||
        previousManifest.value.resourceProof !== transaction.old.resourceProof ||
        previousManifest.value.applicationManifestFingerprint !==
          transaction.old.applicationManifestFingerprint ||
        previousManifest.value.shawlManifestFingerprint !== transaction.old.shawlManifestFingerprint ||
        previousManifest.value.serviceGeneration !== transaction.old.serviceGeneration ||
        previousResource.value.resourceProof !== transaction.old.resourceProof ||
        previousResource.value.applicationManifestFingerprint !==
          transaction.old.applicationManifestFingerprint ||
        previousResource.value.shawlManifestFingerprint !== transaction.old.shawlManifestFingerprint ||
        previousResource.value.serviceGeneration !== transaction.old.serviceGeneration ||
        currentManifest.value.predecessorManifestFingerprint !==
          previousManifest.value.manifestFingerprint ||
        currentResource.value.predecessorResourceProof !== previousResource.value.resourceProof ||
        !this.#referenceSlotMatchesProof(
          references.value.previous,
          transaction.old,
          predecessor,
        )) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_committed_service_records', this.#calls.writes, true);
    }
  }

  #validateServiceRecords() {
    const currentManifest = this.readManifest('current');
    const previousManifest = this.readManifest('previous');
    const currentResource = this.readResourceProof('current');
    const previousResource = this.readResourceProof('previous');
    const startup = this.readStartupProof();
    const journal = this.readJournal();
    this.#references = this.readReferences();
    const latestTransaction = journal.entries.at(-1);
    const lifecyclePending = journal.pending !== null ||
      (latestTransaction !== undefined && latestTransaction.phase !== 'committed');
    if (latestTransaction === undefined &&
        (currentManifest.present || previousManifest.present ||
         currentResource.present || previousResource.present || startup.present ||
         this.#references.present || this.#tombstone.present || this.#manual.present)) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_records', this.#calls.writes, true);
    }
    for (const [manifest, resource] of [
      [currentManifest, currentResource],
      [previousManifest, previousResource],
    ]) {
      if (manifest.present && resource.present &&
          (manifest.value.configurationFingerprint !== resource.value.configurationFingerprint ||
           manifest.value.rolesFingerprint !== resource.value.rolesFingerprint ||
           (!lifecyclePending &&
            (manifest.value.resourceProof !== resource.value.resourceProof ||
             manifest.value.applicationManifestFingerprint !== resource.value.applicationManifestFingerprint ||
             manifest.value.shawlManifestFingerprint !== resource.value.shawlManifestFingerprint ||
             manifest.value.serviceGeneration !== resource.value.serviceGeneration)))) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_records', this.#calls.writes, true);
      }
    }
    if (currentManifest.present && previousManifest.present &&
        (currentManifest.value.configurationFingerprint !== previousManifest.value.configurationFingerprint ||
         currentManifest.value.rolesFingerprint !== previousManifest.value.rolesFingerprint)) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_records', this.#calls.writes, true);
    }
    if (!lifecyclePending) {
      if (currentManifest.present !== currentResource.present ||
          previousManifest.present !== previousResource.present ||
          (startup.present && !currentManifest.present)) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_records', this.#calls.writes, true);
      }
      const predecessorValid = currentManifest.present
        ? currentManifest.value.serviceGeneration === 1
          ? !previousManifest.present
          : previousManifest.present &&
            previousManifest.value.serviceGeneration === currentManifest.value.serviceGeneration - 1 &&
            currentManifest.value.predecessorManifestFingerprint === previousManifest.value.manifestFingerprint
        : !previousManifest.present;
      if (!predecessorValid) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_records', this.#calls.writes, true);
      }
      const predecessorResourceValid = currentResource.present
        ? currentResource.value.serviceGeneration === 1
          ? !previousResource.present
          : previousResource.present &&
            previousResource.value.serviceGeneration === currentResource.value.serviceGeneration - 1 &&
            currentResource.value.predecessorResourceProof === previousResource.value.resourceProof
        : !previousResource.present;
      if (!predecessorResourceValid) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_records', this.#calls.writes, true);
      }
    }
    if (!lifecyclePending && startup.present && currentResource.present &&
        (startup.value.resourceProof !== currentResource.value.resourceProof ||
         startup.value.applicationManifestFingerprint !== currentResource.value.applicationManifestFingerprint ||
         startup.value.serviceGeneration !== currentResource.value.serviceGeneration ||
         startup.value.transactionId !== latestTransaction?.transactionId)) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_service_records', this.#calls.writes, true);
    }
    if (!lifecyclePending && latestTransaction?.phase === 'committed') {
      this.#validateCommittedMetadata({
        currentManifest,
        previousManifest,
        currentResource,
        previousResource,
        references: this.#references,
        journal,
        transaction: latestTransaction,
      });
    }
    return journal;
  }

  #retainedTransactionByFingerprint(transactionFingerprint) {
    if (!isHex64(transactionFingerprint)) return null;
    return this.#journal.entries.find((entry) =>
      entry.transactionFingerprint === transactionFingerprint) ?? null;
  }

  #latestRetainedTransaction(transactionId, transactionNonce) {
    return this.#journal.entries.findLast((entry) =>
      entry.transactionId === transactionId &&
      entry.transactionNonce === transactionNonce) ?? null;
  }

  #recoveryBindingCandidate(candidate, operation, requireRetained = false) {
    if (candidate === null) return null;
    const anchoredFingerprint = candidate.transactionFingerprint ?? null;
    let transaction = anchoredFingerprint === null
      ? null
      : this.#retainedTransactionByFingerprint(anchoredFingerprint);
    if (transaction === null && anchoredFingerprint === null &&
        candidate.transactionId !== null &&
        candidate.transactionId !== undefined &&
        candidate.transactionNonce !== null &&
        candidate.transactionNonce !== undefined) {
      transaction = this.#latestRetainedTransaction(
        candidate.transactionId,
        candidate.transactionNonce,
      );
    }
    if (requireRetained && transaction === null) {
      throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
    }
    if (transaction !== null) {
      for (const key of ['component', 'serviceKey', 'transactionId', 'transactionNonce']) {
        if (candidate[key] !== null && candidate[key] !== undefined &&
            candidate[key] !== transaction[key]) {
          throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
        }
      }
      if (anchoredFingerprint !== null &&
          this.#retainedTransactionByFingerprint(anchoredFingerprint) === null) {
        throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
      }
    }
    const transactionIndex = transaction === null
      ? -1
      : this.#journal.entries.findIndex((entry) =>
        entry.transactionFingerprint === transaction.transactionFingerprint);
    return {
      component: transaction?.component ?? candidate.component ?? null,
      serviceKey: transaction?.serviceKey ?? candidate.serviceKey ?? null,
      transactionId: transaction?.transactionId ?? candidate.transactionId ?? null,
      transactionNonce: transaction?.transactionNonce ?? candidate.transactionNonce ?? null,
      transactionIdentity: transaction === null ? null : this.#transactionIdentity(transaction),
      transaction,
      transactionIndex,
      unresolvedFingerprints: transaction === null && anchoredFingerprint !== null
        ? [anchoredFingerprint]
        : [],
    };
  }

  #mergeRecoveryBinding(current, candidate, operation, requireRetained = false) {
    candidate = this.#recoveryBindingCandidate(candidate, operation, requireRetained);
    if (candidate === null) return current;
    if (current === null) return candidate;
    for (const key of ['component', 'serviceKey', 'transactionId', 'transactionNonce']) {
      if (current[key] !== null && candidate[key] !== null &&
          current[key] !== candidate[key]) {
        throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
      }
      current[key] ??= candidate[key];
    }
    if (current.transactionIdentity !== null &&
        candidate.transactionIdentity !== null &&
        current.transactionIdentity !== candidate.transactionIdentity) {
      throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
    }
    current.transactionIdentity ??= candidate.transactionIdentity;
    current.unresolvedFingerprints = [
      ...new Set([
        ...current.unresolvedFingerprints,
        ...candidate.unresolvedFingerprints,
      ]),
    ];
    if (candidate.transactionIndex > current.transactionIndex) {
      current.transaction = candidate.transaction;
      current.transactionIndex = candidate.transactionIndex;
    }
    return current;
  }

  #finalizeRecoveryBinding(binding, operation) {
    if (binding === null) return null;
    if (binding.transactionIdentity !== null &&
        binding.unresolvedFingerprints.length !== 0) {
      throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
    }
    if (binding.transactionIdentity === null &&
        binding.unresolvedFingerprints.length !== 1) {
      throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
    }
    return binding;
  }

  #deriveRecoveryBinding() {
    let global = null;
    for (const pair of this.#floors.values()) {
      if (pair.historyPhase !== 'stable') {
        const source = pair.historyIntent?.value ?? pair.historyDescriptor;
        global = this.#mergeRecoveryBinding(global, {
          component: source.component ??
            (source.serviceKey === 'bot' ? 'bot' : 'daemon'),
          serviceKey: source.serviceKey,
          transactionId: source.transactionId ?? null,
          transactionNonce: source.transactionNonce ?? null,
          transactionFingerprint: source.transactionFingerprint,
        }, 'derive_recovery_binding');
      }
      if (pair.floor.value.activeReservation !== null) {
        const reservation = pair.floor.value.activeReservation;
        global = this.#mergeRecoveryBinding(global, {
          component: reservation.component,
          serviceKey: reservation.serviceKey,
          transactionId: reservation.transactionId,
          transactionNonce: reservation.transactionNonce,
          transactionFingerprint: reservation.transactionFingerprint,
        }, 'derive_recovery_binding');
      }
    }
    this.#globalRecoveryBinding = global;
    if (global && global.serviceKey !== this.#config.serviceKey) {
      this.#recoveryBinding = null;
      return;
    }
    let local = global === null ? null : { ...global };
    const latest = this.#journal.entries.at(-1);
    if (latest && (global !== null || latest.phase !== 'committed' ||
        this.#journal.pending !== null)) {
      local = this.#mergeRecoveryBinding(local, {
        component: latest.component,
        serviceKey: latest.serviceKey,
        transactionId: latest.transactionId,
        transactionNonce: latest.transactionNonce,
        transactionFingerprint: latest.transactionFingerprint,
      }, 'derive_recovery_binding');
    }
    if (this.#references.present && this.#references.value.provisional !== null) {
      const provisional = this.#references.value.provisional;
      local = this.#mergeRecoveryBinding(local, {
        component: this.#config.component,
        serviceKey: this.#config.serviceKey,
        transactionId: provisional.transactionId,
        transactionNonce: provisional.transactionNonce,
        transactionFingerprint: null,
      }, 'derive_recovery_binding', true);
    }
    if (this.#manual.present) {
      local = this.#mergeRecoveryBinding(local, {
        component: this.#config.component,
        serviceKey: this.#config.serviceKey,
        transactionId: this.#manual.value.transactionId,
        transactionNonce: null,
        transactionFingerprint: this.#manual.value.journalFingerprint,
      }, 'derive_recovery_binding', true);
    }
    if (this.#tombstone.present) {
      local = this.#mergeRecoveryBinding(local, {
        component: this.#config.component,
        serviceKey: this.#config.serviceKey,
        transactionId: this.#tombstone.value.transactionId,
        transactionNonce: null,
        transactionFingerprint: this.#tombstone.value.transactionFingerprint,
      }, 'derive_recovery_binding', true);
    }
    this.#recoveryBinding = this.#finalizeRecoveryBinding(
      local,
      'derive_recovery_binding',
    );
  }

  assertRecoveryAdmission() {
    if (this.#mode !== 'recovery') return;
    if (this.#globalRecoveryBinding &&
        this.#globalRecoveryBinding.serviceKey !== this.#config.serviceKey) {
      throwStore('SERVICE_PENDING', 'open_service_store', this.#calls.writes);
    }
    if (this.#recoveryBinding === null && !this.#manual.present && !this.#tombstone.present) {
      throwStore('SERVICE_NOT_PENDING', 'open_service_store', this.#calls.writes);
    }
  }

  #authorizeRecoveryTransaction(transaction, operation) {
    if (this.#mode !== 'recovery') return;
    const binding = this.#recoveryBinding;
    if (!binding || binding.component !== transaction.component ||
        binding.serviceKey !== transaction.serviceKey ||
        (binding.transactionId !== null && binding.transactionId !== transaction.transactionId) ||
        (binding.transactionNonce !== null &&
         binding.transactionNonce !== transaction.transactionNonce)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const transactionIdentity = this.#transactionIdentity(transaction);
    const floorOperation = this.#floorRecoveryOperation(operation);
    if (binding.transactionIdentity !== null &&
        binding.transactionIdentity !== transactionIdentity) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (binding.transactionIdentity === null) {
      if (floorOperation === null ||
          !this.#isExactFloorReplay(floorOperation, transaction)) {
        throwStore('SERVICE_PENDING', operation, this.#calls.writes);
      }
      return;
    }
    if (floorOperation !== null &&
        this.#retainedTransactionByFingerprint(transaction.transactionFingerprint) === null) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    binding.transactionId = transaction.transactionId;
    binding.transactionNonce = transaction.transactionNonce;
    binding.transaction ??= transaction;
  }

  #floorRecoveryOperation(operation) {
    const applicationScope = `application:${this.#config.platform}:${this.#config.architecture}`;
    return {
      reserve_application_sequence: { scope: applicationScope, action: 'reserve' },
      commit_application_sequence: { scope: applicationScope, action: 'commit' },
      abandon_application_sequence: { scope: applicationScope, action: 'abandon' },
      reserve_shawl_sequence: { scope: 'shawl:win32:x64', action: 'reserve' },
      commit_shawl_sequence: { scope: 'shawl:win32:x64', action: 'commit' },
      abandon_shawl_sequence: { scope: 'shawl:win32:x64', action: 'abandon' },
    }[operation] ?? null;
  }

  #isExactFloorReplay({ scope, action }, transaction) {
    const pair = this.#floors.get(scope);
    if (!pair) return false;
    if (pair.historyPhase !== 'stable') {
      const pending = pair.historyIntent?.value ?? pair.historyDescriptor;
      return pending?.action === action &&
        pending.serviceKey === transaction.serviceKey &&
        pending.transactionFingerprint === transaction.transactionFingerprint;
    }
    const reservation = pair.floor.value.activeReservation;
    return action === 'reserve' && reservation !== null &&
      reservation.serviceKey === transaction.serviceKey &&
      reservation.transactionFingerprint === transaction.transactionFingerprint;
  }

  #predecessorTransaction(transaction) {
    const transactionIdentity = this.#transactionIdentity(transaction);
    const first = this.#journal.entries.findIndex((entry) =>
      this.#transactionIdentity(entry) === transactionIdentity);
    return first <= 0
      ? null
      : this.#journal.entries.slice(0, first).findLast((entry) =>
        entry.phase === 'committed') ?? null;
  }

  #referenceSlotMatchesCandidate(slot, transaction) {
    if (slot === null || transaction.candidate.disposition !== 'release' ||
        slot.serviceGeneration !== transaction.serviceGeneration ||
        slot.transactionId !== transaction.transactionId ||
        slot.transactionNonce !== transaction.transactionNonce) {
      return false;
    }
    const application = slot.artifacts.find(({ artifactKind }) =>
      artifactKind === 'application');
    const shawl = slot.artifacts.find(({ artifactKind }) =>
      artifactKind === 'shawl');
    return application?.manifestFingerprint ===
        transaction.candidate.applicationManifestFingerprint &&
      application?.treeFingerprint === transaction.candidate.releaseTreeFingerprint &&
      (this.#config.platform === 'win32'
        ? shawl?.manifestFingerprint === transaction.candidate.shawlManifestFingerprint
        : shawl === undefined && transaction.candidate.shawlManifestFingerprint === null);
  }

  #tombstoneMatchesTransaction(transaction) {
    if (!this.#tombstone.present) return false;
    const tombstone = this.#tombstone.value;
    const record = this.#retainedTransactionByFingerprint(
      tombstone.transactionFingerprint,
    );
    return record !== null &&
      this.#transactionIdentity(record) === this.#transactionIdentity(transaction) &&
      tombstone.transactionId === transaction.transactionId &&
      tombstone.serviceGeneration === transaction.serviceGeneration &&
      tombstone.resourceProof === transaction.old.resourceProof &&
      tombstone.currentManifestFingerprint === transaction.old.manifestFingerprint;
  }

  #olderPreviousRemovalAllowed(operation, valueFingerprint, slot, transaction) {
    if (slot !== 'previous' || transaction.old.disposition !== 'stable') return false;
    if (!['update', 'rollback'].includes(transaction.operation) &&
        !(transaction.operation === 'uninstall' &&
          this.#tombstoneMatchesTransaction(transaction))) return false;
    const predecessor = this.#predecessorTransaction(transaction);
    if (predecessor === null || predecessor.phase !== 'committed' ||
        predecessor.old.disposition !== 'stable' ||
        transaction.old.oldFingerprint !== predecessor.final.finalFingerprint) {
      return false;
    }
    const predecessorOfPredecessor = this.#predecessorTransaction(predecessor);
    if (predecessorOfPredecessor === null ||
        predecessorOfPredecessor.phase !== 'committed') {
      return false;
    }
    const references = this.readReferences();
    if (!references.present ||
        references.value.serviceGeneration !== transaction.old.serviceGeneration ||
        references.value.current === null ||
        !this.#referenceSlotMatchesProof(
          references.value.current,
          transaction.old,
          predecessor,
        ) ||
        !this.#referenceSlotMatchesCandidate(
          references.value.current,
          predecessor,
        ) ||
        !this.#referenceSlotMatchesProof(
          references.value.previous,
          predecessor.old,
          predecessorOfPredecessor,
        ) ||
        !this.#referenceSlotMatchesCandidate(
          references.value.previous,
          predecessorOfPredecessor,
        )) {
      return false;
    }
    return operation === 'remove_service_manifest'
      ? valueFingerprint === predecessor.old.manifestFingerprint
      : valueFingerprint === predecessor.old.resourceProof;
  }

  #authorizeRecoveryReferences(value, previous, transaction) {
    const predecessor = this.#predecessorTransaction(transaction);
    const oldCurrent = previous?.current ?? null;
    const oldState = transaction.old.disposition === 'stable' &&
      predecessor !== null &&
      previous !== null &&
      previous.serviceGeneration === transaction.old.serviceGeneration &&
      this.#referenceSlotMatchesProof(oldCurrent, transaction.old, predecessor);
    const absentState = transaction.old.disposition === 'absent' &&
      (previous === null ||
       (previous.serviceGeneration === 0 && previous.current === null &&
        previous.previous === null &&
        (previous.provisional === null ||
         this.#referenceSlotMatchesCandidate(previous.provisional, transaction))));
    if (!oldState && !absentState) {
      throwStore('SERVICE_PENDING', 'publish_references', this.#calls.writes);
    }
    if (transaction.operation === 'uninstall') {
      if (!this.#tombstoneMatchesTransaction(transaction) ||
          !oldState || value.serviceGeneration !== transaction.serviceGeneration ||
          value.current !== null || value.previous !== null ||
          value.provisional !== null) {
        throwStore('SERVICE_PENDING', 'publish_references', this.#calls.writes);
      }
      return;
    }
    if (value.serviceGeneration === transaction.old.serviceGeneration) {
      if (!sameJson(value.current, oldCurrent) ||
          !sameJson(value.previous, previous?.previous ?? null) ||
          (value.provisional !== null &&
           !this.#referenceSlotMatchesCandidate(value.provisional, transaction))) {
        throwStore('SERVICE_PENDING', 'publish_references', this.#calls.writes);
      }
      return;
    }
    if (value.serviceGeneration !== transaction.serviceGeneration ||
        !this.#referenceSlotMatchesCandidate(value.current, transaction) ||
        !sameJson(value.previous, oldCurrent) ||
        value.provisional !== null) {
      throwStore('SERVICE_PENDING', 'publish_references', this.#calls.writes);
    }
  }

  #authorizeRecoveryRemoval(operation, value, slot, transaction) {
    if (value === null) {
      throwStore('SERVICE_STALE', operation, this.#calls.writes);
    }
    if (operation === 'remove_startup_proof') {
      const activeStartup = value.transactionId === transaction.transactionId &&
        value.serviceGeneration === transaction.serviceGeneration &&
        value.resourceProof === transaction.final.resourceProof &&
        value.applicationManifestFingerprint ===
          transaction.final.applicationManifestFingerprint;
      const predecessor = this.#predecessorTransaction(transaction);
      const oldStartup = transaction.old.disposition === 'stable' &&
        predecessor !== null &&
        value.transactionId === predecessor.transactionId &&
        value.serviceGeneration === transaction.old.serviceGeneration &&
        value.resourceProof === transaction.old.resourceProof &&
        value.applicationManifestFingerprint ===
          transaction.old.applicationManifestFingerprint;
      const oldStartupAllowed = oldStartup &&
        (transaction.operation !== 'uninstall' ||
         this.#tombstoneMatchesTransaction(transaction));
      if (!activeStartup && !oldStartupAllowed) {
        throwStore('SERVICE_PENDING', operation, this.#calls.writes);
      }
      return;
    }
    const oldFingerprint = operation === 'remove_service_manifest'
      ? transaction.old.manifestFingerprint
      : transaction.old.resourceProof;
    const finalFingerprint = operation === 'remove_service_manifest'
      ? transaction.final.manifestFingerprint
      : transaction.final.resourceProof;
    const valueFingerprint = operation === 'remove_service_manifest'
      ? value.manifestFingerprint
      : value.resourceProof;
    const exactOld = oldFingerprint !== null && valueFingerprint === oldFingerprint;
    const exactFinal = finalFingerprint !== null && valueFingerprint === finalFingerprint;
    const retainedSlot = slot === 'current' ? 'previous' : 'current';
    const retainedManifest = exactOld
      ? this.readManifest(retainedSlot)
      : null;
    const retainedResource = exactOld
      ? this.readResourceProof(retainedSlot)
      : null;
    const stagedOld = retainedManifest?.present === true &&
      retainedResource?.present === true &&
      retainedManifest.value.manifestFingerprint === transaction.old.manifestFingerprint &&
      retainedResource.value.resourceProof === transaction.old.resourceProof;
    const oldRemovalAllowed = exactOld &&
      ((transaction.operation === 'uninstall' && slot === 'current' &&
        this.#tombstoneMatchesTransaction(transaction)) || stagedOld);
    const olderPreviousRemovalAllowed = this.#olderPreviousRemovalAllowed(
      operation,
      valueFingerprint,
      slot,
      transaction,
    );
    if (!(exactFinal && slot === 'current') &&
        !oldRemovalAllowed && !olderPreviousRemovalAllowed) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
  }

  #authorizeRecoveryRecord(operation, value = null, context = undefined) {
    if (this.#mode !== 'recovery') return;
    const binding = this.#recoveryBinding;
    const transaction = binding?.transaction;
    if (!binding || !transaction ||
        this.#retainedTransactionByFingerprint(transaction.transactionFingerprint) === null) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (this.#tombstone.present &&
        (transaction.operation !== 'uninstall' ||
         ['publish_service_manifest', 'publish_service_resource_proof', 'publish_startup_proof']
           .includes(operation))) {
      throwStore('SERVICE_TOMBSTONED', operation, this.#calls.writes);
    }
    if (operation === 'publish_service_manifest') {
      const exactOld = value.manifestFingerprint === transaction.old.manifestFingerprint;
      const exactFinal = value.manifestFingerprint === transaction.final.manifestFingerprint;
      if ((!exactOld && !exactFinal) || (exactFinal && context?.slot !== 'current') ||
          transaction.operation === 'uninstall') {
        throwStore('SERVICE_PENDING', operation, this.#calls.writes);
      }
    }
    if (operation === 'publish_service_resource_proof') {
      const exactOld = value.resourceProof === transaction.old.resourceProof;
      const exactFinal = value.resourceProof === transaction.final.resourceProof;
      if ((!exactOld && !exactFinal) || (exactFinal && context?.slot !== 'current') ||
          transaction.operation === 'uninstall') {
        throwStore('SERVICE_PENDING', operation, this.#calls.writes);
      }
    }
    if (operation === 'publish_startup_proof' &&
        (transaction.operation === 'uninstall' ||
         value.transactionId !== transaction.transactionId ||
         value.serviceGeneration !== transaction.serviceGeneration ||
         value.applicationManifestFingerprint !==
           transaction.final.applicationManifestFingerprint ||
         value.resourceProof !== transaction.final.resourceProof)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (['remove_service_manifest', 'remove_service_resource_proof', 'remove_startup_proof']
      .includes(operation)) {
      this.#authorizeRecoveryRemoval(
        operation,
        value,
        context?.slot ?? null,
        transaction,
      );
    }
    if (operation === 'publish_tombstone' &&
        transaction.operation !== 'uninstall') {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (operation === 'publish_references') {
      this.#authorizeRecoveryReferences(value, context?.previous ?? null, transaction);
    }
  }

  blocked() {
    const latest = this.#journal?.entries.at(-1);
    return this.#tombstone.present || this.#manual.present ||
      (this.#journal !== undefined && this.#journal.pending !== null) ||
      (latest !== undefined && latest.phase !== 'committed') ||
      (this.#references?.present === true && this.#references.value.provisional !== null) ||
      [...this.#floors.values()].some(({ floor, historyPhase }) =>
        historyPhase !== 'stable' || floor.value.activeReservation !== null);
  }

  blockCode() {
    if (this.#manual.present) return 'SERVICE_MANUAL_CLEANUP';
    if (this.#tombstone.present) return 'SERVICE_TOMBSTONED';
    return 'SERVICE_PENDING';
  }

  close() {
    if (this.#closed) return;
    if (this.#artifactCollectorOwner !== null) {
      if (this.#artifactCollectionActive) {
        throwStore(
          'SERVICE_PENDING',
          'close_service_store',
          this.#calls.writes,
        );
      }
      this.#retryArtifactCollectorCleanup('close_service_store');
    }
    if (this.#artifactAccesses !== 0) {
      throwStore('SERVICE_PENDING', 'close_service_store', this.#calls.writes);
    }
    const handles = [
      this.#root.handle,
      this.#artifact.handle,
      this.#shared.handle,
      this.#service.handle,
      ...OPEN_NAMESPACES.map((name) => this.#namespaces[name].handle),
      this.#history.handle,
      ...[...this.#historyDirectories.values()].map((directory) => directory.handle),
      ...[...this.#serviceDirectories.values()].map((directory) => directory.handle),
    ];
    closeReverse(this.#calls, handles);
    this.#closed = true;
  }

  readManifest(slot) {
    if (!Object.hasOwn(SERVICE_STORE_LAYOUT.manifestFiles, slot)) throwStore('SERVICE_INVALID', 'read_service_manifest', this.#calls.writes);
    const receipt = this.#readService('manifest', SERVICE_STORE_LAYOUT.manifestFiles[slot], validateServiceManifest, `manifest:${slot}`);
    if (receipt.present) {
      this.#scope(receipt.value, 'read_service_manifest');
      this.#scopeRoles(receipt.value, 'read_service_manifest');
    }
    return receipt;
  }

  publishManifest(slot, value, expected) {
    if (!Object.hasOwn(SERVICE_STORE_LAYOUT.manifestFiles, slot)) throwStore('SERVICE_INVALID', 'publish_service_manifest', this.#calls.writes);
    value = this.#snapshot(value, validateServiceManifest, 'publish_service_manifest');
    this.#scope(value, 'publish_service_manifest');
    this.#scopeRoles(value, 'publish_service_manifest');
    this.#authorizeRecoveryRecord('publish_service_manifest', value, { slot });
    const sibling = this.readManifest(slot === 'current' ? 'previous' : 'current');
    if (sibling.present && sibling.value.configurationFingerprint !== value.configurationFingerprint) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'publish_service_manifest', this.#calls.writes);
    }
    const resource = this.readResourceProof(slot);
    if (!this.#metadataPairMutation && resource.present &&
        (resource.value.resourceProof !== value.resourceProof ||
         resource.value.configurationFingerprint !== value.configurationFingerprint ||
         resource.value.rolesFingerprint !== value.rolesFingerprint ||
         resource.value.applicationManifestFingerprint !== value.applicationManifestFingerprint ||
         resource.value.shawlManifestFingerprint !== value.shawlManifestFingerprint ||
         resource.value.serviceGeneration !== value.serviceGeneration)) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'publish_service_manifest', this.#calls.writes);
    }
    return this.#publishService('manifest', SERVICE_STORE_LAYOUT.manifestFiles[slot], value, validateServiceManifest, expected, `manifest:${slot}`);
  }

  removeManifest(slot, expected) {
    if (!Object.hasOwn(SERVICE_STORE_LAYOUT.manifestFiles, slot)) throwStore('SERVICE_INVALID', 'remove_service_manifest', this.#calls.writes);
    const directory = this.#serviceDirectory('manifest', false);
    if (!directory) throwStore('SERVICE_STALE', 'remove_service_manifest', this.#calls.writes);
    this.#boundReceipt(expected, `manifest:${slot}`, 'remove_service_manifest');
    this.#authorizeRecoveryRecord(
      'remove_service_manifest',
      expected.value,
      { slot },
    );
    return this.#remove(directory.handle, SERVICE_STORE_LAYOUT.manifestFiles[slot], expected, `manifest:${slot}`);
  }

  readResourceProof(slot) {
    if (!Object.hasOwn(SERVICE_STORE_LAYOUT.resourceFiles, slot)) throwStore('SERVICE_INVALID', 'read_service_resource_proof', this.#calls.writes);
    const receipt = this.#readService('manifest', SERVICE_STORE_LAYOUT.resourceFiles[slot], validateServiceResourceProof, `resource:${slot}`);
    if (receipt.present) {
      this.#scope(receipt.value, 'read_service_resource_proof');
      if (receipt.value.rolesFingerprint !== this.#rolesFingerprint) {
        throwStore('SERVICE_SCOPE_MISMATCH', 'read_service_resource_proof', this.#calls.writes);
      }
    }
    return receipt;
  }

  publishResourceProof(slot, value, expected) {
    if (!Object.hasOwn(SERVICE_STORE_LAYOUT.resourceFiles, slot)) throwStore('SERVICE_INVALID', 'publish_service_resource_proof', this.#calls.writes);
    value = this.#snapshot(value, validateServiceResourceProof, 'publish_service_resource_proof');
    this.#scope(value, 'publish_service_resource_proof');
    this.#authorizeRecoveryRecord('publish_service_resource_proof', value, { slot });
    if (value.rolesFingerprint !== this.#rolesFingerprint) throwStore('SERVICE_SCOPE_MISMATCH', 'publish_service_resource_proof', this.#calls.writes);
    const manifest = this.readManifest(slot);
    if (!this.#metadataPairMutation && manifest.present && (manifest.value.resourceProof !== value.resourceProof ||
        manifest.value.configurationFingerprint !== value.configurationFingerprint ||
        manifest.value.rolesFingerprint !== value.rolesFingerprint ||
        manifest.value.applicationManifestFingerprint !== value.applicationManifestFingerprint ||
        manifest.value.shawlManifestFingerprint !== value.shawlManifestFingerprint ||
        manifest.value.serviceGeneration !== value.serviceGeneration)) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'publish_service_resource_proof', this.#calls.writes);
    }
    return this.#publishService('manifest', SERVICE_STORE_LAYOUT.resourceFiles[slot], value, validateServiceResourceProof, expected, `resource:${slot}`);
  }

  removeResourceProof(slot, expected) {
    if (!Object.hasOwn(SERVICE_STORE_LAYOUT.resourceFiles, slot)) throwStore('SERVICE_INVALID', 'remove_service_resource_proof', this.#calls.writes);
    const directory = this.#serviceDirectory('manifest', false);
    if (!directory) throwStore('SERVICE_STALE', 'remove_service_resource_proof', this.#calls.writes);
    this.#boundReceipt(expected, `resource:${slot}`, 'remove_service_resource_proof');
    this.#authorizeRecoveryRecord(
      'remove_service_resource_proof',
      expected.value,
      { slot },
    );
    return this.#remove(directory.handle, SERVICE_STORE_LAYOUT.resourceFiles[slot], expected, `resource:${slot}`);
  }

  readStartupProof() {
    const receipt = this.#readService('manifest', SERVICE_STORE_LAYOUT.startup, validateServiceStartupProof, 'startup-proof');
    if (receipt.present) this.#scope(receipt.value, 'read_startup_proof');
    return receipt;
  }

  publishStartupProof(value, expected) {
    value = this.#snapshot(value, validateServiceStartupProof, 'publish_startup_proof');
    this.#scope(value, 'publish_startup_proof');
    this.#authorizeRecoveryRecord('publish_startup_proof', value);
    const resource = this.readResourceProof('current');
    const provisional = this.#provisionalMetadata;
    const provisionalMatch = provisional !== null &&
      provisional.transactionId === value.transactionId &&
      provisional.resource.resourceProof === value.resourceProof &&
      provisional.resource.applicationManifestFingerprint === value.applicationManifestFingerprint &&
      provisional.resource.serviceGeneration === value.serviceGeneration;
    if (resource.present && !provisionalMatch && (resource.value.resourceProof !== value.resourceProof ||
        resource.value.applicationManifestFingerprint !== value.applicationManifestFingerprint ||
        resource.value.serviceGeneration !== value.serviceGeneration)) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'publish_startup_proof', this.#calls.writes);
    }
    return this.#publishService('manifest', SERVICE_STORE_LAYOUT.startup, value, validateServiceStartupProof, expected, 'startup-proof');
  }

  removeStartupProof(expected) {
    const directory = this.#serviceDirectory('manifest', false);
    if (!directory) throwStore('SERVICE_STALE', 'remove_startup_proof', this.#calls.writes);
    this.#boundReceipt(expected, 'startup-proof', 'remove_startup_proof');
    this.#authorizeRecoveryRecord(
      'remove_startup_proof',
      expected.value,
    );
    return this.#remove(directory.handle, SERVICE_STORE_LAYOUT.startup, expected, 'startup-proof');
  }

  readTombstone() {
    const receipt = this.#readService('tombstone', SERVICE_STORE_LAYOUT.tombstone, validateServiceTombstone, 'tombstone');
    if (receipt.present) this.#scope(receipt.value, 'read_tombstone');
    return receipt;
  }

  publishTombstone(value, expected) {
    value = this.#snapshot(value, validateServiceTombstone, 'publish_tombstone');
    this.#scope(value, 'publish_tombstone');
    this.#authorizeRecoveryRecord('publish_tombstone', value);
    const journal = this.readJournal();
    const transaction = journal.entries.find((entry) =>
      entry.transactionId === value.transactionId &&
      entry.transactionFingerprint === value.transactionFingerprint);
    if (!transaction || transaction.operation !== 'uninstall' ||
        (this.#mode === 'recovery' &&
         this.#transactionIdentity(transaction) !==
           this.#recoveryBinding.transactionIdentity) ||
        transaction.phase !== 'tombstoned' ||
        transaction.serviceGeneration !== value.serviceGeneration ||
        transaction.old.resourceProof !== value.resourceProof ||
        transaction.old.manifestFingerprint !== value.currentManifestFingerprint) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'publish_tombstone', this.#calls.writes);
    }
    this.#tombstone = this.#publishService('tombstone', SERVICE_STORE_LAYOUT.tombstone, value, validateServiceTombstone, expected, 'tombstone');
    return this.#tombstone;
  }

  readManualCleanup() {
    const receipt = this.#readService('manual', SERVICE_STORE_LAYOUT.manualCleanup, validateServiceManualCleanup, 'manual-cleanup');
    if (receipt.present) this.#scope(receipt.value, 'read_manual_cleanup');
    return receipt;
  }

  #validateArtifactCleanupHost(record, serviceKey, operation) {
    const rootOwner = this.#root.rootBinding.identity.owner;
    const management = this.#config.roles.management.value;
    const targetOwners = record.scope === 'scratch'
      ? [
        record.stagingRootIdentity.owner,
        record.scratchIdentity.owner,
        record.markerFacts.owner,
        record.assetFacts?.owner ?? management,
        record.candidateIdentity?.owner ?? management,
      ]
      : [record.artifactRootIdentity.owner];
    if (record.serviceKey !== serviceKey ||
        record.platform !== this.#config.platform ||
        record.architecture !== this.#config.architecture ||
        record.rolesFingerprint !== this.#rolesFingerprint ||
        !sameJson(record.roles, this.#config.roles) ||
        targetOwners.some((owner) => owner !== rootOwner) ||
        record.artifactLockIdentity.owner !==
          this.#artifact.identity.owner ||
        !sameJson(record.artifactLockIdentity, this.#artifact.identity) ||
        record.controlRootBindingFingerprint !==
          this.#root.rootBinding.bindingFingerprint) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    return record;
  }


  #cleanupFloorScope(purpose) {
    return purpose === 'application'
      ? `application:${this.#config.platform}:${this.#config.architecture}`
      : 'shawl:win32:x64';
  }

  #validateCleanupRecordJournal(cleanup, transaction, operation) {
    if (!transaction ||
        transaction.transactionId !== cleanup.transactionId ||
        transaction.transactionNonce !== cleanup.transactionNonce ||
        transaction.serviceGeneration !== cleanup.serviceGeneration ||
        this.#transactionIdentity(transaction) !==
          cleanup.transactionIdentity) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
  }

  #assertFloorAbandonEvidence(
    purpose,
    transaction,
    releaseSequence,
    manifestFingerprint,
    operation,
  ) {
    const scope = this.#cleanupFloorScope(purpose);
    const pair = this.#floors.get(scope);
    if (!pair) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    if (pair.historyPhase !== 'stable' ||
        pair.floor.value.activeReservation !== null) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const listing = this.#list(this.#history.handle, this.#artifact.handle);
    let admitted = false;
    for (const entry of listing.entries) {
      const descriptor = parseFloorHistoryName(scope, entry.name);
      if (descriptor === null || descriptor.action !== 'abandon' ||
          descriptor.transactionFingerprint !==
            transaction.transactionFingerprint ||
          descriptor.serviceKey !== transaction.serviceKey) {
        continue;
      }
      const directory = this.#historyDirectory(
        scope,
        descriptor.revision,
        false,
        descriptor,
      );
      if (!directory) {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      const intent = this.#read(
        directory.handle,
        SERVICE_STORE_LAYOUT.floorHistoryIntent,
        validateServiceFloorHistoryIntent,
        `floor-history-intent:${scope}:${descriptor.revision}`,
      );
      const state = this.#read(
        directory.handle,
        SERVICE_STORE_LAYOUT.floorHistoryState,
        validateServiceFloorHistoryState,
        `floor-history-state:${scope}:${descriptor.revision}`,
      );
      if (!intent.present || !state.present ||
          intent.value.action !== 'abandon' ||
          intent.value.transactionFingerprint !==
            transaction.transactionFingerprint ||
          intent.value.serviceKey !== transaction.serviceKey ||
          state.value.action !== 'abandon' ||
          state.value.transactionFingerprint !==
            transaction.transactionFingerprint ||
          state.value.serviceKey !== transaction.serviceKey) {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      const intended = intent.value.intendedFloor;
      if (intended.activeReservation === null &&
          intended.highestReservedSequence === releaseSequence &&
          intended.highestReservedManifestFingerprint ===
            manifestFingerprint) {
        admitted = true;
      }
    }
    if (!admitted) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
  }

  #assertScratchCleanupTransaction(
    transaction,
    purpose,
    manifest,
    operation,
  ) {
    transaction = this.#validateTransaction(transaction, operation);
    this.#scope(transaction, operation);
    if (!['install', 'update'].includes(transaction.operation)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const retained = this.#retainedTransactionByFingerprint(
      transaction.transactionFingerprint,
    );
    if (retained === null || !sameJson(retained, transaction)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (retained.phase === 'committed') return transaction;
    const latest = this.#journal.entries.at(-1);
    if (latest === undefined || latest.phase === 'committed' ||
        this.#journal.pending !== null ||
        this.#transactionIdentity(latest) !==
          this.#transactionIdentity(transaction)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    this.#assertFloorAbandonEvidence(
      purpose,
      transaction,
      manifest.releaseSequence,
      manifest.manifestFingerprint,
      operation,
    );
    return transaction;
  }

  #assertScratchCleanupProvenance(record, operation) {
    const retained = this.#readVerifiedRetainedDeploymentForArtifact(
      record.purpose,
      record.manifestFingerprint,
      operation,
    );
    const manifest = retained.verified.manifest;
    const size = record.purpose === 'application'
      ? manifest.archive.byteLength
      : manifest.executable.byteLength;
    const digest = record.purpose === 'application'
      ? manifest.archive.sha256
      : manifest.executable.sha256;
    if (retained.recordSha256 !== record.retainedEnvelopeRecordSha256 ||
        retained.verified.signingKeyId !== record.signingKeyId ||
        retained.verified.signingKeyFingerprint !==
          record.signingKeyFingerprint ||
        manifest.target.platform !== this.#config.platform ||
        manifest.target.architecture !== this.#config.architecture ||
        manifest.releaseSequence !== record.releaseSequence ||
        record.assetSha256 !== digest || record.assetSize !== size) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    return retained;
  }
  #readArtifactCleanup() {
    try {
      const receipt = this.#readService(
        'manual',
        SERVICE_STORE_LAYOUT.artifactCleanup,
        validateServiceArtifactCleanup,
        'artifact-cleanup',
      );
      if (receipt.present) {
        this.#validateArtifactCleanupHost(
          receipt.value,
          this.#config.serviceKey,
          'read_artifact_cleanup',
        );
      }
      return receipt;
    } catch (error) {
      this.#throwArtifactCleanupFailure(
        error,
        'read_artifact_cleanup',
      );
    }
  }

  publishManualCleanup(value, expected) {
    value = this.#snapshot(value, validateServiceManualCleanup, 'publish_manual_cleanup');
    this.#scope(value, 'publish_manual_cleanup');
    this.#authorizeRecoveryRecord('publish_manual_cleanup', value);
    const journal = this.readJournal();
    const transaction = journal.entries.find((entry) =>
      entry.transactionId === value.transactionId &&
      entry.transactionFingerprint === value.journalFingerprint);
    if (!transaction ||
        (this.#mode === 'recovery' &&
         this.#transactionIdentity(transaction) !==
           this.#recoveryBinding.transactionIdentity) ||
        transaction.phase !== value.phase ||
        transaction.serviceGeneration !== value.serviceGeneration ||
        transaction.old.oldFingerprint !== value.expectedOldProofFingerprint ||
        (value.expectedDisposition === 'absent') !==
          (transaction.old.disposition === 'absent')) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'publish_manual_cleanup', this.#calls.writes);
    }
    this.#manual = this.#publishService('manual', SERVICE_STORE_LAYOUT.manualCleanup, value, validateServiceManualCleanup, expected, 'manual-cleanup');
    return this.#manual;
  }

  clearManualCleanup(expected, oldProof) {
    this.#ensureWritable('clear_manual_cleanup');
    if (this.#mode !== 'recovery') throwStore('SERVICE_ACCESS_DENIED', 'clear_manual_cleanup', this.#calls.writes);
    const bound = this.#boundReceipt(expected, 'manual-cleanup', 'clear_manual_cleanup');
    if (bound.native === null) throwStore('SERVICE_STALE', 'clear_manual_cleanup', this.#calls.writes);
    oldProof = this.#snapshot(
      oldProof,
      (value) => validateServiceOldProof(value, this.#config.platform),
      'clear_manual_cleanup',
    );
    const manual = expected.value;
    const transaction = this.#retainedTransactionByFingerprint(
      manual.journalFingerprint,
    );
    if (!transaction || transaction.transactionId !== manual.transactionId ||
        this.#transactionIdentity(transaction) !==
          this.#recoveryBinding?.transactionIdentity ||
        transaction.phase !== manual.phase ||
        transaction.serviceGeneration !== manual.serviceGeneration ||
        transaction.old.oldFingerprint !== manual.expectedOldProofFingerprint) {
      throwStore('SERVICE_PENDING', 'clear_manual_cleanup', this.#calls.writes);
    }
    const exactProof = manual.expectedDisposition === 'absent'
      ? oldProof.disposition === 'absent'
      : oldProof.disposition === 'stable';
    if (oldProof.oldFingerprint !== manual.expectedOldProofFingerprint ||
        !sameJson(oldProof, transaction.old)) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'clear_manual_cleanup', this.#calls.writes);
    }
    if (!exactProof) throwStore('SERVICE_SCOPE_MISMATCH', 'clear_manual_cleanup', this.#calls.writes);
    const directory = this.#serviceDirectory('manual', false);
    if (!directory) throwStore('SERVICE_STALE', 'clear_manual_cleanup', this.#calls.writes);
    this.#manual = this.#remove(
      directory.handle,
      SERVICE_STORE_LAYOUT.manualCleanup,
      expected,
      'manual-cleanup',
      this.#service.handle,
      'clear_manual_cleanup',
    );
    return this.#manual;
  }

  #validateTransaction(value, operation) {
    value = this.#snapshot(value, validateServiceTransaction, operation);
    try {
      validateServiceOldProof(value.old, this.#config.platform);
      validateServiceCandidateProof(value.candidate, this.#config.platform);
      validateServiceTransitionProof(value.transition, this.#config.platform);
      validateServiceFinalProof(value.final, this.#config.platform);
    } catch (error) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes, false, error);
    }
    this.#scope(value, operation);
    return value;
  }

  #transactionIdentity(value) {
    return canonicalJsonHash({
      transactionId: value.transactionId,
      transactionNonce: value.transactionNonce,
      operation: value.operation,
      component: value.component,
      serviceKey: value.serviceKey,
      platform: value.platform,
      architecture: value.architecture,
      serviceGeneration: value.serviceGeneration,
      old: value.old,
      candidate: value.candidate,
      transition: value.transition,
      final: value.final,
    });
  }

  #sameRetainedTransactionIdentity(transactionFingerprint, transaction) {
    if (transactionFingerprint === transaction.transactionFingerprint) return true;
    const anchored = this.#retainedTransactionByFingerprint(transactionFingerprint);
    const current = this.#retainedTransactionByFingerprint(
      transaction.transactionFingerprint,
    );
    return anchored !== null && current !== null &&
      this.#transactionIdentity(anchored) === this.#transactionIdentity(current);
  }

  #assertJournalLink(previous, value, operation) {
    if (value.previousJournalFingerprint !== (previous?.transactionFingerprint ?? null)) {
      throwStore('SERVICE_STALE', operation, this.#calls.writes);
    }
    if (!previous) return;
    const sameTransaction = previous.transactionId === value.transactionId && previous.transactionNonce === value.transactionNonce;
    if (sameTransaction) {
      if (this.#transactionIdentity(previous) !== this.#transactionIdentity(value)) {
        throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
      }
    } else if (previous.phase !== 'committed' || value.phase !== 'prepared' || value.substep !== 'none' ||
        value.serviceGeneration !== previous.serviceGeneration + 1 || value.old.oldFingerprint !== previous.final.finalFingerprint) {
      throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    }
  }

  #assertTransactionBase(value) {
    const manifest = this.readManifest('current');
    const resource = this.readResourceProof('current');
    if (value.old.disposition === 'absent') {
      if (manifest.present || resource.present) {
        throwStore('SERVICE_SCOPE_MISMATCH', 'append_service_journal', this.#calls.writes);
      }
      return;
    }
    if (!manifest.present || !resource.present ||
        value.old.manifestFingerprint !== manifest.value.manifestFingerprint ||
        value.old.resourceProof !== resource.value.resourceProof ||
        value.old.applicationManifestFingerprint !== manifest.value.applicationManifestFingerprint ||
        value.old.shawlManifestFingerprint !== manifest.value.shawlManifestFingerprint ||
        value.old.serviceGeneration !== manifest.value.serviceGeneration ||
        value.old.activation !== manifest.value.platformState.activation ||
        manifest.value.resourceProof !== resource.value.resourceProof) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'append_service_journal', this.#calls.writes);
    }
  }

  readJournal() {
    this.#ensureOpen('read_service_journal');
    const directory = this.#serviceDirectory('transaction', false);
    if (!directory) return Object.freeze({
      head: this.#makeReceipt('journal-head', null, null),
      entries: Object.freeze([]),
      entryReceipts: Object.freeze([]),
      pending: null,
    });
    const listing = this.#list(directory.handle, this.#service.handle);
    const names = listing.entries.map((entry) => entry.name).filter((name) => JOURNAL_ENTRY.test(name)).sort(utf8Compare);
    const head = this.#read(directory.handle, SERVICE_STORE_LAYOUT.journalHead, validateServiceJournalHead, 'journal-head');
    if (head.present) this.#scope(head.value, 'read_service_journal');
    const entries = [];
    const entryReceipts = [];
    for (let index = 0; index < names.length; index += 1) {
      const sequence = index + 1;
      if (names[index] !== journalName(sequence)) throwStore('SERVICE_MANUAL_CLEANUP', 'read_service_journal', this.#calls.writes, true);
      const receipt = this.#read(directory.handle, names[index], validateServiceTransaction, `journal-entry:${sequence}`);
      if (!receipt.present) throwStore('SERVICE_MANUAL_CLEANUP', 'read_service_journal', this.#calls.writes, true);
      this.#validateTransaction(receipt.value, 'read_service_journal');
      try { this.#assertJournalLink(entries.at(-1), receipt.value, 'read_service_journal'); }
      catch (error) { throwStore('SERVICE_MANUAL_CLEANUP', 'read_service_journal', this.#calls.writes, true, error); }
      entries.push(receipt.value);
      entryReceipts.push(receipt);
    }
    let pending = null;
    if (!head.present) {
      if (entries.length > 1) throwStore('SERVICE_MANUAL_CLEANUP', 'read_service_journal', this.#calls.writes, true);
      pending = entries[0] ?? null;
    } else {
      const sequence = head.value.sequence;
      if (sequence > entries.length || entries.length > sequence + 1) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_service_journal', this.#calls.writes, true);
      }
      const committed = entries[sequence - 1];
      if (!committed || head.value.transactionFingerprint !== committed.transactionFingerprint ||
          head.value.transactionId !== committed.transactionId || head.value.transactionNonce !== committed.transactionNonce ||
          head.value.serviceGeneration !== committed.serviceGeneration ||
          head.value.previousJournalFingerprint !== committed.previousJournalFingerprint) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_service_journal', this.#calls.writes, true);
      }
      pending = entries.length === sequence + 1 ? entries.at(-1) : null;
    }
    return Object.freeze({ head, entries: Object.freeze(entries), entryReceipts: Object.freeze(entryReceipts), pending });
  }

  appendJournal(value) {
    this.#ensureWritable('append_service_journal');
    value = this.#validateTransaction(value, 'append_service_journal');
    this.#authorizeRecoveryTransaction(value, 'append_service_journal');
    if (this.#tombstone?.present &&
        (value.operation !== 'uninstall' || value.transactionId !== this.#tombstone.value.transactionId)) {
      throwStore('SERVICE_TOMBSTONED', 'append_service_journal', this.#calls.writes);
    }
    const journal = this.readJournal();
    const committed = journal.head.present ? journal.head.value.sequence : 0;
    if (journal.pending !== null) {
      if (!sameJson(journal.pending, value)) throwStore('SERVICE_PENDING', 'append_service_journal', this.#calls.writes);
      return this.#completeJournalAppend(
        value,
        this.#writeJournalHead(value, journal.head, committed + 1),
      );
    }
    if (journal.entries.length > 0 && sameJson(journal.entries.at(-1), value)) {
      return this.#completeJournalAppend(value, journal.head);
    }
    this.#assertJournalLink(journal.entries.at(-1), value, 'append_service_journal');
    const previous = journal.entries.at(-1);
    if (!previous || previous.transactionId !== value.transactionId ||
        previous.transactionNonce !== value.transactionNonce) {
      this.#assertTransactionBase(value);
    }
    const sequence = committed + 1;
    const directory = this.#serviceDirectory('transaction', true);
    this.#publish(
      directory.handle, journalName(sequence), value, validateServiceTransaction,
      this.#makeReceipt(`journal-entry:${sequence}`, null, null), `journal-entry:${sequence}`,
    );
    return this.#completeJournalAppend(
      value,
      this.#writeJournalHead(value, journal.head, sequence),
    );
  }

  #completeJournalAppend(value, result) {
    this.#journal = this.readJournal();
    if (this.#mode === 'recovery') {
      const retained = this.#retainedTransactionByFingerprint(
        value.transactionFingerprint,
      );
      if (retained === null ||
          this.#transactionIdentity(retained) !==
            this.#recoveryBinding.transactionIdentity) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'append_service_journal', this.#calls.writes, true);
      }
      this.#recoveryBinding.transaction = retained;
      this.#recoveryBinding.transactionIndex = this.#journal.entries.findIndex(
        (entry) => entry.transactionFingerprint === value.transactionFingerprint,
      );
    }
    return result;
  }

  #writeJournalHead(value, expected, sequence) {
    const head = buildServiceJournalHead({
      serviceKey: this.#config.serviceKey,
      component: this.#config.component,
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      sequence,
      serviceGeneration: value.serviceGeneration,
      transactionId: value.transactionId,
      transactionNonce: value.transactionNonce,
      transactionFingerprint: value.transactionFingerprint,
      previousJournalFingerprint: value.previousJournalFingerprint,
    });
    return this.#publish(
      this.#serviceDirectory('transaction', true).handle,
      SERVICE_STORE_LAYOUT.journalHead, head, validateServiceJournalHead,
      expected, 'journal-head',
    );
  }

  #verifyRetainedDeploymentBytes(
    purpose,
    manifestBytes,
    signatureBytes,
    operation,
    stored,
  ) {
    try {
      return verifyPinnedDeploymentProvenance({
        purpose,
        manifestBytes,
        signatureBytes,
        platform: this.#config.platform,
        architecture: this.#config.architecture,
      });
    } catch (error) {
      if (stored) {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      const code = typeof error?.code === 'string' &&
          error.code.startsWith('DEPLOYMENT_')
        ? error.code
        : 'SERVICE_INVALID';
      throwStore(code, operation, this.#calls.writes);
    }
  }

  #transactionCandidateMatchesDeployment(transaction, purpose, manifest) {
    if (transaction.candidate.disposition !== 'release') return false;
    if (purpose === 'application') {
      return transaction.candidate.applicationManifestFingerprint ===
          manifest.manifestFingerprint &&
        transaction.candidate.releaseSequence === manifest.releaseSequence &&
        transaction.candidate.releaseTreeFingerprint ===
          manifest.inventory.treeFingerprint &&
        transaction.candidate.compatibilityFingerprint ===
          canonicalJsonHash(manifest.compatibility);
    }
    return transaction.candidate.shawlManifestFingerprint ===
      manifest.manifestFingerprint;
  }

  #authorizeRetainedDeploymentWrite(transaction, operation) {
    if (!['install', 'update'].includes(transaction.operation)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const retained = this.#retainedTransactionByFingerprint(
      transaction.transactionFingerprint,
    );
    const latest = this.#journal.entries.at(-1);
    const pending = latest !== undefined &&
      (latest.phase !== 'committed' || this.#journal.pending !== null);
    if (retained === null || !sameJson(retained, transaction) ||
        !pending ||
        this.#transactionIdentity(latest) !==
          this.#transactionIdentity(transaction)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    this.#authorizeRecoveryTransaction(transaction, operation);
  }

  #assertArtifactFloorAdmission(purpose, manifest, transaction, operation) {
    const scope = purpose === 'application'
      ? `application:${this.#config.platform}:${this.#config.architecture}`
      : 'shawl:win32:x64';
    const pair = this.#floors.get(scope);
    if (!pair || pair.historyPhase !== 'stable') {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const floor = pair.floor.value;
    const sequence = manifest.releaseSequence;
    const manifestFingerprint = manifest.manifestFingerprint;
    const active = floor.activeReservation;
    if (active !== null) {
      if (active.component === transaction.component &&
          active.serviceKey === transaction.serviceKey &&
          active.transactionId === transaction.transactionId &&
          active.transactionNonce === transaction.transactionNonce &&
          this.#sameRetainedTransactionIdentity(
            active.transactionFingerprint,
            transaction,
          ) &&
          active.sequence === sequence &&
          active.manifestFingerprint === manifestFingerprint) {
        return;
      }
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (floor.highestReservedSequence === sequence &&
        floor.highestReservedManifestFingerprint === manifestFingerprint &&
        floor.committedSequence === sequence &&
        floor.committedManifestFingerprint === manifestFingerprint &&
        floor.committedTransactionId === transaction.transactionId &&
        floor.committedTransactionNonce === transaction.transactionNonce &&
        this.#sameRetainedTransactionIdentity(
          floor.committedTransactionFingerprint,
          transaction,
        )) {
      return;
    }
    throwStore('SERVICE_PENDING', operation, this.#calls.writes);
  }

  #retainedDeploymentRecordMatchesName(record, purpose, manifestFingerprint) {
    return record.component === this.#config.component &&
      record.serviceKey === this.#config.serviceKey &&
      record.platform === this.#config.platform &&
      record.architecture === this.#config.architecture &&
      record.purpose === purpose &&
      record.manifestFingerprint === manifestFingerprint;
  }

  retainDeploymentEnvelope(input) {
    const operation = 'retain_deployment_envelope';
    try {
      return this.#retainDeploymentEnvelope(input, operation);
    } catch (error) {
      throwRetainedDeploymentFailure(error, operation, this.#calls.writes);
    }
  }

  #retainDeploymentEnvelope(input, operation) {
    this.#ensureWritable(operation);
    const fields = dataValues(
      input,
      ['purpose', 'manifestBytes', 'signatureBytes', 'transaction'],
    );
    if (fields === null || !['application', 'shawl'].includes(fields.purpose)) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    const manifestBytes = boundedByteCopy(
      fields.manifestBytes,
      DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
    );
    const signatureBytes = boundedByteCopy(
      fields.signatureBytes,
      DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes,
    );
    if (manifestBytes === null || signatureBytes === null) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    const transaction = this.#validateTransaction(fields.transaction, operation);
    this.#scope(transaction, operation);
    const verified = this.#verifyRetainedDeploymentBytes(
      fields.purpose,
      manifestBytes,
      signatureBytes,
      operation,
      false,
    );
    if (!this.#transactionCandidateMatchesDeployment(
      transaction,
      fields.purpose,
      verified.manifest,
    )) {
      throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    }
    this.#authorizeRetainedDeploymentWrite(transaction, operation);
    const name = retainedDeploymentEnvelopeName(
      fields.purpose,
      verified.manifestFingerprint,
    );
    const logical = `retained-deployment-envelope:${fields.purpose}`;
    const record = {
      schemaVersion: 1,
      kind: 'retained-deployment-envelope',
      serviceKey: this.#config.serviceKey,
      component: this.#config.component,
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      purpose: fields.purpose,
      manifestFingerprint: verified.manifestFingerprint,
      manifestBase64: manifestBytes.toString('base64'),
      signatureBase64: signatureBytes.toString('base64'),
    };
    const existing = this.#readService(
      'manifest',
      name,
      validateRetainedDeploymentEnvelope,
      logical,
    );
    if (existing.present) {
      if (!this.#retainedDeploymentRecordMatchesName(
        existing.value,
        fields.purpose,
        verified.manifestFingerprint,
      ) ||
          !sameJson(existing.value, record)) {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      return verified;
    }
    this.#publishService(
      'manifest',
      name,
      record,
      validateRetainedDeploymentEnvelope,
      existing,
      logical,
    );
    return verified;
  }

  #pendingJournalDeploymentEvidence(purpose, manifestFingerprint) {
    const latest = this.#journal.entries.at(-1);
    if (latest === undefined ||
        (latest.phase === 'committed' && this.#journal.pending === null)) {
      return null;
    }
    const candidateFingerprint = purpose === 'application'
      ? latest.candidate.applicationManifestFingerprint
      : latest.candidate.shawlManifestFingerprint;
    return latest.component === this.#config.component &&
      latest.serviceKey === this.#config.serviceKey &&
      latest.candidate.disposition === 'release' &&
      candidateFingerprint === manifestFingerprint
      ? latest
      : null;
  }

  #floorStateDeploymentEvidence(
    floor,
    transactionFingerprint,
    manifestFingerprint,
  ) {
    const reservation = floor.activeReservation;
    if (reservation !== null &&
        reservation.serviceKey === this.#config.serviceKey &&
        reservation.transactionFingerprint === transactionFingerprint &&
        reservation.manifestFingerprint === manifestFingerprint) {
      return Object.freeze({ sequence: reservation.sequence });
    }
    return floor.committedTransactionFingerprint === transactionFingerprint &&
      floor.committedManifestFingerprint === manifestFingerprint
      ? Object.freeze({ sequence: floor.committedSequence })
      : null;
  }

  #pendingFloorDeploymentEvidence(purpose, manifestFingerprint) {
    const scope = purpose === 'application'
      ? `application:${this.#config.platform}:${this.#config.architecture}`
      : 'shawl:win32:x64';
    const pair = this.#floors.get(scope);
    if (!pair) return null;
    if (pair.historyPhase === 'stable') {
      const reservation = pair.floor.value.activeReservation;
      return reservation !== null &&
        reservation.serviceKey === this.#config.serviceKey &&
        reservation.manifestFingerprint === manifestFingerprint
        ? Object.freeze({ sequence: reservation.sequence })
        : null;
    }
    const source = pair.historyIntent?.value ?? pair.historyDescriptor;
    if (!source || source.serviceKey !== this.#config.serviceKey ||
        !isHex64(source.transactionFingerprint)) {
      return null;
    }
    const transaction = this.#retainedTransactionByFingerprint(
      source.transactionFingerprint,
    );
    if (transaction !== null) {
      const candidateFingerprint = purpose === 'application'
        ? transaction.candidate.applicationManifestFingerprint
        : transaction.candidate.shawlManifestFingerprint;
      if (transaction.component === this.#config.component &&
          transaction.serviceKey === this.#config.serviceKey &&
          transaction.candidate.disposition === 'release' &&
          candidateFingerprint === manifestFingerprint) {
        return Object.freeze({ transaction });
      }
    }
    const currentEvidence = this.#floorStateDeploymentEvidence(
      pair.floor.value,
      source.transactionFingerprint,
      manifestFingerprint,
    );
    if (currentEvidence !== null || pair.historyIntent === null) {
      return currentEvidence;
    }
    return this.#floorStateDeploymentEvidence(
      pair.historyIntent.value.intendedFloor,
      source.transactionFingerprint,
      manifestFingerprint,
    );
  }

  #referencedDeploymentArtifacts(purpose, manifestFingerprint) {
    const references = this.readReferences();
    if (!references.present) return [];
    return ['current', 'previous', 'provisional'].flatMap((slot) =>
      references.value[slot]?.artifacts.filter((artifact) =>
        artifact.artifactKind === purpose &&
        artifact.manifestFingerprint === manifestFingerprint) ?? []);
  }

  #artifactMatchesDeployment(artifact, purpose, manifest) {
    if (purpose === 'application') {
      return artifact.artifactFingerprint === manifest.archive.sha256 &&
        artifact.treeFingerprint === manifest.inventory.treeFingerprint;
    }
    return artifact.artifactFingerprint === manifest.executable.sha256 &&
      artifact.treeFingerprint === null;
  }

  readRetainedDeploymentEnvelope(input) {
    const operation = 'read_retained_deployment_envelope';
    try {
      // Session callers consume the verified deployment record directly.
      // Artifact cleanup uses the private helper below when it also needs
      // the retained-record digest for provenance binding.
      return this.#readRetainedDeploymentEnvelope(input, operation);
    } catch (error) {
      throwRetainedDeploymentFailure(error, operation, this.#calls.writes);
    }
  }

  #readVerifiedRetainedDeploymentForArtifact(
    purpose,
    manifestFingerprint,
    operation,
  ) {
    const name = retainedDeploymentEnvelopeName(
      purpose,
      manifestFingerprint,
    );
    const record = this.#readService(
      'manifest',
      name,
      validateRetainedDeploymentEnvelope,
      `retained-deployment-envelope:${purpose}`,
    );
    if (!record.present ||
        !this.#retainedDeploymentRecordMatchesName(
          record.value,
          purpose,
          manifestFingerprint,
        )) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    const verified = this.#verifyRetainedDeploymentBytes(
      purpose,
      decodeCanonicalBase64(
        record.value.manifestBase64,
        DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
      ),
      decodeCanonicalBase64(
        record.value.signatureBase64,
        DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes,
      ),
      operation,
      true,
    );
    if (verified.manifestFingerprint !== manifestFingerprint ||
        verified.purpose !== purpose) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    return Object.freeze({
      verified,
      recordSha256: canonicalJsonHash(record.value),
    });
  }

  #readRetainedDeploymentEnvelope(input, operation) {
    this.#ensureOpen(operation);
    const fields = dataValues(input, ['purpose', 'manifestFingerprint']);
    if (fields === null || !['application', 'shawl'].includes(fields.purpose) ||
        !isHex64(fields.manifestFingerprint) ||
        (fields.purpose === 'shawl' && this.#config.platform !== 'win32')) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    const referencedArtifacts = this.#referencedDeploymentArtifacts(
      fields.purpose,
      fields.manifestFingerprint,
    );
    const pendingTransaction = this.#pendingJournalDeploymentEvidence(
      fields.purpose,
      fields.manifestFingerprint,
    );
    const pendingFloor = this.#pendingFloorDeploymentEvidence(
      fields.purpose,
      fields.manifestFingerprint,
    );
    if (referencedArtifacts.length === 0 &&
        pendingTransaction === null &&
        pendingFloor === null) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const name = retainedDeploymentEnvelopeName(
      fields.purpose,
      fields.manifestFingerprint,
    );
    const record = this.#readService(
      'manifest',
      name,
      validateRetainedDeploymentEnvelope,
      `retained-deployment-envelope:${fields.purpose}`,
    );
    if (!record.present ||
        !this.#retainedDeploymentRecordMatchesName(
          record.value,
          fields.purpose,
          fields.manifestFingerprint,
        )) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    const verified = this.#verifyRetainedDeploymentBytes(
      fields.purpose,
      decodeCanonicalBase64(
        record.value.manifestBase64,
        DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
      ),
      decodeCanonicalBase64(
        record.value.signatureBase64,
        DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes,
      ),
      operation,
      true,
    );
    if (verified.purpose !== fields.purpose ||
        verified.manifestFingerprint !== fields.manifestFingerprint) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    const referenceMatches = referencedArtifacts.some((artifact) =>
      this.#artifactMatchesDeployment(
        artifact,
        fields.purpose,
        verified.manifest,
      ));
    const transactionMatches = pendingTransaction !== null &&
      this.#transactionCandidateMatchesDeployment(
        pendingTransaction,
        fields.purpose,
        verified.manifest,
      );
    const floorMatches = pendingFloor !== null &&
      (pendingFloor.transaction === undefined
        ? pendingFloor.sequence === verified.manifest.releaseSequence
        : this.#transactionCandidateMatchesDeployment(
          pendingFloor.transaction,
          fields.purpose,
          verified.manifest,
        ));
    if (!referenceMatches && !transactionMatches && !floorMatches) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    return verified;
  }

  #artifactCall(operation, callback) {
    try {
      return callback();
    } catch (error) {
      const code = typeof error?.code === 'string' &&
          /^SERVICE_[A-Z_]+$/.test(error.code)
        ? error.code
        : 'SERVICE_IO_FAILED';
      throwStore(
        code,
        operation,
        this.#calls.writes,
        error?.ambiguous === true || typeof error?.code !== 'string',
      );
    }
  }

  #artifactBridge() {
    const identities = new Map();
    const readers = new Map();
    const operationCall = (operation, callback) =>
      this.#artifactCall(operation, callback);
    const closeInvalidHandle = (error, handle) => {
      throwAfterCleanup(
        this.#calls,
        error,
        () => this.#calls.invoke('close_service_handle', handle),
      );
    };
    const rememberIdentity = (handle, identity) => {
      identities.set(handle, cloneJson(identity));
    };
    const openValidatedRoot = (rootKind, access, operation) => {
      const raw = this.#calls.invoke(
        'open_service_root',
        rootKind,
        access,
      );
      if (raw === null) return null;
      const result = validateOwnedRootResult(
        this.#calls,
        raw,
        this.#config.platform,
        rootKind,
        this.#config.roles.management.value,
      );
      const writesValid = access === 'create-new'
        ? result.writes >= 1
        : result.writes === 0;
      if (!writesValid ||
          result.rootBinding.rolesFingerprint !==
            this.#root.rootBinding.rolesFingerprint) {
        let error;
        try {
          this.#calls.error(
            'SERVICE_MANUAL_CLEANUP',
            operation,
            true,
          );
        } catch (caught) {
          error = caught;
        }
        closeInvalidHandle(error, result.handle);
      }
      rememberIdentity(result.handle, result.rootBinding.identity);
      return Object.freeze({
        handle: result.handle,
        rootBinding: cloneJson(result.rootBinding),
      });
    };
    return Object.freeze({
      bootstrapRoot: (rootKind, operation) =>
        operationCall(operation, () => {
          const before = this.#calls.writes;
          try {
            const created = openValidatedRoot(
              rootKind,
              'create-new',
              operation,
            );
            if (created === null) {
              throwStore(
                'SERVICE_MANUAL_CLEANUP',
                operation,
                this.#calls.writes,
                true,
              );
            }
            return created;
          } catch (error) {
            if (error?.code !== 'SERVICE_ALREADY_EXISTS' ||
                error?.operation !== 'open_service_root' ||
                error?.writes !== before ||
                error?.ambiguous !== false) {
              throw error;
            }
          }
          const reopened = openValidatedRoot(
            rootKind,
            'write-existing',
            operation,
          );
          if (reopened === null) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          return reopened;
        }),
      adoptHandle: (handle, operation) => operationCall(operation, () => {
        this.#calls.adoptHandle(handle);
      }),
      disownHandle: (handle, operation) =>
        operationCall(operation, () => {
          this.#calls.disownHandle(handle);
        }),
      openRoot: (rootKind, access, operation) => operationCall(operation, () => {
        if (access !== 'write-existing') {
          throwStore('SERVICE_INVALID', operation, this.#calls.writes);
        }
        return openValidatedRoot(rootKind, access, operation);
      }),
      openDirectory: (
        parent,
        name,
        access,
        expectedIdentity,
        operation,
      ) => operationCall(operation, () => {
        const raw = this.#calls.invoke(
          'open_service_directory',
          parent,
          name,
          access,
          expectedIdentity,
          this.#artifact.handle,
        );
        const result = validateOwnedDirectoryResult(
          this.#calls,
          raw,
          this.#config.platform,
        );
        const validWrites = access === 'create-new'
          ? result.writes >= 1
          : result.writes === 0;
        if (!validWrites ||
            (expectedIdentity !== null &&
             !sameJson(result.identity, expectedIdentity))) {
          let error;
          try {
            this.#calls.error(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              true,
            );
          } catch (caught) {
            error = caught;
          }
          closeInvalidHandle(error, result.handle);
        }
        rememberIdentity(result.handle, result.identity);
        return Object.freeze({
          handle: result.handle,
          identity: cloneJson(result.identity),
        });
      }),
      readFile: (parent, name, maximumBytes, operation) =>
        operationCall(operation, () => {
          const result = validateReadResult(
            this.#calls,
            this.#calls.invoke(
              'read_service_file',
              parent,
              name,
              maximumBytes,
            ),
          );
          if (result === null) return null;
          validateServiceArtifactFileFacts(
            result.facts,
            this.#config.platform,
          );
          if (result.facts.owner !== this.#config.roles.management.value ||
              result.facts.size !== result.bytes.length) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          return Object.freeze({
            bytes: Buffer.from(result.bytes),
            facts: cloneJson(result.facts),
          });
        }),
      publishFile: (parent, name, bytes, expected, operation) =>
        operationCall(operation, () => {
          const result = validateWriteResult(
            this.#calls,
            this.#calls.invoke(
              'publish_service_file_atomic',
              parent,
              name,
              bytes,
              expected,
              this.#artifact.handle,
            ),
            operation,
          );
          validateServiceArtifactFileFacts(
            result.facts,
            this.#config.platform,
          );
          if (result.facts.owner !== this.#config.roles.management.value) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          return Object.freeze({ facts: cloneJson(result.facts) });
        }),
      listDirectory: (directory, operation) => operationCall(operation, () => {
        const identity = identities.get(directory);
        if (identity === undefined) {
          throwStore('SERVICE_STALE', operation, this.#calls.writes);
        }
        const result = validateArtifactListResult(
          this.#calls,
          this.#calls.invoke(
            'list_service_directory',
            directory,
            ARTIFACT_DIRECTORY_ENTRIES,
            this.#artifact.handle,
          ),
          this.#config.platform,
          identity,
        );
        return Object.freeze({
          directoryIdentity: cloneJson(result.directoryIdentity),
          entries: Object.freeze(result.entries.map((entry) => Object.freeze({
            name: entry.name,
            identity: cloneJson(entry.identity),
          }))),
        });
      }),
      beginWrite: (
        parent,
        name,
        expectedSize,
        expectedSha256,
        operation,
      ) => operationCall(operation, () => {
        const result = validateOwnedDirectoryResult(
          this.#calls,
          this.#calls.invoke(
            'begin_service_artifact_write',
            parent,
            name,
            expectedSize,
            expectedSha256,
            this.#artifact.handle,
          ),
          this.#config.platform,
        );
        if (result.writes < 1 ||
            result.identity.profile !== 'service-staging-file') {
          let error;
          try {
            this.#calls.error(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              true,
            );
          } catch (caught) {
            error = caught;
          }
          closeInvalidHandle(error, result.handle);
        }
        return Object.freeze({
          handle: result.handle,
          identity: cloneJson(result.identity),
        });
      }),
      writeChunk: (writer, expectedOffset, bytes, operation) =>
        operationCall(operation, () => {
          const result = this.#calls.invoke(
            'write_service_artifact_chunk',
            writer,
            expectedOffset,
            bytes,
          );
          if (!exact(result, ['nextOffset', 'writes']) ||
              !Number.isSafeInteger(result.nextOffset) ||
              result.nextOffset !== expectedOffset + bytes.length ||
              !validWrites(result.writes) || result.writes < 1) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          return Object.freeze({ nextOffset: result.nextOffset });
        }),
      finishWrite: (writer, profile, operation) =>
        operationCall(operation, () => {
          const result = this.#calls.invoke(
            'finish_service_artifact_write',
            writer,
            profile,
          );
          if (!exact(result, ['facts', 'writes']) ||
              !validWrites(result.writes)) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          validateServiceArtifactFileFacts(
            result.facts,
            this.#config.platform,
          );
          if (result.facts.owner !== this.#config.roles.management.value) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          return Object.freeze({ facts: cloneJson(result.facts) });
        }),
      openReader: (
        parent,
        name,
        maximumBytes,
        expectedFacts,
        operation,
      ) => operationCall(operation, () => {
        const result = this.#calls.invoke(
          'open_service_artifact_reader',
          parent,
          name,
          maximumBytes,
          expectedFacts,
          this.#artifact.handle,
        );
        if (result === null) return null;
        if (!exact(result, ['handle', 'facts', 'writes']) ||
            result.handle === null || result.writes !== 0) {
          if (plain(result) && Object.hasOwn(result, 'handle') &&
              result.handle !== null) {
            let error;
            try {
              this.#calls.error(
                'SERVICE_MANUAL_CLEANUP',
                operation,
                true,
              );
            } catch (caught) {
              error = caught;
            }
            closeInvalidHandle(error, result.handle);
          }
          throwStore(
            'SERVICE_MANUAL_CLEANUP',
            operation,
            this.#calls.writes,
            true,
          );
        }
        let factsValid = true;
        try {
          validateServiceArtifactFileFacts(
            result.facts,
            this.#config.platform,
          );
        } catch {
          factsValid = false;
        }
        if (!factsValid ||
            result.facts.owner !== this.#config.roles.management.value) {
          let error;
          try {
            this.#calls.error(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              true,
            );
          } catch (caught) {
            error = caught;
          }
          closeInvalidHandle(error, result.handle);
        }
        readers.set(result.handle, {
          facts: cloneJson(result.facts),
          offset: 0,
          eof: false,
        });
        return Object.freeze({
          handle: result.handle,
          facts: cloneJson(result.facts),
        });
      }),
      readChunk: (reader, expectedOffset, maximumBytes, operation) =>
        operationCall(operation, () => {
          const state = readers.get(reader);
          if (!state || state.eof || state.offset !== expectedOffset ||
              !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 ||
              maximumBytes > ARTIFACT_CHUNK_BYTES) {
            throwStore('SERVICE_STALE', operation, this.#calls.writes);
          }
          const result = this.#calls.invoke(
            'read_service_artifact_chunk',
            reader,
            expectedOffset,
            maximumBytes,
          );
          const nextOffset = expectedOffset + (result?.bytes?.length ?? -1);
          if (!exact(result, ['bytes', 'nextOffset', 'eof', 'writes']) ||
              !Buffer.isBuffer(result.bytes) ||
              result.bytes.length > maximumBytes ||
              !Number.isSafeInteger(result.nextOffset) ||
              result.nextOffset !== nextOffset ||
              typeof result.eof !== 'boolean' || result.writes !== 0 ||
              result.nextOffset > state.facts.size ||
              result.eof !== (result.nextOffset === state.facts.size) ||
              (!result.eof && result.bytes.length === 0)) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          state.offset = result.nextOffset;
          state.eof = result.eof;
          return Object.freeze({
            bytes: Buffer.from(result.bytes),
            nextOffset: result.nextOffset,
            eof: result.eof,
          });
        }),
      removeFile: (parent, name, expectedFacts, operation) =>
        operationCall(operation, () => {
          validateServiceArtifactFileFacts(
            expectedFacts,
            this.#config.platform,
          );
          const result = this.#calls.invoke(
            'remove_service_artifact_file_exact',
            parent,
            name,
            expectedFacts,
            this.#artifact.handle,
          );
          if (!exact(result, ['removed', 'writes']) ||
              result.removed !== true ||
              !validWrites(result.writes) ||
              result.writes < 1) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          return Object.freeze({ removed: true });
        }),
      removeObject: (parent, name, expectedIdentity, operation) =>
        operationCall(operation, () => {
          validateServiceNativeIdentity(
            expectedIdentity,
            this.#config.platform,
          );
          if (!['service-release-directory', 'service-staging-directory']
              .includes(expectedIdentity.profile)) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          const result = this.#calls.invoke(
            'remove_service_object_exact',
            parent,
            name,
            { identity: expectedIdentity },
            this.#artifact.handle,
          );
          if (!exact(result, ['removed', 'writes']) ||
              result.removed !== true ||
              !validWrites(result.writes) ||
              result.writes < 1) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          return Object.freeze({ removed: true });
        }),
      sealDirectory: (directory, expectedIdentity, operation) =>
        operationCall(operation, () => {
          const result = this.#calls.invoke(
            'seal_service_directory',
            directory,
            expectedIdentity,
            this.#artifact.handle,
          );
          if (!exact(result, ['handle', 'identity', 'writes']) ||
              result.handle !== directory || !validWrites(result.writes)) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          validateServiceNativeIdentity(
            result.identity,
            this.#config.platform,
            'service-release-directory',
          );
          rememberIdentity(directory, result.identity);
          return Object.freeze({
            handle: directory,
            identity: cloneJson(result.identity),
          });
        }),
      publishDirectory: (
        source,
        destination,
        name,
        expectedIdentity,
        operation,
      ) => operationCall(operation, () => {
        const result = this.#calls.invoke(
          'publish_service_directory_no_replace',
          source,
          destination,
          name,
          expectedIdentity,
          this.#artifact.handle,
        );
        if (!exact(result, ['handle', 'identity', 'writes']) ||
            result.handle !== source || !validWrites(result.writes) ||
            result.writes < 1 ||
            !sameJson(result.identity, expectedIdentity)) {
          throwStore(
            'SERVICE_MANUAL_CLEANUP',
            operation,
            this.#calls.writes,
            true,
          );
        }
        validateServiceNativeIdentity(
          result.identity,
          this.#config.platform,
          'service-release-directory',
        );
        rememberIdentity(source, result.identity);
        return Object.freeze({
          handle: source,
          identity: cloneJson(result.identity),
        });
      }),
      closeHandle: (handle, operation) => operationCall(operation, () => {
        this.#calls.invoke('close_service_handle', handle);
        identities.delete(handle);
        readers.delete(handle);
      }),
      observePublication: (purpose, manifest, identity, operation) =>
        operationCall(operation, () => purpose === 'application'
          ? this.observeApplicationPublication(manifest, identity)
          : this.observeShawlPublication(manifest, identity)),
      fail: (code, operation, ambiguous = false) => {
        throwStore(code, operation, this.#calls.writes, ambiguous);
      },
    });
  }

  openArtifactAccess(input) {
    const operation = 'open_service_artifact_access';
    this.#ensureWritable(operation);
    const fields = dataValues(input, ['purpose', 'manifest', 'transaction']);
    if (fields === null || !['application', 'shawl'].includes(fields.purpose)) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    this.#assertPinnedManifest(fields.manifest, fields.purpose);
    const manifest = this.#snapshot(
      fields.manifest,
      fields.purpose === 'application'
        ? validateApplicationDeploymentManifest
        : validateShawlDeploymentManifest,
      operation,
    );
    if (manifest.target.platform !== this.#config.platform ||
        manifest.target.architecture !== this.#config.architecture ||
        (fields.purpose === 'shawl' && this.#config.platform !== 'win32')) {
      throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    }
    const transaction = this.#validateTransaction(
      fields.transaction,
      operation,
    );
    this.#scope(transaction, operation);
    if (!this.#transactionCandidateMatchesDeployment(
      transaction,
      fields.purpose,
      manifest,
    )) {
      throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    }
    this.#authorizeRetainedDeploymentWrite(transaction, operation);
    const retained = this.#readRetainedDeploymentEnvelope({
      purpose: fields.purpose,
      manifestFingerprint: manifest.manifestFingerprint,
    }, operation);
    if (!sameJson(retained.manifest, manifest)) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    this.#assertArtifactFloorAdmission(
      fields.purpose,
      manifest,
      transaction,
      operation,
    );
    this.#assertNoArtifactCleanupTarget(
      fields.purpose === 'application' ? 'releases' : 'shawl',
      fields.purpose === 'application'
        ? manifest.archive.sha256
        : manifest.executable.sha256,
      operation,
    );
    let released = false;
    const onClose = () => {
      if (released) return;
      released = true;
      this.#artifactAccesses -= 1;
    };
    this.#artifactAccesses += 1;
    try {
      return createServiceArtifactAccessInternal({
        bridge: this.#artifactBridge(),
        purpose: fields.purpose,
        manifest: fields.manifest,
        transaction,
        transactionIdentity: this.#transactionIdentity(transaction),
        roles: this.#config.roles,
        rolesFingerprint: this.#rolesFingerprint,
        platform: this.#config.platform,
        architecture: this.#config.architecture,
        component: this.#config.component,
        serviceKey: this.#config.serviceKey,
        onClose,
      });
    } catch (error) {
      onClose();
      throw error;
    }
  }

  #assertArtifactCleanupTransaction(transaction, operation) {
    transaction = this.#validateTransaction(transaction, operation);
    this.#scope(transaction, operation);
    const retained = this.#retainedTransactionByFingerprint(
      transaction.transactionFingerprint,
    );
    const latest = this.#journal.entries.at(-1);
    if (transaction.phase !== 'committed' ||
        retained === null ||
        !sameJson(retained, transaction) ||
        latest?.transactionFingerprint !==
          transaction.transactionFingerprint ||
        this.#transactionIdentity(transaction) !==
          this.#transactionIdentity(latest)) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    return transaction;
  }

  #assertArtifactCleanupProvenance(record, operation) {
    const retained = this.#readVerifiedRetainedDeploymentForArtifact(
      record.purpose,
      record.manifestFingerprint,
      operation,
    );
    const manifest = retained.verified.manifest;
    const digest = record.purpose === 'application'
      ? manifest.archive.sha256
      : manifest.executable.sha256;
    const tree = record.purpose === 'application'
      ? manifest.inventory.treeFingerprint
      : null;
    if (retained.recordSha256 !==
          record.retainedEnvelopeRecordSha256 ||
        retained.verified.signingKeyId !== record.signingKeyId ||
        retained.verified.signingKeyFingerprint !==
          record.signingKeyFingerprint ||
        manifest.target.platform !== this.#config.platform ||
        manifest.target.architecture !== this.#config.architecture ||
        record.artifactBinding.artifactFingerprint !== digest ||
        record.artifactBinding.treeFingerprint !== tree) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    return retained;
  }

  #withArtifactCleanupMetadata(callback) {
    if (this.#cleanupMetadataMutation) {
      throwStore(
        'SERVICE_PENDING',
        'write_artifact_cleanup',
        this.#calls.writes,
      );
    }
    this.#cleanupMetadataMutation = true;
    try {
      return callback();
    } finally {
      this.#cleanupMetadataMutation = false;
    }
  }

  #throwArtifactCleanupFailure(
    error,
    fallbackOperation,
    preserveOperation = true,
  ) {
    let code = 'SERVICE_IO_FAILED';
    let operation = fallbackOperation;
    let ambiguous = true;
    try {
      const descriptors = Object.getOwnPropertyDescriptors(error);
      const candidateCode = descriptors.code?.get === undefined &&
        descriptors.code?.set === undefined
        ? descriptors.code?.value
        : null;
      const candidateOperation =
        descriptors.operation?.get === undefined &&
        descriptors.operation?.set === undefined
          ? descriptors.operation?.value
          : null;
      if (ARTIFACT_CLEANUP_ERROR_CODES.has(candidateCode)) {
        code = candidateCode;
        ambiguous = descriptors.ambiguous?.get === undefined &&
          descriptors.ambiguous?.set === undefined &&
          descriptors.ambiguous?.value === true;
      }
      if (preserveOperation &&
          typeof candidateOperation === 'string' &&
          [
            'collect_published_artifact',
            'recover_published_artifact_collection',
            'collect_scratch_artifacts',
            'recover_scratch_artifact_collection',
            'inspect_published_service_artifact',
            'collect_published_service_artifact',
            'capture_scratch_artifact_authority',
            'collect_scratch_artifact_space',
            'observe_zero_references',
            'verify_deployment_provenance',
            'artifact-cleanup',
            'advance_artifact_cleanup',
          ].includes(candidateOperation)) {
        operation = candidateOperation;
      }
    } catch {}
    throwStore(
      code,
      operation,
      this.#calls.writes,
      ambiguous,
    );
  }

  #beginArtifactCollection(operation, invocation) {
    if (this.#artifactCollectorOwner !== null ||
        this.#artifactCollectionActive) {
      throwStore(
        'SERVICE_PENDING',
        operation,
        this.#calls.writes,
      );
    }
    const owner = {
      handleOwner: this.#calls.beginHandleOwner(),
      collector: null,
      invocation,
    };
    this.#artifactCollectorOwner = owner;
    this.#artifactAccesses += 1;
    this.#artifactCollectionActive = true;
    return owner;
  }

  #completeArtifactCollection(owner) {
    if (this.#artifactCollectorOwner !== owner) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        'release_published_artifact_collector',
        this.#calls.writes,
        true,
      );
    }
    this.#calls.retryHandleOwner(owner.handleOwner);
    if (owner.collector !== null) {
      owner.collector.retryClose();
      owner.collector = null;
    }
    this.#calls.releaseHandleOwner(owner.handleOwner);
    this.#artifactCollectorOwner = null;
    this.#artifactAccesses -= 1;
    this.#artifactCollectionActive = false;
  }

  #createArtifactCollector(input) {
    const owner = this.#artifactCollectorOwner;
    if (owner === null || !this.#artifactCollectionActive ||
        owner.collector !== null) {
      throwStore(
        'SERVICE_PENDING',
        input.phase === null
          ? 'inspect_published_service_artifact'
          : 'collect_published_service_artifact',
        this.#calls.writes,
      );
    }
    const collector =
      createServicePublishedArtifactCollectorInternal(input);
    owner.collector = collector;
    return collector;
  }

  async #runArtifactCollector(collector, method) {
    const owner = this.#artifactCollectorOwner;
    if (owner === null || !this.#artifactCollectionActive ||
        owner.collector !== collector) {
      throwStore(
        'SERVICE_PENDING',
        'run_published_artifact_collector',
        this.#calls.writes,
      );
    }
    const result = await collector[method]();
    collector.retryClose();
    owner.collector = null;
    return result;
  }

  #retryArtifactCollectorCleanup(
    operation = 'retry_published_artifact_collector',
  ) {
    const owner = this.#artifactCollectorOwner;
    if (owner === null) return false;
    if (this.#artifactCollectionActive) {
      throwStore(
        'SERVICE_PENDING',
        'retry_published_artifact_collector',
        this.#calls.writes,
      );
    }
    try {
      this.#calls.retryHandleOwner(owner.handleOwner);
      if (owner.collector !== null) {
        owner.collector.retryClose();
        owner.collector = null;
      }
      this.#calls.releaseHandleOwner(owner.handleOwner);
    } catch (error) {
      this.#throwArtifactCleanupFailure(error, operation, false);
    }
    this.#artifactCollectorOwner = null;
    this.#artifactAccesses -= 1;
    return true;
  }

  #advanceArtifactCleanupPhase(phase) {
    const current = this.#artifactCleanup;
    if (!current?.present) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        'advance_artifact_cleanup',
        this.#calls.writes,
        true,
      );
    }
    const phases = current.value.scope === 'scratch'
      ? current.value.purpose === 'shawl'
        ? [
          'candidate-payload-removing',
          'candidate-root-removing',
          'asset-removing',
          'marker-removing',
          'scratch-root-removing',
        ]
        : [
          'candidate-payload-removing',
          'candidate-inventory-removing',
          'candidate-root-removing',
          'asset-removing',
          'marker-removing',
          'scratch-root-removing',
        ]
      : ['payload-removing', 'inventory-removing', 'root-removing'];
    const index = phases.indexOf(current.value.phase);
    if (index === -1 || index + 1 >= phases.length ||
        phase !== phases[index + 1]) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        'advance_artifact_cleanup',
        this.#calls.writes,
        true,
      );
    }
    const {
      cleanupFingerprint: ignored,
      ...fields
    } = current.value;
    const next = current.value.scope === 'scratch'
      ? buildServiceArtifactScratchCleanup({
        ...fields,
        phase,
        revision: index + 1,
      })
      : buildServiceArtifactCleanup({
        ...fields,
        phase,
        revision: index + 1,
      });
    this.#artifactCleanup = this.#withArtifactCleanupMetadata(() =>
      this.#publishService(
        'manual',
        SERVICE_STORE_LAYOUT.artifactCleanup,
        next,
        validateServiceArtifactCleanup,
        current,
        'artifact-cleanup',
      ));
  }

  async #executeArtifactCleanup(record, manifest, operation) {
    if (record.scope !== 'published') {
      throwStore(
        'SERVICE_PENDING',
        operation,
        this.#calls.writes,
      );
    }
    const intents = this.#protectedArtifactCleanupIntents(operation);
    if (!intents.some((intent) =>
      intent.cleanupFingerprint === record.cleanupFingerprint)) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    const observation = this.#observeZeroReferences(
      record.artifactBinding,
      record.cleanupFingerprint,
    );
    if (observation.artifactPhysicalTargetFingerprint !==
          record.artifactPhysicalTargetFingerprint) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    const collector = this.#createArtifactCollector({
      bridge: this.#artifactBridge(),
      purpose: record.purpose,
      manifest,
      artifact: record.artifactBinding,
      platform: this.#config.platform,
      expectedRootBindingFingerprint:
        record.artifactRootBindingFingerprint,
      expectedRootIdentity: record.artifactRootIdentity,
      phase: record.phase,
      advancePhase: (phase) =>
        this.#advanceArtifactCleanupPhase(phase),
    });
    await this.#runArtifactCollector(collector, 'collect');
    const directory = this.#serviceDirectory('manual', false);
    if (!directory) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    this.#artifactCleanupUncertain = true;
    this.#artifactCleanup = this.#withArtifactCleanupMetadata(() =>
      this.#remove(
        directory.handle,
        SERVICE_STORE_LAYOUT.artifactCleanup,
        this.#artifactCleanup,
        'artifact-cleanup',
        this.#service.handle,
        operation,
      ));
    this.#artifactCleanupUncertain = false;
    return Object.freeze({
      collected: true,
      artifactBindingFingerprint:
        record.artifactBinding.bindingFingerprint,
    });
  }

  async collectPublishedArtifact(args) {
    const invocation = Object.freeze({});
    try {
      const result = await this.#collectPublishedArtifact(
        args,
        invocation,
      );
      const owner = this.#artifactCollectorOwner;
      if (owner?.invocation === invocation) {
        this.#completeArtifactCollection(owner);
      }
      return result;
    } catch (error) {
      if (this.#artifactCollectorOwner?.invocation === invocation) {
        this.#artifactCollectionActive = false;
      }
      this.#throwArtifactCleanupFailure(
        error,
        'collect_published_artifact',
      );
    }
  }

  async #collectPublishedArtifact(args, invocation) {
    const operation = 'collect_published_artifact';
    this.#ensureWritable(operation);
    if (!Array.isArray(args) || args.length !== 1) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    const input = args[0];
    const fields = dataValues(
      input,
      ['purpose', 'manifest', 'transaction', 'publication'],
    );
    if (fields === null ||
        !['application', 'shawl'].includes(fields.purpose)) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    this.#assertPinnedManifest(fields.manifest, fields.purpose);
    const manifest = this.#snapshot(
      fields.manifest,
      fields.purpose === 'application'
        ? validateApplicationDeploymentManifest
        : validateShawlDeploymentManifest,
      operation,
    );
    if (manifest.target.platform !== this.#config.platform ||
        manifest.target.architecture !== this.#config.architecture ||
        (fields.purpose === 'shawl' &&
         this.#config.platform !== 'win32')) {
      throwStore(
        'SERVICE_SCOPE_MISMATCH',
        operation,
        this.#calls.writes,
      );
    }
    const transaction = this.#assertArtifactCleanupTransaction(
      fields.transaction,
      operation,
    );
    const artifact = this.#publication(
      fields.publication,
      manifest.manifestFingerprint,
      fields.purpose,
      operation,
    );
    const retained = this.#readVerifiedRetainedDeploymentForArtifact(
      fields.purpose,
      manifest.manifestFingerprint,
      operation,
    );
    if (!sameJson(retained.verified.manifest, manifest)) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    this.#beginArtifactCollection(operation, invocation);
    this.#protectedArtifactCleanupIntents(operation);
    const zero = this.#observeZeroReferences(artifact);
    const inspector = this.#createArtifactCollector({
      bridge: this.#artifactBridge(),
      purpose: fields.purpose,
      manifest,
      artifact,
      platform: this.#config.platform,
      expectedRootBindingFingerprint: null,
      expectedRootIdentity: null,
      phase: null,
      advancePhase: () => {
        throwStore(
          'SERVICE_INVALID',
          operation,
          this.#calls.writes,
        );
      },
    });
    const inspected = await this.#runArtifactCollector(
      inspector,
      'inspect',
    );
    const record = buildServiceArtifactCleanup({
      component: this.#config.component,
      serviceKey: this.#config.serviceKey,
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      serviceGeneration: transaction.serviceGeneration,
      transactionId: transaction.transactionId,
      transactionNonce: transaction.transactionNonce,
      transactionFingerprint: transaction.transactionFingerprint,
      transactionIdentity: this.#transactionIdentity(transaction),
      purpose: fields.purpose,
      manifestFingerprint: manifest.manifestFingerprint,
      signingKeyId: retained.verified.signingKeyId,
      signingKeyFingerprint:
        retained.verified.signingKeyFingerprint,
      retainedEnvelopeRecordSha256: retained.recordSha256,
      artifactBinding: artifact,
      artifactPhysicalTargetFingerprint:
        serviceArtifactPhysicalTargetFingerprint(
          artifact,
          this.#config.platform,
        ),
      artifactRootBindingFingerprint:
        inspected.artifactRootBindingFingerprint,
      artifactRootIdentity: inspected.artifactRootIdentity,
      controlRootBindingFingerprint:
        this.#root.rootBinding.bindingFingerprint,
      roles: this.#config.roles,
      rolesFingerprint: this.#rolesFingerprint,
      artifactLockIdentity: this.#artifact.identity,
      zeroReferenceObservationFingerprint:
        zero.observationFingerprint,
      phase: 'payload-removing',
      revision: 0,
    });
    this.#artifactCleanupUncertain = true;
    this.#artifactCleanup = this.#withArtifactCleanupMetadata(() =>
      this.#publishService(
        'manual',
        SERVICE_STORE_LAYOUT.artifactCleanup,
        record,
        validateServiceArtifactCleanup,
        this.#artifactCleanup,
        'artifact-cleanup',
      ));
    return await this.#executeArtifactCleanup(
      record,
      manifest,
      operation,
    );
  }

  async recoverPublishedArtifactCollection(args) {
    const invocation = Object.freeze({});
    try {
      const result = await this.#recoverPublishedArtifactCollection(
        args,
        invocation,
      );
      const owner = this.#artifactCollectorOwner;
      if (owner?.invocation === invocation) {
        this.#completeArtifactCollection(owner);
      }
      return result;
    } catch (error) {
      if (this.#artifactCollectorOwner?.invocation === invocation) {
        this.#artifactCollectionActive = false;
      }
      this.#throwArtifactCleanupFailure(
        error,
        'recover_published_artifact_collection',
      );
    }
  }

  async #recoverPublishedArtifactCollection(args, invocation) {
    const operation = 'recover_published_artifact_collection';
    this.#ensureOpen(operation);
    if (!Array.isArray(args) || args.length !== 0) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    if (this.#mode === 'read-only') {
      throwStore('SERVICE_ACCESS_DENIED', operation, this.#calls.writes);
    }
    const releasedCollector =
      this.#retryArtifactCollectorCleanup(operation);
    if (this.#artifactAccesses !== 0) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (this.#manual?.present) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
      );
    }
    if (!this.#artifactCleanup?.present) {
      if (releasedCollector) {
        return Object.freeze({
          collected: false,
          cleanupReleased: true,
        });
      }
      throwStore('SERVICE_STALE', operation, this.#calls.writes);
    }
    const record = this.#artifactCleanup.value;
    if (record.scope !== 'published') {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const transaction = this.#retainedTransactionByFingerprint(
      record.transactionFingerprint,
    );
    if (transaction === null) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    try {
      this.#assertArtifactCleanupTransaction(transaction, operation);
    } catch {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    const retained = this.#assertArtifactCleanupProvenance(
      record,
      operation,
    );
    this.#beginArtifactCollection(operation, invocation);
    return await this.#executeArtifactCleanup(
      record,
      retained.verified.manifest,
      operation,
    );
  }

  #createScratchArtifactCollector(input) {
    const owner = this.#artifactCollectorOwner;
    if (owner === null || !this.#artifactCollectionActive ||
        owner.collector !== null) {
      throwStore(
        'SERVICE_PENDING',
        input.phase === null
          ? 'capture_scratch_artifact_authority'
          : 'collect_scratch_artifact_space',
        this.#calls.writes,
      );
    }
    const collector = createScratchArtifactCollectorInternal(input);
    owner.collector = collector;
    return collector;
  }

  async #executeScratchArtifactCleanup(record, manifest, operation) {
    const intents = this.#protectedArtifactCleanupIntents(operation);
    if (!intents.some((intent) =>
      intent.cleanupFingerprint === record.cleanupFingerprint)) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    const collector = this.#createScratchArtifactCollector({
      bridge: this.#artifactBridge(),
      purpose: record.purpose,
      manifest,
      transaction: null,
      transactionIdentity: null,
      roles: null,
      rolesFingerprint: null,
      platform: this.#config.platform,
      architecture: null,
      component: null,
      serviceKey: null,
      authority: Object.freeze(Object.fromEntries([
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
      ].map((key) => [key, record[key]]))),
      inspectArchive: record.purpose === 'application'
        ? (chunks) => inspectApplicationArchive({ manifest, chunks })
        : null,
      phase: record.phase,
      advancePhase: (phase) => this.#advanceArtifactCleanupPhase(phase),
    });
    await this.#runArtifactCollector(collector, 'collect');
    const directory = this.#serviceDirectory('manual', false);
    if (!directory) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    this.#artifactCleanupUncertain = true;
    this.#artifactCleanup = this.#withArtifactCleanupMetadata(() =>
      this.#remove(
        directory.handle,
        SERVICE_STORE_LAYOUT.artifactCleanup,
        this.#artifactCleanup,
        'artifact-cleanup',
        this.#service.handle,
        operation,
      ));
    this.#artifactCleanupUncertain = false;
    return Object.freeze({
      collected: true,
      cleanupFingerprint: record.cleanupFingerprint,
    });
  }

  async collectScratchArtifacts(args) {
    const invocation = Object.freeze({});
    try {
      const result = await this.#collectScratchArtifacts(args, invocation);
      const owner = this.#artifactCollectorOwner;
      if (owner?.invocation === invocation) {
        this.#completeArtifactCollection(owner);
      }
      return result;
    } catch (error) {
      if (this.#artifactCollectorOwner?.invocation === invocation) {
        this.#artifactCollectionActive = false;
      }
      this.#throwArtifactCleanupFailure(
        error,
        'collect_scratch_artifacts',
      );
    }
  }

  async #collectScratchArtifacts(args, invocation) {
    const operation = 'collect_scratch_artifacts';
    this.#ensureWritable(operation);
    if (!Array.isArray(args) || args.length !== 1) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    const fields = dataValues(args[0], ['purpose', 'manifest', 'transaction']);
    if (fields === null ||
        !['application', 'shawl'].includes(fields.purpose)) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    this.#assertPinnedManifest(fields.manifest, fields.purpose);
    const manifest = this.#snapshot(
      fields.manifest,
      fields.purpose === 'application'
        ? validateApplicationDeploymentManifest
        : validateShawlDeploymentManifest,
      operation,
    );
    if (manifest.target.platform !== this.#config.platform ||
        manifest.target.architecture !== this.#config.architecture ||
        (fields.purpose === 'shawl' &&
         this.#config.platform !== 'win32')) {
      throwStore(
        'SERVICE_SCOPE_MISMATCH',
        operation,
        this.#calls.writes,
      );
    }
    const transaction = this.#assertScratchCleanupTransaction(
      fields.transaction,
      fields.purpose,
      manifest,
      operation,
    );
    if (!this.#transactionCandidateMatchesDeployment(
      transaction,
      fields.purpose,
      manifest,
    )) {
      throwStore(
        'SERVICE_SCOPE_MISMATCH',
        operation,
        this.#calls.writes,
      );
    }
    const retained = this.#readVerifiedRetainedDeploymentForArtifact(
      fields.purpose,
      manifest.manifestFingerprint,
      operation,
    );
    if (!sameJson(retained.verified.manifest, manifest)) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    this.#beginArtifactCollection(operation, invocation);
    this.#protectedArtifactCleanupIntents(operation);
    const capturer = this.#createScratchArtifactCollector({
      bridge: this.#artifactBridge(),
      purpose: fields.purpose,
      manifest,
      transaction,
      transactionIdentity: this.#transactionIdentity(transaction),
      roles: this.#config.roles,
      rolesFingerprint: this.#rolesFingerprint,
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      component: this.#config.component,
      serviceKey: this.#config.serviceKey,
      authority: null,
      inspectArchive: null,
      phase: null,
      advancePhase: () => {
        throwStore('SERVICE_INVALID', operation, this.#calls.writes);
      },
    });
    const capture = await this.#runArtifactCollector(capturer, 'capture');
    if (capture === null) {
      return Object.freeze({ collected: false, absent: true });
    }
    const phases = fields.purpose === 'shawl'
      ? [
        'candidate-payload-removing',
        'candidate-root-removing',
        'asset-removing',
        'marker-removing',
        'scratch-root-removing',
      ]
      : [
        'candidate-payload-removing',
        'candidate-inventory-removing',
        'candidate-root-removing',
        'asset-removing',
        'marker-removing',
        'scratch-root-removing',
      ];
    const initialPhase = capture.candidateIdentity !== null
      ? 'candidate-payload-removing'
      : 'asset-removing';
    const record = buildServiceArtifactScratchCleanup({
      component: this.#config.component,
      serviceKey: this.#config.serviceKey,
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      serviceGeneration: transaction.serviceGeneration,
      transactionId: transaction.transactionId,
      transactionNonce: transaction.transactionNonce,
      transactionFingerprint: transaction.transactionFingerprint,
      transactionIdentity: this.#transactionIdentity(transaction),
      purpose: fields.purpose,
      manifestFingerprint: manifest.manifestFingerprint,
      releaseSequence: manifest.releaseSequence,
      signingKeyId: retained.verified.signingKeyId,
      signingKeyFingerprint: retained.verified.signingKeyFingerprint,
      retainedEnvelopeRecordSha256: retained.recordSha256,
      controlRootBindingFingerprint:
        this.#root.rootBinding.bindingFingerprint,
      roles: this.#config.roles,
      rolesFingerprint: this.#rolesFingerprint,
      artifactLockIdentity: this.#artifact.identity,
      ...capture,
      phase: initialPhase,
      revision: phases.indexOf(initialPhase),
    });
    this.#artifactCleanupUncertain = true;
    this.#artifactCleanup = this.#withArtifactCleanupMetadata(() =>
      this.#publishService(
        'manual',
        SERVICE_STORE_LAYOUT.artifactCleanup,
        record,
        validateServiceArtifactCleanup,
        this.#artifactCleanup,
        'artifact-cleanup',
      ));
    return await this.#executeScratchArtifactCleanup(
      record,
      manifest,
      operation,
    );
  }

  async recoverScratchArtifactCollection(args) {
    const invocation = Object.freeze({});
    try {
      const result = await this.#recoverScratchArtifactCollection(
        args,
        invocation,
      );
      const owner = this.#artifactCollectorOwner;
      if (owner?.invocation === invocation) {
        this.#completeArtifactCollection(owner);
      }
      return result;
    } catch (error) {
      if (this.#artifactCollectorOwner?.invocation === invocation) {
        this.#artifactCollectionActive = false;
      }
      this.#throwArtifactCleanupFailure(
        error,
        'recover_scratch_artifact_collection',
      );
    }
  }

  async #recoverScratchArtifactCollection(args, invocation) {
    const operation = 'recover_scratch_artifact_collection';
    this.#ensureOpen(operation);
    if (!Array.isArray(args) || args.length !== 0) {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    if (this.#mode === 'read-only') {
      throwStore('SERVICE_ACCESS_DENIED', operation, this.#calls.writes);
    }
    const releasedCollector =
      this.#retryArtifactCollectorCleanup(operation);
    if (this.#artifactAccesses !== 0) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (this.#manual?.present) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
      );
    }
    if (!this.#artifactCleanup?.present) {
      if (releasedCollector) {
        return Object.freeze({
          collected: false,
          cleanupReleased: true,
        });
      }
      throwStore('SERVICE_STALE', operation, this.#calls.writes);
    }
    const record = this.#artifactCleanup.value;
    if (record.scope !== 'scratch') {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    const transaction = this.#retainedTransactionByFingerprint(
      record.transactionFingerprint,
    );
    if (transaction === null) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    this.#validateCleanupRecordJournal(record, transaction, operation);
    const retained = this.#assertScratchCleanupProvenance(
      record,
      operation,
    );
    if (transaction.phase !== 'committed') {
      this.#assertFloorAbandonEvidence(
        record.purpose,
        transaction,
        record.releaseSequence,
        record.manifestFingerprint,
        operation,
      );
    }
    this.#beginArtifactCollection(operation, invocation);
    return await this.#executeScratchArtifactCleanup(
      record,
      retained.verified.manifest,
      operation,
    );
  }

  readReferences() {
    const receipt = this.#read(
      this.#namespaces.reference.handle, `${this.#config.serviceKey}.json`,
      validateServiceReferenceRecord, 'references',
    );
    if (receipt.present) this.#scope(receipt.value, 'read_references');
    return receipt;
  }

  publishReferences(value, expected) {
    this.#ensureWritable('publish_references');
    value = this.#snapshot(value, validateServiceReferenceRecord, 'publish_references');
    this.#scope(value, 'publish_references');
    const cleanupIntents = this.#protectedArtifactCleanupIntents(
      'publish_references',
    );
    for (const slot of ['current', 'previous', 'provisional']) {
      for (const artifact of value[slot]?.artifacts ?? []) {
        if (artifact.artifactKind !== 'shared-template') {
          this.#assertNoArtifactCleanupConflict(
            artifact,
            'publish_references',
            null,
            cleanupIntents,
          );
        }
      }
    }
    const prior = this.#boundReceipt(expected, 'references', 'publish_references');
    this.#authorizeRecoveryRecord('publish_references', value, {
      previous: prior.native === null ? null : expected.value,
    });
    if (prior.native === null) {
      if (value.serviceGeneration !== 0 || value.current !== null ||
          value.previous !== null) {
        throwStore('SERVICE_SCOPE_MISMATCH', 'publish_references', this.#calls.writes);
      }
    } else {
      const previous = expected.value;
      const delta = value.serviceGeneration - previous.serviceGeneration;
      if (delta !== 0 && delta !== 1) {
        throwStore('SERVICE_SCOPE_MISMATCH', 'publish_references', this.#calls.writes);
      }
      if (delta === 0 &&
          (!sameJson(value.current, previous.current) ||
           !sameJson(value.previous, previous.previous))) {
        throwStore('SERVICE_SCOPE_MISMATCH', 'publish_references', this.#calls.writes);
      }
      if (delta === 1) {
        const uninstall = value.current === null;
        const promotedProvisional = !uninstall &&
          sameJson(value.current, previous.provisional);
        const rollbackArtifacts = !uninstall && previous.previous !== null &&
          sameReferenceArtifacts(value.current, previous.previous);
        const carriesOldCurrent = previous.current === null
          ? value.previous === null
          : sameJson(value.previous, previous.current);
        if (value.provisional !== null ||
            (uninstall
              ? value.previous !== null
              : (!carriesOldCurrent || (!promotedProvisional && !rollbackArtifacts)))) {
          throwStore('SERVICE_SCOPE_MISMATCH', 'publish_references', this.#calls.writes);
        }
      }
    }
    const retained = new Set();
    if (prior.native !== null) {
      for (const slot of ['current', 'previous', 'provisional']) {
        for (const artifact of expected.value[slot]?.artifacts ?? []) retained.add(artifact.bindingFingerprint);
      }
    }
    for (const slot of ['current', 'previous', 'provisional']) {
      for (const artifact of value[slot]?.artifacts ?? []) {
        const observed = artifact.artifactKind === 'shared-template'
          ? this.#observedSharedTemplateBindings.has(artifact.bindingFingerprint)
          : this.#observedPublications.has(artifact.bindingFingerprint);
        if (!retained.has(artifact.bindingFingerprint) && !observed) {
          throwStore('SERVICE_SCOPE_MISMATCH', 'publish_references', this.#calls.writes);
        }
      }
    }
    return this.#publish(
      this.#namespaces.reference.handle, `${this.#config.serviceKey}.json`, value,
      validateServiceReferenceRecord, expected, 'references', this.#artifact.handle,
    );
  }

  #openInventoryDirectory(parent, entry, operation) {
    if (!entry) return null;
    const opened = validateOwnedDirectoryResult(this.#calls, this.#calls.invoke(
      'open_service_directory',
      parent,
      entry.name,
      'read-existing',
      entry.identity,
      this.#artifact.handle,
    ), this.#config.platform);
    if (opened.writes !== 0) {
      let error;
      try { this.#calls.error('SERVICE_MANUAL_CLEANUP', operation, true); }
      catch (caught) { error = caught; }
      throwAfterCleanup(
        this.#calls,
        error,
        () => this.#calls.invoke('close_service_handle', opened.handle),
      );
    }
    return opened;
  }

  #readInventoryRecord(handle, name, validator, operation) {
    const raw = validateReadResult(this.#calls, this.#calls.invoke(
      'read_service_file',
      handle,
      name,
      SERVICE_STORE_LIMITS.recordBytes,
    ));
    return raw === null ? null : parseRecord(this.#calls, raw.bytes, validator, operation);
  }

  #readInventoryJournal(entry, serviceKey, { requireCommitted = true } = {}) {
    const directory = this.#openInventoryDirectory(
      this.#namespaces.transaction.handle,
      entry,
      'validate_reference_inventory',
    );
    try {
      const listing = this.#list(directory.handle, this.#artifact.handle);
      const names = listing.entries.map(({ name }) => name);
      if (names.some((name) =>
        name !== SERVICE_STORE_LAYOUT.journalHead && !JOURNAL_ENTRY.test(name))) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      const entryNames = names.filter((name) => JOURNAL_ENTRY.test(name)).sort(utf8Compare);
      const entries = [];
      for (let index = 0; index < entryNames.length; index += 1) {
        if (entryNames[index] !== journalName(index + 1)) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
        }
        const transaction = this.#readInventoryRecord(
          directory.handle,
          entryNames[index],
          validateServiceTransaction,
          'validate_reference_inventory',
        );
        if (!transaction || transaction.serviceKey !== serviceKey ||
            transaction.platform !== this.#config.platform ||
            transaction.architecture !== this.#config.architecture) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
        }
        try { this.#assertJournalLink(entries.at(-1), transaction, 'validate_reference_inventory'); }
        catch (error) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true, error);
        }
        entries.push(transaction);
      }
      const head = this.#readInventoryRecord(
        directory.handle,
        SERVICE_STORE_LAYOUT.journalHead,
        validateServiceJournalHead,
        'validate_reference_inventory',
      );
      const latest = entries.at(-1);
      if (!head || !latest || head.sequence !== entries.length ||
          head.serviceKey !== serviceKey ||
          head.component !== latest.component ||
          head.platform !== this.#config.platform ||
          head.architecture !== this.#config.architecture ||
          head.transactionFingerprint !== latest.transactionFingerprint ||
          head.transactionId !== latest.transactionId ||
          head.transactionNonce !== latest.transactionNonce ||
          head.serviceGeneration !== latest.serviceGeneration ||
          head.previousJournalFingerprint !== latest.previousJournalFingerprint ||
          (requireCommitted && latest.phase !== 'committed')) {
        throwStore(
          latest && latest.phase !== 'committed' ? 'SERVICE_PENDING' : 'SERVICE_MANUAL_CLEANUP',
          'validate_reference_inventory',
          this.#calls.writes,
          latest?.phase === 'committed',
        );
      }
      return Object.freeze({ entries: Object.freeze(entries), latest });
    } finally {
      this.#calls.invoke('close_service_handle', directory.handle);
    }
  }

  #readInventoryManifest(entry, serviceKey) {
    if (!entry) return Object.freeze({
      currentManifest: null,
      previousManifest: null,
      currentResource: null,
      previousResource: null,
      startup: null,
    });
    const directory = this.#openInventoryDirectory(
      this.#namespaces.manifest.handle,
      entry,
      'validate_reference_inventory',
    );
    try {
      const listing = this.#list(directory.handle, this.#artifact.handle);
      for (const { name } of listing.entries) {
        if (MANIFEST_FILE_SET.has(name)) continue;
        const parsed = parseRetainedDeploymentEnvelopeName(name);
        if (parsed === null) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
        }
        const retained = this.#readInventoryRecord(
          directory.handle,
          name,
          validateRetainedDeploymentEnvelope,
          'validate_reference_inventory',
        );
        if (!retained ||
            retained.serviceKey !== serviceKey ||
            retained.platform !== this.#config.platform ||
            retained.architecture !== this.#config.architecture ||
            retained.purpose !== parsed.purpose ||
            retained.manifestFingerprint !==
              parsed.manifestFingerprint) {
          throwStore(
            'SERVICE_MANUAL_CLEANUP',
            'validate_reference_inventory',
            this.#calls.writes,
            true,
          );
        }
      }
      const read = (name, validator) => {
        const value = this.#readInventoryRecord(
          directory.handle,
          name,
          validator,
          'validate_reference_inventory',
        );
        if (value && (value.serviceKey !== serviceKey ||
            value.platform !== this.#config.platform ||
            value.architecture !== this.#config.architecture)) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
        }
        return value;
      };
      return Object.freeze({
        currentManifest: read(SERVICE_STORE_LAYOUT.manifestFiles.current, validateServiceManifest),
        previousManifest: read(SERVICE_STORE_LAYOUT.manifestFiles.previous, validateServiceManifest),
        currentResource: read(SERVICE_STORE_LAYOUT.resourceFiles.current, validateServiceResourceProof),
        previousResource: read(SERVICE_STORE_LAYOUT.resourceFiles.previous, validateServiceResourceProof),
        startup: read(SERVICE_STORE_LAYOUT.startup, validateServiceStartupProof),
      });
    } finally {
      this.#calls.invoke('close_service_handle', directory.handle);
    }
  }

  #readInventoryTombstone(entry, serviceKey) {
    if (!entry) return null;
    const directory = this.#openInventoryDirectory(
      this.#namespaces.tombstone.handle,
      entry,
      'validate_reference_inventory',
    );
    try {
      const listing = this.#list(directory.handle, this.#artifact.handle);
      if (listing.entries.length !== 1 ||
          listing.entries[0].name !== SERVICE_STORE_LAYOUT.tombstone) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      const tombstone = this.#readInventoryRecord(
        directory.handle,
        SERVICE_STORE_LAYOUT.tombstone,
        validateServiceTombstone,
        'validate_reference_inventory',
      );
      if (!tombstone || tombstone.serviceKey !== serviceKey ||
          tombstone.platform !== this.#config.platform ||
          tombstone.architecture !== this.#config.architecture) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      return tombstone;
    } finally {
      this.#calls.invoke('close_service_handle', directory.handle);
    }
  }

  #readInventoryManual(entry, serviceKey) {
    if (!entry) return Object.freeze({ manual: null, cleanup: null });
    const directory = this.#openInventoryDirectory(
      this.#namespaces.manual.handle,
      entry,
      'validate_reference_inventory',
    );
    try {
      const listing = this.#list(directory.handle, this.#artifact.handle);
      if (listing.entries.some(({ name }) => !MANUAL_FILE_SET.has(name))) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      const manual = this.#readInventoryRecord(
        directory.handle,
        SERVICE_STORE_LAYOUT.manualCleanup,
        validateServiceManualCleanup,
        'validate_reference_inventory',
      );
      if (manual && (manual.serviceKey !== serviceKey ||
          manual.platform !== this.#config.platform ||
          manual.architecture !== this.#config.architecture)) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      const cleanup = this.#readInventoryRecord(
        directory.handle,
        SERVICE_STORE_LAYOUT.artifactCleanup,
        validateServiceArtifactCleanup,
        'validate_reference_inventory',
      );
      if (cleanup) {
        this.#validateArtifactCleanupHost(
          cleanup,
          serviceKey,
          'validate_reference_inventory',
        );
      }
      return Object.freeze({ manual, cleanup });
    } finally {
      this.#calls.invoke('close_service_handle', directory.handle);
    }
  }

  #validateInventoryCommittedState(serviceKey, journal, records, reference, tombstone) {
    const transaction = journal.latest;
    const {
      currentManifest,
      previousManifest,
      currentResource,
      previousResource,
      startup,
    } = records;
    if (transaction.final.disposition === 'absent') {
      const emptyReference = reference !== null &&
        reference.current === null && reference.previous === null &&
         reference.provisional === null &&
         reference.serviceGeneration === transaction.serviceGeneration;
      if (currentManifest || previousManifest || currentResource || previousResource || startup ||
          !emptyReference || !tombstone ||
          tombstone.serviceGeneration !== transaction.serviceGeneration ||
          tombstone.resourceProof !== transaction.old.resourceProof ||
          tombstone.currentManifestFingerprint !== transaction.old.manifestFingerprint ||
          !journal.entries.some((entry) =>
            entry.transactionId === tombstone.transactionId &&
            entry.transactionFingerprint === tombstone.transactionFingerprint)) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      return;
    }
    if (!currentManifest || !currentResource || !reference ||
        currentManifest.manifestFingerprint !== transaction.final.manifestFingerprint ||
        currentManifest.resourceProof !== transaction.final.resourceProof ||
        currentResource.resourceProof !== transaction.final.resourceProof ||
        currentManifest.applicationManifestFingerprint !==
          transaction.final.applicationManifestFingerprint ||
        currentResource.applicationManifestFingerprint !==
          transaction.final.applicationManifestFingerprint ||
        currentManifest.shawlManifestFingerprint !== transaction.final.shawlManifestFingerprint ||
        currentResource.shawlManifestFingerprint !== transaction.final.shawlManifestFingerprint ||
        currentManifest.serviceGeneration !== transaction.final.serviceGeneration ||
        currentResource.serviceGeneration !== transaction.final.serviceGeneration ||
        currentResource.operation !== transaction.operation ||
        currentResource.transactionId !== transaction.transactionId ||
        currentResource.transactionNonce !== transaction.transactionNonce ||
        currentManifest.resourceProof !== currentResource.resourceProof ||
        currentManifest.configurationFingerprint !== currentResource.configurationFingerprint ||
        currentManifest.rolesFingerprint !== currentResource.rolesFingerprint ||
        currentManifest.rolesFingerprint !== this.#rolesFingerprint ||
        !sameJson(currentManifest.roles, this.#config.roles) ||
        (startup !== null &&
         (startup.serviceGeneration !== transaction.final.serviceGeneration ||
          startup.applicationManifestFingerprint !== transaction.final.applicationManifestFingerprint ||
          startup.resourceProof !== transaction.final.resourceProof ||
          startup.transactionId !== transaction.transactionId)) ||
        reference.serviceKey !== serviceKey ||
        reference.serviceGeneration !== transaction.final.serviceGeneration ||
        reference.provisional !== null ||
        !this.#referenceSlotMatchesProof(reference.current, transaction.final, transaction) ||
        tombstone !== null) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
    }
    if (transaction.old.disposition === 'absent') {
      if (previousManifest || previousResource || reference.previous !== null ||
          currentManifest.predecessorManifestFingerprint !== null ||
          currentResource.predecessorResourceProof !== null) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      return;
    }
    const first = journal.entries.findIndex((entry) =>
      entry.transactionId === transaction.transactionId &&
      entry.transactionNonce === transaction.transactionNonce);
    const predecessor = journal.entries.slice(0, first).findLast((entry) =>
      entry.phase === 'committed');
    if (!predecessor || !previousManifest || !previousResource ||
        previousManifest.manifestFingerprint !== transaction.old.manifestFingerprint ||
        previousManifest.resourceProof !== transaction.old.resourceProof ||
        previousResource.resourceProof !== transaction.old.resourceProof ||
        previousManifest.applicationManifestFingerprint !==
          transaction.old.applicationManifestFingerprint ||
        previousResource.applicationManifestFingerprint !==
          transaction.old.applicationManifestFingerprint ||
        previousManifest.shawlManifestFingerprint !== transaction.old.shawlManifestFingerprint ||
        previousResource.shawlManifestFingerprint !== transaction.old.shawlManifestFingerprint ||
        previousManifest.serviceGeneration !== transaction.old.serviceGeneration ||
        previousResource.serviceGeneration !== transaction.old.serviceGeneration ||
        previousManifest.configurationFingerprint !== currentManifest.configurationFingerprint ||
        previousManifest.rolesFingerprint !== currentManifest.rolesFingerprint ||
        previousManifest.resourceProof !== previousResource.resourceProof ||
        previousManifest.configurationFingerprint !== previousResource.configurationFingerprint ||
        previousManifest.rolesFingerprint !== previousResource.rolesFingerprint ||
        currentManifest.predecessorManifestFingerprint !== previousManifest.manifestFingerprint ||
        currentResource.predecessorResourceProof !== previousResource.resourceProof ||
        !this.#referenceSlotMatchesProof(reference.previous, transaction.old, predecessor)) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
    }
  }

  #readArtifactCleanupIntents(operation) {
    const intents = [];
    const transactions = new Map(
      this.#namespaceEntries('transaction').map((entry) =>
        [entry.name, entry]),
    );
    const manifests = new Map(
      this.#namespaceEntries('manifest').map((entry) =>
        [entry.name, entry]),
    );
    for (const entry of this.#namespaceEntries('manual')) {
      let serviceKey;
      try {
        serviceKey = validateServiceKey(entry.name);
      } catch {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      const directory = this.#openInventoryDirectory(
        this.#namespaces.manual.handle,
        entry,
        operation,
      );
      try {
        const listing = this.#list(
          directory.handle,
          this.#artifact.handle,
        );
        if (listing.entries.some(({ name }) =>
          !MANUAL_FILE_SET.has(name))) {
          throwStore(
            'SERVICE_MANUAL_CLEANUP',
            operation,
            this.#calls.writes,
            true,
          );
        }
        const cleanup = this.#readInventoryRecord(
          directory.handle,
          SERVICE_STORE_LAYOUT.artifactCleanup,
          validateServiceArtifactCleanup,
          operation,
        );
        if (cleanup !== null) {
          this.#validateArtifactCleanupHost(
            cleanup,
            serviceKey,
            operation,
          );
          const transactionEntry = transactions.get(serviceKey);
          if (!transactionEntry) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          const journal = this.#readInventoryJournal(
            transactionEntry,
            serviceKey,
            { requireCommitted: false },
          );
          const transaction = journal.entries.find((candidate) =>
            candidate.transactionFingerprint ===
              cleanup.transactionFingerprint);
          this.#validateCleanupRecordJournal(
            cleanup,
            transaction,
            operation,
          );
          const manifestEntry = manifests.get(serviceKey);
          if (!manifestEntry) {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              operation,
              this.#calls.writes,
              true,
            );
          }
          const manifestDirectory = this.#openInventoryDirectory(
            this.#namespaces.manifest.handle,
            manifestEntry,
            operation,
          );
          try {
            const retainedRecord = this.#readInventoryRecord(
              manifestDirectory.handle,
              retainedDeploymentEnvelopeName(
                cleanup.purpose,
                cleanup.manifestFingerprint,
              ),
              validateRetainedDeploymentEnvelope,
              operation,
            );
            if (!retainedRecord ||
                retainedRecord.serviceKey !== serviceKey ||
                retainedRecord.platform !== this.#config.platform ||
                retainedRecord.architecture !==
                  this.#config.architecture ||
                retainedRecord.purpose !== cleanup.purpose ||
                retainedRecord.manifestFingerprint !==
                  cleanup.manifestFingerprint ||
                canonicalJsonHash(retainedRecord) !==
                  cleanup.retainedEnvelopeRecordSha256) {
              throwStore(
                'SERVICE_MANUAL_CLEANUP',
                operation,
                this.#calls.writes,
                true,
              );
            }
            const verified = this.#verifyRetainedDeploymentBytes(
              cleanup.purpose,
              decodeCanonicalBase64(
                retainedRecord.manifestBase64,
                DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
              ),
              decodeCanonicalBase64(
                retainedRecord.signatureBase64,
                DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes,
              ),
              operation,
              true,
            );
            const digest = cleanup.purpose === 'application'
              ? verified.manifest.archive.sha256
              : verified.manifest.executable.sha256;
            const size = cleanup.purpose === 'application'
              ? verified.manifest.archive.byteLength
              : verified.manifest.executable.byteLength;
            let provenanceMismatch = verified.purpose !== cleanup.purpose ||
              verified.manifestFingerprint !==
                cleanup.manifestFingerprint ||
              verified.signingKeyId !== cleanup.signingKeyId ||
              verified.signingKeyFingerprint !==
                cleanup.signingKeyFingerprint;
            if (cleanup.scope === 'published') {
              const tree = cleanup.purpose === 'application'
                ? verified.manifest.inventory.treeFingerprint
                : null;
              provenanceMismatch = provenanceMismatch ||
                digest !==
                  cleanup.artifactBinding.artifactFingerprint ||
                tree !== cleanup.artifactBinding.treeFingerprint;
            } else {
              provenanceMismatch = provenanceMismatch ||
                digest !== cleanup.assetSha256 ||
                size !== cleanup.assetSize;
            }
            if (provenanceMismatch) {
              throwStore(
                'SERVICE_MANUAL_CLEANUP',
                operation,
                this.#calls.writes,
                true,
              );
            }
            if (transaction.phase !== 'committed') {
              if (cleanup.scope !== 'scratch') {
                throwStore(
                  'SERVICE_MANUAL_CLEANUP',
                  operation,
                  this.#calls.writes,
                  true,
                );
              }
              this.#assertFloorAbandonEvidence(
                cleanup.purpose,
                transaction,
                cleanup.releaseSequence,
                cleanup.manifestFingerprint,
                operation,
              );
            }
          } finally {
            this.#calls.invoke(
              'close_service_handle',
              manifestDirectory.handle,
            );
          }
          intents.push(cleanup);
        }
      } finally {
        this.#calls.invoke(
          'close_service_handle',
          directory.handle,
        );
      }
    }
    const targets = new Set();
    const identities = new Set();
    for (const cleanup of intents) {
      if (cleanup.scope !== 'published') continue;
      const { artifactBinding } = cleanup;
      const target = `${artifactBinding.rootKind}:` +
        artifactBinding.artifactFingerprint;
      if (targets.has(target) ||
          identities.has(artifactBinding.directoryIdentityFingerprint)) {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      targets.add(target);
      identities.add(artifactBinding.directoryIdentityFingerprint);
    }
    return Object.freeze(intents);
  }

  #protectedArtifactCleanupIntents(operation) {
    try {
      return this.#readArtifactCleanupIntents(operation);
    } catch (error) {
      this.#throwArtifactCleanupFailure(error, operation);
    }
  }

  #assertNoArtifactCleanupConflict(
    artifact,
    operation,
    allowedCleanupFingerprint = null,
    intents = null,
  ) {
    for (const cleanup of intents ??
        this.#protectedArtifactCleanupIntents(operation)) {
      if (cleanup.scope !== 'published') continue;
      const relation = artifactPhysicalRelation(
        cleanup.artifactBinding,
        artifact,
      );
      if (relation === 'ambiguous') {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      if (relation === 'same' &&
          cleanup.cleanupFingerprint !== allowedCleanupFingerprint) {
        throwStore(
          'SERVICE_PENDING',
          operation,
          this.#calls.writes,
        );
      }
    }
  }

  #assertNoArtifactCleanupTarget(rootKind, artifactFingerprint, operation) {
    for (const cleanup of this.#protectedArtifactCleanupIntents(operation)) {
      if (cleanup.scope !== 'published') continue;
      if (cleanup.artifactBinding.rootKind === rootKind &&
          cleanup.artifactBinding.artifactFingerprint ===
            artifactFingerprint) {
        throwStore('SERVICE_PENDING', operation, this.#calls.writes);
      }
    }
  }

  #readCompleteReferenceInventory() {
    const transactionEntries = this.#namespaceEntries('transaction');
    const manifestEntries = this.#namespaceEntries('manifest');
    const tombstoneEntries = this.#namespaceEntries('tombstone');
    const manualEntries = this.#namespaceEntries('manual');
    const referenceListing = this.#list(this.#namespaces.reference.handle, this.#artifact.handle);
    if (referenceListing.entries.length > SERVICE_LIFECYCLE_LIMITS.expectedHostCount) {
      throwStore('SERVICE_PENDING', 'validate_reference_inventory', this.#calls.writes);
    }
    const transactionMap = new Map(transactionEntries.map((entry) => [entry.name, entry]));
    const manifestMap = new Map(manifestEntries.map((entry) => [entry.name, entry]));
    const tombstoneMap = new Map(tombstoneEntries.map((entry) => [entry.name, entry]));
    const manualMap = new Map(manualEntries.map((entry) => [entry.name, entry]));
    const referenceMap = new Map();
    for (const entry of referenceListing.entries) {
      const serviceKey = referenceServiceKey(entry.name);
      if (serviceKey === null) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      const record = this.#readInventoryRecord(
        this.#namespaces.reference.handle,
        entry.name,
        validateServiceReferenceRecord,
        'validate_reference_inventory',
      );
      if (!record || record.serviceKey !== serviceKey ||
          record.platform !== this.#config.platform ||
          record.architecture !== this.#config.architecture) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'validate_reference_inventory', this.#calls.writes, true);
      }
      referenceMap.set(serviceKey, record);
    }
    const serviceKeys = new Set([
      ...transactionMap.keys(),
      ...manifestMap.keys(),
      ...tombstoneMap.keys(),
      ...manualMap.keys(),
      ...referenceMap.keys(),
    ]);
    const cleanups = new Map();
    for (const serviceKey of serviceKeys) {
      const transactionEntry = transactionMap.get(serviceKey);
      const manualState = this.#readInventoryManual(
        manualMap.get(serviceKey),
        serviceKey,
      );
      if (!transactionEntry || manualState.manual !== null) {
        throwStore(
          manualState.manual !== null
            ? 'SERVICE_PENDING'
            : 'SERVICE_MANUAL_CLEANUP',
          'validate_reference_inventory',
          this.#calls.writes,
          manualState.manual === null,
        );
      }
      const journal = this.#readInventoryJournal(transactionEntry, serviceKey);
      if (manualState.cleanup !== null) {
        const cleanup = manualState.cleanup;
        const transaction = journal.entries.find((candidate) =>
          candidate.transactionFingerprint ===
            cleanup.transactionFingerprint);
        this.#validateCleanupRecordJournal(
          cleanup,
          transaction,
          'validate_reference_inventory',
        );
        if (transaction.phase !== 'committed') {
          if (cleanup.scope !== 'scratch') {
            throwStore(
              'SERVICE_MANUAL_CLEANUP',
              'validate_reference_inventory',
              this.#calls.writes,
              true,
            );
          }
          this.#assertFloorAbandonEvidence(
            cleanup.purpose,
            transaction,
            cleanup.releaseSequence,
            cleanup.manifestFingerprint,
            'validate_reference_inventory',
          );
        }
        cleanups.set(serviceKey, cleanup);
      }
      const records = this.#readInventoryManifest(manifestMap.get(serviceKey), serviceKey);
      const tombstone = this.#readInventoryTombstone(
        tombstoneMap.get(serviceKey),
        serviceKey,
      );
      this.#validateInventoryCommittedState(
        serviceKey,
        journal,
        records,
        referenceMap.get(serviceKey) ?? null,
        tombstone,
      );
    }
    return Object.freeze({
      listing: referenceListing,
      records: referenceMap,
      cleanups,
    });
  }

  #observeZeroReferences(artifact, allowedCleanupFingerprint = null) {
    const operation = 'observe_zero_references';
    this.#ensureOpen(operation);
    artifact = this.#snapshot(
      artifact,
      (value) => validateServiceArtifactBinding(value, this.#config.platform),
      operation,
    );
    if (artifact.artifactKind === 'shared-template') {
      throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    }
    const inventory = this.#readCompleteReferenceInventory();
    for (const cleanup of inventory.cleanups.values()) {
      if (cleanup.scope !== 'published') continue;
      const relation = artifactPhysicalRelation(
        cleanup.artifactBinding,
        artifact,
      );
      if (relation === 'ambiguous') {
        throwStore(
          'SERVICE_MANUAL_CLEANUP',
          operation,
          this.#calls.writes,
          true,
        );
      }
      if (relation === 'same' &&
          cleanup.cleanupFingerprint !== allowedCleanupFingerprint) {
        throwStore('SERVICE_PENDING', operation, this.#calls.writes);
      }
    }
    const listing = inventory.listing;
    const fingerprints = [];
    for (const entry of listing.entries) {
      const record = inventory.records.get(referenceServiceKey(entry.name));
      for (const slot of ['current', 'previous', 'provisional']) {
        for (const candidate of record[slot]?.artifacts ?? []) {
          const relation = artifactPhysicalRelation(candidate, artifact);
          if (relation === 'same') {
            throwStore('SERVICE_REFERENCED', 'observe_zero_references', this.#calls.writes);
          }
          if (relation === 'ambiguous') {
            throwStore('SERVICE_MANUAL_CLEANUP', 'observe_zero_references', this.#calls.writes, true);
          }
        }
      }
      fingerprints.push(record.referenceRecordFingerprint);
    }
    fingerprints.sort();
    return cloneJson(buildServiceZeroReferenceObservation({
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      artifactBindingFingerprint: artifact.bindingFingerprint,
      artifactRootKind: artifact.rootKind,
      artifactFingerprint: artifact.artifactFingerprint,
      artifactDirectoryIdentity: artifact.directoryIdentity,
      artifactDirectoryIdentityFingerprint: artifact.directoryIdentityFingerprint,
      artifactPhysicalTargetFingerprint: serviceArtifactPhysicalTargetFingerprint(
        artifact,
        this.#config.platform,
      ),
      controlRootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
      referenceDirectoryIdentity: cloneJson(listing.directoryIdentity),
      artifactLockIdentity: cloneJson(this.#artifact.identity),
      referenceRecordFingerprints: fingerprints,
    }));
  }

  handoffDriverLocks() {
    this.#ensureOpen('handoff_driver_locks');
    const binding = driverLockBindings.get(this.#driverLockHandoff);
    if (!binding || binding.token !== this.#token) {
      throwStore('SERVICE_STALE', 'handoff_driver_locks', this.#calls.writes);
    }
    return this.#driverLockHandoff;
  }

  readSiblingReferences() {
    this.#ensureOpen('read_sibling_references');
    const listing = this.#list(this.#namespaces.reference.handle, this.#artifact.handle);
    const siblings = [];
    for (const entry of listing.entries) {
      const serviceKey = referenceServiceKey(entry.name);
      if (serviceKey === null) throwStore('SERVICE_MANUAL_CLEANUP', 'read_sibling_references', this.#calls.writes, true);
      if (serviceKey === this.#config.serviceKey) continue;
      const receipt = this.#read(
        this.#namespaces.reference.handle,
        entry.name,
        validateServiceReferenceRecord,
        `sibling-reference:${serviceKey}`,
      );
      if (!receipt.present || receipt.value.platform !== this.#config.platform ||
          receipt.value.architecture !== this.#config.architecture) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_sibling_references', this.#calls.writes, true);
      }
      // systemd sibling probes protect the shared daemon template and the
      // active daemon instances only.  Bot records, tombstone-era records,
      // and deliberately empty reference records are not live siblings and
      // must never be forwarded as native service identities.
      if (receipt.value.component !== 'daemon' || receipt.value.current === null) continue;
      // Linux drivers need only the service identity.  The identity list is
      // derived under the artifact lock and is immutable for this session;
      // callers cannot supply a sibling list of their own.
      siblings.push(Object.freeze({ serviceKey }));
    }
    siblings.sort((left, right) => utf8Compare(left.serviceKey, right.serviceKey));
    return Object.freeze(siblings);
  }

  readPublicationReceipt(input) {
    this.#ensureOpen('read_publication_receipt');
    if (!plain(input) || Reflect.ownKeys(input).length !== 2 ||
        !['slot', 'artifactKind'].every((key) => Object.hasOwn(input, key)) ||
        !['current', 'previous', 'provisional'].includes(input.slot) ||
        !['application', 'shawl'].includes(input.artifactKind)) {
      throwStore('SERVICE_INVALID', 'read_publication_receipt', this.#calls.writes);
    }
    const references = this.readReferences();
    const slot = references.present ? references.value[input.slot] : null;
    const binding = slot?.artifacts?.find((artifact) => artifact.artifactKind === input.artifactKind) ?? null;
    if (binding === null) throwStore('SERVICE_STALE', 'read_publication_receipt', this.#calls.writes);
    const rootKind = input.artifactKind === 'application' ? 'releases' : 'shawl';
    let root = null;
    let directory = null;
    try {
      root = validateOwnedRootResult(
        this.#calls,
        this.#calls.invoke('open_service_root', rootKind, 'read-existing'),
        this.#config.platform,
        rootKind,
        this.#config.roles.management.value,
      );
      if (root.writes !== 0 || root.rootBinding.rolesFingerprint !== this.#root.rootBinding.rolesFingerprint) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_publication_receipt', this.#calls.writes, true);
      }
      directory = validateOwnedDirectoryResult(this.#calls, this.#calls.invoke(
        'open_service_directory', root.handle, binding.artifactFingerprint, 'read-existing',
        binding.directoryIdentity, this.#artifact.handle,
      ), this.#config.platform);
      if (directory.writes !== 0 || !sameJson(directory.identity, binding.directoryIdentity) ||
          canonicalJsonHash(directory.identity) !== binding.directoryIdentityFingerprint) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_publication_receipt', this.#calls.writes, true);
      }
    } finally {
      if (directory?.handle) { try { this.#calls.invoke('close_service_handle', directory.handle); } catch {} }
      if (root?.handle) { try { this.#calls.invoke('close_service_handle', root.handle); } catch {} }
    }
    const receipt = Object.freeze({ binding: cloneJson(binding) });
    publicationBindings.set(receipt, {
      token: this.#token,
      fingerprint: binding.bindingFingerprint,
    });
    this.#observedPublications.set(binding.bindingFingerprint, receipt);
    return receipt;
  }

  observeZeroReferences(artifact) {
    return this.#observeZeroReferences(artifact);
  }

  #observePublication(manifest, identity, kind) {
    const operation = `observe_${kind}_publication`;
    this.#ensureOpen(operation);
    if (this.#artifactCollectionActive) {
      throwStore('SERVICE_PENDING', operation, this.#calls.writes);
    }
    if (this.#artifactCleanupUncertain) {
      throwStore(
        'SERVICE_MANUAL_CLEANUP',
        operation,
        this.#calls.writes,
        true,
      );
    }
    this.#assertPinnedManifest(manifest, kind);
    manifest = this.#snapshot(
      manifest,
      kind === 'application' ? validateApplicationDeploymentManifest : validateShawlDeploymentManifest,
      operation,
    );
    identity = this.#snapshot(
      identity,
      (value) => validateServiceNativeIdentity(value, this.#config.platform, 'service-release-directory'),
      operation,
    );
    if (kind === 'application' && (manifest.target.platform !== this.#config.platform || manifest.target.architecture !== this.#config.architecture)) {
      throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    }
    if (kind === 'shawl' && this.#config.platform !== 'win32') throwStore('SERVICE_SCOPE_MISMATCH', operation, this.#calls.writes);
    const rootKind = kind === 'application' ? 'releases' : 'shawl';
    const artifactFingerprint = kind === 'application' ? manifest.archive.sha256 : manifest.executable.sha256;
    let root;
    let directory;
    try {
      const raw = this.#calls.invoke('open_service_root', rootKind, 'read-existing');
      if (raw === null) throwStore('SERVICE_STALE', operation, this.#calls.writes);
      root = validateOwnedRootResult(
        this.#calls,
        raw,
        this.#config.platform,
        rootKind,
        this.#config.roles.management.value,
      );
      if (root.writes !== 0 || root.rootBinding.rolesFingerprint !== this.#root.rootBinding.rolesFingerprint) {
        throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
      }
      directory = validateOwnedDirectoryResult(this.#calls, this.#calls.invoke(
        'open_service_directory', root.handle, artifactFingerprint, 'read-existing', identity, null,
      ), this.#config.platform);
      if (directory.writes !== 0) throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
      const binding = buildServiceArtifactBinding({
        artifactKind: kind,
        rootKind,
        artifactFingerprint,
        manifestFingerprint: manifest.manifestFingerprint,
        treeFingerprint: kind === 'application' ? manifest.inventory.treeFingerprint : null,
        directoryIdentity: cloneJson(directory.identity),
        directoryIdentityFingerprint: canonicalJsonHash(directory.identity),
      }, this.#config.platform);
      this.#assertNoArtifactCleanupConflict(
        binding,
        operation,
      );
      this.#calls.invoke('close_service_handle', directory.handle);
      directory = undefined;
      this.#calls.invoke('close_service_handle', root.handle);
      root = undefined;
      const receipt = Object.freeze({ binding: cloneJson(binding) });
      publicationBindings.set(receipt, { token: this.#token, fingerprint: binding.bindingFingerprint });
      this.#observedPublications.set(binding.bindingFingerprint, receipt);
      return receipt;
    } finally {
      if (directory?.handle) {
        try { this.#calls.invoke('close_service_handle', directory.handle); } catch {}
      }
      if (root?.handle) {
        try { this.#calls.invoke('close_service_handle', root.handle); } catch {}
      }
    }
  }

  observeApplicationPublication(manifest, identity) {
    return this.#observePublication(manifest, identity, 'application');
  }

  observeShawlPublication(manifest, identity) {
    return this.#observePublication(manifest, identity, 'shawl');
  }

  createSharedTemplateBinding(...args) {
    this.#ensureOpen('create_shared_template_binding');
    if (args.length !== 0 || this.#config.platform !== 'linux' || this.#config.component !== 'daemon') {
      throwStore('SERVICE_INVALID', 'create_shared_template_binding', this.#calls.writes);
    }
    // The binding is derived from the concrete template bytes while the
    // authenticated shared-template lock is held.  A caller-provided digest
    // is never accepted as authority.  Older/native-less fixtures cannot
    // produce this receipt and must remain safely pending before references
    // are published.
    const openScope = this.#calls.native.open_linux_service_scope;
    const readObject = this.#calls.native.read_linux_service_object;
    if (typeof openScope !== 'function' || typeof readObject !== 'function') {
      throwStore('SERVICE_PENDING', 'create_shared_template_binding', this.#calls.writes);
    }
    let scope = null;
    try {
      const opened = this.#calls.invoke('open_linux_service_scope', this.#config.roles, null, 'read-existing');
      if (!opened || typeof opened !== 'object' || opened.handle === null || opened.writes !== 0) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'create_shared_template_binding', this.#calls.writes, true);
      }
      scope = opened.handle;
      const result = this.#calls.invoke('read_linux_service_object', scope, 'daemon-template');
      const snapshot = result?.snapshot;
      if (!snapshot || snapshot.state !== 'file' || !Buffer.isBuffer(snapshot.bytes) ||
          !snapshot.facts || snapshot.facts.sha256 !== createHash('sha256').update(snapshot.bytes).digest('hex')) {
        throwStore('SERVICE_PENDING', 'create_shared_template_binding', this.#calls.writes);
      }
      const binding = cloneJson(buildServiceArtifactBinding({
        artifactKind: 'shared-template',
        rootKind: null,
        artifactFingerprint: snapshot.facts.sha256,
        manifestFingerprint: null,
        treeFingerprint: null,
        directoryIdentity: null,
        directoryIdentityFingerprint: null,
      }, this.#config.platform));
      this.#observedSharedTemplateBindings.add(binding.bindingFingerprint);
      return binding;
    } finally {
      if (scope !== null) {
        try { this.#calls.invoke('close_service_handle', scope); } catch {}
      }
    }
  }

  #historyReceiptMatches(receipt, logical, facts, recordSha256) {
    const native = this.#receiptNative(receipt, logical, 'read_floor_history');
    return sameJson(native.facts, facts) &&
      native.facts.sha256 === recordSha256 &&
      canonicalJsonHash(receipt.value) === recordSha256;
  }

  #validateHistoryCommon(record, scope, revision, directory, operation) {
    const identityFingerprint = serviceNativeIdentityFingerprint(
      directory.identity,
      this.#config.platform,
      'service-control-directory',
    );
    if (record.scope !== scope || record.revision !== revision ||
        record.platform !== this.#config.platform ||
        record.architecture !== this.#config.architecture ||
        record.rootBindingFingerprint !== this.#root.rootBinding.bindingFingerprint ||
        record.registrationFingerprint !== this.#registration.registrationFingerprint ||
        record.historyEntryIdentityFingerprint !== identityFingerprint ||
        !sameJson(record.historyEntryIdentity, directory.identity) ||
        record.historyEntryIdentity.owner !== this.#config.roles.management.value ||
        (record.floorFileFacts &&
         record.floorFileFacts.owner !== this.#config.roles.management.value) ||
        (record.witnessFileFacts &&
         record.witnessFileFacts.owner !== this.#config.roles.management.value) ||
        (record.previousFloorFileFacts &&
         record.previousFloorFileFacts.owner !== this.#config.roles.management.value) ||
        (record.previousWitnessFileFacts &&
         record.previousWitnessFileFacts.owner !== this.#config.roles.management.value)) {
      throwStore('SERVICE_MANUAL_CLEANUP', operation, this.#calls.writes, true);
    }
  }

  #readFloorHistory(scope) {
    const entries = this.#list(this.#history.handle, this.#artifact.handle).entries
      .map((entry) => ({
        entry,
        descriptor: parseFloorHistoryName(scope, entry.name),
      }))
      .filter(({ descriptor }) => descriptor !== null)
      .sort((left, right) => left.descriptor.revision - right.descriptor.revision);
    if (entries.length === 0 || entries.length > SERVICE_STORE_LIMITS.directoryEntries) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
    }
    let previousState = null;
    let latest = null;
    for (let index = 0; index < entries.length; index += 1) {
      const { entry, descriptor } = entries[index];
      const { revision } = descriptor;
      if (revision !== index || entry.name !== floorHistoryName(
        scope,
        revision,
        descriptor.action,
        descriptor.transactionFingerprint,
        descriptor.serviceKey,
      )) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
      }
      const directory = this.#historyDirectory(scope, revision, false, descriptor);
      if (!directory || !sameJson(directory.identity, entry.identity)) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
      }
      const names = this.#list(directory.handle, this.#artifact.handle).entries.map(({ name }) => name);
      const expected = revision === 0
        ? [SERVICE_STORE_LAYOUT.floorHistoryState]
        : [SERVICE_STORE_LAYOUT.floorHistoryIntent, SERVICE_STORE_LAYOUT.floorHistoryState];
      const preIntent = revision > 0 && names.length === 0;
      const pending = preIntent || (revision > 0 &&
        names.length === 1 &&
        names[0] === SERVICE_STORE_LAYOUT.floorHistoryIntent);
      if (!pending &&
          (names.length !== expected.length || names.some((name) => !expected.includes(name)))) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
      }
      let intent = null;
      if (revision > 0 && !preIntent) {
        if (descriptor.action === null || descriptor.transactionFingerprint === null ||
            descriptor.serviceKey === null) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
        }
        intent = this.#read(
          directory.handle,
          SERVICE_STORE_LAYOUT.floorHistoryIntent,
          validateServiceFloorHistoryIntent,
          `floor-history-intent:${scope}:${revision}`,
        );
        if (!intent.present) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
        }
        this.#validateHistoryCommon(intent.value, scope, revision, directory, 'read_floor_history');
        if (intent.value.action !== descriptor.action ||
            intent.value.transactionFingerprint !== descriptor.transactionFingerprint ||
            intent.value.serviceKey !== descriptor.serviceKey ||
            !previousState ||
            intent.value.previousHistoryStateFingerprint !== previousState.value.stateFingerprint ||
            intent.value.previousFloorFingerprint !== previousState.value.floorFingerprint ||
            intent.value.previousWitnessFingerprint !== previousState.value.witnessFingerprint ||
            intent.value.previousFloorRecordSha256 !== previousState.value.floorRecordSha256 ||
            intent.value.previousWitnessRecordSha256 !== previousState.value.witnessRecordSha256 ||
            !sameJson(intent.value.previousFloorFileFacts, previousState.value.floorFileFacts) ||
            !sameJson(intent.value.previousWitnessFileFacts, previousState.value.witnessFileFacts)) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
        }
      }
      let state = null;
      if (!pending) {
        state = this.#read(
          directory.handle,
          SERVICE_STORE_LAYOUT.floorHistoryState,
          validateServiceFloorHistoryState,
          `floor-history-state:${scope}:${revision}`,
        );
        if (!state.present) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
        }
        this.#validateHistoryCommon(state.value, scope, revision, directory, 'read_floor_history');
        if (state.value.previousHistoryStateFingerprint !==
              (previousState?.value.stateFingerprint ?? null) ||
            state.value.intentFingerprint !== (intent?.value.intentFingerprint ?? null)) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
        }
        if (intent &&
            (state.value.action !== intent.value.action ||
             state.value.component !== intent.value.component ||
             state.value.serviceKey !== intent.value.serviceKey ||
             state.value.transactionId !== intent.value.transactionId ||
             state.value.transactionNonce !== intent.value.transactionNonce ||
             state.value.transactionFingerprint !== intent.value.transactionFingerprint ||
             state.value.floorFingerprint !== intent.value.intendedFloor.floorFingerprint ||
             state.value.witnessFingerprint !== intent.value.stableWitness.witnessFingerprint ||
             state.value.floorRecordSha256 !== canonicalJsonHash(intent.value.intendedFloor) ||
             state.value.witnessRecordSha256 !== canonicalJsonHash(intent.value.stableWitness))) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
        }
        previousState = state;
      } else if (index !== entries.length - 1) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_floor_history', this.#calls.writes, true);
      }
      latest = Object.freeze({ revision, descriptor, directory, intent, state, previousState });
      if (index !== entries.length - 1) {
        this.#calls.invoke('close_service_handle', directory.handle);
        this.#historyDirectories.delete(entry.name);
      }
    }
    return latest;
  }

  #loadFloor(scope) {
    const floor = this.#read(this.#namespaces.floor.handle, floorName(scope), validateServiceSequenceFloor, `floor:${scope}`);
    const witness = this.#read(this.#namespaces.floor.handle, floorWitnessName(scope), validateServiceFloorWitness, `floor-witness:${scope}`);
    if (!floor.present || !witness.present || floor.value.scope !== scope || witness.value.scope !== scope ||
        witness.value.platform !== this.#config.platform || witness.value.architecture !== this.#config.architecture ||
        witness.value.rootBindingFingerprint !== this.#root.rootBinding.bindingFingerprint) {
      throwStore('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', this.#calls.writes, true);
    }
    const history = this.#readFloorHistory(scope);
    let historyPhase;
    if (history.state !== null) {
      if (history.revision !== floor.value.revision ||
          floorPairState(floor.value, witness.value) !== 'stable' ||
          history.state.value.floorFingerprint !== floor.value.floorFingerprint ||
          history.state.value.witnessFingerprint !== witness.value.witnessFingerprint ||
          floor.value.historyEntryIdentityFingerprint !==
            history.state.value.historyEntryIdentityFingerprint ||
          witness.value.historyEntryIdentityFingerprint !==
            history.state.value.historyEntryIdentityFingerprint ||
          floor.value.previousHistoryStateFingerprint !==
            history.state.value.previousHistoryStateFingerprint ||
          witness.value.previousHistoryStateFingerprint !==
            history.state.value.previousHistoryStateFingerprint ||
          !this.#historyReceiptMatches(
            floor,
            `floor:${scope}`,
            history.state.value.floorFileFacts,
            history.state.value.floorRecordSha256,
          ) ||
          !this.#historyReceiptMatches(
            witness,
            `floor-witness:${scope}`,
            history.state.value.witnessFileFacts,
            history.state.value.witnessRecordSha256,
          )) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', this.#calls.writes, true);
      }
      historyPhase = 'stable';
    } else {
      const floorNative = this.#receiptNative(floor, `floor:${scope}`, 'read_sequence_floor');
      const witnessNative = this.#receiptNative(
        witness,
        `floor-witness:${scope}`,
        'read_sequence_floor',
      );
      if (history.intent === null) {
        const previous = history.previousState;
        if (!previous ||
            floor.value.floorFingerprint !== previous.value.floorFingerprint ||
            witness.value.witnessFingerprint !== previous.value.witnessFingerprint ||
            !sameJson(floorNative.facts, previous.value.floorFileFacts) ||
            !sameJson(witnessNative.facts, previous.value.witnessFileFacts)) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', this.#calls.writes, true);
        }
        historyPhase = 'directory-intent';
        this.#floors.set(scope, {
          floor,
          witness,
          historyDirectory: history.directory,
          historyState: null,
          historyIntent: null,
          historyDescriptor: history.descriptor,
          previousHistoryState: previous,
          historyPhase,
        });
        return;
      }
      const intent = history.intent.value;
      const oldFloor = floor.value.floorFingerprint === intent.previousFloorFingerprint &&
        sameJson(floorNative.facts, intent.previousFloorFileFacts);
      const oldWitness = witness.value.witnessFingerprint === intent.previousWitnessFingerprint &&
        sameJson(witnessNative.facts, intent.previousWitnessFileFacts);
      const intendedFloor = floor.value.floorFingerprint === intent.intendedFloor.floorFingerprint &&
        sameJson(floor.value, intent.intendedFloor);
      const intendedWitness = witness.value.witnessFingerprint ===
          intent.intendedWitness.witnessFingerprint &&
        sameJson(witness.value, intent.intendedWitness);
      const stableWitness = witness.value.witnessFingerprint ===
          intent.stableWitness.witnessFingerprint &&
        sameJson(witness.value, intent.stableWitness);
      if (oldFloor && oldWitness) historyPhase = 'before';
      else if (oldFloor && intendedWitness) historyPhase = 'witness-intent';
      else if (intendedFloor && intendedWitness) historyPhase = 'floor-intent';
      else if (intendedFloor && stableWitness) historyPhase = 'stable-unrecorded';
      else throwStore('SERVICE_MANUAL_CLEANUP', 'read_sequence_floor', this.#calls.writes, true);
    }
    this.#floors.set(scope, {
      floor,
      witness,
      historyDirectory: history.directory,
      historyState: history.state,
      historyIntent: history.intent,
      historyDescriptor: history.descriptor,
      previousHistoryState: history.previousState,
      historyPhase,
    });
  }

  readFloor(scope) {
    this.#ensureOpen('read_sequence_floor');
    const pair = this.#floors.get(scope);
    if (!pair) throwStore('SERVICE_INVALID', 'read_sequence_floor', this.#calls.writes);
    return Object.freeze({
      floor: pair.floor.value,
      witness: pair.witness.value,
      pending: pair.historyPhase !== 'stable',
    });
  }

  assertFloorCas(input) {
    this.#ensureOpen('assert_floor_cas');
    if (!plain(input) || Reflect.ownKeys(input).some((key) =>
      !['applicationSequenceFloor', 'shawlSequenceFloor'].includes(key)) ||
        !Number.isSafeInteger(input.applicationSequenceFloor) ||
        input.applicationSequenceFloor < 0 ||
        (this.#config.platform === 'win32' &&
          (!Number.isSafeInteger(input.shawlSequenceFloor) || input.shawlSequenceFloor < 0))) {
      throwStore('SERVICE_INVALID', 'assert_floor_cas', this.#calls.writes);
    }
    const application = this.readFloor(`application:${this.#config.platform}:${this.#config.architecture}`);
    const shawl = this.#config.platform === 'win32' ? this.readFloor('shawl:win32:x64') : null;
    if (application.pending || (shawl && shawl.pending) ||
        application.floor.committedSequence !== input.applicationSequenceFloor ||
        (shawl && shawl.floor.committedSequence !== input.shawlSequenceFloor)) {
      throwStore('SERVICE_STALE', 'assert_floor_cas', this.#calls.writes);
    }
    return Object.freeze({ application, shawl });
  }

  acceptProvisionalMetadata(input) {
    this.#ensureOpen('accept_provisional_metadata');
    if (!plain(input) || Reflect.ownKeys(input).some((key) =>
      !['transaction', 'manifest', 'resource'].includes(key)) ||
        !input.transaction || !input.manifest || !input.resource) {
      throwStore('SERVICE_INVALID', 'accept_provisional_metadata', this.#calls.writes);
    }
    const transaction = this.#validateTransaction(input.transaction, 'accept_provisional_metadata');
    if (transaction.operation === 'uninstall' || transaction.phase !== 'prepared') {
      throwStore('SERVICE_PENDING', 'accept_provisional_metadata', this.#calls.writes);
    }
    const latest = this.readJournal().entries.at(-1);
    if (!latest || latest.phase !== 'prepared' || latest.substep !== 'none' ||
        this.#transactionIdentity(latest) !== this.#transactionIdentity(transaction)) {
      throwStore('SERVICE_PENDING', 'accept_provisional_metadata', this.#calls.writes);
    }
    const manifest = this.#snapshot(input.manifest, validateServiceManifest, 'accept_provisional_metadata');
    const resource = this.#snapshot(input.resource, validateServiceResourceProof, 'accept_provisional_metadata');
    this.#scope(manifest, 'accept_provisional_metadata');
    this.#scope(resource, 'accept_provisional_metadata');
    if (manifest.resourceProof !== resource.resourceProof ||
        manifest.serviceGeneration !== transaction.serviceGeneration ||
        resource.serviceGeneration !== transaction.serviceGeneration ||
        manifest.manifestFingerprint !== transaction.final.manifestFingerprint ||
        resource.resourceProof !== transaction.final.resourceProof ||
        manifest.applicationManifestFingerprint !== transaction.final.applicationManifestFingerprint ||
        resource.applicationManifestFingerprint !== transaction.final.applicationManifestFingerprint) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'accept_provisional_metadata', this.#calls.writes);
    }
    this.#provisionalMetadata = Object.freeze({
      transactionId: transaction.transactionId,
      transactionFingerprint: transaction.transactionFingerprint,
      manifest,
      resource,
    });
    return Object.freeze({ transactionFingerprint: transaction.transactionFingerprint });
  }

  #assertMetadataAdmission(transaction, manifest) {
    const provisional = this.#provisionalMetadata;
    if (provisional === null ||
        provisional.transactionId !== transaction.transactionId ||
        provisional.transactionFingerprint !== transaction.transactionFingerprint &&
          this.#transactionIdentity(transaction) !== this.#transactionIdentity({
            ...transaction,
            transactionFingerprint: provisional.transactionFingerprint,
          }) ||
        provisional.manifest.resourceProof !== manifest.resourceProof ||
        provisional.manifest.serviceGeneration !== manifest.serviceGeneration) {
      throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
    }
    const latest = this.#journal.entries.at(-1);
    if (!latest || this.#journal.pending !== null ||
        this.#transactionIdentity(latest) !== this.#transactionIdentity(transaction) ||
        latest.phase === 'prepared' || latest.phase === 'committed') {
      throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
    }
    const application = this.#floors.get(`application:${this.#config.platform}:${this.#config.architecture}`);
    if (!application) throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
    const admitted = (floor, expectedManifest, expectedSequence = undefined) => {
      const active = floor.activeReservation;
      if (active !== null) {
        return active.component === transaction.component &&
          active.serviceKey === transaction.serviceKey &&
          active.transactionId === transaction.transactionId &&
          active.transactionNonce === transaction.transactionNonce &&
          this.#sameRetainedTransactionIdentity(active.transactionFingerprint, transaction) &&
          (expectedSequence === undefined || active.sequence === expectedSequence) &&
          active.manifestFingerprint === expectedManifest;
      }
      return (expectedSequence === undefined || floor.committedSequence === expectedSequence) &&
        floor.committedManifestFingerprint === expectedManifest &&
        floor.committedTransactionId === transaction.transactionId &&
        floor.committedTransactionNonce === transaction.transactionNonce &&
        this.#sameRetainedTransactionIdentity(floor.committedTransactionFingerprint, transaction);
    };
    if (application.historyPhase !== 'stable' || !admitted(application.floor.value,
      transaction.candidate.applicationManifestFingerprint, transaction.candidate.releaseSequence)) {
      throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
    }
    if (this.#config.platform === 'win32') {
      const shawl = this.#floors.get('shawl:win32:x64');
      if (!shawl || shawl.historyPhase !== 'stable' || !admitted(
        shawl.floor.value, transaction.candidate.shawlManifestFingerprint)) {
        throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
      }
    }
    const publication = [...this.#observedPublications.values()].some((receipt) =>
      receipt.binding.manifestFingerprint === transaction.candidate.applicationManifestFingerprint);
    if (!publication) throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
    if (this.#config.platform === 'win32' && ![...this.#observedPublications.values()].some((receipt) =>
      receipt.binding.manifestFingerprint === transaction.candidate.shawlManifestFingerprint)) {
      throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
    }
  }

  publishCurrentMetadata(input) {
    this.#ensureWritable('publish_current_metadata');
    if (!plain(input) || Reflect.ownKeys(input).some((key) =>
      !['transaction', 'manifest', 'resource', 'expectedManifest', 'expectedResource'].includes(key)) ||
        !input.transaction || !input.manifest || !input.resource ||
        !input.expectedManifest || !input.expectedResource) {
      throwStore('SERVICE_INVALID', 'publish_current_metadata', this.#calls.writes);
    }
    const transaction = this.#validateTransaction(input.transaction, 'publish_current_metadata');
    if (transaction.operation === 'uninstall') throwStore('SERVICE_PENDING', 'publish_current_metadata', this.#calls.writes);
    const manifest = this.#snapshot(input.manifest, validateServiceManifest, 'publish_current_metadata');
    const resource = this.#snapshot(input.resource, validateServiceResourceProof, 'publish_current_metadata');
    this.#scope(manifest, 'publish_current_metadata'); this.#scope(resource, 'publish_current_metadata');
    if (manifest.resourceProof !== resource.resourceProof ||
        manifest.serviceGeneration !== transaction.serviceGeneration ||
        resource.serviceGeneration !== transaction.serviceGeneration ||
        manifest.manifestFingerprint !== transaction.final.manifestFingerprint ||
        resource.resourceProof !== transaction.final.resourceProof) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'publish_current_metadata', this.#calls.writes);
    }
    this.#assertMetadataAdmission(transaction, manifest);
    const currentManifest = this.#boundReceipt(input.expectedManifest, 'manifest:current', 'publish_current_metadata');
    const currentResource = this.#boundReceipt(input.expectedResource, 'resource:current', 'publish_current_metadata');
    if (currentManifest.native === null || currentResource.native === null) throwStore('SERVICE_STALE', 'publish_current_metadata', this.#calls.writes);
    // This is the single store-accepted pair transition.  The two files are
    // written under one authenticated session and never independently exposed
    // through the lifecycle facade.
    this.#metadataPairMutation = true;
    try {
      const nextResource = this.#publishService('manifest', SERVICE_STORE_LAYOUT.resourceFiles.current, resource, validateServiceResourceProof, input.expectedResource, 'resource:current');
      const nextManifest = this.#publishService('manifest', SERVICE_STORE_LAYOUT.manifestFiles.current, manifest, validateServiceManifest, input.expectedManifest, 'manifest:current');
      this.#provisionalMetadata = null;
      return Object.freeze({ manifest: nextManifest, resource: nextResource });
    } finally {
      this.#metadataPairMutation = false;
    }
  }

  #transaction(value, operation) {
    const transaction = this.#validateTransaction(value, operation);
    if (!['install', 'update'].includes(transaction.operation)) throwStore('SERVICE_INVALID', operation, this.#calls.writes);
    this.#authorizeRecoveryTransaction(transaction, operation);
    return {
      transaction,
      transactionId: transaction.transactionId,
      transactionNonce: transaction.transactionNonce,
    };
  }

  #applyFloor(scope, nextFields, transaction, action) {
    this.#ensureWritable('transition_sequence_floor');
    const pair = this.#floors.get(scope);
    if (!pair) throwStore('SERVICE_INVALID', 'transition_sequence_floor', this.#calls.writes);
    const descriptor = {
      action,
      transactionFingerprint: transaction.transactionFingerprint,
      serviceKey: transaction.serviceKey,
    };
    let historyDirectory;
    let historyIntent;
    let next;
    let intendedWitness;
    let stableWitness;
    if (pair.historyPhase !== 'stable') {
      const pending = pair.historyDescriptor;
      if (!pending || pending.action !== action ||
          pending.transactionFingerprint !== transaction.transactionFingerprint ||
          pending.serviceKey !== transaction.serviceKey) {
        throwStore('SERVICE_PENDING', 'transition_sequence_floor', this.#calls.writes);
      }
      historyDirectory = pair.historyDirectory;
      if (pair.historyIntent === null) {
        const previousState = pair.previousHistoryState;
        if (!previousState || pending.revision !== pair.floor.value.revision + 1 ||
            nextFields.revision !== pending.revision) {
          throwStore('SERVICE_MANUAL_CLEANUP', 'transition_sequence_floor', this.#calls.writes, true);
        }
        const historyEntryIdentityFingerprint = serviceNativeIdentityFingerprint(
          historyDirectory.identity,
          this.#config.platform,
          'service-control-directory',
        );
        next = buildServiceSequenceFloor({
          ...nextFields,
          historyEntryIdentityFingerprint,
          previousHistoryStateFingerprint: previousState.value.stateFingerprint,
        });
        intendedWitness = buildServiceFloorWitness({
          scope,
          platform: this.#config.platform,
          architecture: this.#config.architecture,
          rootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
          revision: next.revision,
          historyEntryIdentityFingerprint,
          previousHistoryStateFingerprint: previousState.value.stateFingerprint,
          state: 'intent',
          action,
          component: transaction.component,
          serviceKey: transaction.serviceKey,
          currentFloorFingerprint: pair.floor.value.floorFingerprint,
          intendedFloorFingerprint: next.floorFingerprint,
          transactionId: transaction.transactionId,
          transactionNonce: transaction.transactionNonce,
          transactionFingerprint: transaction.transactionFingerprint,
        });
        stableWitness = buildServiceFloorWitness({
          scope,
          platform: this.#config.platform,
          architecture: this.#config.architecture,
          rootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
          revision: next.revision,
          historyEntryIdentityFingerprint,
          previousHistoryStateFingerprint: previousState.value.stateFingerprint,
          state: 'stable',
          action: null,
          component: null,
          serviceKey: null,
          currentFloorFingerprint: next.floorFingerprint,
          intendedFloorFingerprint: null,
          transactionId: null,
          transactionNonce: null,
          transactionFingerprint: null,
        });
        const previousFloorNative = this.#receiptNative(
          pair.floor,
          `floor:${scope}`,
          'transition_sequence_floor',
        );
        const previousWitnessNative = this.#receiptNative(
          pair.witness,
          `floor-witness:${scope}`,
          'transition_sequence_floor',
        );
        const intent = buildServiceFloorHistoryIntent({
          scope,
          platform: this.#config.platform,
          architecture: this.#config.architecture,
          rootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
          registrationFingerprint: this.#registration.registrationFingerprint,
          revision: next.revision,
          action,
          component: transaction.component,
          serviceKey: transaction.serviceKey,
          transactionId: transaction.transactionId,
          transactionNonce: transaction.transactionNonce,
          transactionFingerprint: transaction.transactionFingerprint,
          historyEntryIdentity: cloneJson(historyDirectory.identity),
          historyEntryIdentityFingerprint,
          previousHistoryStateFingerprint: previousState.value.stateFingerprint,
          previousFloorFingerprint: pair.floor.value.floorFingerprint,
          previousWitnessFingerprint: pair.witness.value.witnessFingerprint,
          previousFloorRecordSha256: canonicalJsonHash(pair.floor.value),
          previousWitnessRecordSha256: canonicalJsonHash(pair.witness.value),
          previousFloorFileFacts: cloneJson(previousFloorNative.facts),
          previousWitnessFileFacts: cloneJson(previousWitnessNative.facts),
          intendedFloor: next,
          intendedWitness,
          stableWitness,
        });
        pair.historyIntent = this.#publish(
          historyDirectory.handle,
          SERVICE_STORE_LAYOUT.floorHistoryIntent,
          intent,
          validateServiceFloorHistoryIntent,
          this.#makeReceipt(
            `floor-history-intent:${scope}:${next.revision}`,
            null,
            null,
          ),
          `floor-history-intent:${scope}:${next.revision}`,
          this.#artifact.handle,
        );
        pair.historyPhase = 'before';
      } else {
        historyIntent = pair.historyIntent.value;
        next = historyIntent.intendedFloor;
        intendedWitness = historyIntent.intendedWitness;
        stableWitness = historyIntent.stableWitness;
        if (historyIntent.action !== action ||
            historyIntent.component !== transaction.component ||
            historyIntent.serviceKey !== transaction.serviceKey ||
            historyIntent.transactionId !== transaction.transactionId ||
            historyIntent.transactionNonce !== transaction.transactionNonce ||
            historyIntent.transactionFingerprint !== transaction.transactionFingerprint ||
            Object.entries(nextFields).some(([key, value]) => !sameJson(next[key], value))) {
          throwStore('SERVICE_PENDING', 'transition_sequence_floor', this.#calls.writes);
        }
      }
    } else {
      const previousState = pair.historyState;
      if (!previousState || nextFields.revision !== pair.floor.value.revision + 1) {
        throwStore('SERVICE_MANUAL_CLEANUP', 'transition_sequence_floor', this.#calls.writes, true);
      }
      historyDirectory = this.#historyDirectory(
        scope,
        nextFields.revision,
        true,
        descriptor,
      );
      this.#releaseHistoryDirectory(pair.historyDirectory);
      pair.historyDirectory = historyDirectory;
      pair.historyDescriptor = Object.freeze({
        revision: nextFields.revision,
        ...descriptor,
      });
      pair.previousHistoryState = previousState;
      pair.historyState = null;
      pair.historyIntent = null;
      pair.historyPhase = 'directory-intent';
      return this.#applyFloor(scope, nextFields, transaction, action);
    }
    historyIntent ??= pair.historyIntent.value;
    next ??= historyIntent.intendedFloor;
    intendedWitness ??= historyIntent.intendedWitness;
    stableWitness ??= historyIntent.stableWitness;
    if (pair.historyPhase === 'before' || pair.historyPhase === 'directory-intent') {
      pair.witness = this.#publish(
        this.#namespaces.floor.handle,
        floorWitnessName(scope),
        intendedWitness,
        validateServiceFloorWitness,
        pair.witness,
        `floor-witness:${scope}`,
        this.#artifact.handle,
      );
      pair.historyPhase = 'witness-intent';
    }
    if (pair.historyPhase === 'witness-intent') {
      pair.floor = this.#publish(
        this.#namespaces.floor.handle,
        floorName(scope),
        next,
        validateServiceSequenceFloor,
        pair.floor,
        `floor:${scope}`,
        this.#artifact.handle,
      );
      pair.historyPhase = 'floor-intent';
    }
    if (pair.historyPhase === 'floor-intent') {
      pair.witness = this.#publish(
        this.#namespaces.floor.handle,
        floorWitnessName(scope),
        stableWitness,
        validateServiceFloorWitness,
        pair.witness,
        `floor-witness:${scope}`,
        this.#artifact.handle,
      );
      pair.historyPhase = 'stable-unrecorded';
    }
    if (pair.historyPhase !== 'stable-unrecorded') {
      throwStore('SERVICE_MANUAL_CLEANUP', 'transition_sequence_floor', this.#calls.writes, true);
    }
    const floorNative = this.#receiptNative(pair.floor, `floor:${scope}`, 'transition_sequence_floor');
    const witnessNative = this.#receiptNative(
      pair.witness,
      `floor-witness:${scope}`,
      'transition_sequence_floor',
    );
    const state = buildServiceFloorHistoryState({
      scope,
      platform: this.#config.platform,
      architecture: this.#config.architecture,
      rootBindingFingerprint: this.#root.rootBinding.bindingFingerprint,
      registrationFingerprint: this.#registration.registrationFingerprint,
      revision: next.revision,
      action,
      component: transaction.component,
      serviceKey: transaction.serviceKey,
      transactionId: transaction.transactionId,
      transactionNonce: transaction.transactionNonce,
      transactionFingerprint: transaction.transactionFingerprint,
      historyEntryIdentity: cloneJson(historyDirectory.identity),
      historyEntryIdentityFingerprint: next.historyEntryIdentityFingerprint,
      previousHistoryStateFingerprint: next.previousHistoryStateFingerprint,
      intentFingerprint: historyIntent.intentFingerprint,
      floorFingerprint: next.floorFingerprint,
      witnessFingerprint: stableWitness.witnessFingerprint,
      floorRecordSha256: canonicalJsonHash(next),
      witnessRecordSha256: canonicalJsonHash(stableWitness),
      floorFileFacts: cloneJson(floorNative.facts),
      witnessFileFacts: cloneJson(witnessNative.facts),
    });
    pair.historyState = this.#publish(
      historyDirectory.handle,
      SERVICE_STORE_LAYOUT.floorHistoryState,
      state,
      validateServiceFloorHistoryState,
      this.#makeReceipt(`floor-history-state:${scope}:${next.revision}`, null, null),
      `floor-history-state:${scope}:${next.revision}`,
      this.#artifact.handle,
    );
    pair.historyPhase = 'stable';
    return this.readFloor(scope);
  }

  #reserve(scope, manifest, transaction, currentSequence, kind) {
    this.#ensureWritable(`reserve_${kind}_sequence`);
    if (!Number.isSafeInteger(currentSequence) || currentSequence < 0) throwStore('SERVICE_INVALID', `reserve_${kind}_sequence`, this.#calls.writes);
    const tx = this.#transaction(transaction, `reserve_${kind}_sequence`);
    transaction = tx.transaction;
    const transactionManifestFingerprint = kind === 'application'
      ? transaction.candidate.applicationManifestFingerprint
      : transaction.candidate.shawlManifestFingerprint;
    if (transactionManifestFingerprint !== manifest.manifestFingerprint ||
        (kind === 'application' && transaction.candidate.releaseSequence !== manifest.releaseSequence)) {
      throwStore('SERVICE_SCOPE_MISMATCH', `reserve_${kind}_sequence`, this.#calls.writes);
    }
    const pair = this.#floors.get(scope);
    const current = pair.floor.value;
    const sequence = manifest.releaseSequence;
    const manifestFingerprint = manifest.manifestFingerprint;
    if (kind === 'application' && transaction.operation === 'update' &&
        sequence <= currentSequence) {
      throwStore('RELEASE_SEQUENCE_NOT_ADVANCING', `reserve_${kind}_sequence`, this.#calls.writes);
    }
    if (current.activeReservation) {
      const active = current.activeReservation;
      if (active.transactionId !== tx.transactionId || active.transactionNonce !== tx.transactionNonce ||
          !this.#sameRetainedTransactionIdentity(
            active.transactionFingerprint,
            transaction,
          ) ||
          active.component !== transaction.component ||
          active.serviceKey !== transaction.serviceKey ||
          active.sequence !== sequence || active.manifestFingerprint !== manifestFingerprint) {
        throwStore('RELEASE_SEQUENCE_RESERVED', `reserve_${kind}_sequence`, this.#calls.writes);
      }
      if (pair.historyPhase === 'stable') return this.readFloor(scope);
    }
    if (sequence < current.highestReservedSequence) throwStore('RELEASE_SEQUENCE_DOWNGRADE', `reserve_${kind}_sequence`, this.#calls.writes);
    if (sequence === current.highestReservedSequence && current.highestReservedSequence > 0 &&
        manifestFingerprint !== current.highestReservedManifestFingerprint) {
      throwStore('RELEASE_SEQUENCE_CONFLICT', `reserve_${kind}_sequence`, this.#calls.writes);
    }
    const next = pair.historyPhase !== 'stable' && pair.historyIntent !== null
      ? floorTransitionFields(pair.historyIntent.value.intendedFloor)
      : current.activeReservation !== null
        ? floorTransitionFields(current)
        : {
        scope,
        revision: current.revision + 1,
        highestReservedSequence: Math.max(sequence, current.highestReservedSequence),
        highestReservedManifestFingerprint: sequence > current.highestReservedSequence
          ? manifestFingerprint : current.highestReservedManifestFingerprint,
        committedSequence: current.committedSequence,
        committedManifestFingerprint: current.committedManifestFingerprint,
        committedPublicationFingerprint: current.committedPublicationFingerprint,
        committedTransactionId: current.committedTransactionId,
        committedTransactionNonce: current.committedTransactionNonce,
        committedTransactionFingerprint: current.committedTransactionFingerprint,
        activeReservation: {
          component: transaction.component,
          serviceKey: transaction.serviceKey,
          transactionId: tx.transactionId,
          transactionNonce: tx.transactionNonce,
          transactionFingerprint: transaction.transactionFingerprint,
          sequence,
          manifestFingerprint,
        },
      };
    return this.#applyFloor(scope, next, transaction, 'reserve');
  }

  reserveApplicationSequence(input) {
    if (!exact(input, ['manifest', 'transaction', 'currentSequence'])) {
      throwStore('SERVICE_INVALID', 'reserve_application_sequence', this.#calls.writes);
    }
    const { transaction, currentSequence } = input;
    this.#assertPinnedManifest(input.manifest, 'application');
    const manifest = this.#snapshot(input.manifest, validateApplicationDeploymentManifest, 'reserve_application_sequence');
    if (manifest.target.platform !== this.#config.platform || manifest.target.architecture !== this.#config.architecture) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'reserve_application_sequence', this.#calls.writes);
    }
    return this.#reserve(`application:${this.#config.platform}:${this.#config.architecture}`, manifest, transaction, currentSequence, 'application');
  }

  reserveShawlSequence(input) {
    this.#requireShawl('reserve_shawl_sequence');
    if (!exact(input, ['manifest', 'transaction', 'currentSequence'])) {
      throwStore('SERVICE_INVALID', 'reserve_shawl_sequence', this.#calls.writes);
    }
    const { transaction, currentSequence } = input;
    this.#assertPinnedManifest(input.manifest, 'shawl');
    const manifest = this.#snapshot(input.manifest, validateShawlDeploymentManifest, 'reserve_shawl_sequence');
    return this.#reserve('shawl:win32:x64', manifest, transaction, currentSequence, 'shawl');
  }

  #publication(receipt, manifestFingerprint, kind, operation) {
    const state = publicationBindings.get(receipt);
    if (!state || state.token !== this.#token || receipt.binding.artifactKind !== kind ||
        receipt.binding.manifestFingerprint !== manifestFingerprint || state.fingerprint !== receipt.binding.bindingFingerprint) {
      throwStore('SERVICE_STALE', operation, this.#calls.writes);
    }
    return receipt.binding;
  }

  #commit(scope, manifest, transaction, publication, kind) {
    this.#ensureWritable(`commit_${kind}_sequence`);
    const tx = this.#transaction(transaction, `commit_${kind}_sequence`);
    const pair = this.#floors.get(scope);
    const current = pair.floor.value;
    const binding = this.#publication(publication, manifest.manifestFingerprint, kind, `commit_${kind}_sequence`);
    const active = current.activeReservation;
    if (!active && pair.historyPhase === 'stable' &&
        current.committedTransactionId === tx.transactionId &&
        current.committedTransactionNonce === tx.transactionNonce &&
        this.#sameRetainedTransactionIdentity(
          current.committedTransactionFingerprint,
          tx.transaction,
        ) &&
        current.committedSequence === manifest.releaseSequence &&
        current.committedManifestFingerprint === manifest.manifestFingerprint &&
        current.committedPublicationFingerprint === binding.bindingFingerprint) {
      return this.readFloor(scope);
    }
    if (pair.historyPhase !== 'stable' && pair.historyIntent !== null) {
      const intended = pair.historyIntent.value.intendedFloor;
      if (intended.committedSequence !== manifest.releaseSequence ||
          intended.committedManifestFingerprint !== manifest.manifestFingerprint ||
          intended.committedPublicationFingerprint !== binding.bindingFingerprint) {
        throwStore('SERVICE_PENDING', `commit_${kind}_sequence`, this.#calls.writes);
      }
      return this.#applyFloor(
        scope,
        floorTransitionFields(intended),
        tx.transaction,
        'commit',
      );
    }
    if (!active || active.transactionId !== tx.transactionId || active.transactionNonce !== tx.transactionNonce ||
        !this.#sameRetainedTransactionIdentity(
          active.transactionFingerprint,
          tx.transaction,
        ) ||
        active.component !== tx.transaction.component ||
        active.serviceKey !== tx.transaction.serviceKey ||
        active.sequence !== manifest.releaseSequence || active.manifestFingerprint !== manifest.manifestFingerprint) {
      throwStore('RELEASE_SEQUENCE_RESERVED', `commit_${kind}_sequence`, this.#calls.writes);
    }
    return this.#applyFloor(
      scope,
      {
        scope,
        revision: current.revision + 1,
        highestReservedSequence: current.highestReservedSequence,
        highestReservedManifestFingerprint: current.highestReservedManifestFingerprint,
        committedSequence: active.sequence,
        committedManifestFingerprint: active.manifestFingerprint,
        committedPublicationFingerprint: binding.bindingFingerprint,
        committedTransactionId: tx.transactionId,
        committedTransactionNonce: tx.transactionNonce,
        committedTransactionFingerprint: tx.transaction.transactionFingerprint,
        activeReservation: null,
      },
      tx.transaction,
      'commit',
    );
  }

  commitApplicationSequence(input) {
    if (!exact(input, ['manifest', 'transaction', 'publication'])) {
      throwStore('SERVICE_INVALID', 'commit_application_sequence', this.#calls.writes);
    }
    const { transaction, publication } = input;
    this.#assertPinnedManifest(input.manifest, 'application');
    const manifest = this.#snapshot(input.manifest, validateApplicationDeploymentManifest, 'commit_application_sequence');
    if (manifest.target.platform !== this.#config.platform || manifest.target.architecture !== this.#config.architecture) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'commit_application_sequence', this.#calls.writes);
    }
    return this.#commit(`application:${this.#config.platform}:${this.#config.architecture}`, manifest, transaction, publication, 'application');
  }

  commitShawlSequence(input) {
    this.#requireShawl('commit_shawl_sequence');
    if (!exact(input, ['manifest', 'transaction', 'publication'])) {
      throwStore('SERVICE_INVALID', 'commit_shawl_sequence', this.#calls.writes);
    }
    const { transaction, publication } = input;
    this.#assertPinnedManifest(input.manifest, 'shawl');
    const manifest = this.#snapshot(input.manifest, validateShawlDeploymentManifest, 'commit_shawl_sequence');
    return this.#commit('shawl:win32:x64', manifest, transaction, publication, 'shawl');
  }

  #abandon(scope, transaction, kind) {
    this.#ensureWritable(`abandon_${kind}_sequence`);
    const tx = this.#transaction(transaction, `abandon_${kind}_sequence`);
    const pair = this.#floors.get(scope);
    const current = pair.floor.value;
    const active = current.activeReservation;
    if (pair.historyPhase !== 'stable' && pair.historyIntent !== null) {
      return this.#applyFloor(
        scope,
        floorTransitionFields(pair.historyIntent.value.intendedFloor),
        tx.transaction,
        'abandon',
      );
    }
    if (!active || active.transactionId !== tx.transactionId || active.transactionNonce !== tx.transactionNonce ||
        !this.#sameRetainedTransactionIdentity(
          active.transactionFingerprint,
          tx.transaction,
        ) ||
        active.component !== tx.transaction.component ||
        active.serviceKey !== tx.transaction.serviceKey) {
      throwStore('RELEASE_SEQUENCE_RESERVED', `abandon_${kind}_sequence`, this.#calls.writes);
    }
    return this.#applyFloor(
      scope,
      {
        scope,
        revision: current.revision + 1,
        highestReservedSequence: current.highestReservedSequence,
        highestReservedManifestFingerprint: current.highestReservedManifestFingerprint,
        committedSequence: current.committedSequence,
        committedManifestFingerprint: current.committedManifestFingerprint,
        committedPublicationFingerprint: current.committedPublicationFingerprint,
        committedTransactionId: current.committedTransactionId,
        committedTransactionNonce: current.committedTransactionNonce,
        committedTransactionFingerprint: current.committedTransactionFingerprint,
        activeReservation: null,
      },
      tx.transaction,
      'abandon',
    );
  }

  abandonApplicationSequence(input) {
    if (!exact(input, ['transaction'])) {
      throwStore('SERVICE_INVALID', 'abandon_application_sequence', this.#calls.writes);
    }
    return this.#abandon(`application:${this.#config.platform}:${this.#config.architecture}`, input.transaction, 'application');
  }

  abandonShawlSequence(input) {
    this.#requireShawl('abandon_shawl_sequence');
    if (!exact(input, ['transaction'])) {
      throwStore('SERVICE_INVALID', 'abandon_shawl_sequence', this.#calls.writes);
    }
    return this.#abandon('shawl:win32:x64', input.transaction, 'shawl');
  }

  #assertRollback(scope, manifest, publication, kind) {
    this.#ensureOpen(`assert_${kind}_rollback`);
    const references = this.readReferences();
    const retained = references.value?.previous?.artifacts.find(
      (artifact) => artifact.artifactKind === kind,
    );
    const binding = this.#publication(
      publication,
      manifest.manifestFingerprint,
      kind,
      `assert_${kind}_rollback`,
    );
    if (!references.present || !retained ||
        retained.bindingFingerprint !== binding.bindingFingerprint) {
      throwStore('SERVICE_SCOPE_MISMATCH', `assert_${kind}_rollback`, this.#calls.writes);
    }
    const pair = this.#floors.get(scope);
    if (pair.witness.value.state !== 'stable' || pair.floor.value.committedSequence === 0 ||
        manifest.releaseSequence > pair.floor.value.highestReservedSequence) {
      throwStore('RELEASE_SEQUENCE_DOWNGRADE', `assert_${kind}_rollback`, this.#calls.writes);
    }
    return Object.freeze({
      scope,
      retainedManifestFingerprint: manifest.manifestFingerprint,
      retainedSequence: manifest.releaseSequence,
      floorFingerprint: pair.floor.value.floorFingerprint,
    });
  }

  assertApplicationRollback(input) {
    if (!exact(input, ['manifest', 'publication'])) {
      throwStore('SERVICE_INVALID', 'assert_application_rollback', this.#calls.writes);
    }
    const { publication } = input;
    this.#assertPinnedManifest(input.manifest, 'application');
    const manifest = this.#snapshot(input.manifest, validateApplicationDeploymentManifest, 'assert_application_rollback');
    if (manifest.target.platform !== this.#config.platform || manifest.target.architecture !== this.#config.architecture) {
      throwStore('SERVICE_SCOPE_MISMATCH', 'assert_application_rollback', this.#calls.writes);
    }
    return this.#assertRollback(
      `application:${this.#config.platform}:${this.#config.architecture}`,
      manifest,
      publication,
      'application',
    );
  }

  assertShawlRollback(input) {
    this.#requireShawl('assert_shawl_rollback');
    if (!exact(input, ['manifest', 'publication'])) {
      throwStore('SERVICE_INVALID', 'assert_shawl_rollback', this.#calls.writes);
    }
    const { publication } = input;
    this.#assertPinnedManifest(input.manifest, 'shawl');
    const manifest = this.#snapshot(input.manifest, validateShawlDeploymentManifest, 'assert_shawl_rollback');
    return this.#assertRollback('shawl:win32:x64', manifest, publication, 'shawl');
  }

  readShawlFloor() {
    this.#requireShawl('read_shawl_floor');
    return this.readFloor('shawl:win32:x64');
  }

  #requireShawl(operation) {
    if (this.#config.platform !== 'win32') throwStore('SERVICE_UNSUPPORTED', operation, this.#calls.writes);
  }
}
