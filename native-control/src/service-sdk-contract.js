import { createHash } from 'node:crypto';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  buildSdkExternalStateContract,
} from '@gjc-remote/shared/deployment-envelope';
import { assertStrictText, canonicalJsonBytes, utf8Compare } from '@gjc-remote/shared/strict-json';

export const SDK_EXTERNAL_STATE_REQUIREMENTS = Object.freeze({
  packageName: '@gajae-code/coding-agent',
  packageVersion: '0.16.7',
  lockIntegrity: 'sha512-rqhs7FELytNw0zfumqroc5EaVrtEUccGGp4YNpFbycF89o+Q+dzWWof1uRVnZvS+GLzCKR9psWZiDEacJzXY7A==',
  configSchemaVersion: 2,
  transcriptVersion: 5,
  sourceRoots: Object.freeze({
    settings: 'src/config/settings.ts',
    model: 'src/config/model-registry.ts',
    auth: 'src/session/auth-storage.ts',
    session: 'src/session/session-manager.ts',
  }),
  sourceContractDomain: 'gjc-remote/sdk-external-state-source/v1',
  closureDomain: 'gjc-remote/sdk-production-closure/v1',
});

const SDK_ROOT_IDENTITY = `${SDK_EXTERNAL_STATE_REQUIREMENTS.packageName}@${SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion}`;
const MAX_SOURCE_BYTES = 256 * 1024 * 1024;
const MAX_CLOSURE_PACKAGES = DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries;
const MAX_CLOSURE_FILES = DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries;
const MAX_CLOSURE_EDGES = 1_000_000;
const CLOSURE_CANONICAL_LIMITS = Object.freeze({
  maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
  maxDepth: 16,
  maxNodes: 1_000_000,
});
const CLOSURE_KINDS = new Set(['dependency', 'optional', 'peer', 'optional-peer']);
const PACKAGE_NAME = /^(?:@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+|[A-Za-z0-9][A-Za-z0-9._-]*)$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const CONFIG_SCHEMA_MARKER = /export const CONFIG_SCHEMA_VERSION = 2;/g;
const SESSION_VERSION_MARKER = /export const CURRENT_SESSION_VERSION = 5;/g;

function invalid() {
  throw new TypeError('SDK_EXTERNAL_STATE_CONTRACT_INVALID');
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function dataRecord(value, keys) {
  if (!plain(value)) invalid();
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))) {
    invalid();
  }
  const record = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    record[key] = descriptor.value;
  }
  return record;
}

function dataArray(value, maximum) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid();
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, 'value') ||
      !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0 ||
      lengthDescriptor.value > maximum) invalid();
  const length = lengthDescriptor.value;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== length + 1 || keys.some((key) => typeof key !== 'string')) invalid();
  const result = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    result.push(descriptor.value);
  }
  return result;
}

function boundedString(value, maximum) {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    assertStrictText(value, 'SDK contract string', maximum);
    return true;
  } catch {
    return false;
  }
}

function validIntegrity(value) {
  if (!boundedString(value, 256) || !value.startsWith('sha512-')) return false;
  try {
    const digest = Buffer.from(value.slice(7), 'base64');
    return digest.byteLength === 64 && `sha512-${digest.toString('base64')}` === value;
  } catch {
    return false;
  }
}

function validPackageIdentity(value) {
  if (!boundedString(value, 512)) return false;
  const at = value.lastIndexOf('@');
  return at > 0 && PACKAGE_NAME.test(value.slice(0, at)) && boundedString(value.slice(at + 1), 128);
}

function validPackageRelativePath(value) {
  if (!boundedString(value, DEPLOYMENT_ENVELOPE_LIMITS.pathBytes) || value.startsWith('/') || value.includes('\\')) {
    return false;
  }
  const segments = value.split('/');
  return segments.length <= DEPLOYMENT_ENVELOPE_LIMITS.pathSegments &&
    segments.every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function filePathCompare(left, right) {
  return utf8Compare(left, right);
}

function edgeCompare(left, right) {
  return filePathCompare(
    `${left.kind}:${left.name}:${left.targetIdentity}`,
    `${right.kind}:${right.name}:${right.targetIdentity}`,
  );
}

function hashBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalJsonByteLength(value, depth = 0, state = { nodes: 0 }) {
  if (depth > CLOSURE_CANONICAL_LIMITS.maxDepth) invalid();
  state.nodes += 1;
  if (state.nodes > CLOSURE_CANONICAL_LIMITS.maxNodes) invalid();
  if (value === null || typeof value === 'boolean') return value === null ? 4 : (value ? 4 : 5);
  if (typeof value === 'string') return Buffer.byteLength(JSON.stringify(value), 'utf8');
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) invalid();
    return String(value).length;
  }
  if (Array.isArray(value)) {
    let size = 2;
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) size += 1;
      size += canonicalJsonByteLength(value[index], depth + 1, state);
      if (size > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes) invalid();
    }
    return size;
  }
  if (!plain(value)) invalid();
  let size = 2;
  const keys = Object.keys(value).sort(utf8Compare);
  for (let index = 0; index < keys.length; index += 1) {
    if (index > 0) size += 1;
    size += Buffer.byteLength(JSON.stringify(keys[index]), 'utf8') + 1 +
      canonicalJsonByteLength(value[keys[index]], depth + 1, state);
    if (size > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes) invalid();
  }
  return size;
}

function canonicalJsonWithinLimit(value) {
  if (canonicalJsonByteLength(value) > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes) invalid();
  const bytes = canonicalJsonBytes(value, CLOSURE_CANONICAL_LIMITS);
  if (bytes.byteLength > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes) invalid();
  return bytes;
}

function normalizePackage(record, counts) {
  const input = dataRecord(record, ['identity', 'integrity', 'files', 'edges']);
  if (!validPackageIdentity(input.identity) || !validIntegrity(input.integrity)) invalid();
  const inputFiles = dataArray(input.files, MAX_CLOSURE_FILES);
  const inputEdges = dataArray(input.edges, MAX_CLOSURE_EDGES);
  if (inputFiles.length === 0) invalid();
  counts.files += inputFiles.length;
  counts.edges += inputEdges.length;
  if (counts.files > MAX_CLOSURE_FILES || counts.edges > MAX_CLOSURE_EDGES) invalid();

  const files = [];
  const filePaths = new Set();
  for (const candidate of inputFiles) {
    const file = dataRecord(candidate, ['path', 'size', 'sha256', 'executablePolicy']);
    if (!validPackageRelativePath(file.path) || filePaths.has(file.path) ||
        !Number.isSafeInteger(file.size) || file.size < 0 ||
        typeof file.sha256 !== 'string' || !HEX_64.test(file.sha256) ||
        (file.executablePolicy !== 'required' && file.executablePolicy !== 'forbidden')) invalid();
    filePaths.add(file.path);
    counts.bytes += file.size;
    if (!Number.isSafeInteger(counts.bytes) || counts.bytes > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes) invalid();
    files.push({
      path: file.path,
      size: file.size,
      sha256: file.sha256,
      executablePolicy: file.executablePolicy,
    });
  }
  files.sort((left, right) => filePathCompare(left.path, right.path));

  const edges = [];
  for (const candidate of inputEdges) {
    const edge = dataRecord(candidate, ['kind', 'name', 'targetIdentity']);
    if (!CLOSURE_KINDS.has(edge.kind) || !boundedString(edge.name, 512) || !PACKAGE_NAME.test(edge.name) ||
        !validPackageIdentity(edge.targetIdentity)) invalid();
    edges.push({ kind: edge.kind, name: edge.name, targetIdentity: edge.targetIdentity });
  }
  edges.sort(edgeCompare);
  return {
    identity: input.identity,
    integrity: input.integrity,
    files,
    edges,
  };
}

function validateVersionSource(bytes, record, marker) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > MAX_SOURCE_BYTES ||
      bytes.byteLength !== record.size || hashBytes(bytes) !== record.sha256) invalid();
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    invalid();
  }
  if ((text.match(marker) ?? []).length !== 1) invalid();
}

function derive(input) {
  const sourceInput = dataRecord(input, ['packages', 'configSchemaVersionSource', 'sessionManagerSource']);
  const inputPackages = dataArray(sourceInput.packages, MAX_CLOSURE_PACKAGES);
  if (inputPackages.length === 0 || inputPackages.length > MAX_CLOSURE_PACKAGES) invalid();

  const counts = { files: 0, edges: 0, bytes: 0 };
  const byIdentity = new Map();
  for (const record of inputPackages) {
    const item = normalizePackage(record, counts);
    const encoded = canonicalJsonWithinLimit(item);
    const previous = byIdentity.get(item.identity);
    if (previous && !previous.encoded.equals(encoded)) invalid();
    if (!previous) byIdentity.set(item.identity, { encoded, item });
  }

  const packages = [...byIdentity.values()].map(({ item }) => item)
    .sort((left, right) => filePathCompare(left.identity, right.identity));
  if (packages.length > MAX_CLOSURE_PACKAGES) invalid();
  const packageByIdentity = new Map(packages.map((item) => [item.identity, item]));
  const root = packageByIdentity.get(SDK_ROOT_IDENTITY);
  if (!root || root.integrity !== SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity) invalid();

  const reachable = new Set();
  const visit = (identity) => {
    if (reachable.has(identity)) return;
    const item = packageByIdentity.get(identity);
    if (!item) invalid();
    reachable.add(identity);
    for (const edge of item.edges) visit(edge.targetIdentity);
  };
  visit(root.identity);
  if (reachable.size !== packages.length) invalid();

  const rootFiles = new Map(root.files.map((file) => [file.path, file]));
  for (const path of Object.values(SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots)) {
    if (!rootFiles.has(path)) invalid();
  }
  const configSchemaRecord = rootFiles.get('src/config/config-schema-version.ts');
  const sessionManagerRecord = rootFiles.get('src/session/session-manager.ts');
  if (!configSchemaRecord || !sessionManagerRecord) invalid();
  validateVersionSource(sourceInput.configSchemaVersionSource, configSchemaRecord, CONFIG_SCHEMA_MARKER);
  validateVersionSource(sourceInput.sessionManagerSource, sessionManagerRecord, SESSION_VERSION_MARKER);

  const closureBytes = canonicalJsonWithinLimit({ packages });
  const closureFingerprint = createHash('sha256')
    .update(SDK_EXTERNAL_STATE_REQUIREMENTS.closureDomain, 'utf8')
    .update(Buffer.from([0]))
    .update(closureBytes)
    .digest('hex');
  const sourceContracts = {};
  for (const [domain, sourcePath] of Object.entries(SDK_EXTERNAL_STATE_REQUIREMENTS.sourceRoots)) {
    const record = rootFiles.get(sourcePath);
    sourceContracts[domain] = createHash('sha256')
      .update(`${SDK_EXTERNAL_STATE_REQUIREMENTS.sourceContractDomain}/${domain}`, 'utf8')
      .update(Buffer.from([0]))
      .update(canonicalJsonBytes({
        rootIdentity: root.identity,
        sourcePath,
        sourceSha256: record.sha256,
        closureFingerprint,
      }))
      .digest('hex');
  }
  const sdkContract = buildSdkExternalStateContract({
    packageName: SDK_EXTERNAL_STATE_REQUIREMENTS.packageName,
    packageVersion: SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion,
    lockIntegrity: SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity,
    configSchemaVersion: SDK_EXTERNAL_STATE_REQUIREMENTS.configSchemaVersion,
    sourceContracts,
  });
  return Object.freeze({
    sdkContract: deepFreeze(sdkContract),
    closureFingerprint,
    packageCount: packages.length,
  });
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

/**
 * Derive the pinned SDK external-state contract from bounded installed-package
 * closure records and the two version-marker source files. This function is
 * synchronous, pure, and does not import or read the SDK installation. The
 * caller must obtain the complete records and integrity values from its
 * authoritative installation reader; this module does not collect files,
 * locate a lockfile, or verify a deployment signature.
 *
 * @param {{packages: Array<{identity: string, integrity: string, files: Array<{path: string, size: number, sha256: string, executablePolicy: 'required'|'forbidden'}>, edges: Array<{kind: 'dependency'|'optional'|'peer'|'optional-peer', name: string, targetIdentity: string}>}>, configSchemaVersionSource: Uint8Array, sessionManagerSource: Uint8Array}} input
 * @returns {{sdkContract: object, closureFingerprint: string, packageCount: number}}
 */
export function deriveSdkExternalStateContract(input) {
  try {
    return derive(input);
  } catch {
    return invalid();
  }
}

/**
 * Derive the declared installation contract and compare it to the fingerprint
 * field from an independently verified signed application manifest. This
 * checks the fingerprint relation only; the caller verifies the signature and
 * supplies a complete observation of the declared installation.
 *
 * @param {{packages: Array<object>, configSchemaVersionSource: Uint8Array, sessionManagerSource: Uint8Array, sdkExternalStateContractFingerprint: string}} input
 * @returns {{sdkContract: object, closureFingerprint: string, packageCount: number}}
 */
export function assertSdkExternalStateContract(input) {
  try {
    const observed = dataRecord(input, [
      'packages', 'configSchemaVersionSource', 'sessionManagerSource', 'sdkExternalStateContractFingerprint',
    ]);
    if (typeof observed.sdkExternalStateContractFingerprint !== 'string' ||
        !HEX_64.test(observed.sdkExternalStateContractFingerprint)) invalid();
    const derived = derive({
      packages: observed.packages,
      configSchemaVersionSource: observed.configSchemaVersionSource,
      sessionManagerSource: observed.sessionManagerSource,
    });
    if (derived.sdkContract.sdkExternalStateContractFingerprint !==
        observed.sdkExternalStateContractFingerprint) invalid();
    return derived;
  } catch {
    return invalid();
  }
}
