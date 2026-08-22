import {
  STRICT_JSON_LIMITS, canonicalJsonBytes, canonicalJsonHash,
  isHex64, parseCanonicalJsonBytes,
} from '@gjc-remote/shared/strict-json';

const objectPrototype = Object.prototype;
export const commitKeys = Object.freeze(['version', 'hostId', 'inventoryGeneration', 'inventoryFingerprint', 'inventoryObjectIdentityFingerprint', 'publicationNonce', 'commitFingerprint']);
export const floorKeys = Object.freeze(['version', 'hostId', 'inventoryGeneration', 'inventoryFingerprint', 'floorFingerprint']);
export const markerKeys = Object.freeze([
  'version', 'hostId', 'reason', 'inventoryGeneration', 'inventoryFingerprint',
  'commitFingerprint', 'floorFingerprint', 'routeDisposition',
  'blockedUntilOwnerAction', 'manualCleanupFingerprint',
]);
const markerReasons = Object.freeze([
  'invalid-object', 'floor-conflict', 'partial-publication',
  'publication-ambiguous', 'post-publication-verification-failed',
]);

export function exact(value, names) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== objectPrototype) return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== names.length || own.some((name) => typeof name !== 'string') || !names.every((name) => own.includes(name))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value); const result = {};
    for (const name of names) {
      const descriptor = descriptors[name];
      if (!descriptor || !descriptor.enumerable || descriptor.get || descriptor.set || !Object.hasOwn(descriptor, 'value')) return null;
      result[name] = descriptor.value;
    }
    return result;
  } catch { return null; }
}
export function leaf(root, name) { return `${root}${root.endsWith('/') || root.endsWith('\\') ? '' : process.platform === 'win32' ? '\\' : '/'}${name}`; }
export function hash(value) { return canonicalJsonHash(value, STRICT_JSON_LIMITS); }
export function sameBytes(left, right) { return Buffer.isBuffer(left) && left.equals(right); }
export function documentFingerprint(value, name) { const { [name]: ignored, ...preimage } = value; return canonicalJsonHash(preimage, STRICT_JSON_LIMITS); }
export function uint64(value) { return typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && (() => { try { return BigInt(value) <= 18446744073709551615n; } catch { return false; } })(); }
function uid(value) {
  if (typeof value !== 'string' || !/^uid:(0|[1-9][0-9]*)$/.test(value)) return false;
  try { return BigInt(value.slice(4)) <= 4294967295n; } catch { return false; }
}
function sid(value) {
  if (typeof value !== 'string') return false;
  const fields = value.split('-');
  if (fields.length < 4 || fields.length > 18 || fields[0] !== 'S' || fields[1] !== '1' || !fields.slice(2).every((field) => /^(0|[1-9][0-9]*)$/.test(field))) return false;
  try { return BigInt(fields[2]) <= 281474976710655n && fields.slice(3).every((field) => BigInt(field) <= 4294967295n); } catch { return false; }
}
export function objectIdentity(value) {
  const posix = exact(value, ['device', 'inode', 'mode', 'owner']);
  if (posix && uint64(posix.device) && uint64(posix.inode) && Number.isInteger(posix.mode) && posix.mode >= 0 && posix.mode <= 0xffffffff && uid(posix.owner)) return posix;
  const windows = exact(value, ['volumeSerial', 'fileId', 'attributes', 'owner']);
  if (windows && /^[a-f0-9]{16}$/.test(windows.volumeSerial) && /^[a-f0-9]{32}$/.test(windows.fileId) && Number.isInteger(windows.attributes) && windows.attributes >= 0 && windows.attributes <= 0xffffffff && sid(windows.owner)) return windows;
  return null;
}
function validDocument(value, names, fingerprintName, hostId) {
  const result = exact(value, names);
  return result && result.version === 1 && result.hostId === hostId && isHex64(result[fingerprintName]) && documentFingerprint(result, fingerprintName) === result[fingerprintName] ? result : null;
}
export function parseCommit(bytes, hostId) {
  const result = validDocument(parseCanonicalJsonBytes(bytes, STRICT_JSON_LIMITS), commitKeys, 'commitFingerprint', hostId);
  return result && Number.isSafeInteger(result.inventoryGeneration) && result.inventoryGeneration >= 1 && isHex64(result.inventoryFingerprint) && isHex64(result.inventoryObjectIdentityFingerprint) && /^[a-f0-9]{32}$/.test(result.publicationNonce) ? Object.freeze(result) : null;
}
export function parseFloor(bytes, hostId) {
  const result = validDocument(parseCanonicalJsonBytes(bytes, STRICT_JSON_LIMITS), floorKeys, 'floorFingerprint', hostId);
  return result && Number.isSafeInteger(result.inventoryGeneration) && result.inventoryGeneration >= 1 && isHex64(result.inventoryFingerprint) ? Object.freeze(result) : null;
}
export function parseMarker(bytes, hostId) {
  const result = validDocument(
    parseCanonicalJsonBytes(bytes, STRICT_JSON_LIMITS), markerKeys,
    'manualCleanupFingerprint', hostId);
  if (!result || !markerReasons.includes(result.reason) ||
      result.routeDisposition !== 'no-route' ||
      result.blockedUntilOwnerAction !== true ||
      !(result.inventoryGeneration === null ||
        Number.isSafeInteger(result.inventoryGeneration) &&
        result.inventoryGeneration >= 1) ||
      !['inventoryFingerprint', 'commitFingerprint', 'floorFingerprint']
        .every((name) => result[name] === null || isHex64(result[name]))) {
    return null;
  }
  return Object.freeze(result);
}
export function buildCommit({
  hostId, inventoryGeneration, inventoryFingerprint,
  inventoryObjectIdentityFingerprint, publicationNonce,
}) {
  const result = {
    version: 1, hostId, inventoryGeneration, inventoryFingerprint,
    inventoryObjectIdentityFingerprint, publicationNonce,
  };
  result.commitFingerprint = documentFingerprint(result, 'commitFingerprint');
  return Object.freeze(result);
}
export function buildFloor({ hostId, inventoryGeneration, inventoryFingerprint }) {
  const result = {
    version: 1, hostId, inventoryGeneration, inventoryFingerprint,
  };
  result.floorFingerprint = documentFingerprint(result, 'floorFingerprint');
  return Object.freeze(result);
}
export function buildMarker({
  hostId, reason, inventoryGeneration, inventoryFingerprint,
  commitFingerprint, floorFingerprint,
}) {
  const result = {
    version: 1, hostId, reason, inventoryGeneration, inventoryFingerprint,
    commitFingerprint, floorFingerprint, routeDisposition: 'no-route',
    blockedUntilOwnerAction: true,
  };
  result.manualCleanupFingerprint = documentFingerprint(
    result, 'manualCleanupFingerprint');
  return Object.freeze(result);
}
export function commitBytes(value) {
  return canonicalJsonBytes(value, STRICT_JSON_LIMITS);
}
export function floorBytes(value) {
  return canonicalJsonBytes(value, STRICT_JSON_LIMITS);
}
export function markerBytes(value) {
  return canonicalJsonBytes(value, STRICT_JSON_LIMITS);
}
export function readEnvelope(value, parser) {
  if (value === null) return null;
  const envelope = exact(value, ['bytes', 'identity']);
  if (!envelope || !Buffer.isBuffer(envelope.bytes) || !objectIdentity(envelope.identity)) return undefined;
  try { const document = parser(envelope.bytes); return document ? { bytes: envelope.bytes, identity: envelope.identity, document } : undefined; } catch { return undefined; }
}
