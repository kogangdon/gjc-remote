import { isAbsolute, normalize, parse, resolve } from 'node:path';
import { assertStrictText } from '@gjc-remote/shared/strict-json';

const DECISION_KEYS = ['version', 'grantId', 'allowed', 'profile'];
const PROFILE_KEYS = ['agentDir', 'credentialPath', 'recipient', 'configIdentity', 'credentialIdentity'];
const IDENTITY_BYTES = 1024;
const WINDOWS_RESERVED_NAME = /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)/i;

function exactObject(value, keys, name) {
  if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== keys.length || keys.some(key => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return !descriptor?.enumerable || !Object.hasOwn(descriptor, 'value');
      })) {
    throw new TypeError(`${name} must contain exactly ${keys.join(', ')}`);
  }
}

function identity(value, name) {
  assertStrictText(value, name, IDENTITY_BYTES);
  if (value.length === 0 || value.trim() !== value) {
    throw new TypeError(`${name} must be a nonempty, unpadded identity`);
  }
  return value;
}

function absolutePath(value, name) {
  assertStrictText(value, name);
  if (value.length === 0 || value.trim() !== value || !isAbsolute(value) ||
      normalize(value) !== value || resolve(value) !== value) {
    throw new TypeError(`${name} must be a canonical absolute path`);
  }
  if (process.platform === 'win32') {
    // Root-relative paths depend on a drive, and device namespaces and Win32
    // aliases are not canonical references to the selected original target.
    if (!/^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\)/.test(parse(value).root) ||
        /^\\\\[?.]\\/.test(value)) {
      throw new TypeError(`${name} must be a canonical absolute path`);
    }
    const components = value.slice(value.startsWith('\\\\') ? 2 : 3).split('\\');
    if (components.some(component => component !== '' &&
        (/[<>:"|?*]/.test(component) || /[ .]$/.test(component) || WINDOWS_RESERVED_NAME.test(component)))) {
      throw new TypeError(`${name} must not contain Windows path aliases`);
    }
  }
  return value;
}

function normalizeProfile(profile) {
  exactObject(profile, PROFILE_KEYS, 'SDK profile');
  return Object.freeze({
    agentDir: absolutePath(profile.agentDir, 'agentDir'),
    credentialPath: absolutePath(profile.credentialPath, 'credentialPath'),
    recipient: identity(profile.recipient, 'recipient'),
    configIdentity: identity(profile.configIdentity, 'configIdentity'),
    credentialIdentity: identity(profile.credentialIdentity, 'credentialIdentity'),
  });
}

function sameProfile(left, right) {
  return PROFILE_KEYS.every(key => left[key] === right[key]);
}

/** Validate JSON data, copy it, and freeze both the record and its profile. */
export function normalizeProfileDecision(record) {
  exactObject(record, DECISION_KEYS, 'SDK profile decision');
  if (record.version !== 1 || !Number.isSafeInteger(record.grantId) || record.grantId < 1 ||
      typeof record.allowed !== 'boolean') {
    throw new TypeError('SDK profile decision requires version 1, a positive safe integer grantId, and boolean allowed');
  }
  return Object.freeze({
    version: 1,
    grantId: record.grantId,
    allowed: record.allowed,
    profile: normalizeProfile(record.profile),
  });
}

/**
 * Compute a management write without I/O. `current` must be null (no known
 * history) or the last trusted FULL decision, including withdrawn grants;
 * capture() is not history. `profileOrNull` is a verified selection or null
 * to withdraw. After a read failure, retain history as withdrawn before
 * requesting another allow. Callers must serialize writes and compare-and-set
 * against the authoritative record; this helper cannot detect stale callers,
 * erased durable history, target replacement, or recipient access changes.
 */
export function nextProfileDecision(current, profileOrNull) {
  const previous = current === null ? null : normalizeProfileDecision(current);
  if (profileOrNull === null) {
    if (previous === null || !previous.allowed) return previous;
    return Object.freeze({ ...previous, allowed: false });
  }
  const profile = normalizeProfile(profileOrNull);
  if (previous?.allowed && sameProfile(previous.profile, profile)) return previous;
  if (previous?.grantId === Number.MAX_SAFE_INTEGER) {
    throw new RangeError('SDK profile grantId is exhausted');
  }
  return Object.freeze({
    version: 1,
    grantId: previous === null ? 1 : previous.grantId + 1,
    allowed: true,
    profile,
  });
}

/**
 * Process-local grant authority; no filesystem or credential access.
 * apply() reports active-grant changes, not high-water-only changes. Invalid,
 * missing, regressing, or conflicting records withdraw the current grant;
 * only a higher valid grantId can restore sharing. Equivalent values keep the
 * same capture. Subscribers run synchronously after publication, receive the
 * active record or null, and are not called just for subscribing. Durable
 * history and full withdrawn records belong to the caller, not capture().
 */
export function createProfileDecisionState() {
  let current = null;
  let active = null;
  let epoch = Symbol('SDK profile decision epoch');
  const bindingEpochs = new WeakMap();
  const subscribers = new Set();

  function publish(record) {
    if (active === null && record === null) return false;
    active = record;
    epoch = Symbol('SDK profile decision epoch');
    if (active !== null) bindingEpochs.set(active, epoch);
    for (const subscriber of [...subscribers]) {
      try {
        subscriber(record);
      } catch {
        // One consumer must not prevent the others from observing revocation.
      }
    }
    return true;
  }

  function disable() {
    if (current?.allowed) current = Object.freeze({ ...current, allowed: false });
    return publish(null);
  }

  function apply(recordOrNull) {
    let record;
    try {
      record = normalizeProfileDecision(recordOrNull);
    } catch {
      return disable();
    }
    if (current !== null && record.grantId <= current.grantId) {
      if (record.grantId < current.grantId || !sameProfile(record.profile, current.profile) ||
          (record.allowed && !current.allowed)) {
        return disable();
      }
      if (record.allowed === current.allowed) return false;
    }
    current = record;
    return publish(record.allowed ? record : null);
  }

  function capture() {
    return active;
  }

  function isCurrent(binding) {
    return active !== null && binding === active && bindingEpochs.get(binding) === epoch;
  }

  function subscribe(callback) {
    if (typeof callback !== 'function') throw new TypeError('SDK profile subscriber must be a function');
    subscribers.add(callback);
    return () => subscribers.delete(callback);
  }

  return Object.freeze({ apply, capture, isCurrent, subscribe });
}
