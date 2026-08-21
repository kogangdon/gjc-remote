import { isPrincipal } from '@gjc-remote/shared/identity';
import { workspaceInventoryHostKey } from '@gjc-remote/shared/workspace-inventory';

const FACTORY_KEYS = Object.freeze(['hostId', 'roles']);
const ROLE_KEYS = Object.freeze(['management', 'bot', 'recovery', 'daemon', 'system']);
const PRINCIPAL_KEYS = Object.freeze(['kind', 'value']);
const getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const getPrototypeOf = Object.getPrototypeOf;
const ownKeys = Reflect.ownKeys;

function localError(code, operation) {
  const error = new Error('inventory operation failed');
  Object.defineProperties(error, {
    code: { value: code, enumerable: true },
    operation: { value: operation, enumerable: true },
    writes: { value: 0, enumerable: true },
    ambiguous: { value: false, enumerable: true },
  });
  return error;
}

function invalid() {
  throw localError('INVENTORY_INVALID', 'resolve_native_state_root');
}

function exactDataValues(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        getPrototypeOf(value) !== Object.prototype) return null;
    const names = ownKeys(value);
    if (names.length !== keys.length || names.some((name) => typeof name !== 'string') ||
        !keys.every((key) => names.includes(key))) return null;
    const descriptors = getOwnPropertyDescriptors(value);
    const values = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.enumerable !== true || descriptor.get !== undefined ||
          descriptor.set !== undefined || !Object.hasOwn(descriptor, 'value')) return null;
      values[key] = descriptor.value;
    }
    return values;
  } catch {
    return null;
  }
}

function isWindowsSidShape(value) {
  const fields = value.split('-');
  if (fields.length < 4 || fields.length > 18 ||
      fields[0] !== 'S' || fields[1] !== '1') return false;
  const decimal = /^(0|[1-9][0-9]*)$/;
  if (!fields.slice(2).every((field) => decimal.test(field))) return false;
  try {
    if (BigInt(fields[2]) > 281474976710655n) return false;
    return fields.slice(3).every((field) => BigInt(field) <= 4294967295n);
  } catch {
    return false;
  }
}

function principalSnapshot(value) {
  const values = exactDataValues(value, PRINCIPAL_KEYS);
  if (!values) return null;
  if (typeof values.value !== 'string' ||
      Buffer.byteLength(values.value, 'utf8') > 4096 ||
      (values.kind === 'sid' && !isWindowsSidShape(values.value))) return null;
  const principal = { kind: values.kind, value: values.value };
  try {
    return isPrincipal(principal) ? Object.freeze(principal) : null;
  } catch {
    return null;
  }
}

function validateOptions(options) {
  const values = exactDataValues(options, FACTORY_KEYS);
  if (!values) invalid();
  const roleValues = exactDataValues(values.roles, ROLE_KEYS);
  if (!roleValues) invalid();
  const principals = ROLE_KEYS.map((key) => principalSnapshot(roleValues[key]));
  if (principals.some((principal) => principal === null)) invalid();
  const kind = principals[0].kind;
  const requiredKind = process.platform === 'win32' ? 'sid' :
    process.platform === 'linux' ? 'uid' : null;
  if (!principals.every((principal) => principal.kind === kind) ||
      kind !== requiredKind ||
      new Set(principals.map((principal) => principal.value)).size !== principals.length ||
      (kind === 'sid' ? principals[4].value !== 'S-1-5-18' : principals[4].value !== 'uid:0')) invalid();
  let hostKey;
  try {
    hostKey = workspaceInventoryHostKey(values.hostId);
  } catch {
    invalid();
  }
  return Object.freeze({
    hostKey,
    roles: Object.freeze(
      Object.fromEntries(ROLE_KEYS.map((key, index) => [key, principals[index]]))),
  });
}

function requireLowLevel(lowLevel) {
  if (lowLevel === null || typeof lowLevel !== 'object' ||
      typeof lowLevel.resolve_native_state_root !== 'function' ||
      typeof lowLevel.verify_inventory_acl !== 'function') invalid();
  return lowLevel;
}

async function verifyAcl(lowLevel, path, roles, profile, expectedActor) {
  if (await lowLevel.verify_inventory_acl(path, roles, profile, expectedActor) !== true) {
    throw localError('INVENTORY_ACCESS_DENIED', 'verify_inventory_acl');
  }
}

function requireResolvedRoot(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw localError('INVENTORY_IO_FAILED', 'resolve_native_state_root');
  }
  return value;
}

async function createAdapter(loadLowLevel, options, role) {
  const validated = validateOptions(options);
  if (typeof loadLowLevel !== 'function') invalid();
  const lowLevel = requireLowLevel(await loadLowLevel());
  const inventoryRoot = requireResolvedRoot(
    await lowLevel.resolve_native_state_root(validated.hostKey, 'inventory'));
  const readerRoot = role === 'daemon'
    ? requireResolvedRoot(await lowLevel.resolve_native_state_root(validated.hostKey, 'reader'))
    : null;
  const selfTest = async () => {
    await verifyAcl(lowLevel, inventoryRoot, validated.roles, 'inventory-directory', role);
    if (readerRoot !== null) {
      await verifyAcl(lowLevel, readerRoot, validated.roles, 'reader-directory', role);
    }
    return Object.freeze({ role, contractVersion: 4, writes: 0 });
  };
  await selfTest();
  return Object.freeze({ selfTest });
}

export function createInventoryPublisherAdapter(loadLowLevel, options) {
  return createAdapter(loadLowLevel, options, 'management');
}

export function createInventoryReaderAdapter(loadLowLevel, options) {
  return createAdapter(loadLowLevel, options, 'daemon');
}
