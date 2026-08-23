import { createInventoryReader as nativeCreateInventoryReader } from '@gjc-remote/native-control';
import { STRICT_JSON_LIMITS, parseStrictJsonBytes } from '@gjc-remote/shared/strict-json';

const ROLE_KEYS = Object.freeze(['management', 'bot', 'recovery', 'daemon', 'system']);
const PRINCIPAL_KEYS = Object.freeze(['kind', 'value']);
const READER_KEYS = Object.freeze(['selfTest', 'readAccepted']);
const SELF_TEST_KEYS = Object.freeze(['role', 'contractVersion', 'writes']);
const ROLE_LIMIT = 32 * 1024;
const SAFE_CODES = new Set([
  'INVENTORY_IO_FAILED',
  'INVENTORY_INVALID',
  'INVENTORY_ACCESS_DENIED',
  'INVENTORY_STALE',
  'INVENTORY_PENDING',
  'INVENTORY_MANUAL_CLEANUP',
  'WORKSPACE_ROOT_ESCAPE',
  'CONTAINMENT_UNSUPPORTED',
]);
const SAFE_OPERATIONS = new Set([
  'resolve_native_state_root',
  'verify_inventory_acl',
  'acquire_inventory_fence',
  'read_inventory_object',
  'read_workspace_root_facts',
  'read_inventory',
]);

function configError() {
  const error = new Error('Inventory configuration is invalid.');
  Object.defineProperties(error, {
    code: { value: 'CONFIG_INVALID', enumerable: true },
    operation: { value: 'initialize_inventory_config', enumerable: true },
    writes: { value: 0, enumerable: true },
    ambiguous: { value: false, enumerable: true },
  });
  return Object.freeze(error);
}

function environmentValue(env, key) {
  try {
    return env?.[key];
  } catch {
    throw configError();
  }
}

function exactDataValues(value, keys, frozen = false) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype || (frozen && !Object.isFrozen(value))) {
      return null;
    }
    const names = Reflect.ownKeys(value);
    if (names.length !== keys.length || names.some((name) => typeof name !== 'string') ||
        !keys.every((key) => names.includes(key))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
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

function isWindowsSid(value) {
  const fields = value.split('-');
  if (fields.length < 4 || fields.length > 18 || fields[0] !== 'S' || fields[1] !== '1') {
    return false;
  }
  const decimal = /^(0|[1-9][0-9]*)$/;
  if (!fields.slice(2).every((field) => decimal.test(field))) return false;
  try {
    return BigInt(fields[2]) <= 281474976710655n &&
      fields.slice(3).every((field) => BigInt(field) <= 4294967295n);
  } catch {
    return false;
  }
}

function validPrincipal(principal, kind) {
  const values = exactDataValues(principal, PRINCIPAL_KEYS);
  if (!values || values.kind !== kind || typeof values.value !== 'string' ||
      Buffer.byteLength(values.value, 'utf8') > 4096) return null;
  if (kind === 'uid' && !/^uid:(0|[1-9][0-9]{0,9})$/.test(values.value)) return null;
  if (kind === 'uid' && BigInt(values.value.slice(4)) > 4294967295n) return null;
  if (kind === 'sid' && !isWindowsSid(values.value)) return null;
  return Object.freeze({ kind, value: values.value });
}

function parseRoles(env, platform) {
  const kind = platform === 'linux' ? 'uid' : platform === 'win32' ? 'sid' : null;
  if (kind === null) throw configError();
  const raw = environmentValue(env, 'GJC_INVENTORY_ROLE_BINDINGS');
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > ROLE_LIMIT) throw configError();
  let parsed;
  try {
    parsed = parseStrictJsonBytes(Buffer.from(raw, 'utf8'), {
      ...STRICT_JSON_LIMITS, maxBytes: ROLE_LIMIT,
    });
  } catch {
    throw configError();
  }
  const roleValues = exactDataValues(parsed, ROLE_KEYS);
  if (!roleValues) throw configError();
  const roles = {};
  for (const key of ROLE_KEYS) {
    const principal = validPrincipal(roleValues[key], kind);
    if (!principal) throw configError();
    roles[key] = principal;
  }
  if (new Set(ROLE_KEYS.map((key) => roles[key].value)).size !== ROLE_KEYS.length ||
      roles.system.value !== (kind === 'uid' ? 'uid:0' : 'S-1-5-18')) throw configError();
  return Object.freeze(roles);
}

function validReader(reader) {
  const values = exactDataValues(reader, READER_KEYS, true);
  return values && typeof values.selfTest === 'function' && typeof values.readAccepted === 'function'
    ? values : null;
}

function validSelfTest(receipt) {
  const values = exactDataValues(receipt, SELF_TEST_KEYS, true);
  return values && values.role === 'daemon' && values.contractVersion === 4 && values.writes === 0;
}

export async function initializeInventoryConfig(
  { env = process.env, hostId, platform = process.platform } = {},
  { createInventoryReader = nativeCreateInventoryReader } = {},
) {
  const mode = environmentValue(env, 'GJC_NATIVE_INVENTORY_MODE');
  if (mode === undefined) return Object.freeze({ mode: 'off' });
  if (mode !== 'off' && mode !== 'verify') throw configError();
  if (mode === 'off') return Object.freeze({ mode: 'off' });
  if (environmentValue(env, 'GJC_READINESS_TEST_INJECTION') === '1') throw configError();
  const roles = parseRoles(env, platform);
  if (typeof createInventoryReader !== 'function') throw configError();
  const reader = await createInventoryReader(Object.freeze({ hostId, roles }));
  const readerValues = validReader(reader);
  if (!readerValues) throw configError();
  const selfTest = await readerValues.selfTest.call(reader);
  if (!validSelfTest(selfTest)) throw configError();
  return Object.freeze({ mode: 'verify', reader, selfTest });
}

export function inventoryConfigDiagnostic(error) {
  try {
    const { code, operation, writes, ambiguous } = error ?? {};
    if (code === 'CONFIG_INVALID' &&
        operation === 'initialize_inventory_config' &&
        writes === 0 && ambiguous === false) {
      return Object.freeze({
        code: 'CONFIG_INVALID', operation: 'initialize_inventory_config', writes: 0, ambiguous: false,
      });
    }
    if (code === 'ERR_NATIVE_CONTROL_REFUSED' && operation === 'load_native_control' &&
        writes === 0 && ambiguous !== true) {
      return Object.freeze({
        code: 'ERR_NATIVE_CONTROL_REFUSED', operation: 'load_native_control', writes: 0, ambiguous: false,
      });
    }
    if (SAFE_CODES.has(code) && SAFE_OPERATIONS.has(operation) &&
        writes === 0 && typeof ambiguous === 'boolean') {
      return Object.freeze({ code, operation, writes: 0, ambiguous });
    }
  } catch {}
  return Object.freeze({
    code: 'INVENTORY_IO_FAILED', operation: 'initialize_inventory_config', writes: 0, ambiguous: true,
  });
}
