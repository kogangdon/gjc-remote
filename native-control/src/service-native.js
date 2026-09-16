import { validateServiceRoles } from '@gjc-remote/shared/service-lifecycle-envelope';
import { capabilitySignatures, serviceCapabilities } from './capabilities.js';

const FACTORY_KEYS = Object.freeze(['roles']);
const ROLE_KEYS = Object.freeze(['management', 'bot', 'recovery', 'daemon', 'system']);
const PRINCIPAL_KEYS = Object.freeze(['kind', 'value']);
const getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const getPrototypeOf = Object.getPrototypeOf;
const ownKeys = Reflect.ownKeys;

function serviceError(code, operation) {
  const error = new Error(`${operation} failed`);
  error.code = code;
  error.operation = operation;
  error.writes = 0;
  error.ambiguous = false;
  throw error;
}

function refused(reason) {
  const error = new Error(`create_service_native refused: ${reason}`);
  error.code = 'ERR_NATIVE_CONTROL_REFUSED';
  error.operation = 'create_service_native';
  error.reason = reason;
  error.writes = 0;
  throw error;
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
  return values ? Object.freeze({ kind: values.kind, value: values.value }) : null;
}

function roleSnapshot(options) {
  const values = exactDataValues(options, FACTORY_KEYS);
  if (!values) serviceError('SERVICE_INVALID', 'create_service_native');
  const roleValues = exactDataValues(values.roles, ROLE_KEYS);
  if (!roleValues) serviceError('SERVICE_INVALID', 'create_service_native');
  const principals = ROLE_KEYS.map((role) => principalSnapshot(roleValues[role]));
  if (principals.some((principal) => principal === null)) {
    serviceError('SERVICE_INVALID', 'create_service_native');
  }
  const roles = Object.freeze(Object.fromEntries(
    ROLE_KEYS.map((role, index) => [role, principals[index]]),
  ));
  try {
    validateServiceRoles(roles, process.platform);
  } catch {
    serviceError('SERVICE_INVALID', 'create_service_native');
  }
  // The shared validator is the canonical role-authority policy. This extra
  // Windows-only bound mirrors the native SID parser's numeric/count limits so
  // a role tuple that native code cannot represent is refused before loading.
  if (process.platform === 'win32' &&
      !ROLE_KEYS.every((role) => isWindowsSidShape(roles[role].value))) {
    serviceError('SERVICE_INVALID', 'create_service_native');
  }
  return roles;
}

const projection = Object.freeze(serviceCapabilities.map((name) => {
  const signature = capabilitySignatures[name];
  if (!Array.isArray(signature)) {
    throw new Error(`missing service capability signature: ${name}`);
  }
  const rolesIndex = signature.indexOf('roles');
  if (rolesIndex !== signature.lastIndexOf('roles')) {
    throw new Error(`duplicate roles argument in service capability signature: ${name}`);
  }
  return Object.freeze({
    name,
    rolesIndex,
    publicArity: signature.length - (rolesIndex === -1 ? 0 : 1),
  });
}));

function captureCapabilities(addon) {
  if (addon === null || (typeof addon !== 'object' && typeof addon !== 'function')) {
    refused(`verified addon is missing native capability: ${serviceCapabilities[0]}`);
  }
  let descriptors;
  try {
    descriptors = getOwnPropertyDescriptors(addon);
  } catch {
    refused(`verified addon is missing native capability: ${serviceCapabilities[0]}`);
  }
  const captured = Object.create(null);
  for (const { name } of projection) {
    const descriptor = descriptors[name];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
      refused(`verified addon is missing native capability: ${name}`);
    }
    captured[name] = descriptor.value;
  }
  return Object.freeze(captured);
}

function projectCapabilities(captured, roles) {
  const facade = {};
  for (const { name, rolesIndex, publicArity } of projection) {
    const nativeCapability = captured[name];
    const serviceCapability = function (...args) {
      if (args.length !== publicArity) serviceError('SERVICE_INVALID', name);
      if (rolesIndex !== -1) args.splice(rolesIndex, 0, roles);
      return Reflect.apply(nativeCapability, undefined, args);
    };
    Object.defineProperties(serviceCapability, {
      name: { value: name, configurable: true },
      length: { value: publicArity, configurable: true },
    });
    facade[name] = Object.freeze(serviceCapability);
  }
  return Object.freeze(facade);
}

// This binding helper is intentionally available only from this private module
// so isolated tests can supply a verified-addon loader. The package entrypoint
// exports only the bound createServiceNative factory.
export function createServiceNativeFactory(loadVerifiedAddon) {
  if (typeof loadVerifiedAddon !== 'function') {
    refused('verified addon loader is unavailable');
  }
  return function createServiceNative(options) {
    if (arguments.length !== 1) serviceError('SERVICE_INVALID', 'create_service_native');
    const roles = roleSnapshot(options);
    const addon = loadVerifiedAddon();
    return projectCapabilities(captureCapabilities(addon), roles);
  };
}
