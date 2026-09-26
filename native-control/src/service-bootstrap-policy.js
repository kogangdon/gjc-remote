import { createHash } from 'node:crypto';

// Pure policy for the signed Windows service bootstrap guard. This module is
// part of the guard's static closure, so it imports only node:crypto.

export const SERVICE_BOOTSTRAP_CLOSURE_DOMAIN = 'gjc-remote/windows-service-bootstrap-closure/v1';
export const SERVICE_EFFECTIVE_CONFIG_DOMAIN = 'gjc-remote/windows-service-effective-config/v1';
export const SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
export const SERVICE_BOOTSTRAP_RUNTIMES = Object.freeze({
  bot: Object.freeze({ version: '26.7.0', sourceRevision: 'b4f23d3619c98bed09af93a21192f6080197a8c6' }),
  daemon: Object.freeze({ version: '1.4.2', sourceRevision: '744846f844374847c902b5e7fd59b4342a51ef99' }),
});

// Repository-relative static import/resolution closure of
// native-control/src/service-bootstrap.js. Sorted by UTF-8 code units; the
// closure test recomputes it from source and the release builder maps it into
// signed windowsServiceBootstrap.staticClosure metadata.
export const SERVICE_BOOTSTRAP_STATIC_CLOSURE = Object.freeze([
  'native-control/package.json',
  'native-control/src/capabilities.js',
  'native-control/src/native-provenance.js',
  'native-control/src/service-bootstrap-native.js',
  'native-control/src/service-bootstrap-policy.js',
  'native-control/src/service-bootstrap.js',
  'node_modules/dotenv/lib/main.js',
  'node_modules/dotenv/package.json',
  'shared/package.json',
  'shared/strict-json.js',
]);

export const SERVICE_BOOTSTRAP_CONTEXT_KEYS = Object.freeze([
  'schemaVersion', 'component', 'serviceKey', 'processEpochFingerprint',
  'effectiveConfigFingerprint', 'configSourceIdentityFingerprint',
  'launchFingerprint', 'runtimePolicyFingerprint', 'bootstrapClosureFingerprint',
  'scopeFingerprint',
]);

const HEX = /^[0-9a-f]{64}$/;
const DAEMON_KEY = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?-[0-9a-f]{64}$/;
const DOTENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;
const WINDOWS_ABSOLUTE = /^[A-Za-z]:\\(?:[^\\/:*?"<>|\u0000-\u001f]+\\)*[^\\/:*?"<>|\u0000-\u001f]+$/;
const RESERVED_PREFIXES = Object.freeze(['GJC_REMOTE_', 'NODE_', 'BUN_']);
const RESERVED_KEYS = new Set([
  'HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'GJC_CODING_AGENT_DIR', 'PI_CODING_AGENT_DIR',
]);
const COMMON_HASH_KEYS = Object.freeze([
  'GJC_REMOTE_SUPERVISOR_SHA256', 'GJC_REMOTE_RUNTIME_SHA256',
  'GJC_REMOTE_ENTRYPOINT_SHA256', 'GJC_REMOTE_BOOTSTRAP_SHA256',
  'GJC_REMOTE_BOOTSTRAP_CLOSURE_FINGERPRINT', 'GJC_REMOTE_SCOPE_FINGERPRINT',
  'GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT', 'GJC_REMOTE_CONFIG_SOURCE_IDENTITY_FINGERPRINT',
  'GJC_REMOTE_LAUNCH_FINGERPRINT', 'GJC_REMOTE_RUNTIME_POLICY_FINGERPRINT',
]);
const RUNTIME_CONFIG_KEYS = Object.freeze([
  'GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT', 'GJC_REMOTE_RUNTIME_CONFIG_PATH',
  'GJC_REMOTE_RUNTIME_CONFIG_SHA256', 'GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT',
  'GJC_REMOTE_SDK_PROFILE_PATH',
]);
const SELF_CONFIG_KEYS = Object.freeze(['schemaVersion', 'sourceIdentityFingerprint', 'bytes', 'runtimeConfig', 'writes']);
const RUNTIME_CONFIG_RESULT_KEYS = Object.freeze(['rootIdentityFingerprint', 'fileIdentityFingerprint', 'fileSha256', 'byteLength']);
const EPOCH_KEYS = Object.freeze(['processEpochFingerprint', 'writes']);

export class ServiceBootstrapRefusal extends Error {
  constructor(reason) {
    super(`service bootstrap refused: ${reason}`);
    this.name = 'ServiceBootstrapRefusal';
    this.code = 'SERVICE_BOOTSTRAP_REFUSED';
    this.reason = reason;
    this.writes = 0;
  }
}

function refuse(reason) { throw new ServiceBootstrapRefusal(reason); }

function exactData(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) return null;
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const values = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor.get || descriptor.set || !Object.hasOwn(descriptor, 'value')) return null;
    values[key] = descriptor.value;
  }
  return values;
}

function utf8Compare(left, right) { return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')); }

function leaf(path) { return path.slice(path.lastIndexOf('\\') + 1).toLowerCase(); }

function samePath(left, right) {
  return typeof left === 'string' && typeof right === 'string' &&
    WINDOWS_ABSOLUTE.test(left) && left.toLowerCase() === right.toLowerCase();
}

function envString(env, key) {
  const value = env[key];
  if (typeof value !== 'string') refuse('environment-missing');
  return value;
}

function sha256Hex(domain, value) {
  return createHash('sha256').update(`${domain}\n${JSON.stringify(value)}`, 'utf8').digest('hex');
}

export function serviceBootstrapClosureFingerprint(entries) {
  if (!Array.isArray(entries) || entries.length === 0) throw new TypeError('invalid bootstrap closure');
  let previous = null;
  const canonical = entries.map((entry) => {
    const record = exactData(entry, ['relativePath', 'sha256']);
    if (record === null || typeof record.relativePath !== 'string' || record.relativePath.length === 0 ||
        !HEX.test(record.sha256) || (previous !== null && utf8Compare(previous, record.relativePath) >= 0)) {
      throw new TypeError('invalid bootstrap closure');
    }
    previous = record.relativePath;
    return [record.relativePath, record.sha256];
  });
  return sha256Hex(SERVICE_BOOTSTRAP_CLOSURE_DOMAIN, canonical);
}

// Validates parsed dotenv entries against the reserved-key and inherited
// environment policy. Returns a frozen, sorted [key, value] list.
export function validateServiceDotenvEntries(parsed, env) {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) refuse('config-invalid');
  const keys = Object.keys(parsed).sort(utf8Compare);
  if (keys.length > 4096) refuse('config-invalid');
  const entries = [];
  for (const key of keys) {
    const value = parsed[key];
    if (!DOTENV_KEY.test(key) || typeof value !== 'string') refuse('config-invalid');
    const upper = key.toUpperCase();
    if (RESERVED_KEYS.has(upper) || RESERVED_PREFIXES.some((prefix) => upper.startsWith(prefix))) {
      refuse('config-reserved-key');
    }
    const inherited = env[key];
    if (inherited !== undefined && inherited !== value) refuse('inherited-env-conflict');
    entries.push(Object.freeze([key, value]));
  }
  return Object.freeze(entries);
}

export function serviceEffectiveConfigFingerprint({ component, serviceKey, entries }) {
  if ((component !== 'bot' && component !== 'daemon') || typeof serviceKey !== 'string' ||
      !Array.isArray(entries)) {
    throw new TypeError('invalid effective config');
  }
  let previous = null;
  const canonical = entries.map((entry) => {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' ||
        typeof entry[1] !== 'string' || (previous !== null && utf8Compare(previous, entry[0]) >= 0)) {
      throw new TypeError('invalid effective config');
    }
    previous = entry[0];
    return [entry[0], entry[1]];
  });
  return sha256Hex(SERVICE_EFFECTIVE_CONFIG_DOMAIN, { component, entries: canonical, serviceKey });
}

function validateServiceKey(component, serviceKey) {
  if (component === 'bot' ? serviceKey !== 'bot' : !DAEMON_KEY.test(serviceKey)) refuse('service-key-invalid');
}

function validateRuntime(component, env, runtime) {
  const pinned = SERVICE_BOOTSTRAP_RUNTIMES[component];
  if (envString(env, 'GJC_REMOTE_RUNTIME_VERSION') !== pinned.version ||
      envString(env, 'GJC_REMOTE_RUNTIME_SOURCE_REVISION') !== pinned.sourceRevision) {
    refuse('runtime-policy-mismatch');
  }
  const versions = runtime.versions ?? {};
  if (component === 'bot'
    ? versions.node !== pinned.version || versions.bun !== undefined
    : versions.bun !== pinned.version || runtime.bunRevision !== pinned.sourceRevision) {
    refuse('runtime-mismatch');
  }
  if (typeof runtime.execPath !== 'string' ||
      leaf(runtime.execPath) !== (component === 'bot' ? 'node.exe' : 'bun.exe')) refuse('runtime-mismatch');
  const argv = runtime.argv;
  if (!Array.isArray(argv) || argv.length !== 2 || typeof argv[1] !== 'string' ||
      leaf(argv[1]) !== (component === 'bot' ? 'bot.js' : 'daemon.js')) refuse('argv-policy');
  const execArgv = runtime.execArgv;
  if (!Array.isArray(execArgv)) refuse('argv-policy');
  if (component === 'bot') {
    if (execArgv.length !== 0) refuse('argv-policy');
    return;
  }
  const configPath = env.GJC_REMOTE_RUNTIME_CONFIG_PATH;
  const allowed = execArgv.length === 0 ||
    (execArgv.length === 3 && execArgv[0] === '--config' && samePath(execArgv[1], configPath) &&
      execArgv[2] === '--no-env-file') ||
    (execArgv.length === 2 && typeof execArgv[0] === 'string' && execArgv[0].startsWith('--config=') &&
      samePath(execArgv[0].slice('--config='.length), configPath) && execArgv[1] === '--no-env-file');
  if (!allowed) refuse('argv-policy');
}

function validateEnvironment(component, env, bootstrapPath) {
  for (const key of ['NODE_OPTIONS', 'NODE_PATH']) if (envString(env, key) !== '') refuse('environment-policy');
  const home = envString(env, 'HOME');
  if (!WINDOWS_ABSOLUTE.test(home) || envString(env, 'USERPROFILE') !== home) refuse('home-policy');
  for (const key of COMMON_HASH_KEYS) if (!HEX.test(envString(env, key))) refuse('environment-policy');
  if (!samePath(envString(env, 'GJC_REMOTE_BOOTSTRAP_PATH'), bootstrapPath)) refuse('bootstrap-path-mismatch');
  if (component === 'bot') {
    for (const key of RUNTIME_CONFIG_KEYS) if (envString(env, key) !== '') refuse('environment-policy');
    if (!WINDOWS_ABSOLUTE.test(envString(env, 'CHANNELS_CONFIG'))) refuse('environment-policy');
    return;
  }
  for (const key of ['BUN_OPTIONS', 'BUN_INSPECT', 'BUN_INSPECT_CONNECT_TO']) {
    if (envString(env, key) !== '') refuse('inspector-policy');
  }
  if (!samePath(envString(env, 'BUN_INSPECT_PRELOAD'), bootstrapPath)) refuse('bootstrap-path-mismatch');
  const root = envString(env, 'XDG_CONFIG_HOME');
  const configPath = envString(env, 'GJC_REMOTE_RUNTIME_CONFIG_PATH');
  if (!WINDOWS_ABSOLUTE.test(root) || configPath !== `${root}\\.bunfig.toml`) refuse('runtime-config-policy');
  if (!HEX.test(envString(env, 'GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT')) ||
      !HEX.test(envString(env, 'GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT')) ||
      envString(env, 'GJC_REMOTE_RUNTIME_CONFIG_SHA256') !== SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256) {
    refuse('runtime-config-policy');
  }
  const profile = envString(env, 'GJC_REMOTE_SDK_PROFILE_PATH');
  if (!WINDOWS_ABSOLUTE.test(profile) || envString(env, 'GJC_CODING_AGENT_DIR') !== profile ||
      (env.PI_CODING_AGENT_DIR !== undefined && env.PI_CODING_AGENT_DIR !== profile)) {
    refuse('sdk-profile-policy');
  }
}

function validateSelfConfig(component, env, selfConfig) {
  const config = exactData(selfConfig, SELF_CONFIG_KEYS);
  if (config === null || config.schemaVersion !== 1 || config.writes !== 0 ||
      !(config.bytes instanceof Uint8Array) ||
      config.sourceIdentityFingerprint !== env.GJC_REMOTE_CONFIG_SOURCE_IDENTITY_FINGERPRINT) {
    refuse('config-source-drift');
  }
  if (component === 'bot') {
    if (config.runtimeConfig !== null) refuse('runtime-config-drift');
    return config.bytes;
  }
  const runtimeConfig = exactData(config.runtimeConfig, RUNTIME_CONFIG_RESULT_KEYS);
  if (runtimeConfig === null ||
      runtimeConfig.rootIdentityFingerprint !== env.GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT ||
      runtimeConfig.fileIdentityFingerprint !== env.GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT ||
      runtimeConfig.fileSha256 !== SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256 || runtimeConfig.byteLength !== 0) {
    refuse('runtime-config-drift');
  }
  return config.bytes;
}

// Validates every pre-application input and returns the frozen nonsecret
// context plus the verified dotenv entries. Throws ServiceBootstrapRefusal.
export function evaluateServiceBootstrap({ env, runtime, bootstrapPath, selfConfig, epoch, parseDotenv }) {
  if (env === null || typeof env !== 'object' || runtime === null || typeof runtime !== 'object' ||
      typeof parseDotenv !== 'function') refuse('invalid-input');
  if (runtime.platform !== 'win32') refuse('unsupported-platform');
  const component = envString(env, 'GJC_REMOTE_SERVICE_COMPONENT');
  if (component !== 'bot' && component !== 'daemon') refuse('component-invalid');
  const serviceKey = envString(env, 'GJC_REMOTE_SERVICE_KEY');
  validateServiceKey(component, serviceKey);
  validateEnvironment(component, env, bootstrapPath);
  validateRuntime(component, env, runtime);
  const bytes = validateSelfConfig(component, env, selfConfig);
  const observed = exactData(epoch, EPOCH_KEYS);
  if (observed === null || observed.writes !== 0 || !HEX.test(observed.processEpochFingerprint)) {
    refuse('epoch-invalid');
  }
  let parsed;
  try {
    parsed = parseDotenv(bytes);
  } catch {
    refuse('config-invalid');
  }
  const entries = validateServiceDotenvEntries(parsed, env);
  const effectiveConfigFingerprint = serviceEffectiveConfigFingerprint({ component, serviceKey, entries });
  if (effectiveConfigFingerprint !== env.GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT) refuse('effective-config-drift');
  const context = Object.freeze({
    schemaVersion: 1,
    component,
    serviceKey,
    processEpochFingerprint: observed.processEpochFingerprint,
    effectiveConfigFingerprint,
    configSourceIdentityFingerprint: env.GJC_REMOTE_CONFIG_SOURCE_IDENTITY_FINGERPRINT,
    launchFingerprint: env.GJC_REMOTE_LAUNCH_FINGERPRINT,
    runtimePolicyFingerprint: env.GJC_REMOTE_RUNTIME_POLICY_FINGERPRINT,
    bootstrapClosureFingerprint: env.GJC_REMOTE_BOOTSTRAP_CLOSURE_FINGERPRINT,
    scopeFingerprint: env.GJC_REMOTE_SCOPE_FINGERPRINT,
  });
  return Object.freeze({ context, entries });
}
