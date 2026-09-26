import dotenv from 'dotenv';
import { createServiceNative } from './index.js';
import {
  createServiceCompatibilityObserver,
  readServiceAuthorityScope,
} from './service-compatibility.js';
import { createServiceStartupObserver } from './service-startup-observer.js';
import {
  createWindowsServiceDriver,
  windowsServiceRuntimePolicyFingerprint,
} from './service-windows.js';
import {
  SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256,
  SERVICE_BOOTSTRAP_RUNTIMES,
  serviceEffectiveConfigFingerprint,
  validateServiceDotenvEntries,
} from './service-bootstrap-policy.js';
import { serviceDaemonTargetFingerprint } from '@gjc-remote/shared/service-startup-observation';
import {
  SERVICE_MUTATION_OPERATIONS,
  serviceConfigurationFingerprint,
  serviceKeyForTarget,
  validateServiceArtifactFileFacts,
  win32PhysicalSecurityIdentityFingerprint,
} from '@gjc-remote/shared/service-lifecycle-envelope';

// Windows production service-host producer. One instance serves exactly one
// CLI operation: it binds the validated request at preflight, captures the
// protected host authority (effective .env, runtime config, scope catalog,
// runtime binary facts) through native read-only external roots, and derives
// the signed Launch from the lifecycle-provided release. It never provisions
// accounts, ACLs, configuration or runtimes and never writes outside the
// lifecycle/driver authorities it hands out.

export const WINDOWS_HOST_LIMITS = Object.freeze({
  envBytes: 256 * 1024,
  runtimeConfigBytes: 0,
  runtimeBytes: 512 * 1024 * 1024,
});

const MUTATIONS = new Set(SERVICE_MUTATION_OPERATIONS);
const OPERATIONS = new Set([...SERVICE_MUTATION_OPERATIONS, 'status', 'recover']);
const PHYSICAL_IDENTITY_KIND = 'gjc-remote/win32-physical-security-identity/v1';
const OPEN_ROOT_KEYS = Object.freeze(['handle', 'profile', 'absolutePath', 'rootIdentity', 'absence', 'writes']);
const OBJECT_KEYS = Object.freeze(['kind', 'identity', 'absence', 'bytes', 'entries', 'writes']);
const IDENTITY_KEYS = Object.freeze(['profile', 'kind', 'volumeSerial', 'fileId', 'attributes', 'owner', 'securitySha256']);
const HEX = /^[0-9a-f]{64}$/;
const DEPENDENCY_KEYS = Object.freeze([
  'createNative', 'createDriver', 'createCompatibilityObserver', 'readAuthorityScope',
  'createStartupObserver', 'parseDotenv', 'clock', 'sleep',
]);

export class WindowsHostRefusal extends Error {
  constructor(code, operation, reason) {
    super(`${operation} failed`);
    this.name = 'WindowsHostRefusal';
    this.code = code;
    this.operation = operation;
    this.reason = reason;
    this.writes = 0;
    this.ambiguous = false;
  }
}

function refuse(code, operation, reason) { throw new WindowsHostRefusal(code, operation, reason); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}
function exact(value, keys) {
  return plain(value) && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function validHash(value) { return typeof value === 'string' && HEX.test(value); }

function canonicalWindowsPath(value) {
  if (typeof value !== 'string' || !/^[A-Z]:\\/.test(value) || value.includes('/') || value.endsWith('\\')) return false;
  return value.slice(3).split('\\').every((part) => part !== '' && part !== '.' && part !== '..' &&
    !/[<>:"|?*\u0000-\u001f]/.test(part) && !/[. ]$/.test(part));
}

function physicalFingerprint(identity, operation) {
  if (!exact(identity, IDENTITY_KEYS) || identity.kind !== 'win32-service-object-v1') {
    refuse('SERVICE_STALE', operation, 'identity-invalid');
  }
  try {
    return win32PhysicalSecurityIdentityFingerprint({
      kind: PHYSICAL_IDENTITY_KIND,
      attributes: identity.attributes,
      fileId: identity.fileId,
      owner: identity.owner,
      securitySha256: identity.securitySha256,
      volumeSerial: identity.volumeSerial,
    });
  } catch {
    return refuse('SERVICE_STALE', operation, 'identity-invalid');
  }
}

function closeHandle(native, handle, operation) {
  try { native.close_service_handle(handle); } catch { refuse('SERVICE_IO_FAILED', operation, 'close'); }
}

// Reads one regular file below a protected external root. Returns the root
// and file physical-security identity fingerprints plus a private byte copy.
function readProtectedFile(native, directory, leaf, maximum, operation) {
  const opened = native.open_service_external_root(directory, 'config');
  if (!exact(opened, OPEN_ROOT_KEYS) || opened.handle === null || typeof opened.handle !== 'object') {
    refuse('SERVICE_IO_FAILED', operation, 'external-root');
  }
  try {
    if (opened.profile !== 'config' || opened.absolutePath !== directory || opened.writes !== 0 ||
        opened.absence !== null || opened.rootIdentity === null) {
      refuse('SERVICE_PENDING', operation, 'external-root-absent');
    }
    const rootIdentityFingerprint = physicalFingerprint(opened.rootIdentity, operation);
    const observed = native.read_service_external_object(opened.handle, leaf, 'bytes', maximum);
    if (!exact(observed, OBJECT_KEYS) || observed.writes !== 0) refuse('SERVICE_IO_FAILED', operation, 'external-object');
    if (observed.kind === 'absent') refuse('SERVICE_PENDING', operation, `${leaf}-absent`);
    if (observed.kind !== 'file' || !(observed.bytes instanceof Uint8Array) || observed.bytes.byteLength > maximum) {
      refuse('SERVICE_STALE', operation, 'external-object');
    }
    const bytes = Buffer.from(observed.bytes);
    observed.bytes.fill(0);
    return { rootIdentityFingerprint, fileIdentityFingerprint: physicalFingerprint(observed.identity, operation), bytes };
  } finally {
    closeHandle(native, opened.handle, operation);
  }
}

function windowsJoin(root, relative) { return `${root}\\${relative.replaceAll('/', '\\')}`; }

// Captures the protected host authority for one configuration. Nothing here
// is caller supplied beyond the lifecycle-validated configuration record.
function captureAuthority(dependencies, native, { component, serviceKey, roles, configuration }, operation) {
  for (const key of ['runtimePath', 'workingDirectory', 'homeDirectory', 'logDirectory']) {
    if (!canonicalWindowsPath(configuration[key])) refuse('SERVICE_INVALID', operation, 'configuration-path');
  }
  if (component === 'bot' && !canonicalWindowsPath(configuration.channelsConfig)) {
    refuse('SERVICE_INVALID', operation, 'configuration-path');
  }
  const workingDirectory = configuration.workingDirectory;
  const env = readProtectedFile(native, workingDirectory, '.env', WINDOWS_HOST_LIMITS.envBytes, operation);
  let entries;
  try {
    let parsed;
    try { parsed = dependencies.parseDotenv(env.bytes); } catch { refuse('SERVICE_INVALID', operation, 'config-invalid'); }
    // The child inherits CHANNELS_CONFIG from the Launch; the guard refuses a
    // conflicting .env value, so refuse it here before any write.
    const inherited = component === 'bot' ? { CHANNELS_CONFIG: configuration.channelsConfig } : {};
    try { entries = validateServiceDotenvEntries(parsed, inherited); } catch (error) {
      refuse('SERVICE_INVALID', operation, error?.reason ?? 'config-invalid');
    }
  } finally {
    env.bytes.fill(0);
  }
  const effectiveConfigFingerprint = serviceEffectiveConfigFingerprint({ component, serviceKey, entries });
  let expectedState;
  if (component === 'bot') {
    expectedState = Object.freeze({
      expectedHostSetFingerprint: configuration.expectedHostSetFingerprint,
      expectedHostCount: configuration.expectedHostCount,
    });
  } else {
    const values = new Map(entries);
    try {
      expectedState = Object.freeze({
        targetFingerprint: serviceDaemonTargetFingerprint({ botWsUrl: values.get('BOT_WS_URL'), hostId: values.get('HOST_ID') }),
      });
    } catch {
      refuse('SERVICE_INVALID', operation, 'daemon-target-invalid');
    }
  }
  let runtimeConfig = null;
  if (component === 'daemon') {
    const root = `${workingDirectory}\\runtime-config`;
    const file = readProtectedFile(native, root, '.bunfig.toml', WINDOWS_HOST_LIMITS.runtimeConfigBytes, operation);
    if (file.bytes.byteLength !== 0) refuse('SERVICE_INVALID', operation, 'runtime-config-policy');
    runtimeConfig = Object.freeze({
      root,
      rootIdentityFingerprint: file.rootIdentityFingerprint,
      path: `${root}\\.bunfig.toml`,
      sha256: SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256,
      identityFingerprint: file.fileIdentityFingerprint,
    });
  }
  let scope;
  try {
    scope = dependencies.readAuthorityScope(native, { component, serviceKey, roles, workingDirectory });
  } catch {
    refuse('SERVICE_PENDING', operation, 'scope-catalog');
  }
  if (!exact(scope, ['scopeFingerprint', 'sdkProfileRoot']) || !validHash(scope.scopeFingerprint) ||
      (component === 'daemon' ? !canonicalWindowsPath(scope.sdkProfileRoot) : scope.sdkProfileRoot !== null)) {
    refuse('SERVICE_PENDING', operation, 'scope-catalog');
  }
  let runtimeFacts;
  try {
    runtimeFacts = validateServiceArtifactFileFacts(
      native.read_file_facts_no_follow(configuration.runtimePath, WINDOWS_HOST_LIMITS.runtimeBytes), 'win32');
  } catch {
    refuse('SERVICE_PENDING', operation, 'runtime-unavailable');
  }
  return Object.freeze({
    configurationFingerprint: serviceConfigurationFingerprint(configuration, { component, platform: 'win32' }),
    configuration,
    effectiveConfigFingerprint,
    configSourceIdentityFingerprint: env.fileIdentityFingerprint,
    expectedState,
    runtimeConfig,
    scopeFingerprint: scope.scopeFingerprint,
    sdkProfilePath: scope.sdkProfileRoot,
    runtimeSha256: runtimeFacts.sha256,
  });
}

// Derives the exact Launch for one release from signed manifest metadata, the
// lifecycle release binding and the captured host authority.
export function deriveWindowsServiceLaunch({ component, serviceKey, release, authority }, operation = 'derive_launch') {
  const manifest = release?.manifest;
  const bootstrap = manifest?.windowsServiceBootstrap;
  const relative = manifest?.entrypoints?.[component];
  if (!plain(bootstrap) || typeof relative !== 'string' || !Array.isArray(bootstrap.staticClosure) ||
      typeof bootstrap.guardPath !== 'string' || !validHash(bootstrap.staticClosureFingerprint)) {
    refuse('SERVICE_PENDING', operation, 'bootstrap-metadata-missing');
  }
  const policy = bootstrap.runtimePolicies?.[component];
  const runtime = SERVICE_BOOTSTRAP_RUNTIMES[component];
  if (!plain(policy) || policy.version !== runtime.version || policy.sourceRevision !== runtime.sourceRevision) {
    refuse('SERVICE_PENDING', operation, 'runtime-policy-mismatch');
  }
  const entrypointPath = release.entrypointPath;
  const suffix = `\\${relative.replaceAll('/', '\\')}`;
  if (!canonicalWindowsPath(entrypointPath) || entrypointPath.length <= suffix.length ||
      entrypointPath.slice(-suffix.length).toLowerCase() !== suffix.toLowerCase() ||
      !validHash(release.entrypointSha256) || !canonicalWindowsPath(release.supervisorPath) ||
      !validHash(release.supervisorSha256)) {
    refuse('SERVICE_PENDING', operation, 'release-binding');
  }
  const releaseRoot = entrypointPath.slice(0, -suffix.length);
  const guard = bootstrap.staticClosure.find((entry) => entry?.relativePath === bootstrap.guardPath);
  if (!guard || !validHash(guard.sha256)) refuse('SERVICE_PENDING', operation, 'bootstrap-metadata-missing');
  const { configuration, runtimeConfig } = authority;
  const launch = {
    supervisorPath: release.supervisorPath,
    supervisorSha256: release.supervisorSha256,
    workingDirectory: configuration.workingDirectory,
    homeDirectory: configuration.homeDirectory,
    runtimePath: configuration.runtimePath,
    runtimeSha256: authority.runtimeSha256,
    runtimeVersion: runtime.version,
    runtimeSourceRevision: runtime.sourceRevision,
    entrypointPath,
    entrypointSha256: release.entrypointSha256,
    bootstrapPath: windowsJoin(releaseRoot, bootstrap.guardPath),
    bootstrapSha256: guard.sha256,
    bootstrapClosureFingerprint: bootstrap.staticClosureFingerprint,
    runtimeConfigRoot: runtimeConfig?.root ?? null,
    runtimeConfigRootIdentityFingerprint: runtimeConfig?.rootIdentityFingerprint ?? null,
    runtimeConfigPath: runtimeConfig?.path ?? null,
    runtimeConfigSha256: runtimeConfig?.sha256 ?? null,
    runtimeConfigIdentityFingerprint: runtimeConfig?.identityFingerprint ?? null,
    sdkProfilePath: authority.sdkProfilePath,
    scopeFingerprint: authority.scopeFingerprint,
    logDirectory: configuration.logDirectory,
    logAs: component === 'bot' ? 'gjc-remote-bot-wrapper' : `gjc-remote-daemon-${serviceKey}-wrapper`,
    logCmdAs: component === 'bot' ? 'gjc-remote-bot-child' : `gjc-remote-daemon-${serviceKey}-child`,
    channelsConfig: component === 'bot' ? configuration.channelsConfig : null,
    effectiveConfigFingerprint: authority.effectiveConfigFingerprint,
    configSourceIdentityFingerprint: authority.configSourceIdentityFingerprint,
  };
  try {
    launch.runtimePolicyFingerprint = windowsServiceRuntimePolicyFingerprint(launch, component, serviceKey);
  } catch {
    refuse('SERVICE_PENDING', operation, 'launch-invalid');
  }
  return Object.freeze(launch);
}

function captureDependencies(value) {
  if (!exact(value, DEPENDENCY_KEYS) || DEPENDENCY_KEYS.some((key) => typeof value[key] !== 'function')) {
    throw new TypeError('invalid Windows host dependencies');
  }
  return Object.freeze({ ...value });
}

/** @internal Dependency-injected producer; production uses createWindowsHostOperation. */
export function createWindowsHostOperationFactory(dependencyValues) {
  const dependencies = captureDependencies(dependencyValues);
  // Construction is write-free and never throws; the platform/tuple binding
  // is refused at the first operation call so the CLI renders a receipt.
  return function createOperation() {
    let state = 'new';
    let bound = null;
    let native = null;
    let authority = null;
    let driver = null;
    let compatibilityObserver = null;

    const nativeFor = (roles) => {
      if (native === null) {
        try { native = dependencies.createNative({ roles }); } catch { refuse('SERVICE_INVALID', bound.operation, 'native-unavailable'); }
      }
      return native;
    };
    const bind = (context, operationName) => {
      if (state === 'closed') refuse('SERVICE_INVALID', operationName, 'operation-closed');
      if (!plain(context) || !OPERATIONS.has(context.operation) || !plain(context.request)) refuse('SERVICE_INVALID', operationName, 'context');
      if (context.platform !== 'win32' || context.architecture !== 'x64') refuse('SERVICE_UNSUPPORTED', context.operation, 'unsupported-platform');
      if (bound === null) {
        bound = Object.freeze({
          operation: context.operation, request: context.request,
          component: context.request.target?.component, roles: context.request.roles,
        });
      } else if (bound.operation !== context.operation || bound.request !== context.request) {
        refuse('SERVICE_INVALID', operationName, 'context-drift');
      }
      return bound;
    };
    // The service key is derived from the validated request target, never
    // carried in it; the lifecycle session must be bound to the same key.
    const targetServiceKey = () => {
      try { return serviceKeyForTarget(bound.request.target); } catch { return refuse('SERVICE_INVALID', bound.operation, 'target'); }
    };
    const serviceKeyOf = (session) => {
      const serviceKey = session?.serviceKey;
      if (typeof serviceKey !== 'string' || serviceKey !== targetServiceKey()) refuse('SERVICE_INVALID', bound.operation, 'service-key');
      return serviceKey;
    };
    // Authority is captured once per operation and bound to one configuration
    // fingerprint; a later caller with a different configuration is refused.
    const authorityFor = (configuration, serviceKey) => {
      const fingerprint = (() => {
        try { return serviceConfigurationFingerprint(configuration, { component: bound.component, platform: 'win32' }); } catch {
          return refuse('SERVICE_INVALID', bound.operation, 'configuration');
        }
      })();
      if (authority !== null) {
        if (authority.serviceKey !== serviceKey || authority.value.configurationFingerprint !== fingerprint) {
          refuse('SERVICE_STALE', bound.operation, 'configuration-drift');
        }
        return authority.value;
      }
      const value = captureAuthority(dependencies, nativeFor(bound.roles), {
        component: bound.component, serviceKey, roles: bound.roles, configuration,
      }, bound.operation);
      authority = Object.freeze({ serviceKey, value });
      return value;
    };
    const retainedConfiguration = (session, request) => {
      if (request.configuration !== undefined) return request.configuration;
      const current = typeof session?.readManifest === 'function' ? session.readManifest('current') : null;
      if (!current?.present || !plain(current.value?.configuration)) refuse('SERVICE_PENDING', bound.operation, 'configuration-unavailable');
      return current.value.configuration;
    };
    const driverFor = ({ session, request, release, locks }) => {
      const serviceKey = serviceKeyOf(session);
      const configuration = retainedConfiguration(session, request);
      const captured = authorityFor(configuration, serviceKey);
      const launch = deriveWindowsServiceLaunch({ component: bound.component, serviceKey, release, authority: captured }, bound.operation);
      if (driver !== null) {
        if (driver.session !== session || driver.launch.runtimePolicyFingerprint !== launch.runtimePolicyFingerprint) {
          refuse('SERVICE_STALE', bound.operation, 'launch-drift');
        }
        return driver.value;
      }
      const options = {
        native: nativeFor(bound.roles), session, locks: locks ?? session.handoffDriverLocks(), roles: bound.roles,
        configuration, launch,
        shawl: {
          path: release.supervisorPath, sha256: release.supervisorSha256,
          runtimeSha256: captured.runtimeSha256, entrypointSha256: release.entrypointSha256,
        },
        clock: dependencies.clock, sleep: dependencies.sleep,
      };
      if (bound.operation === 'install' && Object.hasOwn(request, 'servicePassword')) options.servicePassword = request.servicePassword;
      const value = dependencies.createDriver(options);
      driver = Object.freeze({ session, launch, value });
      return value;
    };

    async function effectiveConfigPreflight(context) {
      const current = bind(context, 'effective_config_preflight');
      if (state !== 'new') refuse('SERVICE_INVALID', current.operation, 'preflight-repeated');
      if (!MUTATIONS.has(current.operation)) refuse('SERVICE_INVALID', current.operation, 'preflight-operation');
      if (current.operation === 'install' || (current.operation === 'update' && current.request.configuration !== undefined)) {
        authorityFor(current.request.configuration, targetServiceKey());
      }
      state = 'preflighted';
    }

    function lifecycleOptions(context) {
      const current = bind(context, 'compose_service_lifecycle');
      if (MUTATIONS.has(current.operation) ? state !== 'preflighted' : state !== 'new') {
        refuse('SERVICE_INVALID', current.operation, 'preflight-missing');
      }
      state = 'composed';
      const planResource = ({ session, request, release }) => {
        const planner = driverFor({ session, request, release, locks: undefined });
        const trial = planner.planResource({ phase: 'trial', applicationManifestFingerprint: release.applicationManifestFingerprint });
        const final = planner.planResource({ phase: 'final', applicationManifestFingerprint: release.applicationManifestFingerprint });
        return { trial: { ...trial }, final: { ...final } };
      };
      const compatibility = async ({ operation, request, release, old, session }) => {
        if (operation !== 'install' && operation !== 'update') refuse('SERVICE_INVALID', operation, 'compatibility-operation');
        // Recovery passes the recover request; the driver (created first)
        // already bound the authenticated recovery configuration.
        const configuration = authority?.value.configuration ?? retainedConfiguration(session, request);
        if (compatibilityObserver === null) {
          compatibilityObserver = dependencies.createCompatibilityObserver({
            candidate: release.manifest, component: bound.component, serviceKey: serviceKeyOf(session),
            roles: bound.roles, workingDirectory: configuration.workingDirectory,
            channelsConfig: bound.component === 'bot' ? configuration.channelsConfig : null,
          });
        }
        const captured = authority?.value ?? authorityFor(configuration, serviceKeyOf(session));
        const expected = { expectedScopeFingerprint: captured.scopeFingerprint };
        if (operation === 'install') return compatibilityObserver.assertFirstInstall(expected);
        // Update: `old` is the fingerprint-only old proof; authenticate the
        // current signed application manifest from the retained envelope.
        const fingerprint = old?.applicationManifestFingerprint;
        const retained = validHash(fingerprint) && typeof session?.readRetainedDeploymentEnvelope === 'function'
          ? session.readRetainedDeploymentEnvelope({ purpose: 'application', manifestFingerprint: fingerprint })
          : null;
        if (!plain(retained?.manifest) || retained.manifest.manifestFingerprint !== fingerprint) {
          refuse('SERVICE_PENDING', operation, 'current-release-unavailable');
        }
        return compatibilityObserver.assertUpdate({ current: retained.manifest, ...expected });
      };
      const observeApplication = (trialObservation) => {
        if (authority === null) refuse('SERVICE_PENDING', current.operation, 'authority-unavailable');
        return dependencies.createStartupObserver({
          trialObservation, expectedState: authority.value.expectedState,
        }).observeApplication;
      };
      return Object.freeze({
        roles: current.roles,
        target: current.request.target,
        native: nativeFor(current.roles),
        effectiveConfigPreflight,
        observeApplication,
        compatibility,
        planResource,
        createWindowsDriver: driverFor,
        clock: dependencies.clock,
        sleep: dependencies.sleep,
      });
    }

    function close() {
      state = 'closed';
      authority = null;
      driver = null;
      compatibilityObserver = null;
    }

    return Object.freeze({ effectiveConfigPreflight, lifecycleOptions, close });
  };
}

export const createWindowsHostOperation = createWindowsHostOperationFactory({
  createNative: (options) => createServiceNative(options),
  createDriver: (options) => createWindowsServiceDriver(options),
  createCompatibilityObserver: (input) => createServiceCompatibilityObserver(input),
  readAuthorityScope: (native, input) => readServiceAuthorityScope(native, input),
  createStartupObserver: (options) => createServiceStartupObserver(options),
  parseDotenv: (bytes) => dotenv.parse(bytes),
  clock: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => { setTimeout(resolve, ms); }),
});
