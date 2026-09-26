import { createHash } from 'node:crypto';
import { win32 as path } from 'node:path';
import {
  APPLICATION_BUNDLE_INVENTORY_PATH,
  DEPLOYMENT_ENVELOPE_LIMITS,
  assertFirstServiceInstallCompatible,
  assertReleaseTransitionCompatible,
  validateApplicationDeploymentManifest,
  validateBundleInventory,
} from '@gjc-remote/shared/deployment-envelope';
import { DEPLOYMENT_FORMAT_REGISTRY } from '@gjc-remote/shared/deployment-format-registry';
import { canonicalJsonHash, isHex64, parseCanonicalJsonBytes, parseStrictJsonBytes, utf8Compare } from '@gjc-remote/shared/strict-json';
import * as admissionEnvelope from '@gjc-remote/shared/admission-envelope';
import * as genesisEnvelope from '@gjc-remote/shared/genesis-envelope';
import * as mappingEnvelope from '@gjc-remote/shared/mapping-envelope';
import {
  serviceNativeIdentityFingerprint,
  validateServiceArtifactFileFacts,
  serviceRolesFingerprint,
  validateServiceKey,
  validateServiceNativeIdentity,
  validateServiceRoles,
  win32PhysicalSecurityIdentityFingerprint,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import {
  isControlRoot,
  isLegacyRetainedWrapper,
  isManagedV1Wrapper,
  validateManagedMappingRecord,
  validateManagedChannelsV2,
} from '@gjc-remote/shared/mapping-envelope';
import { validateManualCleanup } from '@gjc-remote/shared/recovery-envelope';
import * as recoveryEnvelope from '@gjc-remote/shared/recovery-envelope';
import * as publicationEnvelope from '@gjc-remote/shared/publication-envelope';
import * as successorEnvelope from '@gjc-remote/shared/successor-envelope';
import {
  parseBunProductionLock,
  resolveBunProductionClosure,
  collectBunPackageClosure,
  SERVICE_PRODUCTION_WORKSPACES,
} from './service-production-closure.js';
import { validateManagedHistoryMarker } from '@gjc-remote/shared/successor-envelope';
import {
  validateWorkspaceLifecycleCheckpoint,
  validateWorkspaceLifecycleHead,
  validateWorkspaceLifecycleTransaction,
} from '@gjc-remote/shared/workspace-lifecycle-envelope';
import { createServiceNative } from './index.js';
import { assertPinnedDeploymentManifest, verifyPinnedDeploymentProvenance } from './deployment-provenance.js';
import {
  assertSdkExternalStateContract,
  SDK_EXTERNAL_STATE_REQUIREMENTS,
} from './service-sdk-contract.js';

const SDK_INVENTORY_LIMITS = Object.freeze({
  maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
  maxDepth: 16,
  maxNodes: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries * 6 + 32,
});
const SDK_INVENTORY_MAX_BYTES = DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes;
const SDK_METADATA_MAX_BYTES = 1024 * 1024;
const WIN32_PHYSICAL_IDENTITY_KIND = 'gjc-remote/win32-physical-security-identity/v1';

export const SERVICE_COMPATIBILITY_LIMITS = Object.freeze({
  inventoryEntries: 100_000,
  depth: 64,
  markerBytes: 64 * 1024 * 1024,
  catalogBytes: 256 * 1024,
  jsonBytes: 1024 * 1024,
  sessionHeaderBytes: 16 * 1024,
});

export const SERVICE_COMPATIBILITY_ROOT_PROFILES = Object.freeze([
  'config',
  'retained-state',
  'sdk-install',
]);

const ROOT_PROFILES = new Set(SERVICE_COMPATIBILITY_ROOT_PROFILES);
const COMPONENTS = new Set(['bot', 'daemon']);
const ROLE_KEYS = Object.freeze(['management', 'bot', 'recovery', 'daemon', 'system']);
const CATALOG_KEYS = Object.freeze([
  'schemaVersion', 'kind', 'serviceKey', 'rolesFingerprint', 'workDirs',
  'nativeWorkspaceRoots', 'sdk', 'scopeFingerprint',
]);
const ROOT_REF_KEYS = Object.freeze(['path', 'identityFingerprint']);
const SDK_KEYS = Object.freeze([
  'installationRoot', 'profileRoot', 'packageVersion', 'lockIntegrity',
  'sdkExternalStateContractFingerprint', 'provenanceManifestPath',
  'provenanceSignaturePath', 'stateIdentityAttestation',
]);
const ATTESTATION_KEYS = Object.freeze([
  'schemaVersion', 'profileIdentityFingerprint', 'sdkExternalStateContractFingerprint',
  'guarantee', 'attestationFingerprint',
]);
const OPEN_ROOT_KEYS = Object.freeze([
  'handle', 'profile', 'absolutePath', 'rootIdentity', 'absence', 'writes',
]);
const OBSERVATION_KEYS = Object.freeze([
  'kind', 'identity', 'absence', 'bytes', 'entries', 'writes',
]);
const DIRECTORY_ENTRY_KEYS = Object.freeze(['name', 'kind', 'identity']);
const REGISTRY_DOMAINS = Object.freeze([
  DEPLOYMENT_FORMAT_REGISTRY.bot,
  DEPLOYMENT_FORMAT_REGISTRY.daemonAppSession,
  DEPLOYMENT_FORMAT_REGISTRY.workspaceLifecycle,
]);
const REGISTRY_FORMAT_IDS = new Map(REGISTRY_DOMAINS.map(({ domain, formats }) => [
  domain,
  new Set(formats.map((format) => format.formatId)),
]));
const CONTROL_CHARS = /[\p{Cc}\p{Cs}\u2028\u2029]/u;
const RECEIPT_BRANDS = new WeakSet();

function refuse(reason) {
  const error = new TypeError(`SERVICE_COMPATIBILITY_${reason.toUpperCase().replaceAll('-', '_')}`);
  error.code = `SERVICE_COMPATIBILITY_${reason.toUpperCase().replaceAll('-', '_')}`;
  error.operation = 'observe_service_compatibility';
  error.writes = 0;
  throw error;
}

function exactData(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))) return null;
    const copy = {};
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function exactArray(value, maximum) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || keys.some((key) => typeof key !== 'string') || value.length > maximum) return null;
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      copy.push(descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function freezeCopy(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return Object.freeze(value.map(freezeCopy));
  const result = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') refuse('evidence-shape');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) refuse('evidence-shape');
    Object.defineProperty(result, key, {
      value: freezeCopy(descriptor.value), enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(result);
}

function text(value, maximum, reason) {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > maximum ||
      CONTROL_CHARS.test(value)) refuse(reason);
  return value;
}

function windowsPath(value, reason) {
  text(value, 4096, reason);
  if (!/^[A-Z]:\\/.test(value) || value.includes('/') || value !== path.normalize(value) ||
      value.startsWith('\\\\?\\') || value.startsWith('\\\\.\\') ||
      (value.length > 3 && value.endsWith('\\'))) refuse(reason);
  if (value.slice(3).split('\\').some((part) => part === '' || part === '.' || part === '..' ||
      /[<>:"|?*]/.test(part) || /[. ]$/.test(part) ||
      /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/i.test(part))) refuse(reason);
  return value;
}

function relativePath(value, reason, allowEmpty = false) {
  if (allowEmpty && value === '') return value;
  text(value, 4096, reason);
  if (value.startsWith('/') || value.includes('\\')) refuse(reason);
  const parts = value.split('/');
  if (parts.length > SERVICE_COMPATIBILITY_LIMITS.depth || parts.some((part) => part === '' || part === '.' ||
      part === '..' || /[<>:"|?*]/.test(part) || /[. ]$/.test(part) ||
      /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/i.test(part))) refuse(reason);
  return value;
}

function componentRootProfile(component, profile, directory) {
  if (profile === 'sdk-install') return directory ? 'service-sdk-install-directory' : 'service-sdk-install-file';
  const componentName = component === 'bot' ? 'bot' : 'daemon';
  return `service-${componentName}-${profile === 'config' ? 'config' : 'retained'}-${directory ? 'directory' : 'file'}`;
}

function identityFingerprint(identity, component, profile, directory, roles) {
  const expectedProfile = componentRootProfile(component, profile, directory);
  try {
    validateServiceNativeIdentity(identity, 'win32', expectedProfile);
  } catch {
    refuse('native-identity');
  }
  const expectedOwner = profile === 'retained-state' ? roles[component].value : roles.management.value;
  if (identity.owner !== expectedOwner) refuse('native-owner');
  return serviceNativeIdentityFingerprint(identity, 'win32', expectedProfile);
}

function absenceFingerprint(value) {
  const absence = exactData(value, ['parentIdentity', 'missingSegments']);
  const segments = absence && exactArray(absence.missingSegments, SERVICE_COMPATIBILITY_LIMITS.depth);
  if (!absence || !segments || segments.length === 0) refuse('anchored-absence');
  try { validateServiceNativeIdentity(absence.parentIdentity, 'win32'); } catch { refuse('anchored-absence'); }
  if (segments.some((segment) => typeof segment !== 'string' || segment.length === 0 ||
      segment === '.' || segment === '..' || segment.includes('/') || segment.includes('\\') || CONTROL_CHARS.test(segment))) {
    refuse('anchored-absence');
  }
  return canonicalJsonHash({ parentIdentity: absence.parentIdentity, missingSegments: segments });
}

function externalObject(native, handle, relative, mode, maximum) {
  const value = native.read_service_external_object(handle, relative, mode, maximum);
  const observation = exactData(value, OBSERVATION_KEYS);
  if (!observation || observation.writes !== 0 || !['absent', 'directory', 'file'].includes(observation.kind)) {
    refuse('native-observation');
  }
  if (observation.kind === 'absent') {
    if (observation.identity !== null || observation.bytes !== null || observation.entries !== null) refuse('native-absence');
    absenceFingerprint(observation.absence);
  } else {
    if (observation.absence !== null) refuse('native-observation');
    if (observation.kind === 'directory') {
      if (observation.bytes !== null || !Array.isArray(observation.entries)) refuse('native-directory');
    } else if (observation.entries !== null ||
        (mode === 'bytes' || mode === 'first-line'
          ? !(Buffer.isBuffer(observation.bytes) || observation.bytes instanceof Uint8Array)
          : observation.bytes !== null)) {
      refuse('native-file');
    }
  }
  return observation;
}

function openRoot(native, absolutePath, profile, component, roles, required) {
  if (!ROOT_PROFILES.has(profile)) refuse('root-profile');
  const value = native.open_service_external_root(absolutePath, profile);
  const opened = exactData(value, OPEN_ROOT_KEYS);
  if (!opened || opened.profile !== profile || opened.absolutePath !== absolutePath || opened.writes !== 0 ||
      opened.handle === null || typeof opened.handle !== 'object') {
    if (opened?.handle !== null && typeof opened?.handle === 'object') {
      try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
    }
    refuse('native-root');
  }
  if (opened.rootIdentity === null) {
    try {
      if (required || opened.absence === null) refuse('root-absent');
      const fingerprint = absenceFingerprint(opened.absence);
      return { handle: opened.handle, identity: null, identityFingerprint: null,
        absenceFingerprint: fingerprint };
    } catch (error) {
      try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
      throw error;
    }
  }
  try {
    if (opened.absence !== null) refuse('native-root');
    return {
      handle: opened.handle,
      identity: opened.rootIdentity,
      identityFingerprint: identityFingerprint(opened.rootIdentity, component, profile, true, roles),
      absenceFingerprint: null,
    };
  } catch (error) {
    try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
    throw error;
  }
}

function parseJson(bytes, maximum, reason) {
  try {
    return parseStrictJsonBytes(bytes, { maxBytes: maximum, maxDepth: 64, maxNodes: 100_000 });
  } catch {
    refuse(reason);
  }
}

function readFile(native, handle, relative, maximum, component, profile, roles, mode = 'bytes') {
  relativePath(relative, 'relative-path');
  const observation = externalObject(native, handle, relative, mode, maximum);
  if (observation.kind === 'absent') return observation;
  if (observation.kind !== 'file') refuse('expected-file');
  identityFingerprint(observation.identity, component, profile, false, roles);
  if (mode === 'bytes' || mode === 'first-line') {
    if (observation.bytes.byteLength > maximum) refuse('file-size');
  }
  return observation;
}

function chargeBudget(budget, entries, markerBytes) {
  budget.entries += entries;
  budget.markerBytes += markerBytes;
  if (!Number.isSafeInteger(budget.entries) || !Number.isSafeInteger(budget.markerBytes) ||
      budget.entries > SERVICE_COMPATIBILITY_LIMITS.inventoryEntries ||
      budget.markerBytes > SERVICE_COMPATIBILITY_LIMITS.markerBytes) refuse('inventory-limit');
}

function rootObservation(rootId, profile, absolutePath, identity, absence, listing, count, markerBytes) {
  return Object.freeze({
    rootId,
    profile,
    pathFingerprint: canonicalJsonHash(absolutePath),
    rootIdentityFingerprint: identity,
    absenceFingerprint: absence,
    listingFingerprint: listing,
    entryCount: count,
    markerBytes,
  });
}

function validateEntries(entries, component, profile, roles, budget, depth) {
  const values = exactArray(entries, SERVICE_COMPATIBILITY_LIMITS.inventoryEntries);
  if (!values || depth > SERVICE_COMPATIBILITY_LIMITS.depth) refuse('inventory-incomplete');
  let previous = null;
  const aliases = new Set();
  return values.map((value) => {
    const entry = exactData(value, DIRECTORY_ENTRY_KEYS);
    if (!entry || !['file', 'directory'].includes(entry.kind)) refuse('directory-entry');
    text(entry.name, 255, 'directory-entry-name');
    if (entry.name === '.' || entry.name === '..' || entry.name.includes('/') || entry.name.includes('\\') ||
        /[<>:"|?*]/.test(entry.name) || /[. ]$/.test(entry.name) ||
        /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/i.test(entry.name) ||
        (previous !== null && utf8Compare(previous, entry.name) >= 0)) refuse('directory-entry');
    previous = entry.name;
    const alias = entry.name.toLowerCase().toUpperCase();
    if (aliases.has(alias)) refuse('directory-alias');
    aliases.add(alias);
    const fingerprint = identityFingerprint(entry.identity, component, profile, entry.kind === 'directory', roles);
    chargeBudget(budget, 1, Buffer.byteLength(entry.name, 'utf8'));
    return Object.freeze({ name: entry.name, kind: entry.kind, identity: entry.identity, identityFingerprint: fingerprint });
  });
}

function scanTree(native, handle, rootIdentity, component, profile, roles, budget, prefix = '') {
  const first = externalObject(native, handle, prefix, 'directory', 0);
  const expectedRoot = serviceNativeIdentityFingerprint(rootIdentity, 'win32', rootIdentity.profile);
  if (first.kind !== 'directory' || serviceNativeIdentityFingerprint(first.identity, 'win32', rootIdentity.profile) !== expectedRoot) {
    refuse('root-drift');
  }
  const beforeEntries = budget.entries;
  const beforeBytes = budget.markerBytes;
  const queue = [{ relative: prefix, entries: first.entries, depth: 0 }];
  const inventory = [];
  while (queue.length > 0) {
    const current = queue.pop();
    const entries = validateEntries(current.entries, component, profile, roles, budget, current.depth + 1);
    for (const entry of entries) {
      const relative = current.relative === '' ? entry.name : `${current.relative}/${entry.name}`;
      relativePath(relative, 'inventory-path');
      inventory.push({ path: relative, kind: entry.kind, identity: entry.identity,
        identityFingerprint: entry.identityFingerprint });
      const recheck = externalObject(native, handle, relative, entry.kind === 'directory' ? 'directory' : 'facts', 0);
      if (recheck.kind !== entry.kind || serviceNativeIdentityFingerprint(
        recheck.identity, 'win32', entry.identity.profile) !== entry.identityFingerprint) refuse('root-drift');
      if (entry.kind === 'directory') queue.push({ relative, entries: recheck.entries, depth: current.depth + 1 });
    }
  }
  inventory.sort((left, right) => utf8Compare(left.path, right.path));
  const listingFingerprint = canonicalJsonHash(inventory.map(({ path: relative, kind, identityFingerprint }) => ({
    path: relative, kind, identityFingerprint,
  })));
  return Object.freeze({
    items: Object.freeze(inventory.map(Object.freeze)),
    listingFingerprint,
    entryCount: budget.entries - beforeEntries,
    markerBytes: budget.markerBytes - beforeBytes,
  });
}

function observeDirectory(native, {
  rootId, absolutePath, profile, component, roles, required = true,
  expectedIdentityFingerprint = undefined, budget,
  prefix = '', inspect = undefined,
}) {
  windowsPath(absolutePath, 'root-path');
  const opened = openRoot(native, absolutePath, profile, component, roles, required);
  if (opened.identity === null) {
    try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
    return Object.freeze({
      observation: rootObservation(rootId, profile, absolutePath, null, opened.absenceFingerprint, null, 0, 0),
      items: Object.freeze([]),
      result: null,
      rootIdentityFingerprint: null,
    });
  }
  if (expectedIdentityFingerprint !== undefined && opened.identityFingerprint !== expectedIdentityFingerprint) {
    try { native.close_service_handle(opened.handle); } catch { /* preserve drift refusal */ }
    refuse('root-drift');
  }
  try {
    const tree = scanTree(native, opened.handle, opened.identity, component, profile, roles, budget, prefix);
    const pathFingerprint = prefix === '' ? absolutePath : path.join(absolutePath, ...prefix.split('/'));
    const rootIdFingerprint = prefix === '' ? opened.identityFingerprint :
      tree.items.find((item) => item.path === prefix)?.identityFingerprint;
    const observation = rootObservation(rootId, profile, pathFingerprint,
      rootIdFingerprint ?? opened.identityFingerprint, null, tree.listingFingerprint, tree.entryCount, tree.markerBytes);
    const result = inspect ? inspect({ handle: opened.handle, tree, rootIdentity: opened.identity }) : null;
    return Object.freeze({ observation, items: tree.items, result,
      rootIdentityFingerprint: opened.identityFingerprint });
  } finally {
    try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
  }
}

function observeFile(native, {
  rootId, absolutePath, profile, component, roles, required = true, maximum, mode = 'bytes', budget,
}) {
  windowsPath(absolutePath, 'file-path');
  const parent = path.dirname(absolutePath);
  const opened = openRoot(native, parent, profile, component, roles, true);
  try {
    const relative = path.basename(absolutePath);
    const observation = externalObject(native, opened.handle, relative, mode, maximum);
    if (observation.kind === 'absent') {
      if (required) refuse('declared-file-missing');
      if (budget) {
        chargeBudget(budget, 1, Buffer.byteLength(relative, 'utf8'));
      }
      return Object.freeze({ observation: rootObservation(rootId, profile, absolutePath, null,
        absenceFingerprint(observation.absence), null, 0, 0), bytes: null, value: null });
    }
    if (observation.kind !== 'file') refuse('expected-file');
    const fingerprint = identityFingerprint(observation.identity, component, profile, false, roles);
    if (mode !== 'bytes' || observation.bytes.byteLength > maximum) refuse('file-read-mode');
    const bytes = Buffer.from(observation.bytes);
    const payloadFingerprint = createHash('sha256').update(bytes).digest('hex');
    if (budget) {
      chargeBudget(budget, 1, Buffer.byteLength(relative, 'utf8'));
    }
    return Object.freeze({
      observation: rootObservation(rootId, profile, absolutePath, opened.identityFingerprint, null,
        canonicalJsonHash({ fileIdentityFingerprint: fingerprint, payloadFingerprint }), 1, 0),
      bytes,
      value: parseJson(bytes, maximum, 'declared-file-json'),
    });
  } finally {
    try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
  }
}

function validateRootRefs(input, name) {
  const values = exactArray(input, 1000);
  if (!values) refuse(`${name}-schema`);
  const refs = [];
  let previous = null;
  const keys = new Set();
  for (const value of values) {
    const record = exactData(value, ROOT_REF_KEYS);
    if (!record || !isHex64(record.identityFingerprint)) refuse(`${name}-entry`);
    const absolutePath = windowsPath(record.path, `${name}-path`);
    const folded = absolutePath.toLowerCase().toUpperCase();
    if (keys.has(folded) || (previous !== null && utf8Compare(previous, absolutePath) >= 0)) refuse(`${name}-order`);
    keys.add(folded);
    previous = absolutePath;
    refs.push(Object.freeze({ path: absolutePath, identityFingerprint: record.identityFingerprint }));
  }
  for (let left = 0; left < refs.length; left += 1) {
    for (let right = left + 1; right < refs.length; right += 1) {
      const a = refs[left].path.toLowerCase().toUpperCase().replace(/\\$/, '');
      const b = refs[right].path.toLowerCase().toUpperCase().replace(/\\$/, '');
      if (a === b || a.startsWith(`${b}\\`) || b.startsWith(`${a}\\`)) refuse(`${name}-overlap`);
    }
  }
  return Object.freeze(refs);
}

function assertDisjointRoots(...groups) {
  const roots = groups.flat();
  for (let left = 0; left < roots.length; left += 1) {
    const a = roots[left].path.toLowerCase().toUpperCase().replace(/\\$/, '');
    for (let right = left + 1; right < roots.length; right += 1) {
      const b = roots[right].path.toLowerCase().toUpperCase().replace(/\\$/, '');
      if (a === b || a.startsWith(`${b}\\`) || b.startsWith(`${a}\\`)) refuse('scope-root-overlap');
    }
  }
}

function validateAttestation(value) {
  const record = exactData(value, ATTESTATION_KEYS);
  if (!record || record.schemaVersion !== 1 || !isHex64(record.profileIdentityFingerprint) ||
      !isHex64(record.sdkExternalStateContractFingerprint) || record.guarantee !== 'operator-attested-identity' ||
      !isHex64(record.attestationFingerprint) ||
      canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) =>
        key !== 'attestationFingerprint'))) !== record.attestationFingerprint) refuse('sdk-attestation');
  return Object.freeze(record);
}

function validateSdkScope(value) {
  if (value === null) return null;
  const record = exactData(value, SDK_KEYS);
  if (!record || record.packageVersion !== SDK_EXTERNAL_STATE_REQUIREMENTS.packageVersion ||
      record.lockIntegrity !== SDK_EXTERNAL_STATE_REQUIREMENTS.lockIntegrity ||
      !isHex64(record.sdkExternalStateContractFingerprint)) refuse('sdk-scope');
  const result = Object.freeze({
    installationRoot: windowsPath(record.installationRoot, 'sdk-installation-root'),
    profileRoot: windowsPath(record.profileRoot, 'sdk-profile-root'),
    packageVersion: record.packageVersion,
    lockIntegrity: record.lockIntegrity,
    sdkExternalStateContractFingerprint: record.sdkExternalStateContractFingerprint,
    provenanceManifestPath: relativePath(record.provenanceManifestPath, 'sdk-provenance-path'),
    provenanceSignaturePath: relativePath(record.provenanceSignaturePath, 'sdk-signature-path'),
    stateIdentityAttestation: validateAttestation(record.stateIdentityAttestation),
  });
  if (result.provenanceManifestPath === result.provenanceSignaturePath) refuse('sdk-provenance-path');
  return result;
}

function validateCatalog(bytes, binding) {
  const value = parseJson(bytes, SERVICE_COMPATIBILITY_LIMITS.catalogBytes, 'scope-catalog');
  const record = exactData(value, CATALOG_KEYS);
  if (!record || record.schemaVersion !== 1 || record.kind !== 'windows-service-state-scope' ||
      record.serviceKey !== binding.serviceKey ||
      record.rolesFingerprint !== serviceRolesFingerprint(binding.roles, 'win32') ||
      !isHex64(record.scopeFingerprint)) refuse('scope-catalog');
  const workDirs = validateRootRefs(record.workDirs, 'workdirs');
  const nativeWorkspaceRoots = validateRootRefs(record.nativeWorkspaceRoots, 'workspace-roots');
  const sdk = validateSdkScope(record.sdk);
  assertDisjointRoots(workDirs, nativeWorkspaceRoots, sdk === null ? [] : [
    { path: sdk.installationRoot }, { path: sdk.profileRoot },
  ]);
  if (binding.component === 'bot' &&
      (workDirs.length !== 0 || nativeWorkspaceRoots.length !== 0 || sdk !== null)) refuse('scope-component');
  if (binding.component === 'daemon' && sdk === null) refuse('sdk-scope-missing');
  if (sdk !== null && (sdk.installationRoot.toLowerCase().toUpperCase() === sdk.profileRoot.toLowerCase().toUpperCase() ||
      sdk.installationRoot.toLowerCase().toUpperCase().startsWith(`${sdk.profileRoot.toLowerCase().toUpperCase()}\\`) ||
      sdk.profileRoot.toLowerCase().toUpperCase().startsWith(`${sdk.installationRoot.toLowerCase().toUpperCase()}\\`))) {
    refuse('sdk-scope-overlap');
  }
  const normalized = Object.freeze({
    schemaVersion: record.schemaVersion,
    kind: record.kind,
    serviceKey: record.serviceKey,
    rolesFingerprint: record.rolesFingerprint,
    workDirs,
    nativeWorkspaceRoots,
    sdk,
    scopeFingerprint: record.scopeFingerprint,
  });
  const expected = canonicalJsonHash(Object.fromEntries(Object.entries(normalized).filter(([key]) =>
    key !== 'scopeFingerprint')));
  if (expected !== normalized.scopeFingerprint) refuse('scope-fingerprint');
  return normalized;
}

function recordFormat(formats, domain, formatId) {
  if (!REGISTRY_FORMAT_IDS.get(domain)?.has(formatId)) refuse('unregistered-format');
  formats[domain].add(formatId);
}

function registeredFormatDefinition(domain, value) {
  const definition = REGISTRY_DOMAINS.find((candidate) => candidate.domain === domain);
  if (!definition || value === null || typeof value !== 'object' || Array.isArray(value)) refuse('unknown-format');
  const matches = definition.formats.filter(({ marker }) =>
    Object.entries(marker).every(([key, expected]) => value[key] === expected));
  if (matches.length !== 1) refuse('unknown-or-ambiguous-format');
  return matches[0];
}

function registeredFormat(domain, value) {
  return registeredFormatDefinition(domain, value).formatId;
}

const FORMAT_VALIDATORS = new Map([
  ['shared/admission-envelope.js', admissionEnvelope],
  ['shared/genesis-envelope.js', genesisEnvelope],
  ['shared/mapping-envelope.js', mappingEnvelope],
  ['shared/publication-envelope.js', publicationEnvelope],
  ['shared/recovery-envelope.js', recoveryEnvelope],
  ['shared/successor-envelope.js', successorEnvelope],
]);
const FORMAT_VALIDATOR_ALIASES = new Map([
  ['admission-ack', 'validateAdmissionAckRecord'],
  ['authority-baseline', 'validateBaselineSnapshot'],
  ['genesis-finality', 'validateZFinality'],
  ['legacy-retained-wrapper', 'isLegacyRetainedWrapper'],
  ['managed-v1-wrapper', 'isManagedV1Wrapper'],
  ['management-control-root', 'isControlRoot'],
  ['mapping-recovery-bk', 'validateMappingRecoveryBackup'],
  ['mapping-recovery-pub', 'validateMappingRecoveryPublication'],
  ['mapping-recovery-rc', 'validateMappingRecoveryCheckpoint'],
  ['mapping-recovery-tx', 'validateMappingRecoveryTransaction'],
  ['reader-fence-binding', 'validateFenceBinding'],
  ['reader-lease-binding', 'validateLeaseBinding'],
  ['token-generation-floor', 'validateTokenFloor'],
]);

function relatedBotRecord(records, kind, source, fields) {
  const matches = records.filter((record) => record.kind === kind && fields.every(([left, right]) =>
    record[left] === source[right]));
  if (matches.length === 0) refuse('bot-format-relation-missing');
  const fingerprints = new Set(matches.map((record) => canonicalJsonHash(record)));
  if (fingerprints.size !== 1) refuse('bot-format-relation-ambiguous');
  return matches[0];
}

function relatedByFingerprint(records, kind, source, sourceField, recordField) {
  return relatedBotRecord(records, kind, source, [[sourceField, recordField]]);
}

function readerVersionFloorFor(records, source) {
  return relatedBotRecord(records, 'reader-version-floor', source, [
    ['anchorFingerprint', 'anchorFingerprint'], ['readerVersionFloor', 'readerVersion'],
  ]);
}

function botValidatorName(format) {
  const kind = format.marker.kind;
  if (typeof kind === 'string') {
    return FORMAT_VALIDATOR_ALIASES.get(kind) ?? `validate${kind.split('-').map((part) =>
      `${part[0].toUpperCase()}${part.slice(1)}`).join('')}`;
  }
  if (format.marker.mappingVersion === 1) return 'validateManagedMappingRecord';
  if (format.marker.readerVersion === 2 && format.source === 'shared/genesis-envelope.js') {
    return 'validateReaderRelations';
  }
  return null;
}

function botValidatorArguments(name, value, records) {
  switch (name) {
    case 'validateAdmissionAckRecord':
      return [value];
    case 'validateAdmissionGrant':
      return [value, relatedByFingerprint(records, 'admission-request', value, 'requestFingerprint', 'requestFingerprint')];
    case 'validateAuthorityCommitSnapshot':
      return [value, relatedByFingerprint(records, 'authority-reservation', value, 'reservationFingerprint', 'reservationFingerprint')];
    case 'validateFenceBinding':
      return [value,
        relatedByFingerprint(records, 'authority-commit-snapshot', value, 'authorityCommitSnapshotFingerprint', 'authorityCommitSnapshotFingerprint'),
        readerVersionFloorFor(records, value)];
    case 'validateFinalityProof': {
      const request = relatedBotRecord(records, 'genesis-request', value, [['genesisTxId', 'genesisTxId']]);
      const finality = relatedByFingerprint(records, 'genesis-finality', value, 'zFinalityFingerprint', 'zFinalityFingerprint');
      if (value.ackFingerprint === null) return [value, request, finality];
      const ack = relatedByFingerprint(records, 'admission-ack', value, 'ackFingerprint', 'ackFingerprint');
      return [value, request, finality, ack, ack.readerProjectionFingerprint];
    }
    case 'validateGenesisAuthorityReceipt':
      return [value, relatedBotRecord(records, 'genesis-authority-request', value,
        [['genesisTxId', 'genesisTxId'], ['requestFingerprint', 'requestFingerprint']])];
    case 'validateGenesisReceipt': {
      const request = relatedBotRecord(records, 'genesis-request', value, [['genesisTxId', 'genesisTxId']]);
      const finality = relatedBotRecord(records, 'genesis-finality', value, [['genesisTxId', 'genesisTxId']]);
      const proof = relatedByFingerprint(records, 'finality-proof', value,
        'finalityProofFingerprint', 'finalityProofFingerprint');
      return [value, request, finality, proof];
    }
    case 'validateLeaseBinding':
      return [value, relatedByFingerprint(records, 'reader-fence-binding', value, 'fenceBindingFingerprint', 'fenceBindingFingerprint')];
    case 'validateMappingRecoveryBackup':
    case 'validateMappingRecoveryPublication':
      return [value, relatedBotRecord(records, 'mapping-recovery-tx', value, [['txId', 'txId']])];
    case 'validateMappingRecoveryCheckpoint': {
      const transaction = relatedBotRecord(records, 'mapping-recovery-tx', value, [['txId', 'txId']]);
      const publication = relatedBotRecord(records, 'mapping-recovery-pub', value, [['txId', 'txId']]);
      const backup = relatedBotRecord(records, 'mapping-recovery-bk', value, [['txId', 'txId']]);
      return [value, transaction, publication, backup];
    }
    case 'validatePublicationP':
      return [value, relatedByFingerprint(records, 'publication-u', value, 'uFingerprint', 'publication-uFingerprint')];
    case 'validatePublicationS':
      return [value, relatedByFingerprint(records, 'publication-p', value, 'pFingerprint', 'publication-pFingerprint')];
    case 'validatePublicationC':
      return [value, relatedByFingerprint(records, 'publication-s', value, 'sFingerprint', 'publication-sFingerprint')];
    case 'validatePublicationQ':
      return [value, relatedByFingerprint(records, 'publication-c', value, 'cFingerprint', 'publication-cFingerprint')];
    case 'validatePublicationZp':
      return [value, relatedByFingerprint(records, 'publication-q', value, 'qFingerprint', 'publication-qFingerprint')];
    case 'validatePublicationK':
      return [value, relatedByFingerprint(records, 'publication-zp', value, 'zpFingerprint', 'publication-zpFingerprint')];
    case 'validatePublicationY':
      return [value, relatedByFingerprint(records, 'publication-k', value, 'kFingerprint', 'publication-kFingerprint')];
    case 'validatePublicationState':
      return [value, relatedBotRecord(records, 'publication-transaction', value, [['txId', 'txId']])];
    case 'validateReaderProjection': {
      const finality = relatedByFingerprint(records, 'genesis-finality', value, 'zFinalityFingerprint', 'zFinalityFingerprint');
      const tokenFloor = relatedByFingerprint(records, 'token-generation-floor', finality,
        'tokenFloorFingerprint', 'floorFingerprint');
      return [value, readerVersionFloorFor(records, value), tokenFloor, finality.zFinalityFingerprint];
    }
    case 'validateReaderRelations':
      return [value, readerVersionFloorFor(records, value)];
    case 'validateZFinality': {
      const request = relatedBotRecord(records, 'genesis-request', value, [['genesisTxId', 'genesisTxId']]);
      const tokenFloor = relatedByFingerprint(records, 'token-generation-floor', value, 'tokenFloorFingerprint', 'floorFingerprint');
      const precommit = relatedByFingerprint(records, 'genesis-precommit-proof', value,
        'precommitFingerprint', 'precommitFingerprint');
      return [value, request, tokenFloor, precommit];
    }
    case 'validateAttestedTokenFloorProof':
      return [value,
        relatedByFingerprint(records, 'token-floor-reservation', value, 'reservationFingerprint', 'floorFingerprint'),
        relatedByFingerprint(records, 'token-config-attestation', value, 'attestationFingerprint', 'attestationFingerprint')];
    default:
      return [value];
  }
}

function validateBotRegisteredRecords(values, formats) {
  if (values.some((value) => Array.isArray(value) && value.length === 0)) refuse('unregistered-bot-format');
  const records = values.flatMap((value) => Array.isArray(value) ? value : [value]);
  if (records.some((record) => record === null || typeof record !== 'object' || Array.isArray(record))) {
    refuse('unregistered-bot-format');
  }
  for (const record of records) {
    const format = registeredFormatDefinition('bot-mapping-reader', record);
    const validators = FORMAT_VALIDATORS.get(format.source);
    const name = botValidatorName(format);
    const validator = validators?.[name];
    if (typeof validator !== 'function') refuse('unvalidated-bot-format');
    try {
      const result = validator(...botValidatorArguments(name, record, records));
      if (result === false) refuse('unvalidated-bot-format');
    } catch {
      refuse('unvalidated-bot-format');
    }
    recordFormat(formats, 'bot-mapping-reader', format.formatId);
  }
}

function parseSessionHeader(native, handle, relative, expectedIdentityFingerprint,
  component, profile, roles, formats) {
  const observation = readFile(native, handle, relative, SERVICE_COMPATIBILITY_LIMITS.sessionHeaderBytes,
    component, profile, roles, 'first-line');
  if (observation.kind !== 'file') refuse('session-header');
  if (serviceNativeIdentityFingerprint(observation.identity, 'win32',
      componentRootProfile(component, profile, false)) !== expectedIdentityFingerprint) refuse('root-drift');
  const bytes = Buffer.from(observation.bytes);
  const newline = bytes.indexOf(0x0a);
  const line = newline === -1 ? bytes : bytes.subarray(0, newline);
  const json = line.length > 0 && line.at(-1) === 0x0d ? line.subarray(0, line.length - 1) : line;
  const header = parseJson(json, SERVICE_COMPATIBILITY_LIMITS.sessionHeaderBytes, 'session-header');
  if (header === null || typeof header !== 'object' || Array.isArray(header) ||
      header.type !== 'session' || header.version !== SDK_EXTERNAL_STATE_REQUIREMENTS.transcriptVersion) {
    refuse('unsupported-session-format');
  }
  recordFormat(formats, 'daemon-app-session', registeredFormat('daemon-app-session', header));
}

function scanSessionSubtree(native, handle, workDir, relative, component, roles, budget, formats) {
  const observation = externalObject(native, handle, relative, 'directory', 0);
  if (observation.kind === 'absent') {
    return rootObservation('daemon-workdir-session', 'retained-state', path.join(workDir, relative), null,
      absenceFingerprint(observation.absence), null, 0, 0);
  }
  if (observation.kind !== 'directory') refuse('session-root-type');
  const tree = scanTree(native, handle, observation.identity, component, 'retained-state', roles, budget, relative);
  for (const item of tree.items) {
    if (item.kind === 'file' && item.path.toLowerCase().endsWith('.jsonl')) {
      parseSessionHeader(native, handle, item.path, item.identityFingerprint,
        component, 'retained-state', roles, formats);
    }
  }
  const identity = identityFingerprint(observation.identity, component, 'retained-state', true, roles);
  return rootObservation('daemon-workdir-session', 'retained-state', path.join(workDir, relative), identity,
    null, tree.listingFingerprint, tree.entryCount, tree.markerBytes);
}

function inspectWorkspaceRecords(native, binding, rootRef, items, formats) {
  const lifecycleWorkspaces = new Set();
  for (const item of items) {
    const parts = item.path.split('/');
    if (parts.length >= 2 && parts[1] === 'lifecycle') {
      if ((parts.length === 2 && item.kind !== 'directory') || parts.length > 3 ||
          (parts.length === 3 && (item.kind !== 'file' ||
            !['transaction.json', 'checkpoint.json', 'manual-cleanup.json', 'head.json'].includes(parts[2])))) {
        refuse('unknown-workspace-lifecycle');
      }
      lifecycleWorkspaces.add(parts[0]);
    }
  }
  for (const workspaceId of lifecycleWorkspaces) {
    const prefix = `${workspaceId}/lifecycle`;
    const files = items.filter((item) => item.path.startsWith(`${prefix}/`) && item.kind === 'file');
    let transaction = null;
    let checkpoint = null;
    for (const item of files) {
      const name = item.path.slice(item.path.lastIndexOf('/') + 1);
      if (!['transaction.json', 'checkpoint.json', 'manual-cleanup.json', 'head.json'].includes(name)) {
        refuse('unknown-workspace-lifecycle');
      }
      const opened = openRoot(native, rootRef.path, 'retained-state', 'daemon', binding.roles, true);
      try {
        if (opened.identityFingerprint !== rootRef.identityFingerprint) refuse('root-drift');
        const observed = readFile(native, opened.handle, item.path, SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
          'daemon', 'retained-state', binding.roles);
        if (observed.kind !== 'file' || serviceNativeIdentityFingerprint(observed.identity,
            'win32', 'service-daemon-retained-file') !== item.identityFingerprint) {
          refuse('workspace-lifecycle-drift');
        }
        const record = parseJson(Buffer.from(observed.bytes), SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
          'workspace-lifecycle-json');
        if (name === 'transaction.json') {
          transaction = validateWorkspaceLifecycleTransaction(record);
          recordFormat(formats, 'workspace-lifecycle', registeredFormat('workspace-lifecycle', record));
        } else if (name === 'checkpoint.json') {
          checkpoint = record;
        } else if (name === 'head.json') {
          validateWorkspaceLifecycleHead(record);
          recordFormat(formats, 'workspace-lifecycle', registeredFormat('workspace-lifecycle', record));
        } else {
          validateManualCleanup(record);
          recordFormat(formats, 'workspace-lifecycle', registeredFormat('workspace-lifecycle', record));
        }
      } finally {
        try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
      }
    }
    if (checkpoint !== null) {
      if (transaction === null) refuse('workspace-transaction-missing');
      validateWorkspaceLifecycleCheckpoint(checkpoint, transaction);
      recordFormat(formats, 'workspace-lifecycle', registeredFormat('workspace-lifecycle', checkpoint));
    }
  }
}

function observeWorkDir(native, binding, rootRef, index, budget, formats, observations) {
  const rootId = `daemon-workdir-${String(index).padStart(4, '0')}`;
  const sessionPath = path.join(rootRef.path, '.gjc-remote-session');
  const opened = openRoot(native, rootRef.path, 'retained-state', 'daemon', binding.roles, true);
  if (opened.identityFingerprint !== rootRef.identityFingerprint) {
    try { native.close_service_handle(opened.handle); } catch { /* preserve drift refusal */ }
    refuse('root-drift');
  }
  try {
    const result = scanSessionSubtree(native, opened.handle, rootRef.path,
      '.gjc-remote-session', 'daemon', binding.roles, budget, formats);
    observations.push(Object.freeze({ ...result, rootId, pathFingerprint: canonicalJsonHash(sessionPath) }));
  } finally {
    try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
  }
}

async function inspectDaemonScope(native, binding, catalog, budget, observations, formats) {
  for (let index = 0; index < catalog.workDirs.length; index += 1) {
    observeWorkDir(native, binding, catalog.workDirs[index], index, budget, formats, observations);
  }
  for (let index = 0; index < catalog.nativeWorkspaceRoots.length; index += 1) {
    const rootRef = catalog.nativeWorkspaceRoots[index];
    const result = observeDirectory(native, {
      rootId: `daemon-workspace-root-${String(index).padStart(4, '0')}`,
      absolutePath: rootRef.path,
      profile: 'retained-state',
      component: 'daemon',
      roles: binding.roles,
      expectedIdentityFingerprint: rootRef.identityFingerprint,
      budget,
    });
    observations.push(result.observation);
    inspectWorkspaceRecords(native, binding, rootRef, result.items, formats);
  }
  return inspectSdkInstallation(native, binding, catalog.sdk, budget, observations);
}

function closeServiceHandle(native, handle) {
  try {
    native.close_service_handle(handle);
  } catch {
    refuse('native-close');
  }
}

function observeSdkProfileRoot(native, binding, sdk, budget, observations) {
  const openedProfile = openRoot(native, sdk.profileRoot, 'sdk-install', 'daemon', binding.roles, true);
  try {
    if (openedProfile.identityFingerprint !== sdk.stateIdentityAttestation.profileIdentityFingerprint ||
        sdk.stateIdentityAttestation.sdkExternalStateContractFingerprint !==
          sdk.sdkExternalStateContractFingerprint) refuse('sdk-profile-attestation');
    const beforeEntries = budget.entries;
    const beforeMarkerBytes = budget.markerBytes;
    const rootListing = externalObject(native, openedProfile.handle, '', 'directory', 0);
    if (rootListing.kind !== 'directory' ||
        serviceNativeIdentityFingerprint(rootListing.identity, 'win32', 'service-sdk-install-directory') !==
          openedProfile.identityFingerprint) refuse('sdk-profile-root-drift');
    const entries = validateEntries(rootListing.entries, 'daemon', 'sdk-install', binding.roles, budget, 1);
    const listingFingerprint = canonicalJsonHash(entries.map(({ name, kind, identityFingerprint }) => ({
      path: name,
      kind,
      identityFingerprint,
    })));
    observations.push(rootObservation(
      'daemon-sdk-profile-root',
      'sdk-install',
      sdk.profileRoot,
      openedProfile.identityFingerprint,
      null,
      listingFingerprint,
      budget.entries - beforeEntries,
      budget.markerBytes - beforeMarkerBytes,
    ));
  } finally {
    closeServiceHandle(native, openedProfile.handle);
  }
}

function physicalSecurityFacts(value) {
  try {
    return win32PhysicalSecurityIdentityFingerprint({
      attributes: value.attributes,
      fileId: value.fileId,
      owner: value.owner,
      securitySha256: value.securitySha256,
      volumeSerial: value.volumeSerial,
      kind: WIN32_PHYSICAL_IDENTITY_KIND,
    });
  } catch {
    refuse('sdk-physical-identity');
  }
}

function assertSdkPhysicalIdentity(profileIdentity, rawFacts) {
  if (physicalSecurityFacts(profileIdentity) !== physicalSecurityFacts(rawFacts)) {
    refuse('sdk-physical-identity-mismatch');
  }
}

function readSdkRawFacts(native, absolutePath, maximum) {
  let value;
  try {
    value = native.read_file_facts_no_follow(absolutePath, maximum);
  } catch {
    refuse('sdk-file-facts-unavailable');
  }
  try {
    validateServiceArtifactFileFacts(value, 'win32');
  } catch {
    refuse('sdk-file-facts-invalid');
  }
  if (value.size > maximum) refuse('sdk-file-size');
  return value;
}

function sdkInventoryEntryMap(inventory) {
  return new Map(inventory.payloadEntries.map((entry) => [entry.path, entry]));
}

function sdkPackageRootForInventoryPath(value) {
  const segments = value.split('/');
  if (segments.length === 2 && SERVICE_PRODUCTION_WORKSPACES.includes(segments[0]) &&
      segments[1].toLowerCase() === 'package.json') {
    if (segments[1] !== 'package.json') refuse('sdk-package-root-case');
    return segments[0];
  }
  if (segments.at(-1)?.toLowerCase() !== 'package.json') return null;
  if (segments.at(-1) !== 'package.json') refuse('sdk-package-root-case');
  let moduleIndex = -1;
  for (let index = segments.length - 2; index >= 0; index -= 1) {
    if (segments[index].toLowerCase() === 'node_modules') {
      if (segments[index] !== 'node_modules') refuse('sdk-package-root-case');
      moduleIndex = index;
      break;
    }
  }
  if (moduleIndex < 0) return null;
  const packageLength = segments[moduleIndex + 1]?.startsWith('@') ? 2 : 1;
  if (moduleIndex + packageLength + 1 !== segments.length - 1) return null;
  return segments.slice(0, moduleIndex + packageLength + 1).join('/');
}

function validateSdkInstalledLayout(treeItems, sdk, manifest, inventory) {
  const expected = new Map();
  const folded = new Map();
  const add = (value, kind) => {
    const relative = relativePath(value, 'sdk-layout-path');
    const alias = relative.toLowerCase().toUpperCase();
    if (folded.has(alias) && folded.get(alias) !== relative) refuse('sdk-layout-alias');
    folded.set(alias, relative);
    const previous = expected.get(relative);
    if (previous !== undefined && previous !== kind) refuse('sdk-layout-kind');
    expected.set(relative, kind);
  };
  const addFile = (relativePath) => {
    const segments = relativePath.split('/');
    for (let index = 1; index < segments.length; index += 1) {
      add(segments.slice(0, index).join('/'), 'directory');
    }
    add(relativePath, 'file');
  };
  for (const entry of inventory.payloadEntries) addFile(entry.path);
  addFile(manifest.inventory.path);
  addFile(sdk.provenanceManifestPath);
  addFile(sdk.provenanceSignaturePath);
  if (expected.size !== treeItems.length) refuse('sdk-install-layout');
  for (const item of treeItems) {
    if (expected.get(item.path) !== item.kind) refuse('sdk-install-layout');
  }
}

function observeSdkFileFacts(native, installation, sdk, relativePathValue, expectedEntry, treeByPath, cache) {
  const relative = relativePath(relativePathValue, 'sdk-file-path');
  const treeItem = treeByPath.get(relative);
  if (!treeItem || treeItem.kind !== 'file') refuse('sdk-file-not-in-installation');
  const observation = externalObject(native, installation.handle, relative, 'facts', 0);
  if (observation.kind !== 'file' ||
      serviceNativeIdentityFingerprint(observation.identity, 'win32', 'service-sdk-install-file') !==
        treeItem.identityFingerprint) refuse('sdk-file-profile-drift');
  const maximum = expectedEntry === null ? DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes :
    Math.max(expectedEntry.size, 1);
  const absolutePath = path.join(sdk.installationRoot, ...relative.split('/'));
  const rawFacts = readSdkRawFacts(native, absolutePath, maximum);
  assertSdkPhysicalIdentity(observation.identity, rawFacts);
  if (expectedEntry !== null &&
      (rawFacts.size !== expectedEntry.size || rawFacts.sha256 !== expectedEntry.sha256)) {
    refuse('sdk-file-inventory-mismatch');
  }
  const cached = Object.freeze({ rawFacts, identityFingerprint: treeItem.identityFingerprint });
  cache.set(relative, cached);
  return cached;
}

function readSdkFile(native, installation, sdk, relativePathValue, maximum, expectedEntry, treeByPath, cache) {
  const relative = relativePath(relativePathValue, 'sdk-file-path');
  if (expectedEntry !== null && expectedEntry.size > maximum) refuse('sdk-metadata-limit');
  const treeItem = treeByPath.get(relative);
  if (!treeItem || treeItem.kind !== 'file') refuse('sdk-file-not-in-installation');
  const observation = readFile(native, installation.handle, relative, maximum,
    'daemon', 'sdk-install', installation.roles);
  if (observation.kind !== 'file' ||
      serviceNativeIdentityFingerprint(observation.identity, 'win32', 'service-sdk-install-file') !==
        treeItem.identityFingerprint) refuse('sdk-file-profile-drift');
  const bytes = Buffer.from(observation.bytes);
  const absolutePath = path.join(sdk.installationRoot, ...relative.split('/'));
  const rawFacts = readSdkRawFacts(native, absolutePath, Math.max(bytes.byteLength, 1));
  assertSdkPhysicalIdentity(observation.identity, rawFacts);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (rawFacts.size !== bytes.byteLength || rawFacts.sha256 !== sha256 ||
      (expectedEntry !== null && (rawFacts.size !== expectedEntry.size ||
        rawFacts.sha256 !== expectedEntry.sha256))) refuse('sdk-file-content-mismatch');
  cache.set(relative, Object.freeze({
    rawFacts,
    identityFingerprint: treeItem.identityFingerprint,
    bytes,
  }));
  return Object.freeze({ bytes, rawFacts, identity: observation.identity });
}

function readSdkInventoryStream(native, absolutePath, expectedFacts) {
  let value;
  try {
    value = native.open_service_artifact_source(absolutePath, SDK_INVENTORY_MAX_BYTES, expectedFacts);
  } catch {
    refuse('sdk-inventory-source-open');
  }
  const opened = exactData(value, ['handle', 'facts', 'writes']);
  if (!opened || opened.handle === null || typeof opened.handle !== 'object' || opened.writes !== 0) {
    if (opened?.handle !== null && typeof opened?.handle === 'object') {
      closeServiceHandle(native, opened.handle);
    }
    refuse('sdk-inventory-source-open');
  }
  let bytes;
  try {
    try {
      validateServiceArtifactFileFacts(opened.facts, 'win32');
    } catch {
      refuse('sdk-inventory-source-facts');
    }
    if (canonicalJsonHash(opened.facts) !== canonicalJsonHash(expectedFacts) ||
        opened.facts.size === 0 || opened.facts.size > SDK_INVENTORY_MAX_BYTES) {
      refuse('sdk-inventory-source-facts');
    }
    bytes = Buffer.allocUnsafe(opened.facts.size);
    const digest = createHash('sha256');
    let offset = 0;
    let eof = false;
    while (offset < opened.facts.size) {
      let chunkValue;
      try {
        chunkValue = native.read_service_artifact_chunk(opened.handle, offset, 1024 * 1024);
      } catch {
        refuse('sdk-inventory-source-read');
      }
      const chunk = exactData(chunkValue, ['bytes', 'nextOffset', 'eof', 'writes']);
      if (!chunk || chunk.writes !== 0 || !(Buffer.isBuffer(chunk.bytes) || chunk.bytes instanceof Uint8Array) ||
          chunk.bytes.byteLength === 0 || chunk.bytes.byteLength > 1024 * 1024 ||
          chunk.nextOffset !== offset + chunk.bytes.byteLength ||
          chunk.nextOffset > opened.facts.size || chunk.eof !== (chunk.nextOffset === opened.facts.size)) {
        refuse('sdk-inventory-source-chunk');
      }
      const piece = Buffer.from(chunk.bytes.buffer, chunk.bytes.byteOffset, chunk.bytes.byteLength);
      piece.copy(bytes, offset);
      digest.update(piece);
      offset = chunk.nextOffset;
      eof = chunk.eof;
    }
    if (offset !== opened.facts.size || !eof || digest.digest('hex') !== expectedFacts.sha256) {
      refuse('sdk-inventory-source-incomplete');
    }
  } finally {
    closeServiceHandle(native, opened.handle);
  }
  return bytes;
}

function inventoryPackageRoots(inventory) {
  const roots = new Set();
  const rootEntries = new Map();
  for (const entry of inventory.payloadEntries) {
    if (entry.path.split('/').at(-1)?.toLowerCase() !== 'package.json') continue;
    const root = sdkPackageRootForInventoryPath(entry.path);
    if (root === null) continue;
    if (rootEntries.has(root)) refuse('sdk-package-root-duplicate');
    roots.add(root);
    rootEntries.set(root, entry);
  }
  for (const workspace of SERVICE_PRODUCTION_WORKSPACES) {
    if (!rootEntries.has(workspace)) refuse('sdk-workspace-package-missing');
  }
  return { roots, rootEntries };
}

async function inspectSdkInstallation(native, binding, sdk, budget, observations) {
  observeSdkProfileRoot(native, binding, sdk, budget, observations);
  const installation = openRoot(native, sdk.installationRoot, 'sdk-install', 'daemon', binding.roles, true);
  installation.roles = binding.roles;
  try {
    const manifestPath = relativePath(sdk.provenanceManifestPath, 'sdk-provenance-path');
    const signaturePath = relativePath(sdk.provenanceSignaturePath, 'sdk-signature-path');
    const budgetBeforeRoot = { entries: budget.entries, markerBytes: budget.markerBytes };
    const tree = scanTree(native, installation.handle, installation.identity,
      'daemon', 'sdk-install', binding.roles, budget);
    const treeByPath = new Map(tree.items.map((item) => [item.path, item]));
    const observedFacts = new Map();
    const manifestObservation = readSdkFile(native, installation, sdk, manifestPath,
      SDK_METADATA_MAX_BYTES, null, new Map(), observedFacts);
    const signatureObservation = readSdkFile(native, installation, sdk, signaturePath,
      16 * 1024, null, new Map(), observedFacts);
    const verified = verifyPinnedDeploymentProvenance({
      purpose: 'application',
      manifestBytes: manifestObservation.bytes,
      signatureBytes: signatureObservation.bytes,
      platform: 'win32',
      architecture: 'x64',
    }).manifest;
    let inventoryFacts;
    const inventoryRelative = relativePath(verified.inventory.path, 'sdk-inventory-path');
    const inventoryTreeItem = treeByPath.get(inventoryRelative);
    if (!inventoryTreeItem || inventoryTreeItem.kind !== 'file') refuse('sdk-inventory-missing');
    const inventoryProfileFacts = externalObject(native, installation.handle, inventoryRelative, 'facts', 0);
    if (inventoryProfileFacts.kind !== 'file' ||
        serviceNativeIdentityFingerprint(inventoryProfileFacts.identity, 'win32', 'service-sdk-install-file') !==
          inventoryTreeItem.identityFingerprint) refuse('sdk-inventory-profile-facts');
    const inventoryAbsolutePath = path.join(sdk.installationRoot, ...inventoryRelative.split('/'));
    inventoryFacts = readSdkRawFacts(native, inventoryAbsolutePath, SDK_INVENTORY_MAX_BYTES);
    assertSdkPhysicalIdentity(inventoryProfileFacts.identity, inventoryFacts);
    if (inventoryFacts.size !== verified.inventory.byteLength ||
        inventoryFacts.sha256 !== verified.inventory.sha256) refuse('sdk-inventory-manifest-binding');
    const inventoryBytes = readSdkInventoryStream(native, inventoryAbsolutePath, inventoryFacts);
    const inventoryProfileAfter = externalObject(native, installation.handle, inventoryRelative, 'facts', 0);
    const inventoryFactsAfter = readSdkRawFacts(native, inventoryAbsolutePath, SDK_INVENTORY_MAX_BYTES);
    if (inventoryProfileAfter.kind !== 'file' ||
        serviceNativeIdentityFingerprint(inventoryProfileAfter.identity, 'win32', 'service-sdk-install-file') !==
          inventoryTreeItem.identityFingerprint ||
        canonicalJsonHash(inventoryFactsAfter) !== canonicalJsonHash(inventoryFacts)) {
      refuse('sdk-inventory-root-drift');
    }
    let inventoryValue;
    try {
      inventoryValue = parseCanonicalJsonBytes(inventoryBytes, SDK_INVENTORY_LIMITS);
      validateBundleInventory(inventoryValue, { platform: 'win32' });
      validateApplicationDeploymentManifest(verified, inventoryValue);
    } catch {
      refuse('sdk-inventory-invalid');
    }
    if (verified.target.platform !== 'win32' || verified.target.architecture !== 'x64' ||
        verified.compatibility.roles.daemon.sdkExternalStateContractFingerprint !==
          sdk.sdkExternalStateContractFingerprint ||
        binding.candidate.compatibility.roles.daemon.sdkExternalStateContractFingerprint !==
          sdk.sdkExternalStateContractFingerprint) refuse('sdk-signed-contract');
    validateSdkInstalledLayout(tree.items, sdk, verified, inventoryValue);
    observations.push(rootObservation(
      'daemon-sdk-installation-root', 'sdk-install', sdk.installationRoot,
      installation.identityFingerprint, null, tree.listingFingerprint,
      budget.entries - budgetBeforeRoot.entries,
      budget.markerBytes - budgetBeforeRoot.markerBytes,
    ));
    const inventoryByPath = sdkInventoryEntryMap(inventoryValue);
    const { roots: packageRoots, rootEntries } = inventoryPackageRoots(inventoryValue);
    const packageMetadata = new Map();
    const packageObservedFacts = new Map(observedFacts);
    const readPackageRoot = async (root) => {
      if (!packageRoots.has(root)) return null;
      const entry = rootEntries.get(root);
      if (!entry || entry.size === 0 || entry.size > SDK_METADATA_MAX_BYTES) refuse('sdk-package-json-limit');
      const relative = `${root}/package.json`;
      let captured = packageMetadata.get(root);
      if (!captured) {
        captured = readSdkFile(native, installation, sdk, relative, SDK_METADATA_MAX_BYTES,
          entry, treeByPath, packageObservedFacts);
        packageMetadata.set(root, captured);
      }
      let packageJson;
      try {
        packageJson = parseStrictJsonBytes(captured.bytes, {
          maxBytes: SDK_METADATA_MAX_BYTES,
          maxDepth: 32,
          maxNodes: 100_000,
        });
      } catch {
        refuse('sdk-package-json-invalid');
      }
      const rootDirectory = treeByPath.get(root);
      if (!rootDirectory || rootDirectory.kind !== 'directory') refuse('sdk-package-root-missing');
      return { realRoot: rootDirectory.identityFingerprint, packageBytes: captured.bytes, packageJson };
    };
    const lockEntry = inventoryByPath.get('bun.lock');
    if (!lockEntry || lockEntry.size === 0 || lockEntry.size > SDK_METADATA_MAX_BYTES ||
        lockEntry.sha256 !== verified.source.bunLockSha256) refuse('sdk-lock-inventory-binding');
    const lockFile = readSdkFile(native, installation, sdk, 'bun.lock', SDK_METADATA_MAX_BYTES,
      lockEntry, treeByPath, packageObservedFacts);
    let lock;
    try {
      lock = parseBunProductionLock(lockFile.bytes);
    } catch {
      refuse('sdk-lock-invalid');
    }
    if (lock.sha256 !== verified.source.bunLockSha256) refuse('sdk-lock-signed-hash');
    const lockWorkspacePaths = Object.keys(lock.lock.workspaces).filter((key) => key !== '').sort();
    if (lockWorkspacePaths.length !== SERVICE_PRODUCTION_WORKSPACES.length ||
        lockWorkspacePaths.some((path, index) => path !== [...SERVICE_PRODUCTION_WORKSPACES].sort()[index])) {
      refuse('sdk-workspace-set-mismatch');
    }
    const sourceWorkspaces = [];
    for (const workspace of SERVICE_PRODUCTION_WORKSPACES) {
      const raw = lock.lock.workspaces[workspace];
      if (raw === null || typeof raw !== 'object' || Array.isArray(raw) ||
          Object.getPrototypeOf(raw) !== Object.prototype) refuse('sdk-workspace-lock-identity');
      const nameDescriptor = Object.getOwnPropertyDescriptor(raw, 'name');
      const versionDescriptor = Object.getOwnPropertyDescriptor(raw, 'version');
      if (!nameDescriptor || !versionDescriptor || nameDescriptor.get !== undefined ||
          versionDescriptor.get !== undefined || !Object.hasOwn(nameDescriptor, 'value') ||
          !Object.hasOwn(versionDescriptor, 'value') || typeof nameDescriptor.value !== 'string' ||
          typeof versionDescriptor.value !== 'string') refuse('sdk-workspace-lock-identity');
      sourceWorkspaces.push(Object.freeze({
        path: workspace,
        packageName: nameDescriptor.value,
        packageVersion: versionDescriptor.value,
      }));
    }
    let closure;
    try {
      closure = await resolveBunProductionClosure({
        lock,
        contract: Object.freeze({ sourceWorkspaces: Object.freeze(sourceWorkspaces) }),
        platform: 'win32',
        architecture: 'x64',
        packageRoots,
        readPackageRoot,
      });
    } catch {
      refuse('sdk-production-closure');
    }
    const { nodes, admittedRoots } = closure;
    if (admittedRoots.size !== packageRoots.size ||
        [...packageRoots].some((root) => !admittedRoots.has(root))) refuse('sdk-package-root-unadmitted');
    const recordsByOwner = new Map([...nodes.values()].map((node) => {
      const prefix = `${node.root}/`;
      const records = inventoryValue.payloadEntries
        .filter((entry) => entry.path.startsWith(prefix))
        .map((entry) => {
          const packageRelativePath = entry.path.slice(prefix.length);
          if (packageRelativePath.length === 0 || packageRelativePath === 'node_modules' ||
              packageRelativePath.startsWith('node_modules/') ||
              packageRelativePath.includes('/node_modules/')) return null;
          return Object.freeze({ ...entry, packageRelativePath });
        })
        .filter((record) => record !== null);
      return [node.key, Object.freeze(records)];
    }));
    const ownedPaths = new Set(['package.json', 'bun.lock', APPLICATION_BUNDLE_INVENTORY_PATH]);
    for (const records of recordsByOwner.values()) {
      for (const record of records) {
        if (ownedPaths.has(record.path)) refuse('sdk-package-record-duplicate');
        ownedPaths.add(record.path);
      }
    }
    for (const entry of inventoryValue.payloadEntries) {
      if (!ownedPaths.has(entry.path)) refuse('sdk-package-inventory-unowned');
    }
    for (const records of recordsByOwner.values()) {
      for (const record of records) {
        observeSdkFileFacts(native, installation, sdk, record.path, record,
          treeByPath, packageObservedFacts);
      }
    }
    const daemonNode = nodes.get('workspace:daemon');
    const sdkEdge = daemonNode?.edges.find((edge) => edge.name === SDK_EXTERNAL_STATE_REQUIREMENTS.packageName &&
      edge.kind === 'dependency');
    const sdkNode = sdkEdge ? nodes.get(sdkEdge.targetKey) : null;
    if (!sdkNode || sdkNode.identity !== `${SDK_EXTERNAL_STATE_REQUIREMENTS.packageName}@${sdk.packageVersion}` ||
        sdkNode.integrity !== sdk.lockIntegrity) refuse('sdk-package-lock-identity');
    let sdkClosure;
    try {
      sdkClosure = collectBunPackageClosure({
        nodes,
        rootKey: sdkNode.key,
        recordsByOwner,
        requireExternal: true,
      });
    } catch {
      refuse('sdk-package-closure');
    }
    const rootRecords = sdkClosure.recordsByOwner.get(sdkNode.key) ?? [];
    const configRecord = rootRecords.find((record) =>
      record.packageRelativePath === 'src/config/config-schema-version.ts');
    const sessionRecord = rootRecords.find((record) =>
      record.packageRelativePath === 'src/session/session-manager.ts');
    if (!configRecord || !sessionRecord || configRecord.size > SDK_METADATA_MAX_BYTES ||
        sessionRecord.size > SDK_METADATA_MAX_BYTES) refuse('sdk-marker-source-missing');
    const configSource = readSdkFile(native, installation, sdk, configRecord.path,
      SDK_METADATA_MAX_BYTES, configRecord, treeByPath, packageObservedFacts).bytes;
    const sessionSource = readSdkFile(native, installation, sdk, sessionRecord.path,
      SDK_METADATA_MAX_BYTES, sessionRecord, treeByPath, packageObservedFacts).bytes;
    let observedSdkContract;
    try {
      observedSdkContract = assertSdkExternalStateContract({
        packages: sdkClosure.packages,
        configSchemaVersionSource: configSource,
        sessionManagerSource: sessionSource,
        sdkExternalStateContractFingerprint: verified.compatibility.roles.daemon.sdkExternalStateContractFingerprint,
      }).sdkContract;
    } catch {
      refuse('sdk-external-state-contract');
    }
    const finalTree = scanTree(native, installation.handle, installation.identity,
      'daemon', 'sdk-install', binding.roles, {
        entries: 0,
        markerBytes: 0,
      });
    if (finalTree.listingFingerprint !== tree.listingFingerprint) refuse('sdk-install-tree-drift');
    return observedSdkContract;
  } finally {
    closeServiceHandle(native, installation.handle);
  }
}

function inspectBotChannels(native, binding, observations, formats) {
  const absolutePath = binding.channelsConfig;
  const file = observeFile(native, {
    rootId: 'bot-channels-config', absolutePath, profile: 'config', component: 'bot',
    roles: binding.roles, required: true, maximum: SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
  });
  try { validateManagedChannelsV2(file.value); } catch { refuse('unsupported-channels-format'); }
  recordFormat(formats, 'bot-mapping-reader', registeredFormat('bot-mapping-reader', file.value));
  observations.push(file.observation);
  const parent = path.dirname(absolutePath);
  const historyPath = path.join(parent, `.${path.basename(absolutePath)}.managed-history.json`);
  const blockerPath = path.join(parent, `.${path.basename(absolutePath)}.genesis-bootstrap-blocker`);
  const opened = openRoot(native, parent, 'config', 'bot', binding.roles, true);
  try {
    const history = externalObject(native, opened.handle, path.basename(historyPath), 'facts', 0);
    if (history.kind === 'absent') {
      observations.push(rootObservation('bot-managed-history', 'config', historyPath, null,
        absenceFingerprint(history.absence), null, 0, 0));
    } else {
      if (history.kind !== 'file') refuse('managed-history-type');
      identityFingerprint(history.identity, 'bot', 'config', false, binding.roles);
      const bytes = readFile(native, opened.handle, path.basename(historyPath), SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
        'bot', 'config', binding.roles);
      if (serviceNativeIdentityFingerprint(bytes.identity, 'win32', 'service-bot-config-file') !==
          serviceNativeIdentityFingerprint(history.identity, 'win32', 'service-bot-config-file')) {
        refuse('managed-history-drift');
      }
      const marker = parseJson(Buffer.from(bytes.bytes), SERVICE_COMPATIBILITY_LIMITS.jsonBytes, 'managed-history-json');
      validateManagedHistoryMarker(marker);
      recordFormat(formats, 'bot-mapping-reader', registeredFormat('bot-mapping-reader', marker));
      observations.push(rootObservation('bot-managed-history', 'config', historyPath,
        opened.identityFingerprint, null,
        canonicalJsonHash({ fileIdentityFingerprint: serviceNativeIdentityFingerprint(
          history.identity, 'win32', 'service-bot-config-file'),
        payloadFingerprint: createHash('sha256').update(bytes.bytes).digest('hex') }), 1, 0));
    }
    const blocker = externalObject(native, opened.handle, path.basename(blockerPath), 'facts', 0);
    if (blocker.kind === 'file') refuse('genesis-blocker-present');
    if (blocker.kind === 'directory') refuse('genesis-blocker-type');
    observations.push(rootObservation('bot-genesis-blocker', 'config', blockerPath, null,
      absenceFingerprint(blocker.absence), null, 0, 0));
  } finally {
    try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
  }
}

function inspectBotRetained(native, binding, budget, observations, formats) {
  const rootPath = path.join(path.dirname(binding.channelsConfig), '.gjc-remote-control');
  const result = observeDirectory(native, {
    rootId: 'bot-control-state', absolutePath: rootPath, profile: 'retained-state',
    component: 'bot', roles: binding.roles, required: false, budget,
  });
  observations.push(result.observation);
  if (result.items.length === 0) return;
  const byPath = new Map(result.items.map((item) => [item.path, item]));
  const retainedRecords = [];
  const root = byPath.get('control-root.json');
  let activeWrapperName = null;
  if (root && root.kind !== 'file') refuse('control-root-type');
  if (root) {
    const opened = openRoot(native, rootPath, 'retained-state', 'bot', binding.roles, true);
    try {
      if (opened.identityFingerprint !== result.rootIdentityFingerprint) refuse('root-drift');
      const control = readFile(native, opened.handle, 'control-root.json', SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
        'bot', 'retained-state', binding.roles);
      if (serviceNativeIdentityFingerprint(control.identity, 'win32', 'service-bot-retained-file') !==
          root.identityFingerprint) refuse('control-root-drift');
      const record = parseJson(Buffer.from(control.bytes), SERVICE_COMPATIBILITY_LIMITS.jsonBytes, 'control-root-json');
      if (!isControlRoot(record)) refuse('control-root');
      retainedRecords.push(record);
      recordFormat(formats, 'bot-mapping-reader', registeredFormat('bot-mapping-reader', record));
      const wrapperName = record.wrapperRelativeName;
      activeWrapperName = wrapperName;
      const wrapperRecord = byPath.get(wrapperName);
      if (!wrapperRecord || wrapperRecord.kind !== 'file') refuse('control-wrapper-missing');
      const wrapperObservation = readFile(native, opened.handle, wrapperName, SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
        'bot', 'retained-state', binding.roles);
      if (serviceNativeIdentityFingerprint(wrapperObservation.identity, 'win32', 'service-bot-retained-file') !==
          wrapperRecord.identityFingerprint) refuse('control-wrapper-drift');
      const wrapper = parseJson(Buffer.from(wrapperObservation.bytes), SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
        'control-wrapper-json');
      retainedRecords.push(wrapper);
      const valid = record.wrapperKind === 'managed-v1-wrapper'
        ? isManagedV1Wrapper(wrapper)
        : isLegacyRetainedWrapper(wrapper);
      if (!valid || wrapper.wrapperFingerprint !== record.wrapperFingerprint ||
          wrapper.anchorFingerprint !== record.anchorFingerprint || wrapper.fenceGeneration !== record.fenceGeneration) {
        refuse('control-wrapper');
      }
      recordFormat(formats, 'bot-mapping-reader', registeredFormat('bot-mapping-reader', wrapper));
    } finally {
      try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
    }
  }
  if (!root && (byPath.has('managed-v1-wrapper.json') || byPath.has('legacy-retained.json'))) {
    refuse('control-root-missing');
  }
  for (const item of result.items) {
    if (item.kind === 'directory' && item.path !== 'bot-state') refuse('unknown-bot-retained-directory');
  }
  for (const item of result.items) {
    if (item.kind === 'directory' || item.path === 'control-root.json' || item.path === activeWrapperName) continue;
    if (!item.path.endsWith('.json')) refuse('unknown-bot-retained-file');
    const opened = openRoot(native, rootPath, 'retained-state', 'bot', binding.roles, true);
    try {
      const file = readFile(native, opened.handle, item.path, SERVICE_COMPATIBILITY_LIMITS.jsonBytes,
        'bot', 'retained-state', binding.roles);
      if (serviceNativeIdentityFingerprint(file.identity, 'win32', 'service-bot-retained-file') !==
          item.identityFingerprint) refuse('bot-retained-drift');
      const record = parseJson(Buffer.from(file.bytes), SERVICE_COMPATIBILITY_LIMITS.jsonBytes, 'bot-retained-json');
      retainedRecords.push(record);
    } finally {
      try { native.close_service_handle(opened.handle); } catch { refuse('native-close'); }
    }
  }
  validateBotRegisteredRecords(retainedRecords, formats);
}

function makeFormats(component, sets) {
  const domains = component === 'bot'
    ? [DEPLOYMENT_FORMAT_REGISTRY.bot]
    : [DEPLOYMENT_FORMAT_REGISTRY.daemonAppSession, DEPLOYMENT_FORMAT_REGISTRY.workspaceLifecycle];
  return Object.freeze(Object.fromEntries(domains.map(({ domain }) => [
    domain,
    Object.freeze([...sets[domain]].sort(utf8Compare)),
  ])));
}

function makeReceipt(serviceKey, scopeFingerprint, observations, formats, sdkContractFingerprint, nativeAuthority) {
  const roots = [...observations].sort((left, right) => utf8Compare(left.rootId, right.rootId));
  for (let index = 1; index < roots.length; index += 1) {
    if (roots[index - 1].rootId === roots[index].rootId) refuse('duplicate-root');
  }
  const receipt = {
    schemaVersion: 1,
    serviceKey,
    scopeFingerprint,
    rootObservations: roots,
    observedRetainedFormats: formats,
    sdkExternalStateContractFingerprint: sdkContractFingerprint,
    coverage: 'declared-roots-only',
    receiptFingerprint: null,
  };
  receipt.receiptFingerprint = canonicalJsonHash(Object.fromEntries(Object.entries(receipt).filter(([key]) =>
    key !== 'receiptFingerprint')));
  const frozen = freezeCopy(receipt);
  if (nativeAuthority) RECEIPT_BRANDS.add(frozen);
  return frozen;
}

async function observeScope(native, binding, nativeAuthority) {
  const budget = { entries: 0, markerBytes: 0 };
  const observations = [];
  const sets = Object.fromEntries(REGISTRY_DOMAINS.map(({ domain }) => [domain, new Set()]));
  const catalogFile = observeFile(native, {
    rootId: 'service-authority-catalog',
    absolutePath: path.join(binding.workingDirectory, 'service-authority.json'),
    profile: 'config', component: binding.component, roles: binding.roles,
    required: true, maximum: SERVICE_COMPATIBILITY_LIMITS.catalogBytes, budget,
  });
  observations.push(catalogFile.observation);
  const catalog = validateCatalog(catalogFile.bytes, binding);
  let observedSdkContract = null;
  if (binding.component === 'bot') {
    inspectBotChannels(native, binding, observations, sets);
    inspectBotRetained(native, binding, budget, observations, sets);
  } else {
    observedSdkContract = await inspectDaemonScope(native, binding, catalog, budget, observations, sets);
  }
  const observedRetainedFormats = makeFormats(binding.component, sets);
  const scopeReceipt = makeReceipt(binding.serviceKey, catalog.scopeFingerprint, observations,
    observedRetainedFormats, observedSdkContract?.sdkExternalStateContractFingerprint ?? null,
    nativeAuthority);
  return Object.freeze({ scopeReceipt, observedRetainedFormats, observedSdkContract });
}

function captureBinding(input, testOnly = false) {
  const fields = exactData(input, [
    'candidate', 'component', 'serviceKey', 'roles', 'workingDirectory', 'channelsConfig',
  ]);
  if (!fields || !COMPONENTS.has(fields.component)) refuse('binding');
  try { validateServiceKey(fields.serviceKey, fields.component); } catch { refuse('service-key'); }
  const roleFields = exactData(fields.roles, ROLE_KEYS);
  if (!roleFields) refuse('roles');
  try { validateServiceRoles(roleFields, 'win32'); } catch { refuse('roles'); }
  const roles = Object.freeze(Object.fromEntries(ROLE_KEYS.map((key) => {
    const principal = exactData(roleFields[key], ['kind', 'value']);
    if (!principal) refuse('roles');
    return [key, Object.freeze(principal)];
  })));
  const workingDirectory = windowsPath(fields.workingDirectory, 'working-directory');
  const channelsConfig = fields.component === 'bot'
    ? windowsPath(fields.channelsConfig, 'channels-config')
    : fields.channelsConfig === null ? null : refuse('channels-config');
  try {
    validateApplicationDeploymentManifest(fields.candidate);
    if (fields.candidate.target.platform !== 'win32' || fields.candidate.target.architecture !== 'x64') refuse('candidate-target');
    if (!testOnly) assertPinnedDeploymentManifest(fields.candidate, 'application');
  } catch (error) {
    if (error?.code?.startsWith('SERVICE_COMPATIBILITY_')) throw error;
    refuse('candidate-provenance');
  }
  return Object.freeze({ candidate: fields.candidate, component: fields.component,
    serviceKey: fields.serviceKey, roles, workingDirectory, channelsConfig });
}

function createObserver(native, binding, nativeAuthority = true) {
  let evidence = null;
  let failed = false;
  const capture = async () => {
    if (failed) refuse('observer-failed');
    if (evidence !== null) return evidence;
    try {
      evidence = await observeScope(native, binding, nativeAuthority);
      return evidence;
    } catch (error) {
      failed = true;
      throw error;
    }
  };
  // The host derives the Launch scope from readServiceAuthorityScope; the
  // observed receipt must bind the same catalog fingerprint.
  const observedFor = async (expected) => {
    const observed = await capture();
    if (!RECEIPT_BRANDS.has(observed.scopeReceipt)) refuse('receipt-provenance');
    if (expected !== undefined) {
      const fields = exactData(expected, ['expectedScopeFingerprint']);
      if (!fields || typeof fields.expectedScopeFingerprint !== 'string') refuse('binding');
      if (observed.scopeReceipt.scopeFingerprint !== fields.expectedScopeFingerprint) refuse('scope-drift');
    }
    return observed;
  };
  const assertFirstInstall = async (expected = undefined) => {
    const observed = await observedFor(expected);
    return assertFirstServiceInstallCompatible({
      candidate: binding.candidate,
      component: binding.component,
      scopeReceipt: observed.scopeReceipt,
      observedRetainedFormats: observed.observedRetainedFormats,
      observedSdkContract: observed.observedSdkContract,
    });
  };
  const revalidate = async () => {
    if (failed || evidence === null) refuse('observer-not-observed');
    try {
      const current = await observeScope(native, binding, nativeAuthority);
      if (current.scopeReceipt.receiptFingerprint !== evidence.scopeReceipt.receiptFingerprint ||
          canonicalJsonHash(current.observedRetainedFormats) !== canonicalJsonHash(evidence.observedRetainedFormats) ||
          canonicalJsonHash(current.observedSdkContract) !== canonicalJsonHash(evidence.observedSdkContract)) refuse('scope-drift');
      return true;
    } catch (error) {
      failed = true;
      throw error;
    }
  };
  // Windows update: the signed candidate must read every observed retained
  // format and keep the stable target/runtime/native/wire/SDK contracts of the
  // authenticated current release, which stays the rollback predecessor.
  const assertUpdate = async (input) => {
    const fields = exactData(input, ['current', 'expectedScopeFingerprint']);
    if (!fields) refuse('binding');
    const observed = await observedFor({ expectedScopeFingerprint: fields.expectedScopeFingerprint });
    try {
      return assertReleaseTransitionCompatible({
        current: fields.current,
        candidate: binding.candidate,
        predecessor: fields.current,
        component: binding.component,
        observedRetainedFormats: observed.observedRetainedFormats,
        sdkExternalStateContractFingerprint: binding.component === 'daemon'
          ? observed.observedSdkContract?.sdkExternalStateContractFingerprint ?? null
          : null,
      });
    } catch (error) {
      if (error?.code?.startsWith('SERVICE_COMPATIBILITY_')) throw error;
      return refuse('transition-incompatible');
    }
  };
  return Object.freeze({ assertFirstInstall, assertUpdate, revalidate });
}

/**
 * Read-only projection of the protected service-authority catalog used to
 * derive the Windows service Launch before any service write. The catalog is
 * opened through the native external-root authority and fully validated,
 * including its self fingerprint and roles binding. The compatibility
 * observer re-reads the same catalog and the host compares both fingerprints.
 */
export function readServiceAuthorityScope(native, input) {
  const fields = exactData(input, ['component', 'serviceKey', 'roles', 'workingDirectory']);
  if (!fields || !COMPONENTS.has(fields.component) || native === null || typeof native !== 'object') refuse('binding');
  try { validateServiceKey(fields.serviceKey, fields.component); } catch { refuse('service-key'); }
  try { validateServiceRoles(fields.roles, 'win32'); } catch { refuse('roles'); }
  const binding = Object.freeze({
    component: fields.component, serviceKey: fields.serviceKey, roles: fields.roles,
    workingDirectory: windowsPath(fields.workingDirectory, 'working-directory'),
  });
  const catalogFile = observeFile(native, {
    rootId: 'service-authority-catalog',
    absolutePath: path.join(binding.workingDirectory, 'service-authority.json'),
    profile: 'config', component: binding.component, roles: binding.roles,
    required: true, maximum: SERVICE_COMPATIBILITY_LIMITS.catalogBytes,
  });
  const catalog = validateCatalog(catalogFile.bytes, binding);
  return Object.freeze({
    scopeFingerprint: catalog.scopeFingerprint,
    sdkProfileRoot: catalog.sdk === null ? null : catalog.sdk.profileRoot,
  });
}

/**
 * Build a single-operation observer over already-bound effective service
 * configuration. The production caller must bind paths and component to its
 * verified request before constructing this object; this observer never accepts
 * caller-supplied roots, format sets, receipts, SDK contracts, or trust keys.
 */
export function createServiceCompatibilityObserver(input) {
  if (process.platform !== 'win32') refuse('windows-only');
  const binding = captureBinding(input);
  return createObserver(createServiceNative({ roles: binding.roles }), binding, true);
}

/** @internal Fake observations can exercise refusals but never receive native-evidence authority. */
export function createServiceCompatibilityObserverForTest(input) {
  const fields = exactData(input, ['binding', 'native']);
  if (!fields || fields.native === null || typeof fields.native !== 'object') refuse('test-adapter');
  const binding = captureBinding(fields.binding, true);
  for (const name of ['open_service_external_root', 'read_service_external_object', 'close_service_handle']) {
    if (typeof fields.native[name] !== 'function') refuse('test-adapter');
  }
  const native = { ...fields.native };
  return createObserver(Object.freeze(native), binding, false);
}
