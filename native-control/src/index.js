import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { advanceReaderVersionFloor, buildAttestedTokenFloorProof, commitTokenFloor, validateAttestedTokenFloorProof, validateAuthorityCommitSnapshot, validateAuthorityEpoch, validateAuthorityReservation, validateBaselineSnapshot, validateFenceBinding, validateGenesisAuthorityReceipt, validateGenesisAuthorityRequest, validateGenesisPrecommit, validateGenesisReceipt, validateGenesisRequest, validateLeaseBinding, validateReaderProjection, validateReaderRelations, validateReaderVersionFloor, validateTokenConfigAttestation, validateTokenFloor, validateTokenFloorReservation, validateZFinality } from '@gjc-remote/shared/genesis-envelope';
import { createGenesisEmptyChannels, isManagedV1Wrapper, validateManagedMappingRecord, validateManagedRouteRecord, validateManagedChannelsV2, validateManagementEnvelope } from '@gjc-remote/shared/mapping-envelope';
import { buildMappingRecoveryRecords, validateManualCleanup, validateMappingRecoveryRecords } from '@gjc-remote/shared/recovery-envelope';
import { canCleanGenesisScratch, fingerprintGenesisProbe, transitionGenesisProspectiveProbe, validateGenesisProspectiveProbe } from '@gjc-remote/shared/genesis-probe';
import { validateAdmissionAck, validateAdmissionAckRecord, validateAdmissionGrant, validateAdmissionRequest, validateFinalityProof } from '@gjc-remote/shared/admission-envelope';
import { buildPublicationC, buildPublicationK, buildPublicationP, buildPublicationQ, buildPublicationS, buildPublicationState, buildPublicationTransaction, buildPublicationU, buildPublicationY, buildPublicationZp, validatePublicationC, validatePublicationGraph, validatePublicationK, validatePublicationP, validatePublicationQ, validatePublicationS, validatePublicationState, validatePublicationTransaction, validatePublicationU, validatePublicationY, validatePublicationZp } from '@gjc-remote/shared/publication-envelope';
import { validateAuthorityCloseProof, validateAuthoritySuccessorAck, validateAuthoritySuccessorBaseline, validateAuthoritySuccessorBundle, validateAuthoritySuccessorFence, validateAuthoritySuccessorFinality, validateAuthoritySuccessorHead, validateAuthoritySuccessorHeadTransition, validateAuthoritySuccessorLease, validateAuthoritySuccessorReaderProjection, validateAuthoritySuccessorReceipt, validateAuthoritySuccessorRequest } from '@gjc-remote/shared/successor-envelope';
import { canonicalJson, canonicalJsonHash, parseCanonicalJsonBytes } from '@gjc-remote/shared/strict-json';

const require = createRequire(import.meta.url);
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const releaseDirectory = join(packageRoot, 'build', 'Release');
const addonPath = join(releaseDirectory, 'native_control.node');
const manifestPath = join(releaseDirectory, 'native-control.manifest.json');
export const capabilities = Object.freeze(['open_verified_parent', 'open_no_follow', 'read_identity', 'read_acl', 'path_exists_no_follow', 'set_exact_role_acl', 'verify_exact_role_acl', 'read_verified_bytes', 'create_exclusive_temp', 'flush_file', 'flush_directory_or_volume', 'replace_existing_atomic', 'create_absent_exclusive', 'ensure_control_directory', 'acquire_native_lock', 'current_os_principal', 'principal_access_check', 'remove_verified_file', 'open_verified_parent_handle', 'open_verified_object_handle', 'read_handle_identity', 'read_handle_bytes', 'write_handle_bytes', 'remove_verified_handle']);
export const capabilitySignatures = Object.freeze({
  open_verified_parent: ['path'], open_no_follow: ['path'], read_identity: ['path'], read_acl: ['path'], path_exists_no_follow: ['path'],
  set_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  verify_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  read_verified_bytes: ['path'], create_exclusive_temp: ['parent', 'prefix', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  flush_file: ['path'], flush_directory_or_volume: ['path'],
  replace_existing_atomic: ['source', 'destination', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  create_absent_exclusive: ['path', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  ensure_control_directory: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  acquire_native_lock: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  current_os_principal: [], principal_access_check: ['path', 'kind', 'principal', 'mode'], remove_verified_file: ['path', 'expectedBytes'],
  open_verified_parent_handle: ['path'], open_verified_object_handle: ['parentHandle', 'name'],
  read_handle_identity: ['handle'], read_handle_bytes: ['handle'], write_handle_bytes: ['handle', 'bytes'],
  remove_verified_handle: ['handle', 'expectedBytes'],
});
for (const signature of Object.values(capabilitySignatures)) Object.freeze(signature);
const approvedPlatforms = Object.freeze(['linux-x64', 'linux-arm64', 'win32-x64']);
const refused = (operation, reason) => { const error = new Error(`${operation} refused: ${reason}`); error.code = 'ERR_NATIVE_CONTROL_REFUSED'; error.operation = operation; error.reason = reason; error.writes = 0; throw error; };
const pendingHandshake = () => {
  const error = new Error('managed reader handshake is pending');
  error.code = 'MANAGED_HANDSHAKE_PENDING';
  error.writes = 0;
  throw error;
};
const canonical = (value) => canonicalJson(value);
const encode = (value) => Buffer.from(canonical(value));
const fingerprint = (value) => createHash('sha256').update(value).digest('hex');
const normalizeNativeIdentity = (identity) => {
  if (!identity || Object.getPrototypeOf(identity) !== Object.prototype) return null;
  const owner = typeof identity.owner === 'string' ? identity.owner : undefined;
  if (Number.isSafeInteger(identity.volumeSerial) && Number.isSafeInteger(identity.fileIndexHigh) &&
      Number.isSafeInteger(identity.fileIndexLow) && Number.isSafeInteger(identity.attributes)) {
    return { kind: 'win32', volumeSerial: identity.volumeSerial, fileIndexHigh: identity.fileIndexHigh,
      fileIndexLow: identity.fileIndexLow, attributes: identity.attributes, ...(owner === undefined ? {} : { owner }) };
  }
  if (typeof identity.device === 'string' && typeof identity.inode === 'string' && Number.isSafeInteger(identity.mode)) {
    return { kind: 'posix', device: identity.device, inode: identity.inode, mode: identity.mode,
      ...(owner === undefined ? {} : { owner }) };
  }
  if (typeof identity.path === 'string') {
    return { kind: 'test', path: identity.path, ...(Number.isSafeInteger(identity.generation) ? { generation: identity.generation } : {}),
      ...(owner === undefined ? {} : { owner }) };
  }
  return null;
};
const identityFingerprint = (identity) => {
  const normalized = normalizeNativeIdentity(identity);
  if (!normalized) throw new TypeError('unreadable native identity');
  return fingerprint(encode(normalized));
};
const sameIdentity = (left, right) => {
  const normalizedLeft = normalizeNativeIdentity(left);
  const normalizedRight = normalizeNativeIdentity(right);
  return normalizedLeft !== null && normalizedRight !== null && canonical(normalizedLeft) === canonical(normalizedRight);
};
const hex = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const recordFingerprint = (record, field) => fingerprint(encode(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field))));
const same = (left, right) => canonical(left) === canonical(right);
const validManagementAuth = (auth) => {
  if (!auth || Object.getPrototypeOf(auth) !== Object.prototype ||
      auth.version !== 1 || !hex(auth.ownerPrincipalKey) ||
      !auth.ownerPrincipal || Object.getPrototypeOf(auth.ownerPrincipal) !== Object.prototype ||
      !auth.credentials || Object.getPrototypeOf(auth.credentials) !== Object.prototype ||
      !Object.hasOwn(auth.credentials, auth.ownerPrincipalKey)) return false;
  const entries = Object.entries(auth.credentials);
  if (entries.length === 0 || entries.length > 256) return false;
  for (const [key, credential] of entries) {
    if (!hex(key) || !credential || Object.getPrototypeOf(credential) !== Object.prototype ||
        credential.version !== 1 || !credential.principal ||
        credential.kdf?.name !== 'scrypt' || credential.kdf.N !== 16384 ||
        credential.kdf.r !== 8 || credential.kdf.p !== 1 ||
        credential.kdf.keyLength !== 32 || credential.kdf.saltBytes !== 16 ||
        !/^[a-f0-9]{32}$/.test(credential.salt) ||
        !hex(credential.hash) || !Number.isSafeInteger(credential.epoch) ||
        credential.epoch < 1 || typeof credential.revoked !== 'boolean') return false;
  }
  try { canonicalJson(auth); } catch { return false; }
  return true;
};
const validateManagementSnapshot = (snapshot) => {
  validateManagedChannelsV2(snapshot);
  if (Object.values(snapshot.mappings).some((mapping) =>
    typeof mapping.workspaceId !== 'string' || mapping.workDir !== null)) {
    throw new TypeError('management mappings must be workspace-only');
  }
  return snapshot;
};
export function validateBuildManifest(manifest, packageJson, addonBytes, platform = process.platform, arch = process.arch) {
  if (!manifest || Object.getPrototypeOf(manifest) !== Object.prototype || !packageJson || Object.getPrototypeOf(packageJson) !== Object.prototype || !Buffer.isBuffer(addonBytes)) return false;
  const expected = {
    contractVersion: 1, package: packageJson.name, version: packageJson.version, napi: 8,
    platform, arch, addon: 'native_control.node', sha256: fingerprint(addonBytes),
    capabilities, capabilitySignatures,
  };
  try {
    return approvedPlatforms.includes(`${platform}-${arch}`) &&
      Object.keys(expected).every((key) => same(manifest[key], expected[key]));
  } catch { return false; }
}

function loadVerifiedAddon() {
  let manifest; let packageJson; let addonBytes;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    packageJson = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
    addonBytes = readFileSync(addonPath);
  } catch { refused('load_native_control', 'verified build manifest or native addon is missing, invalid, or unreadable'); }
  try {
    if (!same(packageJson.nativeControlContract, { version: 1, napi: 8, platforms: approvedPlatforms })) {
      refused('load_native_control', 'package native capability contract is invalid');
    }
  } catch { refused('load_native_control', 'package native capability contract is invalid'); }
  const expected = {
    contractVersion: 1, package: packageJson.name, version: packageJson.version, napi: 8,
    platform: process.platform, arch: process.arch, addon: 'native_control.node', sha256: fingerprint(addonBytes),
    capabilities, capabilitySignatures,
  };
  if (!validateBuildManifest(manifest, packageJson, addonBytes)) {
    refused('load_native_control', 'build manifest verification failed');
  }
  let addon;
  try { addon = require(addonPath); } catch { refused('load_native_control', 'verified native addon could not be loaded'); }
  for (const name of capabilities) if (typeof addon[name] !== 'function') refused('load_native_control', `missing native capability: ${name}`);
  let contract;
  try { contract = addon.native_control_contract(); } catch { refused('load_native_control', 'native capability contract is unreadable'); }
  let validContract = false;
  try {
    validContract = contract?.contractVersion === expected.contractVersion && contract.napi === expected.napi &&
      same(contract.capabilities, capabilities) && same(contract.capabilitySignatures, capabilitySignatures);
  } catch {}
  if (!validContract) refused('load_native_control', 'native capability contract verification failed');
  return addon;
}
export const buildManifest = Object.freeze({ contractVersion: 1, napi: 8, capabilities, capabilitySignatures });

function createAdapter({ lowLevel, configPath, arbitraryPrincipalProbe, roles, platform = process.platform }) {
  if (!lowLevel || !configPath || basename(configPath) !== 'channels.json') refused('create_management_native', 'a channels.json management path and verified native primitives are required');
  for (const name of capabilities) if (typeof lowLevel[name] !== 'function') refused('create_management_native', `missing native capability: ${name}`);
  const roleKind = platform === 'win32' ? 'sid' : 'uid';
  const normalizeUid = (value) => {
    if (typeof value !== 'string') return null;
    const decimal = value.startsWith('uid:') ? value.slice(4) : value;
    if (!/^(?:0|[1-9]\d*)$/.test(decimal)) return null;
    const numeric = Number(decimal);
    if (!Number.isSafeInteger(numeric) || numeric > 0xffffffff) return null;
    return `uid:${numeric}`;
  };
  const normalizeRoles = (candidate) => {
    if (!candidate || Object.getPrototypeOf(candidate) !== Object.prototype || Object.keys(candidate).length !== 4) refused('create_management_native', 'exact M/B/R/SYSTEM role configuration is required');
    const { managementSid, botSid, recoverySid, systemSid } = candidate;
    const values = [managementSid, botSid, recoverySid, systemSid];
    const normalized = roleKind === 'sid'
      ? values.every((sid) => typeof sid === 'string' && /^S-\d+(?:-\d+)+$/i.test(sid)) ? values : null
      : values.map(normalizeUid);
    if (!normalized || normalized.some((value) => value === null) || new Set(normalized).size !== 4 ||
        (roleKind === 'sid' ? normalized[3] !== 'S-1-5-18' : normalized[3] !== 'uid:0')) {
      refused('create_management_native', `exact M/B/R/${roleKind === 'sid' ? 'SYSTEM SID' : 'root UID'} role configuration is required`);
    }
    return Object.freeze(Object.fromEntries(['managementSid', 'botSid', 'recoverySid', 'systemSid'].map((key, index) => [key, normalized[index]])));
  };
  let configuredRoles = roles === undefined ? null : normalizeRoles(roles);
  const roleArguments = (profile) => {
    if (!configuredRoles) refused('management_role_configuration', 'exact M/B/R/SYSTEM role configuration is required');
    return [configuredRoles.managementSid, configuredRoles.botSid, configuredRoles.recoverySid, configuredRoles.systemSid, profile];
  };
  const targetPath = configPath; const parent = dirname(configPath); const root = join(parent, '.gjc-remote-control'); const botRoot = join(root, 'bot-state'); const historyMarkerPath = join(parent, `.${basename(configPath)}.managed-history.json`); const path = (name) => join(root, `${name}.json`); const botPath = (name) => join(botRoot, `${name}.json`); const bootstrapBlockerPath = join(parent, `.${basename(configPath)}.genesis-bootstrap-blocker`); const lockPath = (name) => join(parent, `.${basename(configPath)}.${name}.lock`); const tempPrefix = `${basename(configPath)}.tmp`; let prospectiveProof = null; let bootstrapBlocker = null;
  const requireBotPrincipal = async (operation) => {
    const principal = await lowLevel.current_os_principal();
    if (!configuredRoles || principal?.kind !== roleKind || principal.value !== configuredRoles.botSid) refused(operation, `current OS principal is not the configured bot ${roleKind.toUpperCase()}`);
  };
  const requireManagementPrincipal = async (operation) => {
    const principal = await lowLevel.current_os_principal();
    if (!configuredRoles || principal?.kind !== roleKind || principal.value !== configuredRoles.managementSid) refused(operation, `current OS principal is not the configured management ${roleKind.toUpperCase()}`);
  };
  const requireManagementOrBotPrincipal = async (operation) => {
    const principal = await lowLevel.current_os_principal();
    if (!configuredRoles || principal?.kind !== roleKind ||
        ![configuredRoles.managementSid, configuredRoles.botSid].includes(principal.value)) {
      refused(operation, `current OS principal is not a configured authority reader ${roleKind.toUpperCase()}`);
    }
  };
  const verifiedParent = async (name) => {
    const identity = await lowLevel.open_verified_parent(name);
    if (!identity) refused('verify_management_parent', 'parent identity is unreadable');
    return identity;
  };
  const assertConfigParentOwner = async (operation) => {
    const identity = await lowLevel.read_identity(parent);
    const owner = identity?.owner;
    const expected = configuredRoles?.managementSid;
    const matches = roleKind === 'sid'
      ? typeof owner === 'string' && typeof expected === 'string' && owner.toUpperCase() === expected.toUpperCase()
      : owner === expected;
    if (!matches) refused(operation, 'actual config parent owner is not the configured management principal');
    return identity;
  };
  const assertParent = async (name, expected) => {
    if (!sameIdentity(await verifiedParent(name), expected)) refused('verify_management_parent', 'parent identity changed');
  };
  const profileFor = (name) => name === path('management-auth') ? 'management-auth' : name === botRoot || name.startsWith(`${botRoot}${sep}`) ? 'bot-state' : 'authority';
  const assertObject = async (name, bytes, expectedParent, expectedAcl, profile = profileFor(name)) => {
    if (expectedParent) await assertParent(name, expectedParent);
    const identity = await lowLevel.read_identity(name);
    if (!identity) refused('verify_management_object', 'object identity changed');
    await lowLevel.open_no_follow(name);
    const actual = await lowLevel.read_verified_bytes(name);
    if (actual === null || !Buffer.from(actual).equals(bytes) || !sameIdentity(identity, await lowLevel.read_identity(name))) refused('verify_management_object', 'object bytes or identity changed');
    const acl = await lowLevel.read_acl(name);
    if (acl === null || acl === undefined || acl === '' || (expectedAcl !== undefined && acl !== expectedAcl)) refused('verify_management_object', 'object ACL changed or is unreadable');
    if (profile !== null && !await lowLevel.verify_exact_role_acl(name, ...roleArguments(profile))) refused('verify_management_object', 'object exact role ACL changed or is unreadable');
    return { identity, acl };
  };
  const ensure = async () => { const parentIdentity = await verifiedParent(root); await lowLevel.ensure_control_directory(root, ...roleArguments('authority')); await lowLevel.open_no_follow(root); if (!await lowLevel.read_acl(root) || !await lowLevel.verify_exact_role_acl(root, ...roleArguments('authority'))) refused('ensure_control_directory', 'control-root exact role ACL is unreadable'); await assertParent(root, parentIdentity); };
  const ensureBotRoot = async () => { await ensure(); const parentIdentity = await verifiedParent(botRoot); await lowLevel.ensure_control_directory(botRoot, ...roleArguments('bot-state')); await lowLevel.open_no_follow(botRoot); if (!await lowLevel.read_acl(botRoot) || !await lowLevel.verify_exact_role_acl(botRoot, ...roleArguments('bot-state'))) refused('ensure_bot_directory', 'bot-state exact role ACL is unreadable'); await assertParent(botRoot, parentIdentity); };
  const hasPublishedAuthority = async () => (await lowLevel.read_verified_bytes(path('control-root'))) !== null;
  const requireGenesisProof = async () => { if (!prospectiveProof && !await hasPublishedAuthority()) refused('management_authority', 'prospective cleanup must complete before authority publication'); };
  const rawRead = async (name) => {
    const bytes = await lowLevel.read_verified_bytes(name);
    if (bytes === null) return null;
    await assertObject(name, Buffer.from(bytes));
    try {
      return parseCanonicalJsonBytes(Buffer.from(bytes));
    } catch {
      refused('read_management_state', 'verified state is not canonical JSON');
    }
  };
  const requireAuthorityRequest = async (operation) => {
    const request = await rawRead(path('genesis-authority-request'));
    try { validateGenesisAuthorityRequest(request); } catch {
      refused(operation, 'complete immutable genesis authority request is required before this boundary');
    }
    if (request.anchorFingerprint !== await anchorFingerprint() ||
        (prospectiveProof && (request.genesisTxId !== prospectiveProof.txId ||
          request.managementPrincipalFingerprint !== fingerprint(encode(prospectiveProof.managementPrincipal)) ||
          request.botPrincipalFingerprint !== fingerprint(encode(prospectiveProof.botPrincipal)) ||
          request.recoveryPrincipalFingerprint !== fingerprint(encode(prospectiveProof.recoveryPrincipal)) ||
          request.targetPrincipalFingerprint !== fingerprint(encode(prospectiveProof.targetPrincipal)) ||
          request.managementProvisioningFingerprint !== prospectiveProof.managementProvisioningFingerprint ||
          request.botProvisioningFingerprint !== prospectiveProof.botProvisioningFingerprint ||
          request.recoveryProvisioningFingerprint !== prospectiveProof.recoveryProvisioningFingerprint))) {
      refused(operation, 'genesis authority request does not bind the live prospective proof');
    }
    return request;
  };
  const requirePostGpAuthority = async (operation) => {
    if (prospectiveProof || await hasPublishedAuthority()) await requireAuthorityRequest(operation);
  };
  const read = async (name) => rawRead(name);
  const write = async (name, value, profile = 'authority', requireRequest = true) => {
    if (profile === 'bot-state') await requireBotPrincipal('write_bot_state');
    else await requireManagementPrincipal('write_management_state');
    if (requireRequest) await requireAuthorityRequest('write_management_state');
    const bytes = encode(value); const roleArgs = roleArguments(profile); const parentIdentity = await verifiedParent(name);
    const old = await lowLevel.read_verified_bytes(name);
    if (old === null) {
      await lowLevel.create_absent_exclusive(name, bytes, ...roleArgs);
      await assertObject(name, bytes, parentIdentity);
    } else {
      const before = await assertObject(name, Buffer.from(old), parentIdentity);
      const temp = await lowLevel.create_exclusive_temp(dirname(name), tempPrefix, bytes, ...roleArgs);
      const scratch = await assertObject(temp, bytes, parentIdentity);
      await lowLevel.flush_file(temp);
      await assertObject(name, Buffer.from(old), parentIdentity, before.acl);
      await lowLevel.replace_existing_atomic(temp, name, ...roleArgs);
      await assertObject(name, bytes, parentIdentity, scratch.acl);
    }
    await lowLevel.flush_file(name); await lowLevel.flush_directory_or_volume(dirname(name)); await assertParent(name, parentIdentity);
  };
  const writeAuthority = async (name, value, requireRequest = true) => { await requireManagementPrincipal('write_management_state'); await requireGenesisProof(); await ensure(); await write(path(name), value, 'authority', requireRequest); };
  const writeImmutableAuthority = async (name, value, authorityRequest = false) => { await requireManagementPrincipal('write_immutable_authority'); await requireGenesisProof(); await ensure(); if (!authorityRequest) await requireAuthorityRequest('write_immutable_authority'); const destination = path(name); const bytes = encode(value); const parentIdentity = await verifiedParent(destination); if (await lowLevel.read_verified_bytes(destination) !== null) refused('write_immutable_authority', 'immutable authority record already exists'); await lowLevel.create_absent_exclusive(destination, bytes, ...roleArguments('authority')); await assertObject(destination, bytes, parentIdentity); await lowLevel.flush_file(destination); await lowLevel.flush_directory_or_volume(dirname(destination)); await assertParent(destination, parentIdentity); };
  const writeCreateOnceAuthority = async (name, value) => {
    await requireManagementPrincipal('write_create_once_authority'); await requireGenesisProof(); await ensure(); await requireAuthorityRequest('write_create_once_authority');
    const destination = path(name); const bytes = encode(value); const parentIdentity = await verifiedParent(destination);
    const existing = await lowLevel.read_verified_bytes(destination);
    if (existing !== null) {
      await assertObject(destination, Buffer.from(existing), parentIdentity);
      if (Buffer.from(existing).equals(bytes)) return value;
      refused('write_create_once_authority', 'immutable authority record already exists');
    }
    await lowLevel.create_absent_exclusive(destination, bytes, ...roleArguments('authority'));
    await assertObject(destination, bytes, parentIdentity);
    await lowLevel.flush_file(destination); await lowLevel.flush_directory_or_volume(dirname(destination)); await assertParent(destination, parentIdentity);
    return value;
  };
  const verifiedBytes = async (name) => { const bytes = await lowLevel.read_verified_bytes(name); if (bytes === null) refused('read_managed_mapping_snapshot', 'required managed record is absent'); const verified = await assertObject(name, Buffer.from(bytes)); return { bytes: Buffer.from(bytes), ...verified }; };
  const reservationValid = (r) => { try { validateTokenFloorReservation(r); return true; } catch { return false; } };
  const attestationValid = (a) => { try { validateTokenConfigAttestation(a); return true; } catch { return false; } };
  const targetProof = async ({ sourceKind = 'managed-v1' } = {}) => {
    if (!['managed-v1', 'legacy-retained'].includes(sourceKind)) refused('read_managed_mapping_snapshot', 'target source kind is invalid');
    const managed = sourceKind === 'managed-v1';
    await assertConfigParentOwner('read_managed_mapping_snapshot');
    const bytes = await lowLevel.read_verified_bytes(targetPath);
    if (bytes === null) refused('read_managed_mapping_snapshot', 'required managed record is absent');
    const target = await assertObject(targetPath, Buffer.from(bytes), undefined, undefined, managed ? 'authority' : null);
    const principals = managed
      ? [[configuredRoles.managementSid, 'read', true], [configuredRoles.managementSid, 'write', true], [configuredRoles.botSid, 'read', true], [configuredRoles.botSid, 'write', false], [configuredRoles.recoverySid, 'read', true], [configuredRoles.recoverySid, 'write', false]]
      : [[configuredRoles.managementSid, 'read', true], [configuredRoles.botSid, 'read', true]];
    const access = await Promise.all(principals.map(async ([principal, mode, expected]) =>
      (await lowLevel.principal_access_check(targetPath, roleKind, principal, mode)) === expected));
    if (!access.every(Boolean)) refused('read_managed_mapping_snapshot', managed ? 'managed target M/B/R access proof failed' : 'retained target M/B read equality proof failed');
    return { bytes: Buffer.from(bytes), targetIdentity: identityFingerprint(target.identity), targetAclFingerprint: fingerprint(Buffer.from(String(target.acl))) };
  };
  const authorityObjectProof = async (name) => {
    const record = await verifiedBytes(name);
    return {
      bytesFingerprint: fingerprint(record.bytes),
      identityFingerprint: identityFingerprint(record.identity),
      aclFingerprint: fingerprint(Buffer.from(String(record.acl))),
      value: parseCanonicalJsonBytes(record.bytes),
    };
  };
  const exactTarget = async (candidate) => { const target = await targetProof({ sourceKind: 'legacy-retained' }); if (candidate.rawTargetByteFingerprint !== fingerprint(target.bytes) || candidate.rawTargetByteLength !== target.bytes.length || candidate.targetIdentity !== target.targetIdentity || candidate.targetAclFingerprint !== target.targetAclFingerprint) refused('publish_mapping', 'exact legacy target proof failed'); return target; };
  const anchor = async () => ({ anchorVersion: 1, configPathFingerprint: fingerprint(Buffer.from(configPath)), parentIdentity: identityFingerprint(await lowLevel.read_identity(parent)), targetRelativeName: 'channels.json', controlRootRelativeName: '.gjc-remote-control' });
  const readerFloor = async () => { const existing = await read(path('reader-version-floor')); if (existing) { try { return validateReaderVersionFloor(existing); } catch { refused('publish_mapping', 'reader version floor is invalid'); } } const floor = { version: 1, kind: 'reader-version-floor', anchorFingerprint: (await anchorFingerprint()), readerVersionFloor: null, firstPendingTxId: null, firstReaderInstanceId: null, firstReaderStartNonce: null, lastTransitionTxId: null, previousFloorFingerprint: null, floorFingerprint: null }; floor.floorFingerprint = recordFingerprint(floor, 'floorFingerprint'); return validateReaderVersionFloor(floor); };
  const anchorFingerprint = async () => fingerprint(encode(await anchor()));
  const validateHistoryMarker = (record) => {
    if (!record || Object.getPrototypeOf(record) !== Object.prototype ||
        !same(Object.keys(record).sort(), ['anchorFingerprint', 'kind', 'markerFingerprint', 'previousMarkerFingerprint', 'sequence', 'version']) ||
        record.version !== 1 || record.kind !== 'managed-history-marker' || !hex(record.anchorFingerprint) ||
        !Number.isSafeInteger(record.sequence) || record.sequence < 1 ||
        (record.previousMarkerFingerprint !== null && !hex(record.previousMarkerFingerprint)) ||
        !hex(record.markerFingerprint) || record.markerFingerprint !== recordFingerprint(record, 'markerFingerprint')) {
      refused('managed_history_marker', 'exact canonical managed history marker is required');
    }
    return record;
  };
  const publishEnvelope = async (wrapper) => { const currentAnchor = await anchor(); const currentAnchorFingerprint = fingerprint(encode(currentAnchor)); if (wrapper.anchorFingerprint !== currentAnchorFingerprint) refused('publish_mapping', 'wrapper anchor does not bind this management parent'); const floor = await readerFloor(); await writeAuthority('reader-version-floor', floor); const wrapperName = wrapper.sourceKind === 'legacy-retained' ? 'legacy-retained' : 'managed-v1-wrapper'; await writeAuthority(wrapperName, wrapper); const rootRecord = { version: 1, kind: 'management-control-root', managementStamp: 'gjc-management-control/v1', anchor: currentAnchor, anchorFingerprint: currentAnchorFingerprint, sourceKind: wrapper.sourceKind, wrapperKind: wrapper.kind, wrapperRelativeName: `${wrapperName}.json`, targetRelativeName: 'channels.json', controlRootRelativeName: '.gjc-remote-control', readerVersionFloorFingerprint: floor.floorFingerprint, wrapperFingerprint: wrapper.wrapperFingerprint, controlRootFingerprint: null }; rootRecord.controlRootFingerprint = recordFingerprint(rootRecord, 'controlRootFingerprint'); await writeAuthority('control-root', rootRecord); await ensureBotRoot(); await releaseBootstrapBlocker(); };
  const releaseBootstrapBlocker = async () => {
    if (!bootstrapBlocker) return;
    const { bytes, parentIdentity, identity } = bootstrapBlocker;
    if (!Buffer.from(await lowLevel.read_verified_bytes(bootstrapBlockerPath) ?? []).equals(bytes)) {
      refused('release_bootstrap_blocker', 'bootstrap blocker bytes are missing or changed; manual cleanup is required');
    }
    const verified = await assertObject(bootstrapBlockerPath, bytes, parentIdentity, undefined, 'prospective-cleanup');
    if (!sameIdentity(verified.identity, identity)) refused('release_bootstrap_blocker', 'bootstrap blocker identity changed; manual cleanup is required');
    const parentHandle = await lowLevel.open_verified_parent_handle(bootstrapBlockerPath);
    const handle = await lowLevel.open_verified_object_handle(parentHandle, basename(bootstrapBlockerPath));
    if (!handle || !Buffer.from(await lowLevel.read_handle_bytes(handle)).equals(bytes) ||
        !sameIdentity(await lowLevel.read_handle_identity(handle), identity)) {
      refused('release_bootstrap_blocker', 'bootstrap blocker retained handle is ambiguous; manual cleanup is required');
    }
    await lowLevel.remove_verified_handle(handle, bytes);
    await lowLevel.flush_directory_or_volume(parent);
    if (await lowLevel.read_verified_bytes(bootstrapBlockerPath) !== null ||
        await lowLevel.path_exists_no_follow(bootstrapBlockerPath)) {
      refused('release_bootstrap_blocker', 'bootstrap blocker cleanup is ambiguous; manual cleanup is required');
    }
    await assertParent(targetPath, parentIdentity);
    bootstrapBlocker = null;
  };
  const publishManagedSnapshot = async (snapshot) => {
    try { validateManagementSnapshot(snapshot); } catch { refused('publish_mapping', 'exact workspace-only managed channels v2 snapshot is required'); }
    const controlRoot = await read(path('control-root'));
    const currentWrapper = await read(path('managed-v1-wrapper'));
    if (controlRoot?.sourceKind !== 'managed-v1' || !isManagedV1Wrapper(currentWrapper) ||
        controlRoot.wrapperFingerprint !== currentWrapper.wrapperFingerprint) {
      refused('publish_mapping', 'managed envelope predecessor is invalid');
    }
    await write(targetPath, snapshot);
    const target = await targetProof();
    const wrapper = {
      ...currentWrapper,
      targetState: snapshot.targetState,
      targetIdentity: target.targetIdentity,
      targetAclFingerprint: target.targetAclFingerprint,
      semanticStateFingerprint: snapshot.configFingerprint,
      routeDisposition: 'no-route',
      wrapperSequence: currentWrapper.wrapperSequence + 1,
      previousWrapperFingerprint: currentWrapper.wrapperFingerprint,
      wrapperFingerprint: null,
    };
    wrapper.wrapperFingerprint = recordFingerprint(wrapper, 'wrapperFingerprint');
    if (!isManagedV1Wrapper(wrapper)) refused('publish_mapping', 'managed wrapper successor is invalid');
    await publishEnvelope(wrapper);
  };
  const manualCleanupRecord = async (value = {}) => {
    const tokenFloor = await read(path('token-floor'));
    const request = await read(path('genesis-request'));
    const record = {
      version: 1,
      kind: 'manual-cleanup',
      anchorFingerprint: await anchorFingerprint(),
      txId: value.request?.genesisTxId ?? value.recovery?.txId ?? value.recovery?.records?.transaction?.txId ?? request?.genesisTxId ?? null,
      reason: typeof value.reason === 'string' && value.reason.length > 0 ? value.reason.slice(0, 256) : 'MANUAL_CLEANUP_REQUIRED',
      expectedFingerprint: value.recovery?.requestFingerprint ?? value.recovery?.records?.transaction?.candidateSnapshot?.configFingerprint ?? request?.requestFingerprint ?? null,
      observedFingerprint: null,
      expectedFloorFingerprint: value.recovery?.reservationFingerprint ?? null,
      observedFloorFingerprint: tokenFloor?.floorFingerprint ?? null,
      routeDisposition: 'no-route',
      blockedUntilOwnerAction: true,
      manualCleanupFingerprint: null,
    };
    record.manualCleanupFingerprint = recordFingerprint(record, 'manualCleanupFingerprint');
    try { return validateManualCleanup(record); } catch { refused('manual_cleanup', 'exact manual-cleanup record cannot be constructed'); }
  };
  const validateLivePublicationGraph = async (records) => {
    const { transaction } = records ?? {};
    const txId = transaction?.txId;
    const genesisTxId = transaction?.genesisTxId;
    const [
      rootBaseline, successorBaseline, successorRequest, successorClose, successorFence,
      state, control, rootCommit, successorCommit, attestation, floor, fence,
    ] = await Promise.all([
      read(path(`authority-baseline-${encodeURIComponent(genesisTxId ?? '')}`)),
      read(path(`authority-successor-baseline-${encodeURIComponent(txId ?? '')}`)),
      read(path(`authority-successor-request-${encodeURIComponent(txId ?? '')}`)),
      read(path(`authority-close-proof-${encodeURIComponent(txId ?? '')}`)),
      read(path(`authority-successor-fence-${encodeURIComponent(txId ?? '')}`)),
      read(path('management-state')),
      read(path('control-root')),
      read(path(`authority-commit-${encodeURIComponent(genesisTxId ?? '')}`)),
      read(path(`authority-commit-${encodeURIComponent(txId ?? '')}`)),
      read(path('attestation')),
      read(path('reader-version-floor')),
      read(path('reader-fence-binding')),
    ]);
    const baseline = successorBaseline ?? rootBaseline;
    const commit = successorCommit ?? rootCommit;
    if (!baseline || !state || !control || !commit || !attestation || !floor) throw new TypeError('live publication authority is absent');
    if (successorBaseline) {
      validateAuthoritySuccessorRequest(successorRequest);
      validateAuthorityCloseProof(successorClose, successorRequest);
      if (successorFence !== null) validateAuthoritySuccessorFence(successorFence, successorRequest);
      validateAuthoritySuccessorBaseline(successorBaseline, successorRequest, successorClose, successorFence);
    } else {
      validateBaselineSnapshot(baseline, floor);
    }
    validateAuthorityCommitSnapshot(commit);
    validateTokenConfigAttestation(attestation);
    validateReaderVersionFloor(floor);
    const wrapper = control.wrapperRelativeName && await read(join(root, control.wrapperRelativeName));
    const target = await targetProof({ sourceKind: control.sourceKind });
    const controlProof = await authorityObjectProof(path('control-root'));
    const wrapperProof = wrapper && await authorityObjectProof(join(root, control.wrapperRelativeName));
    const envelope = validateManagementEnvelope(control, wrapper, {
      targetBytes: target.bytes, targetIdentity: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint,
    });
    const baselineGenesisTxId = successorBaseline ? baseline.rootGenesisTxId : baseline.genesisTxId;
    const baselineGeneration = successorBaseline ? baseline.tokenConfigGeneration : baseline.generation;
    if (!envelope.ok || !wrapperProof || control.controlRootFingerprint !== controlProof.value.controlRootFingerprint ||
        wrapper.routeDisposition !== 'no-route' || baselineGenesisTxId !== genesisTxId ||
        baselineGeneration !== transaction.generation || baseline.anchorFingerprint !== commit.anchorFingerprint ||
        baseline.attestationFingerprint !== attestation.attestationFingerprint ||
        baseline.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint) throw new TypeError('live publication authority relation');
    if (baseline.readerVersion === null) {
      if (fence !== null || [baseline.fenceBindingFingerprint, baseline.leaseBindingFingerprint, baseline.readerProjectionFingerprint,
        baseline.readerInstanceId, baseline.readerStartNonce].some((value) => value !== null)) throw new TypeError('live no-reader tuple');
    } else if (successorBaseline) {
      if (!successorFence || successorFence.fenceBindingFingerprint !== baseline.fenceBindingFingerprint ||
          successorFence.readerInstanceId !== baseline.readerInstanceId || successorFence.readerStartNonce !== baseline.readerStartNonce) {
        throw new TypeError('live successor reader fence tuple');
      }
    } else {
      validateFenceBinding(fence, commit, floor);
      if (fence.fenceBindingFingerprint !== baseline.fenceBindingFingerprint || fence.genesisTxId !== genesisTxId ||
          fence.readerInstanceId !== baseline.readerInstanceId || fence.readerStartNonce !== baseline.readerStartNonce) {
        throw new TypeError('live reader fence tuple');
      }
    }
    const targetFingerprint = fingerprint(target.bytes);
    let canonicalMappingFingerprint;
    try {
      const snapshot = validateManagementSnapshot(parseCanonicalJsonBytes(target.bytes));
      canonicalMappingFingerprint = canonicalJsonHash({
        mappingGeneration: snapshot.mappingGeneration,
        mappings: snapshot.mappings,
        routes: snapshot.routes,
      });
    } catch {
      if (control.sourceKind !== 'legacy-retained') throw new TypeError('live managed target snapshot is invalid');
      canonicalMappingFingerprint = canonicalJsonHash({
        sourceKind: control.sourceKind,
        targetFingerprint,
        identityFingerprint: target.targetIdentity,
        aclFingerprint: target.targetAclFingerprint,
      });
    }
    const stateFingerprint = canonicalJsonHash({ targetState: baseline.targetState, targetFingerprint, targetIdentityFingerprint: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint, canonicalMappingFingerprint });
    const payloadFingerprint = canonicalJsonHash({ targetFingerprint, targetIdentityFingerprint: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint, wrapperFingerprint: wrapper.wrapperFingerprint, controlRootFingerprint: control.controlRootFingerprint, canonicalMappingFingerprint });
    const snapshotFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, targetFingerprint });
    const publicationFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, snapshotFingerprint, targetFingerprint });
    const checkpointFingerprint = canonicalJsonHash({ genesisTxId, generation: transaction.generation, publicationFingerprint, targetFingerprint });
    const common = { txId, genesisTxId, generation: transaction.generation };
    const expectedTransaction = buildPublicationTransaction({ ...common, baselineFingerprint: baseline.baselineFingerprint });
    const u = buildPublicationU({ ...common, baselineFingerprint: baseline.baselineFingerprint, anchorFingerprint: baseline.anchorFingerprint, targetState: baseline.targetState, attestationFingerprint: baseline.attestationFingerprint, authorityReservationFingerprint: baseline.authorityReservationFingerprint, authorityCommitSnapshotFingerprint: baseline.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: baseline.fenceBindingFingerprint, leaseBindingFingerprint: baseline.leaseBindingFingerprint, readerProjectionFingerprint: baseline.readerProjectionFingerprint, readerInstanceId: baseline.readerInstanceId, readerStartNonce: baseline.readerStartNonce, readerVersion: baseline.readerVersion });
    const p = buildPublicationP({ ...common, uFingerprint: u['publication-uFingerprint'], stateFingerprint, targetState: u.targetState, authorityCommitSnapshotFingerprint: u.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: u.fenceBindingFingerprint, leaseBindingFingerprint: u.leaseBindingFingerprint, readerInstanceId: u.readerInstanceId, readerStartNonce: u.readerStartNonce, readerVersion: u.readerVersion });
    const s = buildPublicationS({ ...common, pFingerprint: p['publication-pFingerprint'], stateFingerprint, payloadFingerprint, targetState: p.targetState, authorityCommitSnapshotFingerprint: p.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: p.fenceBindingFingerprint, readerVersion: p.readerVersion });
    const phase = (value) => buildPublicationState({ ...common, publicationFingerprint, phase: value });
    const c = buildPublicationC({ ...common, sFingerprint: s['publication-sFingerprint'], stateFingerprint, payloadFingerprint, snapshotFingerprint, authorityCommitSnapshotFingerprint: s.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: s.fenceBindingFingerprint, readerInstanceId: p.readerInstanceId, readerStartNonce: p.readerStartNonce, readerVersion: s.readerVersion });
    const q = buildPublicationQ({ ...common, cFingerprint: c['publication-cFingerprint'], baselineFingerprint: baseline.baselineFingerprint, stateFingerprint, payloadFingerprint, snapshotFingerprint, authorityCommitSnapshotFingerprint: c.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: c.fenceBindingFingerprint });
    const zp = buildPublicationZp({ ...common, qFingerprint: q['publication-qFingerprint'], publicationFingerprint, stateFingerprint, payloadFingerprint, snapshotFingerprint });
    const k = buildPublicationK({ ...common, zpFingerprint: zp['publication-zpFingerprint'], publicationFingerprint, authorityCommitSnapshotFingerprint: q.authorityCommitSnapshotFingerprint, checkpointFingerprint });
    const y = buildPublicationY({ ...common, kFingerprint: k['publication-kFingerprint'], publicationFingerprint, targetState: baseline.targetState, authorityCommitSnapshotFingerprint: k.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: q.fenceBindingFingerprint, targetFingerprint });
    return validatePublicationGraph(records, { transaction: expectedTransaction, u, p, s, prepared: phase('prepared'), replaced: phase('replaced'), committed: phase('committed'), c, q, zp, k, y });
  };
  const readPublicationGraph = async (txId) => {
    const suffix = encodeURIComponent(txId);
    const [
      transaction, u, p, s, prepared, replaced, committed,
      c, q, zp, k, y,
    ] = await Promise.all([
      'publication-transaction', 'publication-u', 'publication-p', 'publication-s',
      'publication-state-prepared', 'publication-state-replaced', 'publication-state-committed',
      'publication-c', 'publication-q', 'publication-zp', 'publication-k', 'publication-y',
    ].map((name) => read(path(`${name}-${suffix}`))));
    const records = { transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y };
    try {
      validatePublicationGraph(records);
      await validateLivePublicationGraph(records);
    } catch (error) {
      refused('read_publication_graph', 'persisted publication graph is incomplete, substituted, or inconsistent with live authority');
    }
    return { transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y };
  };
  const validateStoredFinalityGraph = async (proof) => {
    const request = await read(path('genesis-request'));
    const zFinality = await read(path('z-finality'));
    const tokenFloor = request && await read(path(`token-floor-commit-${encodeURIComponent(request.genesisTxId)}`));
    const precommit = await read(path(`genesis-precommit-proof-${encodeURIComponent(request?.genesisTxId ?? '')}`));
    const floor = await read(path('reader-version-floor'));
    const commit = await read(path(`authority-commit-${encodeURIComponent(request?.genesisTxId ?? '')}`));
    const authorityReservation = await read(path(`authority-reservation-${encodeURIComponent(request?.genesisTxId ?? '')}`));
    const fence = await read(path('reader-fence-binding'));
    const lease = await read(botPath('lease'));
    const admissionRequest = await read(path('admission-request'));
    const admissionGrant = await read(path('admission-grant'));
    const projection = await read(botPath('reader-projection'));
    const acknowledgement = await read(botPath('acknowledgement'));
    const readerState = await read(botPath('reader-state'));
    try {
      validateGenesisRequest(request);
      validateTokenFloor(tokenFloor);
      validateGenesisPrecommit(precommit);
      validateZFinality(zFinality, request, tokenFloor, precommit);
      validateReaderVersionFloor(floor);
      if (request.requestedReaderMode === 'no-reader') {
        if ([fence, lease, admissionRequest, admissionGrant, projection, acknowledgement, readerState].some((value) => value !== null)) {
          throw new TypeError('no-reader graph contains reader records');
        }
      } else {
        validateAuthorityReservation(authorityReservation);
        validateAuthorityCommitSnapshot(commit, authorityReservation);
        validateFenceBinding(fence, commit, floor);
        validateLeaseBinding(lease, fence);
        validateAdmissionRequest(admissionRequest);
        if (commit.txId !== request.genesisTxId ||
            commit.generation !== request.generation ||
            commit.anchorFingerprint !== request.anchorFingerprint ||
            fence.genesisTxId !== request.genesisTxId ||
            fence.anchorFingerprint !== request.anchorFingerprint ||
            projection.genesisTxId !== request.genesisTxId ||
            projection.generation !== request.generation ||
            projection.anchorFingerprint !== request.anchorFingerprint ||
            tokenFloor.lastCommittedTxId !== request.genesisTxId ||
            tokenFloor.highestCommittedGeneration !== request.generation ||
            tokenFloor.anchorFingerprint !== request.anchorFingerprint) {
          throw new TypeError('reader finality graph does not bind current Genesis');
        }
        if (admissionRequest.genesisTxId !== request.genesisTxId ||
            admissionRequest.generation !== request.generation ||
            admissionRequest.readerInstanceId !== request.readerInstanceId ||
            admissionRequest.readerStartNonce !== request.readerStartNonce) {
          throw new TypeError('admission request does not bind Genesis');
        }
        validateAdmissionGrant(admissionGrant, admissionRequest);
        validateReaderProjection(projection, floor, tokenFloor, zFinality.zFinalityFingerprint);
        if (projection.fenceBindingFingerprint !== fence.fenceBindingFingerprint ||
            projection.leaseBindingFingerprint !== lease.leaseBindingFingerprint) {
          throw new TypeError('reader projection does not bind fence and lease');
        }
        validateAdmissionAck(acknowledgement, admissionGrant, projection.readerProjectionFingerprint);
        validateReaderRelations(readerState, floor);
        if (readerState.readerInstanceId !== request.readerInstanceId ||
            readerState.readerStartNonce !== request.readerStartNonce ||
            readerState.leaseBindingFingerprint !== lease.leaseBindingFingerprint ||
            readerState.readerProjectionFingerprint !== projection.readerProjectionFingerprint) {
          throw new TypeError('reader state does not bind finality graph');
        }
      }
      validateFinalityProof(
        proof,
        request,
        zFinality,
        acknowledgement,
        projection?.readerProjectionFingerprint ?? null,
      );
    } catch {
      refused('validate_stored_finality_graph', 'complete bound-reader finality graph is invalid');
    }
    return { request, zFinality, proof, projection, acknowledgement, readerState };
  };
  const exactPrecommitBoundary = async (request, precommit) => {
    try {
      validateGenesisRequest(request); validateGenesisPrecommit(precommit);
      const publication = await readPublicationGraph(request.genesisTxId);
      const [reservation, attestedProof, attestation, readerVersionFloor, authorityReservation, authorityCommit, authorityEpoch, control] = await Promise.all([
        read(path(`token-floor-reservation-${encodeURIComponent(request.genesisTxId)}`)),
        read(path(`token-floor-attested-${encodeURIComponent(request.genesisTxId)}`)),
        read(path('attestation')), read(path('reader-version-floor')),
        read(path(`authority-reservation-${encodeURIComponent(request.genesisTxId)}`)),
        read(path(`authority-commit-${encodeURIComponent(request.genesisTxId)}`)),
        read(path('authority-epoch')), read(path('control-root')),
      ]);
      const committedEpoch = authorityEpoch && await read(path(`authority-epoch-${authorityEpoch.epoch}-committed`));
      const wrapper = control?.wrapperRelativeName ? await read(join(root, control.wrapperRelativeName)) : null;
      const target = await targetProof({ sourceKind: control?.sourceKind });
      const controlProof = control && await authorityObjectProof(path('control-root'));
      const wrapperProof = wrapper && await authorityObjectProof(join(root, control.wrapperRelativeName));
      validateTokenFloorReservation(reservation); validateAttestedTokenFloorProof(attestedProof, reservation, attestation);
      validateReaderVersionFloor(readerVersionFloor); validateAuthorityReservation(authorityReservation);
      validateAuthorityCommitSnapshot(authorityCommit, authorityReservation); validateAuthorityEpoch(authorityEpoch); validateAuthorityEpoch(committedEpoch);
      const envelope = validateManagementEnvelope(control, wrapper, {
        targetBytes: target.bytes, targetIdentity: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint,
      });
      if (!envelope.ok || !controlProof || !wrapperProof ||
          request.requestFingerprint !== precommit.requestFingerprint ||
          reservation.floorFingerprint !== precommit.reservationFingerprint ||
          attestedProof.attestedProofFingerprint !== precommit.attestedProofFingerprint ||
          authorityReservation.reservationFingerprint !== precommit.authorityReservationFingerprint ||
          authorityCommit.authorityCommitSnapshotFingerprint !== precommit.authorityCommitSnapshotFingerprint ||
          canonical(authorityEpoch) !== canonical(committedEpoch) ||
          authorityEpoch.commitTxId !== request.genesisTxId ||
          authorityEpoch.anchorFingerprint !== request.anchorFingerprint ||
          authorityEpoch.authorityEpochFingerprint !== precommit.authorityEpochFingerprint ||
          readerVersionFloor.floorFingerprint !== precommit.readerVersionFloorFingerprint ||
          publication.k['publication-kFingerprint'] !== precommit.publicationKFingerprint ||
          publication.y['publication-yFingerprint'] !== precommit.publicationYFingerprint ||
          fingerprint(target.bytes) !== precommit.targetFingerprint ||
          target.targetIdentity !== precommit.targetIdentityFingerprint ||
          target.targetAclFingerprint !== precommit.targetAclFingerprint ||
          control.controlRootFingerprint !== precommit.controlRootFingerprint ||
          controlProof.identityFingerprint !== precommit.controlIdentityFingerprint ||
          controlProof.aclFingerprint !== precommit.controlAclFingerprint ||
          wrapper.wrapperFingerprint !== precommit.wrapperFingerprint ||
          wrapperProof.identityFingerprint !== precommit.wrapperIdentityFingerprint ||
          wrapperProof.aclFingerprint !== precommit.wrapperAclFingerprint ||
          wrapper.routeDisposition !== 'no-route' ||
          (prospectiveProof && prospectiveProof.txId === request.genesisTxId &&
            prospectiveProof.probe?.probeFingerprint !== precommit.genesisProbeFingerprint)) return false;
      return { publication, target, control, wrapper };
    } catch {
      return false;
    }
  };
  const exactLiveSuccessor = async ({ request, finality, lease, projection, ack, receipt }) => {
    const [attestation, floor, attestationHistory, floorHistory, control] = await Promise.all([
      read(path('attestation')), read(path('token-floor')), read(path('attestation-history')),
      read(path('token-floor-history')), read(path('control-root')),
    ]);
    const wrapper = control?.wrapperRelativeName && await read(join(root, control.wrapperRelativeName));
    const target = control && await targetProof({ sourceKind: control.sourceKind });
    try {
      validateAuthoritySuccessorRequest(request);
      validateAuthoritySuccessorFinality(finality, request);
      validateTokenConfigAttestation(attestation);
      validateTokenFloor(floor);
      if (!target || !wrapper || !Array.isArray(attestationHistory) || !Array.isArray(floorHistory) ||
          canonical(attestationHistory.at(-1)) !== canonical(attestation) ||
          canonical(floorHistory.at(-1)) !== canonical(floor) ||
          finality.attestationFingerprint !== attestation.attestationFingerprint ||
          finality.tokenFloorFingerprint !== floor.floorFingerprint ||
          finality.targetFingerprint !== fingerprint(target.bytes) ||
          finality.targetIdentityFingerprint !== target.targetIdentity ||
          finality.targetAclFingerprint !== target.targetAclFingerprint ||
          finality.wrapperFingerprint !== wrapper.wrapperFingerprint ||
          finality.controlRootFingerprint !== control.controlRootFingerprint) throw new TypeError('live successor drift');
      if (receipt) validateAuthoritySuccessorReceipt(receipt, request, finality, lease, projection, ack);
    } catch {
      refused('validate_live_successor', 'committed successor history or live authority drifted');
    }
  };
  const adapter = {
    async runStartupSelfTest() {
      const principal = await lowLevel.current_os_principal();
      const management = configuredRoles?.managementSid;
      const bot = configuredRoles?.botSid;
      if (principal?.kind !== roleKind || ![management, bot].includes(principal.value)) {
        refused('run_startup_self_test', 'current OS principal is not an approved management or bot self-test role');
      }
      const refuseAfterCleanup = (reason) => refused('run_startup_self_test', reason);
      if (principal.value === management) {
        const nonce = randomUUID();
        const scratch = join(parent, `.${basename(configPath)}.mst-${nonce}`);
        const lock = join(parent, `.${basename(configPath)}.mst-lock-${nonce}`);
        const initial = Buffer.from('{"nativeStartupSelfTest":1}');
        const replacement = Buffer.from('{"nativeStartupSelfTest":2}');
        let scratchBytes = null;
        let scratchProof = null;
        let lockBytes = null;
        let lockProof = null;
        let temporary = null;
        let temporaryBytes = null;
        let temporaryProof = null;
        try {
          const parentIdentity = await verifiedParent(scratch);
          await lowLevel.create_absent_exclusive(scratch, initial, ...roleArguments('management-auth'));
          scratchBytes = initial;
          scratchProof = await assertObject(scratch, initial, parentIdentity, undefined, 'management-auth');
          const access = await Promise.all([
            [management, 'read', true], [management, 'write', true], [bot, 'read', false], [bot, 'write', false],
            [configuredRoles.recoverySid, 'read', false], [configuredRoles.recoverySid, 'write', false],
          ].map(async ([role, mode, expected]) => (await lowLevel.principal_access_check(scratch, roleKind, role, mode)) === expected));
          if (!access.every(Boolean)) refuseAfterCleanup('management private scratch ACL is ambiguous');
          await lowLevel.open_no_follow(scratch);
          const scratchParentHandle = await lowLevel.open_verified_parent_handle(scratch);
          const scratchHandle = await lowLevel.open_verified_object_handle(scratchParentHandle, basename(scratch));
          if (!scratchHandle || !Buffer.from(await lowLevel.read_handle_bytes(scratchHandle)).equals(initial) ||
              !sameIdentity(await lowLevel.read_handle_identity(scratchHandle), await lowLevel.read_identity(scratch))) {
            refuseAfterCleanup('management retained private scratch handle is ambiguous');
          }
          await lowLevel.write_handle_bytes(scratchHandle, initial);
          if (!Buffer.from(await lowLevel.read_handle_bytes(scratchHandle)).equals(initial)) {
            refuseAfterCleanup('management private scratch handle write is not durable');
          }
          await lowLevel.flush_file(scratch);
          await lowLevel.flush_directory_or_volume(parent);
          try {
            await lowLevel.create_absent_exclusive(scratch, initial, ...roleArguments('management-auth'));
            refuseAfterCleanup('management no-replace primitive accepted an existing private scratch record');
          } catch (error) {
            if (error?.code === 'ERR_NATIVE_CONTROL_REFUSED' && error.operation === 'run_startup_self_test') throw error;
            if (error?.code !== 'EEXIST') refuseAfterCleanup('management no-replace primitive collision is ambiguous');
          }
          await lowLevel.set_exact_role_acl(scratch, ...roleArguments('management-auth'));
          scratchProof = await assertObject(scratch, initial, parentIdentity, undefined, 'management-auth');
          const nativeLock = await lowLevel.acquire_native_lock(lock, ...roleArguments('management-auth'));
          lockBytes = Buffer.from(await lowLevel.read_verified_bytes(lock) ?? []);
          lockProof = await assertObject(lock, lockBytes, parentIdentity, undefined, 'management-auth');
          await nativeLock.release();
          temporary = await lowLevel.create_exclusive_temp(parent, `${basename(configPath)}.mst-${nonce}`, replacement, ...roleArguments('management-auth'));
          temporaryBytes = replacement;
          temporaryProof = await assertObject(temporary, replacement, parentIdentity, undefined, 'management-auth');
          await lowLevel.flush_file(temporary);
          await lowLevel.replace_existing_atomic(temporary, scratch, ...roleArguments('management-auth'));
          temporary = null;
          temporaryBytes = null;
          temporaryProof = null;
          scratchBytes = replacement;
          scratchProof = await assertObject(scratch, replacement, parentIdentity, undefined, 'management-auth');
          await lowLevel.flush_file(scratch);
          await lowLevel.flush_directory_or_volume(parent);
          await lowLevel.remove_verified_file(scratch, replacement);
          scratchBytes = null;
          scratchProof = null;
          if (await lowLevel.read_verified_bytes(scratch) !== null || await lowLevel.path_exists_no_follow(scratch)) {
            refuseAfterCleanup('management delete primitive did not remove the exact private scratch record');
          }
          await lowLevel.remove_verified_file(lock, lockBytes);
          lockBytes = null;
          lockProof = null;
          if (await lowLevel.read_verified_bytes(lock) !== null || await lowLevel.path_exists_no_follow(lock)) {
            refuseAfterCleanup('management lock cleanup did not remove the exact private lock record');
          }
          return Object.freeze({ role: 'management', mst: true, bst: false, writes: 0 });
        } catch {
          const cleanup = async (name, bytes, proof) => {
            if (bytes === null) return true;
            try {
              const current = await assertObject(name, bytes, undefined, proof?.acl, 'management-auth');
              if (!sameIdentity(current.identity, proof?.identity)) return false;
              await lowLevel.remove_verified_file(name, bytes);
              return await lowLevel.read_verified_bytes(name) === null && !await lowLevel.path_exists_no_follow(name);
            } catch {
              return false;
            }
          };
          const clean = await cleanup(temporary, temporaryBytes, temporaryProof) &&
            await cleanup(scratch, scratchBytes, scratchProof) &&
            await cleanup(lock, lockBytes, lockProof);
          const error = new Error(clean
            ? 'run_startup_self_test refused: management native primitive self-test failed'
            : 'run_startup_self_test refused: manual cleanup/no-route is required after ambiguous management self-test cleanup');
          error.code = 'ERR_NATIVE_CONTROL_REFUSED';
          error.operation = 'run_startup_self_test';
          error.reason = error.message;
          error.writes = 1;
          throw error;
        }
      }
      const targetBytes = await lowLevel.read_verified_bytes(targetPath);
      if (targetBytes === null) refuseAfterCleanup('bot readable management target is absent');
      await assertObject(targetPath, Buffer.from(targetBytes), undefined, undefined, (await hasPublishedAuthority()) ? 'authority' : null);
      const before = Buffer.from(targetBytes);
      const permissions = await Promise.all([
        [targetPath, 'read', true],
        [targetPath, 'write', false],
        [parent, 'write', false],
        [root, 'write', false],
        [lockPath('genesis'), 'write', false],
        [lockPath('mapping'), 'write', false],
        [lockPath('admission'), 'write', false],
      ].map(async ([name, mode, expected]) =>
        (await lowLevel.principal_access_check(name, roleKind, bot, mode)) === expected));
      if (!permissions.every(Boolean)) refuseAfterCleanup('bot management-record permissions are ambiguous');
      if (!Buffer.from(await lowLevel.read_verified_bytes(targetPath) ?? []).equals(before)) {
        refuseAfterCleanup('bot self-test changed a management record');
      }
      return Object.freeze({ role: 'bot', mst: false, bst: true, writes: 0 });
    },
    async configureManagementRoles(candidate) { const normalized = normalizeRoles(candidate); if (configuredRoles && canonical(configuredRoles) !== canonical(normalized)) refused('management_role_configuration', 'role configuration is immutable'); configuredRoles = normalized; return configuredRoles; },
    async readManagementState() { await requirePostGpAuthority('read_management_state'); return read(path('management-state')); },
    async compareAndSwapManagementState(expected, state) {
      await requireManagementPrincipal('write_management_state');
      await requireGenesisProof();
      await ensure();
      const current = await read(path('management-state'));
      if ((current?.revision ?? 0) !== expected) return false;
      const manualCleanup = state?.recovery?.phase === 'manual_cleanup' &&
        state.recovery.routeDisposition === 'no-route' &&
        /^[a-f0-9]{64}$/.test(state.recovery.manualCleanupFingerprint ?? '');
      if (manualCleanup) {
        const terminal = await read(path('terminal-close'));
        if (terminal?.kind !== 'manual-cleanup' ||
            terminal.manualCleanupFingerprint !== state.recovery.manualCleanupFingerprint ||
            terminal.routeDisposition !== 'no-route') {
          refused('write_management_state', 'manual cleanup state is not bound to the durable terminal close');
        }
      }
      await write(path('management-state'), state, 'authority', !manualCleanup);
      return true;
    },
    async readManagementAuth() {
      await requirePostGpAuthority('read_management_auth');
      const auth = await read(path('management-auth'));
      if (auth !== null && !validManagementAuth(auth)) refused('read_management_auth', 'management auth record is invalid');
      return auth;
    },
    async compareAndSwapManagementAuth(expectedFingerprint, auth) {
      await requireManagementPrincipal('write_management_auth');
      await requireGenesisProof();
      await ensure();
      if (!validManagementAuth(auth)) refused('write_management_auth', 'exact management auth record is required');
      const current = await read(path('management-auth'));
      const currentFingerprint = current === null ? null : canonicalJsonHash(current);
      if (currentFingerprint !== expectedFingerprint) return false;
      await write(path('management-auth'), auth, 'management-auth');
      return true;
    },
    async readManagedHistoryMarker() {
      const marker = await rawRead(historyMarkerPath);
      return marker === null ? null : validateHistoryMarker(marker);
    },
    async commitManagedHistoryMarker(record) {
      validateHistoryMarker(record); await requireAuthorityRequest('commit_managed_history_marker');
      const current = await rawRead(historyMarkerPath);
      if (current !== null) {
        validateHistoryMarker(current);
        if (canonical(current) === canonical(record)) return record;
        if (record.sequence !== current.sequence + 1 || record.previousMarkerFingerprint !== current.markerFingerprint) {
          refused('commit_managed_history_marker', 'managed history marker is not a monotonic replay successor');
        }
      } else if (record.sequence !== 1 || record.previousMarkerFingerprint !== null) {
        refused('commit_managed_history_marker', 'managed history marker genesis is invalid');
      }
      await write(historyMarkerPath, record, 'authority');
      const reopened = await rawRead(historyMarkerPath);
      if (!reopened || canonical(reopened) !== canonical(record)) refused('commit_managed_history_marker', 'managed history marker durable reopen failed');
      return record;
    },
    async currentOsPrincipal() { return lowLevel.current_os_principal(); },
    async managementAnchorFingerprint() { return anchorFingerprint(); },
    async writeGenesisAuthorityRequest(record) {
      try {
        validateGenesisAuthorityRequest(record);
      } catch {
        refused('write_genesis_authority_request', 'exact owner-bound genesis authority request is required');
      }
      const tuple = prospectiveProof?.securityTuple;
      const tupleMatches = tuple === null || (
        tuple.version === 1 && tuple.kind === 'genesis-security-tuple' &&
        tuple.anchorFingerprint === await anchorFingerprint() &&
        tuple.actorPrincipalFingerprint === fingerprint(encode(prospectiveProof.managementPrincipal)) &&
        tuple.ownerPrincipalFingerprint === fingerprint(encode(prospectiveProof.managementPrincipal)) &&
        tuple.targetPrincipalFingerprint === fingerprint(encode(prospectiveProof.targetPrincipal)) &&
        tuple.managementRole === configuredRoles.managementSid && tuple.botRole === configuredRoles.botSid &&
        tuple.recoveryRole === configuredRoles.recoverySid &&
        tuple.managementProvisioningFingerprint === prospectiveProof.managementProvisioningFingerprint &&
        tuple.botProvisioningFingerprint === prospectiveProof.botProvisioningFingerprint &&
        tuple.recoveryProvisioningFingerprint === prospectiveProof.recoveryProvisioningFingerprint &&
        record.anchorFingerprint === tuple.anchorFingerprint &&
        record.ownerPrincipalFingerprint === tuple.ownerPrincipalFingerprint &&
        record.managementPrincipalFingerprint === tuple.actorPrincipalFingerprint &&
        record.botPrincipalFingerprint === fingerprint(encode(prospectiveProof.botPrincipal)) &&
        record.recoveryPrincipalFingerprint === fingerprint(encode(prospectiveProof.recoveryPrincipal)) &&
        record.targetPrincipalFingerprint === tuple.targetPrincipalFingerprint &&
        record.managementProvisioningFingerprint === tuple.managementProvisioningFingerprint &&
        record.botProvisioningFingerprint === tuple.botProvisioningFingerprint &&
        record.recoveryProvisioningFingerprint === tuple.recoveryProvisioningFingerprint &&
        record.generation === tuple.generation && record.idempotencyKey === tuple.idempotencyKey && record.requestedReaderMode === tuple.requestedReaderMode &&
        record.readerInstanceId === tuple.readerInstanceId && record.readerStartNonce === tuple.readerStartNonce &&
        record.protectedInputFingerprint === tuple.protectedHostTokensHostSetFingerprint &&
        record.targetInputState === tuple.targetInputState &&
        record.targetFingerprint === (tuple.legacyTargetProof?.rawTargetByteFingerprint ?? null) &&
        record.targetIdentityFingerprint === (tuple.legacyTargetProof ? fingerprint(encode(tuple.legacyTargetProof.targetIdentity)) : null) &&
        record.targetAclFingerprint === (tuple.legacyTargetProof?.targetAclFingerprint ?? null) &&
        record.legacyTargetProofFingerprint === (tuple.legacyTargetProof ? fingerprint(encode(tuple.legacyTargetProof)) : null));
      if (!tupleMatches) refused('write_genesis_authority_request', 'live prospective security tuple does not bind the request');
      const existing = await rawRead(path('genesis-authority-request'));
      if (existing !== null) {
        if (canonical(existing) !== canonical(record)) refused('write_genesis_authority_request', 'immutable authority request replay mismatch');
        return existing;
      }
      await writeImmutableAuthority('genesis-authority-request', record, true);
      return record;
    },
    async reserveAuthorityEpoch(record) {
      try {
        validateAuthorityEpoch(record);
      } catch {
        refused('reserve_authority_epoch', 'exact authority epoch reservation is required');
      }
      const request = await read(path('genesis-authority-request'));
      if (!request || record.reservationTxId !== request.genesisTxId ||
          record.anchorFingerprint !== request.anchorFingerprint || record.commitTxId !== null) {
        refused('reserve_authority_epoch', 'authority epoch is not bound to the genesis request');
      }
      const state = await read(path('management-state'));
      if (!state || state.authorityEpoch !== record.epoch) {
        refused('reserve_authority_epoch', 'authority epoch does not match the durable management reservation');
      }
      await writeImmutableAuthority(`authority-epoch-${record.epoch}-reserved`, record);
      await writeAuthority('authority-epoch', record);
      return record;
    },
    async writeAuthorityReservation(record) {
      try {
        validateAuthorityReservation(record);
      } catch {
        refused('write_authority_reservation', 'exact authority reservation is required');
      }
      const request = await read(path('genesis-authority-request'));
      const epoch = await read(path('authority-epoch'));
      if (!request || !epoch || record.txId !== request.genesisTxId ||
          record.epoch !== epoch.epoch || record.generation !== request.generation ||
          record.anchorFingerprint !== request.anchorFingerprint || epoch.commitTxId !== null) {
        refused('write_authority_reservation', 'authority reservation relation is invalid');
      }
      await writeImmutableAuthority(`authority-reservation-${encodeURIComponent(record.txId)}`, record);
      return record;
    },
    async commitAuthorityEpoch(record, precommit) {
      try {
        validateAuthorityEpoch(record);
        validateGenesisPrecommit(precommit);
      } catch {
        refused('commit_authority_epoch', 'exact committed authority epoch and precommit proof are required');
      }
      const prior = await read(path('authority-epoch'));
      const request = await read(path('genesis-request'));
      const reservation = await read(path(`authority-reservation-${encodeURIComponent(record.reservationTxId)}`));
      const commit = await read(path(`authority-commit-${encodeURIComponent(record.reservationTxId)}`));
      if (!prior || prior.commitTxId !== null || !request || !reservation || !commit ||
          record.commitTxId !== request.genesisTxId || record.reservationTxId !== request.genesisTxId ||
          record.epoch !== prior.epoch || record.anchorFingerprint !== prior.anchorFingerprint ||
          record.authorityEpochFingerprint === prior.authorityEpochFingerprint ||
          precommit.genesisTxId !== request.genesisTxId ||
          precommit.generation !== request.generation ||
          precommit.requestFingerprint !== request.requestFingerprint ||
          precommit.authorityReservationFingerprint !== reservation.reservationFingerprint ||
          precommit.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint ||
          precommit.authorityEpochFingerprint !== record.authorityEpochFingerprint) {
        refused('commit_authority_epoch', 'authority epoch commit relation is invalid');
      }
      await writeImmutableAuthority(`genesis-precommit-proof-${encodeURIComponent(request.genesisTxId)}`, precommit);
      await writeAuthority('genesis-precommit-proof', precommit);
      await writeImmutableAuthority(`authority-epoch-${record.epoch}-committed`, record);
      await writeAuthority('authority-epoch', record);
      const reopened = await read(path('authority-epoch'));
      const reopenedPrecommit = await read(path('genesis-precommit-proof'));
      if (!reopened || canonical(reopened) !== canonical(record) ||
          !reopenedPrecommit || canonical(reopenedPrecommit) !== canonical(precommit)) {
        refused('commit_authority_epoch', 'authority epoch or precommit durable reopen failed');
      }
      return record;
    },
    async writeAuthorityCommitSnapshot(record) {
      const reservation = await read(path(`authority-reservation-${encodeURIComponent(record?.txId)}`));
      try {
        validateAuthorityCommitSnapshot(record, reservation);
      } catch {
        refused('write_authority_commit_snapshot', 'exact authority commit snapshot is required');
      }
      await writeImmutableAuthority(`authority-commit-${encodeURIComponent(record.txId)}`, record);
      const reopened = await read(path(`authority-commit-${encodeURIComponent(record.txId)}`));
      if (!reopened || canonical(reopened) !== canonical(record)) {
        refused('write_authority_commit_snapshot', 'authority commit snapshot failed durable reopen');
      }
      await writeAuthority('authority-commit', record);
      return record;
    },
    async writeAuthorityBaseline(record) {
      try {
        validateBaselineSnapshot(record);
      } catch {
        refused('write_authority_baseline', 'exact no-reader authority baseline is required');
      }
      const commit = await read(path(`authority-commit-${encodeURIComponent(record.genesisTxId)}`));
      if (!commit || record.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint ||
          record.anchorFingerprint !== commit.anchorFingerprint || record.generation !== commit.generation) {
        refused('write_authority_baseline', 'authority baseline relation is invalid');
      }
      await writeImmutableAuthority(`authority-baseline-${encodeURIComponent(record.genesisTxId)}`, record);
      await writeAuthority('authority-baseline', record);
      return record;
    },
    async writeReaderFenceBinding(record) {
      const commit = await read(path(`authority-commit-${encodeURIComponent(record?.genesisTxId)}`));
      const floor = await read(path('reader-version-floor'));
      try {
        validateFenceBinding(record, commit, floor);
      } catch {
        refused('write_reader_fence_binding', 'exact management reader fence binding is required');
      }
      await writeImmutableAuthority(`reader-fence-binding-${encodeURIComponent(record.genesisTxId)}`, record);
      await writeAuthority('reader-fence-binding', record);
      return record;
    },
    async casReaderVersionFloor({ txId, readerInstanceId, readerStartNonce }) {
      const current = await readerFloor();
      if (current.readerVersionFloor === 2) {
        if (current.firstPendingTxId !== txId || current.firstReaderInstanceId !== readerInstanceId ||
            current.firstReaderStartNonce !== readerStartNonce) {
          refused('cas_reader_version_floor', 'reader floor is already bound to another reader');
        }
        return current;
      }
      const next = advanceReaderVersionFloor(current, { txId, readerInstanceId, readerStartNonce });
      const existing = await read(path('reader-version-floor'));
      if (existing !== null && canonical(existing) !== canonical(current)) {
        refused('cas_reader_version_floor', 'reader floor CAS predecessor changed');
      }
      await writeImmutableAuthority(`reader-version-floor-${encodeURIComponent(txId)}`, next);
      await writeAuthority('reader-version-floor', next);
      return next;
    },
    async writeGenesisAuthorityReceipt(record) {
      const request = await read(path('genesis-authority-request'));
      try {
        validateGenesisAuthorityReceipt(record, request);
      } catch {
        refused('write_genesis_authority_receipt', 'exact genesis authority receipt is required');
      }
      const commit = await read(path(`authority-commit-${encodeURIComponent(record.genesisTxId)}`));
      const floor = await read(path('reader-version-floor'));
      if (!commit || !floor ||
          record.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint ||
          record.readerVersionFloorFingerprint !== floor.floorFingerprint) {
        refused('write_genesis_authority_receipt', 'authority receipt proof relation is invalid');
      }
      const immutablePath = path(`genesis-authority-receipt-${encodeURIComponent(record.genesisTxId)}`);
      const [immutable, current] = await Promise.all([read(immutablePath), read(path('genesis-authority-receipt'))]);
      if ((immutable !== null && canonical(immutable) !== canonical(record)) ||
          (current !== null && canonical(current) !== canonical(record))) {
        refused('write_genesis_authority_receipt', 'immutable authority receipt replay mismatch');
      }
      if (immutable === null) await writeImmutableAuthority(`genesis-authority-receipt-${encodeURIComponent(record.genesisTxId)}`, record);
      if (current === null) await writeAuthority('genesis-authority-receipt', record);
      return record;
    },
    async withManagementLocks(names, callback) { await requireManagementPrincipal('with_management_locks'); const order = ['genesis', 'mapping', 'admission']; if (!Array.isArray(names) || names.some((n, i) => !order.includes(n) || names.indexOf(n) !== i || (i && order.indexOf(n) <= order.indexOf(names[i - 1])))) refused('with_management_locks', 'lock order is invalid'); const locks = []; try { for (const n of names) locks.push(await lowLevel.acquire_native_lock(lockPath(n), ...roleArguments('authority'))); return await callback(); } finally { for (const lock of locks.reverse()) await lock.release(); } },
    async probeProspectiveCleanup({ txId, targetPrincipal, managementPrincipal, botPrincipal, recoveryPrincipal, managementProvisioningFingerprint, botProvisioningFingerprint, recoveryProvisioningFingerprint, genesisSecurityTuple, generation, idempotencyKey, requestedReaderMode, readerInstanceId, readerStartNonce, protectedInputFingerprint }) {
      await requireManagementPrincipal('probe_prospective_cleanup');
      if (!arbitraryPrincipalProbe || !txId || ![managementProvisioningFingerprint, botProvisioningFingerprint, recoveryProvisioningFingerprint].every(hex) ||
          !configuredRoles || managementPrincipal?.kind !== roleKind || botPrincipal?.kind !== roleKind || recoveryPrincipal?.kind !== roleKind ||
          managementPrincipal.value !== configuredRoles.managementSid || botPrincipal.value !== configuredRoles.botSid || recoveryPrincipal.value !== configuredRoles.recoverySid) refused('probe_prospective_cleanup', 'prospective cleanup is not proven');
      const flatTuple = { generation, idempotencyKey, requestedReaderMode, readerInstanceId, readerStartNonce, protectedInputFingerprint };
      const flatProvided = Object.values(flatTuple).some((value) => value !== undefined);
      const tupleKeys = ['version', 'kind', 'anchorFingerprint', 'actorPrincipalFingerprint', 'ownerPrincipalFingerprint',
        'targetPrincipalFingerprint', 'managementRole', 'botRole', 'recoveryRole', 'managementProvisioningFingerprint',
        'botProvisioningFingerprint', 'recoveryProvisioningFingerprint', 'protectedHostTokensHostSetFingerprint',
        'generation',
        'idempotencyKey', 'targetInputIntent', 'requestedReaderMode', 'readerInstanceId', 'readerStartNonce'];
      const tupleValid = genesisSecurityTuple && Object.getPrototypeOf(genesisSecurityTuple) === Object.prototype &&
        same(Object.keys(genesisSecurityTuple).sort(), [...tupleKeys].sort()) &&
        genesisSecurityTuple.version === 1 && genesisSecurityTuple.kind === 'genesis-security-tuple' &&
        genesisSecurityTuple.anchorFingerprint === await anchorFingerprint() &&
        genesisSecurityTuple.actorPrincipalFingerprint === fingerprint(encode(managementPrincipal)) &&
        genesisSecurityTuple.ownerPrincipalFingerprint === fingerprint(encode(managementPrincipal)) &&
        genesisSecurityTuple.targetPrincipalFingerprint === fingerprint(encode(targetPrincipal)) &&
        genesisSecurityTuple.managementRole === configuredRoles.managementSid && genesisSecurityTuple.botRole === configuredRoles.botSid &&
        genesisSecurityTuple.recoveryRole === configuredRoles.recoverySid &&
        genesisSecurityTuple.managementProvisioningFingerprint === managementProvisioningFingerprint &&
        genesisSecurityTuple.botProvisioningFingerprint === botProvisioningFingerprint &&
        genesisSecurityTuple.recoveryProvisioningFingerprint === recoveryProvisioningFingerprint &&
        hex(genesisSecurityTuple.protectedHostTokensHostSetFingerprint) &&
        Number.isSafeInteger(genesisSecurityTuple.generation) && genesisSecurityTuple.generation > 0 &&
        typeof genesisSecurityTuple.idempotencyKey === 'string' && genesisSecurityTuple.idempotencyKey.length > 0 &&
        ['no-reader', 'handshake'].includes(genesisSecurityTuple.requestedReaderMode) &&
        (genesisSecurityTuple.requestedReaderMode === 'no-reader'
          ? genesisSecurityTuple.readerInstanceId === null && genesisSecurityTuple.readerStartNonce === null
          : typeof genesisSecurityTuple.readerInstanceId === 'string' && genesisSecurityTuple.readerInstanceId.length > 0 &&
            typeof genesisSecurityTuple.readerStartNonce === 'string' && genesisSecurityTuple.readerStartNonce.length > 0);
      const flatMatches = !flatProvided || (generation === genesisSecurityTuple?.generation &&
        idempotencyKey === genesisSecurityTuple?.idempotencyKey && requestedReaderMode === genesisSecurityTuple?.requestedReaderMode &&
        readerInstanceId === genesisSecurityTuple?.readerInstanceId && readerStartNonce === genesisSecurityTuple?.readerStartNonce &&
        protectedInputFingerprint === genesisSecurityTuple?.protectedHostTokensHostSetFingerprint);
      if (genesisSecurityTuple !== undefined ? !tupleValid || !flatMatches :
        flatProvided && (!Number.isSafeInteger(generation) || generation < 1 || typeof idempotencyKey !== 'string' || idempotencyKey.length === 0 ||
          !['no-reader', 'handshake'].includes(requestedReaderMode) || !hex(protectedInputFingerprint) ||
          (requestedReaderMode === 'no-reader' ? readerInstanceId !== null || readerStartNonce !== null :
            typeof readerInstanceId !== 'string' || readerInstanceId.length === 0 || typeof readerStartNonce !== 'string' || readerStartNonce.length === 0))) {
        refused('probe_prospective_cleanup', 'complete Genesis security tuple is required');
      }
      await assertConfigParentOwner('probe_prospective_cleanup');
      const principals = [targetPrincipal, managementPrincipal, botPrincipal, recoveryPrincipal];
      if (!principals.every((principal) => principal?.kind && principal?.value) ||
          !(await Promise.all(principals.map((principal) => lowLevel.principal_access_check(parent, principal.kind, principal.value, 'read')))).every((result) => result === true)) refused('probe_prospective_cleanup', 'prospective cleanup is not proven');
      const parentIdentity = await verifiedParent(targetPath);
      const blockerBytes = await lowLevel.read_verified_bytes(bootstrapBlockerPath);
      const parentAcl = await lowLevel.read_acl(parent);
      if (!parentAcl) refused('probe_prospective_cleanup', 'prospective cleanup parent ACL is unreadable');
      if (blockerBytes !== null) {
        let persisted;
        try { persisted = parseCanonicalJsonBytes(Buffer.from(blockerBytes)); } catch { refused('probe_prospective_cleanup', 'persisted bootstrap blocker requires manual cleanup; route remains no-route'); }
        const expectedNonce = fingerprint(encode({ txId, parentIdentity, configPath })).slice(0, 32);
        if (persisted?.version !== 1 || persisted.kind !== 'genesis-bootstrap-blocker' ||
            persisted.txId !== txId || persisted.nonce !== expectedNonce ||
            persisted.parentIdentity !== identityFingerprint(parentIdentity) ||
            persisted.parentAclFingerprint !== fingerprint(Buffer.from(String(parentAcl))) ||
            persisted.profile !== 'prospective-cleanup') {
          refused('probe_prospective_cleanup', 'persisted bootstrap blocker requires manual cleanup; route remains no-route');
        }
        const persistedParent = await lowLevel.open_verified_parent_handle(bootstrapBlockerPath);
        const persistedHandle = await lowLevel.open_verified_object_handle(persistedParent, basename(bootstrapBlockerPath));
        if (!persistedHandle || !Buffer.from(await lowLevel.read_handle_bytes(persistedHandle)).equals(Buffer.from(blockerBytes)) ||
            !sameIdentity(await lowLevel.read_handle_identity(persistedHandle), await lowLevel.read_identity(bootstrapBlockerPath))) {
          refused('probe_prospective_cleanup', 'persisted bootstrap blocker descriptor is ambiguous; manual cleanup is required');
        }
        await lowLevel.remove_verified_handle(persistedHandle, Buffer.from(blockerBytes));
        await lowLevel.flush_directory_or_volume(parent);
        if (await lowLevel.path_exists_no_follow(bootstrapBlockerPath)) {
          refused('probe_prospective_cleanup', 'persisted bootstrap blocker cleanup is ambiguous; manual cleanup is required');
        }
      }
      const bootstrapBlockerBytes = encode({
        version: 1, kind: 'genesis-bootstrap-blocker', txId,
        nonce: fingerprint(encode({ txId, parentIdentity, configPath })).slice(0, 32),
        parentIdentity: identityFingerprint(parentIdentity),
        parentAclFingerprint: fingerprint(Buffer.from(String(parentAcl))),
        profile: 'prospective-cleanup',
      });
      try {
        await lowLevel.create_absent_exclusive(bootstrapBlockerPath, bootstrapBlockerBytes, ...roleArguments('prospective-cleanup'));
      } catch {
        refused('probe_prospective_cleanup', 'bootstrap blocker could not be persisted exclusively; manual cleanup is required');
      }
      await lowLevel.flush_file(bootstrapBlockerPath);
      await lowLevel.flush_directory_or_volume(parent);
      const bootstrapParentHandle = await lowLevel.open_verified_parent_handle(bootstrapBlockerPath);
      const bootstrapHandle = await lowLevel.open_verified_object_handle(bootstrapParentHandle, basename(bootstrapBlockerPath));
      const blockerIdentity = bootstrapHandle && await lowLevel.read_handle_identity(bootstrapHandle);
      if (!bootstrapHandle || !Buffer.from(await lowLevel.read_handle_bytes(bootstrapHandle)).equals(bootstrapBlockerBytes) ||
          !blockerIdentity || !sameIdentity(blockerIdentity, await lowLevel.read_identity(bootstrapBlockerPath))) {
        refused('probe_prospective_cleanup', 'bootstrap blocker identity is ambiguous; manual cleanup is required');
      }
      bootstrapBlocker = { bytes: bootstrapBlockerBytes, parentIdentity, identity: blockerIdentity };
      const targetBytes = await lowLevel.read_verified_bytes(targetPath);
      const targetAcl = targetBytes === null ? parentAcl : await lowLevel.read_acl(targetPath);
      const controlAcl = parentAcl;
      if (!targetAcl || !controlAcl) refused('probe_prospective_cleanup', 'prospective cleanup ACL is unreadable');
      let legacyTargetProof = null;
      if (targetBytes !== null) {
        const verifiedTarget = await assertObject(targetPath, Buffer.from(targetBytes), parentIdentity, undefined, null);
        const targetReaders = [managementPrincipal, botPrincipal];
        const targetAccess = await Promise.all(targetReaders.map((principal) =>
          lowLevel.principal_access_check(targetPath, principal.kind, principal.value, 'read')));
        if (!targetAccess.every((result) => result === true)) {
          refused('probe_prospective_cleanup', 'legacy target is not readable by the required principals');
        }
        legacyTargetProof = {
          rawTargetByteFingerprint: fingerprint(Buffer.from(targetBytes)),
          rawTargetByteLength: Buffer.from(targetBytes).length,
          targetIdentity: identityFingerprint(verifiedTarget.identity),
          targetAclFingerprint: fingerprint(Buffer.from(String(verifiedTarget.acl))),
        };
      }
      let scratch; let scratchHandle; let probe;
      let retainedScratchIdentity = null;
      const replaceScratch = async (next) => {
        const bytes = encode(next);
        await lowLevel.write_handle_bytes(scratchHandle, bytes);
        if (!Buffer.from(await lowLevel.read_handle_bytes(scratchHandle)).equals(bytes)) refused('probe_prospective_cleanup', 'prospective scratch handle bytes changed');
        const handleIdentity = await lowLevel.read_handle_identity(scratchHandle);
        const pathVerified = await assertObject(scratch, bytes, parentIdentity);
        if (!retainedScratchIdentity ||
            !sameIdentity(handleIdentity, retainedScratchIdentity) ||
            !sameIdentity(pathVerified.identity, retainedScratchIdentity)) {
          refused('probe_prospective_cleanup', 'prospective scratch identity changed');
        }
        await lowLevel.flush_file(scratch);
        await lowLevel.flush_directory_or_volume(parent);
        if (!sameIdentity(await lowLevel.read_handle_identity(scratchHandle), retainedScratchIdentity)) {
          refused('probe_prospective_cleanup', 'prospective scratch identity changed after flush');
        }
      };
      const parentHandle = await lowLevel.open_verified_parent_handle(targetPath);
      try {
        scratch = await lowLevel.create_exclusive_temp(parent, `${tempPrefix}.gp.seed`, Buffer.from(txId), ...roleArguments('authority'));
        scratchHandle = await lowLevel.open_verified_object_handle(parentHandle, basename(scratch));
        if (!scratchHandle) refused('probe_prospective_cleanup', 'prospective scratch handle is unreadable');
        const handleIdentity = await lowLevel.read_handle_identity(scratchHandle);
        const pathVerified = await assertObject(scratch, Buffer.from(txId), parentIdentity);
        if (!sameIdentity(handleIdentity, pathVerified.identity)) refused('probe_prospective_cleanup', 'prospective scratch handle identity mismatch');
        retainedScratchIdentity = handleIdentity;
        const controlTemplate = await lowLevel.create_exclusive_temp(parent, `${tempPrefix}.gp.control`, Buffer.from(txId), ...roleArguments('authority'));
        const wrapperTemplate = await lowLevel.create_exclusive_temp(parent, `${tempPrefix}.gp.wrapper`, Buffer.from(txId), ...roleArguments('authority'));
        const controlHandle = await lowLevel.open_verified_object_handle(parentHandle, basename(controlTemplate));
        const wrapperHandle = await lowLevel.open_verified_object_handle(parentHandle, basename(wrapperTemplate));
        if (!controlHandle || !wrapperHandle) refused('probe_prospective_cleanup', 'prospective final-profile template handle is unreadable');
        const controlIdentity = await lowLevel.read_handle_identity(controlHandle);
        const wrapperIdentity = await lowLevel.read_handle_identity(wrapperHandle);
        const controlVerified = await assertObject(controlTemplate, Buffer.from(txId), parentIdentity, undefined, 'authority');
        const wrapperVerified = await assertObject(wrapperTemplate, Buffer.from(txId), parentIdentity, undefined, 'authority');
        if (!sameIdentity(controlIdentity, controlVerified.identity) ||
            !sameIdentity(wrapperIdentity, wrapperVerified.identity)) {
          refused('probe_prospective_cleanup', 'prospective final-profile template identity changed');
        }
        const scratchAccess = await Promise.all([
          [managementPrincipal, 'read'],
          [managementPrincipal, 'write'],
          [botPrincipal, 'read'],
          [botPrincipal, 'write'],
          [recoveryPrincipal, 'read'],
          [recoveryPrincipal, 'write'],
        ].map(async ([principal, mode]) => ({
          principal,
          mode,
          result: await lowLevel.principal_access_check(scratch, principal.kind, principal.value, mode),
        })));
        const [managementRead, managementWrite, botRead, botWrite, recoveryRead, recoveryWrite] = scratchAccess;
        if (managementRead.result !== true || managementWrite.result !== true ||
            botRead.result !== true || botWrite.result !== false ||
            recoveryRead.result !== true || recoveryWrite.result !== false) {
          refused('probe_prospective_cleanup', 'prospective exact-role scratch access is not proven');
        }
        const finalTemplateAccess = await Promise.all([controlTemplate, wrapperTemplate].flatMap((template) => [
          [managementPrincipal, 'write', true],
          [botPrincipal, 'read', true],
          [botPrincipal, 'write', false],
          [recoveryPrincipal, 'read', true],
          [recoveryPrincipal, 'write', false],
        ].map(async ([principal, mode, expected]) => ({
          template,
          principal,
          mode,
          expected,
          result: await lowLevel.principal_access_check(template, principal.kind, principal.value, mode),
        }))));
        if (finalTemplateAccess.some(({ expected, result }) => result !== expected)) {
          refused('probe_prospective_cleanup', 'prospective final-profile template access is not proven');
        }
        const accessCheckedScratch = await assertObject(scratch, Buffer.from(txId), parentIdentity);
        if (!sameIdentity(await lowLevel.read_handle_identity(scratchHandle), retainedScratchIdentity) ||
            !sameIdentity(accessCheckedScratch.identity, retainedScratchIdentity)) {
          refused('probe_prospective_cleanup', 'prospective scratch identity changed during access check');
        }
        const scratchIdentity = identityFingerprint(handleIdentity);
        const templateTargetIdentity = identityFingerprint(handleIdentity);
        const templateControlIdentity = identityFingerprint(controlIdentity);
        const templateWrapperIdentity = identityFingerprint(wrapperIdentity);
        const templateTargetAclFingerprint = fingerprint(Buffer.from(String(pathVerified.acl)));
        const templateControlAclFingerprint = fingerprint(Buffer.from(String(controlVerified.acl)));
        const templateWrapperAclFingerprint = fingerprint(Buffer.from(String(wrapperVerified.acl)));
        const mMutationProofFingerprint = fingerprint(encode({ txId, scratchIdentity, access: [managementRead, managementWrite] }));
        const botReadProofFingerprint = fingerprint(encode({ txId, scratchIdentity, access: botRead }));
        const recoveryReadProofFingerprint = fingerprint(encode({ txId, scratchIdentity, access: recoveryRead }));
        const botWriteDeniedProofFingerprint = fingerprint(encode({ txId, scratchIdentity, access: botWrite }));
        const recoveryWriteDeniedProofFingerprint = fingerprint(encode({ txId, scratchIdentity, access: recoveryWrite }));
        probe = {
          version: 1, kind: 'genesis-prospective-probe', probeNonce: fingerprint(Buffer.from(txId)).slice(0, 32),
          anchorFingerprint: await anchorFingerprint(), parentIdentity: identityFingerprint(parentIdentity),
          targetInputState: targetBytes === null ? 'absent' : 'legacy-unmigrated',
          managementIdentity: managementPrincipal, botIdentity: botPrincipal, recoveryIdentity: recoveryPrincipal,
          mProvisioningFingerprint: managementProvisioningFingerprint, bProvisioningFingerprint: botProvisioningFingerprint, rProvisioningFingerprint: recoveryProvisioningFingerprint,
          templateTargetIdentity, templateTargetAclFingerprint,
          templateControlIdentity, templateControlAclFingerprint,
          templateWrapperIdentity, templateWrapperAclFingerprint,
          mMutationProofFingerprint, botReadProofFingerprint, recoveryReadProofFingerprint,
          botWriteDeniedProofFingerprint, recoveryWriteDeniedProofFingerprint,
          scratchIdentity,
          authorityWrites: 0, targetWrites: 0, controlWrites: 0,
          authorityCommittedWrites: 0, targetCommittedWrites: 0, controlCommittedWrites: 0,
          phase: 'prepared', probeFingerprint: null,
        };
        probe.probeFingerprint = fingerprintGenesisProbe(probe); validateGenesisProspectiveProbe(probe);
        await replaceScratch(probe);
        probe = transitionGenesisProspectiveProbe(probe, 'verified'); await replaceScratch(probe);
        const observed = Object.fromEntries([
          'probeNonce', 'managementIdentity', 'parentIdentity', 'scratchIdentity',
          'templateTargetIdentity', 'templateTargetAclFingerprint',
          'templateControlIdentity', 'templateControlAclFingerprint',
          'templateWrapperIdentity', 'templateWrapperAclFingerprint',
          'mMutationProofFingerprint', 'botReadProofFingerprint', 'recoveryReadProofFingerprint',
          'botWriteDeniedProofFingerprint', 'recoveryWriteDeniedProofFingerprint',
          'authorityWrites', 'targetWrites', 'controlWrites',
          'authorityCommittedWrites', 'targetCommittedWrites', 'controlCommittedWrites',
          'probeFingerprint',
        ].map((key) => [key, probe[key]]));
        if (!canCleanGenesisScratch(probe, observed)) refused('probe_prospective_cleanup', 'prospective scratch verification is ambiguous');
        probe = transitionGenesisProspectiveProbe(probe, 'cleaned'); await replaceScratch(probe);
        const cleaned = encode(probe); await lowLevel.remove_verified_handle(scratchHandle, cleaned); await lowLevel.remove_verified_handle(controlHandle, Buffer.from(txId)); await lowLevel.remove_verified_handle(wrapperHandle, Buffer.from(txId)); await lowLevel.flush_directory_or_volume(parent); await assertParent(targetPath, parentIdentity);
      } catch {
        if (scratch && probe) {
          try {
            const manual = probe.phase === 'prepared' || probe.phase === 'verified' ? transitionGenesisProspectiveProbe(probe, 'manual_cleanup') : probe;
            await replaceScratch(manual);
          } catch {}
        }
        refused('probe_prospective_cleanup', 'prospective cleanup is ambiguous; manual cleanup is required');
      }
      const parentMutation = await Promise.all([
        [managementPrincipal, true], [botPrincipal, false], [recoveryPrincipal, false],
      ].map(async ([principal, expected]) =>
        (await lowLevel.principal_access_check(parent, principal.kind, principal.value, 'write')) === expected));
      if (!parentMutation.every(Boolean)) {
        refused('probe_prospective_cleanup', 'actual config parent is not M-owned or permits B/R entry mutation');
      }
      const securityTuple = genesisSecurityTuple === undefined ? null : {
        ...structuredClone(genesisSecurityTuple),
        targetInputState: targetBytes === null ? 'absent' : 'legacy-unmigrated',
        legacyTargetProof,
      };
      prospectiveProof = {
        txId, targetPrincipal, managementPrincipal, botPrincipal, recoveryPrincipal,
        managementProvisioningFingerprint, botProvisioningFingerprint, recoveryProvisioningFingerprint,
        legacyTargetProof, securityTuple, probe,
      };
      return { targetInputState: targetBytes === null ? 'absent' : 'legacy-unmigrated', legacyTargetProof, genesisSecurityTuple: securityTuple, probe };
    },
    async reserveTokenFloor(record) { await requireAuthorityRequest('reserve_token_floor'); if (Object.hasOwn(record ?? {}, 'tokenBytes') || !reservationValid(record)) refused('reserve_token_floor', 'exact secret-free generation reservation is required'); const published = await hasPublishedAuthority(); const request = published ? null : await read(path('genesis-request')); if (!published && (prospectiveProof?.txId !== record.lastReservationTxId || !request || request.genesisTxId !== record.lastReservationTxId || request.tokenFloorFingerprint !== record.floorFingerprint)) refused('reserve_token_floor', 'owner-bound request does not bind reservation'); await writeImmutableAuthority(`token-floor-reservation-${encodeURIComponent(record.lastReservationTxId)}`, record); await writeAuthority('token-floor', record); return record; },
    async writeTokenConfigAttestation(record) {
      await requireAuthorityRequest('write_token_config_attestation');
      if (Object.hasOwn(record ?? {}, 'tokenBytes') || !attestationValid(record)) refused('write_token_config_attestation', 'exact secret-free generation reservation is required');
      const floor = await read(path('token-floor'));
      const published = await hasPublishedAuthority();
      const request = published ? null : await read(path('genesis-request'));
      if (!floor || floor.lastReservationTxId !== record.txId || floor.highestReservedGeneration !== record.tokenConfigGeneration ||
          (!published && (prospectiveProof?.txId !== record.txId || !request || request.attestationFingerprint !== record.attestationFingerprint))) {
        refused('write_token_config_attestation', 'reservation order is invalid');
      }
      const history = await read(path('attestation-history')) ?? [];
      if (!Array.isArray(history) || history.length >= 10000 ||
          (history.length === 0 ? record.previousAttestationFingerprint !== null :
            history.at(-1).attestationFingerprint !== record.previousAttestationFingerprint ||
            history.at(-1).tokenConfigGeneration + 1 !== record.tokenConfigGeneration)) {
        refused('write_token_config_attestation', 'attestation history is invalid');
      }
      await writeImmutableAuthority(`attestation-${encodeURIComponent(record.txId)}`, record);
      await writeAuthority('attestation-history', [...history, record]);
      await writeAuthority('attestation', record);
      return record;
    },
    async writeAttestedTokenFloor(value) {
      const { reservation, attestation, proof, floor } = value ?? {};
      try { validateTokenFloorReservation(reservation); validateTokenConfigAttestation(attestation); validateAttestedTokenFloorProof(proof, reservation, attestation); validateTokenFloor(floor); } catch { refused('write_attested_token_floor', 'exact immutable attested token-floor proof is required'); }
      if (floor.floorPhase !== 'attested' || floor.attestedProofFingerprint !== proof.attestedProofFingerprint) refused('write_attested_token_floor', 'attested token-floor relation is invalid');
      if (canonical(await read(path('token-floor'))) !== canonical(reservation)) refused('write_attested_token_floor', 'attested floor CAS predecessor changed');
      await writeImmutableAuthority(`token-floor-attested-${encodeURIComponent(attestation.txId)}`, proof);
      await writeAuthority('token-floor', floor);
      if (canonical(await read(path('token-floor'))) !== canonical(floor)) refused('write_attested_token_floor', 'attested floor durable reopen failed');
      return floor;
    },
    async writeGenesisRequest(record) { try { validateGenesisRequest(record); } catch { refused('write_genesis_request', 'exact genesis request is required'); } if (prospectiveProof?.txId !== record.genesisTxId || record.ownerPrincipalFingerprint !== fingerprint(encode(prospectiveProof.managementPrincipal))) refused('write_genesis_request', 'prospective owner proof is invalid'); await writeImmutableAuthority('genesis-request', record); return record; },
    async commitTokenFloor(value) {
      const { floor: record, precommit } = value ?? {};
      try { validateTokenFloor(record); } catch { refused('commit_token_floor', 'exact committed generation floor is required'); }
      const prior = await read(path('token-floor'));
      const attestation = await read(path('attestation'));
      const request = await read(path('genesis-request'));
      const reservation = prior && await read(path(`token-floor-reservation-${encodeURIComponent(prior.lastReservationTxId)}`));
      const attested = prior && await read(path(`token-floor-attested-${encodeURIComponent(prior.lastReservationTxId)}`));
      if (!prior || prior.floorPhase !== 'attested' || !attestation || !reservation || !attested) {
        refused('commit_token_floor', 'attested token-floor predecessor is absent');
      }
      try { validateAttestedTokenFloorProof(attested, reservation, attestation); } catch {
        refused('commit_token_floor', 'attested proof is invalid');
      }
      const isGenesisCommit = request !== null && record.lastCommittedTxId === request.genesisTxId;
      if (isGenesisCommit) {
        const storedPrecommit = await read(path('genesis-precommit-proof'));
        const epoch = await read(path('authority-epoch'));
        const authorityReservation = await read(path(`authority-reservation-${encodeURIComponent(request.genesisTxId)}`));
        const authorityCommit = await read(path(`authority-commit-${encodeURIComponent(request.genesisTxId)}`));
        const k = await read(path(`publication-k-${encodeURIComponent(request.genesisTxId)}`));
        const y = await read(path(`publication-y-${encodeURIComponent(request.genesisTxId)}`));
        const state = await read(path('management-state'));
        const controlRoot = await read(path('control-root'));
        const wrapper = controlRoot?.wrapperRelativeName
          ? await read(join(root, controlRoot.wrapperRelativeName))
          : null;
        const liveTarget = await targetProof({ sourceKind: controlRoot?.sourceKind });
        const liveControl = controlRoot && await authorityObjectProof(path('control-root'));
        const liveWrapper = controlRoot?.wrapperRelativeName &&
          await authorityObjectProof(join(root, controlRoot.wrapperRelativeName));
        try {
          validateGenesisPrecommit(precommit);
          validateGenesisPrecommit(storedPrecommit);
          validateAuthorityEpoch(epoch);
          validateAuthorityReservation(authorityReservation);
          validateAuthorityCommitSnapshot(authorityCommit, authorityReservation);
          validatePublicationK(k);
          validatePublicationY(y, k['publication-kFingerprint']);
        } catch {
          refused('commit_token_floor', 'exact precommit graph is invalid');
        }
        const downstreamNames = ['z-finality', 'rvf', 'receipt', 'admission-request', 'admission-grant'];
        const downstreamPresent = (await Promise.all(downstreamNames.map((name) => read(path(name)))))
          .some((entry) => entry !== null) ||
          await read(botPath('reader-projection')) !== null ||
          await read(botPath('acknowledgement')) !== null;
        if (canonical(precommit) !== canonical(storedPrecommit) ||
            precommit.requestFingerprint !== request.requestFingerprint ||
            precommit.reservationFingerprint !== reservation.floorFingerprint ||
            precommit.attestedProofFingerprint !== attested.attestedProofFingerprint ||
            precommit.authorityReservationFingerprint !== authorityReservation.reservationFingerprint ||
            precommit.authorityCommitSnapshotFingerprint !== authorityCommit.authorityCommitSnapshotFingerprint ||
            precommit.publicationKFingerprint !== k['publication-kFingerprint'] ||
            precommit.publicationYFingerprint !== y['publication-yFingerprint'] ||
            precommit.authorityEpochFingerprint !== epoch.authorityEpochFingerprint ||
            epoch.commitTxId !== request.genesisTxId ||
            await read(path('terminal-close')) !== null ||
            state?.admission?.phase !== 'closed' || !['prepared', 'replaced'].includes(state?.recovery?.phase) ||
            !controlRoot || !wrapper || !liveControl || !liveWrapper ||
            precommit.targetFingerprint !== fingerprint(liveTarget.bytes) ||
            precommit.targetIdentityFingerprint !== liveTarget.targetIdentity ||
            precommit.targetAclFingerprint !== liveTarget.targetAclFingerprint ||
            precommit.controlRootFingerprint !== controlRoot.controlRootFingerprint ||
            precommit.controlIdentityFingerprint !== liveControl.identityFingerprint ||
            precommit.controlAclFingerprint !== liveControl.aclFingerprint ||
            precommit.wrapperIdentityFingerprint !== liveWrapper.identityFingerprint ||
            precommit.wrapperAclFingerprint !== liveWrapper.aclFingerprint ||
            precommit.wrapperFingerprint !== wrapper.wrapperFingerprint ||
            wrapper.routeDisposition !== 'no-route' ||
            downstreamPresent) {
          refused('commit_token_floor', 'exact precommit proof is invalid');
        }
        if (!await exactPrecommitBoundary(request, precommit)) refused('commit_token_floor', 'exact live precommit boundary is invalid');
      } else if (precommit !== undefined) {
        refused('commit_token_floor', 'non-Genesis rotation must not supply Genesis precommit proof');
      }
      const expected = commitTokenFloor(prior, {
        generation: record.highestReservedGeneration,
        txId: prior.lastReservationTxId,
        attestationFingerprint: attestation.attestationFingerprint,
      });
      if (canonical(expected) !== canonical(record)) refused('commit_token_floor', 'committed token-floor CAS result is invalid');
      await writeImmutableAuthority(`token-floor-commit-${encodeURIComponent(record.lastCommittedTxId)}`, record);
      const history = await read(path('token-floor-history')) ?? [];
      if (!Array.isArray(history) || history.length >= 10000 ||
          (history.length > 0 && history.at(-1).highestCommittedGeneration + 1 !== record.highestCommittedGeneration)) {
        refused('commit_token_floor', 'token floor history is invalid');
      }
      await writeAuthority('token-floor-history', [...history, record]);
      await writeAuthority('token-floor', record);
      if (canonical(await read(path('token-floor'))) !== canonical(record)) refused('commit_token_floor', 'committed floor durable reopen failed');
      if (isGenesisCommit && !await exactPrecommitBoundary(request, precommit)) refused('commit_token_floor', 'exact live precommit boundary changed after commit');
      return record;
    },
    async writePublicationGraph(records) {
const fail = () => refused('write_publication_graph', 'exact acyclic publication graph is required');
      if (!records || Object.getPrototypeOf(records) !== Object.prototype) fail();
      const { transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y } = records;
      const baseline = await read(path(`authority-baseline-${encodeURIComponent(transaction?.genesisTxId ?? '')}`));
      const control = await read(path('control-root'));
      const wrapper = control?.wrapperRelativeName && await read(join(root, control.wrapperRelativeName));
      const target = control && await targetProof({ sourceKind: control.sourceKind });
      const state = await read(path('management-state'));
      try {
        validateBaselineSnapshot(baseline);
        const canonicalMappingFingerprint = control?.sourceKind === 'legacy-retained'
          ? canonicalJsonHash({
            sourceKind: 'legacy-retained',
            targetFingerprint: fingerprint(target.bytes),
            identityFingerprint: target.targetIdentity,
            aclFingerprint: target.targetAclFingerprint,
          })
          : canonicalJsonHash({ mappingGeneration: state?.mappingGeneration, mappings: state?.mappings, routes: state?.routes });
        const stateFingerprint = canonicalJsonHash({ targetState: baseline.targetState, targetFingerprint: fingerprint(target.bytes), targetIdentityFingerprint: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint, canonicalMappingFingerprint });
        const payloadFingerprint = canonicalJsonHash({ targetFingerprint: fingerprint(target.bytes), targetIdentityFingerprint: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint, wrapperFingerprint: wrapper?.wrapperFingerprint, controlRootFingerprint: control?.controlRootFingerprint, canonicalMappingFingerprint });
        const snapshotFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, targetFingerprint: fingerprint(target.bytes) });
        const publicationFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, snapshotFingerprint, targetFingerprint: fingerprint(target.bytes) });
        const checkpointFingerprint = canonicalJsonHash({ genesisTxId: transaction.genesisTxId, generation: transaction.generation, publicationFingerprint, targetFingerprint: fingerprint(target.bytes) });
        if (transaction.baselineFingerprint !== baseline.baselineFingerprint || u.baselineFingerprint !== baseline.baselineFingerprint ||
            u.anchorFingerprint !== baseline.anchorFingerprint || u.targetState !== baseline.targetState ||
            u.attestationFingerprint !== baseline.attestationFingerprint || u.authorityReservationFingerprint !== baseline.authorityReservationFingerprint ||
            u.authorityCommitSnapshotFingerprint !== baseline.authorityCommitSnapshotFingerprint ||
            u.fenceBindingFingerprint !== baseline.fenceBindingFingerprint || u.leaseBindingFingerprint !== baseline.leaseBindingFingerprint ||
            u.readerProjectionFingerprint !== baseline.readerProjectionFingerprint || u.readerInstanceId !== baseline.readerInstanceId ||
            u.readerStartNonce !== baseline.readerStartNonce || u.readerVersion !== baseline.readerVersion ||
            p.stateFingerprint !== stateFingerprint || s.stateFingerprint !== stateFingerprint || s.payloadFingerprint !== payloadFingerprint ||
            [c, q, zp].some((record) => record.stateFingerprint !== stateFingerprint || record.payloadFingerprint !== payloadFingerprint || record.snapshotFingerprint !== snapshotFingerprint) ||
            q.baselineFingerprint !== baseline.baselineFingerprint || zp.publicationFingerprint !== publicationFingerprint ||
            k.publicationFingerprint !== publicationFingerprint || k.authorityCommitSnapshotFingerprint !== baseline.authorityCommitSnapshotFingerprint ||
            k.checkpointFingerprint !== checkpointFingerprint || y.publicationFingerprint !== publicationFingerprint ||
            y.targetFingerprint !== fingerprint(target.bytes) || y.targetState !== baseline.targetState ||
            y.authorityCommitSnapshotFingerprint !== baseline.authorityCommitSnapshotFingerprint ||
            y.fenceBindingFingerprint !== baseline.fenceBindingFingerprint) fail();
      } catch (error) {
        fail();
      }
      try {
        validatePublicationTransaction(transaction);
        validatePublicationU(u, transaction.baselineFingerprint);
        validatePublicationP(p, u);
        validatePublicationS(s, p);
        if (s.txId !== transaction.txId || s.genesisTxId !== transaction.genesisTxId || s.generation !== transaction.generation) fail();
        for (const phase of [prepared, replaced, committed]) validatePublicationState(phase, transaction);
        if (prepared.phase !== 'prepared' || replaced.phase !== 'replaced' || committed.phase !== 'committed') fail();
        validatePublicationC(c, s);
        validatePublicationQ(q, c);
        validatePublicationZp(zp, q);
        if ([prepared, replaced, committed].some((state) => state.publicationFingerprint !== zp.publicationFingerprint)) fail();
        validatePublicationK(k, zp);
        validatePublicationY(y, k);
        if ([u, p, s, prepared, replaced, committed, c, q, zp, k, y].some((record) =>
          record.txId !== transaction.txId || record.genesisTxId !== transaction.genesisTxId || record.generation !== transaction.generation)) fail();
      } catch (error) {
        fail();
      }
      const immutable = [
        ['publication-transaction', transaction], ['publication-u', u], ['publication-p', p], ['publication-s', s],
        ['publication-state-prepared', prepared], ['publication-state-replaced', replaced], ['publication-c', c],
        ['publication-q', q], ['publication-zp', zp], ['publication-k', k], ['publication-y', y],
        ['publication-state-committed', committed],
      ];
      for (const [name, record] of immutable) {
        const existing = await read(path(`${name}-${encodeURIComponent(transaction.txId)}`));
        if (existing !== null) { if (canonical(existing) !== canonical(record)) fail(); }
        else await writeImmutableAuthority(`${name}-${encodeURIComponent(transaction.txId)}`, record);
      }
      return y;
    },
    async writeZFinality(record) {
      const request = await read(path('genesis-request'));
      const floor = await read(path('token-floor'));
      const precommit = await read(path('genesis-precommit-proof'));
      const epoch = await read(path('authority-epoch'));
      const k = request && await read(path(`publication-k-${encodeURIComponent(request.genesisTxId)}`));
      const y = request && await read(path(`publication-y-${encodeURIComponent(request.genesisTxId)}`));
      try {
        validateZFinality(record, request, floor, precommit);
        validateAuthorityEpoch(epoch);
        validatePublicationK(k);
        validatePublicationY(y, k['publication-kFingerprint']);
      } catch {
        refused('write_z_finality', 'exact committed Genesis finality is required');
      }
      if (record.authorityEpochFingerprint !== epoch.authorityEpochFingerprint ||
          record.publicationKFingerprint !== k['publication-kFingerprint'] ||
          record.publicationYFingerprint !== y['publication-yFingerprint'] ||
          record.precommitFingerprint !== precommit.precommitFingerprint) {
        refused('write_z_finality', 'Genesis finality graph is invalid');
      }
      await writeAuthority('z-finality', record);
      return record;
    },
    async writeFinalityProof(record) {
      await validateStoredFinalityGraph(record);
      await writeAuthority('rvf', record);
      return record;
    },
    async writeAdmissionRequest(record) {
      try { validateAdmissionRequest(record); } catch { refused('write_admission_request', 'exact management admission request is required'); }
      await writeImmutableAuthority(`admission-request-${encodeURIComponent(record.requestId)}`, record);
      await writeAuthority('admission-request', record);
      return record;
    },
    async writeAdmissionGrant(record) {
      const request = await read(path('admission-request'));
      try { validateAdmissionGrant(record, request); } catch { refused('write_admission_grant', 'exact management admission grant is required'); }
      await writeImmutableAuthority(`admission-grant-${encodeURIComponent(record.grantId)}`, record);
      await writeAuthority('admission-grant', record);
      return record;
    },
    async writeGenesisReceipt(record) {
      const finalityProof = await read(path('rvf'));
      const graph = await validateStoredFinalityGraph(finalityProof);
      try {
        validateGenesisReceipt(record, graph.request, graph.zFinality, finalityProof);
      } catch {
        refused('write_genesis_receipt', 'exact Genesis receipt relation is required');
      }
      await writeAuthority('receipt', record);
      return record;
    },
    async readBoundReaderProof() {
      const [readerProjection, admissionAck, readerState, readerVersionFloor, request, tokenFloor, zFinality, admissionRequest, admissionGrant] = await Promise.all([
        read(botPath('reader-projection')), read(botPath('acknowledgement')), read(botPath('reader-state')), read(path('reader-version-floor')),
        read(path('genesis-request')), read(path('token-floor')), read(path('z-finality')),
        read(path('admission-request')), read(path('admission-grant')),
      ]);
      if ((readerProjection === null) !== (admissionAck === null) || (readerProjection === null) !== (readerState === null)) refused('read_bound_reader_proof', 'reader proof must be an exact projection, acknowledgement, and reader-state triple');
      if (readerProjection !== null) {
        try {
          validateGenesisRequest(request);
          validateReaderVersionFloor(readerVersionFloor);
          validateTokenFloor(tokenFloor);
          validateZFinality(zFinality, request, tokenFloor, await read(path('genesis-precommit-proof')));
          validateAdmissionGrant(admissionGrant, admissionRequest, Date.now());
          validateReaderProjection(readerProjection, readerVersionFloor, tokenFloor, zFinality.zFinalityFingerprint);
          validateAdmissionAck(admissionAck, admissionGrant, readerProjection.readerProjectionFingerprint);
          validateReaderRelations(readerState, readerVersionFloor);
          if (readerState.readerInstanceId !== request.readerInstanceId ||
              readerState.readerStartNonce !== request.readerStartNonce ||
              readerState.readerProjectionFingerprint !== readerProjection.readerProjectionFingerprint) {
            throw new TypeError('reader state relation');
          }
        } catch {
          refused('read_bound_reader_proof', 'reader proof is not bound to committed authority');
        }
      }
      return { readerProjection, admissionAck, readerState, readerVersionFloor };
    },
    async recheckAdmissionFinality({ request, zFinality, readerProjection, admissionAck, finalityProof, receipt }) {
      if (await read(path('terminal-close')) !== null) return false;
      if (!request || typeof request.genesisTxId !== 'string') return false;
      let fullPublication;
      let envelope;
      try {
        fullPublication = await readPublicationGraph(request.genesisTxId);
        if (!await exactPrecommitBoundary(request, await read(path('genesis-precommit-proof')))) return false;
        const controlRoot = await read(path('control-root'));
        const wrapper = controlRoot?.wrapperRelativeName
          ? await read(join(root, controlRoot.wrapperRelativeName))
          : null;
        const target = await targetProof({ sourceKind: controlRoot?.sourceKind });
        envelope = validateManagementEnvelope(controlRoot, wrapper, {
          targetBytes: target.bytes,
          targetIdentity: target.targetIdentity,
          targetAclFingerprint: target.targetAclFingerprint,
        });
        if (!envelope.ok || wrapper.routeDisposition !== 'no-route') return false;
      } catch {
        return false;
      }
      const [
        storedRequest,
        tokenFloor,
        precommit,
        attestation,
        attestedProof,
        authorityEpoch,
        authorityReservation,
        authorityCommit,
        publicationK,
        publicationY,
        storedFinality,
        storedProof,
        storedReceipt,
        readerVersionFloor,
        admissionRequest,
        admissionGrant,
        storedProjection,
        storedAck,
        managementState,
        authorityRequest,
        authorityReceipt,
        authorityBaseline,
        fenceBinding,
        storedReaderState,
      ] = await Promise.all([
        read(path('genesis-request')),
        read(path('token-floor')),
        read(path('genesis-precommit-proof')),
        read(path('attestation')),
        request && read(path(`token-floor-attested-${encodeURIComponent(request.genesisTxId)}`)),
        read(path('authority-epoch')),
        request && read(path(`authority-reservation-${encodeURIComponent(request.genesisTxId)}`)),
        request && read(path(`authority-commit-${encodeURIComponent(request.genesisTxId)}`)),
        request && read(path(`publication-k-${encodeURIComponent(request.genesisTxId)}`)),
        request && read(path(`publication-y-${encodeURIComponent(request.genesisTxId)}`)),
        read(path('z-finality')),
        read(path('rvf')),
        read(path('receipt')),
        read(path('reader-version-floor')),
        read(path('admission-request')),
        read(path('admission-grant')),
        read(botPath('reader-projection')),
        read(botPath('acknowledgement')),
        read(path('management-state')),
        read(path('genesis-authority-request')),
        read(path('genesis-authority-receipt')),
        read(path('authority-baseline')),
        read(path('reader-fence-binding')),
        read(botPath('reader-state')),
      ]);
      try {
        validateGenesisRequest(storedRequest);
        validateTokenFloor(tokenFloor);
        validateGenesisPrecommit(precommit);
        validateTokenConfigAttestation(attestation);
        validateAttestedTokenFloorProof(attestedProof,
          await read(path(`token-floor-reservation-${encodeURIComponent(request.genesisTxId)}`)),
          attestation);
        validateAuthorityEpoch(authorityEpoch);
        validateAuthorityReservation(authorityReservation);
        validateAuthorityCommitSnapshot(authorityCommit, authorityReservation);
        validateGenesisAuthorityRequest(authorityRequest);
        validateGenesisAuthorityReceipt(authorityReceipt, authorityRequest);
        validateBaselineSnapshot(authorityBaseline);
        if (storedRequest.requestedReaderMode === 'handshake') {
          validateFenceBinding(fenceBinding, authorityCommit, readerVersionFloor);
        } else if (fenceBinding !== null) {
          throw new TypeError('no-reader fence');
        }
        validatePublicationK(publicationK);
        validatePublicationY(publicationY, publicationK['publication-kFingerprint']);
        validateZFinality(storedFinality, storedRequest, tokenFloor, precommit);
        validateReaderVersionFloor(readerVersionFloor);
        validateFinalityProof(storedProof, storedRequest, storedFinality, storedAck, storedProjection?.readerProjectionFingerprint ?? null);
        validateGenesisReceipt(storedReceipt, storedRequest, storedFinality, storedProof);
        if (storedRequest.requestedReaderMode === 'handshake') {
          validateAdmissionGrant(admissionGrant, admissionRequest, Date.now());
          validateReaderProjection(storedProjection, readerVersionFloor, tokenFloor, storedFinality.zFinalityFingerprint);
          validateAdmissionAck(storedAck, admissionGrant, storedProjection.readerProjectionFingerprint);
          validateReaderRelations(storedReaderState, readerVersionFloor);
          if (storedReaderState.readerInstanceId !== storedRequest.readerInstanceId ||
              storedReaderState.readerStartNonce !== storedRequest.readerStartNonce ||
              storedReaderState.readerProjectionFingerprint !== storedProjection.readerProjectionFingerprint) {
            throw new TypeError('reader state finality relation');
          }
        } else if (storedReaderState !== null) {
          throw new TypeError('no-reader state');
        }
      } catch {
        return false;
      }
      if (canonical(storedRequest) !== canonical(request) ||
          canonical(storedFinality) !== canonical(zFinality) ||
          canonical(storedProof) !== canonical(finalityProof) ||
          canonical(storedReceipt) !== canonical(receipt) ||
          fullPublication.transaction.genesisTxId !== storedRequest.genesisTxId ||
          fullPublication.transaction.generation !== storedRequest.generation ||
          fullPublication.transaction.baselineFingerprint !== authorityBaseline.baselineFingerprint ||
          canonical(fullPublication.k) !== canonical(publicationK) ||
          canonical(fullPublication.y) !== canonical(publicationY) ||
          authorityRequest.genesisTxId !== storedRequest.genesisTxId ||
          authorityRequest.generation !== storedRequest.generation ||
          authorityReceipt.authorityCommitSnapshotFingerprint !== authorityCommit.authorityCommitSnapshotFingerprint ||
          authorityReceipt.readerVersionFloorFingerprint !== readerVersionFloor.floorFingerprint ||
          authorityBaseline.genesisTxId !== storedRequest.genesisTxId ||
          authorityBaseline.generation !== storedRequest.generation ||
          authorityBaseline.attestationFingerprint !== attestation.attestationFingerprint ||
          precommit.requestFingerprint !== storedRequest.requestFingerprint ||
          precommit.attestedProofFingerprint !== attestedProof.attestedProofFingerprint ||
          precommit.authorityReservationFingerprint !== authorityReservation.reservationFingerprint ||
          precommit.authorityCommitSnapshotFingerprint !== authorityCommit.authorityCommitSnapshotFingerprint ||
          precommit.authorityEpochFingerprint !== authorityEpoch.authorityEpochFingerprint ||
          precommit.publicationKFingerprint !== publicationK['publication-kFingerprint'] ||
          precommit.publicationYFingerprint !== publicationY['publication-yFingerprint'] ||
          managementState?.admission?.phase !== 'closed' ||
          managementState?.recovery?.txId !== storedRequest.genesisTxId ||
          managementState?.recovery?.requestFingerprint !== storedRequest.requestFingerprint ||
          managementState?.recovery?.phase !== 'replaced') {
        return false;
      }
      if (storedRequest.requestedReaderMode === 'no-reader') {
        return admissionRequest === null && admissionGrant === null &&
          storedProjection === null && storedAck === null && storedReaderState === null &&
          readerProjection === null && admissionAck === null &&
          Boolean(await exactPrecommitBoundary(storedRequest, precommit));
      }
      return canonical(storedProjection) === canonical(readerProjection) &&
        canonical(storedAck) === canonical(admissionAck) &&
        storedReaderState !== null &&
        Boolean(await exactPrecommitBoundary(storedRequest, precommit));
    },
    async mappingTargetProof() {
      await requireAuthorityRequest('mapping_target_proof');
      const target = await targetProof();
      let snapshot;
      try { snapshot = validateManagementSnapshot(parseCanonicalJsonBytes(target.bytes)); } catch {
        refused('mapping_target_proof', 'managed target snapshot is not exact');
      }
      const control = await read(path('control-root'));
      const wrapper = control?.wrapperRelativeName ? await read(join(root, control.wrapperRelativeName)) : null;
      if (!control || !wrapper) refused('mapping_target_proof', 'managed envelope proof is absent');
      return {
        snapshotFingerprint: snapshot.configFingerprint,
        identityFingerprint: target.targetIdentity,
        aclFingerprint: target.targetAclFingerprint,
        snapshot: structuredClone(snapshot),
        targetFingerprint: fingerprint(target.bytes),
        controlRootFingerprint: control.controlRootFingerprint,
        wrapperFingerprint: wrapper.wrapperFingerprint,
      };
    },
    async writeMappingRecovery(records) {
      try { validateMappingRecoveryRecords(records); } catch {
        refused('write_mapping_recovery', 'exact mapping TX/PUB/BK/RC recovery records are required');
      }
      const { transaction, publication, backup, checkpoint } = records;
      const suffix = encodeURIComponent(transaction.txId);
      const phaseName = publication.phase;
      if (phaseName !== backup.phase || phaseName !== checkpoint.phase) {
        refused('write_mapping_recovery', 'mapping recovery phases disagree');
      }
      if (phaseName !== 'prepared') {
        const prior = await Promise.all(['tx', 'pub', 'bk', 'rc'].map((kind) =>
          read(path(`mapping-recovery-${kind}-${phaseName === 'replaced' ? 'prepared' : 'replaced'}-${suffix}`))));
        if (prior.some((record) => record === null)) refused('write_mapping_recovery', 'mapping recovery predecessor is absent');
      } else {
        const live = await adapter.mappingTargetProof();
        const state = await read(path('management-state'));
        if (state?.revision !== transaction.expectedRevision ||
            live.snapshotFingerprint !== transaction.oldSnapshot.configFingerprint ||
            live.identityFingerprint !== backup.backupIdentityFingerprint ||
            live.aclFingerprint !== backup.backupAclFingerprint) {
          refused('write_mapping_recovery', 'prepared recovery does not bind the exact verified old target snapshot');
        }
      }
      const recordsByKind = { tx: transaction, pub: publication, bk: backup, rc: checkpoint };
      for (const [kind, record] of Object.entries(recordsByKind)) {
        await writeCreateOnceAuthority(`mapping-recovery-${kind}-${phaseName}-${suffix}`, record);
      }
      return checkpoint;
    },
    async writeMappingGeneration(record) {
      if (!record || Object.getPrototypeOf(record) !== Object.prototype ||
          typeof record.mappingId !== 'string' || record.mappingId.length === 0 ||
          !Number.isSafeInteger(record.generation) || record.generation < 1 ||
          record.mapping?.mappingId !== record.mappingId ||
          record.mapping?.mappingGeneration !== record.generation ||
          !Array.isArray(record.routes) || typeof record.publicationTxId !== 'string') {
        refused('write_mapping_generation', 'exact immutable mapping generation is required');
      }
      try {
        validateManagedMappingRecord(record.mapping);
        for (const route of record.routes) validateManagedRouteRecord(route, record.mapping);
        if (typeof record.mapping.workspaceId !== 'string' || record.mapping.workDir !== null) {
          throw new TypeError('management mappings must be workspace-only');
        }
      } catch {
        refused('write_mapping_generation', 'exact immutable mapping generation is required');
      }
      if (await read(path(`mapping-tombstone-${encodeURIComponent(record.mappingId)}`)) !== null) {
        refused('write_mapping_generation', 'mapping identity is permanently tombstoned');
      }
      await writeImmutableAuthority(`mapping-generation-${encodeURIComponent(record.mappingId)}-${record.generation}`, record);
      return record;
    },
    async readMappingGeneration({ mappingId, generation }) {
      if (typeof mappingId !== 'string' || !Number.isSafeInteger(generation) || generation < 1) return null;
      return read(path(`mapping-generation-${encodeURIComponent(mappingId)}-${generation}`));
    },
    async writeMappingTombstone(record) {
      if (!record || Object.getPrototypeOf(record) !== Object.prototype ||
          record.version !== 1 || record.kind !== 'mapping-tombstone' ||
          !['mapping-revoke', 'mapping-rollback'].includes(record.operation) ||
          typeof record.mappingId !== 'string' || record.mappingId.length === 0 ||
          !Number.isSafeInteger(record.mappingGeneration) || record.mappingGeneration < 1 ||
          !hex(record.mappingFingerprint) || typeof record.publicationTxId !== 'string' ||
          !hex(record.snapshotFingerprint) || record.routeDisposition !== 'no-route' ||
          !hex(record.tombstoneFingerprint) ||
          record.tombstoneFingerprint !== recordFingerprint(record, 'tombstoneFingerprint')) {
        refused('write_mapping_tombstone', 'exact immutable mapping tombstone is required');
      }
      const generation = await read(path(`mapping-generation-${encodeURIComponent(record.mappingId)}-${record.mappingGeneration}`));
      if (!generation || generation.mapping?.mappingFingerprint !== record.mappingFingerprint) {
        refused('write_mapping_tombstone', 'tombstone does not bind an immutable mapping generation');
      }
      await writeCreateOnceAuthority(`mapping-tombstone-${encodeURIComponent(record.mappingId)}`, record);
      return record;
    },
    async writeMappingHandoffReceipt(record) {
      if (!record || Object.getPrototypeOf(record) !== Object.prototype ||
          record.version !== 1 || record.kind !== 'mapping-handoff-receipt' ||
          !['mapping-reconcile', 'mapping-revoke', 'mapping-rollback', 'mapping-recovery'].includes(record.operation) ||
          typeof record.publicationTxId !== 'string' || typeof record.oldMappingId !== 'string' && record.oldMappingId !== null ||
          !Number.isSafeInteger(record.oldMappingGeneration) && record.oldMappingGeneration !== null ||
          typeof record.newMappingId !== 'string' && record.newMappingId !== null ||
          !Number.isSafeInteger(record.newMappingGeneration) && record.newMappingGeneration !== null ||
          !hex(record.snapshotFingerprint) || record.routeDisposition !== 'no-route' ||
          !hex(record.handoffReceiptFingerprint) ||
          record.handoffReceiptFingerprint !== recordFingerprint(record, 'handoffReceiptFingerprint') ||
          !Object.hasOwn(record, 'tombstoneFingerprint') ||
          record.tombstoneFingerprint !== null && !hex(record.tombstoneFingerprint)) {
        refused('write_mapping_handoff_receipt', 'exact immutable mapping handoff receipt is required');
      }
      if ((record.oldMappingId === null) !== (record.oldMappingGeneration === null) ||
          (record.newMappingId === null) !== (record.newMappingGeneration === null) ||
          (record.operation === 'mapping-rollback' && (record.oldMappingId === record.newMappingId || !hex(record.tombstoneFingerprint))) ||
          (record.operation === 'mapping-revoke' && (record.newMappingId !== null || !hex(record.tombstoneFingerprint)))) {
        refused('write_mapping_handoff_receipt', 'mapping handoff identity relation is invalid');
      }
      if (record.tombstoneFingerprint !== null) {
        const tombstone = await read(path(`mapping-tombstone-${encodeURIComponent(record.oldMappingId)}`));
        if (!tombstone || tombstone.tombstoneFingerprint !== record.tombstoneFingerprint ||
            tombstone.publicationTxId !== record.publicationTxId || tombstone.snapshotFingerprint !== record.snapshotFingerprint) {
          refused('write_mapping_handoff_receipt', 'mapping handoff does not bind its tombstone');
        }
      }
      const snapshot = await read(targetPath);
      try { validateManagementSnapshot(snapshot); } catch { refused('write_mapping_handoff_receipt', 'managed snapshot is invalid'); }
      if (snapshot.configFingerprint !== record.snapshotFingerprint) refused('write_mapping_handoff_receipt', 'handoff snapshot binding is invalid');
      if (record.oldMappingId !== null) {
        const oldGeneration = await read(path(`mapping-generation-${encodeURIComponent(record.oldMappingId)}-${record.oldMappingGeneration}`));
        if (!oldGeneration) refused('write_mapping_handoff_receipt', 'old mapping generation is not durable');
      }
      if (record.newMappingId !== null) {
        const newGeneration = await read(path(`mapping-generation-${encodeURIComponent(record.newMappingId)}-${record.newMappingGeneration}`));
        if (!newGeneration || newGeneration.publicationTxId !== record.publicationTxId ||
            snapshot.mappings[record.newMappingId]?.mappingFingerprint !== newGeneration.mapping.mappingFingerprint) {
          refused('write_mapping_handoff_receipt', 'new mapping generation does not bind the handoff snapshot');
        }
      } else if (Object.hasOwn(snapshot.mappings, record.oldMappingId)) {
        refused('write_mapping_handoff_receipt', 'revoked mapping remains in the handoff snapshot');
      }
      await writeCreateOnceAuthority(`mapping-handoff-${encodeURIComponent(record.publicationTxId)}`, record);
      return record;
    },
    async readPendingReaderBootstrap() {
      await requireBotPrincipal('read_pending_reader_bootstrap');
      const request = await read(path('genesis-request'));
      const floor = await read(path('reader-version-floor'));
      const tokenFloor = await read(path('token-floor'));
      const zFinality = await read(path('z-finality'));
      const precommit = await read(path('genesis-precommit-proof'));
      const commit = request && await read(path(`authority-commit-${encodeURIComponent(request.genesisTxId)}`));
      const fence = await read(path('reader-fence-binding'));
      const admissionRequest = await read(path('admission-request'));
      const admissionGrant = await read(path('admission-grant'));
      try {
        validateGenesisRequest(request);
        validateReaderVersionFloor(floor);
        validateTokenFloor(tokenFloor);
        validateZFinality(zFinality, request, tokenFloor, precommit);
        validateAuthorityCommitSnapshot(commit);
        validateFenceBinding(fence, commit, floor);
        validateAdmissionGrant(admissionGrant, admissionRequest, Date.now());
      } catch {
        refused('read_pending_reader_bootstrap', 'pending reader authority is incomplete or inconsistent');
      }
      if (request.requestedReaderMode !== 'handshake' ||
          admissionRequest.genesisTxId !== request.genesisTxId ||
          admissionRequest.generation !== request.generation ||
          admissionRequest.readerInstanceId !== request.readerInstanceId ||
          admissionRequest.readerStartNonce !== request.readerStartNonce) {
        refused('read_pending_reader_bootstrap', 'pending reader authority does not bind the Genesis request');
      }
      return { request, floor, tokenFloor, zFinality, precommit, commit, fence, admissionRequest, admissionGrant };
    },
    async completePendingGenesis({ recovery }) {
      const projection = await read(botPath('reader-projection'));
      const acknowledgement = await read(botPath('acknowledgement'));
      if (projection === null && acknowledgement === null) return null;
      if (projection === null || acknowledgement === null) {
        refused('complete_pending_genesis', 'reader projection and acknowledgement must appear atomically as a bound pair');
      }
      return adapter.recoverGenesisSuffix({ recovery });
    },
    async recoverGenesisSuffix({ recovery }) {
      const fail = () => refused('recover_genesis_suffix', 'persisted genesis suffix is incomplete or inconsistent; manual cleanup is required');
      const request = await read(path('genesis-request'));
      const reservation = request && await read(path(`token-floor-reservation-${encodeURIComponent(request.genesisTxId)}`));
      const attestation = await read(path('attestation'));
      const controlRoot = await read(path('control-root'));
      const authorityRequest = await read(path('genesis-authority-request'));
      try {
        validateGenesisRequest(request); validateTokenFloorReservation(reservation); validateTokenConfigAttestation(attestation); validateGenesisAuthorityRequest(authorityRequest);
      } catch { fail(); }
      if (request.genesisTxId !== recovery?.txId || request.requestFingerprint !== recovery?.requestFingerprint ||
          request.tokenFloorFingerprint !== reservation.floorFingerprint || request.attestationFingerprint !== attestation.attestationFingerprint ||
          reservation.lastReservationTxId !== request.genesisTxId || reservation.highestReservedGeneration !== request.generation ||
          attestation.txId !== request.genesisTxId || attestation.tokenConfigGeneration !== request.generation ||
          !controlRoot) fail();
      if (request.requestedReaderMode === 'handshake' && controlRoot.sourceKind === 'legacy-retained') fail();

      let committed = await read(path('token-floor'));
      let zFinality = await read(path('z-finality'));
      const attestedProof = await read(path(`token-floor-attested-${encodeURIComponent(request.genesisTxId)}`));
      const precommit = await read(path('genesis-precommit-proof'));
      const epoch = await read(path('authority-epoch'));
      const authorityReservation = await read(path(`authority-reservation-${encodeURIComponent(request.genesisTxId)}`));
      const authorityCommit = await read(path(`authority-commit-${encodeURIComponent(request.genesisTxId)}`));
      const k = await read(path(`publication-k-${encodeURIComponent(request.genesisTxId)}`));
      const y = await read(path(`publication-y-${encodeURIComponent(request.genesisTxId)}`));
      try {
        validateAttestedTokenFloorProof(attestedProof, reservation, attestation);
        validateTokenFloor(committed);
        validateGenesisPrecommit(precommit);
        validateAuthorityEpoch(epoch);
        validateAuthorityReservation(authorityReservation);
        validateAuthorityCommitSnapshot(authorityCommit, authorityReservation);
        validatePublicationK(k);
        validatePublicationY(y, k['publication-kFingerprint']);
      } catch { fail(); }
      if (precommit.requestFingerprint !== request.requestFingerprint ||
          precommit.reservationFingerprint !== reservation.floorFingerprint ||
          precommit.attestedProofFingerprint !== attestedProof.attestedProofFingerprint ||
          precommit.authorityReservationFingerprint !== authorityReservation.reservationFingerprint ||
          precommit.authorityCommitSnapshotFingerprint !== authorityCommit.authorityCommitSnapshotFingerprint ||
          precommit.authorityEpochFingerprint !== epoch.authorityEpochFingerprint ||
          precommit.publicationKFingerprint !== k['publication-kFingerprint'] ||
          precommit.publicationYFingerprint !== y['publication-yFingerprint'] ||
          epoch.commitTxId !== request.genesisTxId) fail();
      if (!await exactPrecommitBoundary(request, precommit)) fail();
      if (committed.floorPhase === 'attested') {
        const expected = commitTokenFloor(committed, {
          generation: request.generation,
          txId: request.genesisTxId,
          attestationFingerprint: attestation.attestationFingerprint,
        });
        try {
          committed = await adapter.commitTokenFloor({ floor: expected, precommit });
        } catch {
          fail();
        }
      }
      try {
        validateTokenFloor(committed);
      } catch { fail(); }
      if (committed.floorPhase !== 'committed' ||
          committed.lastCommittedTxId !== request.genesisTxId ||
          committed.highestCommittedGeneration !== request.generation) fail();
      const expectedFinality = {
        version: 1,
        kind: 'genesis-finality',
        genesisTxId: request.genesisTxId,
        generation: request.generation,
        anchorFingerprint: request.anchorFingerprint,
        attestationFingerprint: attestation.attestationFingerprint,
        tokenFloorFingerprint: committed.floorFingerprint,
        checkpointFingerprint: canonicalJsonHash(request),
        publicationKFingerprint: k['publication-kFingerprint'],
        publicationYFingerprint: y['publication-yFingerprint'],
        authorityEpochFingerprint: epoch.authorityEpochFingerprint,
        precommitFingerprint: precommit.precommitFingerprint,
        finalityFingerprint: committed.floorFingerprint,
        zFinalityFingerprint: null,
      };
      expectedFinality.zFinalityFingerprint = recordFingerprint(expectedFinality, 'zFinalityFingerprint');
      try {
        validateZFinality(expectedFinality, request, committed, precommit);
      } catch { fail(); }
      if (zFinality === null) {
        try {
          zFinality = await adapter.writeZFinality(expectedFinality);
        } catch {
          fail();
        }
      }
      try {
        validateZFinality(zFinality, request, committed, precommit);
      } catch { fail(); }
      if (canonical(zFinality) !== canonical(expectedFinality)) fail();
      const authorityReceipt = {
        version: 1, kind: 'genesis-authority-receipt', genesisTxId: request.genesisTxId,
        requestFingerprint: authorityRequest.requestFingerprint, sequence: 2, anchorFingerprint: request.anchorFingerprint,
        generation: request.generation, readerVersionFloorFingerprint: (await read(path('reader-version-floor')))?.floorFingerprint,
        authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint, receiptFingerprint: null,
      };
      authorityReceipt.receiptFingerprint = recordFingerprint(authorityReceipt, 'receiptFingerprint');
      try {
        validateGenesisAuthorityReceipt(authorityReceipt, authorityRequest);
        await adapter.writeGenesisAuthorityReceipt(authorityReceipt);
      } catch {
        fail();
      }
      const immutableAuthorityReceipt = await read(path(`genesis-authority-receipt-${encodeURIComponent(request.genesisTxId)}`));
      if (canonical(await read(path('genesis-authority-receipt'))) !== canonical(authorityReceipt) ||
          canonical(immutableAuthorityReceipt) !== canonical(authorityReceipt)) fail();
      const exact = async (name, value) => {
        const current = await read(path(name));
        if (current !== null) {
          if (canonical(current) !== canonical(value)) fail();
          return current;
        }
        await writeAuthority(name, value);
        return value;
      };

      let projection = null; let acknowledgement = null; let readerState = null;
      const admissionRequest = await read(path('admission-request'));
      const admissionGrant = await read(path('admission-grant'));
      if (request.requestedReaderMode === 'handshake') {
        projection = await read(botPath('reader-projection'));
        acknowledgement = await read(botPath('acknowledgement'));
        readerState = await read(botPath('reader-state'));
        const readerFloor = await read(path('reader-version-floor'));
        try {
          validateReaderVersionFloor(readerFloor);
          validateAdmissionGrant(admissionGrant, admissionRequest, Date.now());
          validateReaderProjection(projection, readerFloor, committed, zFinality.zFinalityFingerprint);
          validateAdmissionAck(acknowledgement, admissionGrant, projection.readerProjectionFingerprint);
          validateReaderRelations(readerState, readerFloor);
          if (readerState.readerInstanceId !== request.readerInstanceId ||
              readerState.readerStartNonce !== request.readerStartNonce ||
              readerState.readerProjectionFingerprint !== projection.readerProjectionFingerprint) {
            throw new TypeError('reader state finality relation');
          }
        } catch {
          fail();
        }
        if (projection.genesisTxId !== request.genesisTxId || projection.generation !== request.generation ||
            admissionRequest.genesisTxId !== request.genesisTxId || admissionRequest.generation !== request.generation ||
            acknowledgement.genesisTxId !== request.genesisTxId || acknowledgement.generation !== request.generation ||
            acknowledgement.readerProjectionFingerprint !== projection.readerProjectionFingerprint) fail();
        if (!await exactPrecommitBoundary(request, precommit)) fail();
      } else if (admissionRequest !== null || admissionGrant !== null ||
          await read(botPath('reader-projection')) !== null ||
          await read(botPath('acknowledgement')) !== null ||
          await read(botPath('reader-state')) !== null) {
        fail();
      }
      const proof = {
        version: 1, kind: 'finality-proof', genesisTxId: request.genesisTxId, generation: request.generation,
        zFinalityFingerprint: zFinality.zFinalityFingerprint,
        readerProjectionFingerprint: projection?.readerProjectionFingerprint ?? null, ackFingerprint: acknowledgement?.ackFingerprint ?? null,
        routeFingerprint: acknowledgement?.routeFingerprint ?? 'no-route', finalityProofFingerprint: null,
      };
      proof.finalityProofFingerprint = recordFingerprint(proof, 'finalityProofFingerprint');
      try { validateFinalityProof(proof, request, zFinality, acknowledgement, projection?.readerProjectionFingerprint ?? null); } catch { fail(); }
      await exact('rvf', proof);
      const receipt = {
        version: 1, kind: 'genesis-receipt', genesisTxId: request.genesisTxId, generation: request.generation,
        requestedReaderMode: request.requestedReaderMode, readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce,
        readerProjectionFingerprint: projection?.readerProjectionFingerprint ?? null, ackFingerprint: acknowledgement?.ackFingerprint ?? null,
        finalityProofFingerprint: proof.finalityProofFingerprint, phase: 'terminal', receiptFingerprint: null,
      };
      receipt.receiptFingerprint = recordFingerprint(receipt, 'receiptFingerprint');
      try { validateGenesisReceipt(receipt, request, zFinality, proof); } catch { fail(); }
      await exact('receipt', receipt);
      const value = {
        version: 1, kind: 'genesis-suffix-recovery', txId: request.genesisTxId, requestFingerprint: request.requestFingerprint,
        finalityFingerprint: proof.finalityProofFingerprint, receiptFingerprint: receipt.receiptFingerprint,
        admissionOpen: false, phase: 'terminal', suffixFingerprint: null,
      };
      value.suffixFingerprint = recordFingerprint(value, 'suffixFingerprint');
      await exact('genesis-suffix-recovery', value);
      if (!await exactPrecommitBoundary(request, precommit)) fail();
      return value;
    },
    async publishMapping(value) {
      await requireGenesisProof();
      if (value.refreshReaderFloor === true) {
        const floor = await readerFloor();
        try { validateReaderVersionFloor(value.readerVersionFloor); } catch {
          refused('publish_mapping', 'exact reader version floor is required for envelope refresh');
        }
        if (floor.readerVersionFloor !== 2 || canonical(floor) !== canonical(value.readerVersionFloor)) {
          refused('publish_mapping', 'reader version floor changed before envelope refresh');
        }
        const currentRoot = await read(path('control-root'));
        const currentWrapper = await read(path('managed-v1-wrapper'));
        if (currentRoot?.sourceKind !== 'managed-v1' || !isManagedV1Wrapper(currentWrapper) ||
            currentRoot.wrapperFingerprint !== currentWrapper.wrapperFingerprint) {
          refused('publish_mapping', 'managed envelope predecessor is invalid');
        }
        const target = await targetProof();
        let wrapper = currentWrapper;
        if (wrapper.readerVersion !== 2) {
          wrapper = {
            ...currentWrapper,
            readerVersion: 2,
            wrapperSequence: currentWrapper.wrapperSequence + 1,
            previousWrapperFingerprint: currentWrapper.wrapperFingerprint,
            wrapperFingerprint: null,
          };
          wrapper.wrapperFingerprint = recordFingerprint(wrapper, 'wrapperFingerprint');
          if (!isManagedV1Wrapper(wrapper)) refused('publish_mapping', 'managed wrapper reader-floor successor is invalid');
          await publishEnvelope(wrapper);
        } else if (currentRoot.readerVersionFloorFingerprint !== floor.floorFingerprint) {
          refused('publish_mapping', 'managed envelope reader floor binding is inconsistent');
        }
        const rootProof = await authorityObjectProof(path('control-root'));
        const wrapperProof = await authorityObjectProof(path('managed-v1-wrapper'));
        return {
          targetFingerprint: fingerprint(target.bytes),
          targetIdentityFingerprint: target.targetIdentity,
          targetAclFingerprint: target.targetAclFingerprint,
          controlRootFingerprint: rootProof.value.controlRootFingerprint,
          controlIdentityFingerprint: rootProof.identityFingerprint,
          controlAclFingerprint: rootProof.aclFingerprint,
          wrapperIdentityFingerprint: wrapperProof.identityFingerprint,
          wrapperAclFingerprint: wrapperProof.aclFingerprint,
          wrapperFingerprint: wrapper.wrapperFingerprint,
        };
      }
      if (!value.mappingId) {
        const present = await lowLevel.read_verified_bytes(targetPath);
        if (present === null) {
          const attestation = value.attestation;
          if (!attestationValid(attestation)) refused('publish_mapping', 'exact protected-stream attestation is required');
          await write(targetPath, createGenesisEmptyChannels({ tokenConfigGeneration: attestation.tokenConfigGeneration, tokenConfigHostSetFingerprint: attestation.tokenConfigHostSetFingerprint }));
          if (!(await Promise.all([
            configuredRoles.managementSid,
            configuredRoles.botSid,
            configuredRoles.recoverySid,
          ].map((principal) => lowLevel.principal_access_check(targetPath, roleKind, principal, 'read')))).every((result) => result === true)) {
            refused('publish_mapping', 'new managed target is not readable by M/B/R');
          }
          const target = await targetProof();
          const wrapper = { version: 1, kind: 'managed-v1-wrapper', sourceKind: 'managed-v1', managementStamp: 'gjc-management-envelope/v1', anchorFingerprint: await anchorFingerprint(), targetRelativeName: 'channels.json', targetState: 'genesis-empty', targetIdentity: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint, semanticStateFingerprint: parseCanonicalJsonBytes(target.bytes).configFingerprint, readerVersion: null, dispatchClass: 'workspace-only', routeDisposition: 'no-route', wrapperSequence: 1, previousWrapperFingerprint: null, wrapperFingerprint: null };
          wrapper.wrapperFingerprint = recordFingerprint(wrapper, 'wrapperFingerprint');
          await publishEnvelope(wrapper);
          const rootProof = await authorityObjectProof(path('control-root'));
          const wrapperProof = await authorityObjectProof(path('managed-v1-wrapper'));
          return {
            targetFingerprint: fingerprint(target.bytes),
            targetIdentityFingerprint: target.targetIdentity,
            targetAclFingerprint: target.targetAclFingerprint,
            controlRootFingerprint: rootProof.value.controlRootFingerprint,
            controlIdentityFingerprint: rootProof.identityFingerprint,
            controlAclFingerprint: rootProof.aclFingerprint,
            wrapperIdentityFingerprint: wrapperProof.identityFingerprint,
            wrapperAclFingerprint: wrapperProof.aclFingerprint,
            wrapperFingerprint: wrapper.wrapperFingerprint,
          };
        }
        const expectedLegacyTarget = value.expectedLegacyTarget ?? prospectiveProof?.legacyTargetProof;
        if (!expectedLegacyTarget || canonical(expectedLegacyTarget) !== canonical(prospectiveProof?.legacyTargetProof)) {
          refused('publish_mapping', 'legacy target is not bound to the prospective proof');
        }
        const target = await exactTarget(expectedLegacyTarget);
        const wrapper = { version: 1, kind: 'legacy-retained-wrapper', sourceKind: 'legacy-retained', managementStamp: 'gjc-management-envelope/v1', anchorFingerprint: await anchorFingerprint(), targetRelativeName: 'channels.json', targetState: 'legacy-unmigrated', rawTargetByteFingerprint: fingerprint(target.bytes), rawTargetByteLength: target.bytes.length, targetIdentity: target.targetIdentity, targetAclFingerprint: target.targetAclFingerprint, readerVersion: null, legacyRetention: 'exact', dispatchClass: 'workspace-only', routeDisposition: 'no-route', retentionTxId: value.request?.genesisTxId, retentionSequence: 1, previousWrapperFingerprint: null, wrapperFingerprint: null };
        wrapper.wrapperFingerprint = recordFingerprint(wrapper, 'wrapperFingerprint');
        await publishEnvelope(wrapper);
        await exactTarget(expectedLegacyTarget);
        const rootProof = await authorityObjectProof(path('control-root'));
        const wrapperProof = await authorityObjectProof(path('legacy-retained'));
        return {
          targetFingerprint: fingerprint(target.bytes),
          targetIdentityFingerprint: target.targetIdentity,
          targetAclFingerprint: target.targetAclFingerprint,
          controlRootFingerprint: rootProof.value.controlRootFingerprint,
          controlIdentityFingerprint: rootProof.identityFingerprint,
          controlAclFingerprint: rootProof.aclFingerprint,
          wrapperIdentityFingerprint: wrapperProof.identityFingerprint,
          wrapperAclFingerprint: wrapperProof.aclFingerprint,
          wrapperFingerprint: wrapper.wrapperFingerprint,
        };
      }
      const snapshot = value.snapshot;
      try { validateManagementSnapshot(snapshot); } catch { refused('publish_mapping', 'exact workspace-only managed channels v2 snapshot is required'); }
      const state = await read(path('management-state'));
      if (!state || state.revision !== value.expectedRevision) refused('publish_mapping', 'management revision CAS failed');
      const prior = await lowLevel.read_verified_bytes(targetPath);
      if (prior === null) refused('publish_mapping', 'managed target is absent');
      try { validateManagementSnapshot(parseCanonicalJsonBytes(Buffer.from(prior))); } catch { refused('publish_mapping', 'legacy target bytes are immutable'); }
      await publishManagedSnapshot(snapshot);
      const routes = Object.values(snapshot.routes).filter((route) => route.mappingId === value.mappingId);
      await writeAuthority(`mapping-${encodeURIComponent(value.mappingId)}`, { mapping: snapshot.mappings[value.mappingId], routes, mappingFingerprint: snapshot.mappings[value.mappingId]?.mappingFingerprint });
    },
    async rotateTokenSidecar(record) {
      if (!hex(record?.hostSetFingerprint) ||
          !Number.isSafeInteger(record.generation) || record.generation < 1 ||
          !Number.isSafeInteger(record.revision) || record.revision < 0 ||
          !Number.isSafeInteger(record.authorityEpoch) || record.authorityEpoch < 1 ||
          !Number.isSafeInteger(record.mappingGeneration) || record.mappingGeneration < 0) {
        refused('rotate_token_sidecar', 'attested host-set generation and exact successor counters are required');
      }
      const controlRoot = await read(path('control-root'));
      if (controlRoot?.sourceKind === 'managed-v1') {
        const current = await read(targetPath);
        try { validateManagementSnapshot(current); } catch { refused('rotate_token_sidecar', 'managed target is invalid'); }
        if (record.revision <= current.revision ||
            record.authorityEpoch <= current.authorityEpoch ||
            record.mappingGeneration !== current.mappingGeneration) {
          refused('rotate_token_sidecar', 'token rotation successor counters are invalid');
        }
        const snapshot = {
          ...current,
          revision: record.revision,
          authorityEpoch: record.authorityEpoch,
          mappingGeneration: record.mappingGeneration,
          targetState: current.targetState === 'genesis-empty' ? 'managed-empty' : current.targetState,
          tokenConfigGeneration: record.generation,
          tokenConfigHostSetFingerprint: record.hostSetFingerprint,
          configFingerprint: null,
        };
        snapshot.configFingerprint = recordFingerprint(snapshot, 'configFingerprint');
        await publishManagedSnapshot(snapshot);
      }
      await writeAuthority('token-sidecar', record);
    },
    async terminalCloseOrManualCleanup(value) { const record = await manualCleanupRecord(value); await writeAuthority('terminal-close', record, false); return { phase: 'manual_cleanup', routeDisposition: 'no-route', manualCleanupFingerprint: record.manualCleanupFingerprint }; },
    async recoverManagementState(recovery) {
      const existing = await read(path('terminal-close'));
      if (existing) {
        try { validateManualCleanup(existing); return { ...(recovery ?? {}), phase: 'manual_cleanup', routeDisposition: 'no-route', manualCleanupFingerprint: existing.manualCleanupFingerprint }; } catch { refused('recover_management_state', 'manual-cleanup record is torn or invalid'); }
      }
      const manual = async (reason) => {
        const record = await manualCleanupRecord({ recovery, reason });
        await writeAuthority('terminal-close', record, false);
        return { ...(recovery ?? {}), phase: 'manual_cleanup', routeDisposition: 'no-route', manualCleanupFingerprint: record.manualCleanupFingerprint };
      };
      const txId = recovery?.records?.transaction?.txId;
      if (!txId) return manual('RECOVERY_INCOMPLETE');
      const suffix = encodeURIComponent(txId);
      const load = async (phase) => {
        const [transaction, publication, backup, checkpoint] = await Promise.all(['tx', 'pub', 'bk', 'rc'].map((kind) => read(path(`mapping-recovery-${kind}-${phase}-${suffix}`))));
        const records = { transaction, publication, backup, checkpoint };
        try { validateMappingRecoveryRecords(records); } catch { return null; }
        return records;
      };
      const committed = await load('committed');
      const replaced = await load('replaced');
      const prepared = await load('prepared');
      const records = committed ?? replaced ?? prepared;
      if (!records || canonical(records.transaction) !== canonical(recovery.records.transaction)) return manual('RECOVERY_RECORD_MISMATCH');
      const live = await this.mappingTargetProof();
      const candidateMatches = live.snapshotFingerprint === records.transaction.candidateSnapshot.configFingerprint &&
        (records.publication.phase === 'prepared' || (live.identityFingerprint === records.publication.targetIdentityFingerprint && live.aclFingerprint === records.publication.targetAclFingerprint));
      const oldMatches = live.snapshotFingerprint === records.transaction.oldSnapshot.configFingerprint &&
        live.identityFingerprint === records.backup.backupIdentityFingerprint && live.aclFingerprint === records.backup.backupAclFingerprint;
      if (committed && candidateMatches) return { phase: 'terminal', routeDisposition: 'no-route', records: committed };
      if (replaced && candidateMatches) {
        const next = buildMappingRecoveryRecords({
          tx: replaced.transaction, phase: 'committed',
          targetSnapshotFingerprint: live.snapshotFingerprint, targetIdentityFingerprint: live.identityFingerprint, targetAclFingerprint: live.aclFingerprint,
          backupIdentityFingerprint: replaced.backup.backupIdentityFingerprint, backupAclFingerprint: replaced.backup.backupAclFingerprint,
        });
        await this.writeMappingRecovery(next);
        return { phase: 'terminal', routeDisposition: 'no-route', records: next };
      }
      if (prepared && oldMatches) return { phase: 'terminal', routeDisposition: 'no-route', records: prepared, recoveredOldSnapshot: true };
      return manual('RECOVERY_PROOF_MISMATCH');
    },
    async revokeMapping({ mappingId, expectedFingerprint, expectedRevision, snapshot }) {
      try { validateManagementSnapshot(snapshot); } catch { refused('revoke_mapping', 'exact workspace-only managed channels v2 snapshot is required'); }
      const state = await read(path('management-state'));
      if (!state || state.revision !== expectedRevision || state.admission?.phase !== 'closed') refused('revoke_mapping', 'management revision or admission closure CAS failed');
      const prior = await lowLevel.read_verified_bytes(targetPath);
      if (prior === null) refused('revoke_mapping', 'managed target is absent');
      try { validateManagementSnapshot(parseCanonicalJsonBytes(Buffer.from(prior))); } catch { refused('revoke_mapping', 'legacy target bytes are immutable'); }
      await publishManagedSnapshot(snapshot);
      await writeAuthority(`mapping-revocation-${encodeURIComponent(mappingId)}`, { mappingId, expectedFingerprint, snapshotFingerprint: snapshot.configFingerprint, revoked: true });
    },
    async reopenAdmission({ txId, finalityFingerprint }) {
      const request = await read(path('genesis-request'));
      const zFinality = await read(path('z-finality'));
      const projection = await read(botPath('reader-projection'));
      const acknowledgement = await read(botPath('acknowledgement'));
      const proof = await read(path('rvf'));
      const receipt = await read(path('receipt'));
      const state = await read(path('management-state'));
      try {
        validateGenesisRequest(request);
        if (!zFinality || zFinality.kind !== 'genesis-finality') throw new Error('invalid finality');
        validateFinalityProof(
          proof,
          request,
          zFinality,
          acknowledgement,
          projection?.readerProjectionFingerprint ?? null,
        );
        validateGenesisReceipt(receipt, request, zFinality, proof);
      } catch {
        refused('reopen_admission', 'exact committed finality proof is required');
      }
      if (request.genesisTxId !== txId ||
          proof.finalityProofFingerprint !== finalityFingerprint ||
          receipt.finalityProofFingerprint !== finalityFingerprint ||
          state?.admission?.phase !== 'closed') {
        refused('reopen_admission', 'closed admission state does not match finality');
      }
      // Issue #44 proves authority only; native serving remains deliberately closed.
      return false;
    },
    async appendAudit(entry) {
      const audit = await read(path('audit')) ?? [];
      if (!Array.isArray(audit) || audit.length > 10000) refused('append_audit', 'control audit is invalid or requires owner archival');
      let previousHash = null;
      for (const existing of audit) {
        if (!existing || existing.previousHash !== previousHash || existing.entryHash !== fingerprint(encode(Object.fromEntries(Object.entries(existing).filter(([key]) => key !== 'entryHash'))))) {
          refused('append_audit', 'control audit chain is invalid');
        }
        previousHash = existing.entryHash;
      }
      const unsigned = { version: 1, at: new Date().toISOString(), ...entry, previousHash };
      const record = { ...unsigned, entryHash: fingerprint(encode(unsigned)) };
      const next = [...audit, record];
      if (encode(next).length > 8 * 1024 * 1024) refused('append_audit', 'control audit requires owner archival');
      await writeAuthority('audit', next);
      return record.entryHash;
    },
    async readManagedMappingSnapshot() {
      if (!await hasPublishedAuthority()) {
        const managementMarkerPresent =
          await lowLevel.path_exists_no_follow(root) ||
          await lowLevel.path_exists_no_follow(bootstrapBlockerPath);
        return {
          controlRootAbsent: !managementMarkerPresent,
          managementMarkerPresent,
          bootstrapBlockerPresent: await lowLevel.path_exists_no_follow(bootstrapBlockerPath),
          managementState: await read(path('management-state')),
        };
      }
      await requireAuthorityRequest('read_managed_mapping_snapshot');
      await requireBotPrincipal('read_managed_mapping_snapshot');
      const rootRecord = await verifiedBytes(path('control-root'));
      const rootValue = parseCanonicalJsonBytes(rootRecord.bytes);
      const wrapper = await verifiedBytes(join(root, rootValue.wrapperRelativeName));
      const target = await targetProof({ sourceKind: rootValue.sourceKind });
      const terminalCloseBefore = await lowLevel.read_verified_bytes(path('terminal-close'));
      if (terminalCloseBefore !== null) {
        await assertObject(path('terminal-close'), Buffer.from(terminalCloseBefore));
        refused('read_managed_mapping_snapshot', 'terminal cleanup state is active');
      }
      const historyMarker = await rawRead(historyMarkerPath);
      if (historyMarker !== null) validateHistoryMarker(historyMarker);
      const headBefore = await read(path('authority-head'));
      if (headBefore !== null) {
        try { validateAuthoritySuccessorHead(headBefore); } catch { refused('read_managed_mapping_snapshot', 'successor authority head is invalid'); }
        const tx = encodeURIComponent(headBefore.txId);
        const bundle = {
          request: await read(path(`authority-successor-request-${tx}`)),
          close: await read(path(`authority-close-proof-${tx}`)),
          fence: await read(path(`authority-successor-fence-${tx}`)),
          baseline: await read(path(`authority-successor-baseline-${tx}`)),
          commit: await read(path(`authority-commit-${tx}`)),
          publicationK: await read(path(`publication-k-${tx}`)),
          publicationY: await read(path(`publication-y-${tx}`)),
          finality: await read(path(`authority-successor-finality-${tx}`)),
          lease: await read(botPath(`successor-lease-${tx}`)),
          projection: await read(botPath(`successor-reader-projection-${tx}`)),
          ack: await read(botPath(`successor-ack-${tx}`)),
          receipt: await read(path(`authority-successor-receipt-${tx}`)),
          historyMarker,
          head: headBefore,
        };
        try { validateAuthoritySuccessorBundle(bundle); } catch { refused('read_managed_mapping_snapshot', 'successor authority bundle is torn or substituted'); }
        const headAfter = await read(path('authority-head'));
        if (!headAfter || headAfter.headFingerprint !== headBefore.headFingerprint) refused('read_managed_mapping_snapshot', 'successor authority head changed during read');
        return {
          bootstrapBlockerPresent: await lowLevel.path_exists_no_follow(bootstrapBlockerPath),
          controlRootName: 'control-root.json',
          wrapperName: rootValue.wrapperRelativeName,
          controlRootBytes: rootRecord.bytes,
          wrapperBytes: wrapper.bytes,
          targetBytes: target.bytes,
          targetIdentity: target.targetIdentity,
          targetAclFingerprint: target.targetAclFingerprint,
          successorBundle: bundle,
          nativeVerified: true,
        };
      }
      if (historyMarker?.sequence > 1) refused('read_managed_mapping_snapshot', 'successor history exists without an authority head');
      const request = await verifiedBytes(path('genesis-request'));
      const requestValue = parseCanonicalJsonBytes(request.bytes);
      const attestation = await verifiedBytes(path(`attestation-${encodeURIComponent(requestValue.genesisTxId)}`));
      const tokenFloor = await verifiedBytes(path(`token-floor-commit-${encodeURIComponent(requestValue.genesisTxId)}`));
      const currentAttestation = await verifiedBytes(path('attestation'));
      const currentTokenFloor = await verifiedBytes(path('token-floor'));
      const attestationHistory = await verifiedBytes(path('attestation-history'));
      const tokenFloorHistory = await verifiedBytes(path('token-floor-history'));
      const reservation = await verifiedBytes(path(`token-floor-reservation-${encodeURIComponent(requestValue.genesisTxId)}`));
      const attestedProof = await verifiedBytes(path(`token-floor-attested-${encodeURIComponent(requestValue.genesisTxId)}`));
      const precommit = await verifiedBytes(path(`genesis-precommit-proof-${encodeURIComponent(requestValue.genesisTxId)}`));
      const authorityRequest = await verifiedBytes(path('genesis-authority-request'));
      const authorityReceipt = await verifiedBytes(path('genesis-authority-receipt'));
      const authorityReservation = await verifiedBytes(path(`authority-reservation-${encodeURIComponent(requestValue.genesisTxId)}`));
      const authorityCommit = await verifiedBytes(path(`authority-commit-${encodeURIComponent(requestValue.genesisTxId)}`));
      const authorityBaseline = await verifiedBytes(path(`authority-baseline-${encodeURIComponent(requestValue.genesisTxId)}`));
      const authorityEpoch = await verifiedBytes(path('authority-epoch'));
      const publication = await readPublicationGraph(requestValue.genesisTxId);
      const admissionRequest = await lowLevel.read_verified_bytes(path('admission-request'));
      const admissionGrant = await lowLevel.read_verified_bytes(path('admission-grant'));
      if (admissionRequest !== null) await assertObject(path('admission-request'), Buffer.from(admissionRequest));
      if (admissionGrant !== null) await assertObject(path('admission-grant'), Buffer.from(admissionGrant));
      const managementState = await read(path('management-state'));
      const terminalClose = await lowLevel.read_verified_bytes(path('terminal-close'));
      if (terminalClose !== null) await assertObject(path('terminal-close'), Buffer.from(terminalClose));
      const readerVersionFloor = await verifiedBytes(path('reader-version-floor'));
      const zFinality = await verifiedBytes(path('z-finality'));
      const fenceBinding = await lowLevel.read_verified_bytes(path('reader-fence-binding'));
      if (fenceBinding !== null) await assertObject(path('reader-fence-binding'), Buffer.from(fenceBinding));
      const readerLease = await lowLevel.read_verified_bytes(botPath('lease'));
      if (readerLease !== null) await assertObject(botPath('lease'), Buffer.from(readerLease));
      const readerProjection = await lowLevel.read_verified_bytes(botPath('reader-projection'));
      if (readerProjection !== null) await assertObject(botPath('reader-projection'), Buffer.from(readerProjection));
      const admissionAck = await lowLevel.read_verified_bytes(botPath('acknowledgement'));
      if (admissionAck !== null) await assertObject(botPath('acknowledgement'), Buffer.from(admissionAck));
      const readerState = await lowLevel.read_verified_bytes(botPath('reader-state'));
      if (requestValue.requestedReaderMode === 'handshake') {
        if (readerState === null) refused('read_managed_mapping_snapshot', 'bound reader state is absent');
        await assertObject(botPath('reader-state'), Buffer.from(readerState));
      } else if (readerState !== null) {
        refused('read_managed_mapping_snapshot', 'no-reader authority contains reader state');
      }
      const rvfBytes = await lowLevel.read_verified_bytes(path('rvf'));
      const receiptBytes = await lowLevel.read_verified_bytes(path('receipt'));
      if (rvfBytes === null || receiptBytes === null) {
        if (requestValue.requestedReaderMode === 'handshake' &&
            managementState?.recovery?.phase === 'handshake-pending') {
          pendingHandshake();
        }
        refused('read_managed_mapping_snapshot', 'terminal finality proof or receipt is absent');
      }
      const rvf = await verifiedBytes(path('rvf'));
      const receipt = await verifiedBytes(path('receipt'));
      let finalityGraph;
      try {
        finalityGraph = await validateStoredFinalityGraph(parseCanonicalJsonBytes(rvf.bytes));
        validateGenesisReceipt(parseCanonicalJsonBytes(receipt.bytes), finalityGraph.request, finalityGraph.zFinality, finalityGraph.proof);
      } catch {
        refused('read_managed_mapping_snapshot', 'bound finality, receipt, or reader state is invalid');
      }
      const botOsIdentity = await lowLevel.current_os_principal();
      const botStateAcl = await lowLevel.read_acl(botRoot);
      if (!configuredRoles || !botOsIdentity?.value || !botStateAcl) refused('read_managed_mapping_snapshot', 'bot identity evidence is unavailable');
      return {
        bootstrapBlockerPresent: await lowLevel.path_exists_no_follow(bootstrapBlockerPath),
        controlRootName: 'control-root.json', wrapperName: rootValue.wrapperRelativeName,
        controlRootBytes: rootRecord.bytes, wrapperBytes: wrapper.bytes,
        targetBytes: target.bytes, targetIdentity: target.targetIdentity,
        targetAclFingerprint: target.targetAclFingerprint,
        attestationBytes: attestation.bytes, tokenFloorBytes: tokenFloor.bytes,
        currentAttestationBytes: currentAttestation.bytes, currentTokenFloorBytes: currentTokenFloor.bytes,
        attestationHistoryBytes: attestationHistory.bytes, tokenFloorHistoryBytes: tokenFloorHistory.bytes,
        attestedProofBytes: attestedProof.bytes, precommitBytes: precommit.bytes,
        tokenFloorReservationBytes: reservation.bytes, readerVersionFloorBytes: readerVersionFloor.bytes,
        genesisRequestBytes: request.bytes, zFinalityBytes: zFinality.bytes,
        rvfBytes: rvf.bytes, receiptBytes: receipt.bytes,
        authorityRequestBytes: authorityRequest.bytes, authorityReceiptBytes: authorityReceipt.bytes,
        authorityReservationBytes: authorityReservation.bytes, authorityCommitBytes: authorityCommit.bytes,
        authorityBaselineBytes: authorityBaseline.bytes, authorityEpochBytes: authorityEpoch.bytes,
        publicationTransactionBytes: encode(publication.transaction), publicationUBytes: encode(publication.u),
        publicationPBytes: encode(publication.p), publicationSBytes: encode(publication.s),
        publicationPreparedBytes: encode(publication.prepared), publicationReplacedBytes: encode(publication.replaced),
        publicationCommittedBytes: encode(publication.committed), publicationCBytes: encode(publication.c),
        publicationQBytes: encode(publication.q), publicationZpBytes: encode(publication.zp),
        publicationKBytes: encode(publication.k), publicationYBytes: encode(publication.y),
        admissionRequestBytes: admissionRequest === null ? undefined : Buffer.from(admissionRequest),
        admissionGrantBytes: admissionGrant === null ? undefined : Buffer.from(admissionGrant),
        fenceBindingBytes: fenceBinding === null ? undefined : Buffer.from(fenceBinding),
        readerLeaseBytes: readerLease === null ? undefined : Buffer.from(readerLease),
        readerProjectionBytes: readerProjection === null ? undefined : Buffer.from(readerProjection),
        readerStateBytes: readerState === null ? undefined : Buffer.from(readerState),
        admissionAckBytes: admissionAck === null ? undefined : Buffer.from(admissionAck),
        manualCleanupBytes: terminalClose === null ? undefined : Buffer.from(terminalClose),
        terminalCloseBytes: terminalClose === null ? null : Buffer.from(terminalClose),
        recoveryBytes: managementState?.recovery && managementState.recovery.phase !== 'terminal'
          ? encode(managementState.recovery)
          : undefined,
        botPrincipal: configuredRoles.botSid, botOsPrincipal: botOsIdentity.value,
        botStateAclFingerprint: fingerprint(Buffer.from(String(botStateAcl))), nativeVerified: true,
      };
    },
    async writeBotReaderProjection(value) {
      await requireBotPrincipal('write_bot_reader_projection');
      const floor = await read(path('reader-version-floor'));
      const tokenFloor = await read(path('token-floor'));
      const zFinality = await read(path('z-finality'));
      const request = await read(path('genesis-request'));
      if (!await hasPublishedAuthority() || !floor || floor.readerVersionFloor !== 2 ||
          !tokenFloor || tokenFloor.lastCommittedTxId === null || !zFinality || !request) {
        refused('write_bot_reader_projection', 'validated committed handshake is absent');
      }
      try {
        validateReaderProjection(value, floor, tokenFloor, zFinality.zFinalityFingerprint);
      } catch {
        refused('write_bot_reader_projection', 'exact bound reader projection is required');
      }
      if (value.genesisTxId !== request.genesisTxId || value.generation !== request.generation ||
          value.readerInstanceId !== request.readerInstanceId ||
          value.readerStartNonce !== request.readerStartNonce) {
        refused('write_bot_reader_projection', 'reader projection does not bind the pending request');
      }
      await ensureBotRoot();
      await write(botPath('reader-projection'), value, 'bot-state');
      return value;
    },
    async writeBotReaderState(value) {
      await requireBotPrincipal('write_bot_reader_state');
      const floor = await read(path('reader-version-floor'));
      const tokenFloor = await read(path('token-floor'));
      const request = await read(path('genesis-request'));
      const attestation = await read(path('attestation'));
      const reservation = request && await read(path(`token-floor-reservation-${encodeURIComponent(request.genesisTxId)}`));
      const commit = request && await read(path(`authority-commit-${encodeURIComponent(request.genesisTxId)}`));
      const fence = await read(path('reader-fence-binding'));
      const lease = await read(botPath('lease'));
      const projection = await read(botPath('reader-projection'));
      const zFinality = await read(path('z-finality'));
      if (!await hasPublishedAuthority() || !floor || floor.readerVersionFloor !== 2 ||
          !tokenFloor || tokenFloor.floorPhase !== 'committed' || !request || !attestation ||
          !reservation || !commit || !fence || !lease || !projection || !zFinality) {
        refused('write_bot_reader_state', 'validated committed handshake graph is absent');
      }
      try {
        validateReaderRelations(value, floor);
        validateTokenConfigAttestation(attestation);
        validateTokenFloorReservation(reservation);
        validateFenceBinding(fence, commit, floor);
        validateLeaseBinding(lease, fence);
        validateReaderProjection(projection, floor, tokenFloor, zFinality.zFinalityFingerprint);
      } catch {
        refused('write_bot_reader_state', 'exact reader-state graph is invalid');
      }
      if (value.attestationFingerprint !== attestation.attestationFingerprint ||
          value.authorityReservationFingerprint !== commit.reservationFingerprint ||
          value.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint ||
          value.fenceBindingFingerprint !== fence.fenceBindingFingerprint ||
          value.leaseBindingFingerprint !== lease.leaseBindingFingerprint ||
          value.readerProjectionFingerprint !== projection.readerProjectionFingerprint ||
          value.readerInstanceId !== request.readerInstanceId ||
          value.readerStartNonce !== request.readerStartNonce) {
        refused('write_bot_reader_state', 'reader-state relation is invalid');
      }
      await ensureBotRoot();
      await write(botPath('reader-state'), value, 'bot-state');
      return value;
    },
    async acquireBotLease(value) {
      await requireBotPrincipal('acquire_bot_lease');
      const floor = await read(path('reader-version-floor'));
      const fence = await read(path('reader-fence-binding'));
      try {
        validateReaderVersionFloor(floor);
        validateLeaseBinding(value, fence);
      } catch {
        refused('acquire_bot_lease', 'exact bound reader lease is required');
      }
      if (floor.readerVersionFloor !== 2 || value.readerInstanceId !== floor.firstReaderInstanceId ||
          value.readerStartNonce !== floor.firstReaderStartNonce) {
        refused('acquire_bot_lease', 'lease does not bind the irreversible reader floor');
      }
      await ensureBotRoot();
      await write(botPath('lease'), value, 'bot-state');
      return value;
    },
    async writeBotAcknowledgement(value) {
      await requireBotPrincipal('write_bot_acknowledgement');
      const floor = await read(path('reader-version-floor'));
      if (!floor || floor.readerVersionFloor !== 2) {
        refused('write_bot_acknowledgement', 'validated committed handshake is absent');
      }
      const request = await read(path('admission-request'));
      const grant = await read(path('admission-grant'));
      const projection = await read(botPath('reader-projection'));
      try {
        validateAdmissionGrant(grant, request, Date.now());
        validateAdmissionAck(value, grant, projection?.readerProjectionFingerprint);
      } catch {
        refused('write_bot_acknowledgement', 'exact bound acknowledgement is required');
      }
      if (!projection || value.grantFingerprint !== grant.grantFingerprint ||
          value.grantId !== grant.grantId ||
          value.readerProjectionFingerprint !== projection.readerProjectionFingerprint) {
        refused('write_bot_acknowledgement', 'acknowledgement does not bind the exact grant and projection');
      }
      await ensureBotRoot();
      await write(botPath('acknowledgement'), value, 'bot-state');
      return value;
    },
    async writeAuthoritySuccessorRequest(value) {
      await requireManagementPrincipal('write_authority_successor_request');
      try { validateAuthoritySuccessorRequest(value); } catch { refused('write_authority_successor_request', 'exact successor request is required'); }
      const head = await read(path('authority-head'));
      const marker = await rawRead(historyMarkerPath);
      if (head === null) {
        if (!marker || marker.sequence + 1 !== value.sequence) refused('write_authority_successor_request', 'successor request does not follow durable history');
      } else {
        try { validateAuthoritySuccessorHead(head); } catch { refused('write_authority_successor_request', 'current successor head is invalid'); }
        if (head.phase !== 'terminal' || value.sequence !== head.sequence + 1 ||
            value.previousReceiptFingerprint !== head.receiptFingerprint) {
          refused('write_authority_successor_request', 'successor request does not follow the terminal head');
        }
      }
      const name = `authority-successor-request-${encodeURIComponent(value.txId)}`;
      const existing = await read(path(name));
      if (existing !== null) {
        if (canonical(existing) !== canonical(value)) refused('write_authority_successor_request', 'successor request replay conflicts');
        return existing;
      }
      await writeCreateOnceAuthority(name, value);
      return value;
    },
    async readBotAuthoritySuccessorLiveProof({ txId } = {}) {
      await requireBotPrincipal('read_bot_authority_successor_live_proof');
      if (typeof txId !== 'string' || txId.length === 0) refused('read_bot_authority_successor_live_proof', 'successor transaction is required');
      const encodedTxId = encodeURIComponent(txId);
      const head = await verifiedBytes(path('authority-head'));
      const finality = await verifiedBytes(path(`authority-successor-finality-${encodedTxId}`));
      const attestation = await verifiedBytes(path('attestation'));
      const tokenFloor = await verifiedBytes(path('token-floor'));
      const attestationHistory = await verifiedBytes(path('attestation-history'));
      const tokenFloorHistory = await verifiedBytes(path('token-floor-history'));
      const controlRoot = await verifiedBytes(path('control-root'));
      const controlValue = parseCanonicalJsonBytes(controlRoot.bytes);
      const wrapper = await verifiedBytes(join(root, controlValue.wrapperRelativeName));
      const wrapperValue = parseCanonicalJsonBytes(wrapper.bytes);
      const target = await targetProof({ sourceKind: controlValue.sourceKind });
      const headValue = parseCanonicalJsonBytes(head.bytes);
      const finalityValue = parseCanonicalJsonBytes(finality.bytes);
      const attestationValue = parseCanonicalJsonBytes(attestation.bytes);
      const floorValue = parseCanonicalJsonBytes(tokenFloor.bytes);
      const attestationHistoryValue = parseCanonicalJsonBytes(attestationHistory.bytes);
      const floorHistoryValue = parseCanonicalJsonBytes(tokenFloorHistory.bytes);
      const publication = await readPublicationGraph(txId);
      try {
        validateAuthoritySuccessorHead(headValue);
        validateAuthoritySuccessorFinality(finalityValue);
        validateTokenConfigAttestation(attestationValue);
        validateTokenFloor(floorValue);
        if (!Array.isArray(attestationHistoryValue) || !Array.isArray(floorHistoryValue)) throw new TypeError('token histories');
        for (const [index, entry] of attestationHistoryValue.entries()) {
          validateTokenConfigAttestation(entry);
          if (index && entry.previousAttestationFingerprint !== attestationHistoryValue[index - 1].attestationFingerprint) throw new TypeError('attestation lineage');
        }
        for (const [index, entry] of floorHistoryValue.entries()) {
          validateTokenFloor(entry);
          if (index && entry.highestCommittedGeneration !== floorHistoryValue[index - 1].highestCommittedGeneration + 1) throw new TypeError('floor lineage');
        }
        validatePublicationGraph(publication);
        if (publication.k['publication-kFingerprint'] !== finalityValue.publicationKFingerprint ||
            publication.y['publication-yFingerprint'] !== finalityValue.publicationYFingerprint ||
            controlValue.wrapperRelativeName !== basename(controlValue.wrapperRelativeName) ||
            !controlValue.wrapperRelativeName.endsWith('.json') ||
            controlValue.controlRootRelativeName !== '.gjc-remote-control' ||
            controlValue.targetRelativeName !== 'channels.json') throw new TypeError('control root');
        if (controlValue.sourceKind === 'managed-v1' &&
            validateManagementSnapshot(parseCanonicalJsonBytes(target.bytes)).tokenConfigHostSetFingerprint !== attestationValue.tokenConfigHostSetFingerprint) throw new TypeError('host set');
      } catch {
        refused('read_bot_authority_successor_live_proof', 'live successor authority is invalid');
      }
      if (headValue.txId !== txId || headValue.phase !== 'reader-pending' ||
          headValue.finalityFingerprint !== finalityValue.finalityFingerprint ||
          canonical(attestationHistoryValue.at(-1)) !== canonical(attestationValue) ||
          canonical(floorHistoryValue.at(-1)) !== canonical(floorValue) ||
          attestationValue.tokenConfigGeneration !== floorValue.highestCommittedGeneration ||
          attestationValue.attestationFingerprint !== floorValue.lastAttestationFingerprint ||
          finalityValue.attestationFingerprint !== attestationValue.attestationFingerprint ||
          finalityValue.tokenFloorFingerprint !== floorValue.floorFingerprint ||
          finalityValue.targetFingerprint !== fingerprint(target.bytes) ||
          finalityValue.targetIdentityFingerprint !== target.targetIdentity ||
          finalityValue.targetAclFingerprint !== target.targetAclFingerprint ||
          finalityValue.wrapperFingerprint !== wrapperValue.wrapperFingerprint ||
          finalityValue.controlRootFingerprint !== controlValue.controlRootFingerprint) {
        refused('read_bot_authority_successor_live_proof', 'live successor proof relation is invalid');
      }
      const terminalHead = await verifiedBytes(path('authority-head'));
      if (!terminalHead.bytes.equals(head.bytes) ||
          !sameIdentity(terminalHead.identity, head.identity) ||
          terminalHead.acl !== head.acl) {
        refused('read_bot_authority_successor_live_proof', 'terminal successor head drifted');
      }
      return {
        sourceKind: controlValue.sourceKind,
        headBytes: head.bytes,
        finalityBytes: finality.bytes,
        attestationBytes: attestation.bytes,
        tokenFloorBytes: tokenFloor.bytes,
        attestationHistoryBytes: attestationHistory.bytes,
        tokenFloorHistoryBytes: tokenFloorHistory.bytes,
        controlRootBytes: controlRoot.bytes,
        wrapperBytes: wrapper.bytes,
        targetBytes: target.bytes,
        targetIdentity: target.targetIdentity,
        targetAclFingerprint: target.targetAclFingerprint,
      };
    },
    async readSuccessorTokenLineage() {
      await requireManagementPrincipal('read_successor_token_lineage');
      const [floor, attestation] = await Promise.all([read(path('token-floor')), read(path('attestation'))]);
      try { validateTokenFloor(floor); validateTokenConfigAttestation(attestation); } catch { refused('read_successor_token_lineage', 'committed token lineage is invalid'); }
      return { floor, attestation };
    },
    async writeSuccessorPublicationGraph(records) {
      await requireManagementPrincipal('write_successor_publication_graph');
      const { transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y } = records ?? {};
      const txId = encodeURIComponent(transaction?.txId ?? '');
      const [baseline, request, close, fence] = await Promise.all([
        read(path(`authority-successor-baseline-${txId}`)),
        read(path(`authority-successor-request-${txId}`)),
        read(path(`authority-close-proof-${txId}`)),
        read(path(`authority-successor-fence-${txId}`)),
      ]);
      try {
        validateAuthoritySuccessorRequest(request);
        validateAuthorityCloseProof(close, request);
        if (fence !== null) validateAuthoritySuccessorFence(fence, request);
        validateAuthoritySuccessorBaseline(baseline, request, close, fence);
        validatePublicationTransaction(transaction, baseline.baselineFingerprint);
        validatePublicationU(u, baseline.baselineFingerprint);
        validatePublicationP(p, u, p.stateFingerprint);
        validatePublicationS(s, p, { stateFingerprint: s.stateFingerprint, payloadFingerprint: s.payloadFingerprint });
        validatePublicationC(c, s, { stateFingerprint: c.stateFingerprint, payloadFingerprint: c.payloadFingerprint, snapshotFingerprint: c.snapshotFingerprint });
        validatePublicationQ(q, c, { stateFingerprint: q.stateFingerprint, payloadFingerprint: q.payloadFingerprint, snapshotFingerprint: q.snapshotFingerprint });
        validatePublicationZp(zp, q, { stateFingerprint: zp.stateFingerprint, payloadFingerprint: zp.payloadFingerprint, snapshotFingerprint: zp.snapshotFingerprint, publicationFingerprint: zp.publicationFingerprint });
        validatePublicationK(k, zp, { publicationFingerprint: k.publicationFingerprint, checkpointFingerprint: k.checkpointFingerprint });
        validatePublicationY(y, k, y.targetFingerprint, y.publicationFingerprint);
        for (const value of [prepared, replaced, committed]) validatePublicationState(value, transaction);
      } catch {
        refused('write_successor_publication_graph', 'exact successor publication graph is required');
      }
      for (const [name, value] of Object.entries({ 'publication-transaction': transaction, 'publication-u': u, 'publication-p': p, 'publication-s': s, 'publication-state-prepared': prepared, 'publication-state-replaced': replaced, 'publication-state-committed': committed, 'publication-c': c, 'publication-q': q, 'publication-zp': zp, 'publication-k': k, 'publication-y': y })) {
        await writeCreateOnceAuthority(`${name}-${encodeURIComponent(transaction.txId)}`, value);
      }
      return records;
    },
    async commitAuthoritySuccessorEpoch(record) {
      await requireManagementPrincipal('commit_authority_successor_epoch');
      try { validateAuthorityEpoch(record); } catch { refused('commit_authority_successor_epoch', 'exact committed successor epoch is required'); }
      if (record.commitTxId !== record.reservationTxId) refused('commit_authority_successor_epoch', 'successor epoch commit transaction is invalid');
      await writeCreateOnceAuthority(`authority-epoch-${record.epoch}-committed`, record);
      await writeAuthority('authority-epoch', record);
      return record;
    },
    async writeAuthoritySuccessorHead(value) {
      await requireManagementPrincipal('write_authority_successor_head');
      const request = await read(path(`authority-successor-request-${encodeURIComponent(value?.txId ?? '')}`));
      const current = await read(path('authority-head'));
      if (current !== null && canonical(current) === canonical(value)) {
        try { validateAuthoritySuccessorHead(current, request); } catch { refused('write_authority_successor_head', 'current successor head is invalid'); }
        return current;
      }
      try { validateAuthoritySuccessorHeadTransition(current, value, request); } catch { refused('write_authority_successor_head', 'exact successor head transition is required'); }
      const order = ["reserved", "closed", "replaced", "reader-pending", "terminal"];
      const phase = order.indexOf(value.phase);
      const tx = encodeURIComponent(value.txId);
      const close = phase >= 1 ? await read(path(`authority-close-proof-${tx}`)) : null;
      const baseline = phase >= 2 ? await read(path(`authority-successor-baseline-${tx}`)) : null;
      const commit = phase >= 2 ? await read(path(`authority-commit-${tx}`)) : null;
      const fence = phase >= 2 ? await read(path(`authority-successor-fence-${tx}`)) : null;
      const publicationK = phase >= 2 ? await read(path(`publication-k-${tx}`)) : null;
      const publicationY = phase >= 2 ? await read(path(`publication-y-${tx}`)) : null;
      const finality = phase >= 3 ? await read(path(`authority-successor-finality-${tx}`)) : null;
      const receipt = phase >= 4 ? await read(path(`authority-successor-receipt-${tx}`)) : null;
      const lease = phase >= 4 ? await read(botPath(`successor-lease-${tx}`)) : null;
      const projection = phase >= 4 ? await read(botPath(`successor-reader-projection-${tx}`)) : null;
      const ack = phase >= 4 ? await read(botPath(`successor-ack-${tx}`)) : null;
      try {
        if (phase >= 1) {
          validateAuthorityCloseProof(close, request);
          if (value.closeFingerprint !== close.closeFingerprint) throw new TypeError('close head binding');
        }
        if (phase >= 2) {
          if (fence !== null) validateAuthoritySuccessorFence(fence, request);
          validateAuthoritySuccessorBaseline(baseline, request, close, fence);
          if (!commit || !hex(commit.authorityCommitSnapshotFingerprint) ||
              !publicationK || !hex(publicationK['publication-kFingerprint']) ||
              !publicationY || !hex(publicationY['publication-yFingerprint']) ||
              value.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint ||
              value.baselineFingerprint !== baseline.baselineFingerprint ||
              value.publicationKFingerprint !== publicationK['publication-kFingerprint'] ||
              value.publicationYFingerprint !== publicationY['publication-yFingerprint']) throw new TypeError('replaced head binding');
        }
        if (phase >= 3) {
          validateAuthoritySuccessorFinality(finality, request, baseline);
          if (value.finalityFingerprint !== finality.finalityFingerprint) throw new TypeError('finality head binding');
        }
        if (phase >= 4) {
          const marker = await rawRead(historyMarkerPath);
          validateAuthoritySuccessorReceipt(receipt, request, finality, lease, projection, ack);
          validateHistoryMarker(marker);
          if (value.receiptFingerprint !== receipt.receiptFingerprint ||
              marker.sequence !== value.sequence || marker.markerFingerprint !== value.historyMarkerFingerprint) throw new TypeError('history marker');
          await exactLiveSuccessor({ request, finality, lease, projection, ack, receipt });
        }
      } catch { refused('write_authority_successor_head', 'durable phase proof is required'); }
      const historical = `authority-head-${value.sequence}-${value.phase}`;
      const stored = await read(path(historical));
      if (stored !== null) {
        if (canonical(stored) !== canonical(value)) refused('write_authority_successor_head', 'historical successor head conflicts');
        await writeAuthority('authority-head', stored);
        return stored;
      }
      await writeCreateOnceAuthority(historical, value);
      await writeAuthority('authority-head', value);
      return value;
    },
    async readRetainedTargetProof() {
      await requireManagementOrBotPrincipal('read_retained_target_proof');
      const control = await read(path('control-root'));
      if (!control?.sourceKind || !control.wrapperRelativeName) refused('read_retained_target_proof', 'retained target envelope is absent');
      const wrapper = await read(join(root, control.wrapperRelativeName));
      const target = await targetProof({ sourceKind: control.sourceKind });
      let snapshot = null;
      if (control.sourceKind === 'managed-v1') {
        try { snapshot = validateManagementSnapshot(parseCanonicalJsonBytes(target.bytes)); } catch { refused('read_retained_target_proof', 'retained managed target is invalid'); }
      }
      return {
        sourceKind: control.sourceKind,
        targetBytes: Buffer.from(target.bytes),
        targetFingerprint: fingerprint(target.bytes),
        identityFingerprint: target.targetIdentity,
        aclFingerprint: target.targetAclFingerprint,
        wrapperFingerprint: wrapper?.wrapperFingerprint,
        controlRootFingerprint: control.controlRootFingerprint,
        snapshot,
        snapshotFingerprint: snapshot?.configFingerprint ?? fingerprint(target.bytes),
      };
    },
    async readSuccessorRecovery({ predecessorReceiptFingerprint } = {}) {
      await requireManagementPrincipal('read_successor_recovery');
      if (!hex(predecessorReceiptFingerprint)) refused('read_successor_recovery', 'exact predecessor receipt fingerprint is required');
      const bundle = await this.readSuccessorBundle();
      if (!bundle || bundle.head.phase !== 'reader-pending' ||
          bundle.request.previousReceiptFingerprint !== predecessorReceiptFingerprint ||
          bundle.finality?.finalityFingerprint !== bundle.head.finalityFingerprint) {
        refused('read_successor_recovery', 'exact pending successor recovery is absent');
      }
      const candidate = await this.mappingTargetProof();
      if (candidate.targetFingerprint !== bundle.finality.targetFingerprint ||
          candidate.identityFingerprint !== bundle.finality.targetIdentityFingerprint ||
          candidate.aclFingerprint !== bundle.finality.targetAclFingerprint ||
          candidate.snapshotFingerprint !== bundle.request.candidateSnapshotFingerprint ||
          canonicalJsonHash(candidate.snapshot) !== bundle.request.candidateTargetFingerprint) {
        refused('read_successor_recovery', 'candidate retained target proof is substituted');
      }
      return {
        predecessorReceiptFingerprint,
        predecessorTargetFingerprint: bundle.request.previousTargetFingerprint,
        predecessorWrapperFingerprint: bundle.request.previousWrapperFingerprint,
        predecessorSnapshotFingerprint: bundle.request.previousSnapshotFingerprint,
        candidateTargetFingerprint: bundle.request.candidateTargetFingerprint,
        candidateConfigFingerprint: bundle.request.candidateSnapshotFingerprint,
        candidateState: structuredClone(candidate.snapshot),
        candidateStateFingerprint: canonicalJsonHash(candidate.snapshot),
        sequence: bundle.request.sequence,
        phase: bundle.head.phase,
        headFingerprint: bundle.head.headFingerprint,
        phaseRecordFingerprint: bundle.finality.finalityFingerprint,
      };
    },
    async readAuthoritySuccessorHead() {
      const value = await read(path('authority-head'));
      if (value === null) return null;
      try { validateAuthoritySuccessorHead(value); } catch { refused('read_authority_successor_head', 'successor head is invalid'); }
      return value;
    },
    async readSuccessorBundle() {
      await requireManagementPrincipal('read_authority_successor_bundle');
      const head = await read(path('authority-head'));
      if (head === null) return null;
      try { validateAuthoritySuccessorHead(head); } catch { refused('read_authority_successor_bundle', 'successor head is invalid'); }
      const tx = encodeURIComponent(head.txId);
      const bundle = {
        request: await read(path(`authority-successor-request-${tx}`)),
        close: await read(path(`authority-close-proof-${tx}`)),
        fence: await read(path(`authority-successor-fence-${tx}`)),
        baseline: await read(path(`authority-successor-baseline-${tx}`)),
        commit: await read(path(`authority-commit-${tx}`)),
        publicationK: await read(path(`publication-k-${tx}`)),
        publicationY: await read(path(`publication-y-${tx}`)),
        finality: await read(path(`authority-successor-finality-${tx}`)),
        lease: await read(botPath(`successor-lease-${tx}`)),
        projection: await read(botPath(`successor-reader-projection-${tx}`)),
        ack: await read(botPath(`successor-ack-${tx}`)),
        receipt: await read(path(`authority-successor-receipt-${tx}`)),
        historyMarker: await rawRead(historyMarkerPath),
        head,
      };
      if (bundle.historyMarker !== null) {
        try { validateHistoryMarker(bundle.historyMarker); } catch { refused('read_authority_successor_bundle', 'successor history marker is invalid'); }
      }
      try { validateAuthoritySuccessorBundle(bundle); } catch { refused('read_authority_successor_bundle', 'successor bundle is torn or substituted'); }
      return bundle;
    },
    async writeAuthoritySuccessorFence(value) {
      await requireManagementPrincipal('write_authority_successor_fence');
      try { validateAuthoritySuccessorFence(value); } catch { refused('write_authority_successor_fence', 'exact successor fence is required'); }
      await writeCreateOnceAuthority(`authority-successor-fence-${encodeURIComponent(value.txId)}`, value);
      return value;
    },
    async writeAuthoritySuccessorReservation(value) {
      await requireManagementPrincipal('write_authority_successor_reservation');
      try { validateAuthorityReservation(value); } catch { refused('write_authority_successor_reservation', 'exact successor authority reservation is required'); }
      await writeCreateOnceAuthority(`authority-reservation-${encodeURIComponent(value.txId)}`, value);
      return value;
    },
    async writeAuthoritySuccessorCommit(value) {
      await requireManagementPrincipal('write_authority_successor_commit');
      const reservation = await read(path(`authority-reservation-${encodeURIComponent(value.txId)}`));
      try { validateAuthorityCommitSnapshot(value, reservation); } catch { refused('write_authority_successor_commit', 'exact successor authority commit is required'); }
      await writeCreateOnceAuthority(`authority-commit-${encodeURIComponent(value.txId)}`, value);
      return value;
    },
    async writeAuthoritySuccessorClose(value) {
      await requireManagementPrincipal('write_authority_successor_close');
      const request = await read(path(`authority-successor-request-${encodeURIComponent(value.txId)}`));
      try { validateAuthoritySuccessorRequest(request); validateAuthorityCloseProof(value, request); } catch { refused('write_authority_successor_close', 'exact successor close proof is required'); }
      await writeCreateOnceAuthority(`authority-close-proof-${encodeURIComponent(value.txId)}`, value);
      return value;
    },
    async writeAuthoritySuccessorBaseline(value) {
      await requireManagementPrincipal('write_authority_successor_baseline');
      const request = await read(path(`authority-successor-request-${encodeURIComponent(value.txId)}`));
      const close = await read(path(`authority-close-proof-${encodeURIComponent(value.txId)}`));
      const fence = await read(path(`authority-successor-fence-${encodeURIComponent(value.txId)}`));
      try { validateAuthoritySuccessorRequest(request); validateAuthoritySuccessorBaseline(value, request, close, fence); } catch { refused('write_authority_successor_baseline', 'exact successor baseline is required'); }
      await writeCreateOnceAuthority(`authority-successor-baseline-${encodeURIComponent(value.txId)}`, value);
      return value;
    },
    async writeAuthoritySuccessorFinality(value) {
      await requireManagementPrincipal('write_authority_successor_finality');
      const tx = encodeURIComponent(value.txId);
      const [request, baseline, close, fence] = await Promise.all([
        read(path(`authority-successor-request-${tx}`)),
        read(path(`authority-successor-baseline-${tx}`)),
        read(path(`authority-close-proof-${tx}`)),
        read(path(`authority-successor-fence-${tx}`)),
      ]);
      try {
        validateAuthoritySuccessorRequest(request);
        validateAuthorityCloseProof(close, request);
        if (fence !== null) validateAuthoritySuccessorFence(fence, request);
        validateAuthoritySuccessorBaseline(baseline, request, close, fence);
        validateAuthoritySuccessorFinality(value, request, baseline);
      } catch {
        refused('write_authority_successor_finality', 'exact successor finality is required');
      }
      await writeCreateOnceAuthority(`authority-successor-finality-${encodeURIComponent(value.txId)}`, value);
      return value;
    },
    async writeAuthoritySuccessorReceipt(value) {
      await requireManagementPrincipal('write_authority_successor_receipt');
      const tx = encodeURIComponent(value.txId);
      const [request, finality, lease, projection, ack] = await Promise.all([
        read(path(`authority-successor-request-${tx}`)), read(path(`authority-successor-finality-${tx}`)),
        read(botPath(`successor-lease-${tx}`)), read(botPath(`successor-reader-projection-${tx}`)), read(botPath(`successor-ack-${tx}`)),
      ]);
      try { validateAuthoritySuccessorRequest(request); validateAuthoritySuccessorFinality(finality, request); validateAuthoritySuccessorReceipt(value, request, finality, lease, projection, ack); } catch { refused('write_authority_successor_receipt', 'exact successor receipt is required'); }
      await exactLiveSuccessor({ request, finality, lease, projection, ack, receipt: value });
      await writeCreateOnceAuthority(`authority-successor-receipt-${tx}`, value);
      return value;
    },
    async writeBotAuthoritySuccessorLease(value) {
      await requireBotPrincipal('write_bot_authority_successor_lease');
      await this.readBotAuthoritySuccessorLiveProof({ txId: value.txId });
      const head = await read(path('authority-head'));
      const request = await read(path(`authority-successor-request-${encodeURIComponent(value.txId)}`));
      const fence = await read(path(`authority-successor-fence-${encodeURIComponent(value.txId)}`));
      const finality = await read(path(`authority-successor-finality-${encodeURIComponent(value.txId)}`));
      try { validateAuthoritySuccessorHead(head, request); validateAuthoritySuccessorFinality(finality, request); if (head.phase !== 'reader-pending' || head.finalityFingerprint !== finality.finalityFingerprint) throw new TypeError('pending head'); validateAuthoritySuccessorRequest(request); validateAuthoritySuccessorFence(fence, request); validateAuthoritySuccessorLease(value, request, fence); } catch { refused('write_bot_authority_successor_lease', 'exact pending successor lease is required'); }
      await ensureBotRoot();
      const name = botPath(`successor-lease-${encodeURIComponent(value.txId)}`);
      if (await lowLevel.read_verified_bytes(name) !== null) refused('write_bot_authority_successor_lease', 'successor lease already exists');
      await write(name, value, 'bot-state');
      return value;
    },
    async writeBotAuthoritySuccessorProjection(value) {
      await requireBotPrincipal('write_bot_authority_successor_projection');
      await this.readBotAuthoritySuccessorLiveProof({ txId: value.txId });
      const head = await read(path('authority-head'));
      const request = await read(path(`authority-successor-request-${encodeURIComponent(value.txId)}`));
      const lease = await read(botPath(`successor-lease-${encodeURIComponent(value.txId)}`));
      const finality = await read(path(`authority-successor-finality-${encodeURIComponent(value.txId)}`));
      try { validateAuthoritySuccessorHead(head, request); validateAuthoritySuccessorFinality(finality, request); if (head.phase !== 'reader-pending' || head.finalityFingerprint !== finality.finalityFingerprint) throw new TypeError('pending head'); validateAuthoritySuccessorRequest(request); validateAuthoritySuccessorLease(lease, request); validateAuthoritySuccessorReaderProjection(value, request, finality, lease); } catch { refused('write_bot_authority_successor_projection', 'exact pending successor projection is required'); }
      await ensureBotRoot();
      const name = botPath(`successor-reader-projection-${encodeURIComponent(value.txId)}`);
      if (await lowLevel.read_verified_bytes(name) !== null) refused('write_bot_authority_successor_projection', 'successor projection already exists');
      await write(name, value, 'bot-state');
      return value;
    },
    async writeBotAuthoritySuccessorAck(value) {
      await requireBotPrincipal('write_bot_authority_successor_ack');
      await this.readBotAuthoritySuccessorLiveProof({ txId: value.txId });
      const head = await read(path('authority-head'));
      const request = await read(path(`authority-successor-request-${encodeURIComponent(value.txId)}`));
      const projection = await read(botPath(`successor-reader-projection-${encodeURIComponent(value.txId)}`));
      const finality = await read(path(`authority-successor-finality-${encodeURIComponent(value.txId)}`));
      try { validateAuthoritySuccessorHead(head, request); validateAuthoritySuccessorFinality(finality, request); if (head.phase !== 'reader-pending' || head.finalityFingerprint !== finality.finalityFingerprint) throw new TypeError('pending head'); validateAuthoritySuccessorRequest(request); validateAuthoritySuccessorReaderProjection(projection, request, finality); validateAuthoritySuccessorAck(value, request, finality, projection); } catch { refused('write_bot_authority_successor_ack', 'exact pending successor acknowledgement is required'); }
      await ensureBotRoot();
      const name = botPath(`successor-ack-${encodeURIComponent(value.txId)}`);
      if (await lowLevel.read_verified_bytes(name) !== null) refused('write_bot_authority_successor_ack', 'successor acknowledgement already exists');
      await write(name, value, 'bot-state');
      return value;
    },
    async validateAuthoritySuccessorBundle(bundle) {
      try { return validateAuthoritySuccessorBundle(bundle); } catch { refused('validate_authority_successor_bundle', 'successor authority bundle is invalid'); }
    },
  };
  return Object.freeze(adapter);
}
export async function createManagementNative({ configPath, roles } = {}) { return createAdapter({ lowLevel: loadVerifiedAddon(), configPath, arbitraryPrincipalProbe: true, roles }); }
export function createManagementNativeForTest({ lowLevel, configPath, arbitraryPrincipalProbe = true, roles, platform } = {}) { return createAdapter({ lowLevel, configPath, arbitraryPrincipalProbe, roles, platform }); }
