import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { buildManifest, validateBuildManifest } from '../src/index.js';
import { createManagementNativeForTest } from './helpers/management-native.js';
import * as publicApi from '../src/public.js';
import { ManagementRuntime } from '../../bot/src/management-runtime.js';
import { canonicalJson, canonicalJsonHash } from '@gjc-remote/shared/strict-json';
import { attestTokenFloor, buildAttestedTokenFloorProof, commitTokenFloor } from '@gjc-remote/shared/genesis-envelope';
import { buildAuthoritySuccessorRecord } from '@gjc-remote/shared/successor-envelope';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const recordHash = (record, field) => canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
const normalize = (value) => value.replaceAll("\\", "/");
const fileEnding = (files, ending) => [...files.entries()].find(([name]) => normalize(name).endsWith(ending))?.[1];
const parentOf = (path) => path.replaceAll('\\', '/').slice(0, path.replaceAll('\\', '/').lastIndexOf('/'));
test('production package surface excludes the low-level test adapter', () => {
  assert.equal(publicApi.createManagementNativeForTest, undefined);
  assert.deepEqual(
    Object.keys(publicApi).sort(),
    ['buildManifest', 'createManagementNative', 'validateBuildManifest'],
  );
});

function fake() {
  const files = new Map(); const calls = []; const roleCalls = []; const roles = { managementSid: 'S-1-5-21-100', botSid: 'S-1-5-21-101', recoverySid: 'S-1-5-21-102', systemSid: 'S-1-5-18' };
  const lowLevel = {
    open_verified_parent: async (path) => ({ path: parentOf(path) }), open_no_follow: async () => {}, read_identity: async (path) => path.endsWith('.genesis-bootstrap-blocker') && !files.has(path) ? null : ({ path, owner: roles.managementSid }), read_acl: async () => 'protected:M,B,R,SYSTEM', path_exists_no_follow: async (path) => { const normalized = path.replaceAll('\\', '/'); return [...files.keys()].some((name) => { const candidate = name.replaceAll('\\', '/'); return candidate === normalized || candidate.startsWith(`${normalized}/`); }); }, verify_exact_role_acl: async () => true, set_exact_role_acl: async () => {}, remove_verified_file: async (path, expected) => { assert.deepEqual(files.get(path), Buffer.from(expected)); files.delete(path); }, flush_file: async () => {}, flush_directory_or_volume: async () => {},
    open_verified_parent_handle: async (path) => ({ path: parentOf(path) }), open_verified_object_handle: async (parent, name) => {
      const normalized = `${parent.path}/${name}`;
      const path = [...files.keys()].find((candidate) => candidate.replaceAll('\\', '/') === normalized);
      return path ? { path } : null;
    }, read_handle_identity: async (handle) => ({ path: handle.path, owner: roles.managementSid }), read_handle_bytes: async (handle) => Buffer.from(files.get(handle.path)),
    write_handle_bytes: async (handle, bytes) => { if (!files.has(handle.path)) throw new Error('missing handle'); files.set(handle.path, Buffer.from(bytes)); },
    remove_verified_handle: async (handle, expected) => { assert.deepEqual(files.get(handle.path), Buffer.from(expected)); files.delete(handle.path); },
    read_verified_bytes: async (path) => files.has(path) ? Buffer.from(files.get(path)) : null, ensure_control_directory: async (...args) => { roleCalls.push(args); },
    create_absent_exclusive: async (path, bytes, ...args) => { files.set(path, Buffer.from(bytes)); calls.push(path); roleCalls.push([path, ...args]); }, create_exclusive_temp: async (_dir, prefix, bytes, ...args) => { const path = `${_dir}/${prefix}.tmp`; files.set(path, Buffer.from(bytes)); roleCalls.push([_dir, ...args]); return path; }, replace_existing_atomic: async (from, to, ...args) => { files.set(to, files.get(from)); files.delete(from); calls.push(to); roleCalls.push([from, to, ...args]); },
    acquire_native_lock: async (path, ...args) => { calls.push(path); roleCalls.push([path, ...args]); return { release: async () => {} }; }, current_os_principal: async () => ({ kind: 'sid', value: roles.managementSid }), principal_access_check: async (_path, _kind, principal, mode) => mode !== 'write' || principal === roles.managementSid,
  };
  return { files, calls, roleCalls, roles, lowLevel };
}
function records(managementSid = 'S-1-5-21-100') {
  const h = 'a'.repeat(64); const tx = '123e4567-e89b-42d3-a456-426614174000';
  const floor = { version: 1, kind: 'token-generation-floor', anchorFingerprint: h, genesisGeneration: 1, highestReservedGeneration: 1, highestCommittedGeneration: 0, lastReservationTxId: tx, lastCommittedTxId: null, lastAttestationFingerprint: null, floorPhase: 'reserved', attestedProofFingerprint: null, floorFingerprint: null }; floor.floorFingerprint = recordHash(floor, 'floorFingerprint');
  const attestation = { version: 1, kind: 'token-config-attestation', anchorFingerprint: h, tokenConfigGeneration: 1, tokenConfigHostSetFingerprint: h, managedGrammarVersion: 1, sourceKind: 'protected-stdin', producerPrincipal: `management/${h}`, rotationKind: 'genesis', previousAttestationFingerprint: null, txId: tx, attestationFingerprint: null }; attestation.attestationFingerprint = recordHash(attestation, 'attestationFingerprint');
  const request = { version: 1, kind: 'genesis-request', genesisTxId: tx, idempotencyKey: 'key', anchorFingerprint: h, ownerPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: managementSid }), generation: 1, requestedReaderMode: 'no-reader', readerInstanceId: null, readerStartNonce: null, attestationFingerprint: attestation.attestationFingerprint, tokenFloorFingerprint: floor.floorFingerprint, requestFingerprint: null }; request.requestFingerprint = recordHash(request, 'requestFingerprint');
  const attestedProof = buildAttestedTokenFloorProof(floor, attestation);
  const attestedFloor = attestTokenFloor(floor, attestedProof);
  const committed = commitTokenFloor(attestedFloor, { txId: tx, generation: 1, attestationFingerprint: attestation.attestationFingerprint });
  return { floor, attestation, request, attestedProof, attestedFloor, committed };
}
async function writeAuthorityRequest(native, configPath, request, roles, targetBytes) {
  const targetIdentity = sha(canonicalJson({ kind: 'test', path: configPath, owner: roles.managementSid }));
  const targetAclFingerprint = sha('protected:M,B,R,SYSTEM');
  const legacyTargetProof = {
    rawTargetByteFingerprint: sha(targetBytes),
    rawTargetByteLength: targetBytes.length,
    targetIdentity,
    targetAclFingerprint,
  };
  const record = {
    version: 1, kind: 'genesis-authority-request', genesisTxId: request.genesisTxId, sequence: 1,
    anchorFingerprint: await native.managementAnchorFingerprint(),
    ownerPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: roles.managementSid }),
    managementPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: roles.managementSid }),
    botPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: roles.botSid }),
    recoveryPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: roles.recoverySid }),
    targetPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: 'target' }),
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
    generation: request.generation, requestedReaderMode: request.requestedReaderMode, readerInstanceId: null, readerStartNonce: null,
    idempotencyKey: 'authority-key', targetInputState: 'legacy-unmigrated',
    targetFingerprint: legacyTargetProof.rawTargetByteFingerprint, targetIdentityFingerprint: canonicalJsonHash(targetIdentity),
    targetAclFingerprint, legacyTargetProofFingerprint: canonicalJsonHash(legacyTargetProof), protectedInputFingerprint: 'a'.repeat(64),
    requestFingerprint: null,
  };
  record.requestFingerprint = recordHash(record, 'requestFingerprint');
  await native.writeGenesisAuthorityRequest(record);
  return record;
}
test('persists exact shared records in genesis order and confines bot writes', async () => {
  const { files, calls, roleCalls, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; files.set(configPath, Buffer.from('{"legacy":true}'));
  const native = createManagementNativeForTest({ lowLevel, configPath, roles }); const { floor, attestation, request, attestedProof, attestedFloor, committed } = records();
  await native.probeProspectiveCleanup({ txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' }, managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid }, recoveryPrincipal: { kind: 'sid', value: roles.recoverySid }, managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64) });
  await writeAuthorityRequest(native, configPath, request, roles, Buffer.from('{"legacy":true}'));
  await native.writeGenesisRequest(request); await native.reserveTokenFloor(floor); await native.writeTokenConfigAttestation(attestation);
  await native.writeAttestedTokenFloor({ reservation: floor, attestation, proof: attestedProof, floor: attestedFloor });
  await assert.rejects(native.reserveTokenFloor({ ...floor, tokenBytes: Buffer.from('secret') }), /secret-free/);
  await assert.rejects(native.writeTokenConfigAttestation({ kind: 'A' }), /exact secret-free generation reservation/);
  const reservationPath = [...files.keys()].find((path) => path.includes('token-floor-reservation-'));
  const reservationBytes = Buffer.from(files.get(reservationPath));
  await assert.rejects(native.reserveTokenFloor(floor), /immutable authority record already exists/);
  assert.deepEqual(files.get(reservationPath), reservationBytes);
  assert.ok(calls.findIndex((p) => p.endsWith('attestation.json')) < calls.findIndex((p) => p.includes('token-floor-attested-')));
  await native.publishMapping({ request, attestation, targetPrincipal: null });
  await assert.rejects(native.commitTokenFloor(committed), /exact committed generation floor is required/);
  await assert.rejects(native.commitTokenFloor({ floor: committed }), /attested token-floor predecessor is absent|exact precommit graph is invalid/);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.botSid });
  await assert.rejects(native.writeBotReaderState({ revision: 1 }), /handshake/);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  assert.equal([...files.keys()].filter((p) => p.includes('bot-')).every((p) => p.includes('.gjc-remote-control')), true);
  assert.ok(calls.findIndex((p) => p.endsWith('genesis-request.json')) < calls.findIndex((p) => p.includes('token-floor-reservation-')));
  assert.ok(calls.findIndex((p) => p.includes('token-floor-reservation-')) < calls.findIndex((p) => p.endsWith('attestation.json')));
  assert.equal([...files.values()].some((bytes) => bytes.includes(Buffer.from('secret'))), false);
  await native.terminalCloseOrManualCleanup({ reason: 'test' }); assert.match([...files.entries()].find(([path]) => path.replaceAll("\\", "/").endsWith('/terminal-close.json'))[1].toString(), /manual-cleanup/); assert.match([...files.entries()].find(([path]) => path.replaceAll("\\", "/").endsWith('/terminal-close.json'))[1].toString(), /no-route/); assert.equal(roleCalls.every((args) => args.slice(-5, -1).join(',') === `${roles.managementSid},${roles.botSid},${roles.recoverySid},${roles.systemSid}` && ['authority', 'bot-state', 'prospective-cleanup'].includes(args.at(-1))), true);
});

test('orders parent-scoped locks before the prospective cleanup proof without authority creation', async () => {
  const { files, calls, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json';
  const native = createManagementNativeForTest({ lowLevel, configPath, roles }); const { floor } = records();
  await native.withManagementLocks(['genesis', 'mapping', 'admission'], async () => {
    await assert.rejects(native.reserveTokenFloor(floor), /complete immutable genesis authority request/);
    assert.equal([...files.keys()].some((path) => path.includes('.gjc-remote-control')), false);
  });
  assert.deepEqual(calls.map(normalize), ['C:/state/.channels.json.genesis.lock', 'C:/state/.channels.json.mapping.lock', 'C:/state/.channels.json.admission.lock']);
});
test('rejects missing immutable genesis authority request before reserve and attestation writes', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { floor, attestation, request } = records();
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await native.probeProspectiveCleanup({ txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' }, managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid }, recoveryPrincipal: { kind: 'sid', value: roles.recoverySid }, managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64) });
  const before = new Map(files);
  await assert.rejects(native.reserveTokenFloor(floor), /complete immutable genesis authority request/);
  await assert.rejects(native.writeTokenConfigAttestation(attestation), /complete immutable genesis authority request/);
  assert.deepEqual(files, before);
});
test('refuses GP when B can mutate the actual config parent', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
  const access = lowLevel.principal_access_check;
  lowLevel.principal_access_check = async (path, kind, principal, mode) =>
    path === 'C:/state' && principal === roles.botSid && mode === 'write' ? true : access(path, kind, principal, mode);
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await assert.rejects(native.probeProspectiveCleanup({ txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' }, managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid }, recoveryPrincipal: { kind: 'sid', value: roles.recoverySid }, managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64) }), /actual config parent/);
  assert.equal([...files.keys()].some((path) => path.includes('.gjc-remote-control')), false);
});

test('retained legacy target bytes and identity remain exact through publication', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const original = Buffer.from('{"legacy":true}');
  files.set(configPath, original); const native = createManagementNativeForTest({ lowLevel, configPath, roles }); const { floor, attestation, request } = records();
  await native.withManagementLocks(['genesis', 'mapping', 'admission'], async () => {
    await native.probeProspectiveCleanup({ txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' }, managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid }, recoveryPrincipal: { kind: 'sid', value: roles.recoverySid }, managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64) });
    await writeAuthorityRequest(native, configPath, request, roles, original);
    await native.writeGenesisRequest(request); await native.reserveTokenFloor(floor); await native.writeTokenConfigAttestation(attestation); await native.publishMapping({ request, attestation, targetPrincipal: { kind: 'sid', value: 'target' } });
  });
  assert.deepEqual(files.get(configPath), original);
  assert.equal([...files.keys()].some((path) => path.endsWith('.genesis-bootstrap-blocker')), false);
  assert.equal(JSON.parse(fileEnding(files, '/.gjc-remote-control/legacy-retained.json')).targetIdentity, sha(canonicalJson({ kind: 'test', path: configPath, owner: roles.managementSid })));
});
test('rejects malformed and swapped native M/B/R/SYSTEM role bindings', () => {
  const { lowLevel } = fake();
  assert.throws(
    () => createManagementNativeForTest({
      lowLevel,
      configPath: 'C:/state/channels.json',
      roles: { managementSid: 'S-1-5-21-100', botSid: 'S-1-5-21-100', recoverySid: 'S-1-5-21-102', systemSid: 'S-1-5-18' },
    }),
    /exact M\/B\/R\/SYSTEM SID role configuration/,
  );
  assert.throws(
    () => createManagementNativeForTest({
      lowLevel,
      configPath: 'C:/state/channels.json',
      roles: { managementSid: 'S-1-5-21-100', botSid: 'S-1-5-21-101', recoverySid: 'S-1-5-21-102', systemSid: 'S-1-5-19' },
    }),
    /exact M\/B\/R\/SYSTEM SID role configuration/,
  );
});
test('prospective GP scratch is removed while the durable bootstrap blocker remains until authority handoff', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json';
  files.set(configPath, Buffer.from('{"legacy":true}'));
  const native = createManagementNativeForTest({ lowLevel, configPath, roles }); const { request } = records();
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  assert.equal(files.get(configPath).toString(), '{"legacy":true}');
  assert.ok([...files.keys()].some((path) => path.endsWith('.genesis-bootstrap-blocker')));
});
test('adopts only a descriptor-bound GP blocker after process loss', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json';
  files.set(configPath, Buffer.from('{"legacy":true}')); const { request } = records();
  const input = {
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  };
  await createManagementNativeForTest({ lowLevel, configPath, roles }).probeProspectiveCleanup(input);
  const blocker = [...files.keys()].find((path) => path.endsWith('.genesis-bootstrap-blocker'));
  const persisted = Buffer.from(files.get(blocker));
  await createManagementNativeForTest({ lowLevel, configPath, roles }).probeProspectiveCleanup(input);
  assert.ok(files.has(blocker));
  assert.ok(Buffer.from(files.get(blocker)).equals(persisted));
  assert.equal(JSON.parse(files.get(blocker)).profile, 'prospective-cleanup');
  const torn = JSON.parse(files.get(blocker)); torn.parentAclFingerprint = '0'.repeat(64); files.set(blocker, Buffer.from(canonicalJson(torn)));
  await assert.rejects(createManagementNativeForTest({ lowLevel, configPath, roles }).probeProspectiveCleanup(input), /manual cleanup/);
});
test('uses one retained scratch handle for every GP phase and exact cleanup', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json';
  files.set(configPath, Buffer.from('{"legacy":true}')); const { request } = records();
  const writes = []; const removals = [];
  const originalWrite = lowLevel.write_handle_bytes; const originalRemove = lowLevel.remove_verified_handle;
  lowLevel.write_handle_bytes = async (handle, bytes) => { writes.push(handle); await originalWrite(handle, bytes); };
  lowLevel.remove_verified_handle = async (handle, bytes) => { removals.push(handle); await originalRemove(handle, bytes); };
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const genesisSecurityTuple = {
    version: 1, kind: 'genesis-security-tuple', anchorFingerprint: await native.managementAnchorFingerprint(),
    actorPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: roles.managementSid }),
    ownerPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: roles.managementSid }),
    targetPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: 'target' }),
    managementRole: roles.managementSid, botRole: roles.botSid, recoveryRole: roles.recoverySid,
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64), protectedHostTokensHostSetFingerprint: 'a'.repeat(64),
    generation: 1, idempotencyKey: 'tuple-fixture', targetInputIntent: null,
    requestedReaderMode: 'no-reader', readerInstanceId: null, readerStartNonce: null,
  };
  const prospective = await native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid }, recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
    genesisSecurityTuple, generation: 1, idempotencyKey: 'tuple-fixture', requestedReaderMode: 'no-reader',
    readerInstanceId: null, readerStartNonce: null, protectedInputFingerprint: 'a'.repeat(64),
  });
  assert.equal(writes.length, 3); assert.equal(new Set(writes).size, 1); assert.equal(removals.length, 3); assert.equal(removals[0], writes[0]);
  assert.equal(prospective.genesisSecurityTuple.generation, 1);
  assert.equal(prospective.genesisSecurityTuple.targetInputState, 'legacy-unmigrated');
  assert.equal(prospective.genesisSecurityTuple.legacyTargetProof.rawTargetByteLength, Buffer.byteLength('{"legacy":true}'));
});
test('prospective cleanup requires observed B/R write denial for the retained scratch', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
  const accessCalls = [];
  const originalAccessCheck = lowLevel.principal_access_check;
  lowLevel.principal_access_check = async (path, kind, principal, mode) => {
    accessCalls.push({ path, kind, principal, mode });
    return originalAccessCheck(path, kind, principal, mode);
  };
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const prospective = await native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  const scratchCalls = accessCalls.filter(({ path }) => path.includes('.gp.seed.tmp'));
  assert.deepEqual(scratchCalls.map(({ principal, mode }) => [principal, mode]), [
    [roles.managementSid, 'read'], [roles.managementSid, 'write'],
    [roles.botSid, 'read'], [roles.botSid, 'write'],
    [roles.recoverySid, 'read'], [roles.recoverySid, 'write'],
  ]);
  const scratchIdentity = prospective.probe.scratchIdentity;
  assert.equal(prospective.probe.botWriteDeniedProofFingerprint, sha(canonicalJson({
    txId: request.genesisTxId, scratchIdentity,
    access: { principal: { kind: 'sid', value: roles.botSid }, mode: 'write', result: false },
  })));
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  const denial = fake(); const denialRequest = records().request;
  denial.lowLevel.principal_access_check = async (_path, _kind, _principal, mode) => mode === 'read';
  const denied = createManagementNativeForTest({ lowLevel: denial.lowLevel, configPath, roles: denial.roles });
  await assert.rejects(denied.probeProspectiveCleanup({
    txId: denialRequest.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: denial.roles.managementSid }, botPrincipal: { kind: 'sid', value: denial.roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: denial.roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  }), /prospective cleanup is ambiguous/);
});

test('prospective GP refuses retained-handle and pathname identity drift', async () => {
  const { files, roles, lowLevel } = fake();
  const configPath = 'C:/state/channels.json';
  files.set(configPath, Buffer.from('{"legacy":true}'));
  const { request } = records();
  let handleReads = 0;
  lowLevel.read_handle_identity = async (handle) => ({
    path: handle.path,
    owner: roles.managementSid,
    generation: ++handleReads > 1 ? 2 : 1,
  });
  lowLevel.read_identity = async (path) => ({ path, generation: 1, owner: roles.managementSid });
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await assert.rejects(
    native.probeProspectiveCleanup({
      txId: request.genesisTxId,
      targetPrincipal: { kind: 'sid', value: 'target' },
      managementPrincipal: { kind: 'sid', value: roles.managementSid },
      botPrincipal: { kind: 'sid', value: roles.botSid },
      recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
      managementProvisioningFingerprint: 'b'.repeat(64),
      botProvisioningFingerprint: 'c'.repeat(64),
      recoveryProvisioningFingerprint: 'd'.repeat(64),
    }),
    /identity changed|identity mismatch|manual cleanup/,
  );
});
test('prospective GP refuses an actual config parent owned by a principal other than M before mutation', async () => {
  const { roles, lowLevel, calls } = fake();
  lowLevel.read_identity = async (path) => ({ path, owner: roles.botSid });
  const native = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles });
  await assert.rejects(native.probeProspectiveCleanup({
    txId: records().request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  }), /actual config parent owner is not the configured management principal/);
  assert.deepEqual(calls, []);
});

test('fails closed before replacement when a retained authority ACL drifts', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await native.terminalCloseOrManualCleanup({ reason: 'first' });
  const terminal = [...files.keys()].find((path) => normalize(path).endsWith('/terminal-close.json'));
  const before = Buffer.from(files.get(terminal));
  let reads = 0;
  lowLevel.read_acl = async (path) => normalize(path) === normalize(terminal) && ++reads === 2 ? 'drifted' : 'protected:M,B,R,SYSTEM';
  await assert.rejects(native.terminalCloseOrManualCleanup({ reason: 'second' }), /ACL changed/);
  assert.deepEqual(files.get(terminal), before);
});
test('rejects a post-replace identity or byte mismatch', async () => {
  const { files, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await native.terminalCloseOrManualCleanup({ reason: 'first' });
  lowLevel.replace_existing_atomic = async (_from, to) => { files.set(to, Buffer.from('corrupt')); };
  await assert.rejects(native.terminalCloseOrManualCleanup({ reason: 'second' }), /object bytes or identity changed/);
});
test('fails closed when a retained authority identity drifts', async () => {
  const { roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await native.terminalCloseOrManualCleanup({ reason: 'first' });
  const terminalPath = 'terminal-close.json';
  let reads = 0;
  const originalIdentity = lowLevel.read_identity;
  lowLevel.read_identity = async (path) => normalize(path).endsWith(`/${terminalPath}`) && ++reads === 2 ? { path, replaced: true } : originalIdentity(path);
  await assert.rejects(native.terminalCloseOrManualCleanup({ reason: 'second' }), /object bytes or identity changed/);
});
test('bot writers reject a non-bot OS principal before BST writes', async () => {
  const { roles, lowLevel } = fake();
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  const native = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles });
  await assert.rejects(native.writeBotReaderState({}), /not the configured bot SID/);
});
test('recovers the exact no-reader Genesis suffix idempotently and rejects a torn reservation binding', async () => {
  const { files, roles, lowLevel } = fake();
  const configPath = 'C:/state/channels.json';
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const runtime = new ManagementRuntime({ native });
  const result = await runtime.execute('genesis', {
    actorPrincipal: { kind: 'sid', value: roles.managementSid },
    targetPrincipal: { kind: 'sid', value: 'S-1-5-21-103' },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
    actorSecret: 'owner-secret-is-long-enough',
    idempotencyKey: 'recovery-test',
    hostTokens: 'host=secret',
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  const request = JSON.parse(fileEnding(files, '/.gjc-remote-control/genesis-request.json'));
  const recovery = { txId: request.genesisTxId, requestFingerprint: request.requestFingerprint };
  for (const ending of ['/rvf.json', '/receipt.json', '/genesis-suffix-recovery.json']) {
    const key = [...files.keys()].find((path) => normalize(path).endsWith(`/.gjc-remote-control${ending}`));
    files.delete(key);
  }
  const first = await native.recoverGenesisSuffix({ recovery });
  const second = await native.recoverGenesisSuffix({ recovery });
  assert.deepEqual(second, first);
  assert.ok(fileEnding(files, '/.gjc-remote-control/z-finality.json'));
  assert.ok(fileEnding(files, '/.gjc-remote-control/receipt.json'));
  const reservationPath = [...files.keys()].find((key) => key.includes('token-floor-reservation-'));
  const reservation = JSON.parse(files.get(reservationPath));
  reservation.floorFingerprint = '0'.repeat(64);
  files.set(reservationPath, Buffer.from(JSON.stringify(reservation)));
  await assert.rejects(native.recoverGenesisSuffix({ recovery }), /manual cleanup/);
});

test('finality and receipt writers reject malformed replacement records without mutation', async () => {
  const { files, roles, lowLevel } = fake();
  const configPath = 'C:/state/channels.json';
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const runtime = new ManagementRuntime({ native });
  const result = await runtime.execute('genesis', {
    actorPrincipal: { kind: 'sid', value: roles.managementSid },
    targetPrincipal: { kind: 'sid', value: 'S-1-5-21-103' },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
    actorSecret: 'owner-secret-is-long-enough',
    idempotencyKey: 'proof-validation-test',
    hostTokens: 'host=secret',
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  const proofPath = [...files.keys()].find((path) => normalize(path).endsWith('/rvf.json'));
  const receiptPath = [...files.keys()].find((path) => normalize(path).endsWith('/receipt.json'));
  const proofBefore = Buffer.from(files.get(proofPath));
  const receiptBefore = Buffer.from(files.get(receiptPath));
  await assert.rejects(native.writeFinalityProof({ kind: 'finality-proof' }), /finality graph|exact finality proof/);
  await assert.rejects(native.writeGenesisReceipt({ kind: 'genesis-receipt' }), /exact Genesis receipt/);
  assert.deepEqual(files.get(proofPath), proofBefore);
  assert.deepEqual(files.get(receiptPath), receiptBefore);
});
test('recovers the attested token-floor seam with one monotonic commit CAS', async () => {
  const { files, roles, lowLevel } = fake();
  const configPath = 'C:/state/channels.json';
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const runtime = new ManagementRuntime({ native });
  const result = await runtime.execute('genesis', {
    actorPrincipal: { kind: 'sid', value: roles.managementSid },
    targetPrincipal: { kind: 'sid', value: 'S-1-5-21-103' },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
    actorSecret: 'owner-secret-is-long-enough',
    idempotencyKey: 'attested-recovery-test',
    hostTokens: 'host=secret',
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  const request = JSON.parse(fileEnding(files, '/.gjc-remote-control/genesis-request.json'));
  const reservation = JSON.parse(fileEnding(files, `/token-floor-reservation-${request.genesisTxId}.json`));
  const attestation = JSON.parse(fileEnding(files, '/.gjc-remote-control/attestation.json'));
  const proof = JSON.parse(fileEnding(files, `/token-floor-attested-${request.genesisTxId}.json`));
  const attestedFloor = attestTokenFloor(reservation, proof);
  const currentFloorPath = [...files.keys()].find((path) => normalize(path).endsWith('/.gjc-remote-control/token-floor.json'));
  files.set(currentFloorPath, Buffer.from(canonicalJson(attestedFloor)));
  for (const ending of [
    `/token-floor-commit-${request.genesisTxId}.json`,
    '/token-floor-history.json',
    '/z-finality.json',
    '/rvf.json',
    '/receipt.json',
    '/genesis-suffix-recovery.json',
  ]) {
    const key = [...files.keys()].find((path) => normalize(path).endsWith(`/.gjc-remote-control${ending}`));
    if (key !== undefined) files.delete(key);
  }
  const statePath = [...files.keys()].find((path) => normalize(path).endsWith('/.gjc-remote-control/management-state.json'));
  const state = JSON.parse(files.get(statePath));
  state.admission = { phase: 'closed', finalityFingerprint: null };
  state.recovery = { ...state.recovery, phase: 'replaced' };
  files.set(statePath, Buffer.from(canonicalJson(state)));

  const recovered = await native.recoverGenesisSuffix({
    recovery: { txId: request.genesisTxId, requestFingerprint: request.requestFingerprint },
  });
  assert.equal(recovered.phase, 'terminal');
  const committed = JSON.parse(fileEnding(files, '/.gjc-remote-control/token-floor.json'));
  assert.equal(committed.floorPhase, 'committed');
  assert.equal(committed.highestCommittedGeneration, request.generation);
  assert.equal(committed.lastCommittedTxId, request.genesisTxId);
  assert.ok(fileEnding(files, `/token-floor-commit-${request.genesisTxId}.json`));
  assert.ok(fileEnding(files, '/.gjc-remote-control/z-finality.json'));
});
test('partial management markers block wholly absent legacy fallback', async () => {
  const { files, lowLevel, roles } = fake();
  const native = createManagementNativeForTest({
    lowLevel,
    configPath: 'C:/state/channels.json',
    roles,
  });
  files.set('C:/state/.gjc-remote-control/partial.json', Buffer.from('{}'));
  const snapshot = await native.readManagedMappingSnapshot();
  assert.equal(snapshot.managementMarkerPresent, true);
  assert.equal(snapshot.controlRootAbsent, false);
});

test('accepts Linux POSIX UID roles and normalizes exact decimal inputs', async () => {
  const { lowLevel } = fake();
  const roles = { managementSid: 'uid:100', botSid: '101', recoverySid: 'uid:102', systemSid: '0' };
  const native = createManagementNativeForTest({ lowLevel, configPath: '/state/channels.json', roles, platform: 'linux' });
  assert.deepEqual(await native.configureManagementRoles(roles), { managementSid: 'uid:100', botSid: 'uid:101', recoverySid: 'uid:102', systemSid: 'uid:0' });
  assert.throws(
    () => createManagementNativeForTest({ lowLevel, configPath: '/state/channels.json', roles: { ...roles, botSid: 'uid:01' }, platform: 'linux' }),
    /root UID role configuration/,
  );
  assert.throws(
    () => createManagementNativeForTest({ lowLevel, configPath: '/state/channels.json', roles: { ...roles, recoverySid: 'uid:100' }, platform: 'linux' }),
    /root UID role configuration/,
  );
  assert.equal(validateBuildManifest({ ...buildManifest, package: '@gjc-remote/native-control', version: '1.0.0', platform: 'linux', arch: 'x64', addon: 'native_control.node', sha256: sha(Buffer.from('native-addon')) }, { name: '@gjc-remote/native-control', version: '1.0.0' }, Buffer.from('native-addon'), 'linux', 'x64'), true);
});
test('refuses manifest package, N-API, platform, hash, capability, and signature drift', () => {
  const addonBytes = Buffer.from('native-addon');
  const manifest = {
    ...buildManifest, package: '@gjc-remote/native-control', version: '1.0.0',
    platform: 'linux', arch: 'x64', addon: 'native_control.node', sha256: sha(addonBytes),
  };
  assert.equal(validateBuildManifest(manifest, { name: manifest.package, version: manifest.version }, addonBytes, 'linux', 'x64'), true);
  const win32Manifest = { ...manifest, platform: 'win32' };
  assert.equal(validateBuildManifest(win32Manifest, { name: manifest.package, version: manifest.version }, addonBytes, 'win32', 'x64'), true);
  assert.equal(validateBuildManifest({ ...win32Manifest, arch: 'arm64' }, { name: manifest.package, version: manifest.version }, addonBytes, 'win32', 'arm64'), false);
  assert.equal(validateBuildManifest(win32Manifest, { name: manifest.package, version: manifest.version }, addonBytes, 'linux', 'x64'), false);
  for (const field of ['package', 'version', 'napi', 'platform', 'arch', 'addon', 'sha256', 'capabilities', 'capabilitySignatures']) {
    const altered = structuredClone(manifest);
    altered[field] = field === 'napi' ? 7 : field === 'capabilities' ? [] : field === 'capabilitySignatures' ? {} : 'wrong';
    assert.equal(validateBuildManifest(altered, { name: manifest.package, version: manifest.version }, addonBytes, 'linux', 'x64'), false, field);
  }
  const signatureDrift = structuredClone(manifest);
  signatureDrift.capabilitySignatures.principal_access_check = ['path', 'kind', 'principal'];
  assert.equal(validateBuildManifest(signatureDrift, { name: manifest.package, version: manifest.version }, addonBytes, 'linux', 'x64'), false);
});
test('successor recovery keeps retained proof source-aware for B and management-only for recovery', async () => {
  const { files, lowLevel, roles } = fake();
  const configPath = 'C:/state/channels.json';
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const targetBytes = Buffer.from('{"legacy":true}');
  files.set(configPath, targetBytes);
  files.set('C:\\state\\.gjc-remote-control\\control-root.json', Buffer.from(canonicalJson({
    sourceKind: 'legacy-retained', wrapperRelativeName: 'legacy-retained.json', controlRootFingerprint: 'a'.repeat(64),
  })));
  files.set('C:\\state\\.gjc-remote-control\\legacy-retained.json', Buffer.from(canonicalJson({ wrapperFingerprint: 'b'.repeat(64) })));

  assert.equal(typeof native.readRetainedTargetProof, 'function');
  assert.equal(typeof native.readSuccessorRecovery, 'function');
  const retained = await native.readRetainedTargetProof();
  assert.equal(retained.sourceKind, 'legacy-retained');
  assert.deepEqual(retained.targetBytes, targetBytes);
  assert.equal(retained.identityFingerprint, sha(canonicalJson({ kind: 'test', path: configPath, owner: roles.managementSid })));
  assert.equal(retained.aclFingerprint, sha('protected:M,B,R,SYSTEM'));
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.botSid });
  await assert.rejects(native.readSuccessorRecovery({ predecessorReceiptFingerprint: 'a'.repeat(64) }), /not the configured management SID/);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  await assert.rejects(native.readSuccessorRecovery({ predecessorReceiptFingerprint: 'a'.repeat(64) }), /exact pending successor recovery is absent/);
});
test('successor head writes are principal-confined, exact-replay idempotent, and phase-complete', async () => {
  const { files, lowLevel, roles } = fake();
  const configPath = 'C:/state/channels.json';
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const genesis = records();
  const targetBytes = Buffer.from('{"legacy":true}');
  files.set(configPath, targetBytes);
  const hex = 'a'.repeat(64);
  const request = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-successor-request', sequence: 2, txId: 'successor-2', rootGenesisTxId: genesis.request.genesisTxId,
    idempotencyKey: 'successor-key', operation: 'tokens-attest', anchorFingerprint: await native.managementAnchorFingerprint(),
    actorPrincipalFingerprint: hex, previousReceiptFingerprint: hex, previousTargetFingerprint: hex, previousWrapperFingerprint: hex,
    previousRevision: 1, candidateRevision: 2, previousAuthorityEpoch: 1, candidateAuthorityEpoch: 2,
    previousTokenConfigGeneration: 1, candidateTokenConfigGeneration: 2, previousAttestationFingerprint: hex,
    candidateAttestationFingerprint: hex, previousMappingGeneration: 1, candidateMappingGeneration: 1,
    previousSnapshotFingerprint: hex, candidateSnapshotFingerprint: hex, candidateTargetFingerprint: hex,
    mappingRecoveryTxFingerprint: null, targetState: 'legacy-retained', readerMode: 'no-reader',
    readerInstanceId: null, readerStartNonce: null, readerNonce: null, requestFingerprint: null,
  }, 'requestFingerprint');
  const reserved = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-successor-head', anchorFingerprint: request.anchorFingerprint, sequence: request.sequence,
    txId: request.txId, rootGenesisTxId: request.rootGenesisTxId, operation: request.operation, phase: 'reserved',
    requestFingerprint: request.requestFingerprint, closeFingerprint: null, authorityCommitSnapshotFingerprint: null,
    baselineFingerprint: null, publicationKFingerprint: null, publicationYFingerprint: null, finalityFingerprint: null,
    receiptFingerprint: null, historyMarkerFingerprint: null, previousHeadFingerprint: null,
    previousReceiptFingerprint: request.previousReceiptFingerprint, routeDisposition: 'no-route', headFingerprint: null,
  }, 'headFingerprint');

  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.botSid });
  await assert.rejects(native.writeAuthoritySuccessorRequest(request), /not the configured management SID/);
  await assert.rejects(native.writeAuthoritySuccessorHead(reserved), /not the configured management SID/);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  await native.probeProspectiveCleanup({
    txId: genesis.request.genesisTxId,
    targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await writeAuthorityRequest(native, configPath, genesis.request, roles, targetBytes);
  const marker = { version: 1, kind: 'managed-history-marker', anchorFingerprint: request.anchorFingerprint, sequence: 1, previousMarkerFingerprint: null, markerFingerprint: null };
  marker.markerFingerprint = recordHash(marker, 'markerFingerprint');
  files.set('C:\\state\\.channels.json.managed-history.json', Buffer.from(canonicalJson(marker)));
  files.set('C:\\state\\.gjc-remote-control\\token-floor.json', Buffer.from(canonicalJson(genesis.committed)));
  const readerFloor = { version: 1, kind: 'reader-version-floor', anchorFingerprint: request.anchorFingerprint, readerVersionFloor: null, firstPendingTxId: null, firstReaderInstanceId: null, firstReaderStartNonce: null, lastTransitionTxId: null, previousFloorFingerprint: null, floorFingerprint: null };
  readerFloor.floorFingerprint = recordHash(readerFloor, 'floorFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\reader-version-floor.json', Buffer.from(canonicalJson(readerFloor)));
  await native.writeAuthoritySuccessorRequest(request);
  assert.deepEqual(await native.writeAuthoritySuccessorRequest(request), request);
  await assert.rejects(native.writeAuthoritySuccessorRequest(buildAuthoritySuccessorRecord({ ...request, idempotencyKey: 'conflict', requestFingerprint: null }, 'requestFingerprint')), /replay conflicts/);
  await native.writeAuthoritySuccessorHead(reserved);
  assert.deepEqual(await native.writeAuthoritySuccessorHead(reserved), reserved);
  const skipped = buildAuthoritySuccessorRecord({
    ...reserved, phase: 'replaced', closeFingerprint: 'b'.repeat(64), authorityCommitSnapshotFingerprint: 'c'.repeat(64),
    baselineFingerprint: 'd'.repeat(64), publicationKFingerprint: 'e'.repeat(64), publicationYFingerprint: 'f'.repeat(64),
    previousHeadFingerprint: reserved.headFingerprint, headFingerprint: null,
  }, 'headFingerprint');
  await assert.rejects(native.writeAuthoritySuccessorHead(skipped), /exact successor head transition is required/);
  await assert.rejects(native.writeAuthoritySuccessorHead({ ...reserved, headFingerprint: '0'.repeat(64) }), /exact successor head transition is required/);
  const torn = buildAuthoritySuccessorRecord({ ...reserved, phase: 'closed', previousHeadFingerprint: reserved.headFingerprint, headFingerprint: null }, 'headFingerprint');
  await assert.rejects(native.writeAuthoritySuccessorHead(torn), /exact successor head transition is required/);
});
test('management startup self-test confines mutations to private scratch and reports writes honestly on refusal', async () => {
  const { files, lowLevel, roles } = fake();
  const configPath = 'C:/state/channels.json';
  files.set(configPath, Buffer.from('{"legacy":true}'));
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  lowLevel.principal_access_check = async (path, _kind, principal, mode) =>
    path.includes('.mst-') ? principal === roles.managementSid : mode !== 'write' || principal === roles.managementSid;
  lowLevel.create_absent_exclusive = async (path, bytes) => {
    if (files.has(path)) throw Object.assign(new Error('exists'), { code: 'EEXIST' });
    files.set(path, Buffer.from(bytes));
  };
  lowLevel.acquire_native_lock = async (path) => {
    files.set(path, Buffer.alloc(0));
    return { release: async () => {} };
  };
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  assert.deepEqual(await native.runStartupSelfTest(), { role: 'management', mst: true, bst: false, writes: 0 });
  assert.deepEqual(files, new Map([[configPath, Buffer.from('{"legacy":true}')]]));
  lowLevel.create_exclusive_temp = async () => { throw new Error('denied'); };
  await assert.rejects(native.runStartupSelfTest(), (error) =>
    error.code === 'ERR_NATIVE_CONTROL_REFUSED' && error.operation === 'run_startup_self_test' &&
    /management native primitive self-test failed/.test(error.reason) && error.writes === 1);
  assert.deepEqual(files, new Map([[configPath, Buffer.from('{"legacy":true}')]]));
});
test('MST cleans retained artifacts after temp create, verification, flush, and replacement failures', async () => {
  for (const phase of ['temp-create', 'temp-verify', 'temp-flush', 'replace']) {
    const { files, lowLevel, roles } = fake();
    const configPath = 'C:/state/channels.json';
    files.set(configPath, Buffer.from('{"legacy":true}'));
    lowLevel.create_absent_exclusive = async (path, bytes) => {
      if (files.has(path)) throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      files.set(path, Buffer.from(bytes));
    };
    lowLevel.acquire_native_lock = async (path) => {
      files.set(path, Buffer.alloc(0));
      return { release: async () => {} };
    };
    const originalTemp = lowLevel.create_exclusive_temp;
    const originalIdentity = lowLevel.read_identity;
    const originalFlush = lowLevel.flush_file;
    const originalReplace = lowLevel.replace_existing_atomic;
    if (phase === 'temp-create') lowLevel.create_exclusive_temp = async () => { throw new Error('injected'); };
    if (phase === 'temp-verify') lowLevel.read_identity = async (path) =>
      path.includes('.mst-') && path.includes('.tmp') ? null : originalIdentity(path);
    if (phase === 'temp-flush') lowLevel.flush_file = async (path) => {
      if (path.includes('.mst-') && path.includes('.tmp')) throw new Error('injected');
      return originalFlush(path);
    };
    if (phase === 'replace') lowLevel.replace_existing_atomic = async () => { throw new Error('injected'); };
    await assert.rejects(createManagementNativeForTest({ lowLevel, configPath, roles }).runStartupSelfTest(),
      (error) => error.operation === 'run_startup_self_test' && error.writes === 1);
    assert.deepEqual(files, new Map([[configPath, Buffer.from('{"legacy":true}')]]), phase);
    lowLevel.create_exclusive_temp = originalTemp;
    lowLevel.read_identity = originalIdentity;
    lowLevel.flush_file = originalFlush;
    lowLevel.replace_existing_atomic = originalReplace;
  }
});

test('bot startup self-test is read-only and refuses ambiguous management-record permissions', async () => {
  const { files, lowLevel, roles } = fake();
  const configPath = 'C:/state/channels.json';
  const original = Buffer.from('{"legacy":true}');
  files.set(configPath, original);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.botSid });
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  assert.deepEqual(await native.runStartupSelfTest(), { role: 'bot', mst: false, bst: true, writes: 0 });
  assert.deepEqual(files, new Map([[configPath, original]]));
  lowLevel.principal_access_check = async (path, _kind, _principal, mode) =>
    mode === 'read' || (path === configPath && mode === 'write');
  await assert.rejects(native.runStartupSelfTest(), (error) =>
    error.code === 'ERR_NATIVE_CONTROL_REFUSED' && error.operation === 'run_startup_self_test' &&
    error.reason === 'bot management-record permissions are ambiguous' && error.writes === 0);
  assert.deepEqual(files, new Map([[configPath, original]]));
});
test('M-owned locks reject bot and recovery principals before native mutation', async () => {
  const { calls, lowLevel, roles } = fake();
  const native = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles });
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.botSid });
  await assert.rejects(native.withManagementLocks(['genesis'], async () => {}), /not the configured management SID/);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.recoverySid });
  await assert.rejects(native.withManagementLocks(['genesis'], async () => {}), /not the configured management SID/);
  assert.deepEqual(calls, []);
});

test('MST treats a non-exact no-replace collision as ambiguous', async () => {
  const { files, lowLevel, roles } = fake();
  const configPath = 'C:/state/channels.json';
  files.set(configPath, Buffer.from('{"legacy":true}'));
  let creates = 0;
  const create = lowLevel.create_absent_exclusive;
  lowLevel.create_absent_exclusive = async (...args) => {
    creates += 1;
    if (creates === 2) throw Object.assign(new Error('access denied'), { code: 'EACCES' });
    return create(...args);
  };
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await assert.rejects(native.runStartupSelfTest(), /management native primitive self-test failed/);
});
