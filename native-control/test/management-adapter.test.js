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
    open_verified_parent: async (path) => ({ path: parentOf(path), owner: roles.managementSid }), open_no_follow: async () => {}, read_identity: async (path) => path.endsWith('.genesis-bootstrap-blocker') && !files.has(path) ? null : ({ path, owner: roles.managementSid }), read_acl: async () => 'protected:M,B,R,SYSTEM', path_exists_no_follow: async (path) => { const normalized = path.replaceAll('\\', '/'); return [...files.keys()].some((name) => { const candidate = name.replaceAll('\\', '/'); return candidate === normalized || candidate.startsWith(`${normalized}/`); }); }, verify_exact_role_acl: async () => true, set_exact_role_acl: async () => {}, remove_verified_file: async (path, expected) => { assert.deepEqual(files.get(path), Buffer.from(expected)); files.delete(path); }, flush_file: async () => {}, flush_directory_or_volume: async () => {},
    open_verified_parent_handle: async (path) => ({ path: parentOf(path), owner: roles.managementSid }), open_verified_object_handle: async (parent, name) => {
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
  const floor = { version: 1, kind: 'token-generation-floor', anchorFingerprint: h, fenceGeneration: 1, genesisGeneration: 1, highestReservedGeneration: 1, highestCommittedGeneration: 0, lastReservationTxId: tx, lastCommittedTxId: null, lastAttestationFingerprint: null, floorPhase: 'reserved', attestedProofFingerprint: null, floorFingerprint: null }; floor.floorFingerprint = recordHash(floor, 'floorFingerprint');
  const attestation = { version: 1, kind: 'token-config-attestation', anchorFingerprint: h, fenceGeneration: 1, tokenConfigGeneration: 1, tokenConfigHostSetFingerprint: h, managedGrammarVersion: 1, sourceKind: 'protected-stdin', producerPrincipal: `management/${h}`, rotationKind: 'genesis', previousAttestationFingerprint: null, txId: tx, attestationFingerprint: null }; attestation.attestationFingerprint = recordHash(attestation, 'attestationFingerprint');
  const request = { version: 1, kind: 'genesis-request', genesisTxId: tx, idempotencyKey: 'key', anchorFingerprint: h, ownerPrincipalFingerprint: canonicalJsonHash({ kind: 'sid', value: managementSid }), generation: 1, fenceGeneration: 1, requestedReaderMode: 'no-reader', readerInstanceId: null, readerStartNonce: null, attestationFingerprint: attestation.attestationFingerprint, tokenFloorFingerprint: floor.floorFingerprint, requestFingerprint: null }; request.requestFingerprint = recordHash(request, 'requestFingerprint');
  const attestedProof = buildAttestedTokenFloorProof(floor, attestation);
  const attestedFloor = attestTokenFloor(floor, attestedProof);
  const committed = commitTokenFloor(attestedFloor, { txId: tx, generation: 1, attestationFingerprint: attestation.attestationFingerprint, fenceGeneration: 1 });
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
    fenceGeneration: 1,
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
async function committedGenesisFixture(idempotencyKey) {
  const fixture = fake();
  const configPath = 'C:/state/channels.json';
  fixture.lowLevel.current_os_principal = async () => ({ kind: 'sid', value: fixture.roles.managementSid });
  const native = createManagementNativeForTest({ lowLevel: fixture.lowLevel, configPath, roles: fixture.roles });
  const runtime = new ManagementRuntime({ native });
  const result = await runtime.execute('genesis', {
    actorPrincipal: { kind: 'sid', value: fixture.roles.managementSid },
    targetPrincipal: { kind: 'sid', value: 'S-1-5-21-103' },
    botPrincipal: { kind: 'sid', value: fixture.roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: fixture.roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
    actorSecret: 'owner-secret-is-long-enough',
    idempotencyKey,
    hostTokens: 'host=secret',
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  const request = JSON.parse(fileEnding(fixture.files, '/.gjc-remote-control/genesis-request.json'));
  return { ...fixture, native, request, recovery: { txId: request.genesisTxId, requestFingerprint: request.requestFingerprint } };
}
function restoreReservedAuthorityEpoch(fixture) {
  const { files, request } = fixture;
  const committedEpoch = JSON.parse(fileEnding(files, '/authority-epoch-1-committed.json'));
  const precommit = JSON.parse(fileEnding(files, '/.gjc-remote-control/genesis-precommit-proof.json'));
  const reservedEpoch = JSON.parse(fileEnding(files, '/authority-epoch-1-reserved.json'));
  const floorPath = [...files.keys()].find((path) => normalize(path).endsWith('/.gjc-remote-control/authority-epoch-floor.json'));
  const currentEpochPath = [...files.keys()].find((path) => normalize(path).endsWith('/.gjc-remote-control/authority-epoch.json'));
  const floor = JSON.parse(files.get(floorPath));
  floor.highestCommittedAuthorityEpoch = 0;
  floor.lastCommittedTxId = null;
  floor.floorFingerprint = recordHash(floor, 'floorFingerprint');
  files.set(floorPath, Buffer.from(canonicalJson(floor)));
  for (const ending of [
    '/.gjc-remote-control/genesis-precommit-proof.json',
    `/genesis-precommit-proof-${request.genesisTxId}.json`,
    `/authority-epoch-${committedEpoch.epoch}-committed.json`,
  ]) {
    const key = [...files.keys()].find((path) => normalize(path).endsWith(`/.gjc-remote-control${ending}`) || normalize(path).endsWith(ending));
    if (key !== undefined) files.delete(key);
  }
  files.set(currentEpochPath, Buffer.from(canonicalJson(reservedEpoch)));
  return { committedEpoch, precommit, floorPath };
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
  await assert.rejects(native.commitTokenFloor({ floor: committed }), /attested token-floor predecessor is absent|exact precommit graph is invalid|committed generation floor fence is invalid/);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.botSid });
  await assert.rejects(native.writeBotReaderState({ revision: 1 }), /handshake/);
  lowLevel.current_os_principal = async () => ({ kind: 'sid', value: roles.managementSid });
  assert.equal([...files.keys()].filter((p) => p.includes('bot-')).every((p) => p.includes('.gjc-remote-control')), true);
  assert.ok(calls.findIndex((p) => p.endsWith('genesis-request.json')) < calls.findIndex((p) => p.includes('token-floor-reservation-')));
  assert.ok(calls.findIndex((p) => p.includes('token-floor-reservation-')) < calls.findIndex((p) => p.endsWith('attestation.json')));
  assert.equal([...files.values()].some((bytes) => bytes.includes(Buffer.from('secret'))), false);
  await native.terminalCloseOrManualCleanup({ reason: 'test' }); assert.match([...files.entries()].find(([path]) => path.replaceAll("\\", "/").endsWith('/terminal-close.json'))[1].toString(), /manual-cleanup/); assert.match([...files.entries()].find(([path]) => path.replaceAll("\\", "/").endsWith('/terminal-close.json'))[1].toString(), /no-route/); assert.equal(roleCalls.every((args) => args.slice(-5, -1).join(',') === `${roles.managementSid},${roles.botSid},${roles.recoverySid},${roles.systemSid}` && ['authority', 'bot-state', 'prospective-cleanup'].includes(args.at(-1))), true);
});
test('commitAuthorityEpoch validates the epoch floor before any commit writes', async () => {
  for (const variant of ['missing', 'malformed', 'mismatched']) {
    const fixture = await committedGenesisFixture(`authority-floor-${variant}`);
    const { committedEpoch, precommit, floorPath } = restoreReservedAuthorityEpoch(fixture);
    if (variant === 'missing') {
      fixture.files.delete(floorPath);
    } else if (variant === 'malformed') {
      fixture.files.set(floorPath, Buffer.from(canonicalJson({ version: 1, kind: 'authority-epoch-floor' })));
    } else {
      const floor = JSON.parse(fixture.files.get(floorPath));
      floor.anchorFingerprint = '0'.repeat(64);
      floor.floorFingerprint = recordHash(floor, 'floorFingerprint');
      fixture.files.set(floorPath, Buffer.from(canonicalJson(floor)));
    }
    const before = new Map([...fixture.files.entries()].map(([path, bytes]) => [path, Buffer.from(bytes)]));
    await assert.rejects(
      fixture.native.commitAuthorityEpoch(committedEpoch, precommit),
      /durable authority epoch floor|authority epoch commit is not bound/,
    );
    assert.deepEqual(fixture.files, before, `${variant} floor refusal must be write-free`);
  }
});
test('commitAuthorityEpoch replay and Genesis recovery repair only the exact floor binding', async () => {
  const fixture = await committedGenesisFixture('authority-floor-replay');
  const { committedEpoch, precommit, floorPath } = restoreReservedAuthorityEpoch(fixture);
  const callStart = fixture.calls.length;
  await fixture.native.commitAuthorityEpoch(committedEpoch, precommit);
  const firstCommitCall = normalize(fixture.calls[callStart]);
  assert.match(firstCommitCall, /authority-epoch-floor\.json$/);
  const committedFloor = JSON.parse(fixture.files.get(floorPath));
  assert.equal(committedFloor.highestCommittedAuthorityEpoch, committedEpoch.epoch);
  assert.equal(committedFloor.lastCommittedTxId, committedEpoch.commitTxId);
  const committedPath = [...fixture.files.keys()].find((path) => normalize(path).endsWith(`/authority-epoch-${committedEpoch.epoch}-committed.json`));
  fixture.files.delete(committedPath);
  await fixture.native.commitAuthorityEpoch(committedEpoch, precommit);
  assert.ok(fileEnding(fixture.files, `/authority-epoch-${committedEpoch.epoch}-committed.json`));
  fixture.files.delete(floorPath);
  await fixture.native.recoverGenesisSuffix({ recovery: fixture.recovery });
  const repairedFloor = JSON.parse(fixture.files.get(floorPath));
  assert.deepEqual(repairedFloor, committedFloor);
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
test('refuses GP when target can mutate the actual config parent before any writes', async () => {
  const { calls, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
  const access = lowLevel.principal_access_check;
  lowLevel.principal_access_check = async (path, kind, principal, mode) =>
    path === 'C:/state' && principal === 'target' && mode === 'write' ? true : access(path, kind, principal, mode);
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await assert.rejects(native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  }), /actual config parent mutation capability/);
  assert.deepEqual(calls, []);
});

test('refuses GP when parent mutation capability is unknown before any writes', async () => {
  const { calls, roles, lowLevel } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
  const access = lowLevel.principal_access_check;
  lowLevel.principal_access_check = async (path, kind, principal, mode) =>
    path === 'C:/state' && principal === roles.managementSid && mode === 'write' ? undefined : access(path, kind, principal, mode);
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  await assert.rejects(native.probeProspectiveCleanup({
    txId: request.genesisTxId, targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid }, botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64), botProvisioningFingerprint: 'c'.repeat(64), recoveryProvisioningFingerprint: 'd'.repeat(64),
  }), /actual config parent mutation capability/);
  assert.deepEqual(calls, []);
});

test('authority mutation revalidates parent owner, DACL, and capabilities write-free after GP', async () => {
  for (const [drift, expected] of [
    ['owner', /owner/],
    ['DACL', /DACL/],
    ['capability', /mutation capability/],
  ]) {
    const { files, calls, roles, lowLevel } = fake();
    const configPath = 'C:/state/channels.json';
    const native = createManagementNativeForTest({ lowLevel, configPath, roles });
    const { request } = records();
    await native.probeProspectiveCleanup({
      txId: request.genesisTxId,
      targetPrincipal: { kind: 'sid', value: 'target' },
      managementPrincipal: { kind: 'sid', value: roles.managementSid },
      botPrincipal: { kind: 'sid', value: roles.botSid },
      recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
      managementProvisioningFingerprint: 'b'.repeat(64),
      botProvisioningFingerprint: 'c'.repeat(64),
      recoveryProvisioningFingerprint: 'd'.repeat(64),
    });
    const authorityRequest = await writeAuthorityRequest(native, configPath, request, roles, Buffer.from('{"legacy":true}'));
    const authorityPath = [...files.keys()].find((path) => normalize(path).endsWith('/genesis-authority-request.json'));
    files.delete(authorityPath);
    const before = new Map([...files.entries()].map(([path, bytes]) => [path, Buffer.from(bytes)]));
    const writes = calls.length;
    if (drift === 'owner') {
      const readIdentity = lowLevel.read_identity;
      lowLevel.read_identity = async (path) => path === 'C:/state'
        ? { path, owner: roles.botSid }
        : readIdentity(path);
    } else if (drift === 'DACL') {
      const readAcl = lowLevel.read_acl;
      lowLevel.read_acl = async (path) => path === 'C:/state' ? 'drifted' : readAcl(path);
    } else {
      const access = lowLevel.principal_access_check;
      lowLevel.principal_access_check = async (path, kind, principal, mode) =>
        path === 'C:/state' && principal === roles.managementSid && mode === 'write'
          ? false
          : access(path, kind, principal, mode);
    }
    await assert.rejects(native.writeGenesisAuthorityRequest(authorityRequest), expected);
    assert.deepEqual(files, before, `${drift} drift must not mutate authority files`);
    assert.equal(calls.length, writes, `${drift} drift must not invoke a native write`);
  }
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
  }), /actual config parent mutation capability/);
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
test('terminal close is create-once, idempotent on exact replay, and rejects replacement before writes', async () => {
  const { files, roles, lowLevel, calls } = fake();
  const native = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles });
  const request = records().request;
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId,
    targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  const first = await native.terminalCloseOrManualCleanup({ reason: 'first' });
  const terminal = [...files.keys()].find((path) => normalize(path).endsWith('/terminal-close.json'));
  const before = Buffer.from(files.get(terminal));
  const writes = calls.length;
  const replay = await native.terminalCloseOrManualCleanup({ reason: 'first' });
  assert.deepEqual(replay, first);
  assert.deepEqual(files.get(terminal), before);
  assert.equal(calls.length, writes);
  const stored = JSON.parse(before);
  assert.equal(stored.manualCleanupFingerprint, recordHash(stored, 'manualCleanupFingerprint'));
  await assert.rejects(
    native.terminalCloseOrManualCleanup({ reason: 'second' }),
    /terminal-close replay conflicts/,
  );
  assert.deepEqual(files.get(terminal), before);
  assert.equal(calls.length, writes);
});
test('durable terminal close blocks successor reads, writes, recovery, and publication without writes', async () => {
  const { files, roles, lowLevel, calls } = fake();
  const native = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles });
  const request = records().request;
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId,
    targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await native.terminalCloseOrManualCleanup({ reason: 'successor-block' });
  const before = new Map([...files].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  const writes = calls.length;
  const blocked = [
    ['writeAuthoritySuccessorRequest', {}],
    ['readBotAuthoritySuccessorLiveProof', {}],
    ['readSuccessorTokenLineage', {}],
    ['writeSuccessorPublicationGraph', {}],
    ['commitAuthoritySuccessorEpoch', {}],
    ['writeAuthoritySuccessorHead', {}],
    ['readRetainedTargetProof', {}],
    ['readSuccessorRecovery', { predecessorReceiptFingerprint: 'a'.repeat(64) }],
    ['readAuthoritySuccessorHeadRaw', {}],
    ['readAuthoritySuccessorHead', {}],
    ['readSuccessorBundle', {}],
    ['readManagedHistoryMarker', {}],
    ['commitManagedHistoryMarker', {}],
    ['writeAuthoritySuccessorFence', {}],
    ['writeAuthoritySuccessorReservation', {}],
    ['writeAuthoritySuccessorCommit', {}],
    ['writeAuthoritySuccessorClose', {}],
    ['writeAuthoritySuccessorBaseline', {}],
    ['writeAuthoritySuccessorFinality', {}],
    ['writeAuthoritySuccessorReceipt', {}],
    ['writeBotAuthoritySuccessorLease', {}],
    ['writeBotAuthoritySuccessorProjection', {}],
    ['writeBotAuthoritySuccessorAck', {}],
    ['publishMapping', {}],
    ['writePublicationGraph', {}],
    ['rotateTokenSidecar', {}],
    ['mappingTargetProof', {}],
    ['readMappingGeneration', {}],
    ['writeMappingRecovery', {}],
    ['writeMappingGeneration', {}],
    ['writeMappingTombstone', {}],
    ['writeMappingHandoffReceipt', {}],
    ['revokeMapping', {}],
    ['appendAudit', {}],
  ];
  for (const [method, value] of blocked) {
    await assert.rejects(native[method](value), (error) => {
      assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
      assert.match(error.reason, /no-route/);
      return true;
    }, method);
    assert.deepEqual(files, before, `${method} must not write after terminal close`);
    assert.equal(calls.length, writes, `${method} must not invoke a write primitive`);
  }
});
test('terminal replay requires an immutable terminalization suffix, not phase and transaction booleans', async () => {
  const { files, roles, lowLevel, calls } = fake();
  const native = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles });
  const request = records().request;
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId,
    targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await native.terminalCloseOrManualCleanup({ reason: 'exact-replay' });
  const head = buildAuthoritySuccessorRecord({
    version: 1,
    kind: 'authority-successor-head',
    fenceGeneration: 2,
    anchorFingerprint: await native.managementAnchorFingerprint(),
    sequence: 2,
    txId: 'successor-replay',
    rootGenesisTxId: request.genesisTxId,
    operation: 'tokens-attest',
    phase: 'reserved',
    requestFingerprint: 'a'.repeat(64),
    closeFingerprint: null,
    authorityCommitSnapshotFingerprint: null,
    baselineFingerprint: null,
    publicationKFingerprint: null,
    publicationYFingerprint: null,
    finalityFingerprint: null,
    receiptFingerprint: null,
    historyMarkerFingerprint: null,
    previousHeadFingerprint: null,
    previousReceiptFingerprint: 'b'.repeat(64),
    routeDisposition: 'no-route',
    headFingerprint: null,
  }, 'headFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\authority-head.json', Buffer.from(canonicalJson(head)));
  files.set('C:\\state\\.gjc-remote-control\\management-state.json', Buffer.from(canonicalJson({
    revision: 0,
    authorityEpoch: 0,
    fenceGeneration: 1,
    tokenConfigGeneration: 0,
    mappingGeneration: 0,
    recovery: { phase: 'terminal', txId: head.txId },
  })));
  const before = new Map([...files].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  const writes = calls.length;
  await assert.rejects(native.readAuthoritySuccessorHeadRaw(), (error) => {
    assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
    assert.match(error.reason, /no-route/);
    return true;
  });
  await assert.rejects(native.compareAndSwapManagementState(0, {
    revision: 0,
    authorityEpoch: 0,
    fenceGeneration: 1,
    tokenConfigGeneration: 0,
    mappingGeneration: 0,
    recovery: { phase: 'terminal', txId: head.txId },
  }), /immutable terminal replay evidence/);
  assert.deepEqual(files, before);
  assert.equal(calls.length, writes);
  await assert.rejects(native.writeAuthoritySuccessorReceipt({ txId: 'different' }), /no-route/);
  await assert.rejects(native.writeAuthoritySuccessorHead({ txId: 'different' }), /no-route/);
  await assert.rejects(native.commitManagedHistoryMarker({ markerFingerprint: 'different' }), /no-route/);
  files.set('C:\\state\\.gjc-remote-control\\management-state.json', Buffer.from(canonicalJson({
    recovery: { phase: 'terminalizing', txId: head.txId },
  })));
  await assert.rejects(native.readAuthoritySuccessorHeadRaw(), /no-route/);
  files.set('C:\\state\\.gjc-remote-control\\management-state.json', Buffer.from(canonicalJson({
    recovery: { phase: 'manual_cleanup', txId: head.txId },
  })));
  await assert.rejects(native.readManagedHistoryMarker(), /no-route/);
  assert.equal(calls.length, writes);
  await assert.rejects(native.readSuccessorRecovery({ predecessorReceiptFingerprint: 'a'.repeat(64) }), (error) => {
    assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
    assert.match(error.reason, /no-route/);
    return true;
  });
  assert.equal(calls.length, writes);
});
test('terminal replay rejects torn terminal-close and embedded suffix hints without writes', async () => {
  const { files, roles, lowLevel, calls } = fake();
  const native = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles });
  const request = records().request;
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId,
    targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await native.terminalCloseOrManualCleanup({ reason: 'embedded-suffix' });
  const terminalPath = 'C:\\state\\.gjc-remote-control\\terminal-close.json';
  const statePath = 'C:\\state\\.gjc-remote-control\\management-state.json';
  const suffixPath = 'C:\\state\\.gjc-remote-control\\terminalization-suffix-embedded-suffix.json';
  files.set(statePath, Buffer.from(canonicalJson({
    recovery: {
      phase: 'manual_cleanup',
      txId: 'embedded-suffix',
      terminalization: {},
    },
  })));
  files.set(suffixPath, Buffer.from(canonicalJson({})));
  const validTerminal = Buffer.from(files.get(terminalPath));
  const writes = calls.length;
  files.set(terminalPath, Buffer.from('{}'));
  const malformedTerminal = new Map([...files].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  await assert.rejects(native.readManagedHistoryMarker(), /durable terminal-close record is unreadable|no-route/);
  assert.deepEqual(files, malformedTerminal);
  assert.equal(calls.length, writes);
  files.set(terminalPath, validTerminal);
  const beforeEmbeddedSuffix = new Map([...files].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  await assert.rejects(native.readManagedHistoryMarker(), /no-route/);
  assert.deepEqual(files, beforeEmbeddedSuffix);
  assert.equal(calls.length, writes);
});
test('terminal replay CAS rejects a complete-state mismatch without writes', async () => {
  const { files, roles, lowLevel, calls } = fake();
  const configPath = 'C:/state/channels.json';
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const request = records().request;
  await native.probeProspectiveCleanup({
    txId: request.genesisTxId,
    targetPrincipal: { kind: 'sid', value: 'target' },
    managementPrincipal: { kind: 'sid', value: roles.managementSid },
    botPrincipal: { kind: 'sid', value: roles.botSid },
    recoveryPrincipal: { kind: 'sid', value: roles.recoverySid },
    managementProvisioningFingerprint: 'b'.repeat(64),
    botProvisioningFingerprint: 'c'.repeat(64),
    recoveryProvisioningFingerprint: 'd'.repeat(64),
  });
  await native.terminalCloseOrManualCleanup({ reason: 'state-replay-mismatch' });
  const writes = calls.length;
  const current = {
    revision: 0,
    authorityEpoch: 0,
    fenceGeneration: 1,
    tokenConfigGeneration: 0,
    mappingGeneration: 0,
    recovery: { phase: 'terminal', txId: 'state-replay-mismatch' },
    completeState: 'durable',
  };
  files.set('C:\\state\\.gjc-remote-control\\management-state.json', Buffer.from(canonicalJson(current)));
  const before = new Map(files);
  await assert.rejects(native.compareAndSwapManagementState(0, { ...current, completeState: 'substituted' }), /immutable terminal replay evidence/);
  assert.deepEqual(files, before);
  assert.equal(calls.length, writes);
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
  lowLevel.read_acl = async (path) => normalize(path) === normalize(terminal) && ++reads === 1 ? '' : 'protected:M,B,R,SYSTEM';
  await assert.rejects(native.terminalCloseOrManualCleanup({ reason: 'first' }), /ACL changed/);
  assert.deepEqual(files.get(terminal), before);
});
test('rejects a mismatched terminal-close replacement before writes', async () => {
  const { files, roles, lowLevel, calls } = fake(); const configPath = 'C:/state/channels.json'; const { request } = records();
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
  const writes = calls.length;
  lowLevel.replace_existing_atomic = async () => { throw new Error('replacement must not run'); };
  await assert.rejects(native.terminalCloseOrManualCleanup({ reason: 'second' }), /terminal-close replay conflicts/);
  assert.deepEqual(files.get(terminal), before);
  assert.equal(calls.length, writes);
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

test('Genesis recovery rejects missing or substituted immutable precommit proof before any writes', async () => {
  for (const variant of ['missing', 'substituted', 'malformed']) {
    const fixture = await committedGenesisFixture(`immutable-precommit-${variant}`);
    const { files, native, recovery, request, calls } = fixture;
    for (const ending of ['/rvf.json', '/receipt.json', '/genesis-suffix-recovery.json']) {
      const key = [...files.keys()].find((path) => normalize(path).endsWith(`/.gjc-remote-control${ending}`));
      files.delete(key);
    }
    const immutablePath = [...files.keys()].find((path) =>
      normalize(path).endsWith(`/genesis-precommit-proof-${request.genesisTxId}.json`));
    if (variant === 'missing') {
      files.delete(immutablePath);
    } else if (variant === 'malformed') {
      files.set(immutablePath, Buffer.from('{}'));
    } else {
      const currentPath = [...files.keys()].find((path) =>
        normalize(path).endsWith('/.gjc-remote-control/genesis-precommit-proof.json'));
      const substituted = JSON.parse(files.get(currentPath));
      substituted.targetFingerprint = '0'.repeat(64);
      substituted.precommitFingerprint = null;
      substituted.precommitFingerprint = recordHash(substituted, 'precommitFingerprint');
      files.set(immutablePath, Buffer.from(canonicalJson(substituted)));
    }
    const before = new Map([...files.entries()].map(([path, bytes]) => [path, Buffer.from(bytes)]));
    const writes = calls.length;
    await assert.rejects(native.recoverGenesisSuffix({ recovery }), /manual cleanup/);
    assert.deepEqual(files, before, `${variant} immutable precommit refusal must be write-free`);
    assert.equal(calls.length, writes, `${variant} immutable precommit refusal must not write`);
  }
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
  const anchor = {
    anchorVersion: 1,
    configPathFingerprint: sha(Buffer.from(configPath)),
    parentIdentity: sha(canonicalJson({ kind: 'test', path: 'C:/state', owner: roles.managementSid })),
    targetRelativeName: 'channels.json',
    controlRootRelativeName: '.gjc-remote-control',
  };
  const anchorFingerprint = canonicalJsonHash(anchor);
  const readerFloor = {
    version: 1,
    kind: 'reader-version-floor',
    anchorFingerprint,
    fenceGeneration: 1,
    readerVersionFloor: null,
    firstPendingTxId: null,
    firstReaderInstanceId: null,
    firstReaderStartNonce: null,
    lastTransitionTxId: null,
    previousFloorFingerprint: null,
    floorFingerprint: null,
  };
  readerFloor.floorFingerprint = recordHash(readerFloor, 'floorFingerprint');
  const targetIdentity = sha(canonicalJson({ kind: 'test', path: configPath, owner: roles.managementSid }));
  const targetAclFingerprint = sha('protected:M,B,R,SYSTEM');
  const wrapper = {
    version: 1,
    kind: 'legacy-retained-wrapper',
    sourceKind: 'legacy-retained',
    managementStamp: 'gjc-management-envelope/v1',
    anchorFingerprint,
    fenceGeneration: 1,
    targetRelativeName: 'channels.json',
    targetState: 'legacy-unmigrated',
    rawTargetByteFingerprint: sha(targetBytes),
    rawTargetByteLength: targetBytes.length,
    targetIdentity,
    targetAclFingerprint,
    readerVersion: null,
    legacyRetention: 'exact',
    dispatchClass: 'workspace-only',
    routeDisposition: 'no-route',
    retentionTxId: '123e4567-e89b-42d3-a456-426614174000',
    retentionSequence: 1,
    previousWrapperFingerprint: null,
    wrapperFingerprint: null,
  };
  wrapper.wrapperFingerprint = recordHash(wrapper, 'wrapperFingerprint');
  const controlRoot = {
    version: 1,
    kind: 'management-control-root',
    managementStamp: 'gjc-management-control/v1',
    anchor,
    anchorFingerprint,
    fenceGeneration: 1,
    sourceKind: 'legacy-retained',
    wrapperKind: 'legacy-retained-wrapper',
    wrapperRelativeName: 'legacy-retained.json',
    targetRelativeName: 'channels.json',
    controlRootRelativeName: '.gjc-remote-control',
    readerVersionFloorFingerprint: readerFloor.floorFingerprint,
    wrapperFingerprint: wrapper.wrapperFingerprint,
    controlRootFingerprint: null,
  };
  controlRoot.controlRootFingerprint = recordHash(controlRoot, 'controlRootFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\reader-version-floor.json', Buffer.from(canonicalJson(readerFloor)));
  files.set('C:\\state\\.gjc-remote-control\\control-root.json', Buffer.from(canonicalJson(controlRoot)));
  files.set('C:\\state\\.gjc-remote-control\\legacy-retained.json', Buffer.from(canonicalJson(wrapper)));

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
test('managed history marker loss is terminal and marker rewinds are write-free', async () => {
  const { files, roles, lowLevel, calls } = fake();
  const configPath = 'C:/state/channels.json';
  const targetBytes = Buffer.from('{"legacy":true}');
  files.set(configPath, targetBytes);
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const genesis = records();
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
  const authorityRequest = await writeAuthorityRequest(native, configPath, genesis.request, roles, targetBytes);
  const authorityReceipt = {
    version: 1,
    kind: 'genesis-authority-receipt',
    genesisTxId: authorityRequest.genesisTxId,
    fenceGeneration: 1,
    requestFingerprint: authorityRequest.requestFingerprint,
    sequence: 2,
    anchorFingerprint: authorityRequest.anchorFingerprint,
    generation: authorityRequest.generation,
    readerVersionFloorFingerprint: 'e'.repeat(64),
    authorityCommitSnapshotFingerprint: 'f'.repeat(64),
    receiptFingerprint: null,
  };
  authorityReceipt.receiptFingerprint = recordHash(authorityReceipt, 'receiptFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\genesis-authority-receipt.json', Buffer.from(canonicalJson(authorityReceipt)));
  files.set(`C:\\state\\.gjc-remote-control\\genesis-authority-receipt-${authorityRequest.genesisTxId}.json`, Buffer.from(canonicalJson(authorityReceipt)));
  const marker = {
    version: 1,
    kind: 'managed-history-marker',
    fenceGeneration: 1,
    anchorFingerprint: authorityRequest.anchorFingerprint,
    sequence: 1,
    previousMarkerFingerprint: null,
    markerFingerprint: null,
  };
  marker.markerFingerprint = recordHash(marker, 'markerFingerprint');

  assert.deepEqual(await native.commitManagedHistoryMarker(marker), marker);
  const markerPath = 'C:\\state\\.channels.json.managed-history.json';
  const sealPath = 'C:\\state\\.gjc-remote-control\\managed-history-marker-seal.json';
  assert.ok(files.has(markerPath));
  assert.ok(files.has(sealPath));
  files.delete(sealPath);
  const beforeMissingSealReplay = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(marker), /seal is absent/);
  assert.deepEqual(files, beforeMissingSealReplay);
  files.set(sealPath, Buffer.from(canonicalJson(marker)));
  const beforeReplay = new Map(files);
  assert.deepEqual(await native.commitManagedHistoryMarker(marker), marker);
  assert.deepEqual(files, beforeReplay);

  files.delete(markerPath);
  const beforeMissing = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(marker), /absent after Genesis/);
  assert.deepEqual(files, beforeMissing);

  files.set(markerPath, Buffer.from(canonicalJson(marker)));
  const successorHead = buildAuthoritySuccessorRecord({
    version: 1,
    kind: 'authority-successor-head',
    fenceGeneration: 2,
    anchorFingerprint: marker.anchorFingerprint,
    sequence: 2,
    txId: 'successor-2',
    rootGenesisTxId: authorityRequest.genesisTxId,
    operation: 'tokens-attest',
    phase: 'reserved',
    requestFingerprint: '1'.repeat(64),
    closeFingerprint: null,
    authorityCommitSnapshotFingerprint: null,
    baselineFingerprint: null,
    publicationKFingerprint: null,
    publicationYFingerprint: null,
    finalityFingerprint: null,
    receiptFingerprint: null,
    historyMarkerFingerprint: null,
    previousHeadFingerprint: null,
    previousReceiptFingerprint: '2'.repeat(64),
    routeDisposition: 'no-route',
    headFingerprint: null,
  }, 'headFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\authority-head.json', Buffer.from(canonicalJson(successorHead)));
  const pendingHead = buildAuthoritySuccessorRecord({
    ...successorHead,
    phase: 'reader-pending',
    closeFingerprint: '3'.repeat(64),
    authorityCommitSnapshotFingerprint: '4'.repeat(64),
    baselineFingerprint: '5'.repeat(64),
    publicationKFingerprint: '6'.repeat(64),
    publicationYFingerprint: '7'.repeat(64),
    finalityFingerprint: '8'.repeat(64),
    headFingerprint: null,
  }, 'headFingerprint');
  const successorMarker = {
    version: 1,
    kind: 'managed-history-marker',
    fenceGeneration: 2,
    anchorFingerprint: marker.anchorFingerprint,
    sequence: 2,
    previousMarkerFingerprint: marker.markerFingerprint,
    markerFingerprint: null,
  };
  successorMarker.markerFingerprint = recordHash(successorMarker, 'markerFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\authority-head.json', Buffer.from(canonicalJson(pendingHead)));
  const beforeReceiptBeforeMarker = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(successorMarker), /matching durable successor receipt/);
  assert.deepEqual(files, beforeReceiptBeforeMarker);
  files.set('C:\\state\\.gjc-remote-control\\authority-head.json', Buffer.from(canonicalJson(successorHead)));
  files.delete(markerPath);
  const beforeSuccessorMissing = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(marker), /absent after successor authority publication/);
  assert.deepEqual(files, beforeSuccessorMissing);

  files.set(markerPath, Buffer.from(canonicalJson(marker)));
  files.delete('C:\\state\\.gjc-remote-control\\authority-head.json');

  const rewind = { ...marker, sequence: 2, previousMarkerFingerprint: '0'.repeat(64), markerFingerprint: null };
  rewind.markerFingerprint = recordHash(rewind, 'markerFingerprint');
  const beforeRewind = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(rewind), /monotonic replay successor/);
  assert.deepEqual(files, beforeRewind);

  const pendingTailHead = buildAuthoritySuccessorRecord({
    ...pendingHead,
    sequence: 3,
    fenceGeneration: 3,
    txId: 'successor-3',
    requestFingerprint: '4'.repeat(64),
    phase: 'reader-pending',
    finalityFingerprint: '9'.repeat(64),
    previousHeadFingerprint: pendingHead.headFingerprint,
    previousReceiptFingerprint: 'a'.repeat(64),
    headFingerprint: null,
  }, 'headFingerprint');
  const successorTail = {
    ...successorMarker,
    sequence: 3,
    fenceGeneration: 3,
    previousMarkerFingerprint: successorMarker.markerFingerprint,
    markerFingerprint: null,
  };
  successorTail.markerFingerprint = recordHash(successorTail, 'markerFingerprint');
  files.set(markerPath, Buffer.from(canonicalJson(successorMarker)));
  files.set('C:\\state\\.gjc-remote-control\\authority-head.json', Buffer.from(canonicalJson(pendingTailHead)));
  files.delete(sealPath);
  const missingSealWrites = calls.length;
  const beforeSuccessorMissingSeal = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(successorTail), /seal is absent/);
  assert.deepEqual(files, beforeSuccessorMissingSeal);
  assert.equal(calls.length, missingSealWrites);
  const substitutedSeal = { ...marker, anchorFingerprint: '0'.repeat(64), markerFingerprint: null };
  substitutedSeal.markerFingerprint = recordHash(substitutedSeal, 'markerFingerprint');
  files.set(sealPath, Buffer.from(canonicalJson(substitutedSeal)));
  const substitutedSealWrites = calls.length;
  const beforeSuccessorSubstitutedSeal = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(successorTail), /seal is invalid/);
  assert.deepEqual(files, beforeSuccessorSubstitutedSeal);
  assert.equal(calls.length, substitutedSealWrites);
  files.set(sealPath, Buffer.from(canonicalJson(marker)));
  const missingReceiptWrites = calls.length;
  const beforeSuccessorMissingReceipt = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(successorTail), /matching durable successor receipt/);
  assert.deepEqual(files, beforeSuccessorMissingReceipt);
  assert.equal(calls.length, missingReceiptWrites);
  files.set(markerPath, Buffer.from('{}'));
  const beforeTorn = new Map(files);
  await assert.rejects(native.commitManagedHistoryMarker(marker), /exact canonical managed history marker/);
  assert.deepEqual(files, beforeTorn);
});
test('successor head writes are principal-confined, exact-replay idempotent, and phase-complete', async () => {
  const { files, lowLevel, roles, calls } = fake();
  const configPath = 'C:/state/channels.json';
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const genesis = records();
  const targetBytes = Buffer.from('{"legacy":true}');
  files.set(configPath, targetBytes);
  const hex = 'a'.repeat(64);
  const request = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-successor-request', sequence: 2, previousFenceGeneration: 1, candidateFenceGeneration: 2, txId: 'successor-2', rootGenesisTxId: genesis.request.genesisTxId,
    idempotencyKey: 'successor-key', operation: 'tokens-attest', anchorFingerprint: await native.managementAnchorFingerprint(),
    actorPrincipalFingerprint: hex, previousReceiptFingerprint: hex, previousTargetFingerprint: hex, previousWrapperFingerprint: hex,
    previousRevision: 1, candidateRevision: 2, previousAuthorityEpoch: 1, candidateAuthorityEpoch: 2,
    previousTokenConfigGeneration: 1, candidateTokenConfigGeneration: 2, previousAttestationFingerprint: hex,
    candidateAttestationFingerprint: hex, previousMappingGeneration: 1, candidateMappingGeneration: 1,
    previousSnapshotFingerprint: hex, candidateSnapshotFingerprint: hex, candidateTargetFingerprint: hex,
    mappingRecoveryTxFingerprint: null, targetState: 'legacy-retained', readerMode: 'no-reader',
    readerInstanceId: null, readerStartNonce: null, readerNonce: null, requestFingerprint: null,
  }, 'requestFingerprint');
  const mappingRetained = buildAuthoritySuccessorRecord({
    ...request,
    operation: 'mapping-reconcile',
    candidateTokenConfigGeneration: request.previousTokenConfigGeneration,
    candidateMappingGeneration: request.previousMappingGeneration + 1,
    candidateAttestationFingerprint: request.previousAttestationFingerprint,
    mappingRecoveryTxFingerprint: hex,
    targetState: 'legacy-retained',
    requestFingerprint: null,
  }, 'requestFingerprint');
  const beforeMappingRetained = new Map(files);
  await assert.rejects(native.writeAuthoritySuccessorRequest(mappingRetained), /legacy-retained target state is valid only for tokens-attest/);
  assert.deepEqual(files, beforeMappingRetained);
  const reserved = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-successor-head', anchorFingerprint: request.anchorFingerprint, sequence: request.sequence,
    fenceGeneration: request.candidateFenceGeneration,
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
  const marker = { version: 1, kind: 'managed-history-marker', anchorFingerprint: request.anchorFingerprint, sequence: 1, fenceGeneration: 1, previousMarkerFingerprint: null, markerFingerprint: null };
  marker.markerFingerprint = recordHash(marker, 'markerFingerprint');
  files.set('C:\\state\\.channels.json.managed-history.json', Buffer.from(canonicalJson(marker)));
  files.set('C:\\state\\.gjc-remote-control\\managed-history-marker-seal.json', Buffer.from(canonicalJson(marker)));
  const successorTokenFloor = { ...genesis.committed, anchorFingerprint: request.anchorFingerprint, floorFingerprint: null };
  successorTokenFloor.floorFingerprint = recordHash(successorTokenFloor, 'floorFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\token-floor.json', Buffer.from(canonicalJson(successorTokenFloor)));
  const readerFloor = { version: 1, kind: 'reader-version-floor', anchorFingerprint: request.anchorFingerprint, fenceGeneration: 1, readerVersionFloor: null, firstPendingTxId: null, firstReaderInstanceId: null, firstReaderStartNonce: null, lastTransitionTxId: null, previousFloorFingerprint: null, floorFingerprint: null };
  readerFloor.floorFingerprint = recordHash(readerFloor, 'floorFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\reader-version-floor.json', Buffer.from(canonicalJson(readerFloor)));
  const fenceFloor = {
    version: 1,
    kind: 'fence-generation-floor',
    anchorFingerprint: request.anchorFingerprint,
    genesisFenceGeneration: 1,
    highestReservedFenceGeneration: 2,
    highestCommittedFenceGeneration: 1,
    lastReservationTxId: request.txId,
    lastCommittedTxId: genesis.request.genesisTxId,
    floorFingerprint: null,
  };
  fenceFloor.floorFingerprint = recordHash(fenceFloor, 'floorFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\fence-generation-floor.json', Buffer.from(canonicalJson(fenceFloor)));
  const epochFloor = {
    version: 1,
    kind: 'authority-epoch-floor',
    anchorFingerprint: request.anchorFingerprint,
    genesisAuthorityEpoch: 1,
    highestReservedAuthorityEpoch: 2,
    highestCommittedAuthorityEpoch: 1,
    lastReservationTxId: request.txId,
    lastCommittedTxId: genesis.request.genesisTxId,
    floorFingerprint: null,
  };
  epochFloor.floorFingerprint = recordHash(epochFloor, 'floorFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\authority-epoch-floor.json', Buffer.from(canonicalJson(epochFloor)));
  const authorityEpoch = {
    version: 1,
    kind: 'authority-epoch',
    anchorFingerprint: request.anchorFingerprint,
    fenceGeneration: request.candidateFenceGeneration,
    epoch: request.candidateAuthorityEpoch,
    reservationTxId: request.txId,
    commitTxId: null,
    previousAuthorityCommitSnapshotFingerprint: 'a'.repeat(64),
    authorityEpochFingerprint: null,
  };
  authorityEpoch.authorityEpochFingerprint = recordHash(authorityEpoch, 'authorityEpochFingerprint');
  files.set('C:\\state\\.gjc-remote-control\\authority-epoch.json', Buffer.from(canonicalJson(authorityEpoch)));
  const foreignRootRequest = buildAuthoritySuccessorRecord({ ...request, rootGenesisTxId: 'foreign-genesis', requestFingerprint: null }, 'requestFingerprint');
  const beforeForeignRoot = new Map([...files.entries()].map(([path, bytes]) => [path, Buffer.from(bytes)]));
  const foreignRootWrites = calls.length;
  await assert.rejects(native.writeAuthoritySuccessorRequest(foreignRootRequest), /immutable Genesis authority request/);
  assert.deepEqual(files, beforeForeignRoot);
  assert.equal(calls.length, foreignRootWrites);
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
  const authorityReservation = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-reservation', anchorFingerprint: request.anchorFingerprint, txId: request.txId,
    epoch: request.candidateAuthorityEpoch, generation: request.candidateTokenConfigGeneration,
    fenceGeneration: request.candidateFenceGeneration, candidateFingerprint: request.requestFingerprint,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
  }, 'reservationFingerprint');
  const detachedReservation = buildAuthoritySuccessorRecord({
    ...authorityReservation, candidateFingerprint: '0'.repeat(64),
  }, 'reservationFingerprint');
  const beforeDetachedReservation = new Map(files);
  const detachedReservationWrites = calls.length;
  await assert.rejects(native.writeAuthoritySuccessorReservation(detachedReservation), /lineage|reservation/);
  assert.deepEqual(files, beforeDetachedReservation);
  assert.equal(calls.length, detachedReservationWrites);
  await native.writeAuthoritySuccessorReservation(authorityReservation);

  const authorityCommit = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-commit-snapshot', anchorFingerprint: request.anchorFingerprint, txId: request.txId,
    epoch: request.candidateAuthorityEpoch, generation: request.candidateTokenConfigGeneration,
    fenceGeneration: request.candidateFenceGeneration, candidateFingerprint: request.requestFingerprint,
    reservationFingerprint: authorityReservation.reservationFingerprint,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
  }, 'authorityCommitSnapshotFingerprint');
  const detachedCommit = buildAuthoritySuccessorRecord({
    ...authorityCommit, reservationFingerprint: '0'.repeat(64),
  }, 'authorityCommitSnapshotFingerprint');
  const beforeDetachedCommit = new Map(files);
  const detachedCommitWrites = calls.length;
  await assert.rejects(native.writeAuthoritySuccessorCommit(detachedCommit), /commit|reservation/);
  assert.deepEqual(files, beforeDetachedCommit);
  assert.equal(calls.length, detachedCommitWrites);
  await native.writeAuthoritySuccessorCommit(authorityCommit);

  const authorityEpochCommit = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-epoch', anchorFingerprint: request.anchorFingerprint,
    fenceGeneration: request.candidateFenceGeneration, epoch: request.candidateAuthorityEpoch,
    reservationTxId: request.txId, commitTxId: request.txId,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
  }, 'authorityEpochFingerprint');
  const detachedAuthorityEpoch = buildAuthoritySuccessorRecord({
    ...authorityEpochCommit, previousAuthorityCommitSnapshotFingerprint: '0'.repeat(64),
  }, 'authorityEpochFingerprint');
  const beforeDetachedEpoch = new Map(files);
  const detachedEpochWrites = calls.length;
  await assert.rejects(native.commitAuthoritySuccessorEpoch(detachedAuthorityEpoch), /epoch|reservation|commit/);
  assert.deepEqual(files, beforeDetachedEpoch);
  assert.equal(calls.length, detachedEpochWrites);
  await native.commitAuthoritySuccessorEpoch(authorityEpochCommit);

  const close = {
    version: 1, kind: 'authority-close-proof', txId: request.txId, rootGenesisTxId: request.rootGenesisTxId,
    requestFingerprint: request.requestFingerprint, previousReceiptFingerprint: request.previousReceiptFingerprint,
    fenceGeneration: request.candidateFenceGeneration, previousBarrierGeneration: 1, barrierGeneration: 2,
    affectedScope: 'all', affectedMappingIds: [], affectedRouteFingerprints: [],
    readerInstanceId: null, readerStartNonce: null, retiredGrantFingerprint: null,
    retiredProjectionFingerprint: null, retiredAckFingerprint: null, admissionPhaseBefore: 'closed',
    admissionPhaseAfter: 'closed-drained', admissionDrained: true, outstandingRouteGrantCount: 0,
    routeDisposition: 'no-route', closeFingerprint: null,
  };
  close.closeFingerprint = recordHash(close, 'closeFingerprint');
  await native.writeAuthoritySuccessorClose(close);
  const baseline = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-successor-baseline', txId: request.txId, rootGenesisTxId: request.rootGenesisTxId,
    requestFingerprint: request.requestFingerprint, fenceGeneration: request.candidateFenceGeneration,
    anchorFingerprint: request.anchorFingerprint, operation: request.operation, targetState: request.targetState,
    revision: request.candidateRevision, authorityEpoch: request.candidateAuthorityEpoch,
    tokenConfigGeneration: request.candidateTokenConfigGeneration, tokenConfigHostSetFingerprint: hex,
    mappingGeneration: request.candidateMappingGeneration, candidateSnapshotFingerprint: request.candidateSnapshotFingerprint,
    candidateTargetFingerprint: request.candidateTargetFingerprint,
    attestationFingerprint: request.candidateAttestationFingerprint,
    authorityReservationFingerprint: authorityReservation.reservationFingerprint,
    authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
    closeFingerprint: close.closeFingerprint, fenceBindingFingerprint: null, leaseBindingFingerprint: null,
    readerProjectionFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  }, 'baselineFingerprint');
  await native.writeAuthoritySuccessorBaseline(baseline);

  const finality = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-successor-finality', sequence: request.sequence, txId: request.txId,
    rootGenesisTxId: request.rootGenesisTxId, requestFingerprint: request.requestFingerprint,
    fenceGeneration: request.candidateFenceGeneration, operation: request.operation,
    baselineFingerprint: baseline.baselineFingerprint, closeFingerprint: close.closeFingerprint,
    anchorFingerprint: request.anchorFingerprint,
    authorityReservationFingerprint: authorityReservation.reservationFingerprint,
    authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
    authorityEpochFingerprint: authorityEpochCommit.authorityEpochFingerprint,
    tokenFloorFingerprint: genesis.committed.floorFingerprint, attestationFingerprint: request.candidateAttestationFingerprint,
    publicationKFingerprint: 'b'.repeat(64), publicationYFingerprint: 'c'.repeat(64),
    operationEvidenceFingerprint: 'd'.repeat(64), auditEntryFingerprint: 'e'.repeat(64),
    targetFingerprint: request.candidateTargetFingerprint, targetIdentityFingerprint: 'f'.repeat(64),
    targetAclFingerprint: 'a'.repeat(64), wrapperFingerprint: 'b'.repeat(64),
    controlRootFingerprint: 'c'.repeat(64), revision: request.candidateRevision,
    authorityEpoch: request.candidateAuthorityEpoch, tokenConfigGeneration: request.candidateTokenConfigGeneration,
    mappingGeneration: request.candidateMappingGeneration, snapshotFingerprint: request.candidateSnapshotFingerprint,
    routeDisposition: 'no-route', finalityFingerprint: null,
  }, 'finalityFingerprint');
  const detachedFinality = buildAuthoritySuccessorRecord({
    ...finality, authorityEpochFingerprint: '0'.repeat(64),
  }, 'finalityFingerprint');
  const beforeDetachedFinality = new Map(files);
  const detachedFinalityWrites = calls.length;
  await assert.rejects(native.writeAuthoritySuccessorFinality(detachedFinality), /finality|epoch/);
  assert.deepEqual(files, beforeDetachedFinality);
  assert.equal(calls.length, detachedFinalityWrites);
  await native.writeAuthoritySuccessorFinality(finality);
});
test('rejects a skipped successor authority epoch with zero writes', async () => {
  const fixture = await committedGenesisFixture('successor-epoch-gap');
  const { files, calls, native, request: genesisRequest } = fixture;
  const state = await native.readManagementState();
  const retained = await native.readRetainedTargetProof();
  const genesisReceipt = JSON.parse(fileEnding(files, '/receipt.json'));
  const hex = 'f'.repeat(64);
  const request = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-successor-request', sequence: 2, txId: 'successor-epoch-gap',
    rootGenesisTxId: genesisRequest.genesisTxId, idempotencyKey: 'successor-epoch-gap-key',
    operation: 'tokens-attest', anchorFingerprint: genesisRequest.anchorFingerprint,
    actorPrincipalFingerprint: hex, previousReceiptFingerprint: genesisReceipt.receiptFingerprint,
    previousTargetFingerprint: retained.targetFingerprint, previousWrapperFingerprint: retained.wrapperFingerprint,
    previousRevision: state.revision, candidateRevision: state.revision + 1,
    previousAuthorityEpoch: state.authorityEpoch, candidateAuthorityEpoch: state.authorityEpoch + 1,
    previousTokenConfigGeneration: state.tokenConfigGeneration, candidateTokenConfigGeneration: state.tokenConfigGeneration + 1,
    previousAttestationFingerprint: state.tokenAttestation.attestationFingerprint, candidateAttestationFingerprint: hex,
    previousMappingGeneration: state.mappingGeneration, candidateMappingGeneration: state.mappingGeneration,
    previousSnapshotFingerprint: retained.snapshotFingerprint, candidateSnapshotFingerprint: hex,
    candidateTargetFingerprint: hex, previousFenceGeneration: state.fenceGeneration,
    candidateFenceGeneration: state.fenceGeneration + 1, mappingRecoveryTxFingerprint: null,
    targetState: retained.snapshot?.targetState ?? 'managed-empty', readerMode: 'no-reader',
    readerInstanceId: null, readerStartNonce: null, readerNonce: null, requestFingerprint: null,
  }, 'requestFingerprint');
  await native.writeAuthoritySuccessorRequest(request);
  const reservation = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-reservation', anchorFingerprint: request.anchorFingerprint,
    fenceGeneration: request.candidateFenceGeneration, txId: request.txId,
    epoch: request.candidateAuthorityEpoch, generation: request.candidateTokenConfigGeneration,
    candidateFingerprint: request.requestFingerprint,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
    reservationFingerprint: null,
  }, 'reservationFingerprint');
  await native.writeAuthoritySuccessorReservation(reservation);
  const commit = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-commit-snapshot', anchorFingerprint: request.anchorFingerprint,
    fenceGeneration: request.candidateFenceGeneration, txId: request.txId,
    epoch: request.candidateAuthorityEpoch, generation: request.candidateTokenConfigGeneration,
    candidateFingerprint: request.requestFingerprint, reservationFingerprint: reservation.reservationFingerprint,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
    authorityCommitSnapshotFingerprint: null,
  }, 'authorityCommitSnapshotFingerprint');
  await native.writeAuthoritySuccessorCommit(commit);
  const epoch = buildAuthoritySuccessorRecord({
    version: 1, kind: 'authority-epoch', anchorFingerprint: request.anchorFingerprint,
    fenceGeneration: request.candidateFenceGeneration, epoch: request.candidateAuthorityEpoch,
    reservationTxId: request.txId, commitTxId: request.txId,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
    authorityEpochFingerprint: null,
  }, 'authorityEpochFingerprint');
  const floorPath = [...files.keys()].find((path) => normalize(path).endsWith('/.gjc-remote-control/authority-epoch-floor.json'));
  const floor = JSON.parse(files.get(floorPath));
  floor.highestCommittedAuthorityEpoch = request.previousAuthorityEpoch - 1;
  floor.lastCommittedTxId = null;
  floor.floorFingerprint = recordHash(floor, 'floorFingerprint');
  files.set(floorPath, Buffer.from(canonicalJson(floor)));
  const before = new Map([...files.entries()].map(([path, bytes]) => [path, Buffer.from(bytes)]));
  const writes = calls.length;
  await assert.rejects(native.commitAuthoritySuccessorEpoch(epoch), /contiguous|committed floor/);
  assert.deepEqual(files, before);
  assert.equal(calls.length, writes);
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
test('generic writes clean verified replacement temps or refuse ambiguous cleanup', async () => {
  const phases = ['temp-verify', 'temp-flush', 'replace', 'post-replace'];
  for (const phase of phases) {
    const { files, lowLevel, roles } = fake();
    const configPath = 'C:/state/channels.json';
    const targetBytes = Buffer.from('{"legacy":true}');
    files.set(configPath, targetBytes);
    const native = createManagementNativeForTest({ lowLevel, configPath, roles });
    const genesis = records();
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
    const ownerPrincipal = { kind: 'sid', value: roles.managementSid };
    const ownerPrincipalKey = canonicalJsonHash(ownerPrincipal);
    const auth = {
      version: 1,
      ownerPrincipal,
      ownerPrincipalKey,
      credentials: {
        [ownerPrincipalKey]: {
          version: 1,
          principal: ownerPrincipal,
          kdf: { name: 'scrypt', N: 16384, r: 8, p: 1, keyLength: 32, saltBytes: 16 },
          salt: 'a'.repeat(32),
          hash: 'b'.repeat(64),
          epoch: 1,
          revoked: false,
        },
      },
    };
    const authPath = 'C:\\state\\.gjc-remote-control\\management-auth.json';
    files.set(authPath, Buffer.from(canonicalJson(auth)));
    const replacement = structuredClone(auth);
    replacement.credentials[ownerPrincipalKey].revoked = true;
    const originalIdentity = lowLevel.read_identity;
    const originalFlush = lowLevel.flush_file;
    const originalReplace = lowLevel.replace_existing_atomic;
    if (phase === 'temp-verify') {
      lowLevel.read_identity = async (path) =>
        path.includes('channels.json.tmp') ? null : originalIdentity(path);
    } else if (phase === 'temp-flush') {
      lowLevel.flush_file = async (path) => {
        if (path.includes('channels.json.tmp')) throw new Error('injected temp flush failure');
        return originalFlush(path);
      };
    } else if (phase === 'replace') {
      lowLevel.replace_existing_atomic = async () => { throw new Error('injected replace failure'); };
    } else {
      lowLevel.replace_existing_atomic = async (from, to) => {
        files.set(to, Buffer.from(files.get(from)));
        files.delete(from);
        throw new Error('injected post-rename replace failure');
      };
    }
    try {
      const expectedFingerprint = canonicalJsonHash(auth);
      await assert.rejects(
        native.compareAndSwapManagementAuth(expectedFingerprint, replacement),
        phase === 'temp-verify' || phase === 'post-replace'
          ? /temporary artifact cleanup is ambiguous/
          : /injected/,
      );
      const temporary = [...files.keys()].filter((path) => path.includes('channels.json.tmp'));
      assert.equal(temporary.length, phase === 'temp-verify' ? 1 : 0, phase);
      if (phase === 'post-replace') {
        assert.deepEqual(files.get(authPath), Buffer.from(canonicalJson(replacement)));
      }
    } finally {
      lowLevel.read_identity = originalIdentity;
      lowLevel.flush_file = originalFlush;
      lowLevel.replace_existing_atomic = originalReplace;
    }
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
test('rejects persisted management auth when principal objects and credential keys are not hash-bound', async () => {
  const { files, roles, lowLevel } = fake();
  const configPath = 'C:/state/channels.json';
  const native = createManagementNativeForTest({ lowLevel, configPath, roles });
  const ownerPrincipal = { kind: 'sid', value: roles.managementSid };
  const ownerKey = canonicalJsonHash(ownerPrincipal);
  const credential = {
    version: 1,
    principal: structuredClone(ownerPrincipal),
    kdf: { name: 'scrypt', N: 16384, r: 8, p: 1, keyLength: 32, saltBytes: 16 },
    salt: '0'.repeat(32),
    hash: '0'.repeat(64),
    epoch: 1,
    revoked: false,
  };
  const authPath = 'C:\\state\\.gjc-remote-control\\management-auth.json';
  const auth = {
    version: 1,
    ownerPrincipal: structuredClone(ownerPrincipal),
    ownerPrincipalKey: ownerKey,
    credentials: { [ownerKey]: credential },
  };
  files.set(authPath, Buffer.from(canonicalJson(auth)));
  assert.deepEqual(await native.readManagementAuth(), auth);

  const ownerKeyMismatch = { ...auth, ownerPrincipalKey: canonicalJsonHash({ kind: 'sid', value: roles.botSid }) };
  files.set(authPath, Buffer.from(canonicalJson(ownerKeyMismatch)));
  await assert.rejects(native.readManagementAuth, /management auth record is invalid/);

  const credentialPrincipalMismatch = structuredClone(auth);
  credentialPrincipalMismatch.credentials[ownerKey].principal = { kind: 'sid', value: roles.botSid };
  files.set(authPath, Buffer.from(canonicalJson(credentialPrincipalMismatch)));
  await assert.rejects(native.readManagementAuth, /management auth record is invalid/);
});
test('identical immutable authority replay rechecks the captured config parent before writing', async () => {
  const fixture = await committedGenesisFixture('immutable-parent-replay');
  const authorityRequestPath = [...fixture.files.keys()].find((path) =>
    normalize(path).endsWith('/genesis-authority-request.json'));
  const authorityRequest = JSON.parse(fixture.files.get(authorityRequestPath));
  const replayStart = fixture.calls.length;
  await fixture.native.writeGenesisAuthorityRequest(authorityRequest);
  assert.equal(fixture.calls.length, replayStart);
  const originalParent = fixture.lowLevel.open_verified_parent;
  fixture.lowLevel.open_verified_parent = async (path) => {
    const identity = await originalParent(path);
    if (normalize(path).endsWith('/channels.json')) return { ...identity, path: 'C:/state/foreign-parent' };
    return identity;
  };
  const before = new Map([...fixture.files.entries()].map(([path, bytes]) => [path, Buffer.from(bytes)]));
  const writes = fixture.calls.length;
  await assert.rejects(
    fixture.native.writeGenesisAuthorityRequest(authorityRequest),
    /config parent identity changed/,
  );
  assert.equal(fixture.calls.length, writes);
  assert.deepEqual(fixture.files, before);
});
