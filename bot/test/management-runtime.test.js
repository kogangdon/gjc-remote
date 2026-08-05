import assert from 'node:assert/strict';
import test from 'node:test';
import { ManagementRuntime } from '../src/management-runtime.js';
import { createManagementNativeForTest } from '../../native-control/test/helpers/management-native.js';
import { validateManagedProof } from '../src/managed-authority-reader.js';
import { createTestManagedAuthorityReader } from './helpers/managed-authority-reader.js';
import { buildAdmissionAck } from '../../shared/admission-envelope.js';
import { canonicalJson, canonicalJsonHash } from '../../shared/strict-json.js';
import { fingerprintManagedMappingRecord, fingerprintManagedRouteRecord, managedHostSetFingerprint } from '../../shared/mapping-envelope.js';
import { buildAuthoritySuccessorRecord } from '../../shared/successor-envelope.js';

const owner = { kind: 'sid', value: 'S-1-5-21-100' };
const target = { kind: 'sid', value: 'S-1-5-21-103' };
const botPrincipal = { kind: 'sid', value: 'S-1-5-21-101' };
const recoveryPrincipal = { kind: 'sid', value: 'S-1-5-21-102' };
const roles = { managementSid: owner.value, botSid: botPrincipal.value, recoverySid: recoveryPrincipal.value, systemSid: 'S-1-5-18' };
const provisioning = {
  management: 'a'.repeat(64),
  bot: 'b'.repeat(64),
  recovery: 'c'.repeat(64),
};
const secret = 'owner-secret-is-long-enough';
const fileEnding = (files, ending) => [...files.entries()].find(([path]) => path.replaceAll("\\", "/").endsWith(ending))?.[1];
const genesisInput = (hostTokens) => ({
  actorPrincipal: owner, targetPrincipal: target, botPrincipal, recoveryPrincipal,
  managementProvisioningFingerprint: provisioning.management,
  botProvisioningFingerprint: provisioning.bot,
  recoveryProvisioningFingerprint: provisioning.recovery,
  actorSecret: secret, idempotencyKey: 'one', hostTokens,
});
function adapter({ legacy = true, failAudit = false, roleBindings = roles, initialPrincipal = owner, platform } = {}) {
  const files = new Map();
  if (legacy) files.set('C:/state/channels.json', Buffer.from('{"legacy":true}'));
  const writes = [];
  const payloads = [];
  let currentPrincipal = initialPrincipal;
  const lowLevel = {
    open_verified_parent: async (path) => ({ path: path.replaceAll("\\", "/").slice(0, path.replaceAll("\\", "/").lastIndexOf('/')) }), open_no_follow: async () => {},
    read_identity: async (path) => path.endsWith('.genesis-bootstrap-blocker') && !files.has(path) ? null : ({ path: path.replaceAll("\\", "/"), owner: roleBindings.managementSid }), read_acl: async () => 'protected:M,B,R,SYSTEM',
    path_exists_no_follow: async (path) => files.has(path) || [...files.keys()].some((name) => name.replaceAll("\\", "/").startsWith(`${path.replaceAll("\\", "/")}/`)),
    verify_exact_role_acl: async () => true, set_exact_role_acl: async () => {}, remove_verified_file: async (path) => { files.delete(path); },
    open_verified_parent_handle: async (path) => ({ path: path.replaceAll("\\", "/").slice(0, path.replaceAll("\\", "/").lastIndexOf('/')) }),
    open_verified_object_handle: async (parent, name) => {
      const normalized = `${parent.path}/${name}`;
      const path = [...files.keys()].find((candidate) => candidate.replaceAll("\\", "/") === normalized);
      return path ? { path: normalized, storagePath: path } : null;
    },
    read_handle_identity: async (handle) => ({ path: handle.path, owner: roleBindings.managementSid }),
    read_handle_bytes: async (handle) => Buffer.from(files.get(handle.storagePath ?? handle.path)),
    write_handle_bytes: async (handle, bytes) => {
      const storagePath = handle.storagePath ?? handle.path;
      if (!files.has(storagePath)) throw new Error('missing handle');
      files.set(storagePath, Buffer.from(bytes));
    },
    remove_verified_handle: async (handle, expected) => {
      const storagePath = handle.storagePath ?? handle.path;
      assert.deepEqual(files.get(storagePath), Buffer.from(expected));
      files.delete(storagePath);
    },
    flush_file: async () => {}, flush_directory_or_volume: async () => {},
    ensure_control_directory: async () => {},
    read_verified_bytes: async (path) => files.has(path) ? Buffer.from(files.get(path)) : null,
    create_absent_exclusive: async (path, bytes) => {
      if (failAudit && path.replaceAll("\\", "/").endsWith('/audit.json')) throw new Error('AUDIT_WRITE_FAILED');
      files.set(path, Buffer.from(bytes)); writes.push(path); payloads.push([path, Buffer.from(bytes)]);
    },
    create_exclusive_temp: async (_dir, prefix, bytes) => {
      const path = `${_dir}/${prefix}.${writes.length}`;
      files.set(path, Buffer.from(bytes));
      return path;
    },
    replace_existing_atomic: async (from, to) => { files.set(to, files.get(from)); files.delete(from); writes.push(to); payloads.push([to, Buffer.from(files.get(to))]); },
    acquire_native_lock: async () => ({ release: async () => {} }),
    current_os_principal: async () => currentPrincipal,
    principal_access_check: async (_path, _kind, principal, mode) =>
      mode === 'read' || (mode === 'write' && principal === roleBindings.managementSid),
  };
  const baseNative = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles: roleBindings, platform });
  const native = { ...baseNative };
  return { files, writes, payloads, setPrincipal: (value) => { currentPrincipal = value; }, native };
}
async function boundReaderRuntime() {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = {
    ...genesisInput('host=secret'),
    requestedReaderMode: 'handshake',
    readerInstanceId: 'reader-1',
    readerStartNonce: 'reader-start-1',
  };
  const pending = await runtime.execute('genesis', input);
  assert.equal(pending.pending, true, JSON.stringify(pending));
  const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
  const floor = JSON.parse(fileEnding(harness.files, '/reader-version-floor.json'));
  const zFinality = JSON.parse(fileEnding(harness.files, '/z-finality.json'));
  const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
  const fence = JSON.parse(fileEnding(harness.files, '/reader-fence-binding.json'));
  const lease = {
    version: 1, kind: 'reader-lease-binding', anchorFingerprint: request.anchorFingerprint,
    genesisTxId: request.genesisTxId, readerInstanceId: floor.firstReaderInstanceId,
    readerStartNonce: floor.firstReaderStartNonce, readerVersion: 2,
    fenceBindingFingerprint: fence.fenceBindingFingerprint, leaseBindingFingerprint: null,
  };
  lease.leaseBindingFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(lease).filter(([key]) => key !== 'leaseBindingFingerprint')),
  );
  const projection = {
    version: 1, kind: 'reader-projection', anchorFingerprint: request.anchorFingerprint,
    genesisTxId: request.genesisTxId, generation: request.generation,
    readerInstanceId: floor.firstReaderInstanceId, readerStartNonce: floor.firstReaderStartNonce,
    readerVersion: 2, fenceBindingFingerprint: fence.fenceBindingFingerprint,
    leaseBindingFingerprint: lease.leaseBindingFingerprint, zFinalityFingerprint: zFinality.zFinalityFingerprint,
    readerProjectionFingerprint: null,
  };
  projection.readerProjectionFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(projection).filter(([key]) => key !== 'readerProjectionFingerprint')),
  );
  const readerState = {
    attestationFingerprint: request.attestationFingerprint,
    authorityReservationFingerprint: JSON.parse(fileEnding(harness.files, '/authority-commit.json')).reservationFingerprint,
    authorityCommitSnapshotFingerprint: JSON.parse(fileEnding(harness.files, '/authority-commit.json')).authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: fence.fenceBindingFingerprint,
    leaseBindingFingerprint: lease.leaseBindingFingerprint,
    readerProjectionFingerprint: projection.readerProjectionFingerprint,
    readerInstanceId: request.readerInstanceId,
    readerStartNonce: request.readerStartNonce,
    readerVersion: 2,
  };
  harness.setPrincipal(botPrincipal);
  await harness.native.acquireBotLease(lease);
  await harness.native.writeBotReaderProjection(projection);
  await harness.native.writeBotReaderState(readerState);
  assert.ok(fileEnding(harness.files, '/bot-state/reader-state.json'));
  await harness.native.writeBotAcknowledgement(buildAdmissionAck(grant, projection.readerProjectionFingerprint));
  assert.ok(fileEnding(harness.files, '/bot-state/reader-state.json'));
  assert.ok((await harness.native.readBoundReaderProof()).readerState);
  harness.setPrincipal(owner);
  const completed = await runtime.execute('genesis', input);
  assert.ok(fileEnding(harness.files, '/bot-state/reader-state.json'));
  assert.equal(completed.recovered, true, JSON.stringify(completed));
  harness.setPrincipal(botPrincipal);
  const snapshot = await harness.native.readManagedMappingSnapshot();
  assert.equal(JSON.parse(snapshot.wrapperBytes).readerVersion, 2);
  assert.equal(
    JSON.parse(snapshot.controlRootBytes).readerVersionFloorFingerprint,
    JSON.parse(snapshot.readerVersionFloorBytes).floorFingerprint,
  );
  assert.doesNotThrow(() => validateManagedProof(snapshot, managedHostSetFingerprint('host=secret')));
  return { ...harness, runtime };
}

function mappingInput(mappingId, generation = 1) {
  const mapping = fingerprintManagedMappingRecord({
    mappingId, hostId: 'host', mappingGeneration: generation, mappingVersion: 1,
    sourcePlatform: 'posix', workspaceId: 'workspace-a', workDir: null,
    sourceRoot: '/source', containerRoot: '/workspace', volumeIdentity: 'volume-a',
    casePolicy: 'sensitive', immutableDefault: false, mappingFingerprint: null,
  });
  const route = fingerprintManagedRouteRecord({
    channelId: '123', hostId: mapping.hostId, mappingId: mapping.mappingId,
    mappingGeneration: mapping.mappingGeneration, mappingVersion: mapping.mappingVersion,
    sourcePlatform: mapping.sourcePlatform, workspaceId: mapping.workspaceId,
    workDir: mapping.workDir, routeFingerprint: null,
  }, mapping);
  return { mapping, routes: [route] };
}
async function failClosedSuccessorFailure(method, stage) {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old-secret'))).ok, true);
  const original = harness.native[method].bind(harness.native);
  harness.native[method] = async (...args) => {
    await original(...args);
    throw new Error(`INJECTED_${stage}`);
  };
  const before = await harness.native.readManagementState();
  const candidate = mappingInput(`failure-${stage}`);
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: `failure-${stage}`,
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: before.revision, expectedFingerprint: null,
  });
  assert.equal(result.ok, false, JSON.stringify({ stage, result }));
  assert.equal(result.routeDisposition, 'no-route');
  assert.equal(Object.hasOwn(result, 'txId'), false);
  assert.equal(result.error, 'MANUAL_CLEANUP_REQUIRED');
  const state = await harness.native.readManagementState();
  assert.equal(state.recovery.phase, 'manual_cleanup');
  assert.equal(state.recovery.routeDisposition, 'no-route');
  assert.equal(state.admission.phase, 'closed');
  assert.match(state.recovery.txId, /^successor-[a-f0-9]{64}$/);
  const request = JSON.parse(fileEnding(harness.files, `/authority-successor-request-${state.recovery.txId}.json`));
  assert.equal(request.requestFingerprint, state.recovery.requestFingerprint);
  const cleanup = JSON.parse(fileEnding(harness.files, '/terminal-close.json'));
  assert.equal(cleanup.txId, state.recovery.txId);
  assert.equal(cleanup.routeDisposition, 'no-route');
  assert.equal(cleanup.blockedUntilOwnerAction, true);
  const persisted = [...harness.files.values()].map((bytes) => bytes.toString()).join('\n');
  assert.equal(persisted.includes('old-secret'), false);
  assert.equal(persisted.includes('later-secret'), false);
  const blocked = await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: `blocked-${stage}`, hostTokens: 'host=later-secret',
  });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.error, 'RECOVERY_REQUIRED');
  assert.equal(blocked.routeDisposition, 'no-route');
}
test('successor writes fail closed across request, head, publication, finality, and audit stages', async () => {
  for (const [method, stage] of [
    ['writeAuthoritySuccessorRequest', 'REQUEST'],
    ['writeAuthoritySuccessorHead', 'HEAD'],
    ['publishMapping', 'PUBLICATION'],
    ['writeAuthoritySuccessorFinality', 'FINALITY'],
    ['appendAudit', 'AUDIT'],
  ]) {
    await failClosedSuccessorFailure(method, stage);
  }
});
test('real management adapter receives canonical secret-free genesis records in order', async () => {
  const { native, files, writes } = adapter(); const runtime = new ManagementRuntime({ native });
  const result = await runtime.execute('genesis', genesisInput('b=secret-b\na=secret-a'));
  assert.equal(result.ok, true, JSON.stringify(result)); const root = 'C:/state/.gjc-remote-control/';
  const attestation = JSON.parse(fileEnding(files, '/attestation.json')); const floor = JSON.parse(fileEnding(files, '/token-floor.json'));
  assert.equal(attestation.kind, 'token-config-attestation'); assert.equal(floor.kind, 'token-generation-floor'); assert.equal(floor.highestCommittedGeneration, 1);
  assert.equal(attestation.tokenConfigHostSetFingerprint, managedHostSetFingerprint('a=different-secret\nb=another-secret'));
  const genesisRequestWrite = writes.findIndex((p) => p.endsWith('genesis-request.json'));
  const tokenReservationWrite = writes.findIndex((p) => p.includes('token-floor-reservation-'));
  const attestationWrite = writes.findIndex((p) => p.endsWith('attestation.json'));
  const targetPublicationWrite = writes.findIndex((p) => p.endsWith('legacy-retained.json'));
  const authorityReservationWrite = writes.findIndex((p) => p.includes('authority-reservation-'));
  const authorityCommitWrite = writes.findIndex((p) => p.includes('authority-commit-'));
  const authorityBaselineWrite = writes.findIndex((p) => p.includes('authority-baseline-'));
  const publicationGraphWrite = writes.findIndex((p) => p.includes('publication-u-'));
  assert.ok(genesisRequestWrite < tokenReservationWrite);
  assert.ok(tokenReservationWrite < attestationWrite);
  assert.ok(attestationWrite < targetPublicationWrite);
  assert.ok(targetPublicationWrite < authorityReservationWrite);
  assert.ok(authorityReservationWrite < authorityCommitWrite);
  assert.ok(authorityCommitWrite < authorityBaselineWrite);
  assert.ok(authorityBaselineWrite < publicationGraphWrite);
  assert.ok(targetPublicationWrite < writes.findLastIndex((p) => p.endsWith('token-floor.json')));
  assert.equal([...files.values()].some((bytes) => bytes.includes(Buffer.from('secret-a')) || bytes.includes(Buffer.from('secret-b'))), false);
});
test('final same-lock recheck rejects publication-graph drift and persists no-route cleanup', async () => {
  const harness = adapter({ legacy: false });
  const writeReceipt = harness.native.writeGenesisReceipt.bind(harness.native);
  const native = {
    ...harness.native,
    async writeGenesisReceipt(receipt) {
      await writeReceipt(receipt);
      const publicationY = [...harness.files.keys()].find((path) =>
        path.replaceAll("\\", "/").includes('/.gjc-remote-control/publication-y-'));
      harness.files.set(publicationY, Buffer.from('{}'));
    },
  };
  const result = await new ManagementRuntime({ native }).execute(
    'genesis',
    genesisInput('host=secret'),
  );
  assert.equal(result.ok, false);
  assert.equal(result.routeDisposition, 'no-route');
  assert.equal((await harness.native.readManagementState()).recovery.phase, 'manual_cleanup');
});
test('Genesis suffix recovery reconstructs the exact authority receipt before terminal recovery records', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = genesisInput('host=secret');
  assert.equal((await runtime.execute('genesis', input)).ok, true);
  const statePath = [...harness.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/management-state.json'));
  const state = JSON.parse(harness.files.get(statePath));
  state.genesis = null;
  state.recovery.phase = 'replaced';
  harness.files.set(statePath, Buffer.from(canonicalJson(state)));
  for (const path of [...harness.files.keys()]) {
    if (path.replaceAll('\\', '/').includes('/genesis-authority-receipt')) harness.files.delete(path);
  }

  const recovered = await runtime.execute('genesis', input);

  assert.equal(recovered.ok, true, JSON.stringify(recovered));
  assert.equal(recovered.recovered, true);
  const receipt = JSON.parse(fileEnding(harness.files, '/genesis-authority-receipt.json'));
  const immutableReceipt = JSON.parse([...harness.files.entries()].find(([path]) =>
    path.replaceAll('\\', '/').includes('/genesis-authority-receipt-'))[1]);
  assert.deepEqual(immutableReceipt, receipt);
  assert.ok(fileEnding(harness.files, '/genesis-suffix-recovery.json'));
});
test('legacy-retained Genesis refuses a bound-reader handshake', async () => {
  const runtime = new ManagementRuntime({ native: adapter().native });
  const result = await runtime.execute('genesis', {
    ...genesisInput('host=secret'),
    requestedReaderMode: 'handshake',
    readerInstanceId: 'reader-1',
    readerStartNonce: 'reader-start-1',
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'LEGACY_READER_HANDSHAKE_REFUSED');
  assert.equal(result.routeDisposition, 'no-route');
});
test('bound-reader Genesis resumes only after exact B projection and acknowledgement', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = {
    ...genesisInput('host=secret'),
    requestedReaderMode: 'handshake',
    readerInstanceId: 'reader-1',
    readerStartNonce: 'reader-start-1',
  };

  const pending = await runtime.execute('genesis', input);
  assert.equal(pending.ok, true, JSON.stringify(pending));
  assert.equal(pending.pending, true);
  assert.equal(pending.routeDisposition, 'no-route');

  const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
  const floor = JSON.parse(fileEnding(harness.files, '/reader-version-floor.json'));
  const tokenFloor = JSON.parse(fileEnding(harness.files, '/token-floor.json'));
  const zFinality = JSON.parse(fileEnding(harness.files, '/z-finality.json'));
  const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
  const fence = JSON.parse(fileEnding(harness.files, '/reader-fence-binding.json'));
  const lease = {
    version: 1,
    kind: 'reader-lease-binding',
    anchorFingerprint: request.anchorFingerprint,
    genesisTxId: request.genesisTxId,
    readerInstanceId: floor.firstReaderInstanceId,
    readerStartNonce: floor.firstReaderStartNonce,
    readerVersion: 2,
    fenceBindingFingerprint: fence.fenceBindingFingerprint,
    leaseBindingFingerprint: null,
  };
  lease.leaseBindingFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(lease).filter(([key]) => key !== 'leaseBindingFingerprint')),
  );
  const projection = {
    version: 1,
    kind: 'reader-projection',
    anchorFingerprint: request.anchorFingerprint,
    genesisTxId: request.genesisTxId,
    generation: request.generation,
    readerInstanceId: floor.firstReaderInstanceId,
    readerStartNonce: floor.firstReaderStartNonce,
    readerVersion: 2,
    fenceBindingFingerprint: fence.fenceBindingFingerprint,
    leaseBindingFingerprint: lease.leaseBindingFingerprint,
    zFinalityFingerprint: zFinality.zFinalityFingerprint,
    readerProjectionFingerprint: null,
  };
  projection.readerProjectionFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(projection).filter(([key]) => key !== 'readerProjectionFingerprint')),
  );
  const readerState = {
    attestationFingerprint: request.attestationFingerprint,
    authorityReservationFingerprint: JSON.parse(fileEnding(harness.files, '/authority-commit.json')).reservationFingerprint,
    authorityCommitSnapshotFingerprint: JSON.parse(fileEnding(harness.files, '/authority-commit.json')).authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: fence.fenceBindingFingerprint,
    leaseBindingFingerprint: lease.leaseBindingFingerprint,
    readerProjectionFingerprint: projection.readerProjectionFingerprint,
    readerInstanceId: request.readerInstanceId,
    readerStartNonce: request.readerStartNonce,
    readerVersion: 2,
  };

  harness.setPrincipal(botPrincipal);
  await harness.native.acquireBotLease(lease);
  await harness.native.writeBotReaderProjection(projection);
  await harness.native.writeBotReaderState(readerState);
  await harness.native.writeBotAcknowledgement(buildAdmissionAck(grant, projection.readerProjectionFingerprint));
  harness.setPrincipal(owner);

  const completed = await runtime.execute('genesis', input);
  assert.equal(completed.ok, true, JSON.stringify(completed));
  assert.equal(completed.recovered, true);
  assert.equal(completed.routeDisposition, 'no-route');
  assert.equal((await harness.native.readManagementState()).recovery.phase, 'terminal');
  assert.equal(tokenFloor.highestCommittedGeneration, request.generation);
  const grantPath = [...harness.files.keys()].find((path) => path.replaceAll("\\", "/").endsWith('/admission-grant.json'));
  const proofPath = [...harness.files.keys()].find((path) => path.replaceAll("\\", "/").endsWith('/rvf.json'));
  const proof = JSON.parse(harness.files.get(proofPath));
  const proofBefore = Buffer.from(harness.files.get(proofPath));
  const foreignGrant = { ...grant, readerInstanceId: 'foreign-reader', grantFingerprint: null };
  foreignGrant.grantFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(foreignGrant).filter(([key]) => key !== 'grantFingerprint')),
  );
  harness.files.set(grantPath, Buffer.from(canonicalJson(foreignGrant)));
  await assert.rejects(harness.native.writeFinalityProof(proof), /complete bound-reader finality graph/);
  assert.deepEqual(harness.files.get(proofPath), proofBefore);
});
test('Genesis accepts exact POSIX UID role bindings', async () => {
  const uidOwner = { kind: 'uid', value: 'uid:1000' };
  const uidBot = { kind: 'uid', value: 'uid:1001' };
  const uidRecovery = { kind: 'uid', value: 'uid:1002' };
  const uidTarget = { kind: 'uid', value: 'uid:1003' };
  const roleBindings = {
    managementSid: uidOwner.value,
    botSid: uidBot.value,
    recoverySid: uidRecovery.value,
    systemSid: 'uid:0',
  };
  const { native } = adapter({
    legacy: false,
    roleBindings,
    initialPrincipal: uidOwner,
    platform: 'linux',
  });
  const result = await new ManagementRuntime({ native }).execute('genesis', {
    actorPrincipal: uidOwner,
    targetPrincipal: uidTarget,
    botPrincipal: uidBot,
    recoveryPrincipal: uidRecovery,
    managementProvisioningFingerprint: provisioning.management,
    botProvisioningFingerprint: provisioning.bot,
    recoveryProvisioningFingerprint: provisioning.recovery,
    actorSecret: secret,
    idempotencyKey: 'posix-one',
    hostTokens: 'host=secret',
  });
  assert.equal(result.ok, true, JSON.stringify(result));
});
test('tokens-attest creates successor authority rather than lifecycle refusal', async () => {
  const { native } = adapter();
  const runtime = new ManagementRuntime({ native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  const result = await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, hostTokens: 'other=new', idempotencyKey: 'token-g-plus-one',
  });
  assert.notEqual(result.error, 'TOKEN_LIFECYCLE_UNAVAILABLE');
  assert.equal(result.routeDisposition, 'no-route');
});
test('mapping reconcile creates successor authority rather than lifecycle refusal', async () => {
  const { native } = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  const beforeState = await native.readManagementState();
  const candidate = mappingInput('workspace-map');
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'mapping-successor',
    mappingId: candidate.mapping.mappingId, ...candidate, expectedRevision: beforeState.revision, expectedFingerprint: null,
  });
  assert.notEqual(result.error, 'MAPPING_LIFECYCLE_UNAVAILABLE');
  assert.equal(result.routeDisposition, 'no-route');
});
test('no-reader mapping successors reach the terminal graph with exact lineage and replay through recovery', async () => {
  const { native, files } = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  const beforeState = await native.readManagementState();
  const genesisMarker = await native.readManagedHistoryMarker();
  const candidate = mappingInput('workspace-map');
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'mapping-successor-terminal',
    mappingId: candidate.mapping.mappingId, ...candidate, expectedRevision: beforeState.revision, expectedFingerprint: null,
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.pending, false);
  assert.equal(result.routeDisposition, 'no-route');
  const request = JSON.parse(fileEnding(files, `/authority-successor-request-${result.txId}.json`));
  const close = JSON.parse(fileEnding(files, `/authority-close-proof-${result.txId}.json`));
  const finality = JSON.parse(fileEnding(files, `/authority-successor-finality-${result.txId}.json`));
  const receipt = JSON.parse(fileEnding(files, `/authority-successor-receipt-${result.txId}.json`));
  assert.equal(request.readerMode, 'no-reader');
  assert.equal(request.readerInstanceId, null);
  assert.equal(request.readerStartNonce, null);
  assert.equal(request.readerNonce, null);
  assert.equal(request.candidateMappingGeneration, beforeState.mappingGeneration + 1);
  assert.equal(close.readerInstanceId, null);
  assert.equal(close.readerStartNonce, null);
  assert.equal(close.routeDisposition, 'no-route');
  assert.equal(finality.mappingGeneration, request.candidateMappingGeneration);
  assert.equal(finality.routeDisposition, 'no-route');
  assert.equal(receipt.readerMode, 'no-reader');
  assert.equal(receipt.leaseBindingFingerprint, null);
  assert.equal(receipt.readerProjectionFingerprint, null);
  assert.equal(receipt.ackFingerprint, null);
  const head = JSON.parse(fileEnding(files, '/authority-head.json'));
  assert.equal(head.phase, 'terminal');
  assert.equal(head.finalityFingerprint, finality.finalityFingerprint);
  const marker = await native.readManagedHistoryMarker();
  assert.equal(marker.sequence, genesisMarker.sequence + 1);
  assert.equal(marker.previousMarkerFingerprint, genesisMarker.markerFingerprint);
  const replay = await runtime.execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'mapping-successor-terminal',
  });
  assert.equal(replay.ok, true, JSON.stringify(replay));
  assert.equal(replay.idempotent, true);
  assert.equal(replay.phase, 'terminal');
});
test('a post-publication audit failure persists manual cleanup and blocks later management commands', async () => {
  const { native } = adapter({ failAudit: true });
  const runtime = new ManagementRuntime({ native });
  const result = await runtime.execute('genesis', genesisInput('host=secret'));
  assert.equal(result.ok, false);
  assert.equal(result.error, 'MANUAL_CLEANUP_REQUIRED');
  const state = await native.readManagementState();
  assert.equal(state.recovery.phase, 'manual_cleanup');
  assert.equal((await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, hostTokens: 'other=secret',
  })).error, 'RECOVERY_REQUIRED');
});
test('bound successors bind exact candidates, require fresh B proof, and roll forward', async () => {
  const { native, files, runtime, setPrincipal } = await boundReaderRuntime();
  setPrincipal(owner);
  const beforeState = await native.readManagementState();
  const candidate = mappingInput('workspace-map');

  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'bound-mapping-successor',
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: beforeState.revision, expectedFingerprint: null,
  });

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.pending, true);
  assert.equal(result.phase, 'reader-pending');
  assert.equal(result.routeDisposition, 'no-route');
  const head = JSON.parse(fileEnding(files, '/authority-head.json'));
  assert.equal(head.phase, 'reader-pending');
  assert.equal(head.txId, result.txId);
  assert.deepEqual(await native.readManagementState(), beforeState);
  setPrincipal(botPrincipal);
  const reader = await createTestManagedAuthorityReader({
    configPath: 'C:/state/channels.json',
    expectedHostSetFingerprint: managedHostSetFingerprint('host=secret'),
    roleBindings: roles,
    native,
  });
  const pendingSnapshot = await reader.readSnapshot();
  assert.equal(pendingSnapshot.code, 'MANAGED_AUTHORITY_PENDING');

  setPrincipal(owner);
  const completed = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'bound-mapping-successor',
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: beforeState.revision, expectedFingerprint: null,
  });
  assert.equal(completed.ok, true, JSON.stringify(completed));
  assert.equal(completed.pending, false);
  assert.equal(completed.routeDisposition, 'no-route');
  assert.equal(JSON.parse(fileEnding(files, '/authority-head.json')).phase, 'terminal');
  const mappingFinality = JSON.parse(fileEnding(files, `/authority-successor-finality-${result.txId}.json`));
  const publishedMapping = JSON.parse(files.get('C:/state/channels.json'));
  assert.equal(publishedMapping.revision, mappingFinality.revision);
  assert.equal(publishedMapping.authorityEpoch, mappingFinality.authorityEpoch);
  assert.equal(publishedMapping.mappingGeneration, mappingFinality.mappingGeneration);

  const afterMapping = await native.readManagementState();
  const tokenPending = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    hostTokens: 'host=rotated-secret',
    idempotencyKey: 'bound-token-successor',
  });
  assert.equal(tokenPending.ok, true, JSON.stringify(tokenPending));
  assert.equal(tokenPending.pending, true);
  assert.equal(tokenPending.phase, 'reader-pending');
  assert.deepEqual(await native.readManagementState(), afterMapping);

  setPrincipal(botPrincipal);
  assert.equal((await reader.readSnapshot()).code, 'MANAGED_AUTHORITY_PENDING');
  setPrincipal(owner);
  const tokenCompleted = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    hostTokens: 'host=rotated-secret',
    idempotencyKey: 'bound-token-successor',
  });
  assert.equal(tokenCompleted.ok, true, JSON.stringify(tokenCompleted));
  assert.equal(tokenCompleted.pending, false);
  const terminalHead = JSON.parse(fileEnding(files, '/authority-head.json'));
  assert.equal(terminalHead.phase, 'terminal');
  assert.equal(terminalHead.sequence, 3);
  const afterToken = await native.readManagementState();
  assert.equal(afterToken.tokenConfigGeneration, afterMapping.tokenConfigGeneration + 1);
  assert.equal(afterToken.mappingGeneration, afterMapping.mappingGeneration);
});
test('a second ManagementRuntime adopts only the same stable genesis probe tuple', async () => {
  const harness = adapter();
  const first = new ManagementRuntime({ native: harness.native });
  const input = genesisInput('host=secret');
  const original = harness.native.writeGenesisAuthorityRequest.bind(harness.native);
  const originalTerminal = harness.native.terminalCloseOrManualCleanup.bind(harness.native);
  let crash = true;
  harness.native.writeGenesisAuthorityRequest = async (record) => {
    await original(record);
    if (crash) {
      throw new Error('SIMULATED_PROCESS_CRASH_AFTER_GP');
    }
  };
  harness.native.terminalCloseOrManualCleanup = async (...args) => {
    if (crash) {
      crash = false;
      throw new Error('SIMULATED_PROCESS_CRASH_AFTER_GP');
    }
    return originalTerminal(...args);
  };

  const interrupted = await first.execute('genesis', input);
  harness.native.writeGenesisAuthorityRequest = original;
  harness.native.terminalCloseOrManualCleanup = originalTerminal;
  const adopted = await new ManagementRuntime({ native: harness.native }).execute('genesis', input);

  assert.equal(interrupted.ok, false);
  assert.equal(adopted.ok, true, JSON.stringify(adopted));
  assert.equal(adopted.genesisTxId, (await harness.native.readManagementState()).genesis.txId);
});
test('Genesis security tuple rejects each stale intent field before terminal replay adoption', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = genesisInput('host=secret');
  const completed = await runtime.execute('genesis', input);
  assert.equal(completed.ok, true, JSON.stringify(completed));

  const state = await harness.native.readManagementState();
  const tuple = state.genesis.genesisSecurityTuple;
  assert.equal(tuple.anchorFingerprint, await harness.native.managementAnchorFingerprint());
  assert.equal(tuple.generation, 1);
  assert.equal(tuple.requestedReaderMode, 'no-reader');
  assert.equal(tuple.readerInstanceId, null);
  assert.equal(tuple.readerStartNonce, null);

  const changed = [
    { actorPrincipal: { kind: 'sid', value: 'S-1-5-21-107' } },
    { targetPrincipal: { kind: 'sid', value: 'S-1-5-21-104' } },
    { botPrincipal: { kind: 'sid', value: 'S-1-5-21-105' } },
    { recoveryPrincipal: { kind: 'sid', value: 'S-1-5-21-106' } },
    { managementProvisioningFingerprint: 'd'.repeat(64) },
    { botProvisioningFingerprint: 'e'.repeat(64) },
    { recoveryProvisioningFingerprint: 'f'.repeat(64) },
    { hostTokens: 'other=secret' },
    { idempotencyKey: 'different-idempotency-key' },
    { requestedReaderMode: 'handshake', readerInstanceId: 'reader-2', readerStartNonce: 'reader-start-2' },
  ];
  for (const change of changed) {
    const result = await runtime.execute('genesis', { ...input, ...change });
    assert.equal(result.ok, false, JSON.stringify({ change, result }));
  }

  const originalAnchor = harness.native.managementAnchorFingerprint.bind(harness.native);
  harness.native.managementAnchorFingerprint = async () => '0'.repeat(64);
  const staleAnchor = await runtime.execute('genesis', input);
  harness.native.managementAnchorFingerprint = originalAnchor;
  assert.equal(staleAnchor.ok, false, JSON.stringify(staleAnchor));
});
test('a stale genesis probe blocker is never adopted by an inferred tuple', async () => {
  const harness = adapter();
  let crash = true;
  const native = {
    ...harness.native,
    async writeGenesisAuthorityRequest() {
      if (crash) {
        crash = false;
        throw new Error('SIMULATED_CRASH');
      }
    },
  };

  const first = await new ManagementRuntime({ native }).execute('genesis', genesisInput('host=secret'));
  const stale = await new ManagementRuntime({ native }).execute('genesis', {
    ...genesisInput('host=secret'),
    idempotencyKey: 'different-idempotency-key',
  });

  assert.equal(first.ok, false);
  assert.equal(stale.ok, false);
  assert.equal(stale.routeDisposition, 'no-route');
});

test('recovered no-reader Genesis creates a terminal one-step token successor', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = genesisInput('host=secret');
  assert.equal((await runtime.execute('genesis', input)).ok, true);

  const statePath = [...harness.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/management-state.json'));
  const interrupted = JSON.parse(harness.files.get(statePath));
  interrupted.genesis = null;
  interrupted.recovery.phase = 'replaced';
  harness.files.set(statePath, Buffer.from(canonicalJson(interrupted)));
  for (const path of [...harness.files.keys()]) {
    if (path.replaceAll('\\', '/').includes('/genesis-authority-receipt')) harness.files.delete(path);
  }

  const recovered = await runtime.execute('genesis', input);
  assert.equal(recovered.ok, true, JSON.stringify(recovered));
  assert.equal(recovered.recovered, true);
  assert.equal(recovered.routeDisposition, 'no-route');
  assert.equal((await harness.native.readManagementState()).recovery.phase, 'terminal');
  const genesisMarker = await harness.native.readManagedHistoryMarker();
  assert.equal(genesisMarker.sequence, 1);

  const successor = await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, hostTokens: 'host=rotated-secret', idempotencyKey: 'recovered-no-reader-token-successor',
  });
  assert.equal(successor.ok, true, JSON.stringify(successor));
  assert.equal(successor.pending, false);
  assert.equal(successor.routeDisposition, 'no-route');
  const head = JSON.parse(fileEnding(harness.files, '/authority-head.json'));
  assert.equal(head.phase, 'terminal');
  assert.equal(head.sequence, genesisMarker.sequence + 1);
  const successorMarker = await harness.native.readManagedHistoryMarker();
  assert.equal(successorMarker.sequence, genesisMarker.sequence + 1);
  assert.equal(successorMarker.previousMarkerFingerprint, genesisMarker.markerFingerprint);
});
test('recovered bound-reader Genesis uses its managed history marker for a pending successor', async () => {
  const { files, native, runtime, setPrincipal } = await boundReaderRuntime();
  setPrincipal(owner);
  const genesisMarker = await native.readManagedHistoryMarker();
  assert.equal(genesisMarker.sequence, 1);
  const state = await native.readManagementState();
  const candidate = mappingInput('recovered-bound-map');

  const successor = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recovered-bound-successor',
    mappingId: candidate.mapping.mappingId, ...candidate, expectedRevision: state.revision, expectedFingerprint: null,
  });

  assert.equal(successor.ok, true, JSON.stringify(successor));
  assert.equal(successor.pending, true);
  assert.equal(successor.phase, 'reader-pending');
  assert.equal(successor.routeDisposition, 'no-route');
  const { request, head } = await native.readSuccessorBundle();
  assert.equal(request.sequence, genesisMarker.sequence + 1);
  assert.equal(head.sequence, genesisMarker.sequence + 1);
  assert.equal(head.phase, 'reader-pending');
  assert.equal((await native.readManagedHistoryMarker()).markerFingerprint, genesisMarker.markerFingerprint);
});
test('legacy-retained token rotation leaves target bytes, identity, and ACL immutable', async () => {
  const { files, native } = adapter();
  const runtime = new ManagementRuntime({ native });
  const targetBytes = Buffer.from(files.get('C:/state/channels.json'));
  assert.equal((await runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const retainedBefore = await native.readRetainedTargetProof();
  const stateBefore = await native.readManagementState();

  const rotation = await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, hostTokens: 'host=rotated-secret', idempotencyKey: 'legacy-retained-token-rotation',
  });

  assert.equal(rotation.ok, true, JSON.stringify(rotation));
  assert.equal(rotation.pending, false);
  assert.equal(rotation.routeDisposition, 'no-route');
  assert.deepEqual(files.get('C:/state/channels.json'), targetBytes);
  const retainedAfter = await native.readRetainedTargetProof();
  assert.equal(retainedAfter.sourceKind, 'legacy-retained');
  assert.equal(retainedAfter.targetFingerprint, retainedBefore.targetFingerprint);
  assert.equal(retainedAfter.identityFingerprint, retainedBefore.identityFingerprint);
  assert.equal(retainedAfter.aclFingerprint, retainedBefore.aclFingerprint);
  const stateAfter = await native.readManagementState();
  assert.equal(stateAfter.tokenConfigGeneration, stateBefore.tokenConfigGeneration + 1);
  const head = JSON.parse(fileEnding(files, '/authority-head.json'));
  assert.equal(head.phase, 'terminal');
  assert.equal(head.sequence, 2);
});
test('public recover refuses when no durable successor head is active', async () => {
  const { runtime, setPrincipal } = await boundReaderRuntime();
  setPrincipal(owner);

  const recovered = await runtime.execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'public-recovery-successor',
  });

  assert.equal(recovered.ok, false);
  assert.equal(recovered.error, 'RECOVERY_REQUIRED');
  assert.equal(recovered.routeDisposition, 'no-route');
});

async function terminalSuccessorFixture() {
  const harness = adapter();
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const genesisMarker = await harness.native.readManagedHistoryMarker();
  const successor = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'recoverable-successor-key',
    hostTokens: 'host=rotated-secret',
  });
  assert.equal(successor.ok, true, JSON.stringify(successor));
  return { ...harness, genesisMarker, successor };
}

function setSuccessorHeadPhase(fixture, phase) {
  const headPath = [...fixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/authority-head.json'));
  const markerPath = [...fixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/managed-history-marker.json'));
  const terminal = JSON.parse(fixture.files.get(headPath));
  const keep = {
    reserved: [],
    closed: ['closeFingerprint'],
    replaced: ['closeFingerprint', 'authorityCommitSnapshotFingerprint', 'baselineFingerprint', 'publicationKFingerprint', 'publicationYFingerprint'],
    'reader-pending': ['closeFingerprint', 'authorityCommitSnapshotFingerprint', 'baselineFingerprint', 'publicationKFingerprint', 'publicationYFingerprint', 'finalityFingerprint'],
  }[phase];
  const fields = ['closeFingerprint', 'authorityCommitSnapshotFingerprint', 'baselineFingerprint', 'publicationKFingerprint', 'publicationYFingerprint', 'finalityFingerprint', 'receiptFingerprint', 'historyMarkerFingerprint'];
  const head = buildAuthoritySuccessorRecord({
    ...terminal,
    phase,
    ...Object.fromEntries(fields.map((field) => [field, keep.includes(field) ? terminal[field] : null])),
    previousHeadFingerprint: null,
    headFingerprint: null,
  }, 'headFingerprint');
  fixture.files.set(headPath, Buffer.from(canonicalJson(head)));
  fixture.files.set(markerPath, Buffer.from(canonicalJson(fixture.genesisMarker)));
  const deleted = {
    reserved: ['authority-close-proof-', 'authority-successor-baseline-', 'authority-commit-', 'publication-k-', 'publication-y-', 'authority-successor-finality-', 'authority-successor-receipt-'],
    closed: ['authority-successor-baseline-', 'authority-commit-', 'publication-k-', 'publication-y-', 'authority-successor-finality-', 'authority-successor-receipt-'],
    replaced: ['authority-successor-finality-', 'authority-successor-receipt-'],
    'reader-pending': ['authority-successor-receipt-'],
  }[phase];
  for (const path of [...fixture.files.keys()]) {
    if (typeof path === 'string' && deleted.some((prefix) => path.replaceAll('\\', '/').includes(`/${prefix}${fixture.successor.txId}`))) fixture.files.delete(path);
  }
}

test('public recover binds the active successor request and durably refuses unsupported phases', async () => {
  for (const phase of ['reserved', 'closed', 'replaced']) {
    const fixture = await terminalSuccessorFixture();
    setSuccessorHeadPhase(fixture, phase);
    const recovered = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
      actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recoverable-successor-key',
    });

    assert.equal(recovered.ok, false, JSON.stringify({ phase, recovered }));
    assert.equal(recovered.error, 'MANUAL_CLEANUP_REQUIRED');
    const state = await fixture.native.readManagementState();
    assert.equal(state.recovery.phase, 'manual_cleanup');
    assert.equal(state.recovery.txId, fixture.successor.txId);
    assert.equal(state.recovery.successorPhase, phase);
    assert.equal(state.recovery.routeDisposition, 'no-route');
  }
});

test('public recover exactly replays terminal and reader-pending successor heads across runtime restart', async () => {
  const terminal = await terminalSuccessorFixture();
  const replay = await new ManagementRuntime({ native: terminal.native }).execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recoverable-successor-key',
  });
  assert.equal(replay.ok, true, JSON.stringify(replay));
  assert.equal(replay.idempotent, true);
  assert.equal(replay.phase, 'terminal');

  const pending = await boundReaderRuntime();
  pending.setPrincipal(owner);
  const state = await pending.native.readManagementState();
  const candidate = mappingInput('recover-pending-map');
  const started = await pending.runtime.execute('mapping-reconcile', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'recoverable-pending-key',
    mappingId: candidate.mapping.mappingId,
    ...candidate,
    expectedRevision: state.revision,
    expectedFingerprint: null,
  });
  assert.equal(started.pending, true, JSON.stringify(started));
  const resumed = await new ManagementRuntime({ native: pending.native }).execute('recover', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'recoverable-pending-key',
  });
  assert.equal(resumed.ok, true, JSON.stringify(resumed));
  assert.equal(resumed.pending, true);
  assert.equal(resumed.phase, 'reader-pending');
  assert.equal(JSON.parse(fileEnding(pending.files, '/authority-head.json')).phase, 'reader-pending');
});

test('public recover rejects a conflicting key with transaction-bound no-route cleanup', async () => {
  const fixture = await terminalSuccessorFixture();
  const recovered = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'conflicting-recovery-key',
  });

  assert.equal(recovered.ok, false);
  assert.equal(recovered.error, 'MANUAL_CLEANUP_REQUIRED');
  const state = await fixture.native.readManagementState();
  assert.equal(state.recovery.txId, fixture.successor.txId);
  assert.equal(state.recovery.successorPhase, 'terminal');
  assert.equal(state.recovery.routeDisposition, 'no-route');
});
test('an interrupted reserved successor becomes durable manual cleanup and blocks replay', async () => {
  const harness = await boundReaderRuntime();
  harness.setPrincipal(owner);
  const runtime = harness.runtime;
  const before = await harness.native.readManagementState();
  const candidate = mappingInput('interrupted-map');
  const writeClose = harness.native.writeAuthoritySuccessorClose.bind(harness.native);
  let interrupted = true;
  harness.native.writeAuthoritySuccessorClose = async (value) => {
    if (interrupted) {
      interrupted = false;
      throw new Error('SIMULATED_CRASH_AFTER_RESERVED');
    }
    return writeClose(value);
  };

  assert.equal((await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'reserved-replay',
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: before.revision, expectedFingerprint: null,
  })).ok, false);
  const replay = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'reserved-replay',
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: before.revision, expectedFingerprint: null,
  });

  assert.equal(replay.ok, false);
  assert.equal(replay.error, 'RECOVERY_REQUIRED');
  assert.equal(replay.routeDisposition, 'no-route');
  assert.equal((await harness.native.readManagementState()).recovery.phase, 'manual_cleanup');
});
