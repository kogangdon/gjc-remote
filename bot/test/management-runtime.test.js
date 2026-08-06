import assert from 'node:assert/strict';
import test from 'node:test';
import { ManagementRuntime } from '../src/management-runtime.js';
import { createManagementNativeForTest } from '../../native-control/test/helpers/management-native.js';
import { validateManagedProof } from '../src/managed-authority-reader.js';
import { createTestManagedAuthorityReader } from './helpers/managed-authority-reader.js';
import { buildAdmissionAck, buildAdmissionGrant, buildAdmissionRequest } from '../../shared/admission-envelope.js';
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
const filePathEnding = (files, ending) => [...files.keys()].find((path) => path.replaceAll("\\", "/").endsWith(ending));
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
async function boundReaderRuntime({ complete = true } = {}) {
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
    fenceGeneration: request.fenceGeneration,
    genesisTxId: request.genesisTxId, readerInstanceId: floor.firstReaderInstanceId,
    readerStartNonce: floor.firstReaderStartNonce, readerVersion: 2,
    fenceBindingFingerprint: fence.fenceBindingFingerprint, leaseBindingFingerprint: null,
  };
  lease.leaseBindingFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(lease).filter(([key]) => key !== 'leaseBindingFingerprint')),
  );
  const projection = {
    version: 1, kind: 'reader-projection', anchorFingerprint: request.anchorFingerprint,
    fenceGeneration: request.fenceGeneration,
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
  if (complete) {
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
  } else {
    harness.setPrincipal(owner);
    assert.equal((await harness.native.readBoundReaderProof({ allowPending: true })).readerProjection, null);
  }
  return { ...harness, runtime, input };
}
test('prepared Genesis recovery promotes durable authorized handshake to pending', async () => {
  const { native, runtime, input, setPrincipal, files } = await boundReaderRuntime({ complete: false });
  const before = await native.readManagementState();
  const crashed = structuredClone(before);
  crashed.recovery.phase = 'prepared';
  delete crashed.recovery.readerHandshake;
  crashed.revision = before.revision + 1;
  assert.equal(await native.compareAndSwapManagementState(before.revision, crashed), true);
  setPrincipal(owner);
  const recovered = await runtime.execute('genesis', input);
  assert.equal(recovered.ok, true, JSON.stringify(recovered));
  assert.equal(recovered.pending, true, JSON.stringify(recovered));
  const after = await native.readManagementState();
  assert.equal(after.recovery.phase, 'handshake-pending');
  assert.equal(after.recovery.txId, before.recovery.txId);
  assert.equal(after.recovery.requestFingerprint, before.recovery.requestFingerprint);
  assert.equal(
    after.recovery.readerHandshake.requestFingerprint,
    JSON.parse(fileEnding(files, '/admission-request.json')).requestFingerprint,
  );
});
test('prepared recovery rejects a substituted admission record with transaction-bound cleanup and no admission writes', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = {
    ...genesisInput('host=prepared-substitution'),
    requestedReaderMode: 'handshake',
    readerInstanceId: 'prepared-reader',
    readerStartNonce: 'prepared-start',
  };
  const pending = await runtime.execute('genesis', input);
  assert.equal(pending.ok, true);
  assert.equal(pending.pending, true);
  const statePath = [...harness.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/management-state.json'));
  const state = JSON.parse(harness.files.get(statePath));
  state.recovery.phase = 'prepared';
  delete state.recovery.readerHandshake;
  harness.files.set(statePath, Buffer.from(canonicalJson(state)));
  const requestPath = [...harness.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/admission-request.json'));
  const substituted = JSON.parse(harness.files.get(requestPath));
  substituted.nonce = 'substituted-admission-nonce';
  substituted.requestFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(substituted).filter(([key]) => key !== 'requestFingerprint')),
  );
  harness.files.set(requestPath, Buffer.from(canonicalJson(substituted)));
  const writes = harness.writes.length;
  const recovered = await runtime.execute('genesis', input);
  assert.equal(recovered.ok, false, JSON.stringify(recovered));
  assert.equal(recovered.error, 'MANUAL_CLEANUP_REQUIRED');
  assert.equal(recovered.routeDisposition, 'no-route');
  const after = await harness.native.readManagementState();
  assert.equal(after.recovery.phase, 'manual_cleanup');
  assert.equal(after.recovery.routeDisposition, 'no-route');
  assert.equal(after.recovery.txId, state.recovery.txId);
  assert.equal(
    harness.writes.slice(writes).some((path) => /admission-(?:request|grant)|acknowledgement/.test(path)),
    false,
  );
});

test('admission writers reject no-reader and post-terminal lifecycle records before writes', async () => {
  const noReaderHarness = adapter({ legacy: false });
  const noReaderRuntime = new ManagementRuntime({ native: noReaderHarness.native });
  const noReaderResult = await noReaderRuntime.execute('genesis', genesisInput('host=no-reader'));
  assert.equal(noReaderResult.ok, true, JSON.stringify(noReaderResult));
  const noReaderRequest = JSON.parse(fileEnding(noReaderHarness.files, '/genesis-request.json'));
  const candidateRequest = buildAdmissionRequest({
    requestId: 'no-reader-admission-request',
    genesisTxId: noReaderRequest.genesisTxId,
    generation: noReaderRequest.generation,
    fenceGeneration: noReaderRequest.fenceGeneration,
    readerInstanceId: 'substituted-reader',
    readerStartNonce: 'substituted-start',
    routeFingerprint: 'no-route',
    nonce: 'substituted-nonce',
    expiresAt: Date.now() + 30_000,
  });
  const candidateGrant = buildAdmissionGrant(candidateRequest, {
    grantId: 'no-reader-admission-grant',
    expiresAt: candidateRequest.expiresAt,
  });
  const noReaderWrites = noReaderHarness.writes.length;
  await assert.rejects(noReaderHarness.native.writeAdmissionRequest(candidateRequest), /no-reader Genesis/);
  await assert.rejects(noReaderHarness.native.writeAdmissionGrant(candidateGrant), /no-reader Genesis/);
  assert.equal(noReaderHarness.writes.length, noReaderWrites);

  const terminalHarness = await boundReaderRuntime({ complete: true });
  terminalHarness.setPrincipal(owner);
  const terminalRequest = JSON.parse(fileEnding(terminalHarness.files, '/admission-request.json'));
  const terminalGrant = JSON.parse(fileEnding(terminalHarness.files, '/admission-grant.json'));
  const terminalWrites = terminalHarness.writes.length;
  await assert.rejects(terminalHarness.native.writeAdmissionRequest(terminalRequest), /post-terminal admission/);
  await assert.rejects(terminalHarness.native.writeAdmissionGrant(terminalGrant), /post-terminal admission/);
  assert.equal(terminalHarness.writes.length, terminalWrites);
});
test('admission archive-only seams repair their missing current records and reject foreign pairs without writes', async () => {
  const harness = await boundReaderRuntime({ complete: false });
  const request = JSON.parse(fileEnding(harness.files, '/admission-request.json'));
  const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
  harness.setPrincipal(owner);

  const requestPath = filePathEnding(harness.files, '/admission-request.json');
  const requestArchivePath = filePathEnding(harness.files, `/admission-request-${request.requestId}.json`);
  const requestArchive = Buffer.from(harness.files.get(requestArchivePath));
  harness.files.delete(requestPath);
  const requestWrites = harness.writes.length;
  await harness.native.writeAdmissionRequest(request);
  assert.equal(harness.writes.length, requestWrites + 1);
  assert.deepEqual(harness.files.get(requestPath), requestArchive);
  assert.deepEqual(harness.files.get(requestArchivePath), requestArchive);

  const grantPath = filePathEnding(harness.files, '/admission-grant.json');
  const grantArchivePath = filePathEnding(harness.files, `/admission-grant-${grant.grantId}.json`);
  const grantArchive = Buffer.from(harness.files.get(grantArchivePath));
  harness.files.delete(grantPath);
  const grantWrites = harness.writes.length;
  await harness.native.writeAdmissionGrant(grant);
  assert.equal(harness.writes.length, grantWrites + 1);
  assert.deepEqual(harness.files.get(grantPath), grantArchive);
  assert.deepEqual(harness.files.get(grantArchivePath), grantArchive);

  const foreign = { ...grant, nonce: 'foreign-grant-nonce' };
  foreign.grantFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(foreign).filter(([key]) => key !== 'grantFingerprint')),
  );
  harness.files.set(grantPath, Buffer.from(canonicalJson(foreign)));
  const foreignWrites = harness.writes.length;
  await assert.rejects(harness.native.writeAdmissionGrant(grant), /substitution/);
  assert.equal(harness.writes.length, foreignWrites);
  assert.deepEqual(harness.files.get(grantPath), Buffer.from(canonicalJson(foreign)));
});

test('acknowledgement archive-only seam repairs the current B record exactly', async () => {
  const harness = await boundReaderRuntime({ complete: false });
  const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
  const floor = JSON.parse(fileEnding(harness.files, '/reader-version-floor.json'));
  const zFinality = JSON.parse(fileEnding(harness.files, '/z-finality.json'));
  const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
  const fence = JSON.parse(fileEnding(harness.files, '/reader-fence-binding.json'));
  const lease = {
    version: 1,
    kind: 'reader-lease-binding',
    anchorFingerprint: request.anchorFingerprint,
    fenceGeneration: request.fenceGeneration,
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
    fenceGeneration: request.fenceGeneration,
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
  harness.setPrincipal(botPrincipal);
  await harness.native.writeBotReaderProjection(projection);
  const ack = buildAdmissionAck(grant, projection.readerProjectionFingerprint);
  await harness.native.writeBotAcknowledgement(ack);

  const currentPath = filePathEnding(harness.files, '/bot-state/acknowledgement.json');
  const archivePath = filePathEnding(harness.files, `/bot-state/admission-ack-${grant.grantId}.json`);
  const archive = Buffer.from(harness.files.get(archivePath));
  harness.files.delete(currentPath);
  const writes = harness.writes.length;
  await harness.native.writeBotAcknowledgement(ack);
  assert.equal(harness.writes.length, writes + 1);
  assert.deepEqual(harness.files.get(currentPath), archive);
  assert.deepEqual(harness.files.get(archivePath), archive);
});
test('Genesis finality, recheck, and snapshot reject deleted or substituted admission archives', async () => {
  for (const variant of ['deleted', 'substituted']) {
    const harness = await boundReaderRuntime({ complete: true });
    const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
    const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
    const zFinality = JSON.parse(fileEnding(harness.files, '/z-finality.json'));
    const finalityProof = JSON.parse(fileEnding(harness.files, '/rvf.json'));
    const receipt = JSON.parse(fileEnding(harness.files, '/receipt.json'));
    const readerProjection = JSON.parse(fileEnding(harness.files, '/bot-state/reader-projection.json'));
    const admissionAck = JSON.parse(fileEnding(harness.files, '/bot-state/acknowledgement.json'));
    const archivePath = filePathEnding(harness.files, `/admission-grant-${grant.grantId}.json`);
    if (variant === 'deleted') {
      harness.files.delete(archivePath);
    } else {
      const substituted = JSON.parse(harness.files.get(archivePath));
      substituted.nonce = 'substituted-finality-archive';
      substituted.grantFingerprint = canonicalJsonHash(
        Object.fromEntries(Object.entries(substituted).filter(([key]) => key !== 'grantFingerprint')),
      );
      harness.files.set(archivePath, Buffer.from(canonicalJson(substituted)));
    }

    harness.setPrincipal(owner);
    const writes = harness.writes.length;
    await assert.rejects(
      harness.native.writeFinalityProof(finalityProof),
      /complete bound-reader finality graph is invalid/,
    );
    assert.equal(harness.writes.length, writes);
    assert.equal(
      await harness.native.recheckAdmissionFinality({
        request,
        zFinality,
        readerProjection,
        admissionAck,
        finalityProof,
        receipt,
      }),
      false,
    );
    await assert.rejects(
      harness.native.reopenAdmission({
        txId: request.genesisTxId,
        finalityFingerprint: finalityProof.finalityProofFingerprint,
      }),
      /exact committed finality proof|admission/i,
    );

    harness.setPrincipal(botPrincipal);
    await assert.rejects(
      harness.native.readManagedMappingSnapshot(),
      /admission|finality|invalid/i,
    );
  }
});
test('pending bootstrap rejects mutable/archive drift before any bot writes', async () => {
  const harness = await boundReaderRuntime({ complete: false });
  const grantArchivePath = filePathEnding(harness.files, `/admission-grant-${JSON.parse(fileEnding(harness.files, '/admission-grant.json')).grantId}.json`);
  const grantArchive = JSON.parse(harness.files.get(grantArchivePath));
  grantArchive.nonce = 'foreign-bootstrap-nonce';
  grantArchive.grantFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(grantArchive).filter(([key]) => key !== 'grantFingerprint')),
  );
  harness.files.set(grantArchivePath, Buffer.from(canonicalJson(grantArchive)));
  harness.setPrincipal(botPrincipal);
  const writes = harness.writes.length;
  await assert.rejects(harness.native.readPendingReaderBootstrap(), /pending reader authority/);
  assert.equal(harness.writes.length, writes);
});
test('pending managed snapshot recognizes durable handshake before completed reader state', async () => {
  const harness = await boundReaderRuntime({ complete: false });
  harness.setPrincipal(botPrincipal);
  await assert.rejects(
    harness.native.readManagedMappingSnapshot(),
    (error) => error?.code === 'MANAGED_HANDSHAKE_PENDING',
  );
});

test('managed snapshot rejects mutable Genesis precommit drift against immutable archive', async () => {
  const harness = await boundReaderRuntime({ complete: true });
  const currentPath = filePathEnding(harness.files, '/genesis-precommit-proof.json');
  const current = JSON.parse(harness.files.get(currentPath));
  current.genesisProbeFingerprint = 'f'.repeat(64);
  current.precommitFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(current).filter(([key]) => key !== 'precommitFingerprint')),
  );
  harness.files.set(currentPath, Buffer.from(canonicalJson(current)));
  harness.setPrincipal(botPrincipal);
  await assert.rejects(
    harness.native.readManagedMappingSnapshot(),
    /precommit|Genesis/i,
  );
});
test('pending bot writers require durable handshake and immutable admission archives before writes', async () => {
  const cases = [
    ['missing durable handshake', (harness) => {
      const statePath = filePathEnding(harness.files, '/management-state.json');
      const state = JSON.parse(harness.files.get(statePath));
      delete state.recovery.readerHandshake;
      harness.files.set(statePath, Buffer.from(canonicalJson(state)));
    }],
    ['substituted request archive', (harness) => {
      const request = JSON.parse(fileEnding(harness.files, '/admission-request.json'));
      const archivePath = filePathEnding(harness.files, `/admission-request-${request.requestId}.json`);
      const archive = JSON.parse(harness.files.get(archivePath));
      archive.nonce = 'foreign-pending-writer-nonce';
      archive.requestFingerprint = canonicalJsonHash(
        Object.fromEntries(Object.entries(archive).filter(([key]) => key !== 'requestFingerprint')),
      );
      harness.files.set(archivePath, Buffer.from(canonicalJson(archive)));
    }],
    ['substituted acknowledgement archive', (harness) => {
      const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
      const grantPath = filePathEnding(harness.files, '/admission-grant.json');
      const archivePath = grantPath.replace(
        /admission-grant\.json$/,
        `bot-state${grantPath.includes('\\') ? '\\' : '/'}admission-ack-${grant.grantId}.json`,
      );
      const acknowledgement = buildAdmissionAck(grant, 'a'.repeat(64));
      harness.files.set(archivePath, Buffer.from(canonicalJson(acknowledgement)));
    }],
  ];
  for (const [label, mutate] of cases) {
    const harness = await boundReaderRuntime({ complete: false });
    mutate(harness);
    harness.setPrincipal(botPrincipal);
    const writes = harness.writes.length;
    await assert.rejects(
      harness.native.acquireBotLease({}),
      /durable reader handshake|immutable admission archives/,
      label,
    );
    assert.equal(harness.writes.length, writes, `${label} must be write-free`);
  }
});

function mappingInput(mappingId, generation = 1, fenceGeneration = 1, channelId = '123') {
  const mapping = fingerprintManagedMappingRecord({
    mappingId, hostId: 'host', fenceGeneration, mappingGeneration: generation, mappingVersion: 1,
    sourcePlatform: 'posix', workspaceId: 'workspace-a', workDir: null,
    sourceRoot: '/source', containerRoot: '/workspace', volumeIdentity: 'volume-a',
    casePolicy: 'sensitive', immutableDefault: false, mappingFingerprint: null,
  });
  const route = fingerprintManagedRouteRecord({
    channelId, hostId: mapping.hostId, mappingId: mapping.mappingId,
    fenceGeneration: mapping.fenceGeneration,
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
test('token successor audit failure converges cleanup state to the committed durable token lineage', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old-secret'))).ok, true);
  const before = await harness.native.readManagementState();
  const appendAudit = harness.native.appendAudit.bind(harness.native);
  harness.native.appendAudit = async (...args) => {
    await appendAudit(...args);
    throw new Error('INJECTED_TOKEN_AUDIT');
  };

  const result = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'token-floor-cleanup',
    hostTokens: 'host=new-secret',
  });
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.error, 'MANUAL_CLEANUP_REQUIRED', JSON.stringify(result));
  assert.equal(result.routeDisposition, 'no-route');

  const lineage = await harness.native.readSuccessorTokenLineage();
  assert.equal(lineage.floor.floorPhase, 'committed');
  assert.equal(lineage.floor.highestCommittedGeneration, before.tokenConfigGeneration + 1);
  const state = await harness.native.readManagementState();
  assert.equal(state.recovery.phase, 'manual_cleanup');
  assert.equal(state.recovery.routeDisposition, 'no-route');
  assert.deepEqual(state.tokenFloor, lineage.floor);
  assert.equal(state.tokenConfigGeneration, lineage.floor.highestCommittedGeneration);
  assert.deepEqual(state.tokenAttestation, {
    fingerprint: lineage.attestation.tokenConfigHostSetFingerprint,
    generation: lineage.attestation.tokenConfigGeneration,
    attestationFingerprint: lineage.attestation.attestationFingerprint,
    finalityFingerprint: lineage.floor.floorFingerprint,
  });
  assert.equal(state.tokenFloor.highestReservedGeneration, state.tokenFloor.highestCommittedGeneration);
  assert.ok(fileEnding(harness.files, '/terminal-close.json'));

  const blocked = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'token-floor-cleanup-blocked',
    hostTokens: 'host=blocked-secret',
  });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.error, 'RECOVERY_REQUIRED');
  assert.equal(blocked.routeDisposition, 'no-route');
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
  assert.ok(attestationWrite < authorityReservationWrite);
  assert.ok(authorityReservationWrite < authorityCommitWrite);
  assert.ok(authorityCommitWrite < targetPublicationWrite);
  assert.ok(targetPublicationWrite < authorityBaselineWrite);
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
test('Genesis handshake state CAS crash preserves the exact pending admission tuple', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = {
    ...genesisInput('host=secret'),
    requestedReaderMode: 'handshake',
    readerInstanceId: 'reader-cas-crash',
    readerStartNonce: 'reader-cas-crash-start',
  };
  const compare = harness.native.compareAndSwapManagementState.bind(harness.native);
  let injected = false;
  harness.native.compareAndSwapManagementState = async (expected, next) => {
    const result = await compare(expected, next);
    if (!injected && next.recovery?.phase === 'handshake-pending') {
      injected = true;
      throw new Error('INJECTED_HANDSHAKE_STATE_CAS_CRASH');
    }
    return result;
  };

  const interrupted = await runtime.execute('genesis', input);
  assert.equal(interrupted.ok, false, JSON.stringify(interrupted));
  harness.native.compareAndSwapManagementState = compare;

  const pendingState = await harness.native.readManagementState();
  assert.equal(pendingState.recovery.phase, 'handshake-pending');
  assert.equal(pendingState.recovery.routeDisposition, 'no-route');
  assert.equal(pendingState.recovery.readerHandshake.request.genesisTxId, pendingState.recovery.txId);
  assert.equal(
    pendingState.recovery.readerHandshake.requestFingerprint,
    pendingState.recovery.readerHandshake.request.requestFingerprint,
  );
  assert.equal(
    pendingState.recovery.readerHandshake.grantFingerprint,
    pendingState.recovery.readerHandshake.grant.grantFingerprint,
  );
  assert.equal(fileEnding(harness.files, '/admission-request.json'), undefined);
  assert.equal(fileEnding(harness.files, '/admission-grant.json'), undefined);

  const resumed = await runtime.execute('genesis', input);
  assert.equal(resumed.ok, true, JSON.stringify(resumed));
  assert.equal(resumed.pending, true);
  assert.equal((await harness.native.readManagementState()).recovery.phase, 'handshake-pending');
  const request = JSON.parse(fileEnding(harness.files, '/admission-request.json'));
  const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
  assert.equal(request.requestFingerprint, pendingState.recovery.readerHandshake.requestFingerprint);
  assert.equal(grant.grantFingerprint, pendingState.recovery.readerHandshake.grantFingerprint);
});

test('Genesis suffix recovery audit failure converges manual cleanup after terminal state CAS', async () => {
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
  harness.native.appendAudit = async () => { throw new Error('INJECTED_RECOVERY_AUDIT_FAILURE'); };

  const result = await runtime.execute('genesis', input);
  assert.equal(result.ok, false);
  assert.equal(result.error, 'MANUAL_CLEANUP_REQUIRED');
  const state = await harness.native.readManagementState();
  assert.equal(state.recovery.phase, 'manual_cleanup');
  assert.equal(state.recovery.routeDisposition, 'no-route');
  assert.equal(state.admission.phase, 'closed');
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
    fenceGeneration: request.fenceGeneration,
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
    fenceGeneration: request.fenceGeneration,
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
test('durable authority floors and terminal state counters stay bound across a successor', async () => {
  const { native, files } = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native });
  const genesis = await runtime.execute('genesis', genesisInput('host=old'));
  assert.equal(genesis.ok, true, JSON.stringify(genesis));
  const genesisState = await native.readManagementState();
  const genesisFloor = await native.readAuthorityEpochFloor();
  assert.equal(genesisFloor.highestReservedAuthorityEpoch, 1);
  assert.equal(genesisFloor.highestCommittedAuthorityEpoch, 1);
  assert.equal(genesisState.authorityEpoch, genesisFloor.highestCommittedAuthorityEpoch);
  const tamperedFloor = {
    ...genesisState.tokenFloor,
    fenceGeneration: genesisState.tokenFloor.fenceGeneration + 1,
    floorFingerprint: null,
  };
  tamperedFloor.floorFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(tamperedFloor).filter(([key]) => key !== 'floorFingerprint')),
  );
  await assert.rejects(
    native.compareAndSwapManagementState(genesisState.revision, { ...genesisState, tokenFloor: tamperedFloor }),
    /token lineage/,
  );
  await assert.rejects(
    native.compareAndSwapManagementState(genesisState.revision, {
      ...genesisState,
      tokenAttestation: { ...genesisState.tokenAttestation, finalityFingerprint: '0'.repeat(64) },
    }),
    /durable attestation/,
  );

  const candidate = mappingInput('durable-epoch-map');
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'durable-epoch-successor',
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: genesisState.revision, expectedFingerprint: null,
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  const request = JSON.parse(fileEnding(files, `/authority-successor-request-${result.txId}.json`));
  const finality = JSON.parse(fileEnding(files, `/authority-successor-finality-${result.txId}.json`));
  const successorFloor = await native.readAuthorityEpochFloor();
  const terminalState = await native.readManagementState();
  assert.equal(request.candidateAuthorityEpoch, 2);
  assert.equal(successorFloor.highestReservedAuthorityEpoch, request.candidateAuthorityEpoch);
  assert.equal(successorFloor.highestCommittedAuthorityEpoch, finality.authorityEpoch);
  assert.deepEqual(
    [terminalState.revision, terminalState.authorityEpoch, terminalState.tokenConfigGeneration, terminalState.mappingGeneration],
    [finality.revision, finality.authorityEpoch, finality.tokenConfigGeneration, finality.mappingGeneration],
  );
  await assert.rejects(
    native.compareAndSwapManagementState(terminalState.revision, { ...terminalState, authorityEpoch: terminalState.authorityEpoch - 1 }),
    /authority epoch is not bound/,
  );
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
  const tokenFloor = JSON.parse(fileEnding(files, '/token-floor.json'));
  const tokenAttestation = JSON.parse(fileEnding(files, '/attestation.json'));
  assert.equal(afterToken.tokenFloor.floorFingerprint, tokenFloor.floorFingerprint);
  assert.equal(afterToken.tokenFloor.lastAttestationFingerprint, tokenAttestation.attestationFingerprint);
  assert.equal(afterToken.tokenAttestation.attestationFingerprint, tokenAttestation.attestationFingerprint);
  assert.equal(afterToken.tokenAttestation.fingerprint, tokenAttestation.tokenConfigHostSetFingerprint);
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
test('legacy-retained mapping mutations refuse before any successor write', async () => {
  const harness = adapter();
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const state = await harness.native.readManagementState();
  const candidate = mappingInput('legacy-mutation');
  const beforeFiles = new Map([...harness.files].map(([path, bytes]) => [path, Buffer.from(bytes)]));
  const beforeWrites = harness.writes.length;
  const inputs = {
    'mapping-reconcile': {
      mappingId: candidate.mapping.mappingId, ...candidate,
    },
    'mapping-revoke': {
      mappingId: candidate.mapping.mappingId,
    },
    'mapping-rollback': {
      mappingId: candidate.mapping.mappingId, priorGeneration: 1, replacementMappingId: 'legacy-rollback',
    },
  };
  for (const [command, extra] of Object.entries(inputs)) {
    const result = await runtime.execute(command, {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: `legacy-${command}`,
      expectedRevision: state.revision,
      expectedFingerprint: null,
      ...extra,
    });
    assert.equal(result.ok, false, JSON.stringify({ command, result }));
    assert.equal(result.error, 'LEGACY_MAPPING_MUTATION_REFUSED');
    assert.equal(result.routeDisposition, 'no-route');
    assert.equal(harness.writes.length, beforeWrites);
    assert.deepEqual(
      [...harness.files].map(([path, bytes]) => [path, Buffer.from(bytes)]),
      [...beforeFiles],
    );
  }
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
  const floor = JSON.parse(fileEnding(files, '/token-floor.json'));
  const attestation = JSON.parse(fileEnding(files, '/attestation.json'));
  assert.deepEqual(stateAfter.tokenFloor, floor);
  assert.equal(stateAfter.tokenFloor.floorFingerprint, floor.floorFingerprint);
  assert.equal(stateAfter.tokenFloor.fenceGeneration, floor.fenceGeneration);
  assert.equal(stateAfter.tokenFloor.highestCommittedGeneration, stateAfter.tokenConfigGeneration);
  assert.equal(stateAfter.tokenFloor.lastAttestationFingerprint, attestation.attestationFingerprint);
  assert.equal(stateAfter.tokenAttestation.attestationFingerprint, attestation.attestationFingerprint);
  assert.equal(stateAfter.tokenAttestation.finalityFingerprint, floor.floorFingerprint);
  const head = JSON.parse(fileEnding(files, '/authority-head.json'));
  assert.equal(head.phase, 'terminal');
  assert.equal(head.sequence, 2);
});
test('legacy-retained token rotations advance only the durable envelope fence chain', async () => {
  const { files, native } = adapter();
  const runtime = new ManagementRuntime({ native });
  const targetBytes = Buffer.from(files.get('C:/state/channels.json'));

  assert.equal((await runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const before = await native.readRetainedTargetProof();
  const genesisRoot = JSON.parse(fileEnding(files, '/control-root.json'));
  const genesisWrapper = JSON.parse(fileEnding(files, '/legacy-retained.json'));
  assert.equal(genesisRoot.fenceGeneration, 1);
  assert.equal(genesisWrapper.fenceGeneration, 1);
  assert.equal(genesisWrapper.previousWrapperFingerprint, null);

  const first = await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, hostTokens: 'host=rotated-secret',
    idempotencyKey: 'legacy-retained-token-rotation-1',
  });
  assert.equal(first.ok, true, JSON.stringify(first));
  const firstRoot = JSON.parse(fileEnding(files, '/control-root.json'));
  const firstWrapper = JSON.parse(fileEnding(files, '/legacy-retained.json'));
  assert.equal(firstRoot.fenceGeneration, 2);
  assert.equal(firstWrapper.fenceGeneration, 2);
  assert.equal(firstWrapper.previousWrapperFingerprint, genesisWrapper.wrapperFingerprint);
  assert.notEqual(firstRoot.controlRootFingerprint, genesisRoot.controlRootFingerprint);
  assert.notEqual(firstWrapper.wrapperFingerprint, genesisWrapper.wrapperFingerprint);

  const second = await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, hostTokens: 'host=rotated-secret-2',
    idempotencyKey: 'legacy-retained-token-rotation-2',
  });
  assert.equal(second.ok, true, JSON.stringify(second));
  const secondRoot = JSON.parse(fileEnding(files, '/control-root.json'));
  const secondWrapper = JSON.parse(fileEnding(files, '/legacy-retained.json'));
  assert.equal(secondRoot.fenceGeneration, 3);
  assert.equal(secondWrapper.fenceGeneration, 3);
  assert.equal(secondWrapper.previousWrapperFingerprint, firstWrapper.wrapperFingerprint);
  assert.equal(secondRoot.wrapperFingerprint, secondWrapper.wrapperFingerprint);
  assert.equal(secondWrapper.routeDisposition, 'no-route');
  assert.notEqual(secondRoot.controlRootFingerprint, firstRoot.controlRootFingerprint);
  assert.notEqual(secondWrapper.wrapperFingerprint, firstWrapper.wrapperFingerprint);

  const after = await native.readRetainedTargetProof();
  assert.equal(after.fenceGeneration, 3);
  assert.deepEqual(after.targetBytes, targetBytes);
  assert.equal(after.targetFingerprint, before.targetFingerprint);
  assert.equal(after.identityFingerprint, before.identityFingerprint);
  assert.equal(after.aclFingerprint, before.aclFingerprint);
  assert.equal((await native.readManagementState()).tokenConfigGeneration, 3);
  const floor = JSON.parse(fileEnding(files, '/token-floor.json'));
  assert.equal(floor.fenceGeneration, 3);
  assert.equal(JSON.parse(fileEnding(files, '/authority-head.json')).sequence, 3);
});
test('legacy-retained token rotation refuses a stale management fence without writes', async () => {
  const { files, native } = adapter();
  const runtime = new ManagementRuntime({ native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const statePath = [...files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/management-state.json'));
  assert.ok(statePath);
  const state = await native.readManagementState();
  const root = JSON.parse(fileEnding(files, '/control-root.json'));
  files.set(statePath, Buffer.from(canonicalJson({ ...state, fenceGeneration: root.fenceGeneration - 1 })));
  const writesBefore = files.size;
  await assert.rejects(native.rotateTokenSidecar({
    generation: state.tokenConfigGeneration + 1,
    revision: state.revision + 1,
    authorityEpoch: state.authorityEpoch + 1,
    mappingGeneration: state.mappingGeneration,
    fenceGeneration: root.fenceGeneration + 1,
    hostSetFingerprint: 'a'.repeat(64),
  }), /legacy token rotation counters are not the durable successor/);
  assert.equal(files.size, writesBefore);
  const wrapper = JSON.parse(fileEnding(files, '/legacy-retained.json'));
  assert.equal(wrapper.fenceGeneration, root.fenceGeneration);
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
async function terminalMappingSuccessorFixture() {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const genesisMarker = await harness.native.readManagedHistoryMarker();
  const state = await harness.native.readManagementState();
  const candidate = mappingInput('recoverable-mapping-key');
  const successor = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recoverable-mapping-key',
    mappingId: candidate.mapping.mappingId, ...candidate, expectedRevision: state.revision, expectedFingerprint: null,
  });
  assert.equal(successor.ok, true, JSON.stringify(successor));
  return { ...harness, genesisMarker, successor };
}
async function pendingBoundSuccessorFixture(idempotencyKey = 'reader-pending-recovery') {
  const harness = await boundReaderRuntime();
  harness.setPrincipal(owner);
  const state = await harness.native.readManagementState();
  const candidate = mappingInput(`${idempotencyKey}-map`);
  const input = {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey,
    mappingId: candidate.mapping.mappingId,
    ...candidate,
    expectedRevision: state.revision,
    expectedFingerprint: null,
  };
  const started = await harness.runtime.execute('mapping-reconcile', input);
  assert.equal(started.pending, true, JSON.stringify(started));
  return { ...harness, input, started };
}
function setSuccessorHeadPhase(fixture, phase) {
  const headPath = [...fixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/authority-head.json'));
  const markerPath = [...fixture.files.keys()].find((path) => typeof path === 'string' && path.replaceAll('\\', '/').endsWith('.managed-history.json'));
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
  for (const path of [...fixture.files.keys()]) {
    if (typeof path === 'string' && [`/authority-head-${terminal.sequence}-${phase}.json`, `/authority-head-${terminal.sequence}-terminal.json`].some((suffix) => path.replaceAll('\\', '/').endsWith(suffix))) {
      fixture.files.delete(path);
    }
  }
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
async function boundCompletionFailureFixture(method) {
  const fixture = await boundReaderRuntime();
  fixture.setPrincipal(owner);
  const state = await fixture.native.readManagementState();
  const candidate = mappingInput(`bound-completion-${method}`);
  const input = {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: `bound-completion-${method}`,
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: state.revision, expectedFingerprint: null,
  };
  const started = await fixture.runtime.execute('mapping-reconcile', input);
  assert.equal(started.pending, true, JSON.stringify(started));
  fixture.setPrincipal(botPrincipal);
  const reader = await createTestManagedAuthorityReader({
    expectedHostSetFingerprint: managedHostSetFingerprint('host=secret'),
    roleBindings: roles,
    native: fixture.native,
  });
  assert.equal((await reader.readSnapshot()).code, 'MANAGED_AUTHORITY_PENDING');
  fixture.setPrincipal(owner);
  const original = fixture.native[method].bind(fixture.native);
  let injected = true;
  fixture.native[method] = async (...args) => {
    const result = await original(...args);
    if (injected) {
      injected = false;
      throw new Error(`INJECTED_BOUND_${method}`);
    }
    return result;
  };
  return { ...fixture, input, started, restore: () => { fixture.native[method] = original; } };
}

async function noReaderCompletionFailureFixture(method) {
  const fixture = await terminalMappingSuccessorFixture();
  fixture.runtime = new ManagementRuntime({ native: fixture.native });
  setSuccessorHeadPhase(fixture, 'reader-pending');
  const original = fixture.native[method].bind(fixture.native);
  let injected = true;
  fixture.native[method] = async (...args) => {
    const result = await original(...args);
    if (injected) {
      injected = false;
      throw new Error(`INJECTED_NO_READER_${method}`);
    }
    return result;
  };
  return { ...fixture, restore: () => { fixture.native[method] = original; } };
}
async function initialNoReaderCompletionFailureFixture(method) {
  const fixture = adapter({ legacy: false });
  fixture.runtime = new ManagementRuntime({ native: fixture.native });
  assert.equal((await fixture.runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const state = await fixture.native.readManagementState();
  const candidate = mappingInput(`initial-no-reader-${method}`);
  const input = {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: `initial-no-reader-${method}`,
    mappingId: candidate.mapping.mappingId, ...candidate,
    expectedRevision: state.revision, expectedFingerprint: null,
  };
  const original = fixture.native[method].bind(fixture.native);
  const completionCall = method === 'writeAuthoritySuccessorHead' ? 5 : 1;
  let calls = 0;
  fixture.native[method] = async (...args) => {
    const result = await original(...args);
    calls += 1;
    if (calls === completionCall) throw new Error(`INJECTED_INITIAL_NO_READER_${method}`);
    return result;
  };
  return { ...fixture, input, restore: () => { fixture.native[method] = original; } };
}
test('initial no-reader completion failures persist and replay one terminalization suffix', async () => {
  for (const method of ['writeAuthoritySuccessorReceipt', 'commitManagedHistoryMarker', 'compareAndSwapManagementState', 'writeAuthoritySuccessorHead']) {
    const fixture = await initialNoReaderCompletionFailureFixture(method);
    const interrupted = await fixture.runtime.execute('mapping-reconcile', fixture.input);
    assert.equal(interrupted.ok, false, JSON.stringify({ method, interrupted }));
    assert.equal(interrupted.error, 'MANUAL_CLEANUP_REQUIRED', JSON.stringify({ method, interrupted }));
    assert.equal(interrupted.routeDisposition, 'no-route');
    const state = await fixture.native.readManagementState();
    const suffix = state.recovery.terminalization;
    assert.equal(state.recovery.phase, 'manual_cleanup');
    assert.ok(suffix);
    assert.equal(suffix.phase, 'prepared');
    assert.equal(suffix.txId, state.recovery.txId);
    assert.equal(suffix.suffixFingerprint, canonicalJsonHash(
      Object.fromEntries(Object.entries(suffix).filter(([key]) => key !== 'suffixFingerprint')),
    ));
    assert.equal(suffix.receipt.phase, 'terminal');
    assert.equal(suffix.marker.sequence, suffix.request.sequence);
    assert.equal(suffix.pendingHead.phase, 'reader-pending');
    assert.equal(suffix.terminalHead.phase, 'terminal');

    fixture.restore();
    const replay = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
      actorPrincipal: owner, actorSecret: secret, idempotencyKey: fixture.input.idempotencyKey,
    });
    assert.equal(replay.ok, true, JSON.stringify({ method, replay }));
    assert.equal(replay.idempotent, true);
    assert.equal(replay.phase, 'terminal');
    assert.equal(replay.routeDisposition, 'no-route');
    const receipt = JSON.parse(fileEnding(fixture.files, `/authority-successor-receipt-${suffix.txId}.json`));
    const head = JSON.parse(fileEnding(fixture.files, '/authority-head.json'));
    assert.deepEqual(receipt, suffix.receipt);
    assert.deepEqual(head, suffix.terminalHead);
    assert.equal((await fixture.native.readManagedHistoryMarker()).markerFingerprint, suffix.marker.markerFingerprint);
    assert.equal((await fixture.native.readManagementState()).recovery.terminalization, undefined);
  }
});

test('bound and no-reader completion failures after durable writes remain transaction-bound and no-route', async () => {
  for (const method of ['writeAuthoritySuccessorReceipt', 'commitManagedHistoryMarker', 'compareAndSwapManagementState', 'writeAuthoritySuccessorHead']) {
    const bound = await boundCompletionFailureFixture(method);
    const result = await bound.runtime.execute('mapping-reconcile', bound.input);
    assert.equal(result.ok, false, JSON.stringify({ method, result }));
    assert.equal(result.error, 'MANUAL_CLEANUP_REQUIRED', JSON.stringify({ method, result }));
    assert.equal(result.routeDisposition, 'no-route');
    const state = await bound.native.readManagementState();
    assert.equal(state.recovery.phase, 'manual_cleanup');
    assert.equal(state.recovery.txId, bound.started.txId);
    assert.equal(state.recovery.routeDisposition, 'no-route');
    assert.ok(fileEnding(bound.files, '/terminal-close.json'));
    assert.ok(state.recovery.terminalization);
    assert.equal(state.recovery.terminalization.txId, bound.started.txId);
    bound.restore();
    const replay = await new ManagementRuntime({ native: bound.native }).execute('recover', {
      actorPrincipal: owner, actorSecret: secret, idempotencyKey: bound.input.idempotencyKey,
    });
    assert.equal(replay.routeDisposition, 'no-route');
    assert.equal(replay.ok, true, JSON.stringify({ method, replay }));
    assert.equal(replay.idempotent, true);
    assert.equal(replay.phase, 'terminal');

    const noReader = await noReaderCompletionFailureFixture(method);
    const recovered = await noReader.runtime.execute('recover', {
      actorPrincipal: owner, actorSecret: secret, idempotencyKey: noReader.successor.idempotencyKey ?? 'recoverable-mapping-key',
    });
    assert.equal(recovered.ok, false, JSON.stringify({ method, recovered }));
    assert.equal(recovered.error, 'MANUAL_CLEANUP_REQUIRED');
    assert.equal(recovered.routeDisposition, 'no-route');
    const noReaderState = await noReader.native.readManagementState();
    assert.equal(noReaderState.recovery.phase, 'manual_cleanup');
    assert.equal(noReaderState.recovery.txId, noReader.successor.txId);
    assert.ok(noReaderState.recovery.terminalization);
    assert.equal(noReaderState.recovery.terminalization.txId, noReader.successor.txId);
    assert.equal(noReaderState.recovery.routeDisposition, 'no-route');
    assert.ok(fileEnding(noReader.files, '/terminal-close.json'));
    noReader.restore();
    const noReaderReplay = await new ManagementRuntime({ native: noReader.native }).execute('recover', {
      actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recoverable-mapping-key',
    });
    assert.equal(noReaderReplay.routeDisposition, 'no-route');
    assert.equal(noReaderReplay.ok, true, JSON.stringify({ method, noReaderReplay, terminal: JSON.parse(fileEnding(noReader.files, '/terminal-close.json')), state: await noReader.native.readManagementState() }));
    assert.equal(noReaderReplay.idempotent, true);
    assert.equal(noReaderReplay.phase, 'terminal');
  }
});

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
test('public terminal recover fails closed on token history, marker, and committed epoch drift', async () => {
  for (const [name, ending, mutate] of [
    ['token-history', '/attestation-history.json', (value) => {
      const history = JSON.parse(value);
      history[0].tokenConfigHostSetFingerprint = '0'.repeat(64);
      return canonicalJson(history);
    }],
    ['marker-history', '.managed-history.json', (value) => {
      const marker = JSON.parse(value);
      marker.previousMarkerFingerprint = '0'.repeat(64);
      return canonicalJson(marker);
    }],
    ['committed-epoch', '/authority-epoch-2-committed.json', (value) => {
      const epoch = JSON.parse(value);
      epoch.commitTxId = 'drifted-epoch';
      return canonicalJson(epoch);
    }],
  ]) {
    const fixture = await terminalSuccessorFixture();
    const path = [...fixture.files.keys()].find((candidate) =>
      candidate.replaceAll('\\', '/').endsWith(ending));
    assert.ok(path, name);
    fixture.files.set(path, Buffer.from(mutate(fixture.files.get(path).toString())));
    const recovered = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: 'recoverable-successor-key',
    });
    assert.equal(recovered.ok, false, JSON.stringify({ name, recovered }));
    assert.equal(recovered.error, 'MANUAL_CLEANUP_REQUIRED', name);
    assert.equal(recovered.routeDisposition, 'no-route', name);
  }
});
test('public recover turns missing, torn, or phase-drifted reader-pending bundles into durable cleanup', async () => {
  for (const [kind, mutate] of [
    ['missing', () => null],
    ['torn', (bundle) => ({ ...bundle, finality: null })],
    ['phase-drifted', (bundle) => ({ ...bundle, head: { ...bundle.head, phase: 'replaced' } })],
  ]) {
    const fixture = await pendingBoundSuccessorFixture(`reader-pending-${kind}`);
    const original = fixture.native.readSuccessorBundle.bind(fixture.native);
    fixture.native.readSuccessorBundle = async (...args) => mutate(await original(...args));
    const recovered = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: fixture.input.idempotencyKey,
    });
    assert.equal(recovered.ok, false, JSON.stringify({ kind, recovered }));
    assert.equal(recovered.error, 'MANUAL_CLEANUP_REQUIRED');
    assert.equal(recovered.routeDisposition, 'no-route');
    assert.equal(Object.hasOwn(recovered, 'pending'), false);
    const state = await fixture.native.readManagementState();
    assert.equal(state.recovery.phase, 'manual_cleanup');
    assert.equal(state.recovery.routeDisposition, 'no-route');
    assert.equal(state.recovery.txId, fixture.started.txId);
    const cleanup = JSON.parse(fileEnding(fixture.files, '/terminal-close.json'));
    assert.equal(cleanup.txId, fixture.started.txId);
    assert.equal(cleanup.routeDisposition, 'no-route');
    assert.equal(cleanup.blockedUntilOwnerAction, true);
    assert.ok(fileEnding(fixture.files, '/terminal-close.json'));
  }
});
test('cleanup lineage read failure preserves token high-water state with unresolved evidence', async () => {
  const fixture = await terminalSuccessorFixture();
  const before = await fixture.native.readManagementState();
  const floor = structuredClone(before.tokenFloor);
  const attestation = structuredClone(before.tokenAttestation);
  const lineageGeneration = before.tokenConfigGeneration;
  fixture.native.readSuccessorTokenLineage = async () => {
    throw new Error('TOKEN_LINEAGE_READ_FAILED');
  };
  const recovered = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'conflicting-lineage-recovery-key',
  });
  assert.equal(recovered.ok, false, JSON.stringify(recovered));
  assert.equal(recovered.error, 'MANUAL_CLEANUP_REQUIRED');
  assert.equal(recovered.routeDisposition, 'no-route');
  const state = await fixture.native.readManagementState();
  assert.equal(state.recovery.phase, 'manual_cleanup');
  assert.equal(state.recovery.routeDisposition, 'no-route');
  assert.deepEqual(state.tokenFloor, floor);
  assert.deepEqual(state.tokenAttestation, attestation);
  assert.equal(state.tokenConfigGeneration, lineageGeneration);
  assert.deepEqual(state.recovery.tokenLineage, {
    phase: 'unresolved',
    reason: 'TOKEN_LINEAGE_READ_FAILED',
    floorFingerprint: floor.floorFingerprint,
    attestationFingerprint: attestation.attestationFingerprint,
    generation: lineageGeneration,
  });
});
test('public recover completes an interrupted no-reader successor without reader proof', async () => {
  const fixture = await terminalMappingSuccessorFixture();
  setSuccessorHeadPhase(fixture, 'reader-pending');
  const recovered = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recoverable-mapping-key',
  });
  assert.equal(recovered.ok, true, JSON.stringify(recovered));
  assert.equal(recovered.pending, false);
  assert.equal(recovered.idempotent, true);
  assert.equal(recovered.routeDisposition, 'no-route');
  const head = JSON.parse(fileEnding(fixture.files, '/authority-head.json'));
  const receipt = JSON.parse(fileEnding(fixture.files, `/authority-successor-receipt-${fixture.successor.txId}.json`));
  const marker = await fixture.native.readManagedHistoryMarker();
  assert.equal(head.phase, 'terminal');
  assert.equal(head.receiptFingerprint, receipt.receiptFingerprint);
  assert.equal(head.historyMarkerFingerprint, marker.markerFingerprint);
  assert.equal(marker.sequence, head.sequence);
  assert.equal((await fixture.native.readManagementState()).recovery.phase, 'terminal');
});

test('public recover completes legacy-retained no-reader successor from the predecessor proof', async () => {
  const fixture = await terminalSuccessorFixture();
  const beforeBytes = Buffer.from(fixture.files.get('C:/state/channels.json'));
  const before = await fixture.native.readRetainedTargetProof();
  setSuccessorHeadPhase(fixture, 'reader-pending');
  const recovered = await new ManagementRuntime({ native: fixture.native }).execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recoverable-successor-key',
  });
  assert.equal(recovered.ok, true, JSON.stringify(recovered));
  assert.equal(recovered.pending, false);
  assert.equal(recovered.idempotent, true);
  assert.equal(recovered.routeDisposition, 'no-route');
  assert.deepEqual(fixture.files.get('C:/state/channels.json'), beforeBytes);
  const after = await fixture.native.readRetainedTargetProof();
  assert.equal(after.sourceKind, 'legacy-retained');
  assert.equal(after.fenceGeneration, before.fenceGeneration);
  assert.equal(after.targetFingerprint, before.targetFingerprint);
  assert.equal(after.identityFingerprint, before.identityFingerprint);
  assert.equal(after.aclFingerprint, before.aclFingerprint);
  assert.equal(JSON.parse(fileEnding(fixture.files, '/authority-head.json')).phase, 'terminal');
  const state = await fixture.native.readManagementState();
  const floor = JSON.parse(fileEnding(fixture.files, '/token-floor.json'));
  const attestation = JSON.parse(fileEnding(fixture.files, '/attestation.json'));
  assert.equal(state.recovery.phase, 'terminal');
  assert.deepEqual(state.tokenFloor, floor);
  assert.equal(state.tokenFloor.floorFingerprint, floor.floorFingerprint);
  assert.equal(state.tokenFloor.fenceGeneration, floor.fenceGeneration);
  assert.equal(state.tokenFloor.highestCommittedGeneration, state.tokenConfigGeneration);
  assert.equal(state.tokenFloor.lastAttestationFingerprint, attestation.attestationFingerprint);
  assert.equal(state.tokenAttestation.attestationFingerprint, attestation.attestationFingerprint);
  assert.equal(state.tokenAttestation.finalityFingerprint, floor.floorFingerprint);
});
test('missing post-Genesis fence floor converges to no-route manual cleanup without synthesis', async () => {
  const fixture = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: fixture.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=secret'))).ok, true);
  const before = await fixture.native.readManagementState();
  const floorPath = [...fixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/fence-generation-floor.json'));
  assert.ok(floorPath);
  fixture.files.delete(floorPath);
  const result = await runtime.execute('tokens-attest', {
    actorPrincipal: owner, actorSecret: secret, hostTokens: 'host=rotated-secret', idempotencyKey: 'missing-fence-floor',
  });
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.error, 'MANUAL_CLEANUP_REQUIRED');
  const state = await fixture.native.readManagementState();
  assert.equal(state.recovery.phase, 'manual_cleanup');
  assert.equal(state.recovery.routeDisposition, 'no-route');
  assert.equal(state.fenceGeneration, before.fenceGeneration);
  assert.equal([...fixture.files.keys()].some((path) => path.replaceAll('\\', '/').endsWith('/fence-generation-floor.json')), false);
  assert.ok(fileEnding(fixture.files, '/terminal-close.json'));
});
test('public recover persists transaction-bound cleanup when successor marker or reader floor is missing', async () => {
  const markerFixture = await terminalMappingSuccessorFixture();
  setSuccessorHeadPhase(markerFixture, 'reader-pending');
  const markerPath = [...markerFixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('.managed-history.json'));
  assert.ok(markerPath);
  markerFixture.files.delete(markerPath);
  const markerResult = await new ManagementRuntime({ native: markerFixture.native }).execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'recoverable-mapping-key',
  });
  assert.equal(markerResult.error, 'MANUAL_CLEANUP_REQUIRED', JSON.stringify(markerResult));
  const markerState = await markerFixture.native.readManagementState();
  assert.equal(markerState.recovery.phase, 'manual_cleanup');
  assert.equal(markerState.recovery.txId, markerFixture.successor.txId);
  assert.equal(markerState.recovery.routeDisposition, 'no-route');
  assert.ok(fileEnding(markerFixture.files, '/terminal-close.json'));

  const floorFixture = await boundReaderRuntime();
  floorFixture.setPrincipal(owner);
  const before = await floorFixture.native.readManagementState();
  const candidate = mappingInput('missing-reader-floor-map');
  const started = await floorFixture.runtime.execute('mapping-reconcile', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'missing-reader-floor-successor',
    mappingId: candidate.mapping.mappingId, ...candidate, expectedRevision: before.revision, expectedFingerprint: null,
  });
  assert.equal(started.pending, true, JSON.stringify(started));
  const floorPath = [...floorFixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/reader-version-floor.json'));
  assert.ok(floorPath);
  floorFixture.files.delete(floorPath);
  const floorResult = await floorFixture.runtime.execute('recover', {
    actorPrincipal: owner, actorSecret: secret, idempotencyKey: 'missing-reader-floor-successor',
  });
  assert.equal(floorResult.error, 'MANUAL_CLEANUP_REQUIRED', JSON.stringify(floorResult));
  const floorState = await floorFixture.native.readManagementState();
  assert.equal(floorState.recovery.phase, 'manual_cleanup');
  assert.equal(floorState.recovery.txId, started.txId);
  assert.equal(floorState.recovery.routeDisposition, 'no-route');
  assert.ok(fileEnding(floorFixture.files, '/terminal-close.json'));
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
test('Genesis replay survives successor token and authority tail mutations', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = genesisInput('host=secret');
  assert.equal((await runtime.execute('genesis', input)).ok, true);
  const genesisState = await harness.native.readManagementState();

  const successor = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    hostTokens: 'host=rotated-secret',
    idempotencyKey: 'genesis-replay-successor',
  });
  assert.equal(successor.ok, true, JSON.stringify(successor));
  const successorState = await harness.native.readManagementState();
  assert.ok(successorState.tokenConfigGeneration > genesisState.tokenConfigGeneration);
  assert.ok(successorState.authorityEpoch > genesisState.authorityEpoch);

  const replay = await runtime.execute('genesis', input);
  assert.equal(replay.ok, true, JSON.stringify(replay));
  assert.equal(replay.idempotent, true);
  assert.equal(replay.genesisTxId, genesisState.genesis.txId);
});
test('Genesis terminal replay reopens the exact durable proof graph and fails closed on proof drift', async () => {
  const valid = adapter({ legacy: false });
  const validRuntime = new ManagementRuntime({ native: valid.native });
  const input = genesisInput('host=secret');
  const filePath = (files, ending) => [...files.keys()].find((path) => path.replaceAll('\\', '/').endsWith(ending));
  assert.equal((await validRuntime.execute('genesis', input)).ok, true);
  const replay = await validRuntime.execute('genesis', input);
  assert.equal(replay.ok, true, JSON.stringify(replay));
  assert.equal(replay.idempotent, true);

  for (const tamper of [
    (harness) => harness.files.delete(filePath(harness.files, '/receipt.json')),
    (harness) => harness.files.set(filePath(harness.files, '/rvf.json'), Buffer.from('{}')),
    (harness) => harness.files.set(filePath(harness.files, '/z-finality.json'), Buffer.from('{}')),
    (harness) => {
      const path = filePath(harness.files, '.managed-history.json');
      harness.files.delete(path);
    },
    (harness) => {
      const path = filePath(harness.files, '.managed-history.json');
      const marker = JSON.parse(harness.files.get(path));
      marker.markerFingerprint = '0'.repeat(64);
      harness.files.set(path, Buffer.from(canonicalJson(marker)));
    },
  ]) {
    const harness = adapter({ legacy: false });
    const runtime = new ManagementRuntime({ native: harness.native });
    assert.equal((await runtime.execute('genesis', input)).ok, true);
    tamper(harness);
    const result = await runtime.execute('genesis', input);
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'MANUAL_CLEANUP_REQUIRED');
    assert.equal(result.routeDisposition, 'no-route');
    const state = await harness.native.readManagementState();
    assert.equal(state.recovery.phase, 'manual_cleanup');
    assert.equal(state.recovery.routeDisposition, 'no-route');
    assert.ok(fileEnding(harness.files, '/terminal-close.json'));
  }
});
test('Genesis replay refuses missing finality receipt before suffix reconstruction', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const input = genesisInput('host=secret');
  assert.equal((await runtime.execute('genesis', input)).ok, true);
  const statePath = [...harness.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/management-state.json'));
  const state = JSON.parse(harness.files.get(statePath));
  state.genesis = null;
  state.recovery.phase = 'replaced';
  harness.files.set(statePath, Buffer.from(canonicalJson(state)));
  const receiptPath = [...harness.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith('/receipt.json'));
  harness.files.delete(receiptPath);

  const replay = await runtime.execute('genesis', input);
  assert.equal(replay.ok, false, JSON.stringify(replay));
  assert.equal(replay.error, 'MANUAL_CLEANUP_REQUIRED');
  assert.equal(replay.routeDisposition, 'no-route');
  assert.equal((await harness.native.readManagementState()).recovery.phase, 'manual_cleanup');
  assert.ok(fileEnding(harness.files, '/terminal-close.json'));
});
test('pending bootstrap rejects a foreign authority reservation without bot writes', async () => {
  const harness = await boundReaderRuntime({ complete: false });
  const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
  const reservationPath = filePathEnding(harness.files, `/authority-reservation-${request.genesisTxId}.json`);
  const foreign = JSON.parse(harness.files.get(reservationPath));
  foreign.txId = 'foreign-authority-reservation';
  foreign.reservationFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(foreign).filter(([key]) => key !== 'reservationFingerprint')),
  );
  harness.files.set(reservationPath, Buffer.from(canonicalJson(foreign)));
  harness.setPrincipal(botPrincipal);
  const writes = harness.writes.length;
  await assert.rejects(
    harness.native.readPendingReaderBootstrap(),
    /pending reader authority is incomplete or inconsistent/,
  );
  assert.equal(harness.writes.length, writes);
});

test('post-terminal bot projection mutation is refused without writes', async () => {
  const harness = await boundReaderRuntime({ complete: true });
  const projection = JSON.parse(fileEnding(harness.files, '/bot-state/reader-projection.json'));
  harness.setPrincipal(botPrincipal);
  const writes = harness.writes.length;
  await assert.rejects(
    harness.native.writeBotReaderProjection(projection),
    /handshake-pending closed lifecycle/,
  );
  assert.equal(harness.writes.length, writes);
});

test('no-reader finality rejects foreign authority tuples and admission records without writes', async () => {
  const foreignHarness = adapter({ legacy: false });
  const foreignRuntime = new ManagementRuntime({ native: foreignHarness.native });
  const completed = await foreignRuntime.execute('genesis', genesisInput('host=no-reader-finality'));
  assert.equal(completed.ok, true, JSON.stringify(completed));
  const request = JSON.parse(fileEnding(foreignHarness.files, '/genesis-request.json'));
  const reservationPath = filePathEnding(foreignHarness.files, `/authority-reservation-${request.genesisTxId}.json`);
  const foreign = JSON.parse(foreignHarness.files.get(reservationPath));
  foreign.txId = 'foreign-authority-reservation';
  foreign.reservationFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(foreign).filter(([key]) => key !== 'reservationFingerprint')),
  );
  foreignHarness.files.set(reservationPath, Buffer.from(canonicalJson(foreign)));
  const proof = JSON.parse(fileEnding(foreignHarness.files, '/rvf.json'));
  const foreignWrites = foreignHarness.writes.length;
  await assert.rejects(
    foreignHarness.native.writeFinalityProof(proof),
    /complete bound-reader finality graph is invalid/,
  );
  assert.equal(foreignHarness.writes.length, foreignWrites);

  const archiveHarness = adapter({ legacy: false });
  const archiveRuntime = new ManagementRuntime({ native: archiveHarness.native });
  const archiveCompleted = await archiveRuntime.execute('genesis', genesisInput('host=no-reader-archive'));
  assert.equal(archiveCompleted.ok, true, JSON.stringify(archiveCompleted));
  archiveHarness.files.set(
    filePathEnding(archiveHarness.files, '/genesis-request.json').replace(/genesis-request\.json$/, '') + 'admission-request.json',
    Buffer.from('{}'),
  );
  const archiveProof = JSON.parse(fileEnding(archiveHarness.files, '/rvf.json'));
  const archiveWrites = archiveHarness.writes.length;
  await assert.rejects(
    archiveHarness.native.writeFinalityProof(archiveProof),
    /complete bound-reader finality graph is invalid|no-reader graph contains reader records/,
  );
  assert.equal(archiveHarness.writes.length, archiveWrites);
});
test('no-reader finality rejects reachable admission identifiers from durable state', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  const completed = await runtime.execute('genesis', genesisInput('host=no-reader-reachable-admission'));
  assert.equal(completed.ok, true, JSON.stringify(completed));
  const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
  const candidateRequest = buildAdmissionRequest({
    requestId: 'reachable-no-reader-request',
    genesisTxId: request.genesisTxId,
    generation: request.generation,
    fenceGeneration: request.fenceGeneration,
    readerInstanceId: 'reachable-reader',
    readerStartNonce: 'reachable-start',
    routeFingerprint: 'no-route',
    nonce: 'reachable-nonce',
    expiresAt: Date.now() + 30_000,
  });
  const candidateGrant = buildAdmissionGrant(candidateRequest, {
    grantId: 'reachable-no-reader-grant',
    expiresAt: candidateRequest.expiresAt,
  });
  const statePath = filePathEnding(harness.files, '/management-state.json');
  const state = JSON.parse(harness.files.get(statePath));
  state.recovery.readerHandshake = {
    requestFingerprint: candidateRequest.requestFingerprint,
    grantFingerprint: candidateGrant.grantFingerprint,
    expiresAt: candidateGrant.expiresAt,
    request: candidateRequest,
    grant: candidateGrant,
  };
  harness.files.set(statePath, Buffer.from(canonicalJson(state)));
  const root = filePathEnding(harness.files, '/genesis-request.json').replace('genesis-request.json', '');
  harness.files.set(`${root}admission-request-${candidateRequest.requestId}.json`, Buffer.from(canonicalJson(candidateRequest)));
  harness.files.set(`${root}admission-grant-${candidateGrant.grantId}.json`, Buffer.from(canonicalJson(candidateGrant)));
  const proof = JSON.parse(fileEnding(harness.files, '/rvf.json'));
  const writes = harness.writes.length;
  await assert.rejects(
    harness.native.writeFinalityProof(proof),
    /complete bound-reader finality graph is invalid/,
  );
  assert.equal(harness.writes.length, writes);
});
test('unbound management-state archive IDs cannot satisfy no-reader absence proof', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=unbound-archive-index'))).ok, true);
  const statePath = filePathEnding(harness.files, '/management-state.json');
  const state = JSON.parse(harness.files.get(statePath));
  state.admissionArchiveIds = ['unbound-archive-id'];
  harness.files.set(statePath, Buffer.from(canonicalJson(state)));
  const root = filePathEnding(harness.files, '/genesis-request.json').replace(/genesis-request\.json$/, '');
  harness.files.set(`${root}admission-request-unbound-archive-id.json`, Buffer.from('{}'));
  const proof = JSON.parse(fileEnding(harness.files, '/rvf.json'));
  const writes = harness.writes.length;
  await assert.rejects(
    harness.native.writeFinalityProof(proof),
    /complete bound-reader finality graph is invalid|archive index|no-reader/i,
  );
  assert.equal(harness.writes.length, writes);
});
test('managed successor snapshot carries sequence-three history predecessors and committed epoch archive', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=sequence-three'))).ok, true);
  for (const index of [1, 2]) {
    const state = await harness.native.readManagementState();
    let result;
    if (index === 1) {
      const candidate = mappingInput(`sequence-three-${index}`, state.mappingGeneration + 1, state.fenceGeneration, String(123 + index));
      result = await runtime.execute('mapping-reconcile', {
        actorPrincipal: owner,
        actorSecret: secret,
        idempotencyKey: `sequence-three-${index}`,
        mappingId: candidate.mapping.mappingId,
        ...candidate,
        expectedRevision: state.revision,
        expectedFingerprint: null,
      });
    } else {
      result = await runtime.execute('tokens-attest', {
        actorPrincipal: owner,
        actorSecret: secret,
        idempotencyKey: `sequence-three-${index}`,
        hostTokens: 'host=sequence-three-rotated',
      });
    }
    assert.equal(result.ok, true, JSON.stringify({ result, state }));
  }
  harness.setPrincipal(botPrincipal);
  const snapshot = await harness.native.readManagedMappingSnapshot();
  assert.equal(snapshot.successorBundle.head.sequence, 3);
  assert.equal(snapshot.successorBundle.historyMarkerPredecessors.length, 1);
  assert.equal(snapshot.successorBundle.historyMarkerPredecessors[0].sequence, 2);
  assert.ok(snapshot.successorBundle.authorityEpochArchive);
  assert.deepEqual(
    JSON.parse(snapshot.historyMarkerPredecessorsBytes.toString('utf8')),
    snapshot.successorBundle.historyMarkerPredecessors,
  );
});

test('managed successor snapshot rejects a missing committed epoch archive', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=missing-epoch-archive'))).ok, true);
  const state = await harness.native.readManagementState();
  const candidate = mappingInput('missing-epoch-archive-map', state.mappingGeneration + 1);
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'missing-epoch-archive',
    mappingId: candidate.mapping.mappingId,
    ...candidate,
    expectedRevision: state.revision,
    expectedFingerprint: null,
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  const head = JSON.parse(fileEnding(harness.files, '/authority-head.json'));
  const epoch = JSON.parse(fileEnding(harness.files, '/authority-epoch.json'));
  const archivePath = filePathEnding(harness.files, `/authority-epoch-${epoch.epoch}-committed.json`);
  assert.ok(archivePath);
  harness.files.delete(archivePath);
  harness.setPrincipal(botPrincipal);
  await assert.rejects(harness.native.readManagedMappingSnapshot(), /epoch|successor|bundle/i);
  assert.equal(head.phase, 'terminal');
});

test('no-reader finality, recheck, and snapshot reject reachable immutable admission archives', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=no-reader-archive-proof'))).ok, true);
  const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
  const root = filePathEnding(harness.files, '/genesis-request.json').replace(/genesis-request\.json$/, '');
  const reachableArchive = `${root}admission-request-${request.genesisTxId}.json`;
  harness.files.set(reachableArchive, Buffer.from(canonicalJson({ orphan: true })));
  const proof = JSON.parse(fileEnding(harness.files, '/rvf.json'));
  const zFinality = JSON.parse(fileEnding(harness.files, '/z-finality.json'));
  const receipt = JSON.parse(fileEnding(harness.files, '/receipt.json'));
  harness.setPrincipal(owner);
  await assert.rejects(
    harness.native.writeFinalityProof(proof),
    /reachable immutable admission archives|complete bound-reader finality graph/i,
  );
  assert.equal(
    await harness.native.recheckAdmissionFinality({
      request,
      zFinality,
      readerProjection: null,
      admissionAck: null,
      finalityProof: proof,
      receipt,
    }),
    false,
  );
  harness.setPrincipal(botPrincipal);
  await assert.rejects(harness.native.readManagedMappingSnapshot(), /reachable immutable admission archives|finality/i);
});
