import assert from 'node:assert/strict';
import test from 'node:test';
import { ManagementRuntime } from '../src/management-runtime.js';
import { createManagementNativeForTest } from '../../native-control/test/helpers/management-native.js';
import { validateManagedProof } from '../src/managed-authority-reader.js';
import { createTestManagedAuthorityReader } from './helpers/managed-authority-reader.js';
import { buildAdmissionAck, buildAdmissionGrant, buildAdmissionRequest } from '../../shared/admission-envelope.js';
import { canonicalJson, canonicalJsonHash } from '../../shared/strict-json.js';
import { fingerprintManagedMappingRecord, fingerprintManagedRouteRecord, managedHostSetFingerprint, validateManagedChannelsV2 } from '../../shared/mapping-envelope.js';
import { buildAuthoritySuccessorRecord } from '../../shared/successor-envelope.js';

const owner = { kind: 'sid', value: 'S-1-5-21-100' };
const target = { kind: 'sid', value: 'S-1-5-21-103' };
const botPrincipal = { kind: 'sid', value: 'S-1-5-21-101' };
const recoveryPrincipal = { kind: 'sid', value: 'S-1-5-21-102' };
const nonowner = { kind: 'sid', value: 'S-1-5-21-104' };
const roles = { managementSid: owner.value, botSid: botPrincipal.value, recoverySid: recoveryPrincipal.value, systemSid: 'S-1-5-18' };
const provisioning = {
  management: 'a'.repeat(64),
  bot: 'b'.repeat(64),
  recovery: 'c'.repeat(64),
};
const secret = 'owner-secret-is-long-enough';
const nonownerSecret = 'nonowner-secret-is-long-enough';
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
  const directories = new Set();
  if (legacy) files.set('C:/state/channels.json', Buffer.from('{"legacy":true}'));
  const writes = [];
  const payloads = [];
  let currentPrincipal = initialPrincipal;
  const lowLevel = {
    open_verified_parent: async (path) => ({ path: path.replaceAll("\\", "/").slice(0, path.replaceAll("\\", "/").lastIndexOf('/')) }), open_no_follow: async () => {},
    read_identity: async (path) => path.endsWith('.genesis-bootstrap-blocker') && !files.has(path) ? null : ({ path: path.replaceAll("\\", "/"), owner: roleBindings.managementSid }), read_acl: async () => 'protected:M,B,R,SYSTEM',
    path_exists_no_follow: async (path) => files.has(path) || directories.has(path) || [...files.keys()].some((name) => name.replaceAll("\\", "/").startsWith(`${path.replaceAll("\\", "/")}/`)),
    verify_exact_role_acl: async () => true, verify_role_sid_not_group: () => true, set_exact_role_acl: async () => {}, remove_verified_file: async (path) => { files.delete(path); },
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
    ensure_control_directory: async (path) => { directories.add(path); },
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
    principal_access_check: async (_path, _kind, principal, mode, ..._role) =>
      mode === 'read' || (mode === 'write' && principal === roleBindings.managementSid),
  };
  const baseNative = createManagementNativeForTest({ lowLevel, configPath: 'C:/state/channels.json', roles: roleBindings, platform });
  const native = { ...baseNative };
  return { files, directories, writes, payloads, setPrincipal: (value) => { currentPrincipal = value; }, native };
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
  return { ...harness, runtime, input, request, floor, zFinality, grant, fence, lease, projection, readerState };
}
test('terminal Genesis proof remains reopenable after its admission grant expires', async () => {
  const harness = await boundReaderRuntime({ complete: true });
  const request = JSON.parse(fileEnding(harness.files, '/genesis-request.json'));
  const grant = JSON.parse(fileEnding(harness.files, '/admission-grant.json'));
  const evidence = {
    request,
    zFinality: JSON.parse(fileEnding(harness.files, '/z-finality.json')),
    readerProjection: JSON.parse(fileEnding(harness.files, '/bot-state/reader-projection.json')),
    admissionAck: JSON.parse(fileEnding(harness.files, '/bot-state/acknowledgement.json')),
    finalityProof: JSON.parse(fileEnding(harness.files, '/rvf.json')),
    receipt: JSON.parse(fileEnding(harness.files, '/receipt.json')),
  };
  harness.setPrincipal(owner);
  const originalNow = Date.now;
  Date.now = () => grant.expiresAt + 1;
  try {
    assert.equal(await harness.native.recheckAdmissionFinality(evidence), true);
  } finally {
    Date.now = originalNow;
  }
});
test('bot write refuses fail-closed with zero writes when bot-state is absent after Genesis provisioning', async () => {
  const { native, setPrincipal, directories, writes, lease } = await boundReaderRuntime({ complete: false });
  // Genesis already provisioned bot-state as M (the control-root-adjacent directory). Simulate it
  // having been removed or never durably provisioned: a bot writer must refuse fail-closed rather
  // than silently (re)creating the M-owned directory itself.
  for (const dir of [...directories]) {
    if (dir.replaceAll('\\', '/').endsWith('/bot-state')) directories.delete(dir);
  }
  setPrincipal(botPrincipal);
  const before = writes.length;
  await assert.rejects(native.acquireBotLease(lease), (error) => {
    assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
    assert.equal(error.operation, 'ensure_bot_directory');
    assert.equal(error.writes, 0);
    return true;
  });
  assert.equal(writes.length, before);
});
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
    mappingId, hostId: 'host', fenceGeneration, mappingGeneration: generation, workspaceGeneration: generation, mappingVersion: 1,
    sourcePlatform: 'posix', workspaceId: 'workspace-a', workDir: null,
    sourceRoot: '/source', containerRoot: '/workspace', volumeIdentity: 'volume-a',
    casePolicy: 'sensitive', immutableDefault: false, mappingFingerprint: null,
  });
  const routes = (Array.isArray(channelId) ? channelId : [channelId]).map((currentChannelId) =>
    fingerprintManagedRouteRecord({
      channelId: currentChannelId, hostId: mapping.hostId, mappingId: mapping.mappingId,
      fenceGeneration: mapping.fenceGeneration,
      mappingGeneration: mapping.mappingGeneration, mappingVersion: mapping.mappingVersion,
      workspaceGeneration: mapping.workspaceGeneration,
      sourcePlatform: mapping.sourcePlatform, workspaceId: mapping.workspaceId,
      workDir: mapping.workDir, routeFingerprint: null,
    }, mapping));
  return { mapping, routes };
}
const mappingSemantics = (mapping) => Object.fromEntries(
  Object.entries(mapping).filter(([key]) => !['fenceGeneration', 'mappingFingerprint'].includes(key)),
);
const routeSemantics = (route) => Object.fromEntries(
  Object.entries(route).filter(([key]) => !['fenceGeneration', 'routeFingerprint'].includes(key)),
);
const authorityRecord = (files, kind, txId) =>
  JSON.parse(fileEnding(files, `/${kind}-${txId}.json`));
const mappingArchivePath = (files, mappingId, generation) =>
  filePathEnding(files, `/mapping-generation-${encodeURIComponent(mappingId)}-${generation}.json`);
const mappingHandoff = (files, operation, oldMappingId, newMappingId) => {
  for (const [path, bytes] of files) {
    if (!path.replaceAll('\\', '/').includes('/mapping-handoff-')) continue;
    const record = JSON.parse(bytes);
    if (record.operation === operation && record.oldMappingId === oldMappingId && record.newMappingId === newMappingId) {
      return record;
    }
  }
  return null;
};
async function assertTerminalManagedSuccessor(harness, before, result, {
  operation,
  mappingId = null,
  mappingGenerationDelta,
  tokenConfigGenerationDelta,
}) {
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.pending, false);
  assert.equal(result.routeDisposition, 'no-route');
  const after = await harness.native.readManagementState();
  const proof = await harness.native.readRetainedTargetProof();
  const fenceFloor = await harness.native.readFenceGenerationFloor();
  const authorityFloor = await harness.native.readAuthorityEpochFloor();
  assert.equal(proof.sourceKind, 'managed-v1');
  assert.doesNotThrow(() => validateManagedChannelsV2(proof.snapshot));
  assert.deepEqual(after.mappings, proof.snapshot.mappings);
  assert.deepEqual(after.routes, proof.snapshot.routes);
  assert.equal(after.revision, before.revision + 1);
  assert.equal(after.authorityEpoch, before.authorityEpoch + 1);
  assert.equal(after.fenceGeneration, before.fenceGeneration + 1);
  assert.equal(after.mappingGeneration, before.mappingGeneration + mappingGenerationDelta);
  assert.equal(after.tokenConfigGeneration, before.tokenConfigGeneration + tokenConfigGenerationDelta);
  assert.equal(fenceFloor.highestReservedFenceGeneration, after.fenceGeneration);
  assert.equal(fenceFloor.highestCommittedFenceGeneration, after.fenceGeneration);
  assert.equal(fenceFloor.lastReservationTxId, result.txId);
  assert.equal(fenceFloor.lastCommittedTxId, result.txId);
  assert.equal(authorityFloor.highestReservedAuthorityEpoch, after.authorityEpoch);
  assert.equal(authorityFloor.highestCommittedAuthorityEpoch, after.authorityEpoch);
  assert.equal(after.admission.phase, 'closed');
  assert.equal(after.admission.finalityFingerprint, null);
  assert.equal(proof.snapshot.revision, after.revision);
  assert.equal(proof.snapshot.authorityEpoch, after.authorityEpoch);
  assert.equal(proof.snapshot.fenceGeneration, after.fenceGeneration);
  assert.equal(proof.snapshot.mappingGeneration, after.mappingGeneration);
  assert.equal(proof.snapshot.tokenConfigGeneration, after.tokenConfigGeneration);
  for (const mapping of Object.values(after.mappings)) assert.equal(mapping.fenceGeneration, after.fenceGeneration);
  for (const route of Object.values(after.routes)) assert.equal(route.fenceGeneration, after.fenceGeneration);

  const request = authorityRecord(harness.files, 'authority-successor-request', result.txId);
  const close = authorityRecord(harness.files, 'authority-close-proof', result.txId);
  const baseline = authorityRecord(harness.files, 'authority-successor-baseline', result.txId);
  const finality = authorityRecord(harness.files, 'authority-successor-finality', result.txId);
  const receipt = authorityRecord(harness.files, 'authority-successor-receipt', result.txId);
  const head = JSON.parse(fileEnding(harness.files, '/authority-head.json'));
  const marker = await harness.native.readManagedHistoryMarker();
  assert.equal(request.operation, operation);
  assert.equal(request.previousRevision, before.revision);
  assert.equal(request.candidateRevision, after.revision);
  assert.equal(request.previousFenceGeneration, before.fenceGeneration);
  assert.equal(request.candidateFenceGeneration, after.fenceGeneration);
  assert.equal(request.candidateSnapshotFingerprint, proof.snapshot.configFingerprint);
  assert.equal(request.candidateTargetFingerprint, proof.targetFingerprint);
  assert.equal(request.candidateMappingGeneration, after.mappingGeneration);
  assert.equal(request.candidateTokenConfigGeneration, after.tokenConfigGeneration);
  assert.equal(close.affectedScope, operation === 'tokens-attest' ? 'all' : 'mapping');
  assert.deepEqual(close.affectedMappingIds, operation === 'tokens-attest' ? [] : [mappingId]);
  assert.deepEqual(close.affectedRouteFingerprints, []);
  assert.equal(close.admissionPhaseBefore, 'closed');
  assert.equal(close.admissionPhaseAfter, 'closed-drained');
  assert.equal(close.admissionDrained, true);
  assert.equal(close.outstandingRouteGrantCount, 0);
  assert.equal(close.routeDisposition, 'no-route');
  assert.equal(baseline.fenceGeneration, after.fenceGeneration);
  assert.equal(baseline.candidateSnapshotFingerprint, proof.snapshot.configFingerprint);
  assert.equal(baseline.candidateTargetFingerprint, proof.targetFingerprint);
  assert.equal(finality.fenceGeneration, after.fenceGeneration);
  assert.equal(finality.targetFingerprint, proof.targetFingerprint);
  assert.equal(finality.wrapperFingerprint, proof.wrapperFingerprint);
  assert.equal(finality.revision, after.revision);
  assert.equal(finality.authorityEpoch, after.authorityEpoch);
  assert.equal(finality.mappingGeneration, after.mappingGeneration);
  assert.equal(finality.tokenConfigGeneration, after.tokenConfigGeneration);
  assert.equal(finality.routeDisposition, 'no-route');
  assert.equal(receipt.fenceGeneration, after.fenceGeneration);
  assert.equal(receipt.revision, after.revision);
  assert.equal(receipt.authorityEpoch, after.authorityEpoch);
  assert.equal(receipt.mappingGeneration, after.mappingGeneration);
  assert.equal(receipt.tokenConfigGeneration, after.tokenConfigGeneration);
  assert.equal(receipt.snapshotFingerprint, finality.snapshotFingerprint);
  assert.equal(receipt.routeDisposition, 'no-route');
  assert.equal(head.phase, 'terminal');
  assert.equal(head.txId, result.txId);
  assert.equal(head.receiptFingerprint, receipt.receiptFingerprint);
  assert.equal(head.historyMarkerFingerprint, marker.markerFingerprint);
  assert.equal(head.fenceGeneration, after.fenceGeneration);
  assert.equal(marker.fenceGeneration, after.fenceGeneration);
  assert.equal(after.recovery.phase, 'terminal');
  assert.equal(after.recovery.txId, result.txId);
  assert.equal(after.recovery.finalityFingerprint, finality.finalityFingerprint);
  return { after, proof, request, close, baseline, finality, receipt, head, marker };
}
async function reconcileMapping(harness, runtime, {
  mappingId,
  channelIds,
  idempotencyKey,
}) {
  const before = await harness.native.readManagementState();
  const candidate = mappingInput(mappingId, before.mappingGeneration + 1, before.fenceGeneration, channelIds);
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey,
    mappingId,
    ...candidate,
    expectedRevision: before.revision,
    expectedFingerprint: Object.hasOwn(before.mappings, mappingId) ? before.mappings[mappingId].mappingFingerprint : null,
  });
  const terminal = await assertTerminalManagedSuccessor(harness, before, result, {
    operation: 'mapping-reconcile',
    mappingId,
    mappingGenerationDelta: 1,
    tokenConfigGenerationDelta: 0,
  });
  return { before, candidate, result, ...terminal };
}
const mappingPreconditionsInput = (mappingId, actorPrincipal = owner, actorSecret = secret) => ({
  actorPrincipal,
  actorSecret,
  mappingId,
});
const durableFileSnapshot = (files) =>
  new Map([...files].map(([path, bytes]) => [path, Buffer.from(bytes)]));
const assertMappingPreconditionsFailure = (result, exitCode, error) => {
  assert.deepEqual(Object.keys(result).sort(), ['error', 'exitCode', 'ok', 'routeDisposition']);
  assert.deepEqual(result, {
    ok: false,
    exitCode,
    error,
    routeDisposition: 'no-route',
  });
};
const assertMappingPreconditionsSuccess = (result, mappingId, expectedRevision, expectedFingerprint) => {
  assert.deepEqual(Object.keys(result).sort(), [
    'exitCode',
    'expectedFingerprint',
    'expectedRevision',
    'mappingId',
    'ok',
    'routeDisposition',
  ]);
  assert.deepEqual(result, {
    ok: true,
    exitCode: 0,
    mappingId,
    expectedRevision,
    expectedFingerprint,
    routeDisposition: 'no-route',
  });
};
function secondStateNative(native, secondState, {
  auth,
  onSecondRead,
  onReadAuth,
  onLock,
} = {}) {
  let reads = 0;
  return {
    ...native,
    async readManagementState() {
      reads += 1;
      if (reads === 1) return native.readManagementState();
      onSecondRead?.(reads);
      return typeof secondState === 'function' ? secondState(reads) : secondState;
    },
    async readManagementAuth() {
      await onReadAuth?.();
      return auth === undefined ? native.readManagementAuth() : auth;
    },
    async withManagementLocks(locks, callback) {
      onLock?.('start', locks);
      try {
        return await callback();
      } finally {
        onLock?.('end', locks);
      }
    },
  };
}
function stateWithMappingId(state, mappingId) {
  const [original] = Object.values(state.mappings);
  const mapping = fingerprintManagedMappingRecord({
    ...structuredClone(original),
    mappingId,
    mappingFingerprint: null,
  });
  const routes = Object.fromEntries(Object.values(state.routes).map((originalRoute) => {
    const route = fingerprintManagedRouteRecord({
      ...structuredClone(originalRoute),
      mappingId,
      routeFingerprint: null,
    }, mapping);
    return [route.channelId, route];
  }));
  return {
    ...structuredClone(state),
    mappings: { [mappingId]: mapping },
    routes,
  };
}
async function mappingPreconditionsFixture({
  mappingIds = ['precondition-map'],
  channelIds = [['1401', '1402']],
} = {}) {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=preconditions'))).ok, true);
  for (let index = 0; index < mappingIds.length; index += 1) {
    await reconcileMapping(harness, runtime, {
      mappingId: mappingIds[index],
      channelIds: channelIds[index],
      idempotencyKey: `${mappingIds[index]}-create`,
    });
  }
  return { ...harness, runtime };
}
test('mapping-preconditions returns exact present, absent, and prototype-name pairs without durable mutation', async () => {
  const fixture = await mappingPreconditionsFixture();
  const beforeState = await fixture.native.readManagementState();
  const beforeAuth = await fixture.native.readManagementAuth();
  const beforeFiles = durableFileSnapshot(fixture.files);
  const directoriesBefore = new Set(fixture.directories);
  const writesBefore = fixture.writes.length;
  const payloadsBefore = fixture.payloads.length;
  const present = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  assertMappingPreconditionsSuccess(
    present,
    'precondition-map',
    beforeState.revision,
    beforeState.mappings['precondition-map'].mappingFingerprint,
  );
  for (const mappingId of ['a', 'a'.repeat(128), 'missing-map', 'constructor', 'toString', 'hasOwnProperty']) {
    const absent = await fixture.runtime.execute(
      'mapping-preconditions',
      mappingPreconditionsInput(mappingId),
    );
    assertMappingPreconditionsSuccess(absent, mappingId, beforeState.revision, null);
  }

  for (const mappingId of ['constructor', 'toString', 'hasOwnProperty']) {
    const projected = stateWithMappingId(beforeState, mappingId);
    const runtime = new ManagementRuntime({
      native: secondStateNative(fixture.native, projected),
    });
    const own = await runtime.execute(
      'mapping-preconditions',
      mappingPreconditionsInput(mappingId),
    );
    assertMappingPreconditionsSuccess(
      own,
      mappingId,
      projected.revision,
      projected.mappings[mappingId].mappingFingerprint,
    );
  }

  assert.equal(fixture.writes.length, writesBefore);
  assert.equal(fixture.payloads.length, payloadsBefore);
  assert.deepEqual(fixture.files, beforeFiles);
  assert.deepEqual(fixture.directories, directoriesBefore);
  assert.deepEqual(await fixture.native.readManagementState(), beforeState);
  assert.deepEqual(await fixture.native.readManagementAuth(), beforeAuth);
});

test('mapping-preconditions accepts the maximum safe positive locked revision', async () => {
  const fixture = await mappingPreconditionsFixture();
  const state = {
    ...await fixture.native.readManagementState(),
    revision: Number.MAX_SAFE_INTEGER,
  };
  const result = await new ManagementRuntime({
    native: secondStateNative(fixture.native, state),
  }).execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  assertMappingPreconditionsSuccess(
    result,
    'precondition-map',
    Number.MAX_SAFE_INTEGER,
    state.mappings['precondition-map'].mappingFingerprint,
  );
});

test('mapping-preconditions returns numeric absence for the post-Genesis empty graph', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=empty-preconditions'))).ok, true);
  const state = await harness.native.readManagementState();
  assert.equal(state.mappingGeneration, 0);
  assert.deepEqual(state.mappings, {});
  assert.deepEqual(state.routes, {});
  const filesBefore = durableFileSnapshot(harness.files);
  const writesBefore = harness.writes.length;
  const result = await runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('not-created'),
  );
  assertMappingPreconditionsSuccess(result, 'not-created', state.revision, null);
  assert.equal(harness.writes.length, writesBefore);
  assert.deepEqual(harness.files, filesBefore);
});

test('mapping-preconditions direct inputs and full runtime boundary use the exact error allowlist', async () => {
  const fixture = await mappingPreconditionsFixture();
  const filesBefore = durableFileSnapshot(fixture.files);
  const directoriesBefore = new Set(fixture.directories);
  const writesBefore = fixture.writes.length;
  for (const [input, exitCode, error] of [
    [{ actorSecret: secret, mappingId: 'precondition-map' }, 6, 'ACTOR_PRINCIPAL_INVALID'],
    [{ actorPrincipal: { kind: 'uid', value: 'uid:01' }, actorSecret: secret, mappingId: 'precondition-map' }, 6, 'ACTOR_PRINCIPAL_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: null }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: false }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: 1 }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: ['precondition-map'] }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: { value: 'precondition-map' } }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: '' }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: '.invalid' }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, actorSecret: secret, mappingId: 'a'.repeat(129) }, 6, 'MAPPING_ID_INVALID'],
    [{ actorPrincipal: owner, mappingId: 'precondition-map' }, 3, 'AUTH_SECRET_REQUIRED'],
    [{ actorPrincipal: owner, actorSecret: 'short', mappingId: 'precondition-map' }, 3, 'AUTH_SECRET_INVALID'],
  ]) {
    assertMappingPreconditionsFailure(
      await fixture.runtime.execute('mapping-preconditions', input),
      exitCode,
      error,
    );
  }

  for (const native of [null, {}, { readManagementState: async () => null }]) {
    assertMappingPreconditionsFailure(
      await new ManagementRuntime({ native }).execute(
        'mapping-preconditions',
        mappingPreconditionsInput('precondition-map'),
      ),
      5,
      'MANAGED_NATIVE_UNAVAILABLE',
    );
  }

  const missingFirstState = {
    ...fixture.native,
    readManagementState: async () => null,
  };
  assertMappingPreconditionsFailure(
    await new ManagementRuntime({ native: missingFirstState }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('precondition-map'),
    ),
    6,
    'MANAGEMENT_ROLE_BINDING_REQUIRED',
  );
  assertMappingPreconditionsFailure(
    await new ManagementRuntime({ native: missingFirstState }).execute(
      'mapping-preconditions',
      {},
    ),
    6,
    'MANAGEMENT_ROLE_BINDING_REQUIRED',
  );

  const nativeRefusal = {
    ...fixture.native,
    async configureManagementRoles() {
      const error = new Error('C:\\secret\\state and owner-secret-is-long-enough');
      error.code = 'ERR_NATIVE_CONTROL_REFUSED';
      error.reason = 'PRIVATE_NATIVE_REASON';
      throw error;
    },
  };
  const refused = await new ManagementRuntime({ native: nativeRefusal }).execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  assertMappingPreconditionsFailure(refused, 5, 'ERR_NATIVE_CONTROL_REFUSED');
  assert.equal(JSON.stringify(refused).includes('secret'), false);
  assert.equal(JSON.stringify(refused).includes('PRIVATE_NATIVE_REASON'), false);

  for (const errorFactory of [
    () => new Error('UPPERCASE_SECRET_CANARY'),
    () => new Error('ERR_NATIVE_CONTROL_REFUSED'),
    () => {
      const error = new Error('OWNER_REQUIRED');
      error.code = 'UPPERCASE_NATIVE_CODE_CANARY';
      return error;
    },
  ]) {
    const native = {
      ...fixture.native,
      async readManagementState() {
        throw errorFactory();
      },
    };
    const result = await new ManagementRuntime({ native }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('precondition-map'),
    );
    assertMappingPreconditionsFailure(result, 70, 'MANAGEMENT_FAILED');
    assert.equal(JSON.stringify(result).includes('CANARY'), false);
  }
  const lockedCanaryNative = secondStateNative(
    fixture.native,
    await fixture.native.readManagementState(),
  );
  lockedCanaryNative.readManagementAuth = async () => {
    throw new Error('UPPERCASE_LOCKED_SECRET_PATH_CANARY');
  };
  const lockedCanary = await new ManagementRuntime({ native: lockedCanaryNative }).execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  assertMappingPreconditionsFailure(lockedCanary, 70, 'MANAGEMENT_FAILED');
  assert.equal(JSON.stringify(lockedCanary).includes('CANARY'), false);
  assert.equal(fixture.writes.length, writesBefore);
  assert.deepEqual(fixture.files, filesBefore);
  assert.deepEqual(fixture.directories, directoriesBefore);
});
test('mapping-preconditions authenticates and requires owner before state, recovery, or target disclosure', async () => {
  const fixture = await mappingPreconditionsFixture();
  const added = await fixture.runtime.execute('auth-add', {
    actorPrincipal: owner,
    actorSecret: secret,
    targetPrincipal: nonowner,
    targetSecret: nonownerSecret,
    idempotencyKey: 'mapping-preconditions-nonowner',
  });
  assert.equal(added.ok, true, JSON.stringify(added));
  const filesAfterAdd = durableFileSnapshot(fixture.files);
  const writesAfterAdd = fixture.writes.length;
  const state = await fixture.native.readManagementState();
  const guardedState = structuredClone(state);
  const mapping = guardedState.mappings['precondition-map'];
  delete guardedState.mappings['precondition-map'];
  let targetReads = 0;
  Object.defineProperty(guardedState.mappings, 'precondition-map', {
    configurable: true,
    enumerable: true,
    get() {
      targetReads += 1;
      return mapping;
    },
  });
  const auth = await fixture.native.readManagementAuth();

  for (const [mappingId, secondState] of [
    ['precondition-map', guardedState],
    ['missing-map', guardedState],
    ['precondition-map', { ...guardedState, recovery: { phase: 'reader-pending' } }],
    ['precondition-map', { ...guardedState, auth: {} }],
    ['precondition-map', null],
  ]) {
    const result = await new ManagementRuntime({
      native: secondStateNative(fixture.native, secondState, { auth }),
    }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput(mappingId, nonowner, nonownerSecret),
    );
    assertMappingPreconditionsFailure(result, 3, 'OWNER_REQUIRED');
    assert.equal(targetReads, 0);
  }

  for (const [actorPrincipal, actorSecret] of [
    [owner, 'incorrect-owner-secret'],
    [{ kind: 'sid', value: 'S-1-5-21-999' }, 'unknown-principal-secret'],
  ]) {
    const present = await new ManagementRuntime({
      native: secondStateNative(fixture.native, guardedState, { auth }),
    }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('precondition-map', actorPrincipal, actorSecret),
    );
    const absent = await new ManagementRuntime({
      native: secondStateNative(fixture.native, null, { auth }),
    }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('missing-map', actorPrincipal, actorSecret),
    );
    assertMappingPreconditionsFailure(present, 3, 'AUTH_DENIED');
    assert.deepEqual(absent, present);
    assert.equal(targetReads, 0);
  }

  for (const [storedAuth, error] of [
    [null, 'MANAGEMENT_AUTH_REQUIRED'],
    [{}, 'AUTH_CREDENTIAL_INVALID'],
  ]) {
    const result = await new ManagementRuntime({
      native: secondStateNative(fixture.native, guardedState, { auth: storedAuth }),
    }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('precondition-map'),
    );
    assertMappingPreconditionsFailure(result, 3, error);
    assert.equal(targetReads, 0);
  }

  const legacyEmbeddedAuth = { ...structuredClone(state), auth: {} };
  assertMappingPreconditionsFailure(
    await new ManagementRuntime({
      native: secondStateNative(fixture.native, legacyEmbeddedAuth, { auth }),
    }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('precondition-map'),
    ),
    3,
    'MANAGEMENT_AUTH_MIGRATION_REQUIRED',
  );
  assert.equal(fixture.writes.length, writesAfterAdd);
  assert.deepEqual(fixture.files, filesAfterAdd);

  const revoked = await fixture.runtime.execute('auth-revoke', {
    actorPrincipal: owner,
    actorSecret: secret,
    targetPrincipal: nonowner,
    idempotencyKey: 'mapping-preconditions-revoke-nonowner',
  });
  assert.equal(revoked.ok, true, JSON.stringify(revoked));
  const filesAfterRevoke = durableFileSnapshot(fixture.files);
  const writesAfterRevoke = fixture.writes.length;
  const revokedPresent = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map', nonowner, nonownerSecret),
  );
  const revokedAbsent = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('missing-map', nonowner, nonownerSecret),
  );
  const revokedAuth = await fixture.native.readManagementAuth();
  const revokedRecovery = await new ManagementRuntime({
    native: secondStateNative(
      fixture.native,
      { ...guardedState, recovery: { phase: 'reader-pending' } },
      { auth: revokedAuth },
    ),
  }).execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map', nonowner, nonownerSecret),
  );
  assertMappingPreconditionsFailure(
    revokedPresent,
    3,
    'AUTH_DENIED',
  );
  assert.deepEqual(revokedAbsent, revokedPresent);
  assert.deepEqual(revokedRecovery, revokedPresent);
  assert.equal(targetReads, 0);
  assert.equal(fixture.writes.length, writesAfterRevoke);
  assert.deepEqual(fixture.files, filesAfterRevoke);
});

test('mapping-preconditions exposes only exact native refusal codes at role and lock boundaries', async () => {
  const fixture = await mappingPreconditionsFixture();
  fixture.setPrincipal(nonowner);
  const wrongOsRole = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  fixture.setPrincipal(owner);
  assertMappingPreconditionsFailure(wrongOsRole, 5, 'ERR_NATIVE_CONTROL_REFUSED');
  for (const [boundary, native] of [
    ['role', {
      ...fixture.native,
      async configureManagementRoles() {
        const error = new Error('wrong OS role at C:\\private\\control');
        error.code = 'ERR_NATIVE_CONTROL_REFUSED';
        throw error;
      },
    }],
    ['lock', {
      ...fixture.native,
      async withManagementLocks() {
        const error = new Error('lock refused for private principal');
        error.code = 'ERR_NATIVE_CONTROL_REFUSED';
        throw error;
      },
    }],
    ['auth read', {
      ...fixture.native,
      async readManagementAuth() {
        const error = new Error('malformed native auth at private path');
        error.code = 'ERR_NATIVE_CONTROL_REFUSED';
        throw error;
      },
    }],
  ]) {
    const result = await new ManagementRuntime({ native }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('precondition-map'),
    );
    assertMappingPreconditionsFailure(result, 5, 'ERR_NATIVE_CONTROL_REFUSED');
    assert.equal(JSON.stringify(result).includes('private'), false, boundary);
  }
});

test('mapping-preconditions refuses every nonterminal recovery phase before target access or recovery calls', async () => {
  const fixture = await mappingPreconditionsFixture();
  const state = await fixture.native.readManagementState();
  const filesBefore = durableFileSnapshot(fixture.files);
  const writesBefore = fixture.writes.length;
  const recoveryMethods = [
    'recoverGenesisSuffix',
    'completePendingGenesis',
    'readAuthoritySuccessorHeadRaw',
    'readSuccessorBundle',
    'readSuccessorRecovery',
    'terminalCloseOrManualCleanup',
  ];
  for (const phase of [
    'prepared',
    'handshake-pending',
    'reserved',
    'closed',
    'replaced',
    'reader-pending',
    'terminalizing',
    'manual_cleanup',
  ]) {
    const guardedState = {
      ...structuredClone(state),
      recovery: { phase },
    };
    const mapping = guardedState.mappings['precondition-map'];
    delete guardedState.mappings['precondition-map'];
    let targetReads = 0;
    Object.defineProperty(guardedState.mappings, 'precondition-map', {
      configurable: true,
      enumerable: true,
      get() {
        targetReads += 1;
        return mapping;
      },
    });
    const recoveryCalls = [];
    const native = secondStateNative(fixture.native, guardedState);
    for (const method of recoveryMethods) {
      if (typeof native[method] !== 'function') continue;
      native[method] = async () => {
        recoveryCalls.push(method);
        throw new Error('RECOVERY_CALL_FORBIDDEN');
      };
    }
    const result = await new ManagementRuntime({ native }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('precondition-map'),
    );
    assertMappingPreconditionsFailure(result, 7, 'RECOVERY_REQUIRED');
    assert.equal(targetReads, 0, phase);
    assert.deepEqual(recoveryCalls, [], phase);
  }
  assert.equal(fixture.writes.length, writesBefore);
  assert.deepEqual(fixture.files, filesBefore);
});
test('mapping-preconditions validates original containers, every nested record, counters, and the complete graph', async () => {
  const fixture = await mappingPreconditionsFixture({
    mappingIds: ['state-alpha', 'state-beta'],
    channelIds: [['1501', '1502'], ['1601', '1602']],
  });
  const state = await fixture.native.readManagementState();
  const cases = [
    ['second read absent', () => null],
    ['second read undefined', () => undefined],
    ['scalar state', () => 1],
    ['array state', () => []],
    ['custom state prototype', () => Object.setPrototypeOf(structuredClone(state), { polluted: true })],
    ['missing mappings', () => {
      const value = structuredClone(state);
      delete value.mappings;
      return value;
    }],
    ['null mappings', () => ({ ...structuredClone(state), mappings: null })],
    ['custom mappings prototype', () => {
      const value = structuredClone(state);
      Object.setPrototypeOf(value.mappings, { inherited: value.mappings['state-alpha'] });
      return value;
    }],
    ['missing routes', () => {
      const value = structuredClone(state);
      delete value.routes;
      return value;
    }],
    ['null routes', () => ({ ...structuredClone(state), routes: null })],
    ['custom routes prototype', () => {
      const value = structuredClone(state);
      Object.setPrototypeOf(value.routes, { inherited: value.routes['1501'] });
      return value;
    }],
    ['custom requested mapping prototype', () => {
      const value = structuredClone(state);
      Object.setPrototypeOf(value.mappings['state-alpha'], { polluted: true });
      return value;
    }],
    ['custom unrelated mapping prototype', () => {
      const value = structuredClone(state);
      Object.setPrototypeOf(value.mappings['state-beta'], { polluted: true });
      return value;
    }],
    ['custom requested route prototype', () => {
      const value = structuredClone(state);
      Object.setPrototypeOf(value.routes['1501'], { polluted: true });
      return value;
    }],
    ['custom unrelated route prototype', () => {
      const value = structuredClone(state);
      Object.setPrototypeOf(value.routes['1601'], { polluted: true });
      return value;
    }],
    ['requested mapping record invalid', () => {
      const value = structuredClone(state);
      value.mappings['state-alpha'].mappingFingerprint = '0'.repeat(64);
      return value;
    }],
    ['coercible requested mapping ID', () => {
      const value = structuredClone(state);
      value.mappings['state-alpha'].mappingId = ['state-alpha'];
      return value;
    }],
    ['unrelated mapping record invalid', () => {
      const value = structuredClone(state);
      value.mappings['state-beta'].mappingFingerprint = '0'.repeat(64);
      return value;
    }],
    ['requested route record invalid', () => {
      const value = structuredClone(state);
      value.routes['1501'].routeFingerprint = '0'.repeat(64);
      return value;
    }],
    ['unrelated route record invalid', () => {
      const value = structuredClone(state);
      value.routes['1601'].routeFingerprint = '0'.repeat(64);
      return value;
    }],
    ['mapping dictionary identity mismatch', () => {
      const value = structuredClone(state);
      value.mappings.foreign = value.mappings['state-beta'];
      delete value.mappings['state-beta'];
      return value;
    }],
    ['route dictionary identity mismatch', () => {
      const value = structuredClone(state);
      value.routes.foreign = value.routes['1601'];
      delete value.routes['1601'];
      return value;
    }],
    ['route mapping relation missing', () => {
      const value = structuredClone(state);
      delete value.mappings['state-beta'];
      return value;
    }],
    ['mapping fence differs from graph', () => {
      const value = structuredClone(state);
      const mapping = fingerprintManagedMappingRecord({
        ...value.mappings['state-beta'],
        fenceGeneration: value.fenceGeneration - 1,
        mappingFingerprint: null,
      });
      value.mappings['state-beta'] = mapping;
      for (const channelId of ['1601', '1602']) {
        value.routes[channelId] = fingerprintManagedRouteRecord({
          ...value.routes[channelId],
          fenceGeneration: mapping.fenceGeneration,
          routeFingerprint: null,
        }, mapping);
      }
      return value;
    }],
    ['mapping generation exceeds graph counter', () => ({
      ...structuredClone(state),
      mappingGeneration: 0,
    })],
    ['missing token attestation', () => {
      const value = structuredClone(state);
      delete value.tokenAttestation;
      return value;
    }],
    ['null token attestation', () => ({
      ...structuredClone(state),
      tokenAttestation: null,
    })],
    ['custom token attestation prototype', () => {
      const value = structuredClone(state);
      Object.setPrototypeOf(value.tokenAttestation, { polluted: true });
      return value;
    }],
    ['missing token host-set fingerprint', () => {
      const value = structuredClone(state);
      delete value.tokenAttestation.fingerprint;
      return value;
    }],
    ['coercible token host-set fingerprint', () => ({
      ...structuredClone(state),
      tokenAttestation: {
        ...structuredClone(state.tokenAttestation),
        fingerprint: { toString: () => 'f'.repeat(64) },
      },
    })],
    ['invalid token host-set fingerprint', () => ({
      ...structuredClone(state),
      tokenAttestation: {
        ...structuredClone(state.tokenAttestation),
        fingerprint: 'F'.repeat(64),
      },
    })],
  ];
  for (const field of ['revision', 'authorityEpoch', 'fenceGeneration', 'tokenConfigGeneration']) {
    for (const value of [undefined, null, 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      cases.push([`${field} ${String(value)}`, () => {
        const candidate = structuredClone(state);
        if (value === undefined) delete candidate[field];
        else candidate[field] = value;
        return candidate;
      }]);
    }
  }
  for (const value of [undefined, null, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    cases.push([`mappingGeneration ${String(value)}`, () => {
      const candidate = structuredClone(state);
      if (value === undefined) delete candidate.mappingGeneration;
      else candidate.mappingGeneration = value;
      return candidate;
    }]);
  }

  for (const [label, build] of cases) {
    const candidate = build();
    const serializedBefore = JSON.stringify(candidate);
    const statePrototype = candidate && typeof candidate === 'object'
      ? Object.getPrototypeOf(candidate)
      : null;
    const mappingsPrototype = candidate?.mappings && typeof candidate.mappings === 'object'
      ? Object.getPrototypeOf(candidate.mappings)
      : null;
    const routesPrototype = candidate?.routes && typeof candidate.routes === 'object'
      ? Object.getPrototypeOf(candidate.routes)
      : null;
    const tokenAttestationPrototype = candidate?.tokenAttestation &&
      typeof candidate.tokenAttestation === 'object'
      ? Object.getPrototypeOf(candidate.tokenAttestation)
      : null;
    const nestedPrototypes = [
      ...Object.values(candidate?.mappings ?? {}),
      ...Object.values(candidate?.routes ?? {}),
    ].filter((value) => value && typeof value === 'object')
      .map((value) => Object.getPrototypeOf(value));
    const filesBefore = durableFileSnapshot(fixture.files);
    const writesBefore = fixture.writes.length;
    const result = await new ManagementRuntime({
      native: secondStateNative(fixture.native, candidate),
    }).execute(
      'mapping-preconditions',
      mappingPreconditionsInput('state-alpha'),
    );
    assertMappingPreconditionsFailure(result, 6, 'MANAGEMENT_STATE_INVALID');
    assert.equal(JSON.stringify(candidate), serializedBefore, label);
    if (candidate && typeof candidate === 'object') assert.equal(Object.getPrototypeOf(candidate), statePrototype, label);
    if (candidate?.mappings && typeof candidate.mappings === 'object') {
      assert.equal(Object.getPrototypeOf(candidate.mappings), mappingsPrototype, label);
    }
    if (candidate?.routes && typeof candidate.routes === 'object') {
      assert.equal(Object.getPrototypeOf(candidate.routes), routesPrototype, label);
    }
    if (candidate?.tokenAttestation && typeof candidate.tokenAttestation === 'object') {
      assert.equal(Object.getPrototypeOf(candidate.tokenAttestation), tokenAttestationPrototype, label);
    }
    assert.deepEqual([
      ...Object.values(candidate?.mappings ?? {}),
      ...Object.values(candidate?.routes ?? {}),
    ].filter((value) => value && typeof value === 'object')
      .map((value) => Object.getPrototypeOf(value)), nestedPrototypes, label);
    assert.equal(fixture.writes.length, writesBefore, label);
    assert.deepEqual(fixture.files, filesBefore, label);
  }
});
test('mapping-preconditions calls only role setup, one mapping lock, and locked state/auth reads', async () => {
  const fixture = await mappingPreconditionsFixture();
  const secondState = await fixture.native.readManagementState();
  const secondAuth = await fixture.native.readManagementAuth();
  const stateBefore = structuredClone(secondState);
  const authBefore = structuredClone(secondAuth);
  const filesBefore = durableFileSnapshot(fixture.files);
  const directoriesBefore = new Set(fixture.directories);
  const writesBefore = fixture.writes.length;
  const payloadsBefore = fixture.payloads.length;
  const calls = [];
  let stateReads = 0;
  const allowed = new Set([
    'readManagementState',
    'readManagementAuth',
    'configureManagementRoles',
    'withManagementLocks',
  ]);
  const native = new Proxy(fixture.native, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== 'function') return value;
      if (property === 'readManagementState') {
        return async () => {
          stateReads += 1;
          calls.push(['readManagementState', stateReads]);
          return stateReads === 1 ? value.call(target) : secondState;
        };
      }
      if (property === 'readManagementAuth') {
        return async () => {
          calls.push(['readManagementAuth']);
          return secondAuth;
        };
      }
      if (property === 'configureManagementRoles') {
        return async (...args) => {
          calls.push(['configureManagementRoles']);
          return value.apply(target, args);
        };
      }
      if (property === 'withManagementLocks') {
        return async (locks, callback) => {
          calls.push(['withManagementLocks:start', structuredClone(locks)]);
          try {
            return await value.call(target, locks, callback);
          } finally {
            calls.push(['withManagementLocks:end', structuredClone(locks)]);
          }
        };
      }
      if (!allowed.has(property)) {
        return async () => {
          calls.push(['forbidden', property]);
          throw new Error(`FORBIDDEN_PRECONDITION_CALL_${String(property)}`);
        };
      }
      return value.bind(target);
    },
  });

  const result = await new ManagementRuntime({ native }).execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );

  assertMappingPreconditionsSuccess(
    result,
    'precondition-map',
    secondState.revision,
    secondState.mappings['precondition-map'].mappingFingerprint,
  );
  assert.deepEqual(calls, [
    ['readManagementState', 1],
    ['configureManagementRoles'],
    ['withManagementLocks:start', ['mapping']],
    ['readManagementState', 2],
    ['readManagementAuth'],
    ['withManagementLocks:end', ['mapping']],
  ]);
  assert.equal(calls.some(([kind]) => kind === 'forbidden'), false);
  assert.deepEqual(secondState, stateBefore);
  assert.deepEqual(secondAuth, authBefore);
  assert.equal(fixture.writes.length, writesBefore);
  assert.equal(fixture.payloads.length, payloadsBefore);
  assert.deepEqual(fixture.files, filesBefore);
  assert.deepEqual(fixture.directories, directoriesBefore);
});

test('mapping-preconditions returns one coherent second-read pair across a gated JavaScript interleaving', async () => {
  const fixture = await mappingPreconditionsFixture();
  const lockedState = await fixture.native.readManagementState();
  const tokenSuccessor = await fixture.runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'mapping-preconditions-intervening-token',
    hostTokens: 'host=preconditions-rotated',
  });
  assert.equal(tokenSuccessor.ok, true, JSON.stringify(tokenSuccessor));
  const laterState = await fixture.native.readManagementState();
  assert.notEqual(laterState.revision, lockedState.revision);
  assert.notEqual(
    laterState.mappings['precondition-map'].mappingFingerprint,
    lockedState.mappings['precondition-map'].mappingFingerprint,
  );
  let releaseAuth;
  const authGate = new Promise((resolve) => {
    releaseAuth = resolve;
  });
  let observeAuthRead;
  const authReadObserved = new Promise((resolve) => {
    observeAuthRead = resolve;
  });
  const order = [];
  let visibleState = lockedState;
  const native = secondStateNative(fixture.native, () => {
    order.push('second-state-read');
    return structuredClone(visibleState);
  }, {
    async onReadAuth() {
      order.push('auth-read-start');
      observeAuthRead();
      await authGate;
      order.push('auth-read-finish');
    },
    onLock(phase, locks) {
      order.push(`${phase}:${locks.join(',')}`);
    },
  });

  const pending = new ManagementRuntime({ native }).execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  await authReadObserved;
  visibleState = laterState;
  order.push('intervening-state-visible');
  releaseAuth();
  const result = await pending;

  assertMappingPreconditionsSuccess(
    result,
    'precondition-map',
    lockedState.revision,
    lockedState.mappings['precondition-map'].mappingFingerprint,
  );
  assert.deepEqual(order, [
    'start:mapping',
    'second-state-read',
    'auth-read-start',
    'intervening-state-visible',
    'auth-read-finish',
    'end:mapping',
  ]);
  assert.equal(result.expectedRevision === laterState.revision, false);
  assert.equal(
    result.expectedFingerprint === laterState.mappings['precondition-map'].mappingFingerprint,
    false,
  );
});
test('mapping-preconditions handoff becomes exact stale CAS after a legitimate intervening successor', async () => {
  const fixture = await mappingPreconditionsFixture();
  const stale = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  const staleState = await fixture.native.readManagementState();
  assertMappingPreconditionsSuccess(
    stale,
    'precondition-map',
    staleState.revision,
    staleState.mappings['precondition-map'].mappingFingerprint,
  );

  await reconcileMapping(fixture, fixture.runtime, {
    mappingId: 'intervening-map',
    channelIds: ['1701', '1702'],
    idempotencyKey: 'mapping-preconditions-intervening-successor',
  });
  const current = await fixture.native.readManagementState();
  assert.notEqual(current.revision, stale.expectedRevision);
  assert.notEqual(
    current.mappings['precondition-map'].mappingFingerprint,
    stale.expectedFingerprint,
  );
  const update = mappingInput(
    'precondition-map',
    current.mappingGeneration + 1,
    current.fenceGeneration,
    ['1403', '1404'],
  );
  const filesBeforeStaleMutation = durableFileSnapshot(fixture.files);
  const writesBeforeStaleMutation = fixture.writes.length;
  const staleMutation = await fixture.runtime.execute('mapping-reconcile', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'mapping-preconditions-stale-consumer',
    mappingId: 'precondition-map',
    ...update,
    expectedRevision: stale.expectedRevision,
    expectedFingerprint: stale.expectedFingerprint,
  });
  assert.deepEqual(staleMutation, {
    exitCode: 4,
    ok: false,
    error: 'CAS_CONFLICT',
    routeDisposition: 'no-route',
  });
  assert.equal(fixture.writes.length, writesBeforeStaleMutation);
  assert.deepEqual(fixture.files, filesBeforeStaleMutation);
  assert.deepEqual(await fixture.native.readManagementState(), current);

  const fresh = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('precondition-map'),
  );
  assertMappingPreconditionsSuccess(
    fresh,
    'precondition-map',
    current.revision,
    current.mappings['precondition-map'].mappingFingerprint,
  );

  const staleAbsent = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('future-map'),
  );
  assertMappingPreconditionsSuccess(staleAbsent, 'future-map', current.revision, null);
  const tokenSuccessor = await fixture.runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'mapping-preconditions-absent-intervening-successor',
    hostTokens: 'host=preconditions-after-absence',
  });
  assert.equal(tokenSuccessor.ok, true, JSON.stringify(tokenSuccessor));
  const afterAbsentDrift = await fixture.native.readManagementState();
  const create = mappingInput(
    'future-map',
    afterAbsentDrift.mappingGeneration + 1,
    afterAbsentDrift.fenceGeneration,
    ['1801', '1802'],
  );
  const filesBeforeStaleCreate = durableFileSnapshot(fixture.files);
  const writesBeforeStaleCreate = fixture.writes.length;
  const staleCreate = await fixture.runtime.execute('mapping-reconcile', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'mapping-preconditions-stale-absent-consumer',
    mappingId: 'future-map',
    ...create,
    expectedRevision: staleAbsent.expectedRevision,
    expectedFingerprint: staleAbsent.expectedFingerprint,
  });
  assert.deepEqual(staleCreate, {
    exitCode: 4,
    ok: false,
    error: 'CAS_CONFLICT',
    routeDisposition: 'no-route',
  });
  assert.equal(fixture.writes.length, writesBeforeStaleCreate);
  assert.deepEqual(fixture.files, filesBeforeStaleCreate);
  const freshAbsent = await fixture.runtime.execute(
    'mapping-preconditions',
    mappingPreconditionsInput('future-map'),
  );
  assertMappingPreconditionsSuccess(
    freshAbsent,
    'future-map',
    afterAbsentDrift.revision,
    null,
  );
});
async function failClosedSuccessorFailure(method, stage, injectedMessage = `INJECTED_${stage}`) {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old-secret'))).ok, true);
  const original = harness.native[method].bind(harness.native);
  harness.native[method] = async (...args) => {
    await original(...args);
    throw new Error(injectedMessage);
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
  return { harness, result, state, request, cleanup };
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
test('a code-shaped post-write failure cannot impersonate completed durable cleanup', async () => {
  const { harness, cleanup, request } = await failClosedSuccessorFailure(
    'writeAuthoritySuccessorHead',
    'MANUAL_CLEANUP_CANARY',
    'MANUAL_CLEANUP_REQUIRED',
  );
  const writtenHead = JSON.parse(fileEnding(
    harness.files,
    `/authority-head-${request.sequence}-reserved.json`,
  ));
  assert.equal(writtenHead.txId, request.txId);
  assert.equal(cleanup.reason, 'MANUAL_CLEANUP_REQUIRED');
  assert.equal(cleanup.txId, request.txId);
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
test('first mapping resolves the explicit Genesis-empty CAS sentinel under the management lock', async () => {
  const { native } = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  const candidate = mappingInput('first-workspace-map');
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'first-mapping-successor',
    mappingId: candidate.mapping.mappingId,
    ...candidate,
    expectedRevision: null,
    expectedFingerprint: null,
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.pending, false);
  assert.equal(result.routeDisposition, 'no-route');
});
test('populated mapping successors preserve the predecessor before advancing every fence', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  for (const index of [1, 2]) {
    const before = await harness.native.readManagementState();
    const candidate = mappingInput(`populated-${index}`, before.mappingGeneration + 1, before.fenceGeneration, String(123 + index));
    const writesBefore = harness.writes.length;
    const result = await runtime.execute('mapping-reconcile', {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: `populated-${index}`,
      mappingId: candidate.mapping.mappingId,
      ...candidate,
      expectedRevision: before.revision,
      expectedFingerprint: null,
    });
    assert.equal(result.ok, true, JSON.stringify({
      result,
      predecessorFence: before.fenceGeneration,
      retainedMappingFences: Object.values(before.mappings).map((mapping) => mapping.fenceGeneration),
      retainedRouteFences: Object.values(before.routes).map((route) => route.fenceGeneration),
      candidateFence: before.fenceGeneration + 1,
      writesAdded: harness.writes.length - writesBefore,
    }));
    assert.equal(result.pending, false);
    assert.equal(result.routeDisposition, 'no-route');
    const after = await harness.native.readManagementState();
    assert.equal(after.fenceGeneration, before.fenceGeneration + 1);
    assert.equal(Object.keys(after.mappings).length, index);
    assert.equal(Object.keys(after.routes).length, index);
    for (const mapping of Object.values(after.mappings)) assert.equal(mapping.fenceGeneration, after.fenceGeneration);
    for (const route of Object.values(after.routes)) assert.equal(route.fenceGeneration, after.fenceGeneration);
  }
});
test('token successor rejects state-to-target mapping generation drift before successor writes', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  await reconcileMapping(harness, runtime, {
    mappingId: 'token-drift-map',
    channelIds: ['91', '92'],
    idempotencyKey: 'token-drift-map-create',
  });
  const durableState = await harness.native.readManagementState();
  const filesBefore = new Map([...harness.files].map(([path, bytes]) => [path, Buffer.from(bytes)]));
  const writesBefore = harness.writes.length;
  const readManagementState = harness.native.readManagementState.bind(harness.native);
  let managementStateReads = 0;
  harness.native.readManagementState = async () => {
    const state = await readManagementState();
    managementStateReads += 1;
    return managementStateReads === 2
      ? { ...structuredClone(state), mappingGeneration: 0 }
      : state;
  };

  const result = await new ManagementRuntime({ native: harness.native }).execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'token-state-target-drift',
    hostTokens: 'host=rotated',
  });

  harness.native.readManagementState = readManagementState;
  assert.deepEqual(result, {
    exitCode: 6,
    ok: false,
    error: 'MANAGED_CHANNELS_V2_INVALID',
    routeDisposition: 'no-route',
  });
  assert.equal(managementStateReads, 2);
  assert.equal(harness.writes.length, writesBefore);
  assert.deepEqual(harness.files, filesBefore);
  assert.deepEqual(await harness.native.readManagementState(), durableState);
});
test('mapping successors carry the complete graph through create, update, token, rollback, and revoke', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);

  const alphaCreated = await reconcileMapping(harness, runtime, {
    mappingId: 'alpha',
    channelIds: ['101', '102'],
    idempotencyKey: 'alpha-create',
  });
  const alphaGenerationOnePath = mappingArchivePath(
    harness.files,
    'alpha',
    alphaCreated.after.mappings.alpha.mappingGeneration,
  );
  assert.ok(alphaGenerationOnePath);
  const alphaGenerationOneBytes = Buffer.from(harness.files.get(alphaGenerationOnePath));

  const betaCreated = await reconcileMapping(harness, runtime, {
    mappingId: 'beta',
    channelIds: ['201', '202'],
    idempotencyKey: 'beta-create',
  });
  assert.deepEqual(
    mappingSemantics(betaCreated.after.mappings.alpha),
    mappingSemantics(betaCreated.before.mappings.alpha),
  );
  assert.notEqual(
    betaCreated.after.mappings.alpha.mappingFingerprint,
    betaCreated.before.mappings.alpha.mappingFingerprint,
  );
  for (const channelId of ['101', '102']) {
    assert.deepEqual(
      routeSemantics(betaCreated.after.routes[channelId]),
      routeSemantics(betaCreated.before.routes[channelId]),
    );
    assert.notEqual(
      betaCreated.after.routes[channelId].routeFingerprint,
      betaCreated.before.routes[channelId].routeFingerprint,
    );
  }
  assert.deepEqual(harness.files.get(alphaGenerationOnePath), alphaGenerationOneBytes);

  const alphaUpdated = await reconcileMapping(harness, runtime, {
    mappingId: 'alpha',
    channelIds: ['103', '104'],
    idempotencyKey: 'alpha-update',
  });
  assert.deepEqual(
    mappingSemantics(alphaUpdated.after.mappings.beta),
    mappingSemantics(alphaUpdated.before.mappings.beta),
  );
  assert.notEqual(
    alphaUpdated.after.mappings.beta.mappingFingerprint,
    alphaUpdated.before.mappings.beta.mappingFingerprint,
  );
  assert.deepEqual(Object.keys(alphaUpdated.after.routes).sort(), ['103', '104', '201', '202']);
  assert.equal(alphaUpdated.after.mappings.alpha.mappingGeneration, alphaUpdated.before.mappingGeneration + 1);
  assert.equal(alphaUpdated.after.mappings.alpha.workspaceGeneration, alphaUpdated.candidate.mapping.workspaceGeneration);
  const alphaCurrentArchivePath = mappingArchivePath(
    harness.files,
    'alpha',
    alphaUpdated.after.mappings.alpha.mappingGeneration,
  );
  assert.ok(alphaCurrentArchivePath);

  const betaReassigned = await reconcileMapping(harness, runtime, {
    mappingId: 'beta',
    channelIds: ['101', '202'],
    idempotencyKey: 'beta-reassign-historic-alpha-channel',
  });
  assert.equal(betaReassigned.after.routes['101'].mappingId, 'beta');
  assert.equal(betaReassigned.after.routes['202'].mappingId, 'beta');
  assert.equal(betaReassigned.after.routes['103'].mappingId, 'alpha');
  assert.equal(betaReassigned.after.routes['104'].mappingId, 'alpha');
  assert.deepEqual(harness.files.get(alphaGenerationOnePath), alphaGenerationOneBytes);
  const betaCurrentArchivePath = mappingArchivePath(
    harness.files,
    'beta',
    betaReassigned.after.mappings.beta.mappingGeneration,
  );
  assert.ok(betaCurrentArchivePath);
  const immutableBytes = new Map([
    [alphaGenerationOnePath, Buffer.from(harness.files.get(alphaGenerationOnePath))],
    [alphaCurrentArchivePath, Buffer.from(harness.files.get(alphaCurrentArchivePath))],
    [betaCurrentArchivePath, Buffer.from(harness.files.get(betaCurrentArchivePath))],
  ]);

  const beforeToken = await harness.native.readManagementState();
  const tokenResult = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'populated-token-refence',
    hostTokens: 'host=rotated',
  });
  const token = await assertTerminalManagedSuccessor(harness, beforeToken, tokenResult, {
    operation: 'tokens-attest',
    mappingGenerationDelta: 0,
    tokenConfigGenerationDelta: 1,
  });
  for (const mappingId of Object.keys(beforeToken.mappings)) {
    assert.deepEqual(mappingSemantics(token.after.mappings[mappingId]), mappingSemantics(beforeToken.mappings[mappingId]));
    assert.notEqual(token.after.mappings[mappingId].mappingFingerprint, beforeToken.mappings[mappingId].mappingFingerprint);
  }
  for (const channelId of Object.keys(beforeToken.routes)) {
    assert.deepEqual(routeSemantics(token.after.routes[channelId]), routeSemantics(beforeToken.routes[channelId]));
    assert.notEqual(token.after.routes[channelId].routeFingerprint, beforeToken.routes[channelId].routeFingerprint);
  }
  for (const [path, bytes] of immutableBytes) assert.deepEqual(harness.files.get(path), bytes);

  const beforeRollback = await harness.native.readManagementState();
  const currentAlphaArchive = JSON.parse(harness.files.get(alphaCurrentArchivePath));
  assert.notEqual(currentAlphaArchive.mapping.fenceGeneration, beforeRollback.mappings.alpha.fenceGeneration);
  const rollbackResult = await runtime.execute('mapping-rollback', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'alpha-rollback',
    mappingId: 'alpha',
    replacementMappingId: 'alpha-restored',
    priorGeneration: alphaCreated.after.mappings.alpha.mappingGeneration,
    expectedRevision: beforeRollback.revision,
    expectedFingerprint: beforeRollback.mappings.alpha.mappingFingerprint,
  });
  const rollback = await assertTerminalManagedSuccessor(harness, beforeRollback, rollbackResult, {
    operation: 'mapping-rollback',
    mappingId: 'alpha',
    mappingGenerationDelta: 1,
    tokenConfigGenerationDelta: 0,
  });
  assert.equal(Object.hasOwn(rollback.after.mappings, 'alpha'), false);
  assert.equal(rollback.after.mappings['alpha-restored'].mappingGeneration, beforeRollback.mappingGeneration + 1);
  assert.equal(rollback.after.mappings['alpha-restored'].workspaceGeneration, alphaCreated.after.mappings.alpha.workspaceGeneration);
  assert.equal(rollback.after.routes['101'].mappingId, 'alpha-restored');
  assert.equal(rollback.after.routes['102'].mappingId, 'alpha-restored');
  assert.equal(rollback.after.routes['202'].mappingId, 'beta');
  assert.equal(Object.hasOwn(rollback.after.routes, '103'), false);
  assert.equal(Object.hasOwn(rollback.after.routes, '104'), false);
  assert.deepEqual(
    mappingSemantics(rollback.after.mappings.beta),
    mappingSemantics(beforeRollback.mappings.beta),
  );
  assert.notEqual(
    rollback.after.mappings.beta.mappingFingerprint,
    beforeRollback.mappings.beta.mappingFingerprint,
  );
  assert.deepEqual(routeSemantics(rollback.after.routes['202']), routeSemantics(beforeRollback.routes['202']));
  assert.notEqual(rollback.after.routes['202'].routeFingerprint, beforeRollback.routes['202'].routeFingerprint);
  const alphaTombstone = JSON.parse(fileEnding(harness.files, '/mapping-tombstone-alpha.json'));
  assert.equal(alphaTombstone.operation, 'mapping-rollback');
  assert.equal(alphaTombstone.fenceGeneration, currentAlphaArchive.mapping.fenceGeneration);
  assert.equal(alphaTombstone.mappingGeneration, currentAlphaArchive.mapping.mappingGeneration);
  assert.equal(alphaTombstone.mappingFingerprint, currentAlphaArchive.mapping.mappingFingerprint);
  assert.equal(alphaTombstone.snapshotFingerprint, rollback.proof.snapshot.configFingerprint);
  const alphaHandoff = mappingHandoff(harness.files, 'mapping-rollback', 'alpha', 'alpha-restored');
  assert.ok(alphaHandoff);
  assert.equal(alphaHandoff.fenceGeneration, rollback.after.fenceGeneration);
  assert.equal(alphaHandoff.snapshotFingerprint, rollback.proof.snapshot.configFingerprint);
  assert.equal(alphaHandoff.tombstoneFingerprint, alphaTombstone.tombstoneFingerprint);
  for (const [path, bytes] of immutableBytes) assert.deepEqual(harness.files.get(path), bytes);

  const beforeRevoke = await harness.native.readManagementState();
  const betaArchive = JSON.parse(harness.files.get(betaCurrentArchivePath));
  assert.notEqual(betaArchive.mapping.fenceGeneration, beforeRevoke.mappings.beta.fenceGeneration);
  const revokeResult = await runtime.execute('mapping-revoke', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'beta-revoke',
    mappingId: 'beta',
    expectedRevision: beforeRevoke.revision,
    expectedFingerprint: beforeRevoke.mappings.beta.mappingFingerprint,
  });
  const revoked = await assertTerminalManagedSuccessor(harness, beforeRevoke, revokeResult, {
    operation: 'mapping-revoke',
    mappingId: 'beta',
    mappingGenerationDelta: 1,
    tokenConfigGenerationDelta: 0,
  });
  assert.deepEqual(Object.keys(revoked.after.mappings), ['alpha-restored']);
  assert.deepEqual(Object.keys(revoked.after.routes).sort(), ['101', '102']);
  assert.deepEqual(
    mappingSemantics(revoked.after.mappings['alpha-restored']),
    mappingSemantics(beforeRevoke.mappings['alpha-restored']),
  );
  assert.notEqual(
    revoked.after.mappings['alpha-restored'].mappingFingerprint,
    beforeRevoke.mappings['alpha-restored'].mappingFingerprint,
  );
  const betaTombstone = JSON.parse(fileEnding(harness.files, '/mapping-tombstone-beta.json'));
  assert.equal(betaTombstone.operation, 'mapping-revoke');
  assert.equal(betaTombstone.fenceGeneration, betaArchive.mapping.fenceGeneration);
  assert.equal(betaTombstone.mappingGeneration, betaArchive.mapping.mappingGeneration);
  assert.equal(betaTombstone.mappingFingerprint, betaArchive.mapping.mappingFingerprint);
  assert.equal(betaTombstone.snapshotFingerprint, revoked.proof.snapshot.configFingerprint);
  const betaHandoff = mappingHandoff(harness.files, 'mapping-revoke', 'beta', null);
  assert.ok(betaHandoff);
  assert.equal(betaHandoff.fenceGeneration, revoked.after.fenceGeneration);
  assert.equal(betaHandoff.snapshotFingerprint, revoked.proof.snapshot.configFingerprint);
  assert.equal(betaHandoff.tombstoneFingerprint, betaTombstone.tombstoneFingerprint);
  for (const [path, bytes] of immutableBytes) assert.deepEqual(harness.files.get(path), bytes);
});
test('create, update, revoke, and rollback reject exact stale CAS before successor writes', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  await reconcileMapping(harness, runtime, {
    mappingId: 'cas-alpha',
    channelIds: ['301', '302'],
    idempotencyKey: 'cas-alpha-create',
  });
  await reconcileMapping(harness, runtime, {
    mappingId: 'cas-beta',
    channelIds: ['401', '402'],
    idempotencyKey: 'cas-beta-create',
  });
  await reconcileMapping(harness, runtime, {
    mappingId: 'cas-alpha',
    channelIds: ['303', '304'],
    idempotencyKey: 'cas-alpha-update',
  });
  const before = await harness.native.readManagementState();
  const create = mappingInput('cas-gamma', before.mappingGeneration + 1, before.fenceGeneration, ['501', '502']);
  const update = mappingInput('cas-alpha', before.mappingGeneration + 1, before.fenceGeneration, ['305', '306']);
  const cases = [
    ['create revision', 'mapping-reconcile', {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: 'stale-create',
      mappingId: 'cas-gamma',
      ...create,
      expectedRevision: before.revision - 1,
      expectedFingerprint: null,
    }],
    ['update fingerprint', 'mapping-reconcile', {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: 'stale-update',
      mappingId: 'cas-alpha',
      ...update,
      expectedRevision: before.revision,
      expectedFingerprint: '0'.repeat(64),
    }],
    ['revoke revision', 'mapping-revoke', {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: 'stale-revoke',
      mappingId: 'cas-beta',
      expectedRevision: before.revision - 1,
      expectedFingerprint: before.mappings['cas-beta'].mappingFingerprint,
    }],
    ['rollback fingerprint', 'mapping-rollback', {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey: 'stale-rollback',
      mappingId: 'cas-alpha',
      replacementMappingId: 'cas-alpha-restored',
      priorGeneration: 1,
      expectedRevision: before.revision,
      expectedFingerprint: '0'.repeat(64),
    }],
  ];
  for (const [label, command, input] of cases) {
    const writesBefore = harness.writes.length;
    const filesBefore = new Map([...harness.files].map(([path, bytes]) => [path, Buffer.from(bytes)]));
    const result = await runtime.execute(command, input);
    assert.deepEqual(result, {
      exitCode: 4,
      ok: false,
      error: 'CAS_CONFLICT',
      routeDisposition: 'no-route',
    }, label);
    assert.equal(harness.writes.length, writesBefore, label);
    assert.deepEqual(harness.files, filesBefore, label);
    assert.deepEqual(await harness.native.readManagementState(), before, label);
  }
});
test('revoke and rollback validate immutable archives and mapping-only live equivalence before writes', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=old'))).ok, true);
  const created = await reconcileMapping(harness, runtime, {
    mappingId: 'archive-map',
    channelIds: ['601', '602'],
    idempotencyKey: 'archive-create',
  });
  await reconcileMapping(harness, runtime, {
    mappingId: 'archive-other',
    channelIds: ['701', '702'],
    idempotencyKey: 'archive-other-create',
  });
  const updated = await reconcileMapping(harness, runtime, {
    mappingId: 'archive-map',
    channelIds: ['603', '604'],
    idempotencyKey: 'archive-update',
  });
  const beforeToken = await harness.native.readManagementState();
  const token = await runtime.execute('tokens-attest', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'archive-token-refence',
    hostTokens: 'host=archive-rotated',
  });
  const tokenTerminal = await assertTerminalManagedSuccessor(harness, beforeToken, token, {
    operation: 'tokens-attest',
    mappingGenerationDelta: 0,
    tokenConfigGenerationDelta: 1,
  });
  const before = tokenTerminal.after;
  const currentGeneration = before.mappings['archive-map'].mappingGeneration;
  const priorGeneration = created.after.mappings['archive-map'].mappingGeneration;
  const currentPath = mappingArchivePath(harness.files, 'archive-map', currentGeneration);
  const priorPath = mappingArchivePath(harness.files, 'archive-map', priorGeneration);
  assert.ok(currentPath);
  assert.ok(priorPath);
  const currentBytes = Buffer.from(harness.files.get(currentPath));
  const priorBytes = Buffer.from(harness.files.get(priorPath));
  const revokeInput = {
    actorPrincipal: owner,
    actorSecret: secret,
    mappingId: 'archive-map',
    expectedRevision: before.revision,
    expectedFingerprint: before.mappings['archive-map'].mappingFingerprint,
  };
  const rollbackInput = {
    actorPrincipal: owner,
    actorSecret: secret,
    mappingId: 'archive-map',
    replacementMappingId: 'archive-restored',
    priorGeneration,
    expectedRevision: before.revision,
    expectedFingerprint: before.mappings['archive-map'].mappingFingerprint,
  };
  const drifted = JSON.parse(currentBytes);
  drifted.mapping = fingerprintManagedMappingRecord({
    ...drifted.mapping,
    sourceRoot: '/different-source',
    mappingFingerprint: null,
  });
  const invalidCurrentRoute = JSON.parse(currentBytes);
  invalidCurrentRoute.routes[0].routeFingerprint = '0'.repeat(64);
  const invalidPriorRoute = JSON.parse(priorBytes);
  invalidPriorRoute.routes[0].routeFingerprint = '0'.repeat(64);
  const legacyPrior = JSON.parse(priorBytes);
  legacyPrior.mapping = fingerprintManagedMappingRecord({
    ...legacyPrior.mapping,
    workspaceId: null,
    workDir: '/legacy-workspace',
    mappingFingerprint: null,
  });
  legacyPrior.routes = legacyPrior.routes.map((route) => fingerprintManagedRouteRecord({
    ...route,
    workspaceId: null,
    workDir: '/legacy-workspace',
    routeFingerprint: null,
  }, legacyPrior.mapping));
  const cases = [
    ['missing current archive', 'mapping-revoke', { ...revokeInput, idempotencyKey: 'archive-missing' }, currentPath, null, 6, 'MAPPING_INVALID'],
    ['invalid current archive route', 'mapping-revoke', { ...revokeInput, idempotencyKey: 'archive-route-invalid' }, currentPath, Buffer.from(canonicalJson(invalidCurrentRoute)), 6, 'MAPPING_INVALID'],
    ['internally valid archive mapping drift', 'mapping-revoke', { ...revokeInput, idempotencyKey: 'archive-mapping-drift' }, currentPath, Buffer.from(canonicalJson(drifted)), 6, 'MAPPING_INVALID'],
    ['rollback current archive drift', 'mapping-rollback', { ...rollbackInput, idempotencyKey: 'archive-rollback-drift' }, currentPath, Buffer.from(canonicalJson(drifted)), 6, 'MAPPING_INVALID'],
    ['invalid prior rollback route', 'mapping-rollback', { ...rollbackInput, idempotencyKey: 'archive-prior-invalid' }, priorPath, Buffer.from(canonicalJson(invalidPriorRoute)), 70, 'ROLLBACK_GENERATION_UNKNOWN'],
    ['shared-valid legacy prior rollback archive', 'mapping-rollback', { ...rollbackInput, idempotencyKey: 'archive-prior-legacy' }, priorPath, Buffer.from(canonicalJson(legacyPrior)), 70, 'ROLLBACK_GENERATION_UNKNOWN'],
  ];
  for (const [label, command, input, path, bytes, exitCode, error] of cases) {
    if (bytes === null) harness.files.delete(path);
    else harness.files.set(path, bytes);
    const writesBefore = harness.writes.length;
    const filesBefore = new Map([...harness.files].map(([name, value]) => [name, Buffer.from(value)]));
    const result = await runtime.execute(command, input);
    assert.deepEqual(result, {
      exitCode,
      ok: false,
      error,
      routeDisposition: 'no-route',
    }, label);
    assert.equal(harness.writes.length, writesBefore, label);
    assert.deepEqual(harness.files, filesBefore, label);
    assert.deepEqual(await harness.native.readManagementState(), before, label);
    harness.files.set(currentPath, Buffer.from(currentBytes));
    harness.files.set(priorPath, Buffer.from(priorBytes));
  }
  assert.deepEqual(harness.files.get(currentPath), currentBytes);
  assert.deepEqual(harness.files.get(priorPath), priorBytes);
  assert.equal(updated.after.mappings['archive-map'].mappingGeneration, currentGeneration);
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
test('bound-reader recovery reconstructs the same populated candidate graph across runtime restart', async () => {
  const harness = await boundReaderRuntime();
  harness.setPrincipal(botPrincipal);
  const reader = await createTestManagedAuthorityReader({
    configPath: 'C:/state/channels.json',
    expectedHostSetFingerprint: managedHostSetFingerprint('host=secret'),
    roleBindings: roles,
    native: harness.native,
  });
  harness.setPrincipal(owner);
  const completeMapping = async (mappingId, channelIds, idempotencyKey) => {
    const before = await harness.native.readManagementState();
    const candidate = mappingInput(mappingId, before.mappingGeneration + 1, before.fenceGeneration, channelIds);
    const input = {
      actorPrincipal: owner,
      actorSecret: secret,
      idempotencyKey,
      mappingId,
      ...candidate,
      expectedRevision: before.revision,
      expectedFingerprint: null,
    };
    const started = await harness.runtime.execute('mapping-reconcile', input);
    assert.equal(started.ok, true, JSON.stringify(started));
    assert.equal(started.pending, true);
    assert.equal(started.phase, 'reader-pending');
    assert.equal(started.routeDisposition, 'no-route');
    assert.deepEqual(await harness.native.readManagementState(), before);
    const request = authorityRecord(harness.files, 'authority-successor-request', started.txId);
    const recovery = await harness.native.readSuccessorRecovery({
      predecessorReceiptFingerprint: request.previousReceiptFingerprint,
    });
    assert.equal(recovery.candidateConfigFingerprint, request.candidateSnapshotFingerprint);
    assert.equal(recovery.candidateState.configFingerprint, request.candidateSnapshotFingerprint);
    assert.equal(recovery.candidateState.fenceGeneration, request.candidateFenceGeneration);
    assert.doesNotThrow(() => validateManagedChannelsV2(recovery.candidateState));

    harness.setPrincipal(botPrincipal);
    const pending = await reader.readSnapshot();
    assert.equal(pending.code, 'MANAGED_AUTHORITY_PENDING');
    harness.setPrincipal(owner);
    const completed = await new ManagementRuntime({ native: harness.native }).execute('mapping-reconcile', input);
    const terminal = await assertTerminalManagedSuccessor(harness, before, completed, {
      operation: 'mapping-reconcile',
      mappingId,
      mappingGenerationDelta: 1,
      tokenConfigGenerationDelta: 0,
    });
    assert.equal(terminal.receipt.readerMode, 'bound-reader');
    assert.match(terminal.receipt.leaseBindingFingerprint, /^[a-f0-9]{64}$/);
    assert.match(terminal.receipt.readerProjectionFingerprint, /^[a-f0-9]{64}$/);
    assert.match(terminal.receipt.ackFingerprint, /^[a-f0-9]{64}$/);
    assert.equal(terminal.request.candidateSnapshotFingerprint, recovery.candidateState.configFingerprint);
    return terminal;
  };

  await completeMapping('bound-alpha', ['801', '802'], 'bound-alpha-create');
  const beforePopulated = await harness.native.readManagementState();
  const alphaBefore = structuredClone(beforePopulated.mappings['bound-alpha']);
  const routesBefore = Object.fromEntries(
    Object.entries(beforePopulated.routes).map(([channelId, route]) => [channelId, structuredClone(route)]),
  );
  const beta = await completeMapping('bound-beta', ['901', '902'], 'bound-beta-create');
  assert.deepEqual(mappingSemantics(beta.after.mappings['bound-alpha']), mappingSemantics(alphaBefore));
  assert.notEqual(beta.after.mappings['bound-alpha'].mappingFingerprint, alphaBefore.mappingFingerprint);
  for (const [channelId, route] of Object.entries(routesBefore)) {
    assert.deepEqual(routeSemantics(beta.after.routes[channelId]), routeSemantics(route));
    assert.notEqual(beta.after.routes[channelId].routeFingerprint, route.routeFingerprint);
  }
  assert.deepEqual(Object.keys(beta.after.mappings).sort(), ['bound-alpha', 'bound-beta']);
  assert.deepEqual(Object.keys(beta.after.routes).sort(), ['801', '802', '901', '902']);
});
test('populated bound-reader recovery rejects an alternate candidate graph with durable cleanup', async () => {
  const harness = await boundReaderRuntime();
  harness.setPrincipal(owner);
  const firstBefore = await harness.native.readManagementState();
  const firstCandidate = mappingInput(
    'recovery-alpha',
    firstBefore.mappingGeneration + 1,
    firstBefore.fenceGeneration,
    ['1001', '1002'],
  );
  const firstInput = {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'recovery-alpha-create',
    mappingId: 'recovery-alpha',
    ...firstCandidate,
    expectedRevision: firstBefore.revision,
    expectedFingerprint: null,
  };
  const firstStarted = await harness.runtime.execute('mapping-reconcile', firstInput);
  assert.equal(firstStarted.pending, true, JSON.stringify(firstStarted));
  harness.setPrincipal(botPrincipal);
  const reader = await createTestManagedAuthorityReader({
    configPath: 'C:/state/channels.json',
    expectedHostSetFingerprint: managedHostSetFingerprint('host=secret'),
    roleBindings: roles,
    native: harness.native,
  });
  assert.equal((await reader.readSnapshot()).code, 'MANAGED_AUTHORITY_PENDING');
  harness.setPrincipal(owner);
  const firstCompleted = await new ManagementRuntime({ native: harness.native }).execute('mapping-reconcile', firstInput);
  await assertTerminalManagedSuccessor(harness, firstBefore, firstCompleted, {
    operation: 'mapping-reconcile',
    mappingId: 'recovery-alpha',
    mappingGenerationDelta: 1,
    tokenConfigGenerationDelta: 0,
  });

  const before = await harness.native.readManagementState();
  const originalCandidate = mappingInput(
    'recovery-beta',
    before.mappingGeneration + 1,
    before.fenceGeneration,
    ['1101', '1102'],
  );
  const originalInput = {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'recovery-beta-create',
    mappingId: 'recovery-beta',
    ...originalCandidate,
    expectedRevision: before.revision,
    expectedFingerprint: null,
  };
  const started = await harness.runtime.execute('mapping-reconcile', originalInput);
  assert.equal(started.ok, true, JSON.stringify(started));
  assert.equal(started.pending, true);
  assert.equal(started.phase, 'reader-pending');
  assert.deepEqual(await harness.native.readManagementState(), before);
  const request = authorityRecord(harness.files, 'authority-successor-request', started.txId);

  const alternateCandidate = mappingInput(
    'recovery-beta',
    before.mappingGeneration + 1,
    before.fenceGeneration,
    ['1101', '1103'],
  );
  const terminalCleanup = harness.native.terminalCloseOrManualCleanup.bind(harness.native);
  let cleanupCalls = 0;
  harness.native.terminalCloseOrManualCleanup = async (...args) => {
    cleanupCalls += 1;
    return terminalCleanup(...args);
  };
  const recovered = await new ManagementRuntime({ native: harness.native }).execute('mapping-reconcile', {
    ...originalInput,
    ...alternateCandidate,
  });
  assert.deepEqual(recovered, {
    exitCode: 7,
    ok: false,
    error: 'MANUAL_CLEANUP_REQUIRED',
    routeDisposition: 'no-route',
  });
  assert.equal(cleanupCalls, 1);
  const state = await harness.native.readManagementState();
  assert.equal(state.recovery.phase, 'manual_cleanup');
  assert.equal(state.recovery.txId, started.txId);
  assert.equal(state.recovery.requestFingerprint, request.requestFingerprint);
  assert.equal(state.recovery.routeDisposition, 'no-route');
  const cleanup = JSON.parse(fileEnding(harness.files, '/terminal-close.json'));
  assert.equal(cleanup.txId, started.txId);
  assert.equal(cleanup.reason, 'RECOVERY_INPUT_MISMATCH');
  assert.equal(cleanup.routeDisposition, 'no-route');
  assert.equal(cleanup.blockedUntilOwnerAction, true);
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
async function pendingAlternateCandidateFixture(idempotencyKey) {
  const fixture = await pendingBoundSuccessorFixture(idempotencyKey);
  fixture.setPrincipal(botPrincipal);
  const reader = await createTestManagedAuthorityReader({
    configPath: 'C:/state/channels.json',
    expectedHostSetFingerprint: managedHostSetFingerprint('host=secret'),
    roleBindings: roles,
    native: fixture.native,
  });
  assert.equal((await reader.readSnapshot()).code, 'MANAGED_AUTHORITY_PENDING');
  fixture.setPrincipal(owner);
  const alternate = mappingInput(
    fixture.input.mappingId,
    fixture.input.mapping.mappingGeneration,
    fixture.input.mapping.fenceGeneration,
    '999',
  );
  return { ...fixture, alternateInput: { ...fixture.input, ...alternate } };
}
test('invalid cleanup evidence never earns same-transaction cleanup deduplication', async () => {
  for (const [kind, expectedCasCalls] of [
    ['wrong transaction', 0],
    ['wrong fingerprint', 0],
    ['wrong disposition', 0],
    ['wrong accepted phase', 2],
    ['null terminal fingerprint', 2],
  ]) {
    const fixture = await pendingAlternateCandidateFixture(`invalid-cleanup-${kind.replaceAll(' ', '-')}`);
    const durableState = await fixture.native.readManagementState();
    const readManagementState = fixture.native.readManagementState.bind(fixture.native);
    const compareAndSwapManagementState = fixture.native.compareAndSwapManagementState.bind(fixture.native);
    const terminalCloseOrManualCleanup = fixture.native.terminalCloseOrManualCleanup.bind(fixture.native);
    let cleanupStarted = false;
    let cleanupCalls = 0;
    let casCalls = 0;
    let terminal = null;

    fixture.native.terminalCloseOrManualCleanup = async (...args) => {
      cleanupCalls += 1;
      if (terminal === null) {
        terminal = kind === 'null terminal fingerprint'
          ? { phase: 'manual_cleanup', routeDisposition: 'no-route', manualCleanupFingerprint: null }
          : await terminalCloseOrManualCleanup(...args);
      }
      cleanupStarted = true;
      return structuredClone(terminal);
    };
    fixture.native.readManagementState = async () => {
      const state = await readManagementState();
      if (!cleanupStarted || ['wrong accepted phase', 'null terminal fingerprint'].includes(kind)) return state;
      const manualCleanupFingerprint = kind === 'wrong fingerprint'
        ? `${terminal.manualCleanupFingerprint[0] === '0' ? '1' : '0'}${terminal.manualCleanupFingerprint.slice(1)}`
        : terminal.manualCleanupFingerprint;
      return {
        ...structuredClone(state),
        recovery: {
          ...structuredClone(state.recovery),
          phase: 'manual_cleanup',
          txId: kind === 'wrong transaction' ? `${fixture.started.txId}-foreign` : fixture.started.txId,
          routeDisposition: kind === 'wrong disposition' ? 'route-open' : 'no-route',
          manualCleanupFingerprint,
        },
      };
    };
    fixture.native.compareAndSwapManagementState = async (expectedRevision, candidate) => {
      if (!cleanupStarted) return compareAndSwapManagementState(expectedRevision, candidate);
      casCalls += 1;
      if (kind === 'wrong accepted phase') candidate.recovery.phase = 'terminal';
      return true;
    };

    const result = await new ManagementRuntime({ native: fixture.native }).execute(
      'mapping-reconcile',
      fixture.alternateInput,
    );

    fixture.native.readManagementState = readManagementState;
    fixture.native.compareAndSwapManagementState = compareAndSwapManagementState;
    fixture.native.terminalCloseOrManualCleanup = terminalCloseOrManualCleanup;
    assert.deepEqual(result, {
      exitCode: 7,
      ok: false,
      error: 'MANUAL_CLEANUP_DURABILITY_FAILED',
      routeDisposition: 'no-route',
    }, kind);
    assert.equal(cleanupCalls, 2, kind);
    assert.equal(casCalls, expectedCasCalls, kind);
    assert.deepEqual(await fixture.native.readManagementState(), durableState, kind);
    assert.equal((await fixture.native.readManagementState()).recovery.phase, 'terminal', kind);
    assert.equal(
      Boolean(fileEnding(fixture.files, '/terminal-close.json')),
      kind !== 'null terminal fingerprint',
      kind,
    );
  }
});
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
  const predecessorPhase = {
    closed: 'reserved',
    replaced: 'closed',
    'reader-pending': 'replaced',
    terminal: 'reader-pending',
  }[phase];
  const predecessorPath = predecessorPhase === undefined && phase === 'reserved' && terminal.sequence > 2
    ? [...fixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith(`/authority-head-${terminal.sequence - 1}-terminal.json`))
    : predecessorPhase === undefined
      ? null
      : [...fixture.files.keys()].find((path) => path.replaceAll('\\', '/').endsWith(`/authority-head-${terminal.sequence}-${predecessorPhase}.json`));
  const predecessor = predecessorPath ? JSON.parse(fixture.files.get(predecessorPath)) : null;
  const head = buildAuthoritySuccessorRecord({
    ...terminal,
    phase,
    ...Object.fromEntries(fields.map((field) => [field, keep.includes(field) ? terminal[field] : null])),
    previousHeadFingerprint: predecessor?.headFingerprint ?? null,
    headFingerprint: null,
  }, 'headFingerprint');
  const headBytes = Buffer.from(canonicalJson(head));
  fixture.files.set(headPath, headBytes);
  fixture.files.set(markerPath, Buffer.from(canonicalJson(fixture.genesisMarker)));
  const historicalPath = headPath.replace(/authority-head\.json$/, `authority-head-${terminal.sequence}-${phase}.json`);
  fixture.files.set(historicalPath, Buffer.from(headBytes));
  for (const path of [...fixture.files.keys()]) {
    if (typeof path === 'string' && phase !== 'terminal' &&
        path.replaceAll('\\', '/').endsWith('/authority-head-' + terminal.sequence + '-terminal.json')) {
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
test('public no-reader recovery preserves a populated complete candidate graph', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=populated-recovery'))).ok, true);
  await reconcileMapping(harness, runtime, {
    mappingId: 'recover-alpha',
    channelIds: ['1201', '1202'],
    idempotencyKey: 'recover-alpha-create',
  });
  const predecessorMarker = await harness.native.readManagedHistoryMarker();
  const second = await reconcileMapping(harness, runtime, {
    mappingId: 'recover-beta',
    channelIds: ['1301', '1302'],
    idempotencyKey: 'recover-beta-create',
  });
  const expectedState = await harness.native.readManagementState();
  const expectedProof = await harness.native.readRetainedTargetProof();
  const fixture = {
    ...harness,
    genesisMarker: predecessorMarker,
    successor: second.result,
  };
  setSuccessorHeadPhase(fixture, 'reader-pending');

  const recovered = await new ManagementRuntime({ native: harness.native }).execute('recover', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'recover-beta-create',
  });
  assert.deepEqual(Object.keys(recovered).sort(), [
    'exitCode',
    'idempotent',
    'ok',
    'pending',
    'phase',
    'receiptFingerprint',
    'routeDisposition',
    'txId',
  ]);
  assert.equal(recovered.exitCode, 0);
  assert.equal(recovered.ok, true);
  assert.equal(recovered.pending, false);
  assert.equal(recovered.idempotent, true);
  assert.equal(recovered.phase, 'terminal');
  assert.equal(recovered.txId, second.result.txId);
  assert.equal(recovered.routeDisposition, 'no-route');
  assert.match(recovered.receiptFingerprint, /^[a-f0-9]{64}$/);
  const after = await harness.native.readManagementState();
  const proof = await harness.native.readRetainedTargetProof();
  assert.deepEqual(after.mappings, expectedState.mappings);
  assert.deepEqual(after.routes, expectedState.routes);
  assert.deepEqual(proof.snapshot, expectedProof.snapshot);
  assert.equal(after.fenceGeneration, expectedState.fenceGeneration);
  assert.equal(after.mappingGeneration, expectedState.mappingGeneration);
  assert.deepEqual(Object.keys(after.mappings).sort(), ['recover-alpha', 'recover-beta']);
  assert.deepEqual(Object.keys(after.routes).sort(), ['1201', '1202', '1301', '1302']);
  assert.equal(after.recovery.phase, 'terminal');
  assert.equal(after.recovery.txId, second.result.txId);
  assert.equal(JSON.parse(fileEnding(harness.files, '/authority-head.json')).phase, 'terminal');
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
  harness.setPrincipal(owner);
  const replayBundle = await harness.native.readSuccessorBundle({ allowTerminalReplay: true, readReplay: true });
  assert.equal(replayBundle.head.sequence, 3);
  const validatedBundle = await harness.native.validateAuthoritySuccessorBundle(replayBundle);
  assert.equal(validatedBundle.head.sequence, 3);
});
test('sequence-three detached predecessor refuses snapshot and replay without writes', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=detached-predecessor'))).ok, true);
  for (const index of [1, 2]) {
    const state = await harness.native.readManagementState();
    let result;
    if (index === 1) {
      const candidate = mappingInput(`detached-predecessor-${index}`, state.mappingGeneration + 1, state.fenceGeneration, String(123 + index));
      result = await runtime.execute('mapping-reconcile', {
        actorPrincipal: owner,
        actorSecret: secret,
        idempotencyKey: `detached-predecessor-${index}`,
        mappingId: candidate.mapping.mappingId,
        ...candidate,
        expectedRevision: state.revision,
        expectedFingerprint: null,
      });
    } else {
      result = await runtime.execute('tokens-attest', {
        actorPrincipal: owner,
        actorSecret: secret,
        idempotencyKey: `detached-predecessor-${index}`,
        hostTokens: 'host=detached-predecessor-rotated',
      });
    }
    assert.equal(result.ok, true, JSON.stringify({ result, state }));
  }
  const predecessorHead = JSON.parse(fileEnding(harness.files, '/authority-head-2-terminal.json'));
  const predecessorReceiptPath = filePathEnding(
    harness.files,
    `/authority-successor-receipt-${encodeURIComponent(predecessorHead.txId)}.json`,
  );
  assert.ok(predecessorReceiptPath);
  harness.files.delete(predecessorReceiptPath);
  harness.setPrincipal(botPrincipal);
  const writes = harness.writes.length;
  await assert.rejects(
    harness.native.readManagedMappingSnapshot(),
    /predecessor|successor|bundle|snapshot/i,
  );
  assert.equal(harness.writes.length, writes);
  harness.setPrincipal(owner);
  await assert.rejects(
    harness.native.readSuccessorBundle({ allowTerminalReplay: true, readReplay: true }),
    /predecessor|successor|bundle|lineage/i,
  );
  assert.equal(harness.writes.length, writes);
});
test('sequence-two detached Genesis predecessor refuses snapshot and replay without writes', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=detached-genesis'))).ok, true);
  const state = await harness.native.readManagementState();
  const candidate = mappingInput('detached-genesis-map', state.mappingGeneration + 1, state.fenceGeneration, '123');
  const result = await runtime.execute('mapping-reconcile', {
    actorPrincipal: owner,
    actorSecret: secret,
    idempotencyKey: 'detached-genesis-map',
    mappingId: candidate.mapping.mappingId,
    ...candidate,
    expectedRevision: state.revision,
    expectedFingerprint: null,
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  const receiptPath = filePathEnding(harness.files, '/receipt.json');
  assert.ok(receiptPath);
  harness.files.delete(receiptPath);
  harness.setPrincipal(botPrincipal);
  const writes = harness.writes.length;
  await assert.rejects(
    harness.native.readManagedMappingSnapshot(),
    /predecessor|Genesis|successor|bundle|snapshot/i,
  );
  assert.equal(harness.writes.length, writes);
  harness.setPrincipal(owner);
  await assert.rejects(
    harness.native.readSuccessorBundle({ allowTerminalReplay: true, readReplay: true }),
    /predecessor|Genesis|successor|bundle|lineage/i,
  );
  assert.equal(harness.writes.length, writes);
});
test('self-hashed detached successor head refuses managed snapshot, replay, and public bundle validation', async () => {
  const harness = adapter({ legacy: false });
  const runtime = new ManagementRuntime({ native: harness.native });
  assert.equal((await runtime.execute('genesis', genesisInput('host=detached-head'))).ok, true);
  for (const [index, hostTokens] of ['host=detached-head-map', 'host=detached-head-rotated'].entries()) {
    const state = await harness.native.readManagementState();
    const candidate = mappingInput(`detached-head-${index}`, state.mappingGeneration + 1, state.fenceGeneration, String(123 + index));
    const result = index === 0
      ? await runtime.execute('mapping-reconcile', {
        actorPrincipal: owner,
        actorSecret: secret,
        idempotencyKey: `detached-head-${index}`,
        mappingId: candidate.mapping.mappingId,
        ...candidate,
        expectedRevision: state.revision,
        expectedFingerprint: null,
      })
      : await runtime.execute('tokens-attest', {
        actorPrincipal: owner,
        actorSecret: secret,
        idempotencyKey: `detached-head-${index}`,
        hostTokens,
      });
    assert.equal(result.ok, true, JSON.stringify(result));
  }
  const validBundle = await harness.native.readSuccessorBundle();
  const headPath = filePathEnding(harness.files, '/authority-head.json');
  const current = JSON.parse(harness.files.get(headPath));
  const detached = buildAuthoritySuccessorRecord({
    ...current,
    previousHeadFingerprint: '0'.repeat(64),
    headFingerprint: null,
  }, 'headFingerprint');
  harness.files.set(headPath, Buffer.from(canonicalJson(detached)));
  const writes = harness.writes.length;
  harness.setPrincipal(botPrincipal);
  await assert.rejects(harness.native.readManagedMappingSnapshot(), /successor|bundle|snapshot/i);
  harness.setPrincipal(owner);
  await assert.rejects(harness.native.readSuccessorBundle({ allowTerminalReplay: true, readReplay: true }), /successor|bundle|lineage/i);
  await assert.rejects(harness.native.readTerminalizationLineage({ txId: detached.txId }), /successor|lineage|terminal/i);
  await assert.rejects(
    harness.native.validateAuthoritySuccessorBundle({ ...validBundle, head: detached }),
    /successor|bundle|invalid/i,
  );
  assert.equal(harness.writes.length, writes);
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
