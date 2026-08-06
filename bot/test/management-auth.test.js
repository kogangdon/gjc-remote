import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ManagementRuntime, EXIT } from "../src/management-runtime.js";
import { authenticate, bootstrapOwner } from "../src/management-auth.js";
import { canonicalJsonHash } from "../../shared/strict-json.js";
import { validateGenesisRequest, validateTokenConfigAttestation, validateTokenFloorReservation } from "../../shared/genesis-envelope.js";
import { fingerprintManagedMappingRecord } from "../../shared/mapping-envelope.js";
import { fingerprintGenesisProbe } from "../../shared/genesis-probe.js";
const owner = { kind: "sid", value: "S-1-5-21-100" };
const member = { kind: "sid", value: "S-1-5-21-104" };
const target = { kind: "sid", value: "S-1-5-21-103" };
const botPrincipal = { kind: "sid", value: "S-1-5-21-101" };
const recoveryPrincipal = { kind: "sid", value: "S-1-5-21-102" };
const provisioning = {
  management: "a".repeat(64),
  bot: "b".repeat(64),
  recovery: "c".repeat(64),
};
const ownerSecret = "owner-secret-is-long-enough";
const memberSecret = "member-secret-is-long-enough";
const rotatedSecret = "rotated-secret-is-long-enough";

function fakeNative() {
  const hex = "f".repeat(64);
  const calls = [];
  const records = [];
  let state = null;
  let auth = null;
  let request = null;
  let managedHistoryMarker = null;
  let fenceGenerationFloor = {
    version: 1, kind: "fence-generation-floor", anchorFingerprint: hex, genesisFenceGeneration: 1,
    highestReservedFenceGeneration: 0, highestCommittedFenceGeneration: 0,
    lastReservationTxId: null, lastCommittedTxId: null, floorFingerprint: null,
  };
  fenceGenerationFloor.floorFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(fenceGenerationFloor).filter(([key]) => key !== "floorFingerprint")),
  );
  return {
    calls,
    records,
    async readManagementState() { return state; },
    async compareAndSwapManagementState(_revision, next) { state = structuredClone(next); return true; },
    async readManagementAuth() { return structuredClone(auth); },
    async compareAndSwapManagementAuth(expectedFingerprint, next) {
      const currentFingerprint = auth === null ? null : canonicalJsonHash(auth);
      if (currentFingerprint !== expectedFingerprint) return false;
      auth = structuredClone(next);
      return true;
    },
    async readManagedHistoryMarker() { return structuredClone(managedHistoryMarker); },
    async commitManagedHistoryMarker(marker) {
      if (managedHistoryMarker !== null &&
          canonicalJsonHash(managedHistoryMarker) !== canonicalJsonHash(marker)) {
        throw new Error("MANAGED_HISTORY_MARKER_CONFLICT");
      }
      managedHistoryMarker = structuredClone(marker);
      return structuredClone(managedHistoryMarker);
    },
    async configureManagementRoles() {},
    async currentOsPrincipal() { return owner; },
    async managementAnchorFingerprint() { return hex; },
    async writeGenesisAuthorityRequest() {},
    async validateGenesisAuthorityBinding() {},
    async writeGenesisAuthorityReceipt() {},
    async reserveAuthorityEpoch() {},
    async commitAuthorityEpoch() {},
    async writeAuthorityReservation() {},
    async writeAuthorityCommitSnapshot() {},
    async writeAuthorityBaseline() {},
    async reserveFenceGeneration({ fenceGeneration, txId }) {
      if (fenceGeneration !== fenceGenerationFloor.highestReservedFenceGeneration + 1 ||
          fenceGeneration <= fenceGenerationFloor.highestCommittedFenceGeneration) throw new Error("FENCE_RESERVATION_INVALID");
      fenceGenerationFloor = {
        ...fenceGenerationFloor,
        highestReservedFenceGeneration: fenceGeneration,
        lastReservationTxId: txId,
        floorFingerprint: null,
      };
      fenceGenerationFloor.floorFingerprint = canonicalJsonHash(
        Object.fromEntries(Object.entries(fenceGenerationFloor).filter(([key]) => key !== "floorFingerprint")),
      );
      return structuredClone(fenceGenerationFloor);
    },
    async commitFenceGeneration({ fenceGeneration, txId }) {
      if (fenceGenerationFloor.highestReservedFenceGeneration !== fenceGeneration ||
          fenceGenerationFloor.lastReservationTxId !== txId ||
          fenceGenerationFloor.highestCommittedFenceGeneration !== fenceGeneration - 1) throw new Error("FENCE_COMMIT_INVALID");
      fenceGenerationFloor = {
        ...fenceGenerationFloor,
        highestCommittedFenceGeneration: fenceGeneration,
        lastCommittedTxId: txId,
        floorFingerprint: null,
      };
      fenceGenerationFloor.floorFingerprint = canonicalJsonHash(
        Object.fromEntries(Object.entries(fenceGenerationFloor).filter(([key]) => key !== "floorFingerprint")),
      );
      return structuredClone(fenceGenerationFloor);
    },
    async readFenceGenerationFloor() { return structuredClone(fenceGenerationFloor); },
    async readSuccessorTokenLineage() {
      return {
        floor: { version: 1, kind: "token-floor", anchorFingerprint: hex, floorPhase: "committed", fenceGeneration: 1, highestReservedGeneration: 1, highestCommittedGeneration: 1, lastReservationTxId: "genesis", lastCommittedTxId: "genesis", lastAttestationFingerprint: hex, floorFingerprint: hex },
        attestation: { version: 1, kind: "token-config-attestation", anchorFingerprint: hex, fenceGeneration: 1, tokenConfigGeneration: 1, tokenConfigHostSetFingerprint: hex, txId: "genesis", attestationFingerprint: hex },
      };
    },
    async readAuthoritySuccessorHeadRaw() { return null; },
    async writeReaderFenceBinding() {},
    async casReaderVersionFloor() { throw new Error("UNEXPECTED_READER_HANDSHAKE"); },
    async withManagementLocks(_locks, fn) { return fn(); },
    async probeProspectiveCleanup(value) {
      assert.deepEqual(value.botPrincipal, botPrincipal);
      assert.deepEqual(value.recoveryPrincipal, recoveryPrincipal);
      assert.notEqual(value.botProvisioningFingerprint, value.recoveryProvisioningFingerprint);
      calls.push("probe");
      const probe = {
        version: 1,
        kind: "genesis-prospective-probe",
        probeNonce: "1".repeat(32),
        anchorFingerprint: hex,
        parentIdentity: "fixture-parent",
        targetInputState: "absent",
        managementIdentity: owner,
        botIdentity: botPrincipal,
        recoveryIdentity: recoveryPrincipal,
        mProvisioningFingerprint: provisioning.management,
        bProvisioningFingerprint: provisioning.bot,
        rProvisioningFingerprint: provisioning.recovery,
        templateTargetIdentity: "fixture-target",
        templateTargetAclFingerprint: hex,
        templateControlIdentity: "fixture-control",
        templateControlAclFingerprint: hex,
        templateWrapperIdentity: "fixture-wrapper",
        templateWrapperAclFingerprint: hex,
        mMutationProofFingerprint: hex,
        botReadProofFingerprint: hex,
        recoveryReadProofFingerprint: hex,
        botWriteDeniedProofFingerprint: hex,
        recoveryWriteDeniedProofFingerprint: hex,
        scratchIdentity: "fixture-scratch",
        authorityWrites: 0,
        targetWrites: 0,
        controlWrites: 0,
        authorityCommittedWrites: 0,
        targetCommittedWrites: 0,
        controlCommittedWrites: 0,
        phase: "cleaned",
        probeFingerprint: null,
      };
      probe.probeFingerprint = fingerprintGenesisProbe(probe);
      return {
        targetInputState: "absent",
        legacyTargetProof: null,
        genesisSecurityTuple: {
          ...structuredClone(value.genesisSecurityTuple),
          targetInputState: "absent",
          legacyTargetProof: null,
        },
        probe,
      };
    },
    async writeGenesisRequest(value) { validateGenesisRequest(value); request = value; records.push(value); calls.push("request"); },
    async reserveTokenFloor(value) {
      validateTokenFloorReservation(value);
      assert.equal(request.tokenFloorFingerprint, value.floorFingerprint);
      records.push(value); calls.push("reservation"); return value;
    },
    async writeTokenConfigAttestation(value) {
      validateTokenConfigAttestation(value);
      assert.equal(value.txId, request.genesisTxId);
      records.push(value); calls.push("attestation"); return value;
    },
    async writeAttestedTokenFloor(value) { records.push(value); calls.push("attested-floor"); return value.floor; },
    async commitTokenFloor(value) { records.push(value); calls.push("commit"); return value.floor; },
    async writePublicationGraph() {},
    async writeZFinality(value) { records.push(value); calls.push("zf"); return value; },
    async readBoundReaderProof() {
      const floor = {
        version: 1, kind: "reader-version-floor", anchorFingerprint: hex, fenceGeneration: 1,
        readerVersionFloor: null, firstPendingTxId: null, firstReaderInstanceId: null,
        firstReaderStartNonce: null, lastTransitionTxId: null, previousFloorFingerprint: null,
        floorFingerprint: null,
      };
      floor.floorFingerprint = canonicalJsonHash(Object.fromEntries(Object.entries(floor).filter(([key]) => key !== "floorFingerprint")));
      return { readerVersionFloor: floor };
    },
    async completePendingGenesis() { return null; },
    async writeAdmissionRequest() {},
    async writeAdmissionGrant() {},
    async writeFinalityProof(value) { records.push(value); calls.push("fp"); return value; },
    async writeGenesisReceipt(value) { records.push(value); calls.push("receipt"); },
    async recheckAdmissionFinality() { return true; },
    async publishMapping() {
      calls.push("publication");
      return {
        targetFingerprint: hex,
        targetIdentityFingerprint: hex,
        targetAclFingerprint: hex,
        controlRootFingerprint: hex,
        controlIdentityFingerprint: hex,
        controlAclFingerprint: hex,
        wrapperIdentityFingerprint: hex,
        wrapperAclFingerprint: hex,
        wrapperFingerprint: hex,
      };
    },
    async writeMappingGeneration(value) { return value; },
    async writeMappingTombstone() {},
    async writeMappingHandoffReceipt() {},
    async readMappingGeneration() { return null; },
    async writeMappingRecovery() {},
    async mappingTargetProof() { return { fingerprint: hex, identityFingerprint: hex, aclFingerprint: hex }; },
    async recoverGenesisSuffix() { return { phase: "manual_cleanup", routeDisposition: "no-route" }; },
    async reopenAdmission() { return true; },
    async terminalCloseOrManualCleanup() { return { phase: "manual_cleanup", routeDisposition: "no-route" }; },
    async rotateTokenSidecar() {},
    async revokeMapping() {},
    async rollbackMapping() { return {}; },
    async recoverManagementState() { return { phase: "manual_cleanup", routeDisposition: "no-route" }; },
    async appendAudit() {},
  };
}

async function execute(runtime, command, input) {
  return runtime.execute(command, input);
}

test("owner may add, rotate, and revoke a distinct actor credential", async () => {
  const file = join(tmpdir(), `gjc-management-auth-${randomUUID()}.audit`);
  try {
    const native = fakeNative();
    const runtime = new ManagementRuntime({ native, auditFile: file });
    assert.equal((await execute(runtime, "genesis", {
      actorPrincipal: owner, targetPrincipal: target, botPrincipal, recoveryPrincipal,
      managementProvisioningFingerprint: provisioning.management, botProvisioningFingerprint: provisioning.bot, recoveryProvisioningFingerprint: provisioning.recovery,
      actorSecret: ownerSecret, idempotencyKey: "one", hostTokens: "host=token",
    })).ok, true);
    assert.ok(native.calls.indexOf("probe") < native.calls.indexOf("request"));
    assert.ok(native.calls.indexOf("request") < native.calls.indexOf("reservation"));
    assert.ok(native.calls.indexOf("reservation") < native.calls.indexOf("attestation"));
    assert.ok(native.calls.indexOf("attestation") < native.calls.indexOf("publication"));
    assert.ok(native.calls.indexOf("publication") < native.calls.indexOf("commit"));
    assert.equal(native.records.every((record) => !JSON.stringify(record).includes(ownerSecret) && !Object.hasOwn(record, "tokenBytes")), true);
    const missing = await execute(runtime, "auth-add", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      targetSecret: memberSecret,
    });
    assert.equal(missing.error, "IDEMPOTENCY_KEY_REQUIRED");
    const added = await execute(runtime, "auth-add", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      targetSecret: memberSecret,
      idempotencyKey: "auth-add-001",
    });
    assert.equal(added.ok, true, JSON.stringify(added));
    const replay = await execute(runtime, "auth-add", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      targetSecret: memberSecret,
      idempotencyKey: "auth-add-001",
    });
    assert.deepEqual(replay, added);
    const conflict = await execute(runtime, "auth-add", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      targetSecret: "different-member-secret-is-long-enough",
      idempotencyKey: "auth-add-001",
    });
    assert.equal(conflict.error, "IDEMPOTENCY_CONFLICT");
    const rotated = await execute(runtime, "auth-rotate", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      targetSecret: rotatedSecret,
      idempotencyKey: "auth-rotate-001",
    });
    assert.equal(rotated.ok, true, JSON.stringify(rotated));
    const rotatedReplay = await execute(runtime, "auth-rotate", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      targetSecret: rotatedSecret,
      idempotencyKey: "auth-rotate-001",
    });
    assert.deepEqual(rotatedReplay, rotated);
    assert.equal((await execute(runtime, "status", { actorPrincipal: member, actorSecret: memberSecret })).error, "AUTH_DENIED");
    const revoked = await execute(runtime, "auth-revoke", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      idempotencyKey: "auth-revoke-001",
    });
    assert.equal(revoked.ok, true, JSON.stringify(revoked));
    const revokedReplay = await execute(runtime, "auth-revoke", {
      actorPrincipal: owner,
      actorSecret: ownerSecret,
      targetPrincipal: member,
      idempotencyKey: "auth-revoke-001",
    });
    assert.deepEqual(revokedReplay, revoked);
    const denied = await execute(runtime, "status", { actorPrincipal: member, actorSecret: rotatedSecret });
    assert.deepEqual(denied, { exitCode: EXIT.AUTH, ok: false, error: "AUTH_DENIED", routeDisposition: "no-route" });
  } finally { await rm(file, { force: true }); }
});

test("legacy retained candidates must satisfy the shared exact wrapper schema", async () => {
  const file = join(tmpdir(), `gjc-management-legacy-${randomUUID()}.audit`);
  try {
    const native = fakeNative();
    const runtime = new ManagementRuntime({ native, auditFile: file });
    await execute(runtime, "genesis", {
      actorPrincipal: owner, targetPrincipal: target, botPrincipal, recoveryPrincipal,
      managementProvisioningFingerprint: provisioning.management, botProvisioningFingerprint: provisioning.bot, recoveryProvisioningFingerprint: provisioning.recovery,
      actorSecret: ownerSecret, idempotencyKey: "one", hostTokens: "host=token",
    });
    const malformed = { legacyRetention: "exact", targetIdentity: "identity-1", rawTargetByteFingerprint: "a", rawTargetByteLength: 1, targetAclFingerprint: "acl-1" };
    const result = await execute(runtime, "mapping-reconcile", { actorPrincipal: owner, actorSecret: ownerSecret, mappingId: "legacy", mapping: malformed });
    assert.equal(result.error, "MAPPING_INVALID");
  } finally { await rm(file, { force: true }); }
});
test("issue #44 management rejects serving-shaped workDir mappings", async () => {
  const native = fakeNative();
  const runtime = new ManagementRuntime({ native });
  const genesis = await execute(runtime, "genesis", {
    actorPrincipal: owner, targetPrincipal: target, botPrincipal, recoveryPrincipal,
    managementProvisioningFingerprint: provisioning.management,
    botProvisioningFingerprint: provisioning.bot,
    recoveryProvisioningFingerprint: provisioning.recovery,
    actorSecret: ownerSecret, idempotencyKey: "workspace-only", hostTokens: "host=token",
  });
  assert.equal(genesis.ok, true, JSON.stringify(genesis));
  const mapping = fingerprintManagedMappingRecord({
    mappingId: "serving-shaped", hostId: "host", fenceGeneration: 1, mappingGeneration: 1,
    mappingVersion: 1, sourcePlatform: "posix", workspaceId: null,
    workDir: "/srv/workspace", sourceRoot: "/srv/workspace",
    containerRoot: null, volumeIdentity: "volume-a", casePolicy: "sensitive",
    immutableDefault: false, mappingFingerprint: null,
  });
  const result = await execute(runtime, "mapping-validate", {
    actorPrincipal: owner, actorSecret: ownerSecret, mapping,
  });
  assert.equal(result.error, "MAPPING_INVALID");
});
test("authentication rejects persisted principal and credential key mismatches", () => {
  const state = {};
  bootstrapOwner(state, { actorPrincipal: owner, osPrincipal: owner, secret: ownerSecret });
  assert.equal(authenticate(state, owner, ownerSecret).owner, true);

  const ownerKey = canonicalJsonHash(owner);
  const ownerCredential = state.auth.credentials[ownerKey];

  const ownerKeyMismatch = structuredClone(state);
  ownerKeyMismatch.auth.ownerPrincipalKey = canonicalJsonHash(member);
  assert.throws(() => authenticate(ownerKeyMismatch, owner, ownerSecret), /AUTH_CREDENTIAL_INVALID/);

  const ownerPrincipalMismatch = structuredClone(state);
  ownerPrincipalMismatch.auth.ownerPrincipal = structuredClone(member);
  assert.throws(() => authenticate(ownerPrincipalMismatch, owner, ownerSecret), /AUTH_CREDENTIAL_INVALID/);

  const credentialPrincipalMismatch = structuredClone(state);
  credentialPrincipalMismatch.auth.credentials[ownerKey].principal = structuredClone(member);
  assert.throws(() => authenticate(credentialPrincipalMismatch, owner, ownerSecret), /AUTH_CREDENTIAL_INVALID/);

  const credentialKeyMismatch = {
    auth: {
      ...structuredClone(state.auth),
      credentials: { [canonicalJsonHash(member)]: ownerCredential },
    },
  };
  assert.throws(() => authenticate(credentialKeyMismatch, owner, ownerSecret), /AUTH_CREDENTIAL_INVALID/);
});
