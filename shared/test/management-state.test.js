import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJsonHash } from "../strict-json.js";
import { canCleanGenesisScratch, transitionGenesisProspectiveProbe, validateGenesisProspectiveProbe } from "../genesis-probe.js";
import { advanceReaderVersionFloor, attestTokenFloor, buildAttestedTokenFloorProof, commitTokenFloor, reserveTokenGeneration, validateReaderVersionFloor, validateTokenConfigAttestation, validateTokenFloor } from "../genesis-envelope.js";
import { validateAdmissionGrant } from "../admission-envelope.js";
import { recoveryDisposition, validateManagementRecoveryResult, validateManualCleanup } from "../recovery-envelope.js";

const hex = "a".repeat(64);
const seal = (record, field) => ({ ...record, [field]: canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field))) });

test("prospective probe remains non-authoritative and cleanup needs the exact observed proof", () => {
  const probe = seal({
    version: 1, kind: "genesis-prospective-probe", probeNonce: "1".repeat(32), anchorFingerprint: hex,
    parentIdentity: "parent", targetInputState: "absent",
    managementIdentity: { kind: "uid", value: "uid:1000" }, botIdentity: { kind: "uid", value: "uid:1001" }, recoveryIdentity: { kind: "uid", value: "uid:1002" },
    mProvisioningFingerprint: hex, bProvisioningFingerprint: hex, rProvisioningFingerprint: hex,
    templateTargetIdentity: "scratch-target", templateTargetAclFingerprint: hex,
    templateControlIdentity: "scratch-control", templateControlAclFingerprint: hex,
    templateWrapperIdentity: "scratch-wrapper", templateWrapperAclFingerprint: hex,
    mMutationProofFingerprint: hex, botReadProofFingerprint: hex, recoveryReadProofFingerprint: hex,
    botWriteDeniedProofFingerprint: hex, recoveryWriteDeniedProofFingerprint: hex,
    scratchIdentity: "scratch", authorityWrites: 0, targetWrites: 0, controlWrites: 0,
    authorityCommittedWrites: 0, targetCommittedWrites: 0, controlCommittedWrites: 0, phase: "prepared",
  }, "probeFingerprint");
  const verified = transitionGenesisProspectiveProbe(probe, "verified");
  const observed = {
    probeNonce: verified.probeNonce, managementIdentity: verified.managementIdentity, parentIdentity: verified.parentIdentity, scratchIdentity: verified.scratchIdentity,
    templateTargetIdentity: verified.templateTargetIdentity, templateTargetAclFingerprint: verified.templateTargetAclFingerprint,
    templateControlIdentity: verified.templateControlIdentity, templateControlAclFingerprint: verified.templateControlAclFingerprint,
    templateWrapperIdentity: verified.templateWrapperIdentity, templateWrapperAclFingerprint: verified.templateWrapperAclFingerprint,
    mMutationProofFingerprint: verified.mMutationProofFingerprint, botReadProofFingerprint: verified.botReadProofFingerprint, recoveryReadProofFingerprint: verified.recoveryReadProofFingerprint,
    botWriteDeniedProofFingerprint: verified.botWriteDeniedProofFingerprint, recoveryWriteDeniedProofFingerprint: verified.recoveryWriteDeniedProofFingerprint,
    authorityWrites: 0, targetWrites: 0, controlWrites: 0, authorityCommittedWrites: 0, targetCommittedWrites: 0, controlCommittedWrites: 0, probeFingerprint: verified.probeFingerprint,
  };
  assert.equal(validateGenesisProspectiveProbe(verified).phase, "verified");
  assert.equal(canCleanGenesisScratch(verified, observed), true);
  assert.equal(canCleanGenesisScratch(verified, { ...observed, botWriteDeniedProofFingerprint: "b".repeat(64) }), false);
  assert.equal(canCleanGenesisScratch(verified, { ...observed, authorityCommittedWrites: 1 }), false);
  assert.throws(() => validateGenesisProspectiveProbe({ ...probe, templateTargetIdentity: null }));
  assert.throws(() => validateGenesisProspectiveProbe({ ...probe, botReadProofFingerprint: null }));
  assert.throws(() => validateGenesisProspectiveProbe({ ...probe, templateWrapperAclFingerprint: "b".repeat(64) }));
  const missingProof = { ...probe }; delete missingProof.recoveryWriteDeniedProofFingerprint;
  assert.throws(() => validateGenesisProspectiveProbe(missingProof));
  assert.throws(() => validateGenesisProspectiveProbe({ ...probe, probeFingerprint: hex }));
});

test("reader floor is literal-null at genesis and irreversible after handshake", () => {
  const floor = seal({ version: 1, kind: "reader-version-floor", anchorFingerprint: hex, fenceGeneration: 1, readerVersionFloor: null, firstPendingTxId: null, firstReaderInstanceId: null, firstReaderStartNonce: null, lastTransitionTxId: null, previousFloorFingerprint: null }, "floorFingerprint");
  const advanced = advanceReaderVersionFloor(floor, { txId: "tx", readerInstanceId: "reader", readerStartNonce: "nonce", fenceGeneration: 2 });
  assert.equal(validateReaderVersionFloor(advanced).readerVersionFloor, 2);
  assert.equal(advanced.fenceGeneration, 2);
  assert.throws(() => advanceReaderVersionFloor(advanced, { txId: "other", readerInstanceId: "reader", readerStartNonce: "nonce" }));
});

test("token generation floor reserves, attests, and commits with monotonic CAS", () => {
  const floor = seal({ version: 1, kind: "token-generation-floor", anchorFingerprint: hex, fenceGeneration: 1, genesisGeneration: 7, highestReservedGeneration: 6, highestCommittedGeneration: 6, lastReservationTxId: null, lastCommittedTxId: null, lastAttestationFingerprint: null, floorPhase: "committed", attestedProofFingerprint: hex }, "floorFingerprint");
  const attestation = seal({ version: 1, kind: "token-config-attestation", anchorFingerprint: hex, fenceGeneration: 1, tokenConfigGeneration: 7, tokenConfigHostSetFingerprint: hex, managedGrammarVersion: 1, sourceKind: "protected-stdin", producerPrincipal: `management/${hex}`, rotationKind: "genesis", previousAttestationFingerprint: null, txId: "genesis" }, "attestationFingerprint");
  const reserved = reserveTokenGeneration(floor, { txId: "genesis", generation: 7, fenceGeneration: 1 });
  const proof = buildAttestedTokenFloorProof(reserved, attestation);
  const attested = attestTokenFloor(reserved, proof);
  const committed = commitTokenFloor(attested, { txId: "genesis", generation: 7, attestationFingerprint: attestation.attestationFingerprint, fenceGeneration: 1 });
  assert.equal(committed.highestCommittedGeneration, 7);
  assert.throws(() => commitTokenFloor(reserved, { txId: "genesis", generation: 7, attestationFingerprint: attestation.attestationFingerprint }));
  assert.throws(() => commitTokenFloor(attested, { txId: "genesis", generation: 8, attestationFingerprint: attestation.attestationFingerprint }));
  assert.equal(validateTokenFloor(floor).highestCommittedGeneration, 6);
  const missingFence = { ...floor }; delete missingFence.fenceGeneration;
  assert.throws(() => validateTokenFloor(missingFence));
  assert.throws(() => validateTokenFloor({ ...floor, fenceGeneration: 0 }));
});

test("token attestation is secret-free and has exact protected-stdin lineage", () => {
  const attestation = seal({ version: 1, kind: "token-config-attestation", anchorFingerprint: hex, fenceGeneration: 1, tokenConfigGeneration: 1, tokenConfigHostSetFingerprint: hex, managedGrammarVersion: 1, sourceKind: "protected-stdin", producerPrincipal: `management/${hex}`, rotationKind: "genesis", previousAttestationFingerprint: null, txId: "genesis" }, "attestationFingerprint");
  assert.equal(validateTokenConfigAttestation(attestation).tokenConfigHostSetFingerprint, hex);
  assert.throws(() => validateTokenConfigAttestation({ ...attestation, tokenBytes: "secret" }));
});

test("admission rejects expiry, replay, and reader mismatches", () => {
  const request = seal({ version: 1, kind: "admission-request", requestId: "rq", genesisTxId: "g", generation: 1, fenceGeneration: 1, readerInstanceId: "reader", readerStartNonce: "start", routeFingerprint: "route", nonce: "nonce", expiresAt: 10 }, "requestFingerprint");
  const grant = seal({ version: 1, kind: "admission-grant", grantId: "at", requestFingerprint: request.requestFingerprint, genesisTxId: "g", generation: 1, fenceGeneration: 1, readerInstanceId: "reader", readerStartNonce: "start", routeFingerprint: "route", nonce: "nonce", expiresAt: 10 }, "grantFingerprint");
  assert.equal(validateAdmissionGrant(grant, request, 10).grantId, "at");
  assert.throws(() => validateAdmissionGrant(grant, request, 11));
  assert.throws(() => validateAdmissionGrant(grant, request, 10, new Set(["at"])));
  assert.throws(() => validateAdmissionGrant({ ...grant, readerInstanceId: "other" }, request, 10));
});

test("manual cleanup wins over torn recovery and remains no-route", () => {
  const cleanup = seal({ version: 1, kind: "manual-cleanup", anchorFingerprint: hex, fenceGeneration: 1, txId: "tx", reason: "fingerprint-mismatch", expectedFingerprint: null, observedFingerprint: hex, expectedFloorFingerprint: hex, observedFloorFingerprint: hex, routeDisposition: "no-route", blockedUntilOwnerAction: true }, "manualCleanupFingerprint");
  assert.equal(validateManualCleanup(cleanup).routeDisposition, "no-route");
  assert.equal(recoveryDisposition({ manualCleanup: cleanup }), "manual_cleanup");
});
test("management recovery manual cleanup result preserves the durable recovery input exactly", () => {
  const recovery = { phase: "replaced", txId: "tx", routeDisposition: "no-route" };
  const result = {
    ...recovery,
    phase: "manual_cleanup",
    routeDisposition: "no-route",
    manualCleanupFingerprint: hex,
  };
  assert.equal(validateManagementRecoveryResult(result, recovery).phase, "manual_cleanup");
  assert.throws(() => validateManagementRecoveryResult({ ...result, txId: "other" }, recovery));
  assert.throws(() => validateManagementRecoveryResult({ ...result, extra: true }, recovery));
});
