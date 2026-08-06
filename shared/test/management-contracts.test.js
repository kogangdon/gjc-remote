import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { canonicalJson, canonicalJsonHash, parseCanonicalJsonBytes } from "../strict-json.js";
import { validateFinalityProof } from "../admission-envelope.js";
import { buildGenesisPrecommit, validateAuthorityCommitSnapshot, validateAuthorityEpoch, validateAuthorityReservation, validateGenesisAuthorityRequest, validateGenesisPrecommit, validateGenesisReceipt, validateZFinality } from "../genesis-envelope.js";
import { buildPublicationC, buildPublicationK, buildPublicationP, buildPublicationQ, buildPublicationS, buildPublicationU, buildPublicationY, buildPublicationZp, validatePublicationC, validatePublicationK, validatePublicationP, validatePublicationQ, validatePublicationS, validatePublicationU, validatePublicationY, validatePublicationZp } from "../publication-envelope.js";
import { buildAuthoritySuccessorRecord, validateAuthorityCloseProof, validateAuthoritySuccessorAck, validateAuthoritySuccessorFence, validateAuthoritySuccessorFinality, validateAuthoritySuccessorHeadTransition, validateAuthoritySuccessorLease, validateAuthoritySuccessorReaderProjection, validateAuthoritySuccessorRequest } from "../successor-envelope.js";

const hex = "a".repeat(64);
const seal = (record, field) => ({ ...record, [field]: canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field))) });

test("management authority accepts only canonical bytes", () => {
  const canonical = Buffer.from('{"a":1,"z":2}');
  assert.deepEqual(parseCanonicalJsonBytes(canonical), { a: 1, z: 2 });
  for (const source of ['{"z":2,"a":1}', '{"a":1,"z":2}\n', '{"a":1, "z":2}', '{"a":1,"z":\\u0032}']) {
    assert.throws(() => parseCanonicalJsonBytes(Buffer.from(source)), /canonically encoded|expected value/);
  }
  assert.equal(canonicalJson({ z: 2, a: 1 }), canonical.toString("utf8"));
});

test("no-reader finality has literal null fields and the no-route target", () => {
  const request = seal({ version: 1, kind: "genesis-request", genesisTxId: "g", idempotencyKey: "i", anchorFingerprint: hex, ownerPrincipalFingerprint: hex, generation: 1, fenceGeneration: 1, requestedReaderMode: "no-reader", readerInstanceId: null, readerStartNonce: null, attestationFingerprint: hex, tokenFloorFingerprint: hex }, "requestFingerprint");
  const zf = { zFinalityFingerprint: hex, fenceGeneration: 1 };
  const proof = seal({ version: 1, kind: "finality-proof", genesisTxId: "g", generation: 1, fenceGeneration: 1, zFinalityFingerprint: hex, readerProjectionFingerprint: null, ackFingerprint: null, routeFingerprint: "no-route" }, "finalityProofFingerprint");
  assert.equal(validateFinalityProof(proof, request, zf), proof);
  for (const value of [{ ...proof, readerProjectionFingerprint: hex }, { ...proof, ackFingerprint: hex }, { ...proof, routeFingerprint: "route" }, (() => { const copy = { ...proof }; delete copy.ackFingerprint; return copy; })()]) {
    assert.throws(() => validateFinalityProof(value, request, zf));
  }
});

test("handshake finality requires the bound acknowledgement", () => {
  const request = seal({ version: 1, kind: "genesis-request", genesisTxId: "g", idempotencyKey: "i", anchorFingerprint: hex, ownerPrincipalFingerprint: hex, generation: 1, fenceGeneration: 1, requestedReaderMode: "handshake", readerInstanceId: "reader", readerStartNonce: "start", attestationFingerprint: hex, tokenFloorFingerprint: hex }, "requestFingerprint");
  const ack = seal({ version: 1, kind: "admission-ack", grantFingerprint: hex, grantId: "grant", genesisTxId: "g", generation: 1, fenceGeneration: 1, readerInstanceId: "reader", readerStartNonce: "start", routeFingerprint: "route", readerProjectionFingerprint: "b".repeat(64), nonce: "nonce" }, "ackFingerprint");
  const proof = seal({ version: 1, kind: "finality-proof", genesisTxId: "g", generation: 1, fenceGeneration: 1, zFinalityFingerprint: hex, readerProjectionFingerprint: ack.readerProjectionFingerprint, ackFingerprint: ack.ackFingerprint, routeFingerprint: "route" }, "finalityProofFingerprint");
  assert.equal(validateFinalityProof(proof, request, { zFinalityFingerprint: hex, fenceGeneration: 1 }, ack, ack.readerProjectionFingerprint), proof);
  assert.throws(() => validateFinalityProof(proof, request, { zFinalityFingerprint: hex, fenceGeneration: 1 }, { ...ack, generation: 2 }, ack.readerProjectionFingerprint));
  assert.throws(() => validateFinalityProof({ ...proof, readerProjectionFingerprint: hex }, request, { zFinalityFingerprint: hex, fenceGeneration: 1 }, ack, ack.readerProjectionFingerprint));
});
test("genesis receipts bind handshake proof fields and preserve no-reader nulls", () => {
  const handshakeRequest = seal({ version: 1, kind: "genesis-request", genesisTxId: "g", idempotencyKey: "i", anchorFingerprint: hex, ownerPrincipalFingerprint: hex, generation: 1, fenceGeneration: 1, requestedReaderMode: "handshake", readerInstanceId: "reader", readerStartNonce: "start", attestationFingerprint: hex, tokenFloorFingerprint: hex }, "requestFingerprint");
  const zf = seal({ version: 1, kind: "genesis-finality", genesisTxId: "g", generation: 1, fenceGeneration: 1 }, "zFinalityFingerprint");
  const proof = { finalityProofFingerprint: hex, readerProjectionFingerprint: "b".repeat(64), ackFingerprint: "c".repeat(64) };
  const receipt = seal({ version: 1, kind: "genesis-receipt", genesisTxId: "g", generation: 1, fenceGeneration: 1, requestedReaderMode: "handshake", readerInstanceId: "reader", readerStartNonce: "start", readerProjectionFingerprint: proof.readerProjectionFingerprint, ackFingerprint: proof.ackFingerprint, finalityProofFingerprint: proof.finalityProofFingerprint, phase: "terminal" }, "receiptFingerprint");
  assert.equal(validateGenesisReceipt(receipt, handshakeRequest, zf, proof), receipt);
  for (const value of [
    seal({ ...receipt, readerProjectionFingerprint: hex }, "receiptFingerprint"),
    seal({ ...receipt, ackFingerprint: hex }, "receiptFingerprint"),
  ]) assert.throws(() => validateGenesisReceipt(value, handshakeRequest, zf, proof));

  const noReaderRequest = seal({ ...handshakeRequest, requestedReaderMode: "no-reader", readerInstanceId: null, readerStartNonce: null }, "requestFingerprint");
  const noReaderZf = seal({ ...zf, genesisTxId: noReaderRequest.genesisTxId }, "zFinalityFingerprint");
  const noReaderReceipt = seal({ ...receipt, requestedReaderMode: "no-reader", readerInstanceId: null, readerStartNonce: null, readerProjectionFingerprint: null, ackFingerprint: null }, "receiptFingerprint");
  assert.equal(validateGenesisReceipt(noReaderReceipt, noReaderRequest, noReaderZf, proof), noReaderReceipt);
  for (const value of [
    seal({ ...noReaderReceipt, readerProjectionFingerprint: hex }, "receiptFingerprint"),
    seal({ ...noReaderReceipt, ackFingerprint: hex }, "receiptFingerprint"),
  ]) assert.throws(() => validateGenesisReceipt(value, noReaderRequest, noReaderZf, proof));
});

test("proof fingerprints are record-specific", () => {
  const first = seal({ version: 1, kind: "finality-proof", genesisTxId: "g", generation: 1, fenceGeneration: 1, zFinalityFingerprint: hex, readerProjectionFingerprint: null, ackFingerprint: null, routeFingerprint: "no-route" }, "finalityProofFingerprint");
  const second = seal({ version: 1, kind: "finality-proof", genesisTxId: "other", generation: 1, fenceGeneration: 1, zFinalityFingerprint: hex, readerProjectionFingerprint: null, ackFingerprint: null, routeFingerprint: "no-route" }, "finalityProofFingerprint");
  assert.notEqual(first.finalityProofFingerprint, second.finalityProofFingerprint);
});
test("genesis precommit binds upstream prospective, role, and zero-grant proofs without finality cycles", () => {
  const inputs = {
    genesisTxId: "genesis", fenceGeneration: 1, generation: 1,
    genesisProbeFingerprint: hex, targetFingerprint: hex, targetIdentityFingerprint: hex, targetAclFingerprint: hex,
    controlRootFingerprint: hex, controlIdentityFingerprint: hex, controlAclFingerprint: hex,
    wrapperIdentityFingerprint: hex, wrapperAclFingerprint: hex, wrapperFingerprint: hex,
    readerVersionFloorFingerprint: hex, requestFingerprint: hex, reservationFingerprint: hex,
    attestedProofFingerprint: hex, authorityReservationFingerprint: hex,
    authorityCommitSnapshotFingerprint: hex, authorityEpochFingerprint: hex,
    publicationKFingerprint: hex, publicationYFingerprint: hex, zeroGrantProofFingerprint: hex,
  };
  const precommit = buildGenesisPrecommit(inputs);
  assert.equal(validateGenesisPrecommit(precommit), precommit);
  assert.equal(Object.hasOwn(precommit, "zFinalityFingerprint"), false);
  assert.equal(Object.hasOwn(precommit, "precommitFingerprint"), true);
  assert.throws(() => validateGenesisPrecommit({ ...precommit, admissionGrantWrites: 1 }));
  assert.throws(() => validateGenesisPrecommit({ ...precommit, outstandingAdmissionGrants: null }));
  const missing = { ...precommit }; delete missing.wrapperFingerprint;
  assert.throws(() => validateGenesisPrecommit(missing));
  assert.throws(() => validateGenesisPrecommit({ ...precommit, precommitFingerprint: hex }));
});
test("semantic publication projections bind the approved baseline state instead of predecessor labels", () => {
  const baselineFingerprint = "b".repeat(64);
  const u = buildPublicationU({
    txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, baselineFingerprint, anchorFingerprint: hex,
    targetState: "genesis-empty", attestationFingerprint: hex, authorityReservationFingerprint: hex,
    authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null, leaseBindingFingerprint: null,
    readerProjectionFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  });
  const p = buildPublicationP({
    txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, uFingerprint: u["publication-uFingerprint"],
    stateFingerprint: "c".repeat(64), targetState: u.targetState,
    authorityCommitSnapshotFingerprint: u.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: null,
    leaseBindingFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  });
  assert.equal(validatePublicationU(u, baselineFingerprint), u);
  assert.equal(validatePublicationP(p, u, "c".repeat(64)), p);
  assert.throws(() => validatePublicationP(p, u, u["publication-uFingerprint"]));
  assert.throws(() => validatePublicationP({ ...p, targetState: "managed" }, u));
  assert.throws(() => validatePublicationU({ ...u, readerVersion: 2 }, baselineFingerprint));
});
test("semantic publication chain rejects independently mutated projections and predecessor substitution", () => {
  const stateFingerprint = "1".repeat(64);
  const payloadFingerprint = "2".repeat(64);
  const snapshotFingerprint = "3".repeat(64);
  const publicationFingerprint = "4".repeat(64);
  const checkpointFingerprint = "5".repeat(64);
  const u = buildPublicationU({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, baselineFingerprint: hex, anchorFingerprint: hex, targetState: "genesis-empty", attestationFingerprint: hex, authorityReservationFingerprint: hex, authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null, leaseBindingFingerprint: null, readerProjectionFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null });
  const p = buildPublicationP({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, uFingerprint: u["publication-uFingerprint"], stateFingerprint, targetState: u.targetState, authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null, leaseBindingFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null });
  const s = buildPublicationS({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, pFingerprint: p["publication-pFingerprint"], stateFingerprint, payloadFingerprint, targetState: u.targetState, authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null, readerVersion: null });
  const c = buildPublicationC({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, sFingerprint: s["publication-sFingerprint"], stateFingerprint, payloadFingerprint, snapshotFingerprint, authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null });
  const q = buildPublicationQ({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, cFingerprint: c["publication-cFingerprint"], baselineFingerprint: hex, stateFingerprint, payloadFingerprint, snapshotFingerprint, authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null });
  const zp = buildPublicationZp({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, qFingerprint: q["publication-qFingerprint"], publicationFingerprint, stateFingerprint, payloadFingerprint, snapshotFingerprint });
  const k = buildPublicationK({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, zpFingerprint: zp["publication-zpFingerprint"], publicationFingerprint, authorityCommitSnapshotFingerprint: hex, checkpointFingerprint });
  assert.equal(validatePublicationS(s, p, { stateFingerprint, payloadFingerprint }), s);
  assert.equal(validatePublicationC(c, s, { stateFingerprint, payloadFingerprint, snapshotFingerprint }), c);
  assert.equal(validatePublicationQ(q, c, { stateFingerprint, payloadFingerprint, snapshotFingerprint }), q);
  assert.equal(validatePublicationZp(zp, q, { stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint }), zp);
  assert.equal(validatePublicationK(k, zp, { publicationFingerprint, checkpointFingerprint }), k);
  assert.throws(() => validatePublicationK(k, zp, { publicationFingerprint, checkpointFingerprint: zp["publication-zpFingerprint"] }));
  assert.throws(() => validatePublicationC(c, s, { stateFingerprint, payloadFingerprint, snapshotFingerprint: s["publication-sFingerprint"] }));
  assert.throws(() => validatePublicationZp(zp, { ...q, "publication-qFingerprint": "6".repeat(64) }, { stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint }));
});
test("prepared GR is complete, owner-bound, and branch-explicit before later authority records", () => {
  const request = seal({
    version: 1, kind: "genesis-authority-request", genesisTxId: "g", sequence: 1, fenceGeneration: 1, anchorFingerprint: hex,
    ownerPrincipalFingerprint: hex, managementPrincipalFingerprint: "b".repeat(64), botPrincipalFingerprint: "c".repeat(64), recoveryPrincipalFingerprint: "d".repeat(64), targetPrincipalFingerprint: "e".repeat(64),
    managementProvisioningFingerprint: "f".repeat(64), botProvisioningFingerprint: "1".repeat(64), recoveryProvisioningFingerprint: "2".repeat(64),
    generation: 1, requestedReaderMode: "no-reader", readerInstanceId: null, readerStartNonce: null, idempotencyKey: "idem",
    targetInputState: "absent", targetFingerprint: null, targetIdentityFingerprint: null, targetAclFingerprint: null, legacyTargetProofFingerprint: null,
    protectedInputFingerprint: "3".repeat(64),
  }, "requestFingerprint");
  assert.equal(validateGenesisAuthorityRequest(request), request);
  for (const key of ["managementProvisioningFingerprint", "targetInputState", "protectedInputFingerprint"]) {
    const missing = { ...request }; delete missing[key];
    assert.throws(() => validateGenesisAuthorityRequest(missing));
  }
  assert.throws(() => validateGenesisAuthorityRequest(seal({ ...request, requestedReaderMode: "handshake" }, "requestFingerprint")));
  assert.throws(() => validateGenesisAuthorityRequest(seal({ ...request, targetInputState: "legacy-unmigrated" }, "requestFingerprint")));
});

test("Y binds the canonical target rather than a substituted predecessor", () => {
  const targetFingerprint = "7".repeat(64);
  const u = buildPublicationU({
    txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, baselineFingerprint: "b".repeat(64), anchorFingerprint: hex,
    targetState: "genesis-empty", attestationFingerprint: hex, authorityReservationFingerprint: hex, authorityCommitSnapshotFingerprint: hex,
    fenceBindingFingerprint: null, leaseBindingFingerprint: null, readerProjectionFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  });
  const p = buildPublicationP({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, uFingerprint: u["publication-uFingerprint"], stateFingerprint: u["publication-uFingerprint"], targetState: u.targetState, authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null, leaseBindingFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null });
  const k = buildPublicationK({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, zpFingerprint: hex, publicationFingerprint: hex, authorityCommitSnapshotFingerprint: hex, checkpointFingerprint: hex });
  const y = buildPublicationY({ txId: "tx", genesisTxId: "tx", fenceGeneration: 1, generation: 1, kFingerprint: k["publication-kFingerprint"], publicationFingerprint: k.publicationFingerprint, targetState: p.targetState, authorityCommitSnapshotFingerprint: hex, fenceBindingFingerprint: null, targetFingerprint });
  assert.equal(validatePublicationY(y, k, targetFingerprint), y);
  assert.throws(() => validatePublicationY(y, k, k["publication-kFingerprint"]));
  assert.throws(() => validatePublicationY(seal({ ...y, kFingerprint: "9".repeat(64) }, "publication-yFingerprint"), k, targetFingerprint));
});
test("Genesis Zf rejects an attested token floor", () => {
  const request = seal({ version: 1, kind: "genesis-request", genesisTxId: "g", idempotencyKey: "i", anchorFingerprint: hex, ownerPrincipalFingerprint: hex, generation: 1, fenceGeneration: 1, requestedReaderMode: "no-reader", readerInstanceId: null, readerStartNonce: null, attestationFingerprint: hex, tokenFloorFingerprint: hex }, "requestFingerprint");
  const floor = seal({ version: 1, kind: "token-generation-floor", anchorFingerprint: hex, fenceGeneration: 1, genesisGeneration: 1, highestReservedGeneration: 1, highestCommittedGeneration: 0, lastReservationTxId: "g", lastCommittedTxId: null, lastAttestationFingerprint: null, floorPhase: "attested", attestedProofFingerprint: hex }, "floorFingerprint");
  const precommit = buildGenesisPrecommit({
    fenceGeneration: 1,
    genesisTxId: "g", generation: 1, genesisProbeFingerprint: hex, targetFingerprint: hex, targetIdentityFingerprint: hex, targetAclFingerprint: hex,
    controlRootFingerprint: hex, controlIdentityFingerprint: hex, controlAclFingerprint: hex, wrapperIdentityFingerprint: hex, wrapperAclFingerprint: hex, wrapperFingerprint: hex,
    readerVersionFloorFingerprint: hex, requestFingerprint: request.requestFingerprint, reservationFingerprint: hex, attestedProofFingerprint: hex,
    authorityReservationFingerprint: hex, authorityCommitSnapshotFingerprint: hex, authorityEpochFingerprint: hex, publicationKFingerprint: hex, publicationYFingerprint: hex, zeroGrantProofFingerprint: hex,
  });
  const zf = seal({ version: 1, kind: "genesis-finality", genesisTxId: "g", generation: 1, fenceGeneration: 1, anchorFingerprint: hex, attestationFingerprint: hex, tokenFloorFingerprint: floor.floorFingerprint, checkpointFingerprint: canonicalJsonHash(request), publicationKFingerprint: hex, publicationYFingerprint: hex, authorityEpochFingerprint: hex, precommitFingerprint: precommit.precommitFingerprint, finalityFingerprint: floor.floorFingerprint }, "zFinalityFingerprint");
  assert.throws(() => validateZFinality(zf, request, floor, precommit));
});
test("frozen management envelope vectors bind canonical UTF-8 bytes independently", () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/management-envelope-vectors.json", import.meta.url)));
  assert.equal(fixture.encoding, "utf-8");
  assert.deepEqual(fixture.vectors.map(({ name }) => name), [
    "tokenFloorReserved", "tokenFloorAttestedProof", "tokenFloorAttested", "tokenFloorCommitted",
    "zf", "noReaderFP", "boundFP", "noReaderGRR", "boundGRR", "authorityReceipt", "manualCleanup",
  ]);
  for (const vector of fixture.vectors) {
    const bytes = Buffer.from(vector.canonicalJson, "utf8");
    const record = parseCanonicalJsonBytes(bytes);
    assert.equal(canonicalJson(record), vector.canonicalJson, vector.name);
    assert.equal(canonicalJsonHash(record), vector.sha256, vector.name);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), vector.sha256, vector.name);
    assert.notEqual(createHash("sha256").update(Buffer.concat([bytes, Buffer.from([0])])).digest("hex"), vector.sha256, vector.name);
  }
});
test("successor heads require exact one-step and terminal rolling lineage", () => {
  const base = {
    version: 1, kind: "authority-successor-head", anchorFingerprint: hex, sequence: 2, fenceGeneration: 2, txId: "successor-2",
    rootGenesisTxId: "genesis", operation: "tokens-attest", phase: "reserved", requestFingerprint: hex,
    closeFingerprint: null, authorityCommitSnapshotFingerprint: null, baselineFingerprint: null,
    publicationKFingerprint: null, publicationYFingerprint: null, finalityFingerprint: null,
    receiptFingerprint: null, historyMarkerFingerprint: null, previousHeadFingerprint: null,
    previousReceiptFingerprint: hex, routeDisposition: "no-route", headFingerprint: null,
  };
  const reserved = buildAuthoritySuccessorRecord(base, "headFingerprint");
  const closed = buildAuthoritySuccessorRecord({ ...base, phase: "closed", closeFingerprint: "b".repeat(64), previousHeadFingerprint: reserved.headFingerprint, headFingerprint: null }, "headFingerprint");
  assert.doesNotThrow(() => validateAuthoritySuccessorHeadTransition(null, reserved));
  assert.doesNotThrow(() => validateAuthoritySuccessorHeadTransition(reserved, closed));
  assert.throws(() => validateAuthoritySuccessorHeadTransition(reserved, buildAuthoritySuccessorRecord({ ...closed, phase: "replaced", previousHeadFingerprint: reserved.headFingerprint, headFingerprint: null }, "headFingerprint")), /SUCCESSOR_ENVELOPE_INVALID/);
  const terminal = buildAuthoritySuccessorRecord({ ...closed, phase: "terminal", authorityCommitSnapshotFingerprint: hex, baselineFingerprint: hex, publicationKFingerprint: hex, publicationYFingerprint: hex, finalityFingerprint: hex, receiptFingerprint: "c".repeat(64), historyMarkerFingerprint: "d".repeat(64), previousHeadFingerprint: closed.headFingerprint, headFingerprint: null }, "headFingerprint");
  const next = buildAuthoritySuccessorRecord({ ...base, sequence: 3, fenceGeneration: 3, txId: "successor-3", previousHeadFingerprint: terminal.headFingerprint, previousReceiptFingerprint: terminal.receiptFingerprint, headFingerprint: null }, "headFingerprint");
  assert.doesNotThrow(() => validateAuthoritySuccessorHeadTransition(terminal, next));
  assert.throws(() => validateAuthoritySuccessorHeadTransition(terminal, buildAuthoritySuccessorRecord({ ...next, sequence: 4, headFingerprint: null }, "headFingerprint")), /SUCCESSOR_ENVELOPE_INVALID/);
});
test("mapping successors require exact next mapping generation", () => {
  const request = buildAuthoritySuccessorRecord({
    version: 1,
    kind: "authority-successor-request",
    sequence: 2,
    previousFenceGeneration: 1,
    candidateFenceGeneration: 2,
    txId: "successor-mapping-2",
    rootGenesisTxId: "genesis",
    idempotencyKey: "mapping-key",
    operation: "mapping-reconcile",
    anchorFingerprint: hex,
    actorPrincipalFingerprint: hex,
    previousReceiptFingerprint: hex,
    previousTargetFingerprint: hex,
    previousWrapperFingerprint: hex,
    previousRevision: 1,
    candidateRevision: 2,
    previousAuthorityEpoch: 1,
    candidateAuthorityEpoch: 2,
    previousTokenConfigGeneration: 1,
    candidateTokenConfigGeneration: 1,
    previousAttestationFingerprint: hex,
    candidateAttestationFingerprint: hex,
    previousMappingGeneration: 0,
    candidateMappingGeneration: 1,
    previousSnapshotFingerprint: hex,
    candidateSnapshotFingerprint: hex,
    candidateTargetFingerprint: hex,
    mappingRecoveryTxFingerprint: hex,
    targetState: "managed-empty",
    readerMode: "bound-reader",
    readerInstanceId: "reader",
    readerStartNonce: "start",
    readerNonce: "nonce",
    requestFingerprint: null,
  }, "requestFingerprint");

  assert.doesNotThrow(() => validateAuthoritySuccessorRequest(request));
  const retainedMapping = buildAuthoritySuccessorRecord({ ...request, targetState: "legacy-retained", requestFingerprint: null }, "requestFingerprint");
  assert.throws(() => validateAuthoritySuccessorRequest(retainedMapping), /SR fields/);
  const retainedAttestation = buildAuthoritySuccessorRecord({
    ...request,
    operation: "tokens-attest",
    candidateTokenConfigGeneration: request.previousTokenConfigGeneration + 1,
    candidateMappingGeneration: request.previousMappingGeneration,
    mappingRecoveryTxFingerprint: null,
    targetState: "legacy-retained",
    requestFingerprint: null,
  }, "requestFingerprint");
  assert.doesNotThrow(() => validateAuthoritySuccessorRequest(retainedAttestation));
  const missingFence = { ...request }; delete missingFence.candidateFenceGeneration;
  assert.throws(() => validateAuthoritySuccessorRequest(missingFence), /SUCCESSOR_ENVELOPE_INVALID/);
  const regressedFence = buildAuthoritySuccessorRecord({ ...request, candidateFenceGeneration: request.previousFenceGeneration, requestFingerprint: null }, "requestFingerprint");
  assert.throws(() => validateAuthoritySuccessorRequest(regressedFence), /fence/);
  const noReader = buildAuthoritySuccessorRecord({
    ...request,
    readerMode: "no-reader",
    readerInstanceId: null,
    readerStartNonce: null,
    readerNonce: null,
    requestFingerprint: null,
  }, "requestFingerprint");
  assert.doesNotThrow(() => validateAuthoritySuccessorRequest(noReader));
  const close = buildAuthoritySuccessorRecord({
    version: 1,
    kind: "authority-close-proof",
    txId: noReader.txId,
    rootGenesisTxId: noReader.rootGenesisTxId,
    requestFingerprint: noReader.requestFingerprint,
    previousReceiptFingerprint: noReader.previousReceiptFingerprint,
    fenceGeneration: noReader.candidateFenceGeneration,
    previousBarrierGeneration: 1,
    barrierGeneration: 2,
    affectedScope: "mapping",
    affectedMappingIds: [],
    affectedRouteFingerprints: [],
    readerInstanceId: null,
    readerStartNonce: null,
    retiredGrantFingerprint: null,
    retiredProjectionFingerprint: null,
    retiredAckFingerprint: null,
    admissionPhaseBefore: "closed",
    admissionPhaseAfter: "closed-drained",
    admissionDrained: true,
    outstandingRouteGrantCount: 0,
    routeDisposition: "no-route",
    closeFingerprint: null,
  }, "closeFingerprint");
  assert.doesNotThrow(() => validateAuthorityCloseProof(close, noReader));
  const mixedClose = buildAuthoritySuccessorRecord({
    ...close,
    readerInstanceId: "reader",
    closeFingerprint: null,
  }, "closeFingerprint");
  assert.throws(() => validateAuthorityCloseProof(mixedClose, noReader), /CL/);
  for (const field of ["readerInstanceId", "readerStartNonce", "readerNonce"]) {
    const mixed = buildAuthoritySuccessorRecord({
      ...noReader,
      [field]: field === "readerNonce" ? "nonce" : "reader",
      requestFingerprint: null,
    }, "requestFingerprint");
    assert.throws(() => validateAuthoritySuccessorRequest(mixed), /SR no-reader/);
  }
  for (const generation of [0, 2, 3]) {
    const invalid = buildAuthoritySuccessorRecord({
      ...request,
      candidateMappingGeneration: generation,
      requestFingerprint: null,
    }, "requestFingerprint");
    assert.throws(() => validateAuthoritySuccessorRequest(invalid), /SR mapping lineage/);
  }
});
test("successor phase recovery retains exact evidence and refuses malformed or skipped heads", () => {
  const base = {
    version: 1, kind: "authority-successor-head", anchorFingerprint: hex, sequence: 2, fenceGeneration: 2, txId: "successor-2",
    rootGenesisTxId: "genesis", operation: "tokens-attest", phase: "reserved", requestFingerprint: hex,
    closeFingerprint: null, authorityCommitSnapshotFingerprint: null, baselineFingerprint: null,
    publicationKFingerprint: null, publicationYFingerprint: null, finalityFingerprint: null,
    receiptFingerprint: null, historyMarkerFingerprint: null, previousHeadFingerprint: null,
    previousReceiptFingerprint: hex, routeDisposition: "no-route", headFingerprint: null,
  };
  const reserved = buildAuthoritySuccessorRecord(base, "headFingerprint");
  const closed = buildAuthoritySuccessorRecord({ ...base, phase: "closed", closeFingerprint: "b".repeat(64), previousHeadFingerprint: reserved.headFingerprint, headFingerprint: null }, "headFingerprint");
  const replaced = buildAuthoritySuccessorRecord({ ...closed, phase: "replaced", authorityCommitSnapshotFingerprint: "c".repeat(64), baselineFingerprint: "d".repeat(64), publicationKFingerprint: "e".repeat(64), publicationYFingerprint: "f".repeat(64), previousHeadFingerprint: closed.headFingerprint, headFingerprint: null }, "headFingerprint");
  const pending = buildAuthoritySuccessorRecord({ ...replaced, phase: "reader-pending", finalityFingerprint: "1".repeat(64), previousHeadFingerprint: replaced.headFingerprint, headFingerprint: null }, "headFingerprint");
  const terminal = buildAuthoritySuccessorRecord({ ...pending, phase: "terminal", receiptFingerprint: "2".repeat(64), historyMarkerFingerprint: "3".repeat(64), previousHeadFingerprint: pending.headFingerprint, headFingerprint: null }, "headFingerprint");

  for (const [previous, next] of [[reserved, closed], [closed, replaced], [replaced, pending], [pending, terminal]]) {
    assert.doesNotThrow(() => validateAuthoritySuccessorHeadTransition(previous, next));
  }
  assert.equal(terminal.closeFingerprint, closed.closeFingerprint);
  assert.equal(terminal.baselineFingerprint, replaced.baselineFingerprint);
  assert.equal(terminal.finalityFingerprint, pending.finalityFingerprint);
  assert.throws(() => validateAuthoritySuccessorHeadTransition(closed, pending), /SUCCESSOR_ENVELOPE_INVALID/);
  assert.throws(() => validateAuthoritySuccessorHeadTransition(reserved, { ...closed, headFingerprint: reserved.headFingerprint }), /SUCCESSOR_ENVELOPE_INVALID/);
});
test("successor reader records reject every substituted authoritative scalar", () => {
  const request = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-request", sequence: 2, previousFenceGeneration: 1, candidateFenceGeneration: 2, txId: "successor", rootGenesisTxId: "genesis", idempotencyKey: "key", operation: "tokens-attest",
    anchorFingerprint: hex, actorPrincipalFingerprint: hex, previousReceiptFingerprint: hex, previousTargetFingerprint: hex, previousWrapperFingerprint: hex,
    previousRevision: 1, candidateRevision: 2, previousAuthorityEpoch: 1, candidateAuthorityEpoch: 2, previousTokenConfigGeneration: 1, candidateTokenConfigGeneration: 2,
    previousAttestationFingerprint: hex, candidateAttestationFingerprint: "b".repeat(64), previousMappingGeneration: 0, candidateMappingGeneration: 0,
    previousSnapshotFingerprint: hex, candidateSnapshotFingerprint: "c".repeat(64), candidateTargetFingerprint: "d".repeat(64), mappingRecoveryTxFingerprint: null,
    targetState: "managed", readerMode: "bound-reader", readerInstanceId: "reader", readerStartNonce: "start", readerNonce: "nonce", requestFingerprint: null,
  }, "requestFingerprint");
  const fence = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-fence", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId, requestFingerprint: request.requestFingerprint,
    fenceGeneration: request.candidateFenceGeneration,
    anchorFingerprint: request.anchorFingerprint, authorityCommitSnapshotFingerprint: hex, readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce,
    readerVersion: 2, previousFenceBindingFingerprint: hex, fenceBindingFingerprint: null,
  }, "fenceBindingFingerprint");
  const finality = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-finality", sequence: request.sequence, fenceGeneration: request.candidateFenceGeneration, txId: request.txId, rootGenesisTxId: request.rootGenesisTxId, operation: request.operation,
    requestFingerprint: request.requestFingerprint, baselineFingerprint: hex, closeFingerprint: hex, anchorFingerprint: request.anchorFingerprint,
    authorityReservationFingerprint: hex, authorityCommitSnapshotFingerprint: fence.authorityCommitSnapshotFingerprint, authorityEpochFingerprint: hex, tokenFloorFingerprint: hex,
    attestationFingerprint: request.candidateAttestationFingerprint, publicationKFingerprint: hex, publicationYFingerprint: hex, operationEvidenceFingerprint: hex, auditEntryFingerprint: hex,
    targetFingerprint: "e".repeat(64), targetIdentityFingerprint: hex, targetAclFingerprint: hex, wrapperFingerprint: "f".repeat(64), controlRootFingerprint: hex,
    revision: request.candidateRevision, authorityEpoch: request.candidateAuthorityEpoch, tokenConfigGeneration: request.candidateTokenConfigGeneration,
    mappingGeneration: request.candidateMappingGeneration, snapshotFingerprint: request.candidateSnapshotFingerprint, routeDisposition: "no-route", finalityFingerprint: null,
  }, "finalityFingerprint");
  const lease = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-lease", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId, requestFingerprint: request.requestFingerprint,
    fenceGeneration: request.candidateFenceGeneration,
    readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce, readerVersion: 2, fenceBindingFingerprint: fence.fenceBindingFingerprint,
    previousLeaseBindingFingerprint: request.previousReceiptFingerprint, leaseBindingFingerprint: null,
  }, "leaseBindingFingerprint");
  const projection = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-reader-projection", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId, requestFingerprint: request.requestFingerprint,
    fenceGeneration: request.candidateFenceGeneration,
    finalityFingerprint: finality.finalityFingerprint, anchorFingerprint: request.anchorFingerprint, authorityCommitSnapshotFingerprint: finality.authorityCommitSnapshotFingerprint,
    targetFingerprint: finality.targetFingerprint, wrapperFingerprint: finality.wrapperFingerprint, revision: finality.revision, authorityEpoch: finality.authorityEpoch,
    tokenConfigGeneration: finality.tokenConfigGeneration, mappingGeneration: finality.mappingGeneration, readerInstanceId: request.readerInstanceId,
    readerStartNonce: request.readerStartNonce, readerVersion: 2, readerNonce: request.readerNonce, fenceBindingFingerprint: fence.fenceBindingFingerprint,
    leaseBindingFingerprint: lease.leaseBindingFingerprint, readerProjectionFingerprint: null,
  }, "readerProjectionFingerprint");
  const ack = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-ack", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId, requestFingerprint: request.requestFingerprint,
    fenceGeneration: request.candidateFenceGeneration,
    finalityFingerprint: finality.finalityFingerprint, readerProjectionFingerprint: projection.readerProjectionFingerprint, leaseBindingFingerprint: lease.leaseBindingFingerprint,
    readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce, readerVersion: 2, readerNonce: request.readerNonce,
    ackDisposition: "verified-no-route", ackFingerprint: null,
  }, "ackFingerprint");
  assert.doesNotThrow(() => validateAuthoritySuccessorFence(fence, request));
  assert.doesNotThrow(() => validateAuthoritySuccessorLease(lease, request, fence));
  assert.doesNotThrow(() => validateAuthoritySuccessorReaderProjection(projection, request, finality, lease));
  assert.doesNotThrow(() => validateAuthoritySuccessorAck(ack, request, finality, projection));
  const rollingRequest = buildAuthoritySuccessorRecord({
    ...request, sequence: 3, txId: "successor-rolling", previousReceiptFingerprint: "7".repeat(64), previousFenceGeneration: 2, candidateFenceGeneration: 3, requestFingerprint: null,
  }, "requestFingerprint");
  const rollingFence = buildAuthoritySuccessorRecord({
    ...fence, txId: rollingRequest.txId, requestFingerprint: rollingRequest.requestFingerprint, fenceGeneration: rollingRequest.candidateFenceGeneration, fenceBindingFingerprint: null,
  }, "fenceBindingFingerprint");
  const rollingLease = buildAuthoritySuccessorRecord({
    ...lease, txId: rollingRequest.txId, requestFingerprint: rollingRequest.requestFingerprint, fenceGeneration: rollingRequest.candidateFenceGeneration,
    fenceBindingFingerprint: rollingFence.fenceBindingFingerprint,
    previousLeaseBindingFingerprint: rollingRequest.previousReceiptFingerprint, leaseBindingFingerprint: null,
  }, "leaseBindingFingerprint");
  assert.doesNotThrow(() => validateAuthoritySuccessorLease(rollingLease, rollingRequest, rollingFence));
  const foreignReceiptRequest = buildAuthoritySuccessorRecord({
    ...request, previousReceiptFingerprint: "8".repeat(64), requestFingerprint: null,
  }, "requestFingerprint");
  assert.throws(() => validateAuthoritySuccessorLease(lease, foreignReceiptRequest, fence), /L2 predecessor relation/);

  const sealedMutation = (record, field, fingerprintField) => buildAuthoritySuccessorRecord({ ...record, [field]: typeof record[field] === "number" ? record[field] + 1 : record[field] === "genesis" ? "foreign-genesis" : record[field] === "reader" ? "foreign-reader" : record[field] === "start" ? "foreign-start" : record[field] === "nonce" ? "foreign-nonce" : "9".repeat(64), [fingerprintField]: null }, fingerprintField);
  for (const field of ["rootGenesisTxId", "requestFingerprint", "fenceGeneration", "readerInstanceId", "readerStartNonce", "readerVersion", "previousLeaseBindingFingerprint"]) assert.throws(() => validateAuthoritySuccessorLease(sealedMutation(lease, field, "leaseBindingFingerprint"), request, fence), /L2/);
  for (const field of ["rootGenesisTxId", "requestFingerprint", "fenceGeneration", "anchorFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion"]) assert.throws(() => validateAuthoritySuccessorFence(sealedMutation(fence, field, "fenceBindingFingerprint"), request), /F2/);
  for (const field of ["rootGenesisTxId", "requestFingerprint", "fenceGeneration", "finalityFingerprint", "anchorFingerprint", "authorityCommitSnapshotFingerprint", "targetFingerprint", "wrapperFingerprint", "revision", "authorityEpoch", "tokenConfigGeneration", "mappingGeneration", "readerInstanceId", "readerStartNonce", "readerVersion", "readerNonce", "fenceBindingFingerprint", "leaseBindingFingerprint"]) assert.throws(() => validateAuthoritySuccessorReaderProjection(sealedMutation(projection, field, "readerProjectionFingerprint"), request, finality, lease), /RP2/);
  for (const field of ["rootGenesisTxId", "requestFingerprint", "fenceGeneration", "finalityFingerprint", "readerProjectionFingerprint", "leaseBindingFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion", "readerNonce"]) assert.throws(() => validateAuthoritySuccessorAck(sealedMutation(ack, field, "ackFingerprint"), request, finality, projection), /AK2/);
});
test("successor authority tuples bind request candidates, reservation/commit fingerprints, and finality epoch", () => {
  const request = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-request", sequence: 2, txId: "successor-lineage", rootGenesisTxId: "genesis",
    idempotencyKey: "lineage-key", operation: "tokens-attest", anchorFingerprint: hex, actorPrincipalFingerprint: hex,
    previousReceiptFingerprint: "b".repeat(64), previousTargetFingerprint: hex, previousWrapperFingerprint: hex,
    previousRevision: 1, candidateRevision: 2, previousAuthorityEpoch: 1, candidateAuthorityEpoch: 2,
    previousTokenConfigGeneration: 1, candidateTokenConfigGeneration: 2, previousAttestationFingerprint: hex,
    candidateAttestationFingerprint: "c".repeat(64), previousMappingGeneration: 0, candidateMappingGeneration: 0,
    previousSnapshotFingerprint: hex, candidateSnapshotFingerprint: "d".repeat(64), candidateTargetFingerprint: "e".repeat(64),
    previousFenceGeneration: 1, candidateFenceGeneration: 2, mappingRecoveryTxFingerprint: null, targetState: "managed-empty",
    readerMode: "no-reader", readerInstanceId: null, readerStartNonce: null, readerNonce: null, requestFingerprint: null,
  }, "requestFingerprint");
  const reservation = seal({
    version: 1, kind: "authority-reservation", anchorFingerprint: request.anchorFingerprint, fenceGeneration: request.candidateFenceGeneration,
    txId: request.txId, epoch: request.candidateAuthorityEpoch, generation: request.candidateTokenConfigGeneration,
    candidateFingerprint: request.requestFingerprint, previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
    reservationFingerprint: null,
  }, "reservationFingerprint");
  const commit = seal({
    version: 1, kind: "authority-commit-snapshot", anchorFingerprint: request.anchorFingerprint, fenceGeneration: request.candidateFenceGeneration,
    txId: request.txId, epoch: request.candidateAuthorityEpoch, generation: request.candidateTokenConfigGeneration,
    candidateFingerprint: request.requestFingerprint, reservationFingerprint: reservation.reservationFingerprint,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint, authorityCommitSnapshotFingerprint: null,
  }, "authorityCommitSnapshotFingerprint");
  const authorityEpoch = seal({
    version: 1, kind: "authority-epoch", anchorFingerprint: request.anchorFingerprint, fenceGeneration: request.candidateFenceGeneration,
    epoch: request.candidateAuthorityEpoch, reservationTxId: request.txId, commitTxId: request.txId,
    previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint, authorityEpochFingerprint: null,
  }, "authorityEpochFingerprint");
  const finality = buildAuthoritySuccessorRecord({
    version: 1, kind: "authority-successor-finality", sequence: request.sequence, txId: request.txId,
    rootGenesisTxId: request.rootGenesisTxId, requestFingerprint: request.requestFingerprint,
    fenceGeneration: request.candidateFenceGeneration, operation: request.operation, baselineFingerprint: hex,
    closeFingerprint: hex, anchorFingerprint: request.anchorFingerprint, authorityReservationFingerprint: reservation.reservationFingerprint,
    authorityCommitSnapshotFingerprint: commit.authorityCommitSnapshotFingerprint, authorityEpochFingerprint: authorityEpoch.authorityEpochFingerprint,
    tokenFloorFingerprint: hex, attestationFingerprint: request.candidateAttestationFingerprint, publicationKFingerprint: hex,
    publicationYFingerprint: hex, operationEvidenceFingerprint: hex, auditEntryFingerprint: hex, targetFingerprint: hex,
    targetIdentityFingerprint: hex, targetAclFingerprint: hex, wrapperFingerprint: hex, controlRootFingerprint: hex,
    revision: request.candidateRevision, authorityEpoch: request.candidateAuthorityEpoch,
    tokenConfigGeneration: request.candidateTokenConfigGeneration, mappingGeneration: request.candidateMappingGeneration,
    snapshotFingerprint: request.candidateSnapshotFingerprint, routeDisposition: "no-route", finalityFingerprint: null,
  }, "finalityFingerprint");
  assert.doesNotThrow(() => validateAuthorityReservation(reservation, request));
  assert.doesNotThrow(() => validateAuthorityCommitSnapshot(commit, reservation, request));
  assert.doesNotThrow(() => validateAuthorityEpoch(authorityEpoch, request, reservation, commit));
  assert.doesNotThrow(() => validateAuthoritySuccessorFinality(finality, request, null, reservation, commit, authorityEpoch));
  assert.throws(() => validateAuthorityReservation(seal({ ...reservation, txId: "foreign-tx", reservationFingerprint: null }, "reservationFingerprint"), request));
  assert.throws(() => validateAuthorityCommitSnapshot(seal({ ...commit, reservationFingerprint: hex, authorityCommitSnapshotFingerprint: null }, "authorityCommitSnapshotFingerprint"), reservation, request));
  const foreignEpoch = seal({ ...authorityEpoch, authorityEpochFingerprint: null, previousAuthorityCommitSnapshotFingerprint: hex }, "authorityEpochFingerprint");
  assert.throws(() => validateAuthoritySuccessorFinality(finality, request, null, reservation, commit, foreignEpoch));
  const detachedFinality = seal({ ...finality, authorityEpochFingerprint: hex }, "finalityFingerprint");
  assert.throws(() => validateAuthoritySuccessorFinality(detachedFinality, request, null, reservation, commit, authorityEpoch));
  assert.throws(() => validateAuthorityEpoch(seal({ ...authorityEpoch, fenceGeneration: 1, authorityEpochFingerprint: null }, "authorityEpochFingerprint"), request, reservation, commit));
});
