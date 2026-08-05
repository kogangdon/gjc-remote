import { canonicalJsonHash, isHex64 } from "./strict-json.js";
import { isOpaqueIdentity } from "./identity.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, expected) => plain(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`GENESIS_ENVELOPE_INVALID: ${message}`); };
const nullableHex = (value) => value === null || isHex64(value);
const nullableText = (value) => value === null || isOpaqueIdentity(value);
const hash = (record, field) => canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));

const attestationKeys = ["version", "kind", "anchorFingerprint", "tokenConfigGeneration", "tokenConfigHostSetFingerprint", "managedGrammarVersion", "sourceKind", "producerPrincipal", "rotationKind", "previousAttestationFingerprint", "txId", "attestationFingerprint"];
export function validateTokenConfigAttestation(attestation) {
  if (!exact(attestation, attestationKeys) || attestation.version !== 1 || attestation.kind !== "token-config-attestation" || !isHex64(attestation.anchorFingerprint) || !Number.isSafeInteger(attestation.tokenConfigGeneration) || attestation.tokenConfigGeneration < 1 || !isHex64(attestation.tokenConfigHostSetFingerprint) || attestation.managedGrammarVersion !== 1 || attestation.sourceKind !== "protected-stdin" || !isOpaqueIdentity(attestation.producerPrincipal) || !attestation.producerPrincipal.startsWith("management/") || !["genesis", "same-key", "host-set-change"].includes(attestation.rotationKind) || !nullableHex(attestation.previousAttestationFingerprint) || !isOpaqueIdentity(attestation.txId) || !isHex64(attestation.attestationFingerprint)) fail("token attestation schema");
  if ((attestation.rotationKind === "genesis") !== (attestation.previousAttestationFingerprint === null)) fail("token attestation lineage");
  if ((attestation.rotationKind !== "genesis") !== (attestation.previousAttestationFingerprint !== null)) fail("token attestation lineage");
  if (hash(attestation, "attestationFingerprint") !== attestation.attestationFingerprint) fail("token attestation fingerprint");
  return attestation;
}
const floorKeys = ["version", "kind", "anchorFingerprint", "readerVersionFloor", "firstPendingTxId", "firstReaderInstanceId", "firstReaderStartNonce", "lastTransitionTxId", "previousFloorFingerprint", "floorFingerprint"];
export function validateReaderVersionFloor(floor) {
  if (!exact(floor, floorKeys) || floor.version !== 1 || floor.kind !== "reader-version-floor" || !isHex64(floor.anchorFingerprint) || !nullableHex(floor.previousFloorFingerprint) || !isHex64(floor.floorFingerprint)) fail("reader floor schema");
  if (floor.readerVersionFloor !== null && floor.readerVersionFloor !== 2) fail("reader version floor");
  for (const key of ["firstPendingTxId", "firstReaderInstanceId", "firstReaderStartNonce", "lastTransitionTxId"]) if (!nullableText(floor[key])) fail(`${key} must be text or null`);
  if (floor.readerVersionFloor === null && [floor.firstPendingTxId, floor.firstReaderInstanceId, floor.firstReaderStartNonce, floor.lastTransitionTxId, floor.previousFloorFingerprint].some((value) => value !== null)) fail("null floor has relation");
  if (floor.readerVersionFloor === 2 && [floor.firstPendingTxId, floor.firstReaderInstanceId, floor.firstReaderStartNonce, floor.lastTransitionTxId].some((value) => value === null)) fail("bound floor relation missing");
  if (hash(floor, "floorFingerprint") !== floor.floorFingerprint) fail("reader floor fingerprint");
  return floor;
}

export function advanceReaderVersionFloor(floor, { txId, readerInstanceId, readerStartNonce }) {
  validateReaderVersionFloor(floor);
  if (floor.readerVersionFloor !== null) fail("reader floor is irreversible");
  if (![txId, readerInstanceId, readerStartNonce].every(isOpaqueIdentity)) fail("reader floor transition identity");
  const next = { ...floor, readerVersionFloor: 2, firstPendingTxId: txId, firstReaderInstanceId: readerInstanceId, firstReaderStartNonce: readerStartNonce, lastTransitionTxId: txId, previousFloorFingerprint: floor.floorFingerprint };
  next.floorFingerprint = hash(next, "floorFingerprint");
  return validateReaderVersionFloor(next);
}
const readerRelationKeys = ["attestationFingerprint", "authorityReservationFingerprint", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint", "leaseBindingFingerprint", "readerProjectionFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion"];
export function validateReaderRelations(relations, floor = null) {
  if (!exact(relations, readerRelationKeys)) fail("reader relation schema");
  for (const key of readerRelationKeys.slice(0, 6)) if (!nullableHex(relations[key])) fail(`${key} must be hex or null`);
  if (!nullableText(relations.readerInstanceId) || !nullableText(relations.readerStartNonce) || (relations.readerVersion !== null && relations.readerVersion !== 2)) fail("reader relation identity or version");
  const values = [relations.fenceBindingFingerprint, relations.leaseBindingFingerprint, relations.readerProjectionFingerprint, relations.readerInstanceId, relations.readerStartNonce, relations.readerVersion];
  if (values.some((value) => value === null) && values.some((value) => value !== null)) fail("reader relation partial branch");
  if (floor !== null) {
    validateReaderVersionFloor(floor);
    if ((floor.readerVersionFloor === null) !== (relations.readerVersion === null)) fail("reader floor disagreement");
    if (floor.readerVersionFloor === 2 && (relations.readerInstanceId !== floor.firstReaderInstanceId || relations.readerStartNonce !== floor.firstReaderStartNonce)) fail("reader floor identity disagreement");
  }
  return relations;
}

const projectionKeys = ["version", "kind", "anchorFingerprint", "genesisTxId", "generation", "readerInstanceId", "readerStartNonce", "readerVersion", "fenceBindingFingerprint", "leaseBindingFingerprint", "zFinalityFingerprint", "readerProjectionFingerprint"];
export function validateReaderProjection(projection, floor, tokenFloor, zFinalityFingerprint) {
  if (!exact(projection, projectionKeys) || projection.version !== 1 || projection.kind !== "reader-projection") fail("reader projection schema");
  validateReaderVersionFloor(floor); validateTokenFloor(tokenFloor);
  if (tokenFloor.floorPhase !== "committed" || tokenFloor.lastCommittedTxId === null || tokenFloor.lastAttestationFingerprint === null || floor.readerVersionFloor !== 2 || projection.readerVersion !== 2 || !isOpaqueIdentity(projection.genesisTxId) || !Number.isSafeInteger(projection.generation)) fail("reader projection finality order");
  for (const key of ["anchorFingerprint", "fenceBindingFingerprint", "leaseBindingFingerprint", "zFinalityFingerprint", "readerProjectionFingerprint"]) if (!isHex64(projection[key])) fail(`${key} fingerprint`);
  if (!isOpaqueIdentity(projection.readerInstanceId) || !isOpaqueIdentity(projection.readerStartNonce) || projection.readerInstanceId !== floor.firstReaderInstanceId || projection.readerStartNonce !== floor.firstReaderStartNonce || projection.zFinalityFingerprint !== zFinalityFingerprint) fail("reader projection binding");
  if (hash(projection, "readerProjectionFingerprint") !== projection.readerProjectionFingerprint) fail("reader projection fingerprint");
  return projection;
}

const tokenFloorKeys = ["version", "kind", "anchorFingerprint", "genesisGeneration", "highestReservedGeneration", "highestCommittedGeneration", "lastReservationTxId", "lastCommittedTxId", "lastAttestationFingerprint", "floorPhase", "attestedProofFingerprint", "floorFingerprint"];
export function validateTokenFloor(floor) {
  if (!exact(floor, tokenFloorKeys) || floor.version !== 1 || floor.kind !== "token-generation-floor" || !isHex64(floor.anchorFingerprint) || !Number.isSafeInteger(floor.genesisGeneration) || floor.genesisGeneration < 1 || !Number.isSafeInteger(floor.highestReservedGeneration) || !Number.isSafeInteger(floor.highestCommittedGeneration) || floor.highestReservedGeneration < floor.genesisGeneration - 1 || floor.highestCommittedGeneration < floor.genesisGeneration - 1 || floor.highestCommittedGeneration > floor.highestReservedGeneration || !nullableText(floor.lastReservationTxId) || !nullableText(floor.lastCommittedTxId) || !nullableHex(floor.lastAttestationFingerprint) || !["reserved", "attested", "committed"].includes(floor.floorPhase) || !nullableHex(floor.attestedProofFingerprint) || !isHex64(floor.floorFingerprint)) fail("token floor schema");
  if ((floor.highestReservedGeneration < floor.genesisGeneration) !== (floor.lastReservationTxId === null) || (floor.highestCommittedGeneration < floor.genesisGeneration) !== (floor.lastCommittedTxId === null || floor.lastAttestationFingerprint === null)) fail("token floor relation");
  if (floor.floorPhase === "reserved" && floor.attestedProofFingerprint !== null) fail("reserved floor proof");
  if (floor.floorPhase === "attested" && (floor.attestedProofFingerprint === null || floor.highestReservedGeneration !== floor.highestCommittedGeneration + 1)) fail("attested floor relation");
  if (floor.floorPhase === "committed" && (floor.attestedProofFingerprint === null || floor.highestReservedGeneration !== floor.highestCommittedGeneration)) fail("committed floor relation");
  if (hash(floor, "floorFingerprint") !== floor.floorFingerprint) fail("token floor fingerprint");
  return floor;
}
export function reserveTokenGeneration(floor, { generation, txId }) {
  validateTokenFloor(floor);
  if (floor.floorPhase !== "reserved" && floor.floorPhase !== "committed") fail("token floor reservation phase");
  if (!Number.isSafeInteger(generation) || generation !== floor.highestReservedGeneration + 1 || !isOpaqueIdentity(txId)) fail("token floor reservation CAS mismatch");
  const next = { ...floor, highestReservedGeneration: generation, lastReservationTxId: txId, floorPhase: "reserved", attestedProofFingerprint: null, floorFingerprint: null };
  next.floorFingerprint = hash(next, "floorFingerprint");
  return validateTokenFloor(next);
}
const attestedTokenFloorKeys = ["version", "kind", "genesisTxId", "generation", "reservationFingerprint", "attestationFingerprint", "attestedProofFingerprint"];
export function buildAttestedTokenFloorProof(reservation, attestation) {
  validateTokenFloorReservation(reservation); validateTokenConfigAttestation(attestation);
  if (reservation.lastReservationTxId !== attestation.txId || reservation.highestReservedGeneration !== attestation.tokenConfigGeneration) fail("attested token floor binding");
  const proof = { version: 1, kind: "attested-token-floor-proof", genesisTxId: attestation.txId, generation: attestation.tokenConfigGeneration, reservationFingerprint: reservation.floorFingerprint, attestationFingerprint: attestation.attestationFingerprint, attestedProofFingerprint: null };
  proof.attestedProofFingerprint = hash(proof, "attestedProofFingerprint");
  return proof;
}
export function validateAttestedTokenFloorProof(proof, reservation, attestation) {
  if (!exact(proof, attestedTokenFloorKeys) || proof.version !== 1 || proof.kind !== "attested-token-floor-proof" || !isOpaqueIdentity(proof.genesisTxId) || !Number.isSafeInteger(proof.generation) || !isHex64(proof.reservationFingerprint) || !isHex64(proof.attestationFingerprint) || !isHex64(proof.attestedProofFingerprint) || hash(proof, "attestedProofFingerprint") !== proof.attestedProofFingerprint) fail("attested token floor proof");
  const expected = buildAttestedTokenFloorProof(reservation, attestation);
  if (hash(proof, "attestedProofFingerprint") !== hash(expected, "attestedProofFingerprint")) fail("attested token floor proof relation");
  return proof;
}
export function attestTokenFloor(reservation, proof) {
  validateTokenFloorReservation(reservation);
  if (reservation.floorPhase !== "reserved" || !isHex64(proof?.attestedProofFingerprint)) fail("token floor attest CAS mismatch");
  const next = { ...reservation, floorPhase: "attested", attestedProofFingerprint: proof.attestedProofFingerprint, floorFingerprint: null };
  next.floorFingerprint = hash(next, "floorFingerprint");
  return validateTokenFloor(next);
}
export function commitTokenFloor(floor, { generation, txId, attestationFingerprint }) {
  validateTokenFloor(floor);
  if (floor.floorPhase !== "attested" || !Number.isSafeInteger(generation) || generation !== floor.highestReservedGeneration || generation !== floor.highestCommittedGeneration + 1 || floor.lastReservationTxId !== txId || !isOpaqueIdentity(txId) || !isHex64(attestationFingerprint)) fail("token floor commit CAS mismatch");
  const next = { ...floor, highestCommittedGeneration: generation, lastCommittedTxId: txId, lastAttestationFingerprint: attestationFingerprint, floorPhase: "committed", floorFingerprint: null };
  next.floorFingerprint = hash(next, "floorFingerprint");
  return validateTokenFloor(next);
}
export function validateTokenFloorReservation(reservation) {
  validateTokenFloor(reservation);
  if (reservation.floorPhase !== "reserved" || reservation.highestReservedGeneration !== reservation.highestCommittedGeneration + 1 ||
      reservation.lastReservationTxId === null ||
      (reservation.lastCommittedTxId === null) !== (reservation.lastAttestationFingerprint === null)) {
    fail("token floor reservation");
  }
  return reservation;
}

const requestKeys = ["version", "kind", "genesisTxId", "idempotencyKey", "anchorFingerprint", "ownerPrincipalFingerprint", "generation", "requestedReaderMode", "readerInstanceId", "readerStartNonce", "attestationFingerprint", "tokenFloorFingerprint", "requestFingerprint"];
export function validateGenesisRequest(request) {
  if (!exact(request, requestKeys) || request.version !== 1 || request.kind !== "genesis-request" || !Number.isSafeInteger(request.generation) || request.generation < 1) fail("genesis request schema");
  if (!isOpaqueIdentity(request.genesisTxId) || !isOpaqueIdentity(request.idempotencyKey) || !isHex64(request.anchorFingerprint) || !isHex64(request.ownerPrincipalFingerprint) || !isHex64(request.attestationFingerprint) || !isHex64(request.tokenFloorFingerprint)) fail("genesis request relation");
  if (![["no-reader", null, null], ["handshake", request.readerInstanceId, request.readerStartNonce]].some(([mode, id, nonce]) => request.requestedReaderMode === mode && request.readerInstanceId === id && request.readerStartNonce === nonce)) fail("reader branch");
  if (!isHex64(request.requestFingerprint) || hash(request, "requestFingerprint") !== request.requestFingerprint) fail("request fingerprint");
  return request;
}

const precommitKeys = ["version", "kind", "genesisTxId", "generation", "genesisProbeFingerprint", "targetFingerprint", "targetIdentityFingerprint", "targetAclFingerprint", "controlRootFingerprint", "controlIdentityFingerprint", "controlAclFingerprint", "wrapperIdentityFingerprint", "wrapperAclFingerprint", "wrapperFingerprint", "readerVersionFloorFingerprint", "requestFingerprint", "reservationFingerprint", "attestedProofFingerprint", "authorityReservationFingerprint", "authorityCommitSnapshotFingerprint", "authorityEpochFingerprint", "publicationKFingerprint", "publicationYFingerprint", "zeroGrantProofFingerprint", "admissionState", "admissionClosed", "admissionDrained", "outstandingAdmissionGrants", "admissionGrantWrites", "admissionAckWrites", "routeDisposition", "precommitFingerprint"];
export function buildGenesisPrecommit({
  genesisTxId,
  generation,
  genesisProbeFingerprint,
  targetFingerprint,
  targetIdentityFingerprint,
  targetAclFingerprint,
  controlIdentityFingerprint,
  controlRootFingerprint,
  controlAclFingerprint,
  wrapperIdentityFingerprint,
  wrapperAclFingerprint,
  wrapperFingerprint,
  readerVersionFloorFingerprint,
  requestFingerprint,
  reservationFingerprint,
  attestedProofFingerprint,
  authorityReservationFingerprint,
  authorityCommitSnapshotFingerprint,
  authorityEpochFingerprint,
  publicationKFingerprint,
  publicationYFingerprint,
  zeroGrantProofFingerprint,
}) {
  const precommit = {
    version: 1,
    kind: "genesis-precommit-proof",
    genesisTxId,
    generation,
    genesisProbeFingerprint,
    targetFingerprint,
    targetIdentityFingerprint,
    targetAclFingerprint,
    controlIdentityFingerprint,
    controlRootFingerprint,
    controlAclFingerprint,
    wrapperIdentityFingerprint,
    wrapperAclFingerprint,
    wrapperFingerprint,
    readerVersionFloorFingerprint,
    requestFingerprint,
    reservationFingerprint,
    attestedProofFingerprint,
    authorityReservationFingerprint,
    authorityCommitSnapshotFingerprint,
    authorityEpochFingerprint,
    publicationKFingerprint,
    publicationYFingerprint,
    zeroGrantProofFingerprint,
    admissionState: "closed-drained-zero-grants",
    admissionClosed: true,
    admissionDrained: true,
    outstandingAdmissionGrants: 0,
    admissionGrantWrites: 0,
    admissionAckWrites: 0,
    routeDisposition: "no-route",
    precommitFingerprint: null,
  };
  precommit.precommitFingerprint = hash(precommit, "precommitFingerprint");
  return validateGenesisPrecommit(precommit);
}
export function validateGenesisPrecommit(precommit) {
  if (!exact(precommit, precommitKeys) || precommit.version !== 1 ||
      precommit.kind !== "genesis-precommit-proof" ||
      !isOpaqueIdentity(precommit.genesisTxId) ||
      !Number.isSafeInteger(precommit.generation) || precommit.generation < 1 ||
      precommit.admissionState !== "closed-drained-zero-grants" ||
      precommit.admissionClosed !== true || precommit.admissionDrained !== true ||
      precommit.outstandingAdmissionGrants !== 0 || precommit.admissionGrantWrites !== 0 ||
      precommit.admissionAckWrites !== 0 || precommit.routeDisposition !== "no-route") {
    fail("precommit schema");
  }
  for (const key of precommitKeys.slice(4, 24)) if (!isHex64(precommit[key])) fail(`${key} fingerprint`);
  if (!isHex64(precommit.precommitFingerprint) ||
      hash(precommit, "precommitFingerprint") !== precommit.precommitFingerprint) {
    fail("precommit fingerprint");
  }
  return precommit;
}

const zfKeys = ["version", "kind", "genesisTxId", "generation", "anchorFingerprint", "attestationFingerprint", "tokenFloorFingerprint", "checkpointFingerprint", "publicationKFingerprint", "publicationYFingerprint", "authorityEpochFingerprint", "precommitFingerprint", "finalityFingerprint", "zFinalityFingerprint"];
export function validateZFinality(zf, request, floor, precommit) {
  if (!exact(zf, zfKeys) || zf.version !== 1 || zf.kind !== "genesis-finality") fail("Zf schema");
  validateGenesisRequest(request);
  validateTokenFloor(floor);
  validateGenesisPrecommit(precommit);
  if (floor.floorPhase !== "committed" || floor.lastCommittedTxId !== request.genesisTxId ||
      floor.lastReservationTxId !== request.genesisTxId ||
      floor.highestReservedGeneration !== request.generation ||
      floor.highestCommittedGeneration !== request.generation ||
      floor.lastAttestationFingerprint !== request.attestationFingerprint) {
    fail("Zf requires committed token floor");
  }
  if (precommit.genesisTxId !== request.genesisTxId ||
      precommit.generation !== request.generation ||
      precommit.requestFingerprint !== request.requestFingerprint ||
      zf.genesisTxId !== request.genesisTxId || zf.generation !== request.generation ||
      zf.anchorFingerprint !== request.anchorFingerprint ||
      zf.attestationFingerprint !== request.attestationFingerprint ||
      zf.tokenFloorFingerprint !== floor.floorFingerprint ||
      zf.checkpointFingerprint !== canonicalJsonHash(request) ||
      zf.publicationKFingerprint !== precommit.publicationKFingerprint ||
      zf.publicationYFingerprint !== precommit.publicationYFingerprint ||
      zf.authorityEpochFingerprint !== precommit.authorityEpochFingerprint ||
      zf.precommitFingerprint !== precommit.precommitFingerprint ||
      zf.finalityFingerprint !== floor.floorFingerprint) {
    fail("Zf frozen relation");
  }
  for (const key of ["checkpointFingerprint", "publicationKFingerprint", "publicationYFingerprint", "authorityEpochFingerprint", "precommitFingerprint", "finalityFingerprint", "zFinalityFingerprint"]) if (!isHex64(zf[key])) fail(`${key} fingerprint`);
  if (hash(zf, "zFinalityFingerprint") !== zf.zFinalityFingerprint) fail("Zf fingerprint");
  return zf;
}

const receiptKeys = ["version", "kind", "genesisTxId", "generation", "requestedReaderMode", "readerInstanceId", "readerStartNonce", "readerProjectionFingerprint", "ackFingerprint", "finalityProofFingerprint", "phase", "receiptFingerprint"];
export function validateGenesisReceipt(receipt, request, zf, fp) {
  if (!exact(receipt, receiptKeys) || receipt.version !== 1 || receipt.kind !== "genesis-receipt" || receipt.phase !== "terminal") fail("genesis receipt schema");
  validateGenesisRequest(request);
  if (!plain(zf) || zf.kind !== "genesis-finality" || zf.genesisTxId !== request.genesisTxId ||
      zf.generation !== request.generation || !isHex64(zf.zFinalityFingerprint) ||
      hash(zf, "zFinalityFingerprint") !== zf.zFinalityFingerprint) fail("receipt Zf relation");
  if (receipt.genesisTxId !== request.genesisTxId || receipt.generation !== request.generation || receipt.requestedReaderMode !== request.requestedReaderMode || receipt.readerInstanceId !== request.readerInstanceId || receipt.readerStartNonce !== request.readerStartNonce) fail("receipt request relation");
  if (receipt.finalityProofFingerprint !== fp.finalityProofFingerprint || !isHex64(receipt.finalityProofFingerprint) || !isHex64(receipt.receiptFingerprint)) fail("receipt finality relation");
  const noReader = request.requestedReaderMode === "no-reader";
  if (noReader ? receipt.readerProjectionFingerprint !== null || receipt.ackFingerprint !== null :
      !isHex64(receipt.readerProjectionFingerprint) || !isHex64(receipt.ackFingerprint) ||
      receipt.readerProjectionFingerprint !== fp.readerProjectionFingerprint || receipt.ackFingerprint !== fp.ackFingerprint) fail("receipt reader branch");
  if (hash(receipt, "receiptFingerprint") !== receipt.receiptFingerprint) fail("receipt fingerprint");
  return receipt;
}

export const authorityRecordFingerprint = (record, field) => hash(record, field);

const authorityEpochKeys = ["version", "kind", "anchorFingerprint", "epoch", "reservationTxId", "commitTxId", "previousAuthorityCommitSnapshotFingerprint", "authorityEpochFingerprint"];
export function validateAuthorityEpoch(epoch) {
  if (!exact(epoch, authorityEpochKeys) || epoch.version !== 1 || epoch.kind !== "authority-epoch" || !isHex64(epoch.anchorFingerprint) || !Number.isSafeInteger(epoch.epoch) || epoch.epoch < 1 || !isOpaqueIdentity(epoch.reservationTxId) || !nullableText(epoch.commitTxId) || !nullableHex(epoch.previousAuthorityCommitSnapshotFingerprint) || !isHex64(epoch.authorityEpochFingerprint)) fail("authority epoch schema");
  if (hash(epoch, "authorityEpochFingerprint") !== epoch.authorityEpochFingerprint) fail("authority epoch fingerprint");
  return epoch;
}

const authorityReservationKeys = ["version", "kind", "anchorFingerprint", "txId", "epoch", "generation", "candidateFingerprint", "previousAuthorityCommitSnapshotFingerprint", "reservationFingerprint"];
export function validateAuthorityReservation(reservation) {
  if (!exact(reservation, authorityReservationKeys) || reservation.version !== 1 || reservation.kind !== "authority-reservation" || !isHex64(reservation.anchorFingerprint) || !isOpaqueIdentity(reservation.txId) || !Number.isSafeInteger(reservation.epoch) || reservation.epoch < 1 || !Number.isSafeInteger(reservation.generation) || reservation.generation < 1 || !isHex64(reservation.candidateFingerprint) || !nullableHex(reservation.previousAuthorityCommitSnapshotFingerprint) || !isHex64(reservation.reservationFingerprint)) fail("authority reservation schema");
  if (hash(reservation, "reservationFingerprint") !== reservation.reservationFingerprint) fail("authority reservation fingerprint");
  return reservation;
}

const authorityCommitKeys = ["version", "kind", "anchorFingerprint", "txId", "epoch", "generation", "candidateFingerprint", "reservationFingerprint", "previousAuthorityCommitSnapshotFingerprint", "authorityCommitSnapshotFingerprint"];
export function validateAuthorityCommitSnapshot(commit, reservation = null) {
  if (!exact(commit, authorityCommitKeys) || commit.version !== 1 || commit.kind !== "authority-commit-snapshot" || !isHex64(commit.anchorFingerprint) || !isOpaqueIdentity(commit.txId) || !Number.isSafeInteger(commit.epoch) || commit.epoch < 1 || !Number.isSafeInteger(commit.generation) || commit.generation < 1 || !isHex64(commit.candidateFingerprint) || !isHex64(commit.reservationFingerprint) || !nullableHex(commit.previousAuthorityCommitSnapshotFingerprint) || !isHex64(commit.authorityCommitSnapshotFingerprint)) fail("authority commit schema");
  if (reservation !== null) {
    validateAuthorityReservation(reservation);
    for (const key of ["anchorFingerprint", "txId", "epoch", "generation", "candidateFingerprint", "reservationFingerprint", "previousAuthorityCommitSnapshotFingerprint"]) if (commit[key] !== reservation[key]) fail("authority commit reservation relation");
  }
  if (hash(commit, "authorityCommitSnapshotFingerprint") !== commit.authorityCommitSnapshotFingerprint) fail("authority commit fingerprint");
  return commit;
}

const fenceKeys = ["version", "kind", "anchorFingerprint", "genesisTxId", "readerInstanceId", "readerStartNonce", "readerVersion", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint"];
export function validateFenceBinding(fence, commit, floor) {
  if (!exact(fence, fenceKeys) || fence.version !== 1 || fence.kind !== "reader-fence-binding" || !isHex64(fence.anchorFingerprint) || !isOpaqueIdentity(fence.genesisTxId) || !isOpaqueIdentity(fence.readerInstanceId) || !isOpaqueIdentity(fence.readerStartNonce) || fence.readerVersion !== 2 || !isHex64(fence.authorityCommitSnapshotFingerprint) || !isHex64(fence.fenceBindingFingerprint)) fail("fence schema");
  validateAuthorityCommitSnapshot(commit); validateReaderVersionFloor(floor);
  if (fence.anchorFingerprint !== commit.anchorFingerprint || fence.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint || floor.readerVersionFloor !== 2 || fence.readerInstanceId !== floor.firstReaderInstanceId || fence.readerStartNonce !== floor.firstReaderStartNonce) fail("fence relation");
  if (hash(fence, "fenceBindingFingerprint") !== fence.fenceBindingFingerprint) fail("fence fingerprint");
  return fence;
}

const leaseKeys = ["version", "kind", "anchorFingerprint", "genesisTxId", "readerInstanceId", "readerStartNonce", "readerVersion", "fenceBindingFingerprint", "leaseBindingFingerprint"];
export function validateLeaseBinding(lease, fence) {
  if (!exact(lease, leaseKeys) || lease.version !== 1 || lease.kind !== "reader-lease-binding" || !isHex64(lease.anchorFingerprint) || !isOpaqueIdentity(lease.genesisTxId) || !isOpaqueIdentity(lease.readerInstanceId) || !isOpaqueIdentity(lease.readerStartNonce) || lease.readerVersion !== 2 || !isHex64(lease.fenceBindingFingerprint) || !isHex64(lease.leaseBindingFingerprint)) fail("lease schema");
  if (!plain(fence) || fence.kind !== "reader-fence-binding" || !isHex64(fence.fenceBindingFingerprint) || hash(fence, "fenceBindingFingerprint") !== fence.fenceBindingFingerprint) fail("lease fence relation");
  if (lease.anchorFingerprint !== fence.anchorFingerprint || lease.genesisTxId !== fence.genesisTxId || lease.readerInstanceId !== fence.readerInstanceId || lease.readerStartNonce !== fence.readerStartNonce || lease.fenceBindingFingerprint !== fence.fenceBindingFingerprint) fail("lease relation");
  if (hash(lease, "leaseBindingFingerprint") !== lease.leaseBindingFingerprint) fail("lease fingerprint");
  return lease;
}

const baselineKeys = ["version", "kind", "anchorFingerprint", "genesisTxId", "idempotencyKey", "targetState", "generation", "tokenConfigHostSetFingerprint", ...readerRelationKeys, "baselineFingerprint"];
export function validateBaselineSnapshot(baseline, floor = null) {
  if (!exact(baseline, baselineKeys) || baseline.version !== 1 || baseline.kind !== "authority-baseline" || !isHex64(baseline.anchorFingerprint) || !isOpaqueIdentity(baseline.genesisTxId) || !isOpaqueIdentity(baseline.idempotencyKey) || !["prepared", "genesis-empty", "handshake-pending", "committed-no-reader", "committed-bound", "legacy-unmigrated", "managed-empty", "managed"].includes(baseline.targetState) || !Number.isSafeInteger(baseline.generation) || baseline.generation < 1 || !isHex64(baseline.tokenConfigHostSetFingerprint) || !isHex64(baseline.baselineFingerprint)) fail("baseline schema");
  const relations = Object.fromEntries(readerRelationKeys.map((key) => [key, baseline[key]]));
  if (baseline.targetState === "handshake-pending") {
    if (!isHex64(relations.attestationFingerprint) || !isHex64(relations.authorityReservationFingerprint) || !isHex64(relations.authorityCommitSnapshotFingerprint) || !isHex64(relations.fenceBindingFingerprint) || relations.leaseBindingFingerprint !== null || relations.readerProjectionFingerprint !== null || !isOpaqueIdentity(relations.readerInstanceId) || !isOpaqueIdentity(relations.readerStartNonce) || relations.readerVersion !== 2) fail("baseline pending reader relation");
    if (floor !== null && (validateReaderVersionFloor(floor).readerVersionFloor !== 2 || relations.readerInstanceId !== floor.firstReaderInstanceId || relations.readerStartNonce !== floor.firstReaderStartNonce)) fail("baseline pending floor relation");
  } else {
    validateReaderRelations(relations, floor);
  }
  if (Object.hasOwn(baseline, "yFingerprint")) fail("baseline must not reference Y");
  if (hash(baseline, "baselineFingerprint") !== baseline.baselineFingerprint) fail("baseline fingerprint");
  return baseline;
}

const genesisRequestKeys = ["version", "kind", "genesisTxId", "sequence", "anchorFingerprint", "ownerPrincipalFingerprint", "managementPrincipalFingerprint", "botPrincipalFingerprint", "recoveryPrincipalFingerprint", "targetPrincipalFingerprint", "managementProvisioningFingerprint", "botProvisioningFingerprint", "recoveryProvisioningFingerprint", "generation", "requestedReaderMode", "readerInstanceId", "readerStartNonce", "idempotencyKey", "targetInputState", "targetFingerprint", "targetIdentityFingerprint", "targetAclFingerprint", "legacyTargetProofFingerprint", "protectedInputFingerprint", "requestFingerprint"];
export function validateGenesisAuthorityRequest(request) {
  if (!exact(request, genesisRequestKeys) || request.version !== 1 || request.kind !== "genesis-authority-request" || !isOpaqueIdentity(request.genesisTxId) || request.sequence !== 1 || !Number.isSafeInteger(request.generation) || request.generation < 1 || !["no-reader", "handshake"].includes(request.requestedReaderMode) || !isOpaqueIdentity(request.idempotencyKey) || !["absent", "legacy-unmigrated"].includes(request.targetInputState)) fail("genesis authority request schema");
  for (const key of ["anchorFingerprint", "ownerPrincipalFingerprint", "managementPrincipalFingerprint", "botPrincipalFingerprint", "recoveryPrincipalFingerprint", "targetPrincipalFingerprint", "managementProvisioningFingerprint", "botProvisioningFingerprint", "recoveryProvisioningFingerprint", "protectedInputFingerprint", "requestFingerprint"]) if (!isHex64(request[key])) fail("genesis authority request fingerprint");
  if (new Set([request.managementPrincipalFingerprint, request.botPrincipalFingerprint, request.recoveryPrincipalFingerprint]).size !== 3 ||
      (request.requestedReaderMode === "no-reader" ? request.readerInstanceId !== null || request.readerStartNonce !== null : !isOpaqueIdentity(request.readerInstanceId) || !isOpaqueIdentity(request.readerStartNonce)) ||
      (request.targetInputState === "absent" ? [request.targetFingerprint, request.targetIdentityFingerprint, request.targetAclFingerprint, request.legacyTargetProofFingerprint].some((value) => value !== null) : ![request.targetFingerprint, request.targetIdentityFingerprint, request.targetAclFingerprint, request.legacyTargetProofFingerprint].every(isHex64)) ||
      hash(request, "requestFingerprint") !== request.requestFingerprint) fail("genesis authority request relation");
  return request;
}

const genesisReceiptAuthorityKeys = ["version", "kind", "genesisTxId", "requestFingerprint", "sequence", "anchorFingerprint", "generation", "readerVersionFloorFingerprint", "authorityCommitSnapshotFingerprint", "receiptFingerprint"];
export function validateGenesisAuthorityReceipt(receipt, request) {
  if (!exact(receipt, genesisReceiptAuthorityKeys) || receipt.version !== 1 || receipt.kind !== "genesis-authority-receipt" || !isOpaqueIdentity(receipt.genesisTxId) || receipt.sequence !== 2 || !Number.isSafeInteger(receipt.generation) || receipt.generation < 1) fail("genesis authority receipt schema");
  for (const key of ["requestFingerprint", "anchorFingerprint", "readerVersionFloorFingerprint", "authorityCommitSnapshotFingerprint", "receiptFingerprint"]) if (!isHex64(receipt[key])) fail("genesis authority receipt fingerprint");
  validateGenesisAuthorityRequest(request);
  if (receipt.genesisTxId !== request.genesisTxId || receipt.requestFingerprint !== request.requestFingerprint || receipt.anchorFingerprint !== request.anchorFingerprint || receipt.generation !== request.generation || hash(receipt, "receiptFingerprint") !== receipt.receiptFingerprint) fail("genesis authority receipt relation");
  return receipt;
}
