import { createHash } from "node:crypto";
import { validateAdmissionAckRecord, validateAdmissionGenesisBinding, validateAdmissionGrant, validateAdmissionRequest, validateAdmissionRecordPair, validateFinalityProof } from "./admission-envelope.js";
import { buildGenesisZeroGrantProofFingerprint, authorityRecordFingerprint, validateAttestedTokenFloorProof, validateAuthorityCommitSnapshot, validateAuthorityEpoch, validateAuthorityReservation, validateBaselineSnapshot, validateFenceBinding, validateGenesisAuthorityReceipt, validateGenesisAuthorityRequest, validateGenesisPrecommit, validateGenesisReceipt, validateGenesisRequest, validateLeaseBinding, validateReaderProjection, validateReaderRelations, validateReaderVersionFloor, validateTokenConfigAttestation, validateTokenFloor, validateTokenFloorReservation, validateZFinality } from "./genesis-envelope.js";
import { isOpaqueIdentity } from "./identity.js";
import { validateManagedChannelsV2, validateManagementEnvelope } from "./mapping-envelope.js";
import { validateManualCleanup } from "./recovery-envelope.js";
import { validatePublicationC, validatePublicationGraph as validateSharedPublicationGraph, validatePublicationK, validatePublicationP, validatePublicationQ, validatePublicationS, validatePublicationState, validatePublicationTransaction, validatePublicationU, validatePublicationY, validatePublicationZp } from "./publication-envelope.js";
import { canonicalJson, canonicalJsonHash, isHex64, parseCanonicalJsonBytes } from "./strict-json.js";
import { validateAuthoritySuccessorBundle, validateAuthoritySuccessorFinality, validateAuthoritySuccessorRequest, validateManagedHistoryMarkerSeal as validateSharedHistoryMarkerSeal } from "./successor-envelope.js";

export function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}
export function parseAuthorityBytes(bytes) {
  return parseCanonicalJsonBytes(bytes);
}

function validateCommittedLineage(attestation, floor, anchorFingerprint) {
  validateTokenConfigAttestation(attestation);
  validateTokenFloor(floor);
  if (floor.floorPhase !== "committed" ||
      attestation.anchorFingerprint !== anchorFingerprint ||
      floor.anchorFingerprint !== anchorFingerprint ||
      attestation.fenceGeneration !== floor.fenceGeneration ||
      floor.highestReservedGeneration !== attestation.tokenConfigGeneration ||
      floor.highestCommittedGeneration !== attestation.tokenConfigGeneration ||
      floor.lastReservationTxId !== attestation.txId ||
      floor.lastCommittedTxId !== attestation.txId ||
      floor.lastAttestationFingerprint !== attestation.attestationFingerprint) {
    throw new TypeError("committed token lineage");
  }
}
function validateTokenHistory(snapshot, anchorFingerprint, historicalAttestation, historicalFloor, currentAttestation, currentFloor) {
  const attestations = parseAuthorityBytes(snapshot.attestationHistoryBytes);
  const floors = parseAuthorityBytes(snapshot.tokenFloorHistoryBytes);
  if (!Array.isArray(attestations) || !Array.isArray(floors) || attestations.length === 0 || attestations.length !== floors.length) {
    throw new TypeError("token history schema");
  }
  const firstGeneration = attestations[0].tokenConfigGeneration;
  let previous = null;
  for (let index = 0; index < attestations.length; index += 1) {
    const attestation = attestations[index];
    const floor = floors[index];
    validateCommittedLineage(attestation, floor, anchorFingerprint);
    if (attestation.anchorFingerprint !== anchorFingerprint ||
        floor.anchorFingerprint !== anchorFingerprint ||
        floor.genesisGeneration !== 1 ||
        attestation.tokenConfigGeneration !== firstGeneration + index ||
        floor.highestCommittedGeneration !== attestation.tokenConfigGeneration ||
        floor.highestReservedGeneration !== attestation.tokenConfigGeneration ||
        (index === 0 && (attestation.tokenConfigGeneration !== 1 ||
          attestation.rotationKind !== "genesis" ||
          attestation.fenceGeneration !== 1 ||
          attestation.previousAttestationFingerprint !== null)) ||
        (index > 0 && (attestation.previousAttestationFingerprint !== previous.attestationFingerprint ||
          floor.highestCommittedGeneration !== floors[index - 1].highestCommittedGeneration + 1 ||
          (attestation.rotationKind === "same-key") !== (attestation.tokenConfigHostSetFingerprint === previous.tokenConfigHostSetFingerprint) ||
          (attestation.rotationKind === "host-set-change") !== (attestation.tokenConfigHostSetFingerprint !== previous.tokenConfigHostSetFingerprint)))) {
      throw new TypeError("token history lineage");
    }
    previous = attestation;
  }
  const historicalIndex = historicalAttestation === null ? null : historicalAttestation.tokenConfigGeneration - firstGeneration;
  if ((historicalAttestation !== null &&
       (attestations[historicalIndex]?.attestationFingerprint !== historicalAttestation.attestationFingerprint ||
        floors[historicalIndex]?.floorFingerprint !== historicalFloor.floorFingerprint)) ||
      previous.attestationFingerprint !== currentAttestation.attestationFingerprint ||
      floors.at(-1).floorFingerprint !== currentFloor.floorFingerprint) {
    throw new TypeError("token history snapshot binding");
  }
  return { attestations, floors };
}

function rejectTerminalAuthorityState(snapshot, anchorFingerprint) {
  if (snapshot.manualCleanupBytes !== undefined && snapshot.manualCleanupBytes !== null) {
    const cleanup = parseAuthorityBytes(snapshot.manualCleanupBytes);
    validateManualCleanup(cleanup);
    if (cleanup.anchorFingerprint !== anchorFingerprint) throw new TypeError("manual cleanup anchor");
    throw new TypeError("manual cleanup active");
  }
  if ((snapshot.terminalCloseBytes !== undefined && snapshot.terminalCloseBytes !== null) ||
      (snapshot.recoveryBytes !== undefined && snapshot.recoveryBytes !== null)) {
    throw new TypeError("terminal authority state active");
  }
}

export function validateBotPayload(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} schema`);
  canonicalJson(value);
  return value;
}
function fingerprintBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function validateHistoryMarker(marker, anchorFingerprint, expectedSequence = undefined) {
  if (!marker || Object.getPrototypeOf(marker) !== Object.prototype ||
      Object.keys(marker).sort().join(",") !== "anchorFingerprint,fenceGeneration,kind,markerFingerprint,previousMarkerFingerprint,sequence,version" ||
      marker.version !== 1 || marker.kind !== "managed-history-marker" ||
      !isHex64(marker.anchorFingerprint) ||
      !Number.isSafeInteger(marker.fenceGeneration) || marker.fenceGeneration < 1 ||
      !Number.isSafeInteger(marker.sequence) || marker.sequence < 1 ||
      (marker.sequence === 1 ? marker.previousMarkerFingerprint !== null : !isHex64(marker.previousMarkerFingerprint)) ||
      !isHex64(marker.markerFingerprint) ||
      marker.markerFingerprint !== canonicalJsonHash(Object.fromEntries(Object.entries(marker).filter(([key]) => key !== "markerFingerprint"))) ||
      marker.anchorFingerprint !== anchorFingerprint ||
      (expectedSequence !== undefined && marker.sequence !== expectedSequence)) {
    throw new TypeError("history marker proof");
  }
  return marker;
}
const AUTHORITY_EPOCH_FLOOR_KEYS = [
  "version", "kind", "anchorFingerprint", "genesisAuthorityEpoch",
  "highestReservedAuthorityEpoch", "highestCommittedAuthorityEpoch",
  "lastReservationTxId", "lastCommittedTxId", "floorFingerprint",
];
const FENCE_GENERATION_FLOOR_KEYS = [
  "version", "kind", "anchorFingerprint", "genesisFenceGeneration",
  "highestReservedFenceGeneration", "highestCommittedFenceGeneration",
  "lastReservationTxId", "lastCommittedTxId", "floorFingerprint",
];
export function validateAuthorityEpochFloor(floor, anchorFingerprint) {
  if (!floor || Object.getPrototypeOf(floor) !== Object.prototype ||
      Object.keys(floor).length !== AUTHORITY_EPOCH_FLOOR_KEYS.length ||
      !AUTHORITY_EPOCH_FLOOR_KEYS.every((key) => Object.hasOwn(floor, key)) ||
      floor.version !== 1 || floor.kind !== "authority-epoch-floor" ||
      !isHex64(floor.anchorFingerprint) || floor.genesisAuthorityEpoch !== 1 ||
      !Number.isSafeInteger(floor.highestReservedAuthorityEpoch) ||
      !Number.isSafeInteger(floor.highestCommittedAuthorityEpoch) ||
      floor.highestReservedAuthorityEpoch < 0 ||
      floor.highestCommittedAuthorityEpoch < 0 ||
      floor.highestCommittedAuthorityEpoch > floor.highestReservedAuthorityEpoch ||
      ![floor.lastReservationTxId, floor.lastCommittedTxId].every((value) => value === null || (typeof value === "string" && value.length > 0 && value.length <= 256)) ||
      !isHex64(floor.floorFingerprint) ||
      floor.floorFingerprint !== authorityRecordFingerprint(floor, "floorFingerprint") ||
      floor.anchorFingerprint !== anchorFingerprint ||
      (floor.highestReservedAuthorityEpoch < 1) !== (floor.lastReservationTxId === null) ||
      (floor.highestCommittedAuthorityEpoch < 1) !== (floor.lastCommittedTxId === null)) {
    throw new TypeError("authority epoch floor proof");
  }
  return floor;
}
export function validateFenceGenerationFloor(floor, anchorFingerprint) {
  if (!floor || Object.getPrototypeOf(floor) !== Object.prototype ||
      Object.keys(floor).length !== FENCE_GENERATION_FLOOR_KEYS.length ||
      !FENCE_GENERATION_FLOOR_KEYS.every((key) => Object.hasOwn(floor, key)) ||
      floor.version !== 1 || floor.kind !== "fence-generation-floor" ||
      !isHex64(floor.anchorFingerprint) || floor.genesisFenceGeneration !== 1 ||
      !Number.isSafeInteger(floor.highestReservedFenceGeneration) ||
      !Number.isSafeInteger(floor.highestCommittedFenceGeneration) ||
      floor.highestReservedFenceGeneration < 0 ||
      floor.highestCommittedFenceGeneration < 0 ||
      floor.highestCommittedFenceGeneration > floor.highestReservedFenceGeneration ||
      ![floor.lastReservationTxId, floor.lastCommittedTxId].every((value) => value === null || (typeof value === "string" && value.length > 0 && value.length <= 256)) ||
      !isHex64(floor.floorFingerprint) ||
      floor.floorFingerprint !== authorityRecordFingerprint(floor, "floorFingerprint") ||
      floor.anchorFingerprint !== anchorFingerprint ||
      (floor.highestReservedFenceGeneration < 1) !== (floor.lastReservationTxId === null) ||
      (floor.highestCommittedFenceGeneration < 1) !== (floor.lastCommittedTxId === null)) {
    throw new TypeError("fence generation floor proof");
  }
  return floor;
}
export function validatePublishedFloors({ authorityEpochFloor, fenceGenerationFloor, authorityEpoch, anchorFingerprint, request, head = null }) {
  validateAuthorityEpochFloor(authorityEpochFloor, anchorFingerprint);
  validateFenceGenerationFloor(fenceGenerationFloor, anchorFingerprint);
  validateAuthorityEpoch(authorityEpoch);
  if (authorityEpoch.anchorFingerprint !== anchorFingerprint) throw new TypeError("authority epoch floor anchor");
  const successor = head !== null;
  const terminal = !successor || head.phase === "terminal";
  const expectedEpoch = successor ? request.candidateAuthorityEpoch : authorityEpoch.epoch;
  const expectedFence = successor ? request.candidateFenceGeneration : request.fenceGeneration;
  if (authorityEpoch.epoch !== expectedEpoch ||
      authorityEpochFloor.highestReservedAuthorityEpoch !== expectedEpoch ||
      authorityEpochFloor.lastReservationTxId !== authorityEpoch.reservationTxId ||
      fenceGenerationFloor.highestReservedFenceGeneration !== expectedFence ||
      fenceGenerationFloor.lastReservationTxId !== (successor ? request.txId : request.genesisTxId)) {
    throw new TypeError("authority floor reservation binding");
  }
  const committedSuccessor = successor && ["reader-pending", "terminal"].includes(head.phase);
  const expectedCommittedEpoch = successor ? (committedSuccessor ? expectedEpoch : request.previousAuthorityEpoch) : expectedEpoch;
  const expectedCommittedFence = successor ? (committedSuccessor ? expectedFence : request.previousFenceGeneration) : expectedFence;
  if (authorityEpochFloor.highestCommittedAuthorityEpoch !== expectedCommittedEpoch ||
      fenceGenerationFloor.highestCommittedFenceGeneration !== expectedCommittedFence ||
      (committedSuccessor || !successor
        ? authorityEpochFloor.lastCommittedTxId !== authorityEpoch.commitTxId ||
          fenceGenerationFloor.lastCommittedTxId !== (successor ? request.txId : request.genesisTxId)
        : authorityEpochFloor.lastCommittedTxId === null ||
          fenceGenerationFloor.lastCommittedTxId === null)) {
    throw new TypeError("authority floor commit binding");
  }
}
export function validateHistoryMarkerSeal(marker, seal, anchorFingerprint, predecessors = []) {
  validateSharedHistoryMarkerSeal(marker, seal, anchorFingerprint, predecessors);
}
export function validateLiveSuccessorEvidence(bundle, evidence, expectedHostSetFingerprint) {
  const { request, head, finality, baseline } = bundle;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) ||
      !["managed-v1", "legacy-retained"].includes(evidence.sourceKind) ||
      !isBytes(evidence.headBytes) || !isBytes(evidence.finalityBytes) ||
      !isBytes(evidence.attestationBytes) || !isBytes(evidence.tokenFloorBytes) ||
      !isBytes(evidence.attestationHistoryBytes) || !isBytes(evidence.tokenFloorHistoryBytes) ||
      !isBytes(evidence.controlRootBytes) || !isBytes(evidence.wrapperBytes) || !isBytes(evidence.targetBytes) ||
      !isHex64(evidence.targetIdentity) || !isHex64(evidence.targetAclFingerprint) ||
      !isBytes(evidence.authorityEpochFloorBytes) || !isBytes(evidence.fenceGenerationFloorBytes) ||
      !isBytes(evidence.authorityEpochArchiveBytes) ||
      !isBytes(evidence.historyMarkerBytes) || !isBytes(evidence.historyMarkerSealBytes) ||
      !isBytes(evidence.historyMarkerPredecessorsBytes)) {
    throw new Error("SUCCESSOR_LIVE_PROOF_INVALID");
  }

  const liveHead = parseAuthorityBytes(evidence.headBytes);
  const liveFinality = parseAuthorityBytes(evidence.finalityBytes);
  validateAuthoritySuccessorBundle({ ...bundle, head: liveHead, finality: liveFinality });
  if (liveHead.headFingerprint !== head.headFingerprint ||
      liveFinality.finalityFingerprint !== finality.finalityFingerprint ||
      canonicalJson(liveFinality) !== canonicalJson(finality)) {
    throw new Error("SUCCESSOR_LIVE_FINALITY_STALE");
  }

  const attestation = parseAuthorityBytes(evidence.attestationBytes);
  const floor = parseAuthorityBytes(evidence.tokenFloorBytes);
  validateCommittedLineage(attestation, floor, request.anchorFingerprint);
  const authorityEpochFloor = parseAuthorityBytes(evidence.authorityEpochFloorBytes);
  const fenceGenerationFloor = parseAuthorityBytes(evidence.fenceGenerationFloorBytes);
  const authorityEpochArchive = parseAuthorityBytes(evidence.authorityEpochArchiveBytes);
  const historyMarkerPredecessors = parseAuthorityBytes(evidence.historyMarkerPredecessorsBytes);
  validateAuthorityEpoch(authorityEpochArchive, request, bundle.reservation, bundle.commit);
  if (canonicalJson(authorityEpochArchive) !== canonicalJson(bundle.authorityEpochArchive)) {
    throw new Error("SUCCESSOR_LIVE_EPOCH_ARCHIVE_STALE");
  }
  const liveHistoryMarker = parseAuthorityBytes(evidence.historyMarkerBytes);
  const historyMarkerSeal = parseAuthorityBytes(evidence.historyMarkerSealBytes);
  validatePublishedFloors({
    authorityEpochFloor,
    fenceGenerationFloor,
    authorityEpoch: bundle.authorityEpoch,
    anchorFingerprint: request.anchorFingerprint,
    request,
    head: liveHead,
  });
  validateHistoryMarkerSeal(liveHistoryMarker, historyMarkerSeal, request.anchorFingerprint, historyMarkerPredecessors);
  if (canonicalJson(historyMarkerPredecessors) !== canonicalJson(bundle.historyMarkerPredecessors)) {
    throw new Error("SUCCESSOR_LIVE_HISTORY_PREDECESSORS_STALE");
  }
  if (canonicalJson(liveHistoryMarker) !== canonicalJson(bundle.historyMarker) ||
      canonicalJson(historyMarkerSeal) !== canonicalJson(bundle.historyMarkerSeal)) {
    throw new Error("SUCCESSOR_LIVE_HISTORY_MARKER_STALE");
  }
  const { attestations, floors } = validateTokenHistory(
    evidence,
    request.anchorFingerprint,
    null,
    null,
    attestation,
    floor,
  );
  if (attestations.at(-1)?.attestationFingerprint !== attestation.attestationFingerprint ||
      floors.at(-1)?.floorFingerprint !== floor.floorFingerprint ||
      attestation.tokenConfigGeneration !== request.candidateTokenConfigGeneration ||
      attestation.tokenConfigGeneration !== finality.tokenConfigGeneration ||
      attestation.attestationFingerprint !== request.candidateAttestationFingerprint ||
      attestation.attestationFingerprint !== finality.attestationFingerprint ||
      floor.floorFingerprint !== finality.tokenFloorFingerprint ||
      baseline?.tokenConfigHostSetFingerprint !== attestation.tokenConfigHostSetFingerprint ||
      (expectedHostSetFingerprint !== null && attestation.tokenConfigHostSetFingerprint !== expectedHostSetFingerprint)) {
    throw new Error("SUCCESSOR_LIVE_TOKEN_LINEAGE_INVALID");
  }

  const controlRoot = parseAuthorityBytes(evidence.controlRootBytes);
  const wrapper = parseAuthorityBytes(evidence.wrapperBytes);
  const envelope = validateManagementEnvelope(controlRoot, wrapper, {
    targetBytes: evidence.targetBytes,
    targetIdentity: evidence.targetIdentity,
    targetAclFingerprint: evidence.targetAclFingerprint,
  });
  const expectedSourceKind = request.targetState === "legacy-retained" ? "legacy-retained" : "managed-v1";
  if (controlRoot.fenceGeneration !== request.candidateFenceGeneration ||
      wrapper.fenceGeneration !== request.candidateFenceGeneration) {
    throw new Error("SUCCESSOR_FENCE_PROOF_INVALID");
  }
  if (evidence.sourceKind === "managed-v1") {
    const target = parseAuthorityBytes(evidence.targetBytes);
    validateManagedChannelsV2(target);
    if (target.fenceGeneration !== request.candidateFenceGeneration) {
      throw new Error("SUCCESSOR_LIVE_TARGET_FENCE_INVALID");
    }
  }
  if (!envelope.ok || envelope.sourceKind !== evidence.sourceKind || evidence.sourceKind !== expectedSourceKind ||
      fingerprintBytes(evidence.targetBytes) !== finality.targetFingerprint ||
      evidence.targetIdentity !== finality.targetIdentityFingerprint ||
      evidence.targetAclFingerprint !== finality.targetAclFingerprint ||
      wrapper.wrapperFingerprint !== finality.wrapperFingerprint ||
      controlRoot.controlRootFingerprint !== finality.controlRootFingerprint) {
    throw new Error("SUCCESSOR_LIVE_TARGET_PROOF_INVALID");
  }
}
function validatePublicationGraph({
  snapshot,
  controlRoot,
  wrapper,
  target,
  baseline,
  request,
  authorityReservation,
  authorityCommit,
  authorityEpoch,
}) {
  const transaction = parseAuthorityBytes(snapshot.publicationTransactionBytes);
  const u = parseAuthorityBytes(snapshot.publicationUBytes);
  const p = parseAuthorityBytes(snapshot.publicationPBytes);
  const s = parseAuthorityBytes(snapshot.publicationSBytes);
  const prepared = parseAuthorityBytes(snapshot.publicationPreparedBytes);
  const replaced = parseAuthorityBytes(snapshot.publicationReplacedBytes);
  const committed = parseAuthorityBytes(snapshot.publicationCommittedBytes);
  const c = parseAuthorityBytes(snapshot.publicationCBytes);
  const q = parseAuthorityBytes(snapshot.publicationQBytes);
  const zp = parseAuthorityBytes(snapshot.publicationZpBytes);
  const k = parseAuthorityBytes(snapshot.publicationKBytes);
  const y = parseAuthorityBytes(snapshot.publicationYBytes);

  validatePublicationTransaction(transaction, baseline.baselineFingerprint);
  validatePublicationU(u, baseline.baselineFingerprint);
  const targetFingerprint = fingerprintBytes(snapshot.targetBytes);
  let canonicalMappingFingerprint;
  if (controlRoot.sourceKind === "legacy-retained") {
    if (!isHex64(snapshot.targetIdentity) || !isHex64(snapshot.targetAclFingerprint)) {
      throw new TypeError("legacy-retained canonical mapping tuple");
    }
    canonicalMappingFingerprint = canonicalJsonHash({
      sourceKind: "legacy-retained",
      targetFingerprint,
      identityFingerprint: snapshot.targetIdentity,
      aclFingerprint: snapshot.targetAclFingerprint,
    });
  } else {
    canonicalMappingFingerprint = canonicalJsonHash(target === null
      ? { mappingGeneration: 0, mappings: {}, routes: {} }
      : { mappingGeneration: target.mappingGeneration, mappings: target.mappings, routes: target.routes });
  }
  const stateFingerprint = canonicalJsonHash({
    targetState: baseline.targetState,
    targetFingerprint,
    targetIdentityFingerprint: snapshot.targetIdentity,
    targetAclFingerprint: snapshot.targetAclFingerprint,
    canonicalMappingFingerprint,
  });
  const payloadFingerprint = canonicalJsonHash({
    targetFingerprint,
    targetIdentityFingerprint: snapshot.targetIdentity,
    targetAclFingerprint: snapshot.targetAclFingerprint,
    wrapperFingerprint: wrapper.wrapperFingerprint,
    controlRootFingerprint: controlRoot.controlRootFingerprint,
    canonicalMappingFingerprint,
  });
  const snapshotFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, targetFingerprint });
  const publicationFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, snapshotFingerprint, targetFingerprint });
  const checkpointFingerprint = canonicalJsonHash({
    genesisTxId: request.genesisTxId,
    generation: request.generation,
    publicationFingerprint,
    targetFingerprint,
  });

  validatePublicationP(p, u, stateFingerprint);
  validatePublicationS(s, p, { stateFingerprint, payloadFingerprint });
  validatePublicationC(c, s, { stateFingerprint, payloadFingerprint, snapshotFingerprint });
  validatePublicationQ(q, c, { stateFingerprint, payloadFingerprint, snapshotFingerprint });
  validatePublicationZp(zp, q, { stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint });
  validatePublicationK(k, zp, { publicationFingerprint, checkpointFingerprint });
  validatePublicationY(y, k, targetFingerprint, publicationFingerprint);
  for (const phase of [prepared, replaced, committed]) {
    validatePublicationState(phase, transaction);
    if (phase.publicationFingerprint !== publicationFingerprint) throw new TypeError("publication phase projection");
  }
  if ([u, p, s, prepared, replaced, committed, c, q, zp, k, y].some((record) =>
    record.txId !== transaction.txId ||
    record.genesisTxId !== transaction.genesisTxId ||
    record.generation !== transaction.generation ||
    record.fenceGeneration !== transaction.fenceGeneration
  )) throw new TypeError("publication transaction branch");
  if (prepared.phase !== "prepared" || replaced.phase !== "replaced" || committed.phase !== "committed" ||
      transaction.txId !== request.genesisTxId || transaction.genesisTxId !== request.genesisTxId ||
      transaction.generation !== request.generation ||
      transaction.fenceGeneration !== request.fenceGeneration ||
      u.txId !== transaction.txId || u.genesisTxId !== transaction.genesisTxId || u.generation !== transaction.generation ||
      u.anchorFingerprint !== baseline.anchorFingerprint || u.targetState !== baseline.targetState ||
      u.attestationFingerprint !== baseline.attestationFingerprint ||
      u.authorityReservationFingerprint !== baseline.authorityReservationFingerprint ||
      u.authorityCommitSnapshotFingerprint !== baseline.authorityCommitSnapshotFingerprint ||
      u.fenceBindingFingerprint !== baseline.fenceBindingFingerprint ||
      u.leaseBindingFingerprint !== baseline.leaseBindingFingerprint ||
      u.readerProjectionFingerprint !== baseline.readerProjectionFingerprint ||
      u.readerInstanceId !== baseline.readerInstanceId || u.readerStartNonce !== baseline.readerStartNonce ||
      u.readerVersion !== baseline.readerVersion ||
      authorityReservation.txId !== transaction.txId || authorityCommit.txId !== transaction.txId ||
      authorityReservation.generation !== transaction.generation || authorityCommit.generation !== transaction.generation ||
      authorityReservation.epoch !== authorityCommit.epoch || authorityEpoch.epoch !== authorityCommit.epoch ||
      authorityEpoch.reservationTxId !== transaction.txId || authorityEpoch.commitTxId !== transaction.txId) {
    throw new TypeError("publication graph binding");
  }
  return { transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y };
}
export function validateSuccessorPublicationEvidence({ snapshot, bundle }) {
  const { request, baseline, commit, reservation, authorityEpoch, readerFloor, finality, head } = bundle;
  const publication = isBytes(bundle.publicationGraph)
    ? parseAuthorityBytes(bundle.publicationGraph)
    : bundle.publicationGraph;
  if (!publication || typeof publication !== "object" || Array.isArray(publication)) {
    throw new TypeError("successor publication graph absent");
  }
  validateSharedPublicationGraph(publication);
  validateAuthoritySuccessorRequest(request);
  validateAuthorityReservation(reservation, request);
  validateAuthorityCommitSnapshot(commit, reservation, request);
  validateAuthorityEpoch(authorityEpoch, request, reservation, commit);
  validateAuthoritySuccessorFinality(finality, request, baseline, reservation, commit, authorityEpoch);
  if (!isBytes(snapshot.authorityEpochFloorBytes) || !isBytes(snapshot.fenceGenerationFloorBytes)) {
    throw new TypeError("successor authority floor absent");
  }
  const authorityEpochFloor = parseAuthorityBytes(snapshot.authorityEpochFloorBytes);
  const fenceGenerationFloor = parseAuthorityBytes(snapshot.fenceGenerationFloorBytes);
  validatePublishedFloors({
    authorityEpochFloor,
    fenceGenerationFloor,
    authorityEpoch,
    anchorFingerprint: request.anchorFingerprint,
    request,
    head,
  });
  validateReaderVersionFloor(readerFloor);
  if ((readerFloor.readerVersionFloor === 2) !== (request.readerMode === "bound-reader")) {
    throw new TypeError("successor reader floor");
  }
  if (!isBytes(snapshot.authorityEpochArchiveBytes)) throw new TypeError("successor authority epoch archive absent");
  const authorityEpochArchive = parseAuthorityBytes(snapshot.authorityEpochArchiveBytes);
  validateAuthorityEpoch(authorityEpochArchive, request, reservation, commit);
  if (canonicalJson(authorityEpochArchive) !== canonicalJson(bundle.authorityEpochArchive)) {
    throw new TypeError("successor authority epoch archive substitution");
  }
  if (!isBytes(snapshot.historyMarkerBytes)) throw new TypeError("successor history marker absent");
  if (!isBytes(snapshot.historyMarkerSealBytes)) throw new TypeError("successor history marker seal absent");
  if (!isBytes(snapshot.historyMarkerPredecessorsBytes)) throw new TypeError("successor history marker predecessors absent");
  const historyMarker = parseAuthorityBytes(snapshot.historyMarkerBytes);
  const historyMarkerSeal = parseAuthorityBytes(snapshot.historyMarkerSealBytes);
  const historyMarkerPredecessors = parseAuthorityBytes(snapshot.historyMarkerPredecessorsBytes);
  validateHistoryMarker(historyMarker, request.anchorFingerprint, head.phase === "terminal" ? request.sequence : request.sequence - 1);
  validateHistoryMarkerSeal(historyMarker, historyMarkerSeal, request.anchorFingerprint, historyMarkerPredecessors);
  if (!bundle.historyMarker || canonicalJson(bundle.historyMarker) !== canonicalJson(historyMarker)) {
    throw new TypeError("successor history marker substitution");
  }
  if (!bundle.historyMarkerSeal || canonicalJson(bundle.historyMarkerSeal) !== canonicalJson(historyMarkerSeal)) {
    throw new TypeError("successor history marker seal substitution");
  }
  if (!bundle.historyMarkerPredecessors ||
      canonicalJson(bundle.historyMarkerPredecessors) !== canonicalJson(historyMarkerPredecessors)) {
    throw new TypeError("successor history marker predecessor substitution");
  }
  if (head.phase === "terminal" && request.readerMode === "bound-reader" && (!bundle.lease || !bundle.projection || !bundle.ack)) {
    throw new TypeError("successor bound-reader proof absent");
  }
  const controlRoot = parseAuthorityBytes(snapshot.controlRootBytes);
  const wrapper = parseAuthorityBytes(snapshot.wrapperBytes);
  const targetBytes = snapshot.targetBytes;
  const targetIdentity = snapshot.targetIdentity;
  const targetAclFingerprint = snapshot.targetAclFingerprint;
  const envelope = validateManagementEnvelope(controlRoot, wrapper, {
    targetBytes,
    targetIdentity,
    targetAclFingerprint,
  });
  if (!envelope.ok) throw new TypeError("successor management envelope");
  if (controlRoot.fenceGeneration !== request.candidateFenceGeneration ||
      wrapper.fenceGeneration !== request.candidateFenceGeneration) {
    throw new TypeError("successor envelope fence");
  }
  if (controlRoot.readerVersionFloorFingerprint !== readerFloor.floorFingerprint ||
      controlRoot.anchorFingerprint !== readerFloor.anchorFingerprint ||
      readerFloor.anchorFingerprint !== request.anchorFingerprint) {
    throw new TypeError("successor control-root reader-floor binding");
  }
  const expectedSourceKind = request.targetState === "legacy-retained" ? "legacy-retained" : "managed-v1";
  if (envelope.sourceKind !== expectedSourceKind) throw new TypeError("successor source kind");
  const target = expectedSourceKind === "managed-v1" ? parseAuthorityBytes(targetBytes) : null;
  if (target !== null) validateManagedChannelsV2(target);
  if (target !== null && target.fenceGeneration !== request.candidateFenceGeneration) {
    throw new TypeError("successor target fence");
  }
  const targetFingerprint = fingerprintBytes(targetBytes);
  const canonicalMappingFingerprint = target === null
    ? canonicalJsonHash({
      sourceKind: "legacy-retained",
      targetFingerprint,
      identityFingerprint: targetIdentity,
      aclFingerprint: targetAclFingerprint,
    })
    : canonicalJsonHash({
      mappingGeneration: target.mappingGeneration,
      mappings: target.mappings,
      routes: target.routes,
    });
  const stateFingerprint = canonicalJsonHash({
    targetState: baseline.targetState,
    targetFingerprint,
    targetIdentityFingerprint: targetIdentity,
    targetAclFingerprint,
    canonicalMappingFingerprint,
  });
  const payloadFingerprint = canonicalJsonHash({
    targetFingerprint,
    targetIdentityFingerprint: targetIdentity,
    targetAclFingerprint,
    wrapperFingerprint: wrapper.wrapperFingerprint,
    controlRootFingerprint: controlRoot.controlRootFingerprint,
    canonicalMappingFingerprint,
  });
  const snapshotFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, targetFingerprint });
  const publicationFingerprint = canonicalJsonHash({
    stateFingerprint,
    payloadFingerprint,
    snapshotFingerprint,
    targetFingerprint,
  });
  const checkpointFingerprint = canonicalJsonHash({
    genesisTxId: request.rootGenesisTxId,
    generation: request.candidateTokenConfigGeneration,
    publicationFingerprint,
    targetFingerprint,
  });
  const {
    transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y,
  } = publication;
  const expectedTxId = request.txId;
  const expectedGenesisTxId = request.rootGenesisTxId;
  const expectedGeneration = request.candidateTokenConfigGeneration;
  validatePublicationTransaction(transaction, baseline.baselineFingerprint);
  validatePublicationU(u, baseline.baselineFingerprint);
  validatePublicationP(p, u, stateFingerprint);
  validatePublicationS(s, p, { stateFingerprint, payloadFingerprint });
  validatePublicationC(c, s, { stateFingerprint, payloadFingerprint, snapshotFingerprint });
  validatePublicationQ(q, c, { stateFingerprint, payloadFingerprint, snapshotFingerprint });
  validatePublicationZp(zp, q, { stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint });
  validatePublicationK(k, zp, { publicationFingerprint, checkpointFingerprint });
  validatePublicationY(y, k, targetFingerprint, publicationFingerprint);
  for (const phase of [prepared, replaced, committed]) {
    validatePublicationState(phase, transaction);
    if (phase.publicationFingerprint !== publicationFingerprint) throw new TypeError("successor publication phase");
  }
  if ([u, p, s, prepared, replaced, committed, c, q, zp, k, y].some((record) =>
    record.txId !== expectedTxId ||
    record.genesisTxId !== expectedGenesisTxId ||
    record.generation !== expectedGeneration ||
    record.fenceGeneration !== request.candidateFenceGeneration
  )) throw new TypeError("successor publication transaction");
  if (prepared.phase !== "prepared" || replaced.phase !== "replaced" || committed.phase !== "committed" ||
      transaction.fenceGeneration !== request.candidateFenceGeneration ||
      u.anchorFingerprint !== baseline.anchorFingerprint || u.targetState !== baseline.targetState ||
      u.attestationFingerprint !== baseline.attestationFingerprint ||
      u.authorityReservationFingerprint !== baseline.authorityReservationFingerprint ||
      u.authorityCommitSnapshotFingerprint !== baseline.authorityCommitSnapshotFingerprint ||
      u.fenceBindingFingerprint !== baseline.fenceBindingFingerprint ||
      u.leaseBindingFingerprint !== baseline.leaseBindingFingerprint ||
      u.readerProjectionFingerprint !== baseline.readerProjectionFingerprint ||
      u.readerInstanceId !== baseline.readerInstanceId || u.readerStartNonce !== baseline.readerStartNonce ||
      u.readerVersion !== baseline.readerVersion ||
      reservation.txId !== expectedTxId || commit.txId !== expectedTxId ||
      reservation.anchorFingerprint !== request.anchorFingerprint ||
      commit.anchorFingerprint !== request.anchorFingerprint ||
      authorityEpoch.anchorFingerprint !== request.anchorFingerprint ||
      reservation.generation !== expectedGeneration || commit.generation !== expectedGeneration ||
      reservation.epoch !== commit.epoch || authorityEpoch.epoch !== commit.epoch ||
      authorityEpoch.reservationTxId !== expectedTxId || authorityEpoch.commitTxId !== expectedTxId ||
      baseline.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint ||
      baseline.candidateTargetFingerprint !== targetFingerprint ||
      (target !== null && (
        target.targetState !== baseline.targetState ||
        target.mappingGeneration !== baseline.mappingGeneration ||
        target.tokenConfigGeneration !== baseline.tokenConfigGeneration ||
        target.tokenConfigHostSetFingerprint !== baseline.tokenConfigHostSetFingerprint
      ))) {
    throw new TypeError("successor publication binding");
  }
  if (k["publication-kFingerprint"] !== head.publicationKFingerprint ||
      y["publication-yFingerprint"] !== head.publicationYFingerprint ||
      finality.publicationKFingerprint !== k["publication-kFingerprint"] ||
      finality.publicationYFingerprint !== y["publication-yFingerprint"] ||
      finality.targetFingerprint !== targetFingerprint ||
      finality.targetIdentityFingerprint !== targetIdentity ||
      finality.targetAclFingerprint !== targetAclFingerprint ||
      finality.wrapperFingerprint !== wrapper.wrapperFingerprint ||
      finality.controlRootFingerprint !== controlRoot.controlRootFingerprint ||
      finality.snapshotFingerprint !== snapshotFingerprint ||
      head.finalityFingerprint !== finality.finalityFingerprint) {
    throw new TypeError("successor publication finality");
  }
  return publication;
}
export function validateManagedProof(snapshot, expectedHostSetFingerprint = null) {
  const controlRoot = parseAuthorityBytes(snapshot.controlRootBytes);
  const wrapper = parseAuthorityBytes(snapshot.wrapperBytes);
  const attestation = parseAuthorityBytes(snapshot.attestationBytes);
  const tokenFloor = parseAuthorityBytes(snapshot.tokenFloorBytes);
  const currentAttestation = parseAuthorityBytes(snapshot.currentAttestationBytes);
  const currentTokenFloor = parseAuthorityBytes(snapshot.currentTokenFloorBytes);
  const reservation = parseAuthorityBytes(snapshot.tokenFloorReservationBytes);
  const request = parseAuthorityBytes(snapshot.genesisRequestBytes);
  const zFinality = parseAuthorityBytes(snapshot.zFinalityBytes);
  const proof = parseAuthorityBytes(snapshot.rvfBytes);
  const receipt = parseAuthorityBytes(snapshot.receiptBytes);
  const readerFloor = parseAuthorityBytes(snapshot.readerVersionFloorBytes);
  const authorityEpochFloor = parseAuthorityBytes(snapshot.authorityEpochFloorBytes);
  const fenceGenerationFloor = parseAuthorityBytes(snapshot.fenceGenerationFloorBytes);
  const historyMarker = parseAuthorityBytes(snapshot.historyMarkerBytes);
  const historyMarkerSeal = parseAuthorityBytes(snapshot.historyMarkerSealBytes);
  const historyMarkerPredecessors = snapshot.historyMarkerPredecessorsBytes === undefined
    ? []
    : parseAuthorityBytes(snapshot.historyMarkerPredecessorsBytes);
  validateHistoryMarker(historyMarker, request.anchorFingerprint, 1);
  validateHistoryMarkerSeal(historyMarker, historyMarkerSeal, request.anchorFingerprint, historyMarkerPredecessors);
  const attestedProof = parseAuthorityBytes(snapshot.attestedProofBytes);
  const precommit = parseAuthorityBytes(snapshot.precommitBytes);
  const recovery = snapshot.recoveryBytes === undefined ? null : parseAuthorityBytes(snapshot.recoveryBytes);
  const authorityRequest = parseAuthorityBytes(snapshot.authorityRequestBytes);
  const authorityReceipt = parseAuthorityBytes(snapshot.authorityReceiptBytes);
  const authorityReservation = parseAuthorityBytes(snapshot.authorityReservationBytes);
  const authorityCommit = parseAuthorityBytes(snapshot.authorityCommitBytes);
  const authorityBaseline = parseAuthorityBytes(snapshot.authorityBaselineBytes);
  const authorityEpoch = parseAuthorityBytes(snapshot.authorityEpochBytes);
  if (!isBytes(snapshot.authorityEpochArchiveBytes)) throw new TypeError("authority epoch archive absent");
  const authorityEpochArchive = parseAuthorityBytes(snapshot.authorityEpochArchiveBytes);
  validatePublishedFloors({
    authorityEpochFloor,
    fenceGenerationFloor,
    authorityEpoch,
    anchorFingerprint: request.anchorFingerprint,
    request,
  });
  const publicationK = parseAuthorityBytes(snapshot.publicationKBytes);
  const publicationY = parseAuthorityBytes(snapshot.publicationYBytes);

  const envelope = validateManagementEnvelope(controlRoot, wrapper, {
    targetBytes: snapshot.targetBytes,
    targetIdentity: snapshot.targetIdentity,
    targetAclFingerprint: snapshot.targetAclFingerprint,
  });
  if (!envelope.ok) throw new TypeError("management envelope");
  rejectTerminalAuthorityState(snapshot, controlRoot.anchorFingerprint);
  const managedTarget = envelope.sourceKind === "managed-v1" ? parseAuthorityBytes(snapshot.targetBytes) : null;
  if (controlRoot.fenceGeneration !== request.fenceGeneration ||
      wrapper.fenceGeneration !== request.fenceGeneration ||
      (managedTarget !== null && managedTarget.fenceGeneration !== request.fenceGeneration)) {
    throw new TypeError("genesis fence proof");
  }
  validateReaderVersionFloor(readerFloor);
  if ((readerFloor.readerVersionFloor === 2) !== (request.requestedReaderMode === "handshake")) {
    throw new TypeError("genesis reader floor branch");
  }
  if (controlRoot.readerVersionFloorFingerprint !== readerFloor.floorFingerprint ||
      controlRoot.anchorFingerprint !== readerFloor.anchorFingerprint) throw new TypeError("control-root reader-floor binding");

  validateTokenConfigAttestation(attestation);
  validateTokenFloor(tokenFloor);
  validateTokenConfigAttestation(currentAttestation);
  validateTokenFloor(currentTokenFloor);
  validateGenesisRequest(request);
  validateTokenFloorReservation(reservation);
  validateAttestedTokenFloorProof(attestedProof, reservation, attestation);
  validateGenesisPrecommit(precommit);
  validateGenesisAuthorityRequest(authorityRequest);
  validateAuthorityReservation(authorityReservation);
  validateAuthorityCommitSnapshot(authorityCommit, authorityReservation);
  validateAuthorityEpoch(authorityEpoch);
  validateAuthorityEpoch(authorityEpochArchive);
  if (canonicalJson(authorityEpochArchive) !== canonicalJson(authorityEpoch) ||
      authorityReservation.txId !== request.genesisTxId ||
      authorityReservation.generation !== request.generation ||
      authorityReservation.anchorFingerprint !== request.anchorFingerprint ||
      authorityReservation.candidateFingerprint !== request.requestFingerprint ||
      authorityCommit.txId !== request.genesisTxId ||
      authorityCommit.generation !== request.generation ||
      authorityCommit.anchorFingerprint !== request.anchorFingerprint ||
      authorityCommit.candidateFingerprint !== request.requestFingerprint ||
      authorityReservation.epoch !== authorityEpoch.epoch ||
      authorityCommit.epoch !== authorityEpoch.epoch ||
      authorityEpoch.reservationTxId !== request.genesisTxId ||
      authorityEpoch.commitTxId !== request.genesisTxId) {
    throw new TypeError("authority finality graph binding");
  }
  validateBaselineSnapshot(authorityBaseline);
  validateGenesisAuthorityReceipt(authorityReceipt, authorityRequest);
  const graph = validatePublicationGraph({
    snapshot,
    controlRoot,
    wrapper,
    target: managedTarget,
    baseline: authorityBaseline,
    request,
    authorityReservation,
    authorityCommit,
    authorityEpoch,
  });
  if (publicationK["publication-kFingerprint"] !== graph.k["publication-kFingerprint"] ||
      publicationY["publication-yFingerprint"] !== graph.y["publication-yFingerprint"]) {
    throw new TypeError("publication graph substitution");
  }
  if (precommit.targetFingerprint !== fingerprintBytes(snapshot.targetBytes) ||
      precommit.targetIdentityFingerprint !== snapshot.targetIdentity ||
      precommit.targetAclFingerprint !== snapshot.targetAclFingerprint ||
      precommit.controlRootFingerprint !== controlRoot.controlRootFingerprint ||
      precommit.wrapperFingerprint !== wrapper.wrapperFingerprint ||
      authorityReservation.anchorFingerprint !== request.anchorFingerprint ||
      authorityCommit.anchorFingerprint !== request.anchorFingerprint ||
      authorityBaseline.anchorFingerprint !== request.anchorFingerprint ||
      authorityEpoch.anchorFingerprint !== request.anchorFingerprint ||
      authorityReservation.candidateFingerprint !== request.requestFingerprint ||
      authorityCommit.candidateFingerprint !== request.requestFingerprint ||
      authorityBaseline.generation !== request.generation ||
      authorityEpoch.epoch !== authorityCommit.epoch ||
      authorityEpoch.reservationTxId !== request.genesisTxId ||
      authorityEpoch.commitTxId !== request.genesisTxId) {
    throw new TypeError("authority snapshot evidence binding");
  }
  validateZFinality(zFinality, request, tokenFloor, precommit);
  if (authorityRequest.genesisTxId !== request.genesisTxId || authorityRequest.generation !== request.generation ||
      authorityReservation.txId !== request.genesisTxId || authorityCommit.txId !== request.genesisTxId ||
      authorityBaseline.genesisTxId !== request.genesisTxId || authorityEpoch.commitTxId !== request.genesisTxId ||
      authorityReceipt.authorityCommitSnapshotFingerprint !== authorityCommit.authorityCommitSnapshotFingerprint ||
      authorityReceipt.readerVersionFloorFingerprint !== readerFloor.floorFingerprint ||
      precommit.reservationFingerprint !== reservation.floorFingerprint ||
      precommit.attestedProofFingerprint !== attestedProof.attestedProofFingerprint ||
      precommit.zeroGrantProofFingerprint !== buildGenesisZeroGrantProofFingerprint({
        genesisTxId: request.genesisTxId,
        admissionArchiveIds: precommit.admissionArchiveIds,
      }) ||
      precommit.authorityReservationFingerprint !== authorityReservation.reservationFingerprint ||
      precommit.authorityCommitSnapshotFingerprint !== authorityCommit.authorityCommitSnapshotFingerprint ||
      precommit.publicationKFingerprint !== publicationK["publication-kFingerprint"] ||
      precommit.publicationYFingerprint !== publicationY["publication-yFingerprint"] ||
      precommit.authorityEpochFingerprint !== authorityEpoch.authorityEpochFingerprint) {
    throw new TypeError("authority graph relation");
  }

  if (controlRoot.anchorFingerprint !== request.anchorFingerprint ||
      attestation.anchorFingerprint !== request.anchorFingerprint ||
      attestation.tokenConfigGeneration !== request.generation ||
      attestation.attestationFingerprint !== request.attestationFingerprint ||
      reservation.anchorFingerprint !== request.anchorFingerprint ||
      reservation.lastReservationTxId !== request.genesisTxId ||
      reservation.highestReservedGeneration !== request.generation ||
      reservation.floorFingerprint !== request.tokenFloorFingerprint) throw new TypeError("historical proof relation");
  validateCommittedLineage(attestation, tokenFloor, request.anchorFingerprint);
  validateCommittedLineage(currentAttestation, currentTokenFloor, request.anchorFingerprint);
  if (currentAttestation.tokenConfigGeneration !== request.generation ||
      currentTokenFloor.highestCommittedGeneration !== request.generation) {
    throw new TypeError("stale reader or admission proof generation");
  }
  validateTokenHistory(snapshot, request.anchorFingerprint, attestation, tokenFloor, currentAttestation, currentTokenFloor);
  if (expectedHostSetFingerprint !== null && currentAttestation.tokenConfigHostSetFingerprint !== expectedHostSetFingerprint) {
    throw new TypeError("token host-set fingerprint mismatch");
  }

  if (envelope.sourceKind === "managed-v1") {
    const target = managedTarget;
    if (target === null || typeof target !== "object" || Array.isArray(target)) throw new TypeError("target schema");
    validateManagedChannelsV2(target);
    if (wrapper.semanticStateFingerprint !== target.configFingerprint ||
        wrapper.targetState !== target.targetState ||
        wrapper.readerVersion !== (request.requestedReaderMode === "handshake" ? 2 : null) ||
        target.tokenConfigGeneration !== currentAttestation.tokenConfigGeneration ||
        target.tokenConfigHostSetFingerprint !== currentAttestation.tokenConfigHostSetFingerprint) {
      throw new TypeError("managed target binding");
    }
  }

  let admissionRequest = null;
  let admissionGrant = null;
  let fenceBinding = null;
  let readerLease = null;
  let projection = null;
  let readerState = null;
  let ack = null;
  let admissionRequestArchive = null;
  let admissionGrantArchive = null;
  let acknowledgementArchive = null;
  if (request.requestedReaderMode === "no-reader") {
    if (snapshot.readerProjectionBytes !== undefined || snapshot.readerStateBytes !== undefined ||
        snapshot.admissionAckBytes !== undefined || snapshot.admissionAckArchiveBytes !== undefined ||
        snapshot.fenceBindingBytes !== undefined || snapshot.readerLeaseBytes !== undefined) {
      throw new TypeError("no-reader proof branch");
    }
    if (snapshot.admissionRequestBytes !== undefined || snapshot.admissionGrantBytes !== undefined ||
        snapshot.admissionRequestArchiveBytes !== undefined || snapshot.admissionGrantArchiveBytes !== undefined) throw new TypeError("no-reader admission branch");
    if (recovery?.readerHandshake !== undefined && recovery.readerHandshake !== null) throw new TypeError("no-reader admission state branch");
    validateFinalityProof(proof, request, zFinality);
  } else {
    if (!isBytes(snapshot.readerStateBytes) ||
        !isBytes(snapshot.admissionRequestArchiveBytes) ||
        !isBytes(snapshot.admissionGrantArchiveBytes) ||
        !isBytes(snapshot.admissionAckArchiveBytes)) throw new TypeError("bound-reader state or admission archive bytes");
    admissionRequest = parseAuthorityBytes(snapshot.admissionRequestBytes);
    admissionGrant = parseAuthorityBytes(snapshot.admissionGrantBytes);
    admissionRequestArchive = parseAuthorityBytes(snapshot.admissionRequestArchiveBytes);
    admissionGrantArchive = parseAuthorityBytes(snapshot.admissionGrantArchiveBytes);
    acknowledgementArchive = parseAuthorityBytes(snapshot.admissionAckArchiveBytes);
    validateAdmissionRequest(admissionRequest);
    validateAdmissionGrant(admissionGrant, admissionRequest);
    validateAdmissionRequest(admissionRequestArchive);
    validateAdmissionGrant(admissionGrantArchive, admissionRequestArchive);
    validateAdmissionAckRecord(acknowledgementArchive);
    validateAdmissionRecordPair(admissionRequest, admissionRequestArchive, { label: "admission request" });
    validateAdmissionRecordPair(admissionGrant, admissionGrantArchive, { label: "admission grant" });
    validateAdmissionGenesisBinding(request, admissionRequest, admissionGrant);
    fenceBinding = parseAuthorityBytes(snapshot.fenceBindingBytes);
    readerLease = parseAuthorityBytes(snapshot.readerLeaseBytes);
    projection = parseAuthorityBytes(snapshot.readerProjectionBytes);
    readerState = parseAuthorityBytes(snapshot.readerStateBytes);
    ack = parseAuthorityBytes(snapshot.admissionAckBytes);
    validateAdmissionAckRecord(ack);
    validateAdmissionRecordPair(ack, acknowledgementArchive, { label: "admission acknowledgement" });
    validateFenceBinding(fenceBinding, authorityCommit, readerFloor);
    validateLeaseBinding(readerLease, fenceBinding);
    if (admissionRequest.genesisTxId !== request.genesisTxId ||
        admissionRequest.generation !== request.generation ||
        admissionRequest.readerInstanceId !== request.readerInstanceId ||
        admissionRequest.readerStartNonce !== request.readerStartNonce ||
        ack.grantId !== admissionGrant.grantId ||
        ack.grantFingerprint !== admissionGrant.grantFingerprint) {
      throw new TypeError("bound-reader admission relation");
    }
    validateReaderProjection(projection, readerFloor, tokenFloor, zFinality.zFinalityFingerprint);
    validateReaderRelations(readerState, readerFloor);
    if (readerState.attestationFingerprint !== attestation.attestationFingerprint ||
        readerState.authorityReservationFingerprint !== authorityReservation.reservationFingerprint ||
        readerState.authorityCommitSnapshotFingerprint !== authorityCommit.authorityCommitSnapshotFingerprint ||
        readerState.fenceBindingFingerprint !== fenceBinding.fenceBindingFingerprint ||
        readerState.leaseBindingFingerprint !== readerLease.leaseBindingFingerprint ||
        readerState.readerProjectionFingerprint !== projection.readerProjectionFingerprint ||
        readerState.readerInstanceId !== request.readerInstanceId ||
        readerState.readerStartNonce !== request.readerStartNonce) {
      throw new TypeError("bound-reader state relation");
    }
    validateAdmissionAckRecord(ack);
    if (projection.anchorFingerprint !== request.anchorFingerprint ||
        projection.genesisTxId !== request.genesisTxId ||
        projection.generation !== request.generation ||
        projection.fenceBindingFingerprint !== fenceBinding.fenceBindingFingerprint ||
        projection.leaseBindingFingerprint !== readerLease.leaseBindingFingerprint ||
        ack.genesisTxId !== request.genesisTxId ||
        ack.generation !== request.generation ||
        ack.readerInstanceId !== request.readerInstanceId ||
        ack.readerStartNonce !== request.readerStartNonce ||
        ack.readerProjectionFingerprint !== projection.readerProjectionFingerprint) {
      throw new TypeError("bound-reader proof relation");
    }
    validateFinalityProof(proof, request, zFinality, ack, projection.readerProjectionFingerprint);
  }
  validateGenesisReceipt(receipt, request, zFinality, proof);
  if (!isOpaqueIdentity(snapshot.botPrincipal) || !isOpaqueIdentity(snapshot.botOsPrincipal) ||
      snapshot.botPrincipal !== snapshot.botOsPrincipal || !isHex64(snapshot.botStateAclFingerprint)) {
    throw new TypeError("bot identity evidence");
  }
  return {
    request,
    attestation,
    reservation,
    tokenFloor,
    zFinality,
    readerFloor,
    authorityCommit,
    fenceBinding,
    readerLease,
    admissionRequest,
    admissionGrant,
    projection,
    ack,
    readerState,
    snapshot,
  };
}
