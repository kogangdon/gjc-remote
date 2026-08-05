import { createHash } from "node:crypto";
import { createManagementNative } from "@gjc-remote/native-control";
import { buildAdmissionAck, validateAdmissionAck, validateAdmissionAckRecord, validateAdmissionGrant, validateAdmissionRequest, validateFinalityProof } from "@gjc-remote/shared/admission-envelope";
import { authorityRecordFingerprint, validateAttestedTokenFloorProof, validateAuthorityCommitSnapshot, validateAuthorityEpoch, validateAuthorityReservation, validateBaselineSnapshot, validateFenceBinding, validateGenesisAuthorityReceipt, validateGenesisAuthorityRequest, validateGenesisPrecommit, validateGenesisReceipt, validateGenesisRequest, validateLeaseBinding, validateReaderProjection, validateReaderRelations, validateReaderVersionFloor, validateTokenConfigAttestation, validateTokenFloor, validateTokenFloorReservation, validateZFinality } from "@gjc-remote/shared/genesis-envelope";
import { isOpaqueIdentity } from "@gjc-remote/shared/identity";
import { validateManagedChannelsV2, validateManagementEnvelope } from "@gjc-remote/shared/mapping-envelope";
import { validateManualCleanup } from "@gjc-remote/shared/recovery-envelope";
import { validatePublicationC, validatePublicationK, validatePublicationP, validatePublicationQ, validatePublicationS, validatePublicationState, validatePublicationTransaction, validatePublicationU, validatePublicationY, validatePublicationZp } from "@gjc-remote/shared/publication-envelope";
import { canonicalJson, canonicalJsonHash, isHex64, parseCanonicalJsonBytes } from "@gjc-remote/shared/strict-json";
import { authoritySuccessorPreviousLeaseBindingFingerprint, buildAuthoritySuccessorRecord, validateAuthoritySuccessorBundle } from "@gjc-remote/shared/successor-envelope";

const WRAPPER_NAMES = new Set(["managed-v1-wrapper.json", "legacy-retained.json"]);
const CONTROL_ROOT_NAME = "control-root.json";

function trustedRoleBindings(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const keys = ["managementSid", "botSid", "recoverySid", "systemSid"];
  if (Object.keys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) return null;
  if (!keys.every((key) => typeof value[key] === "string" && value[key].trim().length > 0)) return null;
  if (new Set([value.managementSid, value.botSid, value.recoverySid]).size !== 3) return null;
  return Object.freeze({ ...value });
}

function configuredRoleBindings(roleBindings, bootstrapBinding) {
  const direct = trustedRoleBindings(roleBindings);
  if (direct) return direct;
  if (bootstrapBinding?.authenticated !== true) return null;
  return trustedRoleBindings(bootstrapBinding.roleBindings);
}

function unavailable(code = "MANAGED_NATIVE_UNAVAILABLE") {
  return {
    controlRootBytes: Buffer.alloc(0),
    wrapperBytes: undefined,
    targetBytes: Buffer.alloc(0),
    managedSidecarPresent: true,
    nativeVerified: false,
    code,
    managed: false,
    writesPerformed: false,
    managedAuthorityWrites: 0,
    targetWrites: 0,
    controlWrites: 0,
    targetWritesCommitted: 0,
    botStateCommittedWrites: 0,
    retryable: false,
  };
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}
function parseAuthorityBytes(bytes) {
  return parseCanonicalJsonBytes(bytes);
}

function validateCommittedLineage(attestation, floor, anchorFingerprint) {
  validateTokenConfigAttestation(attestation);
  validateTokenFloor(floor);
  if (floor.floorPhase !== "committed" ||
      attestation.anchorFingerprint !== anchorFingerprint ||
      floor.anchorFingerprint !== anchorFingerprint ||
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
    if (attestation.tokenConfigGeneration !== firstGeneration + index ||
        (index === 0 && (attestation.rotationKind !== "genesis" || attestation.previousAttestationFingerprint !== null)) ||
        (index > 0 && (attestation.previousAttestationFingerprint !== previous.attestationFingerprint ||
          (attestation.rotationKind === "same-key") !== (attestation.tokenConfigHostSetFingerprint === previous.tokenConfigHostSetFingerprint) ||
          (attestation.rotationKind === "host-set-change") !== (attestation.tokenConfigHostSetFingerprint !== previous.tokenConfigHostSetFingerprint)))) {
      throw new TypeError("token history lineage");
    }
    previous = attestation;
  }
  const historicalIndex = historicalAttestation.tokenConfigGeneration - firstGeneration;
  if (attestations[historicalIndex]?.attestationFingerprint !== historicalAttestation.attestationFingerprint ||
      floors[historicalIndex]?.floorFingerprint !== historicalFloor.floorFingerprint ||
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

function validateBotPayload(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} schema`);
  canonicalJson(value);
  return value;
}
function fingerprintBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function validateLiveSuccessorEvidence(bundle, evidence, expectedHostSetFingerprint) {
  const { request, head, finality, baseline } = bundle;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) ||
      !["managed-v1", "legacy-retained"].includes(evidence.sourceKind) ||
      !isBytes(evidence.headBytes) || !isBytes(evidence.finalityBytes) ||
      !isBytes(evidence.attestationBytes) || !isBytes(evidence.tokenFloorBytes) ||
      !isBytes(evidence.attestationHistoryBytes) || !isBytes(evidence.tokenFloorHistoryBytes) ||
      !isBytes(evidence.controlRootBytes) || !isBytes(evidence.wrapperBytes) || !isBytes(evidence.targetBytes) ||
      !isHex64(evidence.targetIdentity) || !isHex64(evidence.targetAclFingerprint)) {
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
  const { attestations, floors } = validateTokenHistory(
    evidence,
    request.anchorFingerprint,
    attestation,
    floor,
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
  const canonicalMappingFingerprint = canonicalJsonHash(target === null
    ? { mappingGeneration: 0, mappings: {}, routes: {} }
    : { mappingGeneration: target.mappingGeneration, mappings: target.mappings, routes: target.routes });
  const targetFingerprint = fingerprintBytes(snapshot.targetBytes);
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
    record.generation !== transaction.generation
  )) throw new TypeError("publication transaction branch");
  if (prepared.phase !== "prepared" || replaced.phase !== "replaced" || committed.phase !== "committed" ||
      transaction.txId !== request.genesisTxId || transaction.genesisTxId !== request.genesisTxId ||
      transaction.generation !== request.generation ||
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
  const attestedProof = parseAuthorityBytes(snapshot.attestedProofBytes);
  const precommit = parseAuthorityBytes(snapshot.precommitBytes);
  const authorityRequest = parseAuthorityBytes(snapshot.authorityRequestBytes);
  const authorityReceipt = parseAuthorityBytes(snapshot.authorityReceiptBytes);
  const authorityReservation = parseAuthorityBytes(snapshot.authorityReservationBytes);
  const authorityCommit = parseAuthorityBytes(snapshot.authorityCommitBytes);
  const authorityBaseline = parseAuthorityBytes(snapshot.authorityBaselineBytes);
  const authorityEpoch = parseAuthorityBytes(snapshot.authorityEpochBytes);
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
  validateReaderVersionFloor(readerFloor);
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
  if (request.requestedReaderMode === "no-reader") {
    if (snapshot.readerProjectionBytes !== undefined || snapshot.readerStateBytes !== undefined ||
        snapshot.admissionAckBytes !== undefined || snapshot.fenceBindingBytes !== undefined ||
        snapshot.readerLeaseBytes !== undefined) {
      throw new TypeError("no-reader proof branch");
    }
    if (snapshot.admissionRequestBytes !== undefined || snapshot.admissionGrantBytes !== undefined) throw new TypeError("no-reader admission branch");
    validateFinalityProof(proof, request, zFinality);
  } else {
    if (!isBytes(snapshot.readerStateBytes)) throw new TypeError("bound-reader state bytes");
    admissionRequest = parseAuthorityBytes(snapshot.admissionRequestBytes);
    admissionGrant = parseAuthorityBytes(snapshot.admissionGrantBytes);
    validateAdmissionRequest(admissionRequest);
    validateAdmissionGrant(admissionGrant, admissionRequest);
    fenceBinding = parseAuthorityBytes(snapshot.fenceBindingBytes);
    readerLease = parseAuthorityBytes(snapshot.readerLeaseBytes);
    projection = parseAuthorityBytes(snapshot.readerProjectionBytes);
    readerState = parseAuthorityBytes(snapshot.readerStateBytes);
    ack = parseAuthorityBytes(snapshot.admissionAckBytes);
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

/**
 * The native adapter owns every filesystem operation. This module deliberately
 * has no JavaScript filesystem fallback: a mapping is usable only when the
 * verified native view supplies bytes, identity, and ACL evidence through the
 * manifest-bound native boundary.
 */
export async function createManagedAuthorityReader({
  configPath,
  expectedHostSetFingerprint = null,
  roleBindings = null,
  bootstrapBinding = null,
} = {}) {
  const roles = configuredRoleBindings(roleBindings, bootstrapBinding);
  if (!roles) return Object.freeze({ readSnapshot: async () => unavailable("MANAGEMENT_ROLE_BINDING_REQUIRED") });

  let native;
  try {
    native = await createManagementNative({ configPath, roles, bootstrapBinding });
  } catch {
    return Object.freeze({ readSnapshot: async () => unavailable() });
  }

  if (!native || typeof native.readManagedMappingSnapshot !== "function" ||
      typeof native.configureManagementRoles !== "function") {
    return Object.freeze({ readSnapshot: async () => unavailable() });
  }
  try {
    await native.configureManagementRoles(roles);
    if (typeof native.runStartupSelfTest !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    const selfTest = await native.runStartupSelfTest();
    if (selfTest?.role !== "bot" || selfTest?.bst !== true || selfTest?.mst !== false || selfTest?.writes !== 0) {
      throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    }
  } catch (error) {
    const code = error?.message === "MANAGEMENT_ROLE_BINDING_INVALID"
      ? "MANAGEMENT_ROLE_BINDING_INVALID"
      : "MANAGED_NATIVE_UNAVAILABLE";
    return Object.freeze({ readSnapshot: async () => unavailable(code) });
  }
  let authority = null;
  const requireBotAuthority = () => {
    if (!authority || authority.request.requestedReaderMode !== "handshake") throw new Error("BOT_AUTHORITY_UNAVAILABLE");
    return authority;
  };
  const completePendingHandshake = async () => {
    if (typeof native.readPendingReaderBootstrap !== "function" ||
        typeof native.acquireBotLease !== "function" ||
        typeof native.writeBotReaderProjection !== "function" ||
        typeof native.writeBotReaderState !== "function" ||
        typeof native.writeBotAcknowledgement !== "function") {
      return false;
    }
    const pending = await native.readPendingReaderBootstrap();
    const { request, floor, tokenFloor, zFinality, precommit, commit, fence, admissionRequest, admissionGrant } = pending;
    validateReaderVersionFloor(floor);
    validateTokenFloor(tokenFloor);
    validateZFinality(zFinality, request, tokenFloor, precommit);
    validateFenceBinding(fence, commit, floor);
    validateAdmissionGrant(admissionGrant, admissionRequest, Date.now());

    const lease = {
      version: 1,
      kind: "reader-lease-binding",
      anchorFingerprint: request.anchorFingerprint,
      genesisTxId: request.genesisTxId,
      readerInstanceId: request.readerInstanceId,
      readerStartNonce: request.readerStartNonce,
      readerVersion: 2,
      fenceBindingFingerprint: fence.fenceBindingFingerprint,
      leaseBindingFingerprint: null,
    };
    lease.leaseBindingFingerprint = authorityRecordFingerprint(lease, "leaseBindingFingerprint");
    validateLeaseBinding(lease, fence);

    const projection = {
      version: 1,
      kind: "reader-projection",
      anchorFingerprint: request.anchorFingerprint,
      genesisTxId: request.genesisTxId,
      generation: request.generation,
      readerInstanceId: request.readerInstanceId,
      readerStartNonce: request.readerStartNonce,
      readerVersion: 2,
      fenceBindingFingerprint: fence.fenceBindingFingerprint,
      leaseBindingFingerprint: lease.leaseBindingFingerprint,
      zFinalityFingerprint: zFinality.zFinalityFingerprint,
      readerProjectionFingerprint: null,
    };
    projection.readerProjectionFingerprint = canonicalJsonHash(
      Object.fromEntries(Object.entries(projection).filter(([key]) => key !== "readerProjectionFingerprint")),
    );
    validateReaderProjection(projection, floor, tokenFloor, zFinality.zFinalityFingerprint);
    const acknowledgement = buildAdmissionAck(admissionGrant, projection.readerProjectionFingerprint);
    const readerState = {
      attestationFingerprint: request.attestationFingerprint,
      authorityReservationFingerprint: commit.reservationFingerprint,
      authorityCommitSnapshotFingerprint: commit.authorityCommitSnapshotFingerprint,
      fenceBindingFingerprint: fence.fenceBindingFingerprint,
      leaseBindingFingerprint: lease.leaseBindingFingerprint,
      readerProjectionFingerprint: projection.readerProjectionFingerprint,
      readerInstanceId: request.readerInstanceId,
      readerStartNonce: request.readerStartNonce,
      readerVersion: 2,
    };
    validateReaderRelations(readerState, floor);

    await native.acquireBotLease(lease);
    await native.writeBotReaderProjection(projection);
    await native.writeBotReaderState(readerState);
    await native.writeBotAcknowledgement(acknowledgement);
    return true;
  };
  const completePendingSuccessor = async (bundle) => {
    const { request, fence, finality, lease, projection, ack, head } = bundle;
    if (head.phase !== "reader-pending" || request.readerMode !== "bound-reader") return false;
    if (!fence || !finality) throw new Error("SUCCESSOR_PENDING_INVALID");
    if (typeof native.readBotAuthoritySuccessorLiveProof !== "function") throw new Error("BOT_NATIVE_WRITE_REFUSED");
    const validateLiveProof = async () => {
      const evidence = await native.readBotAuthoritySuccessorLiveProof({ txId: request.txId });
      validateLiveSuccessorEvidence(bundle, evidence, expectedHostSetFingerprint);
    };
    const required = ["writeBotAuthoritySuccessorLease", "writeBotAuthoritySuccessorProjection", "writeBotAuthoritySuccessorAck"];
    if (!required.every((method) => typeof native[method] === "function")) throw new Error("BOT_NATIVE_WRITE_REFUSED");
    const l2 = lease ?? buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-lease", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId,
      requestFingerprint: request.requestFingerprint, readerInstanceId: request.readerInstanceId,
      readerStartNonce: request.readerStartNonce, readerVersion: 2, fenceBindingFingerprint: fence.fenceBindingFingerprint,
      previousLeaseBindingFingerprint: authoritySuccessorPreviousLeaseBindingFingerprint(request), leaseBindingFingerprint: null,
    }, "leaseBindingFingerprint");
    if (!lease) {
      await validateLiveProof();
      await native.writeBotAuthoritySuccessorLease(l2);
    }
    const rp2 = projection ?? buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-reader-projection", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId,
      requestFingerprint: request.requestFingerprint, finalityFingerprint: finality.finalityFingerprint,
      anchorFingerprint: request.anchorFingerprint, authorityCommitSnapshotFingerprint: finality.authorityCommitSnapshotFingerprint,
      targetFingerprint: finality.targetFingerprint, wrapperFingerprint: finality.wrapperFingerprint,
      revision: finality.revision, authorityEpoch: finality.authorityEpoch,
      tokenConfigGeneration: finality.tokenConfigGeneration, mappingGeneration: finality.mappingGeneration,
      readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce, readerVersion: 2,
      readerNonce: request.readerNonce, fenceBindingFingerprint: fence.fenceBindingFingerprint,
      leaseBindingFingerprint: l2.leaseBindingFingerprint, readerProjectionFingerprint: null,
    }, "readerProjectionFingerprint");
    if (!projection) {
      await validateLiveProof();
      await native.writeBotAuthoritySuccessorProjection(rp2);
    }
    const ak2 = ack ?? buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-ack", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId,
      requestFingerprint: request.requestFingerprint, finalityFingerprint: finality.finalityFingerprint,
      readerProjectionFingerprint: rp2.readerProjectionFingerprint, leaseBindingFingerprint: l2.leaseBindingFingerprint,
      readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce, readerVersion: 2,
      readerNonce: request.readerNonce, ackDisposition: "verified-no-route", ackFingerprint: null,
    }, "ackFingerprint");
    if (!ack) {
      await validateLiveProof();
      await native.writeBotAuthoritySuccessorAck(ak2);
    }
    return true;
  };

  return Object.freeze({
    async readSnapshot() {
      let snapshot;
      try {
        snapshot = await native.readManagedMappingSnapshot();
      } catch (error) {
        if (error?.code !== "MANAGED_HANDSHAKE_PENDING") return unavailable();
        try {
          if (await completePendingHandshake()) {
            return unavailable("MANAGED_HANDSHAKE_PENDING");
          }
        } catch {
          return unavailable("MANAGED_HANDSHAKE_INVALID");
        }
        return unavailable("MANAGED_HANDSHAKE_PENDING");
      }
      if (snapshot?.managementMarkerPresent === true || snapshot?.bootstrapBlockerPresent === true ||
          snapshot?.genesisProbePresent === true) return unavailable("MANAGED_MARKER_INCOMPLETE");
      if (snapshot?.controlRootAbsent === true) return { controlRootAbsent: true };
      if (snapshot?.successorBundle) {
        try {
          validateAuthoritySuccessorBundle(snapshot.successorBundle);
          const { head } = snapshot.successorBundle;
          if (head.phase === "reader-pending") {
            try {
              await completePendingSuccessor(snapshot.successorBundle);
            } catch (error) {
              if (process.env.GJC_TRACE_TEST_ERROR === "1") console.error(error?.stack);
              return unavailable("MANAGED_AUTHORITY_INVALID");
            }
            return unavailable("MANAGED_AUTHORITY_PENDING");
          }
          if (head.phase !== "terminal") return unavailable("MANAGED_AUTHORITY_PENDING");
          if (!isBytes(snapshot.controlRootBytes) || !isBytes(snapshot.wrapperBytes) || !isBytes(snapshot.targetBytes) ||
              !isHex64(snapshot.targetIdentity) || !isHex64(snapshot.targetAclFingerprint)) {
            return unavailable("MANAGED_AUTHORITY_INVALID");
          }
          return {
            controlRootBytes: Buffer.from(snapshot.controlRootBytes),
            wrapperBytes: Buffer.from(snapshot.wrapperBytes),
            targetBytes: Buffer.from(snapshot.targetBytes),
            targetIdentity: snapshot.targetIdentity,
            targetAclFingerprint: snapshot.targetAclFingerprint,
            nativeVerified: true,
            successorHeadFingerprint: head.headFingerprint,
            routeDisposition: "no-route",
          };
        } catch (error) {
          if (process.env.GJC_TRACE_TEST_ERROR === "1") console.error(error?.stack);
          return unavailable("MANAGED_AUTHORITY_INVALID");
        }
      }
      if (!snapshot || snapshot.controlRootName !== CONTROL_ROOT_NAME ||
          !WRAPPER_NAMES.has(snapshot.wrapperName) || !isBytes(snapshot.controlRootBytes) ||
          !isBytes(snapshot.wrapperBytes) || !isBytes(snapshot.targetBytes) ||
          !isBytes(snapshot.attestationBytes) || !isBytes(snapshot.tokenFloorBytes) ||
          !isBytes(snapshot.currentAttestationBytes) || !isBytes(snapshot.currentTokenFloorBytes) ||
          !isBytes(snapshot.attestationHistoryBytes) || !isBytes(snapshot.tokenFloorHistoryBytes) ||
          !isBytes(snapshot.tokenFloorReservationBytes) || !isBytes(snapshot.readerVersionFloorBytes) ||
          !isBytes(snapshot.genesisRequestBytes) || !isBytes(snapshot.zFinalityBytes) || !isBytes(snapshot.rvfBytes) ||
          !isBytes(snapshot.receiptBytes) || !isBytes(snapshot.authorityRequestBytes) || !isBytes(snapshot.authorityReceiptBytes) ||
          !isBytes(snapshot.authorityReservationBytes) || !isBytes(snapshot.authorityCommitBytes) || !isBytes(snapshot.authorityBaselineBytes) ||
          !isBytes(snapshot.authorityEpochBytes) || !isBytes(snapshot.publicationTransactionBytes) ||
          !isBytes(snapshot.publicationUBytes) || !isBytes(snapshot.publicationPBytes) ||
          !isBytes(snapshot.publicationSBytes) || !isBytes(snapshot.publicationPreparedBytes) ||
          !isBytes(snapshot.publicationReplacedBytes) || !isBytes(snapshot.publicationCommittedBytes) ||
          !isBytes(snapshot.publicationCBytes) || !isBytes(snapshot.publicationQBytes) ||
          !isBytes(snapshot.publicationZpBytes) || !isBytes(snapshot.publicationKBytes) ||
          !isBytes(snapshot.publicationYBytes) || !isBytes(snapshot.attestedProofBytes) || !isBytes(snapshot.precommitBytes) ||
          (snapshot.readerStateBytes !== undefined && !isBytes(snapshot.readerStateBytes)) ||
          !isHex64(snapshot.targetIdentity) || !isHex64(snapshot.targetAclFingerprint)) {
        return unavailable("MANAGED_NATIVE_AMBIGUOUS");
      }
      try {
        authority = validateManagedProof(snapshot, expectedHostSetFingerprint);
      } catch {
        authority = null;
        return unavailable("MANAGED_AUTHORITY_INVALID");
      }
      return {
        controlRootBytes: Buffer.from(snapshot.controlRootBytes),
        wrapperBytes: Buffer.from(snapshot.wrapperBytes),
        targetBytes: Buffer.from(snapshot.targetBytes),
        targetIdentity: snapshot.targetIdentity,
        targetAclFingerprint: snapshot.targetAclFingerprint,
        nativeVerified: true,
      };
    },
    async completePendingHandshake() {
      return completePendingHandshake();
    },
    // B may persist only bot-owned reader state. M records are intentionally
    // absent from this surface, so they cannot be written through the bot.
    async writeReaderProjection(projection) {
      const current = requireBotAuthority();
      validateReaderProjection(
        projection,
        current.readerFloor,
        current.tokenFloor,
        current.zFinality.zFinalityFingerprint,
      );
      if (projection.anchorFingerprint !== current.request.anchorFingerprint ||
          projection.genesisTxId !== current.request.genesisTxId ||
          projection.generation !== current.request.generation ||
          projection.readerInstanceId !== current.request.readerInstanceId ||
          projection.readerStartNonce !== current.request.readerStartNonce) {
        throw new Error("BOT_READER_PROJECTION_BINDING_INVALID");
      }
      if (typeof native.writeBotReaderProjection !== "function") throw new Error("BOT_NATIVE_WRITE_REFUSED");
      return native.writeBotReaderProjection(projection);
    },
    async writeReaderState(state) {
      const current = requireBotAuthority();
      validateReaderRelations(state, current.readerFloor);
      if (state.attestationFingerprint !== current.attestation.attestationFingerprint ||
          state.authorityReservationFingerprint !== current.reservation.floorFingerprint ||
          state.authorityCommitSnapshotFingerprint !== current.authorityCommit.authorityCommitSnapshotFingerprint ||
          state.fenceBindingFingerprint !== current.fenceBinding.fenceBindingFingerprint ||
          state.leaseBindingFingerprint !== current.readerLease.leaseBindingFingerprint ||
          state.readerProjectionFingerprint !== current.projection.readerProjectionFingerprint ||
          state.readerInstanceId !== current.request.readerInstanceId ||
          state.readerStartNonce !== current.request.readerStartNonce) {
        throw new Error("BOT_READER_STATE_BINDING_INVALID");
      }
      if (typeof native.writeBotReaderState !== "function") throw new Error("BOT_NATIVE_WRITE_REFUSED");
      return native.writeBotReaderState(state);
    },
    async acquireLease(lease) {
      const current = requireBotAuthority();
      validateLeaseBinding(lease, current.fenceBinding);
      if (lease.genesisTxId !== current.request.genesisTxId ||
          lease.readerInstanceId !== current.request.readerInstanceId ||
          lease.readerStartNonce !== current.request.readerStartNonce) {
        throw new Error("BOT_LEASE_BINDING_INVALID");
      }
      if (typeof native.acquireBotLease !== "function") throw new Error("BOT_NATIVE_WRITE_REFUSED");
      return native.acquireBotLease(lease);
    },
    async acknowledge(bundle) {
      const current = requireBotAuthority();
      validateBotPayload(bundle, "acknowledgement");
      const { ack, grant, request } = bundle;
      validateAdmissionGrant(grant, request);
      validateAdmissionAck(ack, grant, ack?.readerProjectionFingerprint);
      if (request.genesisTxId !== current.request.genesisTxId || request.generation !== current.request.generation ||
          request.readerInstanceId !== current.request.readerInstanceId || request.readerStartNonce !== current.request.readerStartNonce ||
          ack.genesisTxId !== current.request.genesisTxId || ack.generation !== current.request.generation ||
          ack.readerInstanceId !== current.request.readerInstanceId || ack.readerStartNonce !== current.request.readerStartNonce) {
        throw new Error("BOT_ACK_BINDING_INVALID");
      }
      if (typeof native.writeBotAcknowledgement !== "function") throw new Error("BOT_NATIVE_WRITE_REFUSED");
      return native.writeBotAcknowledgement(ack);
    },
  });
}
