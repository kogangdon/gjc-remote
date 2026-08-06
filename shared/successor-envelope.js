import { canonicalJsonHash, isHex64 } from "./strict-json.js";
import { isOpaqueIdentity } from "./identity.js";
import { validateAuthorityCommitSnapshot, validateAuthorityEpoch, validateAuthorityReservation } from "./genesis-envelope.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`SUCCESSOR_ENVELOPE_INVALID: ${message}`); };
const fingerprint = (record, field) => canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
const hex = (value) => isHex64(value);
const nullableHex = (value) => value === null || hex(value);
const opaque = (value) => isOpaqueIdentity(value);
const rootGenesisTxId = (authority) => typeof authority === "string" ? authority : authority?.genesisTxId;
const assertGenesisRoot = (record, authority = null) => {
  if (authority !== null && (!plain(record) || !opaque(rootGenesisTxId(authority)) || record.rootGenesisTxId !== rootGenesisTxId(authority))) {
    fail("Genesis authority root relation");
  }
};
const nullableOpaque = (value) => value === null || opaque(value);
const nonNegative = (value) => Number.isSafeInteger(value) && value >= 0;
const positive = (value) => Number.isSafeInteger(value) && value > 0;
const operations = new Set(["tokens-attest", "mapping-reconcile", "mapping-revoke", "mapping-rollback", "mapping-recovery"]);
const targetStates = new Set(["genesis-empty", "managed-empty", "managed", "legacy-retained"]);
const validTargetState = (operation, targetState) => targetStates.has(targetState) && (targetState !== "legacy-retained" || operation === "tokens-attest");
const readerModes = new Set(["no-reader", "bound-reader"]);
const phases = new Set(["reserved", "closed", "replaced", "reader-pending", "terminal"]);
const assertHash = (record, field) => { if (!hex(record[field]) || record[field] !== fingerprint(record, field)) fail(`${record.kind} fingerprint`); };
const assertKeys = (record, keys) => { if (!exact(record, keys) || record.version !== 1) fail("exact schema"); };
const managedHistoryMarkerKeys = ["version", "kind", "anchorFingerprint", "sequence", "fenceGeneration", "previousMarkerFingerprint", "markerFingerprint"];
export function validateManagedHistoryMarker(record, anchorFingerprint = undefined, expectedSequence = undefined) {
  assertKeys(record, managedHistoryMarkerKeys);
  if (record.kind !== "managed-history-marker" || !hex(record.anchorFingerprint) || !positive(record.sequence) ||
      !positive(record.fenceGeneration) || (record.sequence === 1 ? record.previousMarkerFingerprint !== null : !hex(record.previousMarkerFingerprint))) {
    fail("managed history marker fields");
  }
  if (anchorFingerprint !== undefined && record.anchorFingerprint !== anchorFingerprint) fail("managed history marker anchor");
  if (expectedSequence !== undefined && record.sequence !== expectedSequence) fail("managed history marker sequence");
  assertHash(record, "markerFingerprint");
  return record;
}
export function validateManagedHistoryMarkerSeal(marker, seal, anchorFingerprint = undefined) {
  if (marker === null || seal === null) fail("managed history marker seal");
  validateManagedHistoryMarker(marker, anchorFingerprint);
  validateManagedHistoryMarker(seal, anchorFingerprint, 1);
  if (marker.sequence === 1 && marker.markerFingerprint !== seal.markerFingerprint) fail("managed history marker seal mismatch");
  if (marker.sequence === 2 && marker.previousMarkerFingerprint !== seal.markerFingerprint) fail("managed history marker predecessor seal");
  return seal;
}
const assertFence = (record, expected = undefined) => {
  if (!positive(record.fenceGeneration) || (expected !== undefined && record.fenceGeneration !== expected)) fail("fence generation");
};
const sortedUnique = (values, valid) => Array.isArray(values) && values.every(valid) && values.every((value, index) => index === 0 || values[index - 1] < value);
const reader = (record, required = true) => {
  const fields = [record.readerInstanceId, record.readerStartNonce];
  if (required) {
    if (!fields.every(opaque) || record.readerVersion !== 2) fail("reader binding");
  } else if (!fields.every((value) => value === null) || record.readerVersion !== null) fail("no-reader binding");
};

const SR = ["version", "kind", "sequence", "txId", "rootGenesisTxId", "idempotencyKey", "operation", "anchorFingerprint", "actorPrincipalFingerprint", "previousReceiptFingerprint", "previousTargetFingerprint", "previousWrapperFingerprint", "previousRevision", "candidateRevision", "previousAuthorityEpoch", "candidateAuthorityEpoch", "previousTokenConfigGeneration", "candidateTokenConfigGeneration", "previousAttestationFingerprint", "candidateAttestationFingerprint", "previousMappingGeneration", "candidateMappingGeneration", "previousSnapshotFingerprint", "candidateSnapshotFingerprint", "candidateTargetFingerprint", "previousFenceGeneration", "candidateFenceGeneration", "mappingRecoveryTxFingerprint", "targetState", "readerMode", "readerInstanceId", "readerStartNonce", "readerNonce", "requestFingerprint"];
export function validateAuthoritySuccessorRequest(record, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, SR); if (record.kind !== "authority-successor-request" || !positive(record.sequence) || ![record.txId, record.rootGenesisTxId, record.idempotencyKey].every(opaque) || !operations.has(record.operation) || ![record.anchorFingerprint, record.actorPrincipalFingerprint, record.previousReceiptFingerprint, record.previousTargetFingerprint, record.previousWrapperFingerprint, record.previousAttestationFingerprint, record.candidateAttestationFingerprint, record.previousSnapshotFingerprint, record.candidateSnapshotFingerprint, record.candidateTargetFingerprint].every(hex) || ![record.previousRevision, record.previousAuthorityEpoch, record.previousTokenConfigGeneration, record.previousMappingGeneration, record.candidateMappingGeneration].every(nonNegative) || ![record.candidateRevision, record.candidateAuthorityEpoch, record.candidateTokenConfigGeneration].every(positive) || record.candidateRevision !== record.previousRevision + 1 || record.candidateAuthorityEpoch !== record.previousAuthorityEpoch + 1 || !nullableHex(record.mappingRecoveryTxFingerprint) || !validTargetState(record.operation, record.targetState) || !readerModes.has(record.readerMode)) fail("SR fields");
  if (!positive(record.previousFenceGeneration) || !positive(record.candidateFenceGeneration) || record.candidateFenceGeneration !== record.previousFenceGeneration + 1) fail("SR fence CAS");
  if (record.operation === "tokens-attest") { if (record.candidateTokenConfigGeneration !== record.previousTokenConfigGeneration + 1 || record.candidateMappingGeneration !== record.previousMappingGeneration || record.mappingRecoveryTxFingerprint !== null) fail("SR token lineage"); } else if (record.candidateTokenConfigGeneration !== record.previousTokenConfigGeneration || record.candidateAttestationFingerprint !== record.previousAttestationFingerprint || record.candidateMappingGeneration !== record.previousMappingGeneration + 1 || !hex(record.mappingRecoveryTxFingerprint)) fail("SR mapping lineage");
  if (record.readerMode === "bound-reader") { if (![record.readerInstanceId, record.readerStartNonce, record.readerNonce].every(opaque)) fail("SR reader binding"); } else if ([record.readerInstanceId, record.readerStartNonce, record.readerNonce].some((value) => value !== null) || !["tokens-attest", "mapping-reconcile", "mapping-revoke", "mapping-rollback", "mapping-recovery"].includes(record.operation)) fail("SR no-reader");
  assertHash(record, "requestFingerprint"); return record;
}

const CL = ["version", "kind", "txId", "rootGenesisTxId", "requestFingerprint", "previousReceiptFingerprint", "fenceGeneration", "previousBarrierGeneration", "barrierGeneration", "affectedScope", "affectedMappingIds", "affectedRouteFingerprints", "readerInstanceId", "readerStartNonce", "retiredGrantFingerprint", "retiredProjectionFingerprint", "retiredAckFingerprint", "admissionPhaseBefore", "admissionPhaseAfter", "admissionDrained", "outstandingRouteGrantCount", "routeDisposition", "closeFingerprint"];
export function validateAuthorityCloseProof(record, request = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertFence(record);
  assertKeys(record, CL); if (record.kind !== "authority-close-proof" || ![record.txId, record.rootGenesisTxId].every(opaque) || ![record.requestFingerprint, record.previousReceiptFingerprint].every(hex) || !nonNegative(record.previousBarrierGeneration) || record.barrierGeneration !== record.previousBarrierGeneration + 1 || !["all", "mapping"].includes(record.affectedScope) || !sortedUnique(record.affectedMappingIds, opaque) || !sortedUnique(record.affectedRouteFingerprints, hex) || ![record.readerInstanceId, record.readerStartNonce].every(nullableOpaque) || (record.readerInstanceId === null) !== (record.readerStartNonce === null) || ![record.retiredGrantFingerprint, record.retiredProjectionFingerprint, record.retiredAckFingerprint].every(nullableHex) || record.admissionPhaseBefore !== "closed" || record.admissionPhaseAfter !== "closed-drained" || record.admissionDrained !== true || record.outstandingRouteGrantCount !== 0 || record.routeDisposition !== "no-route") fail("CL fields");
  if (request && record.fenceGeneration !== request.candidateFenceGeneration) fail("CL fence relation");
  if (request && (record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.requestFingerprint !== request.requestFingerprint || record.previousReceiptFingerprint !== request.previousReceiptFingerprint || (request.operation === "tokens-attest" ? record.affectedScope !== "all" : record.affectedScope !== "mapping") || (request.readerMode === "no-reader" ? record.readerInstanceId !== null || record.readerStartNonce !== null : record.readerInstanceId !== request.readerInstanceId || record.readerStartNonce !== request.readerStartNonce))) fail("CL request relation");
  assertHash(record, "closeFingerprint"); return record;
}

const F2 = ["version", "kind", "txId", "rootGenesisTxId", "requestFingerprint", "fenceGeneration", "anchorFingerprint", "authorityCommitSnapshotFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion", "previousFenceBindingFingerprint", "fenceBindingFingerprint"];
export function validateAuthoritySuccessorFence(record, request = null, commit = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, F2); assertFence(record);
  if (record.kind !== "authority-successor-fence" || ![record.txId, record.rootGenesisTxId, record.readerInstanceId, record.readerStartNonce].every(opaque) || ![record.requestFingerprint, record.anchorFingerprint, record.authorityCommitSnapshotFingerprint, record.previousFenceBindingFingerprint].every(hex) || record.readerVersion !== 2) fail("F2 fields");
  if (request && (request.readerMode !== "bound-reader" || record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.requestFingerprint !== request.requestFingerprint || record.fenceGeneration !== request.candidateFenceGeneration || record.anchorFingerprint !== request.anchorFingerprint || record.readerInstanceId !== request.readerInstanceId || record.readerStartNonce !== request.readerStartNonce || record.previousFenceBindingFingerprint !== request.previousReceiptFingerprint)) fail("F2 request relation");
  if (commit && (record.txId !== commit.txId || record.fenceGeneration !== commit.fenceGeneration || record.anchorFingerprint !== commit.anchorFingerprint || record.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint)) fail("F2 commit relation");
  assertHash(record, "fenceBindingFingerprint"); return record;
}

const SB = ["version", "kind", "txId", "rootGenesisTxId", "requestFingerprint", "fenceGeneration", "anchorFingerprint", "operation", "targetState", "revision", "authorityEpoch", "tokenConfigGeneration", "tokenConfigHostSetFingerprint", "mappingGeneration", "candidateSnapshotFingerprint", "candidateTargetFingerprint", "attestationFingerprint", "authorityReservationFingerprint", "authorityCommitSnapshotFingerprint", "closeFingerprint", "fenceBindingFingerprint", "leaseBindingFingerprint", "readerProjectionFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion", "baselineFingerprint"];
export function validateAuthoritySuccessorBaseline(record, request = null, close = null, fence = null, reservation = null, commit = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertFence(record);
  assertKeys(record, SB); if (record.kind !== "authority-successor-baseline" || ![record.txId, record.rootGenesisTxId].every(opaque) || ![record.requestFingerprint, record.anchorFingerprint, record.tokenConfigHostSetFingerprint, record.candidateSnapshotFingerprint, record.candidateTargetFingerprint, record.attestationFingerprint, record.authorityReservationFingerprint, record.authorityCommitSnapshotFingerprint, record.closeFingerprint].every(hex) || !operations.has(record.operation) || !validTargetState(record.operation, record.targetState) || ![record.revision, record.authorityEpoch, record.tokenConfigGeneration].every(positive) || !nonNegative(record.mappingGeneration) || ![record.fenceBindingFingerprint, record.leaseBindingFingerprint, record.readerProjectionFingerprint].every(nullableHex) || ![record.readerInstanceId, record.readerStartNonce].every(nullableOpaque) || !(record.readerVersion === null || record.readerVersion === 2)) fail("SB fields");
  if (request && record.fenceGeneration !== request.candidateFenceGeneration) fail("SB fence relation");
  if (record.leaseBindingFingerprint !== null || record.readerProjectionFingerprint !== null) fail("SB B outputs");
  if (request && (record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.requestFingerprint !== request.requestFingerprint || record.anchorFingerprint !== request.anchorFingerprint || record.operation !== request.operation || record.targetState !== request.targetState || record.revision !== request.candidateRevision || record.authorityEpoch !== request.candidateAuthorityEpoch || record.tokenConfigGeneration !== request.candidateTokenConfigGeneration || record.mappingGeneration !== request.candidateMappingGeneration || record.attestationFingerprint !== request.candidateAttestationFingerprint || record.candidateSnapshotFingerprint !== request.candidateSnapshotFingerprint || record.candidateTargetFingerprint !== request.candidateTargetFingerprint)) fail("SB request relation");
  if (request && (request.readerMode === "no-reader"
    ? record.readerInstanceId !== null || record.readerStartNonce !== null || record.readerVersion !== null || record.fenceBindingFingerprint !== null
    : record.readerInstanceId !== request.readerInstanceId || record.readerStartNonce !== request.readerStartNonce || record.readerVersion !== 2)) fail("SB reader relation");
  if (close && record.closeFingerprint !== close.closeFingerprint) fail("SB close relation");
  if (fence ? record.fenceBindingFingerprint !== fence.fenceBindingFingerprint : record.fenceBindingFingerprint !== null) fail("SB fence relation");
  if (reservation && (record.authorityReservationFingerprint !== reservation.reservationFingerprint)) fail("SB reservation relation");
  if (commit && (record.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint)) fail("SB commit relation");
  if (reservation !== null) {
    if (commit === null) fail("SB commit relation");
  }
  if (commit !== null) {
    if (reservation === null) fail("SB reservation relation");
  }
  if (record.fenceBindingFingerprint === null) reader(record, false); else reader(record);
  assertHash(record, "baselineFingerprint"); return record;
}

const SF = ["version", "kind", "sequence", "txId", "rootGenesisTxId", "requestFingerprint", "fenceGeneration", "operation", "baselineFingerprint", "closeFingerprint", "anchorFingerprint", "authorityReservationFingerprint", "authorityCommitSnapshotFingerprint", "authorityEpochFingerprint", "tokenFloorFingerprint", "attestationFingerprint", "publicationKFingerprint", "publicationYFingerprint", "operationEvidenceFingerprint", "auditEntryFingerprint", "targetFingerprint", "targetIdentityFingerprint", "targetAclFingerprint", "wrapperFingerprint", "controlRootFingerprint", "revision", "authorityEpoch", "tokenConfigGeneration", "mappingGeneration", "snapshotFingerprint", "routeDisposition", "finalityFingerprint"];
export function validateAuthoritySuccessorFinality(record, request = null, baseline = null, reservation = null, commit = null, authorityEpoch = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, SF); assertFence(record);
  if (record.kind !== "authority-successor-finality" || !positive(record.sequence) || ![record.txId, record.rootGenesisTxId].every(opaque) || !operations.has(record.operation) || ![record.requestFingerprint, record.baselineFingerprint, record.closeFingerprint, record.anchorFingerprint, record.authorityReservationFingerprint, record.authorityCommitSnapshotFingerprint, record.authorityEpochFingerprint, record.tokenFloorFingerprint, record.attestationFingerprint, record.publicationKFingerprint, record.publicationYFingerprint, record.operationEvidenceFingerprint, record.auditEntryFingerprint, record.targetFingerprint, record.targetIdentityFingerprint, record.targetAclFingerprint, record.wrapperFingerprint, record.controlRootFingerprint, record.snapshotFingerprint].every(hex) || ![record.revision, record.authorityEpoch, record.tokenConfigGeneration].every(positive) || !nonNegative(record.mappingGeneration) || record.routeDisposition !== "no-route") fail("SF fields");
  if (request && (record.txId !== request.txId || record.sequence !== request.sequence || record.rootGenesisTxId !== request.rootGenesisTxId || record.requestFingerprint !== request.requestFingerprint || record.fenceGeneration !== request.candidateFenceGeneration || record.operation !== request.operation || record.anchorFingerprint !== request.anchorFingerprint || record.revision !== request.candidateRevision || record.authorityEpoch !== request.candidateAuthorityEpoch || record.tokenConfigGeneration !== request.candidateTokenConfigGeneration || record.mappingGeneration !== request.candidateMappingGeneration || record.attestationFingerprint !== request.candidateAttestationFingerprint)) fail("SF request relation");
  if (baseline && (record.baselineFingerprint !== baseline.baselineFingerprint || record.fenceGeneration !== baseline.fenceGeneration || record.closeFingerprint !== baseline.closeFingerprint || record.authorityCommitSnapshotFingerprint !== baseline.authorityCommitSnapshotFingerprint || record.revision !== baseline.revision || record.authorityEpoch !== baseline.authorityEpoch || record.tokenConfigGeneration !== baseline.tokenConfigGeneration || record.mappingGeneration !== baseline.mappingGeneration || record.attestationFingerprint !== baseline.attestationFingerprint)) fail("SF baseline relation");
  if (reservation !== null) {
    validateAuthorityReservation(reservation, request);
    if (record.authorityReservationFingerprint !== reservation.reservationFingerprint) fail("SF reservation relation");
  }
  if (commit !== null) {
    validateAuthorityCommitSnapshot(commit, reservation, request);
    if (record.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint) fail("SF commit relation");
  }
  if ((reservation === null) !== (commit === null)) fail("SF reservation/commit relation");
  if (authorityEpoch !== null && (reservation === null || commit === null)) fail("SF authority epoch relation");
  if (authorityEpoch !== null) {
    validateAuthorityEpoch(authorityEpoch, request, reservation, commit);
    if (record.authorityEpochFingerprint !== authorityEpoch.authorityEpochFingerprint) fail("SF authority epoch relation");
  }
  assertHash(record, "finalityFingerprint"); return record;
}

export function authoritySuccessorPreviousLeaseBindingFingerprint(request) {
  validateAuthoritySuccessorRequest(request);
  return request.previousReceiptFingerprint;
}
const L2 = ["version", "kind", "txId", "rootGenesisTxId", "requestFingerprint", "fenceGeneration", "readerInstanceId", "readerStartNonce", "readerVersion", "fenceBindingFingerprint", "previousLeaseBindingFingerprint", "leaseBindingFingerprint"];
export function validateAuthoritySuccessorLease(record, request = null, fence = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, L2); assertFence(record);
  if (record.kind !== "authority-successor-lease" || ![record.txId, record.rootGenesisTxId, record.readerInstanceId, record.readerStartNonce].every(opaque) || ![record.requestFingerprint, record.fenceBindingFingerprint, record.previousLeaseBindingFingerprint].every(hex) || record.readerVersion !== 2) fail("L2 fields");
  if (!request || record.previousLeaseBindingFingerprint !== authoritySuccessorPreviousLeaseBindingFingerprint(request)) fail("L2 predecessor relation");
  if (request && (request.readerMode !== "bound-reader" || record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.requestFingerprint !== request.requestFingerprint || record.fenceGeneration !== request.candidateFenceGeneration || record.readerInstanceId !== request.readerInstanceId || record.readerStartNonce !== request.readerStartNonce)) fail("L2 request relation");
  if (fence && (record.txId !== fence.txId || record.rootGenesisTxId !== fence.rootGenesisTxId || record.requestFingerprint !== fence.requestFingerprint || record.fenceGeneration !== fence.fenceGeneration || record.readerInstanceId !== fence.readerInstanceId || record.readerStartNonce !== fence.readerStartNonce || record.readerVersion !== fence.readerVersion || record.fenceBindingFingerprint !== fence.fenceBindingFingerprint)) fail("L2 fence relation");
  assertHash(record, "leaseBindingFingerprint"); return record;
}
const RP2 = ["version", "kind", "txId", "rootGenesisTxId", "requestFingerprint", "fenceGeneration", "finalityFingerprint", "anchorFingerprint", "authorityCommitSnapshotFingerprint", "targetFingerprint", "wrapperFingerprint", "revision", "authorityEpoch", "tokenConfigGeneration", "mappingGeneration", "readerInstanceId", "readerStartNonce", "readerVersion", "readerNonce", "fenceBindingFingerprint", "leaseBindingFingerprint", "readerProjectionFingerprint"];
export function validateAuthoritySuccessorReaderProjection(record, request = null, finality = null, lease = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, RP2); assertFence(record);
  if (record.kind !== "authority-successor-reader-projection" || ![record.txId, record.rootGenesisTxId, record.readerInstanceId, record.readerStartNonce, record.readerNonce].every(opaque) || ![record.requestFingerprint, record.finalityFingerprint, record.anchorFingerprint, record.authorityCommitSnapshotFingerprint, record.targetFingerprint, record.wrapperFingerprint, record.fenceBindingFingerprint, record.leaseBindingFingerprint].every(hex) || ![record.revision, record.authorityEpoch, record.tokenConfigGeneration].every(positive) || !nonNegative(record.mappingGeneration) || record.readerVersion !== 2) fail("RP2 fields");
  if (request && (request.readerMode !== "bound-reader" || record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.requestFingerprint !== request.requestFingerprint || record.fenceGeneration !== request.candidateFenceGeneration || record.anchorFingerprint !== request.anchorFingerprint || record.readerInstanceId !== request.readerInstanceId || record.readerStartNonce !== request.readerStartNonce || record.readerNonce !== request.readerNonce)) fail("RP2 request relation");
  if (finality && (record.txId !== finality.txId || record.rootGenesisTxId !== finality.rootGenesisTxId || record.requestFingerprint !== finality.requestFingerprint || record.finalityFingerprint !== finality.finalityFingerprint || record.fenceGeneration !== finality.fenceGeneration || record.anchorFingerprint !== finality.anchorFingerprint || record.authorityCommitSnapshotFingerprint !== finality.authorityCommitSnapshotFingerprint || record.targetFingerprint !== finality.targetFingerprint || record.wrapperFingerprint !== finality.wrapperFingerprint || record.revision !== finality.revision || record.authorityEpoch !== finality.authorityEpoch || record.tokenConfigGeneration !== finality.tokenConfigGeneration || record.mappingGeneration !== finality.mappingGeneration)) fail("RP2 SF relation");
  if (lease && (record.txId !== lease.txId || record.rootGenesisTxId !== lease.rootGenesisTxId || record.requestFingerprint !== lease.requestFingerprint || record.fenceGeneration !== lease.fenceGeneration || record.readerInstanceId !== lease.readerInstanceId || record.readerStartNonce !== lease.readerStartNonce || record.readerVersion !== lease.readerVersion || record.fenceBindingFingerprint !== lease.fenceBindingFingerprint || record.leaseBindingFingerprint !== lease.leaseBindingFingerprint)) fail("RP2 L2 relation");
  assertHash(record, "readerProjectionFingerprint"); return record;
}
const AK2 = ["version", "kind", "txId", "rootGenesisTxId", "requestFingerprint", "fenceGeneration", "finalityFingerprint", "readerProjectionFingerprint", "leaseBindingFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion", "readerNonce", "ackDisposition", "ackFingerprint"];
export function validateAuthoritySuccessorAck(record, request = null, finality = null, projection = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, AK2); assertFence(record);
  if (record.kind !== "authority-successor-ack" || ![record.txId, record.rootGenesisTxId, record.readerInstanceId, record.readerStartNonce, record.readerNonce].every(opaque) || ![record.requestFingerprint, record.finalityFingerprint, record.readerProjectionFingerprint, record.leaseBindingFingerprint].every(hex) || record.readerVersion !== 2 || record.ackDisposition !== "verified-no-route") fail("AK2 fields");
  if (request && (request.readerMode !== "bound-reader" || record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.requestFingerprint !== request.requestFingerprint || record.fenceGeneration !== request.candidateFenceGeneration || record.readerInstanceId !== request.readerInstanceId || record.readerStartNonce !== request.readerStartNonce || record.readerNonce !== request.readerNonce)) fail("AK2 request relation");
  if (finality && (record.txId !== finality.txId || record.rootGenesisTxId !== finality.rootGenesisTxId || record.requestFingerprint !== finality.requestFingerprint || record.fenceGeneration !== finality.fenceGeneration || record.finalityFingerprint !== finality.finalityFingerprint)) fail("AK2 SF relation");
  if (projection && (record.txId !== projection.txId || record.rootGenesisTxId !== projection.rootGenesisTxId || record.requestFingerprint !== projection.requestFingerprint || record.fenceGeneration !== projection.fenceGeneration || record.finalityFingerprint !== projection.finalityFingerprint || record.readerProjectionFingerprint !== projection.readerProjectionFingerprint || record.leaseBindingFingerprint !== projection.leaseBindingFingerprint || record.readerInstanceId !== projection.readerInstanceId || record.readerStartNonce !== projection.readerStartNonce || record.readerVersion !== projection.readerVersion || record.readerNonce !== projection.readerNonce)) fail("AK2 RP2 relation");
  assertHash(record, "ackFingerprint"); return record;
}

const SRC = ["version", "kind", "sequence", "txId", "rootGenesisTxId", "requestFingerprint", "fenceGeneration", "operation", "previousReceiptFingerprint", "finalityFingerprint", "readerMode", "leaseBindingFingerprint", "readerProjectionFingerprint", "ackFingerprint", "snapshotFingerprint", "revision", "authorityEpoch", "tokenConfigGeneration", "mappingGeneration", "phase", "routeDisposition", "receiptFingerprint"];
export function validateAuthoritySuccessorReceipt(record, request = null, finality = null, lease = null, projection = null, ack = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, SRC); assertFence(record);
  if (record.kind !== "authority-successor-receipt" || !positive(record.sequence) || ![record.txId, record.rootGenesisTxId].every(opaque) || !operations.has(record.operation) || ![record.requestFingerprint, record.previousReceiptFingerprint, record.finalityFingerprint, record.snapshotFingerprint].every(hex) || !readerModes.has(record.readerMode) || ![record.leaseBindingFingerprint, record.readerProjectionFingerprint, record.ackFingerprint].every(nullableHex) || ![record.revision, record.authorityEpoch, record.tokenConfigGeneration].every(positive) || !nonNegative(record.mappingGeneration) || record.phase !== "terminal" || record.routeDisposition !== "no-route") fail("SRC fields");
  if (request && (record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.sequence !== request.sequence || record.fenceGeneration !== request.candidateFenceGeneration || record.operation !== request.operation || record.requestFingerprint !== request.requestFingerprint || record.previousReceiptFingerprint !== request.previousReceiptFingerprint || record.readerMode !== request.readerMode || record.revision !== request.candidateRevision || record.authorityEpoch !== request.candidateAuthorityEpoch || record.tokenConfigGeneration !== request.candidateTokenConfigGeneration || record.mappingGeneration !== request.candidateMappingGeneration)) fail("SRC request relation");
  if (finality && (record.txId !== finality.txId || record.rootGenesisTxId !== finality.rootGenesisTxId || record.requestFingerprint !== finality.requestFingerprint || record.fenceGeneration !== finality.fenceGeneration || record.finalityFingerprint !== finality.finalityFingerprint || record.snapshotFingerprint !== finality.snapshotFingerprint || record.revision !== finality.revision || record.authorityEpoch !== finality.authorityEpoch || record.tokenConfigGeneration !== finality.tokenConfigGeneration || record.mappingGeneration !== finality.mappingGeneration)) fail("SRC SF relation");
  if (record.readerMode === "no-reader") { if ([record.leaseBindingFingerprint, record.readerProjectionFingerprint, record.ackFingerprint].some((value) => value !== null)) fail("SRC no-reader B outputs"); } else if (!lease || !projection || !ack || record.leaseBindingFingerprint !== lease.leaseBindingFingerprint || record.readerProjectionFingerprint !== projection.readerProjectionFingerprint || record.ackFingerprint !== ack.ackFingerprint) fail("SRC B outputs");
  assertHash(record, "receiptFingerprint"); return record;
}

const AH = ["version", "kind", "anchorFingerprint", "sequence", "txId", "rootGenesisTxId", "fenceGeneration", "operation", "phase", "requestFingerprint", "closeFingerprint", "authorityCommitSnapshotFingerprint", "baselineFingerprint", "publicationKFingerprint", "publicationYFingerprint", "finalityFingerprint", "receiptFingerprint", "historyMarkerFingerprint", "previousHeadFingerprint", "previousReceiptFingerprint", "routeDisposition", "headFingerprint"];
export function validateAuthoritySuccessorHead(record, request = null, genesisAuthorityRequest = null) {
  assertGenesisRoot(record, genesisAuthorityRequest);
  assertKeys(record, AH); assertFence(record);
  if (record.kind !== "authority-successor-head" || !hex(record.anchorFingerprint) || !positive(record.sequence) || ![record.txId, record.rootGenesisTxId].every(opaque) || !operations.has(record.operation) || !phases.has(record.phase) || !hex(record.requestFingerprint) || ![record.closeFingerprint, record.authorityCommitSnapshotFingerprint, record.baselineFingerprint, record.publicationKFingerprint, record.publicationYFingerprint, record.finalityFingerprint, record.receiptFingerprint, record.historyMarkerFingerprint, record.previousHeadFingerprint].every(nullableHex) || !hex(record.previousReceiptFingerprint) || record.routeDisposition !== "no-route") fail("AH fields");
  const level = ["reserved", "closed", "replaced", "reader-pending", "terminal"].indexOf(record.phase);
  const required = [[], ["closeFingerprint"], ["closeFingerprint", "authorityCommitSnapshotFingerprint", "baselineFingerprint", "publicationKFingerprint", "publicationYFingerprint"], ["closeFingerprint", "authorityCommitSnapshotFingerprint", "baselineFingerprint", "publicationKFingerprint", "publicationYFingerprint", "finalityFingerprint"], ["closeFingerprint", "authorityCommitSnapshotFingerprint", "baselineFingerprint", "publicationKFingerprint", "publicationYFingerprint", "finalityFingerprint", "receiptFingerprint", "historyMarkerFingerprint"]];
  for (const field of required[level]) if (record[field] === null) fail("AH phase fields");
  if (level < 3 && (record.receiptFingerprint !== null || record.historyMarkerFingerprint !== null)) fail("AH premature terminal");
  if (request && (record.txId !== request.txId || record.rootGenesisTxId !== request.rootGenesisTxId || record.anchorFingerprint !== request.anchorFingerprint || record.sequence !== request.sequence || record.requestFingerprint !== request.requestFingerprint || record.fenceGeneration !== request.candidateFenceGeneration || record.operation !== request.operation)) fail("AH request relation");
  assertHash(record, "headFingerprint"); return record;
}
export function validateAuthoritySuccessorHeadTransition(previous, next, request = null, genesisAuthorityRequest = null) {
  validateAuthoritySuccessorHead(next, request, genesisAuthorityRequest);
  if (previous !== null) assertGenesisRoot(previous, genesisAuthorityRequest);
  const order = ["reserved", "closed", "replaced", "reader-pending", "terminal"];
  if (previous === null) {
    if (next.phase !== "reserved" || next.previousHeadFingerprint !== null) fail("AH genesis transition");
    if (request && (request.previousFenceGeneration !== 1 || next.fenceGeneration !== request.candidateFenceGeneration)) fail("AH genesis fence relation");
    return next;
  }
  validateAuthoritySuccessorHead(previous, null, genesisAuthorityRequest);
  const previousLevel = order.indexOf(previous.phase);
  const nextLevel = order.indexOf(next.phase);
  if (previous.txId === next.txId && previous.sequence === next.sequence) {
    if (nextLevel !== previousLevel + 1 || next.previousHeadFingerprint !== previous.headFingerprint) fail("AH phase transition");
    if (next.fenceGeneration !== previous.fenceGeneration) fail("AH fence replay");
    for (const field of ["anchorFingerprint", "sequence", "txId", "rootGenesisTxId", "operation", "requestFingerprint", "previousReceiptFingerprint", "routeDisposition"]) {
      if (next[field] !== previous[field]) fail("AH immutable transition");
    }
    for (const field of ["closeFingerprint", "authorityCommitSnapshotFingerprint", "baselineFingerprint", "publicationKFingerprint", "publicationYFingerprint", "finalityFingerprint", "receiptFingerprint", "historyMarkerFingerprint"]) {
      if (previous[field] !== null && next[field] !== previous[field]) fail("AH durable transition");
    }
    return next;
  }
  if (previous.phase !== "terminal" || next.phase !== "reserved" ||
      next.sequence !== previous.sequence + 1 ||
      next.previousHeadFingerprint !== previous.headFingerprint ||
      next.previousReceiptFingerprint !== previous.receiptFingerprint ||
      (request && request.previousFenceGeneration !== previous.fenceGeneration) ||
      next.fenceGeneration !== previous.fenceGeneration + 1) fail("AH rolling transition");
  return next;
}

export const buildAuthoritySuccessorRecord = (record, fingerprintField) => { const value = { ...record, [fingerprintField]: null }; value[fingerprintField] = fingerprint(value, fingerprintField); return value; };
export const authoritySuccessorFingerprint = fingerprint;
export function validateAuthoritySuccessorBundle(bundle, genesisAuthorityRequest = null) {
  const { request, close = null, fence = null, baseline = null, commit = null, reservation = null, authorityEpoch = null, publicationK = null, publicationY = null, finality = null, lease = null, projection = null, ack = null, receipt = null, historyMarker = null, historyMarkerSeal = null, head } = bundle ?? {};
  validateAuthoritySuccessorRequest(request, genesisAuthorityRequest); validateAuthoritySuccessorHead(head, request, genesisAuthorityRequest);
  if (close !== null) validateAuthorityCloseProof(close, request, genesisAuthorityRequest);
  if (fence !== null) validateAuthoritySuccessorFence(fence, request, commit, genesisAuthorityRequest);
  if (baseline !== null) validateAuthoritySuccessorBaseline(baseline, request, close, fence, reservation, commit, genesisAuthorityRequest);
  if (finality !== null) validateAuthoritySuccessorFinality(finality, request, baseline, reservation, commit, authorityEpoch, genesisAuthorityRequest);
  if (lease !== null) validateAuthoritySuccessorLease(lease, request, fence, genesisAuthorityRequest);
  if (projection !== null) validateAuthoritySuccessorReaderProjection(projection, request, finality, lease, genesisAuthorityRequest);
  if (ack !== null) validateAuthoritySuccessorAck(ack, request, finality, projection, genesisAuthorityRequest);
  if (genesisAuthorityRequest !== null) {
    const root = rootGenesisTxId(genesisAuthorityRequest);
    for (const publication of [publicationK, publicationY]) {
      if (publication !== null && publication?.genesisTxId !== root) fail("publication Genesis authority root");
    }
  }
  if (receipt !== null) validateAuthoritySuccessorReceipt(receipt, request, finality, lease, projection, ack, genesisAuthorityRequest);
  const candidateRecords = [close, fence, baseline, reservation, commit, publicationK, publicationY, finality, lease, projection, ack, receipt].filter((value) => value !== null);
  for (const record of candidateRecords) assertFence(record, request.candidateFenceGeneration);
  if (["replaced", "reader-pending", "terminal"].includes(head.phase)) {
    if (reservation === null || commit === null) fail("AH authority reservation/commit evidence");
    validateAuthorityReservation(reservation, request);
    validateAuthorityCommitSnapshot(commit, reservation, request);
  }
  if (finality !== null) {
    if (authorityEpoch === null) fail("AH authority epoch evidence");
    validateAuthorityEpoch(authorityEpoch, request, reservation, commit);
  }
  const fields = { closeFingerprint: close?.closeFingerprint ?? null, baselineFingerprint: baseline?.baselineFingerprint ?? null, finalityFingerprint: finality?.finalityFingerprint ?? null, receiptFingerprint: receipt?.receiptFingerprint ?? null };
  for (const [field, value] of Object.entries(fields)) if (head[field] !== value) fail(`AH ${field}`);
  const expectedHistorySequence = head.phase === "terminal" ? head.sequence : head.sequence - 1;
  if (historyMarker === null || historyMarkerSeal === null) fail("AH history evidence");
  validateManagedHistoryMarker(historyMarker, head.anchorFingerprint, expectedHistorySequence);
  validateManagedHistoryMarkerSeal(historyMarker, historyMarkerSeal, head.anchorFingerprint);
  const priorHistory = historyMarker !== null &&
    exact(historyMarker, ["version", "kind", "anchorFingerprint", "sequence", "fenceGeneration", "previousMarkerFingerprint", "markerFingerprint"]) &&
    historyMarker.version === 1 && historyMarker.kind === "managed-history-marker" &&
    historyMarker.anchorFingerprint === head.anchorFingerprint &&
    historyMarker.sequence === head.sequence - 1 &&
    historyMarker.fenceGeneration === request.previousFenceGeneration &&
    nullableHex(historyMarker.previousMarkerFingerprint);
  if (historyMarker !== null && !exact(historyMarker, ["version", "kind", "anchorFingerprint", "sequence", "fenceGeneration", "previousMarkerFingerprint", "markerFingerprint"])) fail("AH history schema");
  if (historyMarker !== null) assertHash(historyMarker, "markerFingerprint");
  if (head.phase !== "terminal" && !priorHistory) fail("AH predecessor history");
  const readerRecords = [fence, lease, projection, ack];
  if (request.readerMode === "no-reader" && readerRecords.some((value) => value !== null)) fail("B no-reader bundle");
  if (request.readerMode === "bound-reader" && fence === null && readerRecords.some((value) => value !== null)) fail("B fence prerequisite");
  if (lease !== null && fence === null) fail("B lease prerequisite");
  if (projection !== null && (fence === null || lease === null || finality === null)) fail("B projection prerequisite");
  if (ack !== null && (projection === null || finality === null)) fail("B ack prerequisite");
  if (head.phase === "reserved" && [close, fence, baseline, commit, publicationK, publicationY, finality, lease, projection, ack, receipt].some((value) => value !== null)) fail("AH reserved bundle");
  if (head.phase === "closed" && (close === null || baseline !== null || commit !== null || publicationK !== null || publicationY !== null || finality !== null || lease !== null || projection !== null || ack !== null || receipt !== null)) fail("AH closed bundle");
  if (["replaced", "reader-pending", "terminal"].includes(head.phase)) {
    if (!commit || commit.authorityCommitSnapshotFingerprint !== head.authorityCommitSnapshotFingerprint ||
        !publicationK || publicationK["publication-kFingerprint"] !== head.publicationKFingerprint ||
        !publicationY || publicationY["publication-yFingerprint"] !== head.publicationYFingerprint) fail("AH replaced proof");
  }
  if (head.phase === "replaced" && (finality !== null || lease !== null || projection !== null || ack !== null || receipt !== null)) fail("AH replaced bundle");
  if (head.phase === "reader-pending" && (finality === null || receipt !== null || !["bound-reader", "no-reader"].includes(request.readerMode) || (request.readerMode === "bound-reader" && fence === null))) fail("AH pending bundle");
  if (head.phase === "terminal" && (finality === null || receipt === null || !historyMarker || !positive(historyMarker.fenceGeneration) || historyMarker.fenceGeneration !== head.fenceGeneration || historyMarker.markerFingerprint !== head.historyMarkerFingerprint || historyMarker.sequence !== head.sequence || (request.readerMode === "bound-reader" && [fence, lease, projection, ack].some((value) => value === null)))) fail("AH terminal bundle");
  return bundle;
}
