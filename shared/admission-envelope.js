import { canonicalJson, canonicalJsonHash, isHex64 } from "./strict-json.js";
import { isOpaqueIdentity } from "./identity.js";
import { validateGenesisReceipt, validateGenesisRequest, validateTokenFloor, validateZFinality } from "./genesis-envelope.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, expected) => plain(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`ADMISSION_ENVELOPE_INVALID: ${message}`); };
const bindGenesisTuple = (genesisRequest, record, label) => {
  validateGenesisRequest(genesisRequest);
  if (genesisRequest.requestedReaderMode !== "handshake" ||
      record.genesisTxId !== genesisRequest.genesisTxId ||
      record.generation !== genesisRequest.generation ||
      record.fenceGeneration !== genesisRequest.fenceGeneration ||
      record.readerInstanceId !== genesisRequest.readerInstanceId ||
      record.readerStartNonce !== genesisRequest.readerStartNonce ||
      record.routeFingerprint !== "no-route") {
    fail(`${label} does not bind Genesis reader tuple`);
  }
  return record;
};
const recordHash = (record, field) => canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
const positiveFence = (value) => Number.isSafeInteger(value) && value >= 1;
const branch = (request, rp, ak) => request.requestedReaderMode === "no-reader" ? rp === null && ak === null : isHex64(rp) && isHex64(ak);

const requestKeys = ["version", "kind", "requestId", "genesisTxId", "generation", "fenceGeneration", "readerInstanceId", "readerStartNonce", "routeFingerprint", "nonce", "expiresAt", "requestFingerprint"];
export function validateAdmissionRequest(request) {
  if (!exact(request, requestKeys) || request.version !== 1 || request.kind !== "admission-request") fail("request schema");
  for (const key of ["requestId", "genesisTxId", "readerInstanceId", "readerStartNonce", "routeFingerprint", "nonce"]) if (!isOpaqueIdentity(request[key])) fail(`${key} relation`);
  if (!Number.isSafeInteger(request.generation) || request.generation < 1 || !positiveFence(request.fenceGeneration) || !Number.isSafeInteger(request.expiresAt) || request.expiresAt < 0 || !isHex64(request.requestFingerprint)) fail("request generation, fence, expiry, or hash");
  if (recordHash(request, "requestFingerprint") !== request.requestFingerprint) fail("request fingerprint");
  return request;
}

const grantKeys = ["version", "kind", "grantId", "requestFingerprint", "genesisTxId", "generation", "fenceGeneration", "readerInstanceId", "readerStartNonce", "routeFingerprint", "nonce", "expiresAt", "grantFingerprint"];
export function validateAdmissionGrant(grant, request, now = null, consumedGrantIds = new Set()) {
  if (!exact(grant, grantKeys) || grant.version !== 1 || grant.kind !== "admission-grant") fail("grant schema");
  validateAdmissionRequest(request);
  for (const key of ["requestFingerprint", "genesisTxId", "readerInstanceId", "readerStartNonce", "routeFingerprint", "nonce", "grantFingerprint"]) if ((key === "requestFingerprint" || key === "grantFingerprint") ? !isHex64(grant[key]) : !isOpaqueIdentity(grant[key])) fail(`${key} relation`);
  if (!isOpaqueIdentity(grant.grantId) || !Number.isSafeInteger(grant.generation) || !positiveFence(grant.fenceGeneration) || !Number.isSafeInteger(grant.expiresAt)) fail("grant id, generation, fence, or expiry");
  for (const key of ["requestFingerprint", "genesisTxId", "generation", "fenceGeneration", "readerInstanceId", "readerStartNonce", "routeFingerprint", "nonce", "expiresAt"]) if (grant[key] !== request[key]) fail("grant does not bind request");
  if (now !== null && (!Number.isSafeInteger(now) || grant.expiresAt < now)) fail("expired grant");
  if (consumedGrantIds.has(grant.grantId)) fail("replayed grant");
  if (recordHash(grant, "grantFingerprint") !== grant.grantFingerprint) fail("grant fingerprint");
  return grant;
}

const ackKeys = ["version", "kind", "grantFingerprint", "grantId", "genesisTxId", "generation", "fenceGeneration", "readerInstanceId", "readerStartNonce", "routeFingerprint", "readerProjectionFingerprint", "nonce", "ackFingerprint"];
export function validateAdmissionAckRecord(ack) {
  if (!exact(ack, ackKeys) || ack.version !== 1 || ack.kind !== "admission-ack") fail("ack schema");
  for (const key of ["grantFingerprint", "ackFingerprint", "readerProjectionFingerprint"]) if (!isHex64(ack[key])) fail("ack hashes");
  for (const key of ["grantId", "genesisTxId", "readerInstanceId", "readerStartNonce", "routeFingerprint", "nonce"]) if (!isOpaqueIdentity(ack[key])) fail("ack relation");
  if (!Number.isSafeInteger(ack.generation) || ack.generation < 1 || !positiveFence(ack.fenceGeneration) || recordHash(ack, "ackFingerprint") !== ack.ackFingerprint) fail("ack fingerprint");
  return ack;
}

export function validateAdmissionAck(ack, grant, projectionFingerprint) {
  validateAdmissionAckRecord(ack);
  if (!exact(grant, grantKeys) || grant.version !== 1 || grant.kind !== "admission-grant" || !isHex64(grant.grantFingerprint) || recordHash(grant, "grantFingerprint") !== grant.grantFingerprint) fail("grant fingerprint");
  for (const key of ["grantFingerprint", "grantId", "genesisTxId", "generation", "fenceGeneration", "readerInstanceId", "readerStartNonce", "routeFingerprint", "nonce"]) if (ack[key] !== grant[key]) fail("ack does not bind grant");
  if (ack.readerProjectionFingerprint !== projectionFingerprint) fail("ack projection mismatch");
  if (recordHash(ack, "ackFingerprint") !== ack.ackFingerprint) fail("ack fingerprint");
  return ack;
}
export function validateAdmissionGenesisBinding(genesisRequest, admissionRequest, admissionGrant = null, admissionAck = null, projectionFingerprint = null, now = null) {
  bindGenesisTuple(genesisRequest, validateAdmissionRequest(admissionRequest), "admission request");
  if (admissionGrant !== null) {
    validateAdmissionGrant(admissionGrant, admissionRequest, now);
    bindGenesisTuple(genesisRequest, admissionGrant, "admission grant");
  }
  if (admissionAck !== null) {
    if (projectionFingerprint === null) validateAdmissionAckRecord(admissionAck);
    else validateAdmissionAck(admissionAck, admissionGrant, projectionFingerprint);
    bindGenesisTuple(genesisRequest, admissionAck, "admission acknowledgement");
    if (admissionGrant === null || admissionAck.grantFingerprint !== admissionGrant.grantFingerprint ||
        admissionAck.grantId !== admissionGrant.grantId || admissionAck.nonce !== admissionGrant.nonce) {
      fail("admission acknowledgement does not bind grant");
    }
  }
  return { request: admissionRequest, grant: admissionGrant, ack: admissionAck };
}
export function validateAdmissionRecordPair(current, immutable, { allowMissingCurrent = false, label = "admission record" } = {}) {
  if (current === undefined || immutable === undefined) fail(`${label} presence is ambiguous`);
  if (current === null && immutable === null) return null;
  if (current !== null && immutable === null) fail(`${label} archive is absent`);
  if (immutable !== null && current === null) {
    if (!allowMissingCurrent) fail(`${label} current record is absent`);
    return immutable;
  }
  if (canonicalJson(current) !== canonicalJson(immutable)) fail(`${label} current/archive mismatch`);
  return current;
}

const proofKeys = ["version", "kind", "genesisTxId", "generation", "fenceGeneration", "zFinalityFingerprint", "readerProjectionFingerprint", "ackFingerprint", "routeFingerprint", "finalityProofFingerprint"];
export function validateFinalityProof(proof, request, zf, ack = null, projectionFingerprint = null) {
  if (!exact(proof, proofKeys) || proof.version !== 1 || proof.kind !== "finality-proof") fail("finality proof schema");
  validateGenesisRequest(request);
  if (proof.genesisTxId !== request.genesisTxId || proof.generation !== request.generation || !positiveFence(proof.fenceGeneration) || proof.fenceGeneration !== request.fenceGeneration || proof.fenceGeneration !== zf.fenceGeneration || proof.zFinalityFingerprint !== zf.zFinalityFingerprint || !isHex64(proof.zFinalityFingerprint) || !isOpaqueIdentity(proof.routeFingerprint) || !isHex64(proof.finalityProofFingerprint)) fail("finality proof relation");
  if (!branch(request, proof.readerProjectionFingerprint, proof.ackFingerprint) || (request.requestedReaderMode === "no-reader" && proof.routeFingerprint !== "no-route")) fail("finality proof reader branch");
  if (request.requestedReaderMode === "handshake") {
    validateAdmissionAckRecord(ack);
    if (proof.ackFingerprint !== ack.ackFingerprint || proof.readerProjectionFingerprint !== projectionFingerprint) fail("finality proof acknowledgement relation");
  }
  if (recordHash(proof, "finalityProofFingerprint") !== proof.finalityProofFingerprint) fail("finality proof fingerprint");
  return proof;
}

export function isRouteAdmissionEligible({ request, tokenFloor, zFinality, proof, receipt, admissionOpen, routeFingerprint, ack = null, projectionFingerprint = null }) {
  try {
    validateGenesisRequest(request); validateTokenFloor(tokenFloor); validateZFinality(zFinality, request, tokenFloor);
    validateFinalityProof(proof, request, zFinality, ack, projectionFingerprint);
    validateGenesisReceipt(receipt, request, zFinality, proof);
    return admissionOpen === true && proof.routeFingerprint === routeFingerprint;
  } catch { return false; }
}

export const admissionRecordFingerprint = recordHash;

export function buildAdmissionRequest(input) {
  const request = { version: 1, kind: "admission-request", ...input, requestFingerprint: null };
  request.requestFingerprint = recordHash(request, "requestFingerprint");
  return validateAdmissionRequest(request);
}

export function buildAdmissionGrant(request, { grantId, expiresAt }) {
  validateAdmissionRequest(request);
  const grant = { version: 1, kind: "admission-grant", grantId, requestFingerprint: request.requestFingerprint, genesisTxId: request.genesisTxId, generation: request.generation, fenceGeneration: request.fenceGeneration, readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce, routeFingerprint: request.routeFingerprint, nonce: request.nonce, expiresAt, grantFingerprint: null };
  grant.grantFingerprint = recordHash(grant, "grantFingerprint");
  return validateAdmissionGrant(grant, request);
}

export function buildAdmissionAck(grant, readerProjectionFingerprint) {
  const ack = { version: 1, kind: "admission-ack", grantFingerprint: grant.grantFingerprint, grantId: grant.grantId, genesisTxId: grant.genesisTxId, generation: grant.generation, fenceGeneration: grant.fenceGeneration, readerInstanceId: grant.readerInstanceId, readerStartNonce: grant.readerStartNonce, routeFingerprint: grant.routeFingerprint, readerProjectionFingerprint, nonce: grant.nonce, ackFingerprint: null };
  ack.ackFingerprint = recordHash(ack, "ackFingerprint");
  return validateAdmissionAck(ack, grant, readerProjectionFingerprint);
}
