import { randomUUID } from "node:crypto";
import { assertStrictText, canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { isPrincipal } from "@gjc-remote/shared/identity";
import { fingerprintManagedMappingRecord, fingerprintManagedRouteRecord, managedHostSetFingerprint, parseManagedHostTokens, validateManagedChannelsV2, validateManagedMappingRecord } from "@gjc-remote/shared/mapping-envelope";
import { attestTokenFloor, authorityRecordFingerprint, advanceReaderVersionFloor, buildAttestedTokenFloorProof, buildGenesisPrecommit, commitTokenFloor, reserveTokenGeneration, validateAuthorityCommitSnapshot, validateAuthorityEpoch, validateAuthorityReservation, validateBaselineSnapshot, validateFenceBinding, validateGenesisAuthorityReceipt, validateGenesisAuthorityRequest, validateGenesisRequest, validateGenesisReceipt, validateReaderProjection, validateReaderVersionFloor, validateTokenConfigAttestation, validateTokenFloor, validateTokenFloorReservation, validateZFinality } from "@gjc-remote/shared/genesis-envelope";
import { addCredential, authenticate, bootstrapOwner, revokeCredential, rotateCredential, requireOwner } from "./management-auth.js";
import { buildAdmissionGrant, buildAdmissionRequest, validateAdmissionAck, validateFinalityProof } from "@gjc-remote/shared/admission-envelope";
import { validateGenesisSuffixRecovery } from "@gjc-remote/shared/recovery-envelope";
import { buildPublicationC, buildPublicationK, buildPublicationP, buildPublicationQ, buildPublicationS, buildPublicationState, buildPublicationTransaction, buildPublicationU, buildPublicationY, buildPublicationZp, validatePublicationC, validatePublicationK, validatePublicationP, validatePublicationQ, validatePublicationS, validatePublicationY, validatePublicationZp } from "@gjc-remote/shared/publication-envelope";
import { buildAuthoritySuccessorRecord, validateAuthorityCloseProof, validateAuthoritySuccessorBundle, validateAuthoritySuccessorFence, validateAuthoritySuccessorFinality, validateAuthoritySuccessorHeadTransition, validateAuthoritySuccessorReceipt, validateAuthoritySuccessorRequest } from "@gjc-remote/shared/successor-envelope";

export const EXIT = Object.freeze({ OK: 0, USAGE: 2, AUTH: 3, CONFLICT: 4, NATIVE: 5, INVALID: 6, RECOVERY: 7, INTERNAL: 70 });
const LOCK_ORDER = ["genesis", "mapping", "admission"];
const MAX_MAPPING_BYTES = 1024 * 1024;
const emptyState = () => ({ version: 1, revision: 0, authorityEpoch: 0, fenceGeneration: 1, tokenConfigGeneration: 0, mappingGeneration: 0, roleBindings: null, mappings: {}, routes: {}, tokenAttestation: null, recovery: null, genesis: null, admission: { phase: "closed", finalityFingerprint: null } });
const safe = (error) => ({ code: /^[A-Z0-9_]+$/.test(error?.code ?? "") ? error.code : /^[A-Z0-9_]+$/.test(error?.message ?? "") ? error.message : "MANAGEMENT_FAILED" });
const principal = (value, name) => { if (!isPrincipal(value)) throw new Error(`${name}_INVALID`); return value; };
const protectedTokenFingerprint = (value) => managedHostSetFingerprint(parseManagedHostTokens(value));
const recordHash = (record, field) => canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
const assertCommittedTokenLineage = (lineage, finality, baseline, { requireSuccessorFence = false, successorTxId = null } = {}) => {
  const floor = lineage?.floor;
  const attestation = lineage?.attestation;
  if (!floor || !attestation ||
      floor.floorFingerprint !== finality.tokenFloorFingerprint ||
      floor.anchorFingerprint !== finality.anchorFingerprint ||
      (requireSuccessorFence && floor.fenceGeneration !== finality.fenceGeneration) ||
      floor.floorPhase !== "committed" ||
      floor.highestCommittedGeneration !== finality.tokenConfigGeneration ||
      floor.highestReservedGeneration !== finality.tokenConfigGeneration ||
      floor.lastAttestationFingerprint !== attestation.attestationFingerprint ||
      floor.fenceGeneration !== attestation.fenceGeneration ||
      floor.lastCommittedTxId !== attestation.txId ||
      (successorTxId !== null && floor.lastCommittedTxId !== successorTxId) ||
      attestation.anchorFingerprint !== finality.anchorFingerprint ||
      (requireSuccessorFence && attestation.fenceGeneration !== finality.fenceGeneration) ||
      attestation.tokenConfigGeneration !== finality.tokenConfigGeneration ||
      (successorTxId !== null && attestation.txId !== successorTxId) ||
      attestation.attestationFingerprint !== finality.attestationFingerprint ||
      attestation.tokenConfigHostSetFingerprint !== baseline.tokenConfigHostSetFingerprint) {
    throw new Error("SUCCESSOR_TOKEN_LINEAGE_INVALID");
  }
  return lineage;
};
const validateCommittedTokenLineage = (lineage) => {
  const floor = lineage?.floor;
  const attestation = lineage?.attestation;
  try {
    validateTokenFloor(floor);
    validateTokenConfigAttestation(attestation);
  } catch {
    throw new Error("MANUAL_CLEANUP_DURABILITY_FAILED");
  }
  if (floor.floorPhase !== "committed" ||
      floor.highestReservedGeneration !== floor.highestCommittedGeneration ||
      floor.lastAttestationFingerprint !== attestation.attestationFingerprint ||
      floor.lastCommittedTxId !== attestation.txId ||
      floor.fenceGeneration !== attestation.fenceGeneration ||
      floor.anchorFingerprint !== attestation.anchorFingerprint ||
      attestation.tokenConfigGeneration !== floor.highestCommittedGeneration) {
    throw new Error("MANUAL_CLEANUP_DURABILITY_FAILED");
  }
  return lineage;
};
const validateManagedHistoryMarker = (marker, anchorFingerprint, expectedSequence = undefined) => {
  if (!marker || Object.getPrototypeOf(marker) !== Object.prototype ||
      Object.keys(marker).sort().join(',') !== 'anchorFingerprint,fenceGeneration,kind,markerFingerprint,previousMarkerFingerprint,sequence,version' ||
      marker.version !== 1 || marker.kind !== 'managed-history-marker' ||
      typeof marker.anchorFingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(marker.anchorFingerprint) ||
      !Number.isSafeInteger(marker.fenceGeneration) || marker.fenceGeneration < 1 ||
      !Number.isSafeInteger(marker.sequence) || marker.sequence < 1 ||
      (marker.sequence === 1 ? marker.previousMarkerFingerprint !== null : !/^[a-f0-9]{64}$/.test(marker.previousMarkerFingerprint)) ||
      typeof marker.markerFingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(marker.markerFingerprint) ||
      marker.markerFingerprint !== recordHash(marker, 'markerFingerprint') ||
      marker.anchorFingerprint !== anchorFingerprint ||
      (expectedSequence !== undefined && marker.sequence !== expectedSequence)) {
    throw new Error('MANAGED_HISTORY_MARKER_REQUIRED');
  }
  return marker;
};
const AUTH_IDEMPOTENCY_KEY_MAX_LENGTH = 256;
const AUTH_MUTATION_COMMANDS = new Set(["auth-add", "auth-rotate", "auth-revoke"]);
const validAuthIdempotencyKey = (value) => {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    assertStrictText(value, "idempotency key", AUTH_IDEMPOTENCY_KEY_MAX_LENGTH);
    return true;
  } catch {
    return false;
  }
};
const authMutationIntentFingerprint = ({ action, actorPrincipal, targetPrincipal, targetSecret }) => canonicalJsonHash({
  version: 1,
  kind: "management-auth-mutation-intent",
  action,
  actorPrincipalFingerprint: canonicalJsonHash(actorPrincipal),
  targetPrincipalFingerprint: canonicalJsonHash(targetPrincipal),
  targetSecretFingerprint: targetSecret === undefined ? null : canonicalJsonHash(targetSecret),
});
const authMutationRecords = (auth) => {
  if (auth.idempotency === undefined) auth.idempotency = {};
  if (!auth.idempotency || Object.getPrototypeOf(auth.idempotency) !== Object.prototype) {
    throw new Error("IDEMPOTENCY_RECORD_INVALID");
  }
  return auth.idempotency;
};
const authMutationRecord = ({ idempotencyKey, action, intentFingerprint, actorPrincipal, targetPrincipal, result, beforeFingerprint, afterFingerprint }) => ({
  version: 1,
  kind: "management-auth-idempotency-record",
  idempotencyKey,
  action,
  intentFingerprint,
  actorPrincipalFingerprint: canonicalJsonHash(actorPrincipal),
  targetPrincipalFingerprint: canonicalJsonHash(targetPrincipal),
  result: structuredClone(result),
  authBeforeFingerprint: beforeFingerprint,
  authAfterFingerprint: afterFingerprint,
});
const validAuthMutationRecord = (record, key) =>
  record && Object.getPrototypeOf(record) === Object.prototype &&
  record.version === 1 && record.kind === "management-auth-idempotency-record" &&
  record.idempotencyKey === key &&
  typeof record.action === "string" &&
  /^[a-f0-9]{64}$/.test(record.intentFingerprint) &&
  /^[a-f0-9]{64}$/.test(record.actorPrincipalFingerprint) &&
  /^[a-f0-9]{64}$/.test(record.targetPrincipalFingerprint) &&
  /^[a-f0-9]{64}$/.test(record.authBeforeFingerprint) &&
  /^[a-f0-9]{64}$/.test(record.authAfterFingerprint) &&
  record.result && Object.getPrototypeOf(record.result) === Object.prototype &&
  Object.keys(record.result).length === 1 &&
  Number.isSafeInteger(record.result.epoch) &&
  record.result.epoch > 0;
const normalizedGenesisSecurityTuple = ({
  anchorFingerprint,
  actorPrincipal,
  targetPrincipal,
  roleBindings,
  generation,
  managementProvisioningFingerprint,
  botProvisioningFingerprint,
  recoveryProvisioningFingerprint,
  protectedHostTokensHostSetFingerprint,
  idempotencyKey,
  targetInputIntent,
  requestedReaderMode,
  readerInstanceId,
  readerStartNonce,
}) => ({
  version: 1,
  kind: "genesis-security-tuple",
  anchorFingerprint,
  generation,
  actorPrincipalFingerprint: canonicalJsonHash(actorPrincipal),
  ownerPrincipalFingerprint: canonicalJsonHash(actorPrincipal),
  targetPrincipalFingerprint: canonicalJsonHash(targetPrincipal),
  managementRole: roleBindings.managementSid,
  botRole: roleBindings.botSid,
  recoveryRole: roleBindings.recoverySid,
  managementProvisioningFingerprint,
  botProvisioningFingerprint,
  recoveryProvisioningFingerprint,
  protectedHostTokensHostSetFingerprint,
  idempotencyKey,
  targetInputIntent,
  requestedReaderMode,
  readerInstanceId,
  readerStartNonce,
});
const comparableGenesisSecurityTuple = (tuple) => {
  const {
    targetInputState,
    targetFingerprint,
    targetIdentityFingerprint,
    targetAclFingerprint,
    legacyTargetProofFingerprint,
    legacyTargetProof,
    ...inputTuple
  } = tuple ?? {};
  return inputTuple;
};
const sameGenesisSecurityTuple = (left, right) =>
  canonicalJsonHash(comparableGenesisSecurityTuple(left)) === canonicalJsonHash(comparableGenesisSecurityTuple(right));
const stableGenesisProbe = (tuple) => {
  const replayFingerprint = canonicalJsonHash(tuple);
  const uuidHex = `${replayFingerprint.slice(0, 12)}5${replayFingerprint.slice(13, 16)}8${replayFingerprint.slice(17, 32)}`;
  return {
    replayFingerprint,
    txId: `${uuidHex.slice(0, 8)}-${uuidHex.slice(8, 12)}-${uuidHex.slice(12, 16)}-${uuidHex.slice(16, 20)}-${uuidHex.slice(20, 32)}`,
  };
};
const exactRoleBindings = (management, bot, recovery) => {
  if (![management, bot, recovery].every(isPrincipal) ||
      new Set([management.kind, bot.kind, recovery.kind]).size !== 1 ||
      !["sid", "uid"].includes(management.kind)) {
    throw new Error("GENESIS_ROLE_BINDING_INVALID");
  }
  return {
    managementSid: management.value,
    botSid: bot.value,
    recoverySid: recovery.value,
    systemSid: management.kind === "sid" ? "S-1-5-18" : "uid:0",
  };
};
const boundedMapping = (mapping) => {
  if (!mapping || typeof mapping !== "object") throw new Error("MAPPING_INVALID");
  try {
    if (Buffer.byteLength(JSON.stringify(mapping), "utf8") > MAX_MAPPING_BYTES) throw new Error("MAPPING_INVALID");
  } catch { throw new Error("MAPPING_INVALID"); }
  return mapping;
};
const validMappingCandidate = (mapping) => {
  try {
    validateManagedMappingRecord(mapping);
    return typeof mapping.workspaceId === "string" && mapping.workDir === null;
  } catch {
    return false;
  }
};
const redactAudit = (value) => {
  if (Array.isArray(value)) return value.map(redactAudit);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      /secret|token|password|path|stdin/i.test(key) ? "[redacted]" : redactAudit(item),
    ])
  );
};
const channelsSnapshot = (state, revision = state.revision, authorityEpoch = state.authorityEpoch) => {
  const snapshot = {
    version: 2, managementStamp: "gjc-management-channels/v2", revision, authorityEpoch,
    fenceGeneration: state.fenceGeneration, mappingGeneration: state.mappingGeneration, tokenConfigGeneration: state.tokenConfigGeneration,
    tokenConfigHostSetFingerprint: state.tokenAttestation?.fingerprint, targetState: Object.keys(state.routes ?? {}).length ? "managed" : "managed-empty",
    dispatchClass: "workspace-only", mappings: structuredClone(state.mappings), routes: structuredClone(state.routes ?? {}), configFingerprint: null,
  };
  snapshot.configFingerprint = recordHash(snapshot, "configFingerprint");
  return validateManagedChannelsV2(snapshot);
};
const publicationGraph = ({ txId, genesisTxId, generation, fenceGeneration, baseline, targetFingerprint, stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint, checkpointFingerprint }) => {
  const transaction = buildPublicationTransaction({ txId, genesisTxId, generation, fenceGeneration, baselineFingerprint: baseline.baselineFingerprint });
  const u = buildPublicationU({
    txId, genesisTxId, generation, fenceGeneration, baselineFingerprint: baseline.baselineFingerprint,
    anchorFingerprint: baseline.anchorFingerprint, targetState: baseline.targetState,
    attestationFingerprint: baseline.attestationFingerprint,
    authorityReservationFingerprint: baseline.authorityReservationFingerprint,
    authorityCommitSnapshotFingerprint: baseline.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: baseline.fenceBindingFingerprint,
    leaseBindingFingerprint: baseline.leaseBindingFingerprint,
    readerProjectionFingerprint: baseline.readerProjectionFingerprint,
    readerInstanceId: baseline.readerInstanceId, readerStartNonce: baseline.readerStartNonce, readerVersion: baseline.readerVersion,
  });
  const p = buildPublicationP({
    txId, genesisTxId, generation, fenceGeneration, uFingerprint: u["publication-uFingerprint"], stateFingerprint,
    targetState: u.targetState, authorityCommitSnapshotFingerprint: u.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: u.fenceBindingFingerprint, leaseBindingFingerprint: u.leaseBindingFingerprint,
    readerInstanceId: u.readerInstanceId, readerStartNonce: u.readerStartNonce, readerVersion: u.readerVersion,
  });
  const s = buildPublicationS({
    txId, genesisTxId, generation, fenceGeneration, pFingerprint: p["publication-pFingerprint"], stateFingerprint,
    payloadFingerprint, targetState: p.targetState,
    authorityCommitSnapshotFingerprint: p.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: p.fenceBindingFingerprint, readerVersion: p.readerVersion,
  });
  const phase = (value) => buildPublicationState({ txId, genesisTxId, generation, fenceGeneration, publicationFingerprint, phase: value });
  const prepared = phase("prepared");
  const replaced = phase("replaced");
  const c = buildPublicationC({
    txId, genesisTxId, generation, fenceGeneration, sFingerprint: s["publication-sFingerprint"], stateFingerprint,
    payloadFingerprint, snapshotFingerprint,
    authorityCommitSnapshotFingerprint: s.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: s.fenceBindingFingerprint,
    readerInstanceId: p.readerInstanceId, readerStartNonce: p.readerStartNonce, readerVersion: s.readerVersion,
  });
  const q = buildPublicationQ({
    txId, genesisTxId, generation, fenceGeneration, cFingerprint: c["publication-cFingerprint"], baselineFingerprint: baseline.baselineFingerprint,
    stateFingerprint: c.stateFingerprint, payloadFingerprint: c.payloadFingerprint, snapshotFingerprint: c.snapshotFingerprint,
    authorityCommitSnapshotFingerprint: c.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: c.fenceBindingFingerprint,
  });
  const zp = buildPublicationZp({
    txId, genesisTxId, generation, fenceGeneration, qFingerprint: q["publication-qFingerprint"], publicationFingerprint,
    stateFingerprint: q.stateFingerprint, payloadFingerprint: q.payloadFingerprint, snapshotFingerprint: q.snapshotFingerprint,
  });
  const k = buildPublicationK({
    txId, genesisTxId, generation, fenceGeneration, zpFingerprint: zp["publication-zpFingerprint"], publicationFingerprint,
    authorityCommitSnapshotFingerprint: q.authorityCommitSnapshotFingerprint, checkpointFingerprint,
  });
  const y = buildPublicationY({
    txId, genesisTxId, generation, fenceGeneration, kFingerprint: k["publication-kFingerprint"], publicationFingerprint,
    targetState: baseline.targetState, authorityCommitSnapshotFingerprint: k.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: q.fenceBindingFingerprint, targetFingerprint,
  });
  const committed = buildPublicationState({ txId, genesisTxId, generation, fenceGeneration, publicationFingerprint, phase: "committed" });
  validatePublicationP(p, u, stateFingerprint);
  validatePublicationS(s, p, { stateFingerprint, payloadFingerprint });
  validatePublicationC(c, s, { stateFingerprint, payloadFingerprint, snapshotFingerprint });
  validatePublicationQ(q, c, { stateFingerprint, payloadFingerprint, snapshotFingerprint });
  validatePublicationZp(zp, q, { stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint });
  validatePublicationK(k, zp, { publicationFingerprint, checkpointFingerprint });
  validatePublicationY(y, k, targetFingerprint, publicationFingerprint);
  return { transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y };
};

export class ManagementRuntime {
  constructor({ native }) { this.native = native; }

  async execute(command, input) {
    try {
      if (AUTH_MUTATION_COMMANDS.has(command) && !validAuthIdempotencyKey(input?.idempotencyKey)) {
        throw new Error("IDEMPOTENCY_KEY_REQUIRED");
      }
      this.#assertNative();
      await this.#configureRoles(command, input);
      const outcome = command === "genesis" ? await this.#genesis(input) : await this.#authenticated(command, input);
      return { exitCode: EXIT.OK, ok: true, ...outcome };
    } catch (error) {
      const code = safe(error).code;
      return { exitCode: code.includes("AUTH") || code.includes("OWNER") ? EXIT.AUTH : code.includes("CONFLICT") ? EXIT.CONFLICT : code.includes("NATIVE") ? EXIT.NATIVE : code.includes("RECOVERY") || code.includes("MANUAL_CLEANUP") ? EXIT.RECOVERY : code.includes("INVALID") || code.includes("REQUIRED") ? EXIT.INVALID : EXIT.INTERNAL, ok: false, error: code, routeDisposition: "no-route" };
    }
  }

  #assertNative() {
    const methods = ["readManagementState", "compareAndSwapManagementState", "readManagementAuth", "compareAndSwapManagementAuth", "readManagedHistoryMarker", "commitManagedHistoryMarker", "configureManagementRoles", "currentOsPrincipal", "managementAnchorFingerprint", "withManagementLocks", "probeProspectiveCleanup", "writeGenesisAuthorityRequest", "writeGenesisAuthorityReceipt", "reserveFenceGeneration", "commitFenceGeneration", "readFenceGenerationFloor", "reserveAuthorityEpoch", "commitAuthorityEpoch", "writeAuthorityReservation", "writeAuthorityCommitSnapshot", "writeAuthorityBaseline", "writeReaderFenceBinding", "casReaderVersionFloor", "reserveTokenFloor", "writeTokenConfigAttestation", "writeAttestedTokenFloor", "writeGenesisRequest", "commitTokenFloor", "writePublicationGraph", "writeZFinality", "writeAdmissionRequest", "writeAdmissionGrant", "readBoundReaderProof", "readSuccessorTokenLineage", "readAuthoritySuccessorHeadRaw", "completePendingGenesis", "writeFinalityProof", "writeGenesisReceipt", "recheckAdmissionFinality", "publishMapping", "reopenAdmission", "revokeMapping", "writeMappingGeneration", "readMappingGeneration", "writeMappingTombstone", "writeMappingHandoffReceipt", "mappingTargetProof", "recoverGenesisSuffix", "appendAudit", "terminalCloseOrManualCleanup", "rotateTokenSidecar"];
    for (const method of methods) if (typeof this.native?.[method] !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
  }
  async #configureRoles(command, input) {
    let bindings;
    if (command === "genesis") {
      bindings = exactRoleBindings(input.actorPrincipal, input.botPrincipal, input.recoveryPrincipal);
    } else {
      const state = await this.native.readManagementState();
      bindings = state?.roleBindings;
      if (!bindings) throw new Error("MANAGEMENT_ROLE_BINDING_REQUIRED");
    }
    await this.native.configureManagementRoles(bindings);
  }

  async #read() {
    const state = await this.native.readManagementState();
    return state ?? emptyState();
  }
  async #readAuthorityEpochFloor() {
    if (typeof this.native.readAuthorityEpochFloor !== "function") return null;
    return this.native.readAuthorityEpochFloor();
  }
  async #nextAuthorityEpoch(state) {
    const floor = await this.#readAuthorityEpochFloor();
    const highest = Number.isSafeInteger(floor?.highestReservedAuthorityEpoch)
      ? floor.highestReservedAuthorityEpoch
      : state.authorityEpoch;
    if (!Number.isSafeInteger(highest) || highest < 0 || highest >= Number.MAX_SAFE_INTEGER) {
      throw new Error("AUTHORITY_EPOCH_FLOOR_INVALID");
    }
    return highest + 1;
  }
  async #committedAuthorityEpoch(state) {
    if (typeof this.native.readAuthorityEpoch === "function") {
      const epoch = await this.native.readAuthorityEpoch();
      if (Number.isSafeInteger(epoch?.epoch) && epoch.epoch > 0) return epoch.epoch;
    }
    return state.authorityEpoch;
  }
  async #readAuth() {
    const auth = await this.native.readManagementAuth();
    if (!auth) throw new Error("MANAGEMENT_AUTH_REQUIRED");
    return structuredClone(auth);
  }

  async #authenticatedState(state) {
    if (Object.hasOwn(state, "auth")) throw new Error("MANAGEMENT_AUTH_MIGRATION_REQUIRED");
    return { ...state, auth: await this.#readAuth() };
  }

  async #audit(entry) {
    return this.native.appendAudit(redactAudit(entry));
  }
  async #commitGenesisHistory(anchorFingerprint, { allowCreate = false } = {}) {
    const existing = await this.native.readManagedHistoryMarker();
    if (existing !== null) {
      validateManagedHistoryMarker(existing, anchorFingerprint, 1);
      return existing;
    }
    if (!allowCreate) throw new Error("MANAGED_HISTORY_MARKER_REQUIRED");
    const marker = {
      version: 1,
      kind: "managed-history-marker",
      anchorFingerprint,
      fenceGeneration: 1,
      sequence: 1,
      previousMarkerFingerprint: null,
      markerFingerprint: null,
    };
    marker.markerFingerprint = recordHash(marker, "markerFingerprint");
    const committed = await this.native.commitManagedHistoryMarker(marker);
    const reopened = await this.native.readManagedHistoryMarker();
    validateManagedHistoryMarker(committed, anchorFingerprint, 1);
    validateManagedHistoryMarker(reopened, anchorFingerprint, 1);
    if (canonicalJsonHash(committed) !== canonicalJsonHash(marker) ||
        canonicalJsonHash(reopened) !== canonicalJsonHash(marker)) {
      throw new Error("MANAGED_HISTORY_MARKER_REQUIRED");
    }
    return marker;
  }
  async #persistGenesisHandshakePending(state, { replayFingerprint, generation, hostSetFingerprint, admissionRequest, admissionGrant }) {
    const before = state.revision;
    state.recovery = {
      ...state.recovery,
      phase: "handshake-pending",
      replayFingerprint,
      generation,
      hostSetFingerprint,
      routeDisposition: "no-route",
      readerHandshake: {
        requestFingerprint: admissionRequest.requestFingerprint,
        grantFingerprint: admissionGrant.grantFingerprint,
        expiresAt: admissionGrant.expiresAt,
        request: structuredClone(admissionRequest),
        grant: structuredClone(admissionGrant),
      },
    };
    state.admission = { phase: "closed", finalityFingerprint: null };
    state.revision = before + 1;
    if (!await this.native.compareAndSwapManagementState(before, state)) throw new Error("MANUAL_CLEANUP_REQUIRED");
  }
  async #finalizeRecoveredGenesis(anchorFingerprint, completed) {
    const evidence = completed?.finalityEvidence ??
      (typeof this.native.readGenesisFinalityEvidence === "function"
        ? await this.native.readGenesisFinalityEvidence({ txId: completed?.txId })
        : null);
    if (evidence && await this.native.recheckAdmissionFinality(evidence) !== true) {
      throw new Error("FINALITY_RECHECK_FAILED");
    }
    await this.#commitGenesisHistory(anchorFingerprint);
    if (evidence && await this.native.recheckAdmissionFinality(evidence) !== true) {
      throw new Error("FINALITY_RECHECK_FAILED");
    }
    const finalityFingerprint = completed?.finalityFingerprint ?? completed?.receiptFingerprint;
    if (typeof finalityFingerprint !== "string") throw new Error("FINALITY_RECHECK_FAILED");
    const reopened = await this.native.reopenAdmission({
      txId: completed.txId,
      finalityFingerprint,
    }) === true;
    return { reopened, finalityFingerprint };
  }
  async #restorePendingGenesisAdmission(recovery) {
    const pending = recovery?.readerHandshake;
    if (!pending?.request || !pending?.grant ||
        pending.requestFingerprint !== pending.request.requestFingerprint ||
        pending.grantFingerprint !== pending.grant.grantFingerprint ||
        pending.request.genesisTxId !== recovery.txId) {
      throw new Error("RECOVERY_PENDING_TUPLE_REQUIRED");
    }
    for (const [method, value] of [
      ["writeAdmissionRequest", pending.request],
      ["writeAdmissionGrant", pending.grant],
    ]) {
      try {
        await this.native[method](value);
      } catch (error) {
        if (error?.reason !== "immutable authority record already exists") throw error;
      }
    }
  }

  async #manualCleanup(state, reason, recovery = state.recovery) {
    const durableRecovery = structuredClone(recovery ?? state.recovery ?? {});
    const terminal = await this.native.terminalCloseOrManualCleanup({ recovery: durableRecovery, reason });
    if (terminal?.phase !== "manual_cleanup" || terminal.routeDisposition !== "no-route") throw new Error("MANUAL_CLEANUP_DURABILITY_FAILED");
    let current;
    try {
      current = await this.#read();
    } catch {
      current = structuredClone(state);
    }
    if (!current.recovery || current.recovery.phase !== "manual_cleanup") {
      const lineage = validateCommittedTokenLineage(await this.native.readSuccessorTokenLineage());
      current.recovery = {
        ...durableRecovery,
        phase: "manual_cleanup",
        routeDisposition: "no-route",
        reason,
        manualCleanupFingerprint: terminal.manualCleanupFingerprint ?? null,
      };
      current.admission = { phase: "closed", finalityFingerprint: null };
      current.tokenFloor = structuredClone(lineage.floor);
      current.tokenConfigGeneration = lineage.floor.highestCommittedGeneration;
      current.tokenAttestation = {
        fingerprint: lineage.attestation.tokenConfigHostSetFingerprint,
        generation: lineage.attestation.tokenConfigGeneration,
        attestationFingerprint: lineage.attestation.attestationFingerprint,
        finalityFingerprint: lineage.floor.floorFingerprint,
      };
      const revision = current.revision;
      current.authorityEpoch = (await this.#readAuthorityEpochFloor())?.highestReservedAuthorityEpoch ?? current.authorityEpoch;
      const fenceFloor = typeof this.native.readFenceGenerationFloor === "function" ? await this.native.readFenceGenerationFloor() : null;
      if (Number.isSafeInteger(fenceFloor?.highestCommittedFenceGeneration) && fenceFloor.highestCommittedFenceGeneration >= 1) {
        current.fenceGeneration = fenceFloor.highestCommittedFenceGeneration;
      }
      if (!await this.native.compareAndSwapManagementState(revision, current)) throw new Error("MANUAL_CLEANUP_DURABILITY_FAILED");
    }
    throw new Error("MANUAL_CLEANUP_REQUIRED");
  }

  async #mutate(action, input, fn, locks = ["mapping"]) {
    if (!validAuthIdempotencyKey(input.idempotencyKey)) {
      throw new Error("IDEMPOTENCY_KEY_REQUIRED");
    }
    const actorPrincipal = principal(input.actorPrincipal, "ACTOR_PRINCIPAL");
    const targetPrincipal = principal(input.targetPrincipal, "TARGET_PRINCIPAL");
    const secret = input.actorSecret;
    if (typeof secret !== "string") throw new Error("AUTH_SECRET_REQUIRED");
    return this.native.withManagementLocks(locks, async () => {
      const state = await this.#read();
      if (state.recovery && state.recovery.phase !== "terminal") throw new Error("RECOVERY_REQUIRED");
      const auth = await this.#readAuth();
      const authState = { auth };
      const identity = authenticate(authState, actorPrincipal, secret);
      const beforeFingerprint = canonicalJsonHash(auth);
      const intentFingerprint = authMutationIntentFingerprint({
        action,
        actorPrincipal,
        targetPrincipal,
        targetSecret: input.targetSecret,
      });
      const records = authMutationRecords(auth);
      const hasExisting = Object.hasOwn(records, input.idempotencyKey);
      if (hasExisting) {
        const existing = records[input.idempotencyKey];
        if (!validAuthMutationRecord(existing, input.idempotencyKey) ||
            existing.action !== action ||
            existing.intentFingerprint !== intentFingerprint) {
          throw new Error("IDEMPOTENCY_CONFLICT");
        }
        return structuredClone(existing.result);
      }
      const result = await fn(authState, identity);
      const afterFingerprint = canonicalJsonHash(authState.auth);
      const record = authMutationRecord({
        idempotencyKey: input.idempotencyKey,
        action,
        intentFingerprint,
        actorPrincipal,
        targetPrincipal,
        result,
        beforeFingerprint,
        afterFingerprint,
      });
      Object.defineProperty(authState.auth.idempotency, input.idempotencyKey, {
        configurable: true,
        enumerable: true,
        value: record,
        writable: true,
      });
      if (!await this.native.compareAndSwapManagementAuth(beforeFingerprint, authState.auth)) throw new Error("CAS_CONFLICT");
      try {
        await this.#audit({
          actorPrincipal,
          action,
          targetPrincipal,
          result: "committed",
          details: {
            idempotencyKey: input.idempotencyKey,
            intentFingerprint,
            authBeforeFingerprint: beforeFingerprint,
            authAfterFingerprint: afterFingerprint,
            result,
          },
        });
      } catch (error) {
        await this.#manualCleanup(state, safe(error).code);
      }
      return result;
    });
  }

  async #readAuthenticated(input, fn) {
    const actorPrincipal = principal(input.actorPrincipal, "ACTOR_PRINCIPAL");
    if (typeof input.actorSecret !== "string") throw new Error("AUTH_SECRET_REQUIRED");
    return this.native.withManagementLocks(["mapping"], async () => {
      const state = await this.#read();
      if (state.recovery && state.recovery.phase !== "terminal") throw new Error("RECOVERY_REQUIRED");
      const authenticated = await this.#authenticatedState(state);
      return fn(state, authenticate(authenticated, actorPrincipal, input.actorSecret));
    });
  }

  async #genesis(input) {
    const actorPrincipal = principal(input.actorPrincipal, "ACTOR_PRINCIPAL");
    const targetPrincipal = principal(input.targetPrincipal, "TARGET_PRINCIPAL");
    if (canonicalJsonHash(actorPrincipal) === canonicalJsonHash(targetPrincipal)) throw new Error("GENESIS_ACTOR_TARGET_DISTINCT_REQUIRED");
    if (typeof input.actorSecret !== "string" || typeof input.idempotencyKey !== "string" || input.idempotencyKey.length === 0 ||
        !isPrincipal(input.botPrincipal) || !isPrincipal(input.recoveryPrincipal) ||
        ![input.managementProvisioningFingerprint, input.botProvisioningFingerprint, input.recoveryProvisioningFingerprint].every((value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value))) throw new Error("GENESIS_INPUT_INVALID");
    if (!["no-reader", "handshake"].includes(input.requestedReaderMode ?? "no-reader") ||
        ((input.requestedReaderMode ?? "no-reader") === "no-reader" && (input.readerInstanceId !== undefined || input.readerStartNonce !== undefined)) ||
        ((input.requestedReaderMode ?? "no-reader") === "handshake" && (typeof input.readerInstanceId !== "string" || typeof input.readerStartNonce !== "string"))) throw new Error("READER_BINDING_REQUIRED");
    const hostSetFingerprint = protectedTokenFingerprint(input.hostTokens);
    return this.native.withManagementLocks(LOCK_ORDER, async () => {
      const state = await this.#read();
      const generation = state.recovery?.phase && state.recovery.phase !== "terminal"
        ? state.recovery.generation ?? state.recovery.genesisSecurityTuple?.generation
        : state.tokenConfigGeneration + 1;
      const anchorFingerprint = await this.native.managementAnchorFingerprint();
      const expectedRoleBindings = exactRoleBindings(actorPrincipal, input.botPrincipal, input.recoveryPrincipal);
      const securityTuple = normalizedGenesisSecurityTuple({
        anchorFingerprint,
        generation,
        actorPrincipal,
        targetPrincipal,
        roleBindings: expectedRoleBindings,
        managementProvisioningFingerprint: input.managementProvisioningFingerprint,
        botProvisioningFingerprint: input.botProvisioningFingerprint,
        recoveryProvisioningFingerprint: input.recoveryProvisioningFingerprint,
        protectedHostTokensHostSetFingerprint: hostSetFingerprint,
        idempotencyKey: input.idempotencyKey,
        targetInputIntent: null,
        requestedReaderMode: input.requestedReaderMode ?? "no-reader",
        readerInstanceId: input.requestedReaderMode === "handshake" ? input.readerInstanceId : null,
        readerStartNonce: input.requestedReaderMode === "handshake" ? input.readerStartNonce : null,
      });
      const { replayFingerprint, txId } = stableGenesisProbe(securityTuple);
      let auth = await this.native.readManagementAuth();
      if (state.recovery?.phase === "handshake-pending" &&
          state.recovery.replayFingerprint === replayFingerprint &&
          state.recovery.genesisSecurityTuple !== undefined &&
          sameGenesisSecurityTuple(state.recovery.genesisSecurityTuple, securityTuple)) {
        authenticate({ auth }, actorPrincipal, input.actorSecret);
        await this.#restorePendingGenesisAdmission(state.recovery);
        const completed = await this.native.completePendingGenesis({
          recovery: state.recovery,
          replayFingerprint,
          genesisSecurityTuple: state.recovery.genesisSecurityTuple,
        });
        if (completed === null) {
          return { idempotent: true, pending: true, genesisTxId: state.recovery.txId, routeDisposition: "no-route" };
        }
        validateGenesisSuffixRecovery(completed, state.recovery);
        const { reopened, finalityFingerprint } = await this.#finalizeRecoveredGenesis(anchorFingerprint, completed);
        const lineage = await this.native.readSuccessorTokenLineage();
        const before = state.revision;
        state.recovery = { ...state.recovery, ...completed, finalityFingerprint: completed.receiptFingerprint, phase: "terminal", readerHandshake: null };
        state.admission = {
          phase: reopened ? "open" : "closed",
          finalityFingerprint: reopened ? finalityFingerprint : null,
        };
        state.tokenFloor = structuredClone(lineage.floor);
        state.tokenConfigGeneration = lineage.attestation.tokenConfigGeneration;
        state.tokenAttestation = {
          fingerprint: lineage.attestation.tokenConfigHostSetFingerprint,
          generation: lineage.attestation.tokenConfigGeneration,
          attestationFingerprint: lineage.attestation.attestationFingerprint,
          finalityFingerprint: lineage.floor.floorFingerprint,
        };
        state.genesis = {
          txId: state.recovery.txId,
          fenceGeneration: 1,
          replayFingerprint,
          genesisSecurityTuple: state.recovery.genesisSecurityTuple,
          requestFingerprint: state.recovery.requestFingerprint,
          finalityFingerprint: completed.receiptFingerprint,
        };
        state.revision = before + 1;
        state.authorityEpoch = await this.#committedAuthorityEpoch(state);
        if (!await this.native.compareAndSwapManagementState(before, state)) {
          throw new Error("MANUAL_CLEANUP_DURABILITY_FAILED");
        }
        try {
          await this.#audit({
            actorPrincipal,
            action: "genesis-handshake-complete",
            targetPrincipal,
            result: "terminal",
            details: { txId: state.recovery.txId, finalityFingerprint: completed.receiptFingerprint },
          });
        } catch (error) {
          await this.#manualCleanup(state, safe(error).code);
        }
        return {
          idempotent: true,
          recovered: true,
          genesisTxId: state.recovery.txId,
          reopened,
          routeDisposition: "no-route",
        };
      }
      if (state.recovery && state.recovery.phase !== "terminal") {
        if (state.recovery.replayFingerprint !== replayFingerprint ||
            state.recovery.genesisSecurityTuple === undefined ||
            !sameGenesisSecurityTuple(state.recovery.genesisSecurityTuple, securityTuple)) {
          await this.#manualCleanup(state, "RECOVERY_INPUT_MISMATCH");
        }
        let recovered;
        try {
          recovered = await this.native.recoverGenesisSuffix({
            recovery: state.recovery,
            replayFingerprint,
            genesisSecurityTuple: state.recovery.genesisSecurityTuple,
          });
          validateGenesisSuffixRecovery(recovered, state.recovery);
        } catch (error) {
          await this.#manualCleanup(state, "RECOVERY_SUFFIX_MISMATCH");
        }
        const { reopened, finalityFingerprint } = await this.#finalizeRecoveredGenesis(anchorFingerprint, recovered);
        const lineage = await this.native.readSuccessorTokenLineage();
        state.recovery = { ...state.recovery, ...recovered, finalityFingerprint: recovered.receiptFingerprint, phase: "terminal" };
        state.admission = {
          phase: reopened ? "open" : "closed",
          finalityFingerprint: reopened ? finalityFingerprint : null,
        };
        state.tokenFloor = structuredClone(lineage.floor);
        state.tokenConfigGeneration = lineage.attestation.tokenConfigGeneration;
        state.tokenAttestation = {
          fingerprint: lineage.attestation.tokenConfigHostSetFingerprint,
          generation: lineage.attestation.tokenConfigGeneration,
          attestationFingerprint: lineage.attestation.attestationFingerprint,
          finalityFingerprint: lineage.floor.floorFingerprint,
        };
        state.genesis = {
          txId: state.recovery.txId,
          fenceGeneration: 1,
          replayFingerprint,
          genesisSecurityTuple: state.recovery.genesisSecurityTuple,
          requestFingerprint: state.recovery.requestFingerprint,
          finalityFingerprint: recovered.receiptFingerprint,
        };
        const before = state.revision;
        state.revision = before + 1;
        state.authorityEpoch = await this.#committedAuthorityEpoch(state);
        if (!await this.native.compareAndSwapManagementState(before, state)) throw new Error("MANUAL_CLEANUP_DURABILITY_FAILED");
        try {
          await this.#audit({
            actorPrincipal,
            action: "genesis-recovery",
            targetPrincipal,
            result: "terminal",
            details: { txId: state.recovery.txId, finalityFingerprint: recovered.receiptFingerprint },
          });
        } catch (error) {
          await this.#manualCleanup(state, safe(error).code);
        }
        return { idempotent: true, recovered: true, genesisTxId: state.recovery.txId, reopened, routeDisposition: "no-route" };
      }
      const authState = { auth };
      let bootstrapAuth = null;
      if (auth) {
        authenticate(authState, actorPrincipal, input.actorSecret);
      } else {
        bootstrapOwner(authState, { actorPrincipal, osPrincipal: await this.native.currentOsPrincipal(), secret: input.actorSecret });
        bootstrapAuth = authState.auth;
        auth = authState.auth;
      }
      state.roleBindings ??= expectedRoleBindings;
      if (canonicalJsonHash(state.roleBindings) !== canonicalJsonHash(expectedRoleBindings)) {
        throw new Error("GENESIS_ROLE_BINDING_CONFLICT");
      }
      if (state.genesis) {
        if (state.genesis.replayFingerprint !== replayFingerprint ||
            state.genesis.genesisSecurityTuple === undefined ||
            !sameGenesisSecurityTuple(state.genesis.genesisSecurityTuple, securityTuple)) {
          throw new Error("GENESIS_IDEMPOTENCY_CONFLICT");
        }
        return { idempotent: true, genesisTxId: state.genesis.txId };
      }
      const baseFloor = state.tokenFloor ?? { version: 1, kind: "token-generation-floor", anchorFingerprint, fenceGeneration: 1, genesisGeneration: generation, highestReservedGeneration: generation - 1, highestCommittedGeneration: generation - 1, lastReservationTxId: null, lastCommittedTxId: null, lastAttestationFingerprint: null, floorPhase: "reserved", attestedProofFingerprint: null, floorFingerprint: null };
      if (baseFloor.floorFingerprint === null) baseFloor.floorFingerprint = recordHash(baseFloor, "floorFingerprint");
      const reservedFloor = reserveTokenGeneration(baseFloor, { generation, txId, fenceGeneration: 1 });
      validateTokenFloorReservation(reservedFloor);
      const attestation = { version: 1, kind: "token-config-attestation", anchorFingerprint, fenceGeneration: 1, tokenConfigGeneration: generation, tokenConfigHostSetFingerprint: hostSetFingerprint, managedGrammarVersion: 1, sourceKind: "protected-stdin", producerPrincipal: `management/${canonicalJsonHash(actorPrincipal)}`, rotationKind: generation === baseFloor.genesisGeneration ? "genesis" : hostSetFingerprint === state.tokenAttestation?.fingerprint ? "same-key" : "host-set-change", previousAttestationFingerprint: baseFloor.lastAttestationFingerprint, txId, attestationFingerprint: null };
      attestation.attestationFingerprint = recordHash(attestation, "attestationFingerprint");
      const request = { version: 1, kind: "genesis-request", genesisTxId: txId, fenceGeneration: 1, idempotencyKey: input.idempotencyKey, anchorFingerprint, ownerPrincipalFingerprint: canonicalJsonHash(actorPrincipal), generation, requestedReaderMode: input.requestedReaderMode ?? "no-reader", readerInstanceId: input.requestedReaderMode === "handshake" ? input.readerInstanceId : null, readerStartNonce: input.requestedReaderMode === "handshake" ? input.readerStartNonce : null, attestationFingerprint: attestation.attestationFingerprint, tokenFloorFingerprint: reservedFloor.floorFingerprint, requestFingerprint: null };
      request.requestFingerprint = recordHash(request, "requestFingerprint");
      validateGenesisRequest(request);
      let authorityRequest;
      const authorityEpochCandidate = await this.#nextAuthorityEpoch(state);
      const authorityReservation = {
        version: 1, kind: "authority-reservation", anchorFingerprint, fenceGeneration: 1, txId, epoch: authorityEpochCandidate,
        generation, candidateFingerprint: request.requestFingerprint, previousAuthorityCommitSnapshotFingerprint: null, reservationFingerprint: null,
      };
      authorityReservation.reservationFingerprint = recordHash(authorityReservation, "reservationFingerprint");
      validateAuthorityReservation(authorityReservation);
      const authorityCommit = {
        version: 1, kind: "authority-commit-snapshot", anchorFingerprint, fenceGeneration: 1, txId, epoch: authorityReservation.epoch,
        generation, candidateFingerprint: authorityReservation.candidateFingerprint, reservationFingerprint: authorityReservation.reservationFingerprint,
        previousAuthorityCommitSnapshotFingerprint: null, authorityCommitSnapshotFingerprint: null,
      };
      authorityCommit.authorityCommitSnapshotFingerprint = recordHash(authorityCommit, "authorityCommitSnapshotFingerprint");
      validateAuthorityCommitSnapshot(authorityCommit, authorityReservation);
      const authorityEpoch = {
        version: 1, kind: "authority-epoch", anchorFingerprint, fenceGeneration: 1, epoch: authorityReservation.epoch, reservationTxId: txId,
        commitTxId: null, previousAuthorityCommitSnapshotFingerprint: null, authorityEpochFingerprint: null,
      };
      authorityEpoch.authorityEpochFingerprint = recordHash(authorityEpoch, "authorityEpochFingerprint");
      validateAuthorityEpoch(authorityEpoch);
      let baseline = {
        version: 1, kind: "authority-baseline", anchorFingerprint, genesisTxId: txId, idempotencyKey: input.idempotencyKey, fenceGeneration: 1,
        targetState: request.requestedReaderMode === "handshake" ? "handshake-pending" : "genesis-empty", generation,
        tokenConfigHostSetFingerprint: hostSetFingerprint, attestationFingerprint: attestation.attestationFingerprint,
        authorityReservationFingerprint: authorityReservation.reservationFingerprint, authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
        fenceBindingFingerprint: null, leaseBindingFingerprint: null, readerProjectionFingerprint: null,
        readerInstanceId: null, readerStartNonce: null, readerVersion: null, baselineFingerprint: null,
      };
      baseline.baselineFingerprint = recordHash(baseline, "baselineFingerprint");
      const attestedProof = buildAttestedTokenFloorProof(reservedFloor, attestation);
      const attestedFloor = attestTokenFloor(reservedFloor, attestedProof);
      const committedFloor = commitTokenFloor(attestedFloor, { txId, generation, attestationFingerprint: attestation.attestationFingerprint, fenceGeneration: 1 });
      let nativeMutation = false;
      let genesisHandshakePending = false;
      try {
        const genesisProbe = await this.native.probeProspectiveCleanup({
          txId,
          replayFingerprint,
          genesisSecurityTuple: securityTuple,
          generation,
          idempotencyKey: input.idempotencyKey,
          requestedReaderMode: request.requestedReaderMode,
          readerInstanceId: request.readerInstanceId,
          readerStartNonce: request.readerStartNonce,
          protectedInputFingerprint: hostSetFingerprint,
          targetPrincipal,
          managementPrincipal: actorPrincipal,
          botPrincipal: input.botPrincipal,
          recoveryPrincipal: input.recoveryPrincipal,
          managementProvisioningFingerprint: input.managementProvisioningFingerprint,
          botProvisioningFingerprint: input.botProvisioningFingerprint,
          recoveryProvisioningFingerprint: input.recoveryProvisioningFingerprint,
        });
        if (!genesisProbe?.genesisSecurityTuple ||
            !sameGenesisSecurityTuple(genesisProbe.genesisSecurityTuple, securityTuple)) {
          throw new Error("GENESIS_SECURITY_TUPLE_MISMATCH");
        }
        const persistedGenesisSecurityTuple = genesisProbe.genesisSecurityTuple;
        const expectedLegacyTarget = genesisProbe.legacyTargetProof ?? null;
        if (genesisProbe?.targetInputState === "legacy-unmigrated" && request.requestedReaderMode !== "no-reader") throw new Error("LEGACY_READER_HANDSHAKE_REFUSED");
        if (genesisProbe?.targetInputState === "legacy-unmigrated" &&
            (!expectedLegacyTarget || !/^[a-f0-9]{64}$/.test(expectedLegacyTarget.rawTargetByteFingerprint) ||
             !Number.isSafeInteger(expectedLegacyTarget.rawTargetByteLength) || expectedLegacyTarget.rawTargetByteLength < 0 ||
             typeof expectedLegacyTarget.targetIdentity !== "string" ||
             !/^[a-f0-9]{64}$/.test(expectedLegacyTarget.targetAclFingerprint))) throw new Error("LEGACY_TARGET_PROOF_REQUIRED");
        authorityRequest = {
          version: 1, kind: "genesis-authority-request", genesisTxId: txId, fenceGeneration: 1, sequence: 1, anchorFingerprint,
          ownerPrincipalFingerprint: canonicalJsonHash(actorPrincipal), managementPrincipalFingerprint: canonicalJsonHash(actorPrincipal),
          botPrincipalFingerprint: canonicalJsonHash(input.botPrincipal), recoveryPrincipalFingerprint: canonicalJsonHash(input.recoveryPrincipal),
          targetPrincipalFingerprint: canonicalJsonHash(targetPrincipal),
          managementProvisioningFingerprint: input.managementProvisioningFingerprint,
          botProvisioningFingerprint: input.botProvisioningFingerprint,
          recoveryProvisioningFingerprint: input.recoveryProvisioningFingerprint,
          generation, requestedReaderMode: request.requestedReaderMode,
          readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce,
          idempotencyKey: input.idempotencyKey, targetInputState: genesisProbe?.targetInputState === "legacy-unmigrated" ? "legacy-unmigrated" : "absent",
          targetFingerprint: expectedLegacyTarget?.rawTargetByteFingerprint ?? null,
          targetIdentityFingerprint: expectedLegacyTarget ? canonicalJsonHash(expectedLegacyTarget.targetIdentity) : null,
          targetAclFingerprint: expectedLegacyTarget?.targetAclFingerprint ?? null,
          legacyTargetProofFingerprint: expectedLegacyTarget ? canonicalJsonHash(expectedLegacyTarget) : null,
          protectedInputFingerprint: hostSetFingerprint, requestFingerprint: null,
        };
        authorityRequest.requestFingerprint = recordHash(authorityRequest, "requestFingerprint");
        validateGenesisAuthorityRequest(authorityRequest);
        state.recovery = {
          ...(state.recovery ?? {}),
          txId,
          fenceGeneration: 1,
          phase: "prepared",
          requestFingerprint: authorityRequest.requestFingerprint,
          routeDisposition: "no-route",
        };
        nativeMutation = true;
        await this.native.writeGenesisAuthorityRequest(authorityRequest);
        await this.native.reserveFenceGeneration({ fenceGeneration: 1, txId });
        nativeMutation = true;
        if (bootstrapAuth && !await this.native.compareAndSwapManagementAuth(null, bootstrapAuth)) throw new Error("CAS_CONFLICT");
        state.recovery = { txId, fenceGeneration: 1, phase: "prepared", replayFingerprint, genesisSecurityTuple: persistedGenesisSecurityTuple, generation, hostSetFingerprint, requestFingerprint: request.requestFingerprint, reservationFingerprint: reservedFloor.floorFingerprint, attestationFingerprint: attestation.attestationFingerprint, finalityFingerprint: null };
        const preparedRevision = state.revision;
        state.revision = preparedRevision + 1;
        state.authorityEpoch = authorityReservation.epoch;
        if (!await this.native.compareAndSwapManagementState(preparedRevision, state)) throw new Error("MANUAL_CLEANUP_REQUIRED");
        await this.native.writeGenesisRequest(request);
        nativeMutation = true;
        await this.native.reserveTokenFloor(reservedFloor);
        await this.native.writeTokenConfigAttestation(attestation);
        await this.native.writeAttestedTokenFloor({ reservation: reservedFloor, attestation, proof: attestedProof, floor: attestedFloor });
        if (genesisProbe?.targetInputState === "legacy-unmigrated") {
          baseline = { ...baseline, targetState: "legacy-unmigrated", baselineFingerprint: null };
        }
        await this.native.reserveAuthorityEpoch(authorityEpoch);
        await this.native.writeAuthorityReservation(authorityReservation);
        await this.native.writeAuthorityCommitSnapshot(authorityCommit);
        let publicationEvidence = await this.native.publishMapping({
          request,
          attestation,
          targetPrincipal,
          genesisProbe,
          expectedLegacyTarget,
          readerVersionFloor: null,
        });
        let readerVersionFloor = null;
        if (request.requestedReaderMode === "handshake") {
          readerVersionFloor = await this.native.casReaderVersionFloor({
            txId,
            readerInstanceId: request.readerInstanceId,
            readerStartNonce: request.readerStartNonce,
            fenceGeneration: 1,
          });
          if (readerVersionFloor?.readerVersionFloor !== 2 || readerVersionFloor.firstPendingTxId !== txId ||
              readerVersionFloor.firstReaderInstanceId !== request.readerInstanceId ||
              readerVersionFloor.firstReaderStartNonce !== request.readerStartNonce) {
            throw new Error("READER_VERSION_FLOOR_CAS_FAILED");
          }
          const fence = {
            version: 1,
            kind: "reader-fence-binding",
            anchorFingerprint,
            fenceGeneration: 1,
            genesisTxId: txId,
            readerInstanceId: request.readerInstanceId,
            readerStartNonce: request.readerStartNonce,
            readerVersion: 2,
            authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
            fenceBindingFingerprint: null,
          };
          fence.fenceBindingFingerprint = authorityRecordFingerprint(fence, "fenceBindingFingerprint");
          validateFenceBinding(fence, authorityCommit, readerVersionFloor);
          await this.native.writeReaderFenceBinding(fence);
          publicationEvidence = await this.native.publishMapping({
            refreshReaderFloor: true,
            request,
            attestation,
            targetPrincipal,
            genesisProbe,
            expectedLegacyTarget,
            readerVersionFloor,
          });
          baseline = {
            ...baseline,
            fenceBindingFingerprint: fence.fenceBindingFingerprint,
            readerInstanceId: request.readerInstanceId,
            readerStartNonce: request.readerStartNonce,
            readerVersion: 2,
            baselineFingerprint: null,
          };
          baseline.baselineFingerprint = recordHash(baseline, "baselineFingerprint");
          validateBaselineSnapshot(baseline, readerVersionFloor);
        }
        if (request.requestedReaderMode !== "handshake") {
          baseline.baselineFingerprint = recordHash(baseline, "baselineFingerprint");
          validateBaselineSnapshot(baseline);
        }
        const canonicalMappingFingerprint = genesisProbe?.targetInputState === "legacy-unmigrated"
          ? canonicalJsonHash({
            sourceKind: "legacy-retained",
            targetFingerprint: publicationEvidence.targetFingerprint,
            identityFingerprint: publicationEvidence.targetIdentityFingerprint,
            aclFingerprint: publicationEvidence.targetAclFingerprint,
          })
          : canonicalJsonHash({
            mappingGeneration: state.mappingGeneration,
            mappings: state.mappings,
            routes: state.routes,
          });
        const semanticStateFingerprint = canonicalJsonHash({
          targetState: baseline.targetState,
          targetFingerprint: publicationEvidence.targetFingerprint,
          targetIdentityFingerprint: publicationEvidence.targetIdentityFingerprint,
          targetAclFingerprint: publicationEvidence.targetAclFingerprint,
          canonicalMappingFingerprint,
        });
        const semanticPayloadFingerprint = canonicalJsonHash({
          targetFingerprint: publicationEvidence.targetFingerprint,
          targetIdentityFingerprint: publicationEvidence.targetIdentityFingerprint,
          targetAclFingerprint: publicationEvidence.targetAclFingerprint,
          wrapperFingerprint: publicationEvidence.wrapperFingerprint,
          controlRootFingerprint: publicationEvidence.controlRootFingerprint,
          canonicalMappingFingerprint,
        });
        const semanticSnapshotFingerprint = canonicalJsonHash({
          stateFingerprint: semanticStateFingerprint,
          payloadFingerprint: semanticPayloadFingerprint,
          targetFingerprint: publicationEvidence.targetFingerprint,
        });
        const semanticPublicationFingerprint = canonicalJsonHash({
          stateFingerprint: semanticStateFingerprint,
          payloadFingerprint: semanticPayloadFingerprint,
          snapshotFingerprint: semanticSnapshotFingerprint,
          targetFingerprint: publicationEvidence.targetFingerprint,
        });
        const semanticCheckpointFingerprint = canonicalJsonHash({
          genesisTxId: txId,
          generation,
          publicationFingerprint: semanticPublicationFingerprint,
          targetFingerprint: publicationEvidence.targetFingerprint,
        });
        await this.native.writeAuthorityBaseline(baseline);
        const graph = publicationGraph({
          txId, genesisTxId: txId, generation, fenceGeneration: 1, baseline, targetFingerprint: publicationEvidence.targetFingerprint,
          stateFingerprint: semanticStateFingerprint, payloadFingerprint: semanticPayloadFingerprint,
          snapshotFingerprint: semanticSnapshotFingerprint, publicationFingerprint: semanticPublicationFingerprint,
          checkpointFingerprint: semanticCheckpointFingerprint,
        });
        await this.native.writePublicationGraph(graph);
        const authorityProof = await this.native.readBoundReaderProof({ allowPending: true });
        const authorityReaderFloor = authorityProof?.readerVersionFloor;
        validateReaderVersionFloor(authorityReaderFloor);
        state.recovery.phase = "replaced";
        state.revision += 1;
        if (!await this.native.compareAndSwapManagementState(state.revision - 1, state)) throw new Error("MANUAL_CLEANUP_REQUIRED");
        const committedAuthorityEpoch = {
          ...authorityEpoch,
          commitTxId: txId,
          authorityEpochFingerprint: null,
        };
        committedAuthorityEpoch.authorityEpochFingerprint = recordHash(committedAuthorityEpoch, "authorityEpochFingerprint");
        validateAuthorityEpoch(committedAuthorityEpoch);
        const precommit = buildGenesisPrecommit({
          fenceGeneration: 1,
          genesisTxId: txId,
          generation,
          genesisProbeFingerprint: genesisProbe.probe.probeFingerprint,
          targetFingerprint: publicationEvidence.targetFingerprint,
          targetIdentityFingerprint: publicationEvidence.targetIdentityFingerprint,
          targetAclFingerprint: publicationEvidence.targetAclFingerprint,
          controlRootFingerprint: publicationEvidence.controlRootFingerprint,
          controlIdentityFingerprint: publicationEvidence.controlIdentityFingerprint,
          controlAclFingerprint: publicationEvidence.controlAclFingerprint,
          wrapperIdentityFingerprint: publicationEvidence.wrapperIdentityFingerprint,
          wrapperAclFingerprint: publicationEvidence.wrapperAclFingerprint,
          wrapperFingerprint: publicationEvidence.wrapperFingerprint,
          readerVersionFloorFingerprint: authorityReaderFloor.floorFingerprint,
          requestFingerprint: request.requestFingerprint,
          reservationFingerprint: reservedFloor.floorFingerprint,
          attestedProofFingerprint: attestedProof.attestedProofFingerprint,
          authorityReservationFingerprint: authorityReservation.reservationFingerprint,
          authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
          authorityEpochFingerprint: committedAuthorityEpoch.authorityEpochFingerprint,
          publicationKFingerprint: graph.k["publication-kFingerprint"],
          publicationYFingerprint: graph.y["publication-yFingerprint"],
          zeroGrantProofFingerprint: canonicalJsonHash({
            admissionClosed: true,
            admissionDrained: true,
            admissionGrantWrites: 0,
            admissionAckWrites: 0,
            outstandingAdmissionGrants: 0,
            txId,
          }),
        });
        await this.native.commitAuthorityEpoch(committedAuthorityEpoch, precommit);
        await this.native.commitTokenFloor({ floor: committedFloor, precommit, fenceGeneration: 1 });
        await this.native.commitFenceGeneration({ fenceGeneration: 1, txId });
        const zFinality = { version: 1, kind: "genesis-finality", genesisTxId: txId, fenceGeneration: 1, generation, anchorFingerprint, attestationFingerprint: attestation.attestationFingerprint, tokenFloorFingerprint: committedFloor.floorFingerprint, checkpointFingerprint: canonicalJsonHash(request), publicationKFingerprint: graph.k["publication-kFingerprint"], publicationYFingerprint: graph.y["publication-yFingerprint"], authorityEpochFingerprint: committedAuthorityEpoch.authorityEpochFingerprint, precommitFingerprint: precommit.precommitFingerprint, finalityFingerprint: committedFloor.floorFingerprint, zFinalityFingerprint: null };
        zFinality.zFinalityFingerprint = recordHash(zFinality, "zFinalityFingerprint");
        validateZFinality(zFinality, request, committedFloor, precommit);
        await this.native.writeZFinality(zFinality);
        const authorityReceipt = {
          fenceGeneration: 1,
          version: 1, kind: "genesis-authority-receipt", genesisTxId: txId, requestFingerprint: authorityRequest.requestFingerprint,
          sequence: 2, anchorFingerprint, generation, readerVersionFloorFingerprint: authorityReaderFloor.floorFingerprint,
          authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint, receiptFingerprint: null,
        };
        authorityReceipt.receiptFingerprint = recordHash(authorityReceipt, "receiptFingerprint");
        validateGenesisAuthorityReceipt(authorityReceipt, authorityRequest);
        await this.native.writeGenesisAuthorityReceipt(authorityReceipt);
        let admissionRequest = null;
        let admissionGrant = null;
        if (request.requestedReaderMode === "handshake") {
          admissionRequest = buildAdmissionRequest({
            requestId: randomUUID(), genesisTxId: txId, generation, fenceGeneration: 1, readerInstanceId: request.readerInstanceId,
            readerStartNonce: request.readerStartNonce, routeFingerprint: "no-route", nonce: randomUUID(),
            expiresAt: Date.now() + 30_000,
          });
          admissionGrant = buildAdmissionGrant(admissionRequest, { grantId: randomUUID(), expiresAt: admissionRequest.expiresAt });
          await this.#persistGenesisHandshakePending(state, {
            replayFingerprint,
            generation,
            hostSetFingerprint,
            admissionRequest,
            admissionGrant,
          });
          genesisHandshakePending = true;
          await this.native.writeAdmissionRequest(admissionRequest);
          await this.native.writeAdmissionGrant(admissionGrant);
          await this.#commitGenesisHistory(anchorFingerprint, { allowCreate: true });
        }
        let readerProjection = null;
        let admissionAck = null;
        if (request.requestedReaderMode === "handshake") {
          const bound = await this.native.readBoundReaderProof({ allowPending: true, request, zFinality });
          readerProjection = bound?.readerProjection;
          admissionAck = bound?.admissionAck;
          if (!readerProjection || !admissionAck) {
            return { genesisTxId: txId, pending: true, reopened: false, routeDisposition: "no-route" };
          }
          validateAdmissionAck(admissionAck, admissionGrant, readerProjection.readerProjectionFingerprint);
          validateReaderProjection(readerProjection, bound?.readerVersionFloor, committedFloor, zFinality.zFinalityFingerprint);
          validateFinalityProof({
            version: 1, kind: "finality-proof", genesisTxId: txId, fenceGeneration: 1, generation,
            zFinalityFingerprint: zFinality.zFinalityFingerprint,
            readerProjectionFingerprint: readerProjection.readerProjectionFingerprint,
            ackFingerprint: admissionAck?.ackFingerprint,
            routeFingerprint: admissionAck?.routeFingerprint,
            finalityProofFingerprint: canonicalJsonHash({
              version: 1, kind: "finality-proof", genesisTxId: txId, fenceGeneration: 1, generation,
              zFinalityFingerprint: zFinality.zFinalityFingerprint,
              readerProjectionFingerprint: readerProjection.readerProjectionFingerprint,
              ackFingerprint: admissionAck?.ackFingerprint,
              routeFingerprint: admissionAck?.routeFingerprint,
            }),
          }, request, zFinality, admissionAck, readerProjection.readerProjectionFingerprint);
        }
        const finalityProof = {
          version: 1, kind: "finality-proof", genesisTxId: txId, fenceGeneration: 1, generation,
          zFinalityFingerprint: zFinality.zFinalityFingerprint,
          readerProjectionFingerprint: readerProjection?.readerProjectionFingerprint ?? null,
          ackFingerprint: admissionAck?.ackFingerprint ?? null,
          routeFingerprint: admissionAck?.routeFingerprint ?? "no-route",
          finalityProofFingerprint: null,
        };
        finalityProof.finalityProofFingerprint = recordHash(finalityProof, "finalityProofFingerprint");
        validateFinalityProof(finalityProof, request, zFinality, admissionAck, readerProjection?.readerProjectionFingerprint ?? null);
        const receipt = {
          version: 1, kind: "genesis-receipt", genesisTxId: txId, fenceGeneration: 1, generation,
          requestedReaderMode: request.requestedReaderMode, readerInstanceId: request.readerInstanceId,
          readerStartNonce: request.readerStartNonce,
          readerProjectionFingerprint: readerProjection?.readerProjectionFingerprint ?? null,
          ackFingerprint: admissionAck?.ackFingerprint ?? null,
          finalityProofFingerprint: finalityProof.finalityProofFingerprint, phase: "terminal", receiptFingerprint: null,
        };
        receipt.receiptFingerprint = recordHash(receipt, "receiptFingerprint");
        validateGenesisReceipt(receipt, request, zFinality, finalityProof);
        await this.native.writeFinalityProof(finalityProof);
        await this.native.writeGenesisReceipt(receipt);
        if (await this.native.recheckAdmissionFinality({ request, zFinality, readerProjection, admissionAck, finalityProof, receipt }) !== true) throw new Error("FINALITY_RECHECK_FAILED");
        const historyMarker = {
          version: 1,
          fenceGeneration: 1,
          kind: "managed-history-marker",
          anchorFingerprint,
          sequence: 1,
          previousMarkerFingerprint: null,
          markerFingerprint: null,
        };
        historyMarker.markerFingerprint = recordHash(historyMarker, "markerFingerprint");
        const committedHistory = await this.native.commitManagedHistoryMarker(historyMarker);
        if (!committedHistory ||
            canonicalJsonHash(committedHistory) !== canonicalJsonHash(historyMarker) ||
            canonicalJsonHash(await this.native.readManagedHistoryMarker()) !== canonicalJsonHash(historyMarker)) {
          throw new Error("MANAGED_HISTORY_MARKER_REQUIRED");
        }
        if (await this.native.recheckAdmissionFinality({ request, zFinality, readerProjection, admissionAck, finalityProof, receipt }) !== true) throw new Error("FINALITY_RECHECK_FAILED");
        const reopened = await this.native.reopenAdmission({ txId, finalityFingerprint: finalityProof.finalityProofFingerprint }) === true;
        state.tokenFloor = committedFloor;
        state.tokenAttestation = { fingerprint: hostSetFingerprint, generation, attestationFingerprint: attestation.attestationFingerprint, finalityFingerprint: committedFloor.floorFingerprint };
        state.recovery.finalityFingerprint = receipt.receiptFingerprint;
        state.genesis = { txId, fenceGeneration: 1, replayFingerprint, genesisSecurityTuple: persistedGenesisSecurityTuple, requestFingerprint: request.requestFingerprint, finalityFingerprint: receipt.receiptFingerprint };
        state.recovery = { ...state.recovery, phase: "terminal", readerHandshake: null, replayFingerprint };
        state.admission = reopened
          ? { phase: "open", finalityFingerprint: finalityProof.finalityProofFingerprint }
          : { phase: "closed", finalityFingerprint: null };
        state.tokenConfigGeneration = generation;
        state.authorityEpoch = committedAuthorityEpoch.epoch;
        state.revision += 1;
        if (!await this.native.compareAndSwapManagementState(state.revision - 1, state)) throw new Error("MANUAL_CLEANUP_REQUIRED");
        try {
          await this.#audit({ actorPrincipal, action: "genesis", targetPrincipal, result: "terminal", details: { txId, requestFingerprint: request.requestFingerprint, finalityFingerprint: state.recovery.finalityFingerprint } });
        } catch (error) {
          await this.#manualCleanup(state, safe(error).code);
        }
        return { genesisTxId: txId, authorityEpoch: state.authorityEpoch, tokenConfigGeneration: state.tokenConfigGeneration, reopened, routeDisposition: "no-route" };
      } catch (error) {
        if (["MANUAL_CLEANUP_REQUIRED", "MANUAL_CLEANUP_DURABILITY_FAILED"].includes(safe(error).code)) throw error;
        if (nativeMutation) {
          let preservePending = genesisHandshakePending;
          if (!preservePending && state.recovery?.phase === "handshake-pending" && state.recovery.readerHandshake) {
            try {
              const durable = await this.#read();
              preservePending = durable.recovery?.phase === "handshake-pending" &&
                durable.recovery.txId === state.recovery.txId &&
                durable.recovery.readerHandshake?.requestFingerprint === state.recovery.readerHandshake.requestFingerprint &&
                durable.recovery.readerHandshake?.grantFingerprint === state.recovery.readerHandshake.grantFingerprint;
            } catch {
              preservePending = false;
            }
          }
          if (!preservePending) await this.#manualCleanup(state, safe(error).code);
        }
        throw error;
      }
    });
  }

  async #authenticated(command, input) {
    const target = input.targetPrincipal === undefined ? null : principal(input.targetPrincipal, "TARGET_PRINCIPAL");
    const actor = { actorPrincipal: input.actorPrincipal, secret: input.actorSecret };
    if (command === "auth-add") return this.#mutate(command, input, (state) => ({ epoch: addCredential(state, actor, target, input.targetSecret) }));
    if (command === "auth-rotate") return this.#mutate(command, input, (state) => ({ epoch: rotateCredential(state, actor, target, input.targetSecret) }));
    if (command === "auth-revoke") return this.#mutate(command, input, (state) => ({ epoch: revokeCredential(state, actor, target) }));
    if (command === "status") return this.#readAuthenticated(input, (state) => ({ authorityEpoch: state.authorityEpoch, tokenConfigGeneration: state.tokenConfigGeneration, genesis: Boolean(state.genesis), recovery: state.recovery?.phase ?? null, routeDisposition: "no-route" }));
    if (command === "tokens-attest") return this.#tokensAttest(input);
    if (["mapping-validate", "mapping-snapshot"].includes(command)) return this.#readAuthenticated(input, (state, identity) => this.#mapping(command, state, identity, input));
    if (["mapping-reconcile", "mapping-revoke", "mapping-rollback", "recover"].includes(command)) return this.#mappingMutation(command, input);
    throw new Error("COMMAND_INVALID");
  }
  #assertLegacyRetainedPredecessor(request, proof, finality = null) {
    const predecessorEnvelope =
      proof?.fenceGeneration === request.previousFenceGeneration &&
      proof.wrapperFingerprint === request.previousWrapperFingerprint;
    const successorEnvelope =
      finality !== null &&
      proof?.fenceGeneration === request.candidateFenceGeneration &&
      proof.wrapperFingerprint === finality.wrapperFingerprint &&
      proof.controlRootFingerprint === finality.controlRootFingerprint;
    if (request.targetState !== "legacy-retained" ||
        proof?.sourceKind !== "legacy-retained" ||
        !Buffer.isBuffer(proof.targetBytes) ||
        (!predecessorEnvelope && !successorEnvelope) ||
        proof.targetFingerprint !== request.previousTargetFingerprint ||
        proof.snapshotFingerprint !== request.previousSnapshotFingerprint ||
        !/^[a-f0-9]{64}$/.test(proof.identityFingerprint) ||
        !/^[a-f0-9]{64}$/.test(proof.aclFingerprint) ||
        !/^[a-f0-9]{64}$/.test(proof.controlRootFingerprint)) {
      throw new Error("SUCCESSOR_RECOVERY_EVIDENCE_INVALID");
    }
    return proof;
  }
  #terminalizationSuffix(state, suffix) {
    const current = state?.recovery?.terminalization;
    if (!current) return null;
    if (current.kind !== "authority-successor-terminalization" ||
        current.version !== 1 || current.phase !== "prepared" ||
        current.txId !== suffix.txId ||
        current.requestFingerprint !== suffix.requestFingerprint ||
        current.suffixFingerprint !== recordHash(current, "suffixFingerprint")) {
      throw new Error("SUCCESSOR_TERMINALIZATION_INVALID");
    }
    return current;
  }
  #validateTerminalizationSuffix(suffix) {
    if (!suffix || suffix.kind !== "authority-successor-terminalization" || suffix.version !== 1 ||
        suffix.phase !== "prepared" || typeof suffix.txId !== "string" ||
        !/^[a-f0-9]{64}$/.test(suffix.requestFingerprint) ||
        suffix.suffixFingerprint !== recordHash(suffix, "suffixFingerprint")) {
      throw new Error("SUCCESSOR_TERMINALIZATION_INVALID");
    }
    validateAuthoritySuccessorRequest(suffix.request);
    validateAuthoritySuccessorFinality(suffix.finality, suffix.request);
    validateAuthoritySuccessorReceipt(
      suffix.receipt,
      suffix.request,
      suffix.finality,
      suffix.lease,
      suffix.projection,
      suffix.ack,
    );
    validateManagedHistoryMarker(suffix.marker, suffix.request.anchorFingerprint, suffix.request.sequence);
    validateAuthoritySuccessorHeadTransition(suffix.pendingHead, suffix.terminalHead, suffix.request);
    if (!suffix.finalState || suffix.finalState.recovery?.phase !== "terminal" ||
        suffix.finalState.recovery.txId !== suffix.txId ||
        suffix.finalState.recovery.successorHeadFingerprint !== suffix.terminalHead.headFingerprint) {
      throw new Error("SUCCESSOR_TERMINALIZATION_STATE_INVALID");
    }
    return suffix;
  }
  async #resumeTerminalization(state, suffix) {
    this.#validateTerminalizationSuffix(suffix);
    let head = await this.native.readAuthoritySuccessorHeadRaw();
    if (!head || head.txId !== suffix.txId ||
        (head.phase !== "terminal" && head.headFingerprint !== suffix.pendingHead.headFingerprint) ||
        (head.phase === "terminal" && head.headFingerprint !== suffix.terminalHead.headFingerprint)) {
      throw new Error("SUCCESSOR_TERMINALIZATION_HEAD_INVALID");
    }
    await this.native.writeAuthoritySuccessorReceipt(suffix.receipt);
    const marker = await this.native.readManagedHistoryMarker();
    if (marker === null || marker.markerFingerprint !== suffix.marker.markerFingerprint) {
      if (marker !== null &&
          (marker.sequence !== suffix.marker.sequence - 1 ||
           marker.markerFingerprint !== suffix.marker.previousMarkerFingerprint)) {
        throw new Error("SUCCESSOR_TERMINALIZATION_MARKER_INVALID");
      }
      await this.native.commitManagedHistoryMarker(suffix.marker);
    }
    let current = await this.#read();
    if (current.recovery?.phase !== "terminal" ||
        current.recovery.txId !== suffix.txId ||
        current.recovery.successorHeadFingerprint !== suffix.terminalHead.headFingerprint) {
      if (current.revision !== suffix.finalState.revision) {
        throw new Error("SUCCESSOR_TERMINALIZATION_STATE_INVALID");
      }
      if (!await this.native.compareAndSwapManagementState(current.revision, structuredClone(suffix.finalState))) {
        throw new Error("CAS_CONFLICT");
      }
      current = await this.#read();
    }
    head = await this.native.readAuthoritySuccessorHeadRaw();
    if (head.phase !== "terminal") {
      if (head.headFingerprint !== suffix.pendingHead.headFingerprint) {
        throw new Error("SUCCESSOR_TERMINALIZATION_HEAD_INVALID");
      }
      await this.native.writeAuthoritySuccessorHead(suffix.terminalHead);
    } else if (head.headFingerprint !== suffix.terminalHead.headFingerprint) {
      throw new Error("SUCCESSOR_TERMINALIZATION_HEAD_INVALID");
    }
    return {
      pending: false,
      idempotent: true,
      txId: suffix.txId,
      phase: "terminal",
      receiptFingerprint: suffix.receipt.receiptFingerprint,
      routeDisposition: "no-route",
    };
  }
  async #persistTerminalization({ state, suffix }) {
    this.#validateTerminalizationSuffix(suffix);
    const existing = this.#terminalizationSuffix(state, suffix);
    if (existing) return existing;
    const pendingState = structuredClone(suffix.finalState);
    pendingState.recovery = {
      ...structuredClone(suffix.finalState.recovery),
      phase: "terminalizing",
      successorPhase: "terminalizing",
      terminalization: structuredClone(suffix),
      routeDisposition: "no-route",
    };
    Object.assign(state.recovery ?? (state.recovery = {}), pendingState.recovery);
    try {
      if (!await this.native.compareAndSwapManagementState(state.revision, pendingState)) {
        const reopened = await this.#read();
        this.#terminalizationSuffix(reopened, suffix);
        throw new Error("CAS_CONFLICT");
      }
    } catch (error) {
      try {
        const reopened = await this.#read();
        this.#terminalizationSuffix(reopened, suffix);
      } catch {}
      throw error;
    }
    return suffix;
  }
  async #terminalizeSuccessor({ state, request, finality, lease = null, projection = null, ack = null, receipt, marker, pendingHead, terminalHead, finalState }) {
    const suffix = {
      version: 1,
      kind: "authority-successor-terminalization",
      phase: "prepared",
      txId: request.txId,
      requestFingerprint: request.requestFingerprint,
      request: structuredClone(request),
      finality: structuredClone(finality),
      lease: lease === null ? null : structuredClone(lease),
      projection: projection === null ? null : structuredClone(projection),
      ack: ack === null ? null : structuredClone(ack),
      receipt: structuredClone(receipt),
      marker: structuredClone(marker),
      pendingHead: structuredClone(pendingHead),
      terminalHead: structuredClone(terminalHead),
      finalState: structuredClone(finalState),
      suffixFingerprint: null,
    };
    suffix.suffixFingerprint = recordHash(suffix, "suffixFingerprint");
    const persisted = await this.#persistTerminalization({ state, suffix });
    return this.#resumeTerminalization(state, persisted);
  }
  async #completeBoundSuccessor(state, txId) {
    if (typeof this.native.readSuccessorBundle !== "function" ||
        typeof this.native.readSuccessorRecovery !== "function" ||
        typeof this.native.writeAuthoritySuccessorReceipt !== "function") {
      throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    }
    const terminalization = state.recovery?.terminalization;
    if (terminalization?.txId === txId) return this.#resumeTerminalization(state, terminalization);
    const bundle = await this.native.readSuccessorBundle();
    if (!bundle || bundle.head.txId !== txId || bundle.head.phase !== "reader-pending" || !bundle.lease || !bundle.projection || !bundle.ack) return null;
    validateAuthoritySuccessorBundle(bundle);
    if (bundle.request.targetState === "legacy-retained") throw new Error("LEGACY_READER_HANDSHAKE_REFUSED");
    validateReaderVersionFloor(bundle.readerFloor);
    if (bundle.readerFloor.readerVersionFloor !== 2 || bundle.request.readerMode !== "bound-reader") {
      throw new Error("READER_FLOOR_PROOF_MISMATCH");
    }
    validateManagedHistoryMarker(bundle.historyMarker, bundle.request.anchorFingerprint, bundle.request.sequence - 1);
    const { request, finality, lease, projection, ack, head } = bundle;
    const recovery = await this.native.readSuccessorRecovery({
      predecessorReceiptFingerprint: request.previousReceiptFingerprint,
    });
    if (!recovery ||
        recovery.predecessorReceiptFingerprint !== request.previousReceiptFingerprint ||
        recovery.predecessorTargetFingerprint !== request.previousTargetFingerprint ||
        recovery.predecessorWrapperFingerprint !== request.previousWrapperFingerprint ||
        recovery.predecessorSnapshotFingerprint !== request.previousSnapshotFingerprint ||
        recovery.candidateTargetFingerprint !== request.candidateTargetFingerprint ||
        recovery.candidateConfigFingerprint !== request.candidateSnapshotFingerprint ||
        recovery.sequence !== request.sequence ||
        recovery.phase !== "reader-pending" ||
        recovery.headFingerprint !== head.headFingerprint ||
        recovery.phaseRecordFingerprint !== finality.finalityFingerprint ||
        recovery.fenceGeneration !== finality.fenceGeneration ||
        !recovery.candidateState ||
        canonicalJsonHash(recovery.candidateState) !== recovery.candidateStateFingerprint) {
      throw new Error("SUCCESSOR_RECOVERY_EVIDENCE_INVALID");
    }
    validateManagedChannelsV2(recovery.candidateState);
    if (recovery.candidateState.revision !== finality.revision ||
        recovery.candidateState.authorityEpoch !== finality.authorityEpoch ||
        recovery.candidateState.mappingGeneration !== finality.mappingGeneration ||
        recovery.candidateState.fenceGeneration !== finality.fenceGeneration ||
        recovery.candidateState.configFingerprint !== recovery.candidateConfigFingerprint) {
      throw new Error("SUCCESSOR_RECOVERY_STATE_INVALID");
    }
    const lineage = await this.native.readSuccessorTokenLineage();
    assertCommittedTokenLineage(lineage, finality, bundle.baseline, {
      requireSuccessorFence: request.operation === "tokens-attest",
      successorTxId: request.operation === "tokens-attest" ? txId : null,
    });
    const receipt = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-receipt", sequence: request.sequence, txId, rootGenesisTxId: request.rootGenesisTxId,
      operation: request.operation, requestFingerprint: request.requestFingerprint, previousReceiptFingerprint: request.previousReceiptFingerprint,
      finalityFingerprint: finality.finalityFingerprint, readerMode: "bound-reader",
      leaseBindingFingerprint: lease.leaseBindingFingerprint, readerProjectionFingerprint: projection.readerProjectionFingerprint, ackFingerprint: ack.ackFingerprint,
      snapshotFingerprint: finality.snapshotFingerprint, revision: finality.revision, authorityEpoch: finality.authorityEpoch,
      tokenConfigGeneration: finality.tokenConfigGeneration, mappingGeneration: finality.mappingGeneration,
      fenceGeneration: finality.fenceGeneration,
      phase: "terminal", routeDisposition: "no-route", receiptFingerprint: null,
    }, "receiptFingerprint");
    validateAuthoritySuccessorReceipt(receipt, request, finality, lease, projection, ack);
    const previousMarker = await this.native.readManagedHistoryMarker();
    validateManagedHistoryMarker(previousMarker, request.anchorFingerprint, request.sequence - 1);
    const marker = {
      version: 1,
      kind: "managed-history-marker",
      anchorFingerprint: request.anchorFingerprint,
      fenceGeneration: request.candidateFenceGeneration,
      sequence: request.sequence,
      previousMarkerFingerprint: previousMarker.markerFingerprint,
      markerFingerprint: null,
    };
    marker.markerFingerprint = recordHash(marker, "markerFingerprint");
    const terminal = buildAuthoritySuccessorRecord({
      ...head,
      phase: "terminal",
      receiptFingerprint: receipt.receiptFingerprint,
      historyMarkerFingerprint: marker.markerFingerprint,
      previousHeadFingerprint: head.headFingerprint,
      headFingerprint: null,
    }, "headFingerprint");
    validateAuthoritySuccessorHeadTransition(head, terminal, request);
    const terminalState = structuredClone(state);
    terminalState.revision = finality.revision;
    terminalState.authorityEpoch = finality.authorityEpoch;
    terminalState.tokenConfigGeneration = finality.tokenConfigGeneration;
    terminalState.mappingGeneration = finality.mappingGeneration;
    terminalState.mappings = structuredClone(recovery.candidateState.mappings);
    terminalState.routes = structuredClone(recovery.candidateState.routes);
    terminalState.admission = { phase: "closed", finalityFingerprint: null };
    terminalState.tokenFloor = structuredClone(lineage.floor);
    terminalState.tokenAttestation = {
      fingerprint: lineage.attestation.tokenConfigHostSetFingerprint,
      generation: lineage.attestation.tokenConfigGeneration,
      attestationFingerprint: lineage.attestation.attestationFingerprint,
      finalityFingerprint: lineage.floor.floorFingerprint,
    };
    terminalState.fenceGeneration = finality.fenceGeneration;
    terminalState.recovery = {
      ...terminalState.recovery,
      phase: "terminal",
      successorPhase: "terminal",
      txId,
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: terminal.headFingerprint,
      fenceGeneration: finality.fenceGeneration,
      finalityFingerprint: finality.finalityFingerprint,
    };
    return this.#terminalizeSuccessor({
      state,
      request,
      finality,
      lease,
      projection,
      ack,
      receipt,
      marker,
      pendingHead: head,
      terminalHead: terminal,
      finalState: terminalState,
    });
  }
  async #completeNoReaderSuccessor(state, txId, bundle = null) {
    if (typeof this.native.readSuccessorBundle !== "function" ||
        typeof this.native.readSuccessorRecovery !== "function" ||
        typeof this.native.writeAuthoritySuccessorReceipt !== "function") {
      throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    }
    const terminalization = state.recovery?.terminalization;
    if (terminalization?.txId === txId) return this.#resumeTerminalization(state, terminalization);
    const successor = bundle ?? await this.native.readSuccessorBundle();
    if (!successor || successor.head.txId !== txId || successor.head.phase !== "reader-pending") return null;
    validateAuthoritySuccessorBundle(successor);
    validateReaderVersionFloor(successor.readerFloor);
    if (!successor.baseline || successor.readerFloor.readerVersionFloor !== null || successor.request.readerMode !== "no-reader" ||
        successor.fence !== null || successor.lease !== null || successor.projection !== null || successor.ack !== null) {
      throw new Error("READER_FLOOR_PROOF_MISMATCH");
    }
    const { request, finality, baseline, head } = successor;
    const legacyRetained = request.targetState === "legacy-retained";
    const retained = legacyRetained ? this.#assertLegacyRetainedPredecessor(request, await this.native.readRetainedTargetProof(), finality) : null;
    const recovery = await this.native.readSuccessorRecovery({
      predecessorReceiptFingerprint: request.previousReceiptFingerprint,
    });
    if (!recovery ||
        recovery.predecessorReceiptFingerprint !== request.previousReceiptFingerprint ||
        recovery.predecessorTargetFingerprint !== request.previousTargetFingerprint ||
        recovery.predecessorWrapperFingerprint !== request.previousWrapperFingerprint ||
        recovery.predecessorSnapshotFingerprint !== request.previousSnapshotFingerprint ||
        recovery.candidateTargetFingerprint !== request.candidateTargetFingerprint ||
        recovery.candidateConfigFingerprint !== request.candidateSnapshotFingerprint ||
        recovery.sequence !== request.sequence ||
        recovery.phase !== "reader-pending" ||
        recovery.headFingerprint !== head.headFingerprint ||
        recovery.phaseRecordFingerprint !== finality.finalityFingerprint ||
        recovery.fenceGeneration !== finality.fenceGeneration ||
        (legacyRetained
          ? (!Buffer.isBuffer(recovery.candidateTargetBytes) ||
             !recovery.candidateTargetBytes.equals(retained.targetBytes) ||
             recovery.candidateTargetIdentityFingerprint !== retained.identityFingerprint ||
             recovery.candidateTargetAclFingerprint !== retained.aclFingerprint)
          : (!recovery.candidateState ||
             canonicalJsonHash(recovery.candidateState) !== recovery.candidateStateFingerprint))) {
      throw new Error("SUCCESSOR_RECOVERY_EVIDENCE_INVALID");
    }
    if (!legacyRetained) {
      validateManagedChannelsV2(recovery.candidateState);
      if (recovery.candidateState.revision !== finality.revision ||
          recovery.candidateState.authorityEpoch !== finality.authorityEpoch ||
          recovery.candidateState.mappingGeneration !== finality.mappingGeneration ||
          recovery.candidateState.fenceGeneration !== finality.fenceGeneration ||
          recovery.candidateState.configFingerprint !== recovery.candidateConfigFingerprint) {
        throw new Error("SUCCESSOR_RECOVERY_STATE_INVALID");
      }
    }
    const lineage = await this.native.readSuccessorTokenLineage();
    assertCommittedTokenLineage(lineage, finality, baseline, {
      requireSuccessorFence: request.operation === "tokens-attest",
      successorTxId: request.operation === "tokens-attest" ? txId : null,
    });
    const receipt = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-receipt", sequence: request.sequence, txId, rootGenesisTxId: request.rootGenesisTxId,
      operation: request.operation, requestFingerprint: request.requestFingerprint, previousReceiptFingerprint: request.previousReceiptFingerprint,
      finalityFingerprint: finality.finalityFingerprint, readerMode: "no-reader",
      leaseBindingFingerprint: null, readerProjectionFingerprint: null, ackFingerprint: null,
      snapshotFingerprint: finality.snapshotFingerprint, revision: finality.revision, authorityEpoch: finality.authorityEpoch,
      tokenConfigGeneration: finality.tokenConfigGeneration, mappingGeneration: finality.mappingGeneration,
      fenceGeneration: finality.fenceGeneration,
      phase: "terminal", routeDisposition: "no-route", receiptFingerprint: null,
    }, "receiptFingerprint");
    validateAuthoritySuccessorReceipt(receipt, request, finality);
    const previousMarker = await this.native.readManagedHistoryMarker();
    validateManagedHistoryMarker(previousMarker, request.anchorFingerprint, request.sequence - 1);
    const marker = {
      version: 1,
      kind: "managed-history-marker",
      anchorFingerprint: request.anchorFingerprint,
      fenceGeneration: request.candidateFenceGeneration,
      sequence: request.sequence,
      previousMarkerFingerprint: previousMarker.markerFingerprint,
      markerFingerprint: null,
    };
    marker.markerFingerprint = recordHash(marker, "markerFingerprint");
    const terminal = buildAuthoritySuccessorRecord({
      ...head,
      phase: "terminal",
      receiptFingerprint: receipt.receiptFingerprint,
      historyMarkerFingerprint: marker.markerFingerprint,
      previousHeadFingerprint: head.headFingerprint,
      headFingerprint: null,
    }, "headFingerprint");
    validateAuthoritySuccessorHeadTransition(head, terminal, request);
    const terminalState = structuredClone(state);
    terminalState.revision = finality.revision;
    terminalState.authorityEpoch = finality.authorityEpoch;
    terminalState.tokenConfigGeneration = finality.tokenConfigGeneration;
    terminalState.mappingGeneration = finality.mappingGeneration;
    if (!legacyRetained) {
      terminalState.mappings = structuredClone(recovery.candidateState.mappings);
      terminalState.routes = structuredClone(recovery.candidateState.routes);
    }
    terminalState.tokenFloor = structuredClone(lineage.floor);
    terminalState.tokenAttestation = {
      fingerprint: baseline.tokenConfigHostSetFingerprint,
      generation: finality.tokenConfigGeneration,
      attestationFingerprint: finality.attestationFingerprint,
      finalityFingerprint: finality.tokenFloorFingerprint,
    };
    terminalState.admission = { phase: "closed", finalityFingerprint: null };
    terminalState.fenceGeneration = finality.fenceGeneration;
    terminalState.recovery = {
      phase: "terminal",
      txId,
      fenceGeneration: finality.fenceGeneration,
      finalityFingerprint: finality.finalityFingerprint,
      successorHeadFingerprint: terminal.headFingerprint,
    };
    return this.#terminalizeSuccessor({
      state,
      request,
      finality,
      receipt,
      marker,
      pendingHead: head,
      terminalHead: terminal,
      finalState: terminalState,
    });
  }
  async #recoverSuccessorHead({ state, input, actorPrincipal, operation, txId, intent, head }) {
    const recovery = {
      ...(state.recovery ?? {}),
      txId: head.txId,
      phase: head.phase,
      successorPhase: head.phase,
      requestFingerprint: head.requestFingerprint,
      successorHeadFingerprint: head.headFingerprint,
      routeDisposition: "no-route",
    };
    const terminalization = state.recovery?.terminalization;
    if (terminalization?.txId === head.txId) {
      try {
        if (terminalization.request?.actorPrincipalFingerprint !== canonicalJsonHash(actorPrincipal) ||
            terminalization.request?.idempotencyKey !== input.idempotencyKey ||
            terminalization.request?.operation !== operation) {
          throw new Error("RECOVERY_INPUT_MISMATCH");
        }
        return await this.#resumeTerminalization(state, terminalization);
      } catch {
        await this.#manualCleanup(state, "SUCCESSOR_TERMINALIZATION_INVALID", {
          ...recovery,
          terminalization,
        });
      }
    }
    if (head.txId !== txId) await this.#manualCleanup(state, "RECOVERY_INPUT_MISMATCH", recovery);
    let bundle;
    try {
      if (typeof this.native.readSuccessorBundle !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
      bundle = await this.native.readSuccessorBundle();
      if (!bundle || bundle.head.headFingerprint !== head.headFingerprint ||
          bundle.request.txId !== txId ||
          bundle.request.actorPrincipalFingerprint !== canonicalJsonHash(actorPrincipal) ||
          bundle.request.idempotencyKey !== input.idempotencyKey ||
          bundle.request.operation !== operation ||
          bundle.request.previousRevision !== intent.expectedRevision) {
        throw new Error("RECOVERY_INPUT_MISMATCH_HEAD");
      }
      const retained = await this.native.readRetainedTargetProof();
      if (retained.sourceKind === "legacy-retained") {
        this.#assertLegacyRetainedPredecessor(bundle.request, retained, bundle.finality);
        if (operation !== "tokens-attest") throw new Error("RECOVERY_INPUT_MISMATCH_LEGACY");
      } else if (retained.sourceKind === "managed-v1") {
        if (bundle.request.targetState === "legacy-retained") throw new Error("RECOVERY_INPUT_MISMATCH_SOURCE");
        if (operation === "tokens-attest") {
          if (bundle.baseline?.tokenConfigHostSetFingerprint !== intent.hostSetFingerprint) {
            throw new Error("RECOVERY_INPUT_MISMATCH_TOKENS");
          }
        } else {
          const recoveryState = structuredClone(state);
          recoveryState.authorityEpoch = bundle.request.candidateAuthorityEpoch - 1;
          recoveryState.fenceGeneration = bundle.request.candidateFenceGeneration;
          const prepared = await this.#prepareMappingMutation(operation, recoveryState, input);
          if (prepared.snapshot.configFingerprint !== bundle.request.candidateSnapshotFingerprint) {
            throw new Error("RECOVERY_INPUT_MISMATCH");
          }
          if (canonicalJsonHash({ operation, mappingId: input.mappingId ?? null, snapshotFingerprint: prepared.snapshot.configFingerprint }) !== bundle.request.mappingRecoveryTxFingerprint) {
            throw new Error("RECOVERY_INPUT_MISMATCH");
          }
        }
      } else {
        throw new Error("RECOVERY_INPUT_MISMATCH_SOURCE");
      }
    } catch {
      await this.#manualCleanup(state, "RECOVERY_INPUT_MISMATCH", recovery);
    }
    if (head.phase === "reader-pending") {
      if (bundle.request.readerMode === "no-reader") {
        return (await this.#completeNoReaderSuccessor(state, txId, bundle)) ?? {
          pending: true, idempotent: true, txId, phase: head.phase, routeDisposition: "no-route",
        };
      }
      return (await this.#completeBoundSuccessor(state, txId)) ?? {
        pending: true, idempotent: true, txId, phase: head.phase, routeDisposition: "no-route",
      };
    }
    await this.#manualCleanup(state, "SUCCESSOR_RECOVERY_NATIVE_UNAVAILABLE", recovery);
  }

  async #reserveSuccessor(operation, input, state, actorPrincipal) {
    const mutation = { attempted: false, recovery: null };
    try {
      return await this.#reserveSuccessorMutation(operation, input, state, actorPrincipal, mutation);
    } catch (error) {
      if (!mutation.attempted) throw error;
      await this.#manualCleanup(state, safe(error).code, mutation.recovery);
      throw error;
    }
  }
  async #reserveSuccessorMutation(operation, input, state, actorPrincipal, mutation) {
    for (const method of ["writeAuthoritySuccessorRequest", "writeAuthoritySuccessorHead", "writeAuthoritySuccessorClose", "writeAuthoritySuccessorReservation", "writeAuthoritySuccessorCommit", "writeAuthoritySuccessorBaseline", "writeSuccessorPublicationGraph", "mappingTargetProof", "readRetainedTargetProof", "readAuthoritySuccessorHead"]) {
      if (typeof this.native[method] !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    }
    if (!state.genesis?.txId || !state.genesis?.requestFingerprint) throw new Error("GENESIS_REQUIRED");
    const anchorFingerprint = await this.native.managementAnchorFingerprint();
    if (typeof input.idempotencyKey !== "string" || input.idempotencyKey.length === 0) throw new Error("IDEMPOTENCY_KEY_REQUIRED");
    const intent = {
      anchorFingerprint, actorPrincipalFingerprint: canonicalJsonHash(actorPrincipal), operation,
      idempotencyKey: input.idempotencyKey, expectedRevision: input.expectedRevision ?? state.revision,
      expectedFingerprint: input.expectedFingerprint ?? null,
      hostSetFingerprint: operation === "tokens-attest" ? protectedTokenFingerprint(input.hostTokens) : null,
      mappingId: input.mappingId ?? null,
    };
    const txId = `successor-${canonicalJsonHash(intent)}`;
    const setRecovery = (patch = {}) => {
      const recovery = {
        ...(mutation.recovery ?? state.recovery ?? {}),
        txId,
        ...patch,
        routeDisposition: "no-route",
      };
      mutation.recovery = recovery;
      state.recovery = recovery;
    };
    let existing;
    try {
      existing = await this.native.readAuthoritySuccessorHead();
    } catch {
      let recovery = state.recovery;
      try {
        const rawHead = await this.native.readAuthoritySuccessorHeadRaw();
        recovery = {
          ...(state.recovery ?? {}),
          txId: rawHead.txId,
          phase: rawHead.phase,
          successorPhase: rawHead.phase,
          requestFingerprint: rawHead.requestFingerprint,
          successorHeadFingerprint: rawHead.headFingerprint,
          routeDisposition: "no-route",
        };
      if (recovery.terminalization?.txId && recovery.terminalization?.txId === recovery.txId &&
          recovery.terminalization.request?.idempotencyKey === input.idempotencyKey &&
          recovery.terminalization.request?.operation === operation) {
        mutation.attempted = true;
        mutation.recovery = recovery;
        state.recovery = recovery;
        return this.#resumeTerminalization(state, recovery.terminalization);
      }
      } catch {
        // Preserve the state-bound recovery when the active head cannot be reopened.
      }
      await this.#manualCleanup(state, "SUCCESSOR_FLOOR_OR_HISTORY_MARKER_INVALID", recovery);
    }
    if (existing !== null && existing.phase !== "terminal") {
      setRecovery({
        phase: existing.phase,
        successorPhase: existing.phase,
        requestFingerprint: existing.requestFingerprint,
        successorHeadFingerprint: existing.headFingerprint,
      });
      mutation.attempted = true;
      return this.#recoverSuccessorHead({ state, input, actorPrincipal, operation, txId, intent, head: existing });
    }
    let durableReaderProof;
    let readerFloor;
    let historyMarker;
    let readerMode;
    let fenceFloor;
    try {
      durableReaderProof = await this.native.readBoundReaderProof();
      readerFloor = durableReaderProof?.readerVersionFloor;
      validateReaderVersionFloor(readerFloor);
      fenceFloor = await this.native.readFenceGenerationFloor();
      if (!fenceFloor || fenceFloor.highestCommittedFenceGeneration !== state.fenceGeneration) throw new Error("FENCE_FLOOR_PROOF_MISMATCH");
      const hasBoundProof = Boolean(durableReaderProof.readerProjection && durableReaderProof.admissionAck && durableReaderProof.readerState);
      if (readerFloor.readerVersionFloor === 2) {
        if (!hasBoundProof) throw new Error("READER_BOUND_PROOF_REQUIRED");
        readerMode = "bound-reader";
      } else {
        if (hasBoundProof) throw new Error("READER_FLOOR_PROOF_MISMATCH");
        readerMode = "no-reader";
      }
      historyMarker = await this.native.readManagedHistoryMarker();
      validateManagedHistoryMarker(historyMarker, anchorFingerprint);
    } catch {
      await this.#manualCleanup(state, "READER_FLOOR_OR_HISTORY_MARKER_INVALID");
    }
    const previousFenceGeneration = fenceFloor.highestCommittedFenceGeneration;
    const candidateFenceGeneration = previousFenceGeneration + 1;
    const readerInstanceId = readerMode === "bound-reader" ? durableReaderProof.readerProjection.readerInstanceId : null;
    const readerStartNonce = readerMode === "bound-reader" ? durableReaderProof.readerProjection.readerStartNonce : null;
    if (readerMode === "bound-reader" && (!readerInstanceId || !readerStartNonce)) throw new Error("READER_BINDING_REQUIRED");
    const sequence = historyMarker.sequence + 1;
    const predecessor = await this.native.readRetainedTargetProof();
    if (!predecessor ||
        !/^[a-f0-9]{64}$/.test(predecessor.targetFingerprint) ||
        !/^[a-f0-9]{64}$/.test(predecessor.identityFingerprint) ||
        !Number.isSafeInteger(predecessor.fenceGeneration) || predecessor.fenceGeneration !== previousFenceGeneration ||
        !/^[a-f0-9]{64}$/.test(predecessor.aclFingerprint) ||
        !["managed-v1", "legacy-retained"].includes(predecessor.sourceKind) ||
        !Buffer.isBuffer(predecessor.targetBytes)) {
      throw new Error("RETAINED_TARGET_PROOF_REQUIRED");
    }
    if (operation !== "tokens-attest" && predecessor.sourceKind === "legacy-retained") {
      throw new Error("LEGACY_MAPPING_MUTATION_REFUSED");
    }
    const candidateAuthorityEpoch = await this.#nextAuthorityEpoch(state);
    const preparedState = operation === "tokens-attest" ? null : structuredClone(state);
    if (preparedState) preparedState.authorityEpoch = candidateAuthorityEpoch - 1;
    if (preparedState) preparedState.fenceGeneration = candidateFenceGeneration;
    const prepared = preparedState ? await this.#prepareMappingMutation(operation, preparedState, input) : null;
    let candidateSnapshot = prepared?.snapshot ?? null;
    if (operation === "tokens-attest" && predecessor.sourceKind === "managed-v1") {
      const candidateMappings = Object.fromEntries(Object.entries(predecessor.snapshot.mappings).map(([mappingId, mapping]) => [
        mappingId,
        fingerprintManagedMappingRecord({
          ...structuredClone(mapping),
          fenceGeneration: candidateFenceGeneration,
          mappingFingerprint: null,
        }),
      ]));
      const candidateRoutes = Object.fromEntries(Object.entries(predecessor.snapshot.routes).map(([channelId, route]) => {
        const mapping = candidateMappings[route.mappingId];
        if (!mapping) throw new Error("CANDIDATE_TARGET_PROOF_REQUIRED");
        return [channelId, fingerprintManagedRouteRecord({
          ...structuredClone(route),
          fenceGeneration: candidateFenceGeneration,
          hostId: mapping.hostId,
          mappingId: mapping.mappingId,
          mappingGeneration: mapping.mappingGeneration,
          mappingVersion: mapping.mappingVersion,
          sourcePlatform: mapping.sourcePlatform,
          workspaceId: mapping.workspaceId,
          workDir: mapping.workDir,
          routeFingerprint: null,
        }, mapping)];
      }));
      candidateSnapshot = {
        ...structuredClone(predecessor.snapshot),
        mappings: candidateMappings,
        routes: candidateRoutes,
        revision: state.revision + 1,
        authorityEpoch: candidateAuthorityEpoch,
        mappingGeneration: state.mappingGeneration,
        fenceGeneration: candidateFenceGeneration,
        targetState: predecessor.snapshot.targetState === "genesis-empty" ? "managed-empty" : predecessor.snapshot.targetState,
        tokenConfigGeneration: state.tokenConfigGeneration + 1,
        tokenConfigHostSetFingerprint: intent.hostSetFingerprint,
        configFingerprint: null,
      };
      candidateSnapshot.configFingerprint = recordHash(candidateSnapshot, "configFingerprint");
    }
    const candidateSnapshotFingerprint = candidateSnapshot?.configFingerprint ?? predecessor.snapshotFingerprint;
    const candidateTargetFingerprint = candidateSnapshot ? canonicalJsonHash(candidateSnapshot) : predecessor.targetFingerprint;
    const candidateTargetState = candidateSnapshot?.targetState ?? "legacy-retained";
    if (!/^[a-f0-9]{64}$/.test(candidateSnapshotFingerprint) ||
        !/^[a-f0-9]{64}$/.test(candidateTargetFingerprint)) {
      throw new Error("CANDIDATE_TARGET_PROOF_REQUIRED");
    }
    const candidateIdentityFingerprint = predecessor.identityFingerprint;
    const candidateAclFingerprint = predecessor.aclFingerprint;
    const previousFingerprint = predecessor.targetFingerprint;
    const candidateAttestationFingerprint = operation === "tokens-attest"
      ? authorityRecordFingerprint({
        version: 1, kind: "token-config-attestation", anchorFingerprint, fenceGeneration: candidateFenceGeneration,
        tokenConfigGeneration: state.tokenConfigGeneration + 1, tokenConfigHostSetFingerprint: intent.hostSetFingerprint,
        managedGrammarVersion: 1, sourceKind: "protected-stdin", producerPrincipal: `management/${canonicalJsonHash(actorPrincipal)}`,
        rotationKind: state.tokenAttestation?.fingerprint === intent.hostSetFingerprint ? "same-key" : "host-set-change",
        previousAttestationFingerprint: state.tokenAttestation?.attestationFingerprint ?? previousFingerprint, txId,
      }, "attestationFingerprint")
      : state.tokenAttestation?.attestationFingerprint ?? canonicalJsonHash({ genesis: state.genesis.txId });
    let predecessorReceiptFingerprint = state.genesis.finalityFingerprint;
    let predecessorHeadFingerprint = null;
    if (existing === null) validateManagedHistoryMarker(historyMarker, anchorFingerprint, 1);
    if (existing?.phase === "terminal") {
      if (typeof this.native.readSuccessorBundle !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
      const terminalBundle = await this.native.readSuccessorBundle();
      if (!terminalBundle?.receipt ||
          terminalBundle.head?.headFingerprint !== existing.headFingerprint ||
          terminalBundle.receipt.phase !== "terminal") {
        throw new Error("SUCCESSOR_TERMINAL_PREDECESSOR_INVALID");
      }
      validateAuthoritySuccessorBundle(terminalBundle);
      predecessorReceiptFingerprint = terminalBundle.receipt.receiptFingerprint;
      predecessorHeadFingerprint = existing.headFingerprint;
      validateManagedHistoryMarker(terminalBundle.historyMarker, anchorFingerprint, existing.sequence);
      validateReaderVersionFloor(terminalBundle.readerFloor);
      if ((terminalBundle.readerFloor.readerVersionFloor === 2) !== (readerMode === "bound-reader") ||
          terminalBundle.historyMarker.markerFingerprint !== existing.historyMarkerFingerprint) {
        throw new Error("SUCCESSOR_TERMINAL_PREDECESSOR_INVALID");
      }
    }
    if (existing === null && !/^[a-f0-9]{64}$/.test(predecessorReceiptFingerprint)) throw new Error("GENESIS_RECEIPT_REQUIRED");
    const request = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-request", sequence, txId, rootGenesisTxId: state.genesis.txId,
      idempotencyKey: input.idempotencyKey, operation, anchorFingerprint,
      actorPrincipalFingerprint: canonicalJsonHash(actorPrincipal),
      previousReceiptFingerprint: predecessorReceiptFingerprint,
      previousTargetFingerprint: predecessor.targetFingerprint, previousWrapperFingerprint: predecessor.wrapperFingerprint,
      previousRevision: state.revision, candidateRevision: state.revision + 1,
      previousAuthorityEpoch: state.authorityEpoch, candidateAuthorityEpoch,
      previousTokenConfigGeneration: state.tokenConfigGeneration,
      candidateTokenConfigGeneration: state.tokenConfigGeneration + (operation === "tokens-attest" ? 1 : 0),
      previousAttestationFingerprint: state.tokenAttestation?.attestationFingerprint ?? previousFingerprint,
      candidateAttestationFingerprint,
      previousMappingGeneration: state.mappingGeneration,
      candidateMappingGeneration: state.mappingGeneration + (operation === "tokens-attest" ? 0 : 1),
      previousSnapshotFingerprint: predecessor.snapshotFingerprint,
      candidateSnapshotFingerprint,
      candidateTargetFingerprint,
      previousFenceGeneration,
      candidateFenceGeneration,
      mappingRecoveryTxFingerprint: operation === "tokens-attest" ? null : canonicalJsonHash({ operation, mappingId: input.mappingId ?? null, snapshotFingerprint: candidateSnapshotFingerprint }),
      targetState: candidateTargetState,
      readerMode, readerInstanceId, readerStartNonce,
      readerNonce: readerMode === "bound-reader" ? `successor-nonce-${canonicalJsonHash({ txId, readerInstanceId, readerStartNonce })}` : null,
      requestFingerprint: null,
    }, "requestFingerprint");
    validateAuthoritySuccessorRequest(request);
    setRecovery({
      phase: "reserved",
      successorPhase: "reserved",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: null,
      reservationFingerprint: null,
    });
    mutation.attempted = true;
    await this.native.writeAuthoritySuccessorRequest(request);
    await this.native.reserveFenceGeneration({ fenceGeneration: candidateFenceGeneration, txId });
    const head = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-head", anchorFingerprint, fenceGeneration: candidateFenceGeneration, sequence, txId, rootGenesisTxId: state.genesis.txId,
      operation, phase: "reserved", requestFingerprint: request.requestFingerprint,
      closeFingerprint: null, authorityCommitSnapshotFingerprint: null, baselineFingerprint: null,
      publicationKFingerprint: null, publicationYFingerprint: null, finalityFingerprint: null,
      receiptFingerprint: null, historyMarkerFingerprint: null, previousHeadFingerprint: predecessorHeadFingerprint,
      previousReceiptFingerprint: request.previousReceiptFingerprint, routeDisposition: "no-route", headFingerprint: null,
    }, "headFingerprint");
    setRecovery({
      phase: "reserved",
      successorPhase: "reserved",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: head.headFingerprint,
    });
    await this.native.writeAuthoritySuccessorHead(head);
    const close = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-close-proof", txId, rootGenesisTxId: request.rootGenesisTxId, fenceGeneration: candidateFenceGeneration,
      requestFingerprint: request.requestFingerprint, previousReceiptFingerprint: request.previousReceiptFingerprint,
      previousBarrierGeneration: state.revision, barrierGeneration: state.revision + 1,
      affectedScope: operation === "tokens-attest" ? "all" : "mapping",
      affectedMappingIds: operation === "tokens-attest" || input.mappingId === undefined ? [] : [input.mappingId],
      affectedRouteFingerprints: [], readerInstanceId, readerStartNonce,
      retiredGrantFingerprint: null, retiredProjectionFingerprint: durableReaderProof?.readerProjection?.readerProjectionFingerprint ?? null,
      retiredAckFingerprint: durableReaderProof?.admissionAck?.ackFingerprint ?? null,
      admissionPhaseBefore: "closed", admissionPhaseAfter: "closed-drained", admissionDrained: true,
      outstandingRouteGrantCount: 0, routeDisposition: "no-route", closeFingerprint: null,
    }, "closeFingerprint");
    validateAuthorityCloseProof(close, request);
    await this.native.writeAuthoritySuccessorClose(close);
    const closedHead = buildAuthoritySuccessorRecord({
      ...head, phase: "closed", closeFingerprint: close.closeFingerprint, previousHeadFingerprint: head.headFingerprint, headFingerprint: null,
    }, "headFingerprint");
    setRecovery({
      phase: "closed",
      successorPhase: "closed",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: closedHead.headFingerprint,
    });
    await this.native.writeAuthoritySuccessorHead(closedHead);
    const reservation = {
      version: 1, kind: "authority-reservation", anchorFingerprint, fenceGeneration: candidateFenceGeneration, txId,
      epoch: request.candidateAuthorityEpoch, generation: request.candidateTokenConfigGeneration,
      candidateFingerprint: request.requestFingerprint,
      previousAuthorityCommitSnapshotFingerprint: request.previousReceiptFingerprint,
      reservationFingerprint: null,
    };
    reservation.reservationFingerprint = authorityRecordFingerprint(reservation, "reservationFingerprint");
    validateAuthorityReservation(reservation);
    setRecovery({
      phase: "closed",
      successorPhase: "closed",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: closedHead.headFingerprint,
      reservationFingerprint: reservation.reservationFingerprint,
    });
    await this.native.writeAuthoritySuccessorReservation(reservation);
    const commit = {
      version: 1, kind: "authority-commit-snapshot", anchorFingerprint, fenceGeneration: candidateFenceGeneration, txId,
      epoch: reservation.epoch, generation: reservation.generation, candidateFingerprint: reservation.candidateFingerprint,
      reservationFingerprint: reservation.reservationFingerprint,
      previousAuthorityCommitSnapshotFingerprint: reservation.previousAuthorityCommitSnapshotFingerprint,
      authorityCommitSnapshotFingerprint: null,
    };
    commit.authorityCommitSnapshotFingerprint = authorityRecordFingerprint(commit, "authorityCommitSnapshotFingerprint");
    validateAuthorityCommitSnapshot(commit, reservation);
    await this.native.writeAuthoritySuccessorCommit(commit);
    let fence = null;
    if (readerMode === "bound-reader") {
      if (typeof this.native.writeAuthoritySuccessorFence !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
      fence = buildAuthoritySuccessorRecord({
        version: 1, kind: "authority-successor-fence", txId, rootGenesisTxId: request.rootGenesisTxId, fenceGeneration: candidateFenceGeneration,
        requestFingerprint: request.requestFingerprint, anchorFingerprint,
        authorityCommitSnapshotFingerprint: commit.authorityCommitSnapshotFingerprint,
        readerInstanceId, readerStartNonce, readerVersion: 2,
        previousFenceBindingFingerprint: request.previousReceiptFingerprint, fenceBindingFingerprint: null,
      }, "fenceBindingFingerprint");
      validateAuthoritySuccessorFence(fence, request);
      await this.native.writeAuthoritySuccessorFence(fence);
    }
    if (typeof this.native.writeAuthoritySuccessorBaseline !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    const baseline = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-baseline", txId, rootGenesisTxId: request.rootGenesisTxId, fenceGeneration: candidateFenceGeneration,
      requestFingerprint: request.requestFingerprint, anchorFingerprint, operation, targetState: request.targetState,
      revision: request.candidateRevision, authorityEpoch: request.candidateAuthorityEpoch,
      tokenConfigGeneration: request.candidateTokenConfigGeneration,
      tokenConfigHostSetFingerprint: operation === "tokens-attest" ? intent.hostSetFingerprint : state.tokenAttestation.fingerprint,
      mappingGeneration: request.candidateMappingGeneration,
      candidateSnapshotFingerprint: request.candidateSnapshotFingerprint, candidateTargetFingerprint: request.candidateTargetFingerprint,
      attestationFingerprint: request.candidateAttestationFingerprint,
      authorityReservationFingerprint: reservation.reservationFingerprint,
      authorityCommitSnapshotFingerprint: commit.authorityCommitSnapshotFingerprint,
      closeFingerprint: close.closeFingerprint, fenceBindingFingerprint: fence?.fenceBindingFingerprint ?? null,
      leaseBindingFingerprint: null, readerProjectionFingerprint: null, readerInstanceId, readerStartNonce,
      readerVersion: readerMode === "bound-reader" ? 2 : null, baselineFingerprint: null,
    }, "baselineFingerprint");
    await this.native.writeAuthoritySuccessorBaseline(baseline);
    let candidate;
    if (operation === "tokens-attest") {
      if (typeof this.native.readSuccessorTokenLineage !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
      const lineage = await this.native.readSuccessorTokenLineage();
      let attestation;
      if (lineage.floor.floorPhase === "attested" && lineage.floor.lastReservationTxId === txId) {
        attestation = lineage.attestation;
        if (attestation.txId !== txId || attestation.attestationFingerprint !== request.candidateAttestationFingerprint) throw new Error("IDEMPOTENCY_CONFLICT");
      } else {
        const tokenReservation = reserveTokenGeneration(lineage.floor, { generation: request.candidateTokenConfigGeneration, txId, fenceGeneration: candidateFenceGeneration });
        attestation = {
          version: 1, kind: "token-config-attestation", anchorFingerprint, fenceGeneration: candidateFenceGeneration,
          tokenConfigGeneration: request.candidateTokenConfigGeneration,
          tokenConfigHostSetFingerprint: intent.hostSetFingerprint, managedGrammarVersion: 1,
          sourceKind: "protected-stdin", producerPrincipal: `management/${canonicalJsonHash(actorPrincipal)}`,
          rotationKind: lineage.attestation.tokenConfigHostSetFingerprint === intent.hostSetFingerprint ? "same-key" : "host-set-change",
          previousAttestationFingerprint: lineage.attestation.attestationFingerprint, txId, attestationFingerprint: null,
        };
        attestation.attestationFingerprint = authorityRecordFingerprint(attestation, "attestationFingerprint");
        const proof = buildAttestedTokenFloorProof(tokenReservation, attestation);
        const attestedFloor = attestTokenFloor(tokenReservation, proof);
        await this.native.reserveTokenFloor(tokenReservation);
        await this.native.writeTokenConfigAttestation(attestation);
        await this.native.writeAttestedTokenFloor({ reservation: tokenReservation, attestation, proof, floor: attestedFloor });
      }
      await this.native.rotateTokenSidecar({
        generation: request.candidateTokenConfigGeneration,
        fenceGeneration: candidateFenceGeneration,
        hostSetFingerprint: intent.hostSetFingerprint,
        revision: request.candidateRevision,
        authorityEpoch: request.candidateAuthorityEpoch,
        mappingGeneration: request.candidateMappingGeneration,
      });
      candidate = await this.native.readRetainedTargetProof();
    } else {
      if (prepared.tombstone) await this.native.writeMappingTombstone(prepared.tombstone);
      await prepared.publish();
      if (prepared.handoffReceipt) await this.native.writeMappingHandoffReceipt(prepared.handoffReceipt);
      candidate = await this.native.mappingTargetProof();
    }
    if (!candidate) throw new Error("CANDIDATE_TARGET_PROOF_MISMATCH");
    const actualSnapshotFingerprint = candidate.snapshot?.configFingerprint ?? candidate.snapshotFingerprint;
    const actualTargetSemanticFingerprint = candidate.snapshot ? canonicalJsonHash(candidate.snapshot) : candidate.targetFingerprint;
    if (candidate.targetFingerprint !== (candidate.snapshot ? request.candidateTargetFingerprint : predecessor.targetFingerprint) ||
        candidate.identityFingerprint !== candidateIdentityFingerprint ||
        candidate.aclFingerprint !== candidateAclFingerprint ||
        actualTargetSemanticFingerprint !== request.candidateTargetFingerprint ||
        actualSnapshotFingerprint !== request.candidateSnapshotFingerprint) {
      throw new Error("CANDIDATE_TARGET_PROOF_MISMATCH");
    }
    const targetFingerprint = candidate.targetFingerprint;
    const canonicalMappingFingerprint = candidate.snapshot
      ? canonicalJsonHash({ mappingGeneration: candidate.snapshot.mappingGeneration, mappings: candidate.snapshot.mappings, routes: candidate.snapshot.routes })
      : canonicalJsonHash({ sourceKind: candidate.sourceKind, targetFingerprint, identityFingerprint: candidate.identityFingerprint, aclFingerprint: candidate.aclFingerprint });
    const stateFingerprint = canonicalJsonHash({ targetState: request.targetState, targetFingerprint, targetIdentityFingerprint: candidate.identityFingerprint, targetAclFingerprint: candidate.aclFingerprint, canonicalMappingFingerprint });
    const payloadFingerprint = canonicalJsonHash({ targetFingerprint, targetIdentityFingerprint: candidate.identityFingerprint, targetAclFingerprint: candidate.aclFingerprint, wrapperFingerprint: candidate.wrapperFingerprint, controlRootFingerprint: candidate.controlRootFingerprint, canonicalMappingFingerprint });
    const snapshotFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, targetFingerprint });
    const publicationFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, snapshotFingerprint, targetFingerprint });
    const graph = publicationGraph({
      txId, genesisTxId: request.rootGenesisTxId, generation: request.candidateTokenConfigGeneration, fenceGeneration: candidateFenceGeneration, baseline, targetFingerprint,
      stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint,
      checkpointFingerprint: canonicalJsonHash({ genesisTxId: request.rootGenesisTxId, generation: request.candidateTokenConfigGeneration, publicationFingerprint, targetFingerprint }),
    });
    await this.native.writeSuccessorPublicationGraph(graph);
    const replacedHead = buildAuthoritySuccessorRecord({
      ...closedHead, phase: "replaced", authorityCommitSnapshotFingerprint: commit.authorityCommitSnapshotFingerprint,
      baselineFingerprint: baseline.baselineFingerprint, publicationKFingerprint: graph.k["publication-kFingerprint"],
      publicationYFingerprint: graph.y["publication-yFingerprint"], previousHeadFingerprint: closedHead.headFingerprint, headFingerprint: null,
    }, "headFingerprint");
    setRecovery({
      phase: "replaced",
      successorPhase: "replaced",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: replacedHead.headFingerprint,
      reservationFingerprint: reservation.reservationFingerprint,
    });
    await this.native.writeAuthoritySuccessorHead(replacedHead);
    if (typeof this.native.commitAuthoritySuccessorEpoch !== "function" || typeof this.native.writeAuthoritySuccessorFinality !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    const epoch = {
      version: 1, kind: "authority-epoch", anchorFingerprint, fenceGeneration: candidateFenceGeneration, epoch: request.candidateAuthorityEpoch,
      reservationTxId: txId, commitTxId: txId,
      previousAuthorityCommitSnapshotFingerprint: reservation.previousAuthorityCommitSnapshotFingerprint,
      authorityEpochFingerprint: null,
    };
    epoch.authorityEpochFingerprint = authorityRecordFingerprint(epoch, "authorityEpochFingerprint");
    validateAuthorityEpoch(epoch);
    await this.native.commitAuthoritySuccessorEpoch(epoch);
    let committedFloor;
    let committedAttestationFingerprint;
    let committedLineage;
    if (operation === "tokens-attest") {
      committedLineage = await this.native.readSuccessorTokenLineage();
      committedFloor = commitTokenFloor(committedLineage.floor, {
        generation: request.candidateTokenConfigGeneration, txId, attestationFingerprint: request.candidateAttestationFingerprint, fenceGeneration: candidateFenceGeneration,
      });
      await this.native.commitTokenFloor({ floor: committedFloor, fenceGeneration: candidateFenceGeneration });
      committedLineage = await this.native.readSuccessorTokenLineage();
      committedAttestationFingerprint = request.candidateAttestationFingerprint;
    } else {
      committedLineage = await this.native.readSuccessorTokenLineage();
      committedFloor = committedLineage.floor;
      committedAttestationFingerprint = committedLineage.attestation.attestationFingerprint;
    }
    const auditEntryFingerprint = await this.#audit({
      actorPrincipal, action: operation, targetPrincipal: null, result: "replaced",
      details: { txId, publicationKFingerprint: graph.k["publication-kFingerprint"], publicationYFingerprint: graph.y["publication-yFingerprint"] },
    });
    const finality = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-finality", sequence: request.sequence, txId, rootGenesisTxId: request.rootGenesisTxId, fenceGeneration: candidateFenceGeneration,
      operation, requestFingerprint: request.requestFingerprint, baselineFingerprint: baseline.baselineFingerprint,
      closeFingerprint: close.closeFingerprint, anchorFingerprint, authorityReservationFingerprint: reservation.reservationFingerprint,
      authorityCommitSnapshotFingerprint: commit.authorityCommitSnapshotFingerprint, authorityEpochFingerprint: epoch.authorityEpochFingerprint,
      tokenFloorFingerprint: committedFloor.floorFingerprint, attestationFingerprint: committedAttestationFingerprint,
      publicationKFingerprint: graph.k["publication-kFingerprint"], publicationYFingerprint: graph.y["publication-yFingerprint"],
      operationEvidenceFingerprint: operation === "tokens-attest" ? committedFloor.floorFingerprint : request.mappingRecoveryTxFingerprint,
      auditEntryFingerprint, targetFingerprint: candidate.targetFingerprint,
      targetIdentityFingerprint: candidate.identityFingerprint, targetAclFingerprint: candidate.aclFingerprint,
      wrapperFingerprint: candidate.wrapperFingerprint, controlRootFingerprint: candidate.controlRootFingerprint,
      revision: request.candidateRevision, authorityEpoch: request.candidateAuthorityEpoch,
      tokenConfigGeneration: request.candidateTokenConfigGeneration, mappingGeneration: request.candidateMappingGeneration,
      snapshotFingerprint, routeDisposition: "no-route", finalityFingerprint: null,
    }, "finalityFingerprint");
    assertCommittedTokenLineage(committedLineage, finality, baseline, {
      requireSuccessorFence: operation === "tokens-attest",
      successorTxId: operation === "tokens-attest" ? txId : null,
    });
    setRecovery({
      phase: "replaced",
      successorPhase: "replaced",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: replacedHead.headFingerprint,
      reservationFingerprint: reservation.reservationFingerprint,
      finalityFingerprint: finality.finalityFingerprint,
    });
    await this.native.writeAuthoritySuccessorFinality(finality);
    await this.native.commitFenceGeneration({ fenceGeneration: candidateFenceGeneration, txId });
    const finalityHead = buildAuthoritySuccessorRecord({
      ...replacedHead, phase: "reader-pending",
      finalityFingerprint: finality.finalityFingerprint, previousHeadFingerprint: replacedHead.headFingerprint, headFingerprint: null,
    }, "headFingerprint");
    setRecovery({
      phase: "reader-pending",
      successorPhase: "reader-pending",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: finalityHead.headFingerprint,
      reservationFingerprint: reservation.reservationFingerprint,
      finalityFingerprint: finality.finalityFingerprint,
    });
    await this.native.writeAuthoritySuccessorHead(finalityHead);
    if (readerMode === "no-reader") {
      const pendingBefore = state.revision;
      state.revision = request.candidateRevision;
      state.authorityEpoch = request.candidateAuthorityEpoch;
      state.tokenConfigGeneration = request.candidateTokenConfigGeneration;
      state.mappingGeneration = request.candidateMappingGeneration;
      if (preparedState) {
        state.mappings = preparedState.mappings;
        state.routes = preparedState.routes;
      }
      state.tokenFloor = structuredClone(committedFloor);
      state.tokenAttestation = {
        fingerprint: operation === "tokens-attest" ? intent.hostSetFingerprint : state.tokenAttestation.fingerprint,
        generation: request.candidateTokenConfigGeneration,
        attestationFingerprint: committedAttestationFingerprint,
        finalityFingerprint: committedFloor.floorFingerprint,
      };
      state.admission = { phase: "closed", finalityFingerprint: null };
      state.recovery = {
        ...state.recovery,
        ...(mutation.recovery ?? {}),
        phase: "reader-pending",
        txId,
        fenceGeneration: candidateFenceGeneration,
        finalityFingerprint: finality.finalityFingerprint,
      };
      state.fenceGeneration = candidateFenceGeneration;
      if (!await this.native.compareAndSwapManagementState(pendingBefore, state)) throw new Error("CAS_CONFLICT");
    }
    if (readerMode === "bound-reader") {
      return { pending: true, idempotent: false, txId, phase: "reader-pending", routeDisposition: "no-route" };
    }
    if (typeof this.native.writeAuthoritySuccessorReceipt !== "function") throw new Error("MANAGED_NATIVE_UNAVAILABLE");
    const receipt = buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-receipt", sequence: request.sequence, txId, rootGenesisTxId: request.rootGenesisTxId, fenceGeneration: candidateFenceGeneration,
      operation, requestFingerprint: request.requestFingerprint, previousReceiptFingerprint: request.previousReceiptFingerprint,
      finalityFingerprint: finality.finalityFingerprint, readerMode: "no-reader",
      leaseBindingFingerprint: null, readerProjectionFingerprint: null, ackFingerprint: null,
      snapshotFingerprint, revision: request.candidateRevision, authorityEpoch: request.candidateAuthorityEpoch,
      tokenConfigGeneration: request.candidateTokenConfigGeneration, mappingGeneration: request.candidateMappingGeneration,
      phase: "terminal", routeDisposition: "no-route", receiptFingerprint: null,
    }, "receiptFingerprint");
    await this.native.writeAuthoritySuccessorReceipt(receipt);
    const previousMarker = await this.native.readManagedHistoryMarker();
    validateManagedHistoryMarker(previousMarker, request.anchorFingerprint, request.sequence - 1);
    const marker = {
      version: 1, kind: "managed-history-marker", anchorFingerprint, fenceGeneration: candidateFenceGeneration, sequence: request.sequence,
      previousMarkerFingerprint: previousMarker.markerFingerprint, markerFingerprint: null,
    };
    marker.markerFingerprint = recordHash(marker, "markerFingerprint");
    const committedMarker = await this.native.commitManagedHistoryMarker(marker);
    validateManagedHistoryMarker(committedMarker, request.anchorFingerprint, request.sequence);
    const terminalHead = buildAuthoritySuccessorRecord({
      ...finalityHead, phase: "terminal", receiptFingerprint: receipt.receiptFingerprint,
      historyMarkerFingerprint: marker.markerFingerprint, previousHeadFingerprint: finalityHead.headFingerprint, headFingerprint: null,
    }, "headFingerprint");
    setRecovery({
      phase: "terminal",
      successorPhase: "terminal",
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: terminalHead.headFingerprint,
      reservationFingerprint: reservation.reservationFingerprint,
      finalityFingerprint: finality.finalityFingerprint,
    });
    const before = state.revision;
    state.revision = request.candidateRevision;
    state.authorityEpoch = request.candidateAuthorityEpoch;
    state.tokenConfigGeneration = request.candidateTokenConfigGeneration;
    state.mappingGeneration = request.candidateMappingGeneration;
    if (preparedState) {
      state.mappings = preparedState.mappings;
      state.routes = preparedState.routes;
    }
    state.tokenFloor = structuredClone(committedFloor);
    state.tokenAttestation = {
      fingerprint: operation === "tokens-attest" ? intent.hostSetFingerprint : state.tokenAttestation.fingerprint,
      generation: request.candidateTokenConfigGeneration,
      attestationFingerprint: committedAttestationFingerprint,
      finalityFingerprint: committedFloor.floorFingerprint,
    };
    state.admission = { phase: "closed", finalityFingerprint: null };
    state.recovery = {
      ...state.recovery,
      phase: "terminal",
      successorPhase: "terminal",
      txId,
      requestFingerprint: request.requestFingerprint,
      successorHeadFingerprint: terminalHead.headFingerprint,
      fenceGeneration: candidateFenceGeneration,
      finalityFingerprint: finality.finalityFingerprint,
    };
    state.fenceGeneration = candidateFenceGeneration;
    if (!await this.native.compareAndSwapManagementState(before, state)) throw new Error("CAS_CONFLICT");
    await this.native.writeAuthoritySuccessorHead(terminalHead);
    return { pending: false, txId, receiptFingerprint: receipt.receiptFingerprint, routeDisposition: "no-route" };
  }
  async #recoverPublicSuccessor(state, input, actorPrincipal) {
    if (typeof input.idempotencyKey !== "string" || input.idempotencyKey.length === 0) {
      throw new Error("IDEMPOTENCY_KEY_REQUIRED");
    }
    const head = await this.native.readAuthoritySuccessorHeadRaw();
    if (head === null) throw new Error("RECOVERY_REQUIRED");
    const recovery = {
      txId: head.txId,
      phase: head.phase,
      requestFingerprint: head.requestFingerprint,
      successorHeadFingerprint: head.headFingerprint,
      successorPhase: head.phase,
    };
    const terminalization = state.recovery?.terminalization;
    if (terminalization?.txId === head.txId) {
      if (terminalization.request?.actorPrincipalFingerprint !== canonicalJsonHash(actorPrincipal) ||
          terminalization.request?.idempotencyKey !== input.idempotencyKey) {
        await this.#manualCleanup(state, "RECOVERY_INPUT_MISMATCH", {
          ...recovery,
          terminalization,
        });
      }
      try {
        return await this.#resumeTerminalization(state, terminalization);
      } catch {
        await this.#manualCleanup(state, "SUCCESSOR_TERMINALIZATION_INVALID", {
          ...recovery,
          terminalization,
        });
      }
    }
    let bundle;
    try {
      bundle = await this.native.readSuccessorBundle();
      if (!bundle ||
          bundle.head.headFingerprint !== head.headFingerprint ||
          bundle.head.txId !== head.txId ||
          bundle.request.txId !== head.txId ||
          bundle.request.actorPrincipalFingerprint !== canonicalJsonHash(actorPrincipal) ||
          bundle.request.idempotencyKey !== input.idempotencyKey) {
        throw new Error("RECOVERY_INPUT_MISMATCH");
      }
      validateAuthoritySuccessorBundle(bundle);
    } catch {
      await this.#manualCleanup(state, "RECOVERY_INPUT_MISMATCH", recovery);
    }
    if (head.phase === "terminal") {
      return { idempotent: true, txId: head.txId, phase: "terminal", routeDisposition: "no-route" };
    }
    if (head.phase === "reader-pending") {
      let completed;
      try {
        completed = bundle.request.readerMode === "no-reader"
          ? await this.#completeNoReaderSuccessor(state, head.txId, bundle)
          : await this.#completeBoundSuccessor(state, head.txId);
      } catch {
        await this.#manualCleanup(state, "SUCCESSOR_RECOVERY_EVIDENCE_INVALID", {
          ...recovery,
          ...(state.recovery?.terminalization ? { terminalization: state.recovery.terminalization } : {}),
        });
      }
      return completed ?? {
        pending: true, idempotent: true, txId: head.txId, phase: "reader-pending", routeDisposition: "no-route",
      };
    }
    await this.#manualCleanup(state, "SUCCESSOR_RECOVERY_UNSUPPORTED_PHASE", recovery);
  }

  async #tokensAttest(input) {
    const actorPrincipal = principal(input.actorPrincipal, "ACTOR_PRINCIPAL");
    if (typeof input.actorSecret !== "string") throw new Error("AUTH_SECRET_REQUIRED");
    protectedTokenFingerprint(input.hostTokens);
    return this.native.withManagementLocks(LOCK_ORDER, async () => {
      const state = await this.#read();
      if (state.recovery && state.recovery.phase !== "terminal") throw new Error("RECOVERY_REQUIRED");
      requireOwner(authenticate(await this.#authenticatedState(state), actorPrincipal, input.actorSecret));
      return this.#reserveSuccessor("tokens-attest", input, state, actorPrincipal);
    });
  }

  async #mappingMutation(command, input) {
    const actorPrincipal = principal(input.actorPrincipal, "ACTOR_PRINCIPAL");
    if (typeof input.actorSecret !== "string") throw new Error("AUTH_SECRET_REQUIRED");
    return this.native.withManagementLocks(LOCK_ORDER, async () => {
      const state = await this.#read();
      if (state.recovery && state.recovery.phase !== "terminal" && command !== "recover") {
        throw new Error("RECOVERY_REQUIRED");
      }
      requireOwner(authenticate(await this.#authenticatedState(state), actorPrincipal, input.actorSecret));
      if (command === "recover") return this.#recoverPublicSuccessor(state, input, actorPrincipal);
      if (command === "mapping-reconcile") {
        let candidate;
        try {
          candidate = boundedMapping(input.mapping);
        } catch {
          throw new Error("MAPPING_INVALID");
        }
        if (!validMappingCandidate(candidate) || candidate.mappingId !== input.mappingId) throw new Error("MAPPING_INVALID");
      }
      return this.#reserveSuccessor(command, input, state, actorPrincipal);
    });
  }

  async #prepareMappingMutation(command, state, input) {
    const key = input.mappingId;
    if (typeof key !== "string" || key.length === 0 || key.length > 256) throw new Error("MAPPING_ID_INVALID");
    state.routes ??= {};
    const oldSnapshot = channelsSnapshot(state);
    const current = state.mappings[key];
    if (command === "mapping-revoke") {
      if (!current) throw new Error("MAPPING_UNKNOWN");
      if (input.expectedRevision !== state.revision || input.expectedFingerprint !== current.mappingFingerprint) throw new Error("CAS_CONFLICT");
      delete state.mappings[key];
      for (const [channelId, route] of Object.entries(state.routes)) if (route.mappingId === key) delete state.routes[channelId];
      state.mappingGeneration += 1;
      const snapshot = channelsSnapshot(state, state.revision + 1, state.authorityEpoch + 1);
      const publicationTxId = randomUUID();
      const tombstone = {
        fenceGeneration: state.fenceGeneration,
        version: 1, kind: "mapping-tombstone", operation: command, publicationTxId,
        mappingId: key, mappingGeneration: current.mappingGeneration, mappingFingerprint: current.mappingFingerprint,
        snapshotFingerprint: snapshot.configFingerprint, routeDisposition: "no-route", tombstoneFingerprint: null,
      };
      tombstone.tombstoneFingerprint = recordHash(tombstone, "tombstoneFingerprint");
      const handoffReceipt = {
        fenceGeneration: state.fenceGeneration,
        version: 1, kind: "mapping-handoff-receipt", operation: command, publicationTxId,
        oldMappingId: key, oldMappingGeneration: current.mappingGeneration, newMappingId: null, newMappingGeneration: null,
        snapshotFingerprint: snapshot.configFingerprint, routeDisposition: "no-route", tombstoneFingerprint: tombstone.tombstoneFingerprint, handoffReceiptFingerprint: null,
      };
      handoffReceipt.handoffReceiptFingerprint = recordHash(handoffReceipt, "handoffReceiptFingerprint");
      return {
        snapshot, oldSnapshot, publicationTxId, tombstone, handoffReceipt,
        expectedFingerprint: current.mappingFingerprint, oldMappingId: key, oldMappingGeneration: current.mappingGeneration,
        candidateMappingId: null, candidateMappingGeneration: null,
        immutableGeneration: { mapping: structuredClone(current), routes: Object.values(oldSnapshot.routes).filter((route) => route.mappingId === key) },
        result: { revoked: true, mappingGeneration: state.mappingGeneration },
        publish: () => this.native.revokeMapping({ mappingId: key, expectedFingerprint: current.mappingFingerprint, expectedRevision: state.revision, snapshot }),
      };
    }

    let candidate;
    let routeCandidates;
    if (command === "mapping-rollback") {
      const priorGeneration = input.priorGeneration;
      const replacementMappingId = input.replacementMappingId;
      if (!current || !Number.isSafeInteger(priorGeneration) || priorGeneration < 1 || priorGeneration === current.mappingGeneration) throw new Error("ROLLBACK_GENERATION_REQUIRED");
      if (typeof replacementMappingId !== "string" || replacementMappingId.length === 0 || replacementMappingId.length > 256 || replacementMappingId === key || state.mappings[replacementMappingId]) throw new Error("ROLLBACK_REPLACEMENT_MAPPING_ID_REQUIRED");
      const retained = await this.native.readMappingGeneration({ mappingId: key, generation: priorGeneration });
      if (!retained || !validMappingCandidate(retained.mapping) || !Array.isArray(retained.routes)) throw new Error("ROLLBACK_GENERATION_UNKNOWN");
      candidate = fingerprintManagedMappingRecord({ ...structuredClone(retained.mapping), mappingId: replacementMappingId, mappingFingerprint: null });
      routeCandidates = structuredClone(retained.routes);
    } else {
      candidate = boundedMapping(input.mapping);
      routeCandidates = input.routes ?? [];
    }
    const mappingId = command === "mapping-rollback" ? input.replacementMappingId : key;
    if (!validMappingCandidate(candidate) || candidate.mappingId !== mappingId || !Array.isArray(routeCandidates)) throw new Error("MAPPING_INVALID");
    if (input.expectedRevision !== state.revision || input.expectedFingerprint !== (current?.mappingFingerprint ?? null)) throw new Error("CAS_CONFLICT");
    const mapping = fingerprintManagedMappingRecord({ ...candidate, fenceGeneration: state.fenceGeneration, mappingGeneration: state.mappingGeneration + 1 });
    const routes = {};
    for (const candidateRoute of routeCandidates) {
      const route = fingerprintManagedRouteRecord({ ...candidateRoute, fenceGeneration: mapping.fenceGeneration, hostId: mapping.hostId, mappingId: mapping.mappingId, mappingGeneration: mapping.mappingGeneration, mappingVersion: mapping.mappingVersion, sourcePlatform: mapping.sourcePlatform, workspaceId: mapping.workspaceId, workDir: mapping.workDir }, mapping);
      if (Object.hasOwn(routes, route.channelId)) throw new Error("MAPPING_INVALID");
      routes[route.channelId] = route;
    }
    state.mappingGeneration = mapping.mappingGeneration;
    if (command === "mapping-rollback") delete state.mappings[key];
    state.mappings[mapping.mappingId] = mapping;
    for (const [channelId, route] of Object.entries(state.routes)) if (route.mappingId === key || route.mappingId === mapping.mappingId) delete state.routes[channelId];
    Object.assign(state.routes, routes);
    const publicationTxId = randomUUID();
    const snapshot = channelsSnapshot(state, state.revision + 1, state.authorityEpoch + 1);
    const tombstone = command === "mapping-rollback" ? {
      fenceGeneration: state.fenceGeneration,
      version: 1, kind: "mapping-tombstone", operation: command, publicationTxId,
      mappingId: key, mappingGeneration: current.mappingGeneration, mappingFingerprint: current.mappingFingerprint,
      snapshotFingerprint: snapshot.configFingerprint, routeDisposition: "no-route", tombstoneFingerprint: null,
    } : null;
    if (tombstone) tombstone.tombstoneFingerprint = recordHash(tombstone, "tombstoneFingerprint");
    const handoffReceipt = {
      fenceGeneration: state.fenceGeneration,
      version: 1, kind: "mapping-handoff-receipt", operation: command, publicationTxId,
      oldMappingId: current?.mappingId ?? null, oldMappingGeneration: current?.mappingGeneration ?? null,
      newMappingId: mapping.mappingId, newMappingGeneration: mapping.mappingGeneration,
      snapshotFingerprint: snapshot.configFingerprint, routeDisposition: "no-route",
      tombstoneFingerprint: tombstone?.tombstoneFingerprint ?? null, handoffReceiptFingerprint: null,
    };
    handoffReceipt.handoffReceiptFingerprint = recordHash(handoffReceipt, "handoffReceiptFingerprint");
    return {
      snapshot, oldSnapshot, publicationTxId, tombstone, handoffReceipt,
      expectedFingerprint: current?.mappingFingerprint ?? null, oldMappingId: current?.mappingId ?? null, oldMappingGeneration: current?.mappingGeneration ?? null,
      candidateMappingId: mapping.mappingId, candidateMappingGeneration: mapping.mappingGeneration,
      immutableGeneration: { mapping: structuredClone(mapping), routes: Object.values(routes) },
      result: { fingerprint: mapping.mappingFingerprint, mappingGeneration: mapping.mappingGeneration, routeCount: Object.keys(routes).length },
      publish: async () => {
        await this.native.writeMappingGeneration({
          fenceGeneration: mapping.fenceGeneration,
          mappingId: mapping.mappingId,
          generation: mapping.mappingGeneration,
          mapping,
          routes: Object.values(routes),
          publicationTxId,
        });
        return this.native.publishMapping({
          mappingId: mapping.mappingId,
          expectedFingerprint: current?.mappingFingerprint ?? null,
          expectedRevision: state.revision,
          snapshot,
          publicationTxId,
        });
      },
    };
  }

  async #mapping(command, state, identity, input) {
    if (command === "mapping-validate") {
      const candidate = boundedMapping(input.mapping);
      if (!validMappingCandidate(candidate)) throw new Error("MAPPING_INVALID");
      return { classification: "managed-mapping-v1", fingerprint: candidate.mappingFingerprint };
    }
    if (command === "mapping-snapshot") return { mappingCount: Object.keys(state.mappings).length, routeCount: Object.keys(state.routes ?? {}).length, authorityEpoch: state.authorityEpoch, mappingGeneration: state.mappingGeneration };
    throw new Error("COMMAND_INVALID");
  }
}
