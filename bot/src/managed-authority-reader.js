import { createManagementNative } from "@gjc-remote/native-control";
import { buildAdmissionAck, validateAdmissionAck, validateAdmissionGenesisBinding, validateAdmissionGrant } from "@gjc-remote/shared/admission-envelope";
import { buildGenesisZeroGrantProofFingerprint, authorityRecordFingerprint, validateAuthorityCommitSnapshot, validateAuthorityEpoch, validateAuthorityReservation, validateFenceBinding, validateLeaseBinding, validateReaderProjection, validateReaderRelations, validateReaderVersionFloor, validateTokenFloor, validateZFinality } from "@gjc-remote/shared/genesis-envelope";
import { canonicalJson, canonicalJsonHash, isHex64 } from "@gjc-remote/shared/strict-json";
import { authoritySuccessorPreviousLeaseBindingFingerprint, buildAuthoritySuccessorRecord, validateAuthoritySuccessorBundle } from "@gjc-remote/shared/successor-envelope";
import { isBytes, parseAuthorityBytes, validateBotPayload, validateHistoryMarkerSeal, validateLiveSuccessorEvidence, validateManagedProof, validatePublishedFloors, validateSuccessorPublicationEvidence } from "@gjc-remote/shared/managed-authority-proof";

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
    const {
      request, floor, tokenFloor, zFinality, precommit, commit, fence, admissionRequest, admissionGrant,
      authorityReservation, authorityEpoch, authorityEpochArchive, authorityEpochFloor, fenceGenerationFloor,
    } = pending;
    validateReaderVersionFloor(floor);
    validateTokenFloor(tokenFloor);
    validateZFinality(zFinality, request, tokenFloor, precommit);
    validateAuthorityReservation(authorityReservation);
    validateAuthorityCommitSnapshot(commit, authorityReservation);
    validateAuthorityEpoch(authorityEpoch);
    validateAuthorityEpoch(authorityEpochArchive);
    validatePublishedFloors({
      authorityEpochFloor,
      fenceGenerationFloor,
      authorityEpoch,
      anchorFingerprint: request.anchorFingerprint,
      request,
    });
    if (canonicalJson(authorityEpochArchive) !== canonicalJson(authorityEpoch) ||
        authorityReservation.txId !== request.genesisTxId ||
        authorityReservation.generation !== request.generation ||
        authorityReservation.anchorFingerprint !== request.anchorFingerprint ||
        authorityReservation.candidateFingerprint !== request.requestFingerprint ||
        commit.txId !== request.genesisTxId ||
        commit.generation !== request.generation ||
        commit.anchorFingerprint !== request.anchorFingerprint ||
        commit.candidateFingerprint !== request.requestFingerprint ||
        authorityReservation.epoch !== authorityEpoch.epoch ||
        commit.epoch !== authorityEpoch.epoch ||
        authorityEpoch.reservationTxId !== request.genesisTxId ||
        authorityEpoch.commitTxId !== request.genesisTxId ||
        precommit.genesisTxId !== request.genesisTxId ||
        precommit.generation !== request.generation ||
        precommit.requestFingerprint !== request.requestFingerprint ||
        precommit.zeroGrantProofFingerprint !== buildGenesisZeroGrantProofFingerprint({
          genesisTxId: request.genesisTxId,
          admissionArchiveIds: precommit.admissionArchiveIds,
        }) ||
        precommit.authorityReservationFingerprint !== authorityReservation.reservationFingerprint ||
        precommit.authorityCommitSnapshotFingerprint !== commit.authorityCommitSnapshotFingerprint ||
        precommit.authorityEpochFingerprint !== authorityEpoch.authorityEpochFingerprint ||
        precommit.readerVersionFloorFingerprint !== floor.floorFingerprint) {
      throw new TypeError("pending authority graph binding");
    }
    validateFenceBinding(fence, commit, floor);
    validateAdmissionGenesisBinding(request, admissionRequest, admissionGrant, null, null, Date.now());

    const lease = {
      version: 1,
      kind: "reader-lease-binding",
      anchorFingerprint: request.anchorFingerprint,
      genesisTxId: request.genesisTxId,
      fenceGeneration: request.fenceGeneration,
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
      fenceGeneration: request.fenceGeneration,
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
    validatePublishedFloors({
      authorityEpochFloor: bundle.authorityEpochFloor,
      fenceGenerationFloor: bundle.fenceGenerationFloor,
      authorityEpoch: bundle.authorityEpoch,
      anchorFingerprint: request.anchorFingerprint,
      request,
      head,
    });
    validateHistoryMarkerSeal(bundle.historyMarker, bundle.historyMarkerSeal, request.anchorFingerprint);
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
      fenceGeneration: request.candidateFenceGeneration,
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
      fenceGeneration: request.candidateFenceGeneration,
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
      fenceGeneration: request.candidateFenceGeneration,
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
              return unavailable("MANAGED_AUTHORITY_INVALID");
            }
            return unavailable("MANAGED_AUTHORITY_PENDING");
          }
          if (head.phase !== "terminal") return unavailable("MANAGED_AUTHORITY_PENDING");
          if (!isBytes(snapshot.controlRootBytes) || !isBytes(snapshot.wrapperBytes) || !isBytes(snapshot.targetBytes) ||
              !isBytes(snapshot.historyMarkerBytes) || !isBytes(snapshot.historyMarkerSealBytes) ||
              !isBytes(snapshot.historyMarkerPredecessorsBytes) || !isBytes(snapshot.authorityEpochArchiveBytes) ||
              !isBytes(snapshot.authorityEpochFloorBytes) || !isBytes(snapshot.fenceGenerationFloorBytes) ||
              !isHex64(snapshot.targetIdentity) || !isHex64(snapshot.targetAclFingerprint)) {
            return unavailable("MANAGED_AUTHORITY_INVALID");
          }
          validateSuccessorPublicationEvidence({ snapshot, bundle: snapshot.successorBundle });
          return {
            controlRootBytes: Buffer.from(snapshot.controlRootBytes),
            wrapperBytes: Buffer.from(snapshot.wrapperBytes),
            targetBytes: Buffer.from(snapshot.targetBytes),
            historyMarkerBytes: Buffer.from(snapshot.historyMarkerBytes),
            historyMarkerSealBytes: Buffer.from(snapshot.historyMarkerSealBytes),
            historyMarkerPredecessorsBytes: Buffer.from(snapshot.historyMarkerPredecessorsBytes),
            authorityEpochFloorBytes: Buffer.from(snapshot.authorityEpochFloorBytes),
            authorityEpochArchiveBytes: Buffer.from(snapshot.authorityEpochArchiveBytes),
            fenceGenerationFloorBytes: Buffer.from(snapshot.fenceGenerationFloorBytes),
            targetIdentity: snapshot.targetIdentity,
            targetAclFingerprint: snapshot.targetAclFingerprint,
            nativeVerified: true,
            successorHeadFingerprint: head.headFingerprint,
            routeDisposition: "no-route",
          };
        } catch (error) {
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
          !isBytes(snapshot.historyMarkerBytes) || !isBytes(snapshot.historyMarkerSealBytes) ||
          !isBytes(snapshot.historyMarkerPredecessorsBytes) || !isBytes(snapshot.authorityEpochFloorBytes) ||
          !isBytes(snapshot.fenceGenerationFloorBytes) ||
          !isBytes(snapshot.genesisRequestBytes) || !isBytes(snapshot.zFinalityBytes) || !isBytes(snapshot.rvfBytes) ||
          !isBytes(snapshot.receiptBytes) || !isBytes(snapshot.authorityRequestBytes) || !isBytes(snapshot.authorityReceiptBytes) ||
          !isBytes(snapshot.authorityReservationBytes) || !isBytes(snapshot.authorityCommitBytes) || !isBytes(snapshot.authorityBaselineBytes) ||
          !isBytes(snapshot.authorityEpochBytes) || !isBytes(snapshot.authorityEpochArchiveBytes) || !isBytes(snapshot.publicationTransactionBytes) ||
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
