import { authoritySuccessorPreviousLeaseBindingFingerprint, buildAuthoritySuccessorRecord, validateAuthoritySuccessorBundle } from "@gjc-remote/shared/successor-envelope";
import { isHex64 } from "@gjc-remote/shared/strict-json";
import { validateManagedProof } from "../../src/managed-authority-reader.js";
const WRAPPER_NAMES = new Set(["managed-v1-wrapper.json", "legacy-retained.json"]);
const CONTROL_ROOT_NAME = "control-root.json";


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

/** Test-only fake-native reader. Production construction is intentionally not injectable. */
export async function createTestManagedAuthorityReader({
  expectedHostSetFingerprint = null,
  roleBindings,
  native,
} = {}) {
  if (!native || typeof native.configureManagementRoles !== "function" ||
      typeof native.readManagedMappingSnapshot !== "function") {
    throw new TypeError("test native reader requires a native adapter");
  }
  await native.configureManagementRoles(roleBindings);
  if (typeof native.runStartupSelfTest !== "function") throw new TypeError("test native reader requires startup self-test");
  const selfTest = await native.runStartupSelfTest();
  if (selfTest?.role !== "bot" || selfTest?.bst !== true || selfTest?.mst !== false || selfTest?.writes !== 0) {
    throw new TypeError("test native reader startup self-test");
  }

  const completePendingSuccessor = async (bundle) => {
    const { request, fence, finality, lease, projection, ack, head } = bundle;
    if (head.phase !== "reader-pending" || request.readerMode !== "bound-reader") return false;
    if (!fence || !finality) throw new Error("SUCCESSOR_PENDING_INVALID");
    const required = ["writeBotAuthoritySuccessorLease", "writeBotAuthoritySuccessorProjection", "writeBotAuthoritySuccessorAck"];
    if (!required.every((method) => typeof native[method] === "function")) throw new Error("BOT_NATIVE_WRITE_REFUSED");
    const l2 = lease ?? buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-lease", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId,
      requestFingerprint: request.requestFingerprint, readerInstanceId: request.readerInstanceId,
      readerStartNonce: request.readerStartNonce, readerVersion: 2, fenceBindingFingerprint: fence.fenceBindingFingerprint,
      previousLeaseBindingFingerprint: authoritySuccessorPreviousLeaseBindingFingerprint(request), leaseBindingFingerprint: null,
    }, "leaseBindingFingerprint");
    if (!lease) await native.writeBotAuthoritySuccessorLease(l2);
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
    if (!projection) await native.writeBotAuthoritySuccessorProjection(rp2);
    const ak2 = ack ?? buildAuthoritySuccessorRecord({
      version: 1, kind: "authority-successor-ack", txId: request.txId, rootGenesisTxId: request.rootGenesisTxId,
      requestFingerprint: request.requestFingerprint, finalityFingerprint: finality.finalityFingerprint,
      readerProjectionFingerprint: rp2.readerProjectionFingerprint, leaseBindingFingerprint: l2.leaseBindingFingerprint,
      readerInstanceId: request.readerInstanceId, readerStartNonce: request.readerStartNonce, readerVersion: 2,
      readerNonce: request.readerNonce, ackDisposition: "verified-no-route", ackFingerprint: null,
    }, "ackFingerprint");
    if (!ack) await native.writeBotAuthoritySuccessorAck(ak2);
    return true;
  };

  return Object.freeze({
    async readSnapshot() {
      let snapshot;
      try {
        snapshot = await native.readManagedMappingSnapshot();
      } catch {
        return unavailable();
      }
      if (snapshot?.managementMarkerPresent === true || snapshot?.bootstrapBlockerPresent === true ||
          snapshot?.genesisProbePresent === true) return unavailable("MANAGED_MARKER_INCOMPLETE");
      if (snapshot?.controlRootAbsent === true) return { controlRootAbsent: true };
      if (snapshot?.successorBundle) {
        try {
          validateAuthoritySuccessorBundle(snapshot.successorBundle);
          const { head } = snapshot.successorBundle;
          if (head.phase === "reader-pending") {
            await completePendingSuccessor(snapshot.successorBundle);
            return unavailable("MANAGED_AUTHORITY_PENDING");
          }
          if (head.phase !== "terminal" || !isBytes(snapshot.controlRootBytes) || !isBytes(snapshot.wrapperBytes) ||
              !isBytes(snapshot.targetBytes) || !isHex64(snapshot.targetIdentity) || !isHex64(snapshot.targetAclFingerprint)) {
            return unavailable("MANAGED_AUTHORITY_INVALID");
          }
          return {
            controlRootBytes: Buffer.from(snapshot.controlRootBytes), wrapperBytes: Buffer.from(snapshot.wrapperBytes),
            targetBytes: Buffer.from(snapshot.targetBytes), targetIdentity: snapshot.targetIdentity,
            targetAclFingerprint: snapshot.targetAclFingerprint, nativeVerified: true,
            successorHeadFingerprint: head.headFingerprint, routeDisposition: "no-route",
          };
        } catch (error) {
          if (process.env.GJC_TRACE_TEST_ERROR === "1") console.error(error?.stack);
          return unavailable("MANAGED_AUTHORITY_INVALID");
        }
      }
      if (!snapshot || snapshot.controlRootName !== CONTROL_ROOT_NAME || !WRAPPER_NAMES.has(snapshot.wrapperName) ||
          !isBytes(snapshot.controlRootBytes) || !isBytes(snapshot.wrapperBytes) || !isBytes(snapshot.targetBytes) ||
          !isHex64(snapshot.targetIdentity) || !isHex64(snapshot.targetAclFingerprint)) return unavailable("MANAGED_NATIVE_AMBIGUOUS");
      try {
        validateManagedProof(snapshot, expectedHostSetFingerprint);
      } catch {
        return unavailable("MANAGED_AUTHORITY_INVALID");
      }
      return {
        controlRootBytes: Buffer.from(snapshot.controlRootBytes), wrapperBytes: Buffer.from(snapshot.wrapperBytes),
        targetBytes: Buffer.from(snapshot.targetBytes), targetIdentity: snapshot.targetIdentity,
        targetAclFingerprint: snapshot.targetAclFingerprint, nativeVerified: true,
      };
    },
    async writeReaderProjection() { throw new Error("BOT_AUTHORITY_UNAVAILABLE"); },
    async writeReaderState() { throw new Error("BOT_AUTHORITY_UNAVAILABLE"); },
    async acquireLease() { throw new Error("BOT_AUTHORITY_UNAVAILABLE"); },
    async acknowledge() { throw new Error("BOT_AUTHORITY_UNAVAILABLE"); },
  });
}
