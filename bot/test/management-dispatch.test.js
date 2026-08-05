import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { canonicalJson, canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { managementAnchorFingerprint } from "@gjc-remote/shared/identity";
import { createGenesisEmptyChannels } from "@gjc-remote/shared/mapping-envelope";
import { attestTokenFloor, buildAttestedTokenFloorProof, buildGenesisPrecommit, commitTokenFloor, reserveTokenGeneration } from "@gjc-remote/shared/genesis-envelope";
import { buildPublicationC, buildPublicationK, buildPublicationP, buildPublicationQ, buildPublicationS, buildPublicationState, buildPublicationTransaction, buildPublicationU, buildPublicationY, buildPublicationZp } from "@gjc-remote/shared/publication-envelope";
import { createManagedAuthoritySelection, loadManagedChannelMapState, readLegacyV0SourceSnapshot, verifyLegacyV0SourceFence } from "../src/config.js";
import { dispatchGate, WORKSPACE_MAPPING_UNAVAILABLE } from "../src/managed-dispatch.js";
import { createManagedAuthorityReader, validateManagedProof } from "../src/managed-authority-reader.js";
import { createTestManagedAuthorityReader } from "./helpers/managed-authority-reader.js";
import { watchConfigHints } from "../src/config-watcher.js";

const anchor = {
  anchorVersion: 1,
  configPathFingerprint: "a".repeat(64),
  parentIdentity: "parent-identity",
  targetRelativeName: "channels.json",
  controlRootRelativeName: ".gjc-remote-control",
};
const provisionedRoles = Object.freeze({
  managementSid: "S-1-5-21-100",
  botSid: "S-1-5-21-101",
  recoverySid: "S-1-5-21-102",
  systemSid: "S-1-5-18",
});
const botStartupSelfTest = async () => ({ role: "bot", mst: false, bst: true, writes: 0 });

function seal(record, field) {
  return { ...record, [field]: canonicalJsonHash(record) };
}

function managedSnapshot(sourceKind = "managed-v1", retainedIdentityOverride = null) {
  const hostSetFingerprint = "d".repeat(64);
  const txId = "123e4567-e89b-42d3-a456-426614174000";
  const targetBytes = Buffer.from(canonicalJson(sourceKind === "managed-v1"
    ? createGenesisEmptyChannels({ tokenConfigGeneration: 1, tokenConfigHostSetFingerprint: hostSetFingerprint })
    : {}));
  const targetIdentity = canonicalJsonHash("target-identity");
  const targetAclFingerprint = createHash("sha256").update("target-acl").digest("hex");
  const anchorFingerprint = managementAnchorFingerprint(anchor);
  const wrapper = sourceKind === "managed-v1"
    ? seal({
      version: 1, kind: "managed-v1-wrapper", sourceKind, managementStamp: "gjc-management-envelope/v1",
      anchorFingerprint, targetRelativeName: "channels.json", targetState: "genesis-empty",
      targetIdentity, targetAclFingerprint, semanticStateFingerprint: JSON.parse(targetBytes).configFingerprint, readerVersion: null,
      dispatchClass: "workspace-only", routeDisposition: "no-route", wrapperSequence: 1, previousWrapperFingerprint: null,
    }, "wrapperFingerprint")
    : seal({
      version: 1, kind: "legacy-retained-wrapper", sourceKind, managementStamp: "gjc-management-envelope/v1",
      anchorFingerprint, targetRelativeName: "channels.json", targetState: "legacy-unmigrated",
      rawTargetByteFingerprint: createHash("sha256").update(targetBytes).digest("hex"), rawTargetByteLength: targetBytes.length,
      targetIdentity, targetAclFingerprint, readerVersion: null,
      legacyRetention: "exact", dispatchClass: "workspace-only", routeDisposition: "no-route", retentionTxId: txId, retentionSequence: 1, previousWrapperFingerprint: null,
    }, "wrapperFingerprint");
  const readerFloor = seal({
    version: 1, kind: "reader-version-floor", anchorFingerprint,
    readerVersionFloor: null, firstPendingTxId: null, firstReaderInstanceId: null,
    firstReaderStartNonce: null, lastTransitionTxId: null, previousFloorFingerprint: null,
  }, "floorFingerprint");
  const historyMarker = seal({
    version: 1, kind: "managed-history-marker", anchorFingerprint,
    sequence: 1, previousMarkerFingerprint: null,
  }, "markerFingerprint");
  const root = seal({
    version: 1, kind: "management-control-root", managementStamp: "gjc-management-control/v1", anchor,
    anchorFingerprint, sourceKind, wrapperKind: sourceKind === "managed-v1" ? "managed-v1-wrapper" : "legacy-retained-wrapper",
    wrapperRelativeName: sourceKind === "managed-v1" ? "managed-v1-wrapper.json" : "legacy-retained.json", targetRelativeName: "channels.json", controlRootRelativeName: ".gjc-remote-control",
    readerVersionFloorFingerprint: readerFloor.floorFingerprint, wrapperFingerprint: wrapper.wrapperFingerprint,
  }, "controlRootFingerprint");
  const reservation = seal({
    version: 1, kind: "token-generation-floor", anchorFingerprint, genesisGeneration: 1,
    highestReservedGeneration: 1, highestCommittedGeneration: 0, lastReservationTxId: txId,
    lastCommittedTxId: null, lastAttestationFingerprint: null, floorPhase: "reserved", attestedProofFingerprint: null,
  }, "floorFingerprint");
  const attestation = seal({
    version: 1, kind: "token-config-attestation", anchorFingerprint, tokenConfigGeneration: 1,
    tokenConfigHostSetFingerprint: hostSetFingerprint, managedGrammarVersion: 1, sourceKind: "protected-stdin",
    producerPrincipal: `management/${"e".repeat(64)}`, rotationKind: "genesis",
    previousAttestationFingerprint: null, txId,
  }, "attestationFingerprint");
  const request = seal({
    version: 1, kind: "genesis-request", genesisTxId: txId, idempotencyKey: "idempotency-key",
    anchorFingerprint, ownerPrincipalFingerprint: "e".repeat(64), generation: 1,
    requestedReaderMode: "no-reader", readerInstanceId: null, readerStartNonce: null,
    attestationFingerprint: attestation.attestationFingerprint, tokenFloorFingerprint: reservation.floorFingerprint,
  }, "requestFingerprint");
  const attestedProof = buildAttestedTokenFloorProof(reservation, attestation);
  const attestedFloor = attestTokenFloor(reservation, attestedProof);
  const tokenFloor = commitTokenFloor(attestedFloor, {
    txId, generation: 1, attestationFingerprint: attestation.attestationFingerprint,
  });
  const legacyProof = sourceKind === "legacy-retained" ? {
    rawTargetByteFingerprint: createHash("sha256").update(targetBytes).digest("hex"),
    rawTargetByteLength: targetBytes.length,
    targetIdentity,
    targetAclFingerprint,
  } : null;
  const authorityRequest = seal({
    version: 1, kind: "genesis-authority-request", genesisTxId: txId, sequence: 1, anchorFingerprint,
    ownerPrincipalFingerprint: "e".repeat(64), managementPrincipalFingerprint: "e".repeat(64),
    botPrincipalFingerprint: "f".repeat(64), recoveryPrincipalFingerprint: "c".repeat(64),
    targetPrincipalFingerprint: "b".repeat(64),
    managementProvisioningFingerprint: "1".repeat(64), botProvisioningFingerprint: "2".repeat(64),
    recoveryProvisioningFingerprint: "3".repeat(64), generation: 1, requestedReaderMode: "no-reader",
    readerInstanceId: null, readerStartNonce: null, idempotencyKey: "idempotency-key",
    targetInputState: legacyProof === null ? "absent" : "legacy-unmigrated",
    targetFingerprint: legacyProof?.rawTargetByteFingerprint ?? null,
    targetIdentityFingerprint: legacyProof === null ? null : canonicalJsonHash(legacyProof.targetIdentity),
    targetAclFingerprint: legacyProof?.targetAclFingerprint ?? null,
    legacyTargetProofFingerprint: legacyProof === null ? null : canonicalJsonHash(legacyProof),
    protectedInputFingerprint: hostSetFingerprint,
  }, "requestFingerprint");
  const authorityReservation = seal({
    version: 1, kind: "authority-reservation", anchorFingerprint, txId, epoch: 1, generation: 1,
    candidateFingerprint: request.requestFingerprint, previousAuthorityCommitSnapshotFingerprint: null,
  }, "reservationFingerprint");
  const authorityCommit = seal({
    version: 1, kind: "authority-commit-snapshot", anchorFingerprint, txId, epoch: 1, generation: 1,
    candidateFingerprint: request.requestFingerprint, reservationFingerprint: authorityReservation.reservationFingerprint,
    previousAuthorityCommitSnapshotFingerprint: null,
  }, "authorityCommitSnapshotFingerprint");
  const authorityEpoch = seal({
    version: 1, kind: "authority-epoch", anchorFingerprint, epoch: 1, reservationTxId: txId,
    commitTxId: txId, previousAuthorityCommitSnapshotFingerprint: null,
  }, "authorityEpochFingerprint");
  const baseline = seal({
    version: 1, kind: "authority-baseline", anchorFingerprint, genesisTxId: txId, idempotencyKey: "idempotency-key",
    targetState: sourceKind === "managed-v1" ? "genesis-empty" : "legacy-unmigrated", generation: 1, tokenConfigHostSetFingerprint: hostSetFingerprint,
    attestationFingerprint: attestation.attestationFingerprint, authorityReservationFingerprint: authorityReservation.reservationFingerprint,
    authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: null,
    leaseBindingFingerprint: null, readerProjectionFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  }, "baselineFingerprint");
  const targetFingerprint = createHash("sha256").update(targetBytes).digest("hex");
  const canonicalMappingFingerprint = sourceKind === "legacy-retained"
    ? canonicalJsonHash({
      sourceKind: "legacy-retained",
      targetFingerprint,
      identityFingerprint: retainedIdentityOverride ?? targetIdentity,
      aclFingerprint: targetAclFingerprint,
    })
    : canonicalJsonHash({
      mappingGeneration: JSON.parse(targetBytes).mappingGeneration,
      mappings: JSON.parse(targetBytes).mappings,
      routes: JSON.parse(targetBytes).routes,
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
    controlRootFingerprint: root.controlRootFingerprint,
    canonicalMappingFingerprint,
  });
  const snapshotFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, targetFingerprint });
  const publicationFingerprint = canonicalJsonHash({ stateFingerprint, payloadFingerprint, snapshotFingerprint, targetFingerprint });
  const checkpointFingerprint = canonicalJsonHash({ genesisTxId: txId, generation: 1, publicationFingerprint, targetFingerprint });
  const transaction = buildPublicationTransaction({
    txId, genesisTxId: txId, generation: 1, baselineFingerprint: baseline.baselineFingerprint,
  });
  const u = buildPublicationU({
    txId, genesisTxId: txId, generation: 1, baselineFingerprint: baseline.baselineFingerprint, anchorFingerprint,
    targetState: baseline.targetState, attestationFingerprint: baseline.attestationFingerprint,
    authorityReservationFingerprint: baseline.authorityReservationFingerprint,
    authorityCommitSnapshotFingerprint: baseline.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: null, leaseBindingFingerprint: null, readerProjectionFingerprint: null,
    readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  });
  const p = buildPublicationP({
    txId, genesisTxId: txId, generation: 1, uFingerprint: u["publication-uFingerprint"], stateFingerprint,
    targetState: u.targetState, authorityCommitSnapshotFingerprint: u.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: null, leaseBindingFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  });
  const s = buildPublicationS({
    txId, genesisTxId: txId, generation: 1, pFingerprint: p["publication-pFingerprint"], stateFingerprint,
    payloadFingerprint, targetState: p.targetState, authorityCommitSnapshotFingerprint: p.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: null, readerVersion: null,
  });
  const prepared = buildPublicationState({
    txId, genesisTxId: txId, generation: 1, publicationFingerprint, phase: "prepared",
  });
  const replaced = buildPublicationState({
    txId, genesisTxId: txId, generation: 1, publicationFingerprint, phase: "replaced",
  });
  const c = buildPublicationC({
    txId, genesisTxId: txId, generation: 1, sFingerprint: s["publication-sFingerprint"], stateFingerprint,
    payloadFingerprint, snapshotFingerprint, authorityCommitSnapshotFingerprint: s.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: null, readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  });
  const q = buildPublicationQ({
    txId, genesisTxId: txId, generation: 1, cFingerprint: c["publication-cFingerprint"], baselineFingerprint: baseline.baselineFingerprint,
    stateFingerprint, payloadFingerprint, snapshotFingerprint, authorityCommitSnapshotFingerprint: c.authorityCommitSnapshotFingerprint,
    fenceBindingFingerprint: null,
  });
  const zp = buildPublicationZp({
    txId, genesisTxId: txId, generation: 1, qFingerprint: q["publication-qFingerprint"], publicationFingerprint,
    stateFingerprint, payloadFingerprint, snapshotFingerprint,
  });
  const publicationK = buildPublicationK({
    txId, genesisTxId: txId, generation: 1, zpFingerprint: zp["publication-zpFingerprint"],
    publicationFingerprint, authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
    checkpointFingerprint,
  });
  const publicationY = buildPublicationY({
    txId, genesisTxId: txId, generation: 1, kFingerprint: publicationK["publication-kFingerprint"],
    publicationFingerprint, targetState: baseline.targetState,
    authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint, fenceBindingFingerprint: null,
    targetFingerprint,
  });
  const committed = buildPublicationState({
    txId, genesisTxId: txId, generation: 1, publicationFingerprint, phase: "committed",
  });
  const zeroGrantProofFingerprint = canonicalJsonHash({
    admissionClosed: true,
    admissionDrained: true,
    admissionGrantWrites: 0,
    admissionAckWrites: 0,
    outstandingAdmissionGrants: 0,
    txId,
  });
  const precommit = buildGenesisPrecommit({
    genesisTxId: txId,
    generation: 1,
    genesisProbeFingerprint: canonicalJsonHash({ kind: "fixture-genesis-probe", txId }),
    targetFingerprint,
    targetIdentityFingerprint: targetIdentity,
    targetAclFingerprint,
    controlRootFingerprint: root.controlRootFingerprint,
    controlIdentityFingerprint: canonicalJsonHash({ identity: "control-root-identity" }),
    controlAclFingerprint: "c".repeat(64),
    wrapperIdentityFingerprint: canonicalJsonHash({ identity: "wrapper-identity" }),
    wrapperAclFingerprint: "c".repeat(64),
    wrapperFingerprint: wrapper.wrapperFingerprint,
    readerVersionFloorFingerprint: readerFloor.floorFingerprint,
    requestFingerprint: request.requestFingerprint,
    reservationFingerprint: reservation.floorFingerprint,
    attestedProofFingerprint: attestedProof.attestedProofFingerprint,
    authorityReservationFingerprint: authorityReservation.reservationFingerprint,
    authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
    authorityEpochFingerprint: authorityEpoch.authorityEpochFingerprint,
    publicationKFingerprint: publicationK["publication-kFingerprint"],
    publicationYFingerprint: publicationY["publication-yFingerprint"],
    zeroGrantProofFingerprint,
  });
  const zFinality = seal({
    version: 1, kind: "genesis-finality", genesisTxId: txId, generation: 1,
    anchorFingerprint, attestationFingerprint: attestation.attestationFingerprint, tokenFloorFingerprint: tokenFloor.floorFingerprint,
    checkpointFingerprint: canonicalJsonHash(request), publicationKFingerprint: publicationK["publication-kFingerprint"],
    publicationYFingerprint: publicationY["publication-yFingerprint"], authorityEpochFingerprint: authorityEpoch.authorityEpochFingerprint,
    precommitFingerprint: precommit.precommitFingerprint, finalityFingerprint: tokenFloor.floorFingerprint,
  }, "zFinalityFingerprint");
  const proof = seal({
    version: 1, kind: "finality-proof", genesisTxId: txId, generation: 1,
    zFinalityFingerprint: zFinality.zFinalityFingerprint, readerProjectionFingerprint: null, ackFingerprint: null, routeFingerprint: "no-route",
  }, "finalityProofFingerprint");
  const receipt = seal({
    version: 1, kind: "genesis-receipt", genesisTxId: txId, generation: 1,
    requestedReaderMode: "no-reader", readerInstanceId: null, readerStartNonce: null, readerProjectionFingerprint: null, ackFingerprint: null,
    finalityProofFingerprint: proof.finalityProofFingerprint, phase: "terminal",
  }, "receiptFingerprint");
  const authorityReceipt = seal({
    version: 1, kind: "genesis-authority-receipt", genesisTxId: txId, requestFingerprint: authorityRequest.requestFingerprint,
    sequence: 2, anchorFingerprint, generation: 1, readerVersionFloorFingerprint: readerFloor.floorFingerprint,
    authorityCommitSnapshotFingerprint: authorityCommit.authorityCommitSnapshotFingerprint,
  }, "receiptFingerprint");
  const bytes = (value) => Buffer.from(canonicalJson(value));
  return {
    controlRootBytes: bytes(root), wrapperBytes: bytes(wrapper), targetBytes,
    targetIdentity, targetAclFingerprint,
    attestationBytes: bytes(attestation), tokenFloorBytes: bytes(tokenFloor),
    currentAttestationBytes: bytes(attestation), currentTokenFloorBytes: bytes(tokenFloor),
    attestationHistoryBytes: bytes([attestation]), tokenFloorHistoryBytes: bytes([tokenFloor]),
    tokenFloorReservationBytes: bytes(reservation), readerVersionFloorBytes: bytes(readerFloor),
    historyMarkerBytes: bytes(historyMarker),
    genesisRequestBytes: bytes(request), attestedProofBytes: bytes(attestedProof),
    precommitBytes: bytes(precommit), zFinalityBytes: bytes(zFinality),
    rvfBytes: bytes(proof), receiptBytes: bytes(receipt), authorityRequestBytes: bytes(authorityRequest),
    authorityReceiptBytes: bytes(authorityReceipt), authorityReservationBytes: bytes(authorityReservation),
    authorityCommitBytes: bytes(authorityCommit), authorityBaselineBytes: bytes(baseline),
    authorityEpochBytes: bytes(authorityEpoch),
    publicationTransactionBytes: bytes(transaction), publicationUBytes: bytes(u), publicationPBytes: bytes(p),
    publicationSBytes: bytes(s), publicationPreparedBytes: bytes(prepared), publicationReplacedBytes: bytes(replaced),
    publicationCommittedBytes: bytes(committed), publicationCBytes: bytes(c), publicationQBytes: bytes(q),
    publicationZpBytes: bytes(zp), publicationKBytes: bytes(publicationK), publicationYBytes: bytes(publicationY),
    readerStateBytes: undefined, readerProjectionBytes: undefined, fenceBindingBytes: undefined,
    readerLeaseBytes: undefined, admissionRequestBytes: undefined, admissionGrantBytes: undefined,
    admissionAckBytes: undefined,
    botPrincipal: provisionedRoles.botSid, botOsPrincipal: provisionedRoles.botSid, botStateAclFingerprint: "f".repeat(64), nativeVerified: true,
  };
}
test("legacy-retained validation is workspace-only with no route", async () => {
  const result = await loadManagedChannelMapState({ current: {}, readSnapshot: () => managedSnapshot("legacy-retained") });
  assert.equal(result.ok, true);
  assert.equal(result.classification.sourceKind, "legacy-retained");
  assert.equal(result.classification.routeDisposition, "no-route");
  assert.deepEqual(result.map, {});
});

test("legacy-v0 parsing and last-good behavior remain unchanged without a control root", async () => {
  const current = { "1": { hostId: "old", workDir: "/old" } };
  const legacyFence = { targetIdentity: "legacy-target", generation: "a".repeat(64) };
  const valid = await loadManagedChannelMapState({ current, readSnapshot: () => ({ controlRootAbsent: true, controlRootBytes: null, managedSidecarPresent: false, managementMarkerPresent: false, legacyV0Verified: true, legacyFence, targetBytes: Buffer.from('{"2":{"hostId":"new","workDir":"/new"}}') }) });
  assert.equal(valid.classification.sourceKind, "legacy-v0");
  assert.deepEqual(valid.map, { "2": { hostId: "new", workDir: "/new" } });
  const invalid = await loadManagedChannelMapState({ current, readSnapshot: () => ({ controlRootAbsent: true, controlRootBytes: null, managedSidecarPresent: false, managementMarkerPresent: false, legacyV0Verified: true, legacyFence, targetBytes: Buffer.from("{") }) });
  assert.equal(invalid.ok, false);
  assert.equal(invalid.map, current);
});
test("management markers block legacy-v0 before dispatch", async () => {
  const current = { "1": { hostId: "old", workDir: "/old" } };
  for (const marker of ["control directory", "GR", "TF", "A", "partial control root", "manual cleanup"]) {
    const result = await loadManagedChannelMapState({
      current,
      readSnapshot: () => ({
        controlRootBytes: null,
        managementMarkerPresent: true,
        targetBytes: Buffer.from('{"2":{"hostId":"new","workDir":"/new"}}'),
      }),
    });
    assert.equal(result.ok, false, marker);
    assert.equal(result.classification.sourceKind, "unavailable", marker);
    assert.equal(result.classification.routeDisposition, "no-route", marker);
    assert.deepEqual(result.map, {}, marker);
    const replies = [];
    assert.equal(dispatchGate(result.classification, (message) => replies.push(message)), false, marker);
    assert.deepEqual(replies, [`Workspace mapping unavailable (${WORKSPACE_MAPPING_UNAVAILABLE}).`], marker);
  }
});
test("managed authority selection latches bootstrap and partial markers for the process lifetime", async () => {
  const legacyFence = { targetIdentity: "legacy-target", generation: "a".repeat(64) };
  const legacySnapshot = {
    controlRootAbsent: true,
    controlRootBytes: null,
    managementMarkerPresent: false,
    managedSidecarPresent: false,
    legacyV0Verified: true,
    legacyFence,
    targetBytes: Buffer.from('{"2":{"hostId":"legacy","workDir":"/legacy"}}'),
  };
  const authoritySelection = createManagedAuthoritySelection();
  const load = (snapshot) => loadManagedChannelMapState({
    current: { stale: true },
    readSnapshot: () => snapshot,
    authoritySelection,
  });

  const initialLegacy = await load(legacySnapshot);
  assert.equal(initialLegacy.classification.sourceKind, "legacy-v0");

  const bootstrap = await load({
    controlRootAbsent: true,
    controlRootBytes: null,
    bootstrapBlockerPresent: true,
    targetBytes: Buffer.alloc(0),
  });
  assert.equal(bootstrap.classification.sourceKind, "unavailable");
  assert.equal(bootstrap.classification.routeDisposition, "no-route");

  const afterMarkerLoss = await load(legacySnapshot);
  assert.equal(afterMarkerLoss.classification.sourceKind, "unavailable");
  assert.equal(afterMarkerLoss.classification.routeDisposition, "no-route");
  const nativeUnavailable = await load({
    controlRootAbsent: false,
    controlRootBytes: Buffer.alloc(0),
    managedSidecarPresent: true,
  });
  assert.equal(nativeUnavailable.classification.sourceKind, "unavailable");
  assert.equal(nativeUnavailable.classification.routeDisposition, "no-route");

  const restartedSelection = createManagedAuthoritySelection();
  const persistedBlocker = await loadManagedChannelMapState({
    current: {},
    readSnapshot: () => ({
      controlRootAbsent: true,
      controlRootBytes: null,
      bootstrapBlockerPresent: true,
      targetBytes: Buffer.alloc(0),
    }),
    authoritySelection: restartedSelection,
  });
  assert.equal(persistedBlocker.classification.sourceKind, "unavailable");

  for (const snapshot of [
    { controlRootAbsent: true, controlRootBytes: null, genesisProbePresent: true, targetBytes: Buffer.alloc(0) },
    { controlRootAbsent: false, controlRootBytes: Buffer.alloc(0), managementMarkerPresent: true, targetBytes: Buffer.alloc(0) },
  ]) {
    const result = await loadManagedChannelMapState({
      current: {},
      readSnapshot: () => snapshot,
      authoritySelection: createManagedAuthoritySelection(),
    });
    assert.equal(result.classification.sourceKind, "unavailable");
    assert.equal(result.classification.routeDisposition, "no-route");
  }
});

test("control directory emergence schedules a mapping reload", () => {
  let controlDirectoryPresent = false;
  const watchers = [];
  const timers = [];
  let reloads = 0;
  const handle = watchConfigHints(["/state/channels.json"], () => reloads++, {
    directoryPaths: ["/state/.gjc-remote-control"],
    existsSyncFn: () => controlDirectoryPresent,
    watchFn(directory, _options, callback) {
      const watcher = { directory, callback, on() {}, close() {} };
      watchers.push(watcher);
      return watcher;
    },
    setTimeoutFn(callback) {
      const timer = { callback };
      timers.push(timer);
      return timer;
    },
    clearTimeoutFn() {},
  });

  assert.deepEqual(watchers.map((watcher) => watcher.directory), ["/state"]);
  controlDirectoryPresent = true;
  watchers[0].callback("rename", ".gjc-remote-control");
  assert.deepEqual(watchers.map((watcher) => watcher.directory), ["/state", "/state/.gjc-remote-control"]);
  timers[0].callback();
  assert.equal(reloads, 1);
  handle.close();
});
test("managed v2 target keeps mapping generation independent of token generation", () => {
  const target = JSON.parse(managedSnapshot().targetBytes);
  assert.equal(target.version, 2);
  assert.equal(target.tokenConfigGeneration, 1);
  assert.equal(target.mappingGeneration, 0);
  assert.equal(target.mappingGeneration < target.tokenConfigGeneration, true);
});

test("control root takes precedence and managed mappings have no routes", async () => {
  const result = await loadManagedChannelMapState({ current: { stale: true }, readSnapshot: () => managedSnapshot() });
  assert.equal(result.ok, true);
  assert.equal(result.classification.sourceKind, "managed-v1");
  assert.deepEqual(result.map, {});
});

test("pointer mismatch and sidecar loss fail closed", async () => {
  const mismatch = managedSnapshot();
  const root = JSON.parse(mismatch.controlRootBytes);
  root.wrapperRelativeName = "legacy-retained.json";
  mismatch.controlRootBytes = Buffer.from(JSON.stringify(root));
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: () => mismatch })).classification.sourceKind, "unavailable");
  const missing = managedSnapshot();
  missing.wrapperBytes = undefined;
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: () => missing })).classification.sourceKind, "unavailable");
});
test("verified native reader accepts canonical managed and retained snapshots", async () => {
  for (const sourceKind of ["managed-v1", "legacy-retained"]) {
    const snapshot = managedSnapshot(sourceKind);
    const expectedHostSetFingerprint = JSON.parse(snapshot.attestationBytes).tokenConfigHostSetFingerprint;
    validateManagedProof(snapshot, expectedHostSetFingerprint);
    assert.throws(() => validateManagedProof(snapshot, "0".repeat(64)), /host-set fingerprint/);
    const reader = await createTestManagedAuthorityReader({
      configPath: "/safe/channels.json",
      expectedHostSetFingerprint,
      roleBindings: provisionedRoles,
      native: ({
        configureManagementRoles: async () => {},
        runStartupSelfTest: botStartupSelfTest,
        readManagedMappingSnapshot: async () => ({
          ...snapshot,
          controlRootName: "control-root.json",
          wrapperName: sourceKind === "managed-v1" ? "managed-v1-wrapper.json" : "legacy-retained.json",
        }),
      }),
    });
    const verified = await reader.readSnapshot();
    assert.equal(verified.nativeVerified, true, JSON.stringify({ sourceKind, code: verified.code }));
    const result = await loadManagedChannelMapState({ current: {}, readSnapshot: async () => verified });
    assert.equal(result.ok, true);
    assert.equal(result.classification.sourceKind, sourceKind);
  }
});
test("legacy-retained publication rejects a mismatched canonical mapping fingerprint", () => {
  assert.throws(
    () => validateManagedProof(managedSnapshot("legacy-retained", "0".repeat(64))),
    /publication/i,
  );
});
test("legacy-retained canonical mapping tuple fields are required", () => {
  const snapshot = managedSnapshot("legacy-retained");
  snapshot.targetAclFingerprint = undefined;
  assert.throws(() => validateManagedProof(snapshot), /management envelope/);
});
test("reader requires provisioned bindings before native construction and configures them before reads", async () => {
  let factoryCalls = 0;
  const unbound = await createManagedAuthorityReader({
    configPath: "/safe/channels.json",
    nativeFactory: async () => { factoryCalls += 1; return null; },
  });
  assert.equal((await unbound.readSnapshot()).code, "MANAGEMENT_ROLE_BINDING_REQUIRED");
  assert.equal(factoryCalls, 0);
  const production = await createManagedAuthorityReader({
    configPath: "/safe/channels.json",
    roleBindings: provisionedRoles,
    nativeFactory: async () => { factoryCalls += 1; return null; },
  });
  assert.equal(factoryCalls, 0);
  assert.equal(typeof production.readSnapshot, "function");

  const calls = [];
  const reader = await createTestManagedAuthorityReader({
    configPath: "/safe/channels.json",
    roleBindings: provisionedRoles,
    native: ({
      configureManagementRoles: async (bindings) => calls.push(["configure", bindings]),
      runStartupSelfTest: botStartupSelfTest,
      readManagedMappingSnapshot: async () => {
        calls.push(["read"]);
        return { controlRootAbsent: true };
      },
    }),
  });
  assert.deepEqual(calls, [["configure", provisionedRoles]]);
  await reader.readSnapshot();
  assert.deepEqual(calls, [["configure", provisionedRoles], ["read"]]);
});
test("loader rejects a Genesis proof after an otherwise valid G+1 token rotation", () => {
  const snapshot = managedSnapshot();
  const attestation = JSON.parse(snapshot.attestationBytes);
  const tokenFloor = JSON.parse(snapshot.tokenFloorBytes);
  const { attestationFingerprint: _attestationFingerprint, ...attestationFields } = attestation;
  const txId = "223e4567-e89b-42d3-a456-426614174000";
  const reservation = reserveTokenGeneration(tokenFloor, { generation: 2, txId });
  const currentAttestation = seal({
    ...attestationFields,
    tokenConfigGeneration: 2,
    rotationKind: "same-key",
    previousAttestationFingerprint: attestation.attestationFingerprint,
    txId,
  }, "attestationFingerprint");
  const attestedProof = buildAttestedTokenFloorProof(reservation, currentAttestation);
  const currentTokenFloor = commitTokenFloor(attestTokenFloor(reservation, attestedProof), {
    generation: 2,
    txId,
    attestationFingerprint: currentAttestation.attestationFingerprint,
  });
  const rotated = {
    ...snapshot,
    currentAttestationBytes: Buffer.from(canonicalJson(currentAttestation)),
    currentTokenFloorBytes: Buffer.from(canonicalJson(currentTokenFloor)),
    attestationHistoryBytes: Buffer.from(canonicalJson([attestation, currentAttestation])),
    tokenFloorHistoryBytes: Buffer.from(canonicalJson([tokenFloor, currentTokenFloor])),
  };
  assert.throws(
    () => validateManagedProof(rotated, attestation.tokenConfigHostSetFingerprint),
    /stale reader or admission proof generation/,
  );
  assert.equal(dispatchGate({ routeDisposition: "no-route" }, () => {}), false);
});

test("native reader fails closed for malformed, swapped, missing, or identity- and ACL-drifted authority records", async () => {
  const source = managedSnapshot();
  validateManagedProof(source);
  const native = {
    configureManagementRoles: async () => {},
    runStartupSelfTest: botStartupSelfTest,
    readManagedMappingSnapshot: async () => ({
      ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
    }),
  };
  const reader = await createTestManagedAuthorityReader({ roleBindings: provisionedRoles, native });
  const baseline = await reader.readSnapshot();
  assert.equal(baseline.nativeVerified, true, JSON.stringify({ code: baseline.code }));
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: async () => baseline })).ok, true);
  for (const key of ["attestationBytes", "tokenFloorBytes", "currentAttestationBytes", "currentTokenFloorBytes", "attestationHistoryBytes", "tokenFloorHistoryBytes", "tokenFloorReservationBytes", "readerVersionFloorBytes", "genesisRequestBytes", "zFinalityBytes", "rvfBytes", "receiptBytes", "authorityRequestBytes", "authorityReceiptBytes", "authorityReservationBytes", "authorityCommitBytes", "authorityBaselineBytes", "authorityEpochBytes", "publicationTransactionBytes", "publicationUBytes", "publicationPBytes", "publicationSBytes", "publicationPreparedBytes", "publicationReplacedBytes", "publicationCommittedBytes", "publicationCBytes", "publicationQBytes", "publicationZpBytes", "publicationKBytes", "publicationYBytes"]) {
    native.readManagedMappingSnapshot = async () => ({
      ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json", [key]: Buffer.from("{}"),
    });
    const result = await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot });
    assert.equal(result.classification.sourceKind, "unavailable");
    assert.equal(result.classification.code, "MANAGED_NATIVE_UNAVAILABLE");
    assert.doesNotMatch(result.error.message, /safe|channels|secret|path/i);
    native.readManagedMappingSnapshot = async () => ({
      ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json", [key]: undefined,
    });
    assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  }
  native.readManagedMappingSnapshot = async () => ({
    ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
    rvfBytes: source.receiptBytes, receiptBytes: source.rvfBytes,
  });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  native.readManagedMappingSnapshot = async () => ({
    ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
    publicationUBytes: source.publicationPBytes, publicationPBytes: source.publicationUBytes,
  });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  const semanticForgery = managedSnapshot();
  const forgedU = buildPublicationU({ ...JSON.parse(semanticForgery.publicationUBytes), targetState: "managed-empty" });
  const forgedP = buildPublicationP({ ...JSON.parse(semanticForgery.publicationPBytes), uFingerprint: forgedU["publication-uFingerprint"], targetState: forgedU.targetState });
  const forgedS = buildPublicationS({ ...JSON.parse(semanticForgery.publicationSBytes), pFingerprint: forgedP["publication-pFingerprint"], targetState: forgedP.targetState });
  const forgedC = buildPublicationC({ ...JSON.parse(semanticForgery.publicationCBytes), sFingerprint: forgedS["publication-sFingerprint"] });
  const forgedQ = buildPublicationQ({ ...JSON.parse(semanticForgery.publicationQBytes), cFingerprint: forgedC["publication-cFingerprint"] });
  const forgedZp = buildPublicationZp({ ...JSON.parse(semanticForgery.publicationZpBytes), qFingerprint: forgedQ["publication-qFingerprint"] });
  const forgedK = buildPublicationK({ ...JSON.parse(semanticForgery.publicationKBytes), zpFingerprint: forgedZp["publication-zpFingerprint"] });
  const forgedY = buildPublicationY({ ...JSON.parse(semanticForgery.publicationYBytes), kFingerprint: forgedK["publication-kFingerprint"], targetState: forgedU.targetState });
  native.readManagedMappingSnapshot = async () => ({
    ...semanticForgery, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
    publicationUBytes: Buffer.from(canonicalJson(forgedU)), publicationPBytes: Buffer.from(canonicalJson(forgedP)),
    publicationSBytes: Buffer.from(canonicalJson(forgedS)), publicationCBytes: Buffer.from(canonicalJson(forgedC)),
    publicationQBytes: Buffer.from(canonicalJson(forgedQ)), publicationZpBytes: Buffer.from(canonicalJson(forgedZp)),
    publicationKBytes: Buffer.from(canonicalJson(forgedK)), publicationYBytes: Buffer.from(canonicalJson(forgedY)),
  });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  const swappedReservation = managedSnapshot();
  native.readManagedMappingSnapshot = async () => ({
    ...swappedReservation, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
    tokenFloorReservationBytes: swappedReservation.tokenFloorBytes,
  });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  const cleanup = seal({
    version: 1, kind: "manual-cleanup", anchorFingerprint: managementAnchorFingerprint(anchor),
    txId: null, reason: "crash", expectedFingerprint: null, observedFingerprint: null,
    expectedFloorFingerprint: null, observedFloorFingerprint: null, routeDisposition: "no-route",
    blockedUntilOwnerAction: true,
  }, "manualCleanupFingerprint");
  native.readManagedMappingSnapshot = async () => ({
    ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
    manualCleanupBytes: Buffer.from(canonicalJson(cleanup)),
  });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  native.readManagedMappingSnapshot = async () => ({
    ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
    recoveryBytes: Buffer.from("{}"),
  });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");

  const staleGeneration = managedSnapshot();
  const { requestFingerprint: _requestFingerprint, ...staleRequest } = JSON.parse(staleGeneration.genesisRequestBytes);
  staleRequest.generation = 2;
  staleGeneration.genesisRequestBytes = Buffer.from(canonicalJson(seal(staleRequest, "requestFingerprint")));
  native.readManagedMappingSnapshot = async () => ({
    ...staleGeneration, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json",
  });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");

  native.readManagedMappingSnapshot = async () => ({ ...source, controlRootName: "control-root.json", wrapperName: "swapped.json" });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  native.readManagedMappingSnapshot = async () => ({ ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json", wrapperBytes: undefined });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  native.readManagedMappingSnapshot = async () => ({ ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json", targetIdentity: "swapped-identity" });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  native.readManagedMappingSnapshot = async () => ({ ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json", targetIdentity: "/safe/channels.json" });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
  native.readManagedMappingSnapshot = async () => ({ ...source, controlRootName: "control-root.json", wrapperName: "managed-v1-wrapper.json", targetAclFingerprint: "d".repeat(64) });
  assert.equal((await loadManagedChannelMapState({ current: {}, readSnapshot: reader.readSnapshot })).classification.sourceKind, "unavailable");
});

test("real native marker emergence cannot collapse to legacy absence", async () => {
  const reader = await createTestManagedAuthorityReader({
    configPath: "/safe/channels.json",
    roleBindings: provisionedRoles,
    native: ({
      configureManagementRoles: async () => {},
      runStartupSelfTest: botStartupSelfTest,
      readManagedMappingSnapshot: async () => ({
        controlRootAbsent: false,
        managementMarkerPresent: true,
      }),
    }),
  });
  const snapshot = await reader.readSnapshot();
  assert.equal(snapshot.code, "MANAGED_MARKER_INCOMPLETE");
  assert.equal(snapshot.managedSidecarPresent, true);
});
test("bot reader writes require authenticated bound-reader authority", async () => {
  const calls = [];
  const reader = await createTestManagedAuthorityReader({
    configPath: "/safe/channels.json",
    roleBindings: provisionedRoles,
    native: ({
      configureManagementRoles: async () => {},
      runStartupSelfTest: botStartupSelfTest,
      readManagedMappingSnapshot: async () => ({ controlRootAbsent: true }),
      writeBotReaderProjection: async (value) => calls.push(["projection", value]),
      writeBotReaderState: async (value) => calls.push(["state", value]),
      acquireBotLease: async (value) => calls.push(["lease", value]),
      writeBotAcknowledgement: async (value) => calls.push(["ack", value]),
    }),
  });
  const readerState = {
    attestationFingerprint: null, authorityReservationFingerprint: null,
    authorityCommitSnapshotFingerprint: null, fenceBindingFingerprint: null,
    leaseBindingFingerprint: null, readerProjectionFingerprint: null,
    readerInstanceId: null, readerStartNonce: null, readerVersion: null,
  };
  await assert.rejects(reader.writeReaderProjection({}), /BOT_AUTHORITY_UNAVAILABLE/);
  await assert.rejects(reader.writeReaderState(readerState), /BOT_AUTHORITY_UNAVAILABLE/);
  await assert.rejects(reader.acquireLease({}), /BOT_AUTHORITY_UNAVAILABLE/);
  await assert.rejects(reader.acknowledge({}), /BOT_AUTHORITY_UNAVAILABLE/);
  assert.deepEqual(calls, []);
  assert.equal(reader.writeControlRoot, undefined);
});

test("generic native snapshot failures never trigger bot authority writes", async () => {
  const calls = [];
  const reader = await createTestManagedAuthorityReader({
    configPath: "/safe/channels.json",
    roleBindings: provisionedRoles,
    native: ({
      configureManagementRoles: async () => {},
      runStartupSelfTest: botStartupSelfTest,
      readManagedMappingSnapshot: async () => { throw new Error("read failed"); },
      writeBotReaderProjection: async () => calls.push("projection"),
      writeBotReaderState: async () => calls.push("state"),
      acquireBotLease: async () => calls.push("lease"),
      writeBotAcknowledgement: async () => calls.push("ack"),
    }),
  });
  const snapshot = await reader.readSnapshot();
  assert.equal(snapshot.code, "MANAGED_NATIVE_UNAVAILABLE");
  assert.deepEqual(calls, []);
});

test("managed dispatch never reaches online or invoke and redacts mapping details", async () => {
  let online = 0;
  let invoke = 0;
  let diagnostic;
  const allowed = dispatchGate({ sourceKind: "managed-v1" }, (text) => { diagnostic = text; });
  assert.equal(allowed, false);
  if (allowed) { online++; invoke++; }
  await Promise.resolve();
  assert.equal(online, 0);
  assert.equal(invoke, 0);
  assert.match(diagnostic, new RegExp(WORKSPACE_MAPPING_UNAVAILABLE));
  assert.doesNotMatch(diagnostic, /secret-host|secret\/path|[A-Za-z]:\\/);
  assert.equal(dispatchGate({ sourceKind: "legacy-retained" }, () => {}), false);
});
test("legacy source fence rejects missed marker events and target identity drift before dispatch", () => {
  const paths = { targetPath: "/safe/channels.json", controlDirectoryPath: "/safe/.gjc-remote-control", controlRootPath: "/safe/.gjc-remote-control/control-root.json" };
  let markerPresent = false;
  let targetVersion = 1;
  const stat = (version) => ({
    dev: 1, ino: version, size: 2, mtimeMs: version, ctimeMs: version,
    isFile: () => true, isSymbolicLink: () => false,
  });
  const fs = {
    lstatSync(path) {
      if (path === paths.targetPath) return stat(targetVersion);
      if (markerPresent && path === paths.controlDirectoryPath) return stat(99);
      const error = new Error("absent"); error.code = "ENOENT"; throw error;
    },
    readFileSync: () => Buffer.from("{}"),
  };
  const snapshot = readLegacyV0SourceSnapshot({ ...paths, fs });
  assert.equal(verifyLegacyV0SourceFence({ ...paths, fs }, snapshot.legacyFence), true);
  markerPresent = true;
  assert.equal(verifyLegacyV0SourceFence({ ...paths, fs }, snapshot.legacyFence), false);
  markerPresent = false;
  targetVersion = 2;
  assert.equal(verifyLegacyV0SourceFence({ ...paths, fs }, snapshot.legacyFence), false);

  let responded = 0;
  const mapping = { sourceKind: "legacy-v0", legacyFence: snapshot.legacyFence };
  assert.equal(dispatchGate(mapping, () => { responded += 1; }, () => false), false);
  assert.equal(responded, 1);
});
