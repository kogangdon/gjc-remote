import { canonicalJsonHash, isHex64 } from "./strict-json.js";
import { isOpaqueIdentity } from "./identity.js";
import { validateManagedChannelsV2 } from "./mapping-envelope.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, expected) => plain(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`RECOVERY_ENVELOPE_INVALID: ${message}`); };
const recordHash = (record, field) => canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
const phase = new Set(["prepared", "replaced", "committed"]);
const nullableHex = (value) => value === null || isHex64(value);

const txKeys = ["version", "kind", "txId", "anchorFingerprint", "operation", "expectedRevision", "expectedFingerprint", "oldSnapshot", "candidateSnapshot", "oldMappingId", "oldMappingGeneration", "candidateMappingId", "candidateMappingGeneration", "immutableGeneration", "txFingerprint"];
const pubKeys = ["version", "kind", "txId", "anchorFingerprint", "phase", "candidateSnapshotFingerprint", "targetSnapshotFingerprint", "targetIdentityFingerprint", "targetAclFingerprint", "publicationFingerprint"];
const backupKeys = ["version", "kind", "txId", "anchorFingerprint", "phase", "oldSnapshotFingerprint", "backupIdentityFingerprint", "backupAclFingerprint", "backupFingerprint"];
const rcKeys = ["version", "kind", "txId", "anchorFingerprint", "phase", "txFingerprint", "publicationFingerprint", "backupFingerprint", "recoveryFingerprint"];

const mappingSnapshot = (value) => plain(value) && isHex64(value.configFingerprint);
const mappingIdentity = (value) => value === null || (typeof value === "string" && value.length > 0 && value.length <= 256);
const mappingGeneration = (value) => value === null || (Number.isSafeInteger(value) && value >= 1);

export function validateMappingRecoveryTransaction(tx) {
  if (!exact(tx, txKeys) || tx.version !== 1 || tx.kind !== "mapping-recovery-tx" || !isOpaqueIdentity(tx.txId) || !isHex64(tx.anchorFingerprint) || !["mapping-reconcile", "mapping-revoke", "mapping-rollback"].includes(tx.operation) || !Number.isSafeInteger(tx.expectedRevision) || tx.expectedRevision < 0 || !nullableHex(tx.expectedFingerprint) || !mappingSnapshot(tx.oldSnapshot) || !mappingSnapshot(tx.candidateSnapshot) || !mappingIdentity(tx.oldMappingId) || !mappingGeneration(tx.oldMappingGeneration) || !mappingIdentity(tx.candidateMappingId) || !mappingGeneration(tx.candidateMappingGeneration) || !plain(tx.immutableGeneration) || !isHex64(tx.txFingerprint)) fail("mapping transaction schema");
  try { validateManagedChannelsV2(tx.oldSnapshot); validateManagedChannelsV2(tx.candidateSnapshot); } catch { fail("mapping transaction snapshots"); }
  if (tx.oldSnapshot.configFingerprint === tx.candidateSnapshot.configFingerprint || recordHash(tx, "txFingerprint") !== tx.txFingerprint) fail("mapping transaction fingerprint");
  return tx;
}

export function validateMappingRecoveryPublication(pub, tx) {
  if (!exact(pub, pubKeys) || pub.version !== 1 || pub.kind !== "mapping-recovery-pub" || !phase.has(pub.phase) || !isOpaqueIdentity(pub.txId) || !isHex64(pub.anchorFingerprint) || !isHex64(pub.candidateSnapshotFingerprint) || !nullableHex(pub.targetSnapshotFingerprint) || !nullableHex(pub.targetIdentityFingerprint) || !nullableHex(pub.targetAclFingerprint) || !isHex64(pub.publicationFingerprint)) fail("mapping publication schema");
  validateMappingRecoveryTransaction(tx);
  if (pub.txId !== tx.txId || pub.anchorFingerprint !== tx.anchorFingerprint || pub.candidateSnapshotFingerprint !== tx.candidateSnapshot.configFingerprint || (pub.phase === "prepared" ? [pub.targetSnapshotFingerprint, pub.targetIdentityFingerprint, pub.targetAclFingerprint].some((value) => value !== null) : [pub.targetSnapshotFingerprint, pub.targetIdentityFingerprint, pub.targetAclFingerprint].some((value) => value === null)) || recordHash(pub, "publicationFingerprint") !== pub.publicationFingerprint) fail("mapping publication relation");
  return pub;
}

export function validateMappingRecoveryBackup(backup, tx) {
  if (!exact(backup, backupKeys) || backup.version !== 1 || backup.kind !== "mapping-recovery-bk" || !phase.has(backup.phase) || !isOpaqueIdentity(backup.txId) || !isHex64(backup.anchorFingerprint) || !isHex64(backup.oldSnapshotFingerprint) || !nullableHex(backup.backupIdentityFingerprint) || !nullableHex(backup.backupAclFingerprint) || !isHex64(backup.backupFingerprint)) fail("mapping backup schema");
  validateMappingRecoveryTransaction(tx);
  if (backup.txId !== tx.txId || backup.anchorFingerprint !== tx.anchorFingerprint || backup.oldSnapshotFingerprint !== tx.oldSnapshot.configFingerprint || [backup.backupIdentityFingerprint, backup.backupAclFingerprint].some((value) => value === null) || recordHash(backup, "backupFingerprint") !== backup.backupFingerprint) fail("mapping backup relation");
  return backup;
}

export function validateMappingRecoveryCheckpoint(rc, tx, pub, backup) {
  if (!exact(rc, rcKeys) || rc.version !== 1 || rc.kind !== "mapping-recovery-rc" || !phase.has(rc.phase) || !isOpaqueIdentity(rc.txId) || !isHex64(rc.anchorFingerprint) || !isHex64(rc.txFingerprint) || !isHex64(rc.publicationFingerprint) || !isHex64(rc.backupFingerprint) || !isHex64(rc.recoveryFingerprint)) fail("mapping recovery checkpoint schema");
  validateMappingRecoveryPublication(pub, tx); validateMappingRecoveryBackup(backup, tx);
  if (rc.txId !== tx.txId || rc.anchorFingerprint !== tx.anchorFingerprint || rc.phase !== pub.phase || rc.phase !== backup.phase || rc.txFingerprint !== tx.txFingerprint || rc.publicationFingerprint !== pub.publicationFingerprint || rc.backupFingerprint !== backup.backupFingerprint || recordHash(rc, "recoveryFingerprint") !== rc.recoveryFingerprint) fail("mapping recovery checkpoint relation");
  return rc;
}

export function buildMappingRecoveryRecords({ tx, phase: currentPhase, targetSnapshotFingerprint = null, targetIdentityFingerprint = null, targetAclFingerprint = null, backupIdentityFingerprint = null, backupAclFingerprint = null }) {
  validateMappingRecoveryTransaction(tx);
  const publication = { version: 1, kind: "mapping-recovery-pub", txId: tx.txId, anchorFingerprint: tx.anchorFingerprint, phase: currentPhase, candidateSnapshotFingerprint: tx.candidateSnapshot.configFingerprint, targetSnapshotFingerprint, targetIdentityFingerprint, targetAclFingerprint, publicationFingerprint: null };
  publication.publicationFingerprint = recordHash(publication, "publicationFingerprint");
  const backup = { version: 1, kind: "mapping-recovery-bk", txId: tx.txId, anchorFingerprint: tx.anchorFingerprint, phase: currentPhase, oldSnapshotFingerprint: tx.oldSnapshot.configFingerprint, backupIdentityFingerprint, backupAclFingerprint, backupFingerprint: null };
  backup.backupFingerprint = recordHash(backup, "backupFingerprint");
  const checkpoint = { version: 1, kind: "mapping-recovery-rc", txId: tx.txId, anchorFingerprint: tx.anchorFingerprint, phase: currentPhase, txFingerprint: tx.txFingerprint, publicationFingerprint: publication.publicationFingerprint, backupFingerprint: backup.backupFingerprint, recoveryFingerprint: null };
  checkpoint.recoveryFingerprint = recordHash(checkpoint, "recoveryFingerprint");
  validateMappingRecoveryCheckpoint(checkpoint, tx, publication, backup);
  return { transaction: tx, publication, backup, checkpoint };
}

export function validateMappingRecoveryRecords(records) {
  if (!plain(records) || !exact(records, ["transaction", "publication", "backup", "checkpoint"])) fail("mapping recovery records schema");
  return validateMappingRecoveryCheckpoint(records.checkpoint, records.transaction, records.publication, records.backup);
}

const mcKeys = ["version", "kind", "anchorFingerprint", "txId", "reason", "expectedFingerprint", "observedFingerprint", "expectedFloorFingerprint", "observedFloorFingerprint", "routeDisposition", "blockedUntilOwnerAction", "manualCleanupFingerprint"];
export function validateManualCleanup(mc) { if (!exact(mc, mcKeys) || mc.version !== 1 || mc.kind !== "manual-cleanup" || !isHex64(mc.anchorFingerprint) || !nullableHex(mc.expectedFingerprint) || !nullableHex(mc.observedFingerprint) || !nullableHex(mc.expectedFloorFingerprint) || !nullableHex(mc.observedFloorFingerprint) || !isOpaqueIdentity(mc.reason) || mc.routeDisposition !== "no-route" || mc.blockedUntilOwnerAction !== true || !isHex64(mc.manualCleanupFingerprint)) fail("manual cleanup schema"); if (mc.txId !== null && !isOpaqueIdentity(mc.txId)) fail("manual cleanup transaction"); if (recordHash(mc, "manualCleanupFingerprint") !== mc.manualCleanupFingerprint) fail("manual cleanup fingerprint"); return mc; }
export const recoveryRecordFingerprint = recordHash;
export function recoveryDisposition({ manualCleanup = null, transaction = null, publication = null, backup = null, checkpoint = null }) {
  try {
    if (manualCleanup !== null) { validateManualCleanup(manualCleanup); return "manual_cleanup"; }
    if (transaction === null || publication === null || backup === null || checkpoint === null) return "no-route";
    validateMappingRecoveryCheckpoint(checkpoint, transaction, publication, backup);
    return checkpoint.phase === "committed" ? "committed" : "recoverable";
  } catch { return "manual_cleanup"; }
}

const suffixKeys = ["version", "kind", "txId", "requestFingerprint", "finalityFingerprint", "receiptFingerprint", "admissionOpen", "phase", "suffixFingerprint"];
export function validateGenesisSuffixRecovery(value, recovery) { if (!exact(value, suffixKeys) || value.version !== 1 || value.kind !== "genesis-suffix-recovery" || value.phase !== "terminal" || !isOpaqueIdentity(value.txId) || !isHex64(value.requestFingerprint) || !isHex64(value.finalityFingerprint) || !isHex64(value.receiptFingerprint) || typeof value.admissionOpen !== "boolean" || !isHex64(value.suffixFingerprint) || recordHash(value, "suffixFingerprint") !== value.suffixFingerprint) fail("genesis suffix schema"); if (!recovery || value.txId !== recovery.txId || value.requestFingerprint !== recovery.requestFingerprint) fail("genesis suffix recovery relation"); return value; }
export function validateManagementRecoveryResult(result, recovery) {
  if (!plain(result) || !plain(recovery)) fail("management recovery result schema");
  if (result.phase === "manual_cleanup") {
    const { manualCleanupFingerprint: _ignored, ...prior } = recovery;
    const expected = { ...prior, phase: "manual_cleanup", routeDisposition: "no-route" };
    if (!isHex64(result.manualCleanupFingerprint) ||
        canonicalJsonHash(Object.fromEntries(Object.entries(result).filter(([key]) => key !== "manualCleanupFingerprint"))) !== canonicalJsonHash(expected)) {
      fail("management recovery manual cleanup relation");
    }
    return result;
  }
  const keys = result.recoveredOldSnapshot === true
    ? ["phase", "routeDisposition", "records", "recoveredOldSnapshot"]
    : ["phase", "routeDisposition", "records"];
  if (!exact(result, keys) || result.phase !== "terminal" || result.routeDisposition !== "no-route" ||
      (result.recoveredOldSnapshot !== undefined && result.recoveredOldSnapshot !== true)) {
    fail("management recovery terminal schema");
  }
  validateMappingRecoveryRecords(result.records);
  validateMappingRecoveryRecords(recovery.records);
  if (canonicalJsonHash(result.records.transaction) !== canonicalJsonHash(recovery.records.transaction)) {
    fail("management recovery transaction relation");
  }
  return result;
}
