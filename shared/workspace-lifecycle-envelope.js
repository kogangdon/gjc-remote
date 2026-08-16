import { canonicalJsonHash, isHex64 } from "./strict-json.js";
import { isOpaqueIdentity } from "./identity.js";
import { validateManualCleanup } from "./recovery-envelope.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`WORKSPACE_LIFECYCLE_ENVELOPE_INVALID: ${message}`); };
const fingerprint = (value, field) => canonicalJsonHash(Object.fromEntries(Object.entries(value).filter(([key]) => key !== field)));
const generation = (value) => Number.isSafeInteger(value) && value >= 1;
const nullableHash = (value) => value === null || isHex64(value);
const operations = new Set(["create", "clone", "refresh", "reset", "delete", "restore", "migration"]);
const txKeys = ["version", "kind", "txId", "hostId", "mappingId", "mappingGeneration", "mappingVersion", "workspaceId", "workspaceGeneration", "sourcePlatform", "routeFingerprint", "authorityFingerprint", "inventoryGeneration", "anchorFingerprint", "operation", "principalFingerprint", "idempotencyFingerprint", "ownerFingerprint", "fenceGeneration", "expectedHeadRevision", "expectedHeadFingerprint", "beforeFingerprint", "candidateFingerprint", "priorFingerprint", "transactionFingerprint"];
const checkpointKeys = ["version", "kind", "txId", "transactionFingerprint", "phase", "operationEvidenceFingerprint", "checkpointFingerprint"];
const headKeys = ["version", "kind", "revision", "currentRecordFingerprint", "disposition", "headFingerprint"];

/** Returns the canonical SHA-256 fingerprint of a lifecycle record excluding its fingerprint field. This is a non-serving contract only; it provides no host durability or recovery. */
export function workspaceLifecycleRecordFingerprint(record, field) { return fingerprint(record, field); }

/** Validates an exact workspace lifecycle transaction. This is a non-serving contract only; it provides no host durability or recovery. */
export function validateWorkspaceLifecycleTransaction(tx) {
  if (!exact(tx, txKeys) || tx.version !== 1 || tx.kind !== "workspace-lifecycle-transaction" || !isOpaqueIdentity(tx.txId) || !isOpaqueIdentity(tx.hostId) || !isOpaqueIdentity(tx.mappingId) || !generation(tx.mappingGeneration) || !generation(tx.mappingVersion) || !isOpaqueIdentity(tx.workspaceId) || !generation(tx.workspaceGeneration) || !isOpaqueIdentity(tx.sourcePlatform) || !isHex64(tx.routeFingerprint) || !isHex64(tx.authorityFingerprint) || !generation(tx.inventoryGeneration) || !isHex64(tx.anchorFingerprint) || !operations.has(tx.operation) || !isHex64(tx.principalFingerprint) || !isHex64(tx.idempotencyFingerprint) || !isHex64(tx.ownerFingerprint) || !generation(tx.fenceGeneration) || !Number.isSafeInteger(tx.expectedHeadRevision) || tx.expectedHeadRevision < 0 || !nullableHash(tx.expectedHeadFingerprint) || !nullableHash(tx.beforeFingerprint) || !isHex64(tx.candidateFingerprint) || !nullableHash(tx.priorFingerprint) || !isHex64(tx.transactionFingerprint)) fail("transaction schema");
  if ((tx.operation === "create" || tx.operation === "clone") ? (tx.beforeFingerprint !== null || tx.priorFingerprint !== null) : (!isHex64(tx.beforeFingerprint) || !isHex64(tx.priorFingerprint))) fail("transaction operation evidence");
  if (fingerprint(tx, "transactionFingerprint") !== tx.transactionFingerprint) fail("transaction fingerprint");
  return tx;
}

/** Builds and validates an exact workspace lifecycle transaction. This is a non-serving contract only; it provides no host durability or recovery. */
export function buildWorkspaceLifecycleTransaction(fields) {
  const tx = { ...fields, version: 1, kind: "workspace-lifecycle-transaction" };
  tx.transactionFingerprint = fingerprint(tx, "transactionFingerprint");
  return validateWorkspaceLifecycleTransaction(tx);
}

/** Validates an exact lifecycle checkpoint and its transaction relation. This is a non-serving contract only; it provides no host durability or recovery. */
export function validateWorkspaceLifecycleCheckpoint(checkpoint, transaction) {
  if (!exact(checkpoint, checkpointKeys) || checkpoint.version !== 1 || checkpoint.kind !== "workspace-lifecycle-checkpoint" || !isOpaqueIdentity(checkpoint.txId) || !isHex64(checkpoint.transactionFingerprint) || !["prepared", "applied", "committed", "manual_cleanup"].includes(checkpoint.phase) || !nullableHash(checkpoint.operationEvidenceFingerprint) || !isHex64(checkpoint.checkpointFingerprint)) fail("checkpoint schema");
  if (fingerprint(checkpoint, "checkpointFingerprint") !== checkpoint.checkpointFingerprint) fail("checkpoint fingerprint");
  if (transaction) {
    validateWorkspaceLifecycleTransaction(transaction);
    if (checkpoint.txId !== transaction.txId || checkpoint.transactionFingerprint !== transaction.transactionFingerprint) fail("checkpoint transaction relation");
  }
  if ((checkpoint.phase === "applied" || checkpoint.phase === "committed") && checkpoint.operationEvidenceFingerprint !== transaction?.candidateFingerprint) fail("checkpoint operation evidence");
  if ((checkpoint.phase === "prepared" || checkpoint.phase === "manual_cleanup") && checkpoint.operationEvidenceFingerprint !== null) fail("checkpoint nullable evidence");
  return checkpoint;
}

/** Builds and validates an exact lifecycle checkpoint. This is a non-serving contract only; it provides no host durability or recovery. */
export function buildWorkspaceLifecycleCheckpoint({ transaction, phase, operationEvidenceFingerprint = null }) {
  validateWorkspaceLifecycleTransaction(transaction);
  const checkpoint = { version: 1, kind: "workspace-lifecycle-checkpoint", txId: transaction.txId, transactionFingerprint: transaction.transactionFingerprint, phase, operationEvidenceFingerprint };
  checkpoint.checkpointFingerprint = fingerprint(checkpoint, "checkpointFingerprint");
  return validateWorkspaceLifecycleCheckpoint(checkpoint, transaction);
}

/** Validates an exact lifecycle CAS head. This is a non-serving contract only; it provides no host durability or recovery. */
export function validateWorkspaceLifecycleHead(head) {
  if (!exact(head, headKeys) || head.version !== 1 || head.kind !== "workspace-lifecycle-head" || !Number.isSafeInteger(head.revision) || head.revision < 0 || !nullableHash(head.currentRecordFingerprint) || !["no-route", "committed"].includes(head.disposition) || !isHex64(head.headFingerprint)) fail("head schema");
  if ((head.disposition === "no-route") !== (head.currentRecordFingerprint === null)) fail("head disposition relation");
  if (fingerprint(head, "headFingerprint") !== head.headFingerprint) fail("head fingerprint");
  return head;
}

/** Builds and validates an exact lifecycle CAS head. This is a non-serving contract only; it provides no host durability or recovery. */
export function buildWorkspaceLifecycleHead({ revision, currentRecordFingerprint = null, disposition = "no-route" }) {
  const head = { version: 1, kind: "workspace-lifecycle-head", revision, currentRecordFingerprint, disposition };
  head.headFingerprint = fingerprint(head, "headFingerprint");
  return validateWorkspaceLifecycleHead(head);
}

/** Classifies lifecycle evidence without serving. This is a non-serving contract only; it provides no host durability or recovery. */
export function classifyWorkspaceLifecycleEvidence({ transaction = null, checkpoint = null, head = null, predecessorHead = null, manualCleanup = null, authorityFingerprint = null } = {}) {
  try {
    if (manualCleanup !== null) { validateManualCleanup(manualCleanup); return "manual_cleanup"; }
    if (!transaction || !checkpoint || !head) return "no-route";
    validateWorkspaceLifecycleTransaction(transaction);
    validateWorkspaceLifecycleCheckpoint(checkpoint, transaction);
    validateWorkspaceLifecycleHead(head);
    if (!isHex64(authorityFingerprint) || authorityFingerprint !== transaction.authorityFingerprint) return "no-route";
    if (head.revision !== transaction.expectedHeadRevision + 1) return "no-route";
    if (transaction.expectedHeadRevision === 0) {
      if (transaction.expectedHeadFingerprint !== null) return "no-route";
    } else {
      validateWorkspaceLifecycleHead(predecessorHead);
      if (predecessorHead.revision !== transaction.expectedHeadRevision ||
          predecessorHead.headFingerprint !== transaction.expectedHeadFingerprint) return "no-route";
    }
    if (head.disposition !== "committed" || head.currentRecordFingerprint !== checkpoint.checkpointFingerprint) return "no-route";
    return checkpoint.phase === "committed" ? "committed" : "no-route";
  } catch { return "no-route"; }
}
