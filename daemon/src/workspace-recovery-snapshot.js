// Boot-recovery snapshot vocabulary primitive (slice S6a, #53 Phase 2 / G004).
//
// Pure, io-free module. A `RecoverySnapshot` is the single shared record every
// downstream crash-recovery classifier (S6b) consumes: it names, for one
// workspace, the durable state a restarted daemon can observe on disk after a
// crash mid-operation - the currently-live generation pointer, the pre-crash
// prior pointer, an OPTIONAL recovered candidate pointer body, the lifecycle
// transaction/checkpoint, and any manual-cleanup record.
//
// This module invents NO new schema. Each present field is validated by its
// OWN already-merged validator:
//   - livePointer / priorPointer / candidatePointer -> S4d validateGenerationPointer
//   - transaction                                    -> shared validateWorkspaceLifecycleTransaction
//   - checkpoint (with its transaction relation)     -> shared validateWorkspaceLifecycleCheckpoint
//   - manualCleanup                                  -> shared validateManualCleanup
// A malformed field therefore throws that field's own structured error
// (WORKSPACE_GENERATION_INVALID / WORKSPACE_LIFECYCLE_ENVELOPE_INVALID /
// RECOVERY_ENVELOPE_INVALID), unchanged. Only the container shape itself
// (wrong key set, bad workspaceId) refuses with this module's local
// WORKSPACE_RECOVERY_SNAPSHOT_INVALID literal.
//
// `candidatePointer` is the F2 addition: checkpoints/transactions store
// FINGERPRINTS only, never a pointer body, so S6b's `safe-replay` disposition
// needs a named durable source for the candidate pointer bytes. When present it
// is validated exactly like livePointer/priorPointer; when null it is a
// structurally distinguishable "no recoverable candidate body" signal that S6b
// treats as fail-closed (manual_cleanup). The concrete durable source of that
// body at boot (io.readCandidatePointer) is S6d's injected capability.
//
// Every field is either a validated record or explicit `null`; there is no
// implicit/undefined middle state. The returned snapshot is frozen.

import { validateGenerationPointer } from "./workspace-generation-publisher.js";
import {
  validateWorkspaceLifecycleCheckpoint,
  validateWorkspaceLifecycleTransaction,
} from "@gjc-remote/shared/workspace-lifecycle-envelope";
import { validateManualCleanup } from "@gjc-remote/shared/recovery-envelope";

const OPERATION = "workspace_recovery_snapshot";

// Module-local refusal code (A5: only genuinely-new PROTOCOL_ERROR_CODES are
// registered centrally; this container-shape refusal stays a local literal and
// is asserted as a literal string by the tests).
const SNAPSHOT_INVALID = "WORKSPACE_RECOVERY_SNAPSHOT_INVALID";

const SNAPSHOT_KEYS = Object.freeze([
  "workspaceId",
  "livePointer",
  "priorPointer",
  "candidatePointer",
  "checkpoint",
  "transaction",
  "manualCleanup",
]);

function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (!["code", "operation", "reason", "message"].includes(key)) error[key] = value;
    }
  }
  throw error;
}

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const hasExactKeys = (value, keys) =>
  isPlainObject(value) && Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

const isId = (value) => typeof value === "string" && value.length > 0 && value.length <= 256;

// Validate every present field by its OWN validator (errors propagate
// unchanged); a null field is an explicit "absent" and passes. The checkpoint
// is validated together with the transaction so their relation is enforced
// whenever both are present (and a committed/applied checkpoint with no
// transaction correctly fails its own evidence rule).
function assertFields(snapshot) {
  if (!isId(snapshot.workspaceId)) {
    refuse(SNAPSHOT_INVALID, "workspaceId must be a 1..256 char string");
  }
  if (snapshot.transaction !== null) validateWorkspaceLifecycleTransaction(snapshot.transaction);
  if (snapshot.checkpoint !== null) validateWorkspaceLifecycleCheckpoint(snapshot.checkpoint, snapshot.transaction);
  if (snapshot.livePointer !== null) validateGenerationPointer(snapshot.livePointer);
  if (snapshot.priorPointer !== null) validateGenerationPointer(snapshot.priorPointer);
  if (snapshot.candidatePointer !== null) validateGenerationPointer(snapshot.candidatePointer);
  if (snapshot.manualCleanup !== null) validateManualCleanup(snapshot.manualCleanup);
}

/**
 * Validate an exact, already-assembled recovery snapshot. Requires the exact
 * key set (each value validated-or-null). Returns the same object on success;
 * throws a structured refusal otherwise (container shape via
 * WORKSPACE_RECOVERY_SNAPSHOT_INVALID, individual fields via their own
 * validator's error).
 */
export function validateRecoverySnapshot(snapshot) {
  if (!hasExactKeys(snapshot, SNAPSHOT_KEYS)) {
    refuse(SNAPSHOT_INVALID, "snapshot must have the exact snapshot key set");
  }
  assertFields(snapshot);
  return snapshot;
}

/**
 * Build and validate a recovery snapshot. Every field defaults to `null` when
 * absent; unknown input keys are rejected (a typo must never be silently
 * dropped). Returns a frozen snapshot with the exact key set.
 */
export function buildRecoverySnapshot(input) {
  if (!isPlainObject(input)) refuse(SNAPSHOT_INVALID, "snapshot input must be an object");
  for (const key of Object.keys(input)) {
    if (!SNAPSHOT_KEYS.includes(key)) refuse(SNAPSHOT_INVALID, `unknown snapshot field: ${key}`);
  }
  const snapshot = {
    workspaceId: input.workspaceId,
    livePointer: input.livePointer ?? null,
    priorPointer: input.priorPointer ?? null,
    candidatePointer: input.candidatePointer ?? null,
    checkpoint: input.checkpoint ?? null,
    transaction: input.transaction ?? null,
    manualCleanup: input.manualCleanup ?? null,
  };
  validateRecoverySnapshot(snapshot);
  return Object.freeze(snapshot);
}

export { SNAPSHOT_KEYS, SNAPSHOT_INVALID };
