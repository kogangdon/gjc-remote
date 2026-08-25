// Reversible-promotion primitive for the restore/migration data plane
// (#53 Phase 2, slice S5h).
//
// Reversible promotion publishes a restored/migrated generation as the new live
// generation, chaining onto the currently-live pointer via S4d's compare-and-
// swap. The prior generation directory is preserved (S4d never deletes it), so
// the promotion is reversible by a subsequent publish that re-points at it.
//
// DESIGN (Amendment A / A3): the record published into the live slot is a
// STANDARD, unmodified S4d generation pointer (exact POINTER_KEYS, built by
// S4d's `buildGenerationPointer` verbatim). There is deliberately NO extended
// pointer shape: `publishGeneration` -> `validateGenerationPointer` enforces
// `hasExactKeys` against POINTER_KEYS, so any extra field would be refused
// WORKSPACE_GENERATION_INVALID. `publishPromotion` is therefore a GENUINE thin
// pass-through to `publishGeneration` -- same PUBLISH_STEPS, same CAS semantics,
// zero divergent atomicity logic.
//
// Restore LINEAGE (which workspace/generation the content was restored from) is
// carried OUT-OF-BAND, never on the published pointer: `buildPromotionLineage`
// produces a frozen, self-fingerprinted lineage record that the S5i restore/
// migration orchestrator attaches to its own frozen result and lifecycle
// transaction evidence. The lineage record never enters the pointer slot and
// never crosses `publishGeneration`; the invariant is enforced structurally by
// S4d's exact-key pointer validation.
//
// This module is a PURE, dependency-injected primitive. It performs NO
// filesystem I/O itself and is NOT wired into the daemon or the native-
// workspace-serving gate (NATIVE_WORKSPACE_SERVING_ENABLED stays false). It
// composes S4d's publisher directly (the one sanctioned sibling import for this
// slice, per the plan) and imports only strict-json helpers from shared.

import { canonicalJsonHash, isHex64 } from "@gjc-remote/shared/strict-json";
import {
  buildGenerationPointer,
  publishGeneration,
  PUBLISH_STEPS,
} from "./workspace-generation-publisher.js";

const OPERATION = "workspace_reversible_promotion";
const LINEAGE_KIND = "workspace-promotion-lineage";
const LINEAGE_VERSION = 1;

// The lineage record is tiny and bounded; a generous cap keeps a hostile or
// corrupt record from exhausting the canonicalizer while dwarfing any
// legitimate record.
const LINEAGE_LIMITS = Object.freeze({ maxBytes: 4096, maxDepth: 8, maxNodes: 64 });

const LINEAGE_INPUT_KEYS = Object.freeze(["restoredFromWorkspaceId", "restoredFromGeneration"]);
const LINEAGE_KEYS = Object.freeze([
  "version",
  "kind",
  "restoredFromWorkspaceId",
  "restoredFromGeneration",
  "lineageFingerprint",
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
const isGeneration = (value) => Number.isSafeInteger(value) && value >= 1;

function lineageFingerprintOf(record) {
  const body = {};
  for (const key of LINEAGE_KEYS) {
    if (key !== "lineageFingerprint") body[key] = record[key];
  }
  try {
    return canonicalJsonHash(body, LINEAGE_LIMITS);
  } catch (error) {
    refuse("CONFIG_INVALID", `lineage body is not canonicalizable: ${error?.message ?? "invalid"}`);
  }
}

/**
 * Validate an exact promotion-lineage record and recheck its self-fingerprint.
 * Returns the same object on success; throws a structured CONFIG_INVALID
 * refusal otherwise.
 */
export function validatePromotionLineage(lineage) {
  if (!hasExactKeys(lineage, LINEAGE_KEYS)) {
    refuse("CONFIG_INVALID", "lineage must have the exact lineage key set");
  }
  if (lineage.version !== LINEAGE_VERSION) refuse("CONFIG_INVALID", "unsupported lineage version");
  if (lineage.kind !== LINEAGE_KIND) refuse("CONFIG_INVALID", "unexpected lineage kind");
  if (!isId(lineage.restoredFromWorkspaceId)) {
    refuse("CONFIG_INVALID", "restoredFromWorkspaceId must be a 1..256 char string");
  }
  if (!isGeneration(lineage.restoredFromGeneration)) {
    refuse("CONFIG_INVALID", "restoredFromGeneration must be a safe integer >= 1");
  }
  if (!isHex64(lineage.lineageFingerprint)) refuse("CONFIG_INVALID", "lineageFingerprint must be hex64");
  if (lineageFingerprintOf(lineage) !== lineage.lineageFingerprint) {
    refuse("CONFIG_INVALID", "lineageFingerprint does not match the lineage body");
  }
  return lineage;
}

/**
 * Build a frozen, self-fingerprinted restore-lineage record from an exact
 * { restoredFromWorkspaceId, restoredFromGeneration } input. This record is
 * out-of-band metadata for the S5i orchestrator result; it NEVER enters the
 * published generation pointer.
 */
export function buildPromotionLineage(input) {
  if (!hasExactKeys(input, LINEAGE_INPUT_KEYS)) {
    refuse("CONFIG_INVALID", "lineage input must have exactly {restoredFromWorkspaceId, restoredFromGeneration}");
  }
  if (!isId(input.restoredFromWorkspaceId)) {
    refuse("CONFIG_INVALID", "restoredFromWorkspaceId must be a 1..256 char string");
  }
  if (!isGeneration(input.restoredFromGeneration)) {
    refuse("CONFIG_INVALID", "restoredFromGeneration must be a safe integer >= 1");
  }
  const record = {
    version: LINEAGE_VERSION,
    kind: LINEAGE_KIND,
    restoredFromWorkspaceId: input.restoredFromWorkspaceId,
    restoredFromGeneration: input.restoredFromGeneration,
    lineageFingerprint: null,
  };
  record.lineageFingerprint = lineageFingerprintOf(record);
  validatePromotionLineage(record);
  return Object.freeze(record);
}

/**
 * Atomically publish a restored/migrated generation as the live generation.
 * This is a GENUINE thin pass-through to S4d's `publishGeneration`: the pointer
 * MUST be a standard S4d generation pointer (exact POINTER_KEYS), and all CAS /
 * ordered-step / crash-safety semantics are S4d's, unmodified. A pointer
 * carrying any extra field (e.g. an attempt to ride restore lineage on the
 * pointer) is refused by S4d's `validateGenerationPointer`
 * (WORKSPACE_GENERATION_INVALID) before any I/O.
 *
 * @param {object} io S4d publisher io (readLivePointer/writeTemp/flushTemp/replace/flushParent)
 * @param {object} pointer a standard S4d generation pointer
 */
export async function publishPromotion(io, pointer) {
  return publishGeneration(io, pointer);
}

// Re-export S4d's pointer builder + step vocabulary verbatim so the promotion
// surface is self-describing; these are NOT wrapped or modified.
export { buildGenerationPointer, PUBLISH_STEPS, LINEAGE_KEYS };
