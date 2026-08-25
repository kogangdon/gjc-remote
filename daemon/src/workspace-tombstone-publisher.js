// S5d -- atomic workspace-tombstone publisher (#53 Phase 2, reset/delete
// lifecycle). Composes S4d's atomic-publish discipline with a NEW record shape.
//
// When a workspace generation is reset or deleted, the live slot is not left
// dangling: it is flipped to a canonical TOMBSTONE record that records the
// disposition (reset/delete), the generation that was disposed, and the dirty
// backup (S5a) captured before destruction. The tombstone occupies the SAME
// single live slot as the generation pointer (S4d), preserving one linearization
// point, so the slot always holds EXACTLY ONE valid record -- a generation
// pointer OR a tombstone -- never both and never torn.
//
// Publication reuses S4d's ordered protocol and its single atomic replace:
//
//     write temp (exclusive) -> flush file -> replace-existing-atomic -> flush dir
//
// Because `replace` is the single linearization point, a crash (SIGKILL) at or
// before it leaves the PRIOR live record (pointer or tombstone) intact, and a
// crash after it leaves the new tombstone live -- never a torn record.
//
// Tombstone publication is a compare-and-swap over the currently-live record:
// the new tombstone chains onto the EXACT record currently live (matching its
// kind and self-fingerprint), rejecting a stale base with the reused
// WORKSPACE_GENERATION_CAS_CONFLICT. Unlike a first generation publication, a
// tombstone can NEVER publish onto an empty slot: you cannot tombstone what is
// not there.
//
// Dual-kind live read: because the slot now holds two possible record kinds,
// this module exports `readLiveDisposition(io)`, which reads the slot bytes ONCE
// and dispatches on `kind` -- delegating a generation pointer to S4d's
// `parseGenerationPointer` and validating a tombstone here. `readLiveGeneration`
// (S4d) is unchanged; the dual-kind read is a NEW function so a tombstone can be
// read back without loosening the pointer reader's kind guard.
//
// This is a PURE, dependency-injected primitive. It performs NO filesystem I/O
// and does NOT wire into the daemon or flip the native-workspace-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false). The caller injects the same
// four native atomic operations plus the live-slot reader used by S4d; the
// injected io IS the only I/O surface, so crash simulation is deterministic (an
// io whose op throws at a chosen step), with no sleep/timing.

import {
  canonicalJsonBytes,
  canonicalJsonHash,
  isHex64,
  parseCanonicalJsonBytes,
} from "@gjc-remote/shared/strict-json";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { parseGenerationPointer } from "./workspace-generation-publisher.js";

const OPERATION = "workspace_tombstone_publish";
const KIND = "workspace-tombstone";
const POINTER_KIND = "workspace-generation-pointer";
const VERSION = 1;
const { CONFIG_INVALID } = PROTOCOL_ERROR_CODES;

// Module-owned strict-JSON limits, identical bounds to the S4d pointer: the
// record is small and bounded; a generous cap stops a hostile/corrupt record
// from exhausting the parser while far exceeding any legitimate tombstone.
const TOMBSTONE_LIMITS = Object.freeze({
  maxBytes: 64 * 1024,
  maxDepth: 8,
  maxNodes: 256,
});

// Same platform vocabulary as shared/workspace-binding.js, the S4c manifest, and
// the S4d pointer.
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);

// The reset/delete lifecycle operations that produce a tombstone. A subset of
// the shared lifecycle operation vocabulary (create/clone/refresh never
// tombstone; restore/migration republish a pointer, not a tombstone).
//
// NOTE (S5e obligation): this primitive treats reset and delete symmetrically
// and does NOT enforce delete-terminality -- a tombstone may chain onto a prior
// tombstone regardless of its operation (reset->delete, delete->reset,
// delete->delete are all representable here). Whether a delete is terminal (no
// further disposal permitted) is a lifecycle POLICY decision owned by the S5e
// runResetDelete orchestrator, which holds the exclusive fence and the lifecycle
// authority; this slice deliberately provides the mechanism, not the policy.
const TOMBSTONE_OPERATIONS = new Set(["reset", "delete"]);

// The kind of the live record a tombstone may chain onto: a generation pointer
// (first disposal of a live generation) or a prior tombstone (a later disposal
// of the same already-tombstoned generation, e.g. reset then delete).
const PRIOR_KINDS = new Set([POINTER_KIND, KIND]);

const TOMBSTONE_KEYS = [
  "version",
  "kind",
  "hostId",
  "workspaceId",
  "sourcePlatform",
  "operation",
  "tombstonedGeneration",
  "priorKind",
  "priorPointerFingerprint",
  "dirtyBackupFingerprint",
  "tombstoneFingerprint",
];

// The ordered atomic publication protocol -- identical to S4d's PUBLISH_STEPS.
// Each step is the crash-sim boundary the injected io throws at; "replace" is
// the single linearization point.
const TOMBSTONE_STEPS = Object.freeze(["writeTemp", "flushTemp", "replace", "flushParent"]);

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
const isNullableHex = (value) => value === null || isHex64(value);

function tombstoneFingerprintOf(record) {
  const body = {};
  for (const key of TOMBSTONE_KEYS) {
    if (key !== "tombstoneFingerprint") body[key] = record[key];
  }
  try {
    return canonicalJsonHash(body, TOMBSTONE_LIMITS);
  } catch (error) {
    refuse("WORKSPACE_TOMBSTONE_INVALID", `tombstone body is not canonicalizable: ${error?.message ?? "invalid"}`);
  }
}

/**
 * Validate an exact tombstone record, recompute and check its self-fingerprint.
 * A tombstone ALWAYS chains onto a live record, so priorKind and
 * priorPointerFingerprint are required (never null). Returns the same object on
 * success; throws a structured WORKSPACE_TOMBSTONE_INVALID refusal otherwise.
 */
export function validateTombstone(tombstone) {
  if (!hasExactKeys(tombstone, TOMBSTONE_KEYS)) {
    refuse("WORKSPACE_TOMBSTONE_INVALID", "tombstone must have the exact tombstone key set");
  }
  if (tombstone.version !== VERSION) refuse("WORKSPACE_TOMBSTONE_INVALID", "unsupported tombstone version");
  if (tombstone.kind !== KIND) refuse("WORKSPACE_TOMBSTONE_INVALID", "unexpected tombstone kind");
  if (!isId(tombstone.hostId)) refuse("WORKSPACE_TOMBSTONE_INVALID", "hostId must be a 1..256 char string");
  if (!isId(tombstone.workspaceId)) refuse("WORKSPACE_TOMBSTONE_INVALID", "workspaceId must be a 1..256 char string");
  if (!SOURCE_PLATFORMS.has(tombstone.sourcePlatform)) refuse("WORKSPACE_TOMBSTONE_INVALID", `unknown sourcePlatform: ${tombstone.sourcePlatform}`);
  if (!TOMBSTONE_OPERATIONS.has(tombstone.operation)) refuse("WORKSPACE_TOMBSTONE_INVALID", `operation must be reset or delete: ${tombstone.operation}`);
  if (!isGeneration(tombstone.tombstonedGeneration)) refuse("WORKSPACE_TOMBSTONE_INVALID", "tombstonedGeneration must be a safe integer >= 1");
  if (!PRIOR_KINDS.has(tombstone.priorKind)) refuse("WORKSPACE_TOMBSTONE_INVALID", `priorKind must name a live-slot record kind: ${tombstone.priorKind}`);
  if (!isHex64(tombstone.priorPointerFingerprint)) refuse("WORKSPACE_TOMBSTONE_INVALID", "priorPointerFingerprint must be hex64 (a tombstone always chains onto a live record)");
  if (!isNullableHex(tombstone.dirtyBackupFingerprint)) refuse("WORKSPACE_TOMBSTONE_INVALID", "dirtyBackupFingerprint must be null or hex64");
  if (!isHex64(tombstone.tombstoneFingerprint)) refuse("WORKSPACE_TOMBSTONE_INVALID", "tombstoneFingerprint must be hex64");
  if (tombstoneFingerprintOf(tombstone) !== tombstone.tombstoneFingerprint) {
    refuse("WORKSPACE_TOMBSTONE_INVALID", "tombstoneFingerprint does not match the tombstone body");
  }
  return tombstone;
}

/**
 * Build and validate a tombstone record. The self-fingerprint is computed last.
 * `dirtyBackupFingerprint` defaults to null (a clean delete with no dirty state
 * captured). Returns a frozen tombstone.
 */
export function buildTombstone(input) {
  if (!isPlainObject(input)) refuse("WORKSPACE_TOMBSTONE_INVALID", "tombstone input must be an object");
  const record = {
    version: VERSION,
    kind: KIND,
    hostId: input.hostId,
    workspaceId: input.workspaceId,
    sourcePlatform: input.sourcePlatform,
    operation: input.operation,
    tombstonedGeneration: input.tombstonedGeneration,
    priorKind: input.priorKind,
    priorPointerFingerprint: input.priorPointerFingerprint,
    dirtyBackupFingerprint: input.dirtyBackupFingerprint ?? null,
    tombstoneFingerprint: null,
  };
  record.tombstoneFingerprint = tombstoneFingerprintOf(record);
  validateTombstone(record);
  return Object.freeze(record);
}

/** Canonical bytes of a validated tombstone (validates first). */
export function tombstoneBytes(tombstone) {
  validateTombstone(tombstone);
  try {
    return canonicalJsonBytes(tombstone, TOMBSTONE_LIMITS);
  } catch (error) {
    refuse("WORKSPACE_TOMBSTONE_INVALID", `tombstone is not serializable: ${error?.message ?? "invalid"}`);
  }
}

/** Parse canonical tombstone bytes and validate the result. */
export function parseTombstone(bytes) {
  let value;
  try {
    value = parseCanonicalJsonBytes(bytes, TOMBSTONE_LIMITS);
  } catch (error) {
    refuse("WORKSPACE_TOMBSTONE_INVALID", `tombstone bytes are not canonical JSON: ${error?.message ?? "parse error"}`);
  }
  return validateTombstone(value);
}

/**
 * Read the currently-live slot record ONCE and dispatch on its kind. The slot
 * may hold a generation pointer (delegated to S4d's parseGenerationPointer) or a
 * tombstone (validated here). Returns a frozen
 *   { kind, fingerprint, record }
 * where `fingerprint` is the record's self-fingerprint (the CAS base for the
 * next publication), or null when the slot is empty. An unknown record kind is
 * refused CONFIG_INVALID -- the slot is corrupt and cannot be interpreted.
 *
 * @param {{ readLivePointer:()=>Promise<Uint8Array|null> }} io
 */
export async function readLiveDisposition(io) {
  if (!io || typeof io.readLivePointer !== "function") {
    refuse("WORKSPACE_TOMBSTONE_INVALID", "io.readLivePointer must be a function");
  }
  let bytes;
  try {
    bytes = await io.readLivePointer();
  } catch (error) {
    if (error?.operation === OPERATION) throw error;
    refuse("WORKSPACE_TOMBSTONE_IO_FAILED", "unable to read the live slot", { step: "readLivePointer", cause: String(error?.code ?? "unknown") });
  }
  if (bytes === null || bytes === undefined) return null;
  if (!(bytes instanceof Uint8Array)) {
    refuse("WORKSPACE_TOMBSTONE_IO_FAILED", "live slot reader did not return bytes", { step: "readLivePointer" });
  }

  // Peek the kind from a single generic parse, then route to the authoritative
  // kind-specific validator (which re-parses the same bytes). A record that is
  // not a canonical JSON object, or carries no string kind, or an unrecognised
  // kind, is a corrupt slot refused CONFIG_INVALID.
  let peek;
  try {
    peek = parseCanonicalJsonBytes(bytes, TOMBSTONE_LIMITS);
  } catch (error) {
    refuse(CONFIG_INVALID, `live slot bytes are not canonical JSON: ${error?.message ?? "parse error"}`);
  }
  if (!isPlainObject(peek) || typeof peek.kind !== "string") {
    refuse(CONFIG_INVALID, "live slot record has no string kind");
  }
  if (peek.kind === POINTER_KIND) {
    const pointer = parseGenerationPointer(bytes);
    return Object.freeze({ kind: POINTER_KIND, fingerprint: pointer.pointerFingerprint, record: Object.freeze(pointer) });
  }
  if (peek.kind === KIND) {
    const tombstone = validateTombstone(peek);
    return Object.freeze({ kind: KIND, fingerprint: tombstone.tombstoneFingerprint, record: Object.freeze(tombstone) });
  }
  refuse(CONFIG_INVALID, `unknown live-slot record kind: ${peek.kind}`);
}

/**
 * Read the currently-live tombstone through the dual-kind reader. Returns the
 * frozen validated tombstone when the live record IS a tombstone, or null when
 * the slot is empty or still holds a generation pointer (not yet tombstoned).
 *
 * @param {{ readLivePointer:()=>Promise<Uint8Array|null> }} io
 */
export async function readLiveTombstone(io) {
  const live = await readLiveDisposition(io);
  if (live === null || live.kind !== KIND) return null;
  return live.record;
}

function assertTombstoneSuccession(next, live) {
  // A tombstone must chain onto the EXACT currently-live record: same host and
  // workspace, priorKind == the live record's kind, priorPointerFingerprint ==
  // the live record's self-fingerprint, and the disposed generation matches the
  // generation the live record represents. This rejects a STALE base (one
  // chaining onto a no-longer-live record); it is not a concurrent-writer lock
  // (same TOCTOU window as S4d, closed by the S5e wiring seam).
  const liveHostId = live.record.hostId;
  const liveWorkspaceId = live.record.workspaceId;
  if (next.hostId !== liveHostId || next.workspaceId !== liveWorkspaceId) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "tombstone host/workspace does not match the live record", { step: "cas" });
  }
  if (next.priorKind !== live.kind) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "priorKind does not match the live record kind", {
      step: "cas",
      expectedPriorKind: live.kind,
      actualPriorKind: next.priorKind,
    });
  }
  if (next.priorPointerFingerprint !== live.fingerprint) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "priorPointerFingerprint does not match the live record fingerprint", { step: "cas" });
  }
  const liveGeneration = live.kind === POINTER_KIND
    ? live.record.activeGeneration
    : live.record.tombstonedGeneration;
  if (next.tombstonedGeneration !== liveGeneration) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "tombstonedGeneration does not match the live generation", {
      step: "cas",
      expectedTombstonedGeneration: liveGeneration,
      actualTombstonedGeneration: next.tombstonedGeneration,
    });
  }
}

/**
 * Atomically publish `tombstone` as the live record via the ordered protocol
 * (write exclusive temp -> flush temp -> atomic replace -> flush parent). The
 * publication is a compare-and-swap over the currently-live record: the slot
 * MUST be non-empty and the tombstone MUST chain onto the exact live record
 * (see assertTombstoneSuccession). The CAS rejects a stale base but is not a
 * concurrent-writer lock; per-workspace serialization is the S5e wiring's
 * obligation.
 *
 * Injected io (all async) -- identical shape to S4d publishGeneration:
 *   - readLivePointer(): Promise<Uint8Array|null> -- current live slot bytes
 *   - writeTemp(bytes): Promise<tempRef> -- create an exclusive temp file
 *   - flushTemp(tempRef): Promise<void> -- fsync the temp file
 *   - replace(tempRef): Promise<void> -- atomically replace the live slot
 *   - flushParent(): Promise<void> -- fsync the slot's parent directory
 *
 * Crash safety: `replace` is the single atomic linearization point, so a throw
 * at or before it leaves the prior live record intact and a throw after it
 * leaves the new tombstone live -- never torn. Returns
 * { published:true, operation, tombstonedGeneration, tombstoneFingerprint,
 *   priorPointerFingerprint, priorKind }.
 *
 * @param {object} io
 * @param {object} tombstone
 */
export async function publishTombstone(io, tombstone) {
  if (!io) refuse("WORKSPACE_TOMBSTONE_INVALID", "io is required");
  for (const method of ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"]) {
    if (typeof io[method] !== "function") refuse("WORKSPACE_TOMBSTONE_INVALID", `io.${method} must be a function`);
  }
  validateTombstone(tombstone);

  const live = await readLiveDisposition(io);
  if (live === null) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "cannot tombstone an empty live slot", { step: "cas" });
  }
  assertTombstoneSuccession(tombstone, live);

  const bytes = tombstoneBytes(tombstone);

  const runStep = async (step, fn) => {
    try {
      return await fn();
    } catch (error) {
      if (error?.operation === OPERATION) throw error;
      refuse("WORKSPACE_TOMBSTONE_IO_FAILED", `native tombstone step '${step}' failed`, {
        step,
        cause: String(error?.code ?? "unknown"),
      });
    }
  };

  const tempRef = await runStep("writeTemp", () => io.writeTemp(bytes));
  await runStep("flushTemp", () => io.flushTemp(tempRef));
  await runStep("replace", () => io.replace(tempRef));
  await runStep("flushParent", () => io.flushParent());

  return {
    published: true,
    operation: tombstone.operation,
    tombstonedGeneration: tombstone.tombstonedGeneration,
    tombstoneFingerprint: tombstone.tombstoneFingerprint,
    priorPointerFingerprint: tombstone.priorPointerFingerprint,
    priorKind: tombstone.priorKind,
  };
}

export { TOMBSTONE_STEPS };
