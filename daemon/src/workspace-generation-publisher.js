// Atomic workspace-generation publisher for the native workspace data plane
// (#53 Phase 2, slice S4d — highest-risk sub-slice).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations):
//   * Create/clone + refresh: publish a staged generation as the live workspace
//     "... atomic promotion ... prior generation preserved ... reversible".
//
// DESIGN: publication flips a single generation-POINTER file, never a directory
// rename. A staged generation is materialised into its own directory; the live
// workspace is defined by a small canonical pointer record naming the active
// generation and binding it to the S4a root/storage identity, the S4b git
// object-graph fingerprint, and the S4c content-manifest fingerprint. Promoting
// a new generation is a single atomic replace of that pointer file:
//
//     write temp (exclusive) -> flush file -> replace-existing-atomic -> flush dir
//
// Because the replace is atomic, a crash (SIGKILL) at any step leaves the live
// pointer as EITHER the exact prior valid pointer OR the exact new valid
// pointer — never torn, never dangling. The prior generation directory is left
// on disk (publication never deletes it), so a rollback is a subsequent publish
// that re-points at the preserved prior generation; the new pointer records the
// prior generation number and the prior pointer's fingerprint so that rollback
// is verifiable.
//
// Promotion is a compare-and-swap over the currently-live pointer: a new pointer
// may only be published as the immediate successor of the exact pointer
// currently live (matching prior generation number + prior pointer fingerprint,
// host/workspace stable, activeGeneration = prior + 1). This rejects a STALE
// successor — one that chains onto a pointer that is no longer live — and
// hash-links the generation chain so a caller cannot skip a generation or fork
// the chain undetectably.
//
// SCOPE OF THE CAS: this module reads the live pointer and then replaces it; the
// native replace_existing_atomic is unconditional (it takes no expected-identity
// precondition), so there is a time-of-check/time-of-use window between the read
// and the replace. Two publishers that both observe the same live pointer can
// both pass the CAS and both replace — this module does NOT by itself provide
// concurrent-writer exclusion. Serialising publication per workspace is the
// caller's obligation at the S4f/S4g wiring seam (a per-workspace mutex /
// acquire_native_lock, or an identity-conditioned replace in the style of the
// native publish_inventory_object_atomic). Even under such a race the on-disk
// atomicity invariant below still holds: the live pointer is always exactly one
// valid generation pointer, never torn.
//
// This module is a PURE, dependency-injected primitive. It performs NO
// filesystem I/O itself and does NOT wire into the daemon or flip the native-
// workspace-serving gate (NATIVE_WORKSPACE_SERVING_ENABLED stays false). The
// caller injects the four native atomic operations (create_exclusive_temp,
// flush_file, replace_existing_atomic, flush_directory_or_volume) plus a live-
// pointer reader; the daemon wires them with the concrete pointer path, temp
// prefix, role SIDs, and ACL profile at the S4f/S4g seam. Because the injected
// io IS the only I/O surface, crash simulation is deterministic: a test injects
// an io whose op throws at a chosen step and asserts the live-pointer slot,
// with no sleep/timing.
//
// SEAM CONTRACT (owned by the S4f/S4g wiring, not this module):
//   - The exclusive temp and the live pointer MUST share a volume, so that
//     replace_existing_atomic is a true atomic rename (a cross-volume move
//     degrades to a non-atomic copy+delete and would violate the invariant).
//   - A publication that fails at flushTemp/replace may leave the exclusive temp
//     on disk; the wiring MUST sweep leftover files under its temp prefix (they
//     never occupy the live pointer path, so they cannot masquerade as live).
//   - flushParent makes the completed rename durable across power loss; if it is
//     skipped or lost, a power-loss crash may revert the live pointer to the
//     prior valid generation — never to a torn pointer.

import {
  canonicalJsonBytes,
  canonicalJsonHash,
  isHex64,
  parseCanonicalJsonBytes,
} from "@gjc-remote/shared/strict-json";

const OPERATION = "workspace_generation_publish";
const KIND = "workspace-generation-pointer";
const VERSION = 1;

// Module-owned strict-JSON limits. The pointer record is small and bounded; a
// generous cap keeps a hostile or corrupt pointer from exhausting the parser
// while still being far larger than any legitimate pointer.
const MAX_PATH_BYTES = 4096;
const GENERATION_POINTER_LIMITS = Object.freeze({
  maxBytes: 64 * 1024,
  maxDepth: 8,
  maxNodes: 256,
});

// Windows reserved device names (rejected as a whole path segment, optionally
// with an extension), matched case-insensitively. Same rule as the S4c manifest
// path guard — each slice owns its guard rather than importing a sibling that
// lives on a separate unmerged branch.
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

// Same platform vocabulary as shared/workspace-binding.js and the S4c manifest.
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);

const POINTER_KEYS = [
  "version",
  "kind",
  "hostId",
  "workspaceId",
  "sourcePlatform",
  "activeGeneration",
  "generationPath",
  "rootIdentityFingerprint",
  "storageIdentityFingerprint",
  "gitGenerationFingerprint",
  "manifestFingerprint",
  "priorGeneration",
  "priorPointerFingerprint",
  "pointerFingerprint",
];

// The ordered atomic publication protocol. Each step is the crash-sim boundary
// the injected io throws at; "replace" is the single linearisation point.
const PUBLISH_STEPS = Object.freeze(["writeTemp", "flushTemp", "replace", "flushParent"]);

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
const isNullableGeneration = (value) => value === null || isGeneration(value);
const isNullableHex = (value) => value === null || isHex64(value);

// A generationPath is a workspace-RELATIVE POSIX path naming the active
// generation directory: '/' separators, no leading separator, no drive/UNC
// prefix, no '.'/'..' segment, no NUL, no backslash, non-empty, no control
// chars / unpaired surrogates, and no windows path aliases (':' NTFS ADS,
// reserved device names, trailing dot/space) that could resolve to an
// unexpected object on a windows-drive host.
function assertGenerationPath(path) {
  if (typeof path !== "string" || path.length === 0) {
    refuse("WORKSPACE_GENERATION_PATH_REJECTED", "generationPath must be a non-empty string");
  }
  if (path.includes("\0")) {
    refuse("WORKSPACE_GENERATION_PATH_REJECTED", "generationPath contains a NUL byte");
  }
  if (Buffer.byteLength(path, "utf8") > MAX_PATH_BYTES) {
    refuse("WORKSPACE_GENERATION_PATH_REJECTED", "generationPath exceeds its byte limit");
  }
  for (let index = 0; index < path.length; index += 1) {
    const code = path.charCodeAt(index);
    if ((code >= 0 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) {
      refuse("WORKSPACE_GENERATION_PATH_REJECTED", "generationPath contains a forbidden control character");
    }
    if (code >= 0xd800 && code <= 0xdfff) {
      const next = path.charCodeAt(index + 1);
      if (code <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) index += 1;
      else refuse("WORKSPACE_GENERATION_PATH_REJECTED", "generationPath contains an unpaired surrogate");
    }
  }
  if (path.includes("\\")) {
    refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath must use '/' separators: ${path}`);
  }
  if (path.startsWith("/")) {
    refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath must be relative: ${path}`);
  }
  if (/^[A-Za-z]:/.test(path)) {
    refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath must not carry a drive prefix: ${path}`);
  }
  for (const segment of path.split("/")) {
    if (segment.length === 0) refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath has an empty segment: ${path}`);
    if (segment === "." || segment === "..") refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath has a dot segment: ${path}`);
    if (segment.includes(":")) refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath segment contains ':' (NTFS ADS alias): ${path}`);
    if (/[ .]$/.test(segment)) refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath segment has a trailing dot or space: ${path}`);
    if (WINDOWS_RESERVED.test(segment)) refuse("WORKSPACE_GENERATION_PATH_REJECTED", `generationPath segment is a Windows reserved name: ${path}`);
  }
}

function pointerFingerprintOf(record) {
  const body = {};
  for (const key of POINTER_KEYS) {
    if (key !== "pointerFingerprint") body[key] = record[key];
  }
  try {
    return canonicalJsonHash(body, GENERATION_POINTER_LIMITS);
  } catch (error) {
    refuse("WORKSPACE_GENERATION_INVALID", `pointer body is not canonicalizable: ${error?.message ?? "invalid"}`);
  }
}

/**
 * Validate an exact generation-pointer record, recompute and check its
 * self-fingerprint, and enforce the prior-generation invariants (a first
 * publication has null prior generation AND null prior pointer fingerprint;
 * every later publication has both, with activeGeneration >= 2). Returns the
 * same object on success; throws a structured WORKSPACE_GENERATION_INVALID
 * refusal otherwise.
 */
export function validateGenerationPointer(pointer) {
  if (!hasExactKeys(pointer, POINTER_KEYS)) {
    refuse("WORKSPACE_GENERATION_INVALID", "pointer must have the exact pointer key set");
  }
  if (pointer.version !== VERSION) refuse("WORKSPACE_GENERATION_INVALID", "unsupported pointer version");
  if (pointer.kind !== KIND) refuse("WORKSPACE_GENERATION_INVALID", "unexpected pointer kind");
  if (!isId(pointer.hostId)) refuse("WORKSPACE_GENERATION_INVALID", "hostId must be a 1..256 char string");
  if (!isId(pointer.workspaceId)) refuse("WORKSPACE_GENERATION_INVALID", "workspaceId must be a 1..256 char string");
  if (!SOURCE_PLATFORMS.has(pointer.sourcePlatform)) refuse("WORKSPACE_GENERATION_INVALID", `unknown sourcePlatform: ${pointer.sourcePlatform}`);
  if (!isGeneration(pointer.activeGeneration)) refuse("WORKSPACE_GENERATION_INVALID", "activeGeneration must be a safe integer >= 1");
  assertGenerationPath(pointer.generationPath);
  if (!isHex64(pointer.rootIdentityFingerprint)) refuse("WORKSPACE_GENERATION_INVALID", "rootIdentityFingerprint must be hex64");
  if (!isHex64(pointer.storageIdentityFingerprint)) refuse("WORKSPACE_GENERATION_INVALID", "storageIdentityFingerprint must be hex64");
  if (!isHex64(pointer.gitGenerationFingerprint)) refuse("WORKSPACE_GENERATION_INVALID", "gitGenerationFingerprint must be hex64");
  if (!isHex64(pointer.manifestFingerprint)) refuse("WORKSPACE_GENERATION_INVALID", "manifestFingerprint must be hex64");
  if (!isNullableGeneration(pointer.priorGeneration)) refuse("WORKSPACE_GENERATION_INVALID", "priorGeneration must be null or a safe integer >= 1");
  if (!isNullableHex(pointer.priorPointerFingerprint)) refuse("WORKSPACE_GENERATION_INVALID", "priorPointerFingerprint must be null or hex64");

  const firstPublication = pointer.priorGeneration === null;
  if (firstPublication) {
    if (pointer.priorPointerFingerprint !== null) {
      refuse("WORKSPACE_GENERATION_INVALID", "first publication must have a null priorPointerFingerprint");
    }
    if (pointer.activeGeneration !== 1) {
      refuse("WORKSPACE_GENERATION_INVALID", "first publication must have activeGeneration === 1");
    }
  } else {
    if (pointer.priorPointerFingerprint === null) {
      refuse("WORKSPACE_GENERATION_INVALID", "a successor publication must carry a priorPointerFingerprint");
    }
    if (pointer.activeGeneration !== pointer.priorGeneration + 1) {
      refuse("WORKSPACE_GENERATION_INVALID", "activeGeneration must be priorGeneration + 1");
    }
  }

  if (!isHex64(pointer.pointerFingerprint)) refuse("WORKSPACE_GENERATION_INVALID", "pointerFingerprint must be hex64");
  if (pointerFingerprintOf(pointer) !== pointer.pointerFingerprint) {
    refuse("WORKSPACE_GENERATION_INVALID", "pointerFingerprint does not match the pointer body");
  }
  return pointer;
}

/**
 * Build and validate a generation-pointer record. The self-fingerprint is
 * computed last. Returns a frozen pointer.
 */
export function buildGenerationPointer(input) {
  if (!isPlainObject(input)) refuse("WORKSPACE_GENERATION_INVALID", "pointer input must be an object");
  // Guard the path before fingerprinting: a control char / unpaired surrogate
  // would otherwise surface as a canonicalization error rather than the precise
  // WORKSPACE_GENERATION_PATH_REJECTED refusal.
  assertGenerationPath(input.generationPath);
  const priorGeneration = input.priorGeneration ?? null;
  const record = {
    version: VERSION,
    kind: KIND,
    hostId: input.hostId,
    workspaceId: input.workspaceId,
    sourcePlatform: input.sourcePlatform,
    activeGeneration: input.activeGeneration,
    generationPath: input.generationPath,
    rootIdentityFingerprint: input.rootIdentityFingerprint,
    storageIdentityFingerprint: input.storageIdentityFingerprint,
    gitGenerationFingerprint: input.gitGenerationFingerprint,
    manifestFingerprint: input.manifestFingerprint,
    priorGeneration,
    priorPointerFingerprint: input.priorPointerFingerprint ?? null,
    pointerFingerprint: null,
  };
  record.pointerFingerprint = pointerFingerprintOf(record);
  validateGenerationPointer(record);
  return Object.freeze(record);
}

/** Canonical bytes of a validated pointer (validates first). */
export function generationPointerBytes(pointer) {
  validateGenerationPointer(pointer);
  try {
    return canonicalJsonBytes(pointer, GENERATION_POINTER_LIMITS);
  } catch (error) {
    refuse("WORKSPACE_GENERATION_INVALID", `pointer is not serializable: ${error?.message ?? "invalid"}`);
  }
}

/** Parse canonical pointer bytes and validate the result. */
export function parseGenerationPointer(bytes) {
  let value;
  try {
    value = parseCanonicalJsonBytes(bytes, GENERATION_POINTER_LIMITS);
  } catch (error) {
    refuse("WORKSPACE_GENERATION_INVALID", `pointer bytes are not canonical JSON: ${error?.message ?? "parse error"}`);
  }
  return validateGenerationPointer(value);
}

/**
 * Read and validate the currently-live pointer through the injected reader.
 * Returns the frozen validated pointer, or null when no pointer is live yet
 * (io.readLivePointer resolves to null/undefined).
 *
 * @param {{ readLivePointer:()=>Promise<Uint8Array|null> }} io
 */
export async function readLiveGeneration(io) {
  if (!io || typeof io.readLivePointer !== "function") {
    refuse("WORKSPACE_GENERATION_INVALID", "io.readLivePointer must be a function");
  }
  let bytes;
  try {
    bytes = await io.readLivePointer();
  } catch (error) {
    if (error?.operation === OPERATION) throw error;
    refuse("WORKSPACE_GENERATION_IO_FAILED", "unable to read the live pointer", { step: "readLivePointer", cause: String(error?.code ?? "unknown") });
  }
  if (bytes === null || bytes === undefined) return null;
  if (!(bytes instanceof Uint8Array)) {
    refuse("WORKSPACE_GENERATION_IO_FAILED", "live pointer reader did not return bytes", { step: "readLivePointer" });
  }
  return parseGenerationPointer(bytes);
}

function assertSuccession(next, current) {
  // A successor publication must chain onto the exact live pointer: same host
  // and workspace, prior generation == current active generation, prior pointer
  // fingerprint == current pointer fingerprint, and next active == current + 1.
  // This rejects a STALE successor (one chaining onto a no-longer-live pointer);
  // it is not a concurrent-writer lock -- see the module header on the TOCTOU
  // window closed by the S4f wiring seam.
  if (next.hostId !== current.hostId || next.workspaceId !== current.workspaceId) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "pointer host/workspace does not match the live pointer", {
      step: "cas",
    });
  }
  if (next.priorGeneration !== current.activeGeneration) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "priorGeneration does not match the live activeGeneration", {
      step: "cas",
      expectedPriorGeneration: current.activeGeneration,
      actualPriorGeneration: next.priorGeneration,
    });
  }
  if (next.priorPointerFingerprint !== current.pointerFingerprint) {
    refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "priorPointerFingerprint does not match the live pointer fingerprint", {
      step: "cas",
    });
  }
  // activeGeneration === priorGeneration + 1 is already enforced by validation.
}

/**
 * Atomically publish `newPointer` as the live generation via the ordered
 * protocol: write an exclusive temp of the canonical pointer bytes, flush it,
 * atomically replace the live pointer, then flush the parent directory. The
 * publication is a compare-and-swap over the currently-live pointer:
 *   - first publication (newPointer.priorGeneration === null): requires that no
 *     pointer is live yet;
 *   - successor publication: requires that the live pointer is exactly the one
 *     newPointer chains onto (see assertSuccession).
 * The CAS rejects a stale successor but is not a concurrent-writer lock (the
 * live-pointer read and the replace are not one atomic step); per-workspace
 * publication serialization is the S4f/S4g wiring's obligation. The prior
 * generation directory is NOT touched, so promotion is reversible by a later
 * publish that re-points at it.
 *
 * Injected io (all async):
 *   - readLivePointer(): Promise<Uint8Array|null> — current live pointer bytes
 *   - writeTemp(bytes): Promise<tempRef> — create an exclusive temp file
 *   - flushTemp(tempRef): Promise<void> — fsync the temp file
 *   - replace(tempRef): Promise<void> — atomically replace the live pointer
 *   - flushParent(): Promise<void> — fsync the pointer's parent directory
 *
 * Crash safety: because `replace` is the single atomic linearisation point, a
 * throw (simulated SIGKILL) at or before `replace` leaves the prior live
 * pointer intact, and a throw after `replace` leaves the new pointer live —
 * never a torn or dangling pointer. Returns
 * { published:true, activeGeneration, priorGeneration, pointerFingerprint,
 *   priorPointerFingerprint }.
 *
 * @param {object} io
 * @param {object} newPointer
 */
export async function publishGeneration(io, newPointer) {
  if (!io) refuse("WORKSPACE_GENERATION_INVALID", "io is required");
  for (const method of ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"]) {
    if (typeof io[method] !== "function") refuse("WORKSPACE_GENERATION_INVALID", `io.${method} must be a function`);
  }
  validateGenerationPointer(newPointer);

  const current = await readLiveGeneration(io);
  if (newPointer.priorGeneration === null) {
    if (current !== null) {
      refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "first publication attempted but a pointer is already live", { step: "cas" });
    }
  } else {
    if (current === null) {
      refuse("WORKSPACE_GENERATION_CAS_CONFLICT", "successor publication attempted but no pointer is live", { step: "cas" });
    }
    assertSuccession(newPointer, current);
  }

  const bytes = generationPointerBytes(newPointer);

  const runStep = async (step, fn) => {
    try {
      return await fn();
    } catch (error) {
      if (error?.operation === OPERATION) throw error;
      refuse("WORKSPACE_GENERATION_IO_FAILED", `native publication step '${step}' failed`, {
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
    activeGeneration: newPointer.activeGeneration,
    priorGeneration: newPointer.priorGeneration,
    pointerFingerprint: newPointer.pointerFingerprint,
    priorPointerFingerprint: newPointer.priorPointerFingerprint,
  };
}

export { PUBLISH_STEPS };
