// Quarantined-staging lexical guard + descriptor primitive (slice S5f).
//
// Pure, dependency-free module supporting the restore/migration data plane
// (#53 Phase 2). Two exports:
//
//   1. buildQuarantineStagingDescriptor(input) - a frozen, self-fingerprinted
//      record naming a quarantined staging area for a restore/migration source.
//      The descriptor is an identity tuple only; it carries no filesystem
//      handles and performs no io.
//   2. assertQuarantined({ stagingPath, candidatePath, workDir, sourcePlatform })
//      - a PURE LEXICAL guard that refuses WORKSPACE_STAGING_NOT_QUARANTINED
//      when the staging path equals, or nests under, the live workspace
//      candidate/generation path. A genuine sibling (outside the live tree) is
//      admitted. This is the structural invariant that keeps a reversible
//      promotion's staged content from living inside the very tree a
//      reset/delete/migration may destroy.
//
// The guard is deliberately lexical only: it never touches the filesystem and
// never follows a reparse point (that reparse-free proof is S4a's job, reused
// at the S5i composition layer). Concrete staging directory layout and cleanup
// policy are deferred to the S7 wiring seam, exactly as S4f/S4g deferred
// concrete pointer/temp paths; this module only enforces the not-equal /
// not-nested-under-live invariant that S5's pure-primitive correctness needs.
//
// Path comparison folds case on Windows (windows-drive / windows-unc) and is
// case-sensitive on posix. The fold direction is fail-closed: an approximate
// NTFS $UpCase fold can only ever OVER-refuse a borderline case-variant, never
// admit a staging path that actually nests under the live tree.

import { canonicalJsonHash, isHex64 } from "@gjc-remote/shared/strict-json";

const OPERATION = "workspace_quarantine_staging";
const KIND = "workspace-quarantine-staging";
const VERSION = 1;

// Same source-platform vocabulary as shared/workspace-binding.js and the S4
// primitives.
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);

// A restore/migration staging area is populated from exactly one kind of
// source. The set is frozen so a descriptor cannot name an unknown provenance;
// wiring that needs a new kind extends this deliberately, not implicitly.
const SOURCE_KINDS = new Set(["dirty-backup", "restore-archive", "migration-export"]);

const MAX_PATH_BYTES = 4096;

// Windows reserved device names (rejected as a whole path segment, optionally
// with an extension), matched case-insensitively. Same rule as the S4c manifest
// / S4d pointer path guards - each slice owns its guard rather than importing a
// sibling that lives on a separate unmerged branch.
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

const DESCRIPTOR_KEYS = [
  "version",
  "kind",
  "hostId",
  "workspaceId",
  "sourcePlatform",
  "stagingPath",
  "sourceKind",
  "descriptorFingerprint",
];

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

const separatorFor = (sourcePlatform) => (sourcePlatform === "posix" ? "/" : "\\");

// Reject control characters, unpaired surrogates, and line separators that
// could smuggle a second logical path segment past the split.
function assertNoForbiddenChars(label, value) {
  if (value.includes("\0")) refuse("CONFIG_INVALID", `${label} contains a NUL byte`);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code >= 0 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) {
      refuse("CONFIG_INVALID", `${label} contains a forbidden control character`);
    }
    if (code >= 0xd800 && code <= 0xdfff) {
      const next = value.charCodeAt(index + 1);
      if (code <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) index += 1;
      else refuse("CONFIG_INVALID", `${label} contains an unpaired surrogate`);
    }
  }
}

// Validate the tail (everything after a windows-drive `C:\` prefix or a
// `\\server\share` UNC prefix) segment by segment with the same aliasing guards
// the S4d pointer path uses.
function assertWindowsTail(label, tail) {
  if (tail === "") return;
  for (const segment of tail.split("\\")) {
    if (segment.length === 0) refuse("CONFIG_INVALID", `${label} has an empty path segment`);
    if (segment === "." || segment === "..") refuse("CONFIG_INVALID", `${label} has a '.'/'..' path segment`);
    if (segment.includes(":")) refuse("CONFIG_INVALID", `${label} segment contains ':' (NTFS ADS alias)`);
    if (/[ .]$/.test(segment)) refuse("CONFIG_INVALID", `${label} segment has a trailing dot or space`);
    if (WINDOWS_RESERVED.test(segment)) refuse("CONFIG_INVALID", `${label} segment is a Windows reserved name`);
  }
}

// Canonicalize + validate a fully-qualified absolute path for its platform.
// Returns the native-separator normalized form. On windows an incoming forward
// slash is tolerated and normalized before validation so the comparison is
// always over a single canonical separator.
function assertAbsolutePath(label, value, sourcePlatform) {
  if (typeof value !== "string" || value.length === 0) {
    refuse("CONFIG_INVALID", `${label} must be a non-empty string`);
  }
  if (Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES) {
    refuse("CONFIG_INVALID", `${label} exceeds its byte limit`);
  }
  assertNoForbiddenChars(label, value);

  if (sourcePlatform === "posix") {
    if (value.includes("\\")) refuse("CONFIG_INVALID", `${label} must use '/' separators`);
    if (!value.startsWith("/")) refuse("CONFIG_INVALID", `${label} must be an absolute posix path`);
    for (const segment of value.split("/").slice(1)) {
      if (segment.length === 0) refuse("CONFIG_INVALID", `${label} has an empty path segment`);
      if (segment === "." || segment === "..") refuse("CONFIG_INVALID", `${label} has a '.'/'..' path segment`);
    }
    return value;
  }

  const normalized = value.replace(/\//g, "\\");
  if (sourcePlatform === "windows-drive") {
    if (!/^[A-Za-z]:\\/.test(normalized)) {
      refuse("CONFIG_INVALID", `${label} must be an absolute windows-drive path (e.g. C:\\...)`);
    }
    assertWindowsTail(label, normalized.slice(3));
    return normalized;
  }

  // windows-unc: \\server\share\...
  if (!/^\\\\[^\\]+\\[^\\]+/.test(normalized)) {
    refuse("CONFIG_INVALID", `${label} must be an absolute windows-unc path (e.g. \\\\server\\share\\...)`);
  }
  // Validate the server and share components with the same aliasing guards as
  // the tail (a trailing dot/space or ':' in a share name is a windows alias).
  const uncPrefixMatch = /^\\\\([^\\]+)\\([^\\]+)/.exec(normalized);
  for (const component of [uncPrefixMatch[1], uncPrefixMatch[2]]) {
    if (component === "." || component === "..") refuse("CONFIG_INVALID", `${label} has a '.'/'..' server/share component`);
    if (component.includes(":")) refuse("CONFIG_INVALID", `${label} server/share component contains ':'`);
    if (/[ .]$/.test(component)) refuse("CONFIG_INVALID", `${label} server/share component has a trailing dot or space`);
  }
  const afterShare = normalized.replace(/^\\\\[^\\]+\\[^\\]+/, "");
  assertWindowsTail(label, afterShare.startsWith("\\") ? afterShare.slice(1) : afterShare);
  return normalized;
}

// Fail-closed lexical "inner is outer, or inner is strictly under outer".
function nestsUnderOrEquals(inner, outer, sourcePlatform) {
  const insensitive = sourcePlatform !== "posix";
  const foldedInner = insensitive ? inner.toLowerCase() : inner;
  const foldedOuter = insensitive ? outer.toLowerCase() : outer;
  if (foldedInner === foldedOuter) return true;
  const sep = separatorFor(sourcePlatform);
  const prefix = foldedOuter.endsWith(sep) ? foldedOuter : foldedOuter + sep;
  return foldedInner.startsWith(prefix);
}

function descriptorFingerprintOf(record) {
  const body = {};
  for (const key of DESCRIPTOR_KEYS) {
    if (key !== "descriptorFingerprint") body[key] = record[key];
  }
  try {
    return canonicalJsonHash(body, { maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 256 });
  } catch (error) {
    refuse("CONFIG_INVALID", `descriptor body is not canonicalizable: ${error?.message ?? "invalid"}`);
  }
}

/**
 * Validate an exact quarantine-staging descriptor and check its
 * self-fingerprint. Returns the same object on success; throws a structured
 * CONFIG_INVALID refusal otherwise.
 */
export function validateQuarantineStagingDescriptor(descriptor) {
  if (!hasExactKeys(descriptor, DESCRIPTOR_KEYS)) {
    refuse("CONFIG_INVALID", "descriptor must have the exact descriptor key set");
  }
  if (descriptor.version !== VERSION) refuse("CONFIG_INVALID", "unsupported descriptor version");
  if (descriptor.kind !== KIND) refuse("CONFIG_INVALID", "unexpected descriptor kind");
  if (!isId(descriptor.hostId)) refuse("CONFIG_INVALID", "hostId must be a 1..256 char string");
  if (!isId(descriptor.workspaceId)) refuse("CONFIG_INVALID", "workspaceId must be a 1..256 char string");
  if (!SOURCE_PLATFORMS.has(descriptor.sourcePlatform)) {
    refuse("CONFIG_INVALID", `unknown sourcePlatform: ${descriptor.sourcePlatform}`);
  }
  if (!SOURCE_KINDS.has(descriptor.sourceKind)) {
    refuse("CONFIG_INVALID", `unknown sourceKind: ${descriptor.sourceKind}`);
  }
  // stagingPath must be a canonical absolute path; a canonical form is what the
  // lexical guard later compares against the live candidate.
  const canonical = assertAbsolutePath("stagingPath", descriptor.stagingPath, descriptor.sourcePlatform);
  if (canonical !== descriptor.stagingPath) {
    refuse("CONFIG_INVALID", "stagingPath must already be in canonical native-separator form");
  }
  if (!isHex64(descriptor.descriptorFingerprint)) {
    refuse("CONFIG_INVALID", "descriptorFingerprint must be hex64");
  }
  if (descriptorFingerprintOf(descriptor) !== descriptor.descriptorFingerprint) {
    refuse("CONFIG_INVALID", "descriptorFingerprint does not match the descriptor body");
  }
  return descriptor;
}

/**
 * Build and validate a quarantine-staging descriptor. The self-fingerprint is
 * computed last. Returns a frozen descriptor. `stagingPath` must already be a
 * canonical absolute path for `sourcePlatform`.
 */
export function buildQuarantineStagingDescriptor(input) {
  if (!isPlainObject(input)) refuse("CONFIG_INVALID", "descriptor input must be an object");
  if (!SOURCE_PLATFORMS.has(input.sourcePlatform)) {
    refuse("CONFIG_INVALID", `unknown sourcePlatform: ${input.sourcePlatform}`);
  }
  const canonical = assertAbsolutePath("stagingPath", input.stagingPath, input.sourcePlatform);
  const record = {
    version: VERSION,
    kind: KIND,
    hostId: input.hostId,
    workspaceId: input.workspaceId,
    sourcePlatform: input.sourcePlatform,
    stagingPath: canonical,
    sourceKind: input.sourceKind,
    descriptorFingerprint: null,
  };
  record.descriptorFingerprint = descriptorFingerprintOf(record);
  validateQuarantineStagingDescriptor(record);
  return Object.freeze(record);
}

/**
 * Pure lexical quarantine guard. Refuses WORKSPACE_STAGING_NOT_QUARANTINED when
 * `stagingPath` equals, or nests under, the live workspace `candidatePath`
 * (the active generation/candidate directory). `candidatePath` must itself be
 * the workspace root `workDir` or a path nested under it; otherwise the input
 * is malformed (CONFIG_INVALID) - a candidate outside its own workspace root is
 * never a valid live target. A genuine sibling staging path returns a frozen
 * `{ quarantined: true }`.
 *
 * No filesystem access, no reparse resolution: this is the structural invariant
 * only. S5i pairs it with S4a's reparse-free containment proof at composition.
 */
export function assertQuarantined({ stagingPath, candidatePath, workDir, sourcePlatform } = {}) {
  if (!SOURCE_PLATFORMS.has(sourcePlatform)) {
    refuse("CONFIG_INVALID", `unknown sourcePlatform: ${sourcePlatform}`);
  }
  const canonicalWorkDir = assertAbsolutePath("workDir", workDir, sourcePlatform);
  const canonicalCandidate = assertAbsolutePath("candidatePath", candidatePath, sourcePlatform);
  const canonicalStaging = assertAbsolutePath("stagingPath", stagingPath, sourcePlatform);

  // The live candidate must live within its own workspace root. A candidate
  // outside workDir is a malformed live target, not a quarantine decision.
  if (!nestsUnderOrEquals(canonicalCandidate, canonicalWorkDir, sourcePlatform)) {
    refuse("CONFIG_INVALID", "candidatePath is not the workspace root or a path nested under it");
  }

  if (nestsUnderOrEquals(canonicalStaging, canonicalCandidate, sourcePlatform)) {
    refuse(
      "WORKSPACE_STAGING_NOT_QUARANTINED",
      "stagingPath equals or nests under the live workspace candidate path",
      { stagingPath: canonicalStaging, candidatePath: canonicalCandidate },
    );
  }

  // Symmetric guard: a staging path that is an ANCESTOR of the live candidate
  // (e.g. stagingPath === workDir) is equally unquarantined -- destroying the
  // staging tree would take the live candidate with it. The equal case is
  // already caught above; this closes the strict-ancestor direction.
  if (nestsUnderOrEquals(canonicalCandidate, canonicalStaging, sourcePlatform)) {
    refuse(
      "WORKSPACE_STAGING_NOT_QUARANTINED",
      "stagingPath is an ancestor of the live workspace candidate path",
      { stagingPath: canonicalStaging, candidatePath: canonicalCandidate },
    );
  }

  return Object.freeze({ quarantined: true });
}

export { SOURCE_KINDS };
