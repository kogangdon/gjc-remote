// Workspace dirty backup for the native workspace reset/delete lifecycle
// (#53 Phase 2, slice S5a).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations
// -> Reset/delete): before a destructive reset/delete may proceed, the daemon
// captures a "dirty backup" -- a content snapshot of the live workspace tree AS
// IT EXISTS AT DELETE TIME -- so an operator can recover work that was never
// promoted into a clean generation. This is distinct from S4c's create/refresh
// -time manifest (which describes a freshly staged, verified generation): the
// dirty backup describes whatever is on disk right now, including uncommitted
// or partially written content.
//
// This module is a PURE, dependency-injected primitive. It does NOT wire into
// the daemon and does NOT flip the native-workspace-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false). It COMPOSES S4c's manifest
// primitive verbatim (computeManifestEntries + buildWorkspaceManifest) rather
// than duplicating the canonical-manifest machinery, so a dirty backup and a
// clean generation manifest are byte-for-byte comparable when they describe the
// same content.
//
// It adds exactly one obligation on top of S4c: a dirty backup MUST cover every
// path the caller intended to snapshot. S4c's buildWorkspaceManifest accepts an
// EMPTY entry set as a structurally valid manifest (a vacuous manifest), which
// the S4f create/clone review flagged as a gap: a reset/delete that silently
// captured zero files would look "backed up" while preserving nothing. So this
// module refuses a zero-path request up front (CONFIG_INVALID) and exposes
// assertDirtyBackupComplete, an explicit count cross-check the reset/delete
// orchestrator (S5e) calls to prove the produced manifest covers all N intended
// paths before it is allowed to authorise destruction.
//
// Byte I/O is injected through S4c's contract: `io.readBytes(relPath)` MUST be
// the reparse-safe native no-follow reader. This module never opens files.

import {
  buildWorkspaceManifest,
  computeManifestEntries,
  validateWorkspaceManifest,
} from "./workspace-backup-manifest.js";

const OPERATION = "workspace_dirty_backup";

// The exact identity + input key set a dirty-backup request must carry. The
// identity fields are passed straight through to S4c's buildWorkspaceManifest
// so the dirty backup binds the same host/workspace/generation/platform and
// git/root/storage fingerprints as the generation it snapshots. relativePaths
// is the live file set to capture.
const DIRTY_BACKUP_REQUEST_KEYS = Object.freeze([
  "hostId",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "rootIdentityFingerprint",
  "storageIdentityFingerprint",
  "gitGenerationFingerprint",
  "relativePaths",
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
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const hasExactKeys = (value, keys) =>
  isPlainObject(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

/**
 * Assert that a produced backup manifest actually COVERS the exact set of paths
 * the caller intended to snapshot -- not merely the right count. This export is
 * the standalone destruction-authorization guard the reset/delete orchestrator
 * (S5e) calls, where the manifest and the intended path set may originate from
 * INDEPENDENT sources (e.g. a manifest recovered from disk cross-checked against
 * a freshly enumerated live tree during crash/partial recovery). A count-only
 * check would pass a manifest of the right number of the WRONG paths, so this
 * proves set equality: every intended path is present, and the manifest carries
 * no entry outside the intended set. Manifest entries are already sorted and
 * unique (S4c validateWorkspaceManifest), so unique membership + equal cardinality
 * is an exact bijection. Throws WORKSPACE_MANIFEST_MISMATCH on any divergence.
 *
 * @param {object} manifest a manifest produced by S4c buildWorkspaceManifest
 * @param {string[]} relativePaths the intended snapshot path set (no duplicates)
 * @returns {object} the validated manifest
 */
export function assertDirtyBackupComplete(manifest, relativePaths) {
  validateWorkspaceManifest(manifest);
  if (!Array.isArray(relativePaths) || relativePaths.length === 0) {
    refuse("CONFIG_INVALID", "relativePaths must be a non-empty array");
  }
  const want = new Set(relativePaths);
  // The intended path set is authoritative; a duplicated intent is a caller bug,
  // not a silent dedup. Refuse it (matching computeManifestEntries' duplicate
  // refusal) so the guard's semantics never diverge from the capture path.
  if (want.size !== relativePaths.length) {
    refuse("CONFIG_INVALID", "relativePaths must not contain duplicates");
  }
  if (manifest.entryCount !== want.size) {
    refuse(
      "WORKSPACE_MANIFEST_MISMATCH",
      `dirty backup covers ${manifest.entryCount} of ${want.size} intended paths`,
      { expectedCount: want.size, actualCount: manifest.entryCount },
    );
  }
  for (const entry of manifest.entries) {
    if (!want.has(entry.path)) {
      refuse(
        "WORKSPACE_MANIFEST_MISMATCH",
        `dirty backup contains an unintended path: ${entry.path}`,
        { unexpectedPath: entry.path },
      );
    }
  }
  return manifest;
}

/**
 * Capture a dirty backup of the live workspace tree. Reads every requested path
 * through the injected reparse-safe reader, builds an S4c canonical manifest,
 * and cross-checks that the manifest covers every distinct requested path.
 * Returns a frozen { manifest, manifestFingerprint }.
 *
 * A zero-path request is refused (CONFIG_INVALID): a destructive reset/delete
 * must never proceed behind a vacuous backup. Duplicate or malformed paths and
 * unreadable files surface as the underlying S4c refusal (WORKSPACE_MANIFEST_*),
 * so nothing is destroyed on a partial read.
 *
 * @param {{ readBytes:(relPath:string)=>Promise<Uint8Array> }} io
 * @param {object} request
 * @returns {Promise<{ manifest: object, manifestFingerprint: string }>}
 */
export async function computeDirtyBackup(io, request) {
  if (!io || typeof io.readBytes !== "function") {
    refuse("CONFIG_INVALID", "io.readBytes must be a function");
  }
  if (!hasExactKeys(request, DIRTY_BACKUP_REQUEST_KEYS)) {
    refuse("CONFIG_INVALID", "dirty backup request must have the exact key set");
  }
  const { relativePaths } = request;
  if (!Array.isArray(relativePaths)) {
    refuse("CONFIG_INVALID", "relativePaths must be an array");
  }
  if (relativePaths.length === 0) {
    refuse("CONFIG_INVALID", "dirty backup requires at least one path (no vacuous backup)");
  }

  // S4c reads, hashes, sorts, and refuses duplicate/malformed paths. Any refusal
  // propagates unchanged (carrying its WORKSPACE_MANIFEST_* code) so a partial
  // or unreadable tree aborts the backup before destruction is authorised.
  const entries = await computeManifestEntries(io, relativePaths);
  const manifest = buildWorkspaceManifest({
    hostId: request.hostId,
    workspaceId: request.workspaceId,
    workspaceGeneration: request.workspaceGeneration,
    sourcePlatform: request.sourcePlatform,
    rootIdentityFingerprint: request.rootIdentityFingerprint,
    storageIdentityFingerprint: request.storageIdentityFingerprint,
    gitGenerationFingerprint: request.gitGenerationFingerprint,
    entries,
  });
  assertDirtyBackupComplete(manifest, relativePaths);

  return Object.freeze({ manifest, manifestFingerprint: manifest.manifestFingerprint });
}

export { DIRTY_BACKUP_REQUEST_KEYS };
