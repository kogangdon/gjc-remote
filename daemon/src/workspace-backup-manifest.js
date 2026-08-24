// Workspace backup / content manifest for the native workspace data plane
// (#53 Phase 2, slice S4c).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations):
//   * Create/clone: "... backup/manifest ..."
//   * Restore/migration: "... checksum verification ... reversible promotion".
//
// This module is a PURE, dependency-injected primitive. It does NOT wire into
// the daemon and does NOT flip the native-workspace-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false). It produces and verifies a
// canonical, content-addressed manifest of a staged workspace generation so
// that:
//   - S4d atomic publication can bind a generation to a verifiable digest, and
//   - a later restore/migration (S5) can prove a recovered generation matches
//     its manifest by re-reading and re-hashing every entry (checksum
//     verification).
//
// The manifest reuses the shared canonical-JSON envelope conventions
// (`@gjc-remote/shared/strict-json`): version/kind, exact key sets, and a
// self-fingerprint field computed as the sha256 of the canonical JSON of the
// record with the fingerprint field removed — identical in shape to
// shared/workspace-lifecycle-envelope.js and the publication envelopes. The
// hashed body is deterministic and timestamp-free so the same staged content
// always yields the same manifest fingerprint.
//
// Byte I/O is injected: the caller provides an async `readBytes(relPath)` that
// MUST be reparse-safe (the daemon wires the native no-follow verified reader).
// This module never opens files itself, so it stays testable and platform-free.

import { createHash } from "node:crypto";
import {
  canonicalJsonBytes,
  canonicalJsonHash,
  isHex64,
  parseCanonicalJsonBytes,
  utf8Compare,
} from "@gjc-remote/shared/strict-json";

const OPERATION = "workspace_backup_manifest";
const KIND = "workspace-backup-manifest";
const VERSION = 1;

// Same platform vocabulary as shared/workspace-binding.js and
// shared/workspace-inventory.js. Kept inline (each envelope declares its own)
// rather than importing a non-exported constant.
const SOURCE_PLATFORMS = new Set(["posix", "windows-drive", "windows-unc"]);

const MANIFEST_KEYS = [
  "version",
  "kind",
  "hostId",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "rootIdentityFingerprint",
  "storageIdentityFingerprint",
  "gitGenerationFingerprint",
  "entryCount",
  "totalSize",
  "entries",
  "manifestFingerprint",
];
const ENTRY_KEYS = ["path", "size", "sha256"];

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
const isSafeCount = (value) => Number.isSafeInteger(value) && value >= 0;

// A manifest entry path is a workspace-RELATIVE POSIX path: '/' separators, no
// leading separator, no drive/UNC prefix, no '.'/'..' segment, no NUL, no
// backslash (callers normalise Windows separators before building), non-empty.
function assertRelativePath(path) {
  if (typeof path !== "string" || path.length === 0) {
    refuse("WORKSPACE_MANIFEST_PATH_REJECTED", "entry path must be a non-empty string");
  }
  if (path.includes("\0")) {
    refuse("WORKSPACE_MANIFEST_PATH_REJECTED", "entry path contains a NUL byte");
  }
  if (path.includes("\\")) {
    refuse("WORKSPACE_MANIFEST_PATH_REJECTED", `entry path must use '/' separators: ${path}`);
  }
  if (path.startsWith("/")) {
    refuse("WORKSPACE_MANIFEST_PATH_REJECTED", `entry path must be relative: ${path}`);
  }
  if (/^[A-Za-z]:/.test(path)) {
    refuse("WORKSPACE_MANIFEST_PATH_REJECTED", `entry path must not carry a drive prefix: ${path}`);
  }
  for (const segment of path.split("/")) {
    if (segment.length === 0) {
      refuse("WORKSPACE_MANIFEST_PATH_REJECTED", `entry path has an empty segment: ${path}`);
    }
    if (segment === "." || segment === "..") {
      refuse("WORKSPACE_MANIFEST_PATH_REJECTED", `entry path has a dot segment: ${path}`);
    }
  }
}

function assertEntry(entry, index) {
  if (!hasExactKeys(entry, ENTRY_KEYS)) {
    refuse("WORKSPACE_MANIFEST_INVALID", `entry ${index} must have exactly {path,size,sha256}`);
  }
  assertRelativePath(entry.path);
  if (!isSafeCount(entry.size)) {
    refuse("WORKSPACE_MANIFEST_INVALID", `entry ${entry.path} size must be a non-negative safe integer`);
  }
  if (!isHex64(entry.sha256)) {
    refuse("WORKSPACE_MANIFEST_INVALID", `entry ${entry.path} sha256 must be a 64-char lowercase hex digest`);
  }
}

function manifestFingerprintOf(record) {
  const withoutFingerprint = {};
  for (const key of MANIFEST_KEYS) {
    if (key !== "manifestFingerprint") withoutFingerprint[key] = record[key];
  }
  return canonicalJsonHash(withoutFingerprint);
}

/**
 * Validate an exact backup manifest, recompute and check its self-fingerprint,
 * and confirm entry ordering/uniqueness and the entryCount/totalSize
 * cross-checks. Returns the same object on success; throws a structured
 * WORKSPACE_MANIFEST_INVALID refusal otherwise.
 */
export function validateWorkspaceManifest(manifest) {
  if (!hasExactKeys(manifest, MANIFEST_KEYS)) {
    refuse("WORKSPACE_MANIFEST_INVALID", "manifest must have the exact manifest key set");
  }
  if (manifest.version !== VERSION) refuse("WORKSPACE_MANIFEST_INVALID", "unsupported manifest version");
  if (manifest.kind !== KIND) refuse("WORKSPACE_MANIFEST_INVALID", "unexpected manifest kind");
  if (!isId(manifest.hostId)) refuse("WORKSPACE_MANIFEST_INVALID", "hostId must be a 1..256 char string");
  if (!isId(manifest.workspaceId)) refuse("WORKSPACE_MANIFEST_INVALID", "workspaceId must be a 1..256 char string");
  if (!Number.isSafeInteger(manifest.workspaceGeneration) || manifest.workspaceGeneration < 1) {
    refuse("WORKSPACE_MANIFEST_INVALID", "workspaceGeneration must be a safe integer >= 1");
  }
  if (!SOURCE_PLATFORMS.has(manifest.sourcePlatform)) {
    refuse("WORKSPACE_MANIFEST_INVALID", `unknown sourcePlatform: ${manifest.sourcePlatform}`);
  }
  if (!isHex64(manifest.rootIdentityFingerprint)) refuse("WORKSPACE_MANIFEST_INVALID", "rootIdentityFingerprint must be hex64");
  if (!isHex64(manifest.storageIdentityFingerprint)) refuse("WORKSPACE_MANIFEST_INVALID", "storageIdentityFingerprint must be hex64");
  if (!isHex64(manifest.gitGenerationFingerprint)) refuse("WORKSPACE_MANIFEST_INVALID", "gitGenerationFingerprint must be hex64");

  if (!Array.isArray(manifest.entries)) refuse("WORKSPACE_MANIFEST_INVALID", "entries must be an array");
  let totalSize = 0;
  let previousPath = null;
  manifest.entries.forEach((entry, index) => {
    assertEntry(entry, index);
    if (previousPath !== null) {
      const order = utf8Compare(previousPath, entry.path);
      if (order > 0) refuse("WORKSPACE_MANIFEST_INVALID", `entries not sorted at ${entry.path}`);
      if (order === 0) refuse("WORKSPACE_MANIFEST_INVALID", `duplicate entry path: ${entry.path}`);
    }
    previousPath = entry.path;
    totalSize += entry.size;
    if (!Number.isSafeInteger(totalSize)) refuse("WORKSPACE_MANIFEST_INVALID", "totalSize overflow");
  });

  if (manifest.entryCount !== manifest.entries.length) {
    refuse("WORKSPACE_MANIFEST_INVALID", "entryCount does not match entries length");
  }
  if (manifest.totalSize !== totalSize) {
    refuse("WORKSPACE_MANIFEST_INVALID", "totalSize does not match the sum of entry sizes");
  }
  if (!isHex64(manifest.manifestFingerprint)) {
    refuse("WORKSPACE_MANIFEST_INVALID", "manifestFingerprint must be hex64");
  }
  if (manifestFingerprintOf(manifest) !== manifest.manifestFingerprint) {
    refuse("WORKSPACE_MANIFEST_INVALID", "manifestFingerprint does not match the manifest body");
  }
  return manifest;
}

/**
 * Build and validate a backup manifest from staged content descriptors. Entries
 * are copied, sorted, and deduplicated-checked; the self-fingerprint is
 * computed last. Returns a frozen manifest.
 */
export function buildWorkspaceManifest(input) {
  if (!isPlainObject(input)) refuse("WORKSPACE_MANIFEST_INVALID", "manifest input must be an object");
  const rawEntries = input.entries;
  if (!Array.isArray(rawEntries)) refuse("WORKSPACE_MANIFEST_INVALID", "entries must be an array");

  const entries = rawEntries.map((entry, index) => {
    assertEntry(entry, index);
    return { path: entry.path, size: entry.size, sha256: entry.sha256 };
  });
  entries.sort((a, b) => utf8Compare(a.path, b.path));

  let totalSize = 0;
  for (const entry of entries) {
    totalSize += entry.size;
    if (!Number.isSafeInteger(totalSize)) refuse("WORKSPACE_MANIFEST_INVALID", "totalSize overflow");
  }

  const record = {
    version: VERSION,
    kind: KIND,
    hostId: input.hostId,
    workspaceId: input.workspaceId,
    workspaceGeneration: input.workspaceGeneration,
    sourcePlatform: input.sourcePlatform,
    rootIdentityFingerprint: input.rootIdentityFingerprint,
    storageIdentityFingerprint: input.storageIdentityFingerprint,
    gitGenerationFingerprint: input.gitGenerationFingerprint,
    entryCount: entries.length,
    totalSize,
    entries: entries.map((entry) => Object.freeze({ ...entry })),
    manifestFingerprint: null,
  };
  record.manifestFingerprint = manifestFingerprintOf(record);
  validateWorkspaceManifest(record);
  record.entries = Object.freeze(record.entries);
  return Object.freeze(record);
}

/** Canonical bytes of a validated manifest (validates first). */
export function workspaceManifestBytes(manifest) {
  validateWorkspaceManifest(manifest);
  return canonicalJsonBytes(manifest);
}

/** Parse canonical manifest bytes and validate the result. */
export function parseWorkspaceManifest(bytes) {
  let value;
  try {
    value = parseCanonicalJsonBytes(bytes);
  } catch (error) {
    refuse("WORKSPACE_MANIFEST_INVALID", `manifest bytes are not canonical JSON: ${error?.message ?? "parse error"}`);
  }
  return validateWorkspaceManifest(value);
}

/**
 * Compute manifest entries by reading each relative path through the injected
 * reparse-safe reader. `readBytes(relPath)` MUST return a Buffer/Uint8Array of
 * the file's exact bytes read with no symlink following. Duplicate and
 * unreadable paths are refused. Returns entries sorted by path.
 *
 * @param {{ readBytes:(relPath:string)=>Promise<Uint8Array> }} io
 * @param {string[]} relativePaths
 */
export async function computeManifestEntries(io, relativePaths) {
  if (!io || typeof io.readBytes !== "function") {
    refuse("WORKSPACE_MANIFEST_INVALID", "io.readBytes must be a function");
  }
  if (!Array.isArray(relativePaths)) {
    refuse("WORKSPACE_MANIFEST_INVALID", "relativePaths must be an array");
  }
  const seen = new Set();
  const entries = [];
  for (const path of relativePaths) {
    assertRelativePath(path);
    if (seen.has(path)) refuse("WORKSPACE_MANIFEST_INVALID", `duplicate path in input: ${path}`);
    seen.add(path);
    let bytes;
    try {
      bytes = await io.readBytes(path);
    } catch (error) {
      if (error?.operation === OPERATION) throw error;
      refuse("WORKSPACE_MANIFEST_READ_FAILED", `unable to read ${path}`, {
        cause: String(error?.code ?? error?.message ?? "unknown"),
      });
    }
    if (!(bytes instanceof Uint8Array)) {
      refuse("WORKSPACE_MANIFEST_READ_FAILED", `reader for ${path} did not return bytes`);
    }
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    entries.push({ path, size: bytes.byteLength, sha256 });
  }
  entries.sort((a, b) => utf8Compare(a.path, b.path));
  return entries;
}

/**
 * Verify a directory's current content matches a manifest by re-reading and
 * re-hashing every entry through the injected reader. Returns
 * { ok:true, verifiedCount } or throws WORKSPACE_MANIFEST_MISMATCH on the first
 * size/digest divergence (checksum verification for restore/migration).
 *
 * @param {{ readBytes:(relPath:string)=>Promise<Uint8Array> }} io
 * @param {object} manifest
 */
export async function verifyManifestAgainst(io, manifest) {
  if (!io || typeof io.readBytes !== "function") {
    refuse("WORKSPACE_MANIFEST_INVALID", "io.readBytes must be a function");
  }
  validateWorkspaceManifest(manifest);
  let verifiedCount = 0;
  for (const entry of manifest.entries) {
    let bytes;
    try {
      bytes = await io.readBytes(entry.path);
    } catch (error) {
      refuse("WORKSPACE_MANIFEST_MISMATCH", `unable to read ${entry.path} during verification`, {
        path: entry.path,
        cause: String(error?.code ?? error?.message ?? "unknown"),
      });
    }
    if (!(bytes instanceof Uint8Array)) {
      refuse("WORKSPACE_MANIFEST_MISMATCH", `reader for ${entry.path} did not return bytes`, { path: entry.path });
    }
    if (bytes.byteLength !== entry.size) {
      refuse("WORKSPACE_MANIFEST_MISMATCH", `size mismatch for ${entry.path}`, {
        path: entry.path,
        expectedSize: entry.size,
        actualSize: bytes.byteLength,
      });
    }
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    if (sha256 !== entry.sha256) {
      refuse("WORKSPACE_MANIFEST_MISMATCH", `sha256 mismatch for ${entry.path}`, {
        path: entry.path,
        expectedSha256: entry.sha256,
        actualSha256: sha256,
      });
    }
    verifiedCount += 1;
  }
  return { ok: true, verifiedCount };
}
