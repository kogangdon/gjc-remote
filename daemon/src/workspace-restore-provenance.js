// Restore provenance + checksum verification primitive (slice S5g).
//
// Pure, dependency-injected module for the restore/migration data plane
// (#53 Phase 2). Two exports:
//
//   1. verifyRestoreProvenance(io, { expectedAuthority, staged }) - proves the
//      role / volume / key / host identity, manifest content, and restore
//      lineage of a STAGED restore source matches a caller-supplied
//      `expectedAuthority`. The authority is the trusted anchor: it is NEVER
//      derived from staged content. The staged provenance record is read through
//      the injected `io.readProvenanceRecord(staged)` and every authority field
//      is compared; any divergence refuses the NEW
//      WORKSPACE_PROVENANCE_MISMATCH. A malformed/absent staged record is a
//      mismatch (fail closed: unverifiable provenance is not trusted), while a
//      malformed `expectedAuthority` is a caller bug (CONFIG_INVALID).
//
//   2. verifyRestoreChecksum(io, manifest) - a thin pass-through to S4c's
//      verifyManifestAgainst: it re-reads and re-hashes every manifested entry
//      and refuses the existing WORKSPACE_MANIFEST_MISMATCH on the first
//      size/digest/missing divergence. This module adds ZERO local hashing
//      logic; the single manifest-integrity implementation stays in S4c.
//
// The provenance/key source of truth (where expectedAuthority.keyFingerprint /
// volumeIdentityFingerprint originate) is out of scope here: this module treats
// expectedAuthority as an opaque, shape-validated caller record, deferring the
// backing key-management/volume registry to a later wiring decision.

import { isHex64 } from "@gjc-remote/shared/strict-json";
import { verifyManifestAgainst } from "./workspace-backup-manifest.js";

const OPERATION = "workspace_restore_provenance";
const PROVENANCE_KIND = "workspace-restore-provenance";
const VERSION = 2;

// The trusted authority anchor and the staged record are compared field for
// field on this exact v2 set. Fingerprints are hex64; ids are bounded opaque
// strings; generation is a positive safe integer.
const AUTHORITY_FIELDS = Object.freeze([
  "hostId",
  "roleFingerprint",
  "volumeIdentityFingerprint",
  "keyFingerprint",
  "manifestFingerprint",
  "restoredFromWorkspaceId",
  "restoredFromGeneration",
]);
const EXPECTED_AUTHORITY_KEYS = Object.freeze([...AUTHORITY_FIELDS]);
const PROVENANCE_RECORD_KEYS = Object.freeze(["version", "kind", ...AUTHORITY_FIELDS]);

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

function isValidAuthorityField(field, value) {
  if (field === "hostId" || field === "restoredFromWorkspaceId") return isId(value);
  if (field === "restoredFromGeneration") return Number.isSafeInteger(value) && value >= 1;
  return isHex64(value);
}

// Validate the caller-supplied trusted authority. A malformed authority is a
// caller contract violation, not a provenance decision -> CONFIG_INVALID.
function assertExpectedAuthority(expectedAuthority) {
  if (!hasExactKeys(expectedAuthority, EXPECTED_AUTHORITY_KEYS)) {
    refuse("CONFIG_INVALID", "expectedAuthority must have the exact v2 authority key set");
  }
  for (const field of AUTHORITY_FIELDS) {
    if (!isValidAuthorityField(field, expectedAuthority[field])) {
      refuse("CONFIG_INVALID", `expectedAuthority.${field} is malformed`);
    }
  }
}

/**
 * Verify the provenance of a staged restore source against a trusted authority.
 * Resolves to frozen trusted-authority values on an exact v2 authority match;
 * refuses WORKSPACE_PROVENANCE_MISMATCH on any field mismatch or a
 * malformed/absent staged record; refuses CONFIG_INVALID on a malformed
 * `expectedAuthority` or a bad io/reader contract.
 *
 * @param {{ readProvenanceRecord:(staged:object)=>Promise<object|null> }} io
 * @param {{ expectedAuthority:object, staged:object }} request
 */
export async function verifyRestoreProvenance(io, request) {
  if (!io || typeof io.readProvenanceRecord !== "function") {
    refuse("CONFIG_INVALID", "io.readProvenanceRecord must be a function");
  }
  if (!isPlainObject(request)) refuse("CONFIG_INVALID", "request must be an object");
  const { expectedAuthority, staged } = request;
  assertExpectedAuthority(expectedAuthority);
  if (!isPlainObject(staged)) refuse("CONFIG_INVALID", "request.staged must be an object");

  let record;
  try {
    record = await io.readProvenanceRecord(staged);
  } catch (error) {
    // A reader failure means the staged provenance cannot be proven -> fail
    // closed as a mismatch, not a soft error.
    refuse("WORKSPACE_PROVENANCE_MISMATCH", "unable to read the staged provenance record", {
      cause: String(error?.code ?? "unknown"),
    });
  }

  // A malformed or absent staged record cannot prove provenance -> mismatch.
  if (!hasExactKeys(record, PROVENANCE_RECORD_KEYS) ||
      record.version !== VERSION ||
      record.kind !== PROVENANCE_KIND) {
    refuse("WORKSPACE_PROVENANCE_MISMATCH", "staged provenance record is malformed or of an unexpected kind");
  }
  for (const field of AUTHORITY_FIELDS) {
    if (!isValidAuthorityField(field, record[field])) {
      refuse("WORKSPACE_PROVENANCE_MISMATCH", `staged provenance ${field} is malformed`, { field });
    }
    if (record[field] !== expectedAuthority[field]) {
      refuse("WORKSPACE_PROVENANCE_MISMATCH", `staged provenance ${field} does not match the expected authority`, {
        field,
      });
    }
  }

  // Return values exclusively from the TRUSTED authority, not the staged
  // record: the equality proof above established they match field-for-field,
  // and copying from the anchor makes the authority-derivation invariant
  // literal (a getter-bearing staged record cannot influence the result).
  return Object.freeze({
    verified: true,
    hostId: expectedAuthority.hostId,
    roleFingerprint: expectedAuthority.roleFingerprint,
    volumeIdentityFingerprint: expectedAuthority.volumeIdentityFingerprint,
    keyFingerprint: expectedAuthority.keyFingerprint,
    manifestFingerprint: expectedAuthority.manifestFingerprint,
    restoredFromWorkspaceId: expectedAuthority.restoredFromWorkspaceId,
    restoredFromGeneration: expectedAuthority.restoredFromGeneration,
  });
}

/**
 * Verify a staged restore source's content matches its manifest by re-reading
 * and re-hashing every entry through the injected reader. Thin pass-through to
 * S4c's verifyManifestAgainst (single manifest-integrity implementation; ZERO
 * local hashing here). Resolves to { ok:true, verifiedCount } or refuses
 * WORKSPACE_MANIFEST_MISMATCH on the first divergence.
 *
 * @param {{ readBytes:(relPath:string)=>Promise<Uint8Array> }} io
 * @param {object} manifest
 */
export async function verifyRestoreChecksum(io, manifest) {
  return verifyManifestAgainst(io, manifest);
}

export { EXPECTED_AUTHORITY_KEYS, PROVENANCE_RECORD_KEYS, PROVENANCE_KIND };
