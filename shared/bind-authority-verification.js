// Bind-authority preimage verification (issue #179).
//
// Pure, dependency-injected verifier that replaces the daemon's former
// trust-on-first-use (TOFU) adoption of routeFingerprint / authorityFingerprint
// with independent, per-bind verification. On EVERY BIND_WORKSPACE the daemon
// runs this at the top of acceptWorkspaceBinding, ahead of every dedup /
// generation-fencing / sameAuthority branch, so a re-bind can never bypass it.
//
// What it proves:
//   1. hostId ground truth: message.hostId === the daemon's own HOST_ID.
//   2. Envelope authenticity: validateManagedRouteRecord(route, mapping)
//      recomputes BOTH fingerprints (routeFingerprint via hashWithout, and
//      mappingFingerprint via the mapping-record precondition) and enforces the
//      9 shared route<->mapping fields -- reusing shared/mapping-envelope.js
//      verbatim, no forked hash logic.
//   3. Identity binding: the daemon-servable top-level tuple (mappingId,
//      generations, workspaceId, sourcePlatform, and the two presented
//      fingerprints) matches the verified preimage records, so a valid
//      envelope for workspace X cannot be presented under a top-level
//      workspaceId Y.
//   4. Layered path containment (tier-2), applied ONLY when the caller injects
//      a configured, daemon-known root (context.containment). It checks the
//      actual path-shaped preimage fields (mapping.sourceRoot,
//      mapping.containerRoot, and legacy mapping.workDir) lexically against that
//      root. On the default deployment (no configured root) this is a NO-OP and
//      is NOT claimed to close any gap: workspaceId is a structurally
//      traversal-proof OPAQUE_TOKEN, workDir-carrying routes are forbidden
//      bot-side, and the daemon serves from its own locally-scanned inventory,
//      never from these preimage path fields.
//
// This module never imports the daemon or the native addon. The daemon injects
// its HOST_ID and (when a root is configured) a lexical containment predicate;
// shared/test injects fakes.
//
// verifyReceiptBindAuthorityPreimage (below) is the SIBLING verifier for the
// LIVE managed-workspace bind path (receipt-shaped BIND_WORKSPACE, dispatched
// to daemon.js#acceptReceiptBinding). That path commits to a single mapping
// record only (no routeFingerprint in the receipt shape), so it is verified
// separately rather than by reusing this function.

import { PROTOCOL_ERROR_CODES } from "./protocol.js";
import { validateManagedRouteRecord, validateManagedMappingRecord } from "./mapping-envelope.js";

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function fail(code) {
  return Object.freeze({ ok: false, code });
}

// The daemon-servable top-level fields whose value MUST equal the verified
// route record. authorityFingerprint binds to mapping.mappingFingerprint
// separately (the bot derives it as authorityFingerprint = mapping
// .mappingFingerprint, bot/src/config.js).
const ROUTE_BOUND_TUPLE_FIELDS = Object.freeze([
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "routeFingerprint",
]);

/**
 * Verify a BIND_WORKSPACE preimage. Returns a frozen result:
 *   { ok: true } on success, or { ok: false, code } where code is a
 *   PROTOCOL_ERROR_CODES.BIND_AUTHORITY_* value for observable, redacted
 *   diagnostics. It never throws on a verification failure (the underlying
 *   validator throws are caught and mapped to a code).
 *
 * @param {object} message  a shape-valid BIND_WORKSPACE (isBindWorkspaceMessage)
 * @param {object} context
 *   context.hostId      {string}  the daemon's own HOST_ID (ground truth)
 *   context.containment {object=} optional; when present tier-2 containment is
 *     applied. Shape: { root, sourcePlatform, assertContained } where
 *     assertContained(root, candidate, sourcePlatform) returns for a contained
 *     path and THROWS on any lexical escape (e.g. daemon's relativeComponents).
 *     Absent/null => tier-2 is a documented no-op (default deployment).
 */
export function verifyBindAuthorityPreimage(message, context) {
  if (!isObject(message) || !isObject(context) || typeof context.hostId !== "string") {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }

  // 1. Ground-truth hostId.
  if (message.hostId !== context.hostId) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HOSTID_MISMATCH);
  }

  const { route, mapping } = message;
  if (!isObject(route) || !isObject(mapping)) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }

  // 2. Envelope authenticity: recompute both fingerprints + cross-field checks.
  try {
    validateManagedRouteRecord(route, mapping);
  } catch {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }

  // 3. Identity binding: the servable top-level tuple must equal the verified
  //    preimage; a genuine envelope for one workspace cannot be re-presented
  //    under a different top-level identity.
  for (const field of ROUTE_BOUND_TUPLE_FIELDS) {
    if (message[field] !== route[field]) {
      return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
    }
  }
  if (message.authorityFingerprint !== mapping.mappingFingerprint) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }
  // route<->mapping identity is already enforced by validateManagedRouteRecord,
  // but bind the ground-truth hostId to the mapping too for defense in depth.
  if (mapping.hostId !== context.hostId) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HOSTID_MISMATCH);
  }

  // 4. Tier-2 lexical containment, ONLY when a daemon root is configured.
  //    The daemon injects the ground-truth root(s) it actually knows. On the
  //    default deployment context.containment is absent and this is a no-op.
  const containment = context.containment;
  if (isObject(containment)) {
    if (typeof containment.assertContained !== "function") {
      return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
    }
    // Host-filesystem path-shaped fields (sourceRoot, and legacy workDir) are
    // checked against the daemon's configured host root, whose grammar must
    // match the mapping's platform; a platform mismatch fails closed.
    if (mapping.sourcePlatform !== containment.sourcePlatform) {
      return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
    }
    const hostChecks = [];
    if (typeof mapping.sourceRoot === "string") {
      hostChecks.push(mapping.sourceRoot);
    }
    if (mapping.workspaceId === null && typeof mapping.workDir === "string") {
      hostChecks.push(mapping.workDir);
    }
    for (const candidate of hostChecks) {
      try {
        containment.assertContained(containment.root, candidate, containment.sourcePlatform);
      } catch {
        return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
      }
    }
    // containerRoot is always a POSIX container-namespace path (never a
    // daemon-host path), so it is only checked when the daemon injects a
    // separate container-root ground truth, against POSIX grammar.
    if (typeof containment.containerRoot === "string" && typeof mapping.containerRoot === "string") {
      try {
        containment.assertContained(containment.containerRoot, mapping.containerRoot, "posix");
      } catch {
        return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
      }
    }
  }

  return Object.freeze({ ok: true, code: null });
}

// The daemon-servable top-level tuple whose value MUST equal the verified
// mapping record, for the LIVE managed-workspace receipt bind path (issue
// #179 Slice 2). authorityFingerprint binds to mapping.mappingFingerprint
// separately (the bot derives it as authorityFingerprint = mapping
// .mappingFingerprint, bot/src/host-registry.js). fenceGeneration IS included
// (unlike the route tuple, which does not need it separately) because the
// daemon fences receiptWorkspaceFloors on the top-level fenceGeneration: an
// unverified, inflated top-level fenceGeneration would poison that floor even
// though the mapping record itself never changed -- an availability DoS.
// authorityEpoch is NOT in this list and CANNOT be cross-checked: it is
// absent from MAPPING_KEYS in shared/mapping-envelope.js, so it remains
// residual trust -- monotonic-fenced (the daemon still enforces authorityEpoch
// ordering) and channel-trusted (carried only over the already-authenticated
// bot<->daemon channel), not preimage-verified by this function.
const RECEIPT_MAPPING_BOUND_TUPLE_FIELDS = Object.freeze([
  "hostId",
  "mappingId",
  "mappingGeneration",
  "workspaceGeneration",
  "mappingVersion",
  "sourcePlatform",
  "workspaceId",
  "fenceGeneration",
]);

/**
 * Verify a receipt-shaped BIND_WORKSPACE preimage (issue #179 Slice 2). The
 * live managed-workspace bind path is receipt-shaped
 * (isInventoryReceiptBindWorkspaceMessage) and always dispatches to
 * daemon.js#acceptReceiptBinding; this is the PRIMARY per-bind verifier for
 * that path (verifyBindAuthorityPreimage above remains defense-in-depth for
 * the non-receipt v2 acceptWorkspaceBinding shape). Unlike the route/mapping
 * pair verified above, a receipt bind commits to a SINGLE mapping-record
 * preimage: the receipt shape carries no routeFingerprint at all, so there is
 * no route<->mapping pair to reconcile -- only
 * message.authorityFingerprint === mapping.mappingFingerprint.
 *
 * Returns a frozen result: { ok: true, code: null } on success, or
 * { ok: false, code } where code is a PROTOCOL_ERROR_CODES.BIND_AUTHORITY_*
 * value. It never throws (validateManagedMappingRecord throws are caught and
 * mapped to a code).
 *
 * @param {object} message  a shape-valid receipt BIND_WORKSPACE
 *   (isInventoryReceiptBindWorkspaceMessage), which already requires an
 *   object-shaped `mapping` field.
 * @param {object} context
 *   context.hostId      {string}  the daemon's own HOST_ID (ground truth)
 *   context.containment {object=} optional; when present tier-2 containment is
 *     applied over mapping.sourceRoot / mapping.containerRoot using the SAME
 *     structure as verifyBindAuthorityPreimage's tier-2 check. Absent/null =>
 *     tier-2 is a documented no-op (default deployment).
 */
export function verifyReceiptBindAuthorityPreimage(message, context) {
  if (!isObject(message) || !isObject(context) || typeof context.hostId !== "string") {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }

  // 1. Ground-truth hostId (top-level).
  if (message.hostId !== context.hostId) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HOSTID_MISMATCH);
  }

  const { mapping } = message;
  if (!isObject(mapping)) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }

  // 2. Envelope authenticity: recompute mappingFingerprint + internal shape.
  try {
    validateManagedMappingRecord(mapping);
  } catch {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }

  // 3. Mapping authority commitment: the receipt shape has no routeFingerprint
  //    -- the SOLE preimage commitment is authorityFingerprint over mapping.
  if (mapping.mappingFingerprint !== message.authorityFingerprint) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
  }

  // 4. Identity binding: the daemon-servable top-level tuple must equal the
  //    verified mapping preimage, so a genuine mapping for one workspace
  //    cannot be re-presented under a different top-level identity.
  for (const field of RECEIPT_MAPPING_BOUND_TUPLE_FIELDS) {
    if (message[field] !== mapping[field]) {
      return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
    }
  }

  // 5. Ground-truth hostId bound to the mapping too, for defense in depth.
  if (mapping.hostId !== context.hostId) {
    return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HOSTID_MISMATCH);
  }

  // 6. Tier-2 lexical containment, ONLY when a daemon root is configured. Same
  //    structure as verifyBindAuthorityPreimage's tier-2 check, over the
  //    mapping's own sourceRoot/containerRoot. mapping.containerRoot may be
  //    null; the typeof === "string" guard below makes that a no-op rather
  //    than a false escape.
  const containment = context.containment;
  if (isObject(containment)) {
    if (typeof containment.assertContained !== "function") {
      return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
    }
    if (mapping.sourcePlatform !== containment.sourcePlatform) {
      return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
    }
    const hostChecks = [];
    if (typeof mapping.sourceRoot === "string") {
      hostChecks.push(mapping.sourceRoot);
    }
    for (const candidate of hostChecks) {
      try {
        containment.assertContained(containment.root, candidate, containment.sourcePlatform);
      } catch {
        return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
      }
    }
    if (typeof containment.containerRoot === "string" && typeof mapping.containerRoot === "string") {
      try {
        containment.assertContained(containment.containerRoot, mapping.containerRoot, "posix");
      } catch {
        return fail(PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
      }
    }
  }

  return Object.freeze({ ok: true, code: null });
}
