import {
  validateWorkspaceAuthorityDescriptor,
} from "@gjc-remote/shared/workspace-binding";

const DESTINATION_AUTHORITY_FIELDS = Object.freeze([
  "authorityEpoch",
  "fenceGeneration",
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "authorityFingerprint",
]);

const PROVENANCE_V2_FIELDS = Object.freeze([
  "hostId",
  "roleFingerprint",
  "volumeIdentityFingerprint",
  "keyFingerprint",
  "manifestFingerprint",
  "restoredFromWorkspaceId",
  "restoredFromGeneration",
]);

const CLAIM_FIELDS = Object.freeze([
  ...DESTINATION_AUTHORITY_FIELDS,
  "operation",
  "idempotencyFingerprint",
  "stagingPath",
  "expectedAuthority",
  "manifest",
  "restoredFromWorkspaceId",
  "restoredFromGeneration",
  "expectedGraph",
  "probedAtMs",
  "expiresAtMs",
]);

const HEX64 = /^[0-9a-f]{64}$/;
const OPERATIONS = new Set(["restore", "migration"]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value, fields) {
  return isPlainObject(value) &&
    Reflect.ownKeys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field));
}

function isId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function isGeneration(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

function isTimestamp(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isHex64(value) {
  return typeof value === "string" && HEX64.test(value);
}

function assertClock(clock) {
  if (!isPlainObject(clock) || typeof clock.now !== "function") {
    throw new TypeError("restore context registry clock.now must be a function");
  }
}

function readNow(clock) {
  const now = clock.now();
  if (!isTimestamp(now)) {
    throw new TypeError("restore context registry clock.now() must return a non-negative safe integer");
  }
  return now;
}

function cloneFrozen(value) {
  if (Array.isArray(value)) {
    return Object.freeze(value.map(cloneFrozen));
  }
  if (isPlainObject(value)) {
    const copy = {};
    for (const key of Object.keys(value)) copy[key] = cloneFrozen(value[key]);
    return Object.freeze(copy);
  }
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new TypeError("restore context registry claims must contain finite JSON values");
    }
    return value;
  }
  throw new TypeError("restore context registry claims must contain JSON values");
}

function assertJsonValue(value) {
  cloneFrozen(value);
}

function assertDestinationAuthority(authority) {
  try {
    validateWorkspaceAuthorityDescriptor(authority);
  } catch {
    throw new TypeError(
      "restore context registry destination authority is invalid"
    );
  }
}

function assertExpectedAuthority(authority) {
  if (!hasExactKeys(authority, PROVENANCE_V2_FIELDS)) {
    throw new TypeError("restore context registry expectedAuthority is invalid");
  }
  if (!isId(authority.hostId) || !isId(authority.restoredFromWorkspaceId) ||
      !isGeneration(authority.restoredFromGeneration)) {
    throw new TypeError("restore context registry expectedAuthority identity is invalid");
  }
  for (const field of ["roleFingerprint", "volumeIdentityFingerprint", "keyFingerprint", "manifestFingerprint"]) {
    if (!isHex64(authority[field])) {
      throw new TypeError(`restore context registry expectedAuthority ${field} is invalid`);
    }
  }
}

function claimKey(authority, operation, idempotencyFingerprint) {
  return JSON.stringify([...DESTINATION_AUTHORITY_FIELDS.map((field) => authority[field]), operation, idempotencyFingerprint]);
}

function assertClaim(claim) {
  const fields = claim?.operation === "migration"
    ? [...CLAIM_FIELDS, "migrationKind"]
    : CLAIM_FIELDS;
  if (!hasExactKeys(claim, fields)) {
    throw new TypeError("restore context registry claim must have the exact field set");
  }
  assertDestinationAuthority(Object.fromEntries(
    DESTINATION_AUTHORITY_FIELDS.map((field) => [field, claim[field]])
  ));
  if (!OPERATIONS.has(claim.operation) || !isHex64(claim.idempotencyFingerprint) || !isId(claim.stagingPath)) {
    throw new TypeError("restore context registry claim operation, idempotencyFingerprint, or stagingPath is invalid");
  }
  if (claim.operation === "migration" && !isId(claim.migrationKind)) {
    throw new TypeError("restore context registry migrationKind is invalid");
  }
  assertExpectedAuthority(claim.expectedAuthority);
  if (!isPlainObject(claim.manifest) || !isHex64(claim.manifest.manifestFingerprint)) {
    throw new TypeError("restore context registry manifest is invalid");
  }
  if (!isId(claim.restoredFromWorkspaceId) || !isGeneration(claim.restoredFromGeneration)) {
    throw new TypeError("restore context registry restore lineage is invalid");
  }
  if (claim.expectedAuthority.manifestFingerprint !== claim.manifest.manifestFingerprint ||
      claim.expectedAuthority.restoredFromWorkspaceId !== claim.restoredFromWorkspaceId ||
      claim.expectedAuthority.restoredFromGeneration !== claim.restoredFromGeneration) {
    throw new TypeError("restore context registry provenance-v2 lineage does not match claim lineage");
  }
  if (!isPlainObject(claim.expectedGraph) || !isTimestamp(claim.probedAtMs) || !isTimestamp(claim.expiresAtMs) ||
      claim.expiresAtMs < claim.probedAtMs) {
    throw new TypeError("restore context registry claim freshness or expectedGraph is invalid");
  }
  assertJsonValue(claim.manifest);
  assertJsonValue(claim.expectedGraph);
}

function trustedAuthority(candidate) {
  if (!isPlainObject(candidate) ||
      !DESTINATION_AUTHORITY_FIELDS.every((field) => Object.hasOwn(candidate, field))) {
    return null;
  }
  const authority = Object.fromEntries(DESTINATION_AUTHORITY_FIELDS.map((field) => [field, candidate[field]]));
  try {
    assertDestinationAuthority(authority);
    return authority;
  } catch {
    return null;
  }
}

/**
 * Host-held, single-use sealed restore context claims. This registry compares a
 * trusted accepted binding but never supplies destination routing information.
 */
export function createRestoreContextRegistry({ claims, clock, maxAgeMs } = {}) {
  if (!Array.isArray(claims)) {
    throw new TypeError("restore context registry claims must be an array");
  }
  assertClock(clock);
  if (!isGeneration(maxAgeMs)) {
    throw new TypeError("restore context registry maxAgeMs must be a positive safe integer");
  }

  const entries = new Map();
  for (const claim of claims) {
    assertClaim(claim);
    if (claim.expiresAtMs - claim.probedAtMs > maxAgeMs) {
      throw new TypeError("restore context registry claim lifetime exceeds maxAgeMs");
    }
    const sealed = cloneFrozen(claim);
    const key = claimKey(sealed, sealed.operation, sealed.idempotencyFingerprint);
    const entry = entries.get(key);
    if (entry) {
      entry.status = "ambiguous";
      entry.claims.push(sealed);
    } else {
      entries.set(key, { status: "available", claims: [sealed] });
    }
  }

  function resolve({
    trustedBinding,
    message,
    operation,
    idempotencyFingerprint,
  } = {}) {
    const authority = trustedAuthority(trustedBinding);
    if (
      !authority ||
      !isPlainObject(message) ||
      !OPERATIONS.has(operation) ||
      message.operation !== operation ||
      !isHex64(idempotencyFingerprint) ||
      message.idempotencyFingerprint !== idempotencyFingerprint ||
      DESTINATION_AUTHORITY_FIELDS.slice(2).some(
        (field) => message[field] !== authority[field]
      )
    ) return null;
    const entry = entries.get(claimKey(authority, operation, idempotencyFingerprint));
    if (!entry || entry.status !== "available" || entry.claims.length !== 1) return null;
    const now = readNow(clock);
    const claim = entry.claims[0];
    if (now < claim.probedAtMs || now > claim.expiresAtMs || now - claim.probedAtMs > maxAgeMs) {
      entry.status = "expired";
      return null;
    }
    entry.status = "consumed";
    return claim;
  }

  function invalidateAuthority(trustedBinding) {
    const authority = trustedAuthority(trustedBinding);
    if (!authority) return 0;
    let invalidated = 0;
    for (const entry of entries.values()) {
      const claim = entry.claims[0];
      if (entry.status === "available" && DESTINATION_AUTHORITY_FIELDS.every((field) => claim[field] === authority[field])) {
        entry.status = "invalidated";
        invalidated += 1;
      }
    }
    return invalidated;
  }

  function snapshot() {
    const counts = { available: 0, consumed: 0, expired: 0, invalidated: 0, ambiguous: 0 };
    for (const entry of entries.values()) counts[entry.status] += 1;
    return Object.freeze({ total: entries.size, ...counts });
  }

  return Object.freeze({ resolve, invalidateAuthority, snapshot });
}

export { DESTINATION_AUTHORITY_FIELDS, PROVENANCE_V2_FIELDS };
