import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

const V3_AUTHORITY_FIELDS = [
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
  "inventoryGeneration",
  "inventoryFingerprint",
];
const V2_AUTHORITY_FIELDS = [
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "routeFingerprint",
  "authorityFingerprint",
  "inventoryGeneration",
];
const GENERATION_FIELDS = [
  "authorityEpoch",
  "fenceGeneration",
  "mappingGeneration",
  "workspaceGeneration",
  "inventoryGeneration",
];
const RECEIPT_IDENTITY_FIELDS = [
  "socketGeneration",
  "bindingId",
  "bindingFingerprint",
];

function leaseConflict() {
  const error = new Error(PROTOCOL_ERROR_CODES.LEASE_CONFLICT);
  error.code = PROTOCOL_ERROR_CODES.LEASE_CONFLICT;
  return error;
}

function requireAuthority(candidate) {
  const fields = candidate?.authorityEpoch === undefined
    ? V2_AUTHORITY_FIELDS
    : V3_AUTHORITY_FIELDS;
  const generationFields = candidate?.authorityEpoch === undefined
    ? ["mappingGeneration", "workspaceGeneration", "inventoryGeneration"]
    : GENERATION_FIELDS;
  const hasReceiptIdentity =
    candidate?.authorityEpoch !== undefined ||
    candidate?.socketGeneration !== undefined;
  if (
    !candidate ||
    fields.some((field) => candidate[field] === undefined) ||
    typeof candidate.workspaceId !== "string" ||
    candidate.workspaceId.length === 0 ||
    generationFields.some(
      (field) =>
        !Number.isSafeInteger(candidate[field]) || candidate[field] < 0
    ) ||
    (hasReceiptIdentity &&
      (!RECEIPT_IDENTITY_FIELDS.every((field) => candidate[field] !== undefined) ||
        !Number.isSafeInteger(candidate.socketGeneration) ||
        candidate.socketGeneration < 1 ||
        typeof candidate.bindingId !== "string" ||
        candidate.bindingId.length === 0 ||
        !/^[0-9a-f]{64}$/.test(candidate.bindingFingerprint)))
  ) {
    throw new TypeError("workspace lease authority is invalid");
  }
  return Object.freeze(Object.fromEntries(
    [...fields, ...(hasReceiptIdentity ? RECEIPT_IDENTITY_FIELDS : [])]
      .map((field) => [field, candidate[field]])
  ));
}

function sameAuthority(left, right) {
  const fields = left?.authorityEpoch === undefined
    ? V2_AUTHORITY_FIELDS
    : V3_AUTHORITY_FIELDS;
  return [...fields, ...RECEIPT_IDENTITY_FIELDS].every(
    (field) => left[field] === right[field]
  );
}

function regresses(previous, candidate) {
  return [
    ...GENERATION_FIELDS,
    ...(previous.socketGeneration === undefined ? [] : ["socketGeneration"]),
  ].some((field) => candidate[field] < previous[field]);
}

function authorityChanged(previous, candidate) {
  return [
    "hostId",
    "mappingId",
    "mappingVersion",
    "sourcePlatform",
    ...(previous.authorityEpoch === undefined ? ["routeFingerprint"] : []),
    "authorityFingerprint",
  ].some((field) => previous[field] !== candidate[field]);
}

/**
 * Process-wide managed-binding authority and activity fence.
 *
 * This registry deliberately does not claim durable crash recovery. It closes
 * live-process replay and admission races while the final durable lifecycle
 * journal remains a separate Phase 2 gate.
 */
export class WorkspaceLeaseRegistry {
  constructor({ maxWorkspaces = 64 } = {}) {
    if (!Number.isSafeInteger(maxWorkspaces) || maxWorkspaces < 1) {
      throw new TypeError("maxWorkspaces must be a positive safe integer");
    }
    this.authorities = new Map();
    this.activities = new Map();
    this.nextFence = 0;
    this.maxWorkspaces = maxWorkspaces;
  }

  adoptBinding(candidate) {
    const authority = requireAuthority(candidate);
    const previous = this.authorities.get(authority.workspaceId);
    if (!previous) {
      if (this.authorities.size >= this.maxWorkspaces) return false;
      this.authorities.set(authority.workspaceId, authority);
      return true;
    }
    if (sameAuthority(previous, authority)) return true;
    if (regresses(previous, authority)) return false;

    const mappingAdvanced =
      authority.mappingGeneration > previous.mappingGeneration ||
      authority.workspaceGeneration > previous.workspaceGeneration;
    const inventoryAdvanced =
      authority.inventoryGeneration > previous.inventoryGeneration;
    const fenceAdvanced =
      (authority.authorityEpoch ?? 0) > (previous.authorityEpoch ?? 0) ||
      (authority.fenceGeneration ?? 0) > (previous.fenceGeneration ?? 0) ||
      (authority.socketGeneration ?? 0) > (previous.socketGeneration ?? 0);
    if (!mappingAdvanced && !inventoryAdvanced && !fenceAdvanced) return false;
    if (authorityChanged(previous, authority) && !mappingAdvanced) return false;

    this.authorities.set(authority.workspaceId, authority);
    const activity = this.activities.get(authority.workspaceId);
    if (activity) {
      activity.invalidated = true;
      if (activity.holders === 0) this.activities.delete(authority.workspaceId);
    }
    return true;
  }

  /**
   * Bulk-invalidate every managed authority and activity.
   *
   * Used by the live-inventory cascade: once the durable inventory snapshot the
   * daemon proved against has drifted, expired, or become unreadable, no prior
   * authority or in-flight activity may remain current. Clearing authorities
   * fails every subsequent adopt/acquire closed until a fresh bind re-proves
   * against the new snapshot, and marking live activities invalidated forces
   * every held lease's isCurrent() to report false. Returns the workspaceIds
   * that were invalidated.
   */
  invalidateAll() {
    const invalidatedIds = new Set();
    for (const [workspaceId, activity] of this.activities) {
      activity.invalidated = true;
      invalidatedIds.add(workspaceId);
      if (activity.holders === 0) this.activities.delete(workspaceId);
    }
    // Adopted authorities with no active activity holder are still cleared
    // below, so they belong in the returned set to keep the contract honest.
    for (const workspaceId of this.authorities.keys()) {
      invalidatedIds.add(workspaceId);
    }
    this.authorities.clear();
    return Object.freeze([...invalidatedIds]);
  }

  retireBinding(candidate) {
    const authority = requireAuthority(candidate);
    const current = this.authorities.get(authority.workspaceId);
    if (!current || !sameAuthority(current, authority)) return false;
    this.authorities.delete(authority.workspaceId);
    const activity = this.activities.get(authority.workspaceId);
    if (activity) {
      activity.invalidated = true;
      if (activity.holders === 0) this.activities.delete(authority.workspaceId);
    }
    return true;
  }

  acquireActivity(candidate) {
    const authority = requireAuthority(candidate);
    const receipt = authority.socketGeneration !== undefined;
    const legacyBindingFingerprint = candidate?.bindingFingerprint;
    if (
      !receipt &&
      (typeof legacyBindingFingerprint !== "string" ||
        legacyBindingFingerprint.length === 0)
    ) {
      throw new TypeError("workspace lease identity is invalid");
    }
    const currentAuthority = this.authorities.get(authority.workspaceId);
    if (!currentAuthority || !sameAuthority(currentAuthority, authority)) {
      throw leaseConflict();
    }

    let entry = this.activities.get(authority.workspaceId);
    if (entry) {
      if (
        entry.invalidated ||
        entry.receipt !== receipt ||
        (receipt &&
          (entry.socketGeneration !== authority.socketGeneration ||
            entry.bindingId !== authority.bindingId ||
            entry.bindingFingerprint !== authority.bindingFingerprint)) ||
        (!receipt && entry.bindingFingerprint !== legacyBindingFingerprint)
      ) {
        if (entry.holders > 0) throw leaseConflict();
        this.activities.delete(authority.workspaceId);
        entry = undefined;
      }
    }

    if (!entry) {
      this.nextFence =
        this.nextFence >= Number.MAX_SAFE_INTEGER ? 1 : this.nextFence + 1;
      entry = {
        receipt,
        socketGeneration: authority.socketGeneration,
        bindingId: authority.bindingId,
        bindingFingerprint: receipt
          ? authority.bindingFingerprint
          : legacyBindingFingerprint,
        fence: this.nextFence,
        holders: 0,
        invalidated: false,
      };
      this.activities.set(authority.workspaceId, entry);
    }

    entry.holders += 1;
    let released = false;
    return Object.freeze({
      fence: entry.fence,
      isCurrent: () =>
        !released &&
        !entry.invalidated &&
        this.activities.get(authority.workspaceId) === entry &&
        sameAuthority(this.authorities.get(authority.workspaceId), authority),
      release: () => {
        if (released) return;
        released = true;
        entry.holders -= 1;
        if (entry.holders === 0) this.activities.delete(authority.workspaceId);
      },
    });
  }

  snapshot() {
    return Object.freeze(
      [...this.authorities.values()].map((authority) => {
        const activity = this.activities.get(authority.workspaceId);
        return Object.freeze({
          workspaceId: authority.workspaceId,
          workspaceGeneration: authority.workspaceGeneration,
          mappingGeneration: authority.mappingGeneration,
          inventoryGeneration: authority.inventoryGeneration,
          fence: activity?.fence,
          holders: activity?.holders ?? 0,
          invalidated: activity?.invalidated ?? false,
        });
      })
    );
  }
}
