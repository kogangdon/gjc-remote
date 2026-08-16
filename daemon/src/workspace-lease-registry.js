import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

const AUTHORITY_FIELDS = [
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
  "mappingGeneration",
  "workspaceGeneration",
  "inventoryGeneration",
];

function leaseConflict() {
  const error = new Error(PROTOCOL_ERROR_CODES.LEASE_CONFLICT);
  error.code = PROTOCOL_ERROR_CODES.LEASE_CONFLICT;
  return error;
}

function requireAuthority(candidate) {
  if (
    !candidate ||
    AUTHORITY_FIELDS.some((field) => candidate[field] === undefined) ||
    typeof candidate.workspaceId !== "string" ||
    candidate.workspaceId.length === 0 ||
    GENERATION_FIELDS.some(
      (field) =>
        !Number.isSafeInteger(candidate[field]) || candidate[field] < 0
    )
  ) {
    throw new TypeError("workspace lease authority is invalid");
  }
  return Object.freeze(
    Object.fromEntries(AUTHORITY_FIELDS.map((field) => [field, candidate[field]]))
  );
}

function sameAuthority(left, right) {
  return AUTHORITY_FIELDS.every((field) => left[field] === right[field]);
}

function regresses(previous, candidate) {
  return GENERATION_FIELDS.some((field) => candidate[field] < previous[field]);
}

function authorityChanged(previous, candidate) {
  return [
    "hostId",
    "mappingId",
    "mappingVersion",
    "sourcePlatform",
    "routeFingerprint",
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
    if (!mappingAdvanced && !inventoryAdvanced) return false;
    if (authorityChanged(previous, authority) && !mappingAdvanced) return false;

    this.authorities.set(authority.workspaceId, authority);
    const activity = this.activities.get(authority.workspaceId);
    if (activity) {
      activity.invalidated = true;
      if (activity.holders === 0) this.activities.delete(authority.workspaceId);
    }
    return true;
  }

  acquireActivity(candidate) {
    const authority = requireAuthority(candidate);
    const bindingFingerprint = candidate?.bindingFingerprint;
    if (typeof bindingFingerprint !== "string" || bindingFingerprint.length === 0) {
      throw new TypeError("workspace lease identity is invalid");
    }
    const currentAuthority = this.authorities.get(authority.workspaceId);
    if (!currentAuthority || !sameAuthority(currentAuthority, authority)) {
      throw leaseConflict();
    }

    let entry = this.activities.get(authority.workspaceId);
    if (entry) {
      if (entry.invalidated || entry.bindingFingerprint !== bindingFingerprint) {
        if (entry.holders > 0) throw leaseConflict();
        this.activities.delete(authority.workspaceId);
        entry = undefined;
      }
    }

    if (!entry) {
      this.nextFence =
        this.nextFence >= Number.MAX_SAFE_INTEGER ? 1 : this.nextFence + 1;
      entry = {
        bindingFingerprint,
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
