import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import {
  emitOwnerEvent,
  isOpaqueId,
  validateOwnerObserver,
} from "./daemon-observability.js";

/** Host-wide active-workspace admission ceiling (#43). */
export const DEFAULT_MAX_ACTIVE_WORKSPACES = 8;

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

function workspaceAdmissionExceeded() {
  const error = new Error(PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED);
  error.code = PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED;
  return error;
}

function workspaceBusy() {
  const error = new Error(PROTOCOL_ERROR_CODES.WORKSPACE_BUSY);
  error.code = PROTOCOL_ERROR_CODES.WORKSPACE_BUSY;
  return error;
}

/**
 * Pure workload-quiescence guard (S5b, #53).
 *
 * A destructive lifecycle op (reset/delete/restore/migration) may only proceed
 * once the workspace is genuinely idle: no invoke is in flight and no coding
 * session is live against it. This is a distinct condition from the activity
 * fence -- the fence proves *authority currency*, this proves *workload
 * idleness* -- so it fails closed with `WORKSPACE_BUSY` on any non-zero count
 * rather than `LEASE_CONFLICT`. Pure and injected-count based: the caller
 * supplies the live counts it observed, keeping this unit free of daemon state.
 */
export function assertQuiescent({ pendingInvokes, pendingSessions } = {}) {
  for (const [name, value] of [
    ["pendingInvokes", pendingInvokes],
    ["pendingSessions", pendingSessions],
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(`assertQuiescent ${name} must be a non-negative safe integer`);
    }
  }
  if (pendingInvokes > 0 || pendingSessions > 0) {
    throw workspaceBusy();
  }
  return Object.freeze({ quiescent: true });
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
 *
 * Two distinct, independently-configured bounds live here:
 *   - `maxWorkspaces` (default 64) caps how many workspace *authorities* a
 *     socket may register via `adoptBinding` (binding/authority retention),
 *     matching `MAX_BINDINGS_PER_SOCKET`.
 *   - `maxActiveWorkspaces` (default 8) caps how many *distinct* workspaces may
 *     simultaneously hold an activity lease host-wide (the #43 active-workspace
 *     admission bound). Enforced inside `acquireActivity` for new-entry
 *     creation only, fail-closed with `WORKSPACE_ADMISSION_EXCEEDED`.
 *
 * Forward-scaffolding / dormancy note: `acquireActivity` is reached from the
 * daemon invoke handler only after the `NATIVE_WORKSPACE_SERVING_ENABLED`
 * serving gate, which is hard-disabled today. The `maxActiveWorkspaces` bound
 * is therefore dormant on the live invoke wire (exactly like the existing
 * 8-session `SessionPool` bound) and is proven at this registry's own API
 * surface, not via a live serving invoke, until a later serving-enable slice.
 */
export class WorkspaceLeaseRegistry {
  constructor({
    maxWorkspaces = 64,
    maxActiveWorkspaces = DEFAULT_MAX_ACTIVE_WORKSPACES,
    observer,
    monotonicNowFn = () => performance.now(),
  } = {}) {
    if (!Number.isSafeInteger(maxWorkspaces) || maxWorkspaces < 1) {
      throw new TypeError("maxWorkspaces must be a positive safe integer");
    }
    if (!Number.isSafeInteger(maxActiveWorkspaces) || maxActiveWorkspaces < 1) {
      throw new TypeError("maxActiveWorkspaces must be a positive safe integer");
    }
    const validatedObserver = validateOwnerObserver(observer);
    this.authorities = new Map();
    this.activities = new Map();
    this.nextFence = 0;
    this.maxWorkspaces = maxWorkspaces;
    this.maxActiveWorkspaces = maxActiveWorkspaces;
    this.observer = validatedObserver;
    this.monotonicNowFn = monotonicNowFn;
  }

  #emit(event) {
    emitOwnerEvent(this.observer, event);
  }
  #durationSince(start) {
    const duration = Math.floor(this.monotonicNowFn() - start);
    return Number.isSafeInteger(duration) && duration >= 0 ? duration : undefined;
  }
  #eventIds(authority) {
    return {
      workspaceId: isOpaqueId(authority.workspaceId) ? authority.workspaceId : undefined,
      mappingId: isOpaqueId(authority.mappingId) ? authority.mappingId : undefined,
    };
  }

  getAdmissionSnapshot() {
    let activityHolders = 0;
    let exclusiveActivityWorkspaces = 0;
    let invalidatedActivityWorkspaces = 0;
    for (const activity of this.activities.values()) {
      activityHolders += activity.holders;
      if (activity.exclusive) exclusiveActivityWorkspaces += 1;
      if (activity.invalidated) invalidatedActivityWorkspaces += 1;
    }
    return Object.freeze({
      workspaceAuthorities: this.authorities.size,
      activityWorkspaces: this.activities.size,
      activityHolders,
      exclusiveActivityWorkspaces,
      invalidatedActivityWorkspaces,
      maxWorkspaceAuthorities: this.maxWorkspaces,
      maxActiveWorkspaces: this.maxActiveWorkspaces,
    });
  }

  adoptBinding(candidate) {
    const authority = requireAuthority(candidate);
    const previous = this.authorities.get(authority.workspaceId);
    if (!previous) {
      if (this.authorities.size >= this.maxWorkspaces) {
        this.#emit({
          name: "workspace_lease_registry",
          action: "adopt",
          outcome: "denied",
          code: "WORKSPACE_ADMISSION_EXCEEDED",
          ...this.#eventIds(authority),
        });
        return false;
      }
      this.authorities.set(authority.workspaceId, authority);
      this.#emit({
        name: "workspace_lease_registry",
        action: "adopt",
        outcome: "succeeded",
        ...this.#eventIds(authority),
      });
      return true;
    }
    if (sameAuthority(previous, authority)) return true;
    if (regresses(previous, authority)) {
      this.#emit({
        name: "workspace_lease_registry",
        action: "adopt",
        outcome: "denied",
        code: "LEASE_CONFLICT",
        ...this.#eventIds(authority),
      });
      return false;
    }

    const mappingAdvanced =
      authority.mappingGeneration > previous.mappingGeneration ||
      authority.workspaceGeneration > previous.workspaceGeneration;
    const inventoryAdvanced =
      authority.inventoryGeneration > previous.inventoryGeneration;
    const fenceAdvanced =
      (authority.authorityEpoch ?? 0) > (previous.authorityEpoch ?? 0) ||
      (authority.fenceGeneration ?? 0) > (previous.fenceGeneration ?? 0) ||
      (authority.socketGeneration ?? 0) > (previous.socketGeneration ?? 0);
    if (!mappingAdvanced && !inventoryAdvanced && !fenceAdvanced) {
      this.#emit({
        name: "workspace_lease_registry",
        action: "adopt",
        outcome: "denied",
        code: "LEASE_CONFLICT",
        ...this.#eventIds(authority),
      });
      return false;
    }
    if (authorityChanged(previous, authority) && !mappingAdvanced) {
      this.#emit({
        name: "workspace_lease_registry",
        action: "adopt",
        outcome: "denied",
        code: "LEASE_CONFLICT",
        ...this.#eventIds(authority),
      });
      return false;
    }

    this.authorities.set(authority.workspaceId, authority);
    const activity = this.activities.get(authority.workspaceId);
    if (activity) {
      activity.invalidated = true;
      if (activity.holders === 0) this.activities.delete(authority.workspaceId);
    }
    this.#emit({
      name: "workspace_lease_registry",
      action: "adopt",
      outcome: "succeeded",
      ...this.#eventIds(authority),
      fenceSequence: activity?.fence,
    });
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
    const emittedIds = new Set();
    for (const [workspaceId, activity] of this.activities) {
      if (!activity.invalidated) {
        activity.invalidated = true;
        this.#emit({
          name: "workspace_lease_registry",
          action: "invalidate",
          outcome: "succeeded",
          workspaceId: isOpaqueId(workspaceId)
            ? workspaceId
            : undefined,
          fenceSequence: activity.fence,
        });
        emittedIds.add(workspaceId);
      }
      invalidatedIds.add(workspaceId);
      if (activity.holders === 0) this.activities.delete(workspaceId);
    }
    // Adopted authorities with no active activity holder are still cleared
    // below, so they belong in the returned set to keep the contract honest.
    for (const [workspaceId, authority] of this.authorities) {
      if (!emittedIds.has(workspaceId)) {
        this.#emit({
          name: "workspace_lease_registry",
          action: "invalidate",
          outcome: "succeeded",
          ...this.#eventIds(authority),
        });
      }
      invalidatedIds.add(workspaceId);
    }
    this.authorities.clear();
    return Object.freeze([...invalidatedIds]);
  }

  retireBinding(candidate) {
    const authority = requireAuthority(candidate);
    const current = this.authorities.get(authority.workspaceId);
    if (!current || !sameAuthority(current, authority)) {
      this.#emit({
        name: "workspace_lease_registry",
        action: "retire",
        outcome: "denied",
        code: "LEASE_CONFLICT",
        ...this.#eventIds(authority),
      });
      return false;
    }
    this.authorities.delete(authority.workspaceId);
    const activity = this.activities.get(authority.workspaceId);
    if (activity) {
      activity.invalidated = true;
      if (activity.holders === 0) this.activities.delete(authority.workspaceId);
    }
    this.#emit({
      name: "workspace_lease_registry",
      action: "retire",
      outcome: "succeeded",
      ...this.#eventIds(authority),
      fenceSequence: activity?.fence,
    });
    return true;
  }

  acquireActivity(candidate, { exclusive = false } = {}) {
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
      this.#emit({
        name: "workspace_lease_registry",
        action: "acquire",
        outcome: "denied",
        code: "LEASE_CONFLICT",
        ...this.#eventIds(authority),
      });
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
        if (entry.holders > 0) {
          this.#emit({
            name: "workspace_lease_registry",
            action: "acquire",
            outcome: "denied",
            code: "LEASE_CONFLICT",
            ...this.#eventIds(authority),
            fenceSequence: entry.fence,
          });
          throw leaseConflict();
        }
        this.activities.delete(authority.workspaceId);
        entry = undefined;
      }
    }

    if (!entry) {
      // Host-wide active-workspace admission (#43): a brand-new distinct active
      // workspace may only be admitted while under the ceiling. Stale entries
      // were already deleted above, so `activities.size` reflects only live
      // holders; re-admitting a stale workspaceId at capacity therefore still
      // succeeds. Fail-closed, synchronous check-then-reserve (no await between
      // the size check and entry creation), matching SessionPool/AdmissionBudget.
      if (this.activities.size >= this.maxActiveWorkspaces) {
        this.#emit({
          name: "workspace_lease_registry",
          action: "acquire",
          outcome: "denied",
          code: "WORKSPACE_ADMISSION_EXCEEDED",
          ...this.#eventIds(authority),
        });
        throw workspaceAdmissionExceeded();
      }
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
        exclusive: false,
        invalidated: false,
      };
      this.activities.set(authority.workspaceId, entry);
    }

    // Exclusive-mode gating (S5b, #53). Two fail-closed, synchronous
    // check-then-reserve rules, evaluated after stale entries were pruned above
    // so `entry.holders` counts only live holders of this exact identity:
    //   1. While an exclusive holder is live, EVERY same-identity acquisition
    //      (exclusive or not) is refused WORKSPACE_BUSY here. This is the
    //      deliberate behavioral delta from ordinary same-identity holder-
    //      stacking: exclusivity forbids re-entrant stacking too. A DIFFERENT
    //      binding identity for the same workspace never reaches this guard --
    //      it is refused earlier as LEASE_CONFLICT by the identity-mismatch
    //      block above -- so authority/identity races stay LEASE_CONFLICT while
    //      workload-not-idle stays WORKSPACE_BUSY.
    //   2. A new exclusive acquisition requires zero existing holders; any live
    //      non-exclusive holder refuses it WORKSPACE_BUSY.
    // WORKSPACE_BUSY (workload-not-idle) is intentionally distinct from the
    // LEASE_CONFLICT raised above for fence-succession / identity races.
    if (entry.exclusive && entry.holders > 0) {
      this.#emit({
        name: "workspace_lease_registry",
        action: "acquire",
        outcome: "denied",
        code: "WORKSPACE_BUSY",
        ...this.#eventIds(authority),
        fenceSequence: entry.fence,
      });
      throw workspaceBusy();
    }
    if (exclusive && entry.holders > 0) {
      this.#emit({
        name: "workspace_lease_registry",
        action: "acquire",
        outcome: "denied",
        code: "WORKSPACE_BUSY",
        ...this.#eventIds(authority),
        fenceSequence: entry.fence,
      });
      throw workspaceBusy();
    }
    if (exclusive) {
      entry.exclusive = true;
    }

    const acquiredAt = this.monotonicNowFn();
    entry.holders += 1;
    this.#emit({
      name: "workspace_lease_registry",
      action: "acquire",
      outcome: "succeeded",
      ...this.#eventIds(authority),
      fenceSequence: entry.fence,
    });
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
        this.#emit({
          name: "workspace_lease_registry",
          action: "release",
          outcome: "succeeded",
          ...this.#eventIds(authority),
          fenceSequence: entry.fence,
          durationMs: this.#durationSince(acquiredAt),
        });
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
          exclusive: activity?.exclusive ?? false,
          invalidated: activity?.invalidated ?? false,
        });
      })
    );
  }
}
