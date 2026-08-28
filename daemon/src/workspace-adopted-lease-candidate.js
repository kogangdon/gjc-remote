// Adopted workspace-lease fence identity (issue #182; #53 Phase 2 / #81).
//
// The activity fence in WorkspaceLeaseRegistry.acquireActivity matches a
// candidate by the SAME identity it adopted at bind time. For a receipt-mode
// (V3) binding that identity is the projected V3 authority PLUS the
// receipt-activity identity (`socketGeneration`, `bindingId`, and the
// inventory-fingerprint-derived `proof.bindingFingerprint`); for a legacy (V2)
// binding it is the flat binding record plus the legacy 11-field
// `bindingFingerprint` hash.
//
// Reconstructing a receipt binding's candidate by recomputing the legacy
// `bindingFingerprint` (the pre-#182 buildXLeaseCandidate helpers) produced the
// WRONG fingerprint and lacked `socketGeneration`, so a served destructive-op
// fence would fail closed (LEASE_CONFLICT). These helpers instead source the
// candidate from the live per-connection binding state exactly the way the
// INVOKE admission path does, so the lifecycle dispatchers and the invoke path
// share one fence-identity definition.
//
// Pure + dependency-injected (`computeLegacyBindingFingerprint` is the daemon's
// own legacy hash). No fs, no daemon boot: unit-testable in isolation.

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Project the V3 receipt authority tuple from a binding message. Verbatim shape
 * of the daemon's former internal `receiptAuthority`.
 */
export function projectReceiptAuthority(message) {
  const {
    authorityEpoch,
    fenceGeneration,
    hostId,
    mappingId,
    mappingGeneration,
    mappingVersion,
    workspaceId,
    workspaceGeneration,
    sourcePlatform,
    authorityFingerprint,
  } = message;
  return {
    authorityEpoch,
    fenceGeneration,
    hostId,
    mappingId,
    mappingGeneration,
    workspaceGeneration,
    mappingVersion,
    sourcePlatform,
    workspaceId,
    authorityFingerprint,
  };
}

/**
 * Resolve the receipt-activity identity ({ socketGeneration, bindingId,
 * bindingFingerprint }) for a receipt-mode binding state, or undefined when the
 * binding is not a receipt binding or the identity is not fully proven.
 * Fail-closed: a missing/short socketGeneration, absent bindingId, or a
 * non-hex64 proof fingerprint yields undefined (the caller then treats the
 * binding as legacy or refuses).
 */
export function resolveReceiptActivityIdentity(socketGeneration, bindingState) {
  const bindingFingerprintValue = bindingState?.proof?.bindingFingerprint;
  if (
    !bindingState?.receipt ||
    !Number.isSafeInteger(socketGeneration) ||
    socketGeneration < 1 ||
    typeof bindingState.binding?.bindingId !== "string" ||
    !HEX64.test(bindingFingerprintValue ?? "")
  ) {
    return undefined;
  }
  return Object.freeze({
    socketGeneration,
    bindingId: bindingState.binding.bindingId,
    bindingFingerprint: bindingFingerprintValue,
  });
}

/**
 * Build the adopted activity-fence lease candidate for a binding state, matching
 * the INVOKE admission path's construction exactly:
 *   { ...(receipt ? projectReceiptAuthority(binding) : binding),
 *     bindingFingerprint: receiptIdentity?.bindingFingerprint ?? legacyHash,
 *     ...(receiptIdentity ?? {}) }
 *
 * Fail-closed: returns null when the binding state is missing/malformed, the
 * legacy hash fn is absent/throws, or the resolved fingerprint is not hex64.
 */
export function buildAdoptedLeaseCandidate({ socketGeneration, bindingState, computeLegacyBindingFingerprint } = {}) {
  const binding = bindingState?.binding;
  if (binding === null || typeof binding !== "object") return null;
  if (typeof computeLegacyBindingFingerprint !== "function") return null;

  const receiptIdentity = resolveReceiptActivityIdentity(socketGeneration, bindingState);
  let bindingFingerprint;
  if (receiptIdentity) {
    bindingFingerprint = receiptIdentity.bindingFingerprint;
  } else {
    try {
      bindingFingerprint = computeLegacyBindingFingerprint(binding);
    } catch {
      return null;
    }
  }
  if (typeof bindingFingerprint !== "string" || !HEX64.test(bindingFingerprint)) return null;

  const authority = bindingState.receipt ? projectReceiptAuthority(binding) : { ...binding };
  return Object.freeze({ ...authority, bindingFingerprint, ...(receiptIdentity ?? {}) });
}

/**
 * Resolve the adopted lease candidate for a workspaceId from the per-connection
 * binding-state map, mirroring resolveTrustedCreateBinding's unambiguous
 * single-match discipline (two bindings claiming one workspaceId -> null).
 */
export function resolveAdoptedLeaseCandidateForWorkspace({ bindings, socketGeneration, workspaceId, computeLegacyBindingFingerprint } = {}) {
  if (!bindings || typeof bindings[Symbol.iterator] !== "function") return null;
  if (typeof workspaceId !== "string" || workspaceId.length === 0) return null;
  let match = null;
  for (const [, bindingState] of bindings) {
    if (bindingState?.binding?.workspaceId === workspaceId) {
      if (match !== null) return null; // ambiguous: two bindings, one workspaceId
      match = bindingState;
    }
  }
  if (match === null) return null;
  return buildAdoptedLeaseCandidate({ socketGeneration, bindingState: match, computeLegacyBindingFingerprint });
}
