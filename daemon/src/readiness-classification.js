import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

/**
 * Lease-boundary rejections are synchronous refusals raised at the
 * lease-acquisition boundary itself (WorkspaceLeaseRegistry.acquireActivity),
 * not downstream session/readiness-state faults. The invoke handler returns
 * them directly as a fail-closed readiness error WITHOUT mutating the binding's
 * readiness state (no setReadinessError/publishReadiness), exactly like the
 * pre-existing LEASE_CONFLICT early-return branch.
 *
 *  - LEASE_CONFLICT: a stale/regressed authority tried to take an in-use lease.
 *  - WORKSPACE_ADMISSION_EXCEEDED: the host-wide active-workspace ceiling (#43)
 *    fail-closed a new distinct workspace before session creation.
 *
 * Kept in its own module so the classification decision is unit-testable
 * without importing daemon.js (which connects to the bot on import).
 */
export const LEASE_BOUNDARY_REJECTION_CODES = Object.freeze([
  PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
  PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED,
]);

export function isLeaseBoundaryRejection(errorCode) {
  return LEASE_BOUNDARY_REJECTION_CODES.includes(errorCode);
}
