import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

/**
 * Admission-boundary rejections are synchronous, request-local refusals rather
 * than durable workspace-readiness faults. The invoke handler returns them
 * directly without mutating or publishing the binding's readiness state.
 *
 *  - LEASE_CONFLICT: a stale/regressed authority tried to take an in-use lease.
 *  - WORKSPACE_ADMISSION_EXCEEDED: the host-wide active-workspace ceiling
 *    rejected a distinct workspace before session creation.
 *  - SESSION_RETIREMENT_PENDING/FAILED: canonical session ownership has not
 *    been positively retired, so this invoke is refused without poisoning the
 *    workspace's otherwise valid readiness receipt.
 *
 * Kept in its own module so the classification decision is unit-testable
 * without importing daemon.js (which connects to the bot on import).
 */
export const ADMISSION_BOUNDARY_REJECTION_CODES = Object.freeze([
  PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
  PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED,
  PROTOCOL_ERROR_CODES.SESSION_RETIREMENT_PENDING,
  PROTOCOL_ERROR_CODES.SESSION_RETIREMENT_FAILED,
]);

export function isAdmissionBoundaryRejection(errorCode) {
  return ADMISSION_BOUNDARY_REJECTION_CODES.includes(errorCode);
}
