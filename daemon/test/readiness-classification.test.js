import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import {
  isLeaseBoundaryRejection,
  LEASE_BOUNDARY_REJECTION_CODES,
} from "../src/readiness-classification.js";

// Component-level proof of the daemon invoke-handler catch-block decision
// (daemon.js:~1533-1547) without importing daemon.js, which connects to the bot
// on import. The invoke handler routes acquireActivity's fail-closed throws
// through classifyReadinessError (which preserves any PROTOCOL_ERROR_CODES
// member) and then uses this predicate to choose the LEASE_CONFLICT-parallel
// early-return branch over the setReadinessError path.

test("WORKSPACE_ADMISSION_EXCEEDED takes the lease-boundary early-return branch", () => {
  assert.equal(
    isLeaseBoundaryRejection(PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED),
    true
  );
});

test("LEASE_CONFLICT remains a lease-boundary rejection", () => {
  assert.equal(
    isLeaseBoundaryRejection(PROTOCOL_ERROR_CODES.LEASE_CONFLICT),
    true
  );
});

test("session/readiness faults do NOT take the lease-boundary branch", () => {
  for (const code of [
    PROTOCOL_ERROR_CODES.SESSION_LIMIT,
    PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED,
    PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
    PROTOCOL_ERROR_CODES.INVENTORY_STALE,
    PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
    undefined,
    "NOT_A_CODE",
  ]) {
    assert.equal(isLeaseBoundaryRejection(code), false);
  }
});

test("lease-boundary codes are exactly the two synchronous acquisition refusals", () => {
  assert.deepEqual([...LEASE_BOUNDARY_REJECTION_CODES].sort(), [
    PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
    PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED,
  ].sort());
  assert.equal(Object.isFrozen(LEASE_BOUNDARY_REJECTION_CODES), true);
});
