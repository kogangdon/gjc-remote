import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import {
  isAdmissionBoundaryRejection,
  ADMISSION_BOUNDARY_REJECTION_CODES,
} from "../src/readiness-classification.js";

// Component-level proof of the daemon invoke-handler catch-block decision
// (daemon.js:~1533-1547) without importing daemon.js, which connects to the bot
// on import. The invoke handler routes acquireActivity's fail-closed throws
// through classifyReadinessError (which preserves any PROTOCOL_ERROR_CODES
// member) and then uses this predicate to choose the request-local
// early-return branch over the setReadinessError path.

test("WORKSPACE_ADMISSION_EXCEEDED takes the admission-boundary early-return branch", () => {
  assert.equal(
    isAdmissionBoundaryRejection(PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED),
    true
  );
});

test("LEASE_CONFLICT remains an admission-boundary rejection", () => {
  assert.equal(
    isAdmissionBoundaryRejection(PROTOCOL_ERROR_CODES.LEASE_CONFLICT),
    true
  );
});

test("session retirement is an admission-boundary refusal", () => {
  assert.equal(
    isAdmissionBoundaryRejection(PROTOCOL_ERROR_CODES.SESSION_RETIREMENT_PENDING),
    true
  );
  assert.equal(
    isAdmissionBoundaryRejection(PROTOCOL_ERROR_CODES.SESSION_RETIREMENT_FAILED),
    true
  );
});

test("durable session/readiness faults do NOT take the admission-boundary branch", () => {
  for (const code of [
    PROTOCOL_ERROR_CODES.SESSION_LIMIT,
    PROTOCOL_ERROR_CODES.RESOURCE_EXHAUSTED,
    PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
    PROTOCOL_ERROR_CODES.INVENTORY_STALE,
    PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME,
    undefined,
    "NOT_A_CODE",
  ]) {
    assert.equal(isAdmissionBoundaryRejection(code), false);
  }
});

test("admission-boundary codes are exactly the request-local refusals", () => {
  assert.deepEqual([...ADMISSION_BOUNDARY_REJECTION_CODES].sort(), [
    PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
    PROTOCOL_ERROR_CODES.SESSION_RETIREMENT_FAILED,
    PROTOCOL_ERROR_CODES.SESSION_RETIREMENT_PENDING,
    PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED,
  ].sort());
  assert.equal(Object.isFrozen(ADMISSION_BOUNDARY_REJECTION_CODES), true);
});
