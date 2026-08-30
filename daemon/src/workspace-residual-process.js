// S5c -- residual-process absence guard (#53 Phase 2, reset/delete lifecycle).
//
// Before a workspace generation is torn down (reset/delete), the lifecycle
// orchestrator (S5e) must prove that NO process still holds the workspace open:
// a lingering child, a detached coding-session process, an OS handle keeping a
// directory busy. Deleting a generation out from under a live process corrupts
// the workspace and can orphan file handles, so this guard fails closed --
// absence must be affirmatively PROVEN, never assumed.
//
// Pure and dependency-injected: the caller supplies `io.listResidualProcesses`,
// the platform-specific enumerator that returns the processes still associated
// with { hostId, workspaceId }. This module never spawns, signals, or inspects
// processes itself; it only decides whether the enumerated set authorises
// destruction. The concrete enumerator (native handle/pid scan) is an S7 wiring
// concern, DI-insulated here.

import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

const OPERATION = "workspace_residual_process";
const { CONFIG_INVALID, WORKSPACE_RESIDUAL_PROCESS } = PROTOCOL_ERROR_CODES;

// The exact identity a residual-process query must carry. Both fields are
// required non-empty strings so the enumerator scopes its scan to one workspace
// on one host and can never be invoked with a partial/ambiguous target.
const RESIDUAL_PROCESS_REQUEST_KEYS = Object.freeze([
  "hostId",
  "workspaceId",
  "workDir",
  "sourcePlatform",
]);

function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (!["code", "operation", "reason", "message"].includes(key)) error[key] = value;
    }
  }
  throw error;
}

const isPlainObject = (value) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value);

const hasExactKeys = (value, keys) =>
  isPlainObject(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

const isNonEmptyString = (value) =>
  typeof value === "string" && value.length > 0;

/**
 * Prove that no process is still bound to { hostId, workspaceId } before the
 * caller is allowed to destroy the workspace generation.
 *
 * `io.listResidualProcesses({ hostId, workspaceId })` MUST return an array of
 * residual-process descriptors; each descriptor MUST be a plain object carrying
 * a positive-safe-integer `pid`. A missing enumerator, a non-array return, or a
 * malformed descriptor is a contract violation refused CONFIG_INVALID -- the
 * guard cannot certify absence it could not correctly read, so it fails closed
 * rather than treating an unreadable result as "empty". A well-formed non-empty
 * list is refused WORKSPACE_RESIDUAL_PROCESS (retryable: the operator/orchestrator
 * terminates or waits out the residual processes and retries). Only a well-formed
 * EMPTY list certifies absence.
 *
 * @param {object} io injected platform seam exposing listResidualProcesses
 * @param {{hostId: string, workspaceId: string}} request scoped query identity
 * @returns {{absent: true}} frozen certificate when no residual process exists
 */
export async function assertResidualProcessAbsence(io, request) {
  if (!isPlainObject(io) || typeof io.listResidualProcesses !== "function") {
    refuse(CONFIG_INVALID, "io.listResidualProcesses must be a function");
  }
  if (!hasExactKeys(request, RESIDUAL_PROCESS_REQUEST_KEYS)) {
    refuse(
      CONFIG_INVALID,
      `residual-process request must carry exactly ${RESIDUAL_PROCESS_REQUEST_KEYS.join(", ")}`
    );
  }
  if (
    !isNonEmptyString(request.hostId) ||
    !isNonEmptyString(request.workspaceId) ||
    !isNonEmptyString(request.workDir) ||
    !isNonEmptyString(request.sourcePlatform)
  ) {
    refuse(
      CONFIG_INVALID,
      "hostId, workspaceId, workDir, and sourcePlatform must be non-empty strings"
    );
  }

  // A rejecting enumerator is an unreadable result, not an empty one: wrap it in
  // the fail-closed envelope so it can never fall through to { absent: true }
  // and so S5e sees a uniform CONFIG_INVALID (raw error preserved as cause).
  let result;
  try {
    result = await io.listResidualProcesses({
      hostId: request.hostId,
      workspaceId: request.workspaceId,
      workDir: request.workDir,
      sourcePlatform: request.sourcePlatform,
    });
  } catch (cause) {
    refuse(CONFIG_INVALID, "listResidualProcesses failed", { cause });
  }

  if (!Array.isArray(result)) {
    refuse(CONFIG_INVALID, "listResidualProcesses must return an array");
  }
  // Descriptor validation runs BEFORE the length>0 refusal on purpose: an
  // unreadable/corrupted non-empty list means we could not READ the residual
  // set, so it is CONFIG_INVALID (non-retryable) -- never WORKSPACE_RESIDUAL_
  // PROCESS, which is retryable and would loop S5e against a broken enumerator.
  for (const [index, descriptor] of result.entries()) {
    if (
      !isPlainObject(descriptor) ||
      !Number.isSafeInteger(descriptor.pid) ||
      descriptor.pid < 1
    ) {
      refuse(
        CONFIG_INVALID,
        "each residual-process descriptor must be an object with a positive-safe-integer pid",
        { index }
      );
    }
  }

  if (result.length > 0) {
    refuse(
      WORKSPACE_RESIDUAL_PROCESS,
      "workspace still has residual processes; destruction is not authorised",
      {
        residualCount: result.length,
        pids: Object.freeze(result.map((descriptor) => descriptor.pid)),
      }
    );
  }

  return Object.freeze({ absent: true });
}

export { RESIDUAL_PROCESS_REQUEST_KEYS };
