// S7.3 -- native residual-process enumeration IO adapter (#171 / #53 Phase 2).
//
// Bridges the pure absence guard (assertResidualProcessAbsence, S5c) to the
// signed native scanner (createResidualProcessEnumerator ->
// enumerate_workspace_process_holders, S7.2). The absence guard's seam passes
// only { hostId, workspaceId }, so this adapter carries the boot-fixed serving
// identity -- this host's id, the contained workspaceRoot, and the host path
// format -- needed to turn that scoped identity into the exact contained
// workspace directory the native scan targets:
//
//     workDir = join(workspaceRoot, workspaceId)
//
// It is deliberately thin: it computes workDir and forwards to the native scan,
// which already returns the [{ pid }] descriptor shape the absence guard
// validates. It performs NO process I/O itself and never re-shapes or swallows
// the native result.
//
// Fail-closed on every axis, because a wrong or loose answer authorises
// irreversible workspace destruction:
//   - the request hostId MUST equal this daemon's own bound hostId; residual
//     processes are host-local, so a scan for a different host cannot be
//     certified here and is refused rather than answered against the wrong host.
//   - workspaceId MUST be a single safe path segment (no separators, no '.' or
//     '..', no NUL, not drive-qualified); it is joined into a path whose scan
//     result authorises destruction, so a traversing id must never redirect the
//     scan at another directory.
//   - native refusals (CONTAINMENT_UNSUPPORTED off Linux, INVENTORY_INVALID,
//     WORKSPACE_RESIDUAL_SCAN_FAILED) propagate UNWRAPPED; assertResidual-
//     ProcessAbsence catches them as a fail-closed CONFIG_INVALID (an
//     unreadable scan is never treated as an empty holder set).

import { posix, win32 } from "node:path";
import { relativeComponents } from "./workspace-containment.js";

// The host path formats the native scan understands. windows-unc is excluded:
// it is not containment-verifiable, and the S7.2 scan is Linux-only ("posix")
// today (windows-drive fails closed with CONTAINMENT_UNSUPPORTED until S7.2b).
const SERVING_SOURCE_PLATFORMS = Object.freeze(["posix", "windows-drive"]);

function configError(reason) {
  const error = new Error(reason);
  error.code = "CONFIG_INVALID";
  error.reason = reason;
  return error;
}

const isNonEmptyString = (value) => typeof value === "string" && value.length > 0;

// A workspaceId safe to join into a filesystem path: a single segment with no
// path separators, not '.'/'..', no NUL, no colon (drive prefix or NTFS
// alternate-data-stream 'ws:stream' syntax), and no trailing '.'/' ' (Windows
// strips these, aliasing 'ws.' -> 'ws'). This is defence in depth over the
// authenticated binding, on the destruction-authorising path, and is pinned
// now so it is already tight when S7.2b enables the windows-drive scan.
const isSafeWorkspaceSegment = (value) =>
  isNonEmptyString(value) &&
  value !== "." &&
  value !== ".." &&
  !value.includes("/") &&
  !value.includes("\\") &&
  !value.includes("\0") &&
  !value.includes(":") &&
  !value.endsWith(".") &&
  !value.endsWith(" ");

/**
 * Build the native residual-process enumeration IO for the reset/delete deps
 * bundle.
 *
 * @param {object} params
 * @param {{enumerate_workspace_process_holders: Function}} params.enumerator
 *   the least-privilege native projection (createResidualProcessEnumerator).
 * @param {string} params.hostId this daemon's own bound host id.
 * @param {string} params.workspaceRoot the contained serving root.
 * @param {"posix"|"windows-drive"} params.sourcePlatform the host path format.
 * @returns {{listResidualProcesses: (request: {hostId: string, workspaceId: string}) => Promise<Array<{pid: number}>>}}
 */
export function createResidualProcessNativeIo({ enumerator, hostId, workspaceRoot, sourcePlatform } = {}) {
  if (
    enumerator === null ||
    typeof enumerator !== "object" ||
    typeof enumerator.enumerate_workspace_process_holders !== "function"
  ) {
    throw configError("enumerator.enumerate_workspace_process_holders must be a function");
  }
  if (!isNonEmptyString(hostId)) throw configError("hostId must be a non-empty string");
  if (!isNonEmptyString(workspaceRoot)) throw configError("workspaceRoot must be a non-empty string");
  if (!SERVING_SOURCE_PLATFORMS.includes(sourcePlatform)) {
    throw configError(`sourcePlatform must be one of ${SERVING_SOURCE_PLATFORMS.join(", ")}`);
  }
  const boundHostId = hostId;

  return Object.freeze({
    async listResidualProcesses(request) {
      if (request === null || typeof request !== "object") {
        throw configError("residual-process request must be an object");
      }
      if (request.hostId !== boundHostId) {
        throw configError("residual-process request hostId does not match this host");
      }
      if (!isSafeWorkspaceSegment(request.workspaceId)) {
        throw configError("workspaceId must be a single safe path segment");
      }
      if (
        request.sourcePlatform !== sourcePlatform ||
        !isNonEmptyString(request.workDir)
      ) {
        throw configError("residual-process request path identity is invalid");
      }
      relativeComponents(workspaceRoot, request.workDir, sourcePlatform);
      const expectedWorkDir = sourcePlatform === "posix"
        ? posix.join(workspaceRoot, request.workspaceId)
        : win32.join(workspaceRoot, request.workspaceId);
      if (request.workDir !== expectedWorkDir) {
        throw configError(
          "trusted inventory workDir does not equal the native workspace path"
        );
      }
      return enumerator.enumerate_workspace_process_holders(
        request.workDir,
        sourcePlatform
      );
    },
  });
}
