// Create/clone lifecycle dispatch wiring for the native workspace data plane
// (#53 Phase 2, slice S6f.2; issue #81 native-serving boundary).
//
// This module is the THIN, PURE, dependency-injected glue that turns an
// authenticated lifecycle WIRE message (shared/protocol.js MSG_TYPES
// .WORKSPACE_CREATE) into a fully-derived create/clone request and runs the
// already-landed pure orchestrator createWorkspaceCreateOperation (S4f). It
// performs NO direct filesystem/subprocess I/O itself and does NOT read or flip
// the native-workspace-serving gate (NATIVE_WORKSPACE_SERVING_ENABLED stays
// false). daemon.js constructs one dispatcher at boot ONLY when both a native
// containment capability and a workspace root are available; otherwise create
// stays refused. Live enablement is the separate S7 boundary.
//
// Authorization model (#44 sole route authority; established by the S6f.2
// trusted-authority-source review, thrice-converged):
//   The 9-field lifecycle authority tuple CANNOT be built from the workspace
//   inventory record (which holds only hostId/workspaceId/sourcePlatform/
//   workDir + two identity fingerprints) nor from daemon readiness state
//   (which lacks routeFingerprint/authorityFingerprint). The ONLY host-held,
//   already-authorized source of all 9 fields is the ACCEPTED BIND_WORKSPACE
//   binding record for that workspaceId -- itself authorized against trusted
//   inventory by acceptWorkspaceBinding and fenced by WorkspaceLeaseRegistry
//   .adoptBinding. The dispatcher therefore:
//     1. requires the daemon to have resolved the trusted binding via its own
//        per-connection accepted-binding state and passed it in as
//        `trustedBinding` (NEVER the message under test), refusing if none is
//        active;
//     2. verifies the message's 9 fields strict-equal that binding-derived
//        tuple via verifyWorkspaceLifecycleAuthority -- a message can never
//        self-authorize;
//     3. uses the trusted inventory workspace ONLY for existence + source
//        workDir, never for authority-tuple fields.
//   Trust in routeFingerprint/authorityFingerprint is trust-on-first-use
//   (TOFU): the daemon adopts the bot-verified fingerprints at first bind over
//   the HOST_TOKEN-authenticated channel and enforces continuity + monotonic
//   fencing thereafter; it does not independently re-verify the mapping
//   envelope (envelope verification is bot-side). Daemon-side independent
//   verification is the deferred hardening tracked in issue #179.

import { join as joinPath } from "node:path";

import {
  verifyWorkspaceLifecycleAuthority,
  workspaceLifecycleAuthority,
} from "@gjc-remote/shared";

import { createWorkspaceCreateOperation } from "./workspace-create-operation.js";

const OPERATION = "workspace_create_dispatch";

// Reused protocol refusal code for an unauthorized / not-yet-serveable create.
const RUNTIME_INCOMPATIBLE = "RUNTIME_INCOMPATIBLE";

const SUPPORTED_CREATE_OPERATIONS = new Set(["create", "clone"]);

// Wire-message sourcePlatform vocabulary (BINDING_SOURCE_PLATFORMS) is
// {posix, windows-drive, windows-unc}. The git materializer and the contained
// byte reader speak {posix, windows}. windows-unc is not containment-verifiable
// and is refused up front.
// null-prototype map (issue #184): a wire sourcePlatform can never resolve an
// inherited Object.prototype key (constructor/__proto__) to a truthy non-string.
const MATERIALIZER_PLATFORM = Object.freeze(
  Object.assign(Object.create(null), {
    posix: "posix",
    "windows-drive": "windows",
  }),
);

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

function configError(reason) {
  const error = new Error(`${OPERATION}: CONFIG_INVALID: ${reason}`);
  error.code = "CONFIG_INVALID";
  error.operation = OPERATION;
  error.reason = reason;
  return error;
}

function refuse(code, reason) {
  return Object.freeze({ ok: false, code, reason });
}

function assertFn(value, name) {
  if (typeof value !== "function") throw configError(`${name} must be a function`);
}

function assertMethods(container, methods, name) {
  if (!isPlainObject(container) && typeof container !== "object") {
    throw configError(`${name} must be an object`);
  }
  for (const method of methods) {
    if (!container || typeof container[method] !== "function") {
      throw configError(`${name}.${method} must be a function`);
    }
  }
}

// Zero-padded generation directory segment (matches the S4d pointer
// convention, e.g. generation 2 -> "000002").
function generationSegment(generation) {
  return String(generation).padStart(6, "0");
}

/**
 * Build the create/clone lifecycle dispatcher.
 *
 * config = {
 *   workspaceRoot,          // absolute native base dir for served workspaces
 *   containment,            // S4a instance { identifyRoot, verifyContained }
 *   gitVerifier,            // S4b instance { verifyRepositoryGraph }
 *   makeManifestIo,         // (candidatePath, byteReaderPlatform) => { readBytes }
 *   makePublisherIo,        // async (workspaceId) => publishIo (S4d io)
 *   materialize,            // async (request) => void (S6f.1d clone/init seam)
 *   resolveManifestPaths,   // async (candidatePath, byteReaderPlatform) => string[]
 *                           //   trusted, non-empty; the real candidate-tree
 *                           //   enumeration is an S7 native concern.
 *   clock,                  // { now(): number } trusted monotonic ms clock
 *   maxAgeMs,               // daemon-config readiness freshness bound
 *   replaySeen,             // { has(fp), add(fp) } single-use seen-set
 *   hashIdentity?,          // optional (identity) => hex64
 * }
 */
export function createLifecycleCreateDispatcher(config = {}) {
  if (!isPlainObject(config)) {
    throw configError("createLifecycleCreateDispatcher requires a config object");
  }
  const {
    workspaceRoot,
    containment,
    gitVerifier,
    makeManifestIo,
    makePublisherIo,
    materialize,
    resolveManifestPaths,
    clock,
    maxAgeMs,
    replaySeen,
    hashIdentity,
  } = config;

  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    throw configError("workspaceRoot must be a non-empty string");
  }
  assertMethods(containment, ["identifyRoot", "verifyContained"], "containment");
  assertMethods(gitVerifier, ["verifyRepositoryGraph"], "gitVerifier");
  assertFn(makeManifestIo, "makeManifestIo");
  assertFn(makePublisherIo, "makePublisherIo");
  assertFn(materialize, "materialize");
  assertFn(resolveManifestPaths, "resolveManifestPaths");
  assertMethods(clock, ["now"], "clock");
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) {
    throw configError("maxAgeMs must be a safe integer >= 1 owned by daemon config");
  }
  assertMethods(replaySeen, ["has", "add"], "replaySeen");
  if (hashIdentity !== undefined && typeof hashIdentity !== "function") {
    throw configError("hashIdentity must be a function when provided");
  }


  /**
   * Authorize + derive + run one create/clone. Resolves to a frozen
   * { ok:true, receipt } on success or a frozen { ok:false, code, reason }
   * refusal. Never throws for an expected refusal; a truly unexpected internal
   * fault is also captured into a fail-closed refusal.
   *
   * `trustedBinding` is the daemon's per-connection ACCEPTED BIND_WORKSPACE
   * binding record for message.workspaceId (the daemon resolves it from its own
   * per-connection binding state and passes it in; it is NEVER the message under
   * test). It is the sole source of the 9 authority fields.
   */
  async function dispatchCreate({ message, trustedBinding, trustedInventoryWorkspace, readiness } = {}) {
    if (!isPlainObject(message)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing lifecycle message");
    }
    if (!SUPPORTED_CREATE_OPERATIONS.has(message.operation)) {
      return refuse(RUNTIME_INCOMPATIBLE, "operation is not a create/clone operation");
    }

    // Guard 1: an accepted, active binding for this workspaceId must have been
    // resolved by the daemon. Its 9 authority fields are the trusted tuple
    // (never the message's own).
    if (!isPlainObject(trustedBinding)) {
      return refuse(RUNTIME_INCOMPATIBLE, "no accepted binding for workspace");
    }
    // Project EXACTLY the 9 authority fields from the accepted binding, so the
    // strict exact-field verify (which rejects extra keys) sees only them.
    const trusted = workspaceLifecycleAuthority(trustedBinding);
    if (!verifyWorkspaceLifecycleAuthority(message, trusted)) {
      return refuse(RUNTIME_INCOMPATIBLE, "lifecycle authority does not match the accepted binding");
    }

    // Guard 2: the workspace must exist in trusted inventory (physical/workDir
    // trust for request derivation). Authority-tuple fields never come from here.
    if (!isPlainObject(trustedInventoryWorkspace) ||
        typeof trustedInventoryWorkspace.workDir !== "string" ||
        trustedInventoryWorkspace.workDir.length === 0) {
      return refuse(RUNTIME_INCOMPATIBLE, "no trusted inventory workspace for source workDir");
    }
    // Defense-in-depth (review S6f.2 LOW): the inventory record's identity must
    // agree with the already-verified message identity before its workDir is
    // trusted for derivation. The current caller resolves inventory by these
    // same fields, so this only fails closed on a future mis-wired caller.
    if (trustedInventoryWorkspace.hostId !== message.hostId ||
        trustedInventoryWorkspace.workspaceId !== message.workspaceId ||
        trustedInventoryWorkspace.sourcePlatform !== message.sourcePlatform) {
      return refuse(RUNTIME_INCOMPATIBLE, "trusted inventory identity does not match the verified message");
    }

    if (!isPlainObject(readiness)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing live readiness dimensions");
    }

    const sourcePlatform = message.sourcePlatform;
    const materializerPlatform = MATERIALIZER_PLATFORM[sourcePlatform];
    if (!materializerPlatform) {
      // windows-unc (or any non-containment-verifiable platform) is refused.
      return refuse("CONTAINMENT_UNSUPPORTED", `source platform ${String(sourcePlatform)} is not serveable`);
    }
    const byteReaderPlatform = materializerPlatform; // reader speaks {posix, windows}

    const workspaceId = message.workspaceId;
    const activeGeneration = message.workspaceGeneration;
    const segment = generationSegment(activeGeneration);
    const candidatePath = joinPath(workspaceRoot, workspaceId, "generations", segment);
    const gitDir = candidatePath;
    // Pointer path is workspace-relative POSIX (S4d separator convention).
    const generationPath = `generations/${segment}`;
    const workDir = trustedInventoryWorkspace.workDir;

    try {
      const publishIo = await makePublisherIo(workspaceId);
      const manifestPaths = await resolveManifestPaths(candidatePath, byteReaderPlatform);
      if (!Array.isArray(manifestPaths) || manifestPaths.length === 0) {
        return refuse(RUNTIME_INCOMPATIBLE, "no trusted manifest paths for candidate");
      }
      const manifestIo = makeManifestIo(candidatePath, byteReaderPlatform);
      assertMethods(manifestIo, ["readBytes"], "manifestIo");

      const deps = {
        containment,
        gitVerifier,
        manifestIo,
        publishIo,
        materialize,
        clock,
        maxAgeMs,
        replaySeen,
        ...(hashIdentity ? { hashIdentity } : {}),
      };

      const probedAtMs = clock.now();
      const request = {
        operation: message.operation,
        hostId: message.hostId,
        workspaceId,
        sourcePlatform,
        workDir,
        generationPath,
        candidatePath,
        gitDir,
        manifestPaths,
        activeGeneration,
        probedAtMs,
        readiness,
        // A create/clone establishes the workspace's first served generation;
        // successor chaining onto a prior generation is the refresh (S6f.3)
        // concern, so create publishes with no prior pointer.
        priorGeneration: null,
        priorPointerFingerprint: null,
        expectedGraph: {},
      };

      const receipt = await createWorkspaceCreateOperation(deps).runCreateClone(request);
      return Object.freeze({ ok: true, receipt });
    } catch (error) {
      // error.code / reason are INTERNAL diagnostics only: the daemon wire
      // boundary whitelists the code against PROTOCOL_ERROR_CODES and never
      // serializes the reason (review S6f.2 F2). Kept precise here for tests
      // and internal logs.
      return refuse(
        typeof error?.code === "string" ? error.code : RUNTIME_INCOMPATIBLE,
        typeof error?.reason === "string" ? error.reason : (error?.message ?? "create dispatch failed"),
      );
    }
  }

  return Object.freeze({ dispatchCreate });
}
