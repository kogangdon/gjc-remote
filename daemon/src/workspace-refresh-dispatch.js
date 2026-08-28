// Refresh lifecycle dispatch wiring for the native workspace data plane
// (#53 Phase 2, slice S6f.3; issue #81 native-serving boundary).
//
// THIN, PURE, dependency-injected glue that turns an authenticated lifecycle
// WIRE message (shared/protocol.js MSG_TYPES.WORKSPACE_REFRESH) into a fully
// derived refresh request and runs the already-landed pure orchestrator
// createWorkspaceRefreshOperation (S4g). It performs NO direct
// filesystem/subprocess I/O and does NOT read or flip the native-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false). Live enablement is the
// separate S7 boundary.
//
// Authorization model is identical to the S6f.2 create dispatcher: the 9-field
// lifecycle authority tuple comes ONLY from the ACCEPTED BIND_WORKSPACE binding
// (passed in as `trustedBinding`, never the message under test), verified
// strict-equal via verifyWorkspaceLifecycleAuthority. Trust in
// routeFingerprint/authorityFingerprint is trust-on-first-use (issue #179).
//
// dispatchRefresh's signature is identical to the S6f.2 create dispatcher
// ({ message, trustedBinding, trustedInventoryWorkspace, readiness }); the two
// refresh-specific inputs are derived INTERNALLY from host-held trusted state,
// never the wire message:
//   - It advances an EXISTING workspace by publishing a SUCCESSOR generation
//     chained onto the current live pointer, under a NON-EXCLUSIVE activity
//     fence (createActivityFence, S6f.1e) that must remain current through the
//     flip.
//   - The base being refreshed is the CURRENT live pointer, read via the
//     injected publisher io (readLiveGeneration). The successor generation and
//     its candidate/git directory derive as base.activeGeneration + 1; the
//     orchestrator independently re-reads the live pointer and refuses
//     WORKSPACE_GENERATION_STALE if a concurrent advance raced this read
//     (optimistic concurrency). A workspace with no published live generation
//     is refused WORKSPACE_GENERATION_STALE.
//   - The activity fence identity (leaseCandidate) is the full adopted binding
//     authority + its bindingFingerprint (what WorkspaceLeaseRegistry adopted
//     at bind time, computed from the authority descriptor + inventory
//     fingerprint the daemon held at bind). The daemon holds it and passes it
//     in as a per-call parameter; the dispatcher forwards it opaquely to
//     acquireFence and never reconstructs it (the inventory fingerprint is not
//     recoverable from the binding record alone).
//
// Reading/writing live storage (makePublisherIo) and enumerating the candidate
// manifest paths (resolveManifestPaths) are native serving low-level concerns
// (S7, issue #171); the daemon supplies them and holds a null dispatcher until
// they land, so the served branch stays inert while the gate is false.

import { join as joinPath } from "node:path";

import {
  verifyWorkspaceLifecycleAuthority,
  workspaceLifecycleAuthority,
} from "@gjc-remote/shared";

import { createWorkspaceRefreshOperation } from "./workspace-refresh-operation.js";
import { readLiveGeneration } from "./workspace-generation-publisher.js";

const OPERATION = "workspace_refresh_dispatch";

const RUNTIME_INCOMPATIBLE = "RUNTIME_INCOMPATIBLE";

const SUPPORTED_REFRESH_OPERATIONS = new Set(["refresh"]);

// Wire sourcePlatform {posix, windows-drive, windows-unc} vs materializer/
// byte-reader {posix, windows}. windows-unc is not containment-verifiable.
const MATERIALIZER_PLATFORM = Object.freeze({
  posix: "posix",
  "windows-drive": "windows",
});

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

function generationSegment(generation) {
  return String(generation).padStart(6, "0");
}

/**
 * Build the refresh lifecycle dispatcher.
 *
 * config = {
 *   workspaceRoot,          // absolute native base dir for served workspaces
 *   containment,            // S4a { identifyRoot, verifyContained }
 *   gitVerifier,            // S4b { verifyRepositoryGraph }
 *   makeManifestIo,         // (candidatePath, byteReaderPlatform) => { readBytes }
 *   makePublisherIo,        // async (workspaceId) => publishIo (S6f.1a)
 *   materialize,            // async (materializeRequest) => void (S6f.1d)
 *   resolveManifestPaths,   // async (candidatePath, platform) => string[] (S7 #171)
 *   acquireFence,           // (leaseCandidate) => lease  (createActivityFence, S6f.1e)
 *   clock,                  // { now(): number } trusted monotonic ms clock
 *   maxAgeMs,               // safe int >= 1 (daemon config; freshness window)
 *   replaySeen,             // { has, add } single-use readiness seen-set
 *   hashIdentity?,          // optional (identity) => hex64
 * }
 */
export function createLifecycleRefreshDispatcher(config = {}) {
  if (!isPlainObject(config)) throw configError("config must be an object");
  const {
    workspaceRoot,
    containment,
    gitVerifier,
    makeManifestIo,
    makePublisherIo,
    materialize,
    resolveManifestPaths,
    acquireFence,
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
  assertFn(acquireFence, "acquireFence");
  assertMethods(clock, ["now"], "clock");
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) {
    throw configError("maxAgeMs must be a safe integer >= 1 owned by daemon config");
  }
  assertMethods(replaySeen, ["has", "add"], "replaySeen");
  if (hashIdentity !== undefined && typeof hashIdentity !== "function") {
    throw configError("hashIdentity must be a function when provided");
  }

  /**
   * Authorize + derive + run one refresh. Resolves to a frozen
   * { ok:true, receipt } on success or a frozen { ok:false, code, reason }
   * refusal. Never throws for an expected refusal. Signature is identical to
   * the S6f.2 create dispatcher; the fence identity and the trusted base
   * generation are derived internally from host-held state, never the message.
   *
   * `trustedBinding` is the accepted BIND_WORKSPACE binding record for
   * message.workspaceId (daemon-resolved; the sole authority source).
   * `leaseCandidate` is the full adopted fence-authority record the daemon
   * held at bind time (authority tuple + bindingFingerprint); it is forwarded
   * opaquely to acquireFence. The base generation being refreshed is read
   * internally from the live pointer (host storage), never the message.
   */
  async function dispatchRefresh({
    message,
    trustedBinding,
    trustedInventoryWorkspace,
    leaseCandidate,
    readiness,
  } = {}) {
    if (!isPlainObject(message)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing lifecycle message");
    }
    if (!SUPPORTED_REFRESH_OPERATIONS.has(message.operation)) {
      return refuse(RUNTIME_INCOMPATIBLE, "operation is not a refresh operation");
    }

    // Guard 1: authorize the message against the trusted binding's 9-field
    // authority tuple (never the message's own claims).
    if (!isPlainObject(trustedBinding)) {
      return refuse(RUNTIME_INCOMPATIBLE, "no accepted binding for workspace");
    }
    const trusted = workspaceLifecycleAuthority(trustedBinding);
    if (!verifyWorkspaceLifecycleAuthority(message, trusted)) {
      return refuse(RUNTIME_INCOMPATIBLE, "lifecycle authority does not match the accepted binding");
    }

    // Guard 2: trusted inventory existence + source workDir, with an identity
    // cross-check against the already-verified message (defense-in-depth).
    if (!isPlainObject(trustedInventoryWorkspace) ||
        typeof trustedInventoryWorkspace.workDir !== "string" ||
        trustedInventoryWorkspace.workDir.length === 0) {
      return refuse(RUNTIME_INCOMPATIBLE, "no trusted inventory workspace for source workDir");
    }
    if (trustedInventoryWorkspace.hostId !== message.hostId ||
        trustedInventoryWorkspace.workspaceId !== message.workspaceId ||
        trustedInventoryWorkspace.sourcePlatform !== message.sourcePlatform) {
      return refuse(RUNTIME_INCOMPATIBLE, "trusted inventory identity does not match the verified message");
    }

    if (!isPlainObject(readiness)) {
      return refuse(RUNTIME_INCOMPATIBLE, "missing live readiness dimensions");
    }

    // Guard 3: the fence identity is host-held bind-time state; the wire
    // message can never supply it.
    if (leaseCandidate === null || typeof leaseCandidate !== "object") {
      return refuse(RUNTIME_INCOMPATIBLE, "missing trusted fence lease candidate");
    }

    const sourcePlatform = message.sourcePlatform;
    const materializerPlatform = MATERIALIZER_PLATFORM[sourcePlatform];
    if (!materializerPlatform) {
      return refuse("CONTAINMENT_UNSUPPORTED", `source platform ${String(sourcePlatform)} is not serveable`);
    }
    const byteReaderPlatform = materializerPlatform;

    const workspaceId = message.workspaceId;
    const workDir = trustedInventoryWorkspace.workDir;

    try {
      const publishIo = await makePublisherIo(workspaceId);
      // The base being refreshed is the CURRENT live pointer (host-held trusted
      // state; the wire message can never pin it). The successor generation and
      // its candidate/git dir derive from base + 1. The orchestrator
      // independently re-reads the live pointer and refuses
      // WORKSPACE_GENERATION_STALE if a concurrent advance raced this read
      // (optimistic concurrency).
      const live = await readLiveGeneration(publishIo);
      if (!live || !Number.isSafeInteger(live.activeGeneration) || live.activeGeneration < 1 ||
          typeof live.pointerFingerprint !== "string" || live.pointerFingerprint.length === 0) {
        return refuse("WORKSPACE_GENERATION_STALE", "no live generation is published to refresh");
      }
      const successorGeneration = live.activeGeneration + 1;
      const segment = generationSegment(successorGeneration);
      const candidatePath = joinPath(workspaceRoot, workspaceId, "generations", segment);
      const gitDir = candidatePath;
      const generationPath = `generations/${segment}`;
      const expectedPointerFingerprint = live.pointerFingerprint;

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
        acquireFence,
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
        leaseCandidate,
        expected: { pointerFingerprint: expectedPointerFingerprint },
        probedAtMs,
        readiness,
        expectedGraph: {},
      };

      const receipt = await createWorkspaceRefreshOperation(deps).runRefresh(request);
      return Object.freeze({ ok: true, receipt });
    } catch (error) {
      // error.code / reason are INTERNAL diagnostics only: the daemon wire
      // boundary whitelists the code against PROTOCOL_ERROR_CODES and never
      // serializes the reason (review S6f.2 F2). Kept precise here for tests
      // and internal logs.
      return refuse(
        typeof error?.code === "string" ? error.code : RUNTIME_INCOMPATIBLE,
        typeof error?.reason === "string" ? error.reason : "refresh operation failed",
      );
    }
  }

  return Object.freeze({ dispatchRefresh });
}
