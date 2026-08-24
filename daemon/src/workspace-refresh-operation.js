// Refresh workspace data-plane operation for the native workspace data plane
// (#53 Phase 2, slice S4g).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations
// -> Refresh row): a refresh generation publication is admissible ONLY when
// every one of these holds:
//   1. Prompt / read fencing                          (activity lease seam)
//   2. Expected mapping / workspace generation         (live pointer == expected base)
//   3. Full graph / ref / OID proof                    (S4b git-graph-verification)
//   4. Post-operation identity check                   (S4a workspace-containment)
//   5. Prior-generation preservation on failure        (S4d workspace-generation-publisher)
//
// Refresh differs from create/clone (S4f): it advances an EXISTING workspace by
// publishing a SUCCESSOR generation chained onto the current live pointer, under
// an activity fence that must remain current through to publish so a concurrent
// prompt / read / invalidation cannot race the flip. The base generation the
// refresh builds on is pinned by an optimistic expected-generation check, and
// the successor generation number is DERIVED from the live pointer (never taken
// from the requester).
//
// This module is a PURE dependency-injected orchestrator: every side effect
// (native root facts, git subprocess, byte reads, the fetch/merge
// materialisation, the live-pointer flip, the activity fence, the clock) is
// injected. It performs no direct filesystem, subprocess, or network I/O
// itself, does NOT read or flip the native-workspace-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false), and is NOT wired into
// daemon.js request dispatch. Live enablement is the separate S7 boundary.
//
// Prior-generation preservation (Final-obligations guarantee): the atomic
// generation publication (step 5, CAS onto the live pointer) is the SOLE
// mutation of the live pointer, and it is itself old-or-new atomic (S4d). Any
// refusal in steps 1-4 -- including a lost fence at either recheck or a stale
// base generation -- therefore leaves the prior live generation exactly intact.
//
// Anti-replay seam contract (owed to S4e): this orchestrator sources `nowMs`
// from a trusted monotonic clock (never the requester), owns `maxAgeMs` from
// daemon config (never requester input), and enforces single-use of every
// readiness attestation through an injected seen-set, refusing reuse with
// READINESS_REPLAYED.

import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared/protocol";

import { computeManifestEntries, buildWorkspaceManifest } from "./workspace-backup-manifest.js";
import { buildGenerationPointer, publishGeneration, readLiveGeneration } from "./workspace-generation-publisher.js";
import { evaluateGenerationReadiness } from "./workspace-generation-probe.js";

const OPERATION = "workspace_refresh";

// The four non-workspace readiness dimensions supplied from the live daemon
// status. The workspace dimension is assembled by this orchestrator from the
// proofs it computes, so it is never accepted from the caller.
const CALLER_DIMENSIONS = ["connection", "runtime", "providerAuth", "modelProfile"];

// Bounds for canonicalising a native identity object into a hex64 fingerprint.
const IDENTITY_LIMITS = Object.freeze({ maxBytes: 16 * 1024, maxDepth: 4, maxNodes: 64 });

/** Refuse with a structured error carrying a protocol `.code`. */
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
  value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

function assertFn(container, name, path) {
  if (!container || typeof container[name] !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `${path}.${name} must be a function`);
  }
}

/**
 * Build a refresh operation bound to its injected collaborators.
 *
 * deps = {
 *   containment,   // S4a instance: { identifyRoot, verifyContained }
 *   gitVerifier,   // S4b instance: { verifyRepositoryGraph }
 *   manifestIo,    // S4c io:       { readBytes(relPath) }
 *   publishIo,     // S4d io:       { readLivePointer, writeTemp, flushTemp, replace, flushParent }
 *   materialize,   // async (request) => void: performs the fetch/merge into the candidate dir
 *   acquireFence,  // (leaseCandidate) => { fence, isCurrent(): boolean, release(): void }
 *                  //   the WorkspaceLeaseRegistry.acquireActivity activity fence; throws
 *                  //   LEASE_CONFLICT / WORKSPACE_ADMISSION_EXCEEDED on acquisition failure.
 *   clock,         // { now(): number } trusted monotonic ms clock (NOT requester-sourced)
 *   maxAgeMs,      // daemon-config readiness freshness bound (NOT requester-sourced)
 *   replaySeen,    // { has(fp), add(fp) } single-use seen-set for readinessFingerprint
 *   hashIdentity?, // optional (identity)=>hex64; defaults to canonicalJsonHash
 * }
 *
 * replaySeen bounding contract (owned by the S7 daemon wiring, not this seam):
 * the injected seen-set is grow-only here and MUST be bounded/evicted by the
 * wiring in step with the freshness window. add-before-publish means a failed
 * publish permanently burns its attestation (fail-closed).
 */
export function createWorkspaceRefreshOperation(deps = {}) {
  if (!isPlainObject(deps)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "createWorkspaceRefreshOperation requires a deps object");
  }
  const { containment, gitVerifier, manifestIo, publishIo, materialize, acquireFence, clock, replaySeen } = deps;

  assertFn(containment, "identifyRoot", "containment");
  assertFn(containment, "verifyContained", "containment");
  assertFn(gitVerifier, "verifyRepositoryGraph", "gitVerifier");
  assertFn(manifestIo, "readBytes", "manifestIo");
  for (const method of ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"]) {
    assertFn(publishIo, method, "publishIo");
  }
  if (typeof materialize !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "materialize must be a function");
  }
  if (typeof acquireFence !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "acquireFence must be a function");
  }
  assertFn(clock, "now", "clock");
  assertFn(replaySeen, "has", "replaySeen");
  assertFn(replaySeen, "add", "replaySeen");

  const maxAgeMs = deps.maxAgeMs;
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "maxAgeMs must be a safe integer >= 1 owned by daemon config");
  }
  const hashIdentity = deps.hashIdentity ?? ((identity) => canonicalJsonHash(identity, IDENTITY_LIMITS));
  if (typeof hashIdentity !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "hashIdentity must be a function");
  }

  function assertRequest(request) {
    if (!isPlainObject(request)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request must be an object");
    }
    if (request.operation !== "refresh") {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "operation must be 'refresh'");
    }
    for (const key of ["hostId", "workspaceId", "sourcePlatform", "workDir", "generationPath", "candidatePath", "gitDir"]) {
      if (typeof request[key] !== "string" || request[key].length === 0) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.${key} must be a non-empty string`);
      }
    }
    if (!Array.isArray(request.manifestPaths) || request.manifestPaths.length === 0) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.manifestPaths must be a non-empty array");
    }
    if (request.leaseCandidate === undefined || request.leaseCandidate === null) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.leaseCandidate is required for the activity fence");
    }
    if (!isPlainObject(request.expected)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.expected (base generation) must be an object");
    }
    if (typeof request.expected.pointerFingerprint !== "string" || request.expected.pointerFingerprint.length === 0) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.expected.pointerFingerprint must be a non-empty string");
    }
    if (!Number.isSafeInteger(request.probedAtMs) || request.probedAtMs < 0) {
      refuse(PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID, "request.probedAtMs must be a non-negative safe integer");
    }
    if (!isPlainObject(request.readiness)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.readiness must be an object");
    }
    for (const dimension of CALLER_DIMENSIONS) {
      if (!isPlainObject(request.readiness[dimension])) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.readiness.${dimension} must be an object`);
      }
    }
  }

  // The live pointer must be exactly the base generation the requester intends
  // to refresh (optimistic concurrency). A mismatch means someone else already
  // advanced the generation; refuse as stale rather than fork off an old base.
  function assertExpectedBase(live, expected) {
    if (live === null) {
      refuse(PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE, "no live generation is published to refresh");
    }
    if (live.pointerFingerprint !== expected.pointerFingerprint) {
      refuse(PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE, "live generation does not match the expected base generation", {
        expectedPointerFingerprint: expected.pointerFingerprint,
        livePointerFingerprint: live.pointerFingerprint,
      });
    }
  }

  // The activity fence must still be current at a checkpoint; a lost fence means
  // a concurrent invalidation / rebind raced this refresh.
  function assertFenceCurrent(lease, checkpoint) {
    if (!lease.isCurrent()) {
      refuse(PROTOCOL_ERROR_CODES.LEASE_CONFLICT, `activity fence was lost before ${checkpoint}`, { checkpoint });
    }
  }

  /**
   * Run one refresh generation publication. Resolves to a frozen success receipt
   * when every proof holds; otherwise rejects with a structured refusal whose
   * `.code` is a PROTOCOL_ERROR_CODES value. The activity fence is always
   * released. No live-pointer mutation occurs unless the readiness attestation
   * is proven single-use and the fence is still current at publish time.
   */
  async function runRefresh(request) {
    assertRequest(request);
    const {
      operation, hostId, workspaceId, sourcePlatform, workDir,
      generationPath, candidatePath, gitDir, manifestPaths,
      probedAtMs, readiness, expected,
    } = request;
    const expectedGraph = isPlainObject(request.expectedGraph) ? request.expectedGraph : {};

    // Step 1 -- acquire the prompt/read activity fence. Throws LEASE_CONFLICT /
    // WORKSPACE_ADMISSION_EXCEEDED on acquisition failure (no fence to release).
    const lease = acquireFence(request.leaseCandidate);
    if (!lease || typeof lease.isCurrent !== "function" || typeof lease.release !== "function") {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "acquireFence must return a lease with { isCurrent, release }");
    }
    try {
      // Step 2 -- expected mapping / workspace-generation check against the live
      // pointer (the base the refresh builds on). Read the live pointer once.
      const live = await readLiveGeneration(publishIo);
      assertExpectedBase(live, expected);
      assertFenceCurrent(lease, "materialisation");

      // Step 2b -- materialise the fetch/merge into the candidate generation dir.
      await materialize({
        operation, hostId, workspaceId, sourcePlatform, workDir,
        generationPath, candidatePath, gitDir,
        baseGeneration: live.activeGeneration,
      });

      // Step 4 (Final-obligation ordering) -- POST-operation no-follow identity
      // check of both the candidate and git directories, re-anchored to a freshly
      // read root identity, to catch a root swap during the fetch/merge.
      const rootProof = await containment.identifyRoot({ workDir, sourcePlatform });
      await containment.verifyContained({
        workDir, sourcePlatform, candidate: candidatePath, expectedRootIdentity: rootProof.rootIdentity,
      });
      await containment.verifyContained({
        workDir, sourcePlatform, candidate: gitDir, expectedRootIdentity: rootProof.rootIdentity,
      });

      // Step 3 -- full graph / ref / OID all-reachable proof of the refreshed repo.
      const graphProof = await gitVerifier.verifyRepositoryGraph(gitDir, expectedGraph);

      // Derive the generation fingerprints exactly once from the proofs above.
      const rootIdentityFingerprint = hashIdentity(rootProof.rootIdentity);
      const storageIdentityFingerprint = hashIdentity(rootProof.storageIdentity);
      const gitGenerationFingerprint = graphProof.generationFingerprint;

      // Backup / content manifest over the refreshed candidate.
      const entries = await computeManifestEntries(manifestIo, manifestPaths);
      const manifest = buildWorkspaceManifest({
        hostId, workspaceId,
        workspaceGeneration: live.activeGeneration + 1,
        sourcePlatform,
        rootIdentityFingerprint, storageIdentityFingerprint, gitGenerationFingerprint,
        entries,
      });
      const manifestFingerprint = manifest.manifestFingerprint;

      // Build the successor pointer chained onto the live base. The successor
      // generation number is DERIVED from the live pointer, never the requester.
      const pointer = buildGenerationPointer({
        hostId, workspaceId, sourcePlatform,
        activeGeneration: live.activeGeneration + 1,
        generationPath,
        rootIdentityFingerprint, storageIdentityFingerprint, gitGenerationFingerprint,
        manifestFingerprint,
        priorGeneration: live.activeGeneration,
        priorPointerFingerprint: live.pointerFingerprint,
      });

      // Current-run readiness probe (S4e). The four caller dimensions must be
      // live; the workspace dimension binds the just-built successor generation
      // to itself. Freshness uses the TRUSTED clock and daemon-owned maxAgeMs.
      const generationFingerprints = {
        pointerFingerprint: pointer.pointerFingerprint,
        rootIdentityFingerprint,
        gitGenerationFingerprint,
        manifestFingerprint,
      };
      const attestation = evaluateGenerationReadiness({
        connection: readiness.connection,
        runtime: readiness.runtime,
        providerAuth: readiness.providerAuth,
        modelProfile: readiness.modelProfile,
        workspace: {
          state: "ready",
          source: "live",
          generation: { ...generationFingerprints },
          expected: { ...generationFingerprints },
        },
        freshness: { probedAtMs, nowMs: clock.now(), maxAgeMs },
      });

      // Anti-replay: each readiness attestation is single-use within the window.
      if (replaySeen.has(attestation.readinessFingerprint)) {
        refuse(PROTOCOL_ERROR_CODES.READINESS_REPLAYED, "readiness attestation has already been consumed");
      }
      replaySeen.add(attestation.readinessFingerprint);

      // Step 1 (fencing, final) -- the activity fence MUST still be current
      // immediately before the flip, closing the prompt/read fence: a concurrent
      // invalidation between the proofs and publish aborts the refresh.
      assertFenceCurrent(lease, "publication");

      // Step 5 -- atomic generation publication, CAS onto the live base. Sole
      // live-pointer mutation; a throw at or before the atomic replace preserves
      // the prior generation. The CAS also refuses if the live pointer advanced
      // since step 2 (WORKSPACE_GENERATION_CAS_CONFLICT).
      const published = await publishGeneration(publishIo, pointer);

      return Object.freeze({
        operation,
        published: Object.freeze({ ...published }),
        pointer,
        fence: lease.fence,
        readinessFingerprint: attestation.readinessFingerprint,
        generationPointerFingerprint: pointer.pointerFingerprint,
        rootIdentityFingerprint,
        storageIdentityFingerprint,
        gitGenerationFingerprint,
        manifestFingerprint,
      });
    } finally {
      lease.release();
    }
  }

  return Object.freeze({ runRefresh });
}
