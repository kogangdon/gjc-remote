// Create/clone workspace data-plane operation for the native workspace data
// plane (#53 Phase 2, slice S4f).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations
// -> Create/clone row): a create/clone generation publication is admissible
// ONLY when every one of these proofs holds, in order:
//   1. Mapping / no-follow containment proof         (S4a workspace-containment)
//   2. Complete graph / ref / OID proof              (S4b git-graph-verification)
//   3. Backup / manifest                             (S4c workspace-backup-manifest)
//   4. Current-run readiness probe                   (S4e workspace-generation-probe)
//   5. Atomic generation publication                 (S4d workspace-generation-publisher)
//
// This module is the WIRING that composes those five isolated primitives into a
// single fail-closed create/clone operation. It is a PURE dependency-injected
// orchestrator: every side effect (native root facts, git subprocess, byte
// reads, the clone/create materialisation, the live-pointer flip, the clock) is
// injected. It performs no direct filesystem, subprocess, or network I/O
// itself, does NOT read or flip the native-workspace-serving gate
// (NATIVE_WORKSPACE_SERVING_ENABLED stays false), and is NOT wired into
// daemon.js request dispatch. Live enablement is the separate S7 boundary.
//
// Prior-generation preservation (Final-obligations guarantee): the atomic
// generation publication (step 5) is the SOLE mutation of the live pointer, and
// it is itself old-or-new atomic (S4d). Any refusal in steps 1-4 therefore
// leaves the prior live generation exactly intact. A materialised-but-
// unpublished candidate directory is an orphan reclaimed by the reset/delete
// slice, never a torn live pointer.
//
// Anti-replay seam contract (owed to S4e, whose module header defers this to the
// wiring): this orchestrator sources `nowMs` from a trusted monotonic clock
// (never the requester), owns `maxAgeMs` from daemon config (never requester
// input), and enforces single-use of every readiness attestation through an
// injected seen-set, refusing reuse with READINESS_REPLAYED.

import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared/protocol";

import { computeManifestEntries, buildWorkspaceManifest } from "./workspace-backup-manifest.js";
import { buildGenerationPointer, publishGeneration } from "./workspace-generation-publisher.js";
import { evaluateGenerationReadiness } from "./workspace-generation-probe.js";

const OPERATION = "workspace_create_clone";

// The four non-workspace readiness dimensions the caller supplies from the live
// daemon status. The workspace dimension is assembled by this orchestrator from
// the proofs it computes, so it is never accepted from the caller.
const CALLER_DIMENSIONS = ["connection", "runtime", "providerAuth", "modelProfile"];

// Bounds for canonicalising a native identity object into a hex64 fingerprint.
// Identity records are tiny, flat, string/number maps.
const IDENTITY_LIMITS = Object.freeze({ maxBytes: 16 * 1024, maxDepth: 4, maxNodes: 64 });

const SUPPORTED_OPERATIONS = new Set(["create", "clone"]);

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
 * Build a create/clone operation bound to its injected collaborators.
 *
 * deps = {
 *   containment,   // S4a instance: { identifyRoot, verifyContained }
 *   gitVerifier,   // S4b instance: { verifyRepositoryGraph }
 *   manifestIo,    // S4c io:       { readBytes(relPath) }
 *   publishIo,     // S4d io:       { readLivePointer, writeTemp, flushTemp, replace, flushParent }
 *   materialize,   // async (request) => void: performs the clone/create into the candidate dir
 *   clock,         // { now(): number } trusted monotonic ms clock (NOT requester-sourced)
 *   maxAgeMs,      // daemon-config readiness freshness bound (NOT requester-sourced)
 *   replaySeen,    // { has(fp), add(fp) } single-use seen-set for readinessFingerprint
 *   hashIdentity?, // optional (identity)=>hex64; defaults to canonicalJsonHash
 * }
 */
export function createWorkspaceCreateOperation(deps = {}) {
  if (!isPlainObject(deps)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "createWorkspaceCreateOperation requires a deps object");
  }
  const { containment, gitVerifier, manifestIo, publishIo, materialize, clock, replaySeen } = deps;

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
    if (!SUPPORTED_OPERATIONS.has(request.operation)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `operation must be one of ${[...SUPPORTED_OPERATIONS].join("/")}`);
    }
    for (const key of ["hostId", "workspaceId", "sourcePlatform", "workDir", "candidateGenerationPath", "gitDir"]) {
      if (typeof request[key] !== "string" || request[key].length === 0) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.${key} must be a non-empty string`);
      }
    }
    if (!Array.isArray(request.manifestPaths)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.manifestPaths must be an array");
    }
    if (!Number.isSafeInteger(request.activeGeneration) || request.activeGeneration < 1) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.activeGeneration must be a safe integer >= 1");
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

  /**
   * Run one create/clone generation publication. Resolves to a frozen success
   * receipt when every proof holds; otherwise rejects with a structured refusal
   * whose `.code` is a PROTOCOL_ERROR_CODES value. No live-pointer mutation
   * occurs unless the readiness attestation is proven and single-use.
   */
  async function runCreateClone(request) {
    assertRequest(request);
    const {
      operation, hostId, workspaceId, sourcePlatform, workDir,
      candidateGenerationPath, gitDir, manifestPaths, activeGeneration,
      probedAtMs, readiness,
    } = request;
    const priorGeneration = request.priorGeneration ?? null;
    const priorPointerFingerprint = request.priorPointerFingerprint ?? null;
    const expectedGraph = isPlainObject(request.expectedGraph) ? request.expectedGraph : {};

    // Step 0 (precondition) — identify + prove the workspace root itself before
    // materialising anything. Captures the root/storage identity used both to
    // detect a post-materialise root swap and to fingerprint the generation.
    const rootProof = await containment.identifyRoot({ workDir, sourcePlatform });

    // Step 1a — materialise the clone/create into the candidate generation dir.
    // The actual git clone / init subprocess lives behind this injected seam.
    await materialize({
      operation, hostId, workspaceId, sourcePlatform, workDir,
      candidateGenerationPath, gitDir, activeGeneration,
    });

    // Step 1b — no-follow containment proof of the materialised candidate. Runs
    // the shallow-to-deep reparse-free prefix walk and re-anchors the root
    // identity to catch a swap between step 0 and now.
    await containment.verifyContained({
      workDir, sourcePlatform,
      candidate: candidateGenerationPath,
      expectedRootIdentity: rootProof.rootIdentity,
    });

    // Step 2 — complete graph / ref / OID all-reachable proof of the repo.
    const graphProof = await gitVerifier.verifyRepositoryGraph(gitDir, expectedGraph);

    // Derive the generation fingerprints exactly once from the proofs above.
    const rootIdentityFingerprint = hashIdentity(rootProof.rootIdentity);
    const storageIdentityFingerprint = hashIdentity(rootProof.storageIdentity);
    const gitGenerationFingerprint = graphProof.generationFingerprint;

    // Step 3 — backup / content manifest over the materialised candidate.
    const entries = await computeManifestEntries(manifestIo, manifestPaths);
    const manifest = buildWorkspaceManifest({
      hostId, workspaceId,
      workspaceGeneration: activeGeneration,
      sourcePlatform,
      rootIdentityFingerprint, storageIdentityFingerprint, gitGenerationFingerprint,
      entries,
    });
    const manifestFingerprint = manifest.manifestFingerprint;

    // Build the candidate generation pointer (pure; not yet published). Its
    // self-fingerprint commits to the identity, git, and manifest fingerprints.
    const pointer = buildGenerationPointer({
      hostId, workspaceId, sourcePlatform,
      activeGeneration,
      generationPath: candidateGenerationPath,
      rootIdentityFingerprint, storageIdentityFingerprint, gitGenerationFingerprint,
      manifestFingerprint,
      priorGeneration, priorPointerFingerprint,
    });

    // Step 4 — current-run readiness probe. The four caller-supplied dimensions
    // must be live; the workspace dimension binds the just-built generation to
    // itself as the expected authority. Freshness uses the TRUSTED clock and
    // daemon-owned maxAgeMs, never requester-sourced values.
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

    // Step 5 — atomic generation publication. Sole live-pointer mutation; a
    // throw at or before the atomic replace preserves the prior generation.
    const published = await publishGeneration(publishIo, pointer);

    return Object.freeze({
      operation,
      published: Object.freeze({ ...published }),
      pointer,
      readinessFingerprint: attestation.readinessFingerprint,
      generationPointerFingerprint: pointer.pointerFingerprint,
      rootIdentityFingerprint,
      storageIdentityFingerprint,
      gitGenerationFingerprint,
      manifestFingerprint,
    });
  }

  return Object.freeze({ runCreateClone });
}
