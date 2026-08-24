// Restore / migration workspace data-plane orchestrator for the native
// workspace data plane (#53 Phase 2, slice S5i).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations
// -> Restore/migration rows): a restore or migration generation publication is
// admissible ONLY when every one of these holds, in this exact order:
//   1. Quarantine of the staging tree              (S5f assertQuarantined)
//   2. Provenance + checksum of the staged source  (S5g verifyRestoreProvenance
//                                                    + verifyRestoreChecksum)
//   3. Post-verification containment / OID recheck  (S4a verifyContained +
//      re-anchored to a freshly read root identity   S4b verifyRepositoryGraph)
//   4. Fresh readiness attestation, single-use      (S4e evaluateGenerationReadiness)
//   5. Reversible promotion CAS onto the live slot  (S5h publishPromotion)
// AND the migration is not a disabled Docker session-volume migration (fixed
// public refusal BEFORE step 1, internal diagnostic never crossing the envelope).
//
// This module is a PURE dependency-injected wiring orchestrator that COMPOSES
// the already-reviewed S5f/S5g/S5h primitives plus the reused S4a/S4b/S4e
// primitives verbatim. Every side effect (native root facts, git subprocess,
// byte reads, provenance-record read, the live-pointer flip, the activity
// fence, the clock) is injected. It performs no direct filesystem, subprocess,
// or network I/O itself, does NOT read or flip the native-workspace-serving
// gate (NATIVE_WORKSPACE_SERVING_ENABLED stays false), and is NOT wired into
// daemon.js request dispatch. Live enablement is the separate S7 boundary.
//
// Reversibility (Final-obligations guarantee): the promotion is a STANDARD S4d
// generation pointer chained (CAS) onto the exact currently-live pointer, so it
// is old-or-new atomic and any refusal in steps 1-4 leaves the prior live
// generation exactly intact. Restore lineage (restoredFromWorkspaceId /
// restoredFromGeneration) travels OUT-OF-BAND in the frozen orchestrator result
// via S5h's buildPromotionLineage; it never enters the published pointer.
//
// Anti-replay seam contract (owed to S4e): this orchestrator sources `nowMs`
// from a trusted monotonic clock (never the requester), owns `maxAgeMs` from
// daemon config (never requester input), and enforces single-use of every
// readiness attestation through an injected seen-set, refusing reuse with
// READINESS_REPLAYED.

import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared/protocol";

import { assertQuarantined } from "./workspace-quarantine-staging.js";
import { verifyRestoreProvenance, verifyRestoreChecksum } from "./workspace-restore-provenance.js";
import { buildGenerationPointer, publishPromotion, buildPromotionLineage } from "./workspace-reversible-promotion.js";
import { readLiveGeneration } from "./workspace-generation-publisher.js";
import { evaluateGenerationReadiness } from "./workspace-generation-probe.js";

const OPERATION = "workspace_restore_migration";

// The four non-workspace readiness dimensions supplied from the live daemon
// status. The workspace dimension is assembled by this orchestrator from the
// proofs it computes, so it is never accepted from the caller.
const CALLER_DIMENSIONS = ["connection", "runtime", "providerAuth", "modelProfile"];

// Bounds for canonicalising a native identity object into a hex64 fingerprint.
const IDENTITY_LIMITS = Object.freeze({ maxBytes: 16 * 1024, maxDepth: 4, maxNodes: 64 });

// A Docker session-volume migration is unsupported in the native data plane.
// The refusal carries EXACTLY this fixed public code + reason (no internal
// diagnostic), enforced by the JSON-scan negative test.
const DOCKER_SESSION_VOLUME_KIND = "docker-session-volume";
const MIGRATION_UNSUPPORTED_CODE = "WORKSPACE_MIGRATION_UNSUPPORTED";
const MIGRATION_UNSUPPORTED_REASON = "docker session-volume migration is not supported";

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
 * Build a restore/migration operation bound to its injected collaborators.
 *
 * deps = {
 *   containment,   // S4a instance: { identifyRoot, verifyContained }
 *   gitVerifier,   // S4b instance: { verifyRepositoryGraph }
 *   provenanceIo,  // S5g io:       { readProvenanceRecord(staged) }
 *   checksumIo,    // S5g/S4c io:   { readBytes(relPath) }
 *   publishIo,     // S4d/S5h io:   { readLivePointer, writeTemp, flushTemp, replace, flushParent }
 *   acquireFence,  // (leaseCandidate) => { fence, isCurrent(): boolean, release(): void }
 *                  //   the WorkspaceLeaseRegistry.acquireActivity exclusive fence; throws
 *                  //   WORKSPACE_BUSY / LEASE_CONFLICT / WORKSPACE_ADMISSION_EXCEEDED on failure.
 *   clock,         // { now(): number } trusted monotonic ms clock (NOT requester-sourced)
 *   maxAgeMs,      // daemon-config readiness freshness bound (NOT requester-sourced)
 *   replaySeen,    // { has(fp), add(fp) } single-use seen-set for readinessFingerprint
 *   hashIdentity?, // optional (identity)=>hex64; defaults to canonicalJsonHash
 * }
 */
export function createWorkspaceRestoreMigrationOperation(deps = {}) {
  if (!isPlainObject(deps)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "createWorkspaceRestoreMigrationOperation requires a deps object");
  }
  const { containment, gitVerifier, provenanceIo, checksumIo, publishIo, acquireFence, clock, replaySeen } = deps;

  assertFn(containment, "identifyRoot", "containment");
  assertFn(containment, "verifyContained", "containment");
  assertFn(gitVerifier, "verifyRepositoryGraph", "gitVerifier");
  assertFn(provenanceIo, "readProvenanceRecord", "provenanceIo");
  assertFn(checksumIo, "readBytes", "checksumIo");
  for (const method of ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"]) {
    assertFn(publishIo, method, "publishIo");
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
    if (request.operation !== "restore") {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "operation must be 'restore'");
    }
    if (request.migrationKind !== undefined &&
        (typeof request.migrationKind !== "string" || request.migrationKind.length === 0)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.migrationKind, when present, must be a non-empty string");
    }
    for (const key of ["hostId", "workspaceId", "sourcePlatform", "workDir", "generationPath", "candidatePath", "gitDir", "stagingPath"]) {
      if (typeof request[key] !== "string" || request[key].length === 0) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.${key} must be a non-empty string`);
      }
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
    if (!isPlainObject(request.expectedAuthority)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.expectedAuthority must be an object");
    }
    if (!isPlainObject(request.staged)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.staged must be an object");
    }
    if (!isPlainObject(request.manifest)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.manifest must be an object");
    }
    if (typeof request.manifest.manifestFingerprint !== "string" || request.manifest.manifestFingerprint.length === 0) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.manifest.manifestFingerprint must be a non-empty string");
    }
    if (typeof request.restoredFromWorkspaceId !== "string" || request.restoredFromWorkspaceId.length === 0) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.restoredFromWorkspaceId must be a non-empty string");
    }
    if (!Number.isSafeInteger(request.restoredFromGeneration) || request.restoredFromGeneration < 1) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.restoredFromGeneration must be a safe integer >= 1");
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
  // to promote onto (optimistic concurrency). A mismatch means someone else
  // advanced the generation; refuse as stale rather than fork off an old base.
  function assertExpectedBase(live, expected) {
    if (live === null) {
      refuse(PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE, "no live generation is published to promote onto");
    }
    if (live.pointerFingerprint !== expected.pointerFingerprint) {
      refuse(PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE, "live generation does not match the expected base generation", {
        expectedPointerFingerprint: expected.pointerFingerprint,
        livePointerFingerprint: live.pointerFingerprint,
      });
    }
  }

  // The activity fence must still be current at a checkpoint; a lost fence means
  // a concurrent invalidation / rebind raced this promotion.
  function assertFenceCurrent(lease, checkpoint) {
    if (!lease.isCurrent()) {
      refuse(PROTOCOL_ERROR_CODES.LEASE_CONFLICT, `activity fence was lost before ${checkpoint}`, { checkpoint });
    }
  }

  /**
   * Run one restore/migration promotion. Resolves to a frozen success receipt
   * when every proof holds; otherwise rejects with a structured refusal whose
   * `.code` is a PROTOCOL_ERROR_CODES value (or a module-local literal). The
   * activity fence is always released. No live-pointer mutation occurs unless
   * every proof passes, the readiness attestation is single-use, and the fence
   * is still current at publish time.
   */
  async function runRestoreMigration(request) {
    assertRequest(request);

    // Docker session-volume migration is disabled. Refuse with the fixed public
    // tuple BEFORE acquiring any fence or touching any I/O so there is provably
    // zero mutation and no internal diagnostic can cross the public envelope.
    if (request.migrationKind === DOCKER_SESSION_VOLUME_KIND) {
      refuse(MIGRATION_UNSUPPORTED_CODE, MIGRATION_UNSUPPORTED_REASON);
    }

    const {
      operation, hostId, workspaceId, sourcePlatform, workDir,
      generationPath, candidatePath, gitDir, stagingPath,
      expected, expectedAuthority, staged, manifest,
      restoredFromWorkspaceId, restoredFromGeneration,
      probedAtMs, readiness,
    } = request;
    const expectedGraph = isPlainObject(request.expectedGraph) ? request.expectedGraph : {};

    // Step 0 -- acquire the exclusive prompt/read activity fence. Throws
    // WORKSPACE_BUSY / LEASE_CONFLICT / WORKSPACE_ADMISSION_EXCEEDED on failure
    // (no fence to release).
    const lease = acquireFence(request.leaseCandidate);
    try {
      // Shape guard runs INSIDE the try so a malformed-but-releasable lease is
      // still released by the finally below.
      if (!lease || typeof lease.isCurrent !== "function" || typeof lease.release !== "function") {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "acquireFence must return a lease with { isCurrent, release }");
      }

      // Step 1 -- structural quarantine of the staging tree (S5f). Throws
      // WORKSPACE_STAGING_NOT_QUARANTINED / CONFIG_INVALID. No I/O; refusal here
      // occurs before any provenance read, giving zero mutation.
      assertQuarantined({ stagingPath, candidatePath, workDir, sourcePlatform });

      // Step 2 -- provenance + checksum of the staged source (S5g). Provenance
      // proves role/volume/key/host identity against the TRUSTED authority;
      // checksum re-hashes every manifest entry (S4c verbatim, zero local
      // hashing). Both refuse before any live-pointer work.
      await verifyRestoreProvenance(provenanceIo, { expectedAuthority, staged });
      await verifyRestoreChecksum(checksumIo, manifest);

      // Step 3 -- POST-verification no-follow identity check of both the
      // candidate and git directories, re-anchored to a freshly read root
      // identity (S4a), then a full graph / ref / OID all-reachable proof (S4b).
      // Catches a root swap or graph tamper on the staged source.
      const rootProof = await containment.identifyRoot({ workDir, sourcePlatform });
      await containment.verifyContained({
        workDir, sourcePlatform, candidate: candidatePath, expectedRootIdentity: rootProof.rootIdentity,
      });
      await containment.verifyContained({
        workDir, sourcePlatform, candidate: gitDir, expectedRootIdentity: rootProof.rootIdentity,
      });
      const graphProof = await gitVerifier.verifyRepositoryGraph(gitDir, expectedGraph);

      // The live pointer must be exactly the base the promotion builds on. Read
      // it once and pin it; a stale base refuses before any CAS (prior
      // generation intact).
      const live = await readLiveGeneration(publishIo);
      assertExpectedBase(live, expected);
      assertFenceCurrent(lease, "readiness");

      // Derive the generation fingerprints from the fresh proofs above; the
      // manifest fingerprint comes from the just-verified staged manifest (the
      // restored content is exactly what the manifest attests to).
      const rootIdentityFingerprint = hashIdentity(rootProof.rootIdentity);
      const storageIdentityFingerprint = hashIdentity(rootProof.storageIdentity);
      const gitGenerationFingerprint = graphProof.generationFingerprint;
      const manifestFingerprint = manifest.manifestFingerprint;

      // Build the successor pointer chained onto the live base. The successor
      // generation number is DERIVED from the live pointer, never the requester.
      // This is a STANDARD S4d pointer (exact POINTER_KEYS); restore lineage
      // never rides it.
      const pointer = buildGenerationPointer({
        hostId, workspaceId, sourcePlatform,
        activeGeneration: live.activeGeneration + 1,
        generationPath,
        rootIdentityFingerprint, storageIdentityFingerprint, gitGenerationFingerprint,
        manifestFingerprint,
        priorGeneration: live.activeGeneration,
        priorPointerFingerprint: live.pointerFingerprint,
      });

      // Step 4 -- current-run readiness probe (S4e). The four caller dimensions
      // must be live; the workspace dimension binds the just-built successor
      // generation to itself. Freshness uses the TRUSTED clock and daemon-owned
      // maxAgeMs.
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

      // The fence MUST still be current immediately before the flip, closing the
      // prompt/read fence: a concurrent invalidation between the proofs and
      // publish aborts the promotion.
      assertFenceCurrent(lease, "promotion");

      // Step 5 -- reversible promotion: atomic generation publication, CAS onto
      // the live base (S5h -> S4d). Sole live-pointer mutation; a throw at or
      // before the atomic replace preserves the prior generation. The CAS also
      // refuses if the live pointer advanced since the base read.
      const published = await publishPromotion(publishIo, pointer);

      // Restore lineage is out-of-band metadata for this result; it never
      // entered the published pointer.
      const lineage = buildPromotionLineage({ restoredFromWorkspaceId, restoredFromGeneration });

      return Object.freeze({
        operation,
        published: Object.freeze({ ...published }),
        pointer,
        lineage,
        fence: lease.fence,
        readinessFingerprint: attestation.readinessFingerprint,
        generationPointerFingerprint: pointer.pointerFingerprint,
        rootIdentityFingerprint,
        storageIdentityFingerprint,
        gitGenerationFingerprint,
        manifestFingerprint,
        restoredFromWorkspaceId,
        restoredFromGeneration,
      });
    } finally {
      if (lease && typeof lease.release === "function") lease.release();
    }
  }

  return Object.freeze({ runRestoreMigration });
}
