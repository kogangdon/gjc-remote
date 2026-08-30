import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared/protocol";

import { assertQuarantined } from "./workspace-quarantine-staging.js";
import {
  verifyRestoreChecksum,
  verifyRestoreProvenance,
} from "./workspace-restore-provenance.js";
import { createProvenanceReader } from "./workspace-provenance-reader.js";
import {
  buildGenerationPointer,
  buildPromotionLineage,
  publishPromotion,
} from "./workspace-reversible-promotion.js";
import { readLiveGeneration } from "./workspace-generation-publisher.js";
import { evaluateGenerationReadiness } from "./workspace-generation-probe.js";

const OPERATION = "workspace_restore_migration";
const PROVENANCE_PATH = "restore-provenance.json";
const CALLER_DIMENSIONS = [
  "connection",
  "runtime",
  "providerAuth",
  "modelProfile",
];
const IDENTITY_LIMITS = Object.freeze({
  maxBytes: 16 * 1024,
  maxDepth: 4,
  maxNodes: 64,
});

function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (!["code", "operation", "reason", "message"].includes(key)) {
        error[key] = value;
      }
    }
  }
  throw error;
}

const isPlainObject = (value) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

function assertMethods(value, methods, name) {
  for (const method of methods) {
    if (!value || typeof value[method] !== "function") {
      refuse(
        PROTOCOL_ERROR_CODES.CONFIG_INVALID,
        `${name}.${method} must be a function`
      );
    }
  }
}

function assertRequest(request) {
  if (!isPlainObject(request) || request.operation !== "restore") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.operation must be 'restore'");
  }
  if (request.migrationKind !== undefined &&
      (typeof request.migrationKind !== "string" || request.migrationKind.length === 0)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.migrationKind must be a non-empty string");
  }
  for (const field of [
    "hostId",
    "workspaceId",
    "sourcePlatform",
    "workspaceRoot",
    "workDir",
    "generationPath",
    "candidatePath",
    "gitDir",
    "stagingPath",
  ]) {
    if (typeof request[field] !== "string" || request[field].length === 0) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `request.${field} must be a non-empty string`);
    }
  }
  if (request.leaseCandidate === null || typeof request.leaseCandidate !== "object") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.leaseCandidate is required");
  }
  if (!Number.isSafeInteger(request.expectedWorkspaceGeneration) ||
      request.expectedWorkspaceGeneration < 1) {
    refuse(
      PROTOCOL_ERROR_CODES.CONFIG_INVALID,
      "request.expectedWorkspaceGeneration must be a positive safe integer"
    );
  }
  if (!isPlainObject(request.expectedAuthority)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.expectedAuthority must be an object");
  }
  if (!isPlainObject(request.manifest) ||
      typeof request.manifest.manifestFingerprint !== "string") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request.manifest must carry manifestFingerprint");
  }
  if (typeof request.restoredFromWorkspaceId !== "string" ||
      request.restoredFromWorkspaceId.length === 0 ||
      !Number.isSafeInteger(request.restoredFromGeneration) ||
      request.restoredFromGeneration < 1) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request restore lineage is invalid");
  }
  if (!Number.isSafeInteger(request.probedAtMs) || request.probedAtMs < 0 ||
      !isPlainObject(request.readiness)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "request readiness is invalid");
  }
  for (const dimension of CALLER_DIMENSIONS) {
    if (!isPlainObject(request.readiness[dimension])) {
      refuse(
        PROTOCOL_ERROR_CODES.CONFIG_INVALID,
        `request.readiness.${dimension} must be an object`
      );
    }
  }
}

function assertFenceCurrent(lease, checkpoint) {
  if (!lease.isCurrent()) {
    refuse(
      PROTOCOL_ERROR_CODES.LEASE_CONFLICT,
      `activity fence was lost before ${checkpoint}`,
      { checkpoint }
    );
  }
}

export function createWorkspaceRestoreMigrationOperation(deps = {}) {
  if (!isPlainObject(deps)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "deps must be an object");
  }
  const {
    containment,
    gitVerifier,
    stagePromotion,
    makeStageReader,
    makePublisherIo,
    acquireFence,
    clock,
    replaySeen,
  } = deps;
  assertMethods(containment, ["identifyRoot", "verifyContained"], "containment");
  assertMethods(gitVerifier, ["verifyRepositoryGraph"], "gitVerifier");
  assertMethods(stagePromotion, ["materializeAndVerify", "cleanup"], "stagePromotion");
  if (typeof makeStageReader !== "function" ||
      typeof makePublisherIo !== "function" ||
      typeof acquireFence !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "restore dependencies must be functions");
  }
  assertMethods(clock, ["now"], "clock");
  assertMethods(replaySeen, ["has", "add"], "replaySeen");
  if (!Number.isSafeInteger(deps.maxAgeMs) || deps.maxAgeMs < 1) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "maxAgeMs must be a safe integer >= 1 owned by daemon config");
  }
  const hashIdentity = deps.hashIdentity ?? ((identity) =>
    canonicalJsonHash(identity, IDENTITY_LIMITS));
  if (typeof hashIdentity !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "hashIdentity must be a function");
  }

  async function runRestoreMigration(request) {
    assertRequest(request);
    if (request.migrationKind === "docker-session-volume") {
      refuse(
        "WORKSPACE_MIGRATION_UNSUPPORTED",
        "docker session-volume migration is not supported"
      );
    }

    const lease = acquireFence(request.leaseCandidate);
    let materialized = false;
    let stageReader = null;
    try {
      if (!lease || typeof lease.isCurrent !== "function" ||
          typeof lease.release !== "function") {
        refuse(
          PROTOCOL_ERROR_CODES.CONFIG_INVALID,
          "acquireFence must return a lease with { isCurrent, release }"
        );
      }
      assertFenceCurrent(lease, "live validation");

      const publishIo = await makePublisherIo(request.workspaceId);
      assertMethods(
        publishIo,
        ["readLivePointer", "writeTemp", "flushTemp", "replace", "flushParent"],
        "publishIo"
      );
      const live = await readLiveGeneration(publishIo);
      if (!live ||
          live.hostId !== request.hostId ||
          live.workspaceId !== request.workspaceId ||
          live.sourcePlatform !== request.sourcePlatform ||
          live.activeGeneration !== request.expectedWorkspaceGeneration) {
        refuse(
          PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
          "live generation does not match accepted workspace authority"
        );
      }
      if (
        request.manifest.hostId !== request.hostId ||
        request.manifest.workspaceId !== request.workspaceId ||
        request.manifest.sourcePlatform !== request.sourcePlatform ||
        request.manifest.workspaceGeneration !== live.activeGeneration + 1
      ) {
        refuse(
          "WORKSPACE_MANIFEST_INVALID",
          "restore manifest destination identity does not match accepted authority"
        );
      }

      assertQuarantined({
        stagingPath: request.stagingPath,
        candidatePath: request.workspaceRoot,
        workDir: request.workspaceRoot,
        sourcePlatform: request.sourcePlatform,
      });
      assertQuarantined({
        stagingPath: request.stagingPath,
        candidatePath: request.candidatePath,
        workDir: request.workDir,
        sourcePlatform: request.sourcePlatform,
      });

      stageReader = await makeStageReader(
        request.stagingPath,
        request.sourcePlatform
      );
      assertMethods(stageReader, ["readBytes"], "stageReader");
      await verifyRestoreProvenance(createProvenanceReader({ reader: stageReader }), {
        expectedAuthority: request.expectedAuthority,
        staged: { provenancePath: PROVENANCE_PATH },
      });
      await verifyRestoreChecksum(stageReader, request.manifest);

      await stagePromotion.materializeAndVerify({
        stagingPath: request.stagingPath,
        candidatePath: request.candidatePath,
        sourcePlatform: request.sourcePlatform,
        manifest: request.manifest,
        stageReader,
      });
      materialized = true;
      if (typeof stageReader.close === "function") {
        await stageReader.close();
      }
      stageReader = null;

      const rootProof = await containment.identifyRoot({
        workDir: request.workDir,
        sourcePlatform: request.sourcePlatform,
      });
      await containment.verifyContained({
        workDir: request.workDir,
        sourcePlatform: request.sourcePlatform,
        candidate: request.candidatePath,
        expectedRootIdentity: rootProof.rootIdentity,
      });
      await containment.verifyContained({
        workDir: request.workDir,
        sourcePlatform: request.sourcePlatform,
        candidate: request.gitDir,
        expectedRootIdentity: rootProof.rootIdentity,
      });
      const graphProof = await gitVerifier.verifyRepositoryGraph(
        request.gitDir,
        isPlainObject(request.expectedGraph) ? request.expectedGraph : {}
      );
      if (
        graphProof.generationFingerprint !==
        request.manifest.gitGenerationFingerprint
      ) {
        refuse(
          "WORKSPACE_MANIFEST_MISMATCH",
          "candidate Git graph does not match the trusted manifest"
        );
      }

      const rootIdentityFingerprint = hashIdentity(rootProof.rootIdentity);
      const storageIdentityFingerprint = hashIdentity(rootProof.storageIdentity);
      const pointer = buildGenerationPointer({
        hostId: request.hostId,
        workspaceId: request.workspaceId,
        sourcePlatform: request.sourcePlatform,
        activeGeneration: live.activeGeneration + 1,
        generationPath: request.generationPath,
        rootIdentityFingerprint,
        storageIdentityFingerprint,
        gitGenerationFingerprint: graphProof.generationFingerprint,
        manifestFingerprint: request.manifest.manifestFingerprint,
        priorGeneration: live.activeGeneration,
        priorPointerFingerprint: live.pointerFingerprint,
      });
      const generation = {
        pointerFingerprint: pointer.pointerFingerprint,
        rootIdentityFingerprint,
        gitGenerationFingerprint: graphProof.generationFingerprint,
        manifestFingerprint: request.manifest.manifestFingerprint,
      };
      const readiness = evaluateGenerationReadiness({
        connection: request.readiness.connection,
        runtime: request.readiness.runtime,
        providerAuth: request.readiness.providerAuth,
        modelProfile: request.readiness.modelProfile,
        workspace: {
          state: "ready",
          source: "live",
          generation,
          expected: generation,
        },
        freshness: {
          probedAtMs: request.probedAtMs,
          nowMs: clock.now(),
          maxAgeMs: deps.maxAgeMs,
        },
      });
      if (replaySeen.has(readiness.readinessFingerprint)) {
        refuse(
          PROTOCOL_ERROR_CODES.READINESS_REPLAYED,
          "readiness attestation has already been consumed"
        );
      }
      replaySeen.add(readiness.readinessFingerprint);
      assertFenceCurrent(lease, "readiness");

      let published;
      try {
        published = await publishPromotion(publishIo, pointer);
      } catch (error) {
        // replace is the linearization point. A flushParent failure may leave
        // the new pointer live, so deleting its candidate would create a
        // published dangling generation. Preserve the verified candidate for
        // boot-time reconciliation in that ambiguous post-replace window.
        if (error?.step === "flushParent") materialized = false;
        throw error;
      }
      materialized = false;
      return Object.freeze({
        operation: request.operation,
        published: Object.freeze({ ...published }),
        pointer,
        lineage: buildPromotionLineage({
          restoredFromWorkspaceId: request.restoredFromWorkspaceId,
          restoredFromGeneration: request.restoredFromGeneration,
        }),
        fence: lease.fence,
        readinessFingerprint: readiness.readinessFingerprint,
        generationPointerFingerprint: pointer.pointerFingerprint,
        rootIdentityFingerprint,
        storageIdentityFingerprint,
        gitGenerationFingerprint: graphProof.generationFingerprint,
        manifestFingerprint: request.manifest.manifestFingerprint,
        restoredFromWorkspaceId: request.restoredFromWorkspaceId,
        restoredFromGeneration: request.restoredFromGeneration,
      });
    } catch (error) {
      if (materialized) {
        try {
          await stagePromotion.cleanup(request.candidatePath);
        } catch (cleanupError) {
          error.cleanupError = cleanupError;
        }
      }
      throw error;
    } finally {
      try {
        if (stageReader && typeof stageReader.close === "function") {
          await stageReader.close();
        }
      } finally {
        if (lease && typeof lease.release === "function") lease.release();
      }
    }
  }

  return Object.freeze({ runRestoreMigration });
}
