// Native serving deps assembly (slice S6f.7d).
//
// Assembles the production `nativeServingDeps` bundles the lifecycle
// dispatchers consume. CREATE and REFRESH remain independently available when
// reset/delete's native residual-process capability is unavailable.
//
// This is the S7/#171 "native serving low-level deps bundle" the boot wirings
// (workspace-create-boot-wiring.js, workspace-refresh-boot-wiring.js) have been
// waiting for: once the human-approved serving gate flips (S6f.7f) the daemon
// passes these bundles to resolveLifecycleCreateDispatcher /
// resolveLifecycleRefreshDispatcher and the dispatchers go live.
//
// Until the gate flips the daemon never calls this (the assembly sits behind
// the still-false NATIVE_WORKSPACE_SERVING_ENABLED const), so this slice is
// wired-but-dormant. It is unit-tested here in full with injected factory fakes.
//
// Bundle contents (verified against the dispatcher config assertions):
//   create:  { containment, gitVerifier, makeManifestIo, makePublisherIo,
//              materialize, resolveManifestPaths, clock, maxAgeMs, replaySeen }
//   refresh: create + { acquireFence }   (non-exclusive activity fence)
//
// The SAME replaySeen instance is shared across the create and refresh bundles
// so a readiness fingerprint burned by one operation cannot be replayed through
// the other (architect caveat C1: pin one shared replay window).

import {
  createContainmentLowLevel,
  createResidualProcessEnumerator,
} from "@gjc-remote/native-control";
import * as fs from "node:fs/promises";

import { createWorkspaceContainment } from "./workspace-containment.js";
import { createGitGraphVerifier } from "./git-graph-verification.js";
import { createGitMaterializer } from "./workspace-git-materializer.js";
import { createContainedByteReader } from "./workspace-contained-byte-reader.js";
import { createGenerationPublisherIo } from "./workspace-generation-storage-io.js";
import { createCandidateManifestResolver } from "./workspace-candidate-tree-resolver.js";
import { createReadinessReplayWindow } from "./workspace-readiness-replay-window.js";
import { createActivityFence, createExclusiveFence } from "./workspace-lease-fence.js";
import { createRestoreStagePromotion } from "./workspace-restore-stage-promotion.js";
import { createLinuxRetainedByteReader } from "./workspace-linux-retained-byte-reader.js";
import { resolveResidualProcessIo } from "./workspace-reset-delete-boot-wiring.js";

const DEFAULT_CLOCK = Object.freeze({ now: () => Date.now() });

/**
 * @param {object} options
 * @param {string} options.workspaceRoot - contained native workspace root.
 * @param {object} options.workspaceLeases - the WorkspaceLeaseRegistry (must
 *   expose acquireActivity; the activity fence binder validates it).
 * @param {number} options.maxAgeMs - validated readiness freshness bound.
 * @param {{ now(): number }} [options.clock] - trusted monotonic ms clock.
 * @param {object} [options.factories] - injectable factory overrides (tests).
 * @param {string} options.hostId - this daemon's bound host identity.
 * @param {"posix"|"windows-drive"} options.sourcePlatform - host path format.
 * @returns {{ create: object, refresh: object, resetDelete: object|null, restoreMigration: object|null }}
 */
export function assembleNativeServingDeps({
  workspaceRoot,
  workspaceLeases,
  maxAgeMs,
  hostId,
  sourcePlatform,
  runtimePlatform = process.platform,
  clock = DEFAULT_CLOCK,
  factories = {},
} = {}) {
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    throw new TypeError("assembleNativeServingDeps requires a non-empty workspaceRoot");
  }
  if (workspaceLeases === null || typeof workspaceLeases !== "object") {
    throw new TypeError("assembleNativeServingDeps requires a workspaceLeases registry");
  }
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) {
    throw new TypeError("assembleNativeServingDeps requires maxAgeMs as a safe integer >= 1");
  }
  if (typeof clock?.now !== "function") {
    throw new TypeError("assembleNativeServingDeps requires a clock with now()");
  }

  const {
    makeContainmentLowLevel = createContainmentLowLevel,
    makeContainment = createWorkspaceContainment,
    makeGitVerifier = createGitGraphVerifier,
    makeMaterializer = createGitMaterializer,
    makeByteReader = createContainedByteReader,
    makePublisher = createGenerationPublisherIo,
    makeManifestResolver = createCandidateManifestResolver,
    makeReplayWindow = createReadinessReplayWindow,
    makeActivityFence = createActivityFence,
    makeExclusiveFence = createExclusiveFence,
    makeResidualEnumerator = createResidualProcessEnumerator,
    makeResidualIo = resolveResidualProcessIo,
    makeRetainedByteReader = createLinuxRetainedByteReader,
  } = factories;

  const containment = makeContainment({ lowLevel: makeContainmentLowLevel() });
  const gitVerifier = makeGitVerifier();
  const materialize = makeMaterializer().materialize;
  const resolveManifestPaths = makeManifestResolver();
  const acquireFence = makeActivityFence(workspaceLeases);

  // (candidatePath, byteReaderPlatform) => { readBytes } - the S4c reparse-safe
  // reader rooted at the already-verified candidate generation directory.
  const makeManifestIo = (candidatePath, byteReaderPlatform) =>
    makeByteReader({ root: candidatePath, sourcePlatform: byteReaderPlatform });

  // async (workspaceId) => publishIo - the S4d atomic generation-pointer io.
  const makePublisherIo = (workspaceId) => makePublisher({ workspaceRoot, workspaceId });

  // ONE shared replay window pinned across both bundles (caveat C1).
  const replaySeen = makeReplayWindow({ maxAgeMs, clock });

  const create = Object.freeze({
    containment,
    gitVerifier,
    makeManifestIo,
    makePublisherIo,
    materialize,
    resolveManifestPaths,
    clock,
    maxAgeMs,
    replaySeen,
  });

  const refresh = Object.freeze({ ...create, acquireFence });
  const resetDelete = assembleResetDelete({
    makePublisherIo,
    makeBackupIo: makeManifestIo,
    resolveManifestPaths,
    makeExclusiveFence,
    makeResidualEnumerator,
    makeResidualIo,
    workspaceLeases,
    hostId,
    workspaceRoot,
    sourcePlatform,
    runtimePlatform,
  });
  const restoreMigration = assembleRestoreMigration({
    makeRetainedByteReader,
    makeManifestResolver,
    makePublisherIo,
    makeExclusiveFence,
    workspaceLeases,
    containment,
    gitVerifier,
    clock,
    maxAgeMs,
    replaySeen,
    runtimePlatform,
  });

  return Object.freeze({ create, refresh, resetDelete, restoreMigration });
}

function assembleResetDelete({
  makePublisherIo,
  makeBackupIo,
  resolveManifestPaths,
  makeExclusiveFence,
  makeResidualEnumerator,
  makeResidualIo,
  workspaceLeases,
  hostId,
  workspaceRoot,
  sourcePlatform,
  runtimePlatform,
}) {
  try {
    if (runtimePlatform !== "linux") return null;
    const acquireFence = makeExclusiveFence(workspaceLeases);
    const enumerator = makeResidualEnumerator();
    if (typeof enumerator?.enumerate_workspace_process_holders !== "function") {
      return null;
    }
    const residualIo = makeResidualIo({ enumerator, hostId, workspaceRoot, sourcePlatform });
    if (
      typeof makePublisherIo !== "function" ||
      typeof makeBackupIo !== "function" ||
      typeof resolveManifestPaths !== "function" ||
      typeof acquireFence !== "function" ||
      typeof residualIo?.listResidualProcesses !== "function"
    ) {
      return null;
    }
    return Object.freeze({
      makePublisherIo,
      makeBackupIo,
      resolveManifestPaths,
      acquireFence,
      residualIo,
    });
  } catch {
    return null;
  }
}

function assembleRestoreMigration({
  makeRetainedByteReader,
  makeManifestResolver,
  makePublisherIo,
  makeExclusiveFence,
  workspaceLeases,
  containment,
  gitVerifier,
  clock,
  maxAgeMs,
  replaySeen,
  runtimePlatform,
}) {
  try {
    // Native no-follow evidence is production-supported only on Linux.
    if (runtimePlatform !== "linux") return null;
    const makeStageReader = (stagingPath, sourcePlatform) =>
      makeRetainedByteReader({ root: stagingPath, sourcePlatform });
    const makeCandidateReader = (candidatePath, sourcePlatform) =>
      makeRetainedByteReader({ root: candidatePath, sourcePlatform });
    const stagePromotion = createRestoreStagePromotion({
      makeStageReader,
      makeCandidateReader,
      resolveManifestPaths: makeManifestResolver({
        rejectUnsupported: true,
      }),
      fs,
    });
    const acquireFence = makeExclusiveFence(workspaceLeases);
    if (
      typeof makePublisherIo !== "function" ||
      typeof makeStageReader !== "function" ||
      typeof acquireFence !== "function" ||
      typeof stagePromotion?.materializeAndVerify !== "function" ||
      typeof stagePromotion?.cleanup !== "function"
    ) {
      return null;
    }
    return Object.freeze({
      containment,
      gitVerifier,
      stagePromotion,
      makeStageReader,
      makePublisherIo,
      acquireFence,
      clock,
      maxAgeMs,
      replaySeen,
    });
  } catch {
    return null;
  }
}
