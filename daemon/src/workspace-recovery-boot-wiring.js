// WIRING slice S6f.1 (#53/#81): composes the landed boot-recovery orchestrator
// (recoverWorkspaces, workspace-recovery-operation.js) with the real S6f.1a
// storage io (workspace-generation-storage-io.js) over the boot-local
// filesystem source GJC_NATIVE_WORKSPACE_ROOT. The native-workspace-serving
// gate stays false; nothing here enables serving. `barredWorkspaceIds` is
// produced here and consulted (dead code until S6f.7) by the daemon
// admission path once the gate flips.

import path from "node:path";

import { recoverWorkspaces } from "./workspace-recovery-operation.js";
import {
  createGenerationPublisherIo,
  enumerateRecoverableWorkspaces,
  readSnapshotInputs,
} from "./workspace-generation-storage-io.js";

const ROOT_INVALID_CODE = "WORKSPACE_RECOVERY_ROOT_INVALID";
const BOOT_CONFIG_INVALID_CODE = "WORKSPACE_RECOVERY_BOOT_CONFIG_INVALID";

/**
 * Resolve the boot crash-recovery configuration from `GJC_NATIVE_WORKSPACE_ROOT`.
 *
 * - Unset/empty (after trim) -> recovery is SKIPPED entirely: `{ ok: true,
 *   enabled: false, workspaceRoot: null }`. Consistent with the serving gate
 *   staying false.
 * - A non-empty ABSOLUTE path string -> `{ ok: true, enabled: true,
 *   workspaceRoot }` (trimmed); recovery enumerates only that base directory.
 * - Anything else (non-string, or a relative/empty-after-trim path) -> fail
 *   closed: `{ ok: false, diagnostic }`. The diagnostic is path-free — it
 *   never echoes the raw env value.
 *
 * @param {{ env?: object }} [options]
 */
export function resolveWorkspaceRecoveryConfig({ env } = {}) {
  const raw = env?.GJC_NATIVE_WORKSPACE_ROOT;
  if (raw === undefined || raw === null || (typeof raw === "string" && raw.trim() === "")) {
    return { ok: true, enabled: false, workspaceRoot: null };
  }
  if (typeof raw !== "string") {
    return {
      ok: false,
      diagnostic: { code: ROOT_INVALID_CODE, reason: "GJC_NATIVE_WORKSPACE_ROOT must be a string" },
    };
  }
  const trimmed = raw.trim();
  if (!path.isAbsolute(trimmed)) {
    return {
      ok: false,
      diagnostic: { code: ROOT_INVALID_CODE, reason: "GJC_NATIVE_WORKSPACE_ROOT must be an absolute path" },
    };
  }
  return { ok: true, enabled: true, workspaceRoot: trimmed };
}

/**
 * Run boot crash-recovery over `workspaceRoot`: enumerate recoverable
 * workspaces, pre-build a real generation-publisher io per workspace, and
 * delegate to `recoverWorkspaces`. Errors from recovery (including the
 * `WORKSPACE_ADMISSION_EXCEEDED` queue-ceiling breach) PROPAGATE unchanged —
 * this function never swallows a failure; the daemon caller hard-exits boot
 * on any rejection.
 *
 * @param {{ workspaceRoot: string, deps?: object }} options
 */
export async function runBootRecovery({ workspaceRoot, deps } = {}) {
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    const error = new Error(`workspace_recovery_boot_wiring: ${BOOT_CONFIG_INVALID_CODE}: workspaceRoot must be a non-empty string`);
    error.operation = "workspace_recovery_boot_wiring";
    error.code = BOOT_CONFIG_INVALID_CODE;
    throw error;
  }

  const {
    enumerate = enumerateRecoverableWorkspaces,
    readInputs = readSnapshotInputs,
    createPublisherIo = createGenerationPublisherIo,
    recover = recoverWorkspaces,
  } = deps ?? {};

  const workspaceIds = await enumerate({ workspaceRoot });

  // Publisher io must be pre-built (async) because recoverWorkspaces calls
  // deps.publisherIo(id) SYNCHRONOUSLY.
  const ioMap = new Map();
  await Promise.all(
    workspaceIds.map(async (id) => {
      ioMap.set(id, await createPublisherIo({ workspaceRoot, workspaceId: id }));
    })
  );

  const recoveryDeps = {
    readSnapshotInputs: (id) => readInputs({ workspaceRoot, workspaceId: id }),
    publisherIo: (id) => ioMap.get(id),
  };

  return recover(recoveryDeps, workspaceIds);
}
