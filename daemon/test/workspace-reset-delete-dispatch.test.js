import test from "node:test";
import assert from "node:assert/strict";
import { MSG_TYPES } from "@gjc-remote/shared";
import { buildGenerationPointer, generationPointerBytes } from "../src/workspace-generation-publisher.js";
import { createLifecycleResetDeleteDispatcher } from "../src/workspace-reset-delete-dispatch.js";

const message = Object.freeze({ type: MSG_TYPES.WORKSPACE_RESET_DELETE, operation: "delete", hostId: "host-a",
  mappingId: "mapping-a", mappingGeneration: 1, mappingVersion: 1, workspaceId: "workspace-a", workspaceGeneration: 3,
  sourcePlatform: "posix", routeFingerprint: "a".repeat(64), authorityFingerprint: "b".repeat(64),
  inventoryGeneration: 1, idempotencyFingerprint: "c".repeat(64) });
const context = (order) => ({ lifecycleAuthority: { anchorFingerprint: "1".repeat(64), fenceGeneration: 1, txId: "tx",
  reason: "owner", expectedFingerprint: null, observedFingerprint: null, expectedFloorFingerprint: null, observedFloorFingerprint: null },
  async probeQuiescence() { order.push("quiescence"); return { pendingInvokes: 0, pendingSessions: 0 }; },
  async prepareTerminal() { order.push("prepare-terminal"); },
  async clearTerminalPreparation() { order.push("clear-terminal"); },
  async commitTerminal() { order.push("terminal"); } });
function pointer() { return buildGenerationPointer({ hostId: message.hostId, workspaceId: message.workspaceId, sourcePlatform: "posix",
  activeGeneration: 3, generationPath: "generations/3", rootIdentityFingerprint: "a".repeat(64), storageIdentityFingerprint: "b".repeat(64),
  gitGenerationFingerprint: "c".repeat(64), manifestFingerprint: "d".repeat(64), priorGeneration: 2, priorPointerFingerprint: "e".repeat(64) }); }
function publisher(bytes, order) { const state = { slot: bytes }; return { async readLivePointer() { order.push("live"); return state.slot; },
  async writeTemp(value) { order.push("publish"); return { value }; }, async flushTemp() {}, async replace(ref) { state.slot = ref.value; }, async flushParent() {} }; }
function args(order, lifecycleContext = context(order)) { return { message, trustedBinding: {
  ...message, authorityEpoch: 1, fenceGeneration: 1,
},
  trustedInventoryWorkspace: { hostId: message.hostId, workspaceId: message.workspaceId, sourcePlatform: "posix", workDir: "D:/work" },
  leaseCandidate: {}, lifecycleContext, readiness: {} }; }

test("dispatcher defers publisher, live, manifest, and reader construction to the fenced operation", async () => {
  const order = []; const live = pointer();
  const dispatcher = createLifecycleResetDeleteDispatcher({ workspaceRoot: "D:/root",
    acquireFence() { order.push("acquire"); return { fence: 1, isCurrent() { order.push("current"); return true; }, release() { order.push("release"); } }; },
    async makePublisherIo() { order.push("publisher"); return publisher(generationPointerBytes(live), order); },
    async resolveManifestPaths() { order.push("manifest"); return ["a"]; },
    makeBackupIo() { order.push("reader"); return { async readBytes() { order.push("backup"); return new TextEncoder().encode("x"); } }; },
    residualIo: { async listResidualProcesses() { order.push("residual"); return []; } },
  });
  const result = await dispatcher.dispatchResetDelete(args(order));
  assert.equal(result.ok, true);
  assert.ok(order.indexOf("acquire") < order.indexOf("quiescence"));
  assert.ok(order.indexOf("quiescence") < order.indexOf("publisher"));
  assert.ok(order.indexOf("live") < order.indexOf("manifest"));
  assert.ok(order.indexOf("manifest") < order.indexOf("reader"));
  assert.ok(order.indexOf("terminal") < order.indexOf("release"));
});

test("dispatcher requires an exact host-held lifecycle context without storage work", async () => {
  let touched = false;
  const dispatcher = createLifecycleResetDeleteDispatcher({ workspaceRoot: "D:/root", acquireFence() { touched = true; },
    makePublisherIo() { touched = true; }, makeBackupIo() { touched = true; }, resolveManifestPaths() { touched = true; },
    residualIo: { async listResidualProcesses() { touched = true; return []; } }, });
  const malformed = context([]); malformed.extra = true;
  const result = await dispatcher.dispatchResetDelete(args([], malformed));
  assert.equal(result.ok, false);
  assert.equal(touched, false);
});
