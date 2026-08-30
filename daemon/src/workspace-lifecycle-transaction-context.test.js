import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJsonHash } from "@gjc-remote/shared/strict-json.js";
import { validateManualCleanup } from "@gjc-remote/shared/recovery-envelope.js";
import { createResetDeleteLifecycleContext } from "./workspace-lifecycle-transaction-context.js";

const AUTHORITY_FINGERPRINT = "b".repeat(64);
const IDEMPOTENCY_FINGERPRINT = "c".repeat(64);

function binding(overrides = {}) {
  return {
    authorityEpoch: 6,
    fenceGeneration: 7,
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 2,
    workspaceId: "workspace-1",
    workspaceGeneration: 4,
    sourcePlatform: "windows-drive",
    authorityFingerprint: AUTHORITY_FINGERPRINT,
    bindingId: "accepted-binding-1",
    inventoryGeneration: 5,
    ...overrides,
  };
}

function input(overrides = {}) {
  return {
    trustedBinding: binding(),
    operation: "reset",
    idempotencyFingerprint: IDEMPOTENCY_FINGERPRINT,
    probeQuiescence: async () => ({ quiescent: true }),
    prepareTerminal: async () => {},
    clearTerminalPreparation: async () => {},
    commitTerminal: async () => {},
    ...overrides,
  };
}

function manualCleanupRecord(authority) {
  const record = {
    version: 1,
    kind: "manual-cleanup",
    ...authority,
    routeDisposition: "no-route",
    blockedUntilOwnerAction: true,
    manualCleanupFingerprint: null,
  };
  record.manualCleanupFingerprint = canonicalJsonHash(
    Object.fromEntries(Object.entries(record).filter(([key]) => key !== "manualCleanupFingerprint")),
  );
  return record;
}

function assertConfigInvalid(call) {
  assert.throws(call, (error) => error?.code === "CONFIG_INVALID");
}

test("reset/delete lifecycle context is exact, deeply frozen, and valid for manual cleanup", () => {
  const args = input();
  const context = createResetDeleteLifecycleContext(args);

  assert.deepEqual(Object.keys(context), [
    "lifecycleAuthority",
    "probeQuiescence",
    "prepareTerminal",
    "clearTerminalPreparation",
    "commitTerminal",
  ]);
  assert.deepEqual(Object.keys(context.lifecycleAuthority), [
    "anchorFingerprint", "fenceGeneration", "txId", "reason",
    "expectedFingerprint", "observedFingerprint", "expectedFloorFingerprint",
    "observedFloorFingerprint",
  ]);
  assert.ok(Object.isFrozen(context));
  assert.ok(Object.isFrozen(context.lifecycleAuthority));
  assert.equal(context.probeQuiescence, args.probeQuiescence);
  assert.equal(context.prepareTerminal, args.prepareTerminal);
  assert.equal(context.clearTerminalPreparation, args.clearTerminalPreparation);
  assert.equal(context.commitTerminal, args.commitTerminal);
  assert.equal(context.lifecycleAuthority.anchorFingerprint, AUTHORITY_FINGERPRINT);
  assert.equal(context.lifecycleAuthority.fenceGeneration, 7);
  validateManualCleanup(manualCleanupRecord(context.lifecycleAuthority));
});

test("reset/delete lifecycle transaction identity is deterministic and operation-bound", () => {
  const first = createResetDeleteLifecycleContext(input());
  const second = createResetDeleteLifecycleContext(input());
  const deleted = createResetDeleteLifecycleContext(input({ operation: "delete" }));
  const replay = createResetDeleteLifecycleContext(input({ idempotencyFingerprint: "d".repeat(64) }));

  assert.equal(first.lifecycleAuthority.txId, second.lifecycleAuthority.txId);
  assert.notEqual(first.lifecycleAuthority.txId, deleted.lifecycleAuthority.txId);
  assert.notEqual(first.lifecycleAuthority.txId, replay.lifecycleAuthority.txId);
});

test("every accepted binding authority identity field affects reset/delete transaction identity", () => {
  const baseline = createResetDeleteLifecycleContext(input()).lifecycleAuthority.txId;
  const changes = {
    authorityEpoch: 7,
    fenceGeneration: 8,
    hostId: "host-2",
    mappingId: "mapping-2",
    mappingGeneration: 4,
    mappingVersion: 3,
    workspaceId: "workspace-2",
    workspaceGeneration: 5,
    sourcePlatform: "posix",
    authorityFingerprint: "e".repeat(64),
  };

  for (const [field, value] of Object.entries(changes)) {
    const txId = createResetDeleteLifecycleContext(input({
      trustedBinding: binding({ [field]: value }),
    })).lifecycleAuthority.txId;
    assert.notEqual(txId, baseline, field);
  }
});

test("reset/delete lifecycle authority keeps recovery observations null", () => {
  const authority = createResetDeleteLifecycleContext(input()).lifecycleAuthority;
  assert.equal(authority.expectedFingerprint, null);
  assert.equal(authority.observedFingerprint, null);
  assert.equal(authority.expectedFloorFingerprint, null);
  assert.equal(authority.observedFloorFingerprint, null);
});

test("reset/delete lifecycle context rejects bad or missing trusted authority", () => {
  for (const trustedBinding of [
    null,
    {},
    binding({ authorityFingerprint: "not-a-fingerprint" }),
    binding({ mappingId: "bad mapping" }),
    binding({ workspaceId: "" }),
  ]) {
    assertConfigInvalid(() => createResetDeleteLifecycleContext(input({ trustedBinding })));
  }
});

test("reset/delete lifecycle context rejects zero and invalid binding generations", () => {
  for (const field of [
    "authorityEpoch",
    "fenceGeneration",
    "mappingGeneration",
    "mappingVersion",
    "workspaceGeneration",
  ]) {
    assertConfigInvalid(() => createResetDeleteLifecycleContext(input({
      trustedBinding: binding({ [field]: 0 }),
    })));
    assertConfigInvalid(() => createResetDeleteLifecycleContext(input({
      trustedBinding: binding({ [field]: 1.5 }),
    })));
  }
});

test("reset/delete lifecycle context rejects unsupported operations, bad idempotency, and callbacks", () => {
  assertConfigInvalid(() => createResetDeleteLifecycleContext(input({ operation: "create" })));
  assertConfigInvalid(() => createResetDeleteLifecycleContext(input({ idempotencyFingerprint: "invalid" })));
  assertConfigInvalid(() => createResetDeleteLifecycleContext(input({ probeQuiescence: null })));
  assertConfigInvalid(() => createResetDeleteLifecycleContext(input({ prepareTerminal: null })));
  assertConfigInvalid(() => createResetDeleteLifecycleContext(input({ clearTerminalPreparation: null })));
  assertConfigInvalid(() => createResetDeleteLifecycleContext(input({ commitTerminal: null })));
});
