import assert from "node:assert/strict";
import { test } from "node:test";

import {
  INVENTORY_RECEIPT_TTL_MS,
  MSG_TYPES,
  PROTOCOL_ERROR_CODES,
  PROTOCOL_VERSION_V2,
  PROTOCOL_VERSION_V3,
  READINESS_REMEDIATIONS,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_READINESS_CAPABILITY,
  isBindOkMessage,
  isBindWorkspaceMessage,
  isInventoryReceiptBindOkMessage,
  isInventoryReceiptBindWorkspaceMessage,
  isInventoryReceiptCapabilityGate,
  isInventoryReceiptReadinessMessage,
  isProtocolVersion,
  isReadinessCapabilityGate,
  isReadinessMessage,
  isUnbindOkMessage,
  isUnbindWorkspaceMessage,
} from "../protocol.js";
import {
  isWorkspaceAuthorityDescriptor,
  validateWorkspaceAuthorityDescriptor,
  workspaceBindingFingerprint,
} from "../workspace-binding.js";
import { fingerprintManagedMappingRecord } from "../mapping-envelope.js";

const AUTHORITY_FINGERPRINT = "a".repeat(64);
const INVENTORY_FINGERPRINT = "b".repeat(64);

function authority(overrides = {}) {
  return {
    authorityEpoch: 7,
    fenceGeneration: 5,
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    workspaceGeneration: 2,
    mappingVersion: 1,
    sourcePlatform: "posix",
    workspaceId: "workspace-1",
    authorityFingerprint: AUTHORITY_FINGERPRINT,
    ...overrides,
  };
}

function receipt(overrides = {}) {
  const descriptor = authority();
  return {
    inventoryGeneration: 11,
    inventoryFingerprint: INVENTORY_FINGERPRINT,
    bindingFingerprint: workspaceBindingFingerprint({
      authority: descriptor,
      inventoryGeneration: 11,
      inventoryFingerprint: INVENTORY_FINGERPRINT,
    }),
    ...overrides,
  };
}

function bind(overrides = {}) {
  return {
    type: MSG_TYPES.BIND_WORKSPACE,
    bindingId: "binding-1",
    ...authority(),
    ...overrides,
  };
}

function statuses(workspace = "unknown", overrides = {}) {
  return {
    connection: "online",
    runtime: "ready",
    providerAuth: "configured",
    modelProfile: "ready",
    workspace,
    ...overrides,
  };
}

function readinessError(code, at = 1_000) {
  return {
    code,
    at,
    remediation: READINESS_REMEDIATIONS[code],
  };
}

function bindingReadiness(overrides = {}) {
  return {
    type: MSG_TYPES.READINESS,
    socketGeneration: 1,
    revision: 1,
    observedAt: 1_000,
    ttlMs: INVENTORY_RECEIPT_TTL_MS,
    bindingId: "binding-1",
    workspaceId: "workspace-1",
    workspaceGeneration: 2,
    status: statuses(),
    lastError: readinessError(PROTOCOL_ERROR_CODES.INVENTORY_PENDING),
    ...overrides,
  };
}

test("validates the exact immutable authority descriptor", () => {
  const descriptor = authority();
  assert.equal(validateWorkspaceAuthorityDescriptor(descriptor), descriptor);
  assert.equal(isWorkspaceAuthorityDescriptor(descriptor), true);

  for (const [field, value] of [
    ["authorityEpoch", 0],
    ["fenceGeneration", 0],
    ["hostId", " host-1"],
    ["mappingId", "../mapping"],
    ["mappingId", 123],
    ["mappingGeneration", 0],
    ["workspaceGeneration", 0],
    ["mappingVersion", 0],
    ["sourcePlatform", "darwin"],
    ["workspaceId", "bad/path"],
    ["workspaceId", true],
    ["authorityFingerprint", "A".repeat(64)],
  ]) {
    assert.equal(isWorkspaceAuthorityDescriptor(authority({ [field]: value })), false, field);
  }
  assert.equal(isWorkspaceAuthorityDescriptor({ ...descriptor, routeFingerprint: "c".repeat(64) }), false);
});

test("computes the canonical binding fingerprint without bindingId", () => {
  const descriptor = authority();
  assert.equal(
    workspaceBindingFingerprint({
      authority: descriptor,
      inventoryGeneration: 11,
      inventoryFingerprint: INVENTORY_FINGERPRINT,
    }),
    "c757a989c35040eb424b89bd367c7a662ed4a760c39403fb7423db809e71637a",
  );
  assert.throws(
    () => workspaceBindingFingerprint({
      authority: descriptor,
      inventoryGeneration: 0,
      inventoryFingerprint: INVENTORY_FINGERPRINT,
    }),
    /inventoryGeneration/,
  );
});

test("gates receipt frames on protocol v3 and both capabilities", () => {
  const capabilities = [
    WORKSPACE_READINESS_CAPABILITY,
    WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  ];
  const register = {
    type: MSG_TYPES.REGISTER,
    hostId: "host-1",
    token: "token",
    protocolVersion: PROTOCOL_VERSION_V3,
    capabilities,
  };
  const registerOk = {
    type: MSG_TYPES.REGISTER_OK,
    protocolVersion: PROTOCOL_VERSION_V3,
    capabilities,
  };
  assert.equal(isInventoryReceiptCapabilityGate(register, registerOk), true);
  assert.equal(isInventoryReceiptCapabilityGate({
    negotiatedVersion: PROTOCOL_VERSION_V3,
    localCapabilities: capabilities,
    remoteCapabilities: capabilities,
  }), true);
  assert.equal(isInventoryReceiptCapabilityGate(
    { ...register, capabilities: [WORKSPACE_READINESS_CAPABILITY] },
    registerOk,
  ), false);
  assert.equal(isInventoryReceiptCapabilityGate(
    { ...register, protocolVersion: PROTOCOL_VERSION_V2 },
    { ...registerOk, protocolVersion: PROTOCOL_VERSION_V2 },
  ), false);
  assert.equal(isReadinessCapabilityGate(register, registerOk), false);
  assert.equal(isProtocolVersion(PROTOCOL_VERSION_V3), true);
  assert.equal(isProtocolVersion(PROTOCOL_VERSION_V3 + 1), false);
});

test("keeps old v2 bind shapes isolated from exact receipt binds", () => {
  const receiptMapping = fingerprintManagedMappingRecord({
    mappingId: "mapping-1",
    hostId: "host-1",
    fenceGeneration: 5,
    mappingGeneration: 3,
    workspaceGeneration: 2,
    mappingVersion: 1,
    sourcePlatform: "posix",
    workspaceId: "workspace-1",
    workDir: null,
    sourceRoot: "/srv/native/workspace-1",
    containerRoot: null,
    volumeIdentity: "volume-1",
    casePolicy: "sensitive",
    immutableDefault: false,
    mappingFingerprint: null,
  });
  const receiptBind = bind({
    authorityFingerprint: receiptMapping.mappingFingerprint,
    mapping: receiptMapping,
  });
  assert.equal(isInventoryReceiptBindWorkspaceMessage(receiptBind), true);
  assert.equal(isBindWorkspaceMessage(receiptBind), false);
  // mapping is now REQUIRED on the receipt shape (issue #179 Slice 2)
  {
    const { mapping: _m, ...withoutMapping } = receiptBind;
    assert.equal(isInventoryReceiptBindWorkspaceMessage(withoutMapping), false);
  }
  assert.equal(
    isInventoryReceiptBindWorkspaceMessage({ ...receiptBind, mapping: "not-an-object" }),
    false,
  );
  for (const field of ["authorityEpoch", "fenceGeneration"]) {
    const invalid = { ...receiptBind };
    delete invalid[field];
    assert.equal(isInventoryReceiptBindWorkspaceMessage(invalid), false, field);
  }
  // an UNKNOWN extra key is still rejected by the exact-field-set gate
  for (const extra of [
    { routeFingerprint: "c".repeat(64) },
    { inventoryGeneration: 11 },
    { workDir: "/srv/workspace" },
  ]) {
    assert.equal(isInventoryReceiptBindWorkspaceMessage({ ...receiptBind, ...extra }), false);
  }

  const oldBind = {
    type: MSG_TYPES.BIND_WORKSPACE,
    bindingId: "binding-1",
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 2,
    sourcePlatform: "posix",
    routeFingerprint: "c".repeat(64),
    authorityFingerprint: AUTHORITY_FINGERPRINT,
    inventoryGeneration: 11,
  };
  assert.equal(isBindWorkspaceMessage(oldBind), false);
  assert.equal(isInventoryReceiptBindWorkspaceMessage(oldBind), false);

  // The non-receipt v2 shape remains distinct, but now requires the authority
  // preimage that the daemon verifies before accepting the bind.
  assert.equal(isBindWorkspaceMessage({
    ...oldBind,
    route: { channelId: "123", routeFingerprint: "c".repeat(64) },
    mapping: { mappingId: "mapping-1", mappingFingerprint: "d".repeat(64) },
  }), true);
  // one half of the preimage without the other is never a valid shape
  assert.equal(isBindWorkspaceMessage({ ...oldBind, route: { channelId: "123" } }), false);
  assert.equal(isBindWorkspaceMessage({ ...oldBind, mapping: { mappingId: "m" } }), false);
});

test("validates exact bind acknowledgements and total bindingId-only unbind", () => {
  const proof = receipt();
  const bindOk = {
    type: MSG_TYPES.BIND_OK,
    bindingId: "binding-1",
    ...proof,
  };
  assert.equal(isInventoryReceiptBindOkMessage(bindOk), true);
  assert.equal(isBindOkMessage(bindOk), false);
  assert.equal(isInventoryReceiptBindOkMessage({ ...bindOk, unexpected: true }), false);

  const oldBindOk = {
    type: MSG_TYPES.BIND_OK,
    bindingId: "binding-1",
    bindingFingerprint: proof.bindingFingerprint,
  };
  assert.equal(isBindOkMessage(oldBindOk), true);
  assert.equal(isInventoryReceiptBindOkMessage(oldBindOk), false);

  assert.equal(isUnbindWorkspaceMessage({
    type: MSG_TYPES.UNBIND_WORKSPACE,
    bindingId: "binding-1",
  }), true);
  assert.equal(isUnbindOkMessage({
    type: MSG_TYPES.UNBIND_OK,
    bindingId: "binding-1",
  }), true);
  assert.equal(isUnbindWorkspaceMessage({
    type: MSG_TYPES.UNBIND_WORKSPACE,
    bindingId: "binding-1",
    bindingFingerprint: proof.bindingFingerprint,
  }), false);
  assert.equal(isUnbindOkMessage({
    type: MSG_TYPES.UNBIND_OK,
    bindingId: "../bad",
  }), false);
});

test("validates pending and verified-negative binding readiness without receipts", () => {
  for (const code of [
    PROTOCOL_ERROR_CODES.INVENTORY_PENDING,
    PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
    PROTOCOL_ERROR_CODES.INVENTORY_INVALID,
    PROTOCOL_ERROR_CODES.INVENTORY_ACCESS_DENIED,
    PROTOCOL_ERROR_CODES.INVENTORY_STALE,
    PROTOCOL_ERROR_CODES.INVENTORY_MANUAL_CLEANUP,
    PROTOCOL_ERROR_CODES.INVENTORY_IO_FAILED,
    PROTOCOL_ERROR_CODES.WORKSPACE_ROOT_ESCAPE,
    PROTOCOL_ERROR_CODES.CONTAINMENT_UNSUPPORTED,
    PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED,
  ]) {
    assert.equal(
      isInventoryReceiptReadinessMessage(bindingReadiness({
        lastError: readinessError(code),
      })),
      true,
      code,
    );
  }
  assert.equal(isInventoryReceiptReadinessMessage(bindingReadiness({
    ...receipt(),
  })), false);
  assert.equal(isInventoryReceiptReadinessMessage(bindingReadiness({
    ttlMs: INVENTORY_RECEIPT_TTL_MS - 1,
  })), false);
  assert.equal(isInventoryReceiptReadinessMessage(bindingReadiness({
    status: statuses("unavailable"),
  })), false);
});

test("validates positive receipt readiness and requires all dimensions for ready", () => {
  const proof = receipt();
  const positive = bindingReadiness({
    ...proof,
    lastError: undefined,
  });
  delete positive.lastError;
  assert.equal(isInventoryReceiptReadinessMessage(positive), true);
  assert.equal(isReadinessMessage(positive), false);

  const ready = { ...positive, status: statuses("ready") };
  assert.equal(isInventoryReceiptReadinessMessage(ready), true);
  assert.equal(isInventoryReceiptReadinessMessage({
    ...ready,
    status: statuses("ready", { providerAuth: "unknown" }),
  }), false);
  const partial = { ...positive };
  delete partial.bindingFingerprint;
  assert.equal(isInventoryReceiptReadinessMessage(partial), false);
  assert.equal(isInventoryReceiptReadinessMessage({
    ...positive,
    unexpected: true,
  }), false);
});

test("accepts host-only readiness but forbids receipt identity without a binding", () => {
  const hostOnly = {
    type: MSG_TYPES.READINESS,
    socketGeneration: 1,
    revision: 1,
    observedAt: 1_000,
    status: statuses("unknown"),
  };
  assert.equal(isInventoryReceiptReadinessMessage(hostOnly), true);
  assert.equal(isInventoryReceiptReadinessMessage({
    ...hostOnly,
    workspaceId: "workspace-1",
    workspaceGeneration: 2,
  }), false);
  assert.equal(isInventoryReceiptReadinessMessage({
    ...hostOnly,
    inventoryGeneration: 11,
    inventoryFingerprint: INVENTORY_FINGERPRINT,
    bindingFingerprint: receipt().bindingFingerprint,
  }), false);
});

test("applies socket, revision, timestamp, and skew fences to receipt readiness", () => {
  const value = bindingReadiness();
  assert.equal(isInventoryReceiptReadinessMessage(value, {
    currentSocketGeneration: 1,
    receivedAt: 1_000,
  }), true);
  assert.equal(isInventoryReceiptReadinessMessage(value, {
    currentSocketGeneration: 2,
  }), false);
  assert.equal(isInventoryReceiptReadinessMessage(value, {
    previous: { ...value, revision: 1 },
  }), false);
  assert.equal(isInventoryReceiptReadinessMessage(value, {
    receivedAt: 1_000 + 5 * 60 * 1_000 + 1,
  }), false);
});
