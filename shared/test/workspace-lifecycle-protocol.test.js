import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MSG_TYPES,
  WORKSPACE_LIFECYCLE_OPERATIONS,
  isBindWorkspaceMessage,
  isWorkspaceCreateMessage,
  isWorkspaceLifecycleMessage,
  isWorkspaceRefreshMessage,
  isWorkspaceResetDeleteMessage,
  isWorkspaceRestoreMigrationMessage,
  verifyWorkspaceLifecycleAuthority,
  workspaceLifecycleAuthority,
} from "../protocol.js";

const ROUTE_FP = "a".repeat(64);
const AUTH_FP = "b".repeat(64);
const IDEMPOTENCY_FP = "c".repeat(64);

const AUTHORITY_FIELDS = [
  "hostId",
  "mappingId",
  "mappingGeneration",
  "mappingVersion",
  "workspaceId",
  "workspaceGeneration",
  "sourcePlatform",
  "routeFingerprint",
  "authorityFingerprint",
];

function baseAuthority(overrides = {}) {
  return {
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 2,
    sourcePlatform: "posix",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
    ...overrides,
  };
}

function lifecycleMessage(type, operation, overrides = {}) {
  return {
    type,
    operation,
    ...baseAuthority(),
    inventoryGeneration: 5,
    idempotencyFingerprint: IDEMPOTENCY_FP,
    ...overrides,
  };
}

// --- Positive: one well-formed message per type -----------------------------

test("workspace_create with operation create/clone validates via type validator and umbrella", () => {
  const createMsg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create");
  const cloneMsg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "clone");
  assert.equal(isWorkspaceCreateMessage(createMsg), true);
  assert.equal(isWorkspaceCreateMessage(cloneMsg), true);
  assert.equal(isWorkspaceLifecycleMessage(createMsg), true);
  assert.equal(isWorkspaceLifecycleMessage(cloneMsg), true);
});

test("workspace_refresh with operation refresh validates", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_REFRESH, "refresh");
  assert.equal(isWorkspaceRefreshMessage(msg), true);
  assert.equal(isWorkspaceLifecycleMessage(msg), true);
});

test("workspace_reset_delete with operation reset or delete validates", () => {
  const resetMsg = lifecycleMessage(MSG_TYPES.WORKSPACE_RESET_DELETE, "reset");
  const deleteMsg = lifecycleMessage(MSG_TYPES.WORKSPACE_RESET_DELETE, "delete");
  assert.equal(isWorkspaceResetDeleteMessage(resetMsg), true);
  assert.equal(isWorkspaceResetDeleteMessage(deleteMsg), true);
  assert.equal(isWorkspaceLifecycleMessage(resetMsg), true);
  assert.equal(isWorkspaceLifecycleMessage(deleteMsg), true);
});

test("workspace_restore_migration with operation restore or migration validates", () => {
  const restoreMsg = lifecycleMessage(MSG_TYPES.WORKSPACE_RESTORE_MIGRATION, "restore");
  const migrationMsg = lifecycleMessage(MSG_TYPES.WORKSPACE_RESTORE_MIGRATION, "migration");
  assert.equal(isWorkspaceRestoreMigrationMessage(restoreMsg), true);
  assert.equal(isWorkspaceRestoreMigrationMessage(migrationMsg), true);
  assert.equal(isWorkspaceLifecycleMessage(restoreMsg), true);
  assert.equal(isWorkspaceLifecycleMessage(migrationMsg), true);
});

test("workspaceLifecycleAuthority extracts exactly the 9-field authority tuple", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create");
  const authority = workspaceLifecycleAuthority(msg);
  assert.deepEqual(Object.keys(authority).sort(), [...AUTHORITY_FIELDS].sort());
  for (const field of AUTHORITY_FIELDS) {
    assert.equal(authority[field], msg[field]);
  }
  assert.equal(Object.isFrozen(authority), true);
  assert.equal(Object.prototype.hasOwnProperty.call(authority, "bindingId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(authority, "inventoryGeneration"), false);
  assert.equal(
    Object.prototype.hasOwnProperty.call(authority, "idempotencyFingerprint"),
    false
  );
});

// --- Operation-subset enforcement -------------------------------------------

test("operation subsets are enforced per lifecycle type", () => {
  assert.equal(
    isWorkspaceRefreshMessage(lifecycleMessage(MSG_TYPES.WORKSPACE_REFRESH, "create")),
    false
  );
  assert.equal(
    isWorkspaceResetDeleteMessage(lifecycleMessage(MSG_TYPES.WORKSPACE_RESET_DELETE, "restore")),
    false
  );
  assert.equal(
    isWorkspaceCreateMessage(lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "refresh")),
    false
  );
  assert.equal(
    isWorkspaceRestoreMigrationMessage(
      lifecycleMessage(MSG_TYPES.WORKSPACE_RESTORE_MIGRATION, "delete")
    ),
    false
  );
});

test("WORKSPACE_LIFECYCLE_OPERATIONS map matches the documented per-type subsets", () => {
  assert.deepEqual(
    [...WORKSPACE_LIFECYCLE_OPERATIONS[MSG_TYPES.WORKSPACE_CREATE]].sort(),
    ["clone", "create"]
  );
  assert.deepEqual(
    [...WORKSPACE_LIFECYCLE_OPERATIONS[MSG_TYPES.WORKSPACE_REFRESH]].sort(),
    ["refresh"]
  );
  assert.deepEqual(
    [...WORKSPACE_LIFECYCLE_OPERATIONS[MSG_TYPES.WORKSPACE_RESET_DELETE]].sort(),
    ["delete", "reset"]
  );
  assert.deepEqual(
    [...WORKSPACE_LIFECYCLE_OPERATIONS[MSG_TYPES.WORKSPACE_RESTORE_MIGRATION]].sort(),
    ["migration", "restore"]
  );
});

// --- Exact-field strictness ---------------------------------------------------

test("an extra key makes the message invalid", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create", { extra: "nope" });
  assert.equal(isWorkspaceCreateMessage(msg), false);
});

test("a missing authority field makes the message invalid", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create");
  delete msg.routeFingerprint;
  assert.equal(isWorkspaceCreateMessage(msg), false);
});

test("a present bindingId makes the message invalid (lifecycle carries none)", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create", { bindingId: "mapping-1" });
  assert.equal(isWorkspaceCreateMessage(msg), false);
});

test("a prototype-polluted object is invalid", () => {
  // JSON.parse defines a literal "__proto__" key as a real own data property
  // (it does not walk the prototype chain), so this both exercises the
  // hasOwnProperty-based exact-field check against a hostile payload and
  // confirms it is rejected as an extra/unexpected key rather than silently
  // accepted or used to pollute Object.prototype.
  const msg = JSON.parse(
    `{"type":"workspace_create","operation":"create","hostId":"host-1","mappingId":"mapping-1","mappingGeneration":3,"mappingVersion":1,"workspaceId":"workspace-1","workspaceGeneration":2,"sourcePlatform":"posix","routeFingerprint":"${ROUTE_FP}","authorityFingerprint":"${AUTH_FP}","inventoryGeneration":5,"idempotencyFingerprint":"${IDEMPOTENCY_FP}","__proto__":{"polluted":true}}`
  );
  assert.equal(Object.prototype.hasOwnProperty.call(msg, "__proto__"), true);
  assert.equal(Object.getPrototypeOf(msg), Object.prototype);
  assert.equal(isWorkspaceCreateMessage(msg), false);

  const arrayShaped = ["not", "an", "object"];
  assert.equal(isWorkspaceCreateMessage(arrayShaped), false);
  assert.equal(isWorkspaceLifecycleMessage(null), false);
});

// --- Field validation ---------------------------------------------------------

test("a non-hex64 routeFingerprint is invalid", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create", {
    routeFingerprint: "not-hex",
  });
  assert.equal(isWorkspaceCreateMessage(msg), false);
});

test("an unknown sourcePlatform is invalid", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create", {
    sourcePlatform: "macos",
  });
  assert.equal(isWorkspaceCreateMessage(msg), false);
});

test("a non-integer generation is invalid", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create", {
    mappingGeneration: 1.5,
  });
  assert.equal(isWorkspaceCreateMessage(msg), false);
});

test("a bad idempotencyFingerprint is invalid", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create", {
    idempotencyFingerprint: "short",
  });
  assert.equal(isWorkspaceCreateMessage(msg), false);
});

// --- Authorization invariant (mandatory) --------------------------------------

test("verifyWorkspaceLifecycleAuthority is true when all 9 fields match the trusted authority", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create");
  const trusted = baseAuthority();
  assert.equal(verifyWorkspaceLifecycleAuthority(msg, trusted), true);
});

test("NEGATIVE AUTHORIZATION: a divergent authority field is rejected", () => {
  const trusted = baseAuthority();
  const tamperedFields = [
    { field: "hostId", value: "host-attacker" },
    { field: "mappingId", value: "mapping-attacker" },
    { field: "mappingGeneration", value: 999 },
    { field: "mappingVersion", value: 2 },
    { field: "workspaceId", value: "workspace-attacker" },
    { field: "workspaceGeneration", value: 999 },
    { field: "sourcePlatform", value: "windows-drive" },
    { field: "routeFingerprint", value: "f".repeat(64) },
    { field: "authorityFingerprint", value: "e".repeat(64) },
  ];
  // Pin that EVERY one of the 9 authority fields is enforced, not a subset.
  assert.deepEqual(
    tamperedFields.map((t) => t.field).sort(),
    [...AUTHORITY_FIELDS].sort()
  );
  assert.equal(tamperedFields.length, 9);
  for (const { field, value } of tamperedFields) {
    const tamperedMsg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create", {
      [field]: value,
    });
    assert.equal(
      verifyWorkspaceLifecycleAuthority(tamperedMsg, trusted),
      false,
      `expected rejection when ${field} diverges from the trusted authority`
    );
  }
});

test("NEGATIVE AUTHORIZATION: trustedAuthority missing a field is rejected", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create");
  const trusted = baseAuthority();
  delete trusted.workspaceGeneration;
  assert.equal(verifyWorkspaceLifecycleAuthority(msg, trusted), false);
});

test("NEGATIVE AUTHORIZATION: trustedAuthority with an extra field is rejected", () => {
  const msg = lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create");
  const trusted = baseAuthority({ unexpectedField: "surprise" });
  assert.equal(verifyWorkspaceLifecycleAuthority(msg, trusted), false);
});

test("NEGATIVE AUTHORIZATION: an invalid lifecycle message never authorizes, regardless of trusted match", () => {
  const trusted = baseAuthority();
  const invalidShapeMsg = { ...lifecycleMessage(MSG_TYPES.WORKSPACE_CREATE, "create"), extra: 1 };
  assert.equal(verifyWorkspaceLifecycleAuthority(invalidShapeMsg, trusted), false);
  assert.equal(verifyWorkspaceLifecycleAuthority({ type: "invoke" }, trusted), false);
  assert.equal(verifyWorkspaceLifecycleAuthority(null, trusted), false);
});

// --- Non-lifecycle types ------------------------------------------------------

test("isWorkspaceLifecycleMessage is false for a bind message and a plain invoke message", () => {
  const bindMsg = {
    type: MSG_TYPES.BIND_WORKSPACE,
    bindingId: "mapping-1",
    hostId: "host-1",
    mappingId: "mapping-1",
    mappingGeneration: 3,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 2,
    sourcePlatform: "posix",
    routeFingerprint: ROUTE_FP,
    authorityFingerprint: AUTH_FP,
    inventoryGeneration: 5,
    route: { channelId: "123", routeFingerprint: ROUTE_FP },
    mapping: { mappingId: "mapping-1", mappingFingerprint: AUTH_FP },
  };
  assert.equal(isBindWorkspaceMessage(bindMsg), true);
  assert.equal(isWorkspaceLifecycleMessage(bindMsg), false);
  assert.equal(isWorkspaceLifecycleMessage({ type: "invoke" }), false);
});
