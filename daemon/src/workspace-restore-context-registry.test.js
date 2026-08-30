import assert from "node:assert/strict";
import test from "node:test";

import { createRestoreContextRegistry, DESTINATION_AUTHORITY_FIELDS } from "./workspace-restore-context-registry.js";

const hex = (character) => character.repeat(64);

function claim(overrides = {}) {
  const base = {
    authorityEpoch: 1,
    fenceGeneration: 2,
    hostId: "host-a",
    mappingId: "mapping-a",
    mappingGeneration: 3,
    mappingVersion: 4,
    workspaceId: "workspace-a",
    workspaceGeneration: 5,
    sourcePlatform: "windows-drive",
    authorityFingerprint: hex("a"),
    operation: "restore",
    idempotencyFingerprint: hex("b"),
    stagingPath: "C:/quarantine/restore-a",
    expectedAuthority: {
      hostId: "source-host",
      roleFingerprint: hex("c"),
      volumeIdentityFingerprint: hex("d"),
      keyFingerprint: hex("e"),
      manifestFingerprint: hex("f"),
      restoredFromWorkspaceId: "source-workspace",
      restoredFromGeneration: 7,
    },
    manifest: { manifestFingerprint: hex("f"), entries: [{ path: "source.txt", size: 1 }] },
    restoredFromWorkspaceId: "source-workspace",
    restoredFromGeneration: 7,
    expectedGraph: { refs: ["refs/heads/main"] },
    probedAtMs: 100,
    expiresAtMs: 200,
  };
  return { ...base, ...overrides };
}

function binding(source = claim()) {
  return Object.fromEntries(DESTINATION_AUTHORITY_FIELDS.map((field) => [field, source[field]]));
}

function registry(claims, now = 150, maxAgeMs = 100) {
  return createRestoreContextRegistry({ claims, clock: { now: () => now }, maxAgeMs });
}

function resolveArgs(source = claim(), overrides = {}) {
  const trustedBinding = overrides.trustedBinding ?? binding(source);
  const operation = overrides.operation ?? source.operation;
  const idempotencyFingerprint =
    overrides.idempotencyFingerprint ?? source.idempotencyFingerprint;
  const message = {
    ...binding(source),
    operation,
    idempotencyFingerprint,
  };
  delete message.authorityEpoch;
  delete message.fenceGeneration;
  return { trustedBinding, message, operation, idempotencyFingerprint };
}

test("resolves an exact trusted receipt-v3 authority once", () => {
  const staged = claim();
  const result = registry([staged]).resolve(resolveArgs(staged));
  assert.ok(result);
  assert.equal(result.stagingPath, staged.stagingPath);
  assert.equal(result.expectedAuthority.keyFingerprint, staged.expectedAuthority.keyFingerprint);
  assert.equal(registry([staged]).snapshot().available, 1);
});

test("rejects every destination authority mismatch", () => {
  const changes = {
    authorityEpoch: 9, fenceGeneration: 9, hostId: "host-b", mappingId: "mapping-b",
    mappingGeneration: 9, mappingVersion: 9, workspaceId: "workspace-b", workspaceGeneration: 9,
    sourcePlatform: "posix", authorityFingerprint: hex("9"),
  };
  for (const [field, value] of Object.entries(changes)) {
    const staged = claim();
    const candidate = binding(staged);
    candidate[field] = value;
    assert.equal(
      registry([staged]).resolve(resolveArgs(staged, {
        trustedBinding: candidate,
      })),
      null,
      field
    );
  }
});

test("rejects operation and idempotency mismatches", () => {
  const staged = claim();
  const contexts = registry([staged]);
  assert.equal(contexts.resolve(resolveArgs(staged, { operation: "migration" })), null);
  assert.equal(contexts.resolve(resolveArgs(staged, { idempotencyFingerprint: hex("1") })), null);
  assert.equal(contexts.snapshot().available, 1);
});

test("a wire authority mismatch cannot consume a sealed claim", () => {
  const staged = claim();
  const contexts = registry([staged]);
  const tampered = resolveArgs(staged);
  tampered.message = { ...tampered.message, mappingGeneration: 99 };
  assert.equal(contexts.resolve(tampered), null);
  assert.equal(contexts.snapshot().available, 1);
  assert.ok(contexts.resolve(resolveArgs(staged)));
});

test("honors inclusive expiry and max-age boundaries, then expires", () => {
  const staged = claim({ expiresAtMs: 200 });
  assert.ok(registry([staged], 200).resolve(resolveArgs(staged)));
  const expired = registry([staged], 201);
  assert.equal(expired.resolve(resolveArgs(staged)), null);
  assert.equal(expired.snapshot().expired, 1);
  assert.throws(() => registry([claim({ expiresAtMs: 201 })]), TypeError);
});

test("consumes claims atomically before returning them", () => {
  const staged = claim();
  const contexts = registry([staged]);
  const request = resolveArgs(staged);
  assert.ok(contexts.resolve(request));
  assert.equal(contexts.resolve(request), null);
  assert.equal(contexts.snapshot().consumed, 1);
});

test("duplicate claim keys are ambiguous and never resolve", () => {
  const staged = claim();
  const contexts = registry([staged, claim({ stagingPath: "C:/quarantine/other" })]);
  assert.equal(contexts.resolve(resolveArgs(staged)), null);
  assert.equal(contexts.snapshot().ambiguous, 1);
});

test("seals a deep defensive copy and freezes returned nested content", () => {
  const staged = claim();
  const contexts = registry([staged]);
  staged.stagingPath = "C:/attacker-path";
  staged.expectedAuthority.keyFingerprint = hex("0");
  staged.manifest.entries[0].path = "attacker";
  const result = contexts.resolve(resolveArgs(claim()));
  assert.equal(result.stagingPath, "C:/quarantine/restore-a");
  assert.equal(result.expectedAuthority.keyFingerprint, hex("e"));
  assert.equal(result.manifest.entries[0].path, "source.txt");
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.manifest) && Object.isFrozen(result.manifest.entries));
  assert.equal(Object.getPrototypeOf(result.expectedAuthority), Object.prototype);
  assert.equal(Object.getPrototypeOf(result.manifest), Object.prototype);
  assert.throws(() => { result.manifest.entries[0].path = "mutated"; }, TypeError);
});

test("requires migrationKind only for migrations", () => {
  assert.throws(() => registry([claim({ operation: "migration" })]), TypeError);
  assert.ok(registry([claim({ operation: "migration", migrationKind: "volume-move" })]));
  assert.throws(() => registry([claim({ migrationKind: "volume-move" })]), TypeError);
});

test("invalidates only exact trusted destination authority", () => {
  const staged = claim();
  const contexts = registry([staged]);
  assert.equal(contexts.invalidateAuthority({ ...binding(staged), fenceGeneration: 99 }), 0);
  assert.equal(contexts.invalidateAuthority(binding(staged)), 1);
  assert.equal(contexts.resolve(resolveArgs(staged)), null);
  assert.equal(contexts.snapshot().invalidated, 1);
});

test("snapshot discloses aggregate state only, never path or claim content", () => {
  const staged = claim({ stagingPath: "C:/secret/quarantine" });
  const snapshot = registry([staged]).snapshot();
  assert.deepEqual(Object.keys(snapshot).sort(), ["ambiguous", "available", "consumed", "expired", "invalidated", "total"]);
  assert.equal(JSON.stringify(snapshot).includes("secret"), false);
  assert.equal(JSON.stringify(snapshot).includes(staged.expectedAuthority.keyFingerprint), false);
  assert.ok(Object.isFrozen(snapshot));
});
