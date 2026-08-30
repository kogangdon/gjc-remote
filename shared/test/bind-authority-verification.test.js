import assert from "node:assert/strict";
import test from "node:test";

import { verifyBindAuthorityPreimage, verifyReceiptBindAuthorityPreimage } from "../bind-authority-verification.js";
import {
  isBindWorkspaceMessage,
  MSG_TYPES,
  PROTOCOL_ERROR_CODES,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
} from "../protocol.js";
import {
  fingerprintManagedMappingRecord,
  fingerprintManagedRouteRecord,
} from "../mapping-envelope.js";

const HOST = "host";

function buildMapping(overrides = {}) {
  return fingerprintManagedMappingRecord({
    mappingId: "mapping-1",
    hostId: HOST,
    fenceGeneration: 1,
    mappingGeneration: 4,
    workspaceGeneration: 7,
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
    ...overrides,
  });
}

function buildRoute(mapping, overrides = {}) {
  return fingerprintManagedRouteRecord({
    channelId: "123",
    hostId: mapping.hostId,
    mappingId: mapping.mappingId,
    fenceGeneration: mapping.fenceGeneration,
    mappingGeneration: mapping.mappingGeneration,
    workspaceGeneration: mapping.workspaceGeneration,
    mappingVersion: mapping.mappingVersion,
    sourcePlatform: mapping.sourcePlatform,
    workspaceId: mapping.workspaceId,
    workDir: mapping.workDir,
    routeFingerprint: null,
    ...overrides,
  }, mapping);
}

function buildBind(route, mapping, overrides = {}) {
  return {
    type: MSG_TYPES.BIND_WORKSPACE,
    bindingId: "binding-1",
    hostId: route.hostId,
    mappingId: route.mappingId,
    mappingGeneration: route.mappingGeneration,
    mappingVersion: route.mappingVersion,
    workspaceId: route.workspaceId,
    workspaceGeneration: route.workspaceGeneration,
    sourcePlatform: route.sourcePlatform,
    routeFingerprint: route.routeFingerprint,
    authorityFingerprint: mapping.mappingFingerprint,
    inventoryGeneration: 1,
    route,
    mapping,
    ...overrides,
  };
}

// Minimal posix-only lexical containment fake mirroring the daemon's
// relativeComponents escape-throwing contract: returns for a contained path,
// throws on any escape.
function lexicalAssertContained(root, candidate, sourcePlatform) {
  const sep = sourcePlatform === "posix" ? "/" : "\\";
  if (typeof candidate !== "string" || candidate.includes("..")) {
    throw new Error("WORKSPACE_ROOT_ESCAPE");
  }
  if (candidate === root) return [];
  const prefix = root.endsWith(sep) ? root : root + sep;
  if (!candidate.startsWith(prefix)) throw new Error("WORKSPACE_ROOT_ESCAPE");
  return candidate.slice(prefix.length).split(sep).filter(Boolean);
}

test("BIND_WORKSPACE requires the complete route and mapping preimage", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  assert.equal(isBindWorkspaceMessage(buildBind(route, mapping)), true);

  const { route: _r, mapping: _m, ...withoutPreimage } = buildBind(route, mapping);
  assert.equal(isBindWorkspaceMessage(withoutPreimage), false);

  const { route: _r2, ...withoutRoute } = buildBind(route, mapping);
  assert.equal(isBindWorkspaceMessage(withoutRoute), false);
  const { mapping: _m2, ...withoutMapping } = buildBind(route, mapping);
  assert.equal(isBindWorkspaceMessage(withoutMapping), false);

  // extra unknown key is rejected (exact key set)
  assert.equal(isBindWorkspaceMessage(buildBind(route, mapping, { extra: 1 })), false);
  // route/mapping present but non-object fails the shape gate
  assert.equal(isBindWorkspaceMessage(buildBind(route, mapping, { route: "x" })), false);
});

test("capability constant is a stable, distinct wire string", () => {
  assert.equal(
    WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
    "workspace_bind_authority_verification_v1",
  );
});

test("valid preimage verifies (no containment configured)", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), { hostId: HOST });
  assert.deepEqual(result, { ok: true, code: null });
});

test("tampered routeFingerprint is rejected", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  const message = buildBind(route, mapping, {
    route: { ...route, routeFingerprint: "f".repeat(64) },
    routeFingerprint: "f".repeat(64),
  });
  const result = verifyBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("tampered mapping (mappingFingerprint) is rejected", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  const message = buildBind(route, mapping, {
    mapping: { ...mapping, mappingFingerprint: "e".repeat(64) },
    authorityFingerprint: "e".repeat(64),
  });
  const result = verifyBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("authorityFingerprint that disagrees with mapping is rejected", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  const message = buildBind(route, mapping, { authorityFingerprint: "a".repeat(64) });
  const result = verifyBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("hostId that is not the daemon's own HOST_ID is rejected", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), { hostId: "other-host" });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HOSTID_MISMATCH);
});

test("route<->mapping cross-field disagreement is rejected", () => {
  // route is internally hash-valid but was built for a DIFFERENT mapping
  // (workspace-2), then presented alongside the workspace-1 mapping. Both
  // records are self-consistent; only the cross-field check catches the
  // disagreement inside validateManagedRouteRecord.
  const mappingA = buildMapping();
  const mappingB = buildMapping({ workspaceId: "workspace-2" });
  const routeB = buildRoute(mappingB);
  const message = buildBind(routeB, mappingA);
  const result = verifyBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("top-level tuple that disagrees with the verified route is rejected", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  // preimage is genuine but the servable top-level workspaceId is swapped.
  const message = buildBind(route, mapping, { workspaceId: "workspace-9" });
  const result = verifyBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("tier-2 containment is a no-op when no daemon root is configured", () => {
  // sourceRoot deliberately points outside any plausible daemon root; with no
  // containment context this must still verify, proving tier-2 is not claimed
  // on the default deployment.
  const mapping = buildMapping({ sourceRoot: "/etc/elsewhere" });
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), { hostId: HOST });
  assert.deepEqual(result, { ok: true, code: null });
});

test("tier-2 containment passes a sourceRoot contained under the configured root", () => {
  const mapping = buildMapping({ sourceRoot: "/srv/native/workspace-1" });
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), {
    hostId: HOST,
    containment: { root: "/srv/native", sourcePlatform: "posix", assertContained: lexicalAssertContained },
  });
  assert.deepEqual(result, { ok: true, code: null });
});

test("tier-2 containment rejects a forged sourceRoot escaping the configured root", () => {
  const mapping = buildMapping({ sourceRoot: "/etc/evil" });
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), {
    hostId: HOST,
    containment: { root: "/srv/native", sourcePlatform: "posix", assertContained: lexicalAssertContained },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
});

test("tier-2 containment fails closed on a platform mismatch with the configured root", () => {
  const mapping = buildMapping({ sourceRoot: "/srv/native/workspace-1" });
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), {
    hostId: HOST,
    containment: { root: "C:\\native", sourcePlatform: "windows-drive", assertContained: lexicalAssertContained },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
});

test("tier-2 containment rejects a forged legacy workDir escaping the configured root", () => {
  const mapping = buildMapping({
    workspaceId: null,
    workDir: "/etc/evil",
    sourceRoot: "/srv/native/legacy",
  });
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), {
    hostId: HOST,
    containment: { root: "/srv/native", sourcePlatform: "posix", assertContained: lexicalAssertContained },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
});

test("tier-2 containerRoot is checked against an injected container root", () => {
  // containerRoot is a canonical POSIX root but escapes the injected
  // container-namespace root "/workspace".
  const mapping = buildMapping({ containerRoot: "/other/tree" });
  const route = buildRoute(mapping);
  const result = verifyBindAuthorityPreimage(buildBind(route, mapping), {
    hostId: HOST,
    containment: {
      root: "/srv/native",
      sourcePlatform: "posix",
      containerRoot: "/workspace",
      assertContained: lexicalAssertContained,
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
});

test("malformed input (missing context.hostId) fails closed", () => {
  const mapping = buildMapping();
  const route = buildRoute(mapping);
  assert.equal(verifyBindAuthorityPreimage(buildBind(route, mapping), {}).ok, false);
  assert.equal(verifyBindAuthorityPreimage(null, { hostId: HOST }).ok, false);
});

// -----------------------------------------------------------------------
// verifyReceiptBindAuthorityPreimage (issue #179 Slice 2): the LIVE
// managed-workspace receipt bind path. Commits to a SINGLE mapping-record
// preimage (no routeFingerprint in the receipt shape).
// -----------------------------------------------------------------------

function buildReceiptMapping(overrides = {}) {
  return fingerprintManagedMappingRecord({
    mappingId: "mapping-1",
    hostId: HOST,
    fenceGeneration: 1,
    mappingGeneration: 4,
    workspaceGeneration: 7,
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
    ...overrides,
  });
}

function buildReceiptBind(mapping, overrides = {}) {
  return {
    type: MSG_TYPES.BIND_WORKSPACE,
    bindingId: "receipt-binding-1",
    authorityEpoch: 1,
    fenceGeneration: mapping.fenceGeneration,
    hostId: mapping.hostId,
    mappingId: mapping.mappingId,
    mappingGeneration: mapping.mappingGeneration,
    mappingVersion: mapping.mappingVersion,
    workspaceId: mapping.workspaceId,
    workspaceGeneration: mapping.workspaceGeneration,
    sourcePlatform: mapping.sourcePlatform,
    authorityFingerprint: mapping.mappingFingerprint,
    mapping,
    ...overrides,
  };
}

test("receipt: valid preimage verifies (no containment configured)", () => {
  const mapping = buildReceiptMapping();
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), { hostId: HOST });
  assert.deepEqual(result, { ok: true, code: null });
});

test("receipt: hash-tampered mapping (mutate without recomputing fingerprint) is rejected", () => {
  const mapping = buildReceiptMapping();
  const tamperedMapping = { ...mapping, sourceRoot: "/srv/native/tampered" };
  const result = verifyReceiptBindAuthorityPreimage(
    buildReceiptBind(mapping, { mapping: tamperedMapping }),
    { hostId: HOST },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("receipt: top-level hostId mismatch (vs context.hostId) is rejected", () => {
  const mapping = buildReceiptMapping();
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), { hostId: "other-host" });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HOSTID_MISMATCH);
});

test("receipt: authorityFingerprint not matching mapping.mappingFingerprint is rejected", () => {
  const mapping = buildReceiptMapping();
  const result = verifyReceiptBindAuthorityPreimage(
    buildReceiptBind(mapping, { authorityFingerprint: "f".repeat(64) }),
    { hostId: HOST },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("receipt: each of the 8 cross-checked tuple fields is enforced", () => {
  const mapping = buildReceiptMapping();
  const fields = [
    ["mappingId", "mapping-2"],
    ["mappingGeneration", mapping.mappingGeneration + 1],
    ["workspaceGeneration", mapping.workspaceGeneration + 1],
    ["mappingVersion", 2],
    ["sourcePlatform", "windows-drive"],
    ["workspaceId", "workspace-2"],
    ["fenceGeneration", mapping.fenceGeneration + 1],
  ];
  for (const [field, badValue] of fields) {
    const message = buildReceiptBind(mapping, { [field]: badValue });
    const result = verifyReceiptBindAuthorityPreimage(message, { hostId: HOST });
    assert.equal(result.ok, false, `expected ${field} mismatch to fail`);
    assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH, field);
  }
  // hostId tuple mismatch (top-level vs mapping) surfaces as HOSTID_MISMATCH
  // via the ground-truth check, not the generic tuple loop, since hostId is
  // checked against context.hostId first.
});

test("receipt: malformed mapping (fails validateManagedMappingRecord) is rejected", () => {
  const mapping = buildReceiptMapping();
  const { mappingFingerprint: _mf, ...brokenMapping } = mapping;
  const message = buildReceiptBind(mapping, { mapping: brokenMapping });
  const result = verifyReceiptBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("receipt: missing/non-object mapping is rejected", () => {
  const mapping = buildReceiptMapping();
  const message = buildReceiptBind(mapping, { mapping: "not-an-object" });
  const result = verifyReceiptBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("receipt: mapping.hostId not matching context.hostId is rejected (defense in depth)", () => {
  const mapping = buildReceiptMapping({ hostId: HOST });
  // Forge a message whose top-level hostId matches context but whose mapping
  // carries a foreign hostId (impossible to construct via a valid mapping
  // fingerprint over a different hostId without recomputation, so we tamper
  // post-fingerprinting to exercise the belt-and-suspenders hostId check in
  // isolation -- this ALSO trips HASH_MISMATCH first since the fingerprint no
  // longer matches; to isolate step 5 we recompute the fingerprint over the
  // forged hostId, matching authorityFingerprint but diverging ground truth).
  const forgedMapping = fingerprintManagedMappingRecord({ ...mapping, mappingFingerprint: null, hostId: "other-host" });
  const message = {
    ...buildReceiptBind(mapping, { mapping: forgedMapping, hostId: HOST }),
    authorityFingerprint: forgedMapping.mappingFingerprint,
  };
  const result = verifyReceiptBindAuthorityPreimage(message, { hostId: HOST });
  assert.equal(result.ok, false);
  // hostId is part of the cross-checked tuple, so a genuine mapping-authored
  // mismatch surfaces as HASH_MISMATCH via the tuple loop before step 5 runs.
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
});

test("receipt: authorityEpoch is not cross-checked (residual trust, absent from mapping)", () => {
  const mapping = buildReceiptMapping();
  // authorityEpoch is not a MAPPING_KEYS field; an inflated top-level
  // authorityEpoch cannot be verified against the mapping and must NOT cause
  // a spurious rejection -- it is documented residual trust.
  const message = buildReceiptBind(mapping, { authorityEpoch: 999 });
  const result = verifyReceiptBindAuthorityPreimage(message, { hostId: HOST });
  assert.deepEqual(result, { ok: true, code: null });
});

test("receipt: no-op tier-2 containment without a configured root", () => {
  const mapping = buildReceiptMapping({ sourceRoot: "/etc/elsewhere" });
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), { hostId: HOST });
  assert.deepEqual(result, { ok: true, code: null });
});

test("receipt: tier-2 containment passes a sourceRoot contained under the configured root", () => {
  const mapping = buildReceiptMapping({ sourceRoot: "/srv/native/workspace-1" });
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), {
    hostId: HOST,
    containment: { root: "/srv/native", sourcePlatform: "posix", assertContained: lexicalAssertContained },
  });
  assert.deepEqual(result, { ok: true, code: null });
});

test("receipt: tier-2 containment rejects a forged sourceRoot escaping the configured root", () => {
  const mapping = buildReceiptMapping({ sourceRoot: "/etc/evil" });
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), {
    hostId: HOST,
    containment: { root: "/srv/native", sourcePlatform: "posix", assertContained: lexicalAssertContained },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
});

test("receipt: tier-2 containment fails closed on a platform mismatch with the configured root", () => {
  const mapping = buildReceiptMapping({ sourceRoot: "/srv/native/workspace-1" });
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), {
    hostId: HOST,
    containment: { root: "C:\\native", sourcePlatform: "windows-drive", assertContained: lexicalAssertContained },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
});

test("receipt: containerRoot===null under a configured containerRoot is a no-op, not an escape", () => {
  const mapping = buildReceiptMapping({ containerRoot: null });
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), {
    hostId: HOST,
    containment: {
      root: "/srv/native",
      sourcePlatform: "posix",
      containerRoot: "/workspace",
      assertContained: lexicalAssertContained,
    },
  });
  assert.deepEqual(result, { ok: true, code: null });
});

test("receipt: containerRoot is checked against an injected container root", () => {
  const mapping = buildReceiptMapping({ containerRoot: "/other/tree" });
  const result = verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), {
    hostId: HOST,
    containment: {
      root: "/srv/native",
      sourcePlatform: "posix",
      containerRoot: "/workspace",
      assertContained: lexicalAssertContained,
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
});

test("receipt: malformed input (missing context.hostId) fails closed", () => {
  const mapping = buildReceiptMapping();
  assert.equal(verifyReceiptBindAuthorityPreimage(buildReceiptBind(mapping), {}).ok, false);
  assert.equal(verifyReceiptBindAuthorityPreimage(null, { hostId: HOST }).ok, false);
});
