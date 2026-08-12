import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJsonHash, parseStrictJsonBytes } from "../strict-json.js";
import { isPrincipal, managementAnchorFingerprint } from "../identity.js";
import { classifyMappingEnvelope, createGenesisEmptyChannels, fingerprintManagedMappingRecord, fingerprintManagedRouteRecord, managedHostSetFingerprint, parseManagedHostTokens, validateManagedChannelsV2 } from "../mapping-envelope.js";

const anchor = {
  anchorVersion: 1,
  configPathFingerprint: "a".repeat(64),
  parentIdentity: "parent-identity",
  targetRelativeName: "channels.json",
  controlRootRelativeName: ".gjc-remote-control",
};

function managedWrapper() {
  const wrapper = {
    version: 1, kind: "managed-v1-wrapper", sourceKind: "managed-v1", managementStamp: "gjc-management-envelope/v1",
    anchorFingerprint: managementAnchorFingerprint(anchor), fenceGeneration: 1, targetRelativeName: "channels.json", targetState: "genesis-empty",
    targetIdentity: "target-identity", targetAclFingerprint: "b".repeat(64), semanticStateFingerprint: null, readerVersion: null,
    dispatchClass: "workspace-only", routeDisposition: "no-route", wrapperSequence: 1, previousWrapperFingerprint: null,
  };
  return { ...wrapper, wrapperFingerprint: canonicalJsonHash(wrapper) };
}

function rootFor(wrapper) {
  const root = {
    version: 1, kind: "management-control-root", managementStamp: "gjc-management-control/v1", anchor,
    anchorFingerprint: managementAnchorFingerprint(anchor), fenceGeneration: 1, sourceKind: "managed-v1", wrapperKind: "managed-v1-wrapper",
    wrapperRelativeName: "managed-v1-wrapper.json", targetRelativeName: "channels.json", controlRootRelativeName: ".gjc-remote-control",
    readerVersionFloorFingerprint: "c".repeat(64), wrapperFingerprint: wrapper.wrapperFingerprint,
  };
  return { ...root, controlRootFingerprint: canonicalJsonHash(root) };
}

test("canonical hash sorts UTF-8 object keys and strict parsing rejects duplicate aliases", () => {
  assert.equal(canonicalJsonHash({ z: 1, ä: 2 }), canonicalJsonHash({ ä: 2, z: 1 }));
  assert.throws(() => parseStrictJsonBytes(Buffer.from('{"a":1,"\\u0061":2}')), /duplicate/);
  assert.throws(() => parseStrictJsonBytes(Buffer.from('{"__proto__":1,"__pro\\u0074o__":2}')), /duplicate/);
  assert.throws(() => parseStrictJsonBytes(Buffer.from([0xc3, 0x28])), /UTF-8/);
});

test("strict parsing keeps prototype-sensitive keys as safe own properties", () => {
  const parsed = parseStrictJsonBytes(Buffer.from('{"__proto__":{"polluted":true},"constructor":{"polluted":true}}'));
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(Object.hasOwn(parsed, "__proto__"), true);
  assert.equal(Object.hasOwn(parsed, "constructor"), true);
  assert.deepEqual(parsed.__proto__, { polluted: true });
  assert.deepEqual(parsed.constructor, { polluted: true });
  assert.equal(Object.prototype.polluted, undefined);
});

test("managed tokens preserve exact IDs and expose only secret-free host fingerprint", () => {
  const tokens = parseManagedHostTokens("z=secret\nä=other\n");
  assert.deepEqual([...tokens.keys()], ["z", "ä"]);
  assert.equal(managedHostSetFingerprint(tokens), managedHostSetFingerprint("ä=different\nz=replaced"));
  assert.throws(() => parseManagedHostTokens("host =token"));
  assert.throws(() => parseManagedHostTokens("host=one\nhost=two"));
  assert.throws(() => parseManagedHostTokens(""));
  assert.throws(() => parseManagedHostTokens("\n"));
});
test("management principals require canonical SID or bounded uid values", () => {
  assert.equal(isPrincipal({ kind: "sid", value: "S-1-5-21-100" }), true);
  assert.equal(isPrincipal({ kind: "uid", value: "uid:1000" }), true);
  assert.equal(isPrincipal({ kind: "uid", value: "1000" }), false);
  assert.equal(isPrincipal({ kind: "uid", value: "uid:01" }), false);
  assert.equal(isPrincipal({ kind: "uid", value: "uid:4294967296" }), false);
  assert.equal(isPrincipal({ kind: "sid", value: "s-1-5-18" }), false);
});

test("managed wrapper pointer rejects mismatch, foreign wrapper, and control-root cycle fields", () => {
  const wrapper = managedWrapper();
  const root = rootFor(wrapper);
  const target = Buffer.from('{}');
  assert.equal(classifyMappingEnvelope({ controlRootBytes: Buffer.from(JSON.stringify(root)), wrapperBytes: Buffer.from(JSON.stringify(wrapper)), targetBytes: target, targetIdentity: "target-identity", targetAclFingerprint: "b".repeat(64) }).ok, true);
  assert.equal(classifyMappingEnvelope({ controlRootBytes: Buffer.from(JSON.stringify({ ...root, wrapperFingerprint: "d".repeat(64) })), wrapperBytes: Buffer.from(JSON.stringify(wrapper)), targetBytes: target }).ok, false);
  assert.equal(classifyMappingEnvelope({ controlRootBytes: Buffer.from(JSON.stringify({ ...root, fenceGeneration: 0 })), wrapperBytes: Buffer.from(JSON.stringify(wrapper)), targetBytes: target }).ok, false);
  const missingFenceRoot = { ...root }; delete missingFenceRoot.fenceGeneration;
  assert.equal(classifyMappingEnvelope({ controlRootBytes: Buffer.from(JSON.stringify(missingFenceRoot)), wrapperBytes: Buffer.from(JSON.stringify(wrapper)), targetBytes: target }).ok, false);
  const foreign = { ...wrapper, anchorFingerprint: "e".repeat(64) };
  foreign.wrapperFingerprint = canonicalJsonHash(Object.fromEntries(Object.entries(foreign).filter(([key]) => key !== "wrapperFingerprint")));
  assert.equal(classifyMappingEnvelope({ controlRootBytes: Buffer.from(JSON.stringify(root)), wrapperBytes: Buffer.from(JSON.stringify(foreign)), targetBytes: target }).ok, false);
  const cycle = { ...wrapper, controlRootFingerprint: root.controlRootFingerprint };
  assert.equal(classifyMappingEnvelope({ controlRootBytes: Buffer.from(JSON.stringify(root)), wrapperBytes: Buffer.from(JSON.stringify(cycle)), targetBytes: target }).ok, false);
});

test("legacy v0 fallback occurs only when the control root is entirely absent", () => {
  const legacy = Buffer.from('{"123":{"hostId":"host","workDir":"/work"}}');
  assert.equal(classifyMappingEnvelope({ controlRootBytes: null, targetBytes: legacy, parseLegacyV0: (value) => value }).sourceKind, "legacy-v0");
  assert.equal(classifyMappingEnvelope({ controlRootBytes: Buffer.from('{}'), targetBytes: legacy }).ok, false);
  assert.equal(classifyMappingEnvelope({ controlRootBytes: null, targetBytes: Buffer.from('{"managementStamp":"gjc-management-envelope/v1"}'), parseLegacyV0: (value) => value }).ok, false);
});

test("versioned channels bind routes to exact mapping identity and generation", () => {
  const mapping = fingerprintManagedMappingRecord({
    mappingId: "mapping-1",
    hostId: "host-A",
    fenceGeneration: 1,
    mappingGeneration: 3,
    workspaceGeneration: 2,
    mappingVersion: 1,
    sourcePlatform: "posix",
    workspaceId: "workspace-1",
    workDir: null,
    sourceRoot: "/srv/repo",
    containerRoot: "/workspace",
    volumeIdentity: "dev:42",
    casePolicy: "sensitive",
    immutableDefault: false,
  });
  const route = fingerprintManagedRouteRecord({
    channelId: "123456789",
    hostId: mapping.hostId,
    mappingId: mapping.mappingId,
    fenceGeneration: mapping.fenceGeneration,
    mappingGeneration: mapping.mappingGeneration,
    workspaceGeneration: mapping.workspaceGeneration,
    mappingVersion: mapping.mappingVersion,
    sourcePlatform: mapping.sourcePlatform,
    workspaceId: mapping.workspaceId,
    workDir: mapping.workDir,
  }, mapping);
  const config = {
    version: 2,
    managementStamp: "gjc-management-channels/v2",
    revision: 4,
    authorityEpoch: 7,
    fenceGeneration: 1,
    mappingGeneration: 3,
    tokenConfigGeneration: 2,
    tokenConfigHostSetFingerprint: "f".repeat(64),
    targetState: "managed",
    dispatchClass: "workspace-only",
    mappings: { [mapping.mappingId]: mapping },
    routes: { [route.channelId]: route },
    configFingerprint: null,
  };
  config.configFingerprint = canonicalJsonHash(Object.fromEntries(Object.entries(config).filter(([key]) => key !== "configFingerprint")));
  assert.equal(validateManagedChannelsV2(config), config);
  assert.throws(() => validateManagedChannelsV2({
    ...config,
    routes: { [route.channelId]: { ...route, mappingGeneration: 2 } },
  }), /MANAGED/);
  const missingFence = { ...config }; delete missingFence.fenceGeneration;
  assert.throws(() => validateManagedChannelsV2(missingFence), /MANAGED/);
  assert.throws(() => validateManagedChannelsV2({ ...config, fenceGeneration: 0 }), /MANAGED/);
});

test("genesis-empty target is exact, route-less, and token-bound", () => {
  const value = createGenesisEmptyChannels({
    tokenConfigGeneration: 1,
    tokenConfigHostSetFingerprint: "a".repeat(64),
    fenceGeneration: 1,
  });
  assert.deepEqual(value.mappings, {});
  assert.deepEqual(value.routes, {});
  assert.equal(value.revision, null);
  assert.throws(() => validateManagedChannelsV2({ ...value, payload: {} }), /INVALID/);
});
