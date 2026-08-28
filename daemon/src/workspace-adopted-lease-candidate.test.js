// Tests for the adopted workspace-lease fence identity helpers (issue #182).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  projectReceiptAuthority,
  resolveReceiptActivityIdentity,
  buildAdoptedLeaseCandidate,
  resolveAdoptedLeaseCandidateForWorkspace,
} from "./workspace-adopted-lease-candidate.js";

const HEX64_A = "a".repeat(64);
const HEX64_B = "b".repeat(64);

function receiptBinding(over = {}) {
  return {
    workspaceId: "ws-1",
    bindingId: "bind-1",
    authorityEpoch: 7,
    fenceGeneration: 3,
    hostId: "host-1",
    mappingId: "map-1",
    mappingGeneration: 2,
    mappingVersion: 1,
    workspaceGeneration: 4,
    sourcePlatform: "linux",
    authorityFingerprint: "af-1",
    ...over,
  };
}

function receiptState(over = {}) {
  return {
    receipt: over.receipt ?? true,
    binding: receiptBinding(over.binding),
    proof: { bindingFingerprint: HEX64_A, ...(over.proof ?? {}) },
  };
}

function legacyState(over = {}) {
  return {
    receipt: false,
    binding: { workspaceId: "ws-legacy", hostId: "host-1", ...(over.binding ?? {}) },
  };
}

const legacyHash = () => HEX64_B;

test("projectReceiptAuthority keeps only the V3 authority tuple", () => {
  const auth = projectReceiptAuthority(receiptBinding());
  assert.deepEqual(Object.keys(auth).sort(), [
    "authorityEpoch", "authorityFingerprint", "fenceGeneration", "hostId",
    "mappingGeneration", "mappingId", "mappingVersion", "sourcePlatform",
    "workspaceGeneration", "workspaceId",
  ]);
  assert.equal(auth.bindingId, undefined);
  assert.equal(auth.authorityEpoch, 7);
});

test("resolveReceiptActivityIdentity returns the proof-sourced identity for a receipt binding", () => {
  const id = resolveReceiptActivityIdentity(5, receiptState());
  assert.deepEqual({ ...id }, { socketGeneration: 5, bindingId: "bind-1", bindingFingerprint: HEX64_A });
});

test("resolveReceiptActivityIdentity fails closed on non-receipt / bad inputs", () => {
  assert.equal(resolveReceiptActivityIdentity(5, legacyState()), undefined);
  assert.equal(resolveReceiptActivityIdentity(0, receiptState()), undefined);
  assert.equal(resolveReceiptActivityIdentity(1.5, receiptState()), undefined);
  assert.equal(resolveReceiptActivityIdentity(5, receiptState({ proof: { bindingFingerprint: "short" } })), undefined);
  assert.equal(resolveReceiptActivityIdentity(5, receiptState({ binding: { bindingId: 42 } })), undefined);
});

test("buildAdoptedLeaseCandidate builds a receipt candidate = authority + fingerprint + activity identity", () => {
  const cand = buildAdoptedLeaseCandidate({
    socketGeneration: 9,
    bindingState: receiptState(),
    computeLegacyBindingFingerprint: legacyHash,
  });
  assert.ok(Object.isFrozen(cand));
  assert.equal(cand.bindingFingerprint, HEX64_A); // proof, NOT legacy hash
  assert.equal(cand.socketGeneration, 9);
  assert.equal(cand.bindingId, "bind-1");
  assert.equal(cand.authorityEpoch, 7);
});

test("buildAdoptedLeaseCandidate builds a legacy candidate from the flat binding + legacy hash", () => {
  const cand = buildAdoptedLeaseCandidate({
    socketGeneration: 9,
    bindingState: legacyState(),
    computeLegacyBindingFingerprint: legacyHash,
  });
  assert.equal(cand.bindingFingerprint, HEX64_B);
  assert.equal(cand.socketGeneration, undefined); // no receipt identity for legacy
  assert.equal(cand.workspaceId, "ws-legacy");
});

test("buildAdoptedLeaseCandidate fails closed on malformed inputs", () => {
  assert.equal(buildAdoptedLeaseCandidate({ socketGeneration: 9, bindingState: null, computeLegacyBindingFingerprint: legacyHash }), null);
  assert.equal(buildAdoptedLeaseCandidate({ socketGeneration: 9, bindingState: { binding: null }, computeLegacyBindingFingerprint: legacyHash }), null);
  assert.equal(buildAdoptedLeaseCandidate({ socketGeneration: 9, bindingState: legacyState() }), null); // no hash fn
  assert.equal(buildAdoptedLeaseCandidate({ socketGeneration: 9, bindingState: legacyState(), computeLegacyBindingFingerprint: () => "nothex" }), null);
  assert.equal(buildAdoptedLeaseCandidate({ socketGeneration: 9, bindingState: legacyState(), computeLegacyBindingFingerprint: () => { throw new Error("boom"); } }), null);
});

test("resolveAdoptedLeaseCandidateForWorkspace matches an unambiguous workspaceId", () => {
  const bindings = new Map([["b1", receiptState()]]);
  const cand = resolveAdoptedLeaseCandidateForWorkspace({
    bindings, socketGeneration: 9, workspaceId: "ws-1", computeLegacyBindingFingerprint: legacyHash,
  });
  assert.equal(cand.bindingFingerprint, HEX64_A);
  assert.equal(cand.bindingId, "bind-1");
});

test("resolveAdoptedLeaseCandidateForWorkspace returns null on ambiguous / missing / bad inputs", () => {
  const dup = new Map([["b1", receiptState()], ["b2", receiptState({ binding: { bindingId: "bind-2", workspaceId: "ws-1" } })]]);
  assert.equal(resolveAdoptedLeaseCandidateForWorkspace({ bindings: dup, socketGeneration: 9, workspaceId: "ws-1", computeLegacyBindingFingerprint: legacyHash }), null);
  const one = new Map([["b1", receiptState()]]);
  assert.equal(resolveAdoptedLeaseCandidateForWorkspace({ bindings: one, socketGeneration: 9, workspaceId: "absent", computeLegacyBindingFingerprint: legacyHash }), null);
  assert.equal(resolveAdoptedLeaseCandidateForWorkspace({ bindings: null, socketGeneration: 9, workspaceId: "ws-1", computeLegacyBindingFingerprint: legacyHash }), null);
  assert.equal(resolveAdoptedLeaseCandidateForWorkspace({ bindings: one, socketGeneration: 9, workspaceId: "", computeLegacyBindingFingerprint: legacyHash }), null);
});
