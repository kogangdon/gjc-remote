import assert from "node:assert/strict";
import test from "node:test";
import { evaluateGenerationReadiness, DIMENSIONS, LIVE_SOURCE } from "../src/workspace-generation-probe.js";

const FP = {
  pointerFingerprint: "1".repeat(64),
  rootIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64),
  manifestFingerprint: "4".repeat(64),
};

function baseEvidence(overrides = {}) {
  const ev = {
    connection: { state: "online", source: LIVE_SOURCE },
    runtime: { state: "ready", source: LIVE_SOURCE },
    providerAuth: { state: "configured", source: LIVE_SOURCE },
    modelProfile: { state: "ready", source: LIVE_SOURCE },
    workspace: { state: "ready", source: LIVE_SOURCE, generation: { ...FP }, expected: { ...FP } },
    freshness: { probedAtMs: 1_000, nowMs: 1_500, maxAgeMs: 5_000 },
  };
  return { ...ev, ...overrides };
}

const rejectsCode = (evidence, code) =>
  assert.throws(() => evaluateGenerationReadiness(evidence), (e) => e.operation === "workspace_generation_probe" && e.code === code);

test("returns a frozen ready attestation when every dimension is proven by live evidence", () => {
  const result = evaluateGenerationReadiness(baseEvidence());
  assert.equal(result.ready, true);
  assert.deepEqual({ ...result.dimensions }, {
    connection: "online", runtime: "ready", providerAuth: "configured", modelProfile: "ready", workspace: "ready",
  });
  assert.equal(result.generationPointerFingerprint, FP.pointerFingerprint);
  assert.equal(result.probedAtMs, 1_000);
  assert.match(result.readinessFingerprint, /^[0-9a-f]{64}$/);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.dimensions));
});

test("the readiness fingerprint is deterministic and changes when any bound field changes", () => {
  const a = evaluateGenerationReadiness(baseEvidence()).readinessFingerprint;
  const b = evaluateGenerationReadiness(baseEvidence()).readinessFingerprint;
  assert.equal(a, b);
  const drifted = evaluateGenerationReadiness(baseEvidence({
    workspace: { state: "ready", source: LIVE_SOURCE, generation: { ...FP, pointerFingerprint: "9".repeat(64) }, expected: { ...FP, pointerFingerprint: "9".repeat(64) } },
  })).readinessFingerprint;
  assert.notEqual(a, drifted);
  const timeDrift = evaluateGenerationReadiness(baseEvidence({ freshness: { probedAtMs: 2_000, nowMs: 2_100, maxAgeMs: 5_000 } })).readinessFingerprint;
  assert.notEqual(a, timeDrift);
});

test("a non-live source on ANY dimension fails closed — a dev/test-injected probe cannot satisfy it", () => {
  for (const dimension of DIMENSIONS) {
    // Even with an affirmative state, a dev/injection source is rejected.
    const affirmative = dimension === "workspace"
      ? { state: "ready", source: "dev-injection", generation: { ...FP }, expected: { ...FP } }
      : { state: { connection: "online", runtime: "ready", providerAuth: "configured", modelProfile: "ready" }[dimension], source: "dev-injection" };
    const evidence = baseEvidence({ [dimension]: affirmative });
    assert.throws(() => evaluateGenerationReadiness(evidence), (e) =>
      e.code === "RUNTIME_INCOMPATIBLE" && e.dimension === dimension && e.rejectedSource === "dev-injection");
  }
});

test("a missing source, wrong type, or unknown source is refused as not live", () => {
  rejectsCode(baseEvidence({ connection: { state: "online" } }), "RUNTIME_INCOMPATIBLE");
  rejectsCode(baseEvidence({ runtime: { state: "ready", source: "test" } }), "RUNTIME_INCOMPATIBLE");
  rejectsCode(baseEvidence({ modelProfile: "ready" }), "CONFIG_INVALID");
});

test("connection dimension maps to CONNECTION_LOST when not online", () => {
  rejectsCode(baseEvidence({ connection: { state: "offline", source: LIVE_SOURCE } }), "CONNECTION_LOST");
});

test("runtime dimension maps incompatible vs unknown correctly", () => {
  rejectsCode(baseEvidence({ runtime: { state: "incompatible", source: LIVE_SOURCE } }), "RUNTIME_INCOMPATIBLE");
  rejectsCode(baseEvidence({ runtime: { state: "error", source: LIVE_SOURCE } }), "UNKNOWN_RUNTIME");
});

test("provider auth dimension maps each non-configured state to its protocol code", () => {
  rejectsCode(baseEvidence({ providerAuth: { state: "missing", source: LIVE_SOURCE } }), "PROVIDER_MISSING");
  rejectsCode(baseEvidence({ providerAuth: { state: "invalid", source: LIVE_SOURCE } }), "PROVIDER_INVALID");
  rejectsCode(baseEvidence({ providerAuth: { state: "expired", source: LIVE_SOURCE } }), "PROVIDER_EXPIRED");
  rejectsCode(baseEvidence({ providerAuth: { state: "unknown", source: LIVE_SOURCE } }), "PROVIDER_UNAVAILABLE");
});

test("model profile dimension maps missing vs invalid", () => {
  rejectsCode(baseEvidence({ modelProfile: { state: "missing", source: LIVE_SOURCE } }), "MODEL_PROFILE_MISSING");
  rejectsCode(baseEvidence({ modelProfile: { state: "invalid", source: LIVE_SOURCE } }), "MODEL_PROFILE_INVALID");
});

test("workspace dimension refuses a non-ready state before inspecting the binding", () => {
  rejectsCode(baseEvidence({ workspace: { state: "not-found", source: LIVE_SOURCE, generation: { ...FP }, expected: { ...FP } } }), "WORKSPACE_NOT_FOUND");
});

test("generation binding mismatch maps to the per-fingerprint failure mode", () => {
  const withGen = (gen) => baseEvidence({ workspace: { state: "ready", source: LIVE_SOURCE, generation: gen, expected: { ...FP } } });
  rejectsCode(withGen({ ...FP, pointerFingerprint: "a".repeat(64) }), "WORKSPACE_GENERATION_STALE");
  rejectsCode(withGen({ ...FP, rootIdentityFingerprint: "a".repeat(64) }), "WORKSPACE_GENERATION_STALE");
  rejectsCode(withGen({ ...FP, gitGenerationFingerprint: "a".repeat(64) }), "GIT_GRAPH_INCOMPLETE");
  rejectsCode(withGen({ ...FP, manifestFingerprint: "a".repeat(64) }), "WORKSPACE_GENERATION_STALE");
});

test("generation fingerprints must be lowercase 64-hex, with exact key sets", () => {
  rejectsCode(baseEvidence({ workspace: { state: "ready", source: LIVE_SOURCE, generation: { ...FP, pointerFingerprint: "1".repeat(63) }, expected: { ...FP } } }), "CONFIG_INVALID");
  rejectsCode(baseEvidence({ workspace: { state: "ready", source: LIVE_SOURCE, generation: { ...FP, pointerFingerprint: "A".repeat(64) }, expected: { ...FP, pointerFingerprint: "A".repeat(64) } } }), "CONFIG_INVALID");
  rejectsCode(baseEvidence({ workspace: { state: "ready", source: LIVE_SOURCE, generation: { ...FP, extra: "x" }, expected: { ...FP } } }), "CONFIG_INVALID");
  rejectsCode(baseEvidence({ workspace: { state: "ready", source: LIVE_SOURCE, generation: { ...FP }, expected: { pointerFingerprint: FP.pointerFingerprint } } }), "CONFIG_INVALID");
});

test("freshness enforces valid, monotonic, non-stale timing", () => {
  rejectsCode(baseEvidence({ freshness: { probedAtMs: 1_000, nowMs: 900, maxAgeMs: 5_000 } }), "READINESS_TIMESTAMP_INVALID");
  rejectsCode(baseEvidence({ freshness: { probedAtMs: 1_000, nowMs: 10_000, maxAgeMs: 5_000 } }), "READINESS_EXPIRED");
  rejectsCode(baseEvidence({ freshness: { probedAtMs: 1.5, nowMs: 2, maxAgeMs: 5_000 } }), "READINESS_TIMESTAMP_INVALID");
  rejectsCode(baseEvidence({ freshness: { probedAtMs: -1, nowMs: 2, maxAgeMs: 5_000 } }), "READINESS_TIMESTAMP_INVALID");
  rejectsCode(baseEvidence({ freshness: { probedAtMs: 1_000, nowMs: 1_000, maxAgeMs: 0 } }), "CONFIG_INVALID");
  // Exactly at the age boundary is still ready.
  assert.equal(evaluateGenerationReadiness(baseEvidence({ freshness: { probedAtMs: 1_000, nowMs: 6_000, maxAgeMs: 5_000 } })).ready, true);
});

test("a missing or extra top-level dimension fails closed", () => {
  const missing = baseEvidence();
  delete missing.workspace;
  rejectsCode(missing, "CONFIG_INVALID");
  rejectsCode(baseEvidence({ unexpected: true }), "CONFIG_INVALID");
});

test("freshness must carry exactly its three fields", () => {
  rejectsCode(baseEvidence({ freshness: { probedAtMs: 1_000, nowMs: 1_500 } }), "CONFIG_INVALID");
  rejectsCode(baseEvidence({ freshness: { probedAtMs: 1_000, nowMs: 1_500, maxAgeMs: 5_000, extra: 1 } }), "CONFIG_INVALID");
});
