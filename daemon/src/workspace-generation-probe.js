// Current-run workspace-generation readiness probe for the native workspace
// data plane (#53 Phase 2, slice S4e).
//
// Obligation (docs/daemon-workspace-implementation-phases.md, Final obligations
// + resolved S4 decision 3): the real current-run readiness probe wired at the
// runCurrentRunProbe seam (daemon.js) must be a FAIL-CLOSED five-dimension gate
// that a development flag CANNOT satisfy. Today that seam trusts an injected
// dev-probe token (READINESS_TEST_INJECTION_ENABLED / readinessTestEvidence);
// this module is the real probe that replaces the dev-probe role. The literal
// GJC_DEV_CONNECTIVITY_PROBE flag was removed in slice S6e (retired gate
// FULL_GRAPH_PUBLICATION_TESTS_PASS); its presence now fails the daemon closed
// at boot (see workspace-removed-flags.js). This module supplies the primitive
// that S4f/S4g wire so connectivity probing is unconditional.
//
// The five dimensions mirror the daemon readiness status vocabulary
// (state.status): connection, runtime, providerAuth, modelProfile, workspace.
// A generation is ready to serve ONLY when every dimension is affirmatively
// proven by LIVE evidence AND the workspace dimension's generation binding
// matches the expected S4a identity + S4b git object-graph + S4c content
// manifest + S4d live pointer fingerprints. Any missing, unknown, mismatched,
// stale, or dev/test-injected evidence fails closed with the mapped protocol
// error code — never "assume ready".
//
// This module is a PURE primitive: a single synchronous evaluation over an
// evidence record. It performs no I/O, keeps no clock (the caller supplies
// nowMs), does NOT wire into the daemon, and does NOT flip the native-
// workspace-serving gate (NATIVE_WORKSPACE_SERVING_ENABLED stays false). The
// daemon binds it at the runCurrentRunProbe seam in S4f/S4g.

import { canonicalJsonHash, isHex64 } from "@gjc-remote/shared/strict-json";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared/protocol";

const OPERATION = "workspace_generation_probe";
const KIND = "workspace-generation-readiness";
const VERSION = 1;

const READINESS_LIMITS = Object.freeze({ maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 256 });

// The only evidence source this probe accepts. A development / test-injection
// source is refused: the dev flag cannot satisfy a real readiness probe.
const LIVE_SOURCE = "live";

const DIMENSIONS = ["connection", "runtime", "providerAuth", "modelProfile", "workspace"];
const GENERATION_FINGERPRINTS = [
  "pointerFingerprint",
  "rootIdentityFingerprint",
  "gitGenerationFingerprint",
  "manifestFingerprint",
];

// Fingerprint -> the protocol code reported when the live binding diverges from
// the expected generation. A pointer / identity / manifest divergence is a
// stale-generation condition; a git object-graph divergence is reported as an
// incomplete graph so it maps onto the S4b failure mode.
const FINGERPRINT_MISMATCH_CODE = Object.freeze({
  pointerFingerprint: PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
  rootIdentityFingerprint: PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
  gitGenerationFingerprint: PROTOCOL_ERROR_CODES.GIT_GRAPH_INCOMPLETE,
  manifestFingerprint: PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
});

function refuse(code, reason, extra) {
  const error = new Error(`${OPERATION}: ${code}: ${reason}`);
  error.code = code; // a PROTOCOL_ERROR_CODES value so the daemon seam classifies it
  error.operation = OPERATION;
  error.reason = reason;
  if (extra && typeof extra === "object") {
    for (const [key, value] of Object.entries(extra)) {
      if (!["code", "operation", "reason", "message"].includes(key)) error[key] = value;
    }
  }
  throw error;
}

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const hasExactKeys = (value, keys) =>
  isPlainObject(value) && Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

// Every dimension carries { state, source }; the workspace dimension also
// carries { generation, expected }. A non-live source is rejected up front so
// dev/test-injected evidence can never pass, regardless of its declared state.
// A non-live source is a shape/configuration fault (CONFIG_INVALID), NOT a
// runtime incompatibility: reusing RUNTIME_INCOMPATIBLE here would make the
// daemon seam mislabel the runtime dimension as incompatible for any
// non-runtime dimension whose source is wrong.
function assertLiveSource(dimension, value) {
  if (!isPlainObject(value)) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `${dimension} evidence must be an object`, { dimension });
  }
  // The four simple dimensions must be exactly { state, source }; the workspace
  // dimension's fuller shape is validated in assertGenerationBinding.
  if (dimension !== "workspace" && !hasExactKeys(value, ["state", "source"])) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `${dimension} evidence must have exactly {state,source}`, { dimension });
  }
  if (value.source !== LIVE_SOURCE) {
    // Fail closed: an injected/dev/test/unknown source cannot satisfy the probe.
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `${dimension} evidence is not live (source=${String(value.source)})`, {
      dimension,
      rejectedSource: String(value.source),
    });
  }
}

// Validate the workspace generation binding and return a frozen snapshot of the
// four live fingerprints, read EXACTLY ONCE. Returning a snapshot (rather than
// re-reading workspace.generation later) closes a getter-based TOCTOU: a
// property getter could otherwise return a validated value here and a different,
// unverified value when the attestation is fingerprinted.
function assertGenerationBinding(workspace) {
  if (!hasExactKeys(workspace, ["state", "source", "generation", "expected"])) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "workspace evidence must have {state,source,generation,expected}", { dimension: "workspace" });
  }
  const snapshot = {};
  for (const side of ["generation", "expected"]) {
    const container = workspace[side];
    if (!hasExactKeys(container, GENERATION_FINGERPRINTS)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `workspace.${side} must carry exactly the four generation fingerprints`, { dimension: "workspace", side });
    }
    const values = {};
    for (const key of GENERATION_FINGERPRINTS) {
      const value = container[key]; // read once
      if (!isHex64(value)) {
        refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `workspace.${side}.${key} must be a 64-char lowercase hex digest`, { dimension: "workspace", side, field: key });
      }
      values[key] = value;
    }
    snapshot[side] = values;
  }
  // The live generation binding must match the expected generation on every
  // fingerprint; the first divergence decides the reported failure mode.
  for (const key of GENERATION_FINGERPRINTS) {
    if (snapshot.generation[key] !== snapshot.expected[key]) {
      refuse(FINGERPRINT_MISMATCH_CODE[key], `workspace generation ${key} does not match the expected generation`, {
        dimension: "workspace",
        field: key,
      });
    }
  }
  return Object.freeze(snapshot.generation);
}

/**
 * Evaluate a current-run generation-readiness probe. Returns a frozen readiness
 * attestation when — and only when — all five dimensions are proven by live
 * evidence and the workspace dimension's generation binding matches the expected
 * S4a/S4b/S4c/S4d fingerprints and the evidence is fresh. Otherwise throws a
 * structured refusal whose `code` is a PROTOCOL_ERROR_CODES value so it drops
 * straight into the daemon runCurrentRunProbe seam.
 *
 * evidence = {
 *   connection:   { state, source },            // state must be "online"
 *   runtime:      { state, source },            // state must be "ready"
 *   providerAuth: { state, source },            // state must be "configured"
 *   modelProfile: { state, source },            // state must be "ready"
 *   workspace:    { state, source, generation, expected }, // state "ready" + binding match
 *   freshness:    { probedAtMs, nowMs, maxAgeMs },
 * }
 *
 * Fail-closed contract: a missing/extra key, a non-live `source` on any
 * dimension, a non-affirmative state, a generation-binding mismatch, or stale/
 * invalid freshness all refuse. There is no code path that returns ready
 * without every dimension affirmatively proven.
 */
export function evaluateGenerationReadiness(evidence) {
  if (!hasExactKeys(evidence, [...DIMENSIONS, "freshness"])) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "readiness evidence must have exactly the five dimensions plus freshness");
  }

  // Every dimension must be live before any state is trusted.
  for (const dimension of DIMENSIONS) assertLiveSource(dimension, evidence[dimension]);

  // Dimension 1 — connection.
  if (evidence.connection.state !== "online") {
    refuse(PROTOCOL_ERROR_CODES.CONNECTION_LOST, `connection is not online (state=${String(evidence.connection.state)})`, { dimension: "connection" });
  }

  // Dimension 2 — runtime (static security preflight + runtime compatibility).
  if (evidence.runtime.state !== "ready") {
    const code = evidence.runtime.state === "incompatible"
      ? PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE
      : PROTOCOL_ERROR_CODES.UNKNOWN_RUNTIME;
    refuse(code, `runtime is not ready (state=${String(evidence.runtime.state)})`, { dimension: "runtime" });
  }

  // Dimension 3 — provider auth.
  if (evidence.providerAuth.state !== "configured") {
    const code = evidence.providerAuth.state === "invalid"
      ? PROTOCOL_ERROR_CODES.PROVIDER_INVALID
      : evidence.providerAuth.state === "expired"
        ? PROTOCOL_ERROR_CODES.PROVIDER_EXPIRED
        : evidence.providerAuth.state === "unknown"
          ? PROTOCOL_ERROR_CODES.PROVIDER_UNAVAILABLE
          : PROTOCOL_ERROR_CODES.PROVIDER_MISSING;
    refuse(code, `provider auth is not configured (state=${String(evidence.providerAuth.state)})`, { dimension: "providerAuth" });
  }

  // Dimension 4 — model profile.
  if (evidence.modelProfile.state !== "ready") {
    const code = evidence.modelProfile.state === "invalid"
      ? PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID
      : PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING;
    refuse(code, `model profile is not ready (state=${String(evidence.modelProfile.state)})`, { dimension: "modelProfile" });
  }

  // Dimension 5 — workspace + generation binding. assertGenerationBinding
  // returns a snapshot of the four live fingerprints read exactly once, so the
  // attestation below is fingerprinted over the same values that were validated
  // and compared (no getter-based re-read).
  if (evidence.workspace.state !== "ready") {
    refuse(PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND, `workspace is not ready (state=${String(evidence.workspace.state)})`, { dimension: "workspace" });
  }
  const generation = assertGenerationBinding(evidence.workspace);

  // Freshness / anti-replay: the caller supplies both timestamps and the bound;
  // the probe holds no clock so it stays pure and deterministically testable.
  // SEAM CONTRACT (owned by the S4f/S4g wiring, not this module): the timestamp
  // window here bounds staleness but is NOT by itself sufficient anti-replay.
  // The wiring MUST (a) source nowMs from a trusted monotonic clock, not the
  // requester; (b) own maxAgeMs from daemon config, never from requester input;
  // and (c) enforce single-use of each readinessFingerprint via a seen-set,
  // emitting READINESS_REPLAYED on reuse within the window.
  const { freshness } = evidence;
  if (!hasExactKeys(freshness, ["probedAtMs", "nowMs", "maxAgeMs"])) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "freshness must have {probedAtMs,nowMs,maxAgeMs}");
  }
  const probedAtMs = freshness.probedAtMs; // read once each
  const nowMs = freshness.nowMs;
  const maxAgeMs = freshness.maxAgeMs;
  for (const [key, value] of [["probedAtMs", probedAtMs], ["nowMs", nowMs], ["maxAgeMs", maxAgeMs]]) {
    if (!Number.isSafeInteger(value) || value < 0) {
      refuse(PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID, `freshness.${key} must be a non-negative safe integer`, { field: key });
    }
  }
  if (maxAgeMs < 1) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "freshness.maxAgeMs must be >= 1");
  }
  if (nowMs < probedAtMs) {
    // A probe stamped in the future is invalid, not merely expired.
    refuse(PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID, "freshness.nowMs precedes probedAtMs");
  }
  if (nowMs - probedAtMs > maxAgeMs) {
    refuse(PROTOCOL_ERROR_CODES.READINESS_EXPIRED, "readiness evidence is older than maxAgeMs");
  }

  const generationPointerFingerprint = generation.pointerFingerprint;
  const attestationBody = {
    version: VERSION,
    kind: KIND,
    connection: "online",
    runtime: "ready",
    providerAuth: "configured",
    modelProfile: "ready",
    workspace: "ready",
    generationPointerFingerprint,
    rootIdentityFingerprint: generation.rootIdentityFingerprint,
    gitGenerationFingerprint: generation.gitGenerationFingerprint,
    manifestFingerprint: generation.manifestFingerprint,
    probedAtMs,
  };
  let readinessFingerprint;
  try {
    readinessFingerprint = canonicalJsonHash(attestationBody, READINESS_LIMITS);
  } catch (error) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, `readiness attestation is not canonicalizable: ${error?.message ?? "invalid"}`);
  }

  return Object.freeze({
    ready: true,
    dimensions: Object.freeze({
      connection: "online",
      runtime: "ready",
      providerAuth: "configured",
      modelProfile: "ready",
      workspace: "ready",
    }),
    generationPointerFingerprint,
    probedAtMs: freshness.probedAtMs,
    readinessFingerprint,
  });
}

export { DIMENSIONS, LIVE_SOURCE };
