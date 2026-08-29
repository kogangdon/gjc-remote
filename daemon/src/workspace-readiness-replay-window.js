// Bounded readiness replay window (slice S6f.7b).
//
// Pure, dependency-injected `{ has(fp), add(fp) }` single-use seen-set that the
// create / refresh / restore-migration orchestrators consume as `replaySeen`:
//
//   - workspace-create-operation.js            -> replaySeen.has/add
//   - workspace-refresh-operation.js           -> replaySeen.has/add
//   - workspace-restore-migration-operation.js -> replaySeen.has/add
//
// The orchestrators call `replaySeen.has(readinessFingerprint)` and refuse a
// replay, then `replaySeen.add(readinessFingerprint)` BEFORE publish (a failed
// publish permanently burns its attestation - fail-closed). Their header
// contracts explicitly delegate the *bounding* of that grow-only set to the
// daemon wiring "in step with the freshness window"; this module IS that
// bound.
//
// Bounding mechanism
// ------------------
// Each fingerprint is stamped with the trusted clock time at insertion. An
// entry is evicted once it is at least `maxAgeMs` old - the SAME freshness
// bound the orchestrators enforce on `probedAtMs` - so the live set can never
// outlive the window in which a fingerprint could still be replayed. Eviction
// runs on every `has` and `add`, so `has(fp)` returns false for an entry that
// has aged out (its attestation is already stale and independently rejected by
// the orchestrator's freshness check).
//
// Memory is bounded by construction: only fully-verified attestations reach
// `add` (add-before-publish, after signature/authority checks), each distinct
// fingerprint lives at most `maxAgeMs`, so the resident size is bounded by the
// daemon's verified-attestation rate times the window. Eviction is time-based
// ONLY - it never drops an un-aged fingerprint, which would reopen a replay
// window inside the freshness bound.
//
// The clock is injected (defaults to Date.now) so it shares the daemon's
// monotonic time base with the orchestrators' clock and so tests can advance
// time deterministically. Insertion order equals chronological order (clock is
// non-decreasing and each fingerprint is added at most once), so eviction can
// stop at the first still-fresh entry.
//
// This module never wires into daemon.js; it is landed-but-unwired foundation
// consumed by the S6f.7d create/refresh bundle assembly (a single shared
// instance is pinned across the create and refresh dispatchers).

import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared/protocol";

function refuse(code, reason) {
  const error = new Error(`readiness replay window refused: ${reason}`);
  error.code = code;
  error.reason = reason;
  throw error;
}

/**
 * @param {object} options
 * @param {number} options.maxAgeMs - freshness bound (safe integer >= 1);
 *   MUST match the orchestrators' daemon-config readiness freshness window.
 * @param {{ now(): number }} [options.clock] - trusted monotonic ms clock;
 *   defaults to a Date.now-backed clock.
 * @returns {{ has(fp: string): boolean, add(fp: string): void }}
 */
export function createReadinessReplayWindow({ maxAgeMs, clock = { now: () => Date.now() } } = {}) {
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "maxAgeMs must be a safe integer >= 1 owned by daemon config");
  }
  if (typeof clock?.now !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "clock must expose now()");
  }

  // fingerprint -> insertion time (ms). Insertion order == chronological order.
  const seen = new Map();

  function evict(nowMs) {
    for (const [fingerprint, insertedAtMs] of seen) {
      if (nowMs - insertedAtMs >= maxAgeMs) {
        seen.delete(fingerprint);
      } else {
        // Every later entry was inserted no earlier, so it is still fresh too.
        break;
      }
    }
  }

  function assertFingerprint(fp) {
    if (typeof fp !== "string" || fp.length === 0) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "fingerprint must be a non-empty string");
    }
  }

  function has(fp) {
    assertFingerprint(fp);
    evict(clock.now());
    return seen.has(fp);
  }

  function add(fp) {
    assertFingerprint(fp);
    const nowMs = clock.now();
    evict(nowMs);
    // Single-use: re-adding an existing (still-fresh) fingerprint keeps its
    // original insertion slot, preserving chronological Map order.
    if (!seen.has(fp)) {
      seen.set(fp, nowMs);
    }
  }

  return Object.freeze({ has, add });
}
