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
// entry is evicted once it is STRICTLY older than `maxAgeMs` - matching the
// probe freshness predicate exactly (workspace-generation-probe.js refuses
// only `nowMs - probedAtMs > maxAgeMs`, so an attestation at age == maxAgeMs is
// still fresh and MUST still be blocked as a replay). Evicting at age >=
// maxAgeMs would drop a still-fresh fingerprint at the exact boundary and
// reopen a one-tick replay window. Eviction runs on every `has` and `add`, so
// `has(fp)` returns false only for an entry that has aged out past the window
// (its attestation is by then independently rejected by the freshness check).
//
// Memory is bounded by construction: only fully-verified attestations reach
// `add` (add-before-publish, after signature/authority checks), each distinct
// fingerprint lives at most `maxAgeMs`, so the resident size is bounded by the
// daemon's verified-attestation rate times the window. Eviction is time-based
// ONLY - it never drops an un-aged fingerprint, which would reopen a replay
// window inside the freshness bound.
//
// The clock is injected (defaults to Date.now) so it shares the daemon's time
// base with the orchestrators' clock and so tests can advance time
// deterministically. Date.now is wall-time and can step backward (NTP slew), so
// the module clamps every reading to the last observed value: time is treated
// as monotonic non-decreasing internally. Combined with each fingerprint being
// added at most once, insertion order equals chronological order, so eviction
// can stop at the first still-fresh entry.
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

  // Monotonic clamp: a backward clock step must never make a fresh fingerprint
  // look older nor break the insertion-order == chronological-order invariant.
  let lastNowMs = Number.NEGATIVE_INFINITY;
  function readClock() {
    const raw = clock.now();
    if (!Number.isFinite(raw)) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "clock.now() must return a finite number");
    }
    lastNowMs = raw > lastNowMs ? raw : lastNowMs;
    return lastNowMs;
  }

  function evict(nowMs) {
    for (const [fingerprint, insertedAtMs] of seen) {
      if (nowMs - insertedAtMs > maxAgeMs) {
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
    evict(readClock());
    return seen.has(fp);
  }

  function add(fp) {
    assertFingerprint(fp);
    const nowMs = readClock();
    evict(nowMs);
    // Single-use: re-adding an existing (still-fresh) fingerprint keeps its
    // original insertion slot, preserving chronological Map order.
    if (!seen.has(fp)) {
      seen.set(fp, nowMs);
    }
  }

  return Object.freeze({ has, add });
}
