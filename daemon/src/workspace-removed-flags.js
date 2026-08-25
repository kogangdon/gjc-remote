// Retired dev-flag startup guard (slice S6e, #53 Phase 2 / G004).
//
// Pure, io-free. Two interim development flags gated capabilities that are now
// unconditional:
//   GJC_DEV_NATIVE_SINGLE_WRITER_LOCK  (retired gate FINAL_LEASE_FENCE_TESTS_PASS)
//   GJC_DEV_CONNECTIVITY_PROBE         (retired gate FULL_GRAPH_PUBLICATION_TESTS_PASS)
// Both are removed. A stale flag left in an operator's environment must never be
// silently ignored - it would imply a toggle that no longer exists. This guard
// makes the daemon FAIL CLOSED at startup if either removed flag name is present
// in the environment, with a per-flag (per-retired-gate) unique diagnostic.
//
// Detection is PRESENCE-based via Object.hasOwn, NOT value-based: a removed flag
// is rejected even when set to `0` or the empty string, because the correct
// operator action is to delete the stale variable entirely, not to disable it.
// This guard does NOT flip the native-serving boundary (NATIVE_WORKSPACE_SERVING_ENABLED
// remains a separate, human-approved decision, issue #81 / S6f).

export const REMOVED_DEV_FLAGS = Object.freeze([
  Object.freeze({
    name: "GJC_DEV_NATIVE_SINGLE_WRITER_LOCK",
    gate: "FINAL_LEASE_FENCE_TESTS_PASS",
    note: "native single-writer lease/fence enforcement is now unconditional",
  }),
  Object.freeze({
    name: "GJC_DEV_CONNECTIVITY_PROBE",
    gate: "FULL_GRAPH_PUBLICATION_TESTS_PASS",
    note: "full-graph publication connectivity probing is now unconditional",
  }),
]);

function messageFor(flag) {
  // Per-gate unique evidence: each message names its own removed flag AND the
  // distinct retired gate, so the two rejections are never interchangeable.
  return `daemon: ${flag.name} was removed (retired gate ${flag.gate}); ${flag.note}. Unset this stale variable to boot.`;
}

/**
 * Return the ordered list of removed dev flags PRESENT in `env`
 * (`{ name, gate, message }` each). Presence-based (Object.hasOwn), so a flag
 * set to any value - including "0" or "" - is reported.
 */
export function detectRemovedDevFlags(env) {
  const source = env ?? {};
  const found = [];
  for (const flag of REMOVED_DEV_FLAGS) {
    if (Object.hasOwn(source, flag.name)) {
      found.push({ name: flag.name, gate: flag.gate, message: messageFor(flag) });
    }
  }
  return found;
}

/**
 * Startup guard: if any removed dev flag is present in `env`, print each unique
 * diagnostic via `logError` and terminate boot via `exit(1)`. Returns the number
 * of violations (0 when clean). `logError`/`exit` are injected so the guard is
 * unit-testable without spawning a process.
 */
export function assertNoRemovedDevFlags(env, { logError = console.error, exit = process.exit } = {}) {
  const violations = detectRemovedDevFlags(env);
  if (violations.length > 0) {
    for (const violation of violations) logError(violation.message);
    exit(1);
  }
  return violations.length;
}
