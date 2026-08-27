/**
 * Pure dependency-injected fence/probe adapters over WorkspaceLeaseRegistry
 * (#53/#81 foundation slice S6f.1e).
 *
 * NOT wired into daemon.js: the NATIVE_WORKSPACE_SERVING_ENABLED serving gate
 * stays hard-disabled (false) after this slice. These factories exist only to
 * shape the `acquireFence` / `probeQuiescence` dependencies the workspace
 * refresh, reset-delete, and restore orchestrators already declare as
 * injected collaborators, binding them to the real, already-shipped
 * WorkspaceLeaseRegistry instead of a test double.
 *
 * Three factories:
 *
 *   - createActivityFence(registry): the NON-exclusive activity fence used by
 *     the refresh orchestrator. Ordinary same-identity acquisitions stack.
 *   - createExclusiveFence(registry): the EXCLUSIVE activity fence used by the
 *     reset-delete and restore orchestrators. Exclusivity forbids re-entrant
 *     stacking and serializes a destructive/promotion step against every other
 *     acquisition of the same workspace identity (see the pre-mortem #3 test
 *     in workspace-lease-fence.test.js for the restore-vs-admission proof).
 *   - createQuiescenceProbe(counts): shapes and validates whatever
 *     pendingInvokes/pendingSessions counts (numbers or zero-arg getters,
 *     sync or async) are injected into a single async () => {...} probe. The
 *     REAL live daemon workload counts (SessionPool / invoke queue) are bound
 *     at the later S6f.4 wiring slice; this probe only validates and shapes
 *     whatever is handed to it today. It deliberately does NOT itself call
 *     assertQuiescent -- the reset-delete orchestrator feeds the probe's
 *     resolved counts to the registry's assertQuiescent itself, keeping the
 *     WORKSPACE_BUSY workload-idleness decision where the registry already
 *     owns it.
 *
 * Both fence factories are thin binders: they validate the registry shape at
 * construction time (raising a config-time refusal here) and otherwise let
 * every runtime error the registry throws (LEASE_CONFLICT, WORKSPACE_BUSY,
 * WORKSPACE_ADMISSION_EXCEEDED, TypeError) pass through completely unchanged.
 */

const OPERATION = "workspace_lease_fence";

function refuse(code, reason) {
  return Object.assign(new Error(reason), { operation: OPERATION, code });
}

function requireRegistry(registry) {
  if (
    !registry ||
    typeof registry !== "object" ||
    typeof registry.acquireActivity !== "function"
  ) {
    throw refuse(
      "LEASE_FENCE_CONFIG_INVALID",
      "workspace lease fence requires a registry with an acquireActivity function"
    );
  }
}

/**
 * Build the non-exclusive `acquireFence` dependency for the refresh
 * orchestrator: `(leaseCandidate) => registry.acquireActivity(leaseCandidate, { exclusive: false })`.
 */
export function createActivityFence(registry) {
  requireRegistry(registry);
  return (leaseCandidate) =>
    registry.acquireActivity(leaseCandidate, { exclusive: false });
}

/**
 * Build the exclusive `acquireFence` dependency for the reset-delete and
 * restore orchestrators: `(leaseCandidate) => registry.acquireActivity(leaseCandidate, { exclusive: true })`.
 */
export function createExclusiveFence(registry) {
  requireRegistry(registry);
  return (leaseCandidate) =>
    registry.acquireActivity(leaseCandidate, { exclusive: true });
}

function isPlainCount(value) {
  return typeof value === "number" || typeof value === "function";
}

async function resolveCount(name, value) {
  const resolved = typeof value === "function" ? await value() : value;
  if (!Number.isSafeInteger(resolved) || resolved < 0) {
    throw refuse(
      "QUIESCENCE_PROBE_INVALID",
      `workspace quiescence probe ${name} must resolve to a non-negative safe integer`
    );
  }
  return resolved;
}

/**
 * Build the `probeQuiescence` dependency for the reset-delete orchestrator:
 * `async () => ({ pendingInvokes, pendingSessions })`, resolving each field
 * (invoking it if it is a zero-arg getter, sync or async) and validating both
 * resolve to non-negative safe integers. The orchestrator feeds the resolved
 * object to the registry's `assertQuiescent`; this probe never raises
 * WORKSPACE_BUSY itself -- only the distinct config-time QUIESCENCE_PROBE_INVALID
 * refusal, for malformed inputs or malformed resolved values.
 */
export function createQuiescenceProbe(counts) {
  if (!counts || typeof counts !== "object") {
    throw refuse(
      "QUIESCENCE_PROBE_INVALID",
      "workspace quiescence probe counts must be an object"
    );
  }
  const { pendingInvokes, pendingSessions } = counts;
  if (!isPlainCount(pendingInvokes) || !isPlainCount(pendingSessions)) {
    throw refuse(
      "QUIESCENCE_PROBE_INVALID",
      "workspace quiescence probe pendingInvokes and pendingSessions must each be a number or a zero-arg getter function"
    );
  }
  return async () =>
    Object.freeze({
      pendingInvokes: await resolveCount("pendingInvokes", pendingInvokes),
      pendingSessions: await resolveCount("pendingSessions", pendingSessions),
    });
}
