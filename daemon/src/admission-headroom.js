import { DEFAULT_MAX_SESSIONS } from "./session-pool.js";
import { DEFAULT_MAX_IN_FLIGHT_INVOKES } from "./admission-budget.js";
import { DEFAULT_MAX_ACTIVE_WORKSPACES } from "./workspace-lease-registry.js";

// #43 cgroup memory-headroom design contract.
//
// This module declares — as real, checkable constants rather than doc prose —
// the memory-headroom relationship the daemon's host-wide admission ceilings
// imply. The daemon itself performs NO cgroup manipulation at runtime; runtime
// enforcement is Phase 3 / #42 scope. What lives here is the arithmetic
// contract: any cgroup memory limit configured for the daemon process MUST be
// at least large enough to hold the worst-case admitted workload plus a fixed
// baseline plus a safety headroom margin.
//
// The estimates below are conservative placeholders owned by #43/#42; they are
// intentionally over-provisioned so the declared minimum never under-counts.
// When real observed SDK-session RSS is available, update these constants — the
// always-on arithmetic-consistency test will keep the relationship honest.

/** Ceilings, re-exported from their single sources of truth (never redeclared). */
export const ADMISSION_CEILINGS = Object.freeze({
  maxActiveWorkspaces: DEFAULT_MAX_ACTIVE_WORKSPACES,
  maxSessions: DEFAULT_MAX_SESSIONS,
  maxInFlightInvokes: DEFAULT_MAX_IN_FLIGHT_INVOKES,
});

/** Conservative per-unit and baseline memory estimates (MiB). */
export const PER_SESSION_MEMORY_ESTIMATE_MB = 512;
export const PER_INVOKE_MEMORY_ESTIMATE_MB = 32;
export const FIXED_DAEMON_BASELINE_MB = 256;

/** Safety margin above the raw worst-case workload. Must be > 1 to add headroom. */
export const CGROUP_MEMORY_HEADROOM_RATIO = 1.25;

/**
 * Worst-case admitted-workload memory, excluding headroom (MiB).
 * Sessions and in-flight invokes are the two unbounded-until-capped resources;
 * active workspaces are bounded by (and never exceed) the session ceiling, so
 * they are not double-counted here.
 */
export function worstCaseWorkloadMemoryMb() {
  return (
    ADMISSION_CEILINGS.maxSessions * PER_SESSION_MEMORY_ESTIMATE_MB +
    ADMISSION_CEILINGS.maxInFlightInvokes * PER_INVOKE_MEMORY_ESTIMATE_MB +
    FIXED_DAEMON_BASELINE_MB
  );
}

/**
 * Minimum cgroup memory limit (MiB) the daemon process should be granted: the
 * worst-case workload scaled by the headroom ratio, rounded up. A configured
 * cgroup memory limit below this value risks OOM-killing an admitted-but-legal
 * workload and MUST be treated as a misconfiguration.
 */
export function cgroupMemoryMinimumMb() {
  return Math.ceil(worstCaseWorkloadMemoryMb() * CGROUP_MEMORY_HEADROOM_RATIO);
}
