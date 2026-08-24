import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  ADMISSION_CEILINGS,
  PER_SESSION_MEMORY_ESTIMATE_MB,
  PER_INVOKE_MEMORY_ESTIMATE_MB,
  FIXED_DAEMON_BASELINE_MB,
  CGROUP_MEMORY_HEADROOM_RATIO,
  worstCaseWorkloadMemoryMb,
  cgroupMemoryMinimumMb,
} from "../src/admission-headroom.js";

// #43 cgroup memory-headroom contract. The arithmetic-consistency assertions
// run on EVERY platform (they need no OS support); the live cgroup read is
// Linux-only and t.skip()s elsewhere with an explicit diagnostic — the same
// explicit-skip-with-diagnostic convention native-control uses for POSIX-only
// paths on Windows.

test("declared headroom constants are positive and add real margin", () => {
  for (const [name, value] of Object.entries({
    PER_SESSION_MEMORY_ESTIMATE_MB,
    PER_INVOKE_MEMORY_ESTIMATE_MB,
    FIXED_DAEMON_BASELINE_MB,
  })) {
    assert.ok(
      Number.isFinite(value) && value > 0,
      `${name} must be a positive finite MiB estimate`
    );
  }
  // Headroom ratio must strictly exceed 1 or it adds no safety margin at all.
  assert.ok(CGROUP_MEMORY_HEADROOM_RATIO > 1, "headroom ratio must exceed 1");
  for (const [name, value] of Object.entries(ADMISSION_CEILINGS)) {
    assert.ok(
      Number.isSafeInteger(value) && value > 0,
      `${name} ceiling must be a positive integer`
    );
  }
});

test("cgroup minimum strictly exceeds the worst-case admitted workload", () => {
  const workload = worstCaseWorkloadMemoryMb();
  const minimum = cgroupMemoryMinimumMb();
  // The concrete, checkable invariant: the declared minimum is a real headroom
  // over the bare worst-case sum of (sessions*perSession + invokes*perInvoke +
  // baseline), not merely equal to it.
  assert.ok(Number.isFinite(workload) && workload > 0);
  assert.ok(
    minimum > workload,
    `cgroup minimum ${minimum}MiB must exceed worst-case workload ${workload}MiB`
  );
  // And the workload arithmetic matches the declared ceilings/estimates exactly.
  assert.equal(
    workload,
    ADMISSION_CEILINGS.maxSessions * PER_SESSION_MEMORY_ESTIMATE_MB +
      ADMISSION_CEILINGS.maxInFlightInvokes * PER_INVOKE_MEMORY_ESTIMATE_MB +
      FIXED_DAEMON_BASELINE_MB
  );
});

test("configured cgroup memory limit satisfies the declared minimum", async (t) => {
  if (process.platform !== "linux") {
    t.skip(
      `cgroup live read skipped on ${process.platform}; arithmetic-consistency ` +
        `assertions above cover the declared contract on this platform`
    );
    return;
  }
  // cgroup v2 first, then v1. "max"/unbounded or absent -> skip (not a failure).
  let raw;
  for (const path of [
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
  ]) {
    try {
      raw = (await readFile(path, "utf8")).trim();
      break;
    } catch {
      raw = undefined;
    }
  }
  if (raw === undefined || raw === "max") {
    t.skip("no bounded cgroup memory limit for this process; nothing to assert");
    return;
  }
  const limitBytes = Number(raw);
  // cgroup v1 uses a sentinel near 2^63 for "unlimited".
  if (!Number.isFinite(limitBytes) || limitBytes <= 0 || limitBytes > 2 ** 62) {
    t.skip(`cgroup memory limit is effectively unbounded (${raw})`);
    return;
  }
  const minimumBytes = cgroupMemoryMinimumMb() * 1024 * 1024;
  assert.ok(
    limitBytes >= minimumBytes,
    `cgroup memory limit ${limitBytes}B is below the #43 headroom minimum ` +
      `${minimumBytes}B (${cgroupMemoryMinimumMb()}MiB)`
  );
});
