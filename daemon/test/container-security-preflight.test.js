import assert from "node:assert/strict";
import test from "node:test";
import {
  CONTAINER_GID,
  CONTAINER_UID,
  ContainerPreflightError,
  ROLE_PATHS,
  assertContainerSecurityPreflight,
  inspectContainerSecurityPreflight,
  parseCpuMax,
  parseLimit,
  parseMountInfo,
  parseProcessStatus,
} from "../src/container-security-preflight.js";
import { cgroupMemoryMinimumMb } from "../src/admission-headroom.js";

const roleMounts = Object.entries(ROLE_PATHS)
  .map(([name, point], index) => `${20 + index} 1 0:${20 + index} / ${point} rw - ext4 /dev/role-${name} rw`)
  .join("\n");
const mountInfo = `1 0 0:1 / / ro - overlay overlay ro\n2 1 0:2 / /tmp rw - tmpfs tmpfs rw,nosuid,nodev,noexec,size=16m\n3 1 0:3 / /sys/fs/cgroup ro - cgroup2 cgroup rw\n${roleMounts}\n`;
const status = `Name:\ttest\nNoNewPrivs:\t1\nSeccomp:\t2\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n`;

function fixture(overrides = {}) {
  const files = {
    "/proc/self/mountinfo": mountInfo,
    "/proc/self/status": status,
    "/proc/self/cgroup": "0::/\n",
    "/sys/fs/cgroup/memory.max": String(cgroupMemoryMinimumMb() * 1024 * 1024),
    "/sys/fs/cgroup/pids.max": "128",
    "/sys/fs/cgroup/cpu.max": "100000 100000",
    ...(overrides.files ?? {}),
  };
  return {
    platform: () => "linux",
    release: () => "6.8.0",
    getuid: () => CONTAINER_UID,
    getgid: () => CONTAINER_GID,
    readFile: async (file) => {
      if (!(file in files)) throw new Error("unreadable fixture file");
      return files[file];
    },
    lstat: async () => ({
      uid: CONTAINER_UID,
      gid: CONTAINER_GID,
      isDirectory: () => true,
      isSymbolicLink: () => false,
    }),
    open: async () => ({ writeFile: async () => {}, sync: async () => {}, close: async () => {} }),
    unlink: async () => {},
    ...overrides,
  };
}

test("accepts the complete constrained-container evidence", async () => {
  const result = await inspectContainerSecurityPreflight(fixture());
  assert.equal(result.ok, true);
  assert.deepEqual(result.diagnostics, []);
  assert.equal((await assertContainerSecurityPreflight(fixture())).ok, true);
});

test("rejects every primary security condition", async () => {
  const cases = [
    ["linux", fixture({ platform: () => "darwin" })],
    ["native-linux-engine", fixture({ release: () => "5.15.90.1-microsoft-standard-WSL2" })],
    ["native-linux-engine", fixture({ release: () => "6.10.14-linuxkit" })],
    ["identity", fixture({ getgid: () => 0 })],
    ["root-readonly", fixture({ files: { "/proc/self/mountinfo": mountInfo.replace(" / / ro ", " / / rw ") } })],
    ["role-mounts", fixture({ files: { "/proc/self/mountinfo": mountInfo.replace("/workspaces rw", "/workspaces ro") } })],
    ["role-mount-identities", fixture({ files: { "/proc/self/mountinfo": mountInfo.replace("/dev/role-session", "/dev/role-workspace") } })],
    ["role-owners", fixture({ lstat: async () => ({
      uid: 0,
      gid: CONTAINER_GID,
      isDirectory: () => true,
      isSymbolicLink: () => false,
    }) })],
    ["tmp-mount", fixture({ files: { "/proc/self/mountinfo": mountInfo.replace(" - tmpfs ", " - ext4 ") } })],
    ["tmp-options", fixture({ files: { "/proc/self/mountinfo": mountInfo.replace(",noexec", "") } })],
    ["tmp-bounded", fixture({ files: { "/proc/self/mountinfo": mountInfo.replace("size=16m", "size=17m") } })],
    ["no-new-privileges", fixture({ files: { "/proc/self/status": status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0") } })],
    ["seccomp", fixture({ files: { "/proc/self/status": status.replace("Seccomp:\t2", "Seccomp:\t0") } })],
    ["capabilities", fixture({ files: { "/proc/self/status": status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001") } })],
    ["cgroup-v2", fixture({ files: { "/proc/self/cgroup": "1:name=systemd:/\n" } })],
    ["cgroup-memory", fixture({ files: { "/sys/fs/cgroup/memory.max": "1" } })],
    ["cgroup-pids", fixture({ files: { "/sys/fs/cgroup/pids.max": "127" } })],
    ["cgroup-cpu", fixture({ files: { "/sys/fs/cgroup/cpu.max": "max 100000" } })],
    ["role-write-probes", fixture({ open: async () => { throw new Error("denied"); } })],
  ];
  for (const [code, io] of cases) {
    const result = await inspectContainerSecurityPreflight(io);
    assert.equal(result.evidence[code], false, code);
  }
});

test("fails closed for malformed proc and cgroup inputs", async () => {
  for (const [file, value] of [
    ["/proc/self/mountinfo", "not mountinfo"],
    ["/proc/self/status", "NoNewPrivs:\t1"],
    ["/proc/self/cgroup", "0::relative"],
    ["/sys/fs/cgroup/memory.max", "max"],
    ["/sys/fs/cgroup/pids.max", "max"],
    ["/sys/fs/cgroup/cpu.max", "0 100000"],
  ]) assert.equal((await inspectContainerSecurityPreflight(fixture({ files: { [file]: value } }))).ok, false);
  assert.equal(parseMountInfo("broken"), null);
  assert.equal(parseProcessStatus("CapEff: zz"), null);
  assert.equal(parseLimit("max"), null);
  assert.equal(parseCpuMax("max 100"), null);
});

test("uses exclusive write, fsync, close, and unlink for each role", async () => {
  const calls = [];
  const io = fixture({
    randomName: () => "test",
    open: async (file, flags) => {
      calls.push(["open", file, flags]);
      return { writeFile: async () => calls.push(["write"]), sync: async () => calls.push(["sync"]), close: async () => calls.push(["close"]) };
    },
    unlink: async (file) => calls.push(["unlink", file]),
  });
  assert.equal((await inspectContainerSecurityPreflight(io)).ok, true);
  assert.equal(calls.filter(([kind]) => kind === "open").length, 4);
  assert.equal(calls.filter(([kind]) => kind === "unlink").length, 4);
  assert.equal((await inspectContainerSecurityPreflight(fixture({ open: async () => { throw new Error("denied"); }, unlink: async () => {} }))).evidence["role-write-probes"], false);
  assert.equal((await inspectContainerSecurityPreflight(fixture({ open: async () => ({ writeFile: async () => {}, sync: async () => {}, close: async () => {} }), unlink: async () => { throw new Error("stuck"); } }))).evidence["role-write-probes"], false);
  assert.equal((await inspectContainerSecurityPreflight(fixture({ open: async () => ({ writeFile: async () => {}, sync: async () => {}, close: async () => { throw new Error("close failed"); } }), unlink: async () => {} }))).evidence["role-write-probes"], false);
});

test("throws stable redacted diagnostics", async () => {
  await assert.rejects(
    () => assertContainerSecurityPreflight(fixture({ getuid: () => 99999 })),
    (error) => error instanceof ContainerPreflightError && error.code === "identity" &&
      !/99999|\/|proc|secret/i.test(`${error.message} ${JSON.stringify(error)}`),
  );
});
