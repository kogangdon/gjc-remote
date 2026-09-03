import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, unlink } from "node:fs/promises";
import { posix as path } from "node:path";
import { platform, release } from "node:os";
import { cgroupMemoryMinimumMb } from "./admission-headroom.js";

export const ROLE_PATHS = Object.freeze({
  workspace: "/workspaces",
  session: "/var/lib/gjc-remote/sessions",
  provider: "/home/gjc/.gjc",
  state: "/var/lib/gjc-remote/state",
});
export const CONTAINER_UID = 1004;
export const CONTAINER_GID = 1004;
export const TMP_MAX_BYTES = 16 * 1024 * 1024;

const CAPABILITY_FIELDS = Object.freeze(["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]);
const CGROUP_ROOT = "/sys/fs/cgroup";

export class ContainerPreflightError extends Error {
  constructor(code) {
    super(`container-security-preflight:${code}`);
    this.name = "ContainerPreflightError";
    this.code = code;
    Object.defineProperty(this, "stack", { value: undefined, enumerable: false });
  }
}

function field(input, name) {
  const match = new RegExp(`^${name}:\\s*(.+)$`, "m").exec(input);
  return match?.[1]?.trim() ?? null;
}

export function parseProcessStatus(input) {
  if (typeof input !== "string") return null;
  const noNewPrivs = field(input, "NoNewPrivs");
  const seccomp = field(input, "Seccomp");
  const capabilities = Object.fromEntries(CAPABILITY_FIELDS.map((name) => [name, field(input, name)]));
  if (!/^[01]$/.test(noNewPrivs ?? "") || !/^\d+$/.test(seccomp ?? "") ||
      Object.values(capabilities).some((value) => !/^[0-9a-fA-F]+$/.test(value ?? ""))) return null;
  return { noNewPrivs: Number(noNewPrivs), seccomp: Number(seccomp), capabilities };
}

export function parseMountInfo(input) {
  if (typeof input !== "string") return null;
  const mounts = [];
  for (const line of input.split("\n")) {
    if (!line) continue;
    const separator = line.indexOf(" - ");
    if (separator < 0) return null;
    const left = line.slice(0, separator).split(" ");
    const right = line.slice(separator + 3).split(" ");
    if (left.length < 6 || right.length < 3 || !/^\d+$/.test(left[0]) || !/^\d+$/.test(left[1])) return null;
    mounts.push({
      id: left[0],
      root: unescapeMount(left[3]),
      point: unescapeMount(left[4]),
      options: new Set(left[5].split(",")),
      type: right[0],
      source: unescapeMount(right[1]),
      superOptions: new Set(right[2].split(",")),
    });
  }
  return mounts;
}

function unescapeMount(value) {
  return value.replace(/\\(040|011|012|134)/g, (_, octal) => String.fromCharCode(Number.parseInt(octal, 8)));
}

export function parseLimit(input) {
  if (typeof input !== "string") return null;
  const value = input.trim();
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

export function parseCpuMax(input) {
  if (typeof input !== "string") return null;
  const match = /^(\d+)\s+(\d+)$/.exec(input.trim());
  if (!match) return null;
  const quota = Number(match[1]);
  const period = Number(match[2]);
  return Number.isSafeInteger(quota) && Number.isSafeInteger(period) && quota > 0 && period > 0 ? { quota, period } : null;
}

function isReadWrite(mount) {
  return mount.options.has("rw") && !mount.options.has("ro") && !mount.superOptions.has("ro");
}

function tmpSize(mount) {
  for (const option of mount.superOptions) {
    const match = /^size=(\d+)([kKmMgG]?)$/.exec(option);
    if (!match) continue;
    const scale = { "": 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[match[2].toLowerCase()];
    const bytes = Number(match[1]) * scale;
    return Number.isSafeInteger(bytes) ? bytes : null;
  }
  return null;
}

function cgroupFile(cgroupPath, file) {
  if (typeof cgroupPath !== "string" || !/^\/(?:[^/]+(?:\/[^/]+)*)?$/.test(cgroupPath)) return null;
  return path.join(CGROUP_ROOT, cgroupPath, file);
}

function v2CgroupPath(input) {
  if (typeof input !== "string") return null;
  const match = /^0::(\/[^\n]*)$/m.exec(input);
  return match?.[1] ?? null;
}

function defaultIo() {
  return {
    platform,
    release,
    getuid: () => process.getuid?.(),
    getgid: () => process.getgid?.(),
    readFile: (file) => readFile(file, "utf8"),
    lstat,
    open: (file, flags, mode) => open(file, flags, mode),
    unlink,
    randomName: () => randomUUID(),
  };
}

async function safely(read, diagnostics, code) {
  try { return await read(); } catch { diagnostics.push(code); return null; }
}

async function writeProbe(io, rolePath) {
  if (typeof io.open !== "function" || typeof io.unlink !== "function") return false;
  let file;
  let handle;
  let cleaned = false;
  let closed = false;
  try {
    const name = `.gjc-preflight-${typeof io.randomName === "function" ? io.randomName() : randomUUID()}`;
    file = path.join(rolePath, name);
    handle = await io.open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    if (typeof handle.writeFile !== "function" || typeof handle.sync !== "function") return false;
    await handle.writeFile("ok");
    await handle.sync();
    return true;
  } catch {
    return false;
  } finally {
    try {
      if (typeof handle?.close === "function") {
        await handle.close();
        closed = true;
      }
    } catch { /* cleanup continues */ }
    try { if (file) { await io.unlink(file); cleaned = true; } } catch { /* cleanup is verified after the probe */ }
    if (!closed || !cleaned) return false;
  }
}

/** Returns only stable compliance evidence and diagnostic codes; it never exposes host values. */
export async function inspectContainerSecurityPreflight(injectedIo = {}) {
  const io = { ...defaultIo(), ...(injectedIo.io ?? injectedIo) };
  const diagnostics = [];
  const evidence = {};
  const add = (code, value) => { evidence[code] = value; if (!value) diagnostics.push(code); };

  const currentPlatform = await safely(() => typeof io.platform === "function" ? io.platform() : io.platform, diagnostics, "platform-unreadable");
  add("linux", currentPlatform === "linux");
  const kernelRelease = await safely(() => typeof io.release === "function" ? io.release() : io.release, diagnostics, "kernel-unreadable");
  add(
    "native-linux-engine",
    typeof kernelRelease === "string" &&
      !/microsoft|wsl|linuxkit/i.test(kernelRelease)
  );
  const uid = await safely(() => io.getuid(), diagnostics, "identity-unreadable");
  const gid = await safely(() => io.getgid(), diagnostics, "identity-unreadable");
  add("identity", uid === CONTAINER_UID && gid === CONTAINER_GID);

  const mountInfo = await safely(() => io.readFile("/proc/self/mountinfo"), diagnostics, "mountinfo-unreadable");
  const mounts = parseMountInfo(mountInfo);
  if (!mounts) diagnostics.push("mountinfo-malformed");
  const root = mounts?.find((mount) => mount.point === "/");
  add("root-readonly", Boolean(root?.options.has("ro")));

  const roleMounts = Object.entries(ROLE_PATHS).map(([role, rolePath]) => [role, mounts?.find((mount) => mount.point === rolePath)]);
  add("role-mounts", roleMounts.every(([, mount]) => Boolean(mount && isReadWrite(mount))));
  const identities = roleMounts.map(([, mount]) =>
    mount && `${mount.source}\u0000${mount.root}`
  );
  add(
    "role-mount-identities",
    identities.every(Boolean) &&
      new Set(identities).size === identities.length &&
      new Set(roleMounts.map(([, mount]) => mount?.id)).size === roleMounts.length
  );

  let roleOwners = true;
  for (const [, rolePath] of Object.entries(ROLE_PATHS)) {
    const stat = await safely(() => io.lstat(rolePath), diagnostics, "role-owner-unreadable");
    roleOwners = (
      stat?.uid === CONTAINER_UID &&
      stat?.gid === CONTAINER_GID &&
      stat?.isDirectory?.() === true &&
      stat?.isSymbolicLink?.() !== true
    ) && roleOwners;
  }
  add("role-owners", roleOwners);

  const tmp = mounts?.find((mount) => mount.point === "/tmp");
  add("tmp-mount", Boolean(tmp?.type === "tmpfs" && isReadWrite(tmp)));
  const tmpOptions = new Set([
    ...(tmp?.options ?? []),
    ...(tmp?.superOptions ?? []),
  ]);
  add(
    "tmp-options",
    Boolean(
      tmp &&
      tmpOptions.has("noexec") &&
      tmpOptions.has("nosuid") &&
      tmpOptions.has("nodev")
    )
  );
  add("tmp-bounded", (tmpSize(tmp ?? { superOptions: new Set() }) ?? Infinity) <= TMP_MAX_BYTES);

  const status = parseProcessStatus(await safely(() => io.readFile("/proc/self/status"), diagnostics, "status-unreadable"));
  if (!status) diagnostics.push("status-malformed");
  add("no-new-privileges", status?.noNewPrivs === 1);
  add("seccomp", status?.seccomp === 2);
  add("capabilities", Boolean(status && Object.values(status.capabilities).every((value) => /^0+$/.test(value))));

  const cgroupInfo = await safely(() => io.readFile("/proc/self/cgroup"), diagnostics, "cgroup-unreadable");
  const cgroupPath = v2CgroupPath(cgroupInfo);
  const cgroupMount = mounts?.find((mount) => mount.type === "cgroup2" && mount.point === CGROUP_ROOT);
  add("cgroup-v2", Boolean(cgroupPath && cgroupMount));
  const memoryFile = cgroupFile(cgroupPath, "memory.max");
  const pidsFile = cgroupFile(cgroupPath, "pids.max");
  const cpuFile = cgroupFile(cgroupPath, "cpu.max");
  const memory = parseLimit(await safely(() => memoryFile && io.readFile(memoryFile), diagnostics, "cgroup-memory-unreadable"));
  add("cgroup-memory", memory !== null && memory >= cgroupMemoryMinimumMb() * 1024 * 1024);
  const pids = parseLimit(await safely(() => pidsFile && io.readFile(pidsFile), diagnostics, "cgroup-pids-unreadable"));
  add("cgroup-pids", pids !== null && pids >= 128);
  add("cgroup-cpu", parseCpuMax(await safely(() => cpuFile && io.readFile(cpuFile), diagnostics, "cgroup-cpu-unreadable")) !== null);

  let probes = true;
  for (const [, rolePath] of Object.entries(ROLE_PATHS)) {
    probes = (await writeProbe(io, rolePath)) && probes;
  }
  add("role-write-probes", probes);
  return Object.freeze({ ok: diagnostics.length === 0, diagnostics: Object.freeze([...new Set(diagnostics)]), evidence: Object.freeze(evidence) });
}

export async function assertContainerSecurityPreflight(io = {}) {
  const result = await inspectContainerSecurityPreflight(io);
  if (!result.ok) throw new ContainerPreflightError(result.diagnostics[0]);
  return result;
}
