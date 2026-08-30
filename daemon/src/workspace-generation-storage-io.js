// Real fs-backed generation-storage io FOUNDATION (#53 Phase 2, slice S6f.1a).
//
// The S4d generation publisher (workspace-generation-publisher.js) and S5d
// tombstone publisher (workspace-tombstone-publisher.js) are PURE, injected-io
// primitives: they perform NO filesystem I/O themselves and consume a 5-method
// async io object (`readLivePointer`, `writeTemp`, `flushTemp`, `replace`,
// `flushParent`). Boot-recovery (S6a-S6e) and the future S6f/S6g lifecycle
// orchestrators need a REAL implementation of that io over the actual
// filesystem before they can be wired up. This module is that implementation.
//
// This module is itself PURE dependency-injection GLUE around `node:fs`: it
// does NOT wire into the daemon, does NOT import daemon.js, and does NOT flip
// the native-workspace-serving gate (NATIVE_WORKSPACE_SERVING_ENABLED stays
// false). It is a foundation the S6f/S6g wiring seam will consume later.
//
// SEAM OBLIGATIONS (owned by this module, matching the publishers' header
// contract for the S4f/S4g-style wiring seam):
//
//   1. ATOMIC REPLACE IS THE LINEARISATION POINT. `replace` is a single
//      `fs.rename` of the exclusive temp onto the live pointer path, in the
//      SAME directory (see obligation 3), so it is an atomic rename on both
//      POSIX and win32 (Node maps rename to `MoveFileExW` with
//      `MOVEFILE_REPLACE_EXISTING` on win32). A crash (SIGKILL) before
//      `replace` leaves the live pointer at its exact prior value (or absent,
//      on a first publication); a crash at/after `replace` leaves the new
//      value live. Never a torn pointer.
//
//   2. EXCLUSIVE TEMP CREATE. `writeTemp` opens its temp file with the `'wx'`
//      flag (`O_CREAT | O_EXCL`), so two concurrent callers can never observe
//      or clobber the same temp file: one wins the exclusive create, the other
//      gets `EEXIST` (surfaced as a rejected promise, not silently ignored).
//      The temp name embeds the process id, a monotonic per-process counter,
//      and random bytes, making a same-process/same-tick collision practically
//      impossible while still funnelling any that occur into EEXIST.
//
//   3. SAME-VOLUME TEMP + LEFTOVER-TEMP SWEEP. The exclusive temp is created in
//      the SAME directory as the live pointer, so the `replace` rename is
//      always same-volume (a cross-volume "rename" degrades to a non-atomic
//      copy+delete and would violate obligation 1). A publication that fails
//      at/after `writeTemp` but before `replace` may leave the exclusive temp
//      on disk (the temp name is `<basename>.<pid>.<counter>.<hex>.tmp`).
//      `sweepLeftoverTemps()` removes EVERY leftover sibling matching this
//      pointer's `<basename>.*.tmp` pattern -- across all pids, so it reclaims
//      orphans left by a CRASHED prior process, not just this one. It is an
//      EXPLICIT boot-recovery operation the wiring seam invokes once at startup
//      BEFORE any writer is active; `writeTemp` deliberately does NOT sweep,
//      so a concurrent in-flight publish can never have its temp unlinked out
//      from under it (per-workspace publication serialization remains the
//      caller's obligation per the publishers' header).
//
// WIN32 HONESTY (documented no-op): `flushParent` fsyncs the pointer's parent
// directory to make a completed rename durable across power loss, which is a
// real POSIX capability (open the directory O_RDONLY, fsync its fd). Win32 has
// no directory-fsync primitive (opening a directory for `fs.fsync` fails); on
// win32, `flushParent` is a documented, deliberate no-op -- durability of the
// rename itself is still provided by the NTFS journal, but a directory-fsync
// power-loss guarantee is unavailable on this platform. This is NOT a bug to
// fix here; it is an intentional lesser guarantee, matching the module's
// dependency-injection contract (the wiring seam owns the concrete
// filesystem/platform tradeoffs).

import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { mkdir, open, readdir, readFile, rename, stat, unlink } from "node:fs/promises";
import path from "node:path";

import { canonicalJsonBytes } from "@gjc-remote/shared/strict-json.js";
import { validateManualCleanup } from "@gjc-remote/shared/recovery-envelope.js";
import { parseGenerationPointer } from "./workspace-generation-publisher.js";

let tempCounter = 0;

function nextTempSuffix() {
  tempCounter += 1;
  return `${process.pid}.${tempCounter}.${randomBytes(6).toString("hex")}`;
}

async function readBytesOrNull(filePath) {
  try {
    const buffer = await readFile(filePath);
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function readJsonOrNull(filePath) {
  let text;
  try {
    text = await readFile(filePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  // A torn/partial write is not valid JSON and MUST throw (not silently null);
  // only ENOENT (the file never existed / was never published) maps to null.
  return JSON.parse(text);
}

/**
 * Create the real fs-backed io consumed by `publishGeneration` /
 * `publishTombstone` / `readLiveGeneration` / `readLiveTombstone`, bound to a
 * single live pointer file. See the module header for the three seam
 * obligations this implementation upholds.
 *
 * @param {{ pointerPath: string }} options
 */
export function createAtomicPointerIo({ pointerPath }) {
  if (typeof pointerPath !== "string" || pointerPath.length === 0) {
    throw new Error("createAtomicPointerIo: pointerPath must be a non-empty string");
  }
  const dir = path.dirname(pointerPath);
  const base = path.basename(pointerPath);
  const tempPrefix = `${base}.`;
  const tempSuffix = ".tmp";

  /** Remove every leftover temp sibling matching this pointer's temp pattern. */
  async function sweepLeftoverTemps() {
    let entries;
    try {
      entries = await readdir(dir);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    await Promise.all(
      entries
        .filter((name) => name.startsWith(tempPrefix) && name.endsWith(tempSuffix))
        .map(async (name) => {
          try {
            await unlink(path.join(dir, name));
          } catch (error) {
            if (error?.code !== "ENOENT") throw error;
          }
        })
    );
  }

  async function readLivePointer() {
    return readBytesOrNull(pointerPath);
  }

  async function writeTemp(bytes) {
    // No sweep here: sweeping on every writeTemp could unlink a concurrent
    // writer's in-flight temp. Orphan reclamation is the explicit
    // boot-recovery responsibility of sweepLeftoverTemps() (seam obligation 3).
    const tempPath = path.join(dir, `${tempPrefix}${nextTempSuffix()}${tempSuffix}`);
    // 'wx' == O_CREAT | O_EXCL | O_WRONLY: exclusive create, rejects EEXIST
    // rather than truncating/overwriting an existing file (seam obligation 2).
    const handle = await open(tempPath, "wx");
    try {
      await handle.writeFile(bytes);
    } catch (error) {
      await handle.close().catch(() => {});
      throw error;
    }
    return { tempPath, handle };
  }

  async function flushTemp(tempRef) {
    // Close ALWAYS runs, even if sync() rejects, so a failed publication step
    // never leaks the open temp fd (on win32 a leaked handle also blocks the
    // temp's later deletion). The sync() error is the one that propagates.
    try {
      await tempRef.handle.sync();
    } finally {
      await tempRef.handle.close().catch(() => {});
    }
  }

  async function replace(tempRef) {
    await rename(tempRef.tempPath, pointerPath);
  }

  async function flushParent() {
    if (process.platform === "win32") {
      // WIN32 HONESTY: no directory-fsync primitive exists; documented no-op
      // (see module header). Deliberately does not attempt to open `dir`.
      return;
    }
    let handle;
    try {
      handle = await open(dir, fsConstants.O_RDONLY);
    } catch (error) {
      // A permission/access failure is a real misconfiguration and MUST surface;
      // only "this platform/FS cannot fsync a directory fd" degrades to a no-op.
      if (error?.code === "EISDIR" || error?.code === "EBADF" || error?.code === "EINVAL") return;
      throw error;
    }
    try {
      await handle.sync();
    } catch (error) {
      if (error?.code === "EISDIR" || error?.code === "EBADF" || error?.code === "EINVAL") return;
      throw error;
    } finally {
      await handle.close().catch(() => {});
    }
  }

  return { readLivePointer, writeTemp, flushTemp, replace, flushParent, sweepLeftoverTemps };
}

async function ensureDir(dirPath) {
  await mkdir(dirPath, { recursive: true });
}

/**
 * `createAtomicPointerIo` bound to the live generation pointer path
 * `<workspaceRoot>/<workspaceId>/generation/live.ptr`. Ensures the
 * `generation/` directory exists (mkdir -p) so the same-volume temp (seam
 * obligation 3) has somewhere to live.
 *
 * @param {{ workspaceRoot: string, workspaceId: string }} options
 */
export async function createGenerationPublisherIo({ workspaceRoot, workspaceId }) {
  const dir = path.join(workspaceRoot, workspaceId, "generation");
  await ensureDir(dir);
  return createAtomicPointerIo({ pointerPath: path.join(dir, "live.ptr") });
}

/**
 * `createAtomicPointerIo` bound to the live tombstone path
 * `<workspaceRoot>/<workspaceId>/tombstone/live.tomb`. Ensures the
 * `tombstone/` directory exists (mkdir -p).
 *
 * @param {{ workspaceRoot: string, workspaceId: string }} options
 */
export async function createTombstonePublisherIo({ workspaceRoot, workspaceId }) {
  const dir = path.join(workspaceRoot, workspaceId, "tombstone");
  await ensureDir(dir);
  return createAtomicPointerIo({ pointerPath: path.join(dir, "live.tomb") });
}

/**
 * Durable contingency record for a reset/delete publication. It is prepared
 * before the ambiguous pointer-write window and removed only after a committed
 * terminal transition. A crash while it exists makes boot recovery bar the
 * workspace through the existing manual-cleanup snapshot field.
 */
export async function createManualCleanupPublisherIo({ workspaceRoot, workspaceId }) {
  const dir = path.join(workspaceRoot, workspaceId, "lifecycle");
  await ensureDir(dir);
  const recordPath = path.join(dir, "manual-cleanup.json");
  const io = createAtomicPointerIo({ pointerPath: recordPath });

  async function publish(record) {
    validateManualCleanup(record);
    const bytes = canonicalJsonBytes(record);
    const existing = await io.readLivePointer();
    if (existing !== null) {
      if (Buffer.from(existing).equals(Buffer.from(bytes))) return;
      const error = new Error("manual-cleanup record already exists");
      error.code = "WORKSPACE_LIFECYCLE_JOURNAL_CONFLICT";
      throw error;
    }
    let replaced = false;
    try {
      const temp = await io.writeTemp(bytes);
      await io.flushTemp(temp);
      await io.replace(temp);
      replaced = true;
      await io.flushParent();
    } catch (error) {
      error.terminalPreparationAmbiguous = replaced;
      throw error;
    }
  }

  async function clear() {
    try {
      await unlink(recordPath);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await io.flushParent();
  }

  return Object.freeze({ publish, clear });
}

/**
 * Read the 6 nullable inputs a boot-recovery snapshot is assembled from (see
 * `workspace-recovery-snapshot.js` / `workspace-recovery-operation.js`):
 * `{ livePointer, priorPointer, candidatePointer, checkpoint, transaction,
 * manualCleanup }`. Each field is read from a fixed on-disk path and is either
 * `null` (the file is absent, ENOENT) or a parsed value:
 *   - the three pointer fields are parsed+validated via
 *     `parseGenerationPointer` (a torn/partial pointer file THROWS, per the
 *     validator);
 *   - checkpoint/transaction/manualCleanup are `JSON.parse`d and returned as
 *     the plain parsed object WITHOUT further validation here (the boot
 *     recovery operation owns validating those against each other) -- a
 *     torn/partial JSON file THROWS via `JSON.parse`, never silently null.
 * Only ENOENT ever maps to `null`.
 *
 * @param {{ workspaceRoot: string, workspaceId: string }} options
 */
export async function readSnapshotInputs({ workspaceRoot, workspaceId }) {
  const root = path.join(workspaceRoot, workspaceId);
  const [livePointerBytes, priorPointerBytes, candidatePointerBytes, checkpoint, transaction, manualCleanup] =
    await Promise.all([
      readBytesOrNull(path.join(root, "generation", "live.ptr")),
      readBytesOrNull(path.join(root, "generation", "prior.ptr")),
      readBytesOrNull(path.join(root, "generation", "candidate.ptr")),
      readJsonOrNull(path.join(root, "lifecycle", "checkpoint.json")),
      readJsonOrNull(path.join(root, "lifecycle", "transaction.json")),
      readJsonOrNull(path.join(root, "lifecycle", "manual-cleanup.json")),
    ]);

  return {
    livePointer: livePointerBytes === null ? null : parseGenerationPointer(livePointerBytes),
    priorPointer: priorPointerBytes === null ? null : parseGenerationPointer(priorPointerBytes),
    candidatePointer: candidatePointerBytes === null ? null : parseGenerationPointer(candidatePointerBytes),
    checkpoint,
    transaction,
    manualCleanup,
  };
}

async function isDirectory(dirPath) {
  try {
    const info = await stat(dirPath);
    return info.isDirectory();
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

/**
 * Enumerate the workspace ids under `workspaceRoot` that carry recoverable
 * on-disk state: a `generation/live.ptr`, a `tombstone/live.tomb`, or a
 * `lifecycle/` directory. This is the boot enumeration source
 * `recoverWorkspaces(deps, workspaceIds)` currently lacks -- a workspace
 * directory with none of these is not yet published/recoverable and is
 * excluded. Returns `[]` when `workspaceRoot` itself does not exist (ENOENT).
 * Results are sorted deterministically (ascending string order).
 *
 * @param {{ workspaceRoot: string }} options
 */
export async function enumerateRecoverableWorkspaces({ workspaceRoot }) {
  let entries;
  try {
    entries = await readdir(workspaceRoot, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }

  const workspaceIds = [];
  for (const entry of entries) {
    // A workspace root MAY be a symlink/junction to a directory; follow it via
    // stat so such roots are not silently excluded from boot enumeration.
    let isDir = entry.isDirectory();
    if (!isDir && entry.isSymbolicLink()) {
      isDir = await isDirectory(path.join(workspaceRoot, entry.name));
    }
    if (!isDir) continue;
    const workspaceId = entry.name;
    const root = path.join(workspaceRoot, workspaceId);
    const [hasLivePointer, hasTombstone, hasLifecycle] = await Promise.all([
      stat(path.join(root, "generation", "live.ptr")).then(() => true).catch((error) => {
        if (error?.code === "ENOENT") return false;
        throw error;
      }),
      stat(path.join(root, "tombstone", "live.tomb")).then(() => true).catch((error) => {
        if (error?.code === "ENOENT") return false;
        throw error;
      }),
      isDirectory(path.join(root, "lifecycle")),
    ]);
    if (hasLivePointer || hasTombstone || hasLifecycle) workspaceIds.push(workspaceId);
  }
  workspaceIds.sort();
  return workspaceIds;
}
