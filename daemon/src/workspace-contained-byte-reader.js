// Contained byte reader (slice S6f.1c).
//
// This is the real `{ readBytes(relPath) }` io that all four workspace
// lifecycle orchestrators (create, refresh, reset/delete, restore-migration)
// consume as manifestIo / backupIo / checksumIo - the "S4c reparse-safe
// reader" referenced in their header contracts:
//   - workspace-create-operation.js            -> manifestIo.readBytes
//   - workspace-refresh-operation.js            -> manifestIo.readBytes
//   - workspace-reset-delete-operation.js       -> backupIo.readBytes
//   - workspace-restore-migration-operation.js  -> checksumIo.readBytes
//
// Contract: `readBytes(relPath)` resolves `relPath` against a fixed `root`
// and returns the file's bytes as a Uint8Array, or throws/rejects.
//
// Containment: path escape (NUL byte, an absolute path outside root, or a
// "."/".." traversal segment) is refused with `WORKSPACE_ROOT_ESCAPE` by
// REUSING the pure lexical guard `relativeComponents` exported from
// workspace-containment.js - this module never re-implements that logic.
//
// Reparse scope (S7 / issue #171 boundary): the `containment` dependency
// injected into the orchestrators owns FULL native, per-component reparse
// verification (junctions/symlinks/mount points at any path segment) via the
// native addon - that deep verification is explicitly descoped from this
// slice and deferred to S7 (issue #171). This reader performs only:
//   1. lexical containment of the relative path (via relativeComponents), and
//   2. a cheap LEAF reparse refusal - the final path component is refused if
//      it is itself a reparse point (symlink). On POSIX this is enforced by
//      opening with O_NOFOLLOW so a symlink leaf fails atomically with ELOOP.
//      On win32, O_NOFOLLOW has no effect on `fs.open`, so an `lstat` of the
//      resolved leaf is used instead and a symbolic-link leaf is refused
//      before any read occurs. Neither path inspects intermediate
//      directory components for reparse points; that remains the
//      `containment` dependency's job.
//
// fs errors other than the leaf-reparse refusal (ENOENT, EISDIR, EACCES, ...)
// propagate to the caller unmodified - the orchestrators own interpreting
// those errors.

import { constants as fsConstants } from "node:fs";
import { open, lstat, readFile } from "node:fs/promises";

import { relativeComponents } from "./workspace-containment.js";

const REPARSE_LEAF_CODE = "WORKSPACE_ROOT_ESCAPE";

function refuseReparseLeaf(reason) {
  const error = new Error(`contained byte reader refused: ${reason}`);
  error.code = REPARSE_LEAF_CODE;
  error.reason = reason;
  throw error;
}

/**
 * @param {object} options
 * @param {string} options.root - workspace root the reader is confined to.
 * @param {"posix"|"windows"} [options.sourcePlatform] - defaults from the
 *   running process's platform; callers verifying a foreign-platform root
 *   (e.g. a Windows root inspected from a POSIX host) must pass it explicitly.
 * @returns {{ readBytes(relPath: string): Promise<Uint8Array> }}
 */
export function createContainedByteReader({
  root,
  sourcePlatform = process.platform === "win32" ? "windows" : "posix",
} = {}) {
  if (typeof root !== "string" || root.length === 0) {
    throw new TypeError("createContainedByteReader requires a non-empty root string");
  }
  if (sourcePlatform !== "posix" && sourcePlatform !== "windows") {
    throw new TypeError("createContainedByteReader sourcePlatform must be 'posix' or 'windows'");
  }

  const containmentPlatform = sourcePlatform === "windows" ? "windows-drive" : "posix";
  const sep = sourcePlatform === "windows" ? "\\" : "/";

  async function readBytes(relPath) {
    // Lexical containment guard (reused, not reimplemented). Throws
    // WORKSPACE_ROOT_ESCAPE on NUL byte / absolute-outside-root / "."/".."
    // traversal segments.
    const components = relativeComponents(root, relPath, containmentPlatform);
    // Defense in depth against a platform-vocabulary mismatch: relativeComponents
    // splits on the sourcePlatform separator only, so in 'posix' mode a component
    // like "..\\secret" survives as one opaque segment that the host filesystem
    // would still resolve as a traversal. Refuse ANY verified component that
    // carries a foreign path separator, so no relPath can escape root regardless
    // of the sourcePlatform vs host-platform combination.
    for (const component of components) {
      if (component.includes("/") || component.includes("\\")) {
        refuseReparseLeaf("byte-reader refuses a path component with an embedded separator");
      }
    }
    const resolvedPath = components.length === 0 ? root : `${root}${sep}${components.join(sep)}`;

    if (process.platform === "win32") {
      // O_NOFOLLOW has no effect on Windows fs.open; use lstat on the
      // resolved leaf to detect and refuse a symlink leaf before reading.
      // NOTE: the lstat -> readFile pair has an inherent leaf-swap TOCTOU window
      // on win32 (readFile follows a symlink); full per-component reparse
      // verification is the containment dep's responsibility, deferred to S7
      // (#171). This is a cheap best-effort leaf guard, not full protection.
      const stats = await lstat(resolvedPath);
      if (stats.isSymbolicLink()) {
        refuseReparseLeaf("byte-reader refuses a reparse-point leaf");
      }
      const buffer = await readFile(resolvedPath);
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    }

    // POSIX: open with O_NOFOLLOW so a symlink leaf fails atomically (ELOOP)
    // without a separate lstat+read TOCTOU window.
    let handle;
    try {
      handle = await open(resolvedPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    } catch (error) {
      if (error?.code === "ELOOP") {
        refuseReparseLeaf("byte-reader refuses a reparse-point leaf");
      }
      throw error;
    }
    try {
      const buffer = await handle.readFile();
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } finally {
      await handle.close();
    }
  }

  return Object.freeze({ readBytes });
}
