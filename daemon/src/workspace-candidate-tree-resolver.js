// Candidate-tree manifest path resolver (slice S6f.7b).
//
// Pure, dependency-injected fs enumerator that produces the `manifestPaths`
// input the create and refresh orchestrators consume:
//
//   resolveManifestPaths(candidatePath, platform) => Promise<string[]>
//
// consumed at:
//   - workspace-create-dispatch.js   -> manifestIo.readBytes(relPath)
//   - workspace-refresh-dispatch.js  -> manifestIo.readBytes(relPath)
//
// Contract
// --------
// Given an already-verified candidate ROOT directory (`candidatePath`), it
// recursively enumerates every regular file underneath it and returns their
// paths RELATIVE to that root, joined with the source-platform separator so
// that the contained byte reader (createContainedByteReader) can re-resolve
// each entry with `relativeComponents(root, relPath, ...)` and read its bytes.
//
// The returned list is sorted for a deterministic manifest ordering.
//
// Escape / reparse scope (mirrors workspace-contained-byte-reader.js S7 #171)
// --------------------------------------------------------------------------
// This enumerator performs only two safety checks and delegates the deep,
// per-component native reparse verification to the injected `containment`
// dependency the orchestrators already own (descoped to S7 / issue #171):
//   1. Symlink LEAF / symlink DIRECTORY entries are SKIPPED - a symlinked
//      subdirectory is never descended (so it cannot smuggle a path that
//      escapes the candidate root through a reparse point), and a symlink
//      file leaf is excluded (the byte reader would refuse it anyway).
//   2. Every emitted relative path is re-validated through the pure lexical
//      guard `relativeComponents` (reused, never reimplemented). A dirent
//      whose name would introduce a "."/".." traversal or an embedded
//      separator is refused with WORKSPACE_ROOT_ESCAPE.
// Intermediate-directory reparse points at deeper components remain the
// `containment` dependency's responsibility, exactly as in the byte reader.
//
// This module never wires into daemon.js; it is landed-but-unwired foundation
// consumed by the S6f.7d create/refresh bundle assembly.

import { readdir as fsReaddir } from "node:fs/promises";

import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared/protocol";

import { relativeComponents } from "./workspace-containment.js";

function refuse(code, reason) {
  const error = new Error(`resolveManifestPaths refused: ${reason}`);
  error.code = code;
  error.reason = reason;
  throw error;
}

/**
 * @param {object} [options]
 * @param {(dir: string, opts: object) => Promise<import("node:fs").Dirent[]>} [options.readdir]
 *   Injectable directory reader (defaults to node:fs/promises readdir with
 *   `{ withFileTypes: true }`). Tests inject a fake to exercise nesting,
 *   symlink exclusion, and escape refusal without real reparse points.
 * @returns {(candidatePath: string, platform: "posix"|"windows") => Promise<string[]>}
 */
export function createCandidateManifestResolver({
  readdir = fsReaddir,
  rejectUnsupported = false,
} = {}) {
  if (typeof readdir !== "function") {
    refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "readdir must be a function");
  }

  async function resolveManifestPaths(candidatePath, platform) {
    if (typeof candidatePath !== "string" || candidatePath.length === 0) {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "candidatePath must be a non-empty string");
    }
    if (platform !== "posix" && platform !== "windows") {
      refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "platform must be 'posix' or 'windows'");
    }

    const sep = platform === "windows" ? "\\" : "/";
    const containmentPlatform = platform === "windows" ? "windows-drive" : "posix";
    const results = [];

    async function walk(dirAbs, relSegments) {
      const entries = await readdir(dirAbs, { withFileTypes: true });
      for (const dirent of entries) {
        // Fail closed on a malformed readdir dep: a dirent MUST expose the
        // classification methods, otherwise a symlink could be silently
        // treated as a regular file (fail-open escape).
        if (
          typeof dirent?.isSymbolicLink !== "function" ||
          typeof dirent?.isDirectory !== "function" ||
          typeof dirent?.isFile !== "function"
        ) {
          refuse(PROTOCOL_ERROR_CODES.CONFIG_INVALID, "readdir must yield dirents with type predicates");
        }
        // Skip reparse leaves / reparse directories: a symlinked subdirectory
        // is never descended, a symlink file leaf is never emitted. Deep
        // per-component reparse verification is the containment dep's job (S7).
        if (dirent.isSymbolicLink()) {
          if (rejectUnsupported) {
            refuse(
              "WORKSPACE_MANIFEST_MISMATCH",
              "candidate contains a symbolic link"
            );
          }
          continue;
        }
        const childRel = [...relSegments, dirent.name];
        if (dirent.isDirectory()) {
          // Descend using the source-platform separator so every filesystem
          // path stays consistent with candidatePath's separator convention
          // (source == host for the local-serving operator case).
          await walk(`${dirAbs}${sep}${dirent.name}`, childRel);
          continue;
        }
        if (!dirent.isFile()) {
          if (rejectUnsupported) {
            refuse(
              "WORKSPACE_MANIFEST_MISMATCH",
              "candidate contains an unsupported filesystem entry"
            );
          }
          // sockets / fifos / block+char devices are not manifest content.
          continue;
        }
        const relPath = childRel.join(sep);
        // Defense in depth: reuse the pure lexical guard. Throws
        // WORKSPACE_ROOT_ESCAPE on a "."/".."/absolute-escape segment. Also
        // refuse any component carrying an embedded separator (a dirent name
        // must be a single path component).
        const components = relativeComponents(
          candidatePath,
          `${candidatePath}${sep}${relPath}`,
          containmentPlatform
        );
        for (const component of components) {
          if (component.includes("/") || component.includes("\\")) {
            refuse("WORKSPACE_ROOT_ESCAPE", "manifest path component carries an embedded separator");
          }
        }
        results.push(relPath);
      }
    }

    await walk(candidatePath, []);
    results.sort();
    return results;
  }

  return resolveManifestPaths;
}
