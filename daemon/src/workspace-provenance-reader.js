// Durable provenance record reader (slice S6f.1f, #53/#81).
//
// PURE, dependency-injected primitive that the restore/migration workspace
// orchestrator injects as `provenanceIo`. NOT wired into daemon.js; the
// serving gate (NATIVE_WORKSPACE_SERVING_ENABLED) stays false.
//
// This module reads and parses the durable restore-provenance JSON file
// through an injected S6f.1c contained byte-reader (`createContainedByteReader`
// from ./workspace-contained-byte-reader.js). It does DURABLE READ + PARSE
// ONLY - it does NOT re-validate the provenance schema (field set, version,
// kind, identity). That full verification is owned exclusively by
// `verifyRestoreProvenance` in ./workspace-restore-provenance.js.
//
// Contract mirrors the S6f.1a durable-JSON precedent (readSnapshotInputs):
//   - absent record (reader throws ENOENT)      -> resolves to null
//   - torn/invalid JSON or invalid UTF-8 bytes  -> throws (fail closed)
//   - any other reader error (including the S6f.1c WORKSPACE_ROOT_ESCAPE
//     containment/reparse refusal) propagates unchanged (fail closed)
//
// S6f.5 wiring (not part of this slice) is responsible for populating
// `staged.provenancePath` with the workspace-relative POSIX path to the
// durable provenance JSON file.

const OPERATION = "workspace_provenance_reader";

function refuse(code, reason) {
  const error = new Error(reason);
  error.operation = OPERATION;
  error.code = code;
  throw error;
}

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

/**
 * @param {object} options
 * @param {{ readBytes(relPath: string): Promise<Uint8Array> }} options.reader
 *   an S6f.1c contained byte-reader.
 * @returns {{ readProvenanceRecord(staged:object): Promise<object|null> }}
 */
export function createProvenanceReader({ reader } = {}) {
  if (!reader || typeof reader !== "object" || typeof reader.readBytes !== "function") {
    refuse("PROVENANCE_READER_CONFIG_INVALID", "reader must be an object with a readBytes function");
  }

  async function readProvenanceRecord(staged) {
    if (
      !isPlainObject(staged) ||
      !Object.hasOwn(staged, "provenancePath") ||
      typeof staged.provenancePath !== "string" ||
      staged.provenancePath.length === 0
    ) {
      refuse("PROVENANCE_RECORD_UNREADABLE", "staged.provenancePath must be a non-empty string");
    }
    // Capture once: a getter-bearing staged (already rejected by isPlainObject,
    // but belt-and-suspenders) can never yield a different value between the
    // validation above and the read below.
    const provenancePath = staged.provenancePath;

    let bytes;
    try {
      bytes = await reader.readBytes(provenancePath);
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      // Any other reader error (WORKSPACE_ROOT_ESCAPE, reparse refusal, ...)
      // propagates unchanged - the caller must fail closed on it.
      throw error;
    }

    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(text);
  }

  return Object.freeze({ readProvenanceRecord });
}
