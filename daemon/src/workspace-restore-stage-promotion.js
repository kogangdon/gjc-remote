import { validateWorkspaceManifest, verifyManifestAgainst } from "./workspace-backup-manifest.js";
import { relativeComponents } from "./workspace-containment.js";

const WINDOWS_PLATFORMS = new Set(["windows", "windows-drive", "windows-unc"]);

function refuse(code, reason) {
  const error = new Error(`workspace restore stage promotion refused: ${reason}`);
  error.code = code;
  error.operation = "workspace_restore_stage_promotion";
  error.reason = reason;
  throw error;
}

function assertFunction(value, name) {
  if (typeof value !== "function") {
    refuse("CONFIG_INVALID", `${name} must be a function`);
  }
}

function assertReader(reader, name) {
  if (!reader || typeof reader.readBytes !== "function") {
    refuse("CONFIG_INVALID", `${name} must return { readBytes }`);
  }
  return reader;
}

function platformDetails(sourcePlatform) {
  if (sourcePlatform === "posix") return { containmentPlatform: "posix", separator: "/" };
  if (WINDOWS_PLATFORMS.has(sourcePlatform)) {
    return { containmentPlatform: "windows-drive", separator: "\\" };
  }
  refuse("CONFIG_INVALID", "sourcePlatform must be 'posix', 'windows-drive', or 'windows-unc'");
}

function joinRoot(root, components, separator) {
  return components.length === 0 ? root : `${root}${separator}${components.join(separator)}`;
}

function expectedPath(entryPath, sourcePlatform) {
  return WINDOWS_PLATFORMS.has(sourcePlatform) ? entryPath.replaceAll("/", "\\") : entryPath;
}

function samePathSet(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length &&
    actual.every((path, index) => typeof path === "string" && path === expected[index]);
}

function isAbsent(error) {
  return error?.code === "ENOENT";
}

/**
 * Materializes a sealed restore staging tree into a private candidate tree.
 * Every filesystem capability is injected so production wiring can provide
 * no-follow readers and tests can exercise every failure boundary.
 */
export function createRestoreStagePromotion({ makeStageReader, makeCandidateReader, resolveManifestPaths, fs } = {}) {
  assertFunction(makeStageReader, "makeStageReader");
  assertFunction(makeCandidateReader, "makeCandidateReader");
  assertFunction(resolveManifestPaths, "resolveManifestPaths");
  if (!fs || typeof fs !== "object") refuse("CONFIG_INVALID", "fs must be an object");
  for (const name of ["lstat", "mkdir", "open", "rm"]) assertFunction(fs[name], `fs.${name}`);

  // A path becomes cleanup-eligible only after this instance created it. This
  // prevents an explicit cleanup request from deleting a dispatcher typo, a
  // parent directory, or a pre-existing candidate owned by someone else.
  const ownedCandidates = new Set();

  async function removeOwned(candidatePath) {
    if (!ownedCandidates.has(candidatePath)) return;
    await fs.rm(candidatePath, { recursive: true, force: true });
    ownedCandidates.delete(candidatePath);
  }

  async function cleanup(candidatePath) {
    if (typeof candidatePath !== "string" || candidatePath.length === 0) {
      refuse("CONFIG_INVALID", "candidatePath must be a non-empty string");
    }
    await removeOwned(candidatePath);
  }

  async function assertCandidateAbsent(candidatePath) {
    try {
      await fs.lstat(candidatePath);
    } catch (error) {
      if (isAbsent(error)) return;
      throw error;
    }
    refuse("RESTORE_STAGE_CANDIDATE_EXISTS", "candidate path already exists");
  }

  async function createParentDirectories(candidatePath, components, separator, createdDirectories) {
    for (let count = 1; count < components.length; count += 1) {
      const parent = joinRoot(candidatePath, components.slice(0, count), separator);
      if (createdDirectories.has(parent)) continue;
      // No recursive mkdir: an EEXIST race is refused rather than traversed.
      await fs.mkdir(parent, { mode: 0o700 });
      createdDirectories.add(parent);
    }
  }

  async function writeExclusive(path, bytes) {
    const handle = await fs.open(path, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  async function syncDirectory(path) {
    const handle = await fs.open(path, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  async function materializeAndVerify({
    stagingPath,
    candidatePath,
    sourcePlatform,
    manifest,
    stageReader: retainedStageReader,
  } = {}) {
    if (typeof stagingPath !== "string" || stagingPath.length === 0) {
      refuse("CONFIG_INVALID", "stagingPath must be a non-empty string");
    }
    if (typeof candidatePath !== "string" || candidatePath.length === 0) {
      refuse("CONFIG_INVALID", "candidatePath must be a non-empty string");
    }
    if (stagingPath === candidatePath) {
      refuse("CONFIG_INVALID", "stagingPath and candidatePath must differ");
    }
    const { containmentPlatform, separator } = platformDetails(sourcePlatform);
    validateWorkspaceManifest(manifest);
    if (manifest.sourcePlatform !== sourcePlatform) {
      refuse("WORKSPACE_MANIFEST_INVALID", "manifest sourcePlatform does not match materialization sourcePlatform");
    }

    let created = false;
    try {
      await assertCandidateAbsent(candidatePath);
      // Atomic, non-recursive creation is both the private-directory boundary
      // and the final defense against a candidate appearing after lstat.
      await fs.mkdir(candidatePath, { mode: 0o700 });
      created = true;
      ownedCandidates.add(candidatePath);

      const stageReader = assertReader(
        retainedStageReader ??
          await makeStageReader(stagingPath, sourcePlatform),
        "stageReader"
      );
      const createdDirectories = new Set();
      for (const entry of manifest.entries) {
        const relativePath = expectedPath(entry.path, sourcePlatform);
        const components = relativeComponents(
          candidatePath,
          `${candidatePath}${separator}${relativePath}`,
          containmentPlatform
        );
        // A POSIX-looking manifest entry must never become an opaque backslash
        // component on a different host path vocabulary.
        if (components.length === 0 || components.some((part) => part.includes("/") || part.includes("\\"))) {
          refuse("WORKSPACE_ROOT_ESCAPE", `manifest path is not a single-component sequence: ${entry.path}`);
        }
        await createParentDirectories(candidatePath, components, separator, createdDirectories);
        const bytes = await stageReader.readBytes(entry.path);
        if (!(bytes instanceof Uint8Array)) {
          refuse("WORKSPACE_MANIFEST_READ_FAILED", `stage reader for ${entry.path} did not return bytes`);
        }
        await writeExclusive(joinRoot(candidatePath, components, separator), bytes);
      }

      const expected = manifest.entries.map((entry) => expectedPath(entry.path, sourcePlatform)).sort();
      const actual = await resolveManifestPaths(candidatePath, sourcePlatform);
      if (!samePathSet(actual, expected)) {
        refuse("WORKSPACE_MANIFEST_MISMATCH", "candidate regular-file paths do not exactly match the manifest");
      }

      const candidateReader = assertReader(await makeCandidateReader(candidatePath, sourcePlatform), "makeCandidateReader");
      let verification;
      try {
        verification = await verifyManifestAgainst(candidateReader, manifest);
      } finally {
        if (typeof candidateReader.close === "function") {
          await candidateReader.close();
        }
      }
      const parentBoundary = candidatePath.lastIndexOf(separator);
      const candidateParent = parentBoundary === 0
        ? separator
        : candidatePath.slice(0, parentBoundary);
      for (const directory of [
        ...[...createdDirectories].sort(
          (left, right) => right.length - left.length
        ),
        candidatePath,
        candidateParent,
      ]) {
        await syncDirectory(directory);
      }
      return Object.freeze({
        manifestFingerprint: manifest.manifestFingerprint,
        verifiedCount: verification.verifiedCount,
      });
    } catch (error) {
      if (created) {
        try {
          await removeOwned(candidatePath);
        } catch (cleanupError) {
          error.cleanupError = cleanupError;
        }
      }
      throw error;
    }
  }

  return Object.freeze({ materializeAndVerify, cleanup });
}
