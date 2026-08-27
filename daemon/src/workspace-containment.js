// Workspace containment + identity primitive (slice S4a).
//
// Pure, dependency-injected module that answers two questions about a native
// workspace root without ever following a reparse point (junction / symlink /
// mount point):
//
//   1. identifyRoot    - what is the canonical, reparse-free identity of this
//                        workspace ROOT directory (POSIX dev/ino or Windows
//                        volume-serial+FileId)? This is the mapping / no-follow
//                        identity proof used by create/clone and refresh.
//   2. verifyContained - does a candidate path resolve, WITHOUT following any
//                        reparse point at ANY component, to an object strictly
//                        inside the workspace root, and what is its identity?
//
// The module never imports the native addon directly; the caller injects a
// `lowLevel` object exposing the verified native capabilities. This keeps the
// module unit-testable with a fake and lets production wiring (a later slice)
// supply the real, signature-verified addon.
//
// No-follow mechanism (validated against the real addon in
// workspace-containment.integration.test.js)
// ----------------------------------------------------------------------------
// The native `open_verified_object_handle` primitive is purpose-built for the
// management control-file object and returns null for directories, so it is not
// a general directory-descent primitive. The capabilities that DO work for
// arbitrary paths are:
//   * read_workspace_root_facts(dir, sourcePlatform) - proves an entire
//     DIRECTORY path is reparse-free and canonical (throws if any component is
//     a reparse point, if the path is a file, or on windows-unc) and returns
//     its win32-root-v1 / posix-root-v1 identity.
//   * path_exists_no_follow(path) - true for a normal existing leaf, false when
//     absent, and THROWS when the leaf itself is a reparse point.
//   * read_identity(path) - no-follow identity of a leaf; throws on a reparse
//     leaf.
// Containment is therefore proven by (a) an identifyRoot canonical proof of the
// root, then (b) a SHALLOW-TO-DEEP prefix walk that no-follow-checks every
// component in order. Because a reparse point at any component is caught when
// that prefix is checked - before the walk descends past it - an intermediate
// junction cannot be silently traversed. `read_identity` on the fully verified
// leaf yields the object identity. A residual same-process TOCTOU window
// between successive prefix checks is unavoidable with path-based primitives;
// the shallow-to-deep ordering minimises it. `expectedRootIdentity` detects a
// replacement of the ROOT directory only (not an intermediate-component swap
// mid-walk); intermediate races remain the caller protocol's concern.

const OPERATION = "verify_workspace_containment";
const SUPPORTED_PLATFORMS = new Set(["posix", "windows-drive"]);
const REQUIRED_CAPABILITIES = ["read_workspace_root_facts", "path_exists_no_follow", "read_identity"];

function refuse(code, reason) {
  const error = new Error(`${OPERATION} refused: ${reason}`);
  error.code = code;
  error.operation = OPERATION;
  error.reason = reason;
  throw error;
}

// Structural identity equality that does not depend on key order and never
// treats two differently-shaped objects as equal.
function sameIdentity(left, right) {
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length) return false;
  for (let index = 0; index < leftKeys.length; index += 1) {
    if (leftKeys[index] !== rightKeys[index]) return false;
    if (left[leftKeys[index]] !== right[rightKeys[index]]) return false;
  }
  return true;
}

const isUint64 = (value) =>
  typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value) && (() => {
    try {
      return BigInt(value) <= 18446744073709551615n;
    } catch {
      return false;
    }
  })();

// Mirrors native-control/src/inventory.js objectIdentityLike for defense in
// depth: the module refuses to treat a malformed native response as a valid
// root identity.
function validRootIdentity(value, sourcePlatform) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (sourcePlatform === "posix") {
    return keys.length === 3 && value.kind === "posix-root-v1" &&
      isUint64(value.device) && isUint64(value.inode);
  }
  return keys.length === 3 && value.kind === "win32-root-v1" &&
    /^[a-f0-9]{16}$/.test(value.volumeSerial) && /^[a-f0-9]{32}$/.test(value.fileId);
}

function validStorageIdentity(value, sourcePlatform) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (sourcePlatform === "posix") {
    return keys.length === 2 && value.kind === "posix-storage-v1" && isUint64(value.device);
  }
  return keys.length === 4 && value.kind === "windows-drive-storage-v1" &&
    /^\\\\\?\\VOLUME\{[0-9A-F-]{36}\}\\$/.test(value.volumeGuid) &&
    /^[0-9A-F]{8}$/.test(value.volumeSerial) &&
    /^[A-Z0-9._-]{1,32}$/.test(value.fileSystem);
}

// Canonical fully-qualified workDir shape per source platform. Matches the
// route-authority canonical root shape (mapping-envelope canonicalPosixRoot /
// canonicalWindowsDriveRoot): absolute, platform-native separators only, and no
// "", "." or ".." segments.
function validWorkDir(workDir, sourcePlatform) {
  if (typeof workDir !== "string" || workDir.length === 0) return false;
  if (sourcePlatform === "posix") {
    if (!workDir.startsWith("/") || workDir.includes("\\")) return false;
    if (workDir !== "/" && workDir.endsWith("/")) return false;
    return !workDir
      .split("/")
      .some((segment, index) => index > 0 && (segment === "" || segment === "." || segment === ".."));
  }
  // windows-drive
  if (!/^[A-Z]:\\/.test(workDir) || workDir.includes("/")) return false;
  const tail = workDir.slice(3);
  return tail === "" || !tail.split("\\").some((segment) => segment === "" || segment === "." || segment === "..");
}

const separatorFor = (sourcePlatform) => (sourcePlatform === "posix" ? "/" : "\\");

// Computes the list of path components between a workspace root and a candidate,
// refusing any lexical escape (NUL byte, "..", absolute path outside the root,
// or a drive/root-prefix mismatch) BEFORE any filesystem access. Returns [] when
// the candidate denotes the root itself.
export function relativeComponents(workDir, candidate, sourcePlatform) {
  if (typeof candidate !== "string" || candidate.length === 0) {
    refuse("WORKSPACE_ROOT_ESCAPE", "candidate is empty");
  }
  if (candidate.includes("\0")) {
    refuse("WORKSPACE_ROOT_ESCAPE", "candidate contains a NUL byte");
  }

  const posix = sourcePlatform === "posix";
  const sep = separatorFor(sourcePlatform);
  // Windows path comparison is case-insensitive. toLowerCase() is an
  // approximation of NTFS $UpCase folding, but the direction is fail-closed:
  // the walked path is always reconstructed from workDir + verified components,
  // so a folding mismatch can only over-refuse, never admit an escape.
  const insensitive = !posix;
  // On Windows tolerate a forward slash in the incoming candidate by
  // normalising to the native separator before any comparison or split.
  const normalize = (value) => (posix ? value : value.replace(/\//g, "\\"));

  const normalizedCandidate = normalize(candidate);
  const normalizedWorkDir = normalize(workDir);

  const isAbsolute = posix
    ? normalizedCandidate.startsWith("/")
    : /^[A-Za-z]:\\/.test(normalizedCandidate);

  let relative;
  if (isAbsolute) {
    const foldedCandidate = insensitive ? normalizedCandidate.toLowerCase() : normalizedCandidate;
    const foldedWorkDir = insensitive ? normalizedWorkDir.toLowerCase() : normalizedWorkDir;
    if (foldedCandidate === foldedWorkDir) return [];
    const prefix = foldedWorkDir.endsWith(sep) ? foldedWorkDir : foldedWorkDir + sep;
    if (!foldedCandidate.startsWith(prefix)) {
      refuse("WORKSPACE_ROOT_ESCAPE", "absolute candidate is outside the workspace root");
    }
    relative = normalizedCandidate.slice(prefix.length);
  } else {
    relative = normalizedCandidate;
  }

  const parts = relative.split(sep).filter((part) => part.length > 0);
  for (const part of parts) {
    if (part === "." || part === "..") {
      refuse("WORKSPACE_ROOT_ESCAPE", "candidate contains a relative traversal segment");
    }
  }
  return parts;
}

const isNoFollowRefusal = (error) =>
  error?.code === "ERR_NATIVE_CONTROL_OPEN" ||
  error?.code === "ERR_NATIVE_CONTROL_REFUSED" ||
  typeof error?.reason === "string";

export function createWorkspaceContainment({ lowLevel, platform = process.platform } = {}) {
  if (lowLevel === null || typeof lowLevel !== "object") {
    throw new TypeError("createWorkspaceContainment requires a lowLevel native capability object");
  }
  for (const name of REQUIRED_CAPABILITIES) {
    if (typeof lowLevel[name] !== "function") {
      throw new TypeError(`lowLevel is missing required capability: ${name}`);
    }
  }

  function assertSupported(sourcePlatform) {
    if (!SUPPORTED_PLATFORMS.has(sourcePlatform)) {
      refuse(
        "CONTAINMENT_UNSUPPORTED",
        sourcePlatform === "windows-unc"
          ? "windows-unc workspace roots are not containment-verifiable"
          : `unsupported source platform: ${String(sourcePlatform)}`,
      );
    }
  }

  async function identifyRoot({ workDir, sourcePlatform } = {}) {
    assertSupported(sourcePlatform);
    if (!validWorkDir(workDir, sourcePlatform)) {
      refuse("WORKSPACE_ROOT_ESCAPE", "workDir is not a fully qualified canonical path for its platform");
    }

    let facts;
    try {
      facts = await lowLevel.read_workspace_root_facts(workDir, sourcePlatform);
    } catch (error) {
      refuse(
        "WORKSPACE_ROOT_UNIDENTIFIABLE",
        `native root facts refused: ${error?.reason ?? error?.code ?? "unknown"}`,
      );
    }

    if (
      facts === null || typeof facts !== "object" ||
      facts.sourcePlatform !== sourcePlatform || facts.workDir !== workDir ||
      !validRootIdentity(facts.rootIdentity, sourcePlatform) ||
      !validStorageIdentity(facts.storageIdentity, sourcePlatform)
    ) {
      refuse("WORKSPACE_ROOT_UNIDENTIFIABLE", "native root facts are malformed");
    }

    return Object.freeze({
      rootIdentity: Object.freeze({ ...facts.rootIdentity }),
      storageIdentity: Object.freeze({ ...facts.storageIdentity }),
    });
  }

  async function verifyContained({ workDir, sourcePlatform, candidate, expectedRootIdentity = null } = {}) {
    assertSupported(sourcePlatform);
    if (!validWorkDir(workDir, sourcePlatform)) {
      refuse("WORKSPACE_ROOT_ESCAPE", "workDir is not a fully qualified canonical path for its platform");
    }

    // Cheap lexical containment guard runs before any filesystem access so a
    // clear escape never touches the filesystem.
    const components = relativeComponents(workDir, candidate, sourcePlatform);

    // Canonical reparse-free proof of the root itself (throws inside identifyRoot
    // if any root component is a reparse point). Doubles as the swap-detection
    // anchor when the caller supplies an expected identity.
    const { rootIdentity } = await identifyRoot({ workDir, sourcePlatform });
    if (expectedRootIdentity !== null && !sameIdentity(rootIdentity, expectedRootIdentity)) {
      refuse("WORKSPACE_ROOT_UNIDENTIFIABLE", "workspace root identity does not match the expected identity");
    }

    // Shallow-to-deep no-follow prefix walk. A reparse point at component k is
    // caught at prefix k, before the walk would descend through it.
    const sep = separatorFor(sourcePlatform);
    let prefix = workDir;
    for (const component of components) {
      prefix = `${prefix}${sep}${component}`;
      let exists;
      try {
        exists = await lowLevel.path_exists_no_follow(prefix);
      } catch (error) {
        if (isNoFollowRefusal(error)) {
          refuse(
            "REPARSE_POINT_REJECTED",
            `candidate component "${component}" cannot be resolved without following a reparse point`,
          );
        }
        refuse("REPARSE_POINT_REJECTED", `candidate component "${component}" could not be verified`);
      }
      if (exists !== true) {
        refuse("CANDIDATE_NOT_FOUND", `candidate component "${component}" does not exist`);
      }
    }

    // Leaf identity of the fully verified path (the root itself when no relative
    // components remain).
    const leafPath = components.length === 0 ? workDir : prefix;
    let identity;
    try {
      identity = await lowLevel.read_identity(leafPath);
    } catch (error) {
      if (isNoFollowRefusal(error)) {
        refuse("REPARSE_POINT_REJECTED", "candidate leaf cannot be read without following a reparse point");
      }
      // Fail closed; fold the native code into the reason so an unexpected
      // condition (EACCES/EIO) is diagnosable rather than silently ENOENT-like.
      refuse("CANDIDATE_NOT_FOUND", `candidate leaf identity is unavailable: ${error?.code ?? "unknown"}`);
    }
    if (identity === null || typeof identity !== "object" || Array.isArray(identity) ||
        Object.keys(identity).length === 0) {
      refuse("CANDIDATE_NOT_FOUND", "candidate leaf identity is empty or malformed");
    }

    return Object.freeze({
      identity: Object.freeze({ ...identity }),
      rootIdentity,
    });
  }

  return Object.freeze({ identifyRoot, verifyContained });
}
