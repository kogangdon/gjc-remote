import { posix } from "node:path";

const WINDOWS_DRIVE_ROOT = /^[A-Za-z]:[\\/]/;
const WINDOWS_UNC_PATH = /^[\\/]{2}[^\\/]+[\\/][^\\/]+(?:[\\/].*)?$/;

function isNormalizedWorkDir(workDir) {
  return typeof workDir === "string" && workDir.length > 0 && workDir.trim() === workDir;
}

function isFullyQualifiedWindowsWorkDir(workDir) {
  return WINDOWS_DRIVE_ROOT.test(workDir) || WINDOWS_UNC_PATH.test(workDir);
}

function hasDotSegment(workDir) {
  return workDir
    .split(/[\\/]+/)
    .some((segment) => segment === "." || segment === "..");
}

export function isFullyQualifiedRouteWorkDir(workDir) {
  return (
    isNormalizedWorkDir(workDir) &&
    !hasDotSegment(workDir) &&
    (posix.isAbsolute(workDir) || isFullyQualifiedWindowsWorkDir(workDir))
  );
}

export function isFullyQualifiedNativeWorkDir(workDir, platform = process.platform) {
  if (!isNormalizedWorkDir(workDir)) return false;
  return platform === "win32" ? isFullyQualifiedWindowsWorkDir(workDir) : posix.isAbsolute(workDir);
}
