import { posix } from "node:path";

const WINDOWS_DRIVE_ROOT = /^[A-Za-z]:[\\/]/;
const WINDOWS_UNC_PATH = /^[\\/]{2}[^\\/]+[\\/][^\\/]+(?:[\\/].*)?$/;

export function isFullyQualifiedWorkDir(workDir, platform = process.platform) {
  if (typeof workDir !== "string" || workDir.length === 0 || workDir.trim() !== workDir) {
    return false;
  }

  if (platform === "win32") {
    return WINDOWS_DRIVE_ROOT.test(workDir) || WINDOWS_UNC_PATH.test(workDir);
  }

  return posix.isAbsolute(workDir);
}

export function validateNativeWorkDir(workDir, platform = process.platform) {
  if (!isFullyQualifiedWorkDir(workDir, platform)) {
    throw new TypeError("workDir must be a fully qualified native path");
  }

  return workDir;
}
