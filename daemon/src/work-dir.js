import { isFullyQualifiedNativeWorkDir } from "@gjc-remote/shared/work-dir.js";

export function isFullyQualifiedWorkDir(workDir, platform = process.platform) {
  return isFullyQualifiedNativeWorkDir(workDir, platform);
}

export function validateNativeWorkDir(workDir, platform = process.platform) {
  if (!isFullyQualifiedWorkDir(workDir, platform)) {
    throw new TypeError("workDir must be a fully qualified native path");
  }

  return workDir;
}
