import { constants as FS_CONSTANTS } from "node:fs";
import {
  open as fsOpen,
  readlink as fsReadlink,
  realpath as fsRealpath,
} from "node:fs/promises";
import { posix } from "node:path";

import { relativeComponents } from "./workspace-containment.js";

const MAX_FILE_BYTES = 16 * 1024 * 1024;
const ROOT_FLAGS =
  FS_CONSTANTS.O_RDONLY |
  FS_CONSTANTS.O_DIRECTORY |
  FS_CONSTANTS.O_NOFOLLOW;
const FILE_FLAGS = FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW;

function refuse(code, reason) {
  const error = new Error(`linux retained byte reader refused: ${reason}`);
  error.code = code;
  error.reason = reason;
  throw error;
}

function procPath(handle, component = null) {
  const root = `/proc/self/fd/${handle.fd}`;
  return component === null ? root : `${root}/${component}`;
}

export async function createLinuxRetainedByteReader({
  root,
  open = fsOpen,
  readlink = fsReadlink,
  realpath = fsRealpath,
  runtimePlatform = process.platform,
} = {}) {
  if (runtimePlatform !== "linux") {
    refuse("CONTAINMENT_UNSUPPORTED", "retained byte reading requires Linux");
  }
  if (typeof root !== "string" || root.length === 0 ||
      typeof open !== "function" || typeof readlink !== "function" ||
      typeof realpath !== "function") {
    refuse("CONFIG_INVALID", "root and filesystem capabilities are required");
  }
  const expectedRoot = posix.resolve(root);
  const canonicalRoot = await realpath(root);
  if (canonicalRoot !== expectedRoot) {
    refuse("WORKSPACE_ROOT_ESCAPE", "reader root contains a symbolic indirection");
  }
  const rootHandle = await open(root, ROOT_FLAGS);
  let closed = false;
  try {
    const retainedPath = await readlink(procPath(rootHandle));
    if (retainedPath !== expectedRoot) {
      refuse("WORKSPACE_ROOT_ESCAPE", "retained reader root identity is ambiguous");
    }
  } catch (error) {
    await rootHandle.close();
    throw error;
  }

  async function readBytes(relativePath) {
    if (closed) refuse("CONFIG_INVALID", "retained reader is closed");
    const components = relativeComponents(
      expectedRoot,
      `${expectedRoot}/${relativePath}`,
      "posix"
    );
    if (components.length === 0) {
      refuse("WORKSPACE_ROOT_ESCAPE", "relative path must name a file");
    }
    let parent = rootHandle;
    const openedDirectories = [];
    let file = null;
    try {
      for (const component of components.slice(0, -1)) {
        const next = await open(procPath(parent, component), ROOT_FLAGS);
        openedDirectories.push(next);
        parent = next;
      }
      file = await open(procPath(parent, components.at(-1)), FILE_FLAGS);
      const before = await file.stat();
      if (!before.isFile() || before.size < 0 || before.size > MAX_FILE_BYTES) {
        refuse("WORKSPACE_MANIFEST_READ_FAILED", "retained object is not a bounded regular file");
      }
      const bytes = await file.readFile();
      const after = await file.stat();
      if (after.dev !== before.dev || after.ino !== before.ino ||
          after.size !== before.size || bytes.byteLength !== before.size) {
        refuse("WORKSPACE_MANIFEST_READ_FAILED", "retained file identity changed while reading");
      }
      return new Uint8Array(bytes);
    } finally {
      if (file) await file.close();
      for (const handle of openedDirectories.reverse()) await handle.close();
    }
  }

  async function close() {
    if (closed) return;
    closed = true;
    await rootHandle.close();
  }

  return Object.freeze({ readBytes, close });
}
