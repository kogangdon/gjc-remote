import { watch } from "node:fs";
import { basename, dirname } from "node:path";

export function watchConfigFile(filePath, onChange, options = {}) {
  const watchFn = options.watchFn ?? watch;
  const setTimeoutFn = options.setTimeoutFn ?? setTimeout;
  const clearTimeoutFn = options.clearTimeoutFn ?? clearTimeout;
  const delayMs = options.delayMs ?? 250;
  const onError =
    options.onError ??
    ((error) => {
      console.error(`Config watcher error for ${filePath}: ${error?.message ?? String(error)}`);
    });
  const directory = dirname(filePath);
  const target = basename(filePath);

  let closed = false;
  let timer = null;

  const watcher = watchFn(directory, { persistent: false }, (_eventType, filename) => {
    if (closed) return;
    if (filename != null && filename.toString() !== target) return;

    if (timer !== null) clearTimeoutFn(timer);
    timer = setTimeoutFn(() => {
      timer = null;
      if (!closed) onChange();
    }, delayMs);
  });

  if (typeof watcher.on === "function") {
    watcher.on("error", onError);
  }

  return {
    close() {
      if (closed) return;
      closed = true;
      if (timer !== null) {
        clearTimeoutFn(timer);
        timer = null;
      }
      watcher.close();
    },
  };
}
export function watchConfigHints(filePaths, onChange, options = {}) {
  const uniquePaths = [...new Set(filePaths)];
  const directoryPaths = [...new Set(options.directoryPaths ?? [])];
  const watchFn = options.watchFn ?? watch;
  const existsSyncFn = options.existsSyncFn;
  const setTimeoutFn = options.setTimeoutFn ?? setTimeout;
  const clearTimeoutFn = options.clearTimeoutFn ?? clearTimeout;
  const delayMs = options.delayMs ?? 250;
  const onError = options.onError ?? (() => {});
  const targetsByDirectory = new Map();
  for (const filePath of uniquePaths) {
    const directory = dirname(filePath);
    const targets = targetsByDirectory.get(directory) ?? new Set();
    targets.add(basename(filePath));
    targetsByDirectory.set(directory, targets);
  }
  for (const directoryPath of directoryPaths) {
    const parent = dirname(directoryPath);
    const targets = targetsByDirectory.get(parent) ?? new Set();
    targets.add(basename(directoryPath));
    targetsByDirectory.set(parent, targets);
  }

  let closed = false;
  let timer = null;
  const watchers = [];

  const schedule = () => {
    if (timer !== null) clearTimeoutFn(timer);
    timer = setTimeoutFn(() => {
      timer = null;
      refreshDirectoryWatchers();
      if (!closed) onChange();
    }, delayMs);
  };
  const addWatcher = (directory, targets = null) => {
    const watcher = watchFn(directory, { persistent: false }, (_eventType, filename) => {
      if (closed || (targets !== null && filename != null && !targets.has(filename.toString()))) return;
      refreshDirectoryWatchers();
      schedule();
    });
    if (typeof watcher.on === "function") watcher.on("error", onError);
    watchers.push(watcher);
  };
  const watchedDirectories = new Set();
  const refreshDirectoryWatchers = () => {
    if (typeof existsSyncFn !== "function") return;
    for (const directoryPath of directoryPaths) {
      if (!watchedDirectories.has(directoryPath) && existsSyncFn(directoryPath)) {
        watchedDirectories.add(directoryPath);
        addWatcher(directoryPath);
      }
    }
  };

  for (const [directory, targets] of targetsByDirectory) addWatcher(directory, targets);
  refreshDirectoryWatchers();

  return {
    close() {
      if (closed) return;
      closed = true;
      if (timer !== null) clearTimeoutFn(timer);
      for (const watcher of watchers) watcher.close();
    },
  };
}
