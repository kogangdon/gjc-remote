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
