import { closeSync, lstatSync, openSync } from "node:fs";
import { createRequire } from "node:module";
import { isAbsolute, join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const isBun = Boolean(process.versions.bun);
const LOCK_FILE = "gjc-lifecycle.lock";
const messages = {
  HOST_OWNER_LOCK_BUSY: "The host lifecycle owner lock is already held.",
  HOST_OWNER_LOCK_INVALID: "The host lifecycle owner lock path is unsafe or invalid.",
  HOST_OWNER_LOCK_FAILED: "The host lifecycle owner lock operation failed.",
};

function failure(code, cause) {
  const error = new Error(messages[code], cause === undefined ? undefined : { cause });
  error.code = code;
  return error;
}

function inspectFile(file) {
  let stat;
  try {
    stat = lstatSync(file, { bigint: true });
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) {
    throw failure("HOST_OWNER_LOCK_INVALID");
  }
  return stat;
}

function inspectFiles(file) {
  const main = inspectFile(file);
  const journal = inspectFile(`${file}-journal`);
  if ((journal && !main) || inspectFile(`${file}-wal`) || inspectFile(`${file}-shm`)) {
    throw failure("HOST_OWNER_LOCK_INVALID");
  }
  return main;
}

function sameFile(left, right) {
  return left && right && left.dev === right.dev && left.ino === right.ino;
}

function openDatabase(file) {
  return isBun
    ? new (require("bun:sqlite").Database)(file, { create: false, strict: true })
    : new (require("node:sqlite").DatabaseSync)(file, { timeout: 0 });
}

function closeDatabase(database) {
  if (isBun) database.close(true);
  else database.close();
}

function pragma(database, sql, column) {
  const statement = database.prepare(sql);
  try {
    return statement.get()[column];
  } finally {
    if (isBun) statement.finalize();
  }
}

function isContention(error) {
  const code = error?.errcode ?? error?.errno;
  return (typeof code === "number" && [5, 6].includes(code & 0xff)) ||
    /^SQLITE_(?:BUSY|LOCKED)(?:_|$)/.test(error?.code ?? "");
}

/**
 * Acquire a lock-only SQLite file, never the decision database. The caller must
 * supply an existing trusted, local directory whose ancestors and entries cannot
 * be replaced by untrusted writers. Leaf checks cannot make SQLite's path-based
 * open race-free, and network filesystems are not supported locking evidence.
 * On POSIX, nothing else in this process may independently open/close the lock
 * file while it is held: that can drop SQLite's process-scoped byte locks.
 */
export function acquireHostOwnerLock(directory) {
  let database;
  try {
    if (typeof directory !== "string" || !isAbsolute(directory) || directory.includes("\0")) {
      throw failure("HOST_OWNER_LOCK_INVALID");
    }
    const root = resolve(directory);
    const directoryStat = lstatSync(root);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      throw failure("HOST_OWNER_LOCK_INVALID");
    }

    const file = join(root, LOCK_FILE);
    const original = inspectFiles(file);
    if (!original) {
      try {
        // Never open/close an existing file outside SQLite: on POSIX, closing
        // such a descriptor could release this process's SQLite byte locks.
        const fd = openSync(file, "wx", 0o600);
        closeSync(fd);
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
    }
    const expected = inspectFiles(file);
    if (!expected || (original && !sameFile(original, expected))) {
      throw failure("HOST_OWNER_LOCK_INVALID");
    }

    database = openDatabase(file);
    database.exec("PRAGMA busy_timeout = 0;");
    if (pragma(database, "PRAGMA locking_mode = EXCLUSIVE;", "locking_mode") !== "exclusive" ||
        pragma(database, "PRAGMA journal_mode = DELETE;", "journal_mode") !== "delete") {
      throw failure("HOST_OWNER_LOCK_INVALID");
    }
    // Initialize a real SQLite header even on first acquisition. EXCLUSIVE
    // locking mode retains the OS lock across this metadata-only commit; the
    // final exclusive transaction remains open for the returned handle's life.
    database.exec("BEGIN EXCLUSIVE; PRAGMA user_version = 1; COMMIT; BEGIN EXCLUSIVE;");
    if (!sameFile(expected, inspectFiles(file))) {
      throw failure("HOST_OWNER_LOCK_INVALID");
    }
  } catch (error) {
    if (database) {
      try {
        closeDatabase(database);
      } catch (closeError) {
        throw failure("HOST_OWNER_LOCK_FAILED", new AggregateError([error, closeError]));
      }
    }
    if (Object.hasOwn(messages, error?.code)) throw error;
    throw failure(isContention(error) ? "HOST_OWNER_LOCK_BUSY" : "HOST_OWNER_LOCK_FAILED", error);
  }

  let closed = false;
  return Object.freeze({
    close() {
      if (closed) return;
      closed = true;
      try {
        closeDatabase(database);
      } catch (error) {
        throw failure("HOST_OWNER_LOCK_FAILED", error);
      }
    },
  });
}
