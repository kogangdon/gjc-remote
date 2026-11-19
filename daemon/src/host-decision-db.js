import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
} from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const require = createRequire(import.meta.url);
const DATABASE_NAME = "gjc-lifecycle.sqlite3";
const APPLICATION_ID = 0x474a4344; // GJCD
const SCHEMA_VERSION = 1;
const MAX_KEY_BYTES = 256;
const SCHEMA_SQL = `CREATE TABLE host_decisions (
  scope_id TEXT NOT NULL CHECK (
    length(CAST(scope_id AS BLOB)) BETWEEN 1 AND 256
    AND instr(scope_id, char(0)) = 0
  ),
  decision_key TEXT NOT NULL CHECK (
    length(CAST(decision_key AS BLOB)) BETWEEN 1 AND 256
    AND instr(decision_key, char(0)) = 0
  ),
  allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
  PRIMARY KEY (scope_id, decision_key)
) STRICT, WITHOUT ROWID`;

function invalidDatabase(reason) {
  const error = new Error(`host decision database refused: ${reason}`);
  error.code = "HOST_DECISION_DB_INVALID";
  return error;
}

function inspectFile(path) {
  let stats;
  try {
    stats = lstatSync(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
    throw invalidDatabase("database and sidecars must be single-link regular files");
  }
  return stats;
}

function reserveDatabase(directory) {
  const path = join(directory, DATABASE_NAME);
  // Reserve case aliases too: Windows opens SQLite sidecars case-insensitively.
  const sidecars = readdirSync(directory)
    .filter((name) => name.toLowerCase().startsWith(`${DATABASE_NAME}-`));
  for (const name of sidecars) inspectFile(join(directory, name));
  const stats = inspectFile(path);
  if (!stats && sidecars.length !== 0) {
    throw invalidDatabase("orphaned SQLite sidecar without its main database");
  }
  if (sidecars.some((name) => name.toLowerCase() !== `${DATABASE_NAME}-journal`)) {
    throw invalidDatabase("unexpected sidecar for a DELETE-journal database");
  }
  if (stats?.size === 0) throw invalidDatabase("existing database is empty");

  // The caller's protected directory and retained host lock exclude pathname
  // replacement. Reserve a new name exclusively; never truncate or reset it,
  // including after interrupted initialization.
  const fd = stats
    ? openSync(path, constants.O_RDWR | (constants.O_NOFOLLOW ?? 0))
    : openSync(path, "wx", 0o600);
  try {
    const opened = fstatSync(fd);
    if (
      !opened.isFile() || opened.nlink !== 1 ||
      (stats && (stats.dev !== opened.dev || stats.ino !== opened.ino))
    ) {
      throw invalidDatabase("database identity changed before open");
    }
  } finally {
    // Do not retain an extra descriptor: closing it while SQLite has an active
    // POSIX record lock could release that connection's locks.
    closeSync(fd);
  }
  return { path, created: stats === null };
}

function openSqlite(path) {
  // Select the actual runtime's built-in driver, not an error-based fallback.
  // Neither driver nor a database is opened during module import.
  if (process.versions.bun) {
    const { Database } = require("bun:sqlite");
    const database = new Database(path, {
      readwrite: true,
      create: false,
      strict: true,
    });
    return {
      prepare: (sql) => database.query(sql),
      exec: (sql) => database.run(sql),
      close: () => {
        // All SQL is static. Finalize every cached statement, including the
        // schema checks on a partially initialized connection, before close.
        database.clearQueryCache();
        database.close(true);
      },
    };
  }
  const { DatabaseSync } = require("node:sqlite");
  const database = new DatabaseSync(path);
  return {
    prepare: (sql) => database.prepare(sql),
    exec: (sql) => database.exec(sql),
    close: () => database.close(),
  };
}

function transaction(driver, action, mode = "IMMEDIATE") {
  driver.exec(`BEGIN ${mode}`);
  try {
    action();
    driver.exec("COMMIT");
  } catch (error) {
    try {
      driver.exec("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], "host decision database rollback failed");
    }
    throw error;
  }
}

function validateDatabase(database) {
  if (
    database.prepare("PRAGMA application_id").get().application_id !== APPLICATION_ID ||
    database.prepare("PRAGMA user_version").get().user_version !== SCHEMA_VERSION
  ) {
    throw invalidDatabase("application identity or schema version mismatch");
  }
  const schema = database.prepare("SELECT type, name, tbl_name, sql FROM main.sqlite_schema").all();
  if (
    schema.length !== 1 || schema[0].type !== "table" ||
    schema[0].name !== "host_decisions" || schema[0].tbl_name !== "host_decisions" ||
    schema[0].sql !== SCHEMA_SQL
  ) {
    throw invalidDatabase("schema does not match the exact supported schema");
  }
  const integrity = database.prepare("PRAGMA quick_check").all();
  if (integrity.length !== 1 || integrity[0].quick_check !== "ok") {
    throw invalidDatabase("database integrity check failed");
  }
}

function validateKey(value, name) {
  if (
    typeof value !== "string" || value.length === 0 ||
    value.length > MAX_KEY_BYTES || value.includes("\0") || !value.isWellFormed() ||
    Buffer.byteLength(value, "utf8") > MAX_KEY_BYTES
  ) {
    throw new TypeError(`${name} must be 1-${MAX_KEY_BYTES} UTF-8 bytes without NUL or malformed Unicode`);
  }
}

/**
 * Open the fixed host DB synchronously, after the caller has verified the
 * protected directory and acquired the process-lifetime host lock. The caller
 * must retain that lock until after close(). This module neither provisions
 * directories nor proves enrollment, authorization, or rollback freshness.
 * setDecision is an internal, authorized-management-only API, not a session or
 * transport capability; the integrating management owner enforces that boundary.
 */
export function openHostDecisionDb(directory) {
  if (typeof directory !== "string" || directory.length === 0 || directory.includes("\0")) {
    throw new TypeError("host decision database requires a non-empty directory path");
  }
  const { path, created } = reserveDatabase(directory);
  const driver = openSqlite(path);
  const database = driver;
  try {
    driver.exec("PRAGMA trusted_schema = OFF; PRAGMA synchronous = EXTRA; PRAGMA locking_mode = NORMAL");
    if (created) {
      if (database.prepare("PRAGMA journal_mode = DELETE").get().journal_mode !== "delete") {
        throw invalidDatabase("DELETE journal mode unavailable");
      }
      transaction(driver, () => {
        driver.exec(`${SCHEMA_SQL}; PRAGMA application_id = ${APPLICATION_ID}; PRAGMA user_version = ${SCHEMA_VERSION}`);
        validateDatabase(database);
      });
    } else {
      // Reads allow SQLite itself to recover a regular hot rollback journal.
      // Never CREATE TABLE (or repair/reset anything) on an existing database.
      transaction(driver, () => validateDatabase(database), "DEFERRED");
    }
    if (
      database.prepare("PRAGMA journal_mode").get().journal_mode !== "delete" ||
      database.prepare("PRAGMA synchronous").get().synchronous !== 3
    ) {
      throw invalidDatabase("DELETE journaling and EXTRA synchronization are required");
    }

    const read = database.prepare("SELECT allowed FROM host_decisions WHERE scope_id = ? AND decision_key = ?");
    const write = database.prepare(`INSERT INTO host_decisions (scope_id, decision_key, allowed)
      VALUES (?, ?, ?) ON CONFLICT (scope_id, decision_key) DO UPDATE SET allowed = excluded.allowed`);
    let closed = false;
    function assertOpen() {
      if (closed) throw new Error("host decision database is closed");
    }
    return Object.freeze({
      close() {
        if (closed) return;
        driver.close();
        closed = true;
      },
      readDecision(scopeId, decisionKey) {
        assertOpen();
        validateKey(scopeId, "scopeId");
        validateKey(decisionKey, "decisionKey");
        const row = read.get(scopeId, decisionKey);
        if (row === undefined || row === null) return null;
        if (row.allowed !== 0 && row.allowed !== 1) {
          throw invalidDatabase("stored decision is not boolean");
        }
        return row.allowed === 1;
      },
      setDecision(scopeId, decisionKey, allowed) {
        assertOpen();
        validateKey(scopeId, "scopeId");
        validateKey(decisionKey, "decisionKey");
        if (typeof allowed !== "boolean") throw new TypeError("allowed must be boolean");
        transaction(driver, () => write.run(scopeId, decisionKey, allowed ? 1 : 0));
      },
    });
  } catch (error) {
    try {
      driver.close();
    } catch (closeError) {
      throw new AggregateError([error, closeError], "host decision database open and cleanup failed");
    }
    throw error;
  }
}
