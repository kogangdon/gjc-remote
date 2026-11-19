import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { openHostDecisionDb } from "../src/host-decision-db.js";

const DATABASE_NAME = "gjc-lifecycle.sqlite3";
const MODULE_URL = new URL("../src/host-decision-db.js", import.meta.url).href;

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "gjc-host-decisions-"));
  const handles = [];
  t.after(() => {
    try {
      for (const db of handles) db.close();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
  return {
    directory,
    path: join(directory, DATABASE_NAME),
    open() {
      const db = openHostDecisionDb(directory);
      handles.push(db);
      return db;
    },
  };
}

function withSqlite(path, action) {
  const db = new DatabaseSync(path);
  try {
    return action(db);
  } finally {
    db.close();
  }
}

function snapshot(directory) {
  return readdirSync(directory).sort().map((name) => {
    const path = join(directory, name);
    const stats = lstatSync(path);
    return [name, stats.isFile() ? readFileSync(path) : stats.mode];
  });
}

function assertRefusedUnchanged(f, expected) {
  const before = snapshot(f.directory);
  assert.throws(() => f.open(), expected);
  assert.deepEqual(snapshot(f.directory), before, "refusal must preserve existing files and bytes");
}

function child(script, args = [], flags = [], executable = process.execPath) {
  return spawnSync(executable, [
    ...flags,
    "--input-type=module",
    "--eval",
    script,
    ...args,
  ], { encoding: "utf8", timeout: 30_000, windowsHide: true });
}

function assertChildSucceeded(result) {
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

test("committed allow and deny decisions survive real process restarts", (t) => {
  const f = fixture(t);
  assertChildSucceeded(child(`
    import { openHostDecisionDb } from ${JSON.stringify(MODULE_URL)};
    const db = openHostDecisionDb(process.argv[1]);
    db.setDecision("scope-a", "consent", true);
    db.setDecision("scope-a", "revoked", false);
    db.setDecision("scope-b", "consent", false);
    db.close();
  `, [f.directory]));

  const db = f.open();
  assert.equal(db.readDecision("scope-a", "consent"), true);
  assert.equal(db.readDecision("scope-a", "revoked"), false);
  assert.equal(db.readDecision("scope-b", "consent"), false);
  assert.equal(db.readDecision("missing", "consent"), null);
  assert.equal(db.readDecision("scope-a", "missing"), null);
  db.setDecision("scope-a", "consent", false);
  db.close();

  assertChildSucceeded(child(`
    import assert from "node:assert/strict";
    import { openHostDecisionDb } from ${JSON.stringify(MODULE_URL)};
    const db = openHostDecisionDb(process.argv[1]);
    assert.equal(db.readDecision("scope-a", "consent"), false);
    assert.equal(db.readDecision("scope-a", "revoked"), false);
    assert.equal(db.readDecision("scope-b", "consent"), false);
    db.close();
  `, [f.directory]));
  withSqlite(f.path, (raw) => {
    assert.equal(raw.prepare("SELECT count(*) AS count FROM host_decisions").get().count, 3);
  });
  assert.deepEqual(readdirSync(f.directory), [DATABASE_NAME]);
});

test("bootstrap creates versioned strict composite-key storage with SQL constraints", (t) => {
  const f = fixture(t);
  f.open().close();
  withSqlite(f.path, (raw) => {
    assert.equal(raw.prepare("PRAGMA application_id").get().application_id, 0x474a4344);
    assert.equal(raw.prepare("PRAGMA user_version").get().user_version, 1);
    const table = raw.prepare("PRAGMA table_list").all().find((row) => row.name === "host_decisions");
    assert.equal(table.strict, 1);
    assert.equal(table.wr, 1);
    const write = raw.prepare("INSERT INTO host_decisions (scope_id, decision_key, allowed) VALUES (?, ?, ?)");
    for (const args of [
      ["scope", "bad-boolean", 2],
      ["scope", "null-boolean", null],
      ["", "key", 1],
      ["scope", "", 1],
      ["scope", "é".repeat(129), 1],
      ["a".repeat(257), "key", 1],
      ["scope\0alias", "key", 1],
      ["scope", "key\0alias", 1],
    ]) {
      assert.throws(() => write.run(...args));
    }
    assert.equal(raw.prepare("SELECT count(*) AS count FROM host_decisions").get().count, 0);
    assert.equal(raw.prepare("PRAGMA journal_mode").get().journal_mode, "delete");
  });
});

test("both keys are parameterized and preserve opaque UTF-8 identities at their byte bounds", (t) => {
  const f = fixture(t);
  const db = f.open();
  const injection = "'; DROP TABLE host_decisions; --";
  const scope = "s".repeat(256);
  const key = "é".repeat(128);
  db.setDecision(injection, injection, true);
  db.setDecision(scope, key, false);
  assert.equal(db.readDecision(injection, injection), true);
  assert.equal(db.readDecision(scope, key), false);
  assert.equal(db.readDecision("é", "consent"), null);
  db.setDecision("é", "consent", true);
  assert.equal(db.readDecision("é", "consent"), null, "do not normalize distinct opaque keys");
  db.close();
  const reopened = f.open();
  assert.equal(reopened.readDecision(injection, injection), true);
  assert.equal(reopened.readDecision(scope, key), false);
});

test("invalid key types, empty/oversize keys, NUL and malformed Unicode throw rather than report missing", (t) => {
  const f = fixture(t);
  const db = f.open();
  const invalidKeys = [
    undefined, null, 0, false, {}, [], new String("key"), "",
    "a".repeat(257), "é".repeat(129), "a\0b",
    String.fromCharCode(0xd800), String.fromCharCode(0xdc00),
  ];
  for (const value of invalidKeys) {
    assert.throws(() => db.readDecision(value, "key"), TypeError);
    assert.throws(() => db.readDecision("scope", value), TypeError);
    assert.throws(() => db.setDecision(value, "key", true), TypeError);
    assert.throws(() => db.setDecision("scope", value, true), TypeError);
  }
  for (const value of [undefined, null, 0, 1, "true", "false", {}, [], NaN]) {
    assert.throws(() => db.setDecision("scope", "key", value), TypeError);
  }
  assert.equal(db.readDecision("scope", "key"), null);
});

test("close is idempotent and neither method operates on a closed connection", (t) => {
  const f = fixture(t);
  const db = f.open();
  db.close();
  db.close();
  assert.throws(() => db.readDecision("scope", "key"), /closed/);
  assert.throws(() => db.setDecision("scope", "key", true), /closed/);
  assert.equal(f.open().readDecision("scope", "key"), null);
});

test("directory validation never provisions a missing directory or an alternate database", (t) => {
  const f = fixture(t);
  for (const value of [undefined, null, {}, "", "bad\0directory"]) {
    assert.throws(() => openHostDecisionDb(value), TypeError);
  }
  const missing = join(f.directory, "not-provisioned");
  assert.throws(() => openHostDecisionDb(missing), { code: "ENOENT" });
  assert.equal(existsSync(missing), false);
  writeFileSync(join(f.directory, "not-a-directory"), "sentinel");
  assert.throws(() => openHostDecisionDb(join(f.directory, "not-a-directory")));
  assert.equal(readFileSync(join(f.directory, "not-a-directory"), "utf8"), "sentinel");
});

for (const [name, bytes] of [
  ["empty", Buffer.alloc(0)],
  ["non-SQLite", Buffer.from("not a database; preserve these bytes")],
  ["malformed", Buffer.alloc(8192, 0xff)],
]) {
  test(`existing ${name} main file fails closed without bootstrap/reset`, (t) => {
    const f = fixture(t);
    writeFileSync(f.path, bytes);
    assertRefusedUnchanged(f);
    assertRefusedUnchanged(f);
  });
}

test("a valid SQLite file with no schema is not treated as a new host database", (t) => {
  const f = fixture(t);
  withSqlite(f.path, (raw) => raw.exec("PRAGMA user_version = 1"));
  assertRefusedUnchanged(f, /identity|version/);
  withSqlite(f.path, (raw) => {
    assert.deepEqual(raw.prepare("SELECT name FROM sqlite_schema").all(), []);
  });
});

for (const [name, sql] of [
  ["missing table", "DROP TABLE host_decisions"],
  ["different version", "PRAGMA user_version = 2"],
  ["different application", "PRAGMA application_id = 1"],
  ["additional table", "CREATE TABLE unrelated (id INTEGER)"],
  ["additional column", "ALTER TABLE host_decisions ADD COLUMN unrelated TEXT"],
  ["additional index", "CREATE INDEX decision_allowed ON host_decisions (allowed)"],
  ["additional view", "CREATE VIEW decision_view AS SELECT * FROM host_decisions"],
  ["additional trigger", `CREATE TRIGGER decision_trigger AFTER INSERT ON host_decisions
    BEGIN DELETE FROM host_decisions; END`],
  ["weakened constraints", `DROP TABLE host_decisions;
    CREATE TABLE host_decisions (scope_id TEXT, decision_key TEXT, allowed INTEGER,
      PRIMARY KEY (scope_id, decision_key)) STRICT, WITHOUT ROWID`],
]) {
  test(`${name} is refused without repairing the existing database`, (t) => {
    const f = fixture(t);
    const db = f.open();
    db.setDecision("scope", "key", true);
    db.close();
    withSqlite(f.path, (raw) => raw.exec(sql));
    assertRefusedUnchanged(f, /schema|identity|version/);
  });
}

test("integrity failures in a real database are not mistaken for missing decisions", (t) => {
  const f = fixture(t);
  f.open().close();
  withSqlite(f.path, (raw) => {
    raw.exec("PRAGMA ignore_check_constraints = ON");
    raw.prepare("INSERT INTO host_decisions VALUES (?, ?, ?)").run("scope", "key", 2);
  });
  assertRefusedUnchanged(f, /integrity/);
});

test("a corrupted data b-tree fails validation even when its schema is intact", (t) => {
  const f = fixture(t);
  f.open().close();
  const { pageSize, rootPage } = withSqlite(f.path, (raw) => ({
    pageSize: raw.prepare("PRAGMA page_size").get().page_size,
    rootPage: raw.prepare("SELECT rootpage FROM sqlite_schema WHERE name = 'host_decisions'").get().rootpage,
  }));
  const bytes = readFileSync(f.path);
  bytes[(rootPage - 1) * pageSize] = 0xff;
  writeFileSync(f.path, bytes);
  assertRefusedUnchanged(f);
});

for (const suffix of ["-journal", "-wal", "-shm", "-mj012345678", "-JOURNAL", "-WAL", "-SHM"]) {
  test(`orphan ${suffix} prevents bootstrap and is preserved`, (t) => {
    const f = fixture(t);
    writeFileSync(`${f.path}${suffix}`, "orphan must not be removed");
    assertRefusedUnchanged(f, /orphan/);
    assert.equal(existsSync(f.path), false);
  });
}

for (const suffix of ["-wal", "-shm", "-mj012345678", "-WAL", "-SHM"]) {
  test(`unexpected ${suffix} beside an existing DB is not deleted or adopted`, (t) => {
    const f = fixture(t);
    f.open().close();
    writeFileSync(`${f.path}${suffix}`, "preserve sidecar");
    assertRefusedUnchanged(f, /sidecar/);
  });
}

for (const suffix of ["", "-journal", "-wal", "-shm"]) {
  test(`nonregular ${suffix || "main"} path is refused before SQLite opens it`, (t) => {
    const f = fixture(t);
    if (suffix) f.open().close();
    mkdirSync(`${f.path}${suffix}`);
    assertRefusedUnchanged(f, /regular files/);
  });

  test(`linked ${suffix || "main"} path is refused without changing its target`, (t) => {
    const f = fixture(t);
    if (suffix) f.open().close();
    const target = join(f.directory, "link-target");
    mkdirSync(target);
    writeFileSync(join(target, "sentinel"), "preserve target");
    symlinkSync(target, `${f.path}${suffix}`, process.platform === "win32" ? "junction" : "dir");
    assertRefusedUnchanged(f, /regular files/);
    assert.equal(readFileSync(join(target, "sentinel"), "utf8"), "preserve target");
  });

  test(`hard-linked ${suffix || "main"} path is refused`, (t) => {
    const f = fixture(t);
    if (suffix) f.open().close();
    const target = join(f.directory, "hard-link-target");
    writeFileSync(target, "preserve hard-linked target");
    linkSync(target, `${f.path}${suffix}`);
    assertRefusedUnchanged(f, /regular files/);
  });
}

test("denied filesystem access is surfaced rather than replaced with an in-memory or new database", (t) => {
  const f = fixture(t);
  const db = f.open();
  db.setDecision("scope", "key", true);
  db.close();
  const before = snapshot(f.directory);
  assertChildSucceeded(child(`
    import assert from "node:assert/strict";
    import { openHostDecisionDb } from ${JSON.stringify(MODULE_URL)};
    assert.equal(process.versions.bun, undefined, "permission probe requires real Node");
    assert.throws(() => openHostDecisionDb(process.argv[1]), { code: "ERR_ACCESS_DENIED" });
  `, [f.directory], ["--permission", "--allow-fs-read=*"], process.versions.bun ? "node" : process.execPath));
  assert.deepEqual(snapshot(f.directory), before);
  assert.equal(f.open().readDecision("scope", "key"), true);
});

test("write contention fails without changing decisions and does not retain a lifetime database lock", (t) => {
  const f = fixture(t);
  const db = f.open();
  db.setDecision("scope", "key", true);
  withSqlite(f.path, (raw) => {
    raw.exec("BEGIN IMMEDIATE");
    try {
      assert.throws(() => db.setDecision("scope", "key", false), /locked|busy/i);
      assert.equal(db.readDecision("scope", "key"), true);
    } finally {
      raw.exec("ROLLBACK");
    }
  });
  db.setDecision("scope", "key", false);
  assert.equal(db.readDecision("scope", "key"), false);
});

test("an aborted management write rolls back its short transaction and permits a later write", (t) => {
  const f = fixture(t);
  const db = f.open();
  db.setDecision("scope", "key", true);
  withSqlite(f.path, (raw) => {
    raw.exec(`CREATE TRIGGER abort_write BEFORE UPDATE ON host_decisions
      BEGIN SELECT RAISE(ABORT, 'injected write failure'); END`);
    assert.throws(() => db.setDecision("scope", "key", false), /injected write failure/);
    assert.equal(db.readDecision("scope", "key"), true);
    raw.exec("DROP TRIGGER abort_write");
  });
  db.setDecision("scope", "key", false);
  db.close();
  assert.equal(f.open().readDecision("scope", "key"), false);
});

test("read errors and invalid stored booleans throw, never return null or truthy coercions", (t) => {
  const f = fixture(t);
  const db = f.open();
  db.setDecision("scope", "key", true);
  withSqlite(f.path, (raw) => {
    raw.exec("PRAGMA ignore_check_constraints = ON; UPDATE host_decisions SET allowed = 2");
    assert.throws(() => db.readDecision("scope", "key"), /not boolean/);
    raw.exec("DROP TABLE host_decisions");
  });
  assert.throws(() => db.readDecision("scope", "key"), /no such table/);
  assert.throws(() => db.setDecision("scope", "key", false), /no such table/);
});

test("SQLite recovers an actual hot DELETE journal after a writer is killed", (t) => {
  const f = fixture(t);
  const db = f.open();
  db.setDecision("scope", "consent", true);
  db.close();
  withSqlite(f.path, (raw) => {
    raw.exec("BEGIN IMMEDIATE");
    const insert = raw.prepare("INSERT INTO host_decisions VALUES (?, ?, ?)");
    for (let index = 0; index < 512; index += 1) {
      insert.run("s".repeat(256), `seed-${index}-${"k".repeat(200)}`, 1);
    }
    raw.exec("COMMIT");
  });
  const killed = child(`
    import { DatabaseSync } from "node:sqlite";
    const db = new DatabaseSync(process.argv[1]);
    db.exec("PRAGMA journal_mode = DELETE; PRAGMA synchronous = EXTRA; PRAGMA cache_size = 1; PRAGMA cache_spill = ON");
    db.exec("BEGIN IMMEDIATE; UPDATE host_decisions SET allowed = 0");
    process.kill(process.pid, "SIGKILL");
  `, [f.path]);
  assert.ifError(killed.error);
  assert.notEqual(killed.status, 0, "writer must exit without commit or cleanup");
  const journal = readFileSync(`${f.path}-journal`);
  assert.ok(journal.length > 512, "a real rollback journal must reach disk");
  assert.equal(journal.subarray(0, 8).toString("hex"), "d9d505f920a163d7");
  const recovered = f.open();
  assert.equal(recovered.readDecision("scope", "consent"), true);
  for (const index of [0, 511]) {
    assert.equal(recovered.readDecision("s".repeat(256), `seed-${index}-${"k".repeat(200)}`), true);
  }
  assert.equal(existsSync(`${f.path}-journal`), false);
  recovered.setDecision("scope", "consent", false);
  recovered.close();
  assert.equal(f.open().readDecision("scope", "consent"), false);
});
