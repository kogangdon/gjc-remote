import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import test from "node:test";
import { acquireHostOwnerLock } from "../src/host-owner-lock.js";

const require = createRequire(import.meta.url);
const moduleUrl = new URL("../src/host-owner-lock.js", import.meta.url).href;
const LOCK_FILE = "gjc-lifecycle.lock";
const TIMEOUT_MS = 10_000;
const nodeExecutable = process.versions.bun ? "node" : process.execPath;
const bunExecutable = process.env.BUN_BIN || (process.versions.bun ? process.execPath : "bun");
const workerSource = `
  (async () => {
    const [moduleUrl, directory, mode] = process.argv.slice(-3);
    const { acquireHostOwnerLock } = await import(moduleUrl);
    const started = performance.now();
    try {
      const lock = acquireHostOwnerLock(directory);
      if (mode === "probe") {
        lock.close();
        console.log(JSON.stringify({ acquired: true }));
        return;
      }
      console.log(JSON.stringify({ acquired: true, pid: process.pid }));
      process.stdin.resume();
      process.stdin.once("data", () => {
        lock.close();
        lock.close();
        process.stdin.pause();
      });
    } catch (error) {
      console.log(JSON.stringify({
        acquired: false,
        code: error.code,
        elapsedMs: performance.now() - started,
      }));
      process.exitCode = error.code === "HOST_OWNER_LOCK_BUSY" ? 23 : 1;
    }
  })().catch((error) => { console.error(error); process.exitCode = 1; });
`;

function bounded(promise, description) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Timed out: ${description}`)), TIMEOUT_MS);
    }),
  ]).finally(() => clearTimeout(timer));
}

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "gjc-host-owner-lock-"));
  chmodSync(directory, 0o700);
  const workers = [];
  const locks = [];
  t.after(async () => {
    for (const lock of locks) lock.close();
    for (const worker of workers) {
      if (worker.child.pid && worker.child.exitCode === null && worker.child.signalCode === null) {
        worker.child.kill("SIGKILL");
      }
      await bounded(worker.exited, "worker cleanup");
    }
    rmSync(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 10 });
  });
  return { directory, workers, locks, file: join(directory, LOCK_FILE) };
}

function worker(f, mode, executable = process.execPath) {
  const child = spawn(executable, ["--eval", workerSource, moduleUrl, f.directory, mode], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exited = new Promise((resolve) => {
    child.once("error", (error) => resolve({ error }));
    child.once("close", (code, signal) => resolve({ code, signal, stderr }));
  });
  const message = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      const newline = stdout.indexOf("\n");
      if (newline < 0) return;
      try {
        resolve(JSON.parse(stdout.slice(0, newline)));
      } catch (error) {
        reject(error);
      }
    });
    child.once("close", (code, signal) => {
      reject(new Error(`Worker exited without a message (${code}, ${signal}): ${stderr}`));
    });
  });
  const result = { child, exited, message };
  f.workers.push(result);
  return result;
}

async function acquiredWorker(f, executable = process.execPath) {
  const owner = worker(f, "hold", executable);
  const message = await bounded(owner.message, "owner acquisition");
  assert.equal(message.acquired, true);
  assert.equal(message.pid, owner.child.pid);
  return owner;
}

async function probe(f, executable = process.execPath) {
  const contender = worker(f, "probe", executable);
  const message = await bounded(contender.message, "contender acquisition");
  const exit = await bounded(contender.exited, "contender exit");
  return { message, exit };
}

async function assertBusy(f, executable = process.execPath) {
  const { message, exit } = await probe(f, executable);
  assert.equal(message.acquired, false);
  assert.equal(message.code, "HOST_OWNER_LOCK_BUSY");
  assert.ok(message.elapsedMs < 1_000, `Contention waited ${message.elapsedMs}ms`);
  assert.equal(exit.code, 23, exit.stderr);
}

function identity(file) {
  const stat = lstatSync(file, { bigint: true });
  return { dev: stat.dev, ino: stat.ino };
}

test("synchronous acquisition closes once without releasing a later owner or unlinking the file", (t) => {
  const f = fixture(t);
  const first = acquireHostOwnerLock(f.directory);
  f.locks.push(first);
  assert.deepEqual(Object.keys(first), ["close"]);
  const original = identity(f.file);
  assert.throws(() => acquireHostOwnerLock(f.directory), { code: "HOST_OWNER_LOCK_BUSY" });
  assert.deepEqual(identity(f.file), original);
  first.close();
  assert.deepEqual(identity(f.file), original);

  const second = acquireHostOwnerLock(f.directory);
  f.locks.push(second);
  first.close();
  assert.throws(() => acquireHostOwnerLock(f.directory), { code: "HOST_OWNER_LOCK_BUSY" });
  second.close();
  second.close();
  assert.deepEqual(identity(f.file), original);

  const Database = process.versions.bun
    ? require("bun:sqlite").Database
    : require("node:sqlite").DatabaseSync;
  const database = new Database(f.file);
  try {
    assert.deepEqual(database.prepare("SELECT name FROM sqlite_schema").all(), []);
    assert.equal(database.prepare("PRAGMA journal_mode").get().journal_mode, "delete");
    assert.equal(readFileSync(f.file).subarray(0, 16).toString(), "SQLite format 3\0");
  } finally {
    if (process.versions.bun) database.close(true);
    else database.close();
  }
});

test("first acquisition excludes an actual second process until graceful close", async (t) => {
  const f = fixture(t);
  const owner = await acquiredWorker(f);
  const original = identity(f.file);
  await assertBusy(f);
  // A failed contender must not release or replace the live owner's OS lock.
  await assertBusy(f);
  assert.deepEqual(identity(f.file), original);
  owner.child.stdin.end("close\n");
  const exit = await bounded(owner.exited, "graceful owner exit");
  assert.equal(exit.code, 0, exit.stderr);
  const reacquired = await probe(f);
  assert.equal(reacquired.message.acquired, true);
  assert.equal(reacquired.exit.code, 0, reacquired.exit.stderr);
  assert.deepEqual(identity(f.file), original);
});

test("killing the actual owner releases its OS lock without stale-file stealing", async (t) => {
  const f = fixture(t);
  const owner = await acquiredWorker(f);
  const original = identity(f.file);
  await assertBusy(f);
  assert.equal(owner.child.kill("SIGKILL"), true);
  const exit = await bounded(owner.exited, "killed owner exit");
  assert.ok(exit.signal === "SIGKILL" || exit.code !== 0);
  assert.deepEqual(identity(f.file), original);
  const reacquired = await probe(f);
  assert.equal(reacquired.message.acquired, true);
  assert.equal(reacquired.exit.code, 0, reacquired.exit.stderr);
  assert.deepEqual(identity(f.file), original);
});

test("Node ownership excludes Bun and Bun acquires the same file after Node exits", async (t) => {
  const f = fixture(t);
  const owner = await acquiredWorker(f, nodeExecutable);
  const original = identity(f.file);
  await assertBusy(f, bunExecutable);
  owner.child.stdin.end("close\n");
  const exit = await bounded(owner.exited, "Node owner exit");
  assert.equal(exit.code, 0, exit.stderr);
  const bunOwner = await acquiredWorker(f, bunExecutable);
  assert.deepEqual(identity(f.file), original);
  await assertBusy(f, nodeExecutable);
  assert.equal(bunOwner.child.kill("SIGKILL"), true);
  const bunExit = await bounded(bunOwner.exited, "killed Bun owner exit");
  assert.ok(bunExit.signal === "SIGKILL" || bunExit.code !== 0);
  const reacquired = await probe(f, nodeExecutable);
  assert.equal(reacquired.message.acquired, true);
  assert.equal(reacquired.exit.code, 0, reacquired.exit.stderr);
  assert.deepEqual(identity(f.file), original);
});

test("different trusted directories have independent owner locks", async (t) => {
  const first = fixture(t);
  const second = fixture(t);
  await acquiredWorker(first);
  const other = await probe(second);
  assert.equal(other.message.acquired, true);
  assert.equal(other.exit.code, 0, other.exit.stderr);
  await assertBusy(first);
});

test("invalid and absent directories fail without creating parents", (t) => {
  const f = fixture(t);
  for (const directory of [undefined, null, 1, "", ".", `${f.directory}\0invalid`]) {
    assert.throws(() => acquireHostOwnerLock(directory), { code: "HOST_OWNER_LOCK_INVALID" });
  }
  const missing = join(f.directory, "missing", "nested");
  assert.throws(() => acquireHostOwnerLock(missing), { code: "HOST_OWNER_LOCK_FAILED" });
  assert.equal(existsSync(join(f.directory, "missing")), false);
  const notDirectory = join(f.directory, "ordinary-file");
  writeFileSync(notDirectory, "unchanged");
  assert.throws(() => acquireHostOwnerLock(notDirectory), { code: "HOST_OWNER_LOCK_INVALID" });
  assert.equal(readFileSync(notDirectory, "utf8"), "unchanged");
  assert.equal(existsSync(f.file), false);
});

test("nonregular lock files and SQLite sidecars are refused before opening SQLite", async (t) => {
  for (const suffix of ["", "-journal", "-wal", "-shm"]) {
    await t.test(suffix || "main", (t) => {
      const f = fixture(t);
      const badPath = `${f.file}${suffix}`;
      if (suffix) writeFileSync(f.file, "preserve-main");
      mkdirSync(badPath);
      assert.throws(() => acquireHostOwnerLock(f.directory), { code: "HOST_OWNER_LOCK_INVALID" });
      assert.equal(lstatSync(badPath).isDirectory(), true);
      if (suffix) assert.equal(readFileSync(f.file, "utf8"), "preserve-main");
    });
  }
});

test("hard-linked lock files and SQLite sidecars are refused without touching their targets", async (t) => {
  for (const suffix of ["", "-journal", "-wal", "-shm"]) {
    await t.test(suffix || "main", (t) => {
      const f = fixture(t);
      const target = join(f.directory, "target");
      writeFileSync(target, "unchanged");
      if (suffix) writeFileSync(f.file, "preserve-main");
      linkSync(target, `${f.file}${suffix}`);
      assert.throws(() => acquireHostOwnerLock(f.directory), { code: "HOST_OWNER_LOCK_INVALID" });
      assert.equal(readFileSync(target, "utf8"), "unchanged");
      assert.equal(lstatSync(target).nlink, 2);
      if (suffix) assert.equal(readFileSync(f.file, "utf8"), "preserve-main");
    });
  }
});

test("symbolic-link lock files, sidecars, and directory junctions are refused", async (t) => {
  for (const suffix of ["", "-journal", "-wal", "-shm", "directory"]) {
    await t.test(suffix || "main", (t) => {
      const f = fixture(t);
      const target = join(f.directory, "target");
      const directoryTarget = process.platform === "win32" || suffix === "directory";
      if (directoryTarget) mkdirSync(target);
      else writeFileSync(target, "unchanged");
      if (suffix && suffix !== "directory") writeFileSync(f.file, "preserve-main");
      const link = suffix === "directory" ? join(f.directory, "linked-directory") : `${f.file}${suffix}`;
      // A directory junction needs no symlink privilege on Windows and must
      // still be rejected for a lock/sidecar leaf or the supplied directory.
      symlinkSync(target, link, process.platform === "win32" ? "junction" : directoryTarget ? "dir" : "file");
      assert.throws(() => acquireHostOwnerLock(suffix === "directory" ? link : f.directory), {
        code: "HOST_OWNER_LOCK_INVALID",
      });
      if (suffix === "directory") {
        for (const ending of [sep, `${sep}.`]) {
          assert.throws(() => acquireHostOwnerLock(`${link}${ending}`), { code: "HOST_OWNER_LOCK_INVALID" });
        }
      }
      assert.equal(lstatSync(link).isSymbolicLink(), true);
      if (directoryTarget) assert.equal(existsSync(join(target, LOCK_FILE)), false);
      else assert.equal(readFileSync(target, "utf8"), "unchanged");
      if (suffix === "directory") assert.equal(existsSync(f.file), false);
      else if (suffix) assert.equal(readFileSync(f.file, "utf8"), "preserve-main");
    });
  }
});

test("orphan rollback journals and unexpected regular WAL sidecars are never deleted", async (t) => {
  for (const suffix of ["-journal", "-wal", "-shm"]) {
    await t.test(suffix, (t) => {
      const f = fixture(t);
      const sidecar = `${f.file}${suffix}`;
      writeFileSync(sidecar, "preserve-sidecar");
      assert.throws(() => acquireHostOwnerLock(f.directory), { code: "HOST_OWNER_LOCK_INVALID" });
      assert.equal(readFileSync(sidecar, "utf8"), "preserve-sidecar");
      assert.equal(existsSync(f.file), false);
      if (suffix !== "-journal") {
        writeFileSync(f.file, "preserve-main");
        assert.throws(() => acquireHostOwnerLock(f.directory), { code: "HOST_OWNER_LOCK_INVALID" });
        assert.equal(readFileSync(f.file, "utf8"), "preserve-main");
        assert.equal(readFileSync(sidecar, "utf8"), "preserve-sidecar");
      }
    });
  }
});

test("SQLite alone handles a regular leftover rollback journal beside an existing lock file", (t) => {
  const f = fixture(t);
  const initial = acquireHostOwnerLock(f.directory);
  initial.close();
  const original = identity(f.file);
  writeFileSync(`${f.file}-journal`, Buffer.alloc(512));
  const lock = acquireHostOwnerLock(f.directory);
  f.locks.push(lock);
  assert.deepEqual(identity(f.file), original);
  lock.close();
  assert.deepEqual(identity(f.file), original);
});

test("corrupt regular lock files fail closed without replacement or truncation", (t) => {
  const f = fixture(t);
  writeFileSync(f.file, "not a SQLite database");
  const original = identity(f.file);
  assert.throws(() => acquireHostOwnerLock(f.directory), { code: "HOST_OWNER_LOCK_FAILED" });
  assert.equal(readFileSync(f.file, "utf8"), "not a SQLite database");
  assert.deepEqual(identity(f.file), original);
});
