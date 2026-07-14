import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { join } from "node:path";
import test from "node:test";

import { SessionPool } from "../src/session-pool.js";

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    this.stdin = { write: () => true };
    this.killCount = 0;
  }

  kill() {
    this.killCount += 1;
    return true;
  }
}

const WORK_DIR = process.platform === "win32" ? String.raw`C:\work` : "/work";
const ALIAS_WORK_DIR = process.platform === "win32" ? "C:/work/." : "/work/.";

test("an exiting poisoned child does not remove its replacement session", () => {
  const children = [];
  const pool = new SessionPool({
    existsSyncFn: () => true,
    realpathSyncFn: () => WORK_DIR,
    spawnFn: () => {
      const child = new FakeChild();
      children.push(child);
      return child;
    },
  });

  try {
    const poisoned = pool.ensureSession(WORK_DIR);
    poisoned.closed = true;
    poisoned.child.kill();

    const replacement = pool.ensureSession(WORK_DIR);
    assert.notStrictEqual(replacement, poisoned);
    assert.equal(children.length, 2);

    children[0].emit("exit", 1, null);

    assert.strictEqual(pool.ensureSession(WORK_DIR), replacement);
    assert.equal(children.length, 2);
  } finally {
    pool.shutdown();
  }
});

test("canonical workDir aliases reuse one session and one spawn path", () => {
  const spawnCalls = [];
  const pool = new SessionPool({
    existsSyncFn: () => true,
    realpathSyncFn: () => WORK_DIR,
    spawnFn: (...args) => {
      spawnCalls.push(args);
      return new FakeChild();
    },
  });

  try {
    const first = pool.ensureSession(ALIAS_WORK_DIR);
    const second = pool.ensureSession(WORK_DIR);

    assert.strictEqual(second, first);
    assert.equal(spawnCalls.length, 1);
    assert.equal(spawnCalls[0][2].cwd, WORK_DIR);
    assert.equal(spawnCalls[0][1][2], join(WORK_DIR, ".gjc-remote-session"));
  } finally {
    pool.shutdown();
  }
});

test("an unresolvable workDir fails before spawning a child", () => {
  let spawnCalls = 0;
  const failure = new Error("realpath failed");
  const pool = new SessionPool({
    existsSyncFn: () => true,
    realpathSyncFn: () => {
      throw failure;
    },
    spawnFn: () => {
      spawnCalls += 1;
      return new FakeChild();
    },
  });

  try {
    assert.throws(
      () => pool.ensureSession(WORK_DIR),
      (error) =>
        error.message === `workDir cannot be resolved on this host: ${WORK_DIR}` &&
        error.cause === failure
    );
    assert.equal(spawnCalls, 0);
  } finally {
    pool.shutdown();
  }
});
