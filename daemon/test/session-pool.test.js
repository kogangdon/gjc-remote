import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
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

test("an exiting poisoned child does not remove its replacement session", () => {
  const children = [];
  const pool = new SessionPool({
    existsSyncFn: () => true,
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
