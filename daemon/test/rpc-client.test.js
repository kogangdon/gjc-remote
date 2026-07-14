import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { RpcSession } from "../src/rpc-client.js";

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.stdout = new EventEmitter();
    this.writes = [];
    this.killCount = 0;
    this.stdin = {
      write: (data) => {
        this.writes.push(data);
        return true;
      },
    };
  }

  kill() {
    this.killCount += 1;
    return true;
  }

  frame(frame) {
    this.stdout.emit("data", `${JSON.stringify(frame)}\n`);
  }
}

async function waitForWriteCount(child, count) {
  while (child.writes.length < count) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

test("send dispatches commands one at a time in FIFO order", async () => {
  const child = new FakeChild();
  const session = new RpcSession(child);
  const events = [];

  const first = session.send({ type: "status" }, (event) => events.push(event), 1_000);
  const second = session.send({ type: "models" }, (event) => events.push(event), 1_000);

  assert.equal(child.writes.length, 1);
  assert.equal(JSON.parse(child.writes[0]).type, "status");

  child.frame({ type: "response", command: "status", success: true });
  await first;
  await waitForWriteCount(child, 2);

  assert.equal(JSON.parse(child.writes[1]).type, "models");
  child.frame({ type: "response", command: "models", success: true });
  await second;
  assert.deepEqual(events.map((event) => event.command), ["status", "models"]);
});

test("child exit rejects the current and all queued requests", async () => {
  const child = new FakeChild();
  const session = new RpcSession(child);
  const current = session.send({ type: "status" }, () => {}, 1_000);
  const queued = session.send({ type: "models" }, () => {}, 1_000);
  const settled = Promise.allSettled([current, queued]);

  child.emit("exit", 1, null);

  const results = await settled;
  assert.equal(child.writes.length, 1);
  for (const result of results) {
    assert.equal(result.status, "rejected");
    assert.equal(result.reason.message, "gjc rpc process exited");
  }
});

test("a timeout poisons the session, rejects queued requests, and kills the child", async () => {
  const child = new FakeChild();
  const session = new RpcSession(child);
  const current = session.send({ type: "status" }, () => {}, 10);
  const queued = session.send({ type: "models" }, () => {}, 1_000);

  const results = await Promise.allSettled([current, queued]);

  assert.equal(child.killCount, 1);
  assert.equal(child.writes.length, 1);
  for (const result of results) {
    assert.equal(result.status, "rejected");
    assert.equal(result.reason.message, "RPC command timed out");
  }
  await assert.rejects(
    session.send({ type: "status" }, () => {}),
    /gjc rpc process is not running/
  );
});

test("late frames after timeout are dropped and cannot reach a later command", async () => {
  const child = new FakeChild();
  const session = new RpcSession(child);
  const seen = [];
  const timedOut = session.send({ type: "status" }, (event) => seen.push(["first", event]), 10);
  const queued = session.send({ type: "models" }, (event) => seen.push(["second", event]), 1_000);

  await Promise.allSettled([timedOut, queued]);
  child.frame({ type: "response", command: "status", success: true });
  child.frame({ type: "response", command: "models", success: true });

  assert.deepEqual(seen, []);
  assert.equal(child.writes.length, 1);
});

test("error followed by exit is terminal only once", async () => {
  const child = new FakeChild();
  const session = new RpcSession(child);
  const current = session.send({ type: "status" }, () => {}, 1_000);
  const queued = session.send({ type: "models" }, () => {}, 1_000);
  const settled = Promise.allSettled([current, queued]);
  const failure = new Error("child stream failed");

  child.emit("error", failure);
  child.emit("exit", 1, null);

  const results = await settled;
  assert.equal(results[0].status, "rejected");
  assert.equal(results[1].status, "rejected");
  assert.strictEqual(results[0].reason, failure);
  assert.strictEqual(results[1].reason, failure);
  assert.equal(child.writes.length, 1);
});

test("send after child closure rejects without writing", async () => {
  const child = new FakeChild();
  const session = new RpcSession(child);

  child.emit("exit", 0, null);

  await assert.rejects(
    session.send({ type: "status" }, () => {}),
    /gjc rpc process is not running/
  );
  assert.equal(child.writes.length, 0);
});
