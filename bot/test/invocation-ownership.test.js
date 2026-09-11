import assert from "node:assert/strict";
import test from "node:test";
import { InvocationOwnership } from "../src/invocation-ownership.js";

test("one user/channel owns at most one invocation in either settlement order", () => {
  for (const releaseFirst of ["first", "second"]) {
    const ownership = new InvocationOwnership();
    const first = ownership.reserve("channel-a", "user-a", "host-a");
    assert.ok(first);
    assert.equal(
      ownership.reserve("channel-a", "user-a", "host-a"),
      undefined
    );
    assert.equal(ownership.attachRequest(first, "request-a"), true);
    assert.strictEqual(ownership.get("channel-a", "user-a"), first);

    const unrelated = ownership.reserve("channel-a", "user-b", "host-a");
    assert.ok(unrelated);
    const firstRelease = releaseFirst === "first" ? first : unrelated;
    const secondRelease = releaseFirst === "first" ? unrelated : first;
    assert.equal(ownership.release(firstRelease), true);
    assert.strictEqual(
      ownership.get("channel-a", "user-a"),
      firstRelease === first ? undefined : first
    );
    assert.equal(ownership.release(secondRelease), true);
    assert.equal(ownership.get("channel-a", "user-a"), undefined);
    assert.equal(ownership.get("channel-a", "user-b"), undefined);
  }
});

test("a stale owner cannot attach or release a successor", () => {
  const ownership = new InvocationOwnership();
  const first = ownership.reserve("channel-a", "user-a", "host-a");
  ownership.release(first);
  const successor = ownership.reserve("channel-a", "user-a", "host-a");
  assert.equal(ownership.attachRequest(first, "stale-request"), false);
  assert.equal(ownership.release(first), false);
  assert.strictEqual(ownership.get("channel-a", "user-a"), successor);
});
