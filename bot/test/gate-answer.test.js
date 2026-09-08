import assert from "node:assert/strict";
import test from "node:test";
import { deliverGateAnswer } from "../src/gate-answer.js";

function fixture() {
  const gate = { hostId: "host", requestId: "request", gateId: "first" };
  const pendingGateByChannel = new Map([["channel", gate]]);
  const effects = [];
  return {
    gate,
    effects,
    options: {
      pendingGateByChannel,
      channelId: "channel",
      answer: "yes",
      onAccepted: async () => effects.push("accepted"),
      onRejected: async () => effects.push("rejected"),
    },
  };
}

test("a sent answer preserves its presentation until confirmed acceptance", async () => {
  const { gate, effects, options } = fixture();
  let resolve;
  const receipt = new Promise((r) => { resolve = r; });
  const work = deliverGateAnswer({ ...options, answerGate: (...args) => {
    assert.deepEqual(args, ["host", "request", "first", "yes"]);
    return receipt;
  } });
  assert.equal(options.pendingGateByChannel.get("channel"), gate);
  assert.deepEqual(effects, []);
  resolve({ ok: true });
  assert.equal(await work, true);
  assert.equal(options.pendingGateByChannel.has("channel"), false);
  assert.deepEqual(effects, ["accepted"]);
});

test("rejected then valid answer stays a gate reply, not a new prompt", async () => {
  const { gate, effects, options } = fixture();
  assert.equal(await deliverGateAnswer({ ...options, answerGate: async () => ({ ok: false }) }), true);
  assert.equal(options.pendingGateByChannel.get("channel"), gate);
  assert.equal(await deliverGateAnswer({ ...options, answerGate: async () => ({ ok: true }) }), true);
  assert.deepEqual(effects, ["rejected", "accepted"]);
});

test("late predecessor acceptance cannot erase its successor", async () => {
  const { options } = fixture();
  const successor = { hostId: "host", requestId: "request", gateId: "second" };
  await deliverGateAnswer({ ...options, answerGate: async () => {
    options.pendingGateByChannel.set("channel", successor);
    return { ok: true };
  } });
  assert.equal(options.pendingGateByChannel.get("channel"), successor);
});

test("delivery rejection is handled without consuming the pending gate", async () => {
  const { gate, effects, options } = fixture();
  assert.equal(await deliverGateAnswer({ ...options, answerGate: async () => { throw new Error("transport"); } }), true);
  assert.equal(options.pendingGateByChannel.get("channel"), gate);
  assert.deepEqual(effects, ["rejected"]);
});

test("ordinary chat falls through only when no gate exists", async () => {
  const { effects, options } = fixture();
  options.pendingGateByChannel.clear();
  assert.equal(await deliverGateAnswer({ ...options, answerGate: () => assert.fail("unexpected gate call") }), false);
  assert.deepEqual(effects, []);
});

test("late rejection never offers retry for a removed or replaced presentation", async () => {
  for (const replaced of [false, true]) {
    const { options } = fixture();
    const successor = { hostId: "host", requestId: "request", gateId: "second" };
    let rejection;
    const handled = await deliverGateAnswer({
      ...options,
      answerGate: async () => {
        if (replaced) options.pendingGateByChannel.set("channel", successor);
        else options.pendingGateByChannel.delete("channel");
        return { ok: false };
      },
      onRejected: async (result) => { rejection = result; },
    });
    assert.equal(handled, true);
    assert.equal(rejection.retryable, false);
    assert.equal(options.pendingGateByChannel.get("channel"), replaced ? successor : undefined);
  }
});

test("same-presentation rejection offers an actual retry", async () => {
  const { options } = fixture();
  let rejection;
  await deliverGateAnswer({
    ...options,
    answerGate: async () => ({ ok: false }),
    onRejected: async (result) => { rejection = result; },
  });
  assert.equal(rejection.retryable, true);
});
