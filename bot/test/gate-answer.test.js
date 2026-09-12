import assert from "node:assert/strict";
import test from "node:test";
import {
  GatePresentationStore,
  classifyGateReply,
  deliverGateAnswer,
} from "../src/gate-answer.js";

function createPresentation(overrides = {}) {
  const store = new GatePresentationStore({
    tokenFactory: () => "token-1",
  });
  const entry = store.create({
    hostId: "host",
    requestId: "request",
    gateId: "gate",
    presentationId: "presentation",
    userId: "owner",
    ...overrides,
  });
  assert.ok(entry);
  assert.equal(store.bindMessage(entry.token, "message"), true);
  return { store, entry };
}

test("a gate is not answerable until its exact message is bound and activated", () => {
  const store = new GatePresentationStore({ tokenFactory: () => "token-1" });
  const entry = store.create({
    hostId: "host",
    requestId: "request",
    gateId: "gate",
    presentationId: "presentation",
    userId: "owner",
  });
  assert.equal(store.findReply("message", "owner"), undefined);
  assert.equal(store.activate(entry.token), false);
  assert.equal(store.bindMessage(entry.token, "message"), true);
  assert.equal(store.findReply("message", "owner"), undefined);
  assert.equal(store.activate(entry.token), true);
  assert.strictEqual(store.findReply("message", "owner"), entry);
});

test("reply routing requires exact message and initiating user", () => {
  const { store, entry } = createPresentation();
  store.activate(entry.token);
  for (const candidate of [
    { token: entry.token, messageId: "wrong", userId: "owner" },
    { token: entry.token, messageId: "message", userId: "other" },
    {
      token: entry.token,
      messageId: "message",
      userId: "owner",
      replyToMessageId: "wrong",
    },
  ]) {
    assert.equal(store.beginAnswer(candidate), undefined);
  }
  assert.strictEqual(
    store.beginAnswer({
      token: entry.token,
      messageId: "message",
      userId: "owner",
      replyToMessageId: "message",
    }),
    entry
  );
});

test("a correlated answer preserves retry only after authoritative rejection", async () => {
  const { store, entry } = createPresentation();
  store.activate(entry.token);
  const states = [];
  const options = {
    store,
    token: entry.token,
    messageId: "message",
    userId: "owner",
    replyToMessageId: "message",
    answer: "yes",
    onState: async (state) => states.push(state),
  };
  assert.equal(
    await deliverGateAnswer({
      ...options,
      answerGate: async (...args) => {
        assert.deepEqual(args, [
          "host",
          "request",
          "gate",
          "presentation",
          "yes",
        ]);
        return { ok: false };
      },
    }),
    true
  );
  assert.equal(entry.state, "answerable");
  assert.deepEqual(states, ["answering", "rejected"]);

  assert.equal(
    await deliverGateAnswer({
      ...options,
      answerGate: async () => ({ ok: true }),
    }),
    true
  );
  assert.equal(entry.state, "answered");
  assert.deepEqual(states, ["answering", "rejected", "answering", "answered"]);
});

test("ordinary or stale messages never become gate answers", async () => {
  const { store, entry } = createPresentation();
  store.activate(entry.token);
  const answerGate = () => assert.fail("unexpected answer delivery");
  for (const candidate of [
    { token: "forged", messageId: "message", userId: "owner" },
    { token: entry.token, messageId: "message", userId: "other" },
    { token: entry.token, messageId: "other", userId: "owner" },
  ]) {
    assert.equal(
      await deliverGateAnswer({
        store,
        ...candidate,
        answer: "ordinary chat",
        answerGate,
        onState: async () => {},
      }),
      false
    );
  }
  assert.equal(entry.state, "answerable");
});

test("replies to owned stale or wrong-user gate messages never become prompts", () => {
  const { store, entry } = createPresentation();
  store.activate(entry.token);
  assert.equal(
    classifyGateReply({
      store,
      messageId: "message",
      channelId: undefined,
      userId: "other",
    }).kind,
    "not_owned"
  );
  store.retire(entry.token, "expired");
  assert.equal(
    classifyGateReply({
      store,
      messageId: "message",
      channelId: undefined,
      userId: "owner",
    }).kind,
    "retired"
  );
  assert.equal(
    classifyGateReply({
      store,
      messageId: "ordinary-message",
      channelId: undefined,
      userId: "owner",
    }).kind,
    "ordinary"
  );
});

test("terminal presentations retain stale-token fences without adoption", () => {
  for (const state of ["answered", "expired", "disconnected", "replaced"]) {
    const { store, entry } = createPresentation();
    store.activate(entry.token);
    assert.equal(store.retire(entry.token, state), true);
    assert.equal(store.findReply("message", "owner"), undefined);
    assert.equal(store.activate(entry.token), false);
    assert.equal(store.retire(entry.token, state), true);
    assert.equal(store.retire(entry.token, "disconnected"), state === "disconnected");
  }
});

test("presentation capacity fails closed without evicting live entries", () => {
  let sequence = 0;
  const store = new GatePresentationStore({
    maxEntries: 2,
    tokenFactory: () => `token-${++sequence}`,
  });
  const input = {
    hostId: "host",
    requestId: "request",
    gateId: "gate",
    presentationId: "presentation",
    userId: "owner",
  };
  assert.ok(store.create(input));
  assert.ok(store.create({ ...input, requestId: "request-2" }));
  assert.equal(store.create({ ...input, requestId: "request-3" }), undefined);
  assert.equal(store.entries.size, 2);
  assert.ok(store.get("token-1"));
});

test("capacity reclaims only terminal tombstones and preserves live owners", () => {
  let sequence = 0;
  const store = new GatePresentationStore({
    maxEntries: 2,
    tokenFactory: () => `token-${++sequence}`,
  });
  const input = {
    hostId: "host",
    requestId: "request",
    gateId: "gate",
    presentationId: "presentation",
    userId: "owner",
  };
  const terminal = store.create(input);
  const live = store.create({ ...input, requestId: "request-2" });
  store.retire(terminal.token, "expired");
  const successor = store.create({ ...input, requestId: "request-3" });
  assert.ok(successor);
  assert.equal(store.get(terminal.token), undefined);
  assert.strictEqual(store.get(live.token), live);
});

test("replacement and duplicate message/token identities fail closed", () => {
  const { store, entry } = createPresentation();
  assert.equal(store.bindMessage(entry.token, "message-2"), false);
  assert.equal(store.activate(entry.token), true);
  assert.equal(store.activate(entry.token), false);
  assert.equal(store.remove(entry.token), true);
  assert.equal(store.findReply("message", "owner"), undefined);
});
