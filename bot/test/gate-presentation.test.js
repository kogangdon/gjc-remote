import assert from "node:assert/strict";
import test from "node:test";
import { GatePresentationStore } from "../src/gate-answer.js";
import {
  gateComponentRows,
  gateMessagePayload,
  renderGatePresentation,
} from "../src/gate-presentation.js";

function entry(overrides = {}) {
  return {
    token: "token-1",
    kind: "question",
    prompt: "Choose",
    choices: [{ value: "a", label: "Alpha" }],
    multi: false,
    ...overrides,
  };
}

test("64 choices remain selectable across bounded Discord menus", () => {
  const choices = Array.from({ length: 64 }, (_, index) => ({
    value: `value-${index}`,
    label: `Choice ${index} ${"x".repeat(120)}`,
  }));
  const candidate = entry({ choices });
  const rows = gateComponentRows(candidate).map((row) => row.toJSON());
  assert.equal(rows.length, 3);
  assert.deepEqual(
    rows.map((row) => row.components[0].options.length),
    [25, 25, 14]
  );
  assert.equal(rows[2].components[0].options[13].value, "63");
  assert.ok(
    rows.every((row) =>
      row.components[0].options.every((option) => option.label.length <= 100)
    )
  );
  const payload = gateMessagePayload(candidate, "Presenting");
  assert.ok(payload.content.length <= 1900);
  assert.match(payload.files[0].attachment.toString("utf8"), /64\. Choice 63/);
});

test("multi-select and oversized prompts preserve complete content in an attachment", () => {
  const prompt = "P".repeat(16_000);
  const choices = Array.from({ length: 64 }, (_, index) => ({
    value: `value-${index}`,
    label: `Choice ${index} ${"x".repeat(140)}`,
  }));
  const candidate = entry({ prompt, choices, multi: true });
  const payload = gateMessagePayload(candidate, "Presenting");
  assert.equal(payload.components.length, 0);
  assert.match(payload.content, /Reply to this exact message/);
  assert.equal(
    payload.files[0].attachment.toString("utf8").startsWith(prompt),
    true
  );
  assert.equal(
    payload.files[0].attachment.toString("utf8").includes("64. Choice 63"),
    true
  );
});

test("presentation activates only after the exact Discord message is sent", async () => {
  const store = new GatePresentationStore({ tokenFactory: () => "token-1" });
  const sent = [];
  const edits = [];
  const message = {
    id: "discord-message-1",
    async edit(payload) {
      edits.push(payload);
    },
  };
  const channel = {
    async send(payload) {
      sent.push(payload);
      return message;
    },
  };
  const handle = await renderGatePresentation({
    store,
    channel,
    channelId: "channel-1",
    hostId: "host-1",
    userId: "user-1",
    gate: {
      requestId: "request-1",
      gateId: "gate-1",
      presentationId: "presentation-1",
      prompt: "Approve?",
      kind: "approval",
      choices: [
        { value: "approve", label: "approve" },
        { value: "reject", label: "reject" },
      ],
    },
  });
  assert.equal(sent.length, 1);
  assert.equal(store.get("token-1").state, "presenting");
  assert.equal(handle.messageId, message.id);
  assert.equal(handle.activate(), true);
  assert.equal(store.get("token-1").state, "answerable");
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(edits.at(-1).content, /Awaiting answer/);
  const exact = store.get("token-1");
  assert.strictEqual(
    store.beginAnswer({
      token: exact.token,
      messageId: exact.messageId,
      userId: exact.userId,
    }),
    exact
  );
  await exact.updateState("answering");
  assert.match(edits.at(-1).content, /Answering/);
  assert.equal(store.rejectAnswer(exact.token), true);
  await exact.updateState("rejected");
  assert.match(edits.at(-1).content, /Rejected — retry available/);
  assert.strictEqual(
    store.beginAnswer({
      token: exact.token,
      messageId: exact.messageId,
      userId: exact.userId,
    }),
    exact
  );
  assert.equal(store.completeAnswer(exact.token), true);
  await exact.updateState("answered");
  assert.equal(store.get("token-1").state, "answered");
  assert.match(edits.at(-1).content, /Answered/);
  assert.ok(
    edits.at(-1).components.every((row) =>
      row.toJSON().components.every((component) => component.disabled === true)
    )
  );
});

test("disconnect edits the exact active presentation and disables controls", async () => {
  const store = new GatePresentationStore({ tokenFactory: () => "token-1" });
  const edits = [];
  const message = {
    id: "discord-message-1",
    async edit(payload) {
      edits.push(payload);
    },
  };
  const handle = await renderGatePresentation({
    store,
    channel: { send: async () => message },
    channelId: "channel-1",
    hostId: "host-1",
    userId: "user-1",
    gate: {
      requestId: "request-1",
      gateId: "gate-1",
      presentationId: "presentation-1",
      prompt: "Approve?",
      kind: "approval",
      choices: [{ value: "approve", label: "approve" }],
    },
  });
  handle.activate();
  await handle.update("Disconnected");
  assert.equal(store.get("token-1").state, "disconnected");
  assert.match(edits.at(-1).content, /Disconnected/);
  assert.ok(
    edits.at(-1).components.every((row) =>
      row.toJSON().components.every((component) => component.disabled === true)
    )
  );
});

test("Discord send failure creates no answerable route", async () => {
  const store = new GatePresentationStore({ tokenFactory: () => "token-1" });
  await assert.rejects(
    renderGatePresentation({
      store,
      channel: { send: async () => { throw new Error("private failure"); } },
      channelId: "channel-1",
      hostId: "host-1",
      userId: "user-1",
      gate: {
        requestId: "request-1",
        gateId: "gate-1",
        presentationId: "presentation-1",
        prompt: "Approve?",
        kind: "approval",
      },
    }),
    /workflow gate presentation failed/
  );
  assert.equal(store.get("token-1").state, "expired");
  assert.equal(store.findReply("discord-message-1", "user-1"), undefined);
});
