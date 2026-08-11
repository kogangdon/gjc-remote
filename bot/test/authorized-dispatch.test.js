import assert from "node:assert/strict";
import test from "node:test";

import { createAuthorizationPolicy } from "../src/authorization.js";
import {
  dispatchAuthorizedInteraction,
  dispatchAuthorizedMessage,
} from "../src/authorized-dispatch.js";

function protectedFakes() {
  const calls = { get: 0, add: 0, listOnline: 0, isOnline: 0, invoke: 0 };
  return {
    calls,
    registry: {
      listOnline() {
        calls.listOnline += 1;
      },
      isOnline() {
        calls.isOnline += 1;
      },
      async invoke() {
        calls.invoke += 1;
      },
    },
    store: {
      get() {
        calls.get += 1;
      },
      add() {
        calls.add += 1;
      },
    },
  };
}

const authorization = createAuthorizationPolicy(["allowed-user"], { required: true });

test("unauthorized slash command is denied ephemerally before registry work", async () => {
  const { calls, registry } = protectedFakes();
  const replies = [];
  const interaction = {
    user: { id: "denied-user" },
    isButton: () => false,
    isChatInputCommand: () => true,
    async reply(payload) {
      replies.push(payload);
    },
  };

  const status = await dispatchAuthorizedInteraction({
    interaction,
    authorization,
    onButton: () => assert.fail("button handler must not run"),
    onChatInput: async () => {
      registry.listOnline();
      registry.isOnline();
      await registry.invoke();
    },
  });

  assert.equal(status, "denied");
  assert.deepEqual(calls, { get: 0, add: 0, listOnline: 0, isOnline: 0, invoke: 0 });
  assert.deepEqual(replies, [
    { content: "You are not authorized to run GJC commands.", ephemeral: true },
  ]);
});

test("unauthorized slash command remains denied when the reply fails", async () => {
  const interaction = {
    user: { id: "denied-user" },
    isButton: () => false,
    isChatInputCommand: () => true,
    reply: () => Promise.reject(new Error("interaction expired")),
  };

  const status = await dispatchAuthorizedInteraction({
    interaction,
    authorization,
    onButton: () => assert.fail("button handler must not run"),
    onChatInput: () => assert.fail("chat handler must not run"),
  });

  assert.equal(status, "denied");
});

test("unauthorized tool-log button is denied ephemerally before store work", async () => {
  const { calls, store } = protectedFakes();
  const replies = [];
  const interaction = {
    user: { id: "denied-user" },
    customId: "tool:missing",
    isButton: () => true,
    isChatInputCommand: () => false,
    reply(payload) {
      replies.push(payload);
      return Promise.resolve();
    },
  };

  const status = await dispatchAuthorizedInteraction({
    interaction,
    authorization,
    onButton: async () => {
      store.get("tool-log-id");
      store.add([]);
    },
    onChatInput: () => assert.fail("chat handler must not run"),
  });

  assert.equal(status, "denied");
  assert.deepEqual(calls, { get: 0, add: 0, listOnline: 0, isOnline: 0, invoke: 0 });
  assert.deepEqual(replies, [
    { content: "You are not authorized to view GJC tool logs.", ephemeral: true },
  ]);
});

test("unauthorized mapped message is silent before registry work", async () => {
  const { calls, registry } = protectedFakes();
  const replies = [];
  const message = {
    guildId: "guild-1",
    author: { id: "denied-user", bot: false },
    async reply(payload) {
      replies.push(payload);
    },
  };

  const status = await dispatchAuthorizedMessage({
    message,
    authorization,
    onMessage: async () => {
      registry.isOnline();
      await registry.invoke();
    },
  });

  assert.equal(status, "denied");
  assert.deepEqual(calls, { get: 0, add: 0, listOnline: 0, isOnline: 0, invoke: 0 });
  assert.deepEqual(replies, []);
});

test("authorized interactions and messages reach their protected handlers", async () => {
  const calls = [];
  const command = {
    user: { id: "allowed-user" },
    isButton: () => false,
    isChatInputCommand: () => true,
  };
  const message = {
    guildId: "guild-1",
    author: { id: "allowed-user", bot: false },
  };

  assert.equal(
    await dispatchAuthorizedInteraction({
      interaction: command,
      authorization,
      onButton: () => assert.fail("button handler must not run"),
      onChatInput: async () => calls.push("command"),
    }),
    "handled"
  );
  assert.equal(
    await dispatchAuthorizedMessage({
      message,
      authorization,
      onMessage: async () => calls.push("message"),
    }),
    "handled"
  );
  assert.deepEqual(calls, ["command", "message"]);
});
test("authorized interaction handler failures are contained", async () => {
  const interaction = {
    user: { id: "allowed-user" },
    isButton: () => false,
    isChatInputCommand: () => true,
  };

  const status = await dispatchAuthorizedInteraction({
    interaction,
    authorization,
    onButton: () => assert.fail("button handler must not run"),
    onChatInput: async () => {
      throw new Error("interaction expired");
    },
  });

  assert.equal(status, "failed");
});
