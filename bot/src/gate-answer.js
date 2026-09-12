import { randomUUID } from "node:crypto";

const TERMINAL_STATES = new Set([
  "answered",
  "expired",
  "disconnected",
  "replaced",
]);

export class GatePresentationStore {
  constructor({ tokenFactory = randomUUID, maxEntries = 64 } = {}) {
    if (typeof tokenFactory !== "function") {
      throw new TypeError("gate token factory must be a function");
    }
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 64) {
      throw new TypeError("gate presentation capacity must be from 1 to 64");
    }
    this.tokenFactory = tokenFactory;
    this.maxEntries = maxEntries;
    this.entries = new Map();
    this.tokensByMessageId = new Map();
  }

  create({
    hostId,
    requestId,
    gateId,
    presentationId,
    userId,
  }) {
    while (this.entries.size >= this.maxEntries) {
      const retired = [...this.entries.values()].find((entry) =>
        TERMINAL_STATES.has(entry.state)
      );
      if (!retired) break;
      this.remove(retired.token);
    }
    if (this.entries.size >= this.maxEntries) {
      return undefined;
    }
    const token = this.tokenFactory();
    if (
      typeof token !== "string" ||
      token.length < 1 ||
      token.length > 64 ||
      this.entries.has(token)
    ) {
      return undefined;
    }
    const values = [hostId, requestId, gateId, presentationId, userId];
    if (values.some((value) => typeof value !== "string" || value.length === 0)) {
      return undefined;
    }
    const entry = {
      token,
      hostId,
      requestId,
      gateId,
      presentationId,
      userId,
      messageId: undefined,
      state: "presenting",
    };
    this.entries.set(token, entry);
    return entry;
  }

  bindMessage(token, messageId) {
    const entry = this.entries.get(token);
    if (
      !entry ||
      entry.state !== "presenting" ||
      entry.messageId !== undefined ||
      typeof messageId !== "string" ||
      messageId.length === 0 ||
      this.tokensByMessageId.has(messageId)
    ) {
      return false;
    }
    entry.messageId = messageId;
    this.tokensByMessageId.set(messageId, token);
    return true;
  }

  activate(token) {
    const entry = this.entries.get(token);
    if (!entry || entry.state !== "presenting" || !entry.messageId) return false;
    entry.state = "answerable";
    return true;
  }

  beginAnswer({ token, messageId, userId, replyToMessageId }) {
    const entry = this.entries.get(token);
    if (!entry || entry.state !== "answerable") return undefined;
    if (entry.userId !== userId || entry.messageId !== messageId) return undefined;
    if (replyToMessageId !== undefined && replyToMessageId !== entry.messageId) {
      return undefined;
    }
    entry.state = "answering";
    return entry;
  }

  rejectAnswer(token) {
    const entry = this.entries.get(token);
    if (!entry || entry.state !== "answering") return false;
    entry.state = "answerable";
    return true;
  }

  completeAnswer(token) {
    const entry = this.entries.get(token);
    if (!entry || entry.state !== "answering") return false;
    entry.state = "answered";
    return true;
  }

  retire(token, state) {
    const entry = this.entries.get(token);
    if (!entry || !TERMINAL_STATES.has(state)) return false;
    if (TERMINAL_STATES.has(entry.state)) return entry.state === state;
    entry.state = state;
    return true;
  }

  findReply(messageId, userId, channelId) {
    const entry = this.findMessage(messageId, channelId);
    return (
      entry?.state === "answerable" &&
      entry.userId === userId
    )
      ? entry
      : undefined;
  }

  findMessage(messageId, channelId) {
    const token = this.tokensByMessageId.get(messageId);
    const entry = token === undefined ? undefined : this.entries.get(token);
    return entry && (channelId === undefined || entry.channelId === channelId)
      ? entry
      : undefined;
  }

  get(token) {
    return this.entries.get(token);
  }

  remove(token) {
    const entry = this.entries.get(token);
    if (!entry) return false;
    if (entry.messageId) this.tokensByMessageId.delete(entry.messageId);
    this.entries.delete(token);
    return true;
  }
}

export function classifyGateReply({ store, messageId, channelId, userId }) {
  const entry = store.findMessage(messageId, channelId);
  if (!entry) return { kind: "ordinary" };
  if (entry.userId !== userId) return { kind: "not_owned", entry };
  if (entry.state !== "answerable") return { kind: "retired", entry };
  return { kind: "answerable", entry };
}

export async function deliverGateAnswer({
  store,
  token,
  messageId,
  userId,
  replyToMessageId,
  answer,
  answerGate,
  onState,
}) {
  const entry = store.beginAnswer({
    token,
    messageId,
    userId,
    replyToMessageId,
  });
  if (!entry) return false;
  await onState("answering", entry);
  let result;
  try {
    result = await answerGate(
      entry.hostId,
      entry.requestId,
      entry.gateId,
      entry.presentationId,
      answer
    );
  } catch {
    result = { ok: false, error: "gate answer delivery failed" };
  }
  if (result?.ok === true) {
    store.completeAnswer(token);
    await onState("answered", entry, result);
  } else {
    store.rejectAnswer(token);
    await onState("rejected", entry, result ?? { ok: false });
  }
  return true;
}
