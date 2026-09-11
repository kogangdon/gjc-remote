import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  StringSelectMenuBuilder,
} from "discord.js";
import {
  CHUNK_LIMIT,
  NO_MENTIONS,
  createTextAttachment,
} from "./delivery.js";

function truncate(value, max) {
  const text = `${value ?? ""}`;
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

export function gateComponentRows(entry, disabled = false) {
  const choices = entry.choices ?? [];
  if (entry.multi || choices.length === 0) return [];
  if (choices.length <= 5) {
    return [
      new ActionRowBuilder().addComponents(
        choices.map((choice, index) =>
          new ButtonBuilder()
            .setCustomId(`gate:${entry.token}:choice:${index}`)
            .setLabel(choice.label.slice(0, 80))
            .setStyle(
              /reject|decline/i.test(choice.label)
                ? ButtonStyle.Danger
                : ButtonStyle.Primary
            )
            .setDisabled(disabled)
        )
      ),
    ];
  }
  const rows = [];
  for (let offset = 0; offset < choices.length; offset += 25) {
    const menu = new StringSelectMenuBuilder()
      .setCustomId(`gate:${entry.token}:select:${offset}`)
      .setPlaceholder(
        `Choose an option (${offset + 1}-${Math.min(offset + 25, choices.length)})`
      )
      .setDisabled(disabled)
      .addOptions(
        choices.slice(offset, offset + 25).map((choice, index) => ({
          label: choice.label.slice(0, 100),
          value: String(offset + index),
        }))
      );
    rows.push(new ActionRowBuilder().addComponents(menu));
  }
  return rows;
}

export function gateMessagePayload(
  entry,
  state,
  disabled = false,
  includeAttachment = true
) {
  const choices = entry.choices ?? [];
  const full = [
    entry.prompt,
    ...choices.map((choice, index) => `${index + 1}. ${choice.label}`),
  ].join("\n");
  const choicePreview = choices
    .slice(0, 5)
    .map((choice, index) => `**${index + 1}.** ${truncate(choice.label, 140)}`);
  const instruction = entry.multi
    ? '_Reply to this exact message with JSON such as `{"selected":["Option A","Option B"]}`._'
    : "_Use a control below, or reply to this exact message with an answer._";
  const lines = [
    `**GJC input — ${state}** (${entry.kind})`,
    instruction,
    truncate(entry.prompt, 1_200),
    ...choicePreview,
  ];
  if (choices.length > choicePreview.length) {
    lines.push(
      `_${choices.length - choicePreview.length} more options are included in the attachment._`
    );
  }
  return {
    content: lines.join("\n").slice(0, CHUNK_LIMIT),
    allowedMentions: NO_MENTIONS,
    components: gateComponentRows(entry, disabled),
    ...(includeAttachment
      ? { files: [createTextAttachment(full, "gjc-gate.txt")] }
      : {}),
  };
}

export async function renderGatePresentation({
  store,
  channel,
  channelId,
  hostId,
  gate,
  userId,
}) {
  if (!channel || typeof channel.send !== "function") {
    throw new Error("workflow gate channel is unavailable");
  }
  const entry = store.create({
    hostId,
    requestId: gate.requestId,
    gateId: gate.gateId,
    presentationId: gate.presentationId,
    userId,
  });
  if (!entry) throw new Error("workflow gate presentation capacity exhausted");
  entry.channelId = channelId;
  entry.kind = gate.kind;
  entry.prompt = gate.prompt;
  entry.choices = Array.isArray(gate.choices) ? gate.choices : [];
  entry.multi = gate.multi === true;
  let message;
  try {
    message = await channel.send(gateMessagePayload(entry, "Presenting"));
  } catch (error) {
    store.retire(entry.token, "expired");
    throw new Error("workflow gate presentation failed", { cause: error });
  }
  if (!store.bindMessage(entry.token, message.id)) {
    store.retire(entry.token, "expired");
    await message
      .edit(gateMessagePayload(entry, "Expired", true, false))
      .catch(() => {});
    throw new Error("workflow gate message ownership conflict");
  }
  entry.message = message;
  entry.updateState = async (state) => {
    const normalized = `${state}`.toLowerCase();
    if (normalized === "answered") store.retire(entry.token, "answered");
    else if (normalized.includes("disconnect")) {
      store.retire(entry.token, "disconnected");
    } else if (normalized.includes("replace")) {
      store.retire(entry.token, "replaced");
    } else if (
      normalized.includes("expire") ||
      normalized.includes("failed") ||
      normalized.includes("timeout") ||
      normalized.includes("reject")
    ) {
      if (normalized !== "rejected") store.retire(entry.token, "expired");
    }
    const disabled = entry.state !== "answerable";
    const label =
      normalized === "answering"
        ? "Answering"
        : normalized === "answered"
          ? "Answered"
          : normalized === "rejected"
            ? "Rejected — retry available"
            : state;
    await entry.message
      .edit(gateMessagePayload(entry, label, disabled, false))
      .catch(() => {});
  };
  return {
    messageId: message.id,
    activate() {
      if (!store.activate(entry.token)) {
        throw new Error("workflow gate presentation is no longer current");
      }
      void entry.updateState("Awaiting answer");
      return true;
    },
    update(state) {
      return entry.updateState(state);
    },
  };
}
