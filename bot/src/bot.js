import "dotenv/config";
import { existsSync, readFileSync, statSync, watch } from "node:fs";
import { fileURLToPath } from "node:url";
import { ActionRowBuilder, AttachmentBuilder, ButtonBuilder, ButtonStyle, Client, GatewayIntentBits } from "discord.js";
import { GJC_SKILLS } from "./skills.js";
import { HostRegistry } from "./host-registry.js";

const {
  DISCORD_TOKEN,
  GJC_BOT_ALLOWED_USERS,
  CHANNELS_CONFIG,
  HOST_WS_PORT,
  HOST_TOKENS,
} = process.env;
const DEBUG_REMOTE = process.env.GJC_REMOTE_DEBUG === "1";

if (!DISCORD_TOKEN) {
  console.error("Missing DISCORD_TOKEN in environment (.env).");
  process.exit(1);
}

// channels.json: { "<discordChannelId>": { "hostId": "...", "workDir": "..." } }
const channelsPath = CHANNELS_CONFIG || fileURLToPath(new URL("../channels.json", import.meta.url));
let channelMap;
channelMap = loadChannelMap({ fatal: true });
let channelWatchTimer;
watch(channelsPath, { persistent: false }, () => {
  clearTimeout(channelWatchTimer);
  channelWatchTimer = setTimeout(() => loadChannelMap({ fatal: false }), 250);
});

// HOST_TOKENS: "hostId1:token1,hostId2:token2" — pre-shared keys daemons must present on register.
const tokensByHostId = new Map(
  (HOST_TOKENS || "")
    .split(",")
    .map((pair) => pair.trim())
    .filter(Boolean)
    .map((pair) => {
      const [hostId, token] = pair.split(":");
      return [hostId, token];
    })
);

const allowedUsers = (GJC_BOT_ALLOWED_USERS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const skillNames = new Set(GJC_SKILLS.map((s) => s.name));
const registry = new HostRegistry({ port: Number(HOST_WS_PORT || 7711), tokensByHostId });
const toolLogStore = new Map();
let toolLogSeq = 0;

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent],
});

client.once("clientReady", () => {
  console.log(`Logged in as ${client.user.tag}. Channels mapped: ${Object.keys(channelMap).length}`);
});

client.on("interactionCreate", async (interaction) => {
  if (interaction.isButton()) {
    await handleButtonInteraction(interaction);
    return;
  }

  if (!interaction.isChatInputCommand()) return;

  if (allowedUsers.length > 0 && !allowedUsers.includes(interaction.user.id)) {
    await interaction.reply({ content: "You are not authorized to run GJC commands.", ephemeral: true });
    return;
  }

  const { commandName } = interaction;

  if (commandName === "hosts") {
    const online = registry.listOnline();
    await interaction.reply(online.length ? `Online: ${online.join(", ")}` : "No hosts connected.");
    return;
  }

  const route = channelMap[interaction.channelId];
  if (!route) {
    await interaction.reply({
      content: "This channel has no host/workDir mapping. Add it to channels.json.",
      ephemeral: true,
    });
    return;
  }

  if (!registry.isOnline(route.hostId)) {
    await interaction.reply({ content: `Host '${route.hostId}' is not connected right now.`, ephemeral: true });
    return;
  }

  const isSkill = skillNames.has(commandName);
  const isModel = commandName === "model";
  const isDirect = commandName === "gjc";
  if (!isSkill && !isModel && !isDirect) return;

  let command;
  if (isModel) {
    const name = interaction.options.getString("name", true);
    command = { kind: "set_model", modelName: name };
  } else {
    const promptArg = interaction.options.getString("prompt", true);
    const message = isSkill ? `/skill:${commandName} ${promptArg}` : promptArg;
    command = { kind: "prompt", message };
  }

  await interaction.deferReply();
  await runAndDeliver({
    commandName,
    command,
    route,
    requestLabel: `${commandName}:${interaction.id}`,
    userId: interaction.user.id,
    channelId: interaction.channelId,
    edit: (content) => interaction.editReply(content),
    deliver: (result) => deliverInteraction(interaction, commandName, result),
  });
});

client.on("messageCreate", async (message) => {
  if (message.author.bot || !message.guildId) return;

  const prompt = message.content.trim();
  if (!prompt) return;

  if (allowedUsers.length > 0 && !allowedUsers.includes(message.author.id)) return;

  const route = channelMap[message.channelId];
  if (!route) return;

  if (!registry.isOnline(route.hostId)) {
    await message.reply(`Host '${route.hostId}' is not connected right now.`).catch(() => {});
    return;
  }

  const progressMessage = await message.reply("Queued `gjc` prompt...").catch(() => undefined);
  if (!progressMessage) return;

  await runAndDeliver({
    commandName: "chat",
    command: { kind: "prompt", message: prompt },
    route,
    requestLabel: `chat:${message.id}`,
    userId: message.author.id,
    channelId: message.channelId,
    edit: (content) => progressMessage.edit(content),
    deliver: (result) => deliverMessage(progressMessage, result),
  });
});

async function runAndDeliver({ commandName, command, route, requestLabel, userId, channelId, edit, deliver }) {
  debugRemote("request", {
    requestLabel,
    userId,
    channelId,
    hostId: route.hostId,
    workDir: route.workDir,
    kind: command.kind,
  });

  let lastEdit = 0;
  const startedAt = Date.now();
  const toolCalls = [];
  const seenToolCalls = new Set();

  let preview = "";
  const editProgress = (force = false) => {
    const now = Date.now();
    if (!force && now - lastEdit < 4000) return;
    lastEdit = now;

    const elapsed = Math.max(1, Math.round((now - startedAt) / 1000));
    const details = [];
    if (toolCalls.length > 0) details.push(`tools: ${summarizeToolCalls(toolCalls)}`);
    if (preview) details.push(`latest: ${truncate(preview, 500)}`);

    const suffix = details.length > 0 ? `\n${details.join("\n")}` : "";
    edit(`Running \`${commandName}\`... (${elapsed}s elapsed)${suffix}`).catch(() => {});
  };

  const heartbeat = setInterval(() => editProgress(), 4000);
  heartbeat.unref?.();

  let result;
  try {
    editProgress(true);
    result = await registry.invoke(route.hostId, route.workDir, command, (evt) => {

      const toolCall = extractToolCall(evt);
      if (toolCall && recordToolCall(toolCalls, seenToolCalls, toolCall)) {
        debugRemote("tool-call", { requestLabel, name: toolCall.name, label: toolCall.label });
      }

      const assistantText = extractAssistantText(evt);
      if (assistantText) preview = assistantText;
      if (assistantText) debugRemote("assistant-text", { requestLabel, chars: assistantText.length });

      editProgress();
    });
  } finally {
    clearInterval(heartbeat);
  }

  if (result) result.toolCalls = toolCalls;
  debugRemote("result", { requestLabel, ok: result?.ok, hasText: Boolean(result?.text), error: result?.error });

  await deliver(result);
}

async function deliverInteraction(interaction, commandName, result) {
  const header = result.ok ? `**/${commandName}** result:` : `**/${commandName}** failed:`;
  const text = result.ok ? result.text ?? "(no text output)" : result.error ?? "unknown error";
  const body = `${header}\n${text}`;

  const attachments = collectLocalAttachments(text, `${commandName}-attachment`);
  const components = toolLogComponents(result.toolCalls);
  if (attachments.length > 0) {
    const content = `${header} (attached ${attachments.length} file${attachments.length === 1 ? "" : "s"})`;
    await interaction.editReply({ content, files: attachments, components }).catch(() => {});
    return;
  }

  if (body.length <= 1900) {
    await interaction.editReply({ content: body, components }).catch(() => {});
    return;
  }

  const file = new AttachmentBuilder(Buffer.from(text, "utf8"), { name: `${commandName}-output.md` });
  await interaction
    .editReply({ content: `${header} (output attached, ${text.length} chars)`, files: [file], components })
    .catch(() => {});
}

async function deliverMessage(message, result) {
  const header = result.ok ? "**GJC** result:" : "**GJC** failed:";
  const text = result.ok ? result.text ?? "(no text output)" : result.error ?? "unknown error";
  const body = `${header}\n${text}`;

  const attachments = collectLocalAttachments(text, "gjc-attachment");
  const components = toolLogComponents(result.toolCalls);
  if (attachments.length > 0) {
    const content = `${header} (attached ${attachments.length} file${attachments.length === 1 ? "" : "s"})`;
    await message.edit({ content, files: attachments, components }).catch(() => {});
    return;
  }

  if (body.length <= 1900) {
    await message.edit({ content: body, components }).catch(() => {});
    return;
  }

  const file = new AttachmentBuilder(Buffer.from(text, "utf8"), { name: "gjc-output.md" });
  await message.edit({ content: `${header} (output attached, ${text.length} chars)`, files: [file], components }).catch(() => {});
}


async function handleButtonInteraction(interaction) {
  if (allowedUsers.length > 0 && !allowedUsers.includes(interaction.user.id)) {
    await interaction.reply({ content: "You are not authorized to view GJC tool logs.", ephemeral: true }).catch(() => {});
    return;
  }

  if (!interaction.customId.startsWith("tool-log:")) return;
  const id = interaction.customId.slice("tool-log:".length);
  const entry = toolLogStore.get(id);
  if (!entry) {
    await interaction.reply({ content: "Tool log is no longer available.", ephemeral: true }).catch(() => {});
    return;
  }

  const text = formatToolLog(entry.toolCalls);
  if (text.length <= 1900) {
    await interaction.reply({ content: text, ephemeral: true }).catch(() => {});
    return;
  }

  const file = new AttachmentBuilder(Buffer.from(text, "utf8"), { name: "gjc-tool-log.md" });
  await interaction.reply({ content: `Tool log (${entry.toolCalls.length} calls)`, files: [file], ephemeral: true }).catch(() => {});
}

function toolLogComponents(toolCalls) {
  if (!Array.isArray(toolCalls) || toolCalls.length === 0) return [];
  const id = String(++toolLogSeq);
  toolLogStore.set(id, { toolCalls, createdAt: Date.now() });
  pruneToolLogs();

  return [
    new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId(`tool-log:${id}`)
        .setLabel(`View tool log (${toolCalls.length})`)
        .setStyle(ButtonStyle.Secondary)
    ),
  ];
}

function formatToolLog(toolCalls) {
  return toolCalls
    .map((call, index) => {
      const input = call.input === undefined ? "" : `\n\`\`\`json\n${JSON.stringify(call.input, null, 2)}\n\`\`\``;
      return `**${index + 1}. ${call.name}**${call.label ? ` — ${call.label}` : ""}${input}`;
    })
    .join("\n\n");
}

function summarizeToolCalls(toolCalls) {
  return toolCalls
    .slice(-5)
    .map((call, index, recent) => {
      const number = toolCalls.length - recent.length + index + 1;
      const label = call.label ? ` ${truncate(call.label, 60)}` : "";
      return `#${number} \`${call.name}\`${label}`;
    })
    .join("; ");
}

function recordToolCall(toolCalls, seenToolCalls, toolCall) {
  const signature = toolCallSignature(toolCall);
  if (seenToolCalls.has(signature)) return false;

  seenToolCalls.add(signature);
  toolCalls.push({ ...toolCall, signature });
  return true;
}

function toolCallSignature(toolCall) {
  if (toolCall.id) return JSON.stringify(["id", toolCall.id]);
  if (toolCall.label) return JSON.stringify(["label", toolCall.name, toolCall.label]);
  return JSON.stringify(["input", toolCall.name, toolCall.input]);
}

function pruneToolLogs() {
  const cutoff = Date.now() - 60 * 60 * 1000;
  for (const [id, entry] of toolLogStore) {
    if (entry.createdAt < cutoff || toolLogStore.size > 100) toolLogStore.delete(id);
  }
}

function collectLocalAttachments(text, baseName) {
  const paths = extractLocalAttachmentPaths(text);
  return paths.map((filePath, index) => new AttachmentBuilder(filePath, { name: attachmentName(filePath, baseName, index) }));
}

function extractLocalAttachmentPaths(text) {
  const candidates = new Set();
  const patterns = [
    /[A-Za-z]:\\[^\r\n"'<>|?*]+?\.(?:png|jpe?g|webp|gif|txt|md|json|csv|log|pdf|zip)/gi,
    /\/[^\s"'<>]+?\.(?:png|jpe?g|webp|gif|txt|md|json|csv|log|pdf|zip)/gi,
  ];

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      candidates.add(match[0].replace(/[),.;:]+$/g, ""));
    }
  }

  return [...candidates].filter((filePath) => {
    try {
      if (!existsSync(filePath)) return false;
      const stat = statSync(filePath);
      return stat.isFile() && stat.size > 0 && stat.size <= 25 * 1024 * 1024;
    } catch {
      return false;
    }
  });
}

function attachmentName(filePath, baseName, index) {
  const normalized = filePath.replaceAll("\\", "/");
  const original = normalized.slice(normalized.lastIndexOf("/") + 1);
  return original || `${baseName}-${index + 1}`;
}


function extractToolCall(evt) {
  if (evt?.type === "toolCall" && typeof evt.name === "string") return normalizeToolCall(evt);

  const content = Array.isArray(evt?.message?.content) ? evt.message.content : [];
  const call = content.find((part) => part?.type === "toolCall" && typeof part.name === "string");
  return call ? normalizeToolCall(call) : undefined;
}

function normalizeToolCall(call) {
  const input = call.input ?? call.arguments ?? call.args ?? call.parameters;
  return {
    id: call.id ?? call.toolCallId ?? call.callId,
    name: call.name,
    label: toolInputLabel(input),
    input,
  };
}

function toolInputLabel(input) {
  if (!input || typeof input !== "object") return typeof input === "string" ? truncate(input, 80) : "";
  const label = input._i ?? input.command ?? input.path ?? input.pattern ?? input.subject ?? input.name ?? input.action;
  return typeof label === "string" ? label : "";
}
function extractAssistantText(evt) {
  const message = evt?.message ?? evt?.assistantMessageEvent?.message;
  if (message?.role !== "assistant") return "";

  return extractTextFromContent(message.content).trim();
}

function extractTextFromContent(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";

  return content
    .map((part) => {
      if (typeof part === "string") return part;
      if (!part || typeof part !== "object") return "";
      if (typeof part.text === "string") return part.text;
      if (typeof part.value === "string") return part.value;
      if (typeof part.content === "string") return part.content;
      return "";
    })
    .join("");
}

function loadChannelMap({ fatal }) {
  try {
    const nextMap = JSON.parse(readFileSync(channelsPath, "utf8"));
    const count = Object.keys(nextMap).length;
    channelMap = nextMap;
    console.log(`Loaded channel map from ${channelsPath}: ${count} channel${count === 1 ? "" : "s"}`);
    return nextMap;
  } catch (err) {
    console.error(`Missing/invalid channel map at ${channelsPath} (copy channels.example.json).`, err.message);
    if (fatal) process.exit(1);
    return channelMap;
  }
}
function truncate(text, maxLength) {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength - 1)}…`;
}

function debugRemote(label, data) {
  if (!DEBUG_REMOTE) return;
  console.error(`[bot] ${label}`, JSON.stringify(data));
}

client.login(DISCORD_TOKEN);
