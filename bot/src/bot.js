import "dotenv/config";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ActionRowBuilder, ButtonBuilder, ButtonStyle, Client, GatewayIntentBits } from "discord.js";
import {
  loadChannelMapState,
  parseAllowedUsers,
  parseHostTokens,
  validateChannelHosts,
} from "./config.js";
import { createAuthorizationPolicy, parseRequireAllowlist } from "./authorization.js";
import { watchConfigFile } from "./config-watcher.js";
import { CHUNK_LIMIT, createTextAttachment, deliverResult } from "./delivery.js";
import { GJC_SKILLS } from "./skills.js";
import { HostRegistry } from "./host-registry.js";
import { transformModelResult, validateModelResolvedEvent } from "./model-result.js";
import { ToolLogStore } from "./tool-log-store.js";

const {
  DISCORD_TOKEN,
  GJC_BOT_ALLOWED_USERS,
  GJC_REMOTE_REQUIRE_ALLOWLIST,
  CHANNELS_CONFIG,
  HOST_WS_PORT,
  HOST_TOKENS,
} = process.env;
const DEBUG_REMOTE = process.env.GJC_REMOTE_DEBUG === "1";

if (!DISCORD_TOKEN) {
  console.error("Missing DISCORD_TOKEN in environment (.env).");
  process.exit(1);
}

let tokensByHostId;
let authorization;
try {
  tokensByHostId = parseHostTokens(HOST_TOKENS || "");
  const allowedUsers = parseAllowedUsers(GJC_BOT_ALLOWED_USERS || "");
  const requireAllowlist = parseRequireAllowlist(GJC_REMOTE_REQUIRE_ALLOWLIST);
  authorization = createAuthorizationPolicy(allowedUsers, { required: requireAllowlist });
} catch (error) {
  console.error(`Invalid bot environment configuration: ${error.message}`);
  process.exit(1);
}

if (authorization.unrestricted) {
  console.warn(
    "SECURITY WARNING: GJC_BOT_ALLOWED_USERS is empty; every user in a mapped channel can run GJC commands."
  );
}

// channels.json: { "<discordChannelId>": { "hostId": "...", "workDir": "..." } }
const channelsPath = resolve(CHANNELS_CONFIG || fileURLToPath(new URL("../channels.json", import.meta.url)));
let channelMap;
channelMap = loadChannelMap({ fatal: true });
watchConfigFile(channelsPath, () => loadChannelMap({ fatal: false }));

const skillNames = new Set(GJC_SKILLS.map((s) => s.name));
const registry = new HostRegistry({ port: Number(HOST_WS_PORT || 7711), tokensByHostId });
const toolLogStore = new ToolLogStore();

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

  if (!authorization.isAuthorized(interaction.user.id)) {
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
  }).catch(async (error) => {
    console.error(`Failed to handle /${commandName} interaction:`, error);
    await interaction.editReply("GJC request failed before a result could be delivered.").catch((editError) => {
      console.error(`Failed to report /${commandName} interaction error:`, editError);
    });
  });
});

client.on("messageCreate", async (message) => {
  if (message.author.bot || !message.guildId) return;

  const prompt = message.content.trim();
  if (!prompt) return;

  if (!authorization.isAuthorized(message.author.id)) return;

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
  }).catch(async (error) => {
    console.error("Failed to handle message delivery:", error);
    await progressMessage.edit("GJC request failed before a result could be delivered.").catch((editError) => {
      console.error("Failed to report message delivery error:", editError);
    });
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
  let modelReceipt;

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
      const receipt = validateModelResolvedEvent(evt);
      if (receipt) modelReceipt = receipt;

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
  result = transformModelResult(command, result, modelReceipt);

  if (result) result.toolCalls = toolCalls;
  debugRemote("result", { requestLabel, ok: result?.ok, hasText: Boolean(result?.text), error: result?.error });

  await deliver(result);
}

async function deliverInteraction(interaction, commandName, result) {
  await deliverResult({
    result,
    header: result.ok ? `**/${commandName}** result:` : `**/${commandName}** failed:`,
    outputName: `${commandName}-output.md`,
    components: toolLogComponents(result.toolCalls),
    sendFirst: (payload) => interaction.editReply(payload),
    sendFollow: (payload) => interaction.followUp(payload),
  });
}

async function deliverMessage(message, result) {
  await deliverResult({
    result,
    header: result.ok ? "**GJC** result:" : "**GJC** failed:",
    outputName: "gjc-output.md",
    components: toolLogComponents(result.toolCalls),
    sendFirst: (payload) => message.edit(payload),
    sendFollow: (payload) => message.channel.send(payload),
  });
}

async function handleButtonInteraction(interaction) {
  if (!authorization.isAuthorized(interaction.user.id)) {
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
  if (text.length <= CHUNK_LIMIT) {
    await interaction.reply({ content: text, ephemeral: true }).catch(() => {});
    return;
  }

  const file = createTextAttachment(text, "gjc-tool-log.md");
  await interaction.reply({ content: `Tool log (${entry.toolCalls.length} calls)`, files: [file], ephemeral: true }).catch(() => {});
}

function toolLogComponents(toolCalls) {
  if (!Array.isArray(toolCalls) || toolCalls.length === 0) return [];
  const id = toolLogStore.add(toolCalls);

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
  toolCalls.push(toolCall);
  return true;
}

function toolCallSignature(toolCall) {
  if (toolCall.id) return JSON.stringify(["id", toolCall.id]);
  if (toolCall.label) return JSON.stringify(["label", toolCall.name, toolCall.label]);
  return JSON.stringify(["input", toolCall.name, toolCall.input]);
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
  const result = loadChannelMapState({
    current: channelMap,
    readText: () => readFileSync(channelsPath, "utf8"),
    validate: (next) => validateChannelHosts(next, tokensByHostId),
  });

  if (result.ok) {
    channelMap = result.map;
    const count = Object.keys(result.map).length;
    console.log(`Loaded channel map from ${channelsPath}: ${count} channel${count === 1 ? "" : "s"}`);
    return result.map;
  }

  const { error } = result;
  console.error(
    JSON.stringify({
      level: "error",
      event: fatal ? "channel_map_startup_failed" : "channel_map_reload_failed",
      path: channelsPath,
      error: error.message,
    })
  );
  if (fatal) process.exit(1);
  return result.map;
}
function truncate(text, maxLength) {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength - 1)}…`;
}

function debugRemote(label, data) {
  if (!DEBUG_REMOTE) return;
  console.error(`[bot] ${label}`, JSON.stringify(data));
}

client.login(DISCORD_TOKEN);
