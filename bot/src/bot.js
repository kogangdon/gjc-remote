import "dotenv/config";
import { readFileSync } from "node:fs";
import { Client, GatewayIntentBits, AttachmentBuilder } from "discord.js";
import { GJC_SKILLS } from "./skills.js";
import { HostRegistry } from "./host-registry.js";

const {
  DISCORD_TOKEN,
  GJC_BOT_ALLOWED_USERS,
  CHANNELS_CONFIG,
  HOST_WS_PORT,
  HOST_TOKENS,
} = process.env;

if (!DISCORD_TOKEN) {
  console.error("Missing DISCORD_TOKEN in environment (.env).");
  process.exit(1);
}

// channels.json: { "<discordChannelId>": { "hostId": "...", "workDir": "..." } }
const channelsPath = CHANNELS_CONFIG || new URL("../channels.json", import.meta.url).pathname;
let channelMap;
try {
  channelMap = JSON.parse(readFileSync(channelsPath, "utf8"));
} catch (err) {
  console.error(`Missing/invalid channel map at ${channelsPath} (copy channels.example.json).`, err.message);
  process.exit(1);
}

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

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once("clientReady", () => {
  console.log(`Logged in as ${client.user.tag}. Channels mapped: ${Object.keys(channelMap).length}`);
});

client.on("interactionCreate", async (interaction) => {
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

  await interaction.deferReply();

  let command;
  if (isModel) {
    const name = interaction.options.getString("name", true);
    command = { kind: "set_model", modelName: name };
  } else {
    const promptArg = interaction.options.getString("prompt", true);
    const message = isSkill ? `/skill:${commandName} ${promptArg}` : promptArg;
    command = { kind: "prompt", message };
  }

  let lastEdit = 0;
  const progress = [];
  const result = await registry.invoke(route.hostId, route.workDir, command, (evt) => {
    if (evt.type === "toolCall" || (evt.message?.content || []).some((c) => c.type === "toolCall")) {
      const call = evt.message?.content?.find((c) => c.type === "toolCall");
      if (call?.name) progress.push(`\`${call.name}\``);
    }
    const now = Date.now();
    if (now - lastEdit > 4000 && progress.length > 0) {
      lastEdit = now;
      interaction.editReply(`Running \`${commandName}\`... (${progress.slice(-8).join(", ")})`).catch(() => {});
    }
  });

  await deliver(interaction, commandName, result);
});

async function deliver(interaction, commandName, result) {
  const header = result.ok ? `**/${commandName}** result:` : `**/${commandName}** failed:`;
  const text = result.ok ? result.text ?? "(no text output)" : result.error ?? "unknown error";
  const body = `${header}\n${text}`;

  if (body.length <= 1900) {
    await interaction.editReply(body).catch(() => {});
    return;
  }

  const file = new AttachmentBuilder(Buffer.from(text, "utf8"), { name: `${commandName}-output.md` });
  await interaction
    .editReply({ content: `${header} (output attached, ${text.length} chars)`, files: [file] })
    .catch(() => {});
}

client.login(DISCORD_TOKEN);
