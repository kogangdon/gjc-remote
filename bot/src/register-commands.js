import "dotenv/config";
import { REST, Routes, SlashCommandBuilder } from "discord.js";
import { GJC_SKILLS } from "./skills.js";

const { DISCORD_TOKEN, DISCORD_CLIENT_ID, DISCORD_GUILD_ID } = process.env;

if (!DISCORD_TOKEN || !DISCORD_CLIENT_ID) {
  console.error("Missing DISCORD_TOKEN or DISCORD_CLIENT_ID in environment (.env).");
  process.exit(1);
}

// One /command per bundled GJC skill, each taking a free-form "prompt" argument
// that becomes the skill invocation payload (e.g. /ralplan prompt:"plan the auth rewrite").
const commands = GJC_SKILLS.map((skill) =>
  new SlashCommandBuilder()
    .setName(skill.name)
    .setDescription(skill.description.slice(0, 100))
    .addStringOption((opt) =>
      opt
        .setName("prompt")
        .setDescription("Arguments/objective passed to the skill")
        .setRequired(true)
    )
    .toJSON()
);

// Raw passthrough for anything not covered by a bundled skill.
commands.push(
  new SlashCommandBuilder()
    .setName("gjc")
    .setDescription("Run a direct GJC prompt (no specific workflow skill)")
    .addStringOption((opt) =>
      opt.setName("prompt").setDescription("Prompt to send").setRequired(true)
    )
    .toJSON()
);

// Runtime model switch for the GJC session bound to this channel.
commands.push(
  new SlashCommandBuilder()
    .setName("model")
    .setDescription("Switch the model used by this channel's GJC session")
    .addStringOption((opt) =>
      opt
        .setName("name")
        .setDescription("Unique model name/ID or exact provider:modelId")
        .setRequired(true)
    )
    .toJSON()
);
// Host/session visibility.
commands.push(
  new SlashCommandBuilder()
    .setName("hosts")
    .setDescription("List connected GJC host daemons and their status")
    .toJSON()
);

const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);

const route = DISCORD_GUILD_ID
  ? Routes.applicationGuildCommands(DISCORD_CLIENT_ID, DISCORD_GUILD_ID)
  : Routes.applicationCommands(DISCORD_CLIENT_ID);

const scope = DISCORD_GUILD_ID ? `guild ${DISCORD_GUILD_ID}` : "global";
console.log(`Registering ${commands.length} commands (${scope})...`);

await rest.put(route, { body: commands });

console.log("Done:", commands.map((c) => `/${c.name}`).join(", "));
