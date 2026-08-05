import "dotenv/config";
import { existsSync, lstatSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ActionRowBuilder, ButtonBuilder, ButtonStyle, Client, GatewayIntentBits } from "discord.js";
import { V0_LIMITS, isModelName } from "@gjc-remote/shared";
import { createManagementNative } from "@gjc-remote/native-control";
import { managedHostSetFingerprint } from "@gjc-remote/shared/mapping-envelope";
import {
  createManagedAuthoritySelection,
  loadManagedChannelMapState,
  parseAllowedUsers,
  parseHostTokensForAuthority,
  parseProvisionedManagementRoleBindings,
  readLegacyV0SourceSnapshot,
  validateChannelHosts,
  verifyLegacyV0SourceFence,
} from "./config.js";
import { createAuthorizationPolicy, parseRequireAllowlist } from "./authorization.js";
import {
  dispatchAuthorizedInteraction,
  dispatchAuthorizedMessage,
} from "./authorized-dispatch.js";
import { watchConfigHints } from "./config-watcher.js";
import { dispatchGate } from "./managed-dispatch.js";
import { createManagedAuthorityReader } from "./managed-authority-reader.js";
import { CHUNK_LIMIT, createTextAttachment, deliverResult } from "./delivery.js";
import { GJC_SKILLS } from "./skills.js";
import { HostRegistry } from "./host-registry.js";
import { transformModelResult, validateModelResolvedEvent } from "./model-result.js";
import { ToolLogStore } from "./tool-log-store.js";
import {
  extractToolCall,
  formatToolLog,
  recordToolCall,
  summarizeToolCalls,
  truncate,
} from "./tool-calls.js";

import { createShutdown } from "./shutdown.js";

const {
  DISCORD_TOKEN,
  GJC_BOT_ALLOWED_USERS,
  GJC_REMOTE_REQUIRE_ALLOWLIST,
  CHANNELS_CONFIG,
  HOST_WS_PORT,
  HOST_TOKENS,
  GJC_INVOKE_IDLE_TIMEOUT_MS,
  GJC_INVOKE_HARD_CAP_MS,
  GJC_MANAGEMENT_ROLE_BINDINGS,
} = process.env;
const DEBUG_REMOTE = process.env.GJC_REMOTE_DEBUG === "1";

if (!DISCORD_TOKEN) {
  console.error("Missing DISCORD_TOKEN in environment (.env).");
  process.exit(1);
}

// Presence of a management marker selects the strict managed token grammar.
// A malformed managed authority never falls back to the legacy parser.
const channelsPath = resolve(CHANNELS_CONFIG || fileURLToPath(new URL("../channels.json", import.meta.url)));
const controlDirectoryPath = resolve(dirname(channelsPath), ".gjc-remote-control");
const controlRootPath = resolve(controlDirectoryPath, "control-root.json");
const bootstrapBlockerPath = resolve(dirname(channelsPath), `.${basename(channelsPath)}.genesis-bootstrap-blocker`);
const managedHistoryMarkerPath = resolve(dirname(channelsPath), `.${basename(channelsPath)}.managed-history.json`);
const managedAuthoritySelection = createManagedAuthoritySelection();

function managedHistoryMarkerPresent() {
  try {
    lstatSync(managedHistoryMarkerPath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    // Inability to inspect the durable discriminator is itself fail-closed.
    return true;
  }
}
function bootstrapBlockerPresent() {
  try {
    lstatSync(bootstrapBlockerPath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    // Inability to inspect the bootstrap blocker is itself fail-closed.
    return true;
  }
}

function observeManagementAuthority() {
  managedAuthoritySelection.observe({
    managementMarkerPresent: existsSync(controlDirectoryPath) || existsSync(controlRootPath) || bootstrapBlockerPresent(),
    managedHistoryMarkerPresent: managedHistoryMarkerPresent(),
  });
  return managedAuthoritySelection.observed;
}

let provisionedManagementRoleBindings = null;
let tokensByHostId;
let authorization;
try {
  observeManagementAuthority();
  if (GJC_MANAGEMENT_ROLE_BINDINGS?.trim()) {
    provisionedManagementRoleBindings = parseProvisionedManagementRoleBindings(GJC_MANAGEMENT_ROLE_BINDINGS);
    try {
      const native = await createManagementNative({
        configPath: channelsPath,
        roles: provisionedManagementRoleBindings,
      });
      managedAuthoritySelection.observe({
        managedHistoryMarkerPresent: (await native.readManagedHistoryMarker()) !== null,
      });
    } catch {
      // A configured management authority whose durable marker cannot be read
      // must not use legacy parsing.
      managedAuthoritySelection.observe({ managedHistoryMarkerPresent: true });
    }
  }
  tokensByHostId = parseHostTokensForAuthority(HOST_TOKENS || "", managedAuthoritySelection.observed);
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

// channels.json is legacy-v0 only when every management marker is absent.
const managedAuthorityReader = await createManagedAuthorityReader({
  configPath: channelsPath,
  expectedHostSetFingerprint: managedHostSetFingerprint(tokensByHostId),
  roleBindings: provisionedManagementRoleBindings,
});
let channelMap;
let channelMapping;
channelMap = await loadChannelMap({ fatal: true });
watchConfigHints(
  [channelsPath, managedHistoryMarkerPath, bootstrapBlockerPath],
  () => {
    const authorityWasObserved = managedAuthoritySelection.observed;
    observeManagementAuthority();
    if (!authorityWasObserved && managedAuthoritySelection.observed) {
      console.error("Managed authority appeared; restarting to activate strict HOST_TOKENS parsing.");
      fatalExitCode = 78;
      requestShutdown("managed-authority-emerged");
      return;
    }
    void loadChannelMap({ fatal: false });
  },
  { directoryPaths: [controlDirectoryPath], existsSyncFn: existsSync }
);

const skillNames = new Set(GJC_SKILLS.map((s) => s.name));
const invokeTimeoutOptions = {};
function readInvokeTimeoutEnv(raw, key, envName) {
  if (raw === undefined || `${raw}`.trim() === "") return;
  const parsed = Number(raw);
  if (Number.isFinite(parsed) && parsed > 0) {
    invokeTimeoutOptions[key] = parsed;
    return;
  }
  console.warn(
    `Ignoring ${envName}=${JSON.stringify(raw)}: not a positive duration; using the default.`
  );
}
readInvokeTimeoutEnv(GJC_INVOKE_IDLE_TIMEOUT_MS, "invokeIdleTimeoutMs", "GJC_INVOKE_IDLE_TIMEOUT_MS");
readInvokeTimeoutEnv(GJC_INVOKE_HARD_CAP_MS, "invokeHardCapMs", "GJC_INVOKE_HARD_CAP_MS");
const sensitiveFatalValues = [DISCORD_TOKEN, ...tokensByHostId.values()]
  .filter((value) => typeof value === "string" && value.length > 0);
let shutdown;
let shutdownInitiated = false;
let fatalExitCode;
let fatalReported = false;
let fatalExitTimer;

function sanitizeFatalError(error) {
  let message = error instanceof Error ? String(error.message) : String(error);
  for (const secret of sensitiveFatalValues) {
    message = message.split(secret).join("[redacted]");
  }
  message = message
    .replace(/:\/\/[^/\s@]+@/g, "://[redacted]@")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (message.length === 0) message = "unknown error";
  return message.slice(0, 500);
}
function exitBot(code) {
  const exitCode = fatalExitCode ?? code;
  if (fatalExitCode === undefined) {
    process.exit(exitCode);
    return;
  }
  process.exitCode = exitCode;
  if (fatalExitTimer) return;
  fatalExitTimer = setTimeout(() => process.exit(exitCode), 100);
}

// The first shutdown trigger owns exit semantics. A later fatal event must not
// override a signal's required 0.
function requestShutdown(signal) {
  shutdownInitiated = true;
  void shutdown?.(signal);
}

function handleFatal(event, error) {
  if (fatalReported) return;
  fatalReported = true;
  if (!shutdownInitiated) fatalExitCode = 1;
  console.error(JSON.stringify({
    level: "error",
    event,
    error: sanitizeFatalError(error),
  }));
  requestShutdown(event);
}

let hostWsPort;
try {
  const rawPort = HOST_WS_PORT === undefined ? undefined : `${HOST_WS_PORT}`;
  hostWsPort = rawPort?.trim() === "" || rawPort === undefined ? 7711 : Number(rawPort);
  if (!Number.isInteger(hostWsPort) || hostWsPort < 1 || hostWsPort > 65535) {
    throw new Error("HOST_WS_PORT must be an integer between 1 and 65535");
  }
} catch (error) {
  handleFatal("host_ws_port_invalid", error);
  process.exit(1);
}

const registry = new HostRegistry({
  port: hostWsPort,
  tokensByHostId,
  ...invokeTimeoutOptions,
  onError: (error) => handleFatal("host_ws_listen_failed", error),
});
const toolLogStore = new ToolLogStore();
// #35: channelId -> { hostId, requestId, gateId } for a workflow gate currently
// awaiting a user's answer in that channel. While an entry exists, the next
// message in the channel is routed to the daemon as the gate answer rather than
// starting a new prompt. Cleared when answered or when the invoke settles.
const pendingGateByChannel = new Map();

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent],
});

client.once("clientReady", () => {
  console.log(`Logged in as ${client.user.tag}. Channels mapped: ${Object.keys(channelMap).length}`);
});

client.on("interactionCreate", async (interaction) => {
  await dispatchAuthorizedInteraction({
    interaction,
    authorization,
    onButton: handleButtonInteraction,
    onChatInput: handleChatInputInteraction,
  });
});

async function handleChatInputInteraction(interaction) {
  const { commandName } = interaction;
  if (!dispatchGate(channelMapping, (content) => interaction.reply({ content, ephemeral: true }), verifyLegacyFence)) return;

  if (commandName === "hosts") {
    if (!dispatchGate(channelMapping, (content) => interaction.reply({ content, ephemeral: true }), verifyLegacyFence)) return;
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

  if (!dispatchGate(channelMapping, (content) => interaction.reply({ content, ephemeral: true }), verifyLegacyFence)) return;
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
    if (!isModelName(name)) {
      await interaction.reply({
        content: `Model name must be between 1 and ${V0_LIMITS.MODEL_NAME} characters.`,
        ephemeral: true,
      });
      return;
    }
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
}

client.on("messageCreate", async (message) => {
  await dispatchAuthorizedMessage({
    message,
    authorization,
    onMessage: handleAuthorizedMessage,
  });
});

async function handleAuthorizedMessage(message) {
  const prompt = message.content.trim();
  if (!prompt) return;
  if (!dispatchGate(channelMapping, (content) => message.reply(content), verifyLegacyFence)) return;

  const route = channelMap[message.channelId];
  if (!route) return;

  // #35: if a workflow gate is awaiting an answer in this channel, route this
  // message to the daemon as the gate answer instead of starting a new prompt.
  const pendingGate = pendingGateByChannel.get(message.channelId);
  if (pendingGate) {
    pendingGateByChannel.delete(message.channelId);
    const result = registry.answerGate(
      pendingGate.hostId,
      pendingGate.requestId,
      pendingGate.gateId,
      prompt
    );
    if (result.ok) {
      await message.react("✅").catch(() => {});
      return;
    }
    // #35: the gate is stale (e.g. the run already resumed without our answer, or
    // the host dropped). Rather than swallow the user's message, fall through and
    // treat it as an ordinary prompt.
    console.warn(
      `gjc-remote bot: stale gate answer for channel ${message.channelId}: ${result.error}; treating as a new prompt.`
    );
  }

  if (!dispatchGate(channelMapping, (content) => message.reply(content), verifyLegacyFence)) return;
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
    onGate: (gate) => renderGateToChannel(message.channel, message.channelId, route.hostId, gate),
  }).catch(async (error) => {
    console.error("Failed to handle message delivery:", error);
    await progressMessage.edit("GJC request failed before a result could be delivered.").catch((editError) => {
      console.error("Failed to report message delivery error:", editError);
    });
  });
}

async function runAndDeliver({ commandName, command, route, requestLabel, userId, channelId, edit, deliver, onGate }) {
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
  const toolCallIndex = new Map();
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
  // #35: the requestId of a gate this invoke raises, so the leaked-marker guard
  // in `finally` only clears a marker THIS invoke owns (a concurrent invoke on
  // the same channel must not have its live marker cross-deleted).
  let ownedGateRequestId;
  const trackedOnGate = onGate
    ? (gate) => {
        ownedGateRequestId = gate.requestId;
        return onGate(gate);
      }
    : undefined;
  try {
    if (!dispatchGate(channelMapping, edit, verifyLegacyFence)) return;
    editProgress(true);
    if (!dispatchGate(channelMapping, edit, verifyLegacyFence)) return;
    result = await registry.invoke(
      route.hostId,
      route.workDir,
      command,
      (evt) => {
        const receipt = validateModelResolvedEvent(evt);
        if (receipt) modelReceipt = receipt;

        const toolCall = extractToolCall(evt);
        if (toolCall && recordToolCall(toolCalls, toolCallIndex, toolCall)) {
          debugRemote("tool-call", { requestLabel, name: toolCall.name, label: toolCall.label });
        }

        const assistantText = extractAssistantText(evt);
        if (assistantText) preview = assistantText;
        if (assistantText) debugRemote("assistant-text", { requestLabel, chars: assistantText.length });

        editProgress();
      },
      undefined,
      trackedOnGate
    );
  } finally {
    clearInterval(heartbeat);
    // #35: an invoke never settles with a gate still pending, but guard against a
    // leaked marker (timeout/hard-cap mid-gate) so a later message is not
    // misrouted as a stale answer. Only clear a marker this invoke owns.
    if (channelId !== undefined && ownedGateRequestId !== undefined) {
      const marker = pendingGateByChannel.get(channelId);
      if (marker && marker.requestId === ownedGateRequestId) {
        pendingGateByChannel.delete(channelId);
      }
    }
  }
  result = transformModelResult(command, result, modelReceipt);

  if (result) result.toolCalls = toolCalls;
  debugRemote("result", { requestLabel, ok: result?.ok, hasText: Boolean(result?.text), error: result?.error });

  await deliver(result);
}

// #35: render a workflow gate to its Discord channel and register the pending
// state so the next message in the channel is routed back as the answer. The
// marker is registered before the (async) send so an immediate reply is not lost.
function renderGateToChannel(channel, channelId, hostId, gate) {
  pendingGateByChannel.set(channelId, {
    hostId,
    requestId: gate.requestId,
    gateId: gate.gateId,
  });
  const lines = [`**GJC needs your input** (${gate.kind}):`, gate.prompt];
  if (Array.isArray(gate.choices) && gate.choices.length > 0) {
    gate.choices.forEach((choice, index) => {
      lines.push(`**${index + 1}.** ${choice.label}`);
    });
    lines.push("_Reply with the option number or its exact text._");
  } else {
    lines.push("_Reply in this channel with your answer._");
  }
  return channel.send(lines.join("\n")).catch((error) => {
    console.error("Failed to render workflow gate:", error);
  });
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

async function loadChannelMap({ fatal }) {
  const result = await loadManagedChannelMapState({
    current: channelMap,
    readSnapshot: readChannelMappingSnapshot,
    validate: (next) => validateChannelHosts(next, tokensByHostId),
    authoritySelection: managedAuthoritySelection,
  });

  channelMap = result.map;
  channelMapping = result.classification ?? { sourceKind: "unavailable", dispatchClass: "workspace-only", routeDisposition: "no-route" };
  if (result.ok) {
    const count = Object.keys(result.map).length;
    console.log(`Loaded channel map from ${channelsPath}: ${count} channel${count === 1 ? "" : "s"}`);
    return result.map;
  }

  if (channelMapping.sourceKind === "unavailable") {
    console.error(JSON.stringify({
      level: "error",
      event: fatal ? "workspace_mapping_startup_unavailable" : "workspace_mapping_reload_unavailable",
      code: channelMapping.code,
    }));
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

function readChannelMappingSnapshot() {
  let legacySnapshot;
  try {
    legacySnapshot = readLegacyV0SourceSnapshot({
      targetPath: channelsPath,
      controlDirectoryPath,
      controlRootPath,
      managedHistoryMarkerPath,
      bootstrapBlockerPath,
    });
  } catch {
    // A source or marker inspection failure must not reopen legacy-v0.
    managedAuthoritySelection.observe({ managedHistoryMarkerPresent: true });
  }

  if (legacySnapshot) {
    managedAuthoritySelection.observe(legacySnapshot);
    if (legacySnapshot.legacyV0Verified === true && !managedAuthoritySelection.observed) {
      return legacySnapshot;
    }
  }

  return managedAuthorityReader.readSnapshot().then((snapshot) => {
    managedAuthoritySelection.observe(snapshot);
    return {
      ...snapshot,
      managementMarkerPresent: managedAuthoritySelection.observed,
    };
  });
}

function verifyLegacyFence(fence) {
  return verifyLegacyV0SourceFence({
    targetPath: channelsPath,
    controlDirectoryPath,
    controlRootPath,
    managedHistoryMarkerPath,
    bootstrapBlockerPath,
  }, fence);
}

function debugRemote(label, data) {
  if (!DEBUG_REMOTE) return;
  console.error(`[bot] ${label}`, JSON.stringify(data));
}

shutdown = createShutdown({
  registry,
  client,
  exit: exitBot,
});
// Register signal handlers before login so a signal received mid-login still
// triggers a graceful shutdown instead of the default abrupt termination.
process.on("SIGINT", () => requestShutdown("SIGINT"));
process.on("SIGTERM", () => requestShutdown("SIGTERM"));
process.on("unhandledRejection", (reason) => handleFatal("unhandled_rejection", reason));
process.on("uncaughtException", (error) => handleFatal("uncaught_exception", error));

try {
  Promise.resolve(client.login(DISCORD_TOKEN)).catch((error) => {
    handleFatal("discord_login_failed", error);
  });
} catch (error) {
  handleFatal("discord_login_failed", error);
}
