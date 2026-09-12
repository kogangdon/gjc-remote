import "./node-version-guard.js";
import "dotenv/config";
import { existsSync, lstatSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  Client,
  GatewayIntentBits,
} from "discord.js";
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
import { dispatchGate, resolveDispatchRoute } from "./managed-dispatch.js";
import { createManagedAuthorityReader } from "./managed-authority-reader.js";
import {
  CHUNK_LIMIT,
  NO_MENTIONS,
  createTextAttachment,
  deliverResult,
  formatDeliveryError,
} from "./delivery.js";
import { GJC_SKILLS } from "./skills.js";
import {
  GatePresentationStore,
  classifyGateReply,
  deliverGateAnswer,
} from "./gate-answer.js";
import { renderGatePresentation } from "./gate-presentation.js";
import { HostRegistry, extractAssistantText } from "./host-registry.js";
import { formatHostList } from "./host-projection.js";
import { transformModelResult, validateModelResolvedEvent } from "./model-result.js";
import { ToolLogStore } from "./tool-log-store.js";
import { InvocationOwnership } from "./invocation-ownership.js";
import {
  extractToolCall,
  formatToolLog,
  recordToolCall,
  summarizeToolCalls,
  truncate,
} from "./tool-calls.js";

import { createShutdown } from "./shutdown.js";
import { resolveBotSecrets } from "./container-secrets.js";

const {
  GJC_BOT_ALLOWED_USERS,
  GJC_REMOTE_REQUIRE_ALLOWLIST,
  CHANNELS_CONFIG,
  HOST_WS_PORT,
  GJC_INVOKE_IDLE_TIMEOUT_MS,
  GJC_INVOKE_HARD_CAP_MS,
  GJC_MANAGEMENT_ROLE_BINDINGS,
  GJC_NATIVE_WORKSPACE_SERVING,
} = process.env;
let DISCORD_TOKEN;
let HOST_TOKENS;
try {
  ({ DISCORD_TOKEN, HOST_TOKENS } = resolveBotSecrets());
} catch (error) {
  console.error(`Invalid bot environment configuration: ${error.message}`);
  process.exit(1);
}
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
let registry;
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

registry = new HostRegistry({
  port: hostWsPort,
  tokensByHostId,
  workspaceServingEnabled: GJC_NATIVE_WORKSPACE_SERVING === "1",
  ...invokeTimeoutOptions,
  onError: (error) => handleFatal("host_ws_listen_failed", error),
});
registry.setManagedRoutes(
  channelMapping.sourceKind === "managed-v1" ? channelMap : {}
);
const toolLogStore = new ToolLogStore();
// Exact initiating user/channel ownership for the Discord `/cancel` surface.
// Entries contain only opaque protocol IDs and are removed by the owning
// run's finally block, so a late interaction cannot target a successor.
const invocationOwnership = new InvocationOwnership();
const gatePresentations = new GatePresentationStore();

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent],
  allowedMentions: { parse: [] },
});

client.once("clientReady", () => {
  console.log(`Logged in as ${client.user.tag}. Channels mapped: ${Object.keys(channelMap).length}`);
});

client.on("interactionCreate", async (interaction) => {
  await dispatchAuthorizedInteraction({
    interaction,
    authorization,
    onButton: handleButtonInteraction,
    onSelect: handleGateSelectInteraction,
    onChatInput: handleChatInputInteraction,
  });
});

function noMentions(content, extra = {}) {
  return {
    ...extra,
    content,
    allowedMentions: NO_MENTIONS,
  };
}

async function handleChatInputInteraction(interaction) {
  const { commandName } = interaction;

  if (commandName === "hosts") {
    const hosts = registry.listHosts();
    await interaction.reply(noMentions(
      formatHostList(hosts)
    ));
    return;
  }
  if (commandName === "cancel") {
    const active = invocationOwnership.get(
      interaction.channelId,
      interaction.user.id
    );
    if (!active?.requestId) {
      await interaction.reply(
        noMentions("There is no active request owned by you in this channel.", {
          ephemeral: true,
        })
      );
      return;
    }
    const cancellation = registry.cancelInvoke(
      active.hostId,
      active.requestId,
      "user_cancelled"
    );
    await interaction.reply(
      noMentions(
        cancellation.ok
          ? "Cancellation requested. Interruption remains unconfirmed until the host reports a terminal outcome."
          : "Cancellation could not be correlated to an active request.",
        { ephemeral: true }
      )
    );
    return;
  }

  const routeSelection = resolveDispatchRoute(
    channelMap,
    interaction.channelId,
    channelMapping,
    (content) => interaction.reply(noMentions(content, { ephemeral: true })),
    verifyLegacyFence
  );
  if (routeSelection.status === "unmapped") {
    await interaction.reply(
      noMentions("This channel has no host/workDir mapping. Add it to channels.json.", { ephemeral: true })
    );
    return;
  }
  if (routeSelection.status === "blocked") return;
  const { route } = routeSelection;
  if (!registry.isOnline(route.hostId)) {
    await interaction.reply(noMentions(`Host '${route.hostId}' is not connected right now.`, { ephemeral: true }));
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
      await interaction.reply(
        noMentions(`Model name must be between 1 and ${V0_LIMITS.MODEL_NAME} characters.`, { ephemeral: true })
      );
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
    edit: (content) => interaction.editReply(noMentions(content)),
    deliver: (result) => deliverInteraction(interaction, commandName, result),
    onGate: (gate) =>
      renderGatePresentation({
        store: gatePresentations,
        channel: interaction.channel,
        channelId: interaction.channelId,
        hostId: route.hostId,
        gate,
        userId: interaction.user.id,
      }),
  }).catch(async (error) => {
    console.error(`Failed to handle /${commandName} interaction:`, error);
    await interaction.editReply(noMentions("GJC request failed before a result could be delivered.")).catch((editError) => {
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
  const replyToMessageId = message.reference?.messageId;
  const gateReply =
    typeof replyToMessageId === "string"
      ? classifyGateReply({
          store: gatePresentations,
          messageId: replyToMessageId,
          channelId: message.channelId,
          userId: message.author.id,
        })
      : { kind: "ordinary" };
  if (gateReply.kind === "not_owned" || gateReply.kind === "retired") {
    await message
      .reply(
        noMentions(
          gateReply.kind === "not_owned"
            ? "That gate belongs to a different initiating user. No prompt was sent."
            : "That gate is no longer answerable. No prompt was sent."
        )
      )
      .catch(() => {});
    return;
  }
  if (gateReply.kind === "answerable") {
    const gateHandled = await deliverGateAnswer({
      store: gatePresentations,
      token: gateReply.entry.token,
      messageId: replyToMessageId,
      userId: message.author.id,
      replyToMessageId,
      answer: prompt,
      answerGate: registry.answerGate.bind(registry),
      onState: (state, entry) => entry.updateState?.(state),
    });
    if (gateHandled) return;
  }
  const routeSelection = resolveDispatchRoute(
    channelMap,
    message.channelId,
    channelMapping,
    (content) => message.reply(noMentions(content)),
    verifyLegacyFence
  );
  if (routeSelection.status !== "ready") return;
  const { route } = routeSelection;

  if (!registry.isOnline(route.hostId)) {
    await message.reply(noMentions(`Host '${route.hostId}' is not connected right now.`)).catch(() => {});
    return;
  }

  const progressMessage = await message.reply(noMentions("Queued `gjc` prompt...")).catch(() => undefined);
  if (!progressMessage) return;

  await runAndDeliver({
    commandName: "chat",
    command: { kind: "prompt", message: prompt },
    route,
    requestLabel: `chat:${message.id}`,
    userId: message.author.id,
    channelId: message.channelId,
    edit: (content) => progressMessage.edit(noMentions(content)),
    deliver: (result) => deliverMessage(progressMessage, result),
    onGate: (gate) =>
      renderGatePresentation({
        store: gatePresentations,
        channel: message.channel,
        channelId: message.channelId,
        hostId: route.hostId,
        gate,
        userId: message.author.id,
      }),
  }).catch(async (error) => {
    console.error("Failed to handle message delivery:", error);
    await progressMessage.edit(noMentions("GJC request failed before a result could be delivered.")).catch((editError) => {
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
  const ownership =
    channelId === undefined || userId === undefined
      ? undefined
      : invocationOwnership.reserve(channelId, userId, route.hostId);
  if (channelId !== undefined && userId !== undefined && !ownership) {
    await edit(
      "You already have an active GJC request in this channel. Use `/cancel` to request cancellation."
    ).catch(() => {});
    return;
  }

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
  const trackedOnGate = onGate;
  try {
    if (!dispatchGate(channelMapping, edit, verifyLegacyFence)) return;
    editProgress(true);
    const managedBinding = route.authority === undefined
      ? undefined
      : registry.getManagedRouteBinding(channelId);
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

        const assistantText = extractAssistantText(evt)?.trim();
        if (assistantText) preview = assistantText;
        if (assistantText) debugRemote("assistant-text", { requestLabel, chars: assistantText.length });

        editProgress();
      },
      undefined,
      trackedOnGate,
      route.mappingId === undefined
        ? undefined
        : {
            bindingId: managedBinding?.bindingId,
            mappingId: route.mappingId,
            mappingGeneration: route.mappingGeneration,
            mappingVersion: route.mappingVersion,
            sourcePlatform: route.sourcePlatform,
            workspaceId: route.workspaceId,
            workspaceGeneration: route.workspaceGeneration,
            authority: route.authority,
          },
      (requestId) => {
        invocationOwnership.attachRequest(ownership, requestId);
      }
    );
  } finally {
    clearInterval(heartbeat);
    invocationOwnership.release(ownership);
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

function gateComponentSelection(interaction, kind) {
  const parts = `${interaction.customId ?? ""}`.split(":");
  if (parts.length !== 4 || parts[0] !== "gate" || parts[2] !== kind) {
    return undefined;
  }
  const entry = gatePresentations.get(parts[1]);
  const declaredIndex = Number(parts[3]);
  const index =
    kind === "choice"
      ? declaredIndex
      : Number(interaction.values?.[0]);
  if (
    !entry ||
    entry.state !== "answerable" ||
    entry.userId !== interaction.user.id ||
    entry.channelId !== interaction.channelId ||
    entry.messageId !== interaction.message?.id ||
    !Number.isInteger(index) ||
    index < 0 ||
    index >= (entry.choices?.length ?? 0) ||
    (kind === "select" &&
      (!Number.isInteger(declaredIndex) ||
        index < declaredIndex ||
        index >= declaredIndex + 25))
  ) {
    return undefined;
  }
  return { entry, answer: entry.choices[index].label };
}

async function handleGateComponent(interaction, kind) {
  const selection = gateComponentSelection(interaction, kind);
  if (!selection) {
    await interaction
      .reply(noMentions("This gate control is stale or is not owned by you.", {
        ephemeral: true,
      }))
      .catch(() => {});
    return;
  }
  await interaction.deferUpdate();
  await deliverGateAnswer({
    store: gatePresentations,
    token: selection.entry.token,
    messageId: interaction.message.id,
    userId: interaction.user.id,
    answer: selection.answer,
    answerGate: registry.answerGate.bind(registry),
    onState: async (state, entry) => {
      await entry.updateState?.(state);
      if (state === "rejected") {
        await interaction
          .followUp(
            noMentions(
              "That answer was rejected. The exact gate remains available for retry.",
              { ephemeral: true }
            )
          )
          .catch(() => {});
      }
    },
  });
}

async function handleGateSelectInteraction(interaction) {
  await handleGateComponent(interaction, "select");
}

async function handleButtonInteraction(interaction) {
  if (interaction.customId.startsWith("gate:")) {
    await handleGateComponent(interaction, "choice");
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
    await interaction.reply(noMentions(text, { ephemeral: true })).catch(() => {});
    return;
  }

  const file = createTextAttachment(text, "gjc-tool-log.md");
  await interaction.reply(
    noMentions(`Tool log (${entry.toolCalls.length} calls)`, {
      files: [file],
      ephemeral: true,
    })
  ).catch(() => {});
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

async function loadChannelMap({ fatal }) {
  const result = await loadManagedChannelMapState({
    current: channelMap,
    readSnapshot: readChannelMappingSnapshot,
    validate: (next) => validateChannelHosts(next, tokensByHostId),
    authoritySelection: managedAuthoritySelection,
  });

  channelMap = result.map;
  channelMapping = result.classification ?? { sourceKind: "unavailable", dispatchClass: "workspace-only", routeDisposition: "no-route" };
  registry?.setManagedRoutes(
    channelMapping.sourceKind === "managed-v1" ? channelMap : {}
  );
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
