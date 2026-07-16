# gjc-remote

Discord-controlled remote GJC sessions.

## Architecture

```
[host machine, per project]                    [always-on bot host, private network]
  gjc --mode=rpc (stdio)   <--stdin/stdout-->    daemon/  --WS(outbound)-->   bot/
  (spawned on demand per                                              (WS server +
   workDir, reaped after                                               Discord client)
   1h idle)
```

1. `daemon/` runs on each machine you want to control. It connects outbound to
   `bot/`'s WebSocket server and registers with a per-host pre-shared token.
2. On the first Discord command routed to a given `workDir`, the daemon resolves
   it to the host filesystem's canonical real path and spawns `gjc --mode=rpc`
   for that directory. Different path spellings for the same directory reuse
   one live process. Idle sessions (no requests for 1 hour) are killed
   automatically.
3. `bot/` exposes mapped-channel plain chat as direct GJC prompts, plus GJC's
   bundled skills (`deep-interview`, `ralplan`, `team`, `ultragoal`), `/gjc`,
   `/model`, and `/hosts` as Discord slash commands.
4. Each Discord channel configures one `{hostId, workDir}` input via
   `bot/channels.json`. The daemon canonicalizes `workDir`, so the effective
   session identity is `(hostId, canonical workDir)`. A host only accepts
   commands while its daemon is connected — turning the daemon off makes that
   channel's commands fail fast instead of hanging.

## Setup

```bash
npm install   # installs both workspaces (bot, daemon, shared)

# On the always-on bot host:
cp bot/.env.example bot/.env        # fill in DISCORD_TOKEN, DISCORD_CLIENT_ID, HOST_TOKENS, GJC_BOT_ALLOWED_USERS
cp bot/channels.example.json bot/channels.json   # map Discord channel IDs -> {hostId, workDir}
# For shared/production deployments, set GJC_REMOTE_REQUIRE_ALLOWLIST=1.
npm run register --workspace=bot    # publish slash commands to Discord
# Enable the Discord Developer Portal "Message Content Intent" for plain chat prompts.
npm run start --workspace=bot

# On each machine you want to control:
cp daemon/.env.example daemon/.env  # fill in HOST_ID, HOST_TOKEN (must match bot's HOST_TOKENS), BOT_WS_URL
npm run start --workspace=daemon
```

Each `channels.json` route must contain exactly `hostId` and `workDir`.
`hostId` must have a matching `HOST_TOKENS` entry, and `workDir` must be a
fully-qualified path native to that daemon host (for example,
`C:/projects/foo` on Windows or `/srv/apps/foo` on Linux/macOS). Relative paths
and extra route fields are rejected.

`/model` accepts an exact `provider:modelId` (for example,
`openai-codex:gpt-5.6-sol`) or an unqualified model ID/display-name fragment.
Unqualified input is accepted only when it has one uniquely best match;
ambiguous requests fail with a bounded candidate list instead of selecting a
provider implicitly. A successful switch reports the selected display name,
provider, and model ID. It does not change the daemon's startup default.

## Verification

```bash
npm run smoke:local
# Also verify model resolution and its structured success receipt:
SMOKE_MODEL_QUERY=sol npm run smoke:local   # POSIX shell
# PowerShell: $env:SMOKE_MODEL_QUERY="sol"; npm run smoke:local
```

`smoke:local` starts a local `HostRegistry`, spawns a real daemon, routes one
prompt through `gjc --mode=rpc`, and asserts that the assistant text comes back
through the relay. When `SMOKE_MODEL_QUERY` is set, it also performs a real
model switch and requires a `model_resolved` receipt. It does not require
Discord credentials.

## Security notes

- `bot/`'s WS port only needs to be reachable from daemon hosts on your
  private network — never expose it to the public internet.
- `HOST_TOKENS`/`HOST_TOKEN` are pre-shared keys; treat them like passwords.
  Rotate per host if one is compromised.
- `GJC_BOT_ALLOWED_USERS` should be set to your own Discord user ID(s) before
  inviting the bot to any shared server — an unrestricted bot lets anyone in
  the channel run arbitrary GJC workflows (file writes, bash, etc.) on your
  hosts.
  Set `GJC_REMOTE_REQUIRE_ALLOWLIST=1` for shared/production deployments so the
  bot refuses to start with an empty allowlist. Both authorization settings are
  startup-only and require a bot restart after changes.
- Invalid `channels.json`, `HOST_TOKENS`, allowed-user entries, or strict
  allowlist flags fail before routing starts. Every mapped `hostId` must have a
  configured token. A failed `channels.json` reload keeps the last valid map.
