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
2. On the first Discord command routed to a given `workDir`, the daemon spawns
   `gjc --mode=rpc` for that directory and talks to it over stdio. Subsequent
   commands for the same `workDir` reuse the live process. Idle sessions (no
   requests for 1 hour) are killed automatically.
3. `bot/` exposes GJC's bundled skills (`deep-interview`, `ralplan`, `team`,
   `ultragoal`) plus `/gjc` (direct prompt), `/model` (runtime model switch),
   and `/hosts` (connection status) as Discord slash commands.
4. Each Discord channel maps to one `(hostId, workDir)` pair via
   `bot/channels.json`. A host only accepts commands while its daemon is
   connected — turning the daemon off makes that channel's commands fail
   fast instead of hanging.

## Setup

```bash
npm install   # installs both workspaces (bot, daemon, shared)

# On the always-on bot host:
cp bot/.env.example bot/.env        # fill in DISCORD_TOKEN, DISCORD_CLIENT_ID, HOST_TOKENS
cp bot/channels.example.json bot/channels.json   # map Discord channel IDs -> {hostId, workDir}
npm run register --workspace=bot    # publish slash commands to Discord
npm run start --workspace=bot

# On each machine you want to control:
cp daemon/.env.example daemon/.env  # fill in HOST_ID, HOST_TOKEN (must match bot's HOST_TOKENS), BOT_WS_URL
npm run start --workspace=daemon
```

## Verification

```bash
npm run smoke:local
```

`smoke:local` starts a local `HostRegistry`, spawns a real daemon, routes one
prompt through `gjc --mode=rpc`, and asserts that the assistant text comes back
through the relay. It does not require Discord credentials.

## Security notes

- `bot/`'s WS port only needs to be reachable from daemon hosts on your
  private network — never expose it to the public internet.
- `HOST_TOKENS`/`HOST_TOKEN` are pre-shared keys; treat them like passwords.
  Rotate per host if one is compromised.
- `GJC_BOT_ALLOWED_USERS` should be set to your own Discord user ID(s) before
  inviting the bot to any shared server — an unrestricted bot lets anyone in
  the channel run arbitrary GJC workflows (file writes, bash, etc.) on your
  hosts.
