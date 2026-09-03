# Native bot deployment

Run the bot as the always-on Discord control plane with **Node.js 26 or later**.
The daemon hosts are separate deployments; they open outbound WebSocket
connections to this process.

## Prerequisites

From a checkout with its workspace dependencies installed, provide Node >=26,
Bun for workspace installation, and the native-control build prerequisites for
your approved platform. Native-control supports Linux x64/arm64 and Windows x64
only; macOS is unsupported. See the repository [local quick start](../../README.md#local-quick-start).

Run the bot under a dedicated OS account and arrange durable, access-controlled
configuration outside untrusted project trees. The bot process and mapped
channels are not tenant-isolated from one another.

## Configure

Create the protected environment file without committing it:

```sh
cp bot/.env.example bot/.env
```

Set `DISCORD_TOKEN`, `DISCORD_CLIENT_ID`, and `GJC_BOT_ALLOWED_USERS`. Keep
`GJC_REMOTE_REQUIRE_ALLOWLIST=1`; it is the shipped fail-closed default and the
bot refuses an empty allowlist. Supply runtime host-authentication tokens
through one protected startup source (`HOST_TOKENS` or `HOST_TOKENS_FILE`).
Set a unique, high-entropy token for every `hostId`; each daemon's
`HOST_TOKEN` must match its entry. Tokens authenticate daemon transport
identity only and never select a route.

Production deployment uses the authenticated management authority. Provision
its role bindings, verified native addon, control root, and initial state with
the `genesis` procedure in
[management mapping](../management-mapping-envelope.md), then perform mapping
changes through authenticated `mapping-reconcile`, `mapping-revoke`, and
`mapping-rollback` operations. Credentials and mapping payloads enter through
protected stdin; secrets never belong in arguments or audit notes. Managed
`channels.json` is generated authority state. Do not create, edit, repair, or
roll it back with an ordinary text editor.

`bot/channels.example.json` is retained only for the isolated legacy/local
quick start. A legacy route maps one channel to exact `{hostId, workDir}` and
does not become managed authority. Do not use that shortcut for a production
deployment or after managed authority history exists.

The WebSocket listener uses `HOST_WS_PORT` (default `7711`). Native foreground
configuration has no listener-address setting: protect that port at the host
firewall and private/VPN network boundary, allow only daemon hosts, and never
port-forward or expose it publicly. It is an RCE control plane, even though
all daemons authenticate with their per-host tokens.

Enable the Discord Developer Portal **Message Content Intent** for plain-chat
prompts. `DISCORD_GUILD_ID` is optional and limits command registration to one
guild for fast propagation.

## Register and start

Run both package scripts with real Node (not `bun run --bun`):

```sh
bun run --filter '@gjc-remote/bot' register
bun run --filter '@gjc-remote/bot' start
```

Register after changing application command definitions. Start the daemon(s)
separately after the bot listener is reachable. The startup log `Logged in as
...` confirms Discord client login; `HostRegistry: WS server listening on ...`
confirms that the local WebSocket listener started.

## Operate

Capture standard output/error in the service manager or centralized log system.
`GJC_REMOTE_DEBUG=1` adds Discord interaction lifecycle and relayed event
summaries; use it temporarily because operational logs must not become a secret
or host-path export channel.

Listener liveness, Discord login, mapped-route validity, daemon registration,
and workspace readiness are distinct:

- A listener log only proves that the WebSocket server could listen.
- Discord login proves the bot authenticated to Discord, not that a daemon is
  connected.
- `/hosts` and structured logs show registered daemon and readiness state.
- Readiness alone does not authorize workspace serving; preserve the fail-closed
  mapping and receipt requirements described in [daemon deployment](daemon.md).

Alert separately for bot exit, listener failure, Discord disconnects, unknown
or rejected host registrations, and absent expected daemons.

## Upgrade and rollback

1. Record the deployed revision, Node version, configuration checksum (never
   secret contents), mapping revision, and connected-host baseline.
2. Quiesce mapping changes, install the new checkout/dependencies, register
   commands when their definition changed, and restart the bot through its
   supervisor.
3. Confirm listener startup, Discord login, expected mappings, and expected
   daemon registrations before accepting traffic.
4. Roll back only the bot executable/dependency revision while retaining the
   current protected configuration. Do not restore an older managed-authority
   snapshot or start an older reader after durable authority state advanced;
   use the authority recovery contract to roll forward instead.

See [management mapping](../management-mapping-envelope.md) for durable
mapping authority and recovery limits.
