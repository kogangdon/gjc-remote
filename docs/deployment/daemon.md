# Native daemon deployment

Run one daemon on each host that owns mapped work directories. It embeds the
pinned `@gajae-code/coding-agent` SDK **0.12.21** and requires **Bun 1.3.14 or
later**. The daemon is not a bot sidecar: it opens an authenticated outbound
WebSocket connection to the independently deployed bot.

## Prerequisites and provider identity

Install the workspace dependencies from the committed lockfile, Bun >=1.3.14,
and the native-control prerequisites for the host. Approved native-control
tuples are Linux x64/arm64 and Windows x64; macOS is unsupported.

Run the service as a dedicated daemon OS account. Before starting the service,
log into the provider interactively as that same account:

```sh
gjc
# then: /login <provider>
```

The provider credential and model configuration are retained in that account's
`~/.gjc`; every SDK session created by the daemon reuses them. Do not copy this
directory, a provider token, or another user's home directory into a service
account. The daemon's normal model profile comes from `~/.gjc/agent/config.yml`
(`modelProfile.default`); `GJC_MODEL_PROFILE` can select a configured profile.
A missing or unusable provider/profile fails session creation rather than
silently selecting another identity.

## Configure and start

Create a protected local file, then set the required values:

```sh
cp daemon/.env.example daemon/.env
bun run --filter '@gjc-remote/daemon' start
```

Required settings are:

- `HOST_ID`: unique daemon identity, matching a bot mapping and bot token entry.
- `HOST_TOKEN`: the high-entropy token for that `HOST_ID`; it must match the
  bot's `HOST_TOKENS` value.
- `BOT_WS_URL`: private-network `ws://` or `wss://` endpoint of the bot
  listener.

`HOST_LABEL` is optional and is shown in bot connection logs. Restrict the
file and account environment so tokens cannot leak through process inspection,
logs, backups, or support archives. An outbound connection does not remove the
need to restrict ingress to the bot listener; it means daemon hosts need only
reach that private endpoint.

Do not run the daemon as a user chosen merely for convenience. Its provider
identity, `~/.gjc` state, and filesystem permissions define the work it can
perform. The session storage and provider state are host-local and must be
included deliberately in host backup and recovery procedures; restoring them
onto a different account or path can invalidate ownership and provider access.

## Shutdown, monitoring, and recovery

On a stop signal the daemon drains under `GJC_SHUTDOWN_TIMEOUT_MS`, default
15,000 ms. The value is bounded (minimum 1,000 ms); configure the external
service supervisor's stop timeout above it. Treat forced termination as an
operational failure, because active workflows and local state may not have
reached their normal cleanup boundary.

Monitor daemon process health, outbound WebSocket registration at the bot,
provider/profile failures, and the expected mapped workspace state separately.
A connected daemon is not proof that provider authentication, model selection,
or a particular workspace is ready. The bot's `/hosts` and its structured logs
are the operator view of connection and readiness, while the daemon service
logs provide local startup and shutdown diagnostics.

Before an upgrade, record the deployed revision, Bun and SDK versions,
`HOST_ID`, service-account identity, model profile, and protected-state backup
status. Stop gracefully, install the new locked dependencies, restart, then
confirm registration and a known authorized route. Roll back binaries only
when the local persistence and mapping-authority state remain compatible. Do
not treat copied `~/.gjc`, session state, or an old authority snapshot as a
safe generic rollback: tokens may be account-bound and durable authority
floors must not be rewound. Prefer forward recovery under the current authority
contract.

## Native inventory and serving boundary

`GJC_NATIVE_INVENTORY_MODE` accepts only `off` (default) or `verify`; another
value fails startup closed. `verify` is a capability-verification mode, not a
route source or a serving switch. In production (outside test injection),
verify constructs and self-tests the production native reader during daemon
boot; configuration or self-test failure hard-exits with a sanitized
diagnostic. Receipt advertisement still requires both `GJC_READINESS_V2=1`
and a receipt-capable verified provider. The test injection variables in
`.env.example` are test-only and must not be set in a deployment; enabling the
injection flag deliberately selects the fixture provider.

Native workspace serving is default-off. It can enable only when both
conditions are true: `GJC_NATIVE_WORKSPACE_SERVING` is the exact string `1`
(no whitespace or truthy alternatives) **and** receipt capability is
advertised by the verified path. `GJC_READINESS_V2=1` and `verify` alone do not
meet that gate. Do not promote this as an active serving deployment: live
serving-on evidence remains outstanding.

The authenticated management mapping remains the sole route authority. Local
inventory and a receipt are capability evidence only. See
[workspaces and paths](workspaces-and-paths.md),
[workspace readiness](../protocol-v2-workspace-readiness.md), and
[bind-authority verification](../adr/0004-workspace-bind-authority-verification.md).
