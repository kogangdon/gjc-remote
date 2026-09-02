# gjc-remote

Discord-controlled remote GJC sessions.

> **⚠️ Security: this grants remote code execution.** A mapped Discord channel
> runs arbitrary GJC workflows (bash, file writes, etc.) on your host machines.
> Keep `bot/`'s WebSocket port on a private network, treat host tokens like
> passwords, and set `GJC_BOT_ALLOWED_USERS` to your own Discord user ID(s). The
> bot ships fail-closed (`GJC_REMOTE_REQUIRE_ALLOWLIST=1`) and refuses to start
> with an empty allowlist. See [SECURITY.md](SECURITY.md) before exposing it to
> anyone else.
>
> Management mapping control-plane operations are documented in
> [`docs/management-mapping-envelope.md`](docs/management-mapping-envelope.md).
> They require a verified native capability, but mapping verification alone
> never enables serving. Native serving is a separate, default-off daemon
> opt-in with additional receipt and lifecycle gates.

## Architecture

[![gjc-remote architecture](docs/architecture.en.png)](docs/architecture.en.png)

_Diagram: [English](docs/architecture.en.png) · [한국어](docs/architecture.ko.png) — editable sources: [`docs/architecture.en.html`](docs/architecture.en.html), [`docs/architecture.ko.html`](docs/architecture.ko.html)._

```
[host machine, per project]                    [always-on bot host, private network]
  GJC embedding SDK          <--in-process-->    daemon/  --WS(outbound)-->   bot/
  (one AgentSession per                                               (WS server +
   workDir, reaped after                                               Discord client)
   1h idle)
```

1. `daemon/` runs on each machine you want to control. It connects outbound to
   `bot/`'s WebSocket server and registers with a per-host pre-shared token. The
   bot sends an application `ping` every 30 seconds and requires `pong` within
   10 seconds; half-open sockets are removed and their pending requests fail.
   A replacement connection for the same host owns its own heartbeat state.
2. On each Discord command, the daemon resolves its configured `workDir` to the
   host filesystem's current canonical real path, so retargeted symlinks or
   junctions cannot reuse a stale target. Different path spellings for the same
   directory reuse one in-process GJC SDK `AgentSession`. Prompt and model
   operations are serialized per session. Idle `steer`/`follow_up` requests join
   that FIFO and start a prompt-equivalent run instead of waiting on an inactive
   control queue. While a prompt or accepted follow-up pipeline is active,
   controls retain their SDK `steer`/`follow_up` semantics instead of waiting
   behind it. A `steer` request remains open through the current run's
   `agent_end`; each successfully queued `follow_up` remains open through its
   own run's `agent_end` and blocks queued prompt/model operations until that
   boundary. Rejected follow-up admissions consume no completion boundary. Each
   request receives its event stream, and later controls rejoin the FIFO. Idle
   sessions (no requests for 1 hour) are disposed automatically.
3. `bot/` exposes mapped-channel plain chat as direct GJC prompts, plus GJC's
   bundled skills (`deep-interview`, `ralplan`, `team`, `ultragoal`), `/gjc`,
   `/model`, and `/hosts` as Discord slash commands.
4. Each Discord channel configures one `{hostId, workDir}` input via
   `bot/channels.json`. The daemon canonicalizes `workDir`, so the effective
   session identity is `(hostId, canonical workDir)`. A host only accepts
   commands while its daemon is connected — turning the daemon off makes that
   channel's commands fail fast instead of hanging.

**Concurrency limits.** All sessions on a host share one daemon process and one
JS event loop: concurrent prompts on different workDirs interleave cooperatively
but do not run in true parallel, and a long synchronous stretch in one session
can briefly stall the others. See `CONTEXT.md` → "Concurrency model: single event
loop (current SDK 0.12.21)" for the full model and the subprocess option
(tracked in #33).

> **Node requirement:** the root package and `bot/` declare `"engines": {
> "node": ">=26.0.0" }`. Node 24 on Windows has been observed in CI to crash
> the bot process (`STATUS_STACK_BUFFER_OVERRUN`, exit `3221226505`) instead
> of the contracted single fatal line + exit 1 — CI is pinned to Node 26
> (`.github/workflows/ci.yml`) and `bot/src/bot.js` /
> `bot/src/management-entrypoint.js` refuse to start on an unsupported Node
> major with a structured `unsupported_node_version` fatal instead of risking
> that crash. Install Node 26+ before running the bot outside Bun.

## Deployment

| Component | Native Linux | Native Windows | macOS | Docker |
| --- | --- | --- | --- | --- |
| Bot | Documented | Documented with supervisor limitations | Unsupported native-control target | Linux release candidate |
| Daemon | Documented | Documented for x64 with supervisor limitations | Unsupported native-control target | Design only; no runnable image |

Start with the [deployment index](docs/deployment/README.md), then use the
[bot](docs/deployment/bot.md), [daemon](docs/deployment/daemon.md), and
[workspace/path](docs/deployment/workspaces-and-paths.md) guides. Platform and
Docker status is recorded there without promoting design-only or unevidenced
paths.

## Local quick start

Install the repository prerequisites before running `bun install`:

- **Node.js 26 or newer.** Node runs the bot, management CLI, smoke harness,
  and every `node --test` workspace suite.
- **Bun 1.3.14 or newer.** Bun installs the committed `bun.lock`, runs the
  daemon, and must be on `PATH` because daemon integration tests spawn a real
  Bun child even when `npm test` is launched with Node.
- **A native C++ build toolchain supported by `node-gyp`.** The
  `native-control` workspace has no portable fallback; installation and the
  native verification path require its N-API addon to build successfully.
- **Linux ACL development headers.** Debian and Ubuntu hosts must install
  `libacl1-dev` before dependency installation, otherwise compilation stops at
  `sys/acl.h`:

  ```bash
  sudo apt-get update
  sudo apt-get install -y libacl1-dev
  ```

  Other Linux distributions must install the package that provides
  `sys/acl.h`. The approved native-control addon targets are **Linux x64**,
  **Linux arm64**, and **Windows x64**. Windows x64 requires the Visual Studio
  C++ build tools. Every other OS/architecture tuple—including Windows arm64
  and all macOS targets—is currently unsupported for native-control.

These are the same runtime and native-header prerequisites enforced by the
repository package metadata and the Ubuntu/Windows CI matrix. A missing native
prerequisite is an installation error, not a reason to skip native-control
verification.

```bash
bun install   # installs all workspaces (bot, daemon, shared, native-control) from bun.lock

# The management authority CLI (not native serving) requires native-control.
# Issue #44 management writes require a C++ toolchain, Node headers, and the
# platform ACL dependencies. The verified addon manifest and platform-specific
# retained-handle/ACL/no-follow/durability probes must pass before any write;
# there is no portable filesystem fallback.
#
# Addon provenance: at load time, native-control checks the built .node file
# and its signed manifest against native-control/release-keys/trusted.json,
# a git-pinned public-key trust store separate from the gitignored build output.
# This checkout pins the production key `prod-2026-08-r2` (Ed25519), so signature
# enforcement is LIVE: a missing, malformed, invalid, or unknown-key signature
# refuses to load. Issue #44 evidence records the real-addon provenance gate
# against that pinned key. The private-key custody, rotation, and fail-closed
# contract are documented in docs/adr/0003-management-mapping-envelope.md
# ("Release signing and provenance") and
# native-control/release-keys/README.md.
#
# Historical (pre-provisioning) note: older revisions described a zero-key
# `trusted.json` and an `UNVERIFIED` warning. That was bootstrap history only;
# it does not describe this checkout.

# On the always-on bot host:
cp bot/.env.example bot/.env        # fill in DISCORD_TOKEN, DISCORD_CLIENT_ID, HOST_TOKENS, GJC_BOT_ALLOWED_USERS
# Isolated legacy/local quick start only:
cp bot/channels.example.json bot/channels.json   # map Discord channel IDs -> {hostId, workDir}
# Production deployments use the authenticated management authority documented
# in docs/management-mapping-envelope.md. Never hand-edit managed channels.json.
# Windows only, management-mapping writes (issue #44): native-control's
# assertConfigParentOwner refuses to write unless the directory holding
# channels.json (bot/, or the CHANNELS_CONFIG target's directory) is owned by
# the OS account the bot/management CLI runs as. If that directory was created
# by an elevated (Administrator-group) process, Windows owns it as
# BUILTIN\Administrators by default, not that account, and management writes
# fail closed (ERR_NATIVE_CONTROL_REFUSED) until you fix it once:
#   icacls <dir> /setowner <management-principal>
# See docs/adr/0003-management-mapping-envelope.md ("Config-parent ownership")
# for why this is fail-closed and cannot be relaxed.
# Fill GJC_BOT_ALLOWED_USERS with your Discord user ID(s): the bot ships
# fail-closed (GJC_REMOTE_REQUIRE_ALLOWLIST=1) and refuses to start otherwise.
# Set GJC_REMOTE_REQUIRE_ALLOWLIST=0 ONLY for isolated local testing.
bun run --filter '@gjc-remote/bot' register    # publish slash commands to Discord
# Enable the Discord Developer Portal "Message Content Intent" for plain chat prompts.
bun run --filter '@gjc-remote/bot' start

# On each machine you want to control (requires Bun 1.3.14 or newer):
cp daemon/.env.example daemon/.env  # fill in HOST_ID, HOST_TOKEN (must match bot's HOST_TOKENS), BOT_WS_URL
bun run --filter '@gjc-remote/daemon' start
```

Every command above is driven by Bun (the repo's lockfile is `bun.lock`). The
daemon runs on Bun (>=1.3.14) and embeds the
[`@gajae-code/coding-agent` SDK](https://github.com/Yeachan-Heo/gajae-code) **0.12.21**
(pinned in `daemon/package.json` and `bun.lock`); `bun install` provisions
exactly that version, and the interactive `gjc` used for provider login (below)
should match it. The bot, `register`, the management CLI (`gjc-remote-admin`),
and the smoke harness require Node.js >=26 and always run under real Node via
their package scripts (`node src/...`); the daemon is the only piece that runs
on Bun. Do not run those Node scripts with `bun run --bun` — Bun does not
report a Node 26 major to `process.versions.node`, so `bot/src/node-version-guard.js`
(loaded first by `bot.js` and `management-entrypoint.js`) refuses to start under
it. `bun run --filter '@gjc-remote/bot' start` (no `--bun`) is fine: Bun just
shells out to the `node src/bot.js` package script on PATH.

> **SDK update:** `@gajae-code/coding-agent` is pinned to **0.12.21**.
> This supersedes the previous 0.12.7 pin. Verification passed on 2026-08-09:
> package/lock reconciliation, canonical SDK imports, root/workspace regression
> suites, local smoke (`SMOKE_OK`), and manual bot/daemon runtime execution.
> Provider/model switch coverage remains environment-dependent.

**Optional environment variables** — beyond the required keys above:

- **bot** — `DISCORD_GUILD_ID` registers slash commands to a single guild for
  instant propagation (global registration can take up to ~1h to appear);
  `GJC_REMOTE_DEBUG=1` logs Discord interaction lifecycle and relayed GJC event
  summaries; `CHANNELS_CONFIG` overrides the `channels.json` path.
- **daemon** — `HOST_LABEL` sets a human-readable name shown in the bot's connect
  logs; `GJC_MODEL_PROFILE` overrides the activated model profile;
  `GJC_SHUTDOWN_TIMEOUT_MS` overrides the daemon shutdown deadline (default
  15000ms, validated from 1000ms through the runtime timer maximum). Keep it
  below the external supervisor's daemon stop timeout;
  `GJC_READINESS_V2=1` enables the opt-in protocol v2 workspace-readiness
  advertisement. `GJC_READINESS_TTL_MS` sets the bounded readiness TTL from
  1,000 through 60,000 milliseconds (default 60,000); it has no effect on
  whether v2 is advertised. Readiness alone does not authorize native workspace
  serving. Serving is default-off and requires the exact
  `GJC_NATIVE_WORKSPACE_SERVING=1` opt-in plus a production inventory receipt;
  each lifecycle operation keeps its own fail-closed dependency gates. See the
  [daemon deployment guide](docs/deployment/daemon.md).

## Provider authentication (e.g. GitHub Copilot)

Browser/device OAuth flows cannot be driven through the Discord bridge, so
provider auth is done once directly on each daemon host:

```bash
# On each daemon host, run interactive GJC and log in:
gjc
# then inside the session:
/login github-copilot
```

The saved token in `~/.gjc` is reused by every SDK session the daemon creates.
Once authenticated, that provider's models appear in `/model` resolution and can
be selected via exact `provider:modelId` or a unique name/ID fragment.

Each legacy/local `channels.json` route must contain exactly `hostId` and
`workDir`.
`hostId` must have a matching `HOST_TOKENS` entry, and `workDir` must be a
fully-qualified path native to that daemon host (for example,
`C:/projects/foo` on Windows or `/srv/apps/foo` on Linux/macOS). Relative paths
and extra route fields are rejected. Production managed routes are generated
only by the authenticated management authority; do not create or repair them
with ordinary file edits.

**Windows hosts:** the SDK applies fail-closed owner-only security to each
session's `<workDir>/.gjc-remote-session` storage. On Windows this can fail with
`owner_mismatch` for workDirs outside the daemon user's profile directory
(observed on `E:/` and `C:/tmp`), which aborts session creation. Configure
Windows channel workDirs under the daemon user's profile (for example
`C:/Users/<user>/projects/foo`), or verify the native ownership check before
mapping other volumes.

`/model` accepts an exact `provider:modelId` (for example,
`openai-codex:gpt-5.6-sol`) or an unqualified model ID/display-name fragment.
Unqualified input is accepted only when it has one uniquely best match;
ambiguous requests fail with a bounded candidate list instead of selecting a
provider implicitly. A successful switch reports the selected display name,
provider, and model ID. It does not change the daemon's startup default.

Each new session activates the host's configured model profile
(`~/.gjc/agent/config.yml` `modelProfile.default`) through GJC's own resolver, so
the daemon starts on the same model your interactive GJC uses instead of the
SDK's first-available fallback. Set `GJC_MODEL_PROFILE` to override the profile
name. A profile that cannot be activated (for example, missing provider
credentials) fails session creation loudly rather than silently returning empty
responses.

## Output & tool logs

GJC output reaches the channel as follows (`bot/src/delivery.js`):

- Responses up to ~1900 characters post as a single message.
- Longer output is split into sequential messages labelled `(Part i/N)`, up to
  7 parts (~600ms apart, with code fences kept intact across the split).
- Output that would exceed 7 parts posts as a short notice plus the full text as
  an in-memory `.md` file attachment — nothing is written to the bot's disk.
- Results that carry tool activity attach a button that expands the tool-call
  log on demand. Tool logs live in bot memory only: at most 100 entries, each
  expiring 1 hour after creation (`bot/src/tool-log-store.js`).

## Verification

```bash
bun run smoke:local
# Also verify model resolution and its structured success receipt:
SMOKE_MODEL_QUERY=openai-codex:gpt-5.6-sol bun run smoke:local   # POSIX shell
# PowerShell: $env:SMOKE_MODEL_QUERY="openai-codex:gpt-5.6-sol"; bun run smoke:local
```

`smoke:local` starts a local `HostRegistry`, starts a real Bun daemon, routes one
prompt through an embedded GJC SDK session, and asserts that the assistant text
comes back through the relay. When `SMOKE_MODEL_QUERY` is set, it also performs
a real model switch and requires a `model_resolved` receipt. It does not require
Discord credentials.

## Operations

### Process supervision

Neither component daemonizes itself. The approved operations boundary is
documented in [`docs/process-supervision.md`](docs/process-supervision.md), with
the decision in [`docs/adr/0001-process-supervision.md`](docs/adr/0001-process-supervision.md)
and failure scenarios in
[`docs/pre-mortem-process-supervision.md`](docs/pre-mortem-process-supervision.md).

### Workspace implementation contract

The phased implementation gates, readiness decisions, interim development boundaries, and release
evidence checklist are documented in
[`docs/daemon-workspace-implementation-phases.md`](docs/daemon-workspace-implementation-phases.md).

### Optional bot container

The hardened Linux bot-container contract and Compose candidate live in
[`deploy/docker/bot/`](deploy/docker/bot/README.md). It requires an externally
produced, production-signed, architecture-matched native-control bundle and
fails the image build before startup when that bundle is absent or invalid.
No supported image is claimed until signed amd64/arm64 bundles and live Linux
container stop/restart/network/rollback evidence are available. Daemon Docker
remains a separate phase.

Shawl is the selected primary Windows supervisor: one `GJCRemoteBot` service and one
`GJCRemoteDaemon-<instance-key>` per exact valid `HOST_ID`. Shawl v1.9.0 has
passed local Windows checks for daemon and bot child replacement, daemon
reconnect/registration after bot recovery, and graceful stop without an
unwanted restart. Shawl is not yet a full production approval because its
distributed binary is unsigned; signed provenance remains a required, still-open
release-owner item, along with hash pinning, artifact provenance,
service-account configuration, and production Windows evidence.

Direct `sc.exe` service registration is the documented Windows fallback when
Shawl is unsuitable, with a known cost: Bun/Node do not implement the Windows
Service Control API, so a directly registered service cannot acknowledge a stop
request, and automatic restart is limited to bare `sc failure` recovery actions
(no jitter/backoff shaping). The production-primary design remains open to a
future first-party signed Windows service wrapper registered through the
Windows SCM. **NSSM is discarded: it was never merged into this repository —
its scripts lived only in an untracked, now-deleted `ops/` tree — and the
operator selected Shawl/`sc.exe` instead.** No NSSM implementation exists in
this repository. Linux systemd units (a bot unit plus a true
`gjc-remote-daemon@.service` template) are documented as the Linux service
path, but those `.service.in` templates are likewise not currently checked
into this repository. The documents define
account/profile/env/ACL boundaries, current-run readiness, restart/rotation,
rollback, transaction proofs, and honest best-effort stop/manual-cleanup
semantics. Host-policy journald is consumed by default; global changes need
separate approval.

**Windows support boundary:** the documented Windows deployment assumes a dedicated
operator-controlled host. Multi-user workstation isolation is not a supported
security boundary, and this repository does not claim protection from unrelated local
users or local administrators. Cross-account read/write isolation for unrelated local
users is therefore outside the dedicated-host release gate, while service-account
separation and protected secret/profile storage remain required for supervised deployment.

**Platform evidence is pending.** These links describe the current contract and
evaluation results; they do not claim that a signed Windows primary wrapper,
production Windows account/ACL behavior, Linux boot/readiness, relay behavior,
Existing foreground commands remain an operational fallback when a supervisor
cannot satisfy its evidence gates:

```text
# from the repository root
cd bot    && node src/bot.js
cd daemon && bun src/daemon.js   # Bun >= 1.3.14
```

Foreground execution does not roll back an application artifact, runtime,
mapping authority, or durable state.

The daemon reconnects with equal-jitter exponential backoff after a
disconnect; this is application behavior and is separate from supervisor
restart policy.
Registration denial is intentionally separate from transport reconnects: the daemon
waits 5 minutes (`GJC_REGISTER_DENIED_RETRY_MS`, validated to a safe timer range)
before retrying and emits a sanitized warning. A successful registration clears that
state. Shutdown is bounded at 15 seconds; signal shutdown exits 0 even when disposal
fails, while fatal shutdown exits non-zero.

### Rotation, retention, rollback

- **Host tokens**: rotate by updating the daemon's `HOST_TOKEN` and the bot's
  matching `HOST_TOKENS` entry, then restarting both; tokens are read at
  startup only. Rotate per host if one is compromised.
- **Discord authorization** (`GJC_BOT_ALLOWED_USERS`,
  `GJC_REMOTE_REQUIRE_ALLOWLIST`): startup-only; restart the bot after changes.
- **Legacy/local `channels.json`**: hot-reloaded on save. An invalid reload
  keeps the last valid in-memory map; this is not authority rollback.
  Production managed state changes only through authenticated management
  operations.
- **Tool logs**: kept in bot memory only — at most 100 entries, each expiring
  1 hour after creation. Nothing is written to disk; no cleanup needed.
- **Session history**: each daemon workDir persists GJC session history under
  `<workDir>/.gjc-remote-session`; idle in-process sessions are disposed after
  1 hour. Delete that directory to reset a project's remote history.
- **Process logs**: both components log to stdout/stderr. Retention is
  supervisor-specific: Shawl's retention/rotation must be explicitly configured
  and verified; the `sc.exe` fallback and Linux host-policy journald provide no
  bounded rotation of their own beyond OS defaults. NSSM is discarded; its
  bounded current/`.old` log policy no longer applies to this repository. See
  [`docs/process-supervision.md`](docs/process-supervision.md).

### Native workspace inventory (off by default)

`GJC_NATIVE_INVENTORY_MODE` controls the daemon's native workspace inventory
capability and defaults to `off`. Setting it to `verify` opts into the native
inventory receipt contract (advertised only alongside opt-in protocol v2
readiness and a receipt-capable inventory provider). Any value other than
`off`/`verify` fails the daemon closed at startup (`process.exit(1)`) — there
is no silent fallback.

Native workspace serving is default-off. Production `verify` mode constructs
and self-tests the signed native reader; configuration or proof failure exits
the daemon with a sanitized diagnostic. Receipt advertisement additionally
requires opt-in protocol readiness and a receipt-capable verified provider.
Serving can enable only when `GJC_NATIVE_WORKSPACE_SERVING` is exactly `1` and
that receipt capability is advertised. Each lifecycle operation retains its
own fail-closed dependencies. This repository does not claim live
serving-enabled deployment evidence.

The inventory contract is capability evidence only. The issue #44
authenticated management mapping remains the sole route authority, never the
local inventory. `GJC_READINESS_TEST_INJECTION` and
`GJC_WORKSPACE_INVENTORY` are test fixtures and must not be set in deployment;
enabling injection deliberately selects the fixture provider.

Five-role access control (`GJC_INVENTORY_ROLE_BINDINGS`, strict JSON) binds
exactly the `management`, `bot`, `recovery`, `daemon`, and `system` roles to
platform-native principals — a `uid:<n>` on Linux or a SID on Windows — with
`system` pinned to `uid:0` / `S-1-5-18`. WSL Linux accounts and native Windows
accounts are separate identity systems; role bindings must match the
platform the daemon actually runs on.

A durable, D(aemon)-owned floor prevents silent inventory rollback: restoring
inventory below a surviving floor is rejected as `INVENTORY_STALE` and enters
manual cleanup — the floor itself is never lowered automatically. Known
limitation: a jointly restored, internally consistent old inventory-and-floor
pair (both rolled back together) is accepted, an availability-cost caveat —
while the daemon is offline, management cannot advance until the floor
catches up.

Observability: the bot's `/hosts` projection exposes a `reconnectCount`
churn counter, advanced only for binding-capable v3 reconnects. Structured
bind/receipt/socket observability events are sanitized before emission
(opaque ids redacted, fingerprints truncated to a safe prefix) and have no
production sink wired by default.

## Security notes

- `bot/`'s WS port only needs to be reachable from daemon hosts on your
  private network — never expose it to the public internet.
- `HOST_TOKENS`/`HOST_TOKEN` are pre-shared keys; treat them like passwords.
  Rotate per host if one is compromised.
- WebSocket frames are text JSON, capped at 8 MiB on both bot and daemon,
  validated against the required v0 fields, and rejected before routing when
  malformed. Invoke message text is capped at 1 MiB to leave room for JSON
  escaping and metadata, and the bot preflights the serialized outbound frame.
  Extra object fields remain allowed for additive compatibility.
  Each host is limited to 64 concurrent in-flight invokes; beyond that the bot
  fails new requests locally instead of growing its pending map.
  The daemon and bot exchange an additive protocol version and capability list
  during registration; legacy daemons that omit them are treated as v0.
  Host tokens authenticate daemon identity but do not encrypt WebSocket
  traffic; use private `wss://`, a VPN, or a tunnel outside a single trusted
  network.
- `GJC_BOT_ALLOWED_USERS` should be set to your own Discord user ID(s) before
  inviting the bot to any shared server — an unrestricted bot lets anyone in
  the channel run arbitrary GJC workflows (file writes, bash, etc.) on your
  hosts.
  `GJC_REMOTE_REQUIRE_ALLOWLIST` ships as `1` (fail-closed): the bot refuses to
  start with an empty allowlist. Override to `0` only for isolated local
  testing, which lets anyone in a mapped channel run arbitrary GJC workflows.
  Both authorization settings are startup-only and require a bot restart after
  changes.
- Invalid `channels.json`, `HOST_TOKENS`, allowed-user entries, or strict
  allowlist flags fail before routing starts. Every mapped `hostId` must have a
  configured token. A failed `channels.json` reload keeps the last valid map.
