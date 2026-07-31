# Context handoff — gjc-remote

Written for whichever GJC session picks this repo up next. Read this before
touching code; it captures *why* things are shaped this way, not just what
they do (README.md covers the what/setup).

## Goal

Control multiple GJC sessions, running on multiple hosts that are not always
online, from a single Discord bot exposing GJC's bundled workflow skills
(`deep-interview`, `ralplan`, `team`, `ultragoal`) plus direct prompts and
runtime model switching as `/slash` commands.

## Architecture (GJC 0.11 SDK; implemented and real-smoke tested)

```
[host machine, per project]                    [always-on bot host, private network]
  GJC embedding SDK          <--in-process-->    daemon/  --WS(outbound)-->   bot/
  (one AgentSession per                                               (WS server +
   workDir, reaped after                                               Discord client)
   1h idle)
```

1. `daemon/` runs on every machine you want to control. It opens an
   **outbound** WebSocket to `bot/`'s WS server and registers with a
   pre-shared per-host token. Outbound-only means the host can sit behind
   NAT/firewall with no inbound port, and does not need to be always-on —
   when its daemon isn't connected, the bot treats that host's channels as
   offline and fails fast instead of hanging.
2. On each Discord command, the daemon resolves its configured `workDir` to the
   host filesystem's current canonical real path, so retargeted symlinks or
   junctions cannot reuse a stale target. Different path spellings for the same
   directory share one in-process GJC SDK `AgentSession` with file-backed history
   under `<workDir>/.gjc-remote-session`. Prompt and model operations are
   serialized per session. Idle `steer`/`follow_up` requests join that FIFO and
   start a prompt-equivalent run instead of waiting on an inactive control queue.
   While a prompt or accepted follow-up pipeline is active, controls retain
   their SDK `steer`/`follow_up` semantics instead of waiting behind it. A
   `steer` request remains open through the current run's `agent_end`; each
   successfully queued `follow_up` remains open through its own run's
   `agent_end` and blocks queued prompt/model operations until that boundary.
   Rejected follow-up admissions consume no completion boundary. Each request
   receives its event stream, and later controls rejoin the FIFO. Idle sessions
   (`IDLE_TIMEOUT_MS` = 1h, in `shared/protocol.js`) are disposed.
3. `bot/` is the only component holding the Discord token. It runs a WS
   server (`bot/src/host-registry.js`) that daemons connect to, and maps
   each Discord channel to one validated `{hostId, workDir}` pair via
   `bot/channels.json` (gitignored — copy from `channels.example.json`). The bot
   watches the parent directory so editor replace/rename saves reload safely;
   an invalid reload keeps the last valid map.
   In mapped channels, ordinary non-bot messages from allowed users are treated
   as direct GJC prompts; slash commands remain available for skills, `/model`,
   and `/hosts`.

## Why NOT the alternatives

- **SSH pull (bot SSHes into each host)** — rejected. Requires the target
  host to run an SSH server and be reachable inbound; breaks the "host isn't
  always online" requirement. The WS-push model (host dials out to the bot)
  was chosen specifically to invert this.
- **Historical RPC stdio/socket transports** — removed upstream in GJC 0.11.
  `--mode rpc` now fails with an explicit SDK migration error. The daemon embeds
  `@gajae-code/coding-agent` instead, preserving per-workDir session reuse
  without a subprocess or Unix socket.
- **`gjc session` / `gjc team` (tmux-backed)** — separately confirmed
  Windows-incompatible: `tmux` binary isn't available/expected on native
  Windows and `gjc session list` hard-crashes with `Executable not found in
  $PATH: "tmux"`. Unrelated to the RPC socket issue above — two independent
  Windows gaps. Not used by this project's architecture at all (we drive skills
  through SDK `AgentSession` prompt methods, not via `gjc team`).
- **One `gjc -p "..."` subprocess per Discord command** — this was the
  *first* working prototype (now deleted, used to live at
  `C:/tmp/gjc-discord-bridge`). It worked (verified: parallel isolated
  sessions via `--session-dir` + `--continue`) but can't inject into an
  *already-running* session or stream live progress — each call is a fresh
  process that exits. The embedded SDK supersedes this path.

## Implementation findings

Items 1, 2, 4, and 7 below document the deleted RPC adapter as regression
history. `daemon/src/rpc-client.js`, `RpcSession`, and the child-process handlers
named in those entries no longer exist after GJC 0.11 removed RPC ingress. The
current transport lives in `daemon/src/sdk-session.js`.

1. **Historical event frame unwrapping.** GJC's RPC stdio protocol wrapped
   streamed frames as `{type:"event", payload:{event_type, event}}`, not a flat
   `{type: event_type}`. The deleted `daemon/src/rpc-client.js` unwrapped those
   frames before handing events to callers.
2. **Historical concurrent-request correlation race.** GJC's streamed frames did
   not echo the request `id`, so the removed adapter could not route multiple
   in-flight commands. It also emitted `turn_end` for intermediate tool-use turns
   before the full run reached `agent_end`. The deleted `RpcSession` serialized
   commands through a single-in-flight FIFO and resolved prompt-like commands at
   the full-run `agent_end` boundary. The SDK adapter retains only the relevant
   completion and serialization invariants without RPC frame correlation.
3. **`set_model` needs exact `{provider, modelId}`, not a free-text name.**
   Discord users may provide exact `provider:modelId`, a unique model ID, or a
   unique display-name/ID fragment. `daemon/src/model-lookup.js` validates the
   `get_available_models` response and refuses cross-provider or equal-rank
   ambiguity instead of selecting by list order. `model-command.js` sends the
   resolved exact pair and emits a bounded `model_resolved` receipt only after
   success; the bot formats that receipt so `/model` never succeeds with
   `(no text output)`. Verified against real GJC: `sol` resolved to
   `openai-codex:gpt-5.6-sol` (`GPT-5.6 Sol`). Startup model selection remains
   unchanged.
4. **Historical daemon-wide crash on spawn failure.** In the removed subprocess
   transport, a `child_process.spawn` `ENOENT` fired an async `'error'` event
   rather than throwing; an unhandled event crashed the whole daemon. The old
   pool and `RpcSession` converted those events into request rejections. Those
   child-process handlers were deleted with the RPC adapter. The current
   `SessionPool` still validates that `workDir` exists before SDK session
   creation, and SDK creation failures reject the affected request.
5. **`/login` was discarded.** An earlier iteration added a real `login`
   command kind (throwaway `gjc --mode=rpc` process, OAuth-URL relaying to
   Discord, copilot device-flow detection). It was removed: browser/device
   OAuth flows can't be driven cleanly through the bridge (the loopback
   callback only completes if the browser runs on the host, and copilot's
   device flow is refused in RPC mode entirely). Provider auth is now expected
   to be done once directly on the host terminal (`gjc` + `/login <provider>`);
   the saved token in `~/.gjc` is reused by every later SDK session. All login
   plumbing (bot `/login` command + `extractLoginRequest`/`formatLoginEvents`/
   `finalizeLoginResult`, the daemon `login` kind, `SessionPool#runEphemeral`,
   `LOGIN_TIMEOUT_MS`) has been deleted.
6. **Bot routing/auth configuration was unvalidated.** `channels.json` routes,
   `HOST_TOKENS`, and `GJC_BOT_ALLOWED_USERS` are now parsed through pure
   validators before use. Every route host must have a configured token.
   Startup rejects malformed values; reload parses and cross-checks a complete
   replacement before swapping and keeps the previous map on failure. The
   watcher follows the parent directory so atomic replace/rename saves do not
   detach it. An empty allowed-user list remains backward-compatible for local
   use but emits an explicit security warning. Shared/production deployments
   set `GJC_REMOTE_REQUIRE_ALLOWLIST=1`, which rejects an empty allowlist before
   channel watching, WS startup, or Discord login. Slash commands, mapped
   plain chat, and tool-log buttons use one startup authorization policy;
   changes to either allowlist setting require a bot restart. `SessionPool`
   rejects workDirs that are not fully-qualified paths under the daemon host's
   native path semantics before lookup or SDK session creation.
7. **Historical RPC termination with unresolved work.** The deleted adapter
   rejected its active and queued commands when the child exited or errored, and
   permanently poisoned timed-out RPC sessions so late frames could not be
   assigned to replacement sessions. The current SDK adapter preserves the
   relevant invariant by timing out and poisoning a stuck `AgentSession`.
   `SessionPool` bounds session creation, idle/replacement/shutdown disposal,
   and shutdown waits for in-flight creation. Timed-out creations are evicted,
   and any session they produce later is disposed, so stalled SDK work cannot
   block a workDir or daemon shutdown indefinitely.
8. **Equivalent workDir spellings created duplicate sessions.** `SessionPool`
   resolves every existing native workDir through the host filesystem and uses
   that canonical real path for the pool key, SDK cwd, and session directory.
   Separator, case, or symlink aliases that resolve to one directory therefore
   reuse one live GJC SDK session.

## Runtime: Bun vs Node

`@gajae-code/coding-agent` 0.12.6 requires Bun 1.3.14 or newer, so the daemon
starts with Bun and embeds GJC in-process. The bot and Node built-in test runner
remain Node-compatible. `bun.lock` is the committed dependency lockfile;
`package-lock.json` is gitignored.

The daemon imports GJC through the **canonical exports-map subpaths**
(`@gajae-code/coding-agent/sdk` for `createAgentSession`,
`@gajae-code/coding-agent/session/session-manager` for `SessionManager`) in
`daemon/src/sdk-session.js`, not the package-root barrel. The barrel re-exports
both symbols but drags the whole runtime graph (TUI/modes, browser/puppeteer
tools) into the daemon process; the subpaths are the surfaces GJC's `exports`
map + `verify:sdk-canonicalization` gate actually bless, so this both shrinks the
daemon's loaded graph and rides the supported SDK surface rather than an
incidental barrel re-export. The `createSdkSession(workDir, loadSdk)` seam is
unchanged — tests still inject a fake `{ createAgentSession, SessionManager }`;
only the default production loader was narrowed.

## Concurrency model: single event loop, and the subprocess alternative (feasibility-confirmed, not implemented)

**Current model — cooperative concurrency, NOT parallelism.** Every pooled
`AgentSession` runs *in-process* inside the one daemon Bun process (see
`session-pool.js` / `sdk-session.js`; `daemon/src` has no `spawn`/`child_process`/
`--mode`). Multiple channels mapped to the same host therefore share **one JS
event loop**. Two concurrent remote prompts (e.g. `gjc-remote` + `nk-jenkins`
channels) do interleave and both make progress — live-observed: both workDirs'
`.gjc-remote-session/*.jsonl` update within seconds of each other, and both
resident-cache dirs carry the **same daemon PID** suffix (`…-<daemonPid>-1`,
`…-<daemonPid>-2`), proving distinct SDK sessions coexisting in one process.

Constraint that follows:
- **No true CPU parallelism.** Sessions advance only while one is `await`-ing
  I/O (LLM calls, tool child-processes). A long *synchronous* CPU stretch on the
  main thread stalls every other session until it yields. Fine while work is
  I/O-bound; degrades under CPU-bound load.
- **Per-session FIFO** serialization is intentional (prompt/model ops; see
  Architecture §2). Cross-session there is no scheduling lock — independent.
- **Cross-session state bleed** is the two documented process-globals, not the
  scheduler: Settings singleton (mitigated by `cloneForCwd`, see that section)
  and the capability module-global (NOT mitigated; last-created wins;
  upstream #2774 / gajae-code#2865, still reproduces on 0.11.10).

**Subprocess alternative — feasible, and the SDK already ships the transport.**
Confirmed against installed `@gajae-code/coding-agent` (asked 2026-07-28):
- `gjc` is a spawnable bin. The CLI exposes `--mode=acp` (`src/cli.ts`:
  `mode: Flags.string({ options: ["text","json","acp"] })`) plus a dedicated
  `gjc acp` subcommand.
- `src/modes/acp/acp-mode.ts` `runAcpMode()` drives an `AgentSideConnection`
  over **ndjson on stdin/stdout** via `@agentclientprotocol/sdk`
  (`ndJsonStream(process.stdout, process.stdin)`). ACP (Agent Client Protocol)
  is the editor-standard "drive an agent session as a subprocess over stdio" —
  exactly this use case, no new protocol needed.
- Precedent: the daemon *used to* run subprocess RPC (see Implementation
  findings — deleted `rpc-client.js`/`RpcSession`, "formerly provided by the RPC
  transport"). The `SdkSession` adapter is already shaped as a swappable
  command/event transport, so a subprocess route replaces only the in-process
  `createAgentSession` seam.

Two routes if pursued:
- **A — `gjc --mode=acp` per session** (standard). Reuses ACP; must map our
  invoke/set_model/steer/follow_up onto ACP session/prompt + its permission
  model (`modes/acp/permission-mode.ts`, `terminal-auth.ts`).
- **B — `Bun.spawn` custom worker per session** (Bun↔Bun `ipc`). Worker imports
  the SDK and runs one session; relays today's `SdkSession` invoke/event
  interface unchanged. No ACP mapping; you own the harness.

Both buy **true parallelism** (N OS processes, N event loops) and **full state
isolation** (dissolves the capability-global caveat). Costs — this re-pays what
the in-process migration deliberately removed:
- **Memory**: one full gjc runtime per session (interactive `gjc` observed ~465
  MB) vs. one shared runtime today → ≈ N×hundreds-MB.
- **Cold start**: spawn + ACP handshake + model-profile activation per session
  (profile activation is why `SESSION_CREATE_TIMEOUT_MS` is 60s).
- **Lifecycle**: idle reap becomes process-kill not object-dispose; child
  crash/zombie reaping; re-apply payload cap + backpressure at the stdio edge.
- **Version drift**: a `GJC_BIN`-spawned child uses the on-PATH gjc, which can
  differ from the daemon's imported SDK (note the existing pin-0.11.10 vs
  installed-0.11.4 gap) — independent upgrades (pro) but two versions to track
  (con).

**Status: feasibility only.** No route chosen, nothing implemented. The real
question is not "can we" (yes) but "is parallelism + full isolation worth
re-paying the memory/complexity the team dropped by going in-process?"

## Decided config values (don't re-ask the user these)

- Idle GJC SDK session timeout: **1 hour** (`IDLE_TIMEOUT_MS` in
  `shared/protocol.js`).
- Host<->bot auth: pre-shared per-host tokens (`HOST_TOKENS` on bot,
  `HOST_TOKEN` on each daemon), explicitly deferred stronger auth
  (mTLS/keypairs) to "later, if it becomes a problem."
- Host<->bot WebSocket frames are text JSON with an **8 MiB inbound cap** on
  both endpoints. Required v0 register/invoke/event fields are validated
  fail-closed while unknown extra object fields remain available for additive
  compatibility. Invoke message text has a **1 MiB character cap** for
  worst-case JSON escaping headroom, and the bot rejects invalid or oversized
  serialized invokes before sending. Event `requestId` values are accepted only
  from the exact daemon socket that owns the pending invocation.
  Each host is capped at **64 concurrent in-flight invokes**
  (`V0_LIMITS.MAX_PENDING_PER_HOST`); excess invokes fail closed locally with
  `too many in-flight requests` rather than growing the pending-request map,
  and completing or failing a request frees the slot. Streamed event volume is
  bounded by the per-frame 8 MiB cap, the invoke timeout, and dropping events
  whose `requestId` has no live pending owner.
  The bot sends protocol `ping` every **30 seconds** and requires `pong` within
  **10 seconds**. A missed deadline removes only the socket that owns that
  heartbeat and fails its pending invocations exactly once; a replacement
  connection for the same host is not affected by stale heartbeat state.
  The register handshake carries an **additive protocol version and capability
  list** (`PROTOCOL_VERSION`, `CAPABILITIES` in `shared/protocol.js`): the daemon
  advertises its version/capabilities on `register` and the bot echoes its own on
  `register_ok`, storing the negotiated `{protocolVersion, capabilities}`
  (capabilities intersected via `negotiateCapabilities`) per host, queryable with
  `HostRegistry.getHostInfo(hostId)`. Both fields are optional and bounded; a
  legacy v0 daemon that omits them is treated as `protocolVersion: 0` with no
  shared capabilities, so the handshake stays backward compatible.
  When the bot process receives `SIGINT`/`SIGTERM` it shuts down gracefully:
  `HostRegistry.close()` first, so in-flight invokes settle and daemons observe
  a clean socket close, then the Discord client is destroyed; the handler is
  idempotent and always reaches `exit(0)` — each step is bounded by a timeout so
  a step that throws *or* hangs cannot wedge the process
  (`bot/src/shutdown.js`). A disconnected daemon reconnects with **equal-jitter
  exponential backoff** (`daemon/src/reconnect.js`): the base doubles from 1s up
  to a 30s ceiling, and each actual wait is drawn from `[base/2, base]` so a
  shared bot restart does not trigger a synchronized reconnect thundering herd.
- Session key / isolation unit = **(hostId, canonical workDir)** pair; one
  Discord channel maps to a configured `{hostId, workDir}` and the daemon
  canonicalizes that path before SDK session lookup or creation.
- Multi-host management = **one bot process**, many daemons connecting to
  it (not one bot per host). Confirmed explicitly by the user.

## Telegram forwarding / long-message rendering guideline

When forwarding GJC session output into Telegram, do **not** assume Telegram will
show one long message in full. Manual rendering checks showed long messages can
be visually collapsed/truncated with a trailing `...`, especially around long
code blocks, long single-line strings, and dense tabular/code-like content.

Use these rules for Telegram delivery:
- Split long chat-visible text into multiple messages at roughly 2,000-3,000
  characters, with explicit `Part N/M` labels.
- Prefer a short visible summary plus `.md`/`.txt`/`.log` attachment for long
  code blocks, logs, tables, or content intended for exact copying.
- Avoid very long single lines; wrap generated/plain text around 80-120
  characters when possible.
- Treat tables and aligned text as attachment-first content because mobile
  widths break visual alignment easily.
## What is NOT done yet (pick up here)

1. **Real Discord E2E: first manual canary passed 2026-07-28; formal evidence
   table still pending.** The non-Discord relay path stays covered by
   `npm run smoke:local` (local `HostRegistry` + `daemon/src/daemon.js` under Bun
   + real embedded GJC SDK session, asserting relayed assistant text). On
   2026-07-28 the bot was additionally run for real: `bot/src/bot.js` with
   registered slash commands against a real Discord application/`DISCORD_TOKEN`
   and a private test guild, driving a live Windows daemon. Manually exercised
   and observed (operator-driven, screenshot evidence — NOT an automated or
   repeatable test):
   - **Authorization** allow + deny across all three entry paths: slash command
     (ephemeral `You are not authorized to run GJC commands.`), mapped plain chat
     (silent deny), tool-log button (ephemeral deny). Strict
     `GJC_REMOTE_REQUIRE_ALLOWLIST=1` boots with a non-empty allowlist and denies
     everyone else.
   - **Routing/failure matrix**: `/hosts` online (`Online: test`) / offline
     (`No hosts connected.`); unmapped channel (slash = mapping-missing
     ephemeral, chat = silent); offline daemon (`Host 'test' is not connected
     right now.`); nonexistent workDir (`workDir does not exist on this host: …`
     surfaced from the daemon `existsSync` check); mid-flight daemon kill
     (`host 'test' disconnected`, partial tool-log preserved); daemon reconnect
     restoring `Online: test`. `channels.json` hot-reload (no bot restart) also
     confirmed via the E-test re-map.
   - **Rendering**: live progress edit + tool-call preview, tool-log button,
     message chunking (`Part N/M`), large-output attachment (`gjc-output.md`),
     and button expiry after a bot restart (`Tool log is no longer available.`,
     the store is bot-process memory so a restart clears it).
   Caveats / still open: this was **manual** (no reproducible harness); it ran
   against the **live repo as workDir** (`D:/dev/gjc-remote`), NOT a disposable
   workDir — a relayed prompt wrote `rep_gen.py`/`rep_out.txt` into the repo,
   demonstrating that an authorized user gets the daemon OS account's write/exec
   authority (artifacts cleaned up afterward). `timeout` and too-many-in-flight
   were not manually triggered (unit-covered only), and the formal pass/fail
   table issue #2 asks for (versions, timestamps, command-registration receipt,
   sanitized logs, rollback procedure) has NOT been produced.
2. **`channels.json` exists on this host** (still gitignored; copy from
   `channels.example.json` elsewhere) — configured with the test guild's real
   channel IDs mapped to `{hostId: "test", workDir}` for the 2026-07-28 canary.
   A fresh deployment still needs its own real channel IDs.
3. **`GJC_BOT_ALLOWED_USERS` allowlisting — manually verified 2026-07-28** against
   the real test guild (allow + deny across all three entry paths, plus
   strict-mode boot with a non-empty allowlist). Still must be set before
   inviting the bot anywhere shared (unrestricted = anyone in-channel can run
   arbitrary GJC workflows — file writes, bash, etc. — on every connected host).
   Shared/production deployment must also set
   `GJC_REMOTE_REQUIRE_ALLOWLIST=1`; local unrestricted mode remains available
   only for backward-compatible development and emits a startup warning.
4. **Linux verified; macOS daemon path still unverified.** Built on native
   Windows (this repo's origin host). 2026-07-25: real local smoke passed on
   WSL2 Ubuntu 24.04 (Bun 1.3.14, repo cloned to native ext4 `~/gjc-remote`,
   Windows `~/.gjc/agent` config + auth DBs copied to WSL `~/.gjc/agent`) —
   `SMOKE_OK`, protocol v1, profile activation against real Copilot creds.
   Two useful fail-fast modes observed en route: no config → "No model
   selected"; profile without credentials → "requires credentials for:
   github-copilot". macOS remains unverified; run `npm run smoke:local` there
   before relying on it.
5. **No process supervision configured** — `README.md` mentions pm2/systemd
   as options but nothing is set up. Bot and each daemon currently need to
   be started manually.
6. **`/hosts` and progress-streaming (tool-call preview during a running
   command) — manually verified 2026-07-28** against the real test guild (see
   item 1: `/hosts` online/offline, live progress edit + tool-call preview
   during a running prompt). Underlying `HostRegistry`/SDK session plumbing
   remains unit-tested.
7. **Remote host files are not attached automatically.** Assistant output may
   contain absolute paths from the daemon host, but the Discord bot treats those
   paths as text. It never reads matching paths from the bot host. A future
   daemon-to-bot file transfer requires an explicit allowlisted protocol; the
   generated long-output and tool-log attachments remain supported because they
   are created in memory by the bot.

## Merge / PR workflow

When a review-pr-loop converges and the PR is merged **directly in the same
session**, merge with a **merge commit** (GitHub "Create a merge commit"), not
squash or rebase. Rationale: PRs #13/#15/#17/#19 landed as two-parent merge
commits, but #20/#21/#22 were squash-merged, which produced single linear
commits on `main` whose source branches then dangled beside the graph as
non-ancestors (same changes, different commit identity) — visually "broken"
history even though nothing was actually wrong. Staying on merge commits keeps
the branch topology legible and the merged branch reachable as an ancestor
(so `git branch -d` can verify-delete it later). Delete the source branch after
merging. Reserve squash for cases the user explicitly asks for.

## Verification pattern to reuse

Whenever you touch `daemon/src/*` or `bot/src/host-registry.js`, run
`npm run smoke:local` against the installed `@gajae-code/coding-agent` SDK
rather than trusting unit doubles. The smoke script is the preferred reusable
verification path because it starts the real Bun daemon and embedded agent.

## SDK Settings is a process-global singleton (per-session isolation gotcha)

`Settings.init({ cwd })` (and the `settings` a bare `createAgentSession`
auto-builds) returns a **process-global cached singleton** whose cwd is frozen
at first call — it does NOT re-scope per pooled session. Probe:
`bun -e "const {Settings}=await import('@gajae-code/coding-agent/config/settings'); const a=await Settings.init({cwd:'D:/tmp/a'}); const b=await Settings.init({cwd:'D:/tmp/b'}); console.log(a===b, b.getCwd())"`
→ `true D:\tmp\a`. Because `activateModelProfile` mutates that settings object
via `settings.override('modelRoles' | 'task.agentModelOverrides')` even with
`persistDefault:false`, sharing one Settings across the SessionPool lets each
new session's activation clobber every other live session's roles. Fix (PR
after #24): `const scoped = await (await Settings.init()).cloneForCwd(workDir)`
and pass `settings: scoped` to `createAgentSession` — `cloneForCwd` returns an
independent instance (`ca===cb` false, override on one does not leak to
another). Regenerate this reasoning with a probe before trusting SDK scoping
assumptions on a version bump.

**Process note:** PR #24 was merged after only ad-hoc self-review; the missed
singleton hazard was caught by a post-merge independent `architect` review.
Run the review-pr-loop (independent reviewer pass) BEFORE merging, not after.

```js
import { SessionPool } from "./daemon/src/session-pool.js";
const pool = new SessionPool();
const s = await pool.ensureSession("<some existing dir>");
const events = [];
await s.send({ type: "prompt", message: "reply with exactly: X" }, e => events.push(e));
console.log(events.find(e => e.type === "agent_end"));
await pool.shutdown();
```

## Capability layer is a process-global NOT isolated by the per-session Settings clone (upstream)

The per-workDir `Settings` clone (above) isolates model roles, but the SDK's
`capability/index.ts` keeps `disabledProviders` (module-global `Set`, src line
40) and its `settings` ref (line 43) as **process-global** state. Every
`createAgentSession` runs `initializeWithSettings(settings)`
(`sdk/session.ts:1060-1062`) which `disabledProviders.clear()` + repopulates
from that session's settings — **last-created session wins process-wide**.
`filterProviders` (line 210-211) reads this global to filter which
skills/rules/tools/MCP/hooks/context-files load, so an earlier live session can
resolve capabilities under a later session's disable-set. Probe confirmed
(0.11.4, re-confirmed 0.11.10): create A(`disabledProviders:["prov-A-only"]`)
then B(`["prov-B-only"]`) → `getDisabledProviders()` returns B's set and
`isProviderEnabled("prov-A-only")===true` (A's intent lost), while
`a.settings.get("disabledProviders")` stays correct — only the capability
module-global diverges. **Cannot be fixed by `cloneForCwd`** (clone isolates
Settings, not the SDK's separate capability global). Impact is LOW for typical
gjc-remote hosts where `disabledProviders` is global-only (every writer writes
the same value); it only bites with divergent per-workDir project overrides +
concurrent sessions. Decision: no local mitigation (any per-prompt
re-`initializeWithSettings` would be racy and reach below `/sdk`); tracked
upstream at **Yeachan-Heo/gajae-code#2774** with repro + suggested fix (thread
active `Settings` through capability load instead of a module global).
Upstream status: closed 2026-07-22 via their PR #2865 merged into `dev`
(`c2ca200`), but the fix is NOT in the 0.11.10 npm release — the probe above
still reproduces on 0.11.10. Re-probe on the next version bump.

## Windows owner-only session storage constraint (found during 0.11.10 bump)

The SDK's managed session storage applies fail-closed "owner-only" security
(`@gajae-code/natives` `applyOwnerOnlyPathSecurity`) to
`<workDir>/.gjc-remote-session`. On this Windows host it fails with
`owner_mismatch` for
workDirs under `E:/` and `C:/tmp` even though `dir /q` shows the same user as
owner, while workDirs under `C:/Users/<user>/` succeed (`~/.gjc/agent/sessions`
verifies ok). Reproduced identically on SDK 0.11.4 and 0.11.10 — an
environment/native-check trait, not a bump regression (earlier E:-drive smoke
passes predate wiping `.gjc-remote-session`; a fresh apply on those volumes
fails). Practical rule: **on Windows hosts, configure channel workDirs under
the daemon user's profile directory**, or investigate the native ownership
check before mapping other volumes. `SMOKE_WORK_DIR`/`SMOKE_WORK_DIR_2` must
also point inside the profile on this machine.

Also note: `SMOKE_MODEL_QUERY=sol` is now ambiguous (Copilot also ships
`gpt-5.6-sol`); the resolver fail-closes with both candidates as designed. Use
the exact `openai-codex:gpt-5.6-sol`.
