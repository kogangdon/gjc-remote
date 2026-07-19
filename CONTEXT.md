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
   serialized per session. `steer` and `follow_up` dispatch into an active run
   without waiting behind its prompt, while each control request remains open
   through the resulting `agent_end` and receives its event stream. Idle sessions
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

Items 1, 2, 4, and 7 below describe the superseded RPC implementation and are
retained only as regression history. GJC 0.11 removed that ingress; current
session transport lives in `daemon/src/sdk-session.js`.

1. **Event frame unwrapping.** GJC's RPC stdio protocol wraps streamed
   frames as `{type:"event", payload:{event_type, event}}`, not a flat
   `{type: event_type}`. `daemon/src/rpc-client.js` unwraps this before
   handing events to callers.
2. **Concurrent-request correlation race.** GJC's streamed frames don't echo
   the request `id`, so there's no way to route a frame to a specific
   in-flight command when more than one is outstanding. GJC can emit
   `turn_end` for intermediate tool-use turns before the full run reaches
   `agent_end`. Fix: `RpcSession` in `rpc-client.js` serializes all commands
   through a single-in-flight FIFO queue, resolves prompt-like commands only
   at the full-run `agent_end` boundary, and holds the queue briefly so trailing
   frames cannot be assigned to the next command.
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
4. **Daemon-wide crash on spawn failure.** A `child_process.spawn` `ENOENT`
   (e.g. bad `workDir`, missing `GJC_BIN`) fires an async `'error'` event,
   not a throw — an unhandled one crashes the whole Node/Bun process, not
   just the failing request (reproduced: one bad `workDir` invoke killed the
   entire daemon, dropping every other host session on that machine). Fixed
   in two places: `session-pool.js` checks `existsSync(workDir)` before
   spawning, and both `session-pool.js`'s `child.on("error", ...)` and
   `rpc-client.js`'s `RpcSession` route spawn errors into a clean rejection
   instead of leaving them unhandled.
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
7. **RPC termination left unresolved work.** Child `exit`/`error` now rejects
   the active command and every queued command exactly once. A command timeout
   permanently closes and kills that RPC session instead of dispatching queued
   work on a process whose late frames cannot be correlated safely. The next
   request creates a replacement session, and a delayed exit from the poisoned
   child cannot remove that replacement from `SessionPool`.
8. **Equivalent workDir spellings created duplicate sessions.** `SessionPool`
   resolves every existing native workDir through the host filesystem and uses
   that canonical real path for the pool key, SDK cwd, and session directory.
   Separator, case, or symlink aliases that resolve to one directory therefore
   reuse one live GJC SDK session.

## Runtime: Bun vs Node

`@gajae-code/coding-agent` 0.11.1 requires Bun 1.3.14 or newer, so the daemon
starts with Bun and embeds GJC in-process. The bot and Node built-in test runner
remain Node-compatible. `bun.lock` is the committed dependency lockfile;
`package-lock.json` is gitignored.

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

1. **Real Discord wiring never run end-to-end.** The non-Discord relay path is
   covered by `npm run smoke:local`, which starts a local `HostRegistry`, starts
   `daemon/src/daemon.js` under Bun, sends a prompt through a real embedded GJC
   SDK session, and asserts the assistant text returned through the bot relay.
   Actually registering slash commands and running `bot/src/bot.js` against a
   real Discord application + real `DISCORD_TOKEN` has not happened.
2. **`channels.json` does not exist yet** (gitignored, copy from
   `channels.example.json`) — needs real Discord channel IDs once a server
   exists.
3. **`GJC_BOT_ALLOWED_USERS` allowlisting** — implemented in `bot.js` but
   never actually exercised against a real Discord guild. Must be set
   before inviting the bot anywhere shared (unrestricted = anyone in-channel
   can run arbitrary GJC workflows — file writes, bash, etc. — on every
   connected host).
   Shared/production deployment must also set
   `GJC_REMOTE_REQUIRE_ALLOWLIST=1`; local unrestricted mode remains available
   only for backward-compatible development and emits a startup warning.
4. **Linux/macOS daemon path unverified.** Everything was built and tested on
   native Windows (this repo's origin host). The Bun embedding SDK path avoids
   socket and tmux dependencies but has not actually been run on Linux/macOS
   yet. Run the real local smoke first on each additional platform.
5. **No process supervision configured** — `README.md` mentions pm2/systemd
   as options but nothing is set up. Bot and each daemon currently need to
   be started manually.
6. **`/hosts` and progress-streaming (tool-call preview during a running
   command) are implemented but unverified against real Discord** — only the
   underlying `HostRegistry`/SDK session plumbing they depend on has been
   tested.
7. **Remote host files are not attached automatically.** Assistant output may
   contain absolute paths from the daemon host, but the Discord bot treats those
   paths as text. It never reads matching paths from the bot host. A future
   daemon-to-bot file transfer requires an explicit allowlisted protocol; the
   generated long-output and tool-log attachments remain supported because they
   are created in memory by the bot.

## Verification pattern to reuse

Whenever you touch `daemon/src/*` or `bot/src/host-registry.js`, run
`npm run smoke:local` against the installed `@gajae-code/coding-agent` SDK
rather than trusting unit doubles. The smoke script is the preferred reusable
verification path because it starts the real Bun daemon and embedded agent.

```js
import { SessionPool } from "./daemon/src/session-pool.js";
const pool = new SessionPool();
const s = await pool.ensureSession("<some existing dir>");
const events = [];
await s.send({ type: "prompt", message: "reply with exactly: X" }, e => events.push(e));
console.log(events.find(e => e.type === "agent_end"));
await pool.shutdown();
```
