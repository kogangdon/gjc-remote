# Context handoff — gjc-remote

Written for whichever GJC session picks this repo up next. Read this before
touching code; it captures *why* things are shaped this way, not just what
they do (README.md covers the what/setup).

## Goal

Control multiple GJC sessions, running on multiple hosts that are not always
online, from a single Discord bot exposing GJC's bundled workflow skills
(`deep-interview`, `ralplan`, `team`, `ultragoal`) plus direct prompts and
runtime model switching as `/slash` commands.

## Architecture (confirmed, implemented, e2e-tested)

```
[host machine, per project]                    [always-on bot host, private network]
  gjc --mode=rpc (stdio)   <--stdin/stdout-->    daemon/  --WS(outbound)-->   bot/
  (spawned on demand per                                              (WS server +
   workDir, reaped after                                               Discord client)
   1h idle)
```

1. `daemon/` runs on every machine you want to control. It opens an
   **outbound** WebSocket to `bot/`'s WS server and registers with a
   pre-shared per-host token. Outbound-only means the host can sit behind
   NAT/firewall with no inbound port, and does not need to be always-on —
   when its daemon isn't connected, the bot treats that host's channels as
   offline and fails fast instead of hanging.
2. On the first Discord command routed to a given `workDir`, the daemon
   spawns `gjc --mode=rpc` (stdio, cwd=workDir) and keeps talking to it over
   its stdin/stdout for subsequent commands on the same `workDir`. Idle
   sessions (`IDLE_TIMEOUT_MS` = 1h, in `shared/protocol.js`) are killed.
3. `bot/` is the only component holding the Discord token. It runs a WS
   server (`bot/src/host-registry.js`) that daemons connect to, and maps
   each Discord channel to one `{hostId, workDir}` pair via
   `bot/channels.json` (gitignored — copy from `channels.example.json`).
   In mapped channels, ordinary non-bot messages from allowed users are treated
   as direct GJC prompts; slash commands remain available for skills/model/hosts.

## Why NOT the alternatives (rejected paths, don't re-litigate these)

- **SSH pull (bot SSHes into each host)** — rejected. Requires the target
  host to run an SSH server and be reachable inbound; breaks the "host isn't
  always online" requirement. The WS-push model (host dials out to the bot)
  was chosen specifically to invert this.
- **`gjc --mode=rpc --listen <unix-socket>`** — rejected for cross-platform
  use. Verified experimentally: GJC's `prepareRpcSocketPath` enforces POSIX
  `0o700`-only directory permissions (`rpc-socket-security.ts`,
  `assertPrivateMode`). Node's `fs.mkdir(..., {mode: 0o700})` is a no-op on
  NTFS, so this **always** throws `RpcSocketSecurityError: ... has
  group/other permissions` on Windows. No env var/flag bypasses it — it's a
  hardcoded security gate. Likely fine on Linux/macOS but not verified there
  yet. Decision: use `gjc --mode=rpc` over **stdio** instead (no socket file
  at all), which works identically on every OS. If a real need for
  reconnect-without-respawn resurfaces, revisit UDS on POSIX hosts only.
- **`gjc session` / `gjc team` (tmux-backed)** — separately confirmed
  Windows-incompatible: `tmux` binary isn't available/expected on native
  Windows and `gjc session list` hard-crashes with `Executable not found in
  $PATH: "tmux"`. Unrelated to the RPC socket issue above — two independent
  Windows gaps. Not used by this project's architecture at all (we drive
  skills via `/skill:<name>` prompt text over RPC, not via `gjc team`).
- **One `gjc -p "..."` subprocess per Discord command** — this was the
  *first* working prototype (now deleted, used to live at
  `C:/tmp/gjc-discord-bridge`). It worked (verified: parallel isolated
  sessions via `--session-dir` + `--continue`) but can't inject into an
  *already-running* session or stream live progress — each call is a fresh
  process that exits. Superseded once `--mode=rpc` was discovered. Don't
  resurrect this path; `daemon/` supersedes it entirely.

## Bugs found and fixed during implementation (all via real `gjc` execution, not guessed)

1. **Event frame unwrapping.** GJC's RPC stdio protocol wraps streamed
   frames as `{type:"event", payload:{event_type, event}}`, not a flat
   `{type: event_type}`. `daemon/src/rpc-client.js` unwraps this before
   handing events to callers.
2. **Concurrent-request correlation race.** GJC's streamed frames don't echo
   the request `id`, so there's no way to route a frame to a specific
   in-flight command when more than one is outstanding. GJC also emits a
   trailing `agent_end` echo *after* `turn_end` for the same turn. If a
   second command had already dispatched by the time that echo arrived, it
   used to get misrouted onto the new command (reproduced: asked for
   "SECOND", got "FIRST" back). Fix: `RpcSession` in `rpc-client.js`
   serializes all commands through a single-in-flight FIFO queue, and
   **only `turn_end` is treated as a completion signal** — `agent_end` is
   deliberately ignored (dropped by the `!waiter` guard once nothing is
   listening for it anymore).
3. **`set_model` needs exact `{provider, modelId}`, not a free-text name.**
   Discord users type "haiku"/"opus"/etc; GJC's CLI does fuzzy matching
   internally for `--model` but the RPC protocol's `set_model` command does
   not. Fix: `daemon/src/model-lookup.js#resolveModel` calls
   `get_available_models` first and fuzzy-matches (exact id match wins;
   otherwise substring match on id/name, preferring entries whose name
   contains "(latest)", then shorter ids). Verified: "haiku" -> `Anthropic
   Haiku 4.5 (latest)` / `claude-haiku-4-5`, applied and confirmed via a
   follow-up prompt.
4. **Daemon-wide crash on spawn failure.** A `child_process.spawn` `ENOENT`
   (e.g. bad `workDir`, missing `GJC_BIN`) fires an async `'error'` event,
   not a throw — an unhandled one crashes the whole Node/Bun process, not
   just the failing request (reproduced: one bad `workDir` invoke killed the
   entire daemon, dropping every other host session on that machine). Fixed
   in two places: `session-pool.js` checks `existsSync(workDir)` before
   spawning, and both `session-pool.js`'s `child.on("error", ...)` and
   `rpc-client.js`'s `RpcSession` route spawn errors into a clean rejection
   instead of leaving them unhandled.

## Runtime: Bun vs Node

`gjc` itself is Bun-compiled (uses `Bun.spawnSync`, `Bun.listen`, etc. —
visible in its own crash stack traces). `bot/` and `daemon/` are written in
plain Node-compatible ESM (no Bun-only APIs) so either runtime works; **Bun
is the intended/tested runtime** (`bun install`, `bun run`) since it matches
what `gjc` itself uses and was what full e2e verification ran under.
`package-lock.json` is gitignored; `bun.lock` is the committed lockfile.

## Decided config values (don't re-ask the user these)

- Idle GJC-RPC-process timeout: **1 hour** (`IDLE_TIMEOUT_MS` in
  `shared/protocol.js`).
- Host<->bot auth: pre-shared per-host tokens (`HOST_TOKENS` on bot,
  `HOST_TOKEN` on each daemon), explicitly deferred stronger auth
  (mTLS/keypairs) to "later, if it becomes a problem."
- Session key / isolation unit = **(hostId, workDir)** pair, one Discord
  channel maps to exactly one pair via `bot/channels.json`.
- Multi-host management = **one bot process**, many daemons connecting to
  it (not one bot per host). Confirmed explicitly by the user.

## What is NOT done yet (pick up here)

1. **Real Discord wiring never run end-to-end.** The non-Discord relay path is
   now covered by `npm run smoke:local`, which starts a local `HostRegistry`,
   spawns `daemon/src/daemon.js`, sends a prompt through a real `gjc --mode=rpc`
   process, and asserts the assistant text returned through the bot relay.
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
4. **Linux/macOS daemon path unverified.** Everything was built and tested
   on native Windows (this repo's origin host). The stdio-based
   `gjc --mode=rpc` approach *should* be OS-agnostic (no socket files, no
   tmux), but has not actually been run on Linux/macOS yet. If you're
   picking this up on such a host: this is the first thing worth smoke
   testing (`npm run smoke:local`).
5. **No process supervision configured** — `README.md` mentions pm2/systemd
   as options but nothing is set up. Bot and each daemon currently need to
   be started manually.
6. **`bot.js`'s `/hosts` and progress-streaming (tool-call preview during a
   running command) are implemented but unverified against real Discord** —
   only the underlying `HostRegistry`/`RpcSession` plumbing they depend on
   has been tested.

## Verification pattern to reuse

Whenever you touch `daemon/src/*` or `bot/src/host-registry.js`, run
`npm run smoke:local` against a **real** `gjc` binary rather than trusting the
protocol docs — every protocol bug so far was only found by actually spawning
`gjc --mode=rpc` and inspecting real stdout frames. The smoke script is the
preferred reusable verification path.

```js
import { SessionPool } from "./daemon/src/session-pool.js";
const pool = new SessionPool();
const s = pool.ensureSession("<some existing dir>");
const events = [];
await s.send({ type: "prompt", message: "reply with exactly: X" }, e => events.push(e));
console.log(events.find(e => e.type === "turn_end"));
pool.shutdown();
```
