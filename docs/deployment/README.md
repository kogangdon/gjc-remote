# Deployment guide

Deploy the bot and each daemon independently. The bot is the Discord-facing
control plane; every daemon runs on the host that owns its work directories and
connects **outbound** to the bot over WebSocket. A mapped channel can execute
code on that host. Read [Security](../../SECURITY.md) before provisioning.

## Status matrix

| Component | Native status | Container status | Supported platforms |
| --- | --- | --- | --- |
| Bot | Foreground available with Node.js >=26; supervisor evidence is platform-specific | Linux-only release candidate; no signed-image release evidence | Native-control: Linux x64/arm64, Windows x64 |
| Daemon | Foreground available with Bun >=1.3.14 and SDK 0.12.21; supervisor evidence is platform-specific | Not available; daemon Docker is a future phase | Native-control: Linux x64/arm64, Windows x64 |
| Native control | Observed only on the approved tuples | Used by the bot container candidate only with an externally verified bundle | Linux x64/arm64, Windows x64 |

macOS is not supported for native-control. “Available” describes the current
foreground execution contract, not boot supervision, production promotion, or
tenant isolation. “Release candidate” and “future phase” are design/release
states, not observed production support.

## Choose a guide

- [Native bot deployment](bot.md)
- [Native daemon deployment](daemon.md)
- [Workspaces and paths](workspaces-and-paths.md)
- [Linux](platforms/linux.md), [Windows](platforms/windows.md), and
  [macOS](platforms/macos.md) platform notes
- [Bot Docker](docker/bot.md) and [daemon Docker status](docker/daemon.md)
  (the current bot-container implementation details are in
  [`deploy/docker/bot/README.md`](../../deploy/docker/bot/README.md))

For mapping-authority and readiness invariants, use
[management mapping](../management-mapping-envelope.md),
[bind-authority verification](../adr/0004-workspace-bind-authority-verification.md),
and [workspace readiness](../protocol-v2-workspace-readiness.md). These are
contracts, not a substitute for an operator rollback plan.
