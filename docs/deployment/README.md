# Deployment guide

Deploy the bot and each daemon independently. The bot is the Discord-facing
control plane; every daemon runs on the host that owns its work directories and
connects **outbound** to the bot over WebSocket. A mapped channel can execute
code on that host. Read [Security](../../SECURITY.md) before provisioning.

## Status matrix

| Component | Native status | Container status | Supported platforms |
| --- | --- | --- | --- |
| Bot | Foreground command documented for Node.js >=26; no native service installer is shipped | Linux-only release candidate; no signed-image release evidence | Native-control: Linux x64/arm64, Windows x64 |
| Daemon | Foreground command documented for Bun >=1.4.0 and SDK 0.16.6; no native service installer is shipped | Not available; daemon Docker is a future phase | Native-control: Linux x64/arm64, Windows x64 |
| Native control | Observed only on the approved tuples | Used by the bot container candidate only with an externally verified bundle | Linux x64/arm64, Windows x64 |

macOS is not supported for native-control. “Foreground command documented”
describes only the current command contract, not boot supervision, production
promotion, or tenant isolation. “Release candidate” and “future phase” are
design/release states, not observed production support.

The installed SDK 0.16.6 pin keeps live controls fail-closed: an active
`steer` or `follow_up` is rejected before SDK queue admission, while an idle
control remains prompt-equivalent FIFO work. The published package lacks the
upstream late-follow-up continuation fix and a supported ownership lifecycle;
the latter is tracked in
[upstream #5429](https://github.com/Yeachan-Heo/gajae-code/issues/5429).
See the [containment record](../../CHANGELOG.md#sdk-0166-containment).

No guide in this directory claims a completed live deployment. The repository
ships no native service installer, Windows service wrapper, or systemd unit;
supervisor material is evaluation and operator guidance only.

The daemon continues to embed the SDK in-process. `gjc-remote` owns host,
route, and workspace policy; the SDK runtime owns model/provider catalogs,
provider authentication, and turn semantics. The Broker/Router surfaces are
reserved for separate evaluation as a future external-session path, with no
migration implemented.

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
