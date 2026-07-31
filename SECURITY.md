# Security Policy

## ⚠️ What this software does

`gjc-remote` bridges Discord to GJC coding-agent sessions running on your
machines. **A mapped Discord channel can run arbitrary GJC workflows — bash
commands, file reads/writes, network access — on the host that channel is
mapped to.** Treat every authorized Discord user as holding a shell on those
hosts. This is the intended capability, not a bug; secure it accordingly.

## Trust model

- **The bot host** holds the Discord token and the map of channels → hosts. It
  is the control plane; compromising it compromises every connected host.
- **Host tokens** (`HOST_TOKENS` on the bot, `HOST_TOKEN` on each daemon) are
  pre-shared secrets that authenticate a daemon's identity. They are **not**
  transport encryption. Treat them like passwords; rotate per host if one leaks.
- **Daemons connect outbound** to the bot's WebSocket server. That port only
  needs to be reachable from your daemon hosts on a private network — it must
  **never** be exposed to the public internet.
- **Authorization** is enforced by `GJC_BOT_ALLOWED_USERS` (Discord user IDs).
  The bot ships fail-closed: `GJC_REMOTE_REQUIRE_ALLOWLIST=1` refuses to start
  with an empty allowlist.

## Built-in guardrails

- Fail-closed authorization by default (`GJC_REMOTE_REQUIRE_ALLOWLIST=1`).
- WebSocket frames are text JSON, validated against required protocol fields and
  rejected before routing when malformed; capped at 8 MiB (both ends). Invoke
  message text is capped at 1 MiB.
- Each host is limited to 64 concurrent in-flight invokes; excess requests fail
  locally instead of growing an unbounded pending map.
- Invalid `channels.json`, `HOST_TOKENS`, allowed-user, or allowlist config
  fails before routing starts; a bad hot-reload of `channels.json` keeps the
  last valid map.
- Session history is stored under `<workDir>/.gjc-remote-session` with the SDK's
  fail-closed owner-only path security.

## Operator hardening checklist

- [ ] Set `GJC_BOT_ALLOWED_USERS` to your own Discord user ID(s) before inviting
      the bot anywhere. Keep `GJC_REMOTE_REQUIRE_ALLOWLIST=1`.
- [ ] Keep the bot's WS port private (VPN, private subnet, or SSH/WireGuard
      tunnel). Host tokens do **not** encrypt traffic — use `wss://`, a VPN, or a
      tunnel outside a single trusted network.
- [ ] Use a unique, high-entropy `HOST_TOKEN` per host. Rotate on suspicion.
- [ ] Run daemons as a least-privilege user, ideally in a container or VM, so a
      compromised channel cannot reach beyond the intended workDirs.
- [ ] Enable the Discord "Message Content Intent" only if you use plain-chat
      prompts; prefer slash commands otherwise.
- [ ] Review which workDirs each channel maps to — each is a code-execution
      surface.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue:

- Use GitHub's private vulnerability reporting (repository **Security → Report a
  vulnerability**), or
- Open a minimal GitHub issue asking for a private contact channel without
  disclosing details.

Include a description, affected component (bot/daemon/shared), reproduction
steps, and impact. Please allow a reasonable window for a fix before public
disclosure. There is no bug-bounty program; this is a community project.

## Supported versions

This project tracks a specific embedded `@gajae-code/coding-agent` release
(currently `0.12.5`, pinned in `daemon/package.json` and `bun.lock`). Security
fixes land on `main`; there are no long-term support branches.
