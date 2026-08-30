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
## Management mapping control plane

#44 management mapping is a separate, native-gated control plane. Its sole
writer uses protected stdin for secrets and stores only a secret-free host-ID
fingerprint; ordinary Discord authorization does not grant management authority.
See [`docs/management-mapping-envelope.md`](docs/management-mapping-envelope.md)
for bootstrap, rotation, recovery, audit, and fail-closed native-addon rules.
Native serving and readiness remain blocked and outside this contract.

## Workspace bind-authority verification (#179)

The daemon no longer trusts a bind's `authorityFingerprint` on first use. Every
managed `BIND_WORKSPACE` frame now carries the full `mapping` preimage, and the
daemon **independently recomputes** the mapping fingerprint and rejects any bind
whose preimage does not self-consistently hash to the claimed authority, whose
`hostId` is not this daemon's own, or (where a native workspace root is
configured) whose `sourceRoot` escapes that root. Verification runs ahead of
every dedup / floor / cap short-circuit on the live receipt-bind path (only a
fail-closed `hostId`/commit guard precedes it), and fails closed (socket
`close(1008)`, no `BIND_OK`, no adoption).
A `WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY` hard floor refuses — in both
directions — to serve a binding-capable peer that lacks the capability, instead
of silently negotiating down to an unverified handshake.

This is an **authenticity** control (the bind matches a self-consistent mapping
the bot committed to), layered on top of the daemon's existing load-bearing
mitigation: **the served `workDir` is resolved exclusively from the daemon's own
locally-scanned inventory, never from any bind preimage field.** Verification
hardens the bind path; it does not, and is not claimed to, replace inventory
resolution.

### Residual-trust model (honestly scoped)

1. **Tier-2 lexical containment is configured-root-only.** The `sourceRoot`
   containment check is an *additive* hardening that only applies when a native
   workspace root is configured; it is a no-op — and is **not** claimed to close
   any gap — on the default no-configured-root deployment. It does not close the
   default-deployment gap.
2. **Inventory resolution is the primary default-deployment mitigation.** On the
   default deployment the served `workDir` always equals the daemon's own
   inventory entry and is never derived from the preimage; this, not lexical
   containment, is the load-bearing control there.
3. **Legacy workDir mappings are hash+hostId-only.** A mapping with no
   daemon-known root is verified for self-consistency and host identity but
   cannot be containment-checked; this is a named, bounded residual.
4. **No no-follow (tier-3) containment.** Where a root *is* configured, the
   absence of a no-follow tier still permits an intermediate reparse-point /
   symlink swap between check and use; named and bounded, tracked in #200.
5. **`authorityEpoch` / generation counters are channel-trusted.** No
   daemon-local ground truth exists to independently verify the epoch/generation
   monotonic counters; they remain fence-checked but not authenticity-verified —
   an explicitly documented residual TOFU, not solved by #179.
6. **Valid-envelope-wrong-intent is permanently out of scope.** #179 proves a
   bind is *authentic* (matches a self-consistent, host-bound mapping the bot
   committed to). It does **not** prove the bind is *authorized* for the intent
   behind it. Authorization is owned by the `HOST_TOKEN` / channel-management
   layer; conflating authenticity with authorization is a standing,
   permanently-open residual, not a phase-1 deferral.

The defense-in-depth wiring of the legacy v2 `acceptWorkspaceBinding` path, the
no-follow tier, `containerRoot` ground truth, and surfacing the `BIND_AUTHORITY_*`
reject code in the socket close reason are tracked follow-ups (#200); they are hardening, not open live
gaps, because the v2 path cannot serve a managed workspace from a compliant bot.
See [`docs/adr/0004-workspace-bind-authority-verification.md`](docs/adr/0004-workspace-bind-authority-verification.md).

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
(currently `0.12.21`, pinned in `daemon/package.json` and `bun.lock`). Security
fixes land on `main`; there are no long-term support branches.
