# Deployment guide

Deploy the bot and each daemon independently. The bot is the Discord-facing
control plane; every daemon runs on the host that owns its work directories and
connects **outbound** to the bot over WebSocket. A mapped channel can execute
code on that host. Read [Security](../../SECURITY.md) before provisioning.

## Status matrix

| Component | Native status | Container status | Supported platforms |
| --- | --- | --- | --- |
| Bot | Foreground command documented for Node.js >=26; no native service installer is shipped | Linux-only release candidate; no signed-image release evidence | Native-control: Linux x64/arm64, Windows x64 |
| Daemon | Foreground command documented for Bun >=1.4.0 and SDK 0.19.0; no native service installer is shipped | Not available; daemon Docker is a future phase | Native-control: Linux x64/arm64, Windows x64 |
| Native control | Observed only on the approved tuples | Used by the bot container candidate only with an externally verified bundle | Linux x64/arm64, Windows x64 |

macOS is not supported for native-control. “Foreground command documented”
describes only the current command contract, not boot supervision, production
promotion, or tenant isolation. “Release candidate” and “future phase” are
design/release states, not observed production support.

The official unpatched SDK 0.19.0 source pin keeps live controls fail-closed: an active
`steer` or `follow_up` is rejected before SDK queue admission, while an idle
control remains prompt-equivalent FIFO work. The published package includes the
late-follow-up continuation fix and public tracked submission ownership, but
daemon live-control integration and qualification remain outstanding. Active
cancellation remains nonterminal `cancellation_pending`, not proof of interruption.
Upstream #6578 is closed and #6700 is closed unmerged. Repair #6970 is included
in the official 0.19.0 release notes; that is not a local workflow-gate PASS.
#6763's approval binding is a separate change. Do not bypass containment.
See the [current SDK boundary](daemon.md).

### Current SDK-only evidence

Current official 0.19.0 source evidence is tracked in the
[current SDK-only 0.19.0 evidence record](../daemon-workspace-verification.md#current-sdk-only-0190-evidence)
and records Windows focused 265/265, unrestricted workspace 2739 pass/zero fail/10
skips, canonical imports, and one newly authorized same-profile provider smoke.
Review/CI/landing are tracked separately; no signed-release, installation, or
deployment PASS is claimed here.
The 0.18.12 receipts and PR #265 below are historical and do not qualify 0.19.0.
The existing uninstall generation/schema defect is tracked separately in
[repository issue #273](https://github.com/kogangdon/gjc-remote/issues/273)
and is excluded from the SDK upgrade scope. Changing the SDK source does not
authorize rebuilding, signing, or installing under an immutable old release tag.

### Historical SDK-only 0.18.12 evidence

Post-admission parent-run local receipts for the prior main-based 0.18.12 SDK-only tree record Windows
focused **333/333 passed**, zero skips, and bounded Windows workspace **2704
tests: 2700 passed, 0 failed, 4 skipped**. Skips are not passes. The workspace
used `--test-concurrency=4` and the explicit `--test-skip-pattern` below; its
nine historical authority exclusions are not represented by just four skips:

```text
inventory ACL verification atomically|Windows verified handle removal unlinks|Windows management-auth native ACL creation|verified native addon enforces retained-handle|POSIX principal access rejects|POSIX named ACL groups match|Win32 legacy no-replace creation|current management or system caller can reapply|opted-in Windows hosted runner provisions
```

Actual isolated, credentialless Linux verification passed **248/248**, without
provider calls. One separately authorized native Windows provider smoke
**passed**, using the existing `codex-eco` profile via a runtime-only child
environment override: three exact `SMOKE_OK` responses in A-B-A order,
heartbeat and three successful invoke terminals, exit 0, and the ephemeral
relay port free after exit. There was no optional model query, wrapper retry,
or wrapper persistent profile write. This proves only same-profile basic
continuity, not profile/tenant isolation or a proven #247 disconnect fix.
Aggregate oracle success does not establish standalone SDK abort support.
The single smoke was not repeated after the historical fixture/test-only changes;
the SDK runtime/package/lock were unchanged within that 0.18.12 verification.
Historical receipts are
`artifacts/sdk-first-0.18.12-admission2-focused.json`,
`artifacts/sdk-first-0.18.12-admission2-workspace.json` and
`artifacts/sdk-first-0.18.12-admission2-wsl-final.json`; the smoke remains
`artifacts/sdk-first-0.18.12-provider-smoke.json`.

Main native code was freshly built unchanged; separate native lifetime, ACL,
publication, construction, and fixture repairs were deferred. No private
native fixture or combined SDK/native result qualified that tree. These local
receipts are unshipped and alone do not approve landing. Both original P2s and
owner-admission are verified and independently cleared in
`artifacts/sdk-first-0.18.12-final-review.json`: static agent review APPROVE,
zero P0/P1/P2, not independent runtime or CI/merge/deployment approval.
The historical 0.18.12 landing reference is [PR #265](https://github.com/kogangdon/gjc-remote/pull/265),
not evidence for the current 0.19.0 source;
each run qualifies only its exact pins. Native/service/security/fault/OOM/noDump, signed deployment,
installation, production, release, and support qualification remain excluded.

No guide in this directory claims a completed live deployment. The repository
ships source systemd templates under `native-control/src/systemd/`, but no
rendered units, live host deployment, native service installer, or Windows
service wrapper; supervisor material is evaluation and operator guidance only.

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
