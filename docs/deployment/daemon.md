# Native daemon foreground deployment

Run one daemon on each host that owns mapped work directories. It embeds the
pinned official unpatched `@gajae-code/coding-agent` SDK **0.18.12**
and requires **Bun 1.4.0 or
later**. The daemon is not a bot sidecar: it opens an authenticated outbound
WebSocket connection to the independently deployed bot.

The daemon adapter rejects `steer` and `follow_up` while a prompt is active,
before SDK queue admission. Idle controls remain prompt-equivalent FIFO work.
SDK 0.18.12 includes the late-follow-up continuation fix for
[#5351](https://github.com/Yeachan-Heo/gajae-code/issues/5351) and public tracked
`submitUserMessage` ownership associated with
[#5429](https://github.com/Yeachan-Heo/gajae-code/issues/5429). API existence is
not qualified daemon integration; active controls remain fail-closed. See the
[containment record](../../CHANGELOG.md#sdk-0166-containment).

Actual post-admission parent SDK-only evidence: Windows focused 333/333; bounded workspace
2704 tests, 2700 pass, 0 fail, 4 skips; isolated Linux 248/248 without provider
calls. The workspace command used nine historical authority exclusion patterns,
not unrestricted `npm test`; skips are not passes or the complete exclusions.
See the [exact evidence boundary](../verification/issue62-evidence.md#current-parent-observations).
Canonical imports are exercised by real SDK probes, not independent
all-platform qualification. A single separately authorized native Windows smoke
passed with three exact `SMOKE_OK` responses in A-B-A order, existing
`codex-eco` child-only override, heartbeat/three successful invoke terminals,
exit 0 and ephemeral relay port free; no optional model query or wrapper retry.
The smoke was not repeated after fixture/test-only changes; production SDK runtime/
package/lock are unchanged. Current local runtime receipts are
`artifacts/sdk-first-0.18.12-admission2-focused.json`,
`artifacts/sdk-first-0.18.12-admission2-workspace.json`, and
`artifacts/sdk-first-0.18.12-admission2-wsl-final.json`.
Same-profile continuity is not isolation or a fix for #247.
Combined-worktree and historical results do not qualify this tree. Main native
code was freshly built unchanged; native lifetime, ACL, publication,
construction, and fixture repairs remain deferred. No private native fixture
pass, SOURCEPATCH change, admission recovery, native/service/security/fault/
OOM/noDump, production, release, support, installation, or deployment
qualification is claimed. Both original P2s and owner-admission are verified and
independently cleared in `artifacts/sdk-first-0.18.12-final-review.json`:
static agent review APPROVE, zero P0/P1/P2, not independent runtime or
CI/merge/deployment approval. Exact-head CI/landing is tracked in
[PR #265](https://github.com/kogangdon/gjc-remote/pull/265); the final follow-up is
not yet committed/pushed, and CI/merge completion is not claimed. Local
receipts alone do not approve landing; each run qualifies only its exact pins.
See [current SDK status](../../README.md#local-quick-start).

Upstream #6578 and direct repair #6700 remain open/unmerged and can affect
SDK-exposed Ultragoal/Ralplan workflow gates. Merged #6763's transcript-content
approval binding does not repair that guard deadlock. Do not bypass containment.

The bot and daemon must negotiate `gate_presentation_v1`,
`terminal_disposition_v1`, and `invoke_cancellation_v1` before serving a
gate-capable invoke; mixed peers refuse an invoke before execution, so deploy
both components lockstep. A workflow gate begins `awaiting_presentation` under
its exact `ownerId`, `gateId`, and `presentationId`. The bot renders a bounded
Discord gate message with the complete wire-bounded prompt/options attached,
then sends `present_gate`; only the exact accepted presentation receipt makes
that gate answerable. Presentation and abandonment receipts are nonterminal.
Answers bind the exact request, gate, and presentation to the original Discord
gate message, channel, and initiating user. Buttons/select menus are used when
suitable; free text must exactly reply to the original gate message, and
ordinary channel messages never satisfy a gate. The bot edits that original
message through Answering, Answered, Rejected—retry available, Expired,
Replaced, and Disconnected. Only an exact accepted answer receipt retires its
presentation; a rejected receipt retains the exact retry route. Presentation
failure or timeout sends `abandon_gate` while the socket is open and separately
requests `presentation_failed` cancellation without claiming active work was
interrupted. Duplicate attempt/answer IDs replay exact receipts, conflicting
reuse policy-closes, and bounded receipt capacity fails closed without evicting
live entries. Oversized gate protocol content is refused and quarantined rather
than silently truncated; the Discord preview is bounded but the attachment
preserves complete wire-bounded content. `cancel_invoke`
reasons are exactly `idle_timeout`, `hard_cap`, `disconnect`, `user_cancelled`,
and `presentation_failed`; `cancel_result` outcomes are exactly
`cancelled_before_start`, `cancellation_pending`, `already_terminal`, and
`not_owned`. A duplicate cancel ID replays its exact receipt. Request/cancel
tombstones are bounded and retained through the hard-cap/receipt horizon.

A queued request is revoked before SDK, provider, or tool execution, receives
`cancelled_before_start`, and then terminal `cancelled`. An active request
receives only nonterminal `cancellation_pending`: the daemon has no qualified
active-interruption integration, and its eventual natural terminal remains
authoritative. A cancellation receipt is not terminal or quiescence proof.

Its authoritative final frame is an `event` with an
`invoke_terminal` event, `done: true`, and no top-level `error`; the first
valid terminal frame wins. The only dispositions are `completed`, `failed`,
`cancelled`, `paused`, `timed_out`, and `disconnected`. Preserve `paused` and
`cancelled` as reported outcomes rather than flattening them to failure.
Neither `timed_out` nor `disconnected` proves the underlying SDK or process
was interrupted. A bot-local response timeout is likewise an unconfirmed local
failure, not a daemon `timed_out` disposition. On adapter timeout, the daemon
transfers the session/activity hold to SessionPool retirement containment (#234)
while cleanup settles because work may continue. On socket close, the daemon
synchronously quarantines exact socket-generation gate owners before
cancellation retirement and reconnect scheduling, revokes queued sibling
invokes, and retires each active shared session once through #234 containment.
It retains associated leases and admission fences until positive disposal
proof; no successor may adopt or downgrade owned work. The #231 live-control containment above remains active:
cancellation does not restore active `steer`/`follow_up` or unblock #231.

This repository provides the foreground start command below; it does not ship a
native service installer, service wrapper, or rendered systemd deployment
(source templates are under `native-control/src/systemd/`), and this guide is
not evidence of a completed live deployment.

The integration boundary is unchanged by the SDK bump. `gjc-remote` owns host
authentication, route/workDir selection, and workspace admission/lifecycle
policy. The embedded SDK runtime owns provider/model catalogs, provider
authentication, and agent-turn semantics. Public SDK `router` and `lifecycle`
namespaces are reserved for separate future external-session evaluation; no
adapter or migration is implemented. `sdk/broker` is not a public entrypoint.

## Prerequisites and provider identity

Install the workspace dependencies from the committed lockfile, Bun >=1.4.0,
and the native-control prerequisites for the host. Approved native-control
tuples are Linux x64/arm64 and Windows x64; macOS is unsupported.

Run the daemon process as a dedicated daemon OS account. Before starting it,
log into the provider interactively as that same account:

```sh
gjc
# then: /login <provider>
```

The provider credential and model configuration are retained in that account's
`~/.gjc`; every SDK session created by the daemon reuses them. Do not copy this
directory, a provider token, or another user's home directory into a service
account. The daemon's normal model profile comes from `~/.gjc/agent/config.yml`
(`modelProfile.default`), with project overrides resolved through SDK-owned
scope-local settings. A nonblank `GJC_MODEL_PROFILE` overrides that name without
persisting a new default. Failure to activate a selected named profile fails
session creation. If no usable name remains, the adapter warns and retains the
SDK default model, which may be unauthenticated and return empty responses.
Explicitly select a usable, authenticated profile for each workDir; this is an
operator requirement, not a new daemon preflight.

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

For a supervised instance, `HOST_ID` is protected configuration input, not a
service name. The service key is the lower-case display slug (at most 32 ASCII
characters) followed by the full lower-case SHA-256 of the exact UTF-8
`HOST_ID`. Do not trim, normalize, case-fold, or substitute the service key;
the raw host ID is never emitted in service metadata, journals, manifests, or
public status.

Do not run the daemon as a user chosen merely for convenience. Its provider
identity, `~/.gjc` state, and filesystem permissions define the work it can
perform. The session storage and provider state are host-local and must be
included deliberately in host backup and recovery procedures; restoring them
onto a different account or path can invalidate ownership and provider access.

## Shutdown, monitoring, and recovery

On a stop signal the daemon begins its bounded shutdown procedure under
`GJC_SHUTDOWN_TIMEOUT_MS`, default 15,000 ms. This is not a drain guarantee:
pending invokes or gates may fail, and forced termination is an operational
failure because active workflows and local state may not have reached their
normal cleanup boundary. Configure the external service supervisor's stop
timeout above it. Socket close containment revokes queued siblings before
execution and starts #234 retirement for active shared sessions; it is not
proof that active SDK/provider work was interrupted.

Monitor daemon process health, outbound WebSocket registration at the bot,
provider/profile failures, gate presentation/abandonment/answer receipt
outcomes, gate quarantine, and the expected mapped workspace state separately.
A connected daemon is not proof that provider authentication, model selection,
or a particular workspace is ready. The bot's `/hosts` and its structured logs
are the operator view of connection and readiness, while the daemon service
logs provide local startup and shutdown diagnostics. Keep gate observability
metadata-only: never export prompt or answer text, workDir/path data, provider
or host tokens, or Discord attachment contents.

`SESSION_RETIREMENT_PENDING` means late SDK cleanup is still pending. Wait for
that cleanup to settle, then retry; do not assume disposal has succeeded.
`SESSION_RETIREMENT_FAILED` is a permanent, process-local fence. Investigate
the old SDK work and ensure it is gone before restarting the daemon; do not
blindly retry the operation or reuse the fenced session.

Before an upgrade, record the deployed revision, Bun and SDK versions,
`HOST_ID`, service-account identity, model profile, and protected-state backup
status. Deploy bot and daemon lockstep for `terminal_disposition_v1` and
`invoke_cancellation_v1`, and `gate_presentation_v1`: after one side updates,
an old peer cannot serve invokes and the mixed pair fails closed. Stop new
in-flight admission and require positive terminal/quiescence evidence where
available before rollback; this is not a supervisor drain guarantee and
pending work may fail. Never downgrade owned work while
#234 leases and fences await positive disposal proof. Stop gracefully, install
the new locked dependencies, restart, then confirm registration, negotiated
invoke capabilities, and a known authorized route. Roll back binaries only
when the local persistence and mapping-authority state remain compatible. Do
not treat copied `~/.gjc`, session state, or an old authority snapshot as a
safe generic rollback: tokens may be account-bound and durable authority floors
must not be rewound. Prefer forward recovery under the current authority
contract.

## Native service lifecycle boundary

The host-local controller is package **`@gjc-remote/native-control`**, exposed
as **`gjc-remote-service`**. The exact six operations are `install`, `status`,
`update`, `rollback`, `uninstall`, and `recover`; the executable accepts one
operation and one strict JSON request on non-terminal stdin, with no flags or
caller-selected URL/root. `status` is read-only and reports no writes.

Install/update/rollback trial an immutable, content-addressed application
release before automatic activation and retain the exact immediate predecessor.
The controller references, but never creates or rewrites, the daemon's Bun
runtime, account, HOME, `.gjc` provider state, `.env`, workspaces,
`.gjc-remote-session`, logs, or mapping authority. A signed application asset,
the purpose-specific application deployment key, and the platform human gate
are release requirements; the repository does not claim a signed production
release or real service run. The Windows Shawl asset uses a separate
purpose-specific deployment key.

Recovery is exact-transaction replay only. Missing, stale, foreign, hybrid,
torn, or recreated records/resources enter durable `manual-cleanup` and remain
untouched until the recorded operator action has produced the expected proof.
Recovery never adopts by name, repairs external state, or claims migration or
drain. Any pending work may be lost during stop; preserve external bytes and
inspect host state before retrying.

Lifecycle `status` separates startup evidence from live health. A fresh
current-epoch receipt binds boot identity, InvocationID or wrapper/child epoch,
exact process lineage, and a continuous log/journal cursor; after the bounded
startup window it is historical, not a health protocol. Connectivity is only a
last observation (`last-observed-connected`/`last-observed-disconnected`), and
provider and workspace health remain `unknown`. A connected daemon or
`active (running)` service therefore does not prove current readiness.

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
