# Daemon workspace-container contract

This document freezes the issue #43 invariants consumed by #42 deployment work. It is a design
contract, not a Dockerfile or production deployment guide.

## Topology and mounts

Use one persistent daemon container per host, independently deployed from the bot. The daemon
has no inbound listener and uses outbound private WebSocket registration. Same-host Compose is
test-only.

| Role | Path | Rules |
| --- | --- | --- |
| workspace | `/workspaces` | Repositories/worktrees; bind-backed only through a declared mapping |
| session | `/var/lib/gjc-remote/sessions` | SDK histories, separate from workspaces |
| provider | `/home/gjc/.gjc` | Runtime daemon identity's provider state |
| state | `/var/lib/gjc-remote/state` | Registry, locks, leases, journals, readiness, manifests |
The daemon state volume contains only an authenticated #44 mapping snapshot/fingerprint and
validation receipts; #44 alone mutates the authoritative mapping registry. The daemon never
creates a parallel mapping source of truth.

Only these roles are writable. The image root is read-only. Runtime defaults are fixed non-root
UID/GID, `HOME=/home/gjc`, bounded isolated `/tmp`, no-new-privileges, dropped capabilities,
pinned seccomp, CPU/memory/PID limits, and no privileged/host namespaces/Docker socket. Egress is
allowlisted to the bot and approved provider/Git endpoints.
Startup has a hard preflight before the daemon run loop: supported Linux engine/platform, fixed
non-root identity, read-only root, bounded tmpfs/cgroups, no-new-privileges, dropped capabilities,
pinned seccomp, declared mounts, private network, and allowlisted egress are inspected. Any
unsupported engine, Windows-host primitive gap, mount mismatch, or failed allow/deny egress probe
fails before workload admission.

## Absolute paths and mappings

The bot remains a syntax-only forwarder for POSIX, Windows drive, and UNC absolute paths. #44's
#44's mapping record is authoritative and includes `mappingId`, `mappingGeneration`,
`workspaceGeneration`, `sourcePlatform`,
canonical source/container roots, volume/share identity, and case policy.

The v2 route and invoke repeat mapping identity, mapping generation, and workspace generation. Resolve the record from
authenticated state, check host ownership, `mappingVersion`, source volume/share identity, and
case policy, then translate only the verified relative suffix. A Windows drive must match drive
identity; a UNC path must match server/share identity. Do not replace slashes or infer a root.
For v0/v1 fallback, the #44 route mapping MUST equal the host's single immutable default mapping;
that default identity and generation are frozen while legacy sockets are connected. Missing,
foreign, unknown-platform, zero/multiple, or changed mappings fail with `MAPPING_ID_REQUIRED` or
`WORKSPACE_MAPPING_CHANGED`.

Containment requires segment-aware root checks and descriptor/handle-relative no-follow operations
for creation, clone, checkout, reset, restore, and extraction. POSIX uses an `openat2`-equivalent
or directory-FD `O_NOFOLLOW` walk; Windows uses handle-relative reparse/no-follow checks and final
file-ID validation. Archive absolute, parent-traversing, symlink, and hardlink escapes are
rejected. Unsupported primitives fail before mutation.

## Workspace lifecycle

The daemon is sole writer and acquires a durable lock plus fencing epoch at startup. Each operation
carries principal, idempotency key, transaction ID, lease, expected generation, and manifests.
Lease expiry alone never grants takeover.
Native history migration into the Docker session role is locked and fenced: checksum the source
`<workDir>/.gjc-remote-session`, copy to a staging root, write dual manifests, verify ownership,
checksums and session identity, then atomically cut over. Preserve the source and a reversible
rollback manifest until the first current-run readiness proof succeeds; any mismatch or interrupted
copy leaves both sides untouched and enters `manual-cleanup`.
A lease records workspaceId, mappingId/generation, operation, daemon instance, fencing
epoch/sequence, expected generation, issued/expiry/renewal times, principal, idempotency key, and
transaction ID. Recovery requires lock, owner/process-absence, journal, manifest, mapping, volume,
and resource identity agreement; TTL alone never authorizes takeover.
An already-admitted legacy invoke either completes against its captured immutable mapping or is
rejected at the final lease/fingerprint check before mutation; it is never silently remapped.

1. **Create/clone:** resolve mapping, create a contained root, fetch the complete Git graph, verify
   all reachable objects and OIDs, write the manifest, perform a real current-run five-dimension
   readiness/SDK probe, and publish a generation only after checks pass.
2. **Refresh:** fence prompt/read activity, verify mapping and generation, fetch and publish the
   next generation only after the same current-run readiness proof; failure retains the prior ready
   generation.
3. **Prompt/session:** acquire a generation-bound activity lease and reserve admission before SDK
   creation. Stale leases return `WORKSPACE_GENERATION_STALE`.
4. **Reset/delete:** quiesce or return `WORKSPACE_BUSY`, back up dirty state, require a fresh verified
   backup and residual-process absence, and preserve tombstone/session/state evidence.
5. **Restore:** stage in a quarantined root, verify key, image/volume/role/mapping and Git
   manifests, then promote atomically under a new fence/generation.
After reset or restore mutation, before promotion under the exclusive lease, rerun containment,
volume/file identity, connectivity/fsck-equivalent full-graph verification, approved-ref checks,
and commit/tree OID verification. Containment failure returns `CONTAINMENT_UNSUPPORTED` or
`WORKSPACE_ROOT_ESCAPE`; mapping/volume identity failure returns `WORKSPACE_MAPPING_CHANGED`;
graph/ref/OID failure returns `GIT_GRAPH_INCOMPLETE`. Any failure preserves the prior generation,
invalidates readiness for the candidate generation, requires a fresh five-dimension SDK/model probe,
and enters `manual-cleanup` when evidence is ambiguous.

## Git and credentials

Ready repositories are complete, non-shallow, non-partial, and non-promisor. Do not use depth,
filter, single-branch, or unapproved refspecs. Verify connectivity, approved refs, commit/tree
OIDs, and remote allowlists. Reject credential-bearing URLs and keep provider/Git values out of
workspaces, state, bot frames, and logs.
Git verification also runs connectivity/fsck-equivalent checks over all reachable objects, protects
the workspace ref namespace from user-supplied writes, and separates Git authentication failures
from network failures. Refresh/reset never force-pushes or rewrites a remote. Dirty worktrees are
surfaced and backed up before destructive action; incomplete graph, unexpected ref movement, or
failed verification returns `GIT_GRAPH_INCOMPLETE` and cannot publish.

Provider login is local to the daemon service account/container UID and its runtime HOME/provider
volume. Credentials are never relayed through Discord, bot, or a future management endpoint.
Provider backups require external encrypted key ownership/recovery, independent signature and
manifest verification, rotation, and restore rehearsal.

## Current tracked-input runtime contract — LOCAL qualified subset

The issue #231 integration uses official unpatched SDK **0.19.0**
`submitUserMessage` for active steering/follow-up input. Track each submission's
admission, execution receipt, terminal outcome, and cancellation ownership; an
admission receipt is not execution or successful completion. Delivery is sequential
within each queue, not a global FIFO across queues. Execution receipts bind inputs
to logical-run cohorts: joined submissions can share the originating run's terminal,
and do not each start an independent generation. Route public events and terminals
by proven cohort ownership, not prompt text, arrival order, or the newest invoke.

Root result proof is separate: the exact SDK-proven public Agent terminal plus
that root's own settled prompt can prove its result despite coalesced readiness
publication. This never manufactures tracked receipts or retires gate authority;
SDK post-raw continuations may still issue Ask. Prompt fulfillment alone and
unknown raw scopes are not completion proof.

Workflow gates require a deliberate, uniquely proven owner. An unresolved ownership
race may wait only within bounded buffering/time limits, then fails explicitly;
never guess an owner, synthesize an answer, or silently drop an ambiguous gate.
Promoted overlap without a public immutable owner bridge is refused with
`SDK_TRACKED_INPUT_GATE_OWNERSHIP`; this limitation is not positive gate support.
Queued cancellation removes an input only when the SDK positively proves removal
before execution. An unknown or running outcome is not proof of removal. Running
cancellation remains nonterminal `cancellation_pending`, not an interruption or
completed cancellation; retain ownership until the authoritative terminal outcome.
There is no selective abort of executing shared-run work or cancellation of siblings.

Idle requests still use real SDK prompts; root prompts and model changes remain
serialized. No Broker/Router/subprocess redesign or new feature flag/opt-in is
introduced. SDK stays 0.19.0 with unchanged SRI, and native C++ is unchanged.

The [current tracked-input evidence](daemon-workspace-verification.md#current-tracked-input-evidence)
records the **LOCAL Windows qualified subset**: focused-04 passed 474/474 with zero
failures, skips or cancellations; unrestricted workspace-02 `npm test` exited 0 with
2897 tests/2887 pass/zero fail/10 existing platform/privilege skips and no exclusion
patterns. Unit-05 passed 240/240 and lifecycle-03 passed 52/52. These post-review
regressions use mock providers, not current-tree real-provider proof. Genuine SDK
harnesses prove primary/joined Ask presentation and exact
ownership, late follow-up/steer successor consumption, tracked handles/public
terminals, and root raw-terminal plus own-prompt proof. Promoted-overlap gate
ownership remains SDK-limited: bounded `SDK_TRACKED_INPUT_GATE_OWNERSHIP` refusal
without a wrong-owner answer is qualified, not universal gate success.

The earlier focused-02 444/444 and workspace-01 2867 tests/2857 pass/10 skips
remain pre-review receipts only. Focused-03 remains a preserved failed receipt
(474 tests/463 pass/11 reported failures), not a pass.
All five independent lanes retain scoped static **APPROVE** verdicts;
lanes 24/25 additionally re-reviewed their respective product corrections,
while lanes 26–28 retain their original scoped approvals;
the final test-only corrections independently **APPROVE** in
`agent://32-FinalTestCorrectionReview`. The aggregate review now records
`STATIC_APPROVE_RUNTIME_PASS` against focused-04/workspace-02. Exact-head CI
remains a separate gate; issue #231 remains **OPEN**.

The issue231 provider grant is **CONSUMED-PASS** on **PRE-REVIEW source only**
(`.git/issue231-provider-smoke.json`, `.git/issue231-pre-review-source.json`): one child-only
`codex-eco` A-B-A run, three exact `SMOKE_OK` responses, current heartbeat and three
successful invoke terminals, exit 0 in 13392 ms and relay port free, without optional
model query or retry. It does not cover the later router, fatal-retirement, or test
corrections and is not current-tree provider proof. Never replay or relabel it.
This is basic root regression only, not tracked active-control provider or
profile/tenant-isolation qualification, and does not resolve #247 disconnect behavior.
PR #274's SDK-adoption receipts and all 0.18 receipts remain historical, not feature
proof; their consumed paid/provider smoke grants cannot be reused. Issue #273 is
excluded and #33 subprocess work remains deferred. These local results do not qualify Linux/macOS/Docker, native/service/SCM,
security, release/install/sign/deploy or isolation; prior immutable release identities
remain unchanged.

## Deployment and shutdown contract

#42 owns platform deployment examples, rollout/rollback instructions, and evidence. This document
must not be copied into a second conflicting source of truth. Bot and daemon upgrade independently.
Docker restart policy is `on-failure` only; provider absence or denied registration is not a restart
storm. Signals perform bounded clean shutdown with exit 0; fatal faults exit non-zero. The effective
deployment configuration must prove `stop_grace_period > GJC_SHUTDOWN_TIMEOUT_MS` after all overrides,
with a documented margin (the daemon default is 15 seconds; a 30-second example is illustrative).
The effective deployment source must reject a configuration whose worst-case daemon/provider/
network/headroom reservation exceeds CPU, memory, or PID cgroup budgets. Admission is synchronous
before SDK creation, worker spawn, or writable workspace activation; there is no unbounded queue.

## Readiness contract

A socket is connected when registration succeeds, but it is ready only when all five dimensions are
current: `connection` (`online|offline`), `runtime` (`ready|incompatible|error`),
`providerAuth` (`configured|missing|invalid|unknown`), `modelProfile`
(`ready|missing|invalid|unknown`), and `workspace` (`ready|unavailable|unknown`). Missing provider
credentials produce connected/not-ready or degraded state, never empty success. Values outside
these enums, oversized fields, or malformed frames are rejected before state mutation.

The negotiated `workspace_readiness_v2` capability gates workspaceId, mapping identity, and
readiness frames atomically on ingress and egress. HostRegistry records local `receivedAt` and a
monotonic receipt time, clamps a validated TTL to the maximum, accepts diagnostic `observedAt`
values only within the bounded receiver-time skew window, rejects out-of-window/malformed/replayed
observations and stale socket generations/revisions, and marks expired state unknown. Sender expiry
and remote timestamps are diagnostic only; receiver-local monotonic expiry is authoritative.
`receivedAt` is diagnostic/projection data and clock changes cannot extend stale state. `/hosts`
exposes opaque IDs, aggregate/per-dimension state, local error time, revision, and generation
without paths or secrets.
Workspace IDs are bounded opaque safe-alphabet tokens and are looked up in authenticated state
before any interpolation into a path; route and frame size limits are implementation gates.

## Observability and rollback

Events use stable codes and opaque host/workspace/mapping/transaction IDs: negotiation,
mapping resolution/rejection, readiness changes/expiry, workspace admission/lease/generation,
containment, Git fetch, backup/restore, lock/fence, shutdown/restart, security preflight, and
egress probes. Do not log paths, tokens, provider values, URLs with credentials, prompts, stacks,
or controls.

Rollback is the existing native daemon and v0/v1 workDir route, or an exact prior signed image
with matching ownership and generation manifests. Unsupported engines, failed provenance, stale
locks, failed restore, or any proof mismatch preserve data and stop for manual cleanup.
The observability contract includes bounded fields: event code, phase, duration, opaque IDs,
socket generation, revision, fencing sequence, and local received/expiry times. Required gauges
cover connected/ready/degraded/expired hosts, active leases/sessions/workspaces/workers,
in-flight invokes, resource denials, lock/fence owner, graph verification, backup age, key version,
and restart count. Every release packet runs path/secret/control sentinel scans.
The five documents carry an assumptions ledger: #44 route/envelope and mapping persistence,
receiver TTL/skew/probe bounds, Git refs/allowlist/dirty policy, lease/resource budgets, provider
key recovery, #42/#45 evidence schedules, and SDK/package/lock reconciliation at official unpatched
0.19.0. The [SDK 0.19.0 adoption record (PR #274)](daemon-workspace-verification.md#current-sdk-only-0190-evidence)
preserves the source base, SRI, original Windows tests/imports/provider smoke,
review/CI/landing history, and unchanged promotion limits. Those receipts do not
qualify the tracked-input integration; its separate **LOCAL qualified subset** and
static review approval and separate CI gate are recorded above. No release, installation, signing, or platform qualification is
claimed. The separate uninstall bug remains issue #273, outside this integration.

Historical 0.18.12 post-admission parent SDK-only evidence recorded Windows focused 333/333 (zero skips),
bounded workspace 2704 tests/2700 pass/zero fail/four skips under nine explicit historical
authority exclusion patterns, and actual isolated Linux credentialless 248/248 without provider
calls. Skips are not passes, and four skips do not represent all nine exclusions.
One separately authorized native Windows `codex-eco` smoke used a child-only profile override
and passed three exact A-B-A `SMOKE_OK` responses, heartbeat/three invoke-terminal assertions,
exit 0, and ephemeral relay-port cleanup, without optional model query or wrapper retry.
That single smoke was not repeated after fixture/test-only changes; the 0.18.12 production SDK runtime/package/lock were unchanged by those changes.
Main native code was freshly built unchanged; separate native repairs and private native fixture
claims are excluded. This same-profile continuity does not establish a fix for #247 or isolation.
The [historical SDK-only verification record](daemon-workspace-verification.md#historical-sdk-only-01812-evidence)
preserves exact exclusions; the historical local unshipped runtime receipts are
`artifacts/sdk-first-0.18.12-admission2-focused.json`,
`artifacts/sdk-first-0.18.12-admission2-workspace.json`, and
`artifacts/sdk-first-0.18.12-admission2-wsl-final.json`. Each run qualifies only its exact pins;
local receipts alone do not approve landing. Both original P2s and owner-admission were verified
and independently cleared in `artifacts/sdk-first-0.18.12-final-review.json`: static agent
review APPROVE, zero P0/P1/P2, not independent runtime or CI/merge/deployment approval.
Historical exact-head CI/landing was tracked in [PR #265](https://github.com/kogangdon/gjc-remote/pull/265);
that record's final follow-up was not yet committed/pushed, and it did not claim CI/merge completion.
In that historical snapshot, active controls remained fail-closed, with no inferred
standalone abort support; active cancellation remained nonterminal `cancellation_pending`.
That is not the current tracked-input admission contract above. #6578 is closed and #6700
is closed-unmerged; #6970 is the actual repair included in the 0.19.0 release notes,
not local workflow qualification. Docker/image/release/security/native/service/fault/OOM/noDump/
installation/deployment and isolation gates remain unqualified and open. Each item
has an owner, closure gate, and fail-closed behavior; illustrative values are not final approvals.
