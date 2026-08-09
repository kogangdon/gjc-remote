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
mapping record is authoritative and includes `mappingId`, `mappingGeneration`, `sourcePlatform`,
canonical source/container roots, volume/share identity, and case policy.

The v2 route and invoke repeat mapping identity and generation. Resolve the record from
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
key recovery, #42/#45 evidence schedules, and SDK/package/lock reconciliation at 0.12.21. Each item
has an owner, closure gate, and fail-closed behavior; illustrative values are not final approvals.
