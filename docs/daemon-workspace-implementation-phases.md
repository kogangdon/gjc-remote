# Daemon workspace implementation phases

This document supplements ADR 0002 and issue #43. It freezes sequencing and MVP boundaries
without weakening the final workspace-container contract. ADR 0002 and the verification matrix
remain authoritative for safety and permissiveness; this document supplies sequencing and
concretization only and never authorizes a more permissive behavior.

## Phase entry and release gates

There are four distinct boundaries. A later boundary MUST NOT be inferred from an earlier one.

| Boundary | May begin after | May claim |
| --- | --- | --- |
| Contract/test scaffolding | #44 exact envelope decision and #33 admission numbers are recorded | Validators, deterministic fakes, fixtures, and non-serving contract tests only |
| Native serving runtime | Every ADR 0002 implementation-stop gate and all #42/#43/#44/#45/#33 ownership/fixture agreements are directly evidenced | Native development behavior under the final contract; never Docker or production release by itself |
| Docker test fixture | Native contracts and Phase 2 gates pass; Docker engine/security/egress fixture is approved | Disposable Compose evidence only; never production deployment or tenant isolation |
| Production/release promotion | Every ADR 0002 and verification-matrix gate has direct evidence | No waiver, copied receipt, interim feature flag, or missing platform evidence |

Before the native-serving boundary, no daemon or bot process may serve workspace invokes. A failed
or missing gate preserves the native rollback and stops promotion. #42 and #45 are consumers of the
contract, but their ownership agreements and relevant deployment/readiness-consumer fixtures remain
required before serving runtime implementation.

## Required preconditions

Before contract/test scaffolding, #44 ownership and the field-level handshake, plus #33 ownership
of the admission numbers, must be recorded. Before any serving runtime, the complete authenticated
envelope and all persistence, migration, authentication, audit, idempotency, concurrency, cgroup,
and fixture gates below must close.
1. **#44 mapping envelope:** the serving-runtime contract is the exact authenticated/versioned route
   envelope, not merely a field sketch. It includes `hostId`, `mappingId`, `mappingGeneration`,
   `mappingVersion`, `sourcePlatform`, and either legacy `workDir` or `workspaceId`; canonical
   native/container roots, volume/share identity, case policy, persistence, migration timing,
   authentication, audit, idempotency, and concurrency ownership are defined. #44 alone mutates
   the mapping registry.
2. **#33 admission numbers:** initial limits are 8 active workspaces, 8 in-process SDK sessions,
   64 in-flight invokes host-wide, and 4 subprocess workers only when subprocess mode is enabled.
   Bounds, cgroup headroom, and per-host accounting are fixed; these values remain provisional until
   their owner gate closes and never authorize an unbounded queue.

#42 owns deployment/grace/rollback/platform evidence and #45 owns bot image/runtime/network and
readiness-consumer guidance. #44 owns route/control-plane schema/auth/audit/idempotency/concurrency.
#33 owns worker transport, nested budgets, and worker evidence. No phase creates a parallel source
of truth for those responsibilities.

## Protocol decisions closed before Phase 1

### Readiness publication

The daemon publishes a readiness update at least every `TTL / 2` while the socket is current and
healthy. The initial configured bounds are `1_000 <= ttlMs <= 60_000`, with a default of 60 seconds;
configuration validation remains an implementation gate. Phase 1 does not add a heartbeat frame or
readiness metadata to ping/pong: the timer publication is mandatory, and existing ping/pong traffic
never advances readiness revision or resets receiver expiry. A future heartbeat optimization requires
a separate bounded v2 protocol decision. Only a strictly newer readiness frame with the applicable
workspace generation refreshes local TTL. Sender `observedAt` and sender expiry are diagnostics only.
Readiness revision is scoped to the current socket generation and starts at 1 for each new socket;
the receiver accepts only newer revisions from that socket. `workspaceGeneration` is mandatory for
workspace-bound readiness and omitted for host-level connected/runtime status. Host-level updates
cannot refresh a workspace's expiry. A replacement socket clears all inherited workspace readiness.

### Clock skew handling

Let `receivedAt` be the receiver wall-clock timestamp and `SKEW_MAX_MS = 300000`. Any future
`observedAt`, even within the skew window, is rejected with `READINESS_TIMESTAMP_INVALID`. A past
timestamp within `[receivedAt - SKEW_MAX_MS, receivedAt]` is accepted as diagnostic metadata; a
past value outside the window, malformed value, or replay is rejected with
`READINESS_TIMESTAMP_INVALID` or `READINESS_REPLAYED`. These provisional bounds become closed only
after the TTL/skew validator owner gate; remote timestamps never extend the receiver's monotonic
deadline.

## Phase 1 — readiness end-to-end

Phase 1 is one vertical slice across shared, daemon, and bot. Before the native-serving boundary it
runs only validators, deterministic fakes, and non-serving contract tests.

### Owned files and callsites

- `shared/protocol.js` and shared tests: bounded v2 register/invoke/readiness fields, version and
  capability negotiation, unknown-peer behavior, atomic commit point, and v0/v1 compatibility.
- `daemon/src/daemon.js`, `daemon/src/reconnect.js`, and daemon tests: readiness classifier,
  publication cadence, static preflight, first-work SDK/model probe, error taxonomy, and generation
  fencing.
- `bot/src/host-registry.js`, `bot/src/bot.js`, and bot tests: receive-time expiry, `/hosts`,
  replacement/revision/socket fencing, and not-ready invoke remediation.
- `bot/src/config.js`, `bot/src/config-watcher.js`, and config tests: #44 versioned route input,
  mapping identity migration, unknown-version rejection, and legacy direct-map migration.
- Focused integration fixtures: fake v0/v1/v2 peers, provider missing/repair, auth-vs-network
  failure, readiness expiry, remap invalidation, and redaction.

### Atomic protocol gate

A socket enables v2 only after negotiated version is at least 2, `workspace_readiness_v2` appears
in both register advertisements and the valid register response, and the response passes bounded
validation. Before that commit point ingress rejects workspaceId/mapping/readiness fields and egress
sends none. Unknown or malformed versions/capabilities fail closed; replacement sockets start with
v2 disabled and no inherited readiness.

A v2 invoke repeats `mappingId`, `mappingGeneration`, and `mappingVersion`; a mappingVersion change
must bump mappingGeneration or be rejected stale. Optional `workspaceId` and legacy `workDir` must
resolve to the same mapping and generation. A legacy socket captures the #44 mapping fingerprint,
route equality, and singleton default identity at registration. Legacy fallback is valid only when
exactly one immutable host-default mapping exists, the authenticated route equals it, and identity,
mappingVersion, and generation remain frozen. Zero/multiple/foreign/changed mappings return stable
mapping errors and invalidate/re-register the socket; no mapping is inferred or silently remapped.
An in-flight legacy invoke either completes against its captured immutable mapping or fails the final
lease/fingerprint check before mutation.

### Readiness and errors

Static security preflight runs before the daemon loop and workload admission. A real current-run
five-dimension SDK/model-profile probe is required before first work and before a generation can
become ready. The dimensions and allowed values are:

- `connection`: `online|offline`
- `runtime`: `ready|incompatible|error`
- `providerAuth`: `configured|missing|invalid|unknown`
- `modelProfile`: `ready|missing|invalid|unknown`
- `workspace`: `ready|unavailable|unknown`

Aggregate precedence is deterministic: `offline`, `incompatible`, `degraded` for a prior-ready
expiry or readiness error, `connected-not-ready` for current registration without prior-ready
expiry, and `ready` only for a current, unexpired selected workspace with all five dimensions ready.
Reset/restore invalidates candidate readiness and requires a fresh probe for the new workspace
generation before promotion.

The complete stable taxonomy is preserved: transport (`AUTH_REJECTED`, `PROTOCOL_INCOMPATIBLE`,
`CONNECTION_LOST`, `HEARTBEAT_TIMEOUT`); provider/profile (`PROVIDER_MISSING`,
`PROVIDER_INVALID`, `PROVIDER_EXPIRED`, `PROVIDER_UNAVAILABLE`, `MODEL_PROFILE_MISSING`,
`MODEL_PROFILE_INVALID`); runtime/config (`RUNTIME_INCOMPATIBLE`, `CONFIG_INVALID`,
`UNKNOWN_RUNTIME`); mapping/workspace/lease (`WORKSPACE_NOT_FOUND`, `WORKSPACE_ROOT_ESCAPE`,
`CONTAINMENT_UNSUPPORTED`, `MAPPING_ID_REQUIRED`, `WORKSPACE_MAPPING_CHANGED`,
`MAPPING_GENERATION_STALE`, `WORKSPACE_BUSY`, `WORKSPACE_GENERATION_STALE`, `LEASE_CONFLICT`);
Git (`GIT_GRAPH_INCOMPLETE`, `GIT_AUTH_FAILED`, `GIT_NETWORK_FAILED`); readiness
(`READINESS_TIMESTAMP_INVALID`, `READINESS_REPLAYED`, `READINESS_EXPIRED`); resource/session
(`RESOURCE_EXHAUSTED`, `SESSION_LIMIT`, `SESSION_CREATE_TIMEOUT`, `SHUTDOWN_TIMEOUT`); and fatal
(`DAEMON_FATAL`, `UNHANDLED_REJECTION`, `UNCAUGHT_EXCEPTION`).

A connected-not-ready, degraded, expired, incompatible, unknown, workspace-not-found, stale
generation, or stale-mapping invoke is rejected before SDK/session work. Remediation is structured as
`{ code, retryable, action }`, where `action` is one of `login`, `repair_profile`, `retry_later`,
`refresh_workspace`, or `contact_admin`. Docker session migration disabled maps to
`{ code: "RUNTIME_INCOMPATIBLE", retryable: false, action: "contact_admin" }`; the internal
`DOCKER_SESSION_MIGRATION_DISABLED` diagnostic never crosses the protocol. It contains no path, URL,
token, credential, prompt, stack, or raw exception. `/hosts` exposes only opaque IDs, aggregate/
per-dimension state, local error time, revision, socket/workspace generation, and bounded diagnostics.

### Phase 1 acceptance and evidence

- v1 peers receive only legacy workDir frames; no v2 fields cross an unnegotiated socket.
- Registration without provider credentials is connected-not-ready, not ready.
- Static preflight runs before the daemon loop and workload admission; first-work SDK/model probe
  failures remain connected-not-ready or degraded and never become empty success.
- Readiness publishes at `TTL / 2`; only newer revisions refresh local monotonic expiry. Existing
  ping/pong traffic never refreshes readiness expiry or carries readiness metadata.
- Tests cover handshake commit/rejection, unknown versions, malformed/oversized/unsafe IDs and
  dimensions, invoke identity equality, remap fencing, duplicate/out-of-order/replayed frames,
  accepted/rejected skew boundaries, TTL min/max/default, clock changes, expiry, replacement sockets,
  all readiness precedence states, provider repair, auth-vs-network classification, hostile errors,
  and exhaustive projection redaction.
- Every not-ready branch is rejected before SDK/session work with the bounded remediation enum.

## Phase 2 — workspace data plane

Phase 2 implements mapping/containment, lifecycle, persistence, Git, backup, and resource controls.

### MVP interim subset

A single-writer durable lock may be used only in a development-only native mode guarded by the
exact feature flag `GJC_DEV_NATIVE_SINGLE_WRITER_LOCK=1`, default off. It records owner identity
and rejects a second writer. It never authorizes stale-owner takeover or resumed writes: process
absence evidence permits only inspection/cleanup, while ambiguity enters `manual-cleanup`. A negative
fixture must prove Docker and production paths cannot select this mode. A named removal gate is the
Phase 2 acceptance `FINAL_LEASE_FENCE_TESTS_PASS`; Phase 4 is blocked while the flag exists.

A development-only `connectivity-only` Git probe may run only in an isolated benchmark command with
`GJC_DEV_CONNECTIVITY_PROBE=1`, default off, no bot socket, no serving daemon, and no writable
candidate/prior generation. It cannot publish a ready or release generation, satisfy a current-run
publication probe, or pass Phase 2/release evidence. Its removal gate is
`FULL_GRAPH_PUBLICATION_TESTS_PASS` before the native-serving boundary; the flag must then be
rejected at startup. Full connectivity/ref/OID/all-reachable verification is required at every
create/clone and refresh generation publication.

Docker session-volume migration is disabled with an internal diagnostic
`DOCKER_SESSION_MIGRATION_DISABLED` that is never sent as a public protocol/remediation code; public
behavior is `{ code: "RUNTIME_INCOMPATIBLE", retryable: false, action: "contact_admin" }`. Native
`<workDir>/.gjc-remote-session` remains the source of truth until locked, checksummed, staged,
dual-manifest, reversible migration succeeds.

### Final obligations and operation-level evidence

| Operation | Required acceptance before promotion |
| --- | --- |
| Create/clone | Mapping/no-follow proof, complete graph/ref/OID proof, backup/manifest, current-run readiness probe, atomic generation publication |
| Refresh | Prompt/read fencing, expected mapping/workspace generation, full graph/ref/OID proof, post-operation identity check, prior-generation preservation on failure |
| Prompt/session | Host-wide 64 invoke and 8-session/workspace admission before SDK creation; activity lease and generation check |
| Reset/delete | Quiescence or `WORKSPACE_BUSY`, dirty backup, exclusive final lease/fence, residual-process absence, tombstone/manual-cleanup proof |
| Restore/migration | Quarantined staging, role/volume/key/provenance and checksum verification, containment/OID recheck, reversible promotion, fresh readiness probe |

The final implementation also requires explicit POSIX/Windows drive/UNC identity, race-resistant
no-follow containment, final lease/fence/generation recovery, cgroup headroom, and no unbounded queue.

## Phase 3 — Docker runtime

Build the pinned non-root daemon image and test-only same-host Compose fixture. Prove read-only root,
mounts, UID/GID, capabilities, seccomp, no-new-privileges, cgroups, private network, allow/deny
egress, provider/session/state persistence, `restart: on-failure`, and
`stop_grace_period > GJC_SHUTDOWN_TIMEOUT_MS`. Unsupported engines/platforms or failed preflight
refuse to start. Docker cannot claim tenant isolation.

#42 owns rendered deployment documentation, grace/rollback/supervisor behavior, and platform
 evidence. #45 owns bot image/runtime/network/readiness-consumer guidance. Neither may redefine the
 daemon contract.

## Phase 4 — release evidence checklist

Every verification-matrix evidence layer and non-negotiable gate must close before promotion:

- ownership/fixture agreement and exact SDK/package/lock provenance at 0.12.7;
- unit/integration/Compose tests for mapping, readiness, lifecycle, resource, Git, backup/restore,
  provider recovery, remap fencing, and cleanup;
- image/base/source/lock/SDK digests, SBOM, scan, signature/attestation, volume manifests, copied or
  hybrid receipt rejection, secret/control/path sentinel scans, and manual-cleanup evidence;
- structured events/gauges, `/hosts` snapshots, supervisor/application timelines, and restart/grace
  evidence including signal exit 0, fatal non-zero, no provider/registration restart storm, and
  effective grace after overrides;
- disposable Compose cleanup, Windows/UNC containment evidence, platform evidence from #42/#45,
  protocol retirement decision, and explicit no-tenant-isolation boundary.

Any missing or failed gate is a hard no-promotion result; interim feature flags are rejected.

## Issue decomposition

The design issue #43 is complete after ADR 0002 and its contract documents. Implementation is tracked
separately and linked to parent #41:

1. Protocol/readiness vertical slice (Phase 1).
2. Workspace data plane and lifecycle (Phase 2).
3. Docker daemon runtime and test fixture (Phase 3).
4. E2E, provenance, and platform evidence (Phase 4).

Each implementation issue must copy its phase acceptance and verification rows, identify temporary
clauses and their removal gate, and link to ADR 0002, this phase contract, and the verification matrix.
