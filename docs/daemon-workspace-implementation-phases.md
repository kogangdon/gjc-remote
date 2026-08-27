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
| Native serving runtime | Every ADR 0002 gate applicable to native serving, plus #42/#43/#44/#45/#33 ownership agreements, is directly evidenced | Native development behavior under the final contract; never Docker or production release by itself |
| Docker test fixture | Native contracts and Phase 2 gates pass; Docker engine/security/egress fixture is approved | Disposable Compose evidence only; never production deployment or tenant isolation |
| Production/release promotion | Every ADR 0002 and verification-matrix gate has direct evidence | No waiver, copied receipt, interim feature flag, or missing platform evidence |

Before the native-serving boundary, no daemon or bot process may serve workspace invokes. A failed
or missing gate preserves the native rollback and stops promotion. #42 and #45 are consumers of the
contract: their ownership agreements are required before native serving, while deployment and
readiness-consumer fixtures are required before Docker fixture approval or release promotion.

## Required preconditions

Before contract/test scaffolding, #44 ownership and the field-level handshake, plus #43 ownership
of host-wide admission and #33 ownership of subprocess budgets, must be recorded.
Before native serving, the complete authenticated envelope and all native-applicable persistence,
migration, authentication, audit, idempotency, concurrency, cgroup, containment, readiness, Git,
provider, and resource gates below must close. Docker, platform, and readiness-consumer fixtures
remain required at their later Docker or release boundary.
1. **#44 mapping envelope:** the serving-runtime contract is the exact authenticated/versioned route
   envelope, not merely a field sketch. It includes `hostId`, `mappingId`, `mappingGeneration`,
   `workspaceGeneration`, `mappingVersion`, `sourcePlatform`, and either legacy `workDir` or
   `workspaceId`; canonical
   native/container roots, volume/share identity, case policy, persistence, migration timing,
   authentication, audit, idempotency, and concurrency ownership are defined. #44 alone mutates
   the mapping registry.
2. **#43 host-wide admission:** initial limits are 8 active workspaces, 8 in-process SDK sessions,
   and 64 in-flight invokes per host. #43 owns their bounds, cgroup headroom, accounting, overflow
   behavior, and boundary fixtures; values remain provisional until that owner gate closes.
3. **#33 subprocess budgets:** #33 owns the optional subprocess worker cap of 4, nested budgets,
   transport, and worker evidence. The cap applies only when subprocess mode is enabled. No owner
   may authorize an unbounded queue.

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

Let `receivedAt` be the receiver wall-clock timestamp and `SKEW_MAX_MS = 300000`. An
`observedAt` within `[receivedAt - SKEW_MAX_MS, receivedAt + SKEW_MAX_MS]` is accepted only as
diagnostic metadata; it never changes the receiver's monotonic expiry deadline. Values outside the
window, malformed values, or replayed/backward timestamps are rejected with
`READINESS_TIMESTAMP_INVALID` or `READINESS_REPLAYED`. These provisional bounds become closed only
after the TTL/skew validator owner gate.

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

A v2 invoke repeats `mappingId`, `mappingGeneration`, `workspaceGeneration`, and `mappingVersion`;
a mappingVersion change
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

A single-writer durable lock was, in the MVP interim, gated by the development-only feature flag
`GJC_DEV_NATIVE_SINGLE_WRITER_LOCK`. That flag is REMOVED as of slice S6e: native single-writer
lease/fence enforcement is now unconditional. It records owner identity and rejects a second writer.
It never authorizes stale-owner takeover or resumed writes: process absence evidence permits only
inspection/cleanup, while ambiguity enters `manual-cleanup`. The removal gate
`FINAL_LEASE_FENCE_TESTS_PASS` is retired; the flag name is now rejected at daemon startup
(presence-based fail-closed, see `daemon/src/workspace-removed-flags.js`).

A development-only `connectivity-only` Git probe was, in the MVP interim, gated by
`GJC_DEV_CONNECTIVITY_PROBE`. That flag is REMOVED as of slice S6e: full connectivity/ref/OID/
all-reachable verification is now unconditional at every create/clone and refresh generation
publication. The removal gate `FULL_GRAPH_PUBLICATION_TESTS_PASS` is retired; the flag name is now
rejected at daemon startup (presence-based fail-closed, see `daemon/src/workspace-removed-flags.js`).
Removing these interim flags does NOT cross the native-serving boundary
(`NATIVE_WORKSPACE_SERVING_ENABLED` stays false) - that flip is the separate human-approved decision
tracked by issue #81 / slice S6f.

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

- ownership/fixture agreement and exact SDK/package/lock provenance at 0.12.21;
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

## Native workspace inventory - as-built status (fa68941)

This section reconciles this phase contract with the observed AS-BUILT native inventory
implementation at main HEAD `fa68941`. Every claim below is grounded in the in-repo source
(`daemon/src/daemon.js`, `daemon/src/inventory-config.js`, `native-control/src/inventory.js`,
`shared/protocol.js`, `bot/src/host-registry.js`). It documents implementation status only and does
not authorize any behavior more permissive than the phase contracts above.

**Serving remains disabled.** The native inventory contract (config modes, five-role bindings, the
durable D floor, the live invalidation cascade, and the bot receipt binding/observability surface) is
implemented as capability scaffolding, but native workspace serving itself remains DISABLED: the
daemon defines `const NATIVE_WORKSPACE_SERVING_ENABLED = false` (daemon/src/daemon.js:228, a const
literal with no env/config override anywhere in the repo), and its sole read site inside
`admitReadyWorkload` returns `RUNTIME_INCOMPATIBLE` when off. On the bot side, `host-registry.js`
defaults the equivalent flag to false and `bot.js` does not override it. A proven verify-mode
receipt binding is fenced and cryptographically proved but still fails this hard serving gate with
`RUNTIME_INCOMPATIBLE`.

**Config mode and capability gate.** `GJC_NATIVE_INVENTORY_MODE` is parsed at daemon boot, defaults
to `off`, and is trimmed/lowercased; any value other than `off` or `verify` causes a fail-closed
`process.exit(1)`. The `workspace_inventory_receipt_v2` capability, and protocol version bump to V3, is
advertised only when mode is `verify` AND `GJC_READINESS_V2` is enabled AND the inventory provider
reports `receiptCapable === true`.

**Five-role config.** `GJC_INVENTORY_ROLE_BINDINGS` is a strict-JSON payload (<=32KiB) with the
exact keys `management`, `bot`, `recovery`, `daemon`, `system`. Each principal is `{kind, value}`
where `kind` is `uid` (Linux, grammar `/^uid:(0|[1-9][0-9]{0,9})$/`, bounded to 2^32-1) or `sid`
(win32, canonical SID string); other platforms are rejected as `CONFIG_INVALID`. All five values
must be pairwise distinct, and `system` must be pinned exactly to `uid:0` (Linux) or `S-1-5-18`
(win32).

**Durable D floor.** The floor is genesis-seeded (only `inventoryGeneration === 1` is accepted with
no prior floor); an exact replay of the current generation/fingerprint against the prior floor is a
read-only success; a `+1` monotonic generation advance with a differing fingerprint atomically
replaces the floor under a fence keyed to the prior floor's identity. Rollback, generation jumps
greater than one, same-generation fingerprint mismatch, or a missing floor at a generation other than
1 are all rejected as `INVENTORY_STALE`. Known limitation: a jointly restored, internally consistent
old inventory+floor pair is accepted via the exact-replay branch (coupled restore is not detected);
cold rollback is detected only once the inventory is restored below a still-surviving floor. This has
an availability cost: the management role cannot advance while the D role is offline, until the
floor catches up.

**Live invalidation cascade.** On invalidation, the daemon guards against re-entrancy, advances the
provider epoch, clears the cached inventory snapshot, invalidates all workspace leases, then per
connection synchronously clears the readiness timer and sets `receiptCommitted = false` (the receipt
fence), invalidates in-flight bind/invoke requests and queues receipt-session disposal, awaits those
disposals, emits one bounded negative readiness frame, and closes the socket with code 1013. A
test-only `GJC_INVENTORY_POLL_MS` override on the default 5-second poll interval is honored only
under test injection.

**Daemon-boot native-reader wiring (#53 Phase 2).** `initializeInventoryConfig`
(daemon/src/inventory-config.js) is now wired into daemon boot through a pure, DI-testable helper
`resolveInventoryProviderConfig` (daemon/src/inventory-boot-wiring.js). At boot the helper applies a
single mutually-exclusive precedence: test injection (`GJC_READINESS_TEST_INJECTION=1`) is checked
FIRST and short-circuits to the unchanged legacy test-injection provider options; only when test
injection is disabled AND `GJC_NATIVE_INVENTORY_MODE` is exactly `verify` does the daemon construct
and self-test the production native reader via `initializeInventoryConfig` and thread it into
`createWorkspaceInventoryProvider({reader})`; otherwise (`off`/unset) it forwards the same legacy
options as before, preserving the fail-closed misconfig guard for a stray `GJC_WORKSPACE_INVENTORY`.
Verify-mode configuration/self-test failure is dispatched through a dedicated catch that maps the
error to a structured, path-free, secret-free `inventoryConfigDiagnostic` and `process.exit(1)` (never
`sanitizeDaemonError`); provider construction/read failures keep their existing `sanitizeDaemonError`
catch. The `workspace_inventory_receipt_v2` advertisement keying is unchanged, so a production
verify-mode receipt now depends on a genuinely self-tested native reader rather than requiring
test-injected inventory. Native serving itself remains FUTURE work gated behind the existing
native-serving boundary defined earlier in this document (`NATIVE_WORKSPACE_SERVING_ENABLED = false`
is unchanged); this wiring does not bring serving into scope.

**Host-wide active-workspace admission (#53 Phase 2, #43 ownership).** Of the three #43 host-wide
bounds, two were already implemented and boundary-tested before this slice: 64 in-flight invokes per
host (`daemon/src/admission-budget.js` `AdmissionBudget`, `DEFAULT_MAX_IN_FLIGHT_INVOKES = 64`) and 8
in-process SDK sessions (`daemon/src/session-pool.js` `SessionPool`, `DEFAULT_MAX_SESSIONS = 8`). This
slice closes the remaining gap -- **8 active workspaces** -- inside `WorkspaceLeaseRegistry`
(`daemon/src/workspace-lease-registry.js`): a new `maxActiveWorkspaces` bound (default
`DEFAULT_MAX_ACTIVE_WORKSPACES = 8`) is enforced inside `acquireActivity` for new distinct-workspace
admission only, fail-closed with the new `WORKSPACE_ADMISSION_EXCEEDED` protocol error code (added to
`PROTOCOL_ERROR_CODES`, its `resourceSession` taxonomy grouping, and a `retry_later` remediation
tuple). The daemon invoke handler classifies this synchronous acquisition refusal through the
lease-boundary early-return branch (`daemon/src/readiness-classification.js`), parallel to
`LEASE_CONFLICT`, without mutating readiness state. Authoritative host-wide admission lives solely in
the daemon process; the bot's per-socket `V0_LIMITS.MAX_PENDING_PER_HOST` (64) is retained unchanged
as a thin network-backpressure guard (two-layer, not two-authorities) and is held equal to the daemon
ceiling by an in-slice constant-reconciliation test.

**Forward-scaffolding / dormancy.** `acquireActivity` is reached from the invoke handler only AFTER
the `NATIVE_WORKSPACE_SERVING_ENABLED` serving gate (source order: mapping/route -> read-before-
admission fence -> serving-disabled gate -> workspace-admission -> session creation), which is
hard-disabled. The new active-workspace bound is therefore dormant on the live invoke wire today --
exactly like the existing 8-session bound -- and is proven at the `WorkspaceLeaseRegistry`
component/unit surface, not via a live serving invoke. Only the 64-invoke `AdmissionBudget` (which
runs upstream of the serving gate) is load-bearing end-to-end today. This slice does not enable native
serving.

**cgroup headroom (contract + Linux-guarded test; enforcement deferred to Phase 3/#42).** The daemon
performs no runtime cgroup manipulation. `daemon/src/admission-headroom.js` declares the memory
headroom relationship as real constants: the minimum cgroup memory limit must satisfy
`ceil(((maxSessions * PER_SESSION_MEMORY_ESTIMATE_MB) + (maxInFlightInvokes *
PER_INVOKE_MEMORY_ESTIMATE_MB) + FIXED_DAEMON_BASELINE_MB) * CGROUP_MEMORY_HEADROOM_RATIO)` with the
ceilings sourced from their single points of definition. `daemon/test/cgroup-headroom.linux.test.js`
asserts this arithmetic inequality unconditionally on every platform and, on Linux only, additionally
reads the process's actual cgroup memory limit and asserts it meets the declared minimum (or skips
with a diagnostic when unbounded/absent). Runtime cgroup enforcement remains Phase 3 / #42 scope.

This is as-built status reconciliation only. It does not authorize native workspace serving, does not
weaken any Phase 1-4 gate above, and does not make local inventory a route or mapping authority: the
#44 mapping envelope remains the sole route authority, and local inventory is capability evidence
only.

## Issue decomposition

The design issue #43 is complete after ADR 0002 and its contract documents. Implementation is tracked
separately and linked to parent #41:

1. Protocol/readiness vertical slice (Phase 1).
2. Workspace data plane and lifecycle (Phase 2).
3. Docker daemon runtime and test fixture (Phase 3).
4. E2E, provenance, and platform evidence (Phase 4).

Each implementation issue must copy its phase acceptance and verification rows, identify temporary
clauses and their removal gate, and link to ADR 0002, this phase contract, and the verification matrix.
