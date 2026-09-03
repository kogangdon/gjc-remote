# ADR 0002: Persistent non-root daemon workspace container

- **Status:** Accepted; Phase 3 implementation is tracked by issue #54.
- **Scope:** Issue #43 design contract only.

## Decision

Run exactly one persistent, immutable, non-root daemon container per host. The daemon owns
workspace, session, provider, and state volumes and connects outbound to an independently
deployed bot over the private WebSocket path. Same-host Compose is a disposable integration
fixture, not a production topology.

The four writable roles are separate:

| Role | Container path | Contents |
| --- | --- | --- |
| Workspace | `/workspaces` | Repository and worktree data only |
| Session | `/var/lib/gjc-remote/sessions` | SDK histories and session files |
| Provider | `/home/gjc/.gjc` | Provider credentials, configuration, and model profile |
| State | `/var/lib/gjc-remote/state` | Mapping, leases, fences, manifests, readiness, journals, and receipts |
The daemon state volume contains only an authenticated #44 mapping snapshot/fingerprint and
validation receipts. #44 alone mutates the authoritative registry; the daemon never creates a
parallel mapping source of truth.

The image root is read-only, runs with a fixed non-root UID/GID, bounded tmpfs and cgroups,
no-new-privileges, dropped capabilities, pinned seccomp, private networking, and no host PID,
privileged mode, Docker socket, or writable host root. Egress is explicitly allowlisted.
A hard security preflight runs before the daemon loop and before workload admission. It rejects
unsupported Linux engines or Windows-host primitive gaps, mount identity mismatches, non-root or
read-only violations, missing capability/seccomp/no-new-privileges controls, cgroup headroom
shortfalls, and failed allow/deny egress probes.

## Compatibility and mapping identity

Existing native absolute `workDir` routes remain supported. Docker translation never guesses a
root from path spelling. #44 owns authenticated mapping records containing an opaque `mappingId`,
`mappingGeneration`, `workspaceGeneration`, `mappingVersion`, source platform, canonical native root, canonical POSIX
container root, volume/share identity, and case policy.
A v2 route and invoke repeat mapping identity, mapping generation, and workspace generation. POSIX, Windows drive, and UNC
paths are validated using native rules, canonicalized by path segments, and translated only after
identity checks. Windows drive/share identity, reparse/junction state, and final file identity
must remain stable. Unsupported no-follow primitives fail closed with `CONTAINMENT_UNSUPPORTED`.
v0/v1 peers may use workDir only when the #44 route mapping equals the host's exactly one immutable
default mapping; that default identity and generation is frozen while legacy sockets are connected.
Missing, foreign, multiple, or changed mappings return `MAPPING_ID_REQUIRED` or
`WORKSPACE_MAPPING_CHANGED`; the daemon never infers a mapping. Workspace IDs are bounded
safe-alphabet tokens looked up in authenticated state before any path interpolation.

## Lifecycle and authority

The daemon is the sole writer for shared volumes. Startup acquires a durable lock, writes an
owner identity and fencing epoch, and rejects a second writer. Create/clone, refresh, prompt,
reset, delete, and restore operations use authenticated principal, idempotency key, transaction
ID, lease, expected generation, and before/after manifests. Ambiguous lock, journal, manifest,
volume, mapping, or process evidence is preserved as `manual-cleanup`; TTL alone never grants
takeover.

Workspace operations are root-contained, complete-Git-graph verified, backup-gated, and
idempotent. Create/clone and refresh require a real current-run five-dimension SDK/model probe
before publishing a generation. Destructive operations quiesce activity, back up dirty state,
preserve the previous generation, and retain tombstones until receipts are independently verified.
Initial admission limits are 8 active workspaces, 8 in-process sessions, 64 in-flight invokes, and
(only with #33 subprocess mode) 4 workers, with worst-case cgroup headroom and synchronous
`RESOURCE_EXHAUSTED` before activation; there is no unbounded queue.
Native SDK history under `<workDir>/.gjc-remote-session` is migrated to the dedicated session role
only under lock/fence. Checksum the source, copy to staging, write dual manifests, verify ownership
and session identity, atomically cut over, and preserve source plus reversible rollback evidence
until current-run readiness succeeds. Any interrupted or mismatched migration preserves both sides
and enters `manual-cleanup`.

## Readiness and protocol

A new additive capability/version, `workspace_readiness_v2`, carries workspace identity and
five readiness dimensions in one atomic per-socket gate. Only sockets negotiating protocol v2
and this capability may use workspaceId-only invokes, mapping identity, or readiness frames.
Replacement sockets start with no inherited readiness; v0/v1 remains workDir-only.

Readiness dimensions are `connection`, `runtime`, `providerAuth`, `modelProfile`, and `workspace`.
Connected is not ready. Provider login is performed as the daemon service/container identity;
the bot and management plane never receive credentials or credential paths.

HostRegistry owns freshness: it records local `receivedAt` and monotonic receipt time, clamps a
validated TTL to a maximum (initial design value 60 seconds), and never uses sender expiry or
remote wall-clock time as authority. It accepts diagnostic `observedAt` values only inside the
bounded receiver-time skew window; out-of-window, malformed, or replayed timestamps, stale socket
generations, duplicate revisions, and invalid TTLs are rejected. Expired or unknown state never
renders ready.
The receiver computes and compares a monotonic expiry deadline at receipt using a bounded TTL;
wall-clock receivedAt is diagnostic only and clock changes cannot extend stale readiness. Aggregate
status degrades only for a previously-ready workspace expiry or readiness error; initial unknown
remains connected-not-ready.

## Ownership and rollback

- **#43:** daemon workspace/protocol invariants, host-wide admission (`8/8/64`), this ADR, and linked fixtures.
- **#42:** platform/component deployment documentation, rendered units, rollout/rollback, and platform evidence.
- **#44:** versioned route envelope, mapping registry, management auth, audit, idempotency, concurrency, and token rotation.
- **#45:** bot image/runtime/network guidance.
- **#33:** optional subprocess transport, worker cap (`4`), nested budgets, and worker evidence.

Keep the current native daemon and v0/v1 workDir route as universal rollback. Roll back only to an
exact prior signed image and matching volume/owner/fingerprint/generation manifest. Missing
provenance, unsupported containment, stale generations, failed restore, or failed backup leaves
data untouched and requires manual cleanup.

## Alternatives rejected

- **Ephemeral container per request/workspace:** breaks SDK history, provider warm state, and gate continuity.
- **One production container per workspace with the bot in Compose:** multiplies host identity and
  supervisor state, couples upgrades, and incorrectly implies tenant isolation.

This container boundary is host-wide trust, not tenant isolation. Separate daemon hosts are
required for tenant isolation.

## Release gates

Implementation must stop before native serving until #42/#43/#44/#45/#33 ownership and the
native-applicable gates agree. Mapping identity, receiver-local readiness, no-follow containment,
lease/fence recovery, resource budgets, full Git verification, and provider provenance gate native
serving; image, Docker security/egress, platform, and consumer evidence gate Docker or release
promotion. Docker uses `restart: on-failure` only.
Implementation and release promotion use separate evidence boundaries:

| Boundary | Required evidence |
| --- | --- |
| Contract/test scaffolding | #44 field handshake and #33 ownership; validators and non-serving fixtures only |
| Native serving | Native-applicable mapping, readiness, containment, lease/fence, resource, Git, and provider gates; #42/#45 ownership |
| Docker fixture | Native gates plus image, engine, security, egress, persistence, and Compose evidence |
| Release promotion | Every ADR and verification-matrix gate, including #42/#45 platform/consumer evidence and strict `stop_grace_period > GJC_SHUTDOWN_TIMEOUT_MS` |

No boundary authorizes a later one. Missing evidence stops serving or promotion, and Docker uses
`restart: on-failure` only.
No cloud VM provisioning, public management endpoint, OAuth implementation, executable packaging,
Docker image, Compose file, or runtime code is part of this ADR change.
