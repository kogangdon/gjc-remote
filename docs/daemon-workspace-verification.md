# Daemon workspace contract verification matrix

This matrix is the handoff boundary for issue #43. It identifies evidence that must exist before
implementation is released; design documents alone are not runtime evidence.

| Owner | Contract boundary | Required verification | Release dependency |
| --- | --- | --- | --- |
| #43 | workspace identity, mapping, containment, lifecycle, readiness | Unit and integration fixtures for POSIX/drive/UNC mapping, no-follow containment, v2 gate, receiver-local TTL, leases, generations, redaction, resource admission, and signal/fatal shutdown | Blocks daemon implementation when any proof is absent |
| #42 | platform/component deployment | Rendered Linux/Windows/macOS deployment guidance, effective timeout/grace, rollback, supervisor behavior, and platform evidence | Consumes #43 invariants; must not redefine them |
| #44 | route/control plane | Versioned `channels.json` envelope, mapping registry, admin auth separate from Discord permissions, audit, idempotency, concurrency, and token rotation | #43 cannot create a parallel schema or mutate the control-plane store |
| #45 | bot container/runtime | Bot image, runtime, outbound network, and readiness-consumer guidance | Must consume the v2 WebSocket contract |
| #33 | optional workers | Subprocess transport, worker cap, nested resource budget, and worker evidence | Must preserve aggregate 8/8/64 admission guarantees |

## Required evidence layers

1. **Unit:** bounded validators, path identity and containment, mapping generations, readiness
   revision/TTL/replay, error taxonomy, redaction, lease/fence, Git graph, resource and grace bounds.
2. **Integration:** real HostRegistry with fake v0/v1/v2 peers; daemon session-root migration;
   lifecycle fencing; complete Git remotes; volume/journal/backup/restore fixtures.
3. **Same-host Compose (test only):** disposable bot/daemon services with four role volumes,
   non-root/read-only/capability/cgroup inspection, egress allow/deny probes, restart and grace,
   v1 singleton fallback, v2 mapping/readiness, and cleanup proving no real state changed.
4. **Security/provenance:** image/base/source/lock/SDK digests, SBOM, scan, signature/attestation,
   provider-key recovery, volume manifests, secret sentinel scans, and manual-cleanup behavior.
5. **Release/observability:** daemon and supervisor timelines, opaque structured events, `/hosts`
   snapshots, exact versions, rollback rehearsal, and #42 platform evidence.

## Linux arm64 CI evidence

The required `ubuntu-24.04-arm` GitHub-hosted CI leg builds `native-control` on
the arm64 runner, writes and verifies its platform manifest, and runs the same
runnable native integration and repository suites as Linux x64 and Windows
x64. This is native arm64 execution evidence, not cross-compilation evidence.
The lane installs `libacl1-dev`, so it covers the addon's real Linux libacl
calls and fail-closed ACL checks under the runner account.

This hosted lane does **not** prove multi-principal deployment behavior. GitHub
Actions supplies one effective runner principal; it does not provision the
separate M/B/R/D/SYSTEM accounts required for real-principal allow/deny and
ownership evidence. Those checks require an owned host fixture with distinct
UIDs and remain a release/platform gate. The arm64 lane also does not claim
distribution-specific ACL behavior beyond Ubuntu 24.04 and its libacl package.

Required structured event fields are `code`, `phase`, `duration`, opaque host/workspace/mapping/
transaction IDs, socket generation, revision, fencing sequence, and local received/expiry times.
Required gauges cover connected/ready/degraded/expired hosts, active leases/sessions/workspaces/
workers, in-flight invokes, resource denials, lock/fence owner, graph verification, backup age,
key version, and restart count. Release evidence includes path/secret/control sentinel scans.

## Non-negotiable gates

- No Docker image, cloud VM, public management endpoint, executable packaging, or runtime code is
  implied by this design-only issue.
- `restart: on-failure` only; provider absence and denied registration do not restart-loop.
- Signal exit is 0, fatal exit is non-zero, and effective stop grace is strictly greater than the
  parsed `GJC_SHUTDOWN_TIMEOUT_MS` after overrides.
- Missing, foreign, stale, copied, hybrid, or unverifiable evidence preserves data and enters
  durable `manual-cleanup`.
- Host-wide mounted authority is not tenant isolation; separate daemon hosts are required.
## Assumptions and closure ledger
| Assumption | Owner | Closure gate | Fail-closed behavior |
| --- | --- | --- | --- |
| #44 route envelope, mapping persistence, and migration timing | #44 | Versioned schema and authenticated mapping fixture | Reject unknown/missing mapping identity; no parallel registry |
| Readiness TTL/skew bounds and SDK/model probe | #43 | Bounded validator and current-run probe fixtures | Connected-not-ready/unknown; never ready |
| Git refs, remote allowlist, dirty policy, cadence, and storage budget | #43/#44 | Complete-graph and destructive-operation fixtures | `GIT_GRAPH_INCOMPLETE` and preserve prior generation |
| Lease TTL, fence recovery, resource budgets, backup RPO/RTO | #43/#33 | Numeric boundary and crash/recovery fixtures | `LEASE_CONFLICT`/`RESOURCE_EXHAUSTED` or manual cleanup |
| Provider backup key ownership, escrow, rotation, and restore | #42/#43 | Independent key recovery and restore rehearsal | Preserve data and require manual cleanup |
| SDK/package/lock reconciliation at 0.12.21 and evidence schedule | #42/#45 | Source/lock/version/provenance packet | Stop image/release work |
| Docker production target and Windows-host primitive support | #42/#43 | Linux-engine matrix and Windows/UNC containment fixtures | Unsupported target refuses startup |
| Singleton legacy fallback fence | #43/#44 | Live remap/invalidation and re-registration fixture | Invalidate socket; never silently remap |
| Protocol v0/v1 retirement | #43/#44/#55 | [ADR 0005](adr/0005-managed-protocol-floor.md): managed v3 floor now; remove local parsers by v0.4.0 RC or 2026-10-01 | Reject managed lower peers with `PROTOCOL_INCOMPATIBLE`; no inferred mapping or downgrade |

Illustrative values such as 60-second readiness maximum and 8/8/64/4 admission are not final
approvals until their owners close the corresponding gates. TTL alone never authorizes takeover.

## Native inventory verification evidence (as-built)

This section records the initial observed automated evidence for the native workspace inventory epic
(G001-G016) on main HEAD `fa68941` and the current runtime contract added by
later slices. Historical counts remain commit-pinned. The landed coverage lives in the in-repo suites
`daemon/test/`, `native-control/test/`, `bot/test/`, and `shared/test/`; run them with
`npm test --workspaces` (plus `npm run test:scripts` at the root) and `npm run smoke:local`. It
supplements, and does not replace, the design-only matrix above.

**Landed automated coverage.**

- Daemon `GJC_NATIVE_INVENTORY_MODE` config parsing and five-role `GJC_INVENTORY_ROLE_BINDINGS`
  parsing/validation fail closed at boot (invalid mode or config -> `console.error` +
  `process.exit(1)` / `CONFIG_INVALID`).
- Durable D floor genesis (generation 1 only, atomic publish), exact replay (0 writes),
  `+1` fenced advance, and rejection of rollback/jump/same-generation-mismatch/missing-floor
  cases as `INVENTORY_STALE`.
- Live invalidation cascade: re-entrancy-guarded epoch bump, lease invalidation, synchronous
  per-connection receipt fence, in-flight bind/invoke invalidation, exactly one bounded negative
  readiness frame, and socket close(1013) -- proving no `bind_ok` and no ready frame is emitted
  under drift.
- Bot-owned local observability is schema-v1 only: deeply frozen flat callback records cover
  bind/receipt/socket transitions, receiver-local v2/v3 readiness acceptance and expiry, and
  invoke start/finish/deny. Records use a fixed allowlist of bounded opaque IDs/codes and local
  wall/monotonic times; they do not carry prompts, paths, labels, tokens, raw errors, or
  fingerprints. The constant-shape bot snapshot reports connected/ready/degraded/expired hosts,
  in-flight invokes, bot pending-cap denials, and v3 socket replacements.
- Reconnect churn counter gating: increments only for binding-capable v3 replacements
  (protocolVersion >= 3 with both `workspace_readiness_v2` and `workspace_inventory_receipt_v2`
  capabilities); an off-mode (v0/v2) replacement does not increment it, and a host that has
  remained entirely off-mode stays at 0. Prior v3 churn can remain nonzero. Replacements are not
  process restart evidence.
- Daemon owner telemetry foundation is local schema-v1 only. `AdmissionBudget`, `SessionPool`,
  and `WorkspaceLeaseRegistry` expose direct aggregate admission snapshots; lease gauges retain
  invalidated activities while holders remain. Their optional owner callbacks emit flat,
  bounded, frozen capacity/session/lease facts plus receipt-retirement cleanup facts with
  process-local registry-issued fence sequences and isolate subscriber exceptions. Receipt
  pending receipt-cleanup gauge deliberately excludes idle, replacement, late-created, and shutdown
  disposal; the failed managed-cleanup gauge includes every managed disposal class already fenced
  by the pool. Broader pending classification remains deferred. The composite snapshot samples each owner
  directly but is not cross-owner atomic. Owner observer types are validated at construction,
  while event IDs use one shared opaque-ID grammar at projection/emission time. Composite
  snapshots reject duplicate/reserved keys rather than
  silently shadowing one owner's gauge. Focused tests pin every owner capacity/busy/retire/create
  and bounded receipt-cleanup terminal. This owner foundation is wired into daemon orchestration:
  one process-local composite attaches the three owner snapshots and emits one correlated,
  bounded daemon `invoke` terminal after each valid invoke. Invoke records use only admitted
  local readiness/mapping/workspace generations and a registry-issued activity fence; they carry
  no wire fields, paths, prompts, errors, credentials, or sender fence. On the deployed Bun
  runtime, `succeeded` means the final frame was queued while the socket was OPEN; Bun's `ws`
  callback does not prove peer receipt or network flush. Flush/receipt evidence remains outside
  this local telemetry claim. Invoke transaction correlation is owned and directly tested by the
  observability module: admitted local generations/IDs and registry-issued fence are frozen,
  non-null when present, and cannot be changed after admission. The local smoke keeps the
  production-shaped v1 readiness/inventory path, opens only the double-gated
  (`GJC_DAEMON_TEST_MODE=1` plus `GJC_OBSERVABILITY_TEST_IPC=1`) daemon-private test IPC channel,
  without changing the embedded SDK's `NODE_ENV`, and requires exactly
  three successful bounded terminals
  for its three real SDK invokes without request-data leakage.
- A spawned protocol-v3 receipt-bound admitted-invoke fixture uses injected readiness, inventory,
  and a fixed daemon-private session factory to reach the real daemon receipt verification and
  `WorkspaceLeaseRegistry` activity-fence path. It proves that one admitted invoke freezes local
  socket/readiness/mapping/workspace correlation and a registry-issued fence, emits exactly one
  local terminal, and adds no telemetry to the normal success wire frame. The fixture explicitly
  regression-locks the receipt proof's inventory generation/fingerprint in the activity authority;
  omitting that daemon-held proof fails admission before session creation. It
  opts into serving with a temporary root and uses a second invoke as an ordering barrier. This is
  not provider evidence, production native inventory/addon evidence, serving lifecycle E2E,
  platform evidence, or bot/HostRegistry mapping-issuance evidence; its inventory/readiness and
  session are test-injected while the receipt proof and lease registry are real daemon code. The
  session factory additionally requires `GJC_SESSION_FACTORY_TEST_INJECTION=1`, which the real-SDK
  smoke never sets. This fixture was the first end-to-end exercise of receipt-bound invoke
  admission and exposed that the leg had been broken until the daemon-held inventory proof was
  included in activity authority.
- Daemon lifecycle telemetry is local schema-v1 only and covers all seven validated operations.
  It freezes trusted binding/inventory correlation when both resolve, emits exactly one
  committed/refused/failed terminal, reports destructive cleanup as `not_required`,
  `manual_required`, or conservatively `indeterminate`, and never projects operation receipts.
  A spawned `daemon.js`, protocol-v2, serving-off integration uses test-injected inventory,
  accepts a daemon-held binding, then sends deliberately divergent wire mapping/generation
  claims. The terminal retains the accepted binding's non-null mapping/workspace generations and
  IDs, while exact WebSocket event/error shapes prove that no additional telemetry properties
  enter the refusal frame (the protocol-required event `workspaceId` remains). Lifecycle
  `fenceSequence` remains null because no registry-issued lifecycle fence is exposed at this
  boundary. This fixture is not invoke admission, serving-on E2E, or platform evidence.
  Manual cleanup produces a separately latched bounded `manual_cleanup/required` signal.
  Reset/delete additionally retains its existing sanitized receipt-backed console checkpoint;
  restore/migration candidate-cleanup failure has no receipt and is surfaced only through the
  bounded telemetry signal. The two local surfaces are not equivalent. Connection loss drains pending destructive
  operations with indeterminate cleanup rather than claiming no cleanup is needed.
- Deferred: durable manual-cleanup backlog/resolution, supervisor restart proof, and
  exporter/evidence ingestion remain separate daemon/supervisor slices. Bot callback/snapshot
  records are local API telemetry, not wire protocol or release evidence.

**Historical observed green baseline (main HEAD fa68941).**

- Full workspace suite: root 46 / bot 273 / daemon 240 / native-control 135 pass plus 3
  platform-gated skips / shared 65, with 0 failures.
- `npm run smoke:local` completes with `SMOKE_OK`.
- `git diff --check` is clean.

**Native-control skips are legitimate platform gates, not hidden failures.** The 3
native-control skips correspond to a Windows owned-user fixture and Linux-only POSIX ACL probes
that require a distinct-principal host and cannot run on a shared CI runner account; they are not
masking implementation gaps.

**Multi-principal ACL and durable-floor evidence.** Owned distinct-principal Linux and Windows
fixtures (separate from hosted CI) proved the five-principal M/B/R/D/SYSTEM ACL allow/deny and
ownership behavior, plus the D durable-floor genesis and `+1` advance behavior, under a
release/platform gate. GitHub-hosted CI (including the required `ubuntu-24.04-arm` leg) supplies
only one effective runner principal and cannot itself prove multi-principal deployment behavior.

**Native workspace serving is env-gated and OFF by default.** Native workspace serving is now a
fail-closed runtime decision (`NATIVE_WORKSPACE_SERVING_ENABLED` at daemon/src/daemon.js:290, an
`= resolveNativeServingEnabled({env, inventoryReceiptAdvertised})` call): it is enabled only when the operator opt-in `GJC_NATIVE_WORKSPACE_SERVING`
is exactly `"1"` AND `inventoryReceiptAdvertised` is boolean `true`. With the env var unset (the
default) the gate reads `false` and its read site inside `admitReadyWorkload` returns
`RUNTIME_INCOMPATIBLE`, exactly as before the S6f.7 flip. The bot side also defaults false and now
passes only the exact `GJC_NATIVE_WORKSPACE_SERVING="1"` opt-in to
`HostRegistry`; when enabled, both peers require ADR 0005's complete managed-v3
floor. CREATE and REFRESH then assemble native serving deps;
reset/delete additionally requires the verified residual-process capability and an exact
receipt-bound lifecycle transaction context. Restore/migration additionally requires Linux native
no-follow support and a single-use, non-expired `GJC_RESTORE_CONTEXTS_JSON` claim bound to the exact
receipt-v3 authority, operation, idempotency fingerprint, provenance-v2 content, and lineage; an
absent or invalid claim leaves only that dispatcher null. Any INV-6 boot-crash-recovery-barred
workspace is refused on every lifecycle op. The
production native-reader daemon-boot wiring is landed (commit e62b7b5, #141): `daemon/src/daemon.js`
imports `initializeInventoryConfig` and, when `GJC_NATIVE_INVENTORY_MODE === 'verify'` and outside
test injection, constructs and self-tests the production native reader via
`daemon/src/inventory-boot-wiring.js`, threading it into `createWorkspaceInventoryProvider({reader})`;
verify-mode config or self-test failure hard-exits with a sanitized diagnostic. Native-serving
enablement (issue #81, S6f.7) is landed as an opt-in boundary; live serving-ON evidence belongs to a
deployment that sets `GJC_NATIVE_WORKSPACE_SERVING=1`.

`GJC_RESTORE_CONTEXTS_JSON` is a JSON array of 1-64 claims (maximum encoded
size 1 MiB). Each claim carries the ten receipt-v3 authority fields, `operation`,
`idempotencyFingerprint`, an absolute `stagingPath` outside `workspaceRoot`,
the exact provenance-v2 `expectedAuthority`, a complete workspace `manifest`,
source workspace/generation lineage, `expectedGraph`, `probedAtMs`, and
`expiresAtMs`; migration claims also carry `migrationKind`. The staged
provenance record is `restore-provenance.json`. Claims whose lifetime exceeds
the configured readiness maximum, duplicate claims, expired claims, reused
claims, and any authority/message mismatch fail closed.
