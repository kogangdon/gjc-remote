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
| Protocol v2 retirement and fallback timing | #43/#44 | Deprecation/version migration decision | Keep v0/v1 fallback or reject clearly; no implicit upgrade |

Illustrative values such as 60-second readiness maximum and 8/8/64/4 admission are not final
approvals until their owners close the corresponding gates. TTL alone never authorizes takeover.

## Native inventory verification evidence (as-built)

This section records the observed automated evidence for the native workspace inventory epic
(G001-G016) on main HEAD `fa68941`. The landed coverage below lives in the in-repo suites
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
- Bot receipt binding lifecycle (`bind.request` / `bind.ok` / `bind.negative` /
  `receipt.invalidate` / `socket.retire`) across arm, fingerprint match, drift, deadline, and
  offline transitions.
- Reconnect churn counter gating: increments only for binding-capable v3 replacements
  (protocolVersion >= 3 with both `workspace_readiness_v2` and `workspace_inventory_receipt_v2`
  capabilities); off-mode (v0/v2) replacements keep the counter at 0.
- Sanitized observability allowlist: emitted fields are limited to `event`, `phase`, `code`,
  redacted `bindingId`/`workspaceId`, safe integer `generation`, and a 12-character
  `fingerprintPrefix`; no token, workDir, ACL, or full-fingerprint bytes can pass through the
  sink.

**Observed green baseline (main HEAD fa68941).**

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

**Native workspace serving verification remains N/A.** Native workspace serving is disabled by a
const literal (`NATIVE_WORKSPACE_SERVING_ENABLED = false`, daemon/src/daemon.js:199), with no env/config
override anywhere in the repository; the bot side defaults to false as well and is not overridden
at startup. Separately, the production native-reader path is not yet wired:
`initializeInventoryConfig` is not imported by daemon boot, so the production daemon never
constructs a native reader, and verify-mode `workspace_inventory_receipt_v2` advertisement is
reachable in production only under `GJC_READINESS_TEST_INJECTION=1` test injection. Both the
native-serving enablement and the native-reader daemon-boot wiring are future slices; their
verification belongs to that future reader-wiring / native-serving boundary, not to this epic's
landed evidence.
