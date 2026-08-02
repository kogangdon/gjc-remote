# Pre-mortem: daemon workspace container

This pre-mortem covers the design contract in issue #43. It does not claim Docker, provider,
backup, or platform evidence.

| Failure scenario and signal | Owner and mitigation | Required evidence |
| --- | --- | --- |
| A POSIX symlink, Windows junction/reparse point, UNC alias, drive retarget, archive link, foreign `mappingId`, or stale generation escapes the root. Signal: identity mismatch or an outside-root write attempt. | **#43/#44.** Bind every route to mapping ID, source platform, generation, and volume/share identity. Use descriptor/handle-relative no-follow operations and post-operation identity checks. Unsupported primitives fail closed and preserve data. | POSIX/drive/UNC traversal and race fixtures; wrong/foreign/missing IDs; generation changes; archive traversal; no outside-root writes; sanitized stable events. |
| A replacement socket or replayed timestamp keeps stale readiness visible. Signal: `/hosts` says ready after disconnect, expiry, duplicate revision, or v2 data reaches a v1 peer. | **#43.** Atomic v2 capability gate, new socket generation, strict revisions, receiver-local monotonic TTL, bounded skew, deterministic expiry aggregation, singleton v1 fallback. | Future/past/skew/replay/TTL fixtures; local timer/lazy expiry; replacement socket; aggregate snapshots; v1/v2 matrix; no stale ready. |
| Two daemons or a crash corrupts state, or provider backup/key evidence is copied or unrecoverable. Signal: lock/fence mismatch, interrupted journal, shallow graph, missing key, or failed restore. | **#43/#42.** Durable sole-writer lock/fence, activity/generation leases, idempotent journal, complete Git graph, pre-destruction backup, external encrypted key recovery, independent signatures/manifests, strict grace, and durable `manual-cleanup`. | Dual-writer/crash fixtures; stale volume/fence races; refresh/prompt fencing; shallow/promisor rejection; backup/restore/key recovery; provenance and secret scans; supervisor/application timelines. |

## Release stop conditions

Stop before implementation or deployment on ownership/schema conflict, absent mapping identity,
unsupported containment, stale readiness authority, missing cgroup admission, ambiguous recovery,
missing provider/image provenance, weak Docker security or egress proof, unsafe shutdown grace,
incomplete Git policy, or any path/secret leakage. Preserve the native daemon rollback.

## Observability

Use opaque host/workspace/mapping/transaction IDs and stable codes for negotiation, mapping,
readiness, leases, generations, containment, Git, resources, backup/restore, lock/fence,
shutdown, restart, security preflight, and egress. Never emit paths, credential values, raw URLs,
prompts, stacks, or controls.
