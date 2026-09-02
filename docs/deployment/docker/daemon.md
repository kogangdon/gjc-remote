# Daemon Docker status

No daemon Dockerfile or Compose fixture exists in this repository. Do not present a daemon Docker command, image, Compose configuration, or deployment procedure as available. Docker runtime work remains open as Phase 3 / issue #54.

The future fixture is a design contract, not runnable guidance. It must be a pinned, non-root daemon image with a test-only same-host Compose fixture and prove a read-only root, declared mounts, UID/GID ownership, dropped capabilities, seccomp, `no-new-privileges`, bounded cgroups, private network with allow/deny egress, provider/session/state persistence, `restart: on-failure`, and `stop_grace_period > GJC_SHUTDOWN_TIMEOUT_MS`. Unsupported engines or platforms and failed preflight must refuse startup. Docker does not establish tenant isolation.

Native inventory remains a fail-closed prerequisite. `GJC_INVENTORY_ROLE_BINDINGS` must contain exactly the distinct `management`, `bot`, `recovery`, `daemon`, and `system` native principals; `system` is `uid:0` on Linux or `S-1-5-18` on Windows. Native serving defaults off and requires both the exact `GJC_NATIVE_WORKSPACE_SERVING="1"` opt-in and an advertised receipt capability. This does not constitute live serving-on evidence, and inventory is not routing authority.

Phase 3 must preserve independent bot/daemon deployment and close the native, image, engine, security, egress, persistence, containment, provenance, shutdown, and platform evidence gates before any Docker promotion. See [Phase 3](../../daemon-workspace-implementation-phases.md#phase-3--docker-runtime), [daemon container ADR](../../adr/0002-daemon-workspace-container.md), [native inventory](../../../native-control/README.md), and [deployment verification](../../daemon-workspace-verification.md).
