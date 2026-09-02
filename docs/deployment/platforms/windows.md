# Windows deployment

Windows x64 supports foreground execution when Node.js is at least 26 for the bot and Bun is at least 1.3.14 for the daemon. Native-control on Windows additionally requires the Visual Studio C++ build tools. Windows arm64 is not an approved native-control target.

Run components independently from the repository root:

```text
cd bot    && node src/bot.js
cd daemon && bun src/daemon.js
```

Foreground operation is the operational fallback when service, provenance, or
evidence gates are not satisfied. It is not boot-managed and does not roll
back the application artifact, runtime, mapping authority, or durable state.

## Service boundary

The selected primary supervisor is Shawl v1.9.0. Its tested distributed binary is unsigned, so it is **not** production provenance evidence. Before use, the release owner must record the source release, exact executable SHA-256, signature/provenance status, and protected staging path; the known hash alone is not provenance. No Shawl installer or service-registration script is checked in.

The Shawl contract uses absolute Node/Bun paths, a protected log directory, `--kill-process-tree`, restart on non-zero exit (`--restart-if-not 0`, not `--restart`), and a restart delay. Its stop bounds are 20 seconds for the daemon and 30 seconds for the bot. The daemon's `GJC_SHUTDOWN_TIMEOUT_MS` must remain below its supervisor stop timeout.

Do not use NSSM: it is discarded and no NSSM implementation, script, or test exists in this repository.

`sc.exe` direct registration is only the documented fallback when Shawl is unsuitable; no `sc.exe` installer, update, or removal script exists. A directly registered Bun or Node process cannot acknowledge `SERVICE_CONTROL_STOP`; SCM ultimately force-ends the tree. Its restart behavior is only a fixed `sc failure` recovery-action list: no clean-exit/crash distinction, jitter, shaped backoff, or coordination with application timers. Accept that degraded contract explicitly or use a reviewed wrapper; do not describe `sc.exe` as equivalent to Shawl.

## Identity, storage, and evidence limits

Use separate least-privilege `gjc-bot-svc` and `gjc-daemon-svc` accounts with **Log on as a service**; never use `LocalSystem` for a daemon. Provider login and profile setup must occur under the actual service account so its `HOME`, `.gjc`, work-directory session data, and component-local `.env` are usable without copying credentials. Protect profiles, `.env`, `.gjc`, `.gjc-remote-session`, logs, manifests, and journals; remove inherited `Users` and `Everyone` access. The Windows native-control config parent must be owned by the management principal or management writes refuse fail-closed.

This is a dedicated-host boundary, not multi-user workstation isolation.
Existing functional supervisor checks do not prove signed Shawl provenance,
production ACL/account behavior, boot/readiness, transaction recovery, or
secret-handling evidence. Current-run readiness requires lineage-aware
PID/start-time and post-boundary evidence, not service state alone. See the
[process-supervision runbook](../../process-supervision.md#windows-supervision),
[ADR 0001](../../adr/0001-process-supervision.md), and
[native-control prerequisites](../../../README.md#local-quick-start).
