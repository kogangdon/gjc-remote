# Linux deployment

Linux supports foreground execution. systemd is the approved
production-oriented design path, but its repository-managed deployment
artifacts and production evidence remain open. This page records the deployment
contract; it is not an installer.

## Foreground

From the repository root, run components independently:

```sh
cd bot && node src/bot.js       # Node.js 26 or newer
cd daemon && bun src/daemon.js  # Bun 1.3.14 or newer
```

Foreground execution is the operational fallback when supervision ownership,
stop, readiness, or evidence requirements are not met. It is not boot-managed
and does not roll back the application artifact, runtime, mapping authority, or
durable state.

## systemd contract

No checked-in systemd unit template, renderer, or installer exists. Do not claim a rendered unit or installation evidence from this repository. When an operator supplies reviewed units, they must implement the [process-supervision contract](../../process-supervision.md#linux-systemd):

- Separate accounts: `gjc-bot` for the bot and `gjc-daemon` for each daemon instance. The bot uses an absolute Node entrypoint and component working directory; the daemon uses an absolute Bun entrypoint, per-instance `HOME`, and one exact `HOST_ID` per instance.
- Environment files are `/etc/gjc-remote/bot.env` and `/etc/gjc-remote/daemon-%i.env`; keep each mode `0600`. `EnvironmentFile` accepts systemd `KEY=value` syntax, not shell syntax: no `export`, command substitution, or shell expansion. Quote special values correctly.
- The required bounds are `Restart=on-failure`, `RestartSec=10s`, `StartLimitIntervalSec=600s`, `StartLimitBurst=5`, `KillSignal=SIGTERM`, `KillMode=control-group`, `TimeoutStopSec=35s`, and `UMask=0077`, with `After=` and `Wants=` `network-online.target`.
- Set the daemon shutdown deadline (`GJC_SHUTDOWN_TIMEOUT_MS`) below `35s`; the default is 15 seconds. Do not configure a deadline at or above the supervisor wall.

Before treating a proposed unit as usable, render concrete values with no placeholders, check it with `systemd-analyze verify`, and collect current-run evidence within a 60-second boundary: invocation ID, boot ID, cgroup, `MainPID`, start time, and exact registration/connection evidence. `active (running)` or an old log line is not readiness.

Use unit-scoped journald queries and retain the host's existing journald storage, retention, and disk policy. A global journald drop-in is outside this contract and requires separate written approval, baseline/diff, rollback ownership, and evidence.

## Native-control boundary

Approved native-control targets are Linux x64 and Linux arm64. Native-control has no portable fallback. Build prerequisites include a node-gyp-capable C++ toolchain and the platform ACL headers (`libacl1-dev` on Debian/Ubuntu, or the package that provides `sys/acl.h` elsewhere); a missing prerequisite is an installation error.

Native inventory/serving remains fail-closed: native serving is off by default and becomes eligible only when `GJC_NATIVE_WORKSPACE_SERVING` is exactly `"1"` **and** a receipt capability is advertised. That condition is not live serving-on evidence. Platform evidence remains limited: CI and static contracts do not replace owned-host, distinct-principal ACL, boot/readiness, journald, and current-run relay evidence. See [native-control](../../../native-control/README.md) and [deployment verification](../../daemon-workspace-verification.md).
