# Windows deployment

Windows x64 supports foreground execution when Node.js is at least 26 for the bot and Bun is at least 1.4.0 for the daemon. Native-control on Windows additionally requires the Visual Studio C++ build tools. Windows arm64 is not an approved native-control target.

Run components independently from the repository root:

```text
cd bot    && node src/bot.js
cd daemon && bun src/daemon.js
```

Foreground operation is the operational fallback when service, provenance, or
evidence gates are not satisfied. It is not boot-managed and does not roll
back the application artifact, runtime, mapping authority, or durable state.

## Service boundary

The host-local lifecycle CLI is **`gjc-remote-service`** from package
**`@gjc-remote/native-control`**. It accepts exactly `install`, `status`,
`update`, `rollback`, `uninstall`, or `recover` and one strict JSON request on
non-terminal stdin; no flags or caller-selected paths are accepted. Node.js
26+ runs the bot and this CLI; Bun 1.4.0+ runs the daemon. `HOST_ID` remains
exact protected daemon input and the instance key is its display slug plus the
full SHA-256 of exact UTF-8 bytes.

The selected primary supervisor is Shawl v1.9.0. Its tested distributed binary is unsigned, so it is **not** production provenance evidence. Before use, the release owner must record the source release, exact executable SHA-256, signature/provenance status, and protected staging path; the known hash alone is not provenance. No Shawl installer or service-registration script is checked in.

The repository contains the source-level lifecycle CLI, orchestration,
protected store, Linux/Windows driver contracts, and fake-native transaction
tests. These artifacts establish the source contract only; signed deployment
assets, production signing/trust, real systemd or SCM mutation, and
disposable-host evidence remain unclaimed.

The Shawl contract uses absolute Node/Bun paths, a protected log directory, `--kill-process-tree`, restart on non-zero exit (`--restart-if-not 0`, not `--restart`), and a restart delay. Its stop bounds are 20 seconds for the daemon and 30 seconds for the bot. The daemon's `GJC_SHUTDOWN_TIMEOUT_MS` must remain below its supervisor stop timeout.

Do not use NSSM: it is discarded and no NSSM implementation, script, or test exists in this repository.

`sc.exe` direct registration is only the documented fallback when Shawl is unsuitable; no production `sc.exe` installer, update, or removal script is claimed. A directly registered Bun or Node process cannot acknowledge `SERVICE_CONTROL_STOP`; SCM ultimately force-ends the tree. Its restart behavior is only a fixed `sc failure` recovery-action list: no clean-exit/crash distinction, jitter, shaped backoff, or coordination with application timers. Accept that degraded contract explicitly or use a reviewed wrapper; do not describe `sc.exe` as equivalent to Shawl.

### Trial and activation contract

During a candidate or predecessor trial, SCM must report exactly
`SERVICE_DEMAND_START`, empty failure actions, and a suppressed
failure-actions flag. `SERVICE_DISABLED` is only the first-create protection
window and is not a startable trial state. Only then may the controller call
`StartServiceW`; API success or `START_PENDING` (including a zero PID) is not
startup evidence. Require a new Shawl wrapper and child PID/start/executable
epoch, then current-run application evidence. Final activation first sets and
queries `SERVICE_AUTO_START` with actions still empty, then sets and queries
the bounded three-at-10-second wrapper actions with a 600-second reset period.
The AUTO_START change is the boot-activation linearization point.

Controller death does not stop a running trial and is not a watchdog. While
automatic activation is suppressed, Shawl's child policy may still operate if
its wrapper survives. Same-boot recovery requires the persisted exact boundary
and current epoch; otherwise stop the exact tree, prove quiescence, and retrial.
Reboot or an epoch change invalidates the old startup receipt.

Windows startup evidence is deliberately conservative. A marker-only SCM
snapshot cannot substitute for the service-scoped log epoch/cursor ABI. Missing
or gapped stdout/stderr log epochs, ambiguous PID-0 or process-tree evidence,
overflow, or a surviving child are safe refusals (`manual-cleanup`/pending),
not reasons to infer readiness or an empty tree. The two-family Shawl log
observer ABI (`open_win32_service_log_observer`/`read_win32_service_log_observer`,
native contract 5 revision 1) exists in source but must be compiled and
qualified on a real host before it counts as release evidence.

## Production host composition (source level)

With no injected lifecycle, the Windows x64 direct CLI composes one
operation-scoped host producer (`native-control/src/service-windows-host.js`).
It binds the validated request, captures protected authority only through
native read-only external roots, and derives the exact Launch from the signed
`windowsServiceBootstrap` release metadata: guard path/hash, static closure
fingerprint, and Node 26.7.0 / Bun 1.4.2 runtime policy. The route stays
SCM → Shawl → Node/Bun → application; there is no extra resident wrapper,
health endpoint, or `sc.exe` bypass.

The operator must provision the following before the first install. The
producer never creates, copies, or relaxes them:

- `<workingDirectory>\.env`: the component effective configuration. Keys
  with the `GJC_REMOTE_`, `NODE_`, or `BUN_` prefix and
  HOME/USERPROFILE/XDG_CONFIG_HOME/`GJC_CODING_AGENT_DIR`/`PI_CODING_AGENT_DIR`
  are refused, as is a bot `CHANNELS_CONFIG` that conflicts with the
  configured value. A daemon `.env` must define `HOST_ID` and `BOT_WS_URL`.
- `<workingDirectory>\service-authority.json`: the declared service-scope
  catalog (daemon: including the provisioned service SDK profile root).
- Daemon only: `<workingDirectory>\runtime-config\.bunfig.toml`, one
  protected zero-byte file shared by `XDG_CONFIG_HOME` and the explicit Bun
  config path.
- The exact Node/Bun runtime binary at `runtimePath`, whose hash is bound into
  the Launch.
- Every ancestor of `workingDirectory`, including the drive root, must grant
  the service account `READ_CONTROL` and traversal but deny it write-data,
  write-EA, write-attributes, delete, delete-child, `WRITE_DAC` and
  `WRITE_OWNER`, and must not be owned by it; the working directory itself
  must also deny append/add-subdirectory. The service re-proves this chain on
  every start and refuses with `SERVICE_ACCESS_DENIED` otherwise. Default ACLs
  commonly fail it: a non-system drive root grants `Authenticated Users`
  Modify, and `C:\ProgramData` grants `Users` write-data. Install does not yet
  preflight this chain, so provision it explicitly (for example a protected
  top-level directory on the system drive).

Install reads and validates these write-free before any mutation. Other
operations reuse the configuration retained in the current service manifest
and re-capture the same host authority (including the protected `.env` and
runtime binary) to derive the exact Launch, so status, uninstall and recovery
refuse rather than guess when that authority has drifted or been removed.
Windows `update` re-observes the declared scope and requires the signed
candidate to read every observed retained format and keep the target, runtime,
native-control, wire, entrypoint and SDK external-state contracts of the
authenticated current release (which stays the rollback predecessor); any
crossing refuses before any journal, metadata or service write. Bot readiness is listener + Discord
login + the exact configured connected-host set/count. Daemon readiness is the
current exact-target accepted registration. Provider and workspace health
stay `unknown`.

`npm run smoke:windows-host-fixture` is a credential-free foreground fixture.
It drives the real bot/daemon startup reporters through the production
observation reducer. Its evidence class is `foreground-fixture`, not an
actual service lifecycle: it uses no SCM, Shawl, account, ACL, native addon,
bootstrap guard, Discord, SDK, or provider.

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

G003 fake-native driver tests and modeled Windows checks establish contract
behavior only. They do not prove signed Shawl bytes, production deployment
keys, SCM mutation, ACL/account behavior, current-run relay, or disposable
Windows-host evidence. Those human/platform gates remain mandatory before
production use. External `.env`, HOME, provider credentials, logs,
`.gjc-remote-session`, and mapping/configuration bytes are never lifecycle
cleanup targets and must survive rollback or uninstall byte-for-byte.
