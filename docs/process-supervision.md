# Process supervision runbook

Linux systemd is the approved production-oriented service path (contract below; the unit templates are not yet checked into this repository — see "Linux (systemd)"). Windows uses Shawl v1.9.0 as the selected primary supervisor; it is not a full production
approval because the distributed binary is unsigned, and signed provenance remains a required, still-open release-owner item. Direct `sc.exe` service registration is the documented Windows fallback when Shawl is unsuitable; it provides no restart/backoff supervision semantics beyond `sc failure` recovery actions. The NSSM-based approach previously evaluated for this decision is discarded — no NSSM implementation exists in this repository (see [ADR 0001](adr/0001-process-supervision.md)). This runbook does not install
any supervisor. See [ADR 0001](adr/0001-process-supervision.md) for the decision
and [the pre-mortem](pre-mortem-process-supervision.md) for failure scenarios.
Platform evidence remains scoped to the checks explicitly recorded below.

| Platform path | Status | Repository artifact/evidence boundary |
| --- | --- | --- |
| Linux foreground | Available | Node/Bun process behavior only; not boot-managed |
| Linux systemd | Approved design path | No checked-in unit templates, renderer, installer, or production boot/readiness evidence |
| Windows foreground | Available on x64 | Node/Bun process behavior only; not boot-managed |
| Windows Shawl | Evaluated candidate | v1.9.0 functional checks; unsigned binary and production identity/ACL evidence remain open |
| Windows `sc.exe` | Documented degraded fallback | No checked-in installer/update/remove implementation |
| macOS launchd | Unsupported | No native-control target, plist, installer, or platform evidence |

Component-specific guidance is indexed in
[deployment documentation](deployment/README.md). The explicit macOS boundary
is in [the macOS deployment status](deployment/platforms/macos.md).

## Windows host support boundary

The supported Windows deployment model is a dedicated host owned by the operator, with
the bot and daemon running under their explicitly configured service identities. This
repository does **not** claim multi-user workstation isolation: protecting credentials
or workspaces from unrelated local users, or from a local administrator, is outside the
supported security boundary. Cross-account read/write isolation for unrelated local
users is therefore outside the dedicated-host release gate and must not be reported as
production evidence.

Service-account separation, protected `.env`/`.gjc`/session storage, and removal of
inherited `Users`/`Everyone` access remain required whenever Windows supervision is
deployed. Re-open the multi-user test scope before using a shared workstation or
supporting that deployment model.


## Topology and identity

Run one bot service on the bot host and one daemon service for each exact valid `HOST_ID`:

| Host | Service | Child | Identity |
| --- | --- | --- | --- |
| bot host | `GJCRemoteBot` | `node src/bot.js` | one singleton |
| daemon host | `GJCRemoteDaemon-<instance-key>` | `bun src/daemon.js` | one per exact `HOST_ID` |

`HOST_ID` is the protocol identity, not a display name. It is non-empty, at most 128 UTF-16 code units, and rejects unpaired surrogates, Cc/Cf controls, bidi/format controls, U+2028, and U+2029. Do not trim, normalize, case-fold, or interpolate it into a service name. Derive an ASCII slug (lower-case, non-alphanumeric runs replaced by `-`, at most 32 characters) and append the lower-case SHA-256 of the exact UTF-8 ID bytes. A slug collision or exact-ID mismatch is a refusal, never an overwrite. Channels and work directories never create services.

## Before installing

1. Use a disposable host or a documented maintenance window. Confirm Node `>=26` for the bot and Bun `>=1.3.14` plus the locked SDK for each daemon.
2. Create dedicated least-privilege service accounts. Windows uses `gjc-bot-svc` and `gjc-daemon-svc` with “Log on as a service”; Linux systemd uses `gjc-bot` and `gjc-daemon`. Do not use `LocalSystem` for a daemon. Provider login and profile setup must be performed as that identity so `HOME`/`~/.gjc` and work-directory session data are readable without copying credentials.
3. Use exactly one protected secret source for the deployment mode: component-local `.env` for foreground/Shawl, mode-0600 `/etc/gjc-remote/*.env` files for systemd, or external secret files for the bot container. Do not put tokens, Discord credentials, provider credentials, prompts, or credential-bearing URLs in service metadata, command lines, journals, manifests, or evidence. Reject arbitrary dotenv paths and `DOTENV_CONFIG_PATH`; reject `BOT_WS_URL` userinfo, query, and fragment components.
4. Protect profiles, `.gjc`, env/channels files, `.gjc-remote-session`, logs, manifests, and journals with the service account/SYSTEM and documented administrator recovery access. Remove inherited `Users`/`Everyone` access. Keep debug off (`GJC_REMOTE_DEBUG=0`).
5. Record the pre-existing journald storage/retention/disk policy on Linux. The default operation does not edit global journald configuration.

### Foreground operational fallback

These are the existing operational fallback and a useful process-level evidence
baseline:

```text
# from the repository root
cd bot    && node src/bot.js
cd daemon && bun src/daemon.js   # Bun >= 1.3.14
```

A foreground process is intentionally not boot-managed. Use it when a supervisor
cannot satisfy ownership, stop, readiness, or evidence gates. This does not roll
back an application artifact, runtime, mapping authority, or durable state.

## Windows supervision
### Shawl v1.9.0 (selected primary)

Shawl is the selected primary Windows supervisor. Stage the operator-supplied
binary at `C:\ProgramData\gjc-remote\shawl\shawl.exe`, protect the directory
from inherited user access, and record the actual executable SHA-256 before
registration. The binary tested locally was v1.9.0, SHA-256
`0985555b71e7f943b8f3fc639952a9890aa62e66617942a2d0996985fe8e7c6d`, and had
no Authenticode signature. Do not treat the hash as provenance without recording
the source release and independently verifying the bytes.
The tested binary was unsigned; production use is blocked until the source
release, exact bytes, signature/provenance status, and protected staging path are
recorded and reviewed.

Use absolute Bun/Node paths; a service account cannot be expected to resolve a
user-scoped runtime from `PATH`. Keep credentials in the component-local `.env`
and do not pass secrets in Shawl arguments or service metadata. Use the tested
restart contract (restart on non-zero exit only; do not pass `--restart`) and
configure these stop bounds:

- daemon: `--stop-timeout 20000`; this exceeds the daemon's default
  `GJC_SHUTDOWN_TIMEOUT_MS=15000`;
- bot: `--stop-timeout 30000`; this exceeds the bot's two sequential 10-second
  teardown steps.

Also configure `--kill-process-tree`, `--restart-if-not 0`, a restart delay, and
a protected log directory. `GJC_SHUTDOWN_TIMEOUT_MS` is validated from 1000 ms
through the runtime timer maximum; values above the supervisor stop timeout are
unsafe. Run Shawl under a least-privilege service account in production; the
local test used the default account only as functional evidence.

The local Windows checks passed:

- killing the daemon child caused Shawl to create a replacement child;
- killing the bot child caused Shawl to create a replacement child;
- the daemon reconnected and received `registration accepted` after bot recovery;
- stopping both services completed without an unwanted restart.

These checks establish functional behavior only. They do not establish signed
artifact provenance, production ACL/account behavior, boot/readiness evidence,
or transaction ownership/recovery. A failed security or provenance gate falls
back to the foreground commands below.

### Windows: NSSM (discarded)

**Decision (2026-08-08):** The NSSM-based Windows supervision path is discarded. It was never merged into this repository — its install/update/remove/recovery scripts and supervision-contract test lived only in an untracked `ops/` tree that has since been archived outside the repository and deleted. No NSSM implementation, script, or test exists anywhere in this repository. The operator selected Shawl as the primary Windows supervisor, with direct `sc.exe` service registration as the documented fallback (see [ADR 0001](adr/0001-process-supervision.md)) instead of resuming NSSM work.

### Windows: `sc.exe` fallback (not yet implemented)

Use this path only when Shawl is unsuitable. Nothing below is implemented yet; there is no install/update/remove script for it in this repository — treat it as the contract a future script must satisfy.

#### Service contract

Register exactly `GJCRemoteBot` or one `GJCRemoteDaemon-<instance-key>` with `sc.exe create`, using absolute Node/Bun and application paths, the component directory as the working directory, and an explicit least-privilege service account (`gjc-bot-svc` or `gjc-daemon-svc`; never `LocalSystem` for the daemon). Configure the existing component-local `.env`; extra environment values are limited to non-secret profile paths and `GJC_REMOTE_DEBUG=0`. The service description contains only secret-free owner/role/operation/fingerprint/nonce/proof metadata.

#### Restart contract — the fallback's real cost

Configure `sc failure <service> reset= <seconds> actions= restart/<delay>/restart/<delay>/.../""`. This is the entire automatic-restart contract this fallback provides: a fixed action list, no jitter, no distinction between a clean exit and a crash, and no coordination with the daemon's own reconnect jitter or the bot's teardown steps. There is no NSSM-style throttle/backoff schedule and no Shawl-style `--restart-if-not`/`--kill-process-tree` behavior available through `sc.exe` alone. Either implement a thin wrapper that shapes restart behavior, or explicitly accept bare `sc failure` behavior (or none) as the production contract before relying on this fallback.

#### Stop and readiness

`sc.exe stop <owned-service>` requests a control code; it does not promise a graceful wall or a drain. Because Bun and Node do not implement the Windows Service Control API, a directly registered service cannot acknowledge `SERVICE_CONTROL_STOP` — the SCM force-ends the process tree once its own stop timeout elapses. Observe existing bot signal/registry-close/Discord-destroy evidence; for the daemon use process-tree, exit-code, and pool evidence — do not invent a daemon marker. These are application observations, not a supervisor drain promise.

1. Suppress automatic restart and verify the service owner, fingerprint/proof metadata, root PID/start time, executable, and descendants.
2. Record the empirical no-child signal result and then poll the owned tree for 35,000 ms as an observation deadline only.
3. Classify `signal-and-quiescence-observed` or `force-required`; never call residual work drained.
4. If force is required, revalidate the root and run only `taskkill.exe /PID <verified-root-pid> /T /F`. Never kill by image name. Re-enumerate PID/start-time pairs.
5. A failed force leaves the service disabled and a durable `manual-cleanup` state; use foreground/manual rollback.

For a start, record the UTC boundary, boot identity, stdout/stderr offsets, service fingerprint, and complete pre-start PID/start-time tree. After start, correlate the registered service and actual child PID/start time. A marker counts only when appended after the boundary at or beyond the old offset and while the current lineage exists. Require bot listening/login plus matching host-connected evidence, or daemon registration-accepted evidence, within 60 seconds. Stale output, reused PID without start time, or service status alone is not readiness.

## Linux (systemd)

**The unit templates below are not currently checked into this repository.** They previously lived only in an untracked `ops/` tree (render script plus `.service.in` templates) that has been archived outside the repository and deleted, alongside the discarded NSSM scripts. This section is the contract they must satisfy once they are added and checked in: render a bot unit and a true `gjc-remote-daemon@.service` template. The bot uses `User=gjc-bot`, an absolute Node entrypoint, component working directory, and `/etc/gjc-remote/bot.env`. The daemon uses `User=gjc-daemon`, an absolute Bun entrypoint, `/etc/gjc-remote/daemon-%i.env`, a per-instance `HOME`, and `SyslogIdentifier=gjc-remote-daemon-%i`. Render concrete instances and reject placeholders before installation.

Both units use:

```ini
After=network-online.target
Wants=network-online.target
Restart=on-failure
RestartSec=10s
StartLimitIntervalSec=600s
StartLimitBurst=5
KillSignal=SIGTERM
KillMode=control-group
TimeoutStopSec=35s
UMask=0077
```

These are systemd values, not Shawl or `sc.exe` semantics. `EnvironmentFile` is a separate adapter from dotenv: use `KEY=value`, no `export`, shell expansion, or command substitution, and quote spaces, quotes, backslashes, and `#` correctly. Keep env files mode 0600. Verify the template and each concrete unit with `systemd-analyze verify`; current invocation, boot ID, cgroup, `MainPID`, start timestamp, and exact host registration/connection evidence are required within a 60-second boundary. `active (running)` alone fails.

The normal install consumes host-policy journald. Query unit-scoped records and retain the host policy; do not create or edit a global drop-in. Any host-global journald change needs separate written approval, baseline/diff, owned rollback, and evidence, and must not be implied by this runbook.

## Transactions, recovery, and manual cleanup

**No implementation of this transaction/journal/fault-injection protocol exists anywhere in this repository.** What follows is the contract a future implementation must satisfy before it may be used in production.

Use per-service ACL/mode-protected storage (`C:\ProgramData\\gjc-remote\\transactions` or `/var/lib/gjc-remote/transactions`, mode 0700). Before every install/update/remove mutation, it must:

1. Acquire the per-key lock and generate a unique CSPRNG 128-bit `txNonce` (32 lower-case hex characters). It must never reuse it.
2. Compute a versioned, canonical SHA-256 `resourceProof` over secret-free transaction/resource fields.
3. Persist the envelope in the journal and staged manifest/tombstone before mutation, and in service/unit metadata after publication.
4. Recompute and compare all copies after every mutation. Only an exact three-way match (journal, manifest/tombstone, queried resource) proves ownership.

Recovery must be symmetric and idempotent: install must commit only after metadata, manifest, and current-run readiness; update must retain old/new proofs and restore old settings only with an exact old proof; remove must use a proof-bound tombstone and remove only after no-process evidence. Env files, provider credentials, logs, and `.gjc-remote-session` must never be cleanup targets.

Any missing, malformed, stale, mismatched, hybrid, foreign, or recreated resource must be treated as **`manual-cleanup`**. This includes a stale journal followed by same-name recreation with the same owner/fingerprint but a different, missing, or malformed nonce/proof. It must write a sanitized record with transaction key, phase, expected/observed non-secret metadata, reason, timestamp, and exact operator action; block new mutation for that key and leave the resource untouched until an operator resolves it. It must never recover by service name alone.

Fault-injection evidence is mandatory after every install/update/remove boundary, including prepared/staged state, service creation, metadata publication, settings verification, manifest rename, start/readiness, commit, disable/stop/quiescence, removal, and marker publication. It must repeat malformed, foreign, and stale/recreated-service fixtures. It must seed sentinel env, provider-store, log, and `.gjc-remote-session` files and prove byte-preserving survival. Missing evidence must stop release.

## Rotation, rollback, and loss

For startup-only host-token rotation:

1. Save a protected old value without printing it.
2. Stop the daemon and confirm no old connection.
3. Update/restart the bot; require current readiness.
4. Update/restart the daemon; require registration and matching host-connected evidence.
5. Use two 60-second readiness deadlines (120 seconds total). On failure, restore the protected value in reverse order and verify old-token rejection without logging values.

`GJC_BOT_ALLOWED_USERS`, `GJC_REMOTE_REQUIRE_ALLOWLIST`, and token settings are startup-only; restart the relevant component. `channels.json` remains hot-reloaded and an invalid replacement keeps the last valid map. Planned or forced stop may fail pending invokes and gates. That is bounded loss/failure evidence, not a drain, migration, or recovery claim.

## Optional Linux bot container

The candidate bot-only Compose contract is documented in
[`deploy/docker/bot/README.md`](../deploy/docker/bot/README.md). It uses
`on-failure:5`, a 30-second stop grace, the bot's existing SIGTERM teardown,
TCP listener liveness, non-root/read-only execution, and private host
publication. TCP health is not Discord, mapping, daemon, or provider readiness.

The runtime image build requires an externally produced, production-signed,
architecture-matched native-control bundle and verifies it before startup. CI
has no production signing key and therefore builds only the pinned dependency
stage. Until signed Linux amd64/arm64 bundles and live stop/restart/private-bind
and digest-rollback evidence exist, this is a release candidate rather than a
supported published image. It does not change daemon deployment or the native
systemd/Shawl paths.

## Evidence and escalation

The required evidence set is static contract coverage, pinned Shawl source/release
and executable-hash evidence for the Windows primary path, disposable Windows
stop/readiness/restart/account/ACL tests for the service identity's protected
secret/profile/session paths and inherited-access controls, pinned Ubuntu systemd
template/readiness/journald tests, relay registration evidence, rotation/rollback,
transaction fault injection, and sentinel scans. Cross-account workstation isolation
is not included. NSSM is discarded; no NSSM archive/executable hash evidence applies
to this repository.
Redact secrets, prompts, local credential paths, and private tokens from every artifact.

Platform evidence is pending. Escalate rather than waive any provenance
mismatch, active-child survival, ambiguous ownership, missing manual-cleanup
record, stale readiness marker, journald global mutation, secret hit, or
missing fault boundary. Foreground commands remain an operational fallback
only; they do not roll back application artifacts, runtimes, mapping authority,
or durable state.

## References

- [Shawl repository and releases](https://github.com/mtkennerly/shawl/releases)
- [`sc.exe` create](https://learn.microsoft.com/windows-server/administration/windows-commands/sc-create) and [`sc.exe` failure](https://learn.microsoft.com/windows-server/administration/windows-commands/sc-failure)
- [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) and [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
- [journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html)
- [Node signal events](https://nodejs.org/api/process.html#signal-events)
- Repository contracts: `shared/protocol.js`, `bot/src/shutdown.js`, `bot/.env.example`, `daemon/.env.example`
