# Process supervision runbook

Linux systemd is the approved production-oriented service path. Windows is currently
documented as a Shawl v1.9.0 evaluation/interim path; it is not a production
approval because the distributed binary is unsigned. This runbook does not install
either supervisor. See [ADR 0001](adr/0001-process-supervision.md) for the decision
and [the pre-mortem](pre-mortem-process-supervision.md) for failure scenarios.
Platform evidence remains scoped to the checks explicitly recorded below.


## Topology and identity

Run one bot service on the bot host and one daemon service for each exact valid `HOST_ID`:

| Host | Service | Child | Identity |
| --- | --- | --- | --- |
| bot host | `GJCRemoteBot` | `node src/bot.js` | one singleton |
| daemon host | `GJCRemoteDaemon-<instance-key>` | `bun src/daemon.js` | one per exact `HOST_ID` |

`HOST_ID` is the protocol identity, not a display name. It is non-empty, at most 128 UTF-16 code units, and rejects unpaired surrogates, Cc/Cf controls, bidi/format controls, U+2028, and U+2029. Do not trim, normalize, case-fold, or interpolate it into a service name. Derive an ASCII slug (lower-case, non-alphanumeric runs replaced by `-`, at most 32 characters) and append the lower-case SHA-256 of the exact UTF-8 ID bytes. A slug collision or exact-ID mismatch is a refusal, never an overwrite. Channels and work directories never create services.

## Before installing

1. Use a disposable host or a documented maintenance window. Confirm Node for the bot and Bun `>=1.3.14` plus the locked SDK for each daemon.
2. Create dedicated least-privilege service accounts (`gjc-bot-svc`, `gjc-daemon-svc`) with “Log on as a service”. Do not use `LocalSystem` for a daemon. Provider login and profile setup must be performed as that identity so `HOME`/`~/.gjc` and work-directory session data are readable without copying credentials.
3. Keep secrets in the component-local `.env` (`bot/.env` or `daemon/.env`) loaded by the existing `dotenv/config`. Do not put tokens, Discord credentials, provider credentials, prompts, or credential-bearing URLs in service metadata, command lines, journals, manifests, or evidence. Reject arbitrary dotenv paths and `DOTENV_CONFIG_PATH`; reject `BOT_WS_URL` userinfo, query, and fragment components.
4. Protect profiles, `.gjc`, env/channels files, `.gjc-remote-session`, logs, manifests, and journals with the service account/SYSTEM and documented administrator recovery access. Remove inherited `Users`/`Everyone` access. Keep debug off (`GJC_REMOTE_DEBUG=0`).
5. Record the pre-existing journald storage/retention/disk policy on Linux. The default operation does not edit global journald configuration.

### Foreground rollback

These are the existing, universal fallback and a useful evidence baseline:

```text
# from the repository root
cd bot    && node src/bot.js
cd daemon && bun src/daemon.js   # Bun >= 1.3.14
```

A foreground process is intentionally not boot-managed. Use it when a supervisor cannot satisfy ownership, stop, readiness, or evidence gates.

## Windows supervision
### Shawl v1.9.0 evaluation path

Shawl is the current Windows evaluation adapter. Stage the operator-supplied
binary at `C:\ProgramData\gjc-remote\shawl\shawl.exe`, protect the directory
from inherited user access, and record the actual executable SHA-256 before
registration. The binary tested locally was v1.9.0, SHA-256
`0985555B71E7F943B8F3FC639952A9890AA62E66617942A2D0996985FE8E7C6D`, and had
no Authenticode signature. Do not treat the hash as provenance without recording
the source release and independently verifying the bytes.
The tested binary was unsigned; production use is blocked until the source
release, exact bytes, signature/provenance status, and protected staging path are
recorded and reviewed.

Use absolute Bun/Node paths; a service account cannot be expected to resolve a
user-scoped runtime from `PATH`. Keep credentials in the component-local `.env`
and do not pass secrets in Shawl arguments or service metadata. Configure
`--kill-process-tree`, a bounded `--stop-timeout`, explicit restart conditions,
delay, and a protected log directory. Run Shawl under a least-privilege service
account in production; the local test used the default account only as functional
evidence.

The local Windows checks passed:

- killing the daemon child caused Shawl to create a replacement child;
- killing the bot child caused Shawl to create a replacement child;
- the daemon reconnected and received `registration accepted` after bot recovery;
- stopping both services completed without an unwanted restart.

These checks establish functional behavior only. They do not establish signed
artifact provenance, production ACL/account behavior, boot/readiness evidence,
or transaction ownership/recovery. A failed security or provenance gate falls
back to the foreground commands below.

### Legacy NSSM fallback (not primary)

### Provenance gate

Obtain NSSM yourself from the approved URL; do not download it from an installer, bundle it, or commit the binary:

`https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip`

Verify the actual bytes before any service mutation:

```powershell
Get-FileHash -LiteralPath .\nssm-2.24-101-g897c7ad.zip -Algorithm SHA256
Get-FileHash -LiteralPath .\win64\nssm.exe -Algorithm SHA256
```

Compare the observations with this receipt and retain sanitized URL/version/path/tool/result evidence:

```text
archive SHA-256       99f5045fffbffb745d67fe3a065a953c4a3d9c253b868892d9b685b0ee7d07b8
official build SHA-1  ca2f6782a05af85facf9b620e047b01271edd11d
win64\nssm.exe SHA-256  eee9c44c29c2be011f1f1e43bb8c3fca888cb81053022ec5a0060035de16d848
```

A receipt string without matching authoritative byte observations fails the release gate. The archive and executable hashes are exactly 64 lower-case hex characters; the build hash is exactly 40.

### Service contract

Install exactly `GJCRemoteBot` or one `GJCRemoteDaemon-<instance-key>` under the component directory with absolute Node/Bun and application paths, delayed automatic start, own-process type, and an explicit service account. Configure the existing component-local `.env`; `AppEnvironmentExtra` is limited to non-secret profile paths and `GJC_REMOTE_DEBUG=0`. Query settings with `nssm get` after writing them:

- `AppStopMethodConsole`, `AppStopMethodWindow`, and `AppStopMethodThreads`: `10000` each. They are independent method waits, not a 30-second graceful window.
- `AppStopMethodSkip=0`, `AppNoConsole=0`, `AppExit 0 Exit`, and `AppExit Default Exit`.
- `AppRestartDelay=0`, `AppThrottle=5000`, delayed start, and SCM recovery reset `3600` seconds.
- First nonzero restart after `10000` ms, second after `30000` ms, then no subsequent restart; `FailureFlag=1`.

NSSM appends stdout/stderr to protected files, keeping current plus one `.old` file at 10 MiB per stream (20 MiB per stream pair). This is a size bound, not an age-retention promise. The service description contains only secret-free owner/role/operation/fingerprint/nonce/proof metadata.

### Stop and readiness

`sc.exe stop <owned-service>` requests a signal. It does not promise a graceful service-wide wall or a drain. Observe existing bot signal/registry-close/Discord-destroy evidence; for the daemon use supervisor, process-tree, exit-code, and pool evidence—do not invent a daemon marker.
The existing child behavior remains unchanged: the bot closes the host WebSocket
registry first (in-flight invokes settle and daemons observe a clean close), then
destroys the Discord client; each step is bounded by 10 seconds. The daemon
disposes its SDK session pool before exit, with the pool's existing timeouts.
These are application observations, not a supervisor drain promise.

1. Suppress automatic restart and verify the service owner, fingerprint/proof metadata, root PID/start time, executable, and descendants.
2. Record the empirical no-child signal result and then poll the owned tree for 35,000 ms as an observation deadline only.
3. Classify `signal-and-quiescence-observed` or `force-required`; never call residual work drained.
4. If force is required, revalidate the root and run only `taskkill.exe /PID <verified-root-pid> /T /F`. Never kill by image name. Re-enumerate PID/start-time pairs.
5. A failed force leaves the service disabled and a durable `manual-cleanup` state; use foreground/manual rollback.

For a start, record the UTC boundary, boot identity, stdout/stderr offsets, service fingerprint, and complete pre-start PID/start-time tree. After start, correlate the NSSM wrapper and actual child PID/start time. A marker counts only when appended after the boundary at or beyond the old offset and while the current lineage exists. Require bot listening/login plus matching host-connected evidence, or daemon registration-accepted evidence, within 60 seconds. Stale output, reused PID without start time, or service status alone is not readiness.

## Linux (systemd)

Render a bot unit and a true `gjc-remote-daemon@.service` template. The bot uses `User=gjc-bot`, an absolute Node entrypoint, component working directory, and `/etc/gjc-remote/bot.env`. The daemon uses `User=gjc-daemon`, an absolute Bun entrypoint, `/etc/gjc-remote/daemon-%i.env`, a per-instance `HOME`, and `SyslogIdentifier=gjc-remote-daemon-%i`. Render concrete instances and reject placeholders before installation.

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

These are systemd values, not NSSM semantics. `EnvironmentFile` is a separate adapter from dotenv: use `KEY=value`, no `export`, shell expansion, or command substitution, and quote spaces, quotes, backslashes, and `#` correctly. Keep env files mode 0600. Verify the template and each concrete unit with `systemd-analyze verify`; current invocation, boot ID, cgroup, `MainPID`, start timestamp, and exact host registration/connection evidence are required within a 60-second boundary. `active (running)` alone fails.

The normal install consumes host-policy journald. Query unit-scoped records and retain the host policy; do not create or edit a global drop-in. Any host-global journald change needs separate written approval, baseline/diff, owned rollback, and evidence, and must not be implied by this runbook.

## Transactions, recovery, and manual cleanup

Use per-service ACL/mode-protected storage (`C:\ProgramData\\gjc-remote\\transactions` or `/var/lib/gjc-remote/transactions`, mode 0700). Before every install/update/remove mutation:

1. Acquire the per-key lock and generate a unique CSPRNG 128-bit `txNonce` (32 lower-case hex characters). Never reuse it.
2. Compute a versioned, canonical SHA-256 `resourceProof` over secret-free transaction/resource fields.
3. Persist the envelope in the journal and staged manifest/tombstone before mutation, and in service/unit metadata after publication.
4. Recompute and compare all copies after every mutation. Only an exact three-way match (journal, manifest/tombstone, queried resource) proves ownership.

Recovery is symmetric and idempotent: install commits only after metadata, manifest, and current-run readiness; update retains old/new proofs and restores old settings only with an exact old proof; remove uses a proof-bound tombstone and removes only after no-process evidence. Env files, provider credentials, logs, and `.gjc-remote-session` are never cleanup targets.

Any missing, malformed, stale, mismatched, hybrid, foreign, or recreated resource is **`manual-cleanup`**. This includes a stale journal followed by same-name recreation with the same owner/fingerprint but a different, missing, or malformed nonce/proof. Write a sanitized record with transaction key, phase, expected/observed non-secret metadata, reason, timestamp, and exact operator action; block new mutation for that key and leave the resource untouched until an operator resolves it. Never recover by service name alone.

Fault-injection evidence is mandatory after every install/update/remove boundary, including prepared/staged state, service creation, metadata publication, settings verification, manifest rename, start/readiness, commit, disable/stop/quiescence, removal, and marker publication. Repeat malformed, foreign, and stale/recreated-service fixtures. Seed sentinel env, provider-store, log, and `.gjc-remote-session` files and prove byte-preserving survival. Missing evidence stops release.

## Rotation, rollback, and loss

For startup-only host-token rotation:

1. Save a protected old value without printing it.
2. Stop the daemon and confirm no old connection.
3. Update/restart the bot; require current readiness.
4. Update/restart the daemon; require registration and matching host-connected evidence.
5. Use two 60-second readiness deadlines (120 seconds total). On failure, restore the protected value in reverse order and verify old-token rejection without logging values.

`GJC_BOT_ALLOWED_USERS`, `GJC_REMOTE_REQUIRE_ALLOWLIST`, and token settings are startup-only; restart the relevant component. `channels.json` remains hot-reloaded and an invalid replacement keeps the last valid map. Planned or forced stop may fail pending invokes and gates. That is bounded loss/failure evidence, not a drain, migration, or recovery claim.

## Evidence and escalation

The required evidence set is static contract coverage, pinned Shawl source/release
and executable-hash evidence for the Windows evaluation path, disposable Windows
stop/readiness/restart/account/ACL tests, pinned Ubuntu systemd
template/readiness/journald tests, relay registration evidence,
rotation/rollback, transaction fault injection, and sentinel scans. NSSM
archive/executable hashes apply only to the legacy fallback. Redact secrets,
prompts, local credential paths, and private tokens from every artifact.

Platform evidence is pending. Escalate rather than waive any provenance mismatch, active-child survival, ambiguous ownership, missing manual-cleanup record, stale readiness marker, journald global mutation, secret hit, or missing fault boundary. Option A foreground commands remain the safe rollback.

## References

- [NSSM usage](https://nssm.cc/usage) and [NSSM commands](https://nssm.cc/commands)
- [Shawl repository and releases](https://github.com/mtkennerly/shawl/releases)
- [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) and [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
- [journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html)
- [Node signal events](https://nodejs.org/api/process.html#signal-events)
- Repository contracts: `shared/protocol.js`, `bot/src/shutdown.js`, `bot/.env.example`, `daemon/.env.example`
