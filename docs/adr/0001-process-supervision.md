# ADR 0001: Process supervision

- **Status:** Revised design; Linux approved, Windows evaluation in progress
- **Date:** 2026-08-01
- **Scope:** This ADR records the supervision decision and its operational documentation. The coordinated SDK pin update is separately verified in this PR; it does not authorize product-source, protocol, or lockfile changes beyond that dependency update.

## Context

`bot/` is a Node process and `daemon/` is a Bun process (`>=1.3.14`) that embeds the GJC SDK. Neither process daemonizes itself. A bot host needs one long-lived bot process; each remote host needs one outbound daemon process. A supervisor must restart an unexpected exit without changing relay, reconnect, shutdown, or session-pool behavior.

The design must not turn a service name into a host identity, leak credentials into service metadata, claim a drain that the application cannot guarantee, or silently modify host-global logging policy.

## Decision

Use native systemd units as the Linux service path. Use Shawl v1.9.0 as the current Windows evaluation/interim adapter, not as the production primary: its distributed win64 binary is unsigned. The production-primary Windows design is a future first-party signed service wrapper registered through the Windows SCM. Keep foreground/manual operation as the universal rollback and retain NSSM only as a legacy fallback candidate.

Do not register Bun or Node directly with `sc.exe`; they do not implement the Windows Service Control API. `sc.exe` is the registration/control layer, not a process wrapper. A first-party wrapper requires a separate ADR or explicit revision of this decision.

### Windows: Shawl evaluation adapter

The current Windows evaluation path stages Shawl v1.9.0 at a protected
`C:\ProgramData\gjc-remote\shawl\shawl.exe` location, records the executable
SHA-256, and invokes Bun/Node through absolute paths. Secrets remain in the
component-local `.env` and never enter Shawl arguments, service metadata, or logs.

Local functional evidence covers:

- daemon child termination followed by a replacement child;
- bot child termination followed by a replacement child;
- daemon reconnect and `registration accepted` after bot recovery; and
- graceful stop without an unwanted restart.

The tested binary was unsigned, so this evidence does not establish production
artifact provenance. Production adoption also requires source/release
attestation, least-privilege account and ACL verification, current-run
readiness, transaction ownership/recovery, and disposable-host evidence.

### Windows: first-party primary wrapper (future)

The production primary should be a small signed Windows service wrapper. It must
report service state, launch Bun/Node, use a Windows Job Object for the process
tree, propagate stop, enforce a bounded force-kill deadline, and preserve
exit-code/restart semantics. The wrapper and its signing/provenance policy need
their own implementation plan and review.

### Windows: NSSM legacy fallback

The existing NSSM scripts and receipt remain a legacy fallback candidate only.
They are not the recommended Windows path. The installer contract has known
provenance, ACL, process-tree, readiness, and recovery gaps and must not be used
for production until separately redesigned and re-reviewed.

The target topology is exactly:

- one `GJCRemoteBot` service on the bot host; and
- one `GJCRemoteDaemon-<instance-key>` service per exact valid `HOST_ID`.

Channels, work directories, Discord servers, and provider profiles do not create services. The instance key is a display slug (ASCII, lower-case, at most 32 characters) plus the lower-case SHA-256 of the exact `HOST_ID` UTF-8 bytes. The exact, case-sensitive `HOST_ID` remains in protected configuration only. Validation follows `shared/protocol.js`: non-empty, at most 128 UTF-16 code units, and no unpaired surrogates, Unicode controls, bidi/format controls, U+2028, or U+2029. Do not trim, normalize, or case-fold the wire ID.

### Legacy NSSM contract details (not primary)

Use only the operator-supplied NSSM `2.24-101-g897c7ad` win64 archive from:

`https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip`

The authoritative receipt is:

- archive SHA-256: `99f5045fffbffb745d67fe3a065a953c4a3d9c253b868892d9b685b0ee7d07b8`;
- official build SHA-1: `ca2f6782a05af85facf9b620e047b01271edd11d`; and
- extracted `win64\\nssm.exe` SHA-256: `eee9c44c29c2be011f1f1e43bb8c3fca888cb81053022ec5a0060035de16d848`.

The archive and executable values must each be exactly 64 lower-case hexadecimal characters; the build value must be exactly 40. Installation must hash the actual operator-supplied ZIP and extracted executable with `Get-FileHash -Algorithm SHA256` (or an independently recorded equivalent), compare both observations with the receipt, and retain sanitized source/version/path/tool/result evidence. A copied receipt is not provenance. NSSM is never downloaded automatically, bundled, or committed.

Services use absolute Node/Bun and application paths, the component directory as `AppDirectory`, delayed automatic start, own-process service type, and an explicit least-privilege account (`gjc-bot-svc` or `gjc-daemon-svc`; never `LocalSystem` for the daemon). Credentials are entered through a protected API or prompt, never a command line. Provider login and profile setup happen as that account. The component-local `.env` is loaded by the existing `dotenv/config`; arbitrary dotenv paths and `DOTENV_CONFIG_PATH` are rejected. Extra environment values may contain only non-secret profile paths and `GJC_REMOTE_DEBUG=0`; Discord, host, provider, token, and credential URL values are not service metadata. `BOT_WS_URL` must not contain userinfo, query, or fragment data.

The service description contains only secret-free ownership metadata (`owner`, role, operation, configuration fingerprint, transaction nonce, and proof). ACLs protect the account profile, `.gjc`, work-directory session data, env/channels files, manifests, journals, and logs; inherited `Users`/`Everyone` access is removed. NSSM output is append-only, retains current plus one `.old` file, and caps each stream at 10 MiB (20 MiB per stream pair); no age-retention promise is made. Debug logging stays off.

Query, do not assume, these NSSM settings:

- `AppStopMethodConsole=10000`, `AppStopMethodWindow=10000`, and `AppStopMethodThreads=10000` (three independent waits, not a 30-second grace period);
- `AppStopMethodSkip=0`, `AppNoConsole=0`, and `AppExit 0 Exit` / `AppExit Default Exit`;
- `AppRestartDelay=0`, `AppThrottle=5000`, and delayed start; and
- SCM recovery reset 3600 seconds, first nonzero restart after 10 seconds, second after 30 seconds, then no further restart (`FailureFlag=1`).

Clean or intentional stop must not be treated as a crash. SCM recovery is separate from the daemon's 1–30 second reconnect jitter.

#### Honest stop semantics

`sc.exe stop <owned-service>` is a best-effort signal request, not a drain guarantee. Observe the NSSM/application tree and existing bot signal/teardown evidence. Do not invent a daemon shutdown marker. Require an empirical no-child result within the configured probe threshold, then poll the owned tree for 35,000 ms as an observation deadline only. Record `signal-and-quiescence-observed` or `force-required`; never call a residual tree graceful or drained.

Before forcing, suppress restart and revalidate owner, service metadata/proof, root PID/start time, executable path, and descendants. Force only a verified root with `taskkill.exe /PID <pid> /T /F`; never kill by image name. Re-enumerate residual PID/start-time pairs. Failed force cleanup disables the service and leaves an explicit `manual-cleanup` record. Unsafe active-child evidence stops unattended NSSM use and falls back to foreground/manual supervision or a new ADR.

### Linux: systemd

Check in and render two units: `gjc-remote-bot.service.in` and the true instance template `gjc-remote-daemon@.service.in`. The bot uses `User=gjc-bot`, its component directory, an absolute Node entrypoint, and `/etc/gjc-remote/bot.env`. The daemon uses `User=gjc-daemon`, an absolute Bun entrypoint, `/etc/gjc-remote/daemon-%i.env`, per-instance `HOME`, and `SyslogIdentifier=gjc-remote-daemon-%i`. Rendered paths, users, and instance keys contain no placeholders.

Both units use network-online ordering, `Restart=on-failure`, `RestartSec=10s`, `StartLimitIntervalSec=600s`, `StartLimitBurst=5`, `KillSignal=SIGTERM`, `KillMode=control-group`, `TimeoutStopSec=35s`, and `UMask=0077`. These are systemd settings and must not be represented as NSSM guarantees. Render systemd `EnvironmentFile` separately from dotenv (`KEY=value`, no `export`, shell expansion, or command substitution); quote spaces, quotes, backslashes, and `#` correctly. Env files are mode 0600 and contain only the intended startup values.

The default installation consumes the host's journald storage and retention policy. It does not create or edit global journald configuration and makes no per-unit retention/capacity claim. Unit-scoped queries and the host policy are recorded as evidence. A host-global drop-in is a separate, written-approval operation with baseline, diff, owned rollback, and evidence.

### Current-run readiness

Readiness is a current-run property, not `active (running)` or a stale log line. Windows records a UTC boundary, boot identity, stdout/stderr offsets, service fingerprint, and complete PID/start-time snapshot before start. After start, query the service PID, descendants, executable paths, and creation/start times; markers count only when appended after the boundary at or beyond the prior offsets and while the current PID lineage exists. The bot requires current listening/login plus matching host-connected evidence; the daemon requires current registration-accepted evidence, within 60 seconds. Linux correlates JSON journal records to the current `InvocationID`, boot ID, unit/cgroup, PID, and start timestamp, then requires exact host registration/connection evidence within the same 60-second boundary. PID reuse without start time, stale markers, and status alone fail.

### Transaction ownership and recovery

Install, update, and remove use an ACL/mode-protected per-service transaction store (`C:\ProgramData\\gjc-remote\\transactions` on Windows; `/var/lib/gjc-remote/transactions` mode 0700 on Linux). Before mutation, acquire the per-key lock, generate a unique CSPRNG 128-bit `txNonce` (32 lower-case hex characters), and compute a versioned SHA-256 `resourceProof` over canonical, secret-free transaction/resource fields. Never reuse a nonce.

The journal, staged/owned manifest (or remove tombstone), and service/unit metadata all carry the transaction envelope: transaction ID, operation, role, owner, configuration fingerprint, nonce, and proof. Resource metadata contains no host ID, env, credential, prompt, token, or log content. Recovery mutates a resource only after independently recomputed, exact agreement among all three copies. Name, owner, role, fingerprint, PID, timestamp, or service state alone is insufficient.

Any missing, malformed, stale, mismatched, or hybrid copy enters durable `manual-cleanup`, records only sanitized metadata and the exact operator action, blocks new mutation for that key, and refuses automatic stop/remove/restore. A stale journal followed by same-name recreation—even with the same owner and fingerprint but a new or missing marker—must leave the recreated resource untouched. Recovery and all rollback paths preserve env files, provider credentials, logs, and `.gjc-remote-session` data.

Install publishes prepared journal and staged manifest before service creation, verifies resource metadata before committing the manifest, and marks committed only after current-run readiness. Update retains old and new proofs and restores old settings only on an exact old-proof match. Remove writes a tombstone, disables recovery, stops/quiesces, and removes the resource only after proof and no-process checks. Every mutation boundary is fault-injected, including marker publication and stale/recreated-service races; missing evidence is a release stop.

### Rotation, rollback, and loss

Host-token rotation is ordered: protected old backup; stop the daemon and confirm no old connection; update/restart bot and current readiness; update/restart daemon and registration plus matching host-connected evidence. Allow two 60-second readiness deadlines (120 seconds total) and reverse the order on failure without printing token values. Startup-only authorization and token settings require restart; `channels.json` remains hot-reloadable and invalid reloads keep the last valid map. Pending invokes/gates may fail during planned or forced stop. No supervisor claims work draining or state migration.

## Boundaries and evidence

Out of scope are product source edits, protocol/SDK/reconnect/shutdown/session-pool changes, package or lockfile changes, PM2/Docker/Kubernetes deployment, SSH or inbound daemon listeners, per-command processes, automatic secret mutation, runtime supervisors, silent NSSM-to-WinSW/native substitution, and silent journald policy changes. Existing foreground commands remain rollback:

```text
bot/:    node src/bot.js
daemon/: bun src/daemon.js   # Bun >= 1.3.14
```

Platform evidence is **pending**. This documentation-only change does not prove NSSM byte provenance, Windows stop/readiness, Linux boot/readiness, relay behavior, transaction fault injection, rotation, or secret scans. Release requires static contracts, authoritative archive/executable hashes, disposable Windows and pinned Ubuntu systemd evidence, current-run relay evidence, fault-injection matrices, and sanitized artifacts. Missing evidence escalates; it is not waived.

## References

- NSSM usage and service parameters: <https://nssm.cc/usage>, <https://nssm.cc/commands>
- NSSM downloads/build provenance: <https://nssm.cc/download>
- systemd service units and restart behavior: <https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html>
- systemd template instances/specifiers: <https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html>
- journald host policy: <https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html>
- Node signal handling: <https://nodejs.org/api/process.html#signal-events>
- Repository child entrypoints and environment examples: `bot/package.json`, `daemon/package.json`, `bot/.env.example`, `daemon/.env.example`.
