# ADR 0001: Process supervision

- **Status:** Revised design; Linux approved; Windows Shawl selected as the primary supervisor with `sc.exe` documented as the fallback; NSSM discarded
- **Date:** 2026-08-01
- **Amendment (2026-08-08):** The NSSM-based Windows supervision path recorded in the original decision is discarded. It was never merged into this repository — its install/update/remove/recovery scripts and supervision-contract test lived only in an untracked `ops/` tree that has since been archived outside the repository and deleted — and the operator selected a different Windows mechanism. No NSSM implementation exists anywhere in this repository. See "Windows: NSSM (discarded)" below. This amendment also supersedes this ADR's original prohibition on registering Bun or Node directly with `sc.exe` (they do not implement the Windows Service Control API); the Decision section below now names `sc.exe` as the documented Windows fallback and accepts, as the named cost of that reversal, that a directly registered service cannot acknowledge `SERVICE_CONTROL_STOP` and that its automatic restart is limited to the fixed, jitter-free `sc failure` recovery-action contract.
- **Scope:** This ADR records the supervision decision and its operational documentation. The coordinated SDK pin update is separately verified in this PR; it does not authorize product-source, protocol, or lockfile changes beyond that dependency update.

## Context

`bot/` is a Node process and `daemon/` is a Bun process (`>=1.3.14`) that embeds the GJC SDK. Neither process daemonizes itself. A bot host needs one long-lived bot process; each remote host needs one outbound daemon process. A supervisor must restart an unexpected exit without changing relay, reconnect, shutdown, or session-pool behavior.

The design must not turn a service name into a host identity, leak credentials into service metadata, claim a drain that the application cannot guarantee, or silently modify host-global logging policy.

## Decision

Use native systemd units as the Linux service path (contract below; the `.service.in` templates are not yet checked into this repository — see "Linux: systemd"). Use Shawl v1.9.0 as the selected primary Windows supervisor, not merely an evaluation adapter: its distributed win64 binary is unsigned, so signed provenance remains a required, still-open release-owner item, and every existing unsigned-binary caveat in this document continues to apply. Use direct `sc.exe` service registration as the named Windows fallback when Shawl is unsuitable, accepting a known cost: Bun and Node do not implement the Windows Service Control API, so a directly registered service cannot acknowledge `SERVICE_CONTROL_STOP` (the SCM instead force-ends the process tree after its own stop timeout), and automatic restart is limited to whatever `sc failure <service> actions=...` recovery-action flags provide — a fixed list with no jitter/backoff shaping and no coordination with the application's own reconnect/shutdown timers. That restart/backoff contract must be separately implemented (a thin wrapper) or explicitly accepted as absent before relying on the fallback in production. The production-primary design remains open to a future first-party signed service wrapper registered through the Windows SCM. Keep foreground/manual operation as the universal rollback. The NSSM-based approach evaluated for this ADR is discarded (see "Windows: NSSM (discarded)"); no NSSM implementation exists in this repository.

`sc.exe` is the registration/control layer for the fallback above, not a process wrapper; a directly registered Bun/Node service is the degraded contract described above, not equivalent to a service-aware wrapper. A first-party signed wrapper requires a separate ADR or explicit revision of this decision.

### Windows: Shawl (selected primary; unsigned-binary evaluation evidence)

The selected Windows primary stages Shawl v1.9.0 at a protected
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

### Windows: target topology and instance identity

The target topology below is mechanism-neutral and applies to whichever Windows supervisor (Shawl or `sc.exe`) is actually configured.

The target topology is exactly:

- one `GJCRemoteBot` service on the bot host; and
- one `GJCRemoteDaemon-<instance-key>` service per exact valid `HOST_ID`.

Channels, work directories, Discord servers, and provider profiles do not create services. The instance key is a display slug (ASCII, lower-case, at most 32 characters) plus the lower-case SHA-256 of the exact `HOST_ID` UTF-8 bytes. The exact, case-sensitive `HOST_ID` remains in protected configuration only. Validation follows `shared/protocol.js`: non-empty, at most 128 UTF-16 code units, and no unpaired surrogates, Unicode controls, bidi/format controls, U+2028, or U+2029. Do not trim, normalize, or case-fold the wire ID.

### Windows: NSSM (discarded)

**Decision (2026-08-08):** The NSSM-based Windows supervision path is discarded. It was evaluated and documented in earlier drafts of this ADR, but the implementation (NSSM install/update/remove/recovery PowerShell scripts and the accompanying supervision-contract test) was never merged into this repository — it lived only in an untracked `ops/` tree that has since been archived outside the repository and deleted. No NSSM implementation, script, or test exists anywhere in this repository. The operator selected Shawl as the primary Windows supervisor with `sc.exe` as the documented fallback (see "Decision" above, "Windows: Shawl (selected primary; unsigned-binary evaluation evidence)", and "Windows: sc.exe fallback" below) instead of resuming NSSM work. Do not reintroduce NSSM without a new ADR.

### Windows: sc.exe fallback (not yet implemented)

This section is the contract that any direct `sc.exe` registration of the bot or daemon must satisfy before it is used in production. Nothing below is implemented yet; there is no install/update/remove script for this path in the repository.

Register exactly `GJCRemoteBot` or one `GJCRemoteDaemon-<instance-key>` with `sc.exe create`, using absolute Node/Bun and application paths, the component directory as the working directory, and an explicit least-privilege service account (`gjc-bot-svc` or `gjc-daemon-svc`; never `LocalSystem` for the daemon). Credentials are entered through a protected API or prompt, never a command line. The component-local `.env` is loaded by the existing `dotenv/config`; arbitrary dotenv paths and `DOTENV_CONFIG_PATH` are rejected. Extra environment values may contain only non-secret profile paths and `GJC_REMOTE_DEBUG=0`.

The service description must contain only secret-free ownership metadata (`owner`, role, operation, configuration fingerprint, transaction nonce, and proof). ACLs must protect the account profile, `.gjc`, work-directory session data, env/channels files, manifests, journals, and logs; inherited `Users`/`Everyone` access must be removed.

Configure restart behavior with `sc failure <service> reset= <seconds> actions= restart/<delay>/restart/<delay>/.../""`. This is the entire restart contract available to this fallback: a fixed action list with no jitter, no distinction between clean and crash exit, and no coordination with the application's own reconnect/shutdown timers. If that is insufficient, either implement a thin wrapper that reports service state and shapes restart behavior, or explicitly accept the bare `sc failure` behavior (or none) as the production contract.

#### Honest stop semantics

`sc.exe stop <owned-service>` is a best-effort control-code request, not a drain guarantee. Because Bun and Node do not implement the Windows Service Control API, the process cannot acknowledge `SERVICE_CONTROL_STOP`; the SCM reports the service stopped once its own stop timeout elapses and forcibly ends the process tree, regardless of in-flight work. Observe the existing bot signal/teardown evidence rather than inventing a shutdown marker. Require an empirical no-child result within the configured probe threshold, then poll the owned tree for 35,000 ms as an observation deadline only. Record `signal-and-quiescence-observed` or `force-required`; never call a residual tree graceful or drained.

Before forcing, suppress restart and revalidate owner, service metadata/proof, root PID/start time, executable path, and descendants. Force only a verified root with `taskkill.exe /PID <pid> /T /F`; never kill by image name. Re-enumerate residual PID/start-time pairs. Failed force cleanup disables the service and leaves an explicit `manual-cleanup` record. Unsafe active-child evidence stops unattended `sc.exe` fallback use and falls back to foreground/manual supervision or a new ADR.

### Linux: systemd

Check in and render two units: `gjc-remote-bot.service.in` and the true instance template `gjc-remote-daemon@.service.in`. **These `.service.in` templates are not currently checked into this repository.** Like the discarded NSSM scripts, they previously lived only in an untracked `ops/` tree that has been archived outside the repository and deleted. This is the contract they must satisfy once they are added and checked in: the bot uses `User=gjc-bot`, its component directory, an absolute Node entrypoint, and `/etc/gjc-remote/bot.env`. The daemon uses `User=gjc-daemon`, an absolute Bun entrypoint, `/etc/gjc-remote/daemon-%i.env`, per-instance `HOME`, and `SyslogIdentifier=gjc-remote-daemon-%i`. Rendered paths, users, and instance keys must contain no placeholders.

Both units use network-online ordering, `Restart=on-failure`, `RestartSec=10s`, `StartLimitIntervalSec=600s`, `StartLimitBurst=5`, `KillSignal=SIGTERM`, `KillMode=control-group`, `TimeoutStopSec=35s`, and `UMask=0077`. These are systemd settings and must not be represented as Shawl or `sc.exe` guarantees, or vice versa. Render systemd `EnvironmentFile` separately from dotenv (`KEY=value`, no `export`, shell expansion, or command substitution); quote spaces, quotes, backslashes, and `#` correctly. Env files are mode 0600 and contain only the intended startup values.

The default installation consumes the host's journald storage and retention policy. It does not create or edit global journald configuration and makes no per-unit retention/capacity claim. Unit-scoped queries and the host policy are recorded as evidence. A host-global drop-in is a separate, written-approval operation with baseline, diff, owned rollback, and evidence.

### Current-run readiness

Readiness is a current-run property, not `active (running)` or a stale log line. Windows records a UTC boundary, boot identity, stdout/stderr offsets, service fingerprint, and complete PID/start-time snapshot before start. After start, query the service PID, descendants, executable paths, and creation/start times; markers count only when appended after the boundary at or beyond the prior offsets and while the current PID lineage exists. The bot requires current listening/login plus matching host-connected evidence; the daemon requires current registration-accepted evidence, within 60 seconds. Linux correlates JSON journal records to the current `InvocationID`, boot ID, unit/cgroup, PID, and start timestamp, then requires exact host registration/connection evidence within the same 60-second boundary. PID reuse without start time, stale markers, and status alone fail.

### Transaction ownership and recovery

**No implementation of this transaction/journal/fault-injection protocol exists anywhere in this repository.** What follows is the contract a future implementation must satisfy before it may be used in production.

Install, update, and remove must use an ACL/mode-protected per-service transaction store (`C:\ProgramData\\gjc-remote\\transactions` on Windows; `/var/lib/gjc-remote/transactions` mode 0700 on Linux). Before mutation, it must acquire the per-key lock, generate a unique CSPRNG 128-bit `txNonce` (32 lower-case hex characters), and compute a versioned SHA-256 `resourceProof` over canonical, secret-free transaction/resource fields. It must never reuse a nonce.

The journal, staged/owned manifest (or remove tombstone), and service/unit metadata must all carry the transaction envelope: transaction ID, operation, role, owner, configuration fingerprint, nonce, and proof. Resource metadata must contain no host ID, env, credential, prompt, token, or log content. Recovery must mutate a resource only after independently recomputed, exact agreement among all three copies. Name, owner, role, fingerprint, PID, timestamp, or service state alone must not be sufficient.

Any missing, malformed, stale, mismatched, or hybrid copy must enter durable `manual-cleanup`, record only sanitized metadata and the exact operator action, block new mutation for that key, and refuse automatic stop/remove/restore. A stale journal followed by same-name recreation—even with the same owner and fingerprint but a new or missing marker—must leave the recreated resource untouched. Recovery and all rollback paths must preserve env files, provider credentials, logs, and `.gjc-remote-session` data.

Install must publish prepared journal and staged manifest before service creation, verify resource metadata before committing the manifest, and mark committed only after current-run readiness. Update must retain old and new proofs and restore old settings only on an exact old-proof match. Remove must write a tombstone, disable recovery, stop/quiesce, and remove the resource only after proof and no-process checks. Every mutation boundary must be fault-injected, including marker publication and stale/recreated-service races; missing evidence must be treated as a release stop.

### Rotation, rollback, and loss

Host-token rotation is ordered: protected old backup; stop the daemon and confirm no old connection; update/restart bot and current readiness; update/restart daemon and registration plus matching host-connected evidence. Allow two 60-second readiness deadlines (120 seconds total) and reverse the order on failure without printing token values. Startup-only authorization and token settings require restart; `channels.json` remains hot-reloadable and invalid reloads keep the last valid map. Pending invokes/gates may fail during planned or forced stop. No supervisor claims work draining or state migration.

## Boundaries and evidence

Out of scope are product source edits, protocol/SDK/reconnect/shutdown/session-pool changes, package or lockfile changes, PM2/Docker/Kubernetes deployment, SSH or inbound daemon listeners, per-command processes, automatic secret mutation, runtime supervisors, silent substitution of the selected Windows supervisor (Shawl or `sc.exe`) without a documented decision, and silent journald policy changes. Existing foreground commands remain rollback:

```text
bot/:    node src/bot.js
daemon/: bun src/daemon.js   # Bun >= 1.3.14
```

Platform evidence is **pending**. This documentation-only change does not prove Shawl byte provenance, Windows stop/readiness, Linux boot/readiness, relay behavior, transaction fault injection, rotation, or secret scans. Release requires pinned Shawl source/release and executable-hash evidence for the Windows primary path, disposable Windows and pinned Ubuntu systemd evidence, current-run relay evidence, fault-injection matrices, and sanitized artifacts. Missing evidence escalates; it is not waived.

## References

- Shawl repository and releases: <https://github.com/mtkennerly/shawl/releases>
- `sc.exe` service control reference: <https://learn.microsoft.com/windows-server/administration/windows-commands/sc-create>, <https://learn.microsoft.com/windows-server/administration/windows-commands/sc-failure>
- systemd service units and restart behavior: <https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html>
- systemd template instances/specifiers: <https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html>
- journald host policy: <https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html>
- Node signal handling: <https://nodejs.org/api/process.html#signal-events>
- Repository child entrypoints and environment examples: `bot/package.json`, `daemon/package.json`, `bot/.env.example`, `daemon/.env.example`.
