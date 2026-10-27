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

## Current SDK-only 0.19.0 source boundary

Current source uses the official unpatched SDK 0.19.0. Its evidence is tracked
in the [current SDK-only 0.19.0 evidence record](../../daemon-workspace-verification.md#current-sdk-only-0190-evidence)
and records Windows focused 265/265, unrestricted workspace 2739 pass/zero fail/10
skips, canonical imports, and one newly authorized same-profile provider smoke.
Historical 0.18.12 receipts, PR #265 and signed/prepared release records below do
not qualify 0.19.0. Review/CI/landing are tracked separately; no signed-release,
installation or deployment PASS is claimed here.

Active `steer` and `follow_up` remain fail-closed. Active cancellation remains
nonterminal `cancellation_pending`, not interruption proof; aggregate oracle
success does not establish standalone SDK abort support. Upstream #6578 is
closed and #6700 is closed unmerged. Repair #6970 is included in the official
0.19.0 release notes, not a local workflow-gate PASS. #6763's approval binding
is a separate change; do not bypass containment.

The existing uninstall generation/schema defect is tracked separately in
[repository issue #273](https://github.com/kogangdon/gjc-remote/issues/273)
and is excluded from this SDK upgrade. The SDK source change does not authorize
rebuilding, signing, or installing under an immutable old release tag.

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

The native state base is `\gjc-remote` on the Windows installation drive,
normally `C:\gjc-remote`, independently of the CLI's location and the component
working directory. The OS-derived location is not configurable through
environment variables. Service state uses `service-control`, `staging`,
`releases`, and `supervisors\shawl`; inventory uses the separate
`native\<host-key>` and daemon-reader `native-reader\<host-key>` subtrees.
Before inventory operations, the canonical witnessed platform container must
already exist. Unreleased native-control 2.1.0 (contract 5 revision 3) adds
`gjc-remote-inventory provision-bases`: an explicit management-only operation,
with exact `{}` standard input and `GJC_INVENTORY_ROLE_BINDINGS`, to create its
absent `native` and `native-reader` parents. It accepts no path override,
preserves the container and witness, and establishes exact protected ACLs with
M and D ownership respectively. Existing objects are never adopted or repaired;
retain partial-failure receipts instead of retrying blindly. Publisher and
reader host leaves still require their actual M and D actors, and normal
publisher/reader construction never provisions the parents. This new command
is not in signed rc.10. There is no ProgramData fallback or
migration for inventory state. Existing ProgramData service state is likewise
not migrated or used as a fallback; preserve it for operator review rather than
copying its identity-bound records into the new store. PR #259 (source commit
`91fe87f7baa5b8da9e501f1f74f77ee7385bab76`) moved Windows inventory and
daemon-reader storage into the same OS-derived `\gjc-remote` tree as service
state. The layout is present in published and deployed rc.8; published rc.7
remains immutable and continues using ProgramData for inventory/native-reader
state. rc.9 was deployed; its CLI and SDK archive contents matched the signed
release, application signatures were verified, and protected ACLs were
verified. The canonical Windows SCM install was refused before journal
creation with `SERVICE_INVALID` and zero writes because the JS driver rejected
valid opaque native lock handles. No SCM mutation occurred, and no service was
installed or qualified. Published rc.10 removes the
unnecessary JS driver lock-handle input and shape check;
authority validation and lock lifetime remain at the existing native/session
boundary. It also projects the already-exported `read_win32_boot_clock`
capability through the `serviceNative` role facade without adding a native ABI
capability, and fixes native observation-directory EOF handling so complete
enumeration reaches canonical ordering for ordinary mixed-case SDK directories.
Read-only Windows launch planning accepts the future signed artifact locations
before publication. Service creation and launch changes still require the
published bytes and exact ACLs. Runtime, configuration, log, and SDK security
checks remain mandatory during planning; invalid pre-existing runtime
permissions are not repaired or relaxed automatically.
Published rc.10 came from immutable tag source
`56de3e3eb77530fe5380b02870e2ad087412ea6a`; deployment and foreground bot
readiness were verified. Canonical service installation then refused with zero
writes because SDK compatibility listing hashing exceeded the generic JSON
node bound. Signed/live rc.10 remains immutable with native-control 2.0.0
(contract 5 revision 1) and SDK 0.16.7, as do all existing rc.1 through rc.10
assets. The historical rc.14 preparation selected application `0.4.0-rc.14`, tag
`v0.4.0-rc.14`, and release sequence 14, with native-control 2.1.0 (contract 5
revision 3), unchanged N-API 8, official unpatched SDK 0.18.12, and Bun 1.4.2. It included PR #269
(merge `ec64e073`): the Windows service creation-accounting repair, and PR #270
(merge `fbe8ccd5`): owned Win32 lineage scopes with fail-closed receipts. This
preparation record is not authorization to publish, sign, install, or deploy
SDK 0.19.0 under `v0.4.0-rc.14`; historical prepared or signed bytes and their
application, sequence, Bun, and native identities remain unchanged.

Published rc.11 remains immutable at `116b60caf0ce6361eb3f17d1b9cf3a17e22e92cb`.
Signed local rc.12 remains immutable at `6af3ef0b480a38da502d8d2ca1cc5c15dbe9b3ae`.
Local rc.13 remains immutable at `87a4d969acac674d620e3b44cdd7f7b010a26817`; the
distinct rc.13 candidate included PR #267's installation-contract repairs
at `24079e3c`. Its local tag followed independent source review, required
exact-head CI and the verified main merge; never move rc.13/rc.12/rc.11 or push a release
tag as part of local reinstall preparation. Signed native compatibility,
application signing custody, preservation and fresh per-operation floor/CAS/UAC
admission remain separate gates. A read-only lock refusal is not evidence of a
pending transaction and never authorizes recovery or uninstall. Genuinely
absent services use fresh install without an artificial uninstall; an owned or
tombstoned service needs a proven supported fresh-install and failure route
before any removal. Neither an unsigned build nor local fixture smoke proves
canonical installation or provider/remote E2E.

### Historical SDK-only 0.18.12 evidence

The following receipts and PR #265 are historical and do not qualify 0.19.0.
Post-admission parent-run main-based 0.18.12 SDK-only verification records Windows focused **333/333
passed**, zero skips, and bounded workspace **2704 tests: 2700 passed, 0 failed,
4 skipped**, under the [nine explicit historical authority exclusions](../README.md#historical-sdk-only-01812-evidence).
Those exclusions are not represented by just four skips; skips are not passes.
Actual isolated credentialless Linux verification passed **248/248** without
provider calls. One separately authorized native Windows provider smoke
**passed**, using the existing `codex-eco` runtime-only child override: three
exact A-B-A `SMOKE_OK` responses, heartbeat, three successful invoke terminals,
exit 0, and ephemeral relay port free. No optional model query, wrapper retry,
or wrapper persistent profile write occurred. This is same-profile basic
continuity, not isolation or a proven #247 disconnect fix.
The smoke was not repeated after the historical fixture/test-only changes;
SDK runtime/package/lock were unchanged within that 0.18.12 verification.
Historical local runtime receipts are
`artifacts/sdk-first-0.18.12-admission2-focused.json`,
`artifacts/sdk-first-0.18.12-admission2-workspace.json`, and
`artifacts/sdk-first-0.18.12-admission2-wsl-final.json`; see the
[historical SDK-only evidence record](../README.md#historical-sdk-only-01812-evidence).

Main native code was freshly built unchanged. Separate native lifetime, ACL,
publication, construction, and fixture repairs were deferred; no private
native fixture or combined-worktree result qualified that tree. No service,
account, ACL, mapping, installed asset, or signed release was changed. Local
receipts alone do not approve landing. Independent review and exact-head
CI/landing are separate: `artifacts/sdk-first-0.18.12-final-review.json` records
static agent review APPROVE, zero P0/P1/P2, clearing both original P2s and
owner-admission, not independent runtime or CI/merge/deployment approval.
The historical 0.18.12 landing reference is [PR #265](https://github.com/kogangdon/gjc-remote/pull/265),
not current 0.19.0 evidence;
each run qualifies only its exact pins.
Native/service/security/fault/OOM/noDump, signed deployment, installation,
production, release, and support qualification remain excluded.

### Historical inventory-base CI evidence

Isolated CI run [37167043415](https://github.com/kogangdon/gjc-remote/actions/runs/37167043415)
and main CI run [37167663638](https://github.com/kogangdon/gjc-remote/actions/runs/37167663638)
qualified the source inventory-base operation on disposable GitHub-hosted
Windows VMs: four writes, exactly four explicit ACEs per parent with M/D
ownership, native directory flush, unchanged container/witness, and duplicate
refusal with zero writes. The three standard CI users for bot, recovery, and
daemon are authorized only on those disposable VMs, not for local E2E opt-in or
production account creation. This does not establish production M/D flush,
deployment, SCM installation/startup, mapping authority, reboot, power-loss
durability, or provider health. Publication and foreground bot readiness are
also not SCM or native-flush qualification.

The new root must pass the same ownership, ACL, no-reparse and NTFS directory
flush checks. A successful directory-flush probe is not evidence of successful
service installation or power-loss durability. Flush errors remain refusals;
there is no volume-flush fallback.

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
