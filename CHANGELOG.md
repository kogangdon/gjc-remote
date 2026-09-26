# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0-rc.4] - 2026-09-27

Supersedes the unpublished `v0.4.0-rc.3` draft, whose native addon cannot
qualify Windows services (see Fixed).

### Windows production service-host composition (source level)

- Compose the Windows x64 direct lifecycle CLI from one operation-scoped host
  producer. It captures protected `.env`, runtime-config, scope-catalog, and
  runtime-binary authority through native read-only roots, and derives the
  exact Launch from signed `windowsServiceBootstrap` release metadata.
- Add the signed same-process service bootstrap guard with the Node 26.7.0 /
  Bun 1.4.2 runtime policy. Bot and daemon now report real startup events, and
  the two-family Shawl log observer lives in native contract 5 revision 1
  (native 2.0.0, application 0.4.0-rc.4).
- Add the credential-free `smoke:windows-host-fixture` foreground fixture.
  The native addon was only compiled unsigned for local audit; none of this is
  signed-addon, SCM, account/ACL, reboot, or actual service lifecycle evidence;
  those qualifications remain separate human-gated steps.

### Fixed

- Fix two native defects that made Windows install/status/start fail on every
  host. Native access
  checks now pass owner, group and DACL to `AuthzAccessCheck`/`AccessCheck`
  (a DACL-only descriptor made every bootstrap-anchor proof and service
  self-observation refuse with `SERVICE_ACCESS_DENIED`), and the daemon
  `.bunfig.toml` read uses a 1-byte bound instead of the invalid 0
  (`SERVICE_INVALID`). Found by `v0.4.0-rc.3` live SCM qualification; requires
  a new signed native addon and live requalification. The Windows guide now
  documents the working-directory ancestor ACL precondition.

## [0.4.0-rc.2] - 2026-09-25

### Signed native verification and candidate preparation

- Add manual verification of existing production-signed native inputs on Linux
  x64, Linux ARM64, and Windows x64 with Node 26.7.0 and Bun 1.4.2. Validate
  trusted source runs, production signatures, hashes, capability contracts,
  real loader behavior, and tamper rejection without private keys or deployment.
- Align application workspace versions and the canonical candidate builder
  contract with `v0.4.0-rc.2`; align the tag workflow with the Bun 1.4.2 producer.
  Candidates remain draft prereleases, not service lifecycle or GA evidence.
- Bound smoke heartbeat timeout configuration and require a pong from the
  current connection using monotonic deadlines. The intermittent real-SDK
  disconnect investigation remains deferred in issue #247; this is not a
  claimed fix for its underlying cause.

### Native addon build reproducibility

- Windows Release linking now preserves the intentional node-gyp option
  replacement while adding `/Brepro` and `/PDBALTPATH:%_PDB%`, making
  linker-controlled PE/COFF metadata deterministic and removing the embedded
  absolute PDB path without reintroducing LLVM-only options that MSVC rejects.
- CI now retains unsigned native-control signing inputs for `linux-x64`,
  `linux-arm64`, and `win32-x64` under explicit OS-and-architecture artifact
  names. Reproducibility applies only to clean builds with the same pinned
  toolchain and checkout path; it is not independent source provenance or a promise across
  toolchain versions.

## [0.4.0-rc.1] - 2026-09-17

### SDK 0.16.7 upgrade

- `@gajae-code/coding-agent` is pinned to **0.16.7** in `daemon/package.json`
  and `bun.lock` (root integrity
  `sha512-rqhs7FELytNw0zfumqroc5EaVrtEUccGGp4YNpFbycF89o+Q+dzWWof1uRVnZvS+GLzCKR9psWZiDEacJzXY7A==`).
  The published 0.16.6 → 0.16.7 tarball diff is one upstream fix
  (`gjc --smoke-test` no longer leaves its isolated-shell worker behind) plus
  the `@gajae-code/*` workspace version bumps; the daemon does not use that
  surface. No SDK API the daemon consumes changed.
- The live-control containment introduced with 0.16.6 stays in force unchanged:
  the `#scheduleNonAdmittedQueuedContinuation` wakeup from upstream
  [#5371](https://github.com/Yeachan-Heo/gajae-code/pull/5371) is present on
  upstream `dev` but absent from both the `v0.16.7` tag and the published
  `@gajae-code/coding-agent@0.16.7` tarball, and
  [#5429](https://github.com/Yeachan-Heo/gajae-code/issues/5429) remains open.
  Active-prompt `steer` / `follow_up` keep rejecting with
  `SDK_LIVE_CONTROL_UNSUPPORTED`; the real-SDK oracle re-verifies this against
  the installed 0.16.7 package.
- Managed pins updated together: daemon Docker `LOCK_SHA256`
  (`ac42d7875284b92183670dc96d30084627edb5a14f5563c3815f6aec61923e40`) and SDK
  version guard/label, `deploy/native/release-contract.json` `sdk` block and
  the service-release builder's pinned `lockIntegrity`, contract oracle and
  isolation probe expected versions, README/CONTEXT/SECURITY/deployment docs.
  Historical 0.16.4/0.16.6 evidence under `docs/verification/` is retained
  as-is and is not relabeled; the #62 isolation probe was rerun on 0.16.7 and
  its evidence page updated to the current run.
- `bun.lock` also picks up one unrelated catch-up hunk: the
  `@gjc-remote/native-control` workspace entry gains the `gjc-remote-service`
  bin already declared in its `package.json` on `main`. No dependency changes.

### Removed

- `@gjc-remote/shared/deployment-envelope` no longer exports
  `assertDeploymentSequenceAdmission`, `buildDeploymentSequenceFloor`,
  `validateDeploymentSequenceFloor`, or `deploymentSequenceFloorFingerprint`.
  They had no caller; release-sequence admission is enforced only by the
  protected service store's reservation path, which additionally binds the
  retained transaction identity.

### Native service lifecycle contract (Issue #240)

- Document the `@gjc-remote/native-control` `gjc-remote-service` boundary with
  exactly six operations: `install`, `status`, `update`, `rollback`,
  `uninstall`, and `recover`. The request is strict UTF-8 JSON on non-terminal
  stdin; `status` is read-only and reports zero writes.
- Pin Bun 1.4.0+ for the daemon and Node.js 26+ for the bot and lifecycle CLI.
  `CHANNELS_CONFIG` is an absolute path to preprovisioned external state, and
  daemon service identity derives from the exact `HOST_ID` plus its full
  lower-case UTF-8 SHA-256 suffix.
- Record immutable content-addressed release and predecessor pins, signed
  application/Shawl asset requirements, byte-preserving external state, and
  proof-bound recovery/manual-cleanup behavior. No drain, migration, or
  automatic repair is implied.
- Specify executable trial semantics: Linux disabled/unmasked with `Restart=no`
  and no activator; Windows demand-start with empty actions; controller death
  does not auto-stop a trial. Startup evidence is distinct from live health.
- Clarify that G003 fake-driver/model evidence is not disposable-host,
  production-signing, SCM, or systemd proof. Windows log/tree ABI gaps and
  Linux shared-template/opaque zero-reference ambiguity remain safe refusals.

### Gate presentation protocol

- Negotiate `gate_presentation_v1` with the terminal-disposition and invocation-
  cancellation capabilities before serving a gate-capable invoke. Bot and daemon
  deploy lockstep; a mixed peer fails closed before execution.
- A workflow gate starts daemon-side as `awaiting_presentation`, owned by its
  exact `ownerId`, `gateId`, and `presentationId`. The bot first renders a
  bounded Discord gate message with the complete wire-bounded prompt and
  options attached, then sends `present_gate`. The gate is answerable only
  after the exact accepted `gate_presentation_result`; presentation and
  abandonment receipts are nonterminal.
- Gate answers bind the exact request, gate, and presentation identifiers to
  the original Discord gate message, channel, and initiating user. Buttons or
  select menus are used where suitable; free text must be an exact reply to
  that gate message. Ordinary channel messages never answer a gate. The
  original gate message is edited through Answering, Answered,
  Rejected—retry available, Expired, Replaced, and Disconnected states.
- Presentation send failure or timeout abandons the still-open exact gate with
  `abandon_gate` and separately requests `presentation_failed` cancellation.
  Neither request claims that active SDK work was interrupted. An accepted
  answer receipt alone retires the exact presentation; a rejected receipt
  re-enables that exact gate for retry.
- Duplicate presentation, abandonment, and answer attempt IDs replay their
  exact prior receipts. Conflicting reuse policy-closes the socket. Bounded
  receipt/presentation capacity fails closed without evicting live entries.
  Oversized gate protocol content is refused and quarantined rather than
  silently truncated; Discord's inline preview is bounded while the complete
  wire-bounded prompt and options remain in its attachment.
- On daemon socket close, exact socket-generation owners are synchronously
  gate-quarantined before cancellation retirement and reconnect scheduling.
  Existing #234 disposal containment remains separate.

### Invocation cancellation and terminal disposition protocol

- Negotiate both `terminal_disposition_v1` and `invoke_cancellation_v1` before
  an invoke. Mixed bot/daemon peers fail closed before execution; deploy the
  two components together.
- Add `cancel_invoke` receipts. The exact reasons are `idle_timeout`,
  `hard_cap`, `disconnect`, `user_cancelled`, and `presentation_failed`; the
  exact `cancel_result` outcomes are `cancelled_before_start`,
  `cancellation_pending`, `already_terminal`, and `not_owned`. A duplicate
  `cancelId` replays its exact original receipt. Request and cancellation
  tombstones are bounded and retained through the hard-cap/receipt horizon.
- A queued cancellation is revoked before SDK, provider, or tool execution,
  receives `cancelled_before_start`, and then receives the authoritative
  terminal `cancelled` frame. Active cancellation receives only
  `cancellation_pending`: SDK 0.16.6 has no supported active-control
  interruption, so the eventual natural terminal remains authoritative. A
  cancellation receipt is not terminal or quiescence proof.
- Bot idle and hard-cap expiry, `/cancel`, presentation failure, and
  shutdown/disconnect ownership transitions use that revocation path. Discord
  says interruption is unconfirmed until a terminal outcome arrives; operators
  must inspect host state before retrying. This does not restore active
  `steer`/`follow_up` or unblock #231.
- On daemon socket close, queued sibling invokes are synchronously revoked.
  Each active shared session is retired once through #234 containment; leases
  and admission fences remain until positive disposal proof, preventing owned
  work from being downgraded or adopted by a successor.
- An invoke now ends with one authoritative final `event` frame whose event is
  `invoke_terminal`, with `done: true` and no top-level `error`. The exact
  dispositions are `completed`, `failed`, `cancelled`, `paused`, `timed_out`,
  and `disconnected`; the first valid terminal frame wins. `paused` and
  `cancelled` are preserved rather than flattened into generic failure.
- `timed_out` and `disconnected` report a terminal protocol outcome, not proof
  that underlying SDK or process work stopped. A bot-local response timeout is
  likewise an unconfirmed local failure, not a daemon timeout disposition.
  On an adapter timeout, the daemon transfers its session/activity hold into
  SessionPool retirement containment tracked in #234, because work may
  continue while retirement settles.

### SDK 0.16.6 containment

- Reject `steer` and `follow_up` with `SDK_LIVE_CONTROL_UNSUPPORTED` while a
  prompt is active. The rejection occurs before SDK queue admission, preventing
  a late follow-up from hanging or being correlated with an unrelated terminal.
  Idle controls remain serialized prompt-equivalent work.
- Historical 0.16.4 evidence: the real SDK oracle observed `waitForIdle()`
  resolving with the exact executable follow-up still queued and no successor
  run after admission beyond the active run's queue cutoff. Disposal rejected
  the pending remote control without false completion. The characterization
  test passed, while its receipt recorded `BLOCK`
  (`SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED`). This receipt is old-run
  evidence, not a 0.16.6 result.
  The required repair belongs in the SDK's lifecycle-owned queue wakeup; no
  lower-level continuation bypass is included here.
- Upstream [#5351](https://github.com/Yeachan-Heo/gajae-code/issues/5351) is
  fixed on the development branch by
  [#5371](https://github.com/Yeachan-Heo/gajae-code/pull/5371), but that fix is
  absent from both the `v0.16.6` tag and the actual published
  `@gajae-code/coding-agent@0.16.6` npm tarball. The merged development source
  and the installed package are distinct evidence surfaces; issue closure does
  not alter the packaged behavior.
- Remove the adapter's dependency on internal `queuedAtDispatch` and
  `onQueuedPromoted` hooks. Upstream
  [#5429](https://github.com/Yeachan-Heo/gajae-code/issues/5429) requests a
  supported queued-input ownership lifecycle; live controls remain disabled
  until that contract is available and verified.

### Changed

- Upgrade the embedded GJC SDK to 0.16.6 and require Bun 1.4.0 or newer.
  Align CI, container base pins, lock provenance, and future observability
  recipes while retaining the existing in-process session architecture.
- Replace the retired Discord `/team` registration with `/autoresearch`,
  matching the SDK's bundled workflow catalog.
- Delegate scoped settings ownership and startup profile activation to the
  SDK's public APIs instead of cloning process-global settings.

### Fixed

- Fence every canonical workDir while an SDK session is retiring. Idle reap,
  managed receipt retirement, closed-session replacement, and late-created
  cleanup now share one fail-closed disposal contract: only positive disposal
  fulfillment permits a successor, while pending and failed retirement expose
  distinct sanitized remediation codes.
- Fail closed instead of admitting live controls through unsupported SDK
  ownership hooks; cancel prompt and gate waiters explicitly during disposal.
- Encode SDK workflow answers as structured objects and confirm acceptance
  through bounded, correlated daemon receipts. Rejections remain retryable only
  for the same live gate, without erasing successors or starting a new prompt.
  The unreleased gate-answer wire shape now requires `answerId` and exact fields;
  it has no mixed-version capability negotiation, so bot and daemon peers must
  be deployed together before the workflow-gate channel is enabled.

## [0.3.1] - 2026-08-09

### Changed

- Upgraded the embedded `@gajae-code/coding-agent` SDK from 0.12.7 to
  0.12.21, including the committed Bun lockfile and current security/provenance
  documentation. Regression suites, canonical import checks, local smoke, and
  manual bot/daemon execution passed on 2026-08-09.

## [0.3.0] - 2026-08-09

### Added

- Management mapping envelope (Issue #44): a signed authority-binding envelope
  for management-role mappings, carried under native capability contract
  version 3 (`native-control/package.json` `nativeControlContract.version`).
- Signed native addon provenance gate: `native-control`'s `loadVerifiedAddon()`
  verifies a detached signature over the build manifest against a git-pinned
  trust store (`native-control/release-keys/trusted.json`) and refuses a
  missing, malformed, or unrecognized-`keyId` sidecar.
- CI now builds the native-control addon on both `ubuntu-latest` and
  `windows-latest` so the retained-handle / ACL / no-follow / replacement /
  durability probes run for real on every supported platform instead of the
  whole native integration suite self-skipping.

### Changed

- Node.js `>=26.0.0` is now enforced, not just recommended, for the bot and
  the `gjc-remote-admin` management CLI: both refuse to start on an older
  Node major with a structured `unsupported_node_version` fatal instead of
  risking an unreported native crash later in startup.
- Windows process supervision decision: the previously evaluated NSSM-based
  approach is discarded. The documented decision records Shawl as the
  intended primary Windows supervisor with an `sc.exe` fallback; neither is
  implemented in this repository yet (see
  `docs/adr/0001-process-supervision.md` and `docs/process-supervision.md`).

### Prior releases

Releases before 0.3.0 (`v0.2.0`-`v0.2.4`) predate this changelog. See the
[GitHub Releases](https://github.com/kogangdon/gjc-remote/releases) and
[tags](https://github.com/kogangdon/gjc-remote/tags) for that history.
