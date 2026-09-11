# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
