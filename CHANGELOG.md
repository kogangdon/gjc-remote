# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
