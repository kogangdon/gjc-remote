# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Upgrade blocker

- SDK 0.16.4 does not automatically continue a follow-up admitted after the
  active run's queue cutoff. The real SDK oracle observes `waitForIdle()`
  resolving with the exact executable message still queued and no successor
  run; disposal rejects the pending remote control without false completion.
  Its defect-detection test passes, but `upgradeAssessment.verdict` is `BLOCK`
  (`SDK_0_16_4_LATE_FOLLOW_UP_NOT_AUTO_CONTINUED`). Passing workspace tests and
  local smoke do not clear this upgrade or authorize release.
  Independent review approves adapter ownership safety, not successor
  delivery: this is an SDK liveness defect, not false completion. That scoped
  approval does not change the recorded upgrade block. The oracle proves
  explicit disposal, not automatic timeout expiry. Repair belongs in the
  SDK's lifecycle-owned queue wakeup; no remote FIFO policy change or
  lower-level continuation bypass is included.

### Changed

- Upgrade the embedded GJC SDK to 0.16.4 and require Bun 1.4.0 or newer.
  Align CI, container base pins, lock provenance, and future observability
  recipes while retaining the existing in-process session architecture.
- Replace the retired Discord `/team` registration with `/autoresearch`,
  matching the SDK's bundled workflow catalog.
- Delegate scoped settings ownership and startup profile activation to the
  SDK's public APIs instead of cloning process-global settings.

### Fixed

- Align live control completion with SDK queue consumption and terminal
  outcomes; cancel adapter waiters explicitly during disposal.
  Live controls use public SDK promotion callbacks with literal-text delivery.
- Encode SDK workflow answers as structured objects and confirm acceptance
  through bounded, correlated daemon receipts. Rejections remain retryable only
  for the same live gate, without erasing successors or starting a new prompt.

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
