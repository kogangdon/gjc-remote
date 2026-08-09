# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Windows process supervision now defaults to Shawl with an `sc.exe`
  fallback; the NSSM-based supervision approach was evaluated and discarded
  (see `docs/adr/0001-process-supervision.md`).

### Prior releases

Releases before 0.3.0 (`v0.2.0`-`v0.2.4`) predate this changelog. See the
[GitHub Releases](https://github.com/kogangdon/gjc-remote/releases) and
[tags](https://github.com/kogangdon/gjc-remote/tags) for that history.
