# macOS deployment status

macOS is not a supported native-control or native-inventory platform. All macOS OS/architecture tuples are outside the approved native-control targets, which are Linux x64/arm64 and Windows x64. There is no portable native-control fallback.

No checked-in launchd plist, renderer, installer, or macOS service evidence exists. This repository therefore provides no production launchd recipe and no basis to represent macOS as a production deployment target. Do not adapt the Linux systemd or Windows supervisor instructions into a launchd deployment claim.

A future macOS approval would require, at minimum:

- a supported, manifest-verified native-control build with macOS capability probes and fail-closed ACL, ownership, no-follow, replacement, and durability behavior;
- reviewed, checked-in launchd artifacts with separate bot/daemon identities, protected environment/profile/session storage, bounded stop/restart behavior, and independent bot/daemon operation;
- current-run boot, readiness, shutdown, logging, provenance, and secret-handling evidence on an owned macOS host; and
- evidence that native inventory's five-principal model and receipt-gated serving preserve the same security contract.

Until those requirements are met, use an approved Linux or Windows target. See
[native-control prerequisites](../../../README.md#local-quick-start),
[process supervision](../../process-supervision.md), and
[deployment verification](../../daemon-workspace-verification.md).
