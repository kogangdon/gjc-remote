# Daemon Docker status

The repository now contains the Phase 3 daemon image source and a disposable,
same-host Compose fixture under `deploy/docker/daemon/`. They are verification
artifacts, not a published image or production deployment procedure. The daemon
image is built independently from the bot and requires an externally signed,
platform-matched native-control bundle. CI and local dependency-stage builds
never substitute an unsigned addon.

The image runs Bun as fixed identity `1004:1004` behind `tini`. A hard preflight
runs before the daemon import and rejects non-Linux, WSL-backed, or
LinuxKit-backed Docker Desktop kernels, writable image roots, missing or
aliased role mounts, wrong ownership,
unbounded cgroups, capabilities, missing `no-new-privileges`, missing seccomp,
or an unbounded `/tmp`. Its four persistent writable roles are:

- workspace: `/workspaces`;
- session: `/var/lib/gjc-remote/sessions`;
- provider: `/home/gjc/.gjc`;
- state: `/var/lib/gjc-remote/state`.

Host coordination is separate from those four service roles. Every daemon on
the same native Linux host, whether native or containerized, must use the exact
protected host directory `/var/lib/gjc-remote/host-state` for the process-lifetime
singleton lock. The Compose daemon binds that literal
host source to the same literal container target with `create_host_path: false`.
A named volume, anonymous volume, per-container directory, alternate bind
source, or environment-selected path is not a substitute: it would split the
host-wide exclusion.

Before startup, an authorized host operator must provision this directory as
`1004:1004`, mode `0700`, under trusted, non-symlink ancestors that cannot be
replaced by untrusted users. The native daemon must use the same UID/GID as the
container; granting a different UID an ACL is not supported. Neither the image,
Compose fixture, nor daemon provisions or repairs this host directory. The image
contains only a root-owned, mode-`000` mountpoint, and container preflight must
reject a missing or private-image-layer host-state mount before importing the
daemon. Runtime mount inspection does not independently attest the engine's
host source pathname; qualification must also verify the actual fixed bind
configuration on the trusted Linux engine.

The host-state directory is not service data: exclude it from service backup,
restore, rollback, and disposable-volume cleanup. Do not restore, replace, or
unlink its lock to recover a service; doing so can split a live lock.
Service restore must leave
this directory and its contents intact.

Container sessions use an opaque hash-derived directory in the session role.
Existing native `.gjc-remote-session` histories are not copied or migrated.
The Compose fixture uses a read-only root, dropped capabilities, a checked-in
seccomp profile, finite CPU/memory/PID limits, an internal-only control network,
`restart: on-failure`, and a 30-second stop grace against the fixed 15-second
daemon shutdown bound. It publishes no daemon port and mounts no Docker socket,
host root, or host namespace.

The fixture deliberately keeps `GJC_NATIVE_INVENTORY_MODE="off"` and
`GJC_NATIVE_WORKSPACE_SERVING="0"`. Its protocol relay proves private
registration only; it is not the production bot, mapping authority, or positive
workspace-serving evidence. The authenticated #44 mapping envelope remains the
sole route authority.

CI runs the topology with the explicitly labeled `compose-fixture-daemon`
stage, which contains no native addon and cannot enable inventory or serving.
Only the four service-role volumes are disposable; the host-state bind remains
host-scoped even for this fixture. An isolated fixture using private host-state
storage cannot qualify native/container singleton exclusion on the same host.
The signed final `runtime` target is a separate boundary: CI supplies an
untrusted bundle and requires that build to fail. This proves rejection, not
that a production-signed image starts.

Docker Desktop on Windows is an unsupported target and is rejected by the
preflight. The checked-in fixture can be rendered there for configuration
validation, but a successful runtime claim requires a supported native Linux
engine and the externally signed addon. Docker does not establish tenant
isolation. Phase 4 / issue #55 still owns published image provenance, SBOM,
scan, signature/attestation, supported-platform evidence, positive end-to-end
workspace serving, and release promotion.

The Dockerfile pins exact Debian package versions as well as its base image.
When the pinned Debian repository no longer serves that exact package closure,
the build fails rather than silently selecting newer packages; updating those
pins is an explicit reviewed image-input change.

See [Phase 3](../../daemon-workspace-implementation-phases.md#phase-3--docker-runtime),
[daemon container ADR](../../adr/0002-daemon-workspace-container.md), and
[deployment verification](../../daemon-workspace-verification.md).
