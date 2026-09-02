# Bot Docker deployment

This is an optional **Linux-only** deployment for the bot. Native Node service
deployment remains supported. Daemon Docker is a separate phase and is not part
of this Compose file.

## Release gate

The runtime image accepts only an externally built, production-signed
`native-control` bundle for its target architecture. The bundle directory must
contain exactly the release artifacts used by the native verifier:

- `native_control.node`
- `native-control.manifest.json`
- `native-control.manifest.json.sig`

Dependencies are installed with lifecycle scripts disabled. Optional `ws`
native accelerators (`bufferutil` and `utf-8-validate`) are therefore absent;
the bot intentionally uses `ws`'s supported pure-JavaScript fallbacks.

Set `GJC_NATIVE_CONTROL_BUNDLE_DIR` to that directory. The Docker build copies
the bundle without rebuilding it and runs `verify-build.mjs
--require-signature`; missing, wrong-platform, modified, self-signed, or
untrusted artifacts fail the image build.

Source-built unsigned CI addons are not release bundles. Until signed Linux
amd64 and arm64 bundles and live container evidence exist, this deployment is a
release candidate rather than a supported published image.

Each Linux CI leg uploads a seven-day
`native-control-unsigned-{X64|ARM64}` signing-input artifact containing the
addon and manifest. Sign the manifest bytes outside CI with the production key,
extract the artifact into `native-control/build/Release`, then use the
repository tooling to wrap the externally produced raw signature and verify
the sidecar:

```sh
node native-control/scripts/verify-build.mjs --write-manifest \\
  --signature /protected/native-control.signature \\
  --key-id prod-2026-08-r2 --algorithm ed25519
node native-control/scripts/verify-build.mjs --require-signature
```

The private key must never enter the repository, Docker build context, GitHub
artifact, workflow secret, image layer, or CI runner. Preserve the verified
three-file bundle as the `native_control_bundle` BuildKit context.

## Configuration

Create two host files outside the repository and restrict them to the account
running Docker:

- Discord token: one UTF-8 line.
- Host-authentication tokens: legacy `host:token,...` or managed LF-delimited
  `host=token` records. These authenticate daemon transport identity only;
  routing still resolves exclusively through the authenticated mapping
  authority.

Set:

```text
GJC_DISCORD_TOKEN_FILE=/protected/discord-token
GJC_HOST_TOKENS_FILE=/protected/host-tokens
GJC_BOT_CONFIG_DIR=/protected/gjc-remote-config
GJC_NATIVE_CONTROL_BUNDLE_DIR=/protected/native-control-linux-amd64
GJC_BOT_ALLOWED_USERS=123456789012345678
GJC_MANAGEMENT_ROLE_BINDINGS={\"managementSid\":\"uid:1001\",\"botSid\":\"uid:1000\",\"recoverySid\":\"uid:1002\",\"systemSid\":\"uid:0\"}
```

`GJC_BOT_CONFIG_DIR` is the persistent managed authority tree mounted at
`/var/lib/gjc-remote`. The container runs as `uid:1000`, which must be the
configured `botSid`; management and recovery must be distinct host UIDs and
system must be `uid:0`. Provision the tree with the native management tooling
and exact role ACLs before mounting it. The mount is writable at the container
boundary because bot-owned handshake/successor records are durable, while the
native ACL contract still denies bot mutation of management-owned mapping
objects. A shared broadly writable directory is invalid. Do not place secrets
in that directory or in the image, Compose file, build arguments, or
environment variables.

Validate before starting:

```sh
docker compose --env-file /protected/gjc-bot.env \
  -f deploy/docker/bot/compose.yaml config --quiet
docker compose --env-file /protected/gjc-bot.env \
  -f deploy/docker/bot/compose.yaml build --pull
docker compose --env-file /protected/gjc-bot.env \
  -f deploy/docker/bot/compose.yaml up -d
```

## Network and health boundary

The WebSocket control port binds to `127.0.0.1` by default. Set
`GJC_BOT_BIND_ADDRESS` only to a private host/VPN address reachable by trusted
daemons. Never publish this raw `ws://` RCE control plane on a public or
wildcard interface.

The image healthcheck is TCP liveness only: it proves the bot listener accepts
a connection. It does not prove Discord login, mapping readiness, provider
readiness, or daemon registration. Use `/hosts` and structured logs for those
states.

## Runtime hardening

The Compose service runs as UID/GID 1000 with a read-only root filesystem,
all Linux capabilities dropped, `no-new-privileges`, bounded PIDs/memory, a
small no-exec `/tmp`, no Docker socket, and `on-failure:5`. The 30-second stop
grace exceeds the bot's two bounded 10-second shutdown steps.

These controls reduce impact; they are not tenant isolation. Compromise of the
bot process exposes its Discord and host tokens.

## Upgrade and rollback

1. Record the current image digest and signed native bundle fingerprints.
2. Pull/build the candidate for the same architecture and verify the signature
   gate.
3. Quiesce management writes and record the authority head, revision, epoch,
   fence generation, token and mapping generations, and a full-tree
   fingerprint.
4. Run `docker compose config --quiet`, then recreate only `bot`.
5. Confirm TCP health, Discord login, mappings, and daemon registrations.
6. Restore the prior image digest and its matched signed native bundle only
   when the recorded authority values and tree fingerprint are byte-for-byte
   unchanged, proving that the candidate committed no authority successor.
   Never combine an image with a different addon/manifest/signature.

Once the candidate commits an authority successor or advances any durable
floor, downgrade is closed. Never start an older reader against that live
volume and never restore an older volume snapshot to rewind monotonic
authority state. Retain snapshots only for audit or isolated recovery, and
roll forward to a current-or-newer image that validates the committed state.
A native startup self-test is not rollback proof; the managed authority reader
must validate before the prior image is considered safe to restore.

Logs go to the Docker logging driver and must be collected by the operator.
Secret values and host paths must not be copied into support bundles.
