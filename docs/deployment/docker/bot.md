# Bot Docker deployment

The canonical bot container instructions are in [deploy/docker/bot/README.md](../../../deploy/docker/bot/README.md).

This is an optional, Linux-only **release candidate**, not a supported published image. It is independent of daemon deployment: the Compose fixture contains no daemon and does not authorize daemon Docker deployment.

The image requires an externally produced, production-signed, architecture-matched native-control bundle; CI's unsigned build output is not a release bundle. Keep Discord and host tokens in protected host files, never in image layers, build arguments, Compose, or environment variables. The WebSocket control port is private-bound by default; never expose it publicly or on a wildcard interface. The canonical page defines the exact Compose, signing, hardening, health, upgrade, and rollback contract.
