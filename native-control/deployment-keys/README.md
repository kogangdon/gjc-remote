# Deployment signing trust

Status: candidate implementation; application and Shawl public trust roots are provisioned in the source tree from separately held Ed25519 private keys. Production release approval remains blocked pending independent review of key custody, signed assets, and platform evidence. Install/update still refuses while either required root is absent.

Deployment trust is independent of `../release-keys/trusted.json` and is split by purpose:

- `application-trusted.json` is read only for application deployment manifests.
- `shawl-trusted.json` is read only for Shawl deployment manifests.

Never reuse the native root's key ID, public key, private key, or signing purpose. Every deployment key ID and SHA-256 SPKI fingerprint must be disjoint from every native-addon key, including unused entries. Bundled native addons still require their own native signature verification. The old shared `deployment-keys/trusted.json` path is not read and is not a compatibility fallback.

The release owner supplies separately reviewed Ed25519 public keys and custody evidence for both roots. Production private keys are held offline and never stored in this repository, CI secrets, or installed artifacts. The current runtime contract requires an Ed25519 signature over the exact deployment preimage and keeps the existing canonical deployment-signature sidecar; Sigstore/Rekor bundles are not part of this contract. The supported local signer is OpenSSL 3.x `pkeyutl -sign -rawin`; the repository does not claim that the tested Cosign v3.1.3 local-key path can consume Ed25519 PEM keys. Each reviewed trust file uses exactly the existing public-key store shape: `version: 1` and a nonempty `keys` array; each entry has only `keyId`, `algorithm: "ed25519"`, and `publicKeyPem` (SPKI PEM). At most 32 entries and 64 KiB are accepted per root. Duplicate IDs, duplicate SPKI keys, malformed keys, private-key fields and native-key collisions refuse. No local development override or empty-store bootstrap is supported.

Application and Shawl manifests use separate signature domains:

- `gjc-remote/application-deployment/v1`
- `gjc-remote/shawl-deployment/v1`

Signatures cover UTF-8 domain bytes, one NUL byte, then the exact canonical complete manifest bytes, including its manifest fingerprint. The sidecar is canonical JSON under the shared deployment signature schema. Whitespace changes, unknown keys, algorithm changes, untrusted key IDs, incorrect fingerprints and cross-domain/native-signature replays refuse.

`verifyPinnedDeploymentProvenance` reads only the module-relative deployment and native public-key stores. Service requests and environment variables cannot provide trust overrides. The lower-level pure verifier accepts explicit public-key bytes for release tooling and isolated tests; it is not the installed acquisition entrypoint.

The pinned verifier privately brands its frozen `result.manifest` for that module
instance and signing purpose. Protected-store admission checks this brand before
cloning a deployment manifest. Plain objects, serialized copies, explicit-trust
verifier results and other module instances do not carry this authority. Reverify
persisted manifests through the pinned verifier before using them for a new
reservation, publication observation, commit or rollback decision. Isolated test
installations have separate fixture-only brands that the real module rejects.

The read-only release verifier accepts exactly these five flags (paths must be absolute):

```text
node native-control/scripts/verify-deployment-manifest.mjs \
  --purpose application --platform linux --architecture x64 \
  --manifest /retained/application.manifest.json \
  --signature /retained/application.manifest.json.sig
```

For Shawl, use `--purpose shawl --platform win32 --architecture x64`. The verifier emits only a bounded fingerprint receipt or sanitized refusal. It verifies manifest signatures, not archive contents, extraction safety, service ownership, native-addon signatures, executable Authenticode, or deployment readiness. Its bounded file reader is not a retained native ownership proof and cannot authorize service mutation. No production signed release has been accepted, so release and deployment gates remain blocked.

## Offline signing

The offline signer consumes an already-built canonical manifest and an
operator-provided Ed25519 private key. It never generates, copies, or stores a
private key. Keep private keys outside the repository and installed artifacts;
the `--key` path is read directly by OpenSSL. Application and Shawl keys remain
separate and the key ID must match the manifest's `signingKeyId`.

```text
node native-control/scripts/sign-deployment-manifest.mjs \
  --purpose application \
  --manifest /retained/application.manifest.json \
  --key /offline/application-ed25519-private.pem \
  --key-id application-release-2026 \
  --output /retained/application.manifest.json.sig \
  --openssl openssl
```

Use `--purpose shawl` with the Shawl manifest and its separately held key. All
manifest, key, and output paths must be absolute; `--openssl` may be an
absolute executable path or a plain executable name. The signer validates the
selected manifest and canonical bytes, signs the exact
`deploymentSignaturePreimage` with `openssl pkeyutl -sign -rawin`, and writes a
canonical sidecar atomically with mode `0600`. The preimage is piped when the
OpenSSL/platform combination accepts a pipe, otherwise it is held only in a
private temporary file that is removed after signing. Refusals emit a bounded
JSON error and never include key paths or OpenSSL output.

Fixture-generated application/Shawl keys and signatures remain ephemeral test data and never establish production provenance. The operator-held private keys remain only under the ignored local signing directory and never enter this directory or any installed artifact root. The application and Shawl public roots are now provisioned, but signed asset publication, custody/rotation review, and real disposable-host verification remain separate release gates; passing unit tests does not satisfy them.
