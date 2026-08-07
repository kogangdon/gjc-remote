# Release signing trust store

`trusted.json` is the committed, git-pinned root of trust for the native
addon build manifest (`build/Release/native-control.manifest.json`). It is
deliberately **not** stored next to the artifact it verifies: an attacker who
can replace the `.node` file and its manifest in `build/Release` (a local,
gitignored build output directory) cannot also rewrite a file that ships in
source control and is reviewed like any other change.

## Shape

```json
{
  "version": 1,
  "keys": [
    { "keyId": "2026-release-1", "algorithm": "ed25519", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" }
  ]
}
```

- `algorithm` is `"ed25519"` or `"p256"` (NIST P-256 / secp256r1, verified as
  ECDSA over SHA-256).
- `keys` may hold more than one entry so a key rotation adds a new `keyId`
  without invalidating manifests signed under an older, still-pinned key.
- The private key never touches this repository or this tooling. The
  operator holds it (a file, a cloud KMS key, or a hardware/PIV token — the
  format is undecided and the verifier does not care) and produces a
  detached signature over the exact bytes of `native-control.manifest.json`
  using whatever process fits that custody model.

## Bootstrap state

This file currently ships with an **empty `keys` array** because the
operator has not yet provisioned the release signing key. With zero pinned
keys, `loadVerifiedAddon()` cannot enforce a signature and falls back to
today's hash/contract-only verification, emitting a single explicit warning
that addon provenance is UNVERIFIED. It never treats an unsigned or
malformed sidecar as verified, and it never accepts an invalid signature —
zero pinned keys means "cannot check", not "check disabled by trusting
anything presented." As soon as the operator adds a key here, signature
enforcement turns on automatically; no code change or flag is required.

## Rotation

To rotate: add a new `{ keyId, algorithm, publicKeyPem }` entry alongside
the old one, start signing new releases with the new key, and only remove
the old entry once no manifest that must still verify was signed with it.

## Local development

`local-dev.json` (same shape, **gitignored**, see `../../.gitignore`) may hold
additional keys accepted only on the machine that created it, and only while
`trusted.json` is still in its bootstrap, zero-key state. Signing a local
build with a development key still turns on enforcement (a missing or
invalid sidecar still refuses to load) but `loadVerifiedAddon()` warns that a
development key was used. This is not an env-var bypass: it requires
deliberately creating a local, untracked trust file, and it never accepts an
unsigned or invalid signature.

As soon as the operator pins even one production key in `trusted.json`, keys
in `local-dev.json` are dropped entirely — not merged, not consulted as a
fallback, not eligible to shadow a production `keyId`. A dev-signed artifact
then fails closed with "unknown signing keyId" exactly like any other
untrusted signature. This is a deliberate one-way transition: dev keys exist
to unblock local iteration before a production key is provisioned, never as
a standing downgrade path once one is. The release gate
(`node scripts/verify-build.mjs --require-signature`) goes further and never
consults `local-dev.json` at all, at any trust-store state, so a release
build can never be satisfied by a development key.

A trust store (`trusted.json` or `local-dev.json`) containing two entries
with the same `keyId` is rejected outright — loading refuses fail-closed
instead of silently using whichever entry `Array.prototype.find` reaches
first and shadowing the other.