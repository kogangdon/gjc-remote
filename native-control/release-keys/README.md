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

## Provisioned key (this repository)

- `keyId`: `prod-2026-08`, algorithm `ed25519`. Signature enforcement is
  therefore LIVE: `loadVerifiedAddon()` refuses a missing, malformed, or
  invalid sidecar and refuses an unknown `keyId`.
- The private key is held OUTSIDE this repository by the operator at
  `~/.gjc/release-keys/gjc-remote-native-control-prod.ed25519.key` with the
  file ACL restricted to that account. It is never committed, never copied
  into `build/`, and never needed to run the test suite.
- Re-sign after every rebuild, because `--write-manifest` regenerates the
  manifest and deletes the stale sidecar:

  ```bash
  cd native-control
  node scripts/verify-build.mjs --write-manifest \
    --sign-key ~/.gjc/release-keys/gjc-remote-native-control-prod.ed25519.key \
    --key-id prod-2026-08
  node scripts/verify-build.mjs --require-signature   # release gate
  ```

- For cloud KMS or a hardware/PIV token instead of a local file, produce the
  detached signature over the exact manifest bytes with that custody tool and
  pass it in: `--signature <file> --key-id <id> --algorithm <alg>`.
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

## Backup, restore, and rotation runbook

Losing this key is recoverable (pin a new `keyId`, re-sign); disclosing it is
not (every release signed under the leaked `keyId` must be invalidated). So
keep the number of plaintext copies at ONE and encrypt every backup.

### Identity of the provisioned key

| Field | Value |
| --- | --- |
| `keyId` | `prod-2026-08` |
| Algorithm | ed25519 |
| Public SPKI SHA-256 | `62789ce90d683922d0f66037c05b87c6842d50683c2a28883617a0939cb2dfa7` |

A restored key is the right one when its public SPKI SHA-256 matches the row
above and the pinned `publicKeyPem` in `trusted.json`:

```bash
node -e "const{createPrivateKey,createPublicKey,createHash}=require('crypto'),fs=require('fs');\
  const pub=createPublicKey(createPrivateKey(fs.readFileSync(process.argv[1])));\
  console.log(createHash('sha256').update(pub.export({type:'spki',format:'der'})).digest('hex'))" <key-path>
```

### Backup

```bash
# Encrypted backup for offline media / a password manager. Keep the working
# copy unencrypted and ACL-restricted; only backups carry a passphrase.
openssl pkcs8 -topk8 -v2 aes-256-cbc \
  -in ~/.gjc/release-keys/gjc-remote-native-control-prod.ed25519.key \
  -out prod-2026-08.key.enc.pem
```

Store two encrypted copies on separate offline media (or one offline plus a
password-manager attachment). Never place a plaintext copy in cloud sync, in
this repository, in `build/`, or in CI secrets.

### Restore drill (run after every backup change)

```bash
openssl pkcs8 -in prod-2026-08.key.enc.pem -out restored.key           # decrypt
# confirm the fingerprint matches the table above, then prove it still signs:
cd native-control
node scripts/verify-build.mjs --write-manifest --sign-key ../restored.key --key-id prod-2026-08
node scripts/verify-build.mjs --require-signature
rm ../restored.key                                                     # discard the copy
```

### Rotation (also the recovery path after loss or disclosure)

1. Generate a new key and add its `{ keyId, algorithm, publicKeyPem }` entry to
   `trusted.json` ALONGSIDE the current one.
2. Sign new releases with the new `keyId`.
3. Remove the old entry once no artifact that must still verify was signed with
   it. After a suspected disclosure, remove it immediately and re-sign every
   artifact that must remain loadable.
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