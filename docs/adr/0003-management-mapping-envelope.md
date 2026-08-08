# ADR 0003: Management mapping envelope

- **Status:** Approved contract; native serving/readiness remains blocked
- **Date:** 2026-08-04
- **Scope:** #44 control-plane mapping management only

## Decision

Management is a versioned, control-root-first envelope. A reader first verifies
`.gjc-remote-control`'s control root, then the referenced versioned wrapper, and
only then the `channels.json` target and its identity/ACL bindings. The root and
wrapper are self-fingerprinted canonical JSON, bound to the same management
anchor. Unknown versions, broken fingerprints, missing components, changed
identity/ACL, or a nonconforming legacy target fail closed.

`M` (the native management authority) is the sole writer of the control root,
wrapper, target, state, locks, and audit chain. `B` consumes authority read-only;
B owns its reader state, lease, and acknowledgement and cannot repair, publish,
or infer authority. Discord authorization is not management authority.

## Bot-state directory provisioning and ownership

`bot-state` is a subdirectory of the control root that holds B's reader
projection, reader state, lease, acknowledgement, and successor handshake
records. Its role profile is **M-owned**: `BuildExactRoleAcl`/`RoleRights`
(Windows) and `RoleMode`/`required_owner_role` (POSIX) grant the directory
object itself `FILE_ALL_ACCESS` to M and `FILE_GENERIC_READ | FILE_GENERIC_WRITE
| FILE_GENERIC_EXECUTE` to B (POSIX: rwx to both M and B, mirroring the
existing per-directory execute grant), while individual bot-state *records*
(files) under it keep the prior file-level semantics — B-owned, B has
read+write, M and R have read-only. R and SYSTEM keep today's semantics at
both levels. The native primitive layer distinguishes the two cases from the
object's own kind (a real directory vs. a regular file) rather than from a
second role-profile name, so `verify_exact_role_acl`/`ensure_control_directory`
continue to take the single `"bot-state"` profile string for both the
directory and its records.

M provisions `bot-state` during Genesis bootstrap, in the same step that
provisions the control root: `ensure()` (the internal helper backing every
M-only authority write) creates and exact-ACL-verifies the control root and
then, immediately after, creates and exact-ACL-verifies `bot-state` alongside
it. Because M is the OS principal actually creating both directories, and
the bot-state role profile requires the *directory* owner to be M, this
creation succeeds without `SeRestorePrivilege` or `chown` — no elevated
right is needed to set the owner of an object you are yourself creating.

A bot-principal writer never attempts to create `bot-state`: `ensureBotRoot()`
only verifies that it exists with the exact bot-state role ACL and refuses
fail-closed (`ERR_NATIVE_CONTROL_REFUSED`, `writes: 0`) if it is absent,
rather than lazily creating it. This closes the real-platform bootstrap
blocker where a bound-reader handshake, reached only through a bot-principal
writer, could never create `bot-state` under the authority role's read+execute
ACL — every bot projection/state/lease/ack write would otherwise fail closed
on a real Windows/POSIX host, even though the fake-native test double (which
ignores ACLs) never observed it. B still cannot mutate the authority root or
any object under it; only `bot-state`, and only in the ways described above,
are open to B.

A managed-v1 wrapper admits only workspace routes. A retained legacy wrapper
preserves the target byte-for-byte and has `legacy-unmigrated`, exact retention,
and `no-route`; it is deliberately not converted or routed. Legacy direct-map
input is migration-only and never a second authority.

## Config-parent ownership: an operator prerequisite on Windows

The adapter's `assertConfigParentOwner` refuses (`ERR_NATIVE_CONTROL_REFUSED`,
`writes: 0`) any operation whose actual configured control parent — the
directory holding the configured `channels.json` (`configPath`, overridable
via `CHANNELS_CONFIG`) — is not owned by the management principal (`M`, the OS
user the management CLI/bot runs as). This is fail-closed by design: unlike
`.gjc-remote-control` and `bot-state`, which M itself creates via
`ensure_control_directory` and so always ends up M-owned (see above), the
config-parent directory is never created by native-control. It is whatever
directory already holds `channels.json` when the process starts, so its owner
is whatever the OS assigned when that directory was created — native-control
only ever verifies it, and correctly refuses to proceed if it is wrong.

On Windows, this bites operators specifically when the config-parent directory
was created by a process running with an elevated (Administrator-group)
token: Windows assigns newly created objects to the `BUILTIN\Administrators`
group as owner by default in that case, not to the invoking user's own SID.
A directory created this way is never usable as a management control parent,
even though the same account owns every file inside it, because group
ownership is not user ownership and the contract requires the latter. This is
correct fail-closed behavior, not a bug: a group-owned parent means any other
member of that group can take ownership and thereby rewrite the DACL, which
defeats the exact-role-ACL guarantee the rest of this document depends on.

**Operator prerequisite:** before first run, the directory holding
`channels.json` (typically `bot/`, or the directory pointed at by
`CHANNELS_CONFIG`) must be owned by the OS principal that will run as `M`.
On a host where an elevated operator created that directory (so it ended up
owned by `BUILTIN\Administrators`), fix ownership once with:

```powershell
icacls <dir> /setowner <management-principal>
```

`<management-principal>` may be an account name (`DOMAIN\user` or `.\user`)
or a raw SID prefixed with `*` (for example `*S-1-5-21-...-500`). Re-run as
the account that will actually own and run the management process; a plain
member of Administrators generally holds the "Take ownership" privilege
needed to do this even though it does not already own the directory. Hosts
whose local policy makes `BUILTIN\Administrators` the default owner for
elevated processes must run this command once per config-parent directory
before management writes will succeed — native-control will never silently
accept a group-owned parent as a substitute.

## Identity and token attestation

The bootstrap actor and target are distinct OS principals, encoded as `uid:<id>`
or `sid:<id>`. Genesis is owner-only: the actor must be the current OS principal
and becomes the initial owner; later credential changes require an owner.

`HOST_TOKENS` is protected input, never persisted in management state, audit
records, CLI output, or a fingerprint. It is strict UTF-8 (no BOM or CR), at
most 1 MiB, with unique `hostId=token` LF records. The exact host-set fingerprint
is:

```text
SHA-256(UTF-8(`{"encoding":"utf-8","hostIds":[<JSON-quoted host IDs sorted by UTF-8 byte order>],"schemaVersion":1}`))
```

It covers host IDs only, not tokens; token replacement with the same host IDs
therefore has the same host-set fingerprint. Token generations and mapping
generations are monotonic. A stale version/generation is rejected; an affected
session is invalidated and must re-register rather than being silently handed
onto a remapped target.

## Atomic genesis and recovery

`M` takes locks in `genesis`, `mapping`, `admission` order, probes prospective
cleanup, writes the genesis request (GR), reserves token floor (TF), writes the
attestation (A), and writes the reader floor before target/wrapper/control-root
publication. TF and A precede publication; the TF **commit** occurs after
publication but before any proof:

```text
GR → TF reservation → A → reader floor → target/wrapper/control publication
→ TF commit → Zf → RP → AK → FP → receipt → reopen
```

`Zf` is finality, `RP` reader projection, `AK` admission acknowledgement, and
`FP` finality proof. Admission opens only after the terminal receipt and a
verified proof. Every state transition is a CAS against the prior revision and
is audit-chained. A CAS failure, native write failure after mutation, torn
transaction, lease/fence disagreement, or failed reopen is `manual_cleanup` and
`no-route`, never an automatic retry that could publish a different authority.
Recovery is native, idempotent, and cannot reopen a route without its complete
proof chain.
### Admission archive and history proof boundary

Successor snapshots carry the complete managed-history predecessor chain and the
immutable committed authority-epoch archive. The Genesis precommit carries the
sorted `admissionArchiveIds` inventory, and its zero-grant fingerprint covers that
inventory. No-reader finality, recheck, and snapshot validation require this
durable, cryptographically bound inventory and reject every reachable archive.
The native primitive set does not enumerate arbitrary control-directory entries;
an archive with an ID not present in the bound inventory remains outside the
proof boundary rather than being silently treated as valid.

## Windows durability contract (non-elevated)
`flush_directory_or_volume` on Windows never opens a raw volume device for
`FlushFileBuffers`, because that call requires `SeManageVolumePrivilege`
(effectively administrator) and fails closed for the non-elevated management
principal this addon is designed to run as. The achievable, non-elevated
durability primitive is a **directory-handle flush**: the target directory is
opened through the same verified no-follow, handle-relative path used
elsewhere (`FILE_OPEN_REPARSE_POINT` intact) with `FILE_GENERIC_READ |
FILE_GENERIC_WRITE`, and `FlushFileBuffers` is called on that directory
handle. NTFS supports flushing a directory handle's own metadata this way
without any special privilege, and it is sufficient to make a prior
create/rename/unlink in that directory durable across a crash — this is the
same guarantee POSIX callers get from `fsync()` on a directory file
descriptor, which this codepath mirrors.

This directory-handle flush is the addon's **only** durability primitive on
Windows: no volume-level flush is attempted, elevated or otherwise, so the
process never needs (and never requests) `SeManageVolumePrivilege`. Before
flushing, `flush_directory_or_volume` confirms via
`GetVolumeInformationByHandleW` on the open directory handle that the
directory's volume reports the `NTFS` filesystem name. This codepath's
durability semantics — a directory-handle `FlushFileBuffers` making prior
create/rename/unlink in that directory durable across a crash — are proven
only for NTFS; any other filesystem reported for the handle's volume (FAT32,
exFAT, ReFS, a network share, etc.) fails closed rather than returning a
durability guarantee the addon cannot back up.

This function fails closed, not silently: if the verified no-follow open of
the directory fails, the filesystem cannot be confirmed as NTFS, or the
directory-handle `FlushFileBuffers` call itself fails, `flush_directory_or_volume`
refuses with `ERR_NATIVE_CONTROL_REFUSED` and reports zero writes. It never
claims durability it did not achieve, and never downgrades a failed
directory flush into a silent no-op.

## Windows replace-rename POSIX semantics
`replace_existing_atomic`'s handle-relative, retained-parent rename uses
`FileRenameInformationEx` (info class 65) with `FILE_RENAME_REPLACE_IF_EXISTS
| FILE_RENAME_POSIX_SEMANTICS` first, falling back to the legacy
`FileRenameInformation` (info class 10, `ReplaceIfExists = TRUE`) only when
the running kernel or filesystem reports `STATUS_NOT_SUPPORTED`,
`STATUS_INVALID_INFO_CLASS`, `STATUS_INVALID_PARAMETER`,
`STATUS_NOT_IMPLEMENTED`, or `STATUS_INVALID_DEVICE_REQUEST` for the `Ex` info
class. POSIX semantics let the filesystem replace a target that still has
other open, properly-shared (`FILE_SHARE_DELETE`) handles — for example a
caller-retained read/write handle obtained via `open_verified_object_handle`
— without weakening any ACL, no-follow, or identity check performed before
the rename is attempted. Any other failure from the `Ex` attempt (for
example a genuine access denial) is authoritative and is never masked by the
legacy-class fallback.

## Native boundary and exclusions

The JavaScript CLI accepts management only through a verified native addon. The
addon must match its manifest (package/version, N-API, platform, architecture,
capabilities, and SHA-256) and must refuse unavailable, malformed, symlink/reparse,
identity, ACL, lock-order, or atomic-write conditions before a write. A missing
or unverifiable addon fails closed; this ADR makes no claim that the current
workstation's native build passed.

### Release signing and provenance

Manifest/hash self-consistency alone proves only that the `.node` file and its
manifest were produced together; it does not prove either came from a trusted
release process, since both live side by side in the same locally produced
`build/Release` output directory. Provenance is closed by a second, independent
trust root: `native-control/release-keys/trusted.json`, a git-committed file
(`{ version: 1, keys: [{ keyId, algorithm: "ed25519" | "p256", publicKeyPem }] }`)
reviewed like any other source change, distinct from the gitignored build
output it verifies. A detached signature sidecar,
`build/Release/native-control.manifest.json.sig`
(`{ keyId, algorithm, signature: <base64> }`), is computed over the exact bytes
of the manifest — never a re-serialization — using `crypto.sign`/`crypto.verify`
(`null` digest for ed25519, `sha256` for P-256/ECDSA). `verifyManifestSignature`
in `native-control/src/index.js` is a pure function of `(manifestBytes, sidecar,
trustStore)` and is called from `loadVerifiedAddon()` strictly after the
existing hash and package-contract checks, before the addon is ever `require`d.

The private key is never held or produced by this repository or its tooling —
the operator's custody model (a local file, a cloud KMS key, or a hardware/PIV
token) is out of scope for the verifier, which only ever consumes a public key
and a signature. `native-control/scripts/verify-build.mjs` supports both
`--sign-key <pem path>` for local-file signing and `--signature <raw sig file>
--key-id <id> --algorithm <ed25519|p256>` for a signature produced externally
(KMS, hardware token); `--require-signature` fails the build outright when the
resulting sidecar is absent or does not verify. `--require-signature` verifies
strictly against `trusted.json` alone — a `local-dev.json` key can never
satisfy the release gate, even if one happens to be pinned locally.
Regenerating the manifest (`--write-manifest`) deletes any existing
`.sig` sidecar before writing the new manifest, so a stale signature
computed over the previous manifest bytes can never linger on disk and be
mistaken for valid; the workflow is rebuild (`--write-manifest`) then
re-sign (`--sign-key`/`--signature`, optionally with `--require-signature`).

A trust store (`trusted.json` or `local-dev.json`) with two entries sharing a
`keyId` is rejected fail-closed rather than silently using whichever entry
`Array.prototype.find` reaches first and shadowing the other.
Enforcement is opt-in and keyed off `trusted.json` contents rather than an
environment variable: with at least one key pinned in `trusted.json`,
`loadVerifiedAddon()` requires a valid sidecar signed by a pinned key and
refuses fail-closed (`ERR_NATIVE_CONTROL_REFUSED`) on a missing, malformed,
unknown-`keyId`, algorithm-mismatched, or cryptographically invalid
signature. With zero keys pinned in `trusted.json` and none in the gitignored
`native-control/release-keys/local-dev.json` either — the state this
repository ships in, since the operator has not yet provisioned the release
key — loading proceeds as before hash/contract verification existed, but
emits one explicit warning that addon provenance is UNVERIFIED; an invalid or
malformed sidecar is never silently treated as verified in this state
either. While `trusted.json` is still in that zero-key bootstrap state,
`local-dev.json` may be used to unblock local iteration: loading with a
`local-dev.json`-pinned key succeeds but warns that a development key was
used. As soon as one production key is pinned in `trusted.json`, keys in
`local-dev.json` are ignored entirely — never merged, never consulted, never
a fallback — so a dev-signed artifact fails closed with an unknown-`keyId`
refusal instead of loading; this is a one-way transition with no downgrade
path back to trusting development keys. Key rotation adds a new
`{ keyId, algorithm, publicKeyPem }` entry to `trusted.json` alongside the
old one — old manifests stay verifiable under their original `keyId` until
it is deliberately removed.

#### Residual assumption: in-tree verification requires a protected deployment

This provenance chain proves the `.node` file matches a manifest signed by a
pinned key; it cannot prove the verifier itself has not been tampered with.
Both `src/index.js` (the code that performs the check) and `trusted.json`
(the trust root it checks against) are ordinary files inside the deployed
`native-control/` tree. An attacker who already has write access to that
tree can edit `src/index.js` to skip or weaken the check, or edit
`trusted.json` to pin their own key, defeating verification entirely —
in-tree signature verification cannot defend against an attacker who can
modify the verifier's own source or trust root. A protected installation
with write access restricted to the release/deployment process (so a
compromised runtime principal cannot edit `native-control/` in place)
therefore remains a deployment requirement, not something this ADR's
in-process check can substitute for. CI-side attestation (verifying the
signature and provenance of `native-control/` as it is built and packaged,
before it ever reaches a host) is the complementary control that closes
this gap; it is out of scope for this change and tracked separately from
the in-tree runtime check documented above.

#44 does not authorize daemon serving or readiness, OAuth/provider setup,
network deployment, container rollout, or changes under `ops/`. Native serving
and readiness remain blocked pending their separately required native-applicable
gates and evidence.
