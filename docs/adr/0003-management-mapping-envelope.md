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

A managed-v1 wrapper admits only workspace routes. A retained legacy wrapper
preserves the target byte-for-byte and has `legacy-unmigrated`, exact retention,
and `no-route`; it is deliberately not converted or routed. Legacy direct-map
input is migration-only and never a second authority.

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

## Native boundary and exclusions

The JavaScript CLI accepts management only through a verified native addon. The
addon must match its manifest (package/version, N-API, platform, architecture,
capabilities, and SHA-256) and must refuse unavailable, malformed, symlink/reparse,
identity, ACL, lock-order, or atomic-write conditions before a write. A missing
or unverifiable addon fails closed; this ADR makes no claim that the current
workstation's native build passed.

#44 does not authorize daemon serving or readiness, OAuth/provider setup,
network deployment, container rollout, or changes under `ops/`. Native serving
and readiness remain blocked pending their separately required native-applicable
gates and evidence.
