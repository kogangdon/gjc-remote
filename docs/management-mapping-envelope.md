# Management mapping envelope

This is the operator contract for #44. It controls the versioned mapping envelope;
it does not enable native serving or readiness.

## Authority and route decision

`M` is the native, sole authority writer. `B` is a read-only authority consumer
and owns its reader state, lease, and acknowledgement. B never publishes,
repairs, or treats a target file as authority. The decision order is
control-root-first: verify the control root, its wrapper, and then the target's
identity/ACL and required fingerprint bindings. Any mismatch, unknown version,
stale generation, missing proof, or recovery state fails closed.

Managed v1 routes are workspace-only. A legacy-retained target is an exact,
untouched byte/identity/ACL retention exemption and remains `no-route`; do not
edit it through management or infer a route from it.

## Bootstrap and credentials

The approved native-addon platform contract is `linux-x64`, `linux-arm64`,
and `win32-x64`. Current live operator evidence covers Linux only; this
document does not claim live Windows verification. Management may run only
when the manifest-bound addon and its platform-specific capability probes
succeed before mutation. Linux principals use canonical `uid:<decimal>`
values; Windows principals use canonical `sid:S-...` values. Discord
identities are never accepted. All credentials and `HOST_TOKENS` enter only
through protected stdin.
The command emits only bounded JSON status/error codes; do not redirect it to a
terminal transcript or log its stdin.

```bash
# Placeholders only: protected stdin, no real credentials or token output.
printf '%s' '{"actorSecret":"REDACTED","hostTokens":"host-a=REDACTED"}' |
  node bot/src/management-entrypoint.js genesis \
  --actor-principal uid:1000 --target-principal uid:1003 \
  --bot-principal uid:1001 --recovery-principal uid:1002 \
  --management-provisioning-fingerprint <lowercase-hex64> \
  --bot-provisioning-fingerprint <lowercase-hex64> \
  --recovery-provisioning-fingerprint <lowercase-hex64> \
  --idempotency-key bootstrap-001 \
  --actor-secret-stdin true --host-tokens-stdin true
```

The native addon must be installed and verified before this command can mutate
anything. Missing, wrong-platform, tampered, or capability-incomplete addon
builds are refused with no write. Do not treat a CLI refusal as a reason to use
ordinary file edits.

Platform inclusion in the addon manifest is not evidence by itself. Missing
or failed platform-specific retained-handle, ACL, no-follow, replacement, or
durability probes refuse management before mutation. Native serving and the
existing daemon platform support are separate concerns.

## Rotation

Token attestation requires at least one strict LF-only `HOST_TOKENS` record
and stores only a secret-free host-set fingerprint. Precisely, it is SHA-256
of UTF-8 JSON:

```text
{"encoding":"utf-8","hostIds":[<JSON-quoted IDs sorted by UTF-8 byte order>],"schemaVersion":1}
```

`tokenConfigGeneration` and `mappingGeneration` each increase monotonically,
but they are independent: token rotation does not increment mapping generation.
When remapping affects a session, invalidate it and
require re-registration; never silently hand it over to a new mapping.

```bash
printf '%s' '{"actorSecret":"REDACTED","hostTokens":"host-a=REDACTED\nhost-b=REDACTED"}' |
  node bot/src/management-entrypoint.js tokens-attest \
  --actor-principal uid:1000 --idempotency-key token-rotation-001 \
  --actor-secret-stdin true --host-tokens-stdin true
```

Credential add/rotate/revoke likewise require an owner actor, distinct target
principal where applicable, and protected `actorSecret`/`targetSecret` stdin
fields. Do not put secrets in flags, environment, filenames, or audit notes.
Every successor-producing mutation (`genesis`, `tokens-attest`,
`mapping-reconcile`, `mapping-revoke`, and `mapping-rollback`) and public
`recover` requires one non-empty public `--idempotency-key` argument. The key is
not a credential; all credential and token values remain protected stdin fields.
Duplicate, unknown, and secret-bearing argv flags are refused.

## Publication, recovery, and audit

Publication is atomic and ordered:

```text
GR → TF reservation → A → reader floor → publication → TF commit
→ Zf → RP → AK → FP → receipt → reopen
```

GR is the genesis request; TF is token floor, A attestation, Zf finality, RP
reader projection, AK acknowledgement, and FP finality proof. TF reservation and
A occur before publication; TF commit occurs after publication and before Zf/RP/
AK/FP/receipt/reopen. The native writer uses ordered locks and revision CAS.
Every successful transition appends a redacted audit-chain record containing the
actor, target, action, result, and non-secret fingerprints/transaction identity.

If a mutation, CAS, proof, lease/fence, audit append, or reopen cannot be
verified, the only disposition is `manual_cleanup` and `no-route`. Inspect
status without printing protected input.

### Successor recovery

`recover` resolves the active durable authority-successor transaction; it never
creates a mapping successor and does not use legacy `state.recovery.records`.
It authenticates the owner and requires the supplied public idempotency key and
actor to exactly match the active durable successor request.

```bash
printf '%s' '{"actorSecret":"REDACTED"}' |
  node bot/src/management-entrypoint.js recover \
  --actor-principal uid:1000 --idempotency-key recovery-001 \
  --actor-secret-stdin true
```

A matching terminal head is an exact idempotent replay. A matching
`reader-pending` head is completed only after the native successor bundle,
lease, projection, acknowledgement, and retained-target proof validate exactly;
otherwise it remains `no-route`. Reserved, closed, replaced, unknown,
mismatched, or torn heads are durably recorded as transaction-bound
`manual_cleanup` with `no-route`. With no active head, recovery refuses without
creating a successor.

Recovery is not permission to delete, rewrite, or route the target manually. It
must retain a failed state until the native proof chain supports a safe result.

## Boundaries

This contract excludes OAuth/provider credentials, daemon commands, readiness,
network or deployment configuration, and operational service scripts. Native
serving/readiness remains blocked and outside #44; a verified native addon is a
necessary fail-closed capability, not evidence that serving is approved.
