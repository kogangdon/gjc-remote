# ADR 0005: Managed protocol v3 floor and legacy retirement

- **Status:** Accepted
- **Date:** 2026-09-03
- **Owners:** issues #43, #44, and #55

## Context

Wire protocol v0 (omitted negotiation fields), protocol v1, the unmanaged
`legacy-v0` channel source, and the managed `legacy-retained` no-route state are
different contracts. The previous documentation described a singleton managed
mapping fallback that was not implemented. In the actual runtime, a modern
daemon could accept a lower `register_ok` and subsequently process a direct
`workDir` invoke outside receipt, readiness, and native-serving admission.
Issue #55 forbids promotion with that implicit downgrade.

## Decision

Every managed or workspace-serving deployment requires exact protocol v3 and
all three capabilities on both registration frames:

- `workspace_readiness_v2`;
- `workspace_inventory_receipt_v2`;
- `workspace_bind_authority_verification_v1`.

The bot enforces this floor whenever its exact
`GJC_NATIVE_WORKSPACE_SERVING="1"` operator opt-in is active. The daemon
enforces it whenever native inventory verify mode or the exact serving opt-in
is active. A lower or incomplete peer is rejected with
`PROTOCOL_INCOMPATIBLE`, WebSocket policy close 1008, and no connection,
readiness, binding, lease, invoke, or SDK-session admission. Neither side
retries at a lower protocol, infers a default mapping, or manufactures identity
from `workDir`.

The v0/v1 parsers remain temporarily for isolated unmanaged `legacy-v0` local
use on the 0.3.x line. That path retains its existing source-byte, target
identity, and management-marker fences before every dispatch. It is not a #44
mapping fallback, a production rollback path, or managed-serving compatibility.
`managed-v1` and `legacy-retained` remain no-route without a live v3 receipt.

## Retirement

The repository maintainer is accountable for removal. The parser removal gate
is the earlier of:

1. the v0.4.0 release candidate; or
2. 2026-10-01.

Removal requires managed-v3 positive-serving E2E and matched-unit rollback
evidence. If those proofs are absent at the gate, v0.4.0 and Phase 4 promotion
remain blocked; the deadline does not reopen managed fallback or authorize an
implicit downgrade. Removal deletes v0/v1 registration and direct `workDir`
invoke acceptance rather than adding a compatibility shim.

## Evidence and consequences

Automated coverage must retain:

- omitted, v1, v2, and each missing-capability managed refusal;
- exact-v3 acceptance;
- no readiness or session work after daemon-side refusal;
- no bot connection/readiness/binding state after bot-side refusal;
- bounded unmanaged local compatibility and its source-fence failures.

A matched rollback uses a signed v3 bot, daemon, addon, and configuration unit
after receipts, leases, and sessions drain. Authority generations and durable
floors never move backward. Missing compatibility, rollback, or retirement
evidence is a hard no-promotion result.

This decision supersedes ADR 0004's register-time error taxonomy for managed
serving: a missing bind-authority capability is one way to miss the complete
managed floor and therefore returns `PROTOCOL_INCOMPATIBLE`. ADR 0004's
`BIND_AUTHORITY_VERIFICATION_REQUIRED` remains applicable only to an
off-mode/non-serving bot that negotiates receipt capability independently; the
daemon cannot reach that state because receipt advertisement requires verify
mode, which activates this ADR's complete floor.
