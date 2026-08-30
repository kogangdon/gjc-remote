# ADR 0004: Workspace bind-authority verification (replace daemon-side TOFU)

- **Status:** Approved and implemented (Slices 1-2 landed to `main`); residual hardening tracked in #200
- **Date:** 2026-08-30
- **Scope:** #179 daemon-side authenticity verification of managed `BIND_WORKSPACE`
- **Supersedes:** the daemon's prior trust-on-first-use (TOFU) adoption of the sender-supplied `authorityFingerprint`

## Context

Before #179 the daemon adopted a bind's `authorityFingerprint` on first use with
only monotonic-generation fencing. A peer that cleared the capability/registration
gates could assert an arbitrary fingerprint for a workspace and have the daemon
record it as authority. The served `workDir` was already resolved from the
daemon's own local inventory (never from the preimage), so this was an
authenticity gap rather than a direct arbitrary-serve, but the TOFU adoption left
the recorded authority unauthenticated.

## Decision

Every managed `BIND_WORKSPACE` frame carries the full `mapping` preimage, and the
daemon **independently verifies** it before adopting any authority.

- **Axis A1 (full-record preimage).** The bind carries the complete self-committed
  `mapping` record; the daemon recomputes its fingerprint via the shared
  `validateManagedMappingRecord` validator verbatim (no daemon-local reimplementation
  of the hash contract).
- **Axis B2 (verify the fingerprint against the record).** The daemon requires
  `mapping.mappingFingerprint === message.authorityFingerprint`, cross-checks the
  full identity tuple `{hostId, mappingId, mappingGeneration, workspaceGeneration,
  mappingVersion, sourcePlatform, workspaceId, fenceGeneration}` message-vs-mapping,
  enforces `hostId` ground truth on both the message and the mapping, and applies
  tier-2 lexical containment to `mapping.sourceRoot` when a native workspace root is
  configured.
- **Axis C1 (atomic flip).** The daemon-verify wiring and the bot-side preimage
  emission land as a single PR with two commits so `main` is never observed in a
  partially-applied state.

### Corrected implementation target (as-built)

The stage-03 plan named `acceptWorkspaceBinding` (the v2 non-receipt path) as the
TOFU site. An independent architect audit during Slice 2 proved this path is **dead
for managed binds**: a compliant bot's managed bind is receipt-shaped
(`RECEIPT_BIND_KEYS`), and `bindingEnabled` (bot) and `receiptCommitted` (daemon)
both derive from the same `isInventoryReceiptCapabilityGate` pair, so they cannot
diverge \u2014 every managed bind dispatches to `acceptReceiptBinding`. The verifier was
therefore wired as the first verifying statement of `acceptReceiptBinding` (only
the pre-existing fail-closed `receiptCommitted`/`hostId` guard precedes it), and made
**mapping-record-only**: the receipt authority commits to the mapping
(`authorityFingerprint === mapping.mappingFingerprint`); there is no `routeFingerprint`
in the receipt shape, so route-record verification is N/A for the receipt path. All
Principles, Findings, and the residual-trust model from the plan of record are
otherwise unchanged.

## Findings and resolutions (as implemented)

1. **Finding 1 (hard-floor, not degrade).** The
   `WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY` is a genuine bidirectional
   hard floor. A version mismatch does not silently negotiate down to an unverified
   handshake (which would reintroduce the exact TOFU gap): the daemon closes with
   `BIND_AUTHORITY_VERIFICATION_REQUIRED` and the bot answers `REGISTER_DENIED` with
   the same code. This is a deliberate deviation from the repo's prior
   check-then-degrade capability precedent \u2014 the repo's first check-then-refuse
   protocol gate. Non-binding v0/v2 peers are structurally unaffected.
2. **Finding 2 (no bypass).** The verifier is the first verifying statement of
   `acceptReceiptBinding` (after only the fail-closed `receiptCommitted`/`hostId`
   guard), ahead of the existing-binding dedup `BIND_OK` resend, the per-socket cap,
   `reserveReceiptAuthorityFloor`, and the receipt-path `adoptBinding` site. No
   early return reaches adoption without passing the verifier;
   `workspace-lease-registry.js` has zero diff and its fencing suite passes unmodified.
3. **Finding 3 (rescoped tier-2).** Tier-2 lexical containment is honestly scoped as
   configured-root-only additive hardening, not a default-deployment gap closure.
   Inventory resolution (served `workDir` always equals the daemon's own inventory,
   never the preimage) is credited as the actual load-bearing default-deployment
   mitigation.
4. **Finding 4 (green main).** Slice 2 is one PR with two commits; making the
   `mapping` preimage required migrated all affected fixtures to real recomputed
   fingerprints so `main` stayed continuously green across the merge.
5. **Finding 5 (authenticity != authorization).** The valid-envelope-wrong-intent
   residual is named as a standing, permanently-open residual owned by the
   `HOST_TOKEN` / channel-management authorization layer, not conflated with #179's
   authenticity guarantee and not a phase-1 deferral.

### Critic-folded corrections (Slice 2)

- **B1 (`fenceGeneration` in the cross-check tuple).** The daemon fences and
  supersedes on the top-level frame's `fenceGeneration`; an inflated verified frame
  would poison the receipt floor (`receiptWorkspaceFloors`), an availability DoS.
  `fenceGeneration` is therefore part of the message-vs-mapping cross-check.
- **B2 (green-main fixture migration).** Requiring `mapping` broke three
  preimage-less fixtures; each was migrated to construct a mapping whose recomputed
  `mappingFingerprint` equals the asserted `authorityFingerprint`.

## Reject-code taxonomy

`BIND_AUTHORITY_HASH_MISMATCH`, `BIND_AUTHORITY_HOSTID_MISMATCH`,
`BIND_AUTHORITY_CONTAINMENT_ESCAPE`, `BIND_AUTHORITY_VERIFICATION_REQUIRED`. On a
verification failure the daemon fails closed (returns false), logs the code, and
dispatches `close(1008, <BIND_AUTHORITY_* code>)`. Shape, guard, capacity,
fencing, and lease failures retain the generic
`close(1008, "invalid workspace binding")` reason.

## Residual trust

The six-item residual-trust model is documented in
[`SECURITY.md`](../../SECURITY.md#residual-trust-model-honestly-scoped): the
configured-root-only tier-2 claim, inventory-resolution as the primary
default-deployment mitigation, the legacy-workDir hash+hostId-only residual, the
absent no-follow (tier-3) reparse-point residual, the `authorityEpoch`/generation
channel-trust residual, and the permanently-out-of-scope valid-envelope-wrong-intent
residual.

Issue **#200** adds defense-in-depth verification to the v2
`acceptWorkspaceBinding` path and code-only close-reason observability. A
no-follow containment tier, trusted `containerRoot` ground truth, and
`authorityEpoch` authenticity remain explicitly out of this decision's closed
scope because the current daemon has no operation-time filesystem handle or
trusted container/epoch authority from which to establish them.

## References

- Issue: #179 (this change); follow-up #200.
- Plan of record: `.gjc/.../plans/ralplan/1d909153-9d26-4692-8185-eac301bc27cf/stage-03-revision.md` (Architect CLEAR/APPROVE + Critic OKAY consensus).
- Independent review lanes: Slice 1 architect approve; Slice 2 path audit (FINDING-CONFIRMED), corrected-scope critic (REWORK -> B1/B2 folded), and pre-merge architect review (APPROVE-WITH-FOLLOWUP -> #200).
- Merged PRs: #199 (Slice 1), #201 (Slice 2).
- Related contract: [`docs/adr/0003-management-mapping-envelope.md`](0003-management-mapping-envelope.md), [`docs/daemon-workspace-verification.md`](../daemon-workspace-verification.md).
