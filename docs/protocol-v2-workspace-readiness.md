# Protocol v2 workspace and readiness contract

Issue #43 defines the daemon-facing invariants. #44 remains the source of truth for the versioned
route envelope, mapping registry, authorization, audit, idempotency, and token rotation.

## Atomic negotiation

Current v0/v1 peers continue to use existing workDir-only frames. A socket enables the extension
only when negotiated version is at least 2 and both register advertisements and the valid response
contain `workspace_readiness_v2`. Until that gate commits, ingress rejects and egress never emits
workspaceId, mapping identity, or readiness fields. A replacement socket starts disabled.
When a release adds a closed-set protocol error code, deploy the bot before its daemons: an older
bot intentionally rejects a newer unknown readiness code, while a newer bot continues to accept
the older daemon's still-supported codes.

Protocol v3 adds the separately negotiated `workspace_inventory_receipt_v2` capability. Receipt
frames are enabled only when both peers negotiate version 3 and advertise both that capability and
`workspace_readiness_v2`. Missing either capability is incompatible for receipt-required managed
routes; it never falls back to authority-bearing inventory or changes the exact v2 frame shapes.
`GJC_NATIVE_INVENTORY_MODE=off` withholds the receipt capability, sends no v3 bind/receipt/unbind
frames, and must not create a reconnect loop. Existing v0/v1 and readiness-v2 sockets retain their
current behavior.

The path-free v3 bind carries one immutable #44 authority descriptor:

```text
{ type: "bind_workspace", bindingId, authorityEpoch, fenceGeneration, hostId,
  mappingId, mappingGeneration, mappingVersion, workspaceId, workspaceGeneration,
  sourcePlatform, authorityFingerprint }
```

`authorityFingerprint` is the verified mapping fingerprint. Per-channel `routeFingerprint`,
`workDir`, and bot-claimed inventory fields are forbidden. A successful daemon observation returns:

```text
{ type: "bind_ok", bindingId, inventoryGeneration, inventoryFingerprint,
  bindingFingerprint }
```

`bindingFingerprint` is SHA-256 over canonical JSON
`{schemaVersion:1,authority:<descriptor>,inventory:{inventoryGeneration,inventoryFingerprint}}`.
`bindingId` is socket-local correlation and is not hashed. Both pending and receipt-bearing
bindings retire through exact `{type:"unbind_workspace",bindingId}` /
`{type:"unbind_ok",bindingId}` frames; requiring a receipt would make negative or pending binds
impossible to remove.

The negotiated v2 invoke is bounded and carries the route identity:

```text
{ type: "invoke", requestId, bindingId?, mappingId, mappingGeneration, workspaceGeneration,
  mappingVersion, workspaceId?, command }
```

Managed v2 invokes are path-free. A `workDir` or any other path-bearing field is rejected even when
the remaining identity tuple is valid. Missing, foreign, stale, or mismatched identity is a stable
rejection. Current v0/v1 peers retain the bounded workDir-only shape.

The daemon may promote a bound workspace to `ready` only after its local inventory independently
matches host, workspace, source platform, and the daemon-observed inventory generation/fingerprint.
Mapping identity and generations remain in the authenticated #44 descriptor; route fingerprints
remain bot-local. The inventory's local `workDir` and root/storage identities are capability
evidence and are never sent as route authority. Missing or drifted inventory remains non-ready.

## Mapping and legacy fallback

A route references an opaque `mappingId`, `mappingGeneration`, `workspaceGeneration`,
`mappingVersion`, `sourcePlatform`,
and optionally `workspaceId` or legacy `workDir`. #44 owns the exact envelope and persistence. The
daemon validates host ownership, source root/share/volume identity, generation, canonical equality,
case policy, and containment. Workspace IDs are bounded safe-alphabet tokens and are looked up in
authenticated state before any path interpolation.
POSIX, Windows drive, and UNC mappings are explicit; no slash heuristic or bot-side filesystem
stat is allowed. v0/v1 Docker fallback is permitted only when exactly one immutable host mapping
exists, the #44 route mapping equals that host's immutable default, and that default identity and
generation remain unchanged while the peer is connected. Multiple, missing, foreign, unknown-
platform, or changed mappings return `MAPPING_ID_REQUIRED` or `WORKSPACE_MAPPING_CHANGED`; old
peers never receive v2 frames.
A legacy socket records the authenticated route mapping fingerprint and generation at registration.
If #44 changes that mapping, mapping version, default identity, or generation, the socket is
invalidated and must re-register; it is never silently remapped. A v2 mappingVersion change must
bump generation or be rejected as stale.

## Readiness frame and freshness

The daemon sends v2 readiness only after static preflight and an actual SDK/model-profile check
before first work:

```text
{ type: "readiness", socketGeneration, revision, observedAt, ttlMs?,
  bindingId?, workspaceId?, workspaceGeneration?, expiresAt?,
  status: { connection, runtime, providerAuth, modelProfile, workspace },
  lastError?: { code, at, remediation } }
```

The five dimensions are independent. Connected means only that registration is current; it does
not imply provider, model, runtime, or workspace readiness.
Readiness is bound to the selected workspace generation. Reset or restore invalidates the
candidate's prior readiness before mutation and must publish a fresh five-dimension probe for the
new generation before `ready` can be rendered. An old readiness frame cannot keep a new generation
ready.

HostRegistry is the freshness authority:
- record local wall-clock `receivedAt` for diagnostics and a monotonic receipt time;
- compute and compare a monotonic expiry deadline at reception using
  `min(ttlMs, READINESS_MAX_TTL_MS)`;
- use a bounded default when TTL is absent (initial design value: 60 seconds);
- treat sender `expiresAt` and remote `observedAt` as diagnostics, never as expiry authority;
- reject invalid/out-of-range TTL, observations outside the bounded receiver-time skew window,
  malformed timestamps, duplicate/lower revisions, old socket generations, and replayed/backward
  timestamps;
- accept `observedAt` only as diagnostic data within the bounded receiver-time window; it never
  changes the receiver's monotonic expiry deadline. A future value inside the window is accepted
  for diagnostics, while a value outside the window is rejected as `READINESS_TIMESTAMP_INVALID`.
- expire per-workspace state using a timer or lazy check; expired/unknown is never ready;
- clear readiness on socket replacement.

The initial remote skew bound is five minutes; exact min/max values and clock implementation are
implementation gates. Aggregate precedence is deterministic: `offline`, `incompatible`,
`degraded` only when a selected/current workspace previously known ready expires or has a readiness
error, `connected-not-ready` when registration is current without a prior-ready expiry, then
`ready` only for a current, unexpired selected workspace with all five dimensions ready.

Receipt binding readiness has an exact 10-second TTL. Pending or verified-negative frames carry
only `bindingId`, workspace identity, `status.workspace:"unknown"`, and one exact error; receipt
fields are forbidden. Positive frames carry `bindingFingerprint`, `inventoryGeneration`, and
`inventoryFingerprint`, have no `lastError`, and may report workspace `unknown` until the current
probe completes. Workspace `ready` requires all five dimensions ready. Positive readiness received
before its matching `bind_ok` is held only until the bind deadline and never renders ready.
Malformed, foreign, replayed, unknown-key, partial-receipt, or mismatched frames close the socket
with policy violation semantics and invalidate its cache.

## Projection and errors

`/hosts` exposes only opaque IDs, current aggregate, per-dimension state, local `lastErrorAt`,
revision, socket generation, and bounded diagnostic timestamps. It never exposes native/container
paths, tokens, credential values/paths, raw URLs, prompts, stacks, or control characters.

Stable classes include:
- registration/transport: `AUTH_REJECTED`, `PROTOCOL_INCOMPATIBLE`, `CONNECTION_LOST`, `HEARTBEAT_TIMEOUT`;
- provider/profile: `PROVIDER_MISSING`, `PROVIDER_INVALID`, `PROVIDER_EXPIRED`,
  `PROVIDER_UNAVAILABLE`, `MODEL_PROFILE_MISSING`, `MODEL_PROFILE_INVALID`;
- runtime/config: `RUNTIME_INCOMPATIBLE`, `CONFIG_INVALID`, `UNKNOWN_RUNTIME`;
- workspace/mapping/lease: `WORKSPACE_ROOT_ESCAPE`, `CONTAINMENT_UNSUPPORTED`,
  `INVENTORY_PENDING`, `INVENTORY_INVALID`, `INVENTORY_ACCESS_DENIED`, `INVENTORY_STALE`,
  `INVENTORY_MANUAL_CLEANUP`, `INVENTORY_IO_FAILED`, `WORKSPACE_NOT_FOUND`,
  `MAPPING_ID_REQUIRED`, `WORKSPACE_MAPPING_CHANGED`, `WORKSPACE_BUSY`,
  `WORKSPACE_GENERATION_STALE`, `LEASE_CONFLICT`;
- Git: `GIT_GRAPH_INCOMPLETE`, `GIT_AUTH_FAILED`;
- readiness: `READINESS_TIMESTAMP_INVALID`, `READINESS_REPLAYED`, `READINESS_EXPIRED`;
- resource/session: `RESOURCE_EXHAUSTED`, `SESSION_LIMIT`, `SESSION_CREATE_TIMEOUT`,
  `SHUTDOWN_TIMEOUT`;
- fatal: `DAEMON_FATAL`, `UNHANDLED_REJECTION`, `UNCAUGHT_EXCEPTION`.
The validator rejects unknown dimension values, oversized frame/ID fields, unsafe IDs, and malformed
status before state mutation. An accepted binding awaiting verified local inventory reports
`INVENTORY_PENDING` with retry-later remediation; a verified absence remains
`WORKSPACE_NOT_FOUND`. Stable workspace outcomes also include `MAPPING_GENERATION_STALE`; Git
transport failures use `GIT_NETWORK_FAILED`, while authentication
uses `GIT_AUTH_FAILED`. These codes have path-free rendering, distinct retry/audit semantics, and
never bypass containment or readiness.

Sanitize before formatting. Unknown or hostile errors map to `UNKNOWN_RUNTIME`; bounded stable
remediation is retained. Error taxonomy does not authorize bypassing containment or readiness.

## v3 inventory receipt capability (as-built)

This section records the as-built shape of the protocol v3 `workspace_inventory_receipt_v2`
capability against the current daemon/bot implementation, without altering the contract prose
above.

Capability advertisement is additive negotiation, not a mixed ABI or compatibility shim: the
daemon computes `inventoryReceiptAdvertised` only when `GJC_NATIVE_INVENTORY_MODE=verify` AND
`GJC_READINESS_V2=1` (readinessV2Advertised) AND the configured inventory provider reports
`receiptCapable === true`. Only when all three hold does the daemon set `DAEMON_PROTOCOL_VERSION` to
v3 and append `workspace_inventory_receipt_v2` to its advertised capabilities. `off` mode never
advertises the receipt capability and a daemon in `off` mode advertises at most v2.

The receipt binding lifecycle rides the existing v3 bind frames: the bot sends
`bind_workspace`, arming a 10-second `BINDING_DEADLINE`. A daemon observation that matches host,
workspace, source platform, and inventory returns `bind_ok` carrying the positive proof
`{inventoryGeneration, inventoryFingerprint, bindingFingerprint}`. A non-matching or not-yet-ready
observation yields negative readiness (surfaced by the bot-side `bind.negative` observability
event) or `INVENTORY_PENDING` instead. A previously bound receipt that drifts, or a binding whose
host disconnects, is invalidated (surfaced by the bot-side `receipt.invalidate` observability
event, phase `drift` or `offline`) rather than silently kept alive. Every issued
receipt is subject to the shared `INVENTORY_RECEIPT_TTL_MS` of 10000ms; the bot enforces this TTL
per binding against its own monotonic clock, independent of the 10-second `BINDING_DEADLINE` that
bounds the bind round-trip itself.

Off vs verify behavior matrix, as observed:
- `off` (default): no v3 receipt advertisement is possible; a managed-authority route attempted
  without a bound v3 binding returns `PROTOCOL_INCOMPATIBLE`; a v2 readiness route with native
  serving off returns `RUNTIME_INCOMPATIBLE`.
- `verify` (plus readinessV2 and a receiptCapable provider): the daemon issues a positive receipt
  proof and `bind_ok` as above, but invoking on that proven receipt still returns
  `RUNTIME_INCOMPATIBLE`, because native workspace serving is hard-disabled at the invoke-time
  serving gate independent of receipt state.
`PROTOCOL_INCOMPATIBLE` and `RUNTIME_INCOMPATIBLE` are both non-retryable, action `contact_admin`,
consistent with the error taxonomy above.

`bind_ok` is an acknowledgement and capability receipt only; it is never route authority. #44's
mapping envelope remains the sole route authority for every managed and legacy path described in
this document; the inventory receipt gates only workspace readiness promotion.

Native workspace serving itself stays disabled in this build (a fixed daemon constant, no
env/config override), and the production wiring that constructs a real native inventory reader at
daemon boot has not landed yet. As implemented today, the `workspace_inventory_receipt_v2` capability
and its receipt bindings are reachable in production only when the daemon is started under test
injection (`GJC_READINESS_TEST_INJECTION=1`); this section documents the capability contract as
implemented scaffolding, not a claim that verify-mode receipts are live in an unmodified production
deployment.

## Ownership and migration

#43 owns this daemon-facing identity/readiness contract. #44 owns the exact `channels.json`
envelope and control-plane mutation API; #42 owns deployment evidence; #45 owns bot image guidance.
Legacy direct maps are migration input only. Unknown versions and malformed routes fail closed.
Discord permissions authorize Discord resources; a separate control-plane identity authorizes host,
mapping, workspace, and route binding, with both gates required for combined actions.
