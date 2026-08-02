# Protocol v2 workspace and readiness contract

Issue #43 defines the daemon-facing invariants. #44 remains the source of truth for the versioned
route envelope, mapping registry, authorization, audit, idempotency, and token rotation.

## Atomic negotiation

Current v0/v1 peers continue to use existing workDir-only frames. A socket enables the extension
only when negotiated version is at least 2 and both register advertisements and the valid response
contain `workspace_readiness_v2`. Until that gate commits, ingress rejects and egress never emits
workspaceId, mapping identity, or readiness fields. A replacement socket starts disabled.

The negotiated v2 invoke is bounded and carries the route identity:

```text
{ type: "invoke", requestId, mappingId, mappingGeneration, mappingVersion,
  workspaceId?, workDir?, command }
```

If both `workspaceId` and `workDir` are present they must resolve to identical mapping and
workspace generation. Missing, foreign, stale, or mismatched identity is a stable rejection.

## Mapping and legacy fallback

A route references an opaque `mappingId`, `mappingGeneration`, `mappingVersion`, `sourcePlatform`,
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
  workspaceId?, workspaceGeneration?, status: { connection, runtime, providerAuth,
  modelProfile, workspace }, lastError?: { code, at, remediation } }
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
  `MAPPING_ID_REQUIRED`, `WORKSPACE_MAPPING_CHANGED`, `WORKSPACE_BUSY`,
  `WORKSPACE_GENERATION_STALE`, `LEASE_CONFLICT`;
- Git: `GIT_GRAPH_INCOMPLETE`, `GIT_AUTH_FAILED`;
- readiness: `READINESS_TIMESTAMP_INVALID`, `READINESS_REPLAYED`, `READINESS_EXPIRED`;
- resource/session: `RESOURCE_EXHAUSTED`, `SESSION_LIMIT`, `SESSION_CREATE_TIMEOUT`,
  `SHUTDOWN_TIMEOUT`;
- fatal: `DAEMON_FATAL`, `UNHANDLED_REJECTION`, `UNCAUGHT_EXCEPTION`.
The validator rejects unknown dimension values, oversized frame/ID fields, unsafe IDs, and malformed
status before state mutation. Stable workspace outcomes include `WORKSPACE_NOT_FOUND` and
`MAPPING_GENERATION_STALE`; Git transport failures use `GIT_NETWORK_FAILED`, while authentication
uses `GIT_AUTH_FAILED`. These codes have path-free rendering, distinct retry/audit semantics, and
never bypass containment or readiness.

Sanitize before formatting. Unknown or hostile errors map to `UNKNOWN_RUNTIME`; bounded stable
remediation is retained. Error taxonomy does not authorize bypassing containment or readiness.

## Ownership and migration

#43 owns this daemon-facing identity/readiness contract. #44 owns the exact `channels.json`
envelope and control-plane mutation API; #42 owns deployment evidence; #45 owns bot image guidance.
Legacy direct maps are migration input only. Unknown versions and malformed routes fail closed.
Discord permissions authorize Discord resources; a separate control-plane identity authorizes host,
mapping, workspace, and route binding, with both gates required for combined actions.
