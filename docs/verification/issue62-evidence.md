# Issue #62 SDK isolation probe

Status: the focused real-SDK probe passes for the installed daemon
dependency `@gajae-code/coding-agent` **0.16.6** with Bun **1.4.0 or newer**.
The current parent-run wrapper passes all three tests on Windows x64 with
Bun 1.4.0 and Node wrapper 26.7.0, including both creation orders and zero
network attempts. This is scoped policy evidence, not tenant isolation.
Each receipt carries separate
`approvedBaseCommit` and `sourceCommit` fields; source may be a descendant of
the approved base. The approved original base remains
`a5bb530bd5a063b6571a7ba963e938bb6f97616f`. A deterministic SHA-256 digest
covers these four files, in this exact order:
`daemon/test-fixtures/sdk-isolation-probe.mjs`,
`daemon/test/sdk-isolation-probe.test.js`,
`docs/verification/issue62-evidence.md`, `CONTEXT.md`.
The focused wrapper requires Node **>=26**; its `nodeWrapperVersion` field records the actual Node runner separately from Bun's compatibility `nodeVersion` field. The source digest is emitted in the receipt rather than copied here, avoiding a self-referential evidence file.

## Sanitized receipts

The Node wrapper is the sole durable receipt writer. It removes any stale output, validates the final bounded child receipt, applies path/secret/URL redaction, and atomically writes only these ignored files:

- [A→B sanitized receipt](../../artifacts/issue62-A-B.json)
- [B→A sanitized receipt](../../artifacts/issue62-B-A.json)

The Bun fixture writes no repository artifact and emits a bounded structured receipt to stdout only. Raw stdout/stderr and unredacted temporary paths are never persisted. The wrapper owns the final files; this document is the durable reader/reference. Receipts are evidence attachments, not source-controlled proof by themselves.

These ignored mutable paths contain current-run receipts but are not permanent
proof of any future checkout. A current receipt must independently report `sdkVersionExpected`,
`sdkVersionObserved`, `daemonDependencyVersion`, and `lockfileVersionEvidence`
as `0.16.6`, and its ordered working-tree digest must match the four live files.
The wrapper removes each stale order-specific output before running that order.

## SDK 0.16.6 observed probe boundary

The installed 0.16.6 package source and exports map were inspected before
retargeting the probe. The scoped surfaces it exercises remain available:

- `@gajae-code/coding-agent/sdk` exports `createAgentSession` and `Settings`;
  omitted settings still select `Settings.loadForScope({ cwd, agentDir })`.
- `session/session-manager`, `session/auth-storage`,
  `config/model-registry`, `config/model-resolver`, and `capability` remain
  exported package subpaths with the constructors and functions used by the
  fixture.
- `createAgentSession` still accepts the fixture's explicit `SessionManager`
  and startup-disable options. SDK-owned sessions dispose their scoped model
  registry, empty auth storage, settings, and session manager; the C oracle
  retains explicit ownership of its registry, empty auth storage, and settings.

The source inspection above is distinct from execution evidence. The executed
probe passes both creation orders, divergent per-workDir settings/model policy,
capability lookups, the no-model/no-session C negative, fail-closed network and
host-environment guards, bounded redaction, and explicit cleanup accounting.
Canonical `createAgentSession` and `SessionManager` imports are exercised by
the real factory path, not inferred merely from package declarations.

The separate queued-follow-up liveness blocker also remains unresolved in this
published package. Upstream issue
[`Yeachan-Heo/gajae-code#5351`](https://github.com/Yeachan-Heo/gajae-code/issues/5351)
was closed after
[#5371](https://github.com/Yeachan-Heo/gajae-code/pull/5371) was squash-merged
to upstream `dev` on 2026-09-07. That does not put the fix in the already
published 0.16.6 package. Installed 0.16.6 has
`#scheduleNonAdmittedSteerContinuation()`, but `#queueFollowUp()` still only
attempts the idle-gated `#scheduleQueuedFollowUpContinuation()` on the
empty-queue transition; it has no
`#scheduleNonAdmittedQueuedContinuation()` from #5371. The 0.16.6 changelog
lists only the smoke-test timing and SDK lifecycle-replay fixes for that
release. Issue closure on `dev` is therefore not release inclusion, and this
isolation probe does not substitute for the separate real contract oracle.

## Historical SDK 0.16.4 observed boundary

The following dated result belongs to the prior 0.16.4 dependency. It remains
historical evidence and is not mechanically relabeled as a 0.16.6 result.

On 2026-09-06, `node --test daemon/test/sdk-isolation-probe.test.js` passed
all three tests on native Windows x64, Bun 1.4.0, Node wrapper v26.7.0.
Both A→B and B→A runs observed:

- SDK-owned `Settings.loadForScope` instances and policies are distinct and
  remain stable after sibling creation. No global `Settings.init` occurs.
- A and B retain their own active model and available canonical resolution.
- Explicit-settings and registered-cwd capability reads select the correct
  per-workDir provider; the disabled sibling loader is not invoked.
- An **unregistered** cwd capability lookup and global introspection observe
  `LAST_CREATED`. These APIs have no session scope in this test; that observation
  is not evidence that the scoped A/B lookup leaks.
- Unfiltered canonical model lookup selects provider A in both scopes, while
  available-model lookup respects A/B policy. Consumers must use the appropriate
  availability-aware API, not treat unfiltered catalog data as authorization.
- C has no permitted model and constructs no session; no prompt is submitted.
- Zero fetch/preconnect calls pass the fixture guard. Startup model-registry
  polling is disabled before SDK import and unauthenticated discovery providers
  are disabled in fixture settings. This does not claim network-free production
  startup or exercise provider credentials, profile activation, or live transport.

The child records SDK-owned session/settings cleanup and explicit fixture-owned
store cleanup. The Node wrapper owns its temporary root and removes it only
after the child exits, recording the exact cleanup boundary. Both runs observed
successful resource cleanup and first-attempt parent removal. A prior standalone
child removal returned Windows `EPERM`; post-exit removal does not identify
which process-owned handle or store caused it, and is not reported as child
cleanup. Standalone diagnostic runs retain their own fail-closed cleanup path.

`sourceIdentity.runtimeHead` names Git HEAD, not uncommitted bytes. The ordered
working-tree digest identifies only the four listed files. Neither field
promotes a dirty checkout into release provenance. Artifact receipts include
actual timestamps and digests; these are regenerated after source edits.

The records below are the **historical 0.12.21 baseline**, not the current
contents of the mutable receipt paths above.

## Historical 0.12.21 boundary and commands

```text
node --test daemon/test/sdk-isolation-probe.test.js
bun daemon/test-fixtures/sdk-isolation-probe.mjs --order=A,B --json
bun daemon/test-fixtures/sdk-isolation-probe.mjs --order=B,A --json
```
The wrapper spawns the fixture with the exact argv
`[fixture, "--order=A,B", "--json"]` and then
`[fixture, "--order=B,A", "--json"]`; every child receipt records its exact
Bun argv, full command string, and parsed order command. The direct Bun runs
are diagnostics only: they emit JSON to stdout and never write repository
artifacts.

The fixture is test harness infrastructure, not a product subprocess or ACP transport. It bootstraps one global `Settings.init`, derives A/B/C with `cloneForCwd`, creates real `SessionManager`/`createAgentSession`/`AgentSession`/`SdkSession`/`SessionPool` lifecycles, and uses fixture-owned temporary workDirs, model configuration, and empty auth stores. Profile activation and live provider transport are intentionally outside this custom-factory oracle.

### Sanitized observed result matrices

The following values are copied from the sanitized A→B and B→A receipts. Paths
are shown only as `<fixture-root>` in the durable artifacts.

| order | A active model | B active model | canonical seed | after first | after second/final | resolver direction | provider-order direction |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A→B | `issue62-provider-a/issue62-model-a` | `issue62-provider-b/issue62-model-b` | A | A | B / B | `LAST_CREATED` | `LAST_CREATED` |
| B→A | `issue62-provider-a/issue62-model-a` | `issue62-provider-b/issue62-model-b` | A | B | A / A | `LAST_CREATED` | `LAST_CREATED` |

Each canonical result is concrete: `resolvedProvider` is
`issue62-provider-a` or `issue62-provider-b`, and `resolvedSelector` is the
corresponding fixture selector. Missing or `UNKNOWN` values fail the oracle;
the classification is not a substitute for the provider-valued observations.

### Policies and counters

| scope | disabled providers (ordered as configured) | default / planner | provider order |
| --- | --- | --- | --- |
| A | `issue62-provider-b`, `issue62-capability-b`, `ollama`, `llama.cpp`, `lm-studio` | `issue62-provider-a/issue62-model-a` / same | A, B |
| B | `issue62-provider-a`, `issue62-capability-a`, `ollama`, `llama.cpp`, `lm-studio` | `issue62-provider-b/issue62-model-b` / same | B, A |
| C | `ollama`, `llama.cpp`, `lm-studio` | `issue62-no-such-provider/issue62-no-such-model` / same | A, B |

The enabled-model allow-list for A and B is exactly the two fixture selectors.
Synthetic A/B providers remain enabled for C; only the local built-ins are
disabled. C's nonmatching enabled-model allow-list therefore produces zero
candidates before session construction.
Capability counters are identical in both orders: A `2`, B `2`, controlled
throwing provider `4`. Reads return one item with provider-specific `_source`
metadata; the sibling disabled loader has zero invocations.

### Global seed

Both order runs start from the same sanitized global seed: disabled providers
`llama.cpp`, `lm-studio`, and `ollama`; enabled models
`issue62-provider-a/issue62-model-a` and `issue62-provider-b/issue62-model-b`;
default and planner model A; provider order A, B; and
`startup.networkPrewarm: false`. The receipt records the fixture cwd and
per-scope policy snapshots.
### Negatives and coverage boundary

- C resolves zero allowed models before any C session construction
  (`cPreSessionCandidates: 0`), and no prompt is issued.
- `loadCapability("issue62-unknown-capability", ...)` rejects with the exact
  SDK error `Error: Unknown capability: "issue62-unknown-capability"` and
  `code: null` (the SDK does not attach an error code); the requested id is
  recorded and compared exactly.
- The controlled throwing provider warning is required, as are disabled-loader
  non-invocation, `modelFallback: false`, and zero network/preconnect events.
- Auth coverage is limited to closing empty fixture-owned `AuthStorage` stores.
  Broker state, profile activation, credentials, and live provider transport are
  not exercised and are explicitly not claimed.

### Timestamps, cleanup, and blocked environments

| order | startedAt/finishedAt | pool shutdown | stores closed | fixture removed | leaks |
| --- | --- | --- | --- | --- | --- |
| A→B | recorded in the sanitized receipt (`startedAt`/`finishedAt`) | true | true | true | `[]` |
| B→A | recorded in the sanitized receipt (`startedAt`/`finishedAt`) | true | true | true | `[]` |

Cleanup now records individual session-disposal and five store-close outcomes
(A auth, B auth, C auth, Settings storage, and model cache); `storesClosed` and
`leaks` are derived from those outcomes, not constants. Raw disposal is bounded
and any timeout/rejection fails the probe.

A direct Bun invocation from a shell containing a credential-bearing environment
was rejected before fixture setup with `ENVIRONMENT_BLOCKED`; the variable name
and value are redacted in the emitted failure receipt. The Node wrapper's stable
environment intentionally excludes those variables. The focused wrapper passed
both A→B and B→A orders on this workstation with Node **v26.5.1**; blocked
environment results are failures, never passes.

### Version and provenance

Observed runtime values are Bun **1.3.14**, Node wrapper **v26.5.1**, Windows
`win32/x64`, SDK and daemon dependency **0.12.21**, and lockfile evidence
**0.12.21**. The approved base is
`a5bb530bd5a063b6571a7ba963e938bb6f97616f`; `sourceCommit` is recorded
separately in each receipt and is not required to equal that base. The source
digest is emitted in each receipt rather than copied here, avoiding a
self-referential evidence file.
A and B use distinct disabled-provider sets and role selectors, the shared
two-selector enabled-model allow-list, and opposite provider orders. Two
equivalent fixture variants map to `issue62-canonical-model`; each receipt
records concrete provider-valued canonical results and classifies the observed
global direction rather than assuming last-writer behavior. Capability reads use
explicit settings and cwd fallback, include valid `_source` metadata and
invocation counters, and exercise disabled-loader, warning, and exact
unknown-capability negatives.

C uses a separate nonmatching `enabledModels` selector and records
`resolveAllowedModels(...) === []` before any C session construction. C never
prompts. Any active fixture, bundled, or host model is classified as
`MODEL_FALLBACK` and fails the probe. `startup.networkPrewarm` is asserted false
on the global settings and every clone; a fixture-only
`fetch.preconnect`/network guard fails closed on unexpected access.

Each child holds two distinct live sessions during concurrent reads. It bounds
raw session disposal, closes all owned auth stores/model-cache/settings storage,
verifies no pending pool operations, and removes its temporary root. Version,
lockfile, platform, exact argv/order command, timestamps, cleanup outcomes, and
failure fields are included in each bounded receipt. The auth stores are empty
fixture stores only; no broker or credential claim is made.

## Residual caveat

When executed against matching version and provenance, the probe measures the
installed SDK behavior; it does not repair process-global
capability/model-provider state or claim full isolation. Current 0.16.6
receipts do not remove those limits. Preserve the requirement to rerun this focused
probe after every SDK bump before changing the caveat. A reproducible global
direction is evidence only for the exact observed upstream/architecture
boundary, not a local workaround authorization.
