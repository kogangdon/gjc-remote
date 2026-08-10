# Issue #62 SDK isolation probe

Status: focused real-SDK probe for the approved issue #62 boundary. The probe checks the installed daemon dependency `@gajae-code/coding-agent` **0.12.21** with Bun **1.3.14**. Each receipt carries separate `approvedBaseCommit` and `sourceCommit` fields; source may be a descendant of the approved base. A deterministic SHA-256 digest covers these four files, in this exact order: `daemon/test-fixtures/sdk-isolation-probe.mjs`, `daemon/test/sdk-isolation-probe.test.js`, `docs/verification/issue62-evidence.md`, `CONTEXT.md`.
The focused wrapper requires Node **>=26**; its `nodeWrapperVersion` field records the actual Node runner separately from Bun's compatibility `nodeVersion` field. The source digest is emitted in the receipt rather than copied here, avoiding a self-referential evidence file.

## Sanitized receipts

The Node wrapper is the sole durable receipt writer. It removes any stale output, validates the final bounded child receipt, applies path/secret/URL redaction, and atomically writes only these ignored files:

- [A→B sanitized receipt](../../artifacts/issue62-A-B.json)
- [B→A sanitized receipt](../../artifacts/issue62-B-A.json)

The Bun fixture writes no repository artifact and emits a bounded structured receipt to stdout only. Raw stdout/stderr and unredacted temporary paths are never persisted. The wrapper owns the final files; this document is the durable reader/reference. Receipts are evidence attachments, not source-controlled proof by themselves.

## Boundary and commands

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

The probe measures current SDK behavior; it does not repair process-global capability/model-provider state or claim full isolation. Preserve the existing requirement to rerun this focused probe after every SDK bump before changing the caveat. A reproducible global direction is evidence for the current upstream/architecture boundary, not a local workaround authorization.
