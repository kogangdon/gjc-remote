# Issue #62 SDK isolation probe

Status: **SDK-ONLY MAIN-BASED IMPLEMENTATION** targeting official, unpatched
`@gajae-code/coding-agent`, `@gajae-code/agent-core` and `@gajae-code/ai`
**0.18.12**. This tree starts from main
`116b60caf0ce6361eb3f17d1b9cf3a17e22e92cb` on
`feat/sdk-0.18.12-upgrade`. **Bounded actual parent verification and one
separately authorized Windows provider smoke are recorded below.** This
documentation refresh ran no tests, gates, builds, lint, formatters or
provider/auth calls. No prior combined-worktree result, count, receipt or
provider smoke qualifies this SDK-only main-based tree. This is not release,
native-repair, deployment or tenant-isolation qualification.

## Current parent observations

The four parent receipts were read directly: `artifacts/sdk-first-0.18.12-focused.json`,
`artifacts/sdk-first-0.18.12-workspace.json`,
`artifacts/sdk-first-0.18.12-wsl-final.json` and
`artifacts/sdk-first-0.18.12-provider-smoke.json` (all local, ignored/unshipped).
They report actual SDK-only execution, not old combined-tree results:

- Windows Node v26.7.0 focused: **318 tests, 318 pass, 0 fail, 0 skips**, exit 0.
  Includes adapter/session/lifecycle, real SDK contract and isolation probes,
  Docker/docs contracts and bounded service SDK/release-builder tests. Those
  source/fixture checks do not qualify native services or deployment.
- Windows bounded workspace: **2689 tests, 2685 pass, 0 fail, 4 skips**, exit 0.
  Command: `node --test --test-reporter=tap --test-concurrency=4` with the exact
  `--test-skip-pattern` alternatives below. This was **not unrestricted
  `npm test`**. Skips are not passes; nine historical authority exclusions are
  distinct from, and not represented solely by, the four reported skips.
- Isolated Linux WSL snapshot: **233 tests, 233 pass, 0 fail, 0 skips**, exit 0,
  Node v26.7.0/Bun 1.4.2; source and snapshot unchanged during execution,
  **no actual provider calls**, no native repairs.
- Exactly one separately user-authorized native Windows provider smoke:
  **PASS**, existing `codex-eco` profile via child-environment-only override,
  three exact `SMOKE_OK` responses in **A-B-A** order, heartbeat and three
  successful invoke-terminal telemetry assertions, exit 0, ephemeral relay
  port 12219 free after exit. No optional model query, wrapper retry or
  persistent profile write. Same-profile continuity is not profile/tenant
  isolation, a generic disconnect repair or a fix for #247.

Exact historical authority exclusion alternatives (joined with `|` in the
workspace receipt's single `--test-skip-pattern` argument):

1. `inventory ACL verification atomically`
2. `Windows verified handle removal unlinks`
3. `Windows management-auth native ACL creation`
4. `verified native addon enforces retained-handle`
5. `POSIX principal access rejects`
6. `POSIX named ACL groups match`
7. `Win32 legacy no-replace creation`
8. `current management or system caller can reapply`
9. `opted-in Windows hosted runner provisions`

Canonical SDK imports are covered by actual real-SDK probes in these bounded
runs, not an independent all-platform import qualification. The real Ask abort
oracle asserts exactly one event-level SDK `cancelled` terminal, rejected owned
prompt and no continuation provider call after unwind; it never fabricates a
terminal. It allows either standalone settlement inside 250 ms or settlement
only after a late-answer unwind. The boolean branch is **not retained in the
aggregate parent receipt**, so a passing aggregate does not prove standalone
bounded interruption. Active daemon cancellation still returns only
nonterminal `cancellation_pending`; active `steer`/`follow_up` remain fail-closed.

Windows local order outputs `artifacts/issue62-A-B.json` and
`artifacts/issue62-B-A.json` (unshipped) independently report expected/observed,
daemon and lock versions 0.18.12, agent-core/ai declared/installed/locked
0.18.12, empty failure codes, no model fallback and zero intercepted
fetch/preconnect attempts through tracked teardown. Both use the real public
factory, remove child scratch on the first immediate post-close attempt and
remove the separate launcher cache only after child exit. Empty fixture auth,
no prompts and scoped policy checks do not qualify live transport, profile
isolation, all network APIs, DLL unload or a process-global drain. Unscoped
capability/global introspection remains `LAST_CREATED`, not scope-bound.

The parent source-set digest
`a5ff0ba21823b01c3fc3781b23a5c9085019c9653f3d63a6a1088294ee7a866e`
uses the parent's recorded file-set algorithm; it is **not** the original
implementation-scope digest or this probe's ordered four-file digest. These
refreshed documentation bytes postdate the receipts and were **not tested**.
The original implementation receipt is preserved; the separate documentation-refresh
receipt records only doc changes and evidence attribution. All artifacts are unshipped local evidence,
not authority or promotion grants. Main native code was freshly built
unchanged; native lifetime/ACL/publication/construction/fixture repairs remain
deferred and no private native fixture passes are claimed. Independent
review/PR/merge remain pending. Native/service/security/fault/OOM/noDump,
installation/deployment/production/support/release remain unqualified.
Upstream #6578 and direct repair #6700 remain open/unmerged; merged #6763's
transcript-content approval binding is not a guard-deadlock fix. No bypass or
admission recovery is authorized.

## Current implementation contract

The probe requires Bun **>=1.4.0** and Node wrapper **>=26**. Exact daemon,
installed coding-agent and lockfile pins must be 0.18.12. The coding-agent
declarations, installed versions and lockfile entries for agent-core and ai
must independently equal 0.18.12; mismatches fail, with no fallback. Dependency
installation used official npm with `--ignore-scripts`; the committed Bun lock
was regenerated separately. The parent isolated Linux install log records Bun
1.4.2 installing 291 packages; the bounded receipts establish version/lock
agreement, not an independent tarball-provenance or release attestation. No
upstream package, node_modules, SOURCEPATCH or native-control repair is part of
this probe change.

The SDK-only delta reuses public `createAgentSession`, `Settings.loadForScope`,
`SessionManager`, `AuthStorage`/`SqliteAuthCredentialStore`, model registry and
resolver, capability APIs, and `closeModelCache(path)`. A/B use the actual
factory without prompts; C is a no-model/no-session allow-list negative. Empty
fixture auth stores are not credentials, profile activation, broker state or
live provider transport evidence. The exact session `models.db` close must
return `true`; disposal rejection or unconfirmed completion fails even when
`isDisposed` is already true. Factory failure retains caller-owned manager
cleanup, primary and nested cleanup errors, without double-close or retries.

The wrapper creates separate contained roots before any SDK import:

```text
issue62-wrapper-*/                    parent-owned disposable root
  launcher/data/gjc/natives/         process-lifetime native-loader cache
  tmp/gjc-issue62-sdk-*/             child-owned immediate-close scratch
    agent/                          settings/auth/model-cache SQLite and config
    home/                           isolated HOME/USERPROFILE and app data
    tmp/, auth/, work-A/, work-B/, work-C/, marker files
```

`XDG_DATA_HOME` points to `launcher/data`; its `gjc/natives` prerequisite is
precreated. The official loader's staged native module has child-process
lifetime, distinct from session SQLite ownership; post-exit cache removal is
not proof of immediate session close. Missing/relative, escaping, overlapping,
redirected or session-data-contaminated launcher layouts are refused. The
non-default `agent/` directory is passed to the public SDK and set as
`GJC_CODING_AGENT_DIR` only after rejecting host overrides. This keeps POSIX
XDG data routing from moving session databases into the launcher. Public
`getAgentDbPath` and `getModelDbPath` must resolve to the exact session files
for both default and explicit agentDir arguments.

After awaited tracked session/AuthStorage/settings/model-cache cleanup, the
child must physically remove its **entire** session scratch before exit in
one immediate filesystem attempt (`force: false`, `maxRetries: 0`). No GC,
delay, retry, chmod/cwd repair, file exclusion, fake fallback or suppressed
close error can turn a failure into success. The first removal verdict and
bounded diagnostics are retained. `cleanup.nativeCache` describes the separate
process-lifetime cache; Windows additionally requires a staged `.node` under
its exact 0.18.12 directory. Only after child close may the parent remove the
launcher root, once, as `cleanup.parentCacheRemoval`; its
`immediateSessionCloseProof` is false. Post-exit failed-scratch salvage is
separate (`cleanup.parentSalvage`) and never replaces the child's verdict.
Failed removal is not retried through ancestor cleanup.

The credentialless regressions cover root ownership/refusals, symlinks and
junctions, missing loader prerequisites, modeled cache lifetime, first-error
and false-removal-success negatives, close rejection, cwd refusal, caller
manager ownership and nested disposal errors. Modeled lifetime is not DLL
unload evidence. The guard is installed before lazy sequential SDK/adapter
imports and remains through tracked teardown; both fetch and preconnect
attempts fail, including exceptions swallowed by imported/disposal code.
Original fetch identity is restored once on success or failure. The controlled
throwing capability-provider warning is **required**, not suppressed; disabled
loaders must not run, model fallback must remain false and intercepted network
attempts must be zero. This guard covers intercepted Bun fetch/preconnect only,
not other network APIs, calls after restoration or production startup.

### Probe commands and environment

Run from `D:/dev/gjc-remote-sdk-only-0.18.12`, with Node >=26 and Bun >=1.4.0.
These focused commands describe the probe entrypoints, not additional
executions by this documentation lane. The actual parent commands/counts are
in the receipts above; do not substitute unrestricted workspace execution:

```text
node --test daemon/test/sdk-isolation-probe.test.js
node --test daemon/test/sdk-session.test.js daemon/test/session-pool.test.js daemon/test/sdk-contract-probe.test.js
```

Use `BUN_BIN` for the intended Bun executable when it is not on PATH (PowerShell:
`$env:BUN_BIN = (Get-Command bun).Source`; POSIX shell: `BUN_BIN="$(command -v bun)" node --test daemon/test/sdk-isolation-probe.test.js`).
The Node wrapper builds its credentialless allow-listed child environment and
isolates HOME/USERPROFILE, TEMP/TMP, LOCALAPPDATA/APPDATA and the separate XDG
launcher cache. It does not inherit provider keys, proxies, profile/auth
overrides or NODE_OPTIONS. The fixture sets
`GJC_MODEL_PRESET_REGISTRY_DISABLED=1` before imports and requires
`startup.networkPrewarm: false` in every scope. Direct Bun invocation without
the wrapper-owned root/cache layout is refused before SDK import. Do not add
provider credentials, forced-GC flags, delays or cleanup retries to make this
probe pass. Preserve the expected controlled-provider warning and all other
warnings in parent output; unexpected warnings require investigation.

Canonical imports were exercised by the actual SDK probes above; this is not
all-platform qualification. The separately authorized single provider smoke
is distinct from this credentialless probe and must not be inferred from it.
Any further provider execution requires separate authorization. Observations
bind the bytes at execution, not later refreshed docs or future checkouts.

### Source identity

Each receipt carries separate
`approvedBaseCommit` and `sourceCommit` fields; source may be a descendant of
the approved base. The approved original base remains
`a5bb530bd5a063b6571a7ba963e938bb6f97616f`. A deterministic SHA-256 digest
covers these four files, in this exact order:
`daemon/test-fixtures/sdk-isolation-probe.mjs`,
`daemon/test/sdk-isolation-probe.test.js`,
`docs/verification/issue62-evidence.md`, `CONTEXT.md`.
The focused wrapper requires Node **>=26**; its `nodeWrapperVersion` field records the actual Node runner separately from Bun's compatibility `nodeVersion` field. The source digest is emitted in the receipt rather than copied here, avoiding a self-referential evidence file.

## Sanitized receipts and identity boundary

The Node wrapper is the sole durable receipt writer. It removes any stale output, validates the final bounded child receipt, applies path/secret/URL redaction, and atomically writes only these ignored files:

- A→B sanitized receipt: `artifacts/issue62-A-B.json` (ignored local output, not shipped)
- B→A sanitized receipt: `artifacts/issue62-B-A.json` (ignored local output, not shipped)

The Bun fixture writes no repository artifact and emits a bounded structured receipt to stdout only. Raw stdout/stderr and unredacted temporary paths are never persisted. The wrapper owns the final files; this document is the durable reader/reference. Receipts are evidence attachments, not source-controlled proof by themselves.

These ignored mutable paths are output locations, not permanent proof of any
checkout. The parent-run outputs inspected above are bounded pre-refresh
observations. Any new receipt must independently report `sdkVersionExpected`,
`sdkVersionObserved`, `daemonDependencyVersion`, and `lockfileVersionEvidence`
as `0.18.12`, and its ordered working-tree digest must match the four live files.
The `sdkDependencyProvenance` entries must independently match 0.18.12 for
agent-core and ai (coding-agent declaration, installed version and lockfile).
The wrapper removes each stale order-specific output before running that order.

## Historical SDK 0.16.7 observed probe boundary

The then-current parent-run wrapper passed all three tests on Windows x64 (Bun
1.4.2, Node wrapper 26.7.0) and Linux x86_64 (WSL Ubuntu 24.04, Bun 1.4.2,
Node wrapper 26.9.0), including both creation orders and zero network
attempts. This remains historical scoped policy evidence, not 0.18.12 evidence
or tenant isolation. The following observations apply to that dependency only.

The installed 0.16.7 package source and exports map were inspected before
retargeting the probe. The published 0.16.6 → 0.16.7 tarball diff touches only
`src/exec/isolated-shell.ts` (CLI `--smoke-test` worker teardown), the
package changelog, and `@gajae-code/*` workspace version pins; none of the
surfaces below changed, so the 0.16.6 boundary inspection carries forward
verbatim. The scoped surfaces it exercises remain available:

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

The source inspection above is distinct from execution evidence. The historical
probe passed both creation orders, divergent per-workDir settings/model policy,
capability lookups, the no-model/no-session C negative, fail-closed network and
host-environment guards, bounded redaction, and explicit cleanup accounting.
Canonical `createAgentSession` and `SessionManager` imports are exercised by
the real factory path, not inferred merely from package declarations.

The queued-follow-up liveness gap remained in that published package. The daemon
contained it by rejecting `steer` and `follow_up` while a prompt was active,
before SDK queue admission; idle controls remain prompt-equivalent FIFO work.
Upstream issue
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
release. Issue closure on `dev` is therefore not release inclusion. A supported
public ownership lifecycle is requested in
[`Yeachan-Heo/gajae-code#5429`](https://github.com/Yeachan-Heo/gajae-code/issues/5429);
the contract oracle verifies fail-closed containment independently of this
historical isolation probe.

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
capability/model-provider state or claim full isolation. Historical 0.16.7
receipts do not qualify 0.18.12 or remove those limits. Preserve the requirement to rerun this focused
probe after every SDK bump before changing the caveat. A reproducible global
direction is evidence only for the exact observed upstream/architecture
boundary, not a local workaround authorization.
