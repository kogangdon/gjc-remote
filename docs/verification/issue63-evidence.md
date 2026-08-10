# Issue #63 documentation reconciliation — static evidence

This record accompanies the approved documentation-only reconciliation. It is
intentionally evidence-scoped: it records repository source truth and static
checks, not a new runtime, native, release, provider, or ACP execution.

## Scope and source truth

Only these five documentation files are in scope for the change:

| Target document | Reconciled source claim | Boundary retained |
| --- | --- | --- |
| `README.md` | The checked-in trust store pins production key `prod-2026-08-r2` with Ed25519 signature enforcement live; old zero-key/`UNVERIFIED` wording is pre-provisioning history. | Private-key custody, rotation, fail-closed loading, and issue #44 scope remain delegated to the detailed contract documents. |
| `native-control/release-keys/README.md` | The provisioned-key identity, operator custody path, fingerprint, incident history, signing commands, and current fail-closed behavior describe `prod-2026-08-r2`. | The zero-key and local-development behavior is labeled historical bootstrap policy; it is not the current checkout's state or a downgrade path. |
| `docs/adr/0003-management-mapping-envelope.md` | The ADR's provenance decision now states that the one pinned Ed25519 production key makes enforcement live. | Unknown/malformed/invalid signatures still fail closed; rotation, independent trust root, protected deployment, and native-serving/readiness exclusions remain. |
| `CONTEXT.md` | The current daemon SDK pin is independently sourced from `daemon/package.json` and `bun.lock` as 0.12.21. ACP notes are historical evidence anchored to `ca411c3` and the 2026-07-28 inspection. | The inspected ACP SDK version is unknown/not established; no ACP adapter, subprocess route, or migration exists. |
| `docs/verification/issue63-evidence.md` | This matrix and the static verification record define the reconciliation boundary. | This file does not turn historical evidence into current conformance or release evidence. |

The read-only source anchors for those claims are:

- `native-control/release-keys/trusted.json`: `version: 1`, exactly one key,
  `keyId: prod-2026-08-r2`, `algorithm: ed25519`.
- `daemon/package.json`: dependency pin `@gajae-code/coding-agent: 0.12.21`.
- `bun.lock`: resolved `@gajae-code/coding-agent@0.12.21` entry and integrity.
- `docs/verification/issue44-evidence.md`: PR #56 / `bc42121` evidence, including
  the real-addon provenance gate against `prod-2026-08-r2`.
- `.github/workflows/release.yml`: the current release workflow source.

None of those source anchors is modified by issue #63.

## Release workflow observation

The current release workflow builds the native addon and runs `npm test`, then
creates the GitHub Release. Its build invocation has no `--sign-key` or
`--signature` input, and the workflow has no
`verify-build.mjs --require-signature` step. The workflow therefore does **not**
sign a native manifest sidecar and does **not** require a verified signature
before creating its release. This is an observation of the existing workflow,
not a request to change it and not a claim that issue #63 produced a signed
release.

Issue #44's provenance receipt remains version-scoped to its recorded merge
commit and execution; it is not inherited as runtime or release evidence for a
later commit merely because the same key ID is pinned.

## ACP option boundary

The historical feasibility note is anchored to source commit `ca411c3` and the
2026-07-28 inspection; the SDK version inspected there was unknown/not
established. It is not ACP conformance evidence for the current 0.12.21 pin.

- **Option A — mandatory standard candidate:** if a future subprocess route is
  approved, begin with `gjc --mode=acp` per session and explicitly verify the
  ACP handshake and mappings for `invoke`, `set_model`, `steer`, and
  `follow_up`, including permission behavior, before claiming support.
- **Option B — optional custom boundary:** a separately approved `Bun.spawn`
  worker may be evaluated as a non-ACP custom harness. It owns its IPC,
  lifecycle, crash/backpressure, and protocol checks; it is not an ACP fallback
  and is not silently enabled by this documentation.

Current source ownership remains the in-process `SdkSession` adapter. There is
no ACP adapter, custom worker, child-process route, or selected migration.

## Exact non-claims and preserved non-goals

This reconciliation does **not** claim:

- current ACP support, ACP wire conformance, or a current child-process route;
- that the 0.12.21 SDK pin proves anything about the historical ACP inspection;
- that the release workflow signs or requires native-addon signatures;
- that a production native artifact was created, shipped, or accepted by a
  release gate in issue #63 (issue #44's receipt remains tied to its own commit);
- that private-key custody, backup media, or operator deployment permissions
  were independently audited by this documentation change;
- native serving/readiness, OAuth/provider setup, network deployment, container
  rollout, process supervision, or changes under `ops/`; or
- multi-user isolation beyond the dedicated operator-controlled host boundary.

No runtime/source, dependency, manifest, lockfile, trust-store, workflow,
generated artifact, or `.gjc` state is part of this change. Existing fail-closed
trust policy, custody and rotation semantics, no-adapter/no-route ownership,
and all issue #44 and platform-readiness exclusions remain explicit.

## Focused static verification plan

Run only the following checks from the repository root; do not run workspace
tests, native builds, smoke, provider calls, ACP children, or release commands.

1. `git diff --check` — reject whitespace errors.
2. Assert `git diff --name-only` is exactly the five target paths listed in the
   matrix (no additions, deletions, or unrelated modifications).
3. Run a source-truth assertion that parses `trusted.json`, reads
   `daemon/package.json`, and checks the matching 0.12.21 package/lock entry,
   key ID, algorithm, and issue #44 key reference.
4. Search the five target docs for stale unqualified zero-key/`UNVERIFIED`
   claims; inspect every match to ensure it is explicitly historical or
   pre-provisioning. Search ACP/workflow terms to confirm historical ACP
   labeling, the no-adapter/no-route boundary, and the unsigned/non-required
   release-workflow observation.
5. Assert the protected-file allowlist has no diff, including runtime/source,
   tests, manifests, `bun.lock`, `trusted.json`, workflows, generated output,
   and `.gjc` state.

The checks above are static/documentation checks only and do not substitute for
issue #44's real-addon evidence or a future release-signature gate.
