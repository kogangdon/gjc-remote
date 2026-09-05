# Issue #55 observability execution evidence

This procedure records authenticated execution evidence for the singular external ledger check `observability=verified`. It is additive to, and never changes, the source-negative packet `gjc-remote.issue55.source-negative.v2`.

## What the receipt means

A manual run of `.github/workflows/issue55-observability-evidence.yml` on `main` creates `issue55-observability.json` and `issue55-observability.json.sha256`. The receipt joins its immutable commit, tree, and source-packet digest, and records one Linux/x64 execution of the closed focused recipe. The final GitHub artifact name starts with `issue55-observability-evidence-`.

`untrusted-issue55-observability-` and `verified-unattested-issue55-observability-` are one-day intermediate prefixes. Consumers must reject those artifacts. The final artifact uses the repository retention default rather than the one-day handoff limit; record its actual `expires_at` from GitHub. Artifact expiry requires regeneration from the same commit with the exact recipe; regeneration does not create new historical execution evidence.

The focused recipe is a test gate. It covers the landed bot local observability tests and daemon owner, invoke, and lifecycle observability tests, including the dual-gated local-only test IPC and absence of observability correlation fields from WebSocket frames. It is not a production telemetry run.

## Consumer verification

Accept only the final `issue55-observability-evidence-` artifact. Extract it into an empty directory and require exactly these two top-level regular, non-symlink files:

```text
issue55-observability.json
issue55-observability.json.sha256
```

Set `EXPECTED_COMMIT` from the immutable artifact receipt, not current main. Check the sidecar before using the receipt:

```sh
sha256sum --check issue55-observability.json.sha256
```

In a clean detached checkout of `EXPECTED_COMMIT`, run:

```sh
node scripts/issue55-observability-evidence.js verify \
  --receipt /absolute/path/issue55-observability.json \
  --expected-commit "$EXPECTED_COMMIT"
```

Verify both attested subjects separately:

```sh
gh attestation verify issue55-observability.json \
  --repo kogangdon/gjc-remote \
  --signer-workflow kogangdon/gjc-remote/.github/workflows/issue55-observability-evidence.yml \
  --signer-digest "$EXPECTED_COMMIT" \
  --source-ref refs/heads/main \
  --source-digest "$EXPECTED_COMMIT"
gh attestation verify issue55-observability.json.sha256 \
  --repo kogangdon/gjc-remote \
  --signer-workflow kogangdon/gjc-remote/.github/workflows/issue55-observability-evidence.yml \
  --signer-digest "$EXPECTED_COMMIT" \
  --source-ref refs/heads/main \
  --source-digest "$EXPECTED_COMMIT"
```

Only after both attestations, local verification, exact run conclusion/event/attempt, artifact ID/name/digests, and receipt subject commit/tree/source-packet digest are recorded may an external ledger mark `observability=verified`. Retain those external control-plane records while GitHub artifacts are available.

## Boundaries and nonclaims

The unchanged source-negative v2 packet continues to report `observability: missing`, `releaseEligible: false`, and all 21 blockers. This receipt is not an override, waiver, promotion, or mutation of that packet.

No production bot, daemon, telemetry collector, exporter, dashboard, alert, SLO, retention policy, or incident is observed. No provider credential, provider API call, provider recovery, readiness, or serving-enabled real-agent session is exercised.

No native-control build/load/signature, container image, OCI platform, Linux platform conformance, arm64, Windows/NTFS, ACL, deployment, supervisor, or hosted-provider behavior is established. `linux/x64` describes only the one test execution environment.

No full candidate test suite, candidate smoke, signed artifact, SBOM, scan, release attestation, rollback, publication, release eligibility, or promotion check is cleared.

Local-only means the landed test-only IPC capture is dual-gated and correlation fields are absent from WebSocket frames. It does not promise that every output or log is secret-free or create a production telemetry transport. Redaction evidence is limited to tested closed schemas, bounded taxonomies, sentinels, and paths; it is not an exhaustive secret scan.

Exactly-once means only that the tested terminal-settlement paths suppress
duplicate settlement. It is not distributed exactly-once across process
crashes, collectors, networks, or storage systems.

GitHub attestation authenticates subject bytes and workflow provenance under the GitHub trust boundary; it does not prove assertions correct, main benign, or an unattested/intermediate artifact executed tests. No receipt timestamp is authenticated event time.

The execution claim also trusts the full-SHA-pinned
`oven-sh/setup-bun` action to install the declared Bun toolchain before the
recipe runs. The frozen install uses `--ignore-scripts`, matching the production
container install boundary and preventing the unrelated native-control addon
from compiling. The tracked bot CLI bin target is committed executable so Bun's
workspace-bin linking cannot create a source mode change. The generator does
not tolerate mode-only drift. The observability recipe does not provide
native-control build or execution evidence.
Independent verification reproduces receipt bytes and source
association but cannot prove that a compromised setup action actually executed
the tests. This third-party action is part of the recorded workflow trust base,
not equivalent to an `actions/*` GitHub-controlled action.

## First authenticated observability run

Workflow run
[`33993917213`](https://github.com/kogangdon/gjc-remote/actions/runs/33993917213)
(run number 3, attempt 1) completed successfully for exact main commit
`e525ff16fc162ee4534dbc5646e5b8d301a6045e` after a
`workflow_dispatch` event. GitHub records
2026-09-05T21:44:39Z through 2026-09-05T21:45:46Z, with all four jobs
(`validate`, `generate`, `verify`, and `attest`) successful.

The final artifact
`issue55-observability-evidence-e525ff16fc162ee4534dbc5646e5b8d301a6045e-33993917213-1`
has artifact ID `9977475402`, archive digest
`sha256:08b3defc52327c6a967b325c35406fa45071ffb41276cd1378dafb7da11988be`,
size 1,015 bytes, and expiry 2026-12-04T21:44:40Z. The attested receipt digest is
`69db59277f101fd4dc3e93dca769ec8dbd84e21cff011e475b55d774015dc518`;
the attested checksum-sidecar digest is
`f3689f1d60bae5a3c045be77e55e6e6abf8e5497f64089931e7c7d82822398c8`.
The receipt subject binds tree
`c67d19bda37ca29cff9cbb16aef21bed8b88bc32` and source-packet SHA-256
`c86c4ec0fb4d0367292e6c31e19aa417f5b31f27abd378b9fc82157e12336c4d`.
Both files passed the repository/signer/source-constrained
`gh attestation verify` commands above, and the downloaded receipt passed the
local verifier.

This authenticated run permits an external ledger to mark only
`observability=verified` for the recorded commit. The unchanged source-negative
packet remains `observability: missing`, `releaseEligible: false`, with all 21
blockers. Runs 1 and 2 failed closed in `generate`; neither uploaded a receipt
or reached verification/attestation.

GitHub emitted deprecation warnings because the pinned upload/download artifact
actions declare Node.js 20 and the hosted runner forced them onto Node.js 24.
The run succeeded, but that forced-runtime behavior is part of this run's
control-plane evidence and should be removed in a later pinned-action update.
