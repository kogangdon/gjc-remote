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
