# Issue #55 source-bound negative evidence packet

`scripts/issue55-evidence.js` creates a deterministic **source-bound negative packet**. It is not release evidence and cannot promote a candidate.

Create a packet from a clean, committed checkout:

```sh
npm run evidence:issue55 -- --output /absolute/path/issue55.json
npm run evidence:issue55:verify -- --packet /absolute/path/issue55.json
```

The collector rejects tracked or untracked checkout changes before and after
collection. It captures HEAD once and reads every package, lock, `.dockerignore`, and Docker
contract input from that immutable commit's Git blobs, so line-ending
conversion and hidden working-tree flags cannot change the packet while
retaining the recorded tree. It derives the commit and tree identities, fixed
repository identity, equal root/bot/daemon/shared package versions, native-contract
version, lock digest, SDK declaration/resolution/integrity, both Dockerfile and
`.dockerignore` SHA-256 values, the daemon Bun/lock/SDK contract, and the bot
Bun/Node pin, signed-native context, production install, signature verification,
and OCI label contract. The JSON is recursively key-sorted with LF termination.
Its sibling checksum contains only `SHA-256`, two spaces, and the packet
basename. Packet output must remain outside the repository; lexical and
canonical-parent checks reject symlink/junction re-entry. Generated packets
must not be committed.

## Promotion behavior

The source-identity check is the sole `verified` check. All other checks are deliberately `missing` with the fixed `not-collected-by-source-snapshot` reason. `promotion.releaseEligible` is therefore always `false`, and its blockers include every unavailable proof. The packet has no status input, waiver mechanism, timestamp, environment capture, path, host, or user fields.

Unavailable proofs are: current candidate tests and smoke; signed native Linux x64 and arm64 artifacts; final image index/platforms; x64 and arm64 SBOMs and scans; attestations; four-role volume manifests and cleanup; serving-enabled E2E; observability; rollback; provider recovery; Linux x64 and arm64 distinct-principal evidence; Windows NTFS distinct-principal evidence; supervisor evidence; sentinel scans; and proof of zero manual cleanup.

`verify` requires byte-for-byte canonical JSON, the matching sibling checksum, the closed check registry, fixed statuses/reason codes, and recomputation of every source-derived fact from a clean checkout. It fails on any mismatch. `--require-promotion` is valid only with `verify` and also fails while the fixed blockers remain.

## Local candidate-execution receipt

This optional, local receipt records one direct execution of the fixed candidate
recipe. It is separate from the source packet:

```sh
npm run evidence:issue55:candidate -- --output /absolute/path/issue55-candidate.json
npm run evidence:issue55:candidate:verify -- --receipt /absolute/path/issue55-candidate.json
```

Generation rejects a dirty checkout and tracked `assume-unchanged` or
`skip-worktree` entries, then runs exactly `bun install --frozen-lockfile`,
`npm run build --workspace @gjc-remote/native-control`, `npm test`, and
`npm run smoke:local`, in that order, without a shell. For portability, logical
`npm` commands run through the JavaScript CLI named by the invoking npm
process, using `process.execPath`; Windows `.cmd` shims are never passed to
Node's direct process API. It rechecks the clean
HEAD/tree/source association after each command and writes no receipt if any
step fails. A successful receipt has only the fixed commit/tree/source-packet
digest subject and two verified checks (`candidate-tests` and
`candidate-smoke`) with the fixed command arrays and
`direct-execution-exit-zero` reason.

The receipt is unauthenticated local evidence, not an attestation, platform
evidence, or release-eligibility decision. Verification checks only its
canonical bytes, checksum, exact schema, and current clean v2 source
association; it never reruns the recipe. It does not alter the negative source
packet: that packet's candidate checks remain missing, every blocker remains,
and release eligibility remains false.

## Authenticated negative source evidence

`.github/workflows/issue55-source-evidence.yml` is manual-dispatch only and has
no inputs. At dispatch validation it accepts only that moment's exact `main`
commit and requires
`github.sha` and `github.workflow_sha` to match. It never accepts a local packet,
candidate receipt, path, artifact URL, or caller-selected revision.
Queued jobs or failed-job reruns may finish after `main` advances; that creates
honest historical source provenance for the recorded commit, not evidence for
the newer tip.

The workflow separates generation, verification, and attestation authority:

1. A `contents: read` hosted job checks out the exact commit, generates the
   negative source packet, verifies it, and uploads a one-day
   `untrusted-issue55-source-*` handoff.
2. A separate hosted job with only `contents: read` and `actions: read`
   downloads that exact artifact ID, checks out the packet commit, requires
   exactly the JSON and checksum files, reruns the local verifier, and uploads a
   one-day `verified-unattested-issue55-source-*` handoff.
3. The final hosted job has `actions: read`, `id-token: write`, and
   `attestations: write`. It executes no shell or checked-out repository code.
   Pinned GitHub actions download the verified artifact ID, attest exactly the
   two files, and upload `issue55-source-evidence-*`.

Intermediate handoffs are transport only and are not evidence. Missing GitHub
OIDC or attestation support fails closed before the final artifact. No provider
login, model profile, self-hosted runner, release permission, candidate test, or
candidate smoke authority is used. The existing `candidate-tests` and
`candidate-smoke` blockers remain missing, as do every other source-packet
blocker.

Consumers must reject both intermediate artifact prefixes and verify each file
from `issue55-source-evidence-*`:
Set `EXPECTED_COMMIT` to the immutable commit encoded in the final artifact name
and source packet; do not substitute the current `main` tip.

```sh
gh attestation verify <downloaded-file> \
  --repo kogangdon/gjc-remote \
  --signer-workflow kogangdon/gjc-remote/.github/workflows/issue55-source-evidence.yml \
  --signer-digest "$EXPECTED_COMMIT" \
  --source-ref refs/heads/main \
  --source-digest "$EXPECTED_COMMIT"
```

Require exactly `issue55-source.json` and `issue55-source.json.sha256`, validate
the sidecar digest, and run the source verifier from a clean checkout of
`$EXPECTED_COMMIT`. GitHub attestation authenticates workflow-produced source
bytes; it does not prove historical execution of tests or smoke. It does not
prove release eligibility, publication, deployment, platform results, provider
recovery, serving-enabled execution, or removal of any blocker. This workflow
does not promote a release.
