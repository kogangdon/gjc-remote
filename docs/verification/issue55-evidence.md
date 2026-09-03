# Issue #55 source-bound negative evidence packet

`scripts/issue55-evidence.js` creates a deterministic **source-bound negative packet**. It is not release evidence and cannot promote a candidate.

Create a packet from a clean, committed checkout:

```sh
npm run evidence:issue55 -- --output /absolute/path/issue55.json
npm run evidence:issue55:verify -- --packet /absolute/path/issue55.json
```

The collector rejects tracked or untracked checkout changes before and after
collection. It captures HEAD once and reads every package, lock, and Docker
contract input from that immutable commit's Git blobs, so line-ending
conversion and hidden working-tree flags cannot change the packet while
retaining the recorded tree. It derives the commit and tree identities, fixed
repository identity, package and native-contract versions, lock digest, SDK
declaration/resolution/integrity, and uniquely declared/consumed Docker
Bun/lock/SDK contract. The JSON is recursively key-sorted with LF termination.
Its sibling checksum contains only `SHA-256`, two spaces, and the packet
basename. Packet output must remain outside the repository; lexical and
canonical-parent checks reject symlink/junction re-entry. Generated packets
must not be committed.

## Promotion behavior

The source-identity check is the sole `verified` check. All other checks are deliberately `missing` with the fixed `not-collected-by-source-snapshot` reason. `promotion.releaseEligible` is therefore always `false`, and its blockers include every unavailable proof. The packet has no status input, waiver mechanism, timestamp, environment capture, path, host, or user fields.

Unavailable proofs are: current candidate tests and smoke; signed native Linux x64 and arm64 artifacts; final image index/platforms; x64 and arm64 SBOMs and scans; attestations; four-role volume manifests and cleanup; serving-enabled E2E; observability; rollback; provider recovery; Linux x64 and arm64 distinct-principal evidence; Windows NTFS distinct-principal evidence; supervisor evidence; sentinel scans; and proof of zero manual cleanup.

`verify` requires byte-for-byte canonical JSON, the matching sibling checksum, the closed check registry, fixed statuses/reason codes, and recomputation of every source-derived fact from a clean checkout. It fails on any mismatch. `--require-promotion` is valid only with `verify` and also fails while the fixed blockers remain.
