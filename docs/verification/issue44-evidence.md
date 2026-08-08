# Issue #44 management mapping envelope — verification evidence

Durable summary of what was proven for the management authority / mapping envelope
work, why, and where the raw receipts live. The raw receipts themselves are
generated output: they are ignored by git (`artifacts/`) and published as release
assets, because they describe one specific commit and go stale the moment the code
changes. This file is the part that must survive.

- Shipped: PR #56, merge commit `bc42121`, `main`.
- Native capability contract: version 3.
- Release signing key pinned for that contract: `prod-2026-08-r2` (ed25519).

## Proven by execution

Everything below ran against the real built native addon, not a mock.

| Property | How it was proven |
| --- | --- |
| Owner identity and exact role ACL apply/verify | `read_identity`, `set_exact_role_acl`, `verify_exact_role_acl` on real files and directories |
| No-follow traversal and retained handles | `open_no_follow`, `open_verified_parent`, `open_verified_parent_handle`, `open_verified_object_handle` |
| Reparse/symlink traversal rejection | A junction reparse point substituted for a verified parent is refused. A directory symlink needs `SeCreateSymbolicLinkPrivilege`; the junction fallback proves the same rejection without elevation |
| Absent-create and exclusive-temp cycles | Full prepare, verify, publish and discard paths including ambiguous-cleanup refusal |
| Atomic replacement | `replace_existing_atomic` with an externally retained handle open on the destination |
| Durability, non-elevated | Directory-handle flush on NTFS; volume-wide flush needs elevation and is never claimed |
| Principal access proofs | Owner allow plus foreign-principal write denial, gated on the exact role ACL for the object's profile |
| Native lock, control directory, verified removal | `acquire_native_lock`, `ensure_control_directory`, `remove_verified_file` |
| Durable lineage | `fenceGeneration` continuity `+1` across every archived marker predecessor back to the Genesis seal; committed epoch archive required before finality; successor requests bound to the full predecessor tuple |
| Fail-closed recovery | Torn, substituted, missing and post-terminal states converge to transaction-bound `manual_cleanup` with `routeDisposition: "no-route"`, with zero writes on refusal |
| Release provenance | The signature gate verifies against the git-pinned key and refuses a tampered signature, an unknown `keyId`, a missing sidecar and a corrupt trust store |

## Suite and CI evidence at the merge commit

- `npm test`: bot 215 pass, daemon 118 pass, native-control 85 (83 pass + 2 POSIX-only skips), shared 33 pass, 0 fail.
- `npm run smoke:local`: `SMOKE_OK`.
- CI: `suite (ubuntu-latest)`, `suite (windows-latest)` and the aggregate required
  `test` context all green. Both matrix legs build `native_control.node` first, so
  the native integration suite runs instead of self-skipping.
- Independent review lanes: architecture reported no software blocker; security
  approved the merge. The review receipt is recorded on PR #56.

## Explicitly NOT proven

These are reported by the suite as named `UNPROVEN` diagnostics rather than passes,
and must not be read as verified:

- Read-mode denial for a principal whose SID cannot be resolved on the host. The
  test's synthetic role SIDs have no local account, so group expansion cannot run
  and the addon refuses rather than asserting an unprovable denial. Proving it
  needs a second real local account.
- Legacy-retained write denial for the bot principal, blocked for the same reason.
- Volume-wide `FlushFileBuffers`, which requires elevation. It is attempted as a
  non-fatal extra only; the directory-handle flush is the actual contract.
- Windows management remains gated on a protected installation: an attacker with
  write access to the deployed `native-control/` tree can edit the verifier itself,
  so in-tree verification is not a substitute for restricted install permissions.

## Where the raw receipts live

Attached to the matching GitHub Release as an evidence bundle, and reproducible
locally into `artifacts/`:

| File | Contents |
| --- | --- |
| `issue44-final-npm-test.txt` | Full workspace suite output |
| `issue44-final-native-integration.txt` | Real-addon native integration suite |
| `issue44-final-provenance.txt` | Signature gate baseline plus three adversarial refusals |
| `issue44-final-smoke.txt` | End-to-end smoke |
| `issue44-<case>-terminal.log` | One focused run per mandatory red-team case |
| `issue44-quality-gate.json` | The quality gate that carries the above as artifact references |

Evidence is version-scoped by design. A later release proves itself with its own
run; it does not inherit these receipts, because the code they describe has moved.
Re-validating this receipt after the raw files are gone requires regenerating them
from the same commit.
