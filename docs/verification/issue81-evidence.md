# Issue #81 native workspace serving — deferred-dimension live-path evidence

Durable summary of the same-host live-path evidence for the two native-serving
dimensions that the #81 epic (slice S6f) explicitly DESCOPED to S7 (issue #171)
per the S6f pass-3 ralplan re-consensus and operator approval (2026-08-26). #81
landed unit + integration evidence for these two dimensions using dependency-
injected doubles; this file records the LIVE-PATH evidence against the real
native addon that issue #171 owns.

The raw harness transcript is generated output (a specific-commit receipt);
this file is the part that must survive.

- Native capability contract: revision **3** (residual-process enumeration added on top of the #44 revision-3 baseline; see native-control `capabilities.js`).
- Release signing key pinned for that contract: `prod-2026-08-r2` (ed25519).
- Evidence commit base: `main` @ `cfee287` (S7.1 #188, S7.2a #189, S7.3 #190 all landed).
- Serving gate at the evidence commit: `NATIVE_WORKSPACE_SERVING_ENABLED = false` (`daemon/src/daemon.js:235`) — the live-path evidence exercises the native seams directly, WITHOUT flipping the human-approved serving gate.

## The two deferred dimensions

1. **Workspace containment `lowLevel`** — `daemon/src/workspace-containment.js`
   (`createWorkspaceContainment({ lowLevel })`) consumes the native root/reparse
   identity facts (`read_workspace_root_facts`, `read_identity`,
   `path_exists_no_follow`). The least-privilege projection is native-control
   `createContainmentLowLevel` (S7.1, PR #188).
2. **Residual-process enumeration** — `daemon/src/workspace-residual-process.js`
   defers the concrete native handle/pid scan (`residualIo.listResidualProcesses`)
   to "an S7 wiring". The native capability is `enumerate_workspace_process_holders`
   (S7.2a, PR #189, contract revision 3); the least-privilege projection is
   native-control `createResidualProcessEnumerator`; the DI-seam adapter that
   maps `{ hostId, workspaceId }` → `(workDir, sourcePlatform)` is
   `createResidualProcessNativeIo` (S7.3, PR #190). No orchestrator API changed.

## Same-host live-path environment

Run on the operator-controlled Windows host, in the same-host WSL2 Linux
distribution (a real Linux kernel and filesystem, same physical host):

- Distro: **Ubuntu 24.04.3 LTS**; kernel `6.18.33.2-microsoft-standard-WSL2`; `x86_64`.
- Toolchain: `node v18.19.1`, `g++ (Ubuntu 13.3.0)`, `make`, `python3` (node-gyp).
- Native addon: built fresh on this Linux host (`node-gyp rebuild` → `SOLINK_MODULE Release/native_control.node`, `gyp info ok`), manifest written by `verify-build.mjs --write-manifest`.
  - manifest: `platform: linux`, `arch: x64`, `contractRevision: 3`, `capabilities: 33`.
  - addon sha256: `f94edfa56341f4c66e364531224b9389b15eb6d6a8f9e0355b6e4b9795664069`.
- Load path: the harness validated the addon through the real
  `validateBuildManifest` (hash + platform/arch + contract-revision check) and
  injected it as `loadAddon` into `createContainmentLowLevel` /
  `createResidualProcessEnumerator`. Release-signature verification is bypassed
  for tests exactly as CI does (the prod key is a release-gate concern, not a
  test-build concern); this is NOT a claim that a signed production artifact was
  produced.

## Proven by live execution (real addon, real Linux, real processes)

Everything below ran against the freshly built native addon, not a mock. Full
transcript ended `S7_4_LIVE_OK`.

### Dimension 1 — containment `lowLevel`

| Property | Live result |
| --- | --- |
| `createContainmentLowLevel` projects exactly the 3 least-privilege caps | `['path_exists_no_follow','read_identity','read_workspace_root_facts']` |
| `read_workspace_root_facts(workDir, 'posix')` returns canonical root/storage identity | `{ sourcePlatform:'posix', workDir:'/tmp/…/ws', rootIdentity:{ kind:'posix-root-v1', device:'2096', inode:'10497' }, storageIdentity:{ kind:'posix-storage-v1', device:'2096' } }` |
| `read_identity(workDir)` returns the real stat identity | `{ device:'2096', inode:'10497', mode:16877, owner:'uid:1000' }` |
| `path_exists_no_follow` distinguishes present vs absent | `held.txt → true`, `nope.txt → false` |

### Dimension 2 — residual-process enumeration (real `/proc` scan)

| Property | Live result |
| --- | --- |
| Quiescent workspace certifies absence | `enumerate_workspace_process_holders(workDir,'posix') → []` |
| A live holder (open fd + cwd inside the workspace) is enumerated | `→ [{ pid: 405 }]`; pid is a positive safe integer |
| After the holder process exits, the set returns to empty | `→ []` (absence re-certified) |

This is the residual-process absence proof the reset/delete lifecycle (S6f.4)
depends on: an EMPTY set authorises destruction, a non-empty set blocks it. The
same-uid (`uid:1000`) holder was inspectable, which is exactly the
same-namespace/same-uid inspectability the scan's fail-closed posture assumes
(`native-control/src/addon.cc`, `EnumerateWorkspaceProcessHolders` scope note).

### Automated live-path coverage (same environment)

The native-control suite was also run on this Linux host
(`node --test test/*.test.js`): **158 tests, 156 pass, 0 fail, 2 skip**. The 3
Linux-only residual real-scan integration tests that self-skip on the Windows
host executed here, including "linux scan returns [] for an unheld workspace and
finds cwd, fd, and boundary holders" (real cwd holder, real fd holder isolated
by an outside cwd, and the prefix-sibling `.../wsX` negative that proves the
path-boundary check under a real scan). GitHub CI likewise builds the addon and
runs these on both `ubuntu-latest` and `ubuntu-24.04-arm` on every push (PR #189
/ #190 runs green).

## Explicitly NOT proven / preserved non-goals

- **Docker Compose container run:** the containerized (PID-namespace) variant was
  NOT executed this session — the Docker Desktop Linux engine was not running and
  did not start non-interactively. The evidence above is same-host WSL2 Linux
  live-path, which exercises the real kernel `/proc` scan and the same-uid
  inspectability model but not a separate container PID namespace. The
  container-namespace variant remains available as a follow-up; nothing here
  claims a Compose run occurred.
- **Windows residual handle scan (S7.2b):** off Linux the native capability fails
  closed with `CONTAINMENT_UNSUPPORTED`; a native Windows handle scan is a
  separate deferred slice. No Windows residual live-path is claimed.
- **Serving enablement:** `NATIVE_WORKSPACE_SERVING_ENABLED` stays `false`; no
  live reset/delete destruction, no daemon serving-path wiring, and no gate flip
  are part of this evidence. The full `nativeServingDeps` bundle assembly and the
  human-approved serving flip (S6f.7) remain gated on a fresh ralplan re-consensus.
- **Release signing:** no signed production artifact was produced or accepted by a
  release gate here; signature verification was bypassed exactly as CI does.
- **mmap-only holders:** a workspace file mapped with its descriptor already
  closed (visible only in `/proc/<pid>/maps`) is a documented non-goal of the S7.2
  scan.

## Sign-off

- Author: GJC agent (kogangdon operator host), 2026 S7 execution.
- Scope: issue #171 acceptance dimension 2 — "Same-host Compose / live-path
  evidence for the two deferred dimensions", satisfied via same-host WSL2 Linux
  live-path against the real addon (contract revision 3, addon sha256
  `f94edfa5…664069`), with the Compose container-namespace variant recorded as a
  non-claim above.
- Independent review: recorded on the PR that lands this evidence file; the S7.1
  / S7.2a / S7.3 native changes each carried their own independent architect
  review (PRs #188 / #189 / #190, all APPROVE, zero blockers).
