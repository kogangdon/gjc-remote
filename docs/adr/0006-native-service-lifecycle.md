# ADR 0006: Native service lifecycle and deployment contract

- **Status:** Accepted design; source implementation exists, while production deployment evidence remains incomplete
- **Date:** 2026-09-14
- **Issue:** #240
- **Scope:** Native application acquisition and host-local service lifecycle contracts

## Context

The bot and daemon need a host-local lifecycle path that can install, inspect,
update, roll back, uninstall, and recover their service resources without
turning mapping state, credentials, workspaces, or session files into installer
state. The operation is privileged and crosses non-atomic filesystem and
system-service APIs. A service name, PID, executable hash, or successful start
call is not enough to prove ownership or readiness after a crash.

The supported design tuples are Linux x64, Linux arm64, and Windows x64. Linux
uses systemd. Windows uses Shawl v1.9.0 under SCM. This decision does not approve
NSSM, direct Node/Bun SCM registration, a replacement wrapper, macOS, Windows
arm64, containers, or shared-workstation Windows as lifecycle targets.

The application bundle includes both production components and their exact
native addon. A host selects one component when installing a service. Runtime
binaries, accounts, configuration, credentials, HOME directories, logs,
workspaces, mapping authority, and session history are preprovisioned external
state.

## Decision

Select one separately signed, self-contained application bundle for each
supported platform tuple. Publish verified bytes into an immutable,
content-addressed release directory. Point each owned service resource directly
to its immutable release entrypoint. Retain the current release and one exact
immediate predecessor per service.

Put acquisition, service ownership, and recovery in a dedicated
`gjc-remote-service` domain with exactly these operations:

- `install`
- `status`
- `update`
- `rollback`
- `uninstall`
- `recover`

The controller owns service resources and protected proof records only. It does
not become route or mapping authority. It never creates or rewrites a runtime,
account, application configuration, credential, provider profile, workspace,
session, or global journald policy.

This ADR approves the contract. The repository now contains source-level
lifecycle CLI/entrypoint, orchestration, protected-store, acquisition, and
Linux/Windows fake-driver implementations with contract tests. Those artifacts
are not production evidence: signed deployment assets, a production trust
root, real systemd/SCM mutation, and disposable-host deployment evidence
remain unclaimed and require their respective gates.

## Deployment trust and immutable artifacts

Application and Shawl deployment signatures use separate purpose-specific
deployment trust stores: `deployment-keys/application-trusted.json` and
`deployment-keys/shawl-trusted.json`. Their key IDs and public-key
fingerprints must be disjoint from the native-addon trust store and from each
other. Native-addon verification remains an independent mandatory check; a
deployment signature cannot replace or weaken it.

Only Ed25519 is accepted for this deployment contract. Signatures use these
purpose-separated preimages:

```text
UTF8("gjc-remote/application-deployment/v1") || 0x00 || canonicalApplicationManifest
UTF8("gjc-remote/shawl-deployment/v1")       || 0x00 || canonicalShawlManifest
```

The outer application manifest is a separate release asset. Its
`manifestFingerprint` hashes canonical manifest fields excluding only that
fingerprint field. The signature covers the complete canonical manifest,
including the fingerprint.

The gzip POSIX-tar archive contains one metadata entry, `bundle-files.json`, and
only regular payload files. The inventory does not list itself. Its
`inventoryFingerprint` excludes only that field. `treeFingerprint` hashes the
canonical UTF-8-sorted payload record array of exact
`{path,size,sha256,executablePolicy}` objects. Payload counts and unpacked bytes
exclude the inventory; archive entry count is payload count plus one. The outer
manifest binds the inventory bytes and hash, tree, archive bytes and hash,
source commit/tree/tag/lock, platform tuple, entrypoints, runtime floors, native
contract, wire capabilities, release sequence, and compatibility contract.

Remote acquisition accepts only a bounded release selector for the fixed
`kogangdon/gjc-remote` release origin. The manifest and signature bootstrap
asset names are fixed by platform and architecture. The signed archive name is
validated before its URL is constructed. Offline acquisition accepts only an
exact platform-complete set of absolute retained file paths. Neither mode
accepts a caller URL, ambient credential, cookie, or arbitrary header.

Application and Shawl sequences have independent, host-wide protected floors.
A lower sequence refuses. An equal sequence is accepted only for identical
manifest bytes. An active reservation is replayable only by its exact
transaction. Update must advance beyond the service's current application
sequence. Explicit rollback alone may select the retained predecessor without
reacquisition; it never lowers a floor.

## Exact service identity

The bot service key is `bot`. A daemon instance key is:

```text
<display-slug>-<sha256(exact UTF-8 bytes of HOST_ID)>
```

The display slug uses only ASCII alphanumeric runs, lower-cases ASCII letters,
collapses every non-ASCII-alphanumeric run to one hyphen, removes edge hyphens,
uses `host` when empty, and is at most 32 characters. The full lower-case
SHA-256 suffix is mandatory.

`HOST_ID` remains the exact protocol value: nonempty, at most 128 UTF-16 code
units, no Unicode `Cc` or `Cf` character, no U+2028 or U+2029, and no unpaired
surrogate. The `Cf` exclusion includes bidi markers, zero-width formatting
characters, soft hyphen, BOM, and astral format tags. It is not trimmed,
normalized, case-folded, or limited to 128 UTF-8 bytes. Leading and trailing
non-control/non-format whitespace and canonically equivalent but byte-distinct
Unicode values therefore remain distinct. Raw `HOST_ID` is protected input and
preprovisioned daemon configuration only; it is not written to service names,
descriptions, journals, manifests, public status, or controller logs.

## Request and authority boundary

Stdin is non-TTY strict UTF-8 JSON, at most 256 KiB, with no BOM, duplicate key,
or trailing data. Every object has exact keys. Paths are absolute strict text
at most 4,096 UTF-8 bytes. Principal objects are canonical, use one platform
kind, are pairwise distinct across `management`, `bot`, `recovery`, `daemon`,
and `system`, and fix system to `uid:0` or `S-1-5-18`. Role JSON is at most
32 KiB. The exact five-role tuple is common protected input for every
operation, including status, so a read can open only the already-existing
protected root and shared lock under the same authority; there is no ambient
role or ownership fallback.

Install supplies source, immutable role-specific external configuration, and
an absence/sequence-floor CAS. Update reuses persisted configuration, supplies
a source, and acknowledges disruption. Rollback uses only the retained exact
predecessor. Uninstall preserves external state and sequence floors. Recover
continues only the exact active transaction and may perform a disruptive step
only when its request acknowledges disruption. Status accepts only
`schemaVersion`, `target`, and `roles`; it has no source, configuration,
expected CAS, disruption acknowledgement, or password. It is read-only and
creates no lock, file, receipt, or platform action.

A Windows password, when required, is optional protected stdin, at most 16 KiB
UTF-8, with no NUL or unpaired surrogate. It is passed directly to the native
SCM call and is never persisted or echoed.

SYSTEM/root is the privileged mechanism executor, not mapping authority.
Configured mapping/inventory role bindings must agree with the five-role tuple
before the first service write. Any narrower existing authority validator still
applies at its own boundary; this decision does not normalize or broaden it.

## Compatibility admission

Every signed application manifest contains complete sorted readable and
writable format sets for the closed bot mapping-reader, daemon app-session, and
workspace-lifecycle domains, plus a format-registry fingerprint. Preflight
inventories retained format markers without modifying them.

Before candidate start:

1. candidate readable formats contain all observed retained formats and all
   formats the current release can write; and
2. predecessor readable formats contain all observed retained formats and all
   formats the candidate can write.

The SDK profile/auth/config/session domain remains opaque. Its fingerprint binds
the exact SDK package version and integrity, config schema, and audited
settings/model/auth/session source contracts. Current, candidate, predecessor,
and the preprovisioned interactive identity must be equal. There is no SDK
migration or nonrollbackable override in v1. Wire, native, runtime, role,
entrypoint, and effective configuration contracts are exact.

## Ownership and transaction proof

Every mutation takes locks in the order `artifact -> shared-template ->
service-key`. Each transaction has a new 128-bit lower-case hexadecimal nonce.
Canonical SHA-256 records bind:

- **O**: exact committed predecessor, or verified absence for install;
- **C**: verified candidate manifest, immutable release, sequence, and
  compatibility;
- **T**: O, C, operation, service key, generation, transaction ID/nonce,
  expected before/after resource snapshots, platform suppression state, and
  the preceding journal fingerprint; and
- **F**: exact final service manifest, resource proof, release, generation, and
  activation.

Before every non-atomic platform call, the controller persists and fsyncs an
intent. It performs one action, queries the exact result, then persists and
fsyncs an observed receipt. Recovery accepts only the declared before or after
state for that action.

Legal durable tuple families are limited to:

1. stable O with final-old activation;
2. T-marked O with C staged/provisionally referenced and activation suppressed;
3. C configured under T in the exact suppressed/manual-trial state, including
   an exact running trial process;
4. stable F with C current, O previous, and final-new activation; and
5. uninstall tombstone with T-marked/deletion-pending/absent resource and
   retained or releasing references.

A cross-transaction, unmarked, recreated, mixed, malformed, or proof-incomplete
resource is not adopted because it resembles an expected service. It enters an
absorbing, sanitized `manual-cleanup` state and remains untouched. Recover may
clear that state only after the recorded operator action has already produced
the exact expected absence or stable O proof.

### Protected metadata store

The lifecycle domain consumes the already verified, role-bound
`createServiceNative({roles})` facade. The JavaScript store captures exactly the
nine bounded native metadata operations; roles are already captured by that
facade and are not repeated at individual calls. No JavaScript filesystem
fallback, caller root, environment root, trust-root override, arbitrary path
writer, or generic record codec exists.

The native control root has these fixed singular namespaces:

```text
transaction/  manifest/  reference/  tombstone/
floor/        manual/    locks/
```

The internal consumer surface is fixed rather than generic:

```text
createServiceStore({native,roles,target,platform,architecture})
  .bootstrap()
  .openReadOnly()
  .openMutation()
  .openRecovery()

session:
  read|publish|remove Manifest
  read|publish|remove ResourceProof
  read|publish|remove StartupProof
  readJournal / appendJournal
  retainDeploymentEnvelope / readRetainedDeploymentEnvelope
  read|publish Tombstone
  read|publish|clear ManualCleanup
  read|publish References / observeZeroReferences
  observe ApplicationPublication / observe ShawlPublication
  createSharedTemplateBinding
  read|reserve|commit|abandon application or Shawl floor
  assert application or Shawl rollback
  close
```

The spelled methods carry their record type and slot; there is no arbitrary
namespace, filename, path, JSON-schema callback, or byte-write method.

Native-derived fixed root path, root and namespace identities, the native
role-binding fingerprint, root nonce, native binding fingerprint, exact shared role tuple, and shared
service-role fingerprint are recorded in `floor/store-registration.json`. The
native role-binding fingerprint is an opaque native-domain value; it is not
computed with or compared to the shared service-role fingerprint. The
registration binds both values without claiming that their hash algorithms are
equivalent. The native root and namespace owners must also equal the registered
shared management principal. Reopening requires the complete current native
binding and exact shared role tuple to equal the protected registration. The
native root path remains protected registration data and is never returned in a
public lifecycle/status receipt.

Bootstrap is create-exclusive. It initializes registration and zero floors only
while holding the live handle returned for a genuinely new native control root.
If that operation becomes partial, a later process does not reinterpret the
existing root as new or recreate missing registration, locks, witnesses, or
floors. Missing, replaced, or torn registered metadata is manual cleanup rather
than sequence zero.

`floor/history` is a create-new physical history root whose retained native
directory identity is part of the immutable registration. An immutable
registration-incarnation receipt records the registration file's native facts
and exact canonical-record digest. Reopening compares the live registration
facts to that independent receipt, so replacing the registration with identical
bytes does not preserve its authority.

For one exact service key, the protected layout is:

```text
transaction/<service-key>/head.json
transaction/<service-key>/entry-<16-digit-sequence>.json
manifest/<service-key>/current.json
manifest/<service-key>/previous.json
manifest/<service-key>/current-resource.json
manifest/<service-key>/previous-resource.json
manifest/<service-key>/startup.json
manifest/<service-key>/deployment-<application|shawl>-<manifest-fingerprint>.json
reference/<service-key>.json
tombstone/<service-key>/current.json
manual/<service-key>/current.json
floor/<scope>.json
floor/<scope>.witness.json
floor/history/registration-incarnation.json
floor/history/<scope>-r<16-digit-revision>-bootstrap/state.json
floor/history/<scope>-r<16-digit-revision>-<action>-<transaction-fingerprint>-<service-key>/intent.json
floor/history/<scope>-r<16-digit-revision>-<action>-<transaction-fingerprint>-<service-key>/state.json
```

Records are strict bounded canonical JSON. Reads retain native file facts and
exact bytes in session-private bindings. Mutation accepts only the immutable
read receipt from the same live session; a caller-created object, consumed
receipt, cross-session receipt, changed physical identity, changed ACL facts,
or changed bytes cannot satisfy CAS. Raw `HOST_ID` and service passwords never
enter a record; only the already-derived service key appears in protected
service and floor-history names. Current/previous manifests and resource proofs
plus the startup proof
have matching exact-CAS publish and removal operations; tombstones and floors
deliberately have no removal operation.

The deployment files in the existing per-service `manifest` namespace retain
the exact signed application or Shawl envelope pair outside the immutable
payload. Their private canonical schema binds service, component, tuple,
purpose, manifest fingerprint, and canonical base64 copies of the original
bounded manifest and signature bytes. The filename is derived internally from
the closed purpose and verified fingerprint; no caller path, filename, schema,
trust callback, or generic byte writer is exposed. Namespace validation admits
only the fixed lifecycle files and those exactly typed deployment names and
records.

Creating a retained pair first runs the installed module's pinned provenance
verifier over copied bounded bytes and checks the complete application
candidate relation (fingerprint, sequence, tree, and compatibility) or exact
Shawl candidate fingerprint and tuple. It then requires an exact retained
phase of the currently active logical install/update transaction. A committed
historical transaction, another service, an unretained phase, rollback, or
uninstall cannot authorize a new pair. Recovery remains restricted to its
already admitted logical transaction. The existing artifact and service-key
fences remain held throughout the operation. Creation is no-replace: an
existing byte-identical pair is idempotent, while a different, corrupt, or
colliding record is never overwritten or repaired.

Reading a retained pair is authorized only when that purpose/fingerprint is in
this service's current, previous, or provisional artifact bindings, or is
named by this service's exact pending journal/floor evidence. Merely existing
as an older cache record grants no authority. Every read decodes the bounded
canonical base64 fields and reruns the installed pinned verifier, returning
its newly frozen receipt and module-local branded manifest rather than
deserializing authority. The verified application archive/tree or Shawl
executable also has to match the authorizing reference, full pending candidate,
or exact floor sequence. A required missing or invalid pair fails closed; the
store does not download or fall back. Read-only remains zero-write. This slice
retains evidence conservatively and deliberately exposes no removal or garbage
collection operation. Failures preserve the cumulative session write count but
do not expose the retained bytes, derived filename/path, or signing-key data.

Read-only sessions use `read-existing` roots/directories and
`shared-existing` artifact, shared-template, and service-key locks. They never
create or repair a root, namespace, lock/witness pair, service directory, floor,
or record. A missing root is absent; a missing registered lock is pending; a
torn or recreated binding is manual cleanup. Mutation verifies existing global
lock identities before acquiring exclusive locks. A pending journal entry,
non-committed latest lifecycle record, provisional artifact reference, floor
intent, or active floor reservation refuses a normal mutation session and is
available only through the recovery session. Handles close in reverse
dependency and reverse lock order: service child directories, fixed namespace
directories, service-key lock, shared-template lock, artifact lock, then the
control root. Errors preserve the aggregate count of earlier native writes; no
later failure resets that count to zero. A valid `writes` count reported by a
failed native call is added to the session total exactly once before the error
is rethrown, so later replay and cleanup retain the mutation evidence.

Recovery admission is host-wide for floor work. Every incomplete application
or Shawl history entry and every active reservation identifies one service key
and an exact transaction phase fingerprint. Journal-backed pending floor
scopes must resolve to one logical transaction; floor-only scopes must instead
agree on one unresolved fingerprint and its service/transaction labels.
Another service cannot enter recovery. A logical transaction identity includes
operation, component, service key, tuple, generation, nonce, and the complete
immutable O/C/T/F proofs; it deliberately excludes phase, substep, predecessor
link, and phase-record fingerprint. Every floor, tombstone, manual-cleanup, and
journal fingerprint used as journal-backed authority is first resolved to an
exact retained journal record. Different retained phase records are compatible
only when their complete logical identities match. A floor-only crash with no
journal record remains unresolved and replayable only by the one exact recorded
phase fingerprint; it cannot authorize journal or metadata writes, and
completing that exact floor replay never promotes either the open session or a
subsequent recovery session. For journal-backed recovery, every new floor
transition—including the first write to an otherwise empty Shawl
floor—requires that exact phase record to already exist in the protected
journal. An unappended later phase with the same logical identity has no floor
authority. Recovery metadata writes are then matched to the resolved logical
transaction. A tombstone never turns recovery into an unrestricted metadata
session.

The journal retains immutable canonical transaction records and a CAS head.
Each entry names the exact predecessor fingerprint. Records within a
transaction keep transaction ID/nonce and O/C/T/F identity fixed; a subsequent
transaction begins only after a committed record, advances service generation,
and binds its O fingerprint to the prior F fingerprint. An immutable entry
written before a failed head update is the sole permissible pending record and
only its exact byte-equivalent replay may advance the head. After that replay,
a correctly predecessor-linked later phase with the same complete logical
identity may advance; recovery does not freeze the transaction at the first
phase fingerprint. This metadata rule does not certify
that an OS action occurred: later platform drivers must supply and validate
their concrete observations before appending the corresponding record.

Application and Shawl floors are independent. Each stores highest reserved
sequence and fingerprint, committed sequence/fingerprint/publication binding,
the exact committing transaction, an optional exact active reservation, and a
monotonically advancing floor revision. Before replacing either mutable member,
the store creates a uniquely named revision directory and append-only intent
that binds the prior floor/witness native facts, prior history-state
fingerprint, intended records, service key, action, and full transaction. The
witness then publishes the action-specific intent, the primary floor changes,
and the witness becomes stable. A final append-only state records the new
floor/witness native facts. This admits the exact transaction at every
directory/intent/witness/floor/state crash boundary and detects same-byte
physical replacement or coherent restoration of an older pair while later
history remains. It does not claim reconstruction or rollback detection after
an operator destroys every independent history anchor.

Application update admission advances beyond that service's current application
sequence, not beyond an identical host-wide committed floor. Thus a sibling may
reuse the same signed higher application release. Host-wide high-water,
same-sequence fingerprint conflict, and active-reservation checks remain
closed. An application update may likewise reuse the identical already-admitted
Shawl release; Shawl does not need an artificial sequence increment.
Abandoning a reservation clears only the active transaction and preserves the
highest reserved value. Every external deployment-manifest
entrypoint—application/Shawl reserve, commit, immutable-publication observation,
and rollback assertion—first requires the exact deeply frozen manifest object
branded by this installed module instance's pinned-trust verifier. The check
precedes cloning or schema validation. A serialized/caller-built manifest, a
manifest verified only with explicit fixture trust, or a brand issued by a
different module instance refuses. Commit additionally requires a same-session
re-open of the exact immutable content-addressed directory. Rollback requires
that same-session immutable-directory observation to equal the exact
`previous` reference slot, only observes the retained lower sequence, and never
rewrites a floor. Reading and replay-validating stored lifecycle, journal,
reference, and floor records does not require a live deployment brand; any new
operation that exercises deployment-manifest authority must reverify pinned
provenance and supply the newly branded manifest object.

Each service has one strict reference record with `current`, `previous`, and
`provisional` slots. Slots bind complete application and, where applicable,
Shawl or shared-template artifact identities. Updating one service is an exact
CAS under the artifact fence and cannot replace a sibling's record.
Same-generation writes may change only the provisional slot. A one-generation
rotation may promote that provisional slot or the immediate previous slot,
retain the complete old current slot—including generation, transaction ID,
nonce, and every artifact binding—only as previous, or clear all slots for
uninstall; generation jumps and arbitrary artifact substitution refuse.
Recovery adds operation-specific authorization: install/update/rollback
candidate slots must carry the active transaction labels and the exact
application tree and application/Shawl manifest provenance recorded by C.
An all-empty next generation is admitted only for the exact tombstoned
uninstall transition to absence. Merely observing another immutable artifact
and copying the active labels does not make it the transaction candidate. The
store does not delete payload directories. It can emit a canonical zero-reference
observation containing the provenance binding, closed physical target
(fixed root, content-addressed name, and retained directory identity), current reference-directory
identity, artifact-lock identity, and complete sorted reference-record
fingerprints. References compare that physical target, so two signed manifests
for one Shawl executable still protect the same directory; conflicting
identity evidence is ambiguous. Before emitting the observation, the store
reconciles every surviving committed journal F with required current/previous
manifest, resource, and reference records. Missing sibling inventory refuses.
This is protected metadata consistency evidence, not OS truth or an unfenced
permission boolean.

Tombstones and floors are not removable through the store lifecycle API and
survive uninstall cleanup. A tombstone blocks a new lifecycle and unrelated
recovery writes. A manual-cleanup record is absorbing until recovery compares
its journal-bound complete O-proof fingerprint, the complete supplied O proof,
and the exact file CAS. The store never adopts a mismatch. Validating that
canonical proof does not observe or certify SCM/systemd/process state; the
later platform driver remains responsible for producing the concrete physical
observation before it calls the store.

Recovery record authorization distinguishes record provenance from active
transaction authority. An exact O manifest or resource keeps the predecessor
transaction's original provenance and may be copied to `previous` or restored
to `current`; an exact F record is bound by the active transaction's complete
final proof. Current O removal during update/rollback is admitted only after
the complete O manifest/resource pair is retained in `previous`. When an
install whose O is absence is abandoned, exact-CAS removal is permitted only
for that install's exact F manifest/resource and active startup proof. A
foreign, merely same-service, or unrelated record remains non-removable.
For generation three and later, the older `previous` pair is removable only
when the immediately preceding committed transaction names it as O, the
committed transaction before that supplies its slot provenance, and the
surviving reference record contains both exact current and previous slots.
Each slot must also match the corresponding committed C application tree and
application/Shawl manifest provenance. That independent journal/reference
evidence remains sufficient across a restart between removing the old pair
and between publishing its replacement for update, rollback, or tombstoned
uninstall. It does not excuse a missing pair in stable committed F, and it
never authorizes removal of a foreign record.

### Recovery matrix

| Durable boundary | Exact acceptable observation | Recovery |
|---|---|---|
| Prepared through source verification | Stable O; no candidate reference | Reverify or abandon without service change |
| Sequence reserved/acquiring | O plus exact transaction staging and reservation | Replay exact acquisition; delete only exact transaction temporary bytes |
| Release published | O plus exact immutable C, provisional reference absent/present | Replay or record the exact reference |
| Transition marker/suppression | Exact O or declared T state | Replay the one pending write/query |
| Stopping/quiescent | Exact T lineage running, stopping, or empty | Supervisor stop, bounded lineage poll, then exact-tree handling |
| Candidate resource published | Exact old or C resource under T | Replay C or record exact query |
| Trial start intent/action | Empty tree or the new exact invocation/child epoch under executable suppression | Start or continue only that exact trial boundary |
| Starting/startup evidence | Exact current trial epoch and continuous source cursor | Resume while fresh; otherwise stop, quiesce, and retrial |
| Startup observed/final activation | Fresh same-epoch receipt plus a declared activation substate | Complete one activation action at a time; epoch change resuppresses and retrials |
| Committed | Stable F and required references | Idempotently finish reference rotation and exact zero-reference GC |
| Tombstone/removal | Exact T/tombstone resource or exact absence | Continue stop/removal; never remove a recreated resource |
| Any state outside the declared pair | Foreign, hybrid, torn, ambiguous, overflow, or unsafe survivor | Sanitized manual cleanup; no adoption or inferred deletion |

Stopping proves no drain or migration. It acknowledges that pending work may
fail, asks the selected supervisor to stop first, and then bounds exact-lineage
cleanup. An ambiguous, overflowing, or surviving tree stays suppressed and
requires manual cleanup.

## Executable trial and final activation

### Linux

A candidate or predecessor trial is loaded but **disabled and unmasked**, has
`Restart=no`, no false `Condition*`/`Assert*`, and no owned or foreign inbound
activator. The proof-owned enablement link is absent. Only after querying that
exact state does the controller call `systemctl start` with fixed arguments. A
zero exit is insufficient: a new InvocationID, MainPID/start time, cgroup, and
executable lineage must be observed.

The owned bot unit and invariant daemon template explicitly set
`Slice=system.slice`. Effective `Slice` and `ControlGroup` must agree with the
native exact-unit cgroup namespace; another hierarchy is a refusal, not a reason
to scan a broader slice. Unit, drop-in and enablement publication uses closed
native resource selectors and ownership CAS. The existing global systemd
parents retain their ownership and ACLs. A daemon enablement link targets the
shared template, while its link name identifies the concrete instance.

After current-run startup proof, final activation is split into two journaled
actions: publish/query `Restart=on-failure` while still disabled, then
create/query only the proof-owned `multi-user.target.wants` link. Link creation
is the boot-activation linearization point.

### Windows

`SERVICE_DISABLED` is limited to the retained-handle first-create protection
window while exact DACL and transition ownership are established. It is not a
startable candidate state. Before candidate or predecessor trial, SCM must
query exactly `SERVICE_DEMAND_START`, empty failure actions, and a suppressed
failure-actions flag under T. Only then may the controller call `StartServiceW`.
API success is insufficient: a new Shawl wrapper and child PID/start/executable
epoch must be observed.

The native launch binds the protected `homeDirectory` into the fixed `HOME`
and `USERPROFILE` environment keys for both components. It neither accepts a
general environment map nor changes profiles or APPDATA. Component-local
`.env` remains tied to the configured working directory. These launch arguments
do not replace effective-home and SDK-state verification.

`START_PENDING` may report an invalid or zero PID. Its receipt acknowledges a
start request only; even a nonzero SCM PID is not an observed process epoch.
Deletion likewise remains pending until retained handles close and exact
absence is observed.

After current-run startup proof, final activation is split into two journaled
actions: set/query `SERVICE_AUTO_START` while actions remain empty, then
set/query the bounded three-at-10-seconds wrapper failure actions with a
600-second reset period and then no further action. AUTO_START is
the boot-activation linearization point. Shawl child restart, SCM wrapper
restart, reboot activation, clean exit, and intentional stop remain distinct.

### Controller loss and reboot

Controller death does not stop a running trial process and is not a watchdog.
Automatic platform activation remains suppressed, but Shawl's selected child
policy may still operate while its wrapper survives. Same-boot recovery may
continue only from the persisted exact boundary and current epoch. Otherwise it
stops the exact tree, proves quiescence, and performs a fresh trial. Reboot while
suppressed leaves the service stopped and requires a fresh trial. Reboot or an
epoch change after partial/final activation invalidates the old startup receipt;
recovery resuppresses and retrials rather than declaring readiness
retrospectively.

## Startup evidence and read-only status

The startup gate lasts at most 60 seconds from its captured explicit-start
boundary. It binds boot, resource and release proof, Linux InvocationID or
Windows wrapper/child epoch, exact process lineage, and a continuous journal or
log cursor. Bot readiness requires current-epoch listener/login and the exact
configured connected-host set at the decision boundary. Daemon readiness
requires the exact target registration attempt and `registration accepted`.
Neither is a live health protocol.

Status uses only closed dimensions:

- ownership: `absent | owned | foreign | ambiguous`
- service: `missing | stopped | running | transitioning | unknown`
- activation: `enabled | suppressed-controller-startable | disabled-not-startable | drifted | unknown`
- tree: `empty | exact-current | ambiguous | overflow | unknown`
- startup evidence: `none | fresh-current-epoch | historical-current-epoch | invalidated | unavailable`
- connectivity: `last-observed-connected | last-observed-disconnected | startup-only | unknown`
- provider health: `unknown`
- workspace health: `unknown`
- recovery: `clean | pending | manual-cleanup`

A startup receipt becomes historical after its bounded gate. Reboot, resource
change, process epoch change, or evidence-source gap invalidates it. Missing
evidence is unavailable. Daemon status cannot infer a same-PID disconnect from
its existing startup-only markers. Status never downloads, creates, waits,
repairs, starts, stops, enables, rotates logs, or exposes raw identity, path,
command, query, credential, environment, prompt, or log content.

## Consequences

- Unified tuple bundles can store files unused by a single-role host.
- Content addressing avoids a mutable current-pointer race and makes exact
  reference-based cleanup possible.
- Purpose-isolated deployment trust limits key reuse, but reviewed production
  public keys and signed application/Shawl assets remain mandatory release-owner
  gates.
- Windows continues to report Shawl as
  `project-attested-unsigned-upstream`; this ADR does not claim Authenticode or
  source-to-binary provenance.
- Candidate and predecessor start are executable before automatic activation,
  but a trial process may outlive controller failure.
- Some Windows crashes between service creation and the protected ownership
  marker intentionally require operator cleanup.
- External state is byte-preserved; incompatible state or SDK identity blocks
  the operation rather than invoking a migration.
- Disk retention includes current, predecessor, and proof-owned temporary
  artifacts plus per-service signed deployment-envelope evidence until exact
  recovery or a later proven-unreferenced garbage-collection design.

## Alternatives rejected

- Split component release sets: adds sibling finality and compatibility states
  without changing lockstep coordination.
- Reuse the native-addon key: violates trust-purpose isolation.
- Mutable checkout, `latest`, package-manager install, or post-extraction build:
  introduces downgrade and TOCTOU behavior.
- Caller URLs: introduce a privileged SSRF and provenance surface.
- Independent shell/PowerShell journals: duplicate ownership and recovery rules.
- `shawl add`, password-bearing command lines, or localized `sc.exe` parsing:
  do not meet credential and exact-query requirements.
- Direct Node/Bun SCM service, NSSM, WinSW, or a new wrapper: changes or degrades
  the approved supervisor contract.
- A systemd mask/false condition or Windows disabled trial: also prevents the
  controller's explicit start and therefore cannot prove candidate startup.
- A resident monitor or new health protocol: outside #240.

## Evidence and remaining gates

The shared schemas, private protected-store implementation, lifecycle
CLI/entrypoint, acquisition/orchestration, Linux/Windows drivers, fake-native
model tests, and this ADR are contract source, not platform evidence.
Production support remains blocked until the source implementation is paired
with the following independently reviewed deployment and evidence gates:

1. a real purpose-isolated deployment public key and nonempty pinned trust
   store;
2. signed application and Shawl manifests/assets accepted through the
   implemented pinned-only, module-local provenance brand;
3. safe streaming acquisition, extraction, immutable publication, and exact
   garbage collection integrated with the retained-envelope store and sequence
   floors;
4. native revision-4 primitives and least-privilege service facade;
5. production-authorized systemd and SCM/Shawl driver deployments implementing
   every intent/action/observed boundary;
6. source-level lifecycle orchestration, CLI, recovery fault injection, and
   no-mutation status tests paired with production qualification; and
7. source-bound real evidence on separately authorized disposable Linux x64,
   Linux arm64, and Windows x64 hosts.

No service command, key generation, signing, release, deployment, or host
mutation is authorized or evidenced by this ADR.
