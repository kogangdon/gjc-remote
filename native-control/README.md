# Native inventory publisher

`gjc-remote-inventory` is the host-local management publisher for the verified
native inventory capability. It has no portable filesystem fallback. Its
authority is limited to capability-derived inventory evidence; it is not route
authority. Issue #44 remains the sole authority for routes, mappings,
authorization, and their persistence.

## Provisioning and invocation

Before publishing, provision both host leaves through the native management
authority:

- the management inventory leaf for the host; and
- the daemon reader leaf for the same host.

The publisher creates neither leaf and never creates, replaces, or advances the
reader floor. UNC workspace inputs are accepted by the schema but are
deterministically refused by the native capability when no supported
containment primitive exists.

The executable accepts exactly one operand:

```text
gjc-remote-inventory publish
```

Standard input must be non-terminal and contain exactly one EOF-terminated,
strict UTF-8 JSON document no larger than 1 MiB:

```json
{"hostId":"host-a","expectedInventoryGeneration":0,"workspaces":[]}
```

The document has exactly `hostId`, `expectedInventoryGeneration`, and
`workspaces`. `expectedInventoryGeneration` is a safe integer from zero through
`Number.MAX_SAFE_INTEGER`; workspaces are at most 64 exact
`{workspaceId,sourcePlatform,workDir}` records. `workspaceId` is a unique
1–128-byte `[A-Za-z0-9][A-Za-z0-9._-]*` token. `sourcePlatform` is `posix`,
`windows-drive`, or `windows-unc`; `workDir` is nonempty strict text of at most
4096 UTF-8 bytes. BOMs, invalid UTF-8, duplicate or unknown keys, unsafe
numbers, controls, and trailing data are refused.

The only role input is `GJC_INVENTORY_ROLE_BINDINGS`, at most 32 KiB, containing
strict JSON with exact keys `management`, `bot`, `recovery`, `daemon`, and
`system`. Each value is an exact canonical `{kind,value}` principal. All values
must use the local platform kind, be pairwise distinct, and `system` must be
`uid:0` on Linux or `S-1-5-18` on Windows. No payload, path, host, generation,
or principal fallback is read from the environment or command line.

## Results and operations

Success writes one canonical JSON line, the public publisher receipt:

```text
{commitFingerprint,inventoryFingerprint,inventoryGeneration,status,writes}
```

Failure writes one canonical JSON line to standard error and exits nonzero:

```text
{ambiguous,code,operation,status,writes}
```

It never writes input, paths, principals, messages, or causes to either stream.

Publishing is generation-CAS. Genesis requires expected generation zero and
publishes generation one. A valid accepted inventory can advance exactly one
generation. A published inventory awaiting the daemon reader floor is pending:
the identical candidate is unchanged, while a semantic change is refused.
The reader floor is read-only here. A malformed, partial, conflicting, or
ambiguous publication produces or respects the absorbing manual-cleanup marker;
operators reconcile it externally and preserve its evidence before retrying.

Inventory records are evidence from retained native workspace facts (canonical
path plus root and storage identity), not claimed routing data. Native serving
and readiness serving flags remain false; this publisher does not enable either.

## Candidate native service substrate

The synchronous package factory is `createServiceNative({ roles })`. Its
options object has exactly the one own data property `roles`. That value has
exactly `management`, `bot`, `recovery`, `daemon`, and `system`, each an exact
canonical `{kind,value}` principal. All five values use the local platform kind,
are pairwise distinct, and pin `system` to `S-1-5-18` on Windows or `uid:0` on
Linux. The factory snapshots and freezes those values before loading native
code, so later caller mutation cannot change authority.

The factory always uses the package's `loadVerifiedAddon()` path and current
platform/ABI/manifest/provenance checks. Callers cannot supply a loader, addon
or manifest path, trust store, platform, or service root. It returns a frozen
facade containing exactly these 43 native methods:

```text
set_exact_service_acl                 verify_exact_service_acl
read_file_facts_no_follow             read_boot_id
read_process_facts                    enumerate_process_tree
read_linux_service_cgroup             terminate_linux_service_cgroup
open_win32_service                    close_win32_service
query_win32_service                   create_win32_service_disabled
protect_win32_service                 set_win32_service_marker
configure_win32_service_launch        set_win32_service_start_type
set_win32_service_failure_actions     set_win32_service_failure_actions_flag
start_win32_service                   stop_win32_service
delete_win32_service                  terminate_win32_service_tree
open_service_root                     open_service_directory
acquire_service_lock                  close_service_handle
read_service_file                     publish_service_file_atomic
remove_service_object_exact           list_service_directory
publish_service_directory_no_replace  open_linux_service_scope
read_linux_service_object             publish_linux_service_object
remove_linux_service_object           begin_service_artifact_write
write_service_artifact_chunk          finish_service_artifact_write
open_service_artifact_reader          read_service_artifact_chunk
remove_service_artifact_file_exact    seal_service_directory
open_service_artifact_source
```

Each public method has the corresponding native capability signature with its
single `roles` parameter removed. The captured tuple is inserted only at that
declared position. Thus the seven authority-bearing public signatures are
`set_exact_service_acl(path, profile)`,
`verify_exact_service_acl(path, profile)`,
`open_win32_service(name, serviceRole, access)`,
`create_win32_service_disabled(name, serviceRole, supervisorPath,
supervisorSha256, workingDirectory, homeDirectory, runtimePath, runtimeSha256,
entrypointPath, entrypointSha256, logDirectory, logAs, logCmdAs,
channelsConfig, servicePassword)`, `open_service_root(rootKind, access)`,
`open_linux_service_scope(serviceKey, access)`, and
`open_service_artifact_source(path, maxBytes, expectedFacts)`. All other signatures are
unchanged. Every wrapper rejects missing or extra arguments and otherwise
passes values, opaque handles, byte buffers, receipts, and native errors
unchanged. It exposes no raw addon, management, inventory, workspace-serving,
generic dispatch, filesystem fallback, or role-substitution surface.

The record APIs retain their 16 MiB bound. Artifact writers and readers instead
stream files up to 2 GiB using chunks of 1 byte through 1 MiB. A zero-byte file
uses no write chunks; a positive-size read at offset zero proves empty EOF.
Offsets must match exactly. Finish requires the declared size/hash, durable
content and parent metadata, and one of `service-staging-file`,
`service-release-file`, or `service-release-executable`. Closing an unfinished
writer leaves its identifiable partial in staging; it never implies completion.
Shared artifact-fact validation has the separate 2 GiB bound; metadata-fact
validation and the nine record primitives still stop at 16 MiB.

An owned reader retains its parent/root and artifact fence. An external-source
reader retains every no-follow ancestor and the regular file, grants no write
authority, and checks physical/security identity and digest through EOF.
`expectedFacts` is either `null` for a new observation or the exact prior facts;
the second archive pass must reopen against those facts. Artifact cleanup uses
exact facts and streaming hashes rather than file-sized expected byte buffers.
Directories seal bottom-up after their children have final profiles; publication
requires a sealed closure and never replaces an existing release. Artifact scans
allow 100,001 immediate entries, including the inventory; control scans retain
their 100,000-entry limit.

The package-private offline acquisition reader uses only retained native source
handles, verifies bounded byte counts and hashes through EOF, and closes readers
on failure or cancellation. Signed asset reads require the installed verifier's
exact manifest brand. Offline input makes no transport-origin claim and does not
replace independent native-addon provenance verification.

The private GitHub transport uses fixed release-asset routes, bundled certificate
roots, at most three approved HTTPS redirects, bounded headers and bodies, and
one ten-minute source lifetime. It accepts no caller URL, credentials, request
options, or trust override. Modeled transport tests are not live TLS evidence.

The private archive verifier uses pinned `tar` 7.5.22 with explicit raw framing
checks and two complete passes. Its accepted gzip subset is one member with no
optional fields, zero MTIME, and portable OS byte 255. Tar contains regular
ustar files, zero padding, and exactly two terminal zero blocks. A local PAX
header may carry `path`, an equal-size assertion, `mtime`, and `SCHILY.nlink=1`;
other rewrites, global metadata, links, special files, and extra bytes refuse.
Its synthetic name must remain `PaxHeader/<single-component>`, whether encoded
entirely in the name field or split across ustar prefix/name fields for Unicode
basenames. That metadata name supplies no payload-path authority.
The release builder must emit this subset. Inspection is not extraction,
publication, or deployment-signature authority.

Session-owned artifact access requires freshly verified retained signatures and
an exact same-transaction sequence reservation or authenticated committed replay
before staging writes. An identical globally committed release from another
transaction does not supply that admission. Borrowed access prevents parent
mutation or close; staged readers release their native child on verified EOF,
cancellation, or failure. Root bootstrap retries only a nonambiguous,
zero-local-write `SERVICE_ALREADY_EXISTS` result from `create-new`; it never
turns an unregistered external parent into existing-mode adoption.

Private session collection uses
`collectPublishedArtifact({purpose, manifest, transaction, publication})`.
It requires an installed-branded manifest, same-session publication, committed
transaction, freshly verified retained signature, and fresh complete
cross-service reference checks under the existing exclusive artifact fence.
A zero-reference observation alone is not deletion authority. Protected
`manual/<service-key>/artifact-cleanup.json` intent retains exact ownership and
progress through `payload-removing`, `inventory-removing`, and `root-removing`.
Application inventory is removed after payload files and descendant directories.
`recoverPublishedArtifactCollection()` takes no target arguments and derives
authority from that retained intent. Collection never creates or repairs fixed
roots, and never removes journals, floors, retained signatures, or external state.
Scratch cleanup uses the same intent record as a scope-discriminated union
(`scope: 'scratch'`) with phases candidate-payload, candidate-inventory,
candidate-root, asset, marker, and scratch-root removal, each CAS-published
before its destructive boundary. Admission requires a committed transaction
with residue or durable floor-history abandon evidence; an active reservation
refuses. A partial staged asset without a candidate is removed by exact native
facts under the artifact fence. A partial candidate is cleaned only when the
complete staged archive freshly passes the authentic two-pass inspection on
every restart; unknown entries always refuse. Missing, corrupt, or incomplete
archive evidence with a nonempty candidate requires manual cleanup. Regression
evidence for both scopes is modeled, not protected-root or platform deletion
proof.

The private acquisition orchestrator composes these boundaries under one
ten-minute lifetime. It retains signed envelopes before reserving floors and
requires the caller's authenticated `sequence-reserved` journal before requesting
asset bodies or opening artifact access. Publication closes each borrowed access
before committing its floor; the caller still owns journal transitions,
references, activation, and the session itself. Closing acquisition cancels its
resources but does not delete partial artifacts or close the caller's session.
GitHub acquisition requires `native: null`; offline acquisition uses only the
role-bound readonly source facade.
Returned resources are registered before post-call deadline checks. Failed
closes retain ownership for retry, including offline readers; errors expose
closed diagnostic codes and validated cumulative session write counts.

The private native-manifest verifier independently uses the installed native
trust store and requires the bundled native keyset to match its complete
normalized key identities. Empty, development-only, foreign, or changed bundled
pins cannot replace installed authority. The application manifest's native
`manifestFingerprint` is SHA-256 of the original signed native manifest bytes.
The frozen result authenticates metadata and an approved addon digest only:
actual streamed bytes must match before publication, and normal native loading
and export verification remain required before activation.

Acquisition also requires the primary
`node_modules/@gjc-remote/native-control` package and every nested alias to match
the root native-control file set, sizes, hashes, and executable policies,
excluding each package's nested `node_modules`. Marker-as-file, dependency-only
shadow packages, and Windows noncanonical alias spelling refuse. Authenticated
platform and architecture fields identify the signed target, not observed
execution. Composition tests use real fixture signatures, archive parsing, and
offline readers with modeled store/native boundaries; they do not prove real
store fencing, protected-root publication, TLS, or platform execution.

Seal and publication verify the complete descendant tree, not just directory
profiles. Closure is bounded to 100,001 files, 6,400,064 containing directories,
64 path segments, 4,096 UTF-8 path bytes, and 2 GiB plus 32 MiB of file content.
Empty directories, special files, unsealed descendants, and identity/hash drift
refuse. Once sealing enters security application, failure poisons and closes its
directory authority. These walks are synchronous; maximum-sized tree performance
remains a disposable-host gate.

Final profiling is publication preparation, not a staging confidentiality
guarantee. On Windows, workload tokens with `SeChangeNotifyPrivilege` can bypass
ancestor traversal checks and read a known final-profile payload path before
publication. This grants neither staging directory listing nor content writes;
unsealed staging files and control records retain their private leaf ACLs.

`open_service_root` returns the native-verified fixed path in
`rootBinding.rootPath`, also bound by its root witness. It is for protected launch
assembly, not an environment override or a field to copy into public lifecycle receipts. Windows native role
admission requires existing user accounts for non-SYSTEM roles; factory shape
validation does not provision accounts or establish their effective permissions.

The fixed Windows daemon command passes Bun `--no-env-file` before its entrypoint.
The application's pinned dotenv loader still reads the external cwd `.env`;
Bun must not prepopulate values from `.env.local`, environment-specific files,
or its own variable expansion. Node bot arguments do not receive this Bun flag.
Effective runtime options and machine/service environment remain preflight
obligations; this flag alone does not prove the effective configuration.

Fixed intermediary containers distinguish native-created managed directories
from preserved safe external directories. Managed creation records independent
history before exposing the fixed name. Only `create-new` may register an
unchanged safe external container, after ruling out prior lifecycle roots,
witnesses, pending markers, and other service history. Existing-container reads
never register or repair: unregistered or inconsistent evidence returns
zero-write manual cleanup. Registration needs child-add rights at the verified
outside anchor and, on Windows, identity-verified durability access including
`FILE_GENERIC_READ | FILE_GENERIC_WRITE`, checked before the first write.
Ordinary inspection needs only read/traverse/security rights.
Pre-existing parent ownership, ACLs, and unrelated contents are not normalized.
Managed intermediaries grant workload traversal while control and unsealed
staging children retain private profiles.

Owned Windows profiles retain `WRITE_DAC | WRITE_OWNER` for management, recovery,
and system so protected objects can undergo authorized profile transitions.
Workload, preserved-container, and external log permissions are not broadened.
An already-correct management owner is preserved during ACL application; owner
changes require existing authority, never automatic privilege enabling.

The unpublished revision-4 service primitives are separate from inventory and
mapping authority. Their SHA-256 operations use maintained operating-system
providers: CNG/BCrypt on Windows and the kernel `AF_ALG` `hash`/`sha256` provider
on Linux. Linux service support requires `CONFIG_CRYPTO_USER_API_HASH` and a
SHA-256 implementation. Missing or failing providers refuse the operation;
there is no handwritten hash or fallback digest. Existing inventory operations
do not acquire service authority through this addition.

A local native build or fixture-signed load is not production provenance.
Deployment signing uses the separate policy in
[`deployment-keys/README.md`](deployment-keys/README.md); a bundled native addon
still needs its own independently trusted signature. Real service mutation and
protected-root evidence require a separately authorized disposable host. The
ordinary native test suite does not perform SCM mutations.
Its temporary-file source tests exercise real read/identity behavior under the
current OS caller. Its empty temporary-directory ACL test exercises repeated
application and a final-directory profile transition under the actual M/S caller.
These do not prove cross-account recovery or workload access, protected-root
bootstrap, artifact writes, sealing, GC, or service operation.

## Native addon build reproducibility

Windows Release builds deliberately replace, rather than append to, node-gyp's
inherited compiler, librarian, and linker `AdditionalOptions`. The linker
replacement contains `/Brepro` and `/PDBALTPATH:%_PDB%`: the first removes
variation in linker-controlled PE/COFF metadata, while the second embeds only
the PDB filename instead of an absolute build-machine path. Do not change the
`AdditionalOptions=` keys to appending `AdditionalOptions`; doing so
reintroduces Node's LLVM-only `-opt:lldltojobs=2` option and causes MSVC
`link.exe` to fail with `LNK1117`.

CI retains the unsigned addon and build manifest for all supported targets as
`native-control-unsigned-linux-x64`,
`native-control-unsigned-linux-arm64`, and
`native-control-unsigned-win32-x64`. Matching bytes from clean builds with the
same pinned source, toolchain, and checkout path demonstrate reproducibility only. They do not
establish independent source provenance, and byte-for-byte identity is not
promised across toolchain versions. External signing and independent provenance
verification remain separate requirements.

Local Windows checks produced identical binaries across two clean builds at
one path. A build at a different checkout path still differed, despite the
normalized embedded PDB filename. Cross-path reproducibility is not established.

## Unsigned application release tooling

Repository-local `build:service-release` and `verify:service-release` npm scripts
invoke the private builder; they do not sign, publish, install, or activate a
release. Build takes exactly `--source`, `--output`, `--platform`,
`--architecture`, `--release-sequence`, `--signing-key-id`, `--native-addon`,
`--native-manifest`, and `--native-signature`. Verify takes only `--candidate`.
Output must be a new directory outside the source tree.

`deploy/native/release-contract.json` fixes the repository, release tag, supported
tuples, Bun 1.4.2 recipe, runtime versions, source selection, and format registry.
The source must be clean Git state at that tag with canonical `bun.lock` and
both separate public trust resources tracked. Git hooks/fsmonitor and replacement
objects cannot supply authority; configured executable filters refuse before
cleanliness checks. Native metadata/signature and actual addon bytes must match
independently installed native pins. These checks do not execute the addon.

Materialization uses actual frozen production Bun installation with fresh cache
and HOME, fixed npm registry, and ignored scripts. Complete selected workspace
and dependency files, resolved dependency edges, native aliases, and SDK source
contracts are checked again from the unsigned archive. Windows producers refuse
Linux targets because their filesystem metadata cannot preserve POSIX executable
policy. Archive modes are projected from inventory policy rather than inferred
again while packing.

Modeled Bun-process tests demonstrate builder behavior, not real registry/SRI
materialization. The separately invoked `test-fixtures/service-release-real-bun.mjs`
requires `--acknowledge-real-bun-fixture-build`; it uses synthetic temporary Git
state and ephemeral fixture trust only. Its outputs are test evidence, never
operation proof, or production signing authority.

## Lifecycle evidence harness

`node scripts/service-lifecycle-evidence.js generate --output <outside-checkout>/service-lifecycle-evidence.json --acknowledge-service-lifecycle-fixture`
creates a bounded, canonical, fixture-only lifecycle receipt. The harness
creates temporary source, worktree, and configuration roots outside the
checkout, uses fake native and in-memory model inputs, and performs no service,
systemd, SCM, protected-root, host, key, or signing operation. Its receipt is
limited to the modeled operation matrix, crash/recovery classifications,
external-sentinel byte preservation, startup/status observations, and explicit
safe platform-driver refusals. It contains no fixture paths, secrets, or raw
diagnostics; generation also fences the source fingerprint and verifies
identity-safe cleanup before returning.

The receipt labels these claims as `fakeEvidence`. They are not human gates:
real systemd and SCM operation, a disposable-host run, and production signing
remain separate `humanGates` requiring independent authorization and evidence.
Verify a receipt without executing anything with:

```text
node scripts/service-lifecycle-evidence.js verify --receipt <outside-checkout>/service-lifecycle-evidence.json
```

The acknowledgement is intentionally required for generation. A fixture receipt
must never be presented as service-operation, platform, deployment, or release
provenance.
