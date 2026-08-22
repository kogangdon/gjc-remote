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
