# Workspaces and paths

## Authority is not discovery

The authenticated management mapping is the **only** route authority. It binds
an authorized channel/workspace identity to its host route. A daemon's local
inventory, native verification result, and receipt can provide capability
evidence; none may select a route, replace the authenticated mapping, or
supply a path by inference. Do not guess paths from repository names, channel
names, labels, inventory entries, or prior sessions.

This boundary prevents a local observation from becoming a remote authorization
decision. Its full contract is in
[bind-authority verification](../adr/0004-workspace-bind-authority-verification.md)
and [management mapping](../management-mapping-envelope.md).

## Native inputs and managed frames

Legacy native configuration keeps `{hostId, workDir}` as its operator input.
`workDir` is an absolute path in the daemon host's own platform syntax: for
example, `C:/projects/app` on Windows or `/srv/app` on Linux. Relative paths
are invalid. The daemon canonicalizes the path before it uses it, so spelling
variants, symlink retargeting, and junction changes are not a basis for a stale
or guessed session identity.

Managed protocol frames do **not** carry raw host paths. They use authenticated
binding/workspace identities and generations. Operators must create or change
routes through the mapping authority, never by inserting a local path into a
managed frame or by treating an inventory record as a route request.

The effective legacy session identity is `(hostId, canonical workDir)`. The
same canonical work directory can reuse a daemon-local SDK session; it does not
confer access to another host, channel, binding, or tenant.

## Persistence, backup, and rollback

A workspace is more than its checked-out files. Account for:

- the daemon service account's `~/.gjc` provider credentials and model profile;
- daemon-local session and state storage, whose security checks can be tied to
  its owner and work directory;
- authenticated mapping authority records, bindings, generations, receipts,
  and monotonic durability floors; and
- application data and any workspace-specific backup/restore procedure.

Back up only through access-controlled processes and keep secrets and raw host
paths out of routine support exports. A snapshot is not permission to rewind:
do not restore an old authority volume, mix it with a newer reader, or use a
backup to bypass a changed binding or durable floor. Once durable authority
state advances, recover forward with a compatible current-or-newer reader.
Likewise, copying `~/.gjc` or session state between OS accounts, hosts, or path
layouts can break ownership/provider assumptions and is not a generic
migration technique.

## Trust boundary

A host-wide daemon account and its mapped workspaces share a trust domain. That
is operational convenience, **not tenant isolation**. Anyone admitted to a
mapped Discord channel can initiate code-capable work under the daemon account,
subject to the bot allowlist and mapping authority. Use separate hosts and
separate credentials for isolation requirements, keep the bot WebSocket
private, and retain the fail-closed allowlist and per-host tokens.

For readiness and receipt semantics, see
[workspace readiness](../protocol-v2-workspace-readiness.md). Native serving
remains default-off and should not be inferred from inventory verification;
[daemon deployment](daemon.md) records its exact opt-in and evidence status.
