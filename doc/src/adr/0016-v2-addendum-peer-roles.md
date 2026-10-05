# ADR 0016-v2 Addendum: Peer Roles for the Raft/Storage gRPC Surface

Date: 2026-10-05

## Status

Accepted

**Amends:** [ADR 0016-v2](0016-v2-raft-storage.md) §4.1 (SPIFFE mode) and the
gRPC authorization model.

## Context

Issue #1303: any peer holding a valid certificate from the trusted CA or trust
domain could call every RPC of the Raft and storage services. A compromised or
merely misconfigured workload in the trust domain could then initialise or
reconfigure the cluster, rotate the DEK, restore data or propose arbitrary state
machine commands. Role information was also taken from loosely matched SVID
paths (including a `/ns/...` fallback) and, in TLS mode, there was no role at
all.

## Decision

Introduce two peer roles and authorise every RPC against them. The role is
derived only from the immutable peer certificate identity (first URI SAN), never
from the CN.

### Role resolution

- SPIFFE mode: `<spiffe_path_prefix>node` is `Node`;
  `<spiffe_path_prefix><operator_role>` is `Operator` (defaults
  `/keystone/storage/` and `storage-operator`); the role convention is resolved
  first, so a path under the prefix with any other role name is rejected even if
  listed; an exact `allowed_peer_svids` entry outside the prefix is `Node`; the
  `/ns/` fallback is removed; any other path is rejected. `allowed_peer_svids`
  must be non-empty when `dev_mode = false`.
- TLS mode: the role is read from the URI SAN using `tls_role_san_prefix`.
  Without it the cluster runs permissively only when `dev_mode = true`;
  `dev_mode = false` without it is a configuration error. There is no default
  prefix.

### RPC matrix

| Role             | RPCs                                                                                                                                                                         |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node             | `RaftService.*`; `StorageService.{Command, ForwardedGet, ForwardedPrefix, ForwardedPrefixIndex, ReportQuarantine}`; `ClusterAdmin.{FetchDek, GossipLocalEmergencyCandidate}` |
| Node or Operator | `ClusterAdmin.{AddLearner, Metrics}`                                                                                                                                         |
| Operator         | `ClusterAdmin.{Init, ChangeMembership}` and all other management RPCs                                                                                                        |

`StorageService.Command` accepts only data mutations: a `Transaction` of `Set`,
`Remove`, `RemoveIndex`, `CreateIfAbsent` and `SetIndex`. Admin and restore
commands (`RestoreChunk`, `RestoreApply`, `RestoreAbort`, `InstallDek`,
`Quarantine`, `ClearQuarantine`, pending rotation commands) are proposed
in-process only and are denied on this RPC.

Follower-to-leader quarantine reporting moves to a dedicated `ReportQuarantine`
RPC, validated against current membership and rate limited to 30 reports per
hour per reporter identity.

## Consequences

- A workload that only holds a `node` identity can no longer initialise or
  reconfigure the cluster, restore backups, rotate or install DEKs, or clear
  quarantine.
- Breaking change: SVIDs under the prefix with an unknown role name (for example
  `<prefix>node-N`) are rejected even when listed in `allowed_peer_svids`; only
  SVIDs outside the prefix (for example `/ns/...`) can be allow-listed.
  Deployments must re-register workloads (the Kubernetes manifests use a fixed
  `.../keystone/storage/node` template) before upgrading.
- All nodes share the `node` role, so `ReportQuarantine` cannot bind the
  reported `node_id` to the caller's certificate. A compromised node can report
  a quarantine for any member's partition; this is bounded by the membership
  check, the rate limit (effectively per serving node, as the reporter identity
  is shared) and audit, and is recoverable with the operator-only
  `ClearQuarantine`. Per-node SVID binding is deferred as future work.
- `AddLearner` is allowed for any `Node`-role peer, so a compromised node can
  enrol an attacker-controlled learner, which then receives replication and can
  call `FetchDek`; this is mitigated only by the shared-node-identity trust
  boundary, and per-node binding or operator-only join is future work.
- Rate limiters (for example 2 rotations per hour) are per node, in memory, and
  reset on restart; they are not replicated through Raft.
