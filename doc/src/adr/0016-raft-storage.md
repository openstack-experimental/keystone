# 16. Distributed Encrypted Storage via Raft and Fjall

Date: 2026-04-12

## Status

Superseded by [ADR 0016-v2](0016-v2-raft-storage.md)

## Context

The current implementation of keystone requires a storage back-end that provides
high availability, strong consistency for identity assignments, and
industry-leading security for PII and secrets. Traditional SQL databases often
introduce complexity in secret management and lack native "At-Rest" encryption
tied to the application's lifecycle.

We need a solution that:

- Guarantees Consistency: Identity changes must be linearizable.

- Embedded Performance: An embedded LSM-tree to avoid external database network
  overhead.

- Cryptographic Sovereignty: Data must be encrypted before it hits the log or
  the disk, ensuring a "Zero-Knowledge" storage layer.

## Decision

We will implement a distributed storage engine using OpenRaft for consensus and
Fjall as the local State Machine and Log Store. The architecture will follow the
"Vault-style" encryption model.

1. The Storage Stack

- Consensus: openraft (Rust) for managing cluster membership and log
  replication.

- LSM-Tree: fjall for high-performance, disk-backed storage of the state
  machine.

- Serialization: rmp-serde (MessagePack) for compact binary representation of
  log entries.

2. The Cryptographic Barrier

To ensure data is never stored in plain-text on disk:

- AEAD Encryption: Use AES-256-GCM for all payloads.

- Log Binding: The Raft Index will be used as Associated Data (AD) for log
  entries to prevent replay attacks.

- Storage Binding: The Primary Key (e.g., UserID) will be used as AD for FjallDB
  entries to prevent key-substitution attacks.

- Key Hierarchy: A Master Key (KEK) provided via Environment/HSM will wrap a
  volatile Data Encryption Key (DEK) kept in memory.

3.  Data Flow

- Write Path:

  API receives a request → Serialize to MsgPack → Encrypt → Propose to OpenRaft.

  Apply step: Decrypt using Raft Index → Re-encrypt for storage → Write to
  Fjall.

- Read Path:

  Linearizable Read: Follower queries Leader for ReadIndex → Follower waits for
  local apply → Decrypt from Fjall → Return over mTLS.

## Technical Specifications

### gRPC Definitions

The internal Raft communication will use an opaque binary payload to keep the
consensus layer decoupled from the IAM logic.

Protocol Buffers

```rust

message RaftEntry {
  uint64 term = 1;
  uint64 index = 2;

  // Optional Membership config.
  Membership membership = 3;

  // Optional Store request.
  // [12b Nonce][Ciphertext][16b Tag] }
  optional bytes app_data = 4;
}
```

### Type Configurations (openraft)

```rust
openraft::declare_raft_types!(
    pub KeystoneConfig:
        D = EncryptedBlob, // Vec<u8> wrapper
        R = Response, // Ephemeral, plain-text over mTLS
        NodeId = u64,
        Node = BasicNode,
);
```

## Alternatives Considered

The decision is scoped to what Keystone owns. Consensus is delegated to OpenRaft
and persistence to Fjall; the code in `crates/storage` is the layer around them
(cryptographic barrier, mTLS transport, cluster operations such as join,
quarantine, restore and DEK rotation). The alternatives below were evaluated
against that scope.

### External consensus store (etcd, Consul, ZooKeeper)

Rejected. Adopting etcd would replace only the thin glue to OpenRaft while
leaving the expensive parts in Keystone.

- **No cryptographic barrier.** The requirement is that data is encrypted before
  it reaches the log or the disk. etcd has no application-layer encryption; its
  WAL, snapshots and keys are plaintext unless the operator encrypts them
  outside the store. Keystone would still need to encrypt every value, bind AD
  to key and Raft index, and manage the DEK/KEK hierarchy, so the security
  surface does not shrink while the guarantees get weaker (key names and
  revision metadata become visible).
- **Second trust and transport model.** etcd brings its own mTLS and auth. It
  would sit next to the SPIFFE/PKI identity used by Keystone and need
  reconciling.
- **Operational cost.** A second stateful cluster with its own backup, upgrade,
  compaction/defragmentation and quota (default 8 GiB) management contradicts
  the self-contained single binary goal.
- **Data model mismatch.** The raft-backed drivers (sessions, mappings, SCIM,
  API keys) rely on prefix and range scans and multi-key atomic commands applied
  in a state machine. etcd offers a flat KV with bounded transactions and
  leases, which moves invariants out of the state machine into client retry
  logic. High-churn data such as sessions is a poor fit for its MVCC B-tree,
  which keeps a revision per write.
- **Testability.** In-process multi-node clusters are used for join, restore,
  quarantine and rotation tests. An external store turns these into
  container-based tests.

Consul and ZooKeeper share these objections and fit the data model less well.

### Distributed SQL / KV databases (FoundationDB, CockroachDB, TiKV)

Rejected. They address horizontal scale that identity data does not need, are
substantially heavier to operate, and provide no application-layer encryption
barrier either.

### Relational database only (PostgreSQL, MySQL)

Not rejected, but not sufficient on its own. It remains available through the
`*-sql` drivers and operators may select it. It does not meet the requirement
that secrets are encrypted under an application-managed key hierarchy and that
the storage layer never observes plaintext, and it adds an external network
dependency. Raft storage is therefore an additional option and must not become
the only one.

### Different consensus or storage library

OpenRaft with Fjall is already the minimal embedded combination. Swapping the
LSM store or the Raft library would not change the surrounding layer and has no
benefit that justifies the migration.

### Revisit criteria

Reconsider this decision if the cluster operations code in `crates/storage`
begins to dominate maintenance cost, or if OpenRaft stops being maintained. In
both cases the remedy is first to simplify the operations surface rather than to
move to an external store.

## Consequences

### Positive

- Security: Compromising the disk or the Raft log does not leak user secrets.

- Performance: Fjall provides SSD-optimized writes and efficient prefix-seeking
  for IAM queries.

- Simplicity: No external dependency on Postgres/MySQL; the binary is
  self-contained. Operator is able to select the traditional SQL backend drivers
  though.

### Negative / Risks

- CPU Overhead: Every write/read involves AES-GCM operations.

- Operational Complexity: Cluster forming, backup/restore operations are now
  part of the Keystone operations.

- Stale Reads: If not configured correctly, followers might serve stale identity
  data unless the ReadIndex protocol is strictly followed.

- Maintenance Ownership: Snapshot, membership and restore handling around
  OpenRaft is maintained by this project rather than by an established external
  store, and the cryptographic design needs independent review.

## Compliance

All secret handling must implement the Zeroize trait to ensure plain-text data
is wiped from RAM immediately after gRPC transmission.
