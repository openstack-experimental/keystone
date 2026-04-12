# 16. Distributed Encrypted Storage via Raft and Fjall

Date: 2026-04-12

## Status

Proposed

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

## Compliance

All secret handling must implement the Zeroize trait to ensure plain-text data
is wiped from RAM immediately after gRPC transmission.
