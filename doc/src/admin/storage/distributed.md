# Distributed Encrypted Storage

This guide covers the architecture, cryptographic design, and operational
procedures for the Keystone-RS distributed storage engine. The design is
specified in [ADR 0016-v2](../../adr/0016-v2-raft-storage.md) and implemented
across four crates: `openstack-keystone-distributed-storage` (consensus, state
machine, gRPC), `openstack-keystone-storage-crypto` (shared cryptographic
primitives and the `KekProvider` trait), and the two production KEK providers,
`openstack-keystone-storage-crypto-pkcs11` and
`openstack-keystone-storage-crypto-tpm`.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Crate Layout](#crate-layout)
3. [Key Hierarchy](#key-hierarchy)
4. [Encryption Details](#encryption-details)
   - [Raft Log Encryption](#raft-log-encryption)
   - [State Machine Encryption](#state-machine-encryption)
   - [Backup Encryption](#backup-encryption)
   - [Nonce Management](#nonce-management)
5. [Data Tiers and Read Consistency](#data-tiers-and-read-consistency)
6. [Intra-Cluster Transport (mTLS)](#intra-cluster-transport-mtls)
   - [Peer Roles](#peer-roles)
7. [Audit Log](#audit-log)
8. [Quarantine and GCM Failure Handling](#quarantine-and-gcm-failure-handling)
9. [DEK Rotation](#dek-rotation)
10. [Deployment Guide](#deployment-guide)
    - [Configuration Reference](#configuration-reference)
    - [PKCS#11 and TPM KEK Providers](#pkcs11-and-tpm-kek-providers)
    - [First-Time Cluster Bootstrap](#first-time-cluster-bootstrap)
    - [Adding Nodes](#adding-nodes)
    - [TLS Certificate Management](#tls-certificate-management)
11. [Operational Runbook](#operational-runbook)
    - [Cluster Metrics](#cluster-metrics)
    - [Scheduled DEK Rotation](#scheduled-dek-rotation)
    - [Emergency DEK Rotation](#emergency-dek-rotation)
    - [Clearing a Quarantined Partition](#clearing-a-quarantined-partition)
    - [Backup and Restore](#backup-and-restore)
12. [Security Invariants](#security-invariants)

---

## CLI Reference

All cluster management operations use `keystone-manage storage <subcommand>`.
Every subcommand except `init` and `join` takes `--cluster-addr <URI>`, the
cluster member to contact; it defaults to `node_cluster_addr` from the config
file when omitted. `init` always targets that local address, and `join` takes
the member to contact as its positional argument.

| Subcommand                                                                          | Target      | Description                                                 |
| ----------------------------------------------------------------------------------- | ----------- | ----------------------------------------------------------- |
| `init`                                                                              | local node  | Bootstrap a new single-node cluster                         |
| `join <cluster-addr>`                                                               | leader      | Join the local node as a Raft learner                       |
| `promote [--cluster-addr] <node-id>`                                                | leader      | Promote a learner to voting member                          |
| `demote [--cluster-addr] <node-id>`                                                 | leader      | Demote a voter to non-voting learner                        |
| `remove-peer [--cluster-addr] <node-id>`                                            | leader      | Remove a voter from the cluster membership                  |
| `list-peers [--cluster-addr]`                                                       | any node    | Show cluster peers in a table                               |
| `metrics [--cluster-addr]`                                                          | any node    | Show raw cluster metrics and leader status                  |
| `status [--cluster-addr]`                                                           | any node    | Show DEK, rotation, quarantine and nonce state of the node  |
| `clear-quarantine [--cluster-addr] [--partition <name>]`                            | leader      | Clear a GCM-failure quarantine (default partition `data`)   |
| `rotate-dek [--cluster-addr] [--emergency]`                                         | leader      | Rotate the Data Encryption Key                              |
| `rotate-dek [--cluster-addr] --local-quorum-bypass --justification <text>`          | given node  | Stage a node-local emergency DEK candidate (no quorum)      |
| `confirm-rotate-dek [--cluster-addr] --rotation-id <id>`                            | leader      | Confirm a pending emergency DEK rotation                    |
| `list-dek-local-emergency-candidates [--cluster-addr]`                              | given node  | List node-local emergency DEK candidates                    |
| `reconcile-dek-local-emergency [--cluster-addr] --rotation-id <id>`                 | leader only | Install a node-local emergency DEK candidate through Raft   |
| `backup [--cluster-addr] --output <file>`                                           | leader      | Create an encrypted Fjall snapshot                          |
| `restore [--cluster-addr] --snapshot <file> [--elect]`                              | leader \*   | Restore an encrypted snapshot to the cluster                |

**Leader targeting.** Membership changes, DEK rotations, quarantine clearing,
backup and restore into a running cluster must be proposed by the Raft leader.
A follower answers these RPCs with `UNAVAILABLE` plus the leader's id and address
(`x-openraft-leader-id`, `x-openraft-leader-endpoint`), and the subcommands
marked _leader_ retry against that address, so `--cluster-addr` may name any
member. The call is not proxied between nodes: the operator's own identity
reaches the leader, which is where the request is authorized, rate limited and
audited. `reconcile-dek-local-emergency` (_leader only_) does not follow the
redirect; it prints the leader's address so the operator can first check that
the leader holds the candidate. (\*) Disaster-recovery `restore` into an
uninitialized node runs on the given node.

`demote` and `remove-peer` of the current leader make it step down once the
change commits; leadership transfer is not implemented, so the cluster has no
leader, and writes fail, until the election timeout elects a new one.

---

## Architecture Overview

The storage engine combines three components:

| Layer                         | Component          | Purpose                                           |
| ----------------------------- | ------------------ | ------------------------------------------------- |
| **Consensus**                 | `openraft`         | Log replication, leader election, linearizability |
| **State machine / log store** | `fjall` (LSM-tree) | Durable on-disk persistence, SSD-optimized        |
| **Transport**                 | gRPC over mTLS     | Intra-cluster Raft RPC (SPIFFE or custom PKI)     |

All data is encrypted before it touches the Raft log or the Fjall on-disk
storage. A full disk compromise or log exfiltration reveals only AES-256-GCM
ciphertext — no plaintext, no key material.

```text
┌─────────────────────────────────────────────────────────────────┐
│  Keystone API layer                                             │
└───────────────────────────────┬─────────────────────────────────┘
                                │  StorageApi trait
┌───────────────────────────────▼─────────────────────────────────┐
│  Storage struct (app.rs)                                        │
│  • Raft client  • DEK epoch  • Audit forwarder                  │
└───────┬───────────────────────┬─────────────────────────────────┘
        │ Raft proposals        │ Local reads (Tier 0/1)
┌───────▼───────────────────────▼─────────────────────────────────┐
│  OpenRaft (consensus)                                           │
│  ┌──────────────────┐         ┌────────────────────────────┐    │
│  │  FjallLogStore   │         │  FjallStateMachine         │    │
│  │  (log_store.rs)  │         │  (state_machine.rs)        │    │
│  │  Log DEK encrypt │         │  State DEK encrypt/decrypt │    │
│  └──────────────────┘         └────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
        │                                       │
        ▼                                       ▼
  Fjall (log keyspace)                Fjall (state keyspace)
  [nonce][ciphertext][tag]            [nonce][ciphertext][tag][version]
```

### Write Path

1. The API serializes the mutation to MessagePack.
2. The Log DEK encrypts the payload (nonce: `node_id_BE ++ counter_BE`, AD:
   `term_BE ++ index_BE`).
3. OpenRaft proposes the encrypted blob and replicates it over mTLS to a quorum.
4. On apply, the state machine decrypts the log entry using the Log DEK.
5. The current per-record `version` is read from Fjall (0 for new records).
6. The State DEK re-encrypts the value for at-rest storage (HKDF-derived nonce,
   AD: `tier ++ domain ++ primary_key`), then writes
   `[nonce_12b][ciphertext][tag_16b][version_u32_BE]` to Fjall.

### Read Path

- **Tier 0 / 1 (PUBLIC / INTERNAL):** The local state machine decrypts and
  returns the value directly.
- **Tier 2 / 3 (SENSITIVE / SECRET):** A `ReadIndex` (linearizable read) is
  issued to OpenRaft first, ensuring no stale follower can return a value that
  has since been revoked.

---

## Crate Layout

```
crates/
├── storage-crypto/            # All cryptographic primitives
│   └── src/
│       ├── lib.rs             # Public re-exports
│       ├── kek.rs             # KekProvider trait, EnvKek (production
│       │                      #   providers: storage-crypto-pkcs11, -tpm)
│       ├── dek.rs             # DekEpoch, LogDek, StateDek, BackupDek, generate_dek
│       ├── cipher.rs          # log_encrypt/decrypt, state_encrypt/decrypt,
│       │                      #   backup_encrypt/decrypt
│       ├── nonce.rs           # NonceManager — durable monotonic counter
│       └── audit.rs           # AuditHmacKey
│
├── storage-crypto-pkcs11/     # Production KekProvider: PKCS#11 HSM/token
│   ├── src/lib.rs             # Pkcs11Kek, Pkcs11KekParams, SlotSelector
│   └── tests/softhsm.rs       # SoftHSM2-backed wrap/unwrap round-trip test
│
├── storage-crypto-tpm/        # Production KekProvider: TPM 2.0 resident key
│   ├── src/lib.rs             # TpmKek, TpmKekParams, KeyReference
│   └── examples/
│       └── tpm_kek_demo.rs    # Runnable sample against a software TPM (swtpm)
│
└── storage/                   # Consensus, gRPC, state machine
    └── src/
        ├── lib.rs             # StorageApi impl, DEK bootstrap
        ├── app.rs             # init_storage, Storage struct, StorageApi impl
        ├── preflight.rs       # OS-level memory protection checks
        ├── audit.rs           # AuditForwarder, AuditRecord
        ├── network.rs         # NetworkManager, SpiffeTlsProvider,
        │                      #   CertExpiryWatchdog, validate_svid_ttl
        ├── store/
        │   ├── log_store.rs   # FjallLogStore (OpenRaft LogStorage impl)
        │   └── state_machine.rs # FjallStateMachine (OpenRaft StateMachine impl)
        ├── grpc/
        │   ├── cluster_admin_service.rs  # init, add_learner, rotate_dek, …
        │   ├── raft_service.rs           # Raft RPC forwarding
        │   └── storage_service.rs        # Data read/write RPCs
        └── store_command.rs   # StoreCommand, MutationInner, DataTier
```

---

## Key Hierarchy

```text
 PKCS#11 HSM/token, or TPM 2.0 resident key  (production)
  │  or
  KEYSTONE_DEV_KEK env var  (dev mode only)
  │
  ▼
Key Encryption Key (KEK)                — never enters RAM as plaintext (prod)
  │
  │  AES-256-GCM unwrap
  ▼
Data Encryption Key (DEK)              — 256-bit random, mlock'd allocation
  │
  ├── Log DEK     HKDF-Expand(DEK, "keystone-raft-log-v1",    L=32)
  ├── State DEK   HKDF-Expand(DEK, "keystone-fjall-state-v1", L=32)
  └── Backup DEK  HKDF-Expand(DEK, "keystone-backup-v1"
                               ++ dek_version_u32_BE,          L=32)

Audit HMAC key  HKDF-Expand(KEK, "keystone-audit-hmac-v1"
                              ++ node_id_u64_BE,               L=32)
```

HKDF-Expand-only is used because the DEK is already uniformly random;
HKDF-Extract would add no entropy. Each sub-key is domain-separated by a
distinct info string, ensuring ciphertexts from different contexts are never
encrypted under the same key material.

The Audit HMAC key is derived from the **KEK** (not the DEK) so it survives DEK
rotation without needing re-derivation, while remaining per-node to prevent
cross-node forgery.

### DEK Persistence

The wrapped DEK is stored in Fjall under the key `_meta:dek:current` as
`[version_u32_BE; 4] ++ wrapped_bytes`. On startup, `init_storage` reads this
key, unwraps the DEK under the KEK, derives sub-keys, and stores an
`Arc<RwLock<Arc<DekEpoch>>>` that all state machine operations share.

---

## Encryption Details

### Raft Log Encryption

**Function:** `log_encrypt(log_dek, plaintext, term, index) → Vec<u8>`

**On-disk layout:** `[nonce_12b][ciphertext][tag_16b]`

| Field            | Value                                          |
| ---------------- | ---------------------------------------------- |
| Nonce (12 bytes) | `[node_id_u64_BE; 8] ++ [counter_u32_BE; 4]`   |
| Associated data  | `term_u64_BE ++ index_u64_BE`                  |
| Tag              | 16 bytes (full GCM tag, truncation prohibited) |

The AD binding of `term ++ index` prevents an attacker from replaying a log
entry from a different Raft position.

### State Machine Encryption

**Function:**
`state_encrypt(state_dek, plaintext, tier, domain_id, pk, version) → Vec<u8>`

**On-disk layout:** `[nonce_12b][ciphertext][tag_16b][version_u32_BE]`

| Field            | Value                                                            |
| ---------------- | ---------------------------------------------------------------- |
| Nonce (12 bytes) | `HKDF-Expand(StateDek, pk ++ version_u32_BE, L=12)`              |
| Associated data  | `[tier_u8] ++ domain_id ++ pk`                                   |
| Tag              | 16 bytes                                                         |
| Version suffix   | `version_u32_BE` (read back on next write to compute next nonce) |

The HKDF-derived nonce guarantees uniqueness across record updates: each
`(pk, version)` pair produces a distinct nonce even if the same plaintext is
re-written. The version starts at 0 for new records and increments on every
write, stored as a 4-byte suffix alongside the ciphertext.

The `tier` byte in the AD cryptographically binds the sensitivity classification
to the ciphertext — altering the stored tier makes the GCM tag invalid.

**Write rate guard:** If `version >= write_rate_threshold` (default `2^30`,
approximately 1 billion writes per record), further writes to that key are
blocked with a `WRITE_RATE_EXCEEDED` violation and a CRITICAL log entry is
emitted; a WARN is logged from 90% of the threshold. The per-record version
keeps counting across DEK rotations (re-encryption increments it too), so a
rotation does not lift the block for a record that reached it.

### Backup Encryption

**Function:**
`backup_encrypt(bdek, snapshot_bytes, dek_version, utc_epoch, nonce_salt) → Vec<u8>`

**On-disk layout:**
`[dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8] ++ [nonce_salt_u64_BE; 8] ++ [nonce_12b][ciphertext][tag_16b]`

| Field           | Value                                                          |
| --------------- | -------------------------------------------------------------- |
| Associated data | `b"keystone-backup-v1" ++ utc_epoch_u64_BE ++ dek_version_u32` |

The `dek_version` and `utc_epoch` in the AD bind the snapshot to a specific
point in time and DEK epoch, preventing time-travel and replay attacks across
backup archives. `nonce_salt` is a fresh random 64-bit value generated per
snapshot and mixed into the nonce derivation alongside `utc_epoch`, so two
snapshots written within the same wall-clock second (including across a process
restart, when a sequential in-memory counter would otherwise reset to 0) still
get distinct nonces; it is stored directly in the header, so decryption reads it
rather than searching for it. The header also carries a DEK manifest: the
current DEK and every retired DEK the snapshot may still need, each wrapped
under the KEK. A node holding the same KEK can therefore decrypt the backup even
if it does not know these DEKs yet.

### Nonce Management

The `NonceManager` (`storage-crypto/src/nonce.rs`) maintains a durable monotonic
counter for Raft log nonces:

- Keeps one counter per DEK epoch, persisted node-locally in Fjall under
  `_meta:nonce:<node_id>:ctr:<epoch>` with its high-water mark under
  `_meta:nonce:<node_id>:hwm:<epoch>`. A DEK rotation therefore starts a fresh
  counter. A counter is never reset, so an epoch that becomes current again
  (after a restore) continues where it stopped. Snapshot installs and restores
  keep the node's own counters.
- Nodes upgraded from the single per-node counter (`_meta:nonce_ctr:<node_id>`)
  record the epoch current at upgrade time; that epoch and every older one start
  no lower than the old counter.
- Reserves blocks of 1024 counts on each flush to absorb node crashes without
  nonce reuse.
- On startup, validates the recovered counter against the persisted high-water
  mark; **refuses to start** if the counter is behind the HWM (operator
  intervention required).
- Emits a WARN when fewer than 10% of the `2^31` threshold remain. From that
  point the leader rotates the DEK automatically (see
  [DEK Rotation](#dek-rotation)). At `2^31` the node can no longer append log
  entries under that DEK.

---

## Data Tiers and Read Consistency

Each record carries a `DataTier` marker (0–3) that is part of the AES-GCM
associated data and stored in the record metadata.

| Tier | Label       | Read path                | Examples                                    |
| ---- | ----------- | ------------------------ | ------------------------------------------- |
| 0    | `PUBLIC`    | Local read               | Feature flags, role display names           |
| 1    | `INTERNAL`  | Local read               | Display attributes, config markers          |
| 2    | `SENSITIVE` | Linearizable (ReadIndex) | Group memberships, session tokens, API keys |
| 3    | `SECRET`    | Linearizable (ReadIndex) | Credential plaintext, TOTP seeds            |

Tier 2 and 3 always issue a `ReadIndex` RPC to the current Raft leader before
reading from the local state machine, ensuring a revoked credential or removed
group member can never be observed as still-valid on a lagging follower.

> **Not implemented:** the local read path for Tier 0/1 and the
> `local_reads_mode` option that would select it do not exist yet. Every read,
> whatever its tier, goes through `ReadIndex`.

---

## Intra-Cluster Transport (mTLS)

All cluster communication uses TLS 1.3 with AEAD cipher suites only
(`TLS_AES_256_GCM_SHA384` or `TLS_CHACHA20_POLY1305_SHA256`). Manual joining is
permanently disabled; every peer must present a valid mTLS identity.

### SPIFFE Mode (Default)

```toml
[distributed_storage]
trust_domains = "example.org"
```

- SVIDs issued by SPIRE are rotated automatically. TTL must not exceed 1 hour.
- Nodes reject SVIDs with less than 5 minutes remaining (force-renewal window).
- If SPIRE is unavailable before the renewal window, the node drains proposals
  and halts — it does **not** fall back to an expired SVID (fail-closed).
- Incoming SVIDs are mapped to a role (see [Peer Roles](#peer-roles)); anything
  that maps to no role is rejected with `PERMISSION_DENIED` at the gRPC
  interceptor.
- Each node pins the SVID it presents: the first `allowed_peer_svids` entry's
  path when that list is set (the cluster's shared storage identity), else
  `spiffe://<trust-domain><spiffe_path_prefix>node`. Register that identity in
  SPIRE for every storage workload; if it is missing, storage initialization
  stalls in the SVID source retry loop and the node never becomes ready.
- `allowed_peer_svids` must be non-empty when `dev_mode = false`; the
  configuration is rejected otherwise.

### TLS Fallback Mode

```toml
[distributed_storage]
tls_cert_file    = "/etc/keystone/storage/node.pem"
tls_key_file     = "/etc/keystone/storage/node.key"
tls_client_ca_file = "/etc/keystone/storage/ca.pem"
```

- Certificates must be signed by a dedicated Keystone Intermediate CA.
- Leaf certificate validity must not exceed 30 days.
- `CertExpiryWatchdog` checks remaining validity hourly: WARN at 7 days, ERROR
  at 2 days. It only logs; it does not shut the node down at expiry. It watches
  a certificate given inline (`tls_cert_content`), not one given as a file.
- The peer role is read from the first URI SAN of the client certificate. Set
  `tls_role_san_prefix` to the SAN URI prefix; the role name follows it. In TLS
  mode the role names are fixed to `node` and `storage-operator`;
  `operator_role` is not honoured:

  ```toml
  [distributed_storage]
  tls_role_san_prefix = "spiffe://keystone/storage/"
  # node cert SAN URI:     spiffe://keystone/storage/node
  # operator cert SAN URI: spiffe://keystone/storage/storage-operator
  ```

- Without `tls_role_san_prefix` the configuration is valid only with
  `dev_mode = true`, where every CA-signed peer is accepted for every RPC
  (legacy permissive behaviour, a warning is logged). With `dev_mode = false` it
  is a configuration error.
- The role is never derived from the certificate CN.

### Peer Roles

Every inter-node and operator RPC is authorised by the role of the calling
certificate. In SPIFFE mode (`spiffe_path_prefix` defaults to
`/keystone/storage/`, `operator_role` to `storage-operator`):

| Peer SVID                                          | Role     |
| -------------------------------------------------- | -------- |
| `spiffe://<td><spiffe_path_prefix>node`            | Node     |
| `spiffe://<td><spiffe_path_prefix><operator_role>` | Operator |
| exact entry of `allowed_peer_svids`                | Node     |
| anything else (including the former `/ns/` form)   | rejected |

The `/ns/...` SVID fallback has been removed. An `allowed_peer_svids` entry that
lies under `spiffe_path_prefix` is resolved by the role convention, not by the
allow-list, so it cannot be used to grant the operator role to an arbitrary
name.

| RPC                                                                                                                      | Node | Operator |
| ------------------------------------------------------------------------------------------------------------------------ | ---- | -------- |
| `RaftService.*`                                                                                                          | yes  | no       |
| `StorageService.{Command, ForwardedGet, ForwardedPrefix, ForwardedPrefixIndex, ReportQuarantine}`                        | yes  | no       |
| `ClusterAdmin.{FetchDek, GossipLocalEmergencyCandidate}`                                                                 | yes  | no       |
| `ClusterAdmin.{AddLearner, Metrics}`                                                                                     | yes  | yes      |
| `ClusterAdmin.{Init, ChangeMembership}` and all other operator RPCs (backup, restore, rotate DEK, clear quarantine, ...) | no   | yes      |

**Which identity each command uses.** In SPIFFE mode `keystone-manage` takes its
SVID from the Workload API of the workload it runs in:

- `join` presents the node's own SVID (`allowed_peer_svids[0]`, else
  `<spiffe_path_prefix>node`) and therefore needs the `Node` role. Run it on the
  joining node, whose `node_id` and `node_cluster_addr` it announces.
- Every other subcommand presents the workload's **only** SVID. `list-peers` and
  `metrics` accept `Node` or `Operator`; `init`, `promote`, `demote`,
  `remove-peer` and all other operator RPCs need `Operator`. Run these from an
  operator workload registered as `<spiffe_path_prefix><operator_role>` (and
  nothing else), not from a storage node: a node holds the `Node` role only, and
  a workload holding several SVIDs presents an arbitrary one. The workload needs
  a `distributed_storage` section so the CLI knows `trust_domains` and the
  cluster address (`node_cluster_addr`; subcommands with a `--cluster-addr`
  option can override it). The skaffold test cluster does this with the
  `keystone-storage-operator` Deployment
  (`tools/k8s/tests/keystone-storage-operator.yaml`).
- When SPIRE is run by the helm chart's controller-manager, every
  `ClusterSPIFFEID` must set `spec.className` (default `spire-spire`); classless
  ones are silently ignored and the workload never receives the SVID.

The data-plane `StorageService.Command` RPC accepts only a `Transaction` made of
`Set`, `Remove`, `RemoveIndex`, `CreateIfAbsent` and `SetIndex` mutations.
Restore, DEK install, quarantine and rotation commands are rejected with
`PERMISSION_DENIED` there; they are proposed in-process only.

> **Upgrade note (breaking change).** Role resolution is stricter than in
> earlier builds. The role path convention is resolved first: any SVID under
> `spiffe_path_prefix` must be exactly `<spiffe_path_prefix>node` or
> `<spiffe_path_prefix><operator_role>`. An SVID such as
> `spiffe://<td>/keystone/storage/node-1` is under the prefix with an unknown
> role name and is denied even when listed in `allowed_peer_svids`; re-register
> it as `<spiffe_path_prefix>node`. `allowed_peer_svids` is only for SVIDs
> outside the prefix (for example `spiffe://<td>/ns/<namespace>/sa/<sa>`), which
> must be listed verbatim. Before upgrading, register every storage workload
> under `<spiffe_path_prefix>node`, and the operator under
> `<spiffe_path_prefix><operator_role>`. In TLS mode, add the role SAN and set
> `tls_role_san_prefix`.

#### Rate limits

Per-identity rate limiters (for example `2` DEK rotations per hour, `10`
`ClearQuarantine` calls per hour, `30` quarantine reports per hour) are held in
memory on each node. They are **not** replicated through Raft and reset on
restart. These RPCs are only served by the leader (a follower redirects before
taking a token), so the limit applies per leader: it starts afresh after a
leader change.

### NodeId Uniqueness

Each node has a manually configured `node_id: u64`. At startup and on every
`add_learner` gRPC call, the cluster membership is checked for a
`(node_id, rpc_addr)` collision. A detected collision is fatal — the node or the
operation is aborted with a clear error message. If membership cannot be queried
(no quorum), startup fails closed.

---

## Audit Log

Every security-relevant operation is signed and written to a durable, fsynced
local spool. An external shipper (for example Filebeat or Vector) tails the
spool and forwards it to the SIEM; the storage engine itself does not open a
network connection to the SIEM.

**Spool line structure** (one JSON object per line):

```json
{
  "record": {
    "timestamp": 1750000000,
    "event_type": "DEK_ROTATION",
    "actor": "operator@example.org",
    "node_id": 1,
    "dek_version": 3,
    "details": {}
  },
  "key_version": 3,
  "hmac": "<hex>"
}
```

**Signature:** `HMAC-SHA256(AuditHmacKey, record_bytes)`, where `record_bytes`
is the exact bytes of the `record` object as written in the line (do not
re-serialise it before verifying).

**Key derivation:** the key is derived from the DEK of the epoch it signs for,
not from the KEK:
`HKDF-Expand(DEK, info = "keystone-audit-dek-v1" ‖ dek_version_u32_be ‖ node_id_u64_be)`.
It rotates with every DEK epoch swap, on every node, and the `key_version` field
names the epoch whose key signed the line — verifiers select the key by
`key_version`. The `node_id` binding gives each node a distinct key. Because the
key derives from the DEK, a verifier needs the epoch's key material exported
from a cluster node; export and retention of epoch keys is an operator
responsibility and is not automated.

**Availability:** the spool is bounded by `audit_max_spool_bytes` (default 256
MiB, directory `audit_spool_dir`, default `<path>/audit-spool`). At 90% a
`CRITICAL` alert is logged; at 100% the oldest sealed segment is deleted and an
`ERROR` is logged. Spool contents are **not** encrypted at rest (files are
created `0600`). Spool exhaustion or write failure never blocks writes to the
identity store, but dropped records are counted in
`keystone_raft_audit_dropped_total`; the current spool size is exposed as
`keystone_raft_audit_spool_bytes`.

**Shipping:** when `[audit] sink` is configured (see
[Configuration options](../../configuration/options.md)), Keystone ships the
sealed `raft-audit-<node_id>.jsonl.seg-*` segments to that sink verbatim and
deletes each one after the sink acknowledged it; the live file is not touched.
Delivery is at-least-once, so receivers should deduplicate. Without a sink, an
external shipper must tail the spool as before. The records keep their own
signature scheme described above; they are not CADF events.

**Ordering and failures:** a record is emitted only after the Raft write it
describes has been attempted. A failed operation produces `<EVENT>_FAILED` with
the error in `details.error`, never the success event. Every node additionally
emits `DEK_INSTALLED` when it applies a DEK epoch swap.

Audited events include: `DEK_ROTATION`, `DEK_ROTATION_EMERGENCY_STAGED`,
`DEK_ROTATION_EMERGENCY_CONFIRMED`, `DEK_ROTATION_EMERGENCY_ABORTED`,
`DEK_ROTATION_LOCAL_EMERGENCY_STAGED`,
`DEK_ROTATION_LOCAL_EMERGENCY_RECONCILED`, `DEK_INSTALLED`,
`QUARANTINE_CLEARED`, `BACKUP_CREATED`, `BACKUP_RESTORED`, and the `_FAILED`
variants of the Raft-committed operations.

---

## Quarantine and GCM Failure Handling

GCM tag verification failures indicate tampered or corrupted ciphertext.

| Failure count (within 60 s) | Action                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| 1                           | WARN log, metric increment                                                                 |
| 2                           | ERROR log, alert                                                                           |
| 3                           | Drain in-flight Raft proposals, commit quarantine marker via Raft, set partition read-only |

Quarantine state is **Raft-committed** (stored in
`_meta:quarantine:<node_id>:<partition>`) and therefore persists across restarts
and is visible to all cluster members. A restarted node reads this key at
startup and re-enters quarantine if the marker is set.

Clearing quarantine requires a `storage-operator` identity:

```sh
keystone-manage storage clear-quarantine --partition <partition>
```

The clear operation is committed via Raft (so it takes effect cluster-wide) and
is recorded in the audit log.

### Reporting Quarantine from Followers

A follower that detects a GCM failure asks the leader to commit the quarantine
marker through the dedicated `StorageService.ReportQuarantine` RPC (Node role).
The leader validates the report against the current Raft membership, applies a
rate limit of 30 reports per hour per reporter identity, and writes an audit
record.

All nodes share the `node` role, so the reported `node_id` is not bound to the
caller's certificate. A compromised node can therefore report a quarantine for
the partition of any cluster member. The exposure is bounded by the membership
check, by the rate limit (which, because every node presents the same identity,
is effectively one bucket per serving node), and by the audit record. Recovery
is `ClearQuarantine`, which is operator-only. Binding each node to its own SVID
is deferred (see ADR 0016-v2 addendum on peer roles).

---

## DEK Rotation

The Raft leader rotates the DEK automatically when either holds:

- **Age:** the current DEK was installed `dek_rotation_days` ago (default 90;
  `0` disables this trigger). Each node records when it applied the DEK under
  `_meta:dek:installed_at`; nodes upgraded from a version that did not record it
  start the interval at their first start after the upgrade.
- **Volume:** the leader's log nonce counter for the current DEK has used 90% of
  its `2^31` space. This trigger cannot be disabled.

The leader checks every 5 minutes and skips the check while an emergency
rotation waits for its confirmation. An automatic rotation is the same
`InstallDek` proposal as a manual one and is audited as `DEK_ROTATION` with the
actor `system:dek-rotation` and the trigger in the details. A rotation proposes
the next DEK version; when two rotations race for the same version (for example
an automatic and a manual one), the second is rejected with a
`STALE_DEK_VERSION` violation and the installed DEK is kept. The rotation is a
live background process with no downtime.

**Normal rotation:**

```sh
keystone-manage storage rotate-dek
```

**Emergency rotation** (suspected DEK compromise — requires dual-control):

```sh
# Operator A initiates:
keystone-manage storage rotate-dek --emergency
# returns rotation_id=<uuid>

# Operator B confirms within 5 minutes:
keystone-manage storage confirm-rotate-dek --rotation-id <uuid>
```

If the 5-minute confirmation window expires without confirmation, the pending
rotation is automatically aborted and an audit entry is written. Emergency
rotations mark the old DEK as `revoked` (not `retired`) — it is never reused for
any decryption, even for backup archives from that epoch.

**Re-encryption:** Each node re-encrypts its own Fjall records under the new
DEK in a background task, keyspace by keyspace in key order. A record is read,
re-encrypted with `version + 1` and written while `apply()` is excluded from
that record, so a concurrent Raft write is never reverted. A record that cannot
be migrated after 3 attempts is skipped and logged at WARN. The sweep runs when
a rotation is applied and again every 5 minutes for every retired DEK that still
has records under it, so skipped records are retried without waiting for the
next rotation. A pass that finds nothing left to migrate marks the retired DEK
as done (`_meta:dek:reencrypt_done:<version>`). Retired DEKs are kept for
reading older snapshots and backups.

**Progress:** Every 1000 records the sweep checkpoints its position and counts
to `_meta:dek:rotation_progress:<node_id>:<version>`. After a restart the next
pass resumes behind the checkpoint, and records skipped before the restart
still keep the retired DEK from being marked done. The checkpoint is removed
when a pass completes and is not carried by snapshots.

> **Not implemented:** a post-rotation verification report, the CRITICAL alert
> for records left unmigrated for 24 hours, and blocking DEK retirement until
> they are resolved. Skipped records are only visible in the WARN logs and are
> retried by the periodic sweep.

---

## Deployment Guide

### Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)
- A SPIRE deployment, or TLS certificates from a dedicated Intermediate CA
- For production: a PKCS#11 HSM/token (`kek_provider = "pkcs11"`) or a TPM 2.0
  chip (`kek_provider = "tpm"`) for KEK storage — see
  [PKCS#11 and TPM KEK Providers](#pkcs11-and-tpm-kek-providers)
- For development: set `KEYSTONE_DEV_KEK` and `KEYSTONE_ALLOW_ENV_KEK=1`

### Configuration Reference

```toml
[distributed_storage]
# Unique identifier for this node within the cluster. Must be a u64.
# Collision with an existing node at a different address is fatal.
node_id = 1

# Advertised cluster-internal address (used by peers for Raft RPC).
node_cluster_addr = "https://10.0.0.1:8310"

# Local listener address for inbound cluster connections.
node_listener_addr = "0.0.0.0:8310"

# Directory where Fjall database files are stored.
path = "/var/lib/keystone/storage"

# Age in days after which the leader rotates the DEK automatically
# (default: 90). 0 disables the age trigger; the log nonce volume trigger
# always stays on.
dek_rotation_days = 90

# Per-record write version at which further writes to the record are
# rejected (default: 2^30).
write_rate_threshold = 1073741824

# Selects the production KEK source. "env" (default) is dev-mode only and is
# rejected unless dev_mode = true. See "PKCS#11 and TPM KEK Providers" below.
# kek_provider = "pkcs11"
# kek_provider = "tpm"

# --- Transport: SPIFFE (default) ---
trust_domains = "example.org"

# --- Transport: TLS fallback ---
# tls_cert_file    = "/etc/keystone/storage/node.pem"
# tls_key_file     = "/etc/keystone/storage/node.key"
# tls_client_ca_file = "/etc/keystone/storage/ca.pem"
# # Or embed content directly (base64 or PEM):
# tls_cert_content = "..."
# tls_key_content  = "..."
# tls_client_ca_content = "..."
```

**Environment variables (development only):**

| Variable                 | Description                                                                    |
| ------------------------ | ------------------------------------------------------------------------------ |
| `KEYSTONE_DEV_KEK`       | Hex-encoded 256-bit KEK. Requires `--dev-mode` and `KEYSTONE_ALLOW_ENV_KEK=1`. |
| `KEYSTONE_ALLOW_ENV_KEK` | Must be set to `1` when using `KEYSTONE_DEV_KEK`.                              |

> **Warning:** `KEYSTONE_DEV_KEK` and `KEYSTONE_ALLOW_ENV_KEK` must never appear
> in production Dockerfiles, Kubernetes manifests, or systemd units. The CI gate
> `tools/check_no_dev_mode.sh` enforces this.

### PKCS#11 and TPM KEK Providers

Production deployments select one of the two hardware-backed `KekProvider`
implementations (ADR 0016-v2 §2.5). Both wrap/unwrap the DEK with
`CKM_AES_GCM`/TPM2 AES-GCM directly against a non-extractable AES-256 key object
— the key material never leaves the token or chip.

#### PKCS#11 (HSM or token)

```toml
[distributed_storage]
kek_provider = "pkcs11"

[distributed_storage.pkcs11]
# Path to the vendor's (or SoftHSM2's) Cryptoki shared library.
pkcs11_module_path = "/usr/lib/softhsm/libsofthsm2.so"

# CKA_LABEL of the AES-256 key object. Must have CKA_EXTRACTABLE = false
# (ADR 0016-v2 §10 invariant 13). init_storage never creates this key —
# it must already exist via an operator's out-of-band provisioning step.
pkcs11_key_label = "keystone-kek"

# Either the slot id or the token label must be given; label is preferred
# since slot ids can shift across token re-initialisation.
pkcs11_slot_label = "keystone-storage"
# pkcs11_slot_id = 0

# File containing the token PIN. Never accepted inline or via env var
# (ADR 0016-v2 §10 invariant 14).
pkcs11_pin_file = "/etc/keystone/storage/pkcs11.pin"
```

Provisioning the key (a one-time operator ceremony, run once per token before
the cluster's first boot) uses any Cryptoki client capable of generating a
non-extractable AES-256 key under the target label — for example,
`pkcs11-tool --keygen --key-type AES:32 --label keystone-kek`, or the
provisioning helper in `crates/storage-crypto-pkcs11/tests/softhsm.rs` and
`crates/storage/tests/test_pkcs11_cluster.rs`, which do the equivalent
programmatically against SoftHSM2 for local testing.

**Local testing against SoftHSM2:**

```sh
# libsofthsm2.so and the softhsm2-util CLI:
sudo apt-get install -y softhsm2

# Run the SoftHSM2-backed tests (skip themselves if the module isn't found):
cargo test -p openstack-keystone-storage-crypto-pkcs11
cargo test -p openstack-keystone-distributed-storage --features pkcs11 --test test_pkcs11_cluster
```

#### TPM 2.0

```toml
[distributed_storage]
kek_provider = "tpm"

[distributed_storage.tpm]
# TCTI connection string: a hardware TPM's resource manager device, or a
# software TPM (swtpm) for testing.
tpm_tcti = "device:/dev/tpmrm0"

# Exactly one of the following identifies the pre-provisioned AES-256 key:
tpm_key_handle = "0x81000001"      # persistent handle, or:
# tpm_key_context_file = "/etc/keystone/storage/tpm-kek.ctx"

# Optional: file containing the key's auth value (userWithAuth keys only).
# tpm_auth_file = "/etc/keystone/storage/tpm.auth"
```

As with PKCS#11, `init_storage` only ever opens the key with
`auto_generate: false` — provisioning is a separate operator step.
`crates/storage-crypto-tpm/examples/tpm_kek_demo.rs` is a runnable sample that
provisions and exercises a KEK against a software TPM:

```sh
# 1. Start a software TPM:
mkdir -p /tmp/swtpm-state
swtpm socket --tpmstate dir=/tmp/swtpm-state \
    --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
    --tpm2 --flags not-need-init &
TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321" tpm2_startup -c

# 2. Run the sample (first run provisions the key, later runs reload it):
cargo run -p openstack-keystone-storage-crypto-tpm --example tpm_kek_demo
```

This example is compiled in CI on every run to catch rot, but is not executed
there — real/virtual TPM availability isn't reliable enough on shared CI runners
to gate merges on (ADR 0016-v2 §2.5.2).

### First-Time Cluster Bootstrap

**Step 1 — Start each node** (do not initialize yet):

```sh
keystone --config /etc/keystone/keystone.conf
```

Each node starts and waits; Raft is not yet initialized.

**Step 2 — Initialize the first node** as a single-node cluster.

`init` registers the `node_id` and `node_cluster_addr` of the config it runs
with as the first member, so its config must describe node 1. In SPIFFE mode it
also needs the `Operator` role (see [CLI Reference](#cli-reference)): run it
from an operator workload whose `distributed_storage` section carries node 1's
values:

```sh
keystone-manage storage init
```

Node 1 becomes the leader of a 1-node cluster. Wait for it to report a leader
(check `keystone-manage storage metrics --cluster-addr https://10.0.0.1:8310`).

**Step 3 — Add learners.**

Run from node 2 and node 3's hosts respectively. The positional argument is the
address of any existing cluster member to contact:

```sh
# On node 2's host:
keystone-manage storage join https://10.0.0.1:8310

# On node 3's host:
keystone-manage storage join https://10.0.0.1:8310
```

**Step 4 — Promote learners to voting members.**

Run from an operator workload (SPIFFE mode: `storage-operator` SVID). The
command locates the leader through `--cluster-addr` (default: the workload's
`node_cluster_addr`), so it can contact any member. Repeat once per learner to
promote:

```sh
keystone-manage storage promote 2
keystone-manage storage promote 3
```

### Adding Nodes

To add a new node to a running cluster:

```sh
# 1. Start the new node process (it will wait for a join instruction).

# 2. On the new node's host, join to an existing cluster member:
keystone-manage storage join https://10.0.0.1:8310

# 3. Optionally promote to voting member (run from an operator workload):
keystone-manage storage promote 4
```

### TLS Certificate Management

**SPIFFE mode:** No operator action required. SPIRE rotates SVIDs automatically.
The node refuses connections from SVIDs with < 5 minutes remaining validity.

**TLS fallback mode:**

1. Generate a new certificate from your Intermediate CA (max 30-day validity).
2. Deploy the new certificate and key to the node.
3. Restart the node, or use a runtime reload mechanism if available.
4. The `CertExpiryWatchdog` logs WARN at 7 days remaining and ERROR at 2 days.

---

## Operational Runbook

### Cluster Metrics

Quick health check — shows current leader, voter set, and raw OpenRaft metrics:

```sh
keystone-manage storage metrics --cluster-addr https://10.0.0.1:8310
```

Sample output:

```
Current leader : node 1
Voters         : [1, 2, 3]
All nodes      : [1=10.0.0.1:8310, 2=10.0.0.2:8310, 3=10.0.0.3:8310]

Raw metrics:
Metrics{id:1, Leader, term:3, ...}
```

For a formatted peer table use `list-peers` instead.

### Storage Status

The DEK, rotation, quarantine and nonce state the runbooks below refer to is
reported per node by `status`:

```sh
keystone-manage storage status --cluster-addr https://10.0.0.2:8310
```

Sample output:

```
Node                  : 2
State                 : Follower
Current leader        : 1
Current term          : 3
Last log index        : 1042
Last applied index    : 1042
DEK version           : 4
Retired DEK versions  : 2, 3
Revoked DEK versions  : none
Pending rotations     : none
Quarantined (local)   : none
Quarantine records    : none
Nonce counter         : 18432 / 2147483648 (0.00%)
```

`Quarantined (local)` lists the partitions whose reads are blocked on this node;
`Quarantine records` lists every marker the node holds, including those reported
by other nodes. `Pending rotations` shows emergency rotations awaiting
`confirm-rotate-dek` (authoritative on the leader). The nonce counter is the
persisted reservation point (at most 1024 ahead of use); the node stops
accepting log writes when it reaches the threshold. Run the command against each
node of interest: DEK state can briefly differ while a follower applies a
rotation, and quarantine is node-local.

### Scheduled DEK Rotation

Automatic rotation fires after `dek_rotation_days` (default: 90) or when the
leader's log nonce counter for the current DEK reaches 90% of `2^31` (see
[DEK Rotation](#dek-rotation)). Manual rotation:

```sh
keystone-manage storage rotate-dek \
  --cluster-addr https://10.0.0.1:8310
```

Monitor the audit log (`event_type = "DEK_ROTATION"`; automatic rotations use
the actor `system:dek-rotation`) and the node logs for records the
re-encryption sweep skipped (`record skipped after exhausting CAS retries`).

### Emergency DEK Rotation

Use when a DEK is suspected compromised.

```sh
# Operator A — initiates rotation, receives rotation_id:
keystone-manage storage rotate-dek \
  --cluster-addr https://10.0.0.1:8310 \
  --emergency
# Output: rotation_id=550e8400-e29b-41d4-a716-446655440000

# Operator B — confirms within 5 minutes:
keystone-manage storage confirm-rotate-dek \
  --cluster-addr https://10.0.0.1:8310 \
  --rotation-id 550e8400-e29b-41d4-a716-446655440000
```

If no confirmation is received within 5 minutes, the rotation aborts
automatically and is recorded in the audit log. The `dek_rotation_days` timer
restarts when the confirmed rotation installs the new DEK.

### Clearing a Quarantined Partition

A partition enters quarantine after 3 GCM verification failures within 60
seconds. In quarantine, the partition is read-only and all writes to affected
keys are rejected with a `QUARANTINED` violation.

**Diagnosis:**

```sh
# Check the quarantine state of the affected node:
keystone-manage storage status --cluster-addr https://10.0.0.1:8310
```

Root-cause the GCM failures (hardware fault, storage corruption, or unauthorized
modification) before clearing quarantine.

**Clear:**

```sh
keystone-manage storage clear-quarantine \
  --cluster-addr https://10.0.0.1:8310 \
  --partition <partition-name>
```

> **Note:** the partition is now the `--partition` option (default `data`).
> Scripts that passed it positionally (`clear-quarantine <partition>`) must be
> updated.

This commits a Raft proposal (visible cluster-wide) and emits an audit entry.

### Backup and Restore

**Create a backup** (Fjall snapshot):

```sh
keystone-manage storage backup \
  --cluster-addr https://10.0.0.1:8310 \
  --output /mnt/backups/keystone-$(date +%Y%m%d).snap
```

The command triggers a fresh Fjall snapshot on the target node, then streams the
AES-256-GCM encrypted bytes to `--output`. The final output includes the
`snapshot_utc_epoch` and `dek_version` printed on completion for verification.

The snapshot is wrapped in a backup-specific AES-256-GCM envelope with the
Backup DEK, bound to the snapshot timestamp and current DEK epoch. Its header
carries the DEK manifest: the current and retired DEKs, wrapped under the KEK.

**Restore into a running cluster** (the usual case):

```sh
keystone-manage storage restore \
  --cluster-addr https://10.0.0.1:8310 \
  --snapshot /mnt/backups/keystone-20260101.snap
```

The backup must reach the **leader**; a follower answers with the leader's
address and the command retries there. The backup is committed through the
Raft log, in 256 KiB chunks followed by a single apply entry, so every node
replaces its data at the same log index. The cluster membership (node list) and
each node's Raft state are unchanged. Everything else, including all data
keyspaces and the DEKs, is replaced by the backup's contents, so anything
written after the backup was taken is gone. The DEKs recorded in the backup's
DEK manifest replace the cluster's current DEK on every node, so the restored
data stays readable. The cluster must use the same KEK material as the cluster
that produced the backup; a backup that cannot be unwrapped is rejected by the
apply entry and leaves the data untouched. The upload is streamed into the Raft
log as it arrives, so the receiving node never buffers it; the client's declared
size (sent with the first chunk) lets an oversized backup be refused before any
of it is read. A stalled upload is dropped after two minutes. The DEKs the
restore replaces are kept on every node so that the node's own Raft log and
older snapshot files stay readable. Backups larger than 1 GiB are refused on
this path (every node holds the reassembled and decrypted backup in memory while
applying it); use the disaster recovery procedure for those. That procedure
buffers the backup on each node (up to 4 GiB) and also needs it to be decrypted
in full. A restore that fails part-way discards its staged chunks.

**Disaster recovery** (the cluster is gone, no leader exists):

```sh
# 1. Start every node with `auto_bootstrap = false` so it stays uninitialized.
# 2. Restore the same backup on each node; pass --elect on exactly one of them:
keystone-manage storage restore \
  --cluster-addr https://10.0.0.1:8310 \
  --snapshot /mnt/backups/keystone-20260101.snap --elect
keystone-manage storage restore \
  --cluster-addr https://10.0.0.2:8310 \
  --snapshot /mnt/backups/keystone-20260101.snap
```

This follows OpenRaft's "restore from snapshot" procedure: the backup is
installed as a Raft snapshot on each node and the backup's Raft state,
**including its membership**, is restored. The original node ids and addresses
must therefore be reachable again. The elected node leads the next term. A node
that is not part of the backup's membership stays a learner and can be joined
afterwards. A node that is already initialized always takes the live path
instead, so a node that auto-initialized before the restore arrives restores
into its own single-node cluster and keeps that membership. `--elect` on an
initialized node is rejected with `FailedPrecondition`.

The restore validates the AES-256-GCM backup envelope (AD binding: epoch and
dek_version) and decrypts it with the Backup DEK derived from the DEK epoch the
backup names, unwrapped from the backup's DEK manifest (or found on the node).
The restoring cluster therefore needs the KEK the backup's DEKs are wrapped
under.

**Retired DEK retention:** Retired DEKs stay in the cluster, wrapped under the
KEK, and every backup carries the ones it needs, so archived backups remain
readable as long as the KEK is. There is no separate KMS role for backup or
retired DEKs; access to archived backups is controlled through the KEK.

---

## Security Invariants

The following invariants are enforced by the implementation and verified at code
review. Any change that violates them must be explicitly justified and approved
by the security team.

1. **No plaintext on disk.** Every byte is AES-256-GCM encrypted before the
   write call returns. GCM tags are always 16 bytes.

2. **No DEK in plaintext outside mlock'd RAM.** The DEK is stored wrapped under
   the KEK on disk. In memory it lives only inside mlock'd `Zeroizing` buffers.

3. **Strict mTLS.** Auto-join is permanently disabled. Every inbound connection
   must present a valid SPIFFE SVID or an operator-managed certificate signed by
   the cluster Intermediate CA.

4. **No stale reads for sensitive data.** Tier 2 and Tier 3 reads always execute
   the ReadIndex protocol before returning data.

5. **GCM failure quarantine is durable.** Quarantine state is committed via Raft
   and persists across node restarts.

6. **No environment-variable KEK in production.** Starting with
   `KEYSTONE_DEV_KEK` requires both `--dev-mode` and `KEYSTONE_ALLOW_ENV_KEK=1`.
   CI rejects deployment artifacts that contain these flags.

7. **NodeId collision detection is fail-closed.** A collision detected at
   startup or on `add_learner` is fatal. Inability to query membership (no
   quorum) is treated as a detected collision.

8. **DEK generation targets mlock'd memory.** The DEK must not be generated into
   an unlocked buffer and subsequently copied.

9. **Per-record write rate guard.** Writes beyond the version threshold (`2^30`
   by default) are blocked with a CRITICAL log. This prevents nonce-space
   exhaustion for pathologically hot keys within a DEK epoch.

10. **Nonce sources are deterministic and audited.** Random nonces are
    prohibited. All nonce strategies are documented in the ADR and reviewed by
    the security team before any new encrypted context is added.

11. **Deployment validation.** `tools/check_no_dev_mode.sh` runs in CI and
    rejects production service definitions containing `--dev-mode` or
    `KEYSTONE_ALLOW_ENV_KEK`.

12. **Startup pre-flight.** Before loading any key material, the node verifies
    `RLIMIT_CORE == 0` and `PR_SET_DUMPABLE == 0`. Failures emit CRITICAL log
    entries and (when `--dev-mode` is not set) prevent startup.
