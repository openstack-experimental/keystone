# Distributed Encrypted Storage

This guide covers the architecture, cryptographic design, and operational
procedures for the Keystone-RS distributed storage engine. The design is
specified in [ADR 0016-v2](adr/0016-v2-raft-storage.md) and implemented across
two crates: `openstack-keystone-distributed-storage` (consensus, state machine,
gRPC) and `openstack-keystone-storage-crypto` (all cryptographic primitives).

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
7. [Audit Log](#audit-log)
8. [Quarantine and GCM Failure Handling](#quarantine-and-gcm-failure-handling)
9. [DEK Rotation](#dek-rotation)
10. [Deployment Guide](#deployment-guide)
    - [Configuration Reference](#configuration-reference)
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
The `--cluster_addr` flag (type `URI`) selects which cluster member to contact;
it defaults to `node_cluster_addr` from the config file when omitted.

| Subcommand                                          | Description                                    |
| --------------------------------------------------- | ---------------------------------------------- |
| `init`                                              | Bootstrap a new single-node cluster            |
| `join <cluster-addr>`                               | Join the local node as a Raft learner          |
| `promote <node-id>`                                 | Promote a learner to voting member             |
| `demote <node-id>`                                  | Demote a voter to non-voting learner           |
| `remove-peer <node-id>`                             | Remove a peer from the cluster membership      |
| `list-peers`                                        | Show cluster peers in a table                  |
| `metrics`                                           | Show raw cluster metrics and leader status     |
| `clear-quarantine [--cluster-addr] [--partition]`   | Clear a GCM-failure quarantine (operator-only) |
| `rotate-dek [--cluster-addr] [--emergency]`         | Rotate the Data Encryption Key                 |
| `confirm-rotate-dek [--cluster-addr] --rotation-id` | Confirm a pending emergency DEK rotation       |
| `backup [--cluster-addr] --output`                  | Create an encrypted Fjall snapshot             |
| `restore [--cluster-addr] --snapshot`               | Restore an encrypted snapshot to the cluster   |

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
│       ├── kek.rs             # KekProvider trait, EnvKek, Pkcs11KekStub
│       ├── dek.rs             # DekEpoch, LogDek, StateDek, BackupDek, generate_dek
│       ├── cipher.rs          # log_encrypt/decrypt, state_encrypt/decrypt,
│       │                      #   backup_encrypt/decrypt
│       ├── nonce.rs           # NonceManager — durable monotonic counter
│       └── audit.rs           # AuditHmacKey
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
 HSM / Cloud KMS  (production)
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

**Write rate guard:** If `version >= 2^30` (approximately 1 billion writes per
record per DEK epoch), further writes to that key are blocked with a
`WRITE_RATE_EXCEEDED` violation and a CRITICAL log entry is emitted. This
prevents nonce-space exhaustion within a DEK epoch for pathologically hot keys.

### Backup Encryption

**Function:**
`backup_encrypt(bdek, snapshot_bytes, dek_version, utc_epoch) → Vec<u8>`

**On-disk layout:**
`[dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8] ++ [nonce_12b][ciphertext][tag_16b]`

| Field           | Value                                                          |
| --------------- | -------------------------------------------------------------- |
| Associated data | `b"keystone-backup-v1" ++ utc_epoch_u64_BE ++ dek_version_u32` |

The `dek_version` and `utc_epoch` in the AD bind the snapshot to a specific
point in time and DEK epoch, preventing time-travel and replay attacks across
backup archives. A separate DEK manifest (itself AES-256-GCM encrypted with AD
bound to the manifest label, epoch, and DEK version) is included in the backup
bundle alongside the encrypted snapshot.

### Nonce Management

The `NonceManager` (`storage-crypto/src/nonce.rs`) maintains a durable monotonic
counter for Raft log nonces:

- Persists the counter in Fjall under `_meta:nonce_hwm:<node_id>`.
- Reserves blocks of 1024 counts on each flush to absorb node crashes without
  nonce reuse.
- On startup, validates the recovered counter against the persisted high-water
  mark; **refuses to start** if the counter ≤ HWM (operator intervention
  required).
- Emits a WARN when fewer than 10% of the `2^31` rotation threshold remain.

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

Configure local reads for Tier 0/1 data:

```toml
[distributed_storage]
local_reads_mode = "local_for_public"   # default
# local_reads_mode = "linearizable_all" # force ReadIndex for everything
```

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
- Incoming SVIDs must match `spiffe://<trust-domain>/keystone/storage/<role>`;
  mismatches are rejected with `PERMISSION_DENIED` at the gRPC interceptor.

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
  at 2 days, configurable shutdown at expiry.

### NodeId Uniqueness

Each node has a manually configured `node_id: u64`. At startup and on every
`add_learner` gRPC call, the cluster membership is checked for a
`(node_id, rpc_addr)` collision. A detected collision is fatal — the node or the
operation is aborted with a clear error message. If membership cannot be queried
(no quorum), startup fails closed.

---

## Audit Log

Every security-relevant operation is signed and forwarded to an external SIEM.

**Record structure:**

```json
{
  "timestamp": 1750000000,
  "event_type": "DEK_ROTATION",
  "actor": "operator@example.org",
  "node_id": 1,
  "dek_version": 3,
  "details": { ... }
}
```

**Signature:** `HMAC-SHA256(AuditHmacKey, canonical_json_of_record)`

The 32-byte MAC is transmitted alongside the record as a hex string. The SIEM
retains each epoch's key for audit retention purposes. The `node_id` in the HKDF
derivation ensures different nodes hold distinct signing keys, preventing a
compromised node from forging records attributed to other nodes.

**Availability:** If the SIEM is unreachable, records are buffered locally
(encrypted under the Log DEK). At 90% buffer capacity a CRITICAL alert is
emitted. Buffer exhaustion does **not** block writes to the identity store.

Audited events include: `DEK_ROTATION`, `DEK_ROTATION_EMERGENCY`,
`QUARANTINE_CLEARED`, and any operator access to gRPC management RPCs.

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

---

## DEK Rotation

DEK rotation is triggered by time (`dek_rotation_days`, default 90 days) or
volume (log-encrypt counter reaches 2^31). The rotation is a live background
process with no downtime.

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

**Re-encryption:** A background task re-encrypts all Fjall records under the new
DEK using optimistic CAS-on-version: it reads the on-disk version, encrypts
under the new DEK with `version + 1`, and writes only if the on-disk version is
unchanged. After 3 failed CAS attempts, the key is skipped (it was already
updated by a concurrent Raft write) and flagged in the post-rotation
verification report.

**Progress:** Progress is checkpointed to `_meta:dek:rotation_progress`. If the
node restarts mid-rotation, it resumes from the last checkpoint.

---

## Deployment Guide

### Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)
- A SPIRE deployment, or TLS certificates from a dedicated Intermediate CA
- For production: HSM or Cloud KMS for KEK storage
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

# Read consistency mode for Tier 0/1 data.
# "local_for_public" (default): serve Tier 0/1 locally, ReadIndex for Tier 2/3.
# "linearizable_all": require ReadIndex for all tiers.
local_reads_mode = "local_for_public"

# DEK rotation interval in days (default: 90).
dek_rotation_days = 90

# Per-record write version threshold before blocking further writes (default: 2^30).
write_rate_threshold = 1073741824

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

### First-Time Cluster Bootstrap

**Step 1 — Start each node** (do not initialize yet):

```sh
keystone --config /etc/keystone/keystone.conf
```

Each node starts and waits; Raft is not yet initialized.

**Step 2 — Initialize the first node** as a single-node cluster.

Run from node 1's host (node address and ID come from the config file):

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

Run from any node. Repeat once per learner to promote:

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

# 3. Optionally promote to voting member (run from any node):
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

### Scheduled DEK Rotation

Automatic rotation fires after `dek_rotation_days` (default: 90) or when the
log-encrypt counter approaches 2^31. Manual rotation:

```sh
keystone-manage storage rotate-dek \
  --cluster-addr https://10.0.0.1:8310
```

Monitor the audit log (`event_type = "DEK_ROTATION"`) and the post-rotation
verification report for any skipped keys.

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
resets after successful completion.

### Clearing a Quarantined Partition

A partition enters quarantine after 3 GCM verification failures within 60
seconds. In quarantine, the partition is read-only and all writes to affected
keys are rejected with a `QUARANTINED` violation.

**Diagnosis:**

```sh
# Check node metrics for quarantine state:
keystone-manage storage metrics --cluster-addr https://10.0.0.1:8310
```

Root-cause the GCM failures (hardware fault, storage corruption, or unauthorized
modification) before clearing quarantine.

**Clear:**

```sh
keystone-manage storage clear-quarantine \
  --cluster-addr https://10.0.0.1:8310 \
  --partition <partition-name>
```

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
Backup DEK and a DEK manifest. Both are bound to the snapshot timestamp and
current DEK epoch.

**Restore:**

```sh
# 1. Bootstrap a fresh single-node cluster (Step 1–2 from bootstrap guide).
# 2. Restore the snapshot to the leader:
keystone-manage storage restore \
  --cluster-addr https://10.0.0.1:8310 \
  --snapshot /mnt/backups/keystone-20260101.snap
# 3. Add remaining nodes as learners (Steps 3–4 from bootstrap guide).
```

The restore command validates the AES-256-GCM backup envelope (AD binding: epoch

- dek_version), decrypts it using the Backup DEK from the KMS, and installs the
  snapshot into the Raft state machine via `install_full_snapshot`. The KMS must
  hold the `backup_dek` role key for the DEK epoch encoded in the snapshot.

**Retired DEK retention:** Retired DEKs must be retained in the KMS for at least
365 days to allow offline decryption of archived backups. Use a separate
`backup_dek_offline` KMS role (distinct from the runtime role) with dual-control
access controls.

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
