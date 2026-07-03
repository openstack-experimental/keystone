# ADR 0016-v2: Distributed Encrypted Storage via Raft and Fjall

Date: 2026-06-13
Last-revised: 2026-07-02 (PKCS#11/TPM KEK provisioning addendum)

## Status

Proposed

**Supersedes:** ADR-0016 (2026-04-12)

**Security review findings applied (2026-06-24):**
- F1 HIGH: Raft log nonce NodeId widened from 4 to 8 bytes; counter shrunk to 4 bytes (§2.2)
- F2 MEDIUM: Audit HMAC key derivation made per-node via `node_id` in HKDF info (§3.1)
- F3 MEDIUM: Backup manifest AD now includes `dek_version_u32` to prevent same-second swap (§7)
- F4 MEDIUM: SPIFFE mode expanded with TTL ceiling, fail-closed behaviour, SPIFFE ID pattern (§4.1)
- F5 MEDIUM: Quarantine state specified as Raft-committed and restart-persistent (§10 invariant 5)
- F6 LOW: Emergency rotation confirmation timeout now has an explicit abort + audit path (§6.2)
- F7 LOW: NodeId uniqueness check specified as fail-closed when leader is unreachable (§4.3)
- F8 LOW: Sub-key derivation notation changed from `HKDF-SHA256` to `HKDF-Expand` (§2.1)

**Addendum applied (2026-07-02):** §2.5 added, specifying the concrete PKCS#11
and TPM 2.0 KEK provider mechanisms that §2.1 previously deferred ("HSM /
PKCS#11 / Cloud KMS"), the `kek_provider` configuration schema, and new
invariants 13–15 (§10).

## Context

Keystone-NG requires a storage backend providing high availability, strong
linearizable consistency for identity assignments, and absolute cryptographic
sovereignty over PII and secrets. Traditional SQL databases lack native
application-lifecycle encryption and introduce external network dependencies.

We need a solution that:

- **Guarantees Consistency:** Identity changes must be linearizable; a revoked
  user or disabled account must never be observable as active by any node.
- **Embedded Performance:** An embedded LSM-tree avoids external database
  network overhead.
- **Cryptographic Sovereignty:** Data must be encrypted before it touches the
  Raft log or disk. A full disk or log compromise must not leak plaintext
  payloads or user identifiers.
- **Zero-Trust Transport:** Intra-cluster communication must be mutually
  authenticated with short-lived, automatically rotated credentials.

## Decision

We will implement a distributed storage engine using **OpenRaft** for consensus
and **Fjall** as the local state machine and log store, following a
"Vault-style" encryption model. Intra-cluster mTLS supports two modes (`spiffe`
and `tls`), and local follower reads are permitted strictly for non-sensitive
data via a cryptographically bound tiering system.

---

## 1. The Storage Stack

| Layer             | Component                 | Role                                                 |
| ----------------- | ------------------------- | ---------------------------------------------------- |
| **Consensus**     | `openraft` (Rust)         | Log replication, cluster membership, linearizability |
| **LSM-Tree**      | `fjall`                   | State machine and log store (SSD-optimized)          |
| **Serialization** | `rmp-serde` (MessagePack) | Compact binary log entries                           |
| **Transport**     | gRPC over mTLS            | Intra-cluster Raft RPC (SPIFFE or Custom PKI)        |
| **Management**    | `keystone-manage` CLI     | Cluster ops: init, join, quarantine, DEK rotation    |

**Management Interface:** Admin operations are performed via the
`keystone-manage storage` CLI, which communicates with the cluster over gRPC
with mTLS enforcement (SPIFFE SVID or operator-managed TLS certificates). This
gRPC interface is not exposed to the public network — it is accessible only on
the internal management network to operators.

Authorization is enforced at the gRPC interceptor level using the mTLS client
identity. Each management RPC has an explicit allow-list mapping SPIFFE SVID
identities (or TLS SAN URIs) to permitted operations. For example, only SVIDs
with a `storage-operator` role tag may invoke `RotateDek` or `ClearQuarantine`.
Network isolation serves as a compensating control, not the sole enforcement
boundary, in accordance with the zero-trust principle stated in §Context.

**Rate Limiting:** Management RPCs enforce per-source-IP and per-identity rate
limits. `RotateDekRequest` is limited to 2 invocations per hour per operator;
`ClearQuarantineRequest` is limited to 10 per hour per operator.
`RotateDekRequest{emergency: true}` additionally requires dual-control approval:
a second operator with the `storage-operator` role must confirm within 5 minutes
via a separate `ConfirmRotateDekRequest` RPC. Dual-control events are recorded
in the audit log with both operator identities.

**Supply Chain:** Core dependencies (`openraft`, `fjall`) are pinned to exact
versions in `Cargo.lock`. New releases must pass a manual security review before
upgrading. A contingency plan (fork, vendor, or replace) is maintained for each
dependency. `cargo-vet` or equivalent is used in CI for these two crates
specifically. `cargo deny` rules reject any transitive dependency that stores
key material without implementing `ZeroizeOnDrop`. `cargo-vet` coverage is
extended to all crates that directly handle key material or ciphertext: the
AES-GCM provider, the mlock wrapper, and the HKDF implementation. Any new
dependency falls under extended cargo-vet coverage if it: (a) receives or stores
a `Zeroizing<T>` value; (b) is in the AES-HKDF-KMS call path; (c) provides
`mlock` or `VirtualLock` functionality; or (d) processes raw ciphertext before
decryption. Pull request reviewers must verify new `Cargo.toml` entries against
this checklist before approval.

---

## 2. The Cryptographic Barrier

### 2.1 Key Hierarchy

```text
HSM / PKCS#11 / Cloud KMS
        │
        ▼
  Master Key (KEK)                ← never touches RAM as plaintext
        │
        │  AES-256-GCM unwrap
        ▼
Data Encryption Key (DEK)       ← 256-bit random key, generated at bootstrap
         │
         ├── Log DEK (LD)          ← HKDF-Expand(DEK, info="keystone-raft-log-v1", L=32)
         ├── State DEK (SD)        ← HKDF-Expand(DEK, info="keystone-fjall-state-v1", L=32)
         └── Backup DEK (BDEK)     ← HKDF-Expand(DEK, info="keystone-backup-v1" ++ dek_version_u32_be, L=32)

```

**DEK Bootstrap:** DEK generation MUST target an already-mlock'd allocation; it
MUST NOT be generated into an unlocked buffer and subsequently copied. A
transient unlocked copy would allow the DEK to be written to swap, bypassing the
memory protection described in §9.

- **KEK Provisioning (Production):** KEK resides in an HSM or Cloud KMS. The KEK
  never enters process memory.
- **KEK Provisioning (Development):** An environment variable `KEYSTONE_DEV_KEK`
  may supply a hex-encoded KEK. The process refuses to start unless `--dev-mode`
  and `KEYSTONE_ALLOW_ENV_KEK=1` are explicitly set. After reading
  `KEYSTONE_DEV_KEK`, the process must immediately unset it via
  `std::env::remove_var` and zero the original string. The variable must not
  persist in the process environment for the lifetime of the process, preventing
  exposure via `/proc/<pid>/environ`.
- **DEK Derivation:** The DEK is derived into isolated sub-keys via
  HKDF-Expand (Expand-only; the DEK is already uniformly random so HKDF-Extract
  is not needed) to ensure log, state, and backup ciphertexts are never
  encrypted under the same key context. The backup DEK (BDEK) incorporates the active
  `dek_version_u32` into its derivation input, binding it to the current DEK
  epoch. This ensures backups created under different DEK rotations do not share
  the same BDEK, limiting the blast radius of a BDEK compromise.

### 2.2 Nonce Management & GCM Tags

AES-256-GCM requires strict nonce uniqueness. Truncated tags are prohibited; all
tags must be 16 bytes.

- **Raft Log (Log DEK):** Nonce is
  `[8-byte NodeId BE] ++ [4-byte monotonic counter BE]`. NodeId occupies the
  full 8 bytes (matching the `u64` type in §8) to prevent nonce-space collision
  between nodes that share the same lower 32 bits. The counter is stored durably
  and increments with a reservation block of 1024 to absorb crashes. On startup,
  the persisted counter is validated against a separately-stored high-water mark
  (kept in a dedicated Fjall metadata key `_meta:nonce_hwm:<node_id>`); if the
  recovered counter is less than or equal to the high-water mark, the node
  refuses to start and requires operator intervention, preventing nonce reuse
  from counter corruption. After each reservation block write, the node verifies
  the write by reading back and comparing; if the read-back does not match, the
  node treats it as a fatal storage error and halts, preventing silent nonce
  reuse during a live session. A warning is emitted when remaining counter space
  drops below 10% of the `2^31` rotation threshold.
- **Fjall State Machine (State DEK):** Nonce is derived via
  `HKDF-Expand(StateDek, info=PrimaryKey || version_u32, L=12)`. The `version`
  field starts at `0` for new records and increments on each update. This
  guarantees that even if the same primary key is re-written, the nonce is
  unique under the current DEK. `u32` is used (allowing ~4.3 billion updates per
  record per DEK epoch); with 90-day rotation and realistic IAM workloads,
  overflow is not expected. The version is stored as a 4-byte big-endian suffix
  alongside the ciphertext in Fjall, laid out as:
  `[nonce_12b][ciphertext][tag_16b][version_u32_BE]`. On read, the version is
  extracted from this suffix to determine the next increment value.

### 2.3 Associated Data (AD) Bindings

To prevent ciphertext substitution and data tampering, we tightly bind the
context of the data to the AES-GCM envelope.

| Context               | Associated Data Binding                                                 | Attack Prevented                         |
| --------------------- | ----------------------------------------------------------------------- | ---------------------------------------- |
| **Raft log entry**    | `term ++ index` (16 bytes, big-endian)                                  | Index-substitution (replay attacks)      |
| **Fjall state entry** | `1b_tier_marker ++ domain_id ++ primary_key`                            | Key-substitution and Read-Tier tampering |
| **Metadata entry**    | `b"keystone-meta-v1" ++ meta_key_bytes`                                 | Metadata confused with app data          |
| **Backup envelope**   | `b"keystone-backup-v1" ++ snapshot_utc_epoch_be_u64 ++ dek_version_u32` | Time-travel / Backup replay              |

### 2.4 Known Limitation: Primary Key Confidentiality

Fjall stores primary keys (UserIDs, domain identifiers, etc.) as plaintext index
entries. An attacker with disk access can enumerate all stored identifiers
without decrypting values. **All primary keys are UUIDv4 — cryptographically
random identifiers with no encoded semantic content.** An attacker can learn
account cardinality (total count) and existence, but cannot determine personal
identities, names, emails, or other PII without decrypting the associated values
under the DEK. This reduces the exposure from PII disclosure to merely revealing
the existence and cardinality of accounts.

This is an accepted limitation: encrypting index keys would require
deterministic encryption (leaking frequency patterns) or an oblivious data
structure (impractical for an LSM-tree). The AES-256-GCM AD binding ensures that
even with full index enumeration, the attacker cannot move values between keys
or decrypt payloads without the DEK.

**Residual Correlation:** LSM-tree key ordering reveals creation order, and
cross-reference fields (e.g., `domain_id` stored as a value in user records)
link identifiers — but only when the values are decrypted. An attacker with
plaintext keys alone cannot perform cross-account correlation.

**Access Pattern Leakage:** Access pattern analysis can reveal which keys are
read or written and when, correlating active accounts and revocation events.
This is evaluated against the in-scope attacker (physical disk access, backup
exfiltration) — the attacker cannot observe real-time access patterns on a cold
disk or static backup. For deployments where an attacker can monitor hardware-
level I/O patterns, this constitutes an accepted limitation.

**Threat Model:** This limitation is evaluated against the following attacker
capabilities:

- **In scope:** Physical disk access, backup exfiltration. The attacker can
  enumerate identifiers but cannot read values, modify data, impersonate nodes,
  or determine account ownership without the DEK and valid mTLS credentials.
- **Out of scope:** Attacker with KMS access, rogue operator with root
  privileges, or supply-chain compromise of `fjall`. The legal/compliance team
  has reviewed this limitation against applicable regulations (GDPR
  pseudonymisation obligations) and confirmed it meets the organization's
  privacy requirements.

### 2.5 PKCS#11 and TPM KEK Provisioning

§2.1 named "HSM / PKCS#11 / Cloud KMS" as the production KEK source but did
not specify a mechanism. This section specifies the PKCS#11 and TPM 2.0
`KekProvider` implementations. Both satisfy invariant 2 (§10): the KEK itself
never enters process memory in plaintext, only wrapped DEK bytes cross the
provider boundary.

**Provider selection:** `[distributed_storage] kek_provider` selects between
`env` (dev-mode only, §2.1), `pkcs11`, and `tpm`. Exactly one provider is
active per node. Production deployments (`dev_mode = false`) MUST set this to
`pkcs11` or `tpm`; `kek_provider = "env"` outside `dev_mode` is rejected at
config-validation time, before any KEK material is touched (invariant 6).

#### 2.5.1 PKCS#11

The KEK is an AES-256 key object resident on a PKCS#11 token (a hardware HSM
or, for development/CI, SoftHSM2), created with `CKA_EXTRACTABLE = false` and
`CKA_SENSITIVE = true`. `wrap_dek`/`unwrap_dek` invoke `CKM_AES_GCM` directly
against that key object (`C_EncryptInit`/`C_Encrypt` and
`C_DecryptInit`/`C_Decrypt` with a `CK_GCM_PARAMS` structure carrying a
freshly generated 12-byte nonce, `DEK_WRAP_AD` as additional authenticated
data, and a 128-bit tag). The resulting wire format is byte-identical to
`EnvKek`'s: `[12-byte nonce][ciphertext][16-byte tag]` — no downstream code
(DEK bootstrap, Fjall metadata storage) needs to distinguish which
`KekProvider` produced a wrapped blob.

- **Key provisioning:** creating the AES-256 key object on the token is an
  out-of-band operator step (e.g. `pkcs11-tool --keygen` or
  `softhsm2-util --init-token` for development), documented in the operator
  guide. The provider MAY auto-generate the key via `CKM_AES_KEY_GEN` on
  first startup if `pkcs11_key_label` is not found on the configured slot —
  this is an ergonomic convenience for fresh clusters, not a substitute for
  operator-controlled key ceremony in regulated deployments.
- **PIN handling:** the token PIN is read once at startup from
  `pkcs11_pin_file` into a `Zeroizing` buffer, used for `C_Login`, and
  zeroed immediately after. The PIN is never accepted via environment
  variable or inline config value — only a file path, consistent with the
  existing `tls_key_file`/`tls_cert_file` convention (§4.2).
- **Failure handling:** a login failure, missing key object, or GCM tag
  mismatch on unwrap is fatal to node startup (or, post-startup, treated the
  same as any other GCM tag failure under invariant 5's quarantine logic).

#### 2.5.2 TPM 2.0

The KEK is a non-duplicable, TPM-resident symmetric-cipher key
(`fixedTPM | fixedParent | sensitiveDataOrigin`, no duplication attribute).
As with PKCS#11, the raw key material never leaves the TPM and never enters
process memory — only the wrapped DEK crosses the boundary.

**TPM 2.0 has no native AES-GCM command.** `TPM2_EncryptDecrypt2` supports
only CFB/CBC/CTR/OFB/ECB symmetric modes; there is no AEAD primitive. The TPM
provider therefore uses Encrypt-then-MAC instead of AES-GCM:

```text
wrap_dek(dek):
  iv          = random 16 bytes
  ciphertext  = TPM2_EncryptDecrypt2(key = tpm_kek, mode = AES-256-CFB, iv, data = dek)
  tag         = TPM2_HMAC(key = tpm_hmac, data = iv ++ ciphertext ++ DEK_WRAP_AD)
  wrapped     = iv ++ ciphertext ++ tag        // [16b][32b][32b] = 80 bytes

unwrap_dek(wrapped):
  split wrapped into iv, ciphertext, tag
  expected_tag = TPM2_HMAC(key = tpm_hmac, data = iv ++ ciphertext ++ DEK_WRAP_AD)
  reject unless expected_tag == tag (constant-time compare) — never attempt
  TPM2_EncryptDecrypt2 on an unauthenticated ciphertext
  dek = TPM2_EncryptDecrypt2(key = tpm_kek, mode = AES-256-CFB, iv, data = ciphertext, decrypt = true)
```

This is a deliberate deviation from "AES-256-GCM for all payloads" (§2.2)
scoped strictly to the TPM KEK-wrap boundary: it does not touch the Log DEK,
State DEK, or Backup DEK, which remain AES-256-GCM as specified elsewhere in
this ADR. `tpm_kek` and `tpm_hmac` MAY be the same TPM key object used in two
different USAGE modes if the provisioning tooling supports it, or two
separate persistent handles; either is acceptable provided both satisfy the
non-duplicable, non-extractable attributes above.

- **Key provisioning:** a persistent handle (`tpm_key_handle`) or a saved key
  context (`tpm_key_context_file`) identifying the pre-provisioned TPM key(s).
  Provisioning itself (via `tpm2_create`/`tpm2_evictcontrol` or equivalent) is
  an out-of-band operator step, documented alongside the PKCS#11 key ceremony.
- **Auth handling:** if the key was provisioned with `userWithAuth`, the auth
  value is read once from `tpm_auth_file` into a `Zeroizing` buffer and used
  to authorize the TPM session; zeroed immediately after. As with PKCS#11,
  only a file path is accepted, never an environment variable or inline
  value. A key relying purely on PCR/policy session authorization may omit
  `tpm_auth_file`.
- **Sample scope:** the TPM provider ships with a runnable example targeting
  a software TPM (`swtpm`) for local exploration, and is not part of the
  required CI gate — real and virtual TPM availability in CI runners is not
  reliable enough to gate merges on. The PKCS#11 path (§2.5.1), backed by
  SoftHSM2, is the CI-gated path (§1).

---

## 3. Read Consistency and Data Tiers

To optimize read-heavy IAM workloads without sacrificing security, data is
categorized into sensitivity tiers. The tier marker is prefixed to the plaintext
and bound into the AES-GCM AD; altering the tier invalidates the ciphertext.

| Tier  | Label       | Allowed Read Modes                | Examples                                           |
| ----- | ----------- | --------------------------------- | -------------------------------------------------- |
| **0** | `PUBLIC`    | Local Read, Linearizable          | Feature flags, role display names                  |
| **1** | `INTERNAL`  | Local Read, Linearizable          | Display attributes, internal configuration markers |
| **2** | `SENSITIVE` | **Linearizable Only** (ReadIndex) | Group memberships, active session tokens, API keys |
| **3** | `SECRET`    | **Linearizable Only** (ReadIndex) | Credential plaintext, TOTP seeds                   |

_Audit data is out of scope for this Raft storage engine. Audit logging is
handled by a separate external pipeline (e.g., SIEM, centralized logging) and is
not subject to the tiering or read consistency model described here._

_Group membership is elevated to Tier 2 (linearizable only) because it is a
direct input to authorization decisions. A stale read of group membership can
cause a recently removed member to still be considered part of a privileged
group, producing an incorrect access grant. Callers must ensure that any Tier 1
data used in live authorization decisions is read via a linearizable path._

_Configuration:_ Operators enable local reads via
`local_reads_mode = "local_for_public"`. Tier 2 and 3 data _always_ require the
ReadIndex protocol, ensuring revoked credentials are never exposed via a stale
follower.

### 3.1 Audit Log Architecture

Audit events referenced in this ADR (DEK rotation, skipped re-encryption keys,
quarantine recovery, emergency rotation, and operator actions) are forwarded to
an external SIEM or centralized logging pipeline. The audit log is not stored
within the Raft storage engine, satisfying GDPR Article 30 requirements
independently of the identity data store.

**Integrity:** Each audit record is signed with a per-node HMAC-SHA256 key
derived from the KEK via
`HKDF-Expand(KEK, info="keystone-audit-hmac-v1" ++ node_id_u64_be, L=32)`. The
`node_id` is included in the derivation so each node holds a distinct signing
key; a compromised node cannot forge audit records attributed to other nodes.
The signing key is rotated on every DEK rotation, binding the HMAC key lifetime
to the DEK epoch. The signature is computed over the canonical JSON
representation of the audit record (including timestamp, event type, actor, and
`node_id`), and transmitted alongside the record. An epoch tag
(`dek_version_u32`) and the originating `node_id` are included in each audit
record to identify which HMAC key signed it. Because the KEK never enters
process memory in production (§2.1), this derivation is performed inside the
HSM or Cloud KMS using a context-keyed derivation operation.

**Transport:** Audit records are forwarded over an authenticated channel
(TCP/TLS) to the SIEM. The keystone node cannot unilaterally modify records
already received by the SIEM, which enforces append-only semantics downstream.

**HMAC Key Lifecycle:** The epoch-tagged HMAC signing key is transmitted to the
SIEM over the same authenticated channel as the audit records, bound to the
`dek_version_u32` epoch. This ensures the HMAC key is protected by the same
transport mechanisms as the audit records themselves. The SIEM retains each
epoch's key for the duration of the audit retention period, enabling re-
verification of historic records across epoch boundaries. The keystone node does
not need to retain epoch keys beyond the current DEK epoch — responsibility for
key lifecycle lies with the SIEM.

**Availability:** If the SIEM endpoint is unreachable, audit records are
buffered locally (encrypted at rest with the Log DEK) and replayed on
connectivity restoration. Buffer capacity is bounded to prevent disk exhaustion;
if the buffer reaches 90% capacity, the node emits a `CRITICAL` alert. Audit
buffer exhaustion is an operational concern for the audit pipeline, and does NOT
affect the Raft storage engine's availability — writes to the identity data
store proceed normally regardless of SIEM connectivity or audit buffer state.

---

## 4. Intra-Cluster Transport (mTLS)

Operators select the transport mode via `[storage] transport_mode`.

**Protocol Requirements:** All mTLS connections (both SPIFFE and TLS fallback)
MUST use TLS 1.3 or later. TLS 1.2 and earlier are prohibited. Permitted cipher
suites are restricted to AEAD-only: `TLS_AES_256_GCM_SHA384` and
`TLS_CHACHA20_POLY1305_SHA256`. The TLS stack must enforce these settings at
configuration time and refuse to start if unsupported ciphers are negotiated.

### 4.1 SPIFFE Mode (Default)

Managed automatically by SPIRE.

- **Identity:** Short-lived X.509 SVIDs rotated automatically. SVID TTL MUST
  NOT exceed 1 hour. Node processes enforce this by refusing to use an SVID
  with a remaining validity of less than 5 minutes (force-renewal window).
- **SPIFFE ID Pattern:** All Keystone storage node SVIDs MUST match
  `spiffe://<trust-domain>/keystone/storage/<role>`. The gRPC interceptor
  validates this pattern before any RPC is dispatched; connections from SVIDs
  that do not match are rejected with `PERMISSION_DENIED`.
- **SPIRE Unavailability (Fail-Closed):** If the SPIRE agent cannot renew an
  expiring SVID before it enters the force-renewal window, the node emits a
  `CRITICAL` log entry. If the SVID expires before renewal succeeds, the node
  refuses to accept new inbound connections and drains in-flight Raft proposals
  before halting. It does NOT fall back to an expired SVID.
- **Trust Bundle Refresh:** The SPIRE agent manages trust bundle rotation
  automatically. No manual intervention is required or permitted for trust
  bundle updates.

### 4.2 TLS Mode (Fallback)

Operator-managed PKI for environments without SPIRE.

- **PKI Rules:** Must use a dedicated Keystone Intermediate CA. Leaf
  certificates MUST NOT exceed 30 days validity (enforced at startup).
- **Certificate Expiry Watchdog:** A runtime watchdog checks remaining
  certificate validity at a regular interval (every hour). It logs warnings at 7
  days remaining, errors at 2 days remaining, and triggers a configurable action
  (warn-only or shutdown) at expiry. This prevents the enforcement gap where a
  node starts with a valid certificate but continues operating after expiry.
- **Certificate Revocation:** CRL and OCSP are not implemented for the TLS
  fallback path. The compensating controls are: (1) the 30-day maximum leaf
  certificate validity limits exposure from a stolen or miss-issued certificate;
  (2) prompt certificate replacement is required on compromise, enforced by the
  operator's PKI management procedures. This is acceptable for an internal
  cluster where the operator manages the Intermediate CA and has direct control
  over certificate issuance and replacement.

**Planned Improvement:** CRL and OCSP support for the TLS fallback path is
planned as a future enhancement to the custom mTLS infrastructure. When
implemented, it will replace the reliance on short certificate validity as the
sole revocation control and provide real-time certificate status verification at
connection time.

### 4.3 NodeId Assignment

**Decision:** NodeId is a manually configured `u64` that must be unique within
the cluster.

**Rationale:** NodeId is an opaque cluster-local identifier, not a secret or
authentication material. Cryptographic derivation (e.g., BLAKE3) adds complexity
without security benefit: mTLS already provides mutual authentication, and the
collision check enforces uniqueness. A deterministic hash of cluster_id and URI
provides no additional assurance over manual assignment — the operator controls
the certificate and the configuration, and under zero-trust both are within the
adversary boundary.

**Uniqueness Enforcement:** At startup, the node queries the Raft membership
config and compares its `(node_id, rpc_addr)` against all existing members. If
any existing member shares the same `node_id` but has a different `rpc_addr`, a
collision is detected. The node emits a fatal log entry and refuses to start.
The leader enforces the same check when processing `add_learner` requests. This
catches both operator misconfiguration and deliberate duplication.
**Fail-closed:** If the node cannot contact any cluster member to retrieve the
membership config at startup (e.g., network partition, no quorum), it MUST
refuse to start rather than skip the uniqueness check. An inability to verify
uniqueness is treated the same as a detected collision. This prevents a
misconfigured node from joining an isolated network segment undetected.

---

## 5. Data Flow Architectures

### 5.1 Write Path

The payload is subject to double-encryption to separate log concerns from state
concerns. This adds approximately 2× symmetric crypto overhead per write (Log
DEK decrypt + State DEK encrypt). With AES-NI, measured at ~0.2ms per operation
at typical IAM payload sizes.

```text
Client API → Serialize (MsgPack)
    │
    ▼
Encrypt with Log DEK (AD = term ++ index)
    │
    ▼
Propose to OpenRaft Leader (Replicated over mTLS)
    │
    ▼
Apply on Node:
  1. Decrypt log entry (Log DEK)
  1.5. Fetch current version for PK from Fjall (default 0 if new); increment
  2. Re-encrypt for state (State DEK, nonce = HKDF-Expand(SD, info=PK ||
        version, L=12), AD = tier ++ domain ++ pk)
  3. Write ciphertext + version suffix to Fjall DB

```

> The state machine is idempotent under Raft replay: a crash between the version
> fetch (§5.1 step 1.5) and the write (§5.1 step 3) results in no persistent
> state change, and the replay reads the same on-disk version, deriving the same
> nonce and producing the same ciphertext. This invariant holds because Fjall's
> batch commit is atomic and Raft entries are deterministic.

---

## 6. DEK Rotation Lifecycle

To prevent AES-256-GCM nonce exhaustion, Data Encryption Keys must be
periodically rotated. Rotation is triggered either by time (configurable via
`[storage] dek_rotation_days`, default 90 days) or by volume (when AES-GCM
encryptions reach 2^31 under any sub-key).

**DEK Version Tracking:** Each DEK epoch is assigned a monotonically increasing
`dek_version_u32`. The version is stored alongside the wrapped DEK in Fjall
metadata (e.g., `_meta:dek:current:version`). The `version` counter used in
state machine nonces (see §2.2) is also tracked per DEK epoch.

**Live Background Rotation Flow:**

1. Generate a fresh DEK in memory with `dek_version = current + 1`.
2. Wrap under the KEK and write to `_meta:dek:pending` via a Raft proposal,
   recording the committed Raft index as `rotation_index` in the same proposal.
   This guarantees the pending DEK and its version exist before any write can
   reference them.
3. `rotation_index` serves as an unambiguous boundary: log entries at index
   `< rotation_index` use the retired DEK; entries at index `≥ rotation_index`
   use the pending DEK.
4. All _new_ Raft writes at or after `rotation_index` use the pending DEK.
5. A background task re-encrypts all existing Fjall records under the new DEK
   atomically in key-sorted order. The re-encryption uses optimistic concurrency
   control (CAS on version): it reads the on-disk version, encrypts under the
   new DEK with `version + 1`, and writes only if the version on disk is
   unchanged. If a concurrent Raft write incremented the version, the key is
   either already encrypted under the new DEK (the Raft write used the pending
   DEK) or is retried. After 3 failed CAS attempts on the same key, the
   background task skips it — the key is assumed to have been updated under the
   new DEK by a Raft write. This CAS-on-version mechanism ensures no
   re-encryption can clobber a concurrent Raft mutation during rotation. Skipped
   keys are flagged in the post-rotation verification report (see step 8), are
   automatically retried on the next scheduled rotation cycle, and are emitted
   to an audit log entry. If a skipped key remains unverified for more than 24
   hours, a CRITICAL alert is emitted and operator intervention is required.
6. During rotation, both DEKs are active. Reads use the per-record `dek_version`
   to select the correct key deterministically — they never fall back via tag
   verification failure. If the `dek_version` is missing or ambiguous, the
   record is treated as corrupt and quarantined rather than probing both keys.
   **Recovery path:** Records with missing or ambiguous `dek_version` can be
   recovered from the Raft log by replaying the entry with the known
   `rotation_index` boundary to determine the correct DEK epoch. If the Raft log
   entry is unavailable (e.g., truncated by snapshots), the record is restored
   from backup. The blast radius is limited to the partition containing the
   affected key. Operators run `keystone-manage storage recover --record` to
   trigger recovery, which emits an audit log entry. For state entries, the
   per-record `version` field is incremented during re-encryption to produce a
   fresh nonce.
7. Upon completion, the old DEK is atomically promoted to
   `_meta:dek:retired:<timestamp>` via a second Raft proposal, and an audit log
   event is recorded.
8. Post-rotation verification: A verification pass reads each record's stored
   `dek_version` and confirms it is consistent with the new DEK epoch. Any
   record that cannot be verified is flagged in an operator-facing report rather
   than silently accepted, ensuring no records remain orphaned under the retired
   DEK after rotation is declared complete. Unverified records trigger an
   automated retry on the next rotation cycle. If verification fails for more
   than 24 hours consecutively, a CRITICAL alert is emitted. The DEK retirement
   is blocked until the operator resolves the flagged records or explicitly
   approves proceeding with a signed audit entry acknowledging the unverified
   records.

_Partial Rotation Recovery:_ If a node restarts mid-rotation, it detects
`_meta:dek:pending`. The leader resumes the idempotent re-encryption from the
last committed progress marker stored in `_meta:dek:rotation_progress` before
normal operations complete. The `rotation_index` boundary remains authoritative
for determining which DEK each log entry was encrypted under.

### 6.2 Emergency Rotation and DEK Compromise

When a DEK is suspected or confirmed compromised, the operator triggers an
emergency rotation that follows the same flow as normal rotation but with
additional containment steps:

1. **Trigger:** Emergency rotation is initiated via
   `keystone-manage storage rotate-dek --emergency`, which connects to the
   cluster over gRPC with mTLS enforcement (see §1). Access requires RBAC
   authorization (`storage-operator` role) and dual-control confirmation via
   `ConfirmRotateDek` from a second operator within 5 minutes.
   **Confirmation timeout:** If the 5-minute window expires without
   confirmation, the pending emergency rotation is automatically aborted: the
   node commits a Raft proposal removing `_meta:dek:pending`. The abort is
   recorded in the audit log with the initiating operator identity, the
   expiry timestamp, and the fact that no confirmation was received. The
   partial-rotation recovery path (end of §6) checks for a `rotation_id`
   timestamp and ignores `_meta:dek:pending` entries older than 5 minutes
   that were never confirmed, preventing an aborted emergency rotation from
   being resumed on restart as a normal rotation.
2. **Immediate containment:** A fresh DEK is generated and committed via Raft
   following the standard flow (§6 step 1-2). The compromised DEK is marked
   `revoked` (not `retired`) in `_meta:dek:revoked:<timestamp>`, preventing its
   reuse for any decryption operation.
3. **Impact assessment:** The operator queries the per-record `dek_version` to
   identify all records encrypted under the compromised DEK epoch. This
   determines the scope of potentially exposed data.
4. **Re-encryption:** The background task re-encrypts all affected records under
   the new DEK following the standard CAS-on-version flow (§6 step 5).
5. **Discard:** The revoked DEK is discarded immediately — it is NOT stored in
   the retired DEK chain and is NOT available to any KMS role. If offline
   decryption of backups from the compromised epoch is required, the operator
   must use the backup manifest (§7) and the BDEK, not the compromised DEK.
6. **Incident logging:** The emergency rotation, affected record count, and
   operator identity are recorded in the audit log with a distinct event type
   (`DEK_EMERGENCY_ROTATION`).

Normal rotation cadence resumes after the emergency rotation completes; the
`dek_rotation_days` timer is reset to account for the forced rotation age.

---

## 7. Backup and Restore

Backups in Keystone-NG are fundamentally Fjall snapshots. Because all values in
Fjall are encrypted via the State DEK, disk snapshots contain exclusively
AES-256-GCM ciphertext.

### Backup Encryption Envelope

Each backup is wrapped in a backup-specific envelope to bind it to a point in
time and a specific DEK epoch, preventing rollback or replay attacks:

```text
AES-256-GCM(
  plaintext  = snapshot_bytes,
  key        = Backup DEK (BDEK),
  AD         = b"keystone-backup-v1" ++ snapshot_utc_epoch_be_u64 ++ dek_version_u32
)

```

_The `dek_version_u32` identifies which DEK epoch the snapshot was taken under
(at time of snapshot, current DEK version). The backup bundle includes a DEK
manifest listing all retired DEKs that may be required for offline decryption,
handling cases where the snapshot spans a rotation boundary. The DEK manifest is
a separate structure included in the backup bundle alongside the encrypted
snapshot. It is encrypted with the BDEK using AES-256-GCM with AD bound to
`b"keystone-backup-manifest-v1" ++ snapshot_utc_epoch_be_u64 ++ dek_version_u32`.
Including `dek_version_u32` in the manifest AD prevents swapping the manifest
between two backups taken within the same UTC second under different DEK epochs.
The manifest itself is not covered by the outer backup envelope but is
independently encrypted and integrity-protected. BDEK incorporates
`dek_version_u32` in its derivation, binding each backup to its DEK epoch, and
the AD provides independent replay protection._

_Note: The timestamp is explicitly an 8-byte big-endian UTC epoch seconds value.
String timestamps are prohibited as Associated Data due to ambiguity and
fragility._

### Restore Process

Restoring a snapshot to a new cluster strictly requires:

1. Access to the Backup DEK (`backup_dek` role) in the KMS.
2. Valid node identity credentials (SPIFFE SVIDs or Intermediate CA certs) for
   the new nodes before they join the cluster.
3. Unwrapping the backup envelope, loading it into Fjall, and immediately
   re-wrapping the restored DEK under the new cluster's runtime KEK.

_Retired DEKs must be retained in the KMS for the organization's audit retention
period (minimum 365 days) to allow offline decryption of archived backups. When
a GDPR data erasure request arrives, the ability to decrypt that subject's data
from archived backups depends on the retained DEKs. The operator must re-encrypt
the affected archived backups under a fresh DEK epoch, or shard the key material
to reduce the DEK retention window. For GDPR Article 17 compliance, the worst-
case re-encryption time for a full backup archive (measured at the
organization's maximum anticipated volume) must be documented and evaluated
against the 30-day erasure timeframe. If re-encryption exceeds 30 days, the
organization must deploy per-subject wrapping keys: each subject's data envelope
is encrypted under a subject-specific envelope key, which is in turn encrypted
under the BDEK. Erasure of a subject's data then requires only destroying the
subject's envelope key, not re-encrypting the entire archive. If re-encryption
remains not feasible, the operator must document the inability to achieve full
erasure and the residual risk, per GDPR Article 17._

**Retired DEK Access Control:** Retired DEKs are accessed through a distinct KMS
role (`backup_dek_offline`) that is separate from the runtime `backup_dek` role.
This limits the blast radius of a KMS breach or insider threat: compromising the
runtime role does not grant access to retired keys and vice versa. Access to any
retired DEK requires dual-control or break-glass approval. Operators should
evaluate whether the 365-day retention mandate can be satisfied with a separate
escrow mechanism instead of keeping keys live in the operational KMS.

---

## 8. gRPC Protocol & Code Definitions

**Protocol Buffers:**

```protobuf
message RaftEntry {
  uint64 term  = 1;
  uint64 index = 2;
  optional Membership membership = 3;

  // Encrypted app payload: [12b counter-nonce][ciphertext][16b GCM tag]
  // AD = big-endian(term) ++ big-endian(index)
  optional bytes app_data = 4;
}

message RaftResponse {
  // SENSITIVE: Ephemeral plaintext response, transmitted only over mTLS.
  // Zeroized by the sender immediately after gRPC send.
  // Rust type: ZeroizingResponse — must be zeroized after use.
  bytes payload = 1;
}

message ClearQuarantineRequest {}

message RotateDekRequest {
  bool emergency = 1;
}

message ConfirmRotateDekRequest {
  // The rotation_id of the pending emergency rotation that requires confirmation.
  string rotation_id = 1;
}

```

_Implementation Note (Residual Risk):_ gRPC implementations (including
tonic/prost) may internally buffer, clone, or copy message bytes before or
during transmission (e.g., into the HTTP/2 frame buffer). Zeroizing the
application-level struct does not guarantee the copies within the gRPC stack are
also zeroized. A stream-based response that processes the minimum plaintext
footprint should be preferred where feasible.

**Compensating Controls:** These are validated at startup pre-flight (§9):

1. Core dumps must be disabled (`RLIMIT_CORE = 0`). The startup pre-flight
   verifies this and refuses to start if the limit is nonzero.
2. Set `PR_SET_DUMPABLE = 0` (Linux) to prevent ptrace and `/proc/<pid>/mem`
   access from co-located processes. The startup pre-flight verifies this and
   refuses to start if it fails.
3. If Tier 3 data (credential plaintext, TOTP seeds) ever flows through a
   `RaftResponse`, streaming must be evaluated to minimize the peak plaintext
   footprint within gRPC stack buffers.

**OpenRaft Types (Rust):**

```rust
openraft::declare_raft_types!(
    pub KeystoneConfig:
        D = EncryptedBlob,   // [u8] wrapper enforcing 16-byte tag check
        R = ZeroizingResponse,
        NodeId = u64,        // Manually configured; collision detection via
                              // (node_id, rpc_addr) comparison against existing
                              // membership at startup and on learner-add
        Node = SpiffeNode,
);

```

---

## 9. Zeroize & Memory Protection

Standard software zeroization (`ZeroizeOnDrop`) is insufficient on its own
because operating system page swapping can silently write key material to disk
(swap pages), bypassing in-process zeroization.

### Memory Locking (`mlock`)

To guarantee key material is physically pinned to RAM and never written to swap
storage, all keys (`Dek`, `LogDek`, `StateDek`) and their immediate working
buffers must be allocated in memory-locked pages using the OS-level `mlock(2)`
(Linux) or `VirtualLock` (Windows) APIs.

This is enforced via a memory-locking wrapper (e.g., `memsec` or `secrecy` with
OS-level locking):

```rust
// Internally wrapped in a secrets-manager to guarantee locked heap allocations:
let buf: memsec::Malloc<[u8; 32]> = memsec::malloc().expect("mlock allocation");

```

**Resource Limits:** The Keystone process must request an `RLIMIT_MEMLOCK`
sufficient for the key material pool at startup. If `mlock` allocation fails due
to insufficient OS limits, the process logs a `CRITICAL` warning and refuses to
start in production mode.

**Startup Pre-Flight:** At process startup (before KEK/DEK are loaded), the node
verifies `RLIMIT_CORE == 0` and `PR_SET_DUMPABLE == 0`. If either check fails,
the node emits a `CRITICAL` log entry and refuses to start in production mode
(same pattern used for `RLIMIT_MEMLOCK`). This ensures the compensating controls
against gRPC stack plaintext exposure are actually active.

**Enforcement Pipeline:**

- A `#[deny(clippy::mem_forget)]` lint prevents accidental bypass of drop-based
  zeroization project-wide.
- `cargo deny` rules reject any storage dependency that transitively stores key
  material without implementing `ZeroizeOnDrop`.
- Key material types MUST NOT derive `Debug` or `Display` to prevent accidental
  formatting in logs, panics, or debugger output.
- Core dump configuration must exclude memory-locked pages from capture.
- Heap profiling tools are prohibited in production environments containing
  active key material. Enforcement: release builds strip profiling symbols
  (`strip --strip-debug`). A seccomp profile denies `ptrace` syscalls, and the
  `PR_SET_DUMPABLE = 0` setting from the startup pre-flight prevents attach.
  Enforcement: (1) release builds strip profiling symbols
  (`strip --strip-debug`); (2) a seccomp profile denies `ptrace` syscalls
  (`PR_SET_NO_NEW_PRIVS = 1` + `SECCOMP_MODE_FILTER`); (3) AppArmor deny rules
  block `/proc/<pid>/mem` access.

---

## 10. Security Invariants

Any code change violating the following is rejected at review:

1. **No plaintext on disk:** Every byte is encrypted with AES-256-GCM before the
   write call returns.
2. **No DEK in plaintext outside mlock'd RAM:** The DEK lives only in
   KMS-wrapped form on disk, and inside `mlock`'d `Zeroizing` buffers in memory.
3. **Strict mTLS:** Auto-join is permanently disabled. SVID or SAN URI patterns
   are mandatory.
4. **No stale reads for sensitive data:** Tier 2 and Tier 3 data must
   exclusively utilize the ReadIndex protocol.
5. **No unauthenticated operations:** GCM tag mismatch is fatal for the affected
   key; 3 distinct key failures within 60 seconds in the same Fjall partition
   trigger read-only quarantine (in-flight Raft proposals are drained, not
   interrupted). **Quarantine state is durable:** it is committed via a Raft
   proposal to `_meta:quarantine:<partition>:<node_id>` (partition first, so an
   operator's `ClearQuarantine` can prefix-scan and remove every reporting
   node's entry for a partition in one pass) so it persists across node
   restarts and is visible to all cluster members. GCM failures reflect
   node-local storage corruption, not a cluster-wide data problem, so
   blocking is node-scoped: only the reporting node re-enters quarantine (and
   refuses local reads) for that partition on restart; other nodes persist
   the record for audit visibility only and continue serving reads. Recovery
   requires the operator to run
   `keystone-manage storage clear-quarantine` on the affected node, which
   requires `storage-operator` RBAC authorization, is committed via Raft (so
   the flag is cleared cluster-wide), and is audit-logged with caller identity
   and timestamp. A single GCM tag failure emits a `WARN` log and increments a
   metric; two failures within 60 seconds emit an `ERROR` log and trigger an
   alert. Per-source-IP and per-identity rate limits apply (see §1): `RotateDek`
   limited to 2/hour, `ClearQuarantine` to 10/hour. Emergency rotation
   (`RotateDekRequest{emergency: true}`) requires dual-control approval from a
   second `storage-operator` via `ConfirmRotateDek` within 5 minutes.
6. **No environment-variable KEK in production:** The `--dev-mode` flag and
   `KEYSTONE_ALLOW_ENV_KEK=1` are explicitly required to start with an
   environment-provided KEK.
7. **NodeId collision detection:** A node that detects a `(node_id, rpc_addr)`
   collision with an existing cluster member at startup must emit a fatal log
   entry and refuse to start. The leader additionally enforces this check when
   processing `add_learner` requests.
8. **DEK bootstrap ordering:** DEK generation MUST target an already-mlock'd
   allocation; it MUST NOT be generated into an unlocked buffer and subsequently
   copied.
9. **Per-record write rate guard:** When the per-record `version` counter
   exceeds a configurable threshold (default `2^30` updates per DEK epoch), the
   node emits a CRITICAL alert, blocks further updates to that key, and requires
   operator intervention. This prevents adversarial write flooding from
   exhausting the `u32` nonce space within a single DEK epoch.
10. **Nonce source exclusivity:** Nonce sources for all AES-256-GCM contexts are
    defined in §2.2. Random nonces are prohibited. Any new encrypted context
    must define a deterministic, collision-resistant nonce strategy reviewed by
    the security team.
11. **Deployment validation:** A pre-flight CI/CD check or Kubernetes admission
    webhook must reject any production service definition containing
    `--dev-mode` or `KEYSTONE_ALLOW_ENV_KEK`. This prevents silent flag
    smuggling via systemd, container images, or manifests.
12. **Startup pre-flight:** At process startup (before KEK/DEK are loaded), the
    node must verify `RLIMIT_CORE == 0` and `PR_SET_DUMPABLE == 0`. If either
    check fails, the node must refuse to start in production mode.
13. **Non-extractable KEK key material (§2.5):** PKCS#11 KEK key objects MUST
    be created with `CKA_EXTRACTABLE = false` / `CKA_SENSITIVE = true`; TPM
    KEK key objects MUST be created with `fixedTPM | fixedParent` and no
    duplication attribute. A `KekProvider` implementation that can export raw
    key bytes from the token/TPM is non-compliant regardless of how it is
    otherwise used.
14. **No PKCS#11/TPM credential via environment variable:** The PKCS#11 PIN
    and TPM auth value are supplied only via `pkcs11_pin_file` /
    `tpm_auth_file` (a file path in config). Neither may be supplied via an
    environment variable or inline config value — that channel is reserved
    exclusively for the dev-mode `KEYSTONE_DEV_KEK` path (invariant 6).
15. **Authenticate-before-decrypt for Encrypt-then-MAC contexts:** Any
    `KekProvider` that does not use an AEAD primitive natively (the TPM
    provider, §2.5.2) MUST verify the MAC over the full ciphertext before
    performing any decryption operation, and MUST use a constant-time
    comparison. Decrypting unauthenticated ciphertext, even transiently, is
    prohibited.
