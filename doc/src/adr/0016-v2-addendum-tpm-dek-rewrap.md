# ADR 0016-v2 Addendum: Per-Node KEK with Leader-Side DEK Rewrap

Date: 2026-10-14

## Status

Proposed

**Amends:** [ADR 0016-v2](0016-v2-raft-storage.md) §2.5.2 (TPM 2.0) and §2.5.3
(Cluster-Wide DEK Distribution).

## Context

§2.5.3 requires every node's KEK to be byte-identical, because `FetchDek`
returns the leader's wrapped DEK unchanged and the joiner unwraps it with its
own KEK. A TPM KEK is created `fixedTPM | fixedParent` (invariant 13), so it
cannot be duplicated to another TPM. With `auto_generate` every node holds a
different KEK, `install_fetched_dek` fails closed on the HMAC check and the join
aborts. TPM mode is therefore single-node only. The same holds for
non-extractable PKCS#11 tokens that are not shared network HSMs.

## Decision

Keep one independent, non-exportable KEK per node and stop requiring KEK
equality. The cluster DEK is moved between nodes under a per-recipient transport
key instead of the stored wrapped blob.

### Joiner transport key

On first boot the joiner creates a restricted-decrypt-incapable but
decrypt-capable RSA-2048 (OAEP-SHA256) or P-256 (ECDH) key under the same
primary as its KEK, with `fixedTPM | fixedParent | sensitiveDataOrigin`. The
public part never needs to be secret; the private part never leaves the TPM.

### Protocol

```text
join_cluster(leader_addr):
  (transport_pub, attestation) = tpm.create_transport_key(nonce)
  resp = leader.FetchDek(transport_pub, attestation, nonce)
  # resp.epochs[i] = { version, rewrapped }
  for e in resp.epochs:
    dek = tpm.decrypt_with_transport_key(e.rewrapped)   # RSA-OAEP / ECDH+HKDF+AES-GCM
    local_wrapped = kek.wrap_dek(dek)                    # own KEK
    install_fetched_dek(e.version, local_wrapped)        # stores local_wrapped
  leader.AddLearner(self)
```

Leader side, per epoch: `dek = kek.unwrap_dek(stored)`; encrypt `dek` to
`transport_pub` with context
`"keystone-dek-transport-v1" || version || joiner_node_id || nonce` as OAEP
label / HKDF info; zeroize `dek`.

### Authorization and trust

- `FetchDek` stays Node-role only (peer-roles addendum). mTLS alone is not
  enough to receive the DEK, so the request also binds the transport key to the
  caller: the transport public key is signed by the TPM key attested via
  `TPM2_Certify` under the node's EK/AK where the operator enrolls EK
  certificates; otherwise the transport key is bound to the TLS channel by
  including its hash in the request and checking it against the peer's SPIFFE
  identity. The operator enrollment mode is explicit configuration, and the
  weaker mode is logged at WARN.
- The nonce is leader-issued (a first `FetchDekChallenge` call) so a captured
  response cannot be replayed to another joiner.
- Rewrapped blobs are never persisted or replicated; only each node's
  locally-wrapped copy is stored under `_meta:dek:*`.

### Consequences

- Each node stores a differently-wrapped copy of the same DEK. Nothing that is
  replicated through Raft (as opposed to local `_meta:dek:*`) may contain a
  KEK-wrapped DEK. `InstallDek` proposals must carry the DEK encrypted to each
  member's transport key, or be applied via the same fetch path. This must be
  audited before rotation is enabled with TPM KEKs.
- Backups carry the DEK manifest wrapped by the node that produced them; restore
  on a different cluster needs the §7 re-wrap step with the new cluster's KEK,
  which this design makes uniform.
- TPM replacement or `TPM2_Clear` no longer strands the cluster: the node
  re-joins as a new member and fetches the DEK again.
- Invariants 2 and 13 are preserved (KEK material never leaves any TPM). The DEK
  is transiently in leader process memory during rewrap, as it already is during
  normal unwrap.
- `auto_generate` for TPM and PKCS#11 becomes valid in clusters.
- Error text in `app/init.rs` ("KEK material must be identical") is replaced.

### Alternatives considered

- **Shared duplicable KEK** (`TPM2_Duplicate` with `PolicyDuplicationSelect`):
  requires `fixedTPM=0`, breaks invariant 13 and needs policy sessions not
  present in `storage-crypto-tpm`.
- **External KMS/network HSM as the KEK root**: works today for PKCS#11 and
  remains the right choice where one is available; not applicable to bare TPMs.

### Open items

- Choose RSA-OAEP vs ECDH (ECDH needs a TPM2_ECDH_ZGen path in `tss-esapi`).
- EK certificate enrollment tooling and trust-store location.
- Trait change: `KekProvider` gains transport-key operations, or a separate
  `DekTransport` trait implemented by the TPM and PKCS#11 crates.
- Proto: new `FetchDekChallenge` and extended `FetchDekRequest/Response`.
