# Implementation plan: PKCS#11 and TPM KEK providers (ADR 0016-v2 §2.5)

Status: **steps 1-2 complete**, steps 3-10 not started.

This is a working implementation plan, not user-facing documentation — it is
intentionally not linked from `doc/src/SUMMARY.md`. The durable design record
is [ADR 0016-v2 §2.5](../src/adr/0016-v2-raft-storage.md); this file tracks
how that design gets built.

## Context

ADR 0016-v2 §2.1 named "HSM / PKCS#11 / Cloud KMS" as the production KEK
source but never specified a mechanism. `crates/storage-crypto/src/kek.rs`
already reserves the abstraction boundary: the `KekProvider` trait, a working
`EnvKek` (dev-mode only), and a `Pkcs11KekStub` that always returns
`CryptoError::Pkcs11NotImplemented`. No TPM path exists at all. This plan
replaces the stub with real PKCS#11 and TPM 2.0 providers.

## Decisions taken

These were confirmed with the requester before design work started:

1. **Crate layout:** separate, feature-gated crates (`storage-crypto-pkcs11`,
   `storage-crypto-tpm`), not new modules inside `storage-crypto`. Keeps the
   FFI-heavy C-library bindings out of the crate that owns the workspace's
   `unsafe_code = "deny"` core primitives, and matches ADR §1's cargo-vet
   scoping for anything in the AES-HKDF-KMS call path.
2. **TPM trust model:** a TPM-resident, non-duplicable AES key performs the
   wrap/unwrap itself (`TPM2_EncryptDecrypt2`) — the KEK never enters process
   RAM, matching invariant 2 exactly, the same guarantee the PKCS#11 path
   gives. (Not the alternative: sealing a software-generated KEK to the TPM,
   which would transiently expose it in RAM on every unseal.)
3. **Test/sample scope:** SoftHSM gets a full CI-gated integration test
   (installed via `apt-get`, same pattern as the existing SPIRE install step —
   this repo does not use testcontainers anywhere). TPM gets a runnable
   example/doc sample only, not wired into the required CI gate — real/virtual
   TPM availability in CI runners isn't reliable enough to gate merges on.
4. **Credential input:** PKCS#11 PIN and TPM auth value are supplied via a
   file path in config (`pkcs11_pin_file`, `tpm_auth_file`), analogous to the
   existing `tls_key_file` convention — never via environment variable (that
   channel stays reserved for the dev-mode `KEYSTONE_DEV_KEK` path only).

## Architecture summary

- **PKCS#11:** a non-extractable (`CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`)
  AES-256 key object on the token. `wrap_dek`/`unwrap_dek` use `CKM_AES_GCM`
  directly against that key object, producing the same
  `[12-byte nonce][ciphertext][16-byte tag]` wire format `EnvKek` already
  uses — nothing downstream of `KekProvider` needs to change.
- **TPM 2.0:** a `fixedTPM | fixedParent`, non-duplicable symmetric-cipher
  key. TPM 2.0 has **no native AES-GCM command** (`TPM2_EncryptDecrypt2` only
  supports CFB/CBC/CTR/OFB/ECB), so the provider uses Encrypt-then-MAC:
  AES-256-CFB via the TPM-resident key for confidentiality, HMAC-SHA256 (also
  TPM-resident, `TPM2_HMAC`) for integrity, with the MAC checked before any
  decryption is attempted. Wire format: `[16b iv][32b ciphertext][32b hmac
  tag]` — different from the GCM format, but still opaque `Vec<u8>` behind the
  `KekProvider` trait.

Full mechanism detail, wire formats, and new invariants (13-15) are in
[ADR 0016-v2 §2.5](../src/adr/0016-v2-raft-storage.md#25-pkcs11-and-tpm-kek-provisioning).

## Sequencing

1. **ADR addendum** (§2.5: mechanism + invariants 13-15). ✅ done
   (`doc/src/adr/0016-v2-raft-storage.md`).
2. **Config schema**: `kek_provider` selector (`env`/`pkcs11`/`tpm`) +
   `Pkcs11KekConfiguration` / `TpmKekConfiguration` + cross-field validation
   (env requires `dev_mode`; pkcs11/tpm require their section; TPM key
   reference is exactly one of handle/context-file) + file-based secret
   loading wired into `Config::load_all`. ✅ done
   (`crates/config/src/distributed_storage.rs`, `crates/config/src/lib.rs`).
3. **`storage-crypto-pkcs11` crate**: `cryptoki` dependency, `Pkcs11Kek`
   implementing `KekProvider`, optional auto-generate-key-if-missing on first
   startup, unit tests against SoftHSM2 (token init, wrap/unwrap round-trip,
   tamper/tag-corruption rejection, wrong-PIN failure). ⬜ not started
4. **`storage-crypto-tpm` crate**: `tss-esapi` dependency, `TpmKek`
   implementing `KekProvider` (Encrypt-then-MAC per §2.5.2), example under
   `examples/tpm_kek_demo.rs` targeting `swtpm`. ⬜ not started
5. **Wire into `crates/storage/src/app.rs`**: replace the hardcoded
   `dev_mode ? EnvKek : Pkcs11KekStub` selection with one driven by
   `ds_config.kek_provider`; remove the implicit stub fallback so production
   requires an explicit, valid provider selection (already enforced at
   config-validation time by step 2, but must also be enforced at runtime
   construction). Feature flags `pkcs11` / `tpm` on the `storage` crate pull
   in the new provider crates. ⬜ not started
6. **SoftHSM-backed integration test**: new file in `crates/storage/tests/`
   (feature-gated `pkcs11`) that boots a single-node cluster with a
   SoftHSM-backed KEK and does an end-to-end write/read, beyond the
   unit-level wrap/unwrap coverage in step 3. ⬜ not started
7. **CI**: add a "Install SoftHSM2 + init test token" step to
   `.github/workflows/ci.yml` (apt-get, same pattern as the SPIRE binary
   install) ahead of running the `pkcs11`-featured tests. Compile (but do not
   run) the TPM example in CI to catch rot, without adding `swtpm` as a hard
   CI dependency. ⬜ not started
8. **Docs**: update `doc/src/raft_storage.md`'s crate-layout tree and key
   hierarchy section, and `CONTRIBUTING.md`'s crate-purpose table, with the
   two new crates. Add the TPM sample walkthrough. ⬜ not started
9. **Supply chain**: add `cryptoki` and `tss-esapi` (pinned versions) to the
   extended cargo-vet coverage list in ADR §1, and check `deny.toml` for any
   new transitive-dependency rules needed. ⬜ not started

## Open questions for step 3 onward

- Exact `cryptoki` and `tss-esapi` version pins, and whether either requires
  system packages beyond what CI/dev containers currently install
  (`libp11-kit`, `tpm2-tss` headers, etc.) — needs a spike before locking
  `Cargo.toml` entries.
- Whether the PKCS#11 auto-generate-key-on-first-use convenience (step 3)
  should be gated behind its own config flag, given it changes the operator
  key-ceremony story for regulated deployments.
