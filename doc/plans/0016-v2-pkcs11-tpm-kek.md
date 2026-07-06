# Implementation plan: PKCS#11 and TPM KEK providers (ADR 0016-v2 §2.5)

Status: **steps 1-9 complete**. Plan finished.

This is a working implementation plan, not user-facing documentation — it is
intentionally not linked from `doc/src/SUMMARY.md`. The durable design record
is [ADR 0016-v2 §2.5](../src/adr/0016-v2-raft-storage.md); this file tracks
how that design gets built.

## Context

ADR 0016-v2 §2.1 named "HSM / PKCS#11 / Cloud KMS" as the production KEK
source but never specified a mechanism. `crates/storage-crypto/src/kek.rs`
already reserved the abstraction boundary: the `KekProvider` trait, a working
`EnvKek` (dev-mode only), and (until step 4) a `Pkcs11KekStub` placeholder
that always returned `CryptoError::Pkcs11NotImplemented`. No TPM path existed
at all. This plan replaced the stub with real PKCS#11 and TPM 2.0 providers;
`Pkcs11KekStub` and `CryptoError::Pkcs11NotImplemented` were deleted in step 5
once `crates/storage/src/app.rs` no longer needed a placeholder to fall back
to.

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
3. **`storage-crypto-pkcs11` crate**: `cryptoki` 0.12 dependency (pure-Rust,
   `dlopen`s the module at runtime — no system PKCS#11 headers needed to
   build), `Pkcs11Kek` implementing `KekProvider` over `CKM_AES_GCM`, with
   `auto_generate: bool` as an explicit `Pkcs11KekParams` field (caller opts
   in rather than it being an implicit default — resolves the corresponding
   open question below), slot selection by numeric id or token label. 8
   SoftHSM2-backed integration tests (round-trip, distinct nonces per wrap,
   tampered-tag rejection, tampered-ciphertext rejection, key reuse across
   sessions, wrong-PIN failure, missing-key-without-auto-generate failure,
   slot-by-id vs slot-by-label equivalence) — all passing against a real
   `libsofthsm2.so`. ✅ done
   (`crates/storage-crypto-pkcs11/`).
4. **`storage-crypto-tpm` crate**: `tss-esapi` 7.7 dependency (requires the
   system `tpm2-tss` library + headers via `pkg-config`, unlike `cryptoki` —
   resolves the corresponding open question below), `TpmKek` implementing
   `KekProvider` via Encrypt-then-MAC (AES-256-CFB `TPM2_EncryptDecrypt2` +
   HMAC-SHA256 `TPM2_HMAC`, constant-time tag comparison before decrypting,
   per §2.5.2). Both child keys are `fixedTPM | fixedParent` and
   `sensitiveDataOrigin` (TPM-generated, non-extractable), children of a
   primary that's recreated deterministically each `open()` rather than
   persisted. `KeyReference::PersistentHandle(u32)` provisions the AES key at
   that handle and the HMAC key at `handle + 1`; `KeyReference::ContextFile`
   stores each key's TPM-encrypted `(public, private)` blob pair at a path /
   `<path>.hmac`. `examples/tpm_kek_demo.rs` exercises both key-reference
   modes and tamper rejection — not CI-gated (compiled only, per the decided
   test/sample scope), but manually verified against a real `swtpm` instance
   for this change, including cross-process-restart reload and wrong-auth
   rejection. ✅ done
   (`crates/storage-crypto-tpm/`).
5. **Wire into `crates/storage/src/app.rs`**: replaced the hardcoded
   `dev_mode ? EnvKek : Pkcs11KekStub` selection with `build_kek`, driven by
   `ds_config.kek_provider` (`Env`/`Pkcs11`/`Tpm`), with per-provider builder
   functions. `Pkcs11KekStub` and `CryptoError::Pkcs11NotImplemented` were
   deleted outright (dead once nothing falls back to them) rather than kept
   around as an unused placeholder. New `pkcs11` / `tpm` feature flags on the
   `storage` crate gate the optional dependency on the corresponding provider
   crate; selecting a provider whose feature isn't compiled in fails at
   `build_kek` construction time with a clear error rather than failing to
   compile or silently falling back. `auto_generate` is hardcoded `false` for
   both providers (resolves the corresponding open question below); PIN/auth
   secrets come from the config's already-loaded `SecretSlice` content
   (`Config::load_all` reads `pkcs11_pin_file` / `tpm_auth_file` before
   `app.rs` ever sees the config). ✅ done
   (`crates/storage/src/app.rs`, `crates/storage/Cargo.toml`).
6. **SoftHSM-backed integration test**: `crates/storage/tests/test_pkcs11_cluster.rs`
   (feature-gated `pkcs11`, whole file behind `#![cfg(feature = "pkcs11")]`)
   provisions a real SoftHSM2 token (via the `cryptoki` crate directly, now a
   dev-dependency of `storage`, matching `storage-crypto-pkcs11`'s own test
   style) and the AES-256 KEK key on it — out-of-band, as `build_pkcs11_kek`'s
   hardcoded `auto_generate: false` requires — then boots a real single-node
   cluster through `init_storage` with `kek_provider = "pkcs11"` and:
   - `test_pkcs11_backed_cluster_write_read`: end-to-end write/read of
     sensitive-tier data, exercising config -> `build_kek` -> `Pkcs11Kek` ->
     the Raft state machine's DEK wrap/unwrap, beyond the crate-level
     wrap/unwrap unit coverage in step 3.
   - `test_pkcs11_backed_cluster_restart_reopens_token`: writes data, does a
     full storage shutdown (`raft.shutdown().await`, same Fjall-lock-release
     requirement as the existing `test_node_restart_with_address_format_change`),
     then restarts against the same on-disk state and the same real token —
     proving the wrapped-DEK-on-disk format survives a full process restart
     and doesn't depend on anything the first PKCS#11 session held in memory.

   Also corrected a stale doc comment on
   `test_kek_gating_production_mode_rejected` (`test_cluster.rs`) that still
   claimed no production `KekProvider` existed — no longer true since step 5.
   ✅ done (`crates/storage/tests/test_pkcs11_cluster.rs`,
   `crates/storage/Cargo.toml`, `crates/storage/tests/test_cluster.rs`).
7. **CI**: `cargo nextest run --all-features --profile ci` in
   `.github/workflows/ci.yml`'s `test` job already builds both new crates on
   every run (it was silently relying on the runner happening to have the
   right system packages — true in this dev environment, not guaranteed on a
   stock `ubuntu-latest` runner). Added:
   - **`libtss2-dev` + `pkg-config`** (apt-get, unconditional): build-time
     requirement for `tss-esapi` to compile at all — needed regardless of
     whether any TPM test runs, since `--all-features` always compiles the
     `tpm` feature.
   - **`softhsm2`** (apt-get): provides `libsofthsm2.so` so the `pkcs11`
     integration tests (`storage-crypto-pkcs11/tests/softhsm.rs`,
     `storage/tests/test_pkcs11_cluster.rs`) actually run instead of
     self-skipping. No system-wide token/PIN setup step needed — every test
     already provisions its own isolated token via `SOFTHSM2_CONF` (step
     3/6), so this is purely a package install.
   - **"Build TPM KEK example"** step: `cargo build -p
     openstack-keystone-storage-crypto-tpm --example tpm_kek_demo`.
     `cargo nextest run` doesn't build `examples/` on its own, so without
     this the sample could silently rot; per the decided test/sample scope
     it's compiled only, not executed — no `swtpm` install in CI.

   Verified with `cargo check --workspace --all-features --tests`, which
   exercises the same build surface `nextest` does. ✅ done
   (`.github/workflows/ci.yml`).
8. **Docs**: `doc/src/raft_storage.md`'s crate-layout tree now lists
   `storage-crypto-pkcs11` and `storage-crypto-tpm` alongside their key
   files/tests; the intro paragraph and Key Hierarchy diagram's KEK-source
   line were updated to name both production providers instead of a generic
   "HSM / Cloud KMS". Added a new "PKCS#11 and TPM KEK Providers" subsection
   (linked from the ToC and from a new Prerequisites bullet) documenting the
   `[distributed_storage.pkcs11]` / `[distributed_storage.tpm]` config blocks,
   the out-of-band key-provisioning requirement (`auto_generate: false` per
   step 5), how to run the SoftHSM2-backed tests locally, and a walkthrough of
   `crates/storage-crypto-tpm/examples/tpm_kek_demo.rs` against `swtpm`
   (mirroring the example's own doc comment). `CONTRIBUTING.md`'s workspace
   structure table gained rows for `storage-crypto`, `storage-crypto-pkcs11`,
   and `storage-crypto-tpm` (none had an entry before). ✅ done
   (`doc/src/raft_storage.md`, `CONTRIBUTING.md`).
9. **Supply chain**: extended the ADR §1 Supply Chain paragraph's
   `cargo-vet` coverage list with `cryptoki` (pinned `0.12.0`) and
   `tss-esapi` (pinned `7.7.0`), explaining why they meet criteria (a)/(b)
   (both transiently hold the unwrapped DEK during `wrap_dek`/`unwrap_dek`
   and sit directly in the KEK call path). Checked every new transitive
   dependency `cryptoki`/`tss-esapi` bring in (via `cargo metadata` +
   `cargo tree --all-features`) against `deny.toml`'s license allow-list —
   all are MIT/Apache-2.0/ISC, already allowed, so no new `deny.toml` rules
   were needed; added a comment recording that review so it isn't silently
   re-derived later. ✅ done
   (`doc/src/adr/0016-v2-raft-storage.md`, `deny.toml`).

## Open questions resolved in step 5

- `auto_generate`: hardcoded `false` in both `build_pkcs11_kek` and
  `build_tpm_kek` (`crates/storage/src/app.rs`) rather than given a config
  key. First-run auto-provisioning bypasses any out-of-band key ceremony a
  regulated deployment might require, so it's not offered as an implicit
  production default; revisit only if an actual deployment asks for it (a
  dedicated `keystone-manage` provisioning command is the more likely shape
  for that, not a config flag toggling behaviour inside `init_storage`).
- `storage-crypto-tpm::KeyReference::PersistentHandle`'s `handle + 1` (AES /
  HMAC) convention was carried into `app.rs`'s config-to-params translation
  as-is, not promoted to a second `TpmKekConfiguration` field.
  `TpmKekConfiguration` continues to carry exactly one key reference; nothing
  about the ADR or the initial deployment target needs the two child keys at
  independently chosen locations.

## Open questions resolved in step 7

- CI system-package needs, resolved as anticipated: `cryptoki` needed nothing
  beyond the module itself (pure Rust, `dlopen`s at runtime, so `pkcs11`'s
  only CI need is `softhsm2` for the module file); `tss-esapi` needed
  `libtss2-dev` + `pkg-config` at build time, installed unconditionally since
  `--all-features` always compiles it. `swtpm` was not added to CI, matching
  the decided test/sample scope (TPM has no CI-gated tests).

## Open questions resolved in step 8

None arose — the docs work was mechanical (crate-layout tree, a new config
walkthrough section, a workspace-structure table row) with no design
decisions to make.

## Open questions resolved in step 9

None arose — every transitive dependency `cryptoki`/`tss-esapi` bring in was
already under a license `deny.toml` already allows, so no bans/exceptions
needed adding.

## Plan complete

All 9 steps are done: ADR addendum, config schema, `storage-crypto-pkcs11`,
`storage-crypto-tpm`, `app.rs` wiring, the SoftHSM2-backed cluster test, CI
system-package wiring, docs, and supply-chain coverage. No further steps are
planned.
