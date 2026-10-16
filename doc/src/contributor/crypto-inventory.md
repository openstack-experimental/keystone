# Cryptography inventory and FIPS 140-3 status

This page lists every cryptographic primitive the workspace uses, where it
lives, which library provides it, and whether it can run on the FIPS 140-3
validated AWS-LC module. It is the reference for FIPS and crypto audits.

Each source file that implements or selects a primitive carries a one-line
comment `// Crypto inventory: <ID>` that points at a row below. Callers that
only use a seam (for example HTTPS clients built on rustls) are covered by the
marker of the seam (`tls-provider`, NET-1) and carry none of their own. When you
add, move or remove cryptography, update the row and the comment in the same
change (see the checklist at the end).

## Reading the status column

| Status                       | Meaning                                                                                                                                             |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Validated**                | Runs on the validated AWS-LC module when built with the `fips` feature of its crate (or of the service).                                            |
| **Not validated**            | Uses a library without a FIPS 140-3 validation. Replacing it needs a design change or a different library.                                          |
| **Compat-fixed**             | The algorithm is dictated by an external format (Python Keystone, AWS, RFC 6238, WebAuthn). It cannot be swapped without breaking interoperability. |
| **Not a security primitive** | Hashing or randomness for identifiers, never a secret or a trust decision.                                                                          |
| **Delegated**                | The work happens outside this process (HSM, TPM, PostgreSQL). Its validation is the device's.                                                       |

"Validated" is a statement about which implementation is linked, based on the
`aws-lc-rs` documentation and tests for the `fips` feature. It is not a CMVP
certificate claim, and an operator still has to check the security policy of the
module version that ships (see [Caveats](#caveats)).

## Build modes

| Crate                                    | Default build                     | `fips` feature                                                                                                                                                     |
| ---------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `openstack-keystone-storage-crypto`      | `ring` (AES-GCM, HKDF, HMAC, RNG) | `aws-lc-rs` with its `fips` feature: AES-256-GCM, HKDF, HMAC, RNG. GCM IVs are generated inside the module, with a per-message key. See ADR 0016-v2 "FIPS builds". |
| `cadf`                                   | `ring` (HMAC-SHA256, HKDF, RNG)   | `aws-lc-rs` with its `fips` feature: HMAC, HKDF, RNG.                                                                                                              |
| `openstack-keystone-tls-provider`        | `ring`                            | `aws-lc` selects `aws-lc-rs`; `fips` adds rustls' `fips` feature (validated module). Used by rustls, tokio-rustls, tonic, reqwest, vaultrs, ldap3.                 |
| `openstack-keystone-distributed-storage` | forwards to storage-crypto        | `fips` forwards to storage-crypto.                                                                                                                                 |
| `openstack-keystone` (service)           | `ring` everywhere                 | `rustls-aws-lc` switches TLS to `aws-lc-rs`; `fips` also selects the validated module for TLS and for the storage cryptography.                                    |

Use `--no-default-features --features fips` on `storage-crypto` and `cadf` to
keep `ring` out of those crates. A process that makes a FIPS claim must call
`assert_fips()` (storage-crypto and cadf both export it) and
`openstack_keystone_tls_provider::is_fips()` at start-up. They fail unless the
validated module is linked and in FIPS mode.

Mixing builds in one Raft cluster is unsupported. By design a `fips` node can
read records written by a default node (legacy base-key fallback in
`storage-crypto`), but a default node cannot read records written by a `fips`
node. Only the first direction has a unit test (the legacy state-record version
binding); the cross-build read is not tested end to end.

## Inventory

### Distributed storage (`storage-crypto`, `storage`, KEK providers)

| ID     | Where                                                                 | Primitive                                                                                                  | Provider                                           | Status                                                                                                                                        |
| ------ | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| STO-1  | `storage-crypto/src/cipher.rs`, `backend.rs`                          | AES-256-GCM for Raft log, state machine and backup records                                                 | `ring`; `aws-lc-rs` `RandomizedNonceKey` in `fips` | **Validated** in `fips` (module-generated IV, per-message key). Default build uses deterministic nonces (SP 800-38D §8.2.1).                  |
| STO-2  | `storage-crypto/src/dek.rs`, `backend.rs`                             | HKDF-SHA256 (Extract-then-Expand) for the Log, State, Backup and audit sub-keys                            | `ring`; `aws-lc-rs`                                | **Validated** in `fips`.                                                                                                                      |
| STO-3  | `storage-crypto/src/cipher.rs`                                        | HKDF-SHA256 per-message key (`fips` only) and Expand-only nonce derivation (default only)                  | same                                               | **Validated** in `fips`. The default-build Expand-only nonce derivation is not an approved flow; it is skipped in `fips`.                     |
| STO-4  | `storage-crypto/src/kek.rs`                                           | `EnvKek`: AES-256-GCM wrap of the DEK. Wrap nonce is a truncated HMAC-SHA256 (default); module IV (`fips`) | same                                               | **Validated** in `fips`.                                                                                                                      |
| STO-5  | `storage-crypto/src/dek.rs`                                           | DEK generation from the system RNG                                                                         | `ring` `SystemRandom`; `aws-lc-rs` DRBG            | **Validated** in `fips`.                                                                                                                      |
| STO-6  | `storage-crypto-pkcs11/src/lib.rs`                                    | `CKM_AES_GCM` wrap of the DEK inside the token; optional token-generated IV                                | `cryptoki`                                         | **Delegated** to the PKCS#11 token. The token-generated-IV path uses the message API and is untested on hardware.                             |
| STO-7  | `storage-crypto-tpm/src/lib.rs`                                       | TPM 2.0 AES-CFB wrap of the DEK, HMAC tag computed by the TPM, 16-byte IV from `rand`                      | `tss-esapi`                                        | **Delegated** to the TPM. Single-node only. The IV comes from `rand`, not the TPM RNG, and AES-CFB is not the SP 800-38D mode used elsewhere. |
| STO-8  | `storage/src/store/state_machine/snapshot.rs`                         | Random 64-bit nonce salt of a backup                                                                       | `storage-crypto` `random_bytes`                    | **Validated** in `fips`.                                                                                                                      |
| STO-9  | `storage/src/network.rs`, `keystone/src/server/listener/raft_grpc.rs` | mTLS between Raft nodes, tonic, `x509-parser` for peer certificates                                        | `rustls` through `openstack-keystone-tls-provider` | **Validated** with the service `fips` feature, except SPIFFE mTLS (STO-12).                                                                   |
| STO-12 | `spiffe-rustls`, `spiffe-rustls-tokio`                                | SPIFFE X.509-SVID mTLS                                                                                     | `ring`, hardwired by `spiffe-rustls`               | **Not validated.** Always `ring`; see [TLS](#tls-and-transport-gaps).                                                                         |
| STO-10 | `storage/src/network.rs`, `raft_grpc.rs` (tests, dev certs)           | `rcgen` certificate generation                                                                             | `rcgen` `ring`                                     | **Not validated.** Test and development only.                                                                                                 |
| STO-11 | `storage/src/store/state_machine/*.rs`, `raft_sm.rs`                  | `rand` for snapshot indexes                                                                                | `rand`                                             | **Not a security primitive.**                                                                                                                 |

### Audit framework (`cadf`)

| ID    | Where                                 | Primitive                                                                                                                  | Provider                                           | Status                                         |
| ----- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------------- |
| AUD-1 | `cadf/src/crypto.rs`, `dispatcher.rs` | HMAC-SHA256 signature over the JCS-canonical event, constant-time verification                                             | `ring`; `aws-lc-rs`                                | **Validated** in `fips`.                       |
| AUD-2 | `cadf/src/kdf.rs`, `identity.rs`      | Per-node signing key: `HKDF(salt = "{service}-audit-hmac-salt-v1", IKM = KEK, info = "{service}-audit-hmac-v1:{node_id}")` | `ring`; `aws-lc-rs`                                | **Validated** in `fips`.                       |
| AUD-3 | `cadf/src/keyring.rs`                 | 32-byte KEK generation for the audit keyring                                                                               | `ring` `SystemRandom`; `aws-lc-rs` DRBG            | **Validated** in `fips`.                       |
| AUD-4 | `cadf/src/syslog.rs`                  | RFC 5425 syslog over TLS (`audit-syslog` feature), webpki roots from `rustls-native-certs`                                 | `rustls` through `openstack-keystone-tls-provider` | **Validated** with the service `fips` feature. |
| AUD-5 | `cadf/src/runtime.rs`, `spool.rs`     | `uuid` v4 event identifiers                                                                                                | `uuid` (OS RNG)                                    | **Not a security primitive.**                  |

### Tokens, keys and credentials

| ID     | Where                                                                                                                        | Primitive                                                                                                | Provider                                       | Status                                                                                              |
| ------ | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| TOK-1  | `key-repository`, `token-driver-fernet`, `credential-driver-sql`                                                             | Fernet (AES-128-CBC + HMAC-SHA256) for tokens and for credential blobs; keys from `Fernet::generate_key` | `fernet` 0.2 (RustCrypto `aes`, `cbc`, `hmac`) | **Compat-fixed** (Python Keystone format) and **Not validated**.                                    |
| TOK-2  | `key-repository/src/asymmetric/keygen.rs`, `jwt_bridge.rs`, `token-driver-jws`                                               | ES256 (P-256) and RS256 (RSA-2048) key generation and JWS signing                                        | `p256`, `rsa`, `jsonwebtoken` `rust_crypto`    | **Not validated.** RSA-2048 is allowed through 2030 by SP 800-131A; ES256 is approved by algorithm. |
| TOK-3  | `core/src/oauth2_key/*`, `spiffe_key/*`                                                                                      | JWKS publication, key ids, domain signing keys (ES256/RS256)                                             | same                                           | **Not validated.**                                                                                  |
| TOK-4  | `keystone/src/federation/api/oidc_utils.rs`, `core/src/oauth2_client/verify.rs`                                              | Verification of upstream OIDC ID tokens and client assertions (asymmetric algorithms only)               | `jsonwebtoken`                                 | **Not validated.** The algorithm set is the peer's.                                                 |
| TOK-5  | `core/src/oauth2_client/pkce.rs`, `oauth2_session*.rs`, `auth_plugin_auth.rs`, `mapping/version.rs`, `identity/shadow_id.rs` | SHA-256 (PKCE S256, token and code hashes, ids)                                                          | `sha2`                                         | SHA-256 is approved; the implementation is **Not validated**.                                       |
| TOK-6  | `core/src/auth_plugin.rs`, `mapping/hmac.rs`                                                                                 | HMAC-SHA256 for auth-plugin handles and mapping fingerprints                                             | `hmac`+`sha2`                                  | **Not validated** (approved algorithm).                                                             |
| TOK-7  | `core/src/api_key/crypto.rs`, `oauth2_client/crypto.rs`                                                                      | Argon2id for API key and OAuth2 client secrets; random secrets from `rand`                               | `argon2`, `rand`                               | **Not validated.** Argon2id is not an approved KDF under SP 800-132.                                |
| TOK-8  | `core/src/api_key/token.rs`                                                                                                  | SHA-256 and CRC32 of the API key checksum, random base62 entropy                                         | `sha2`, `crc32fast`, `rand`                    | CRC32 is **Not a security primitive**; entropy source **Not validated**.                            |
| TOK-9  | `keystone/src/api/v4/oauth2/html.rs`, `federation/api/oidc_utils.rs`                                                         | CSP nonce, OIDC `state`/`nonce` values from `rand`                                                       | `rand`                                         | **Not validated** (OS RNG).                                                                         |
| TOK-10 | `auth-plugin-runtime/src/lib.rs`                                                                                             | SHA-256 integrity check of plugin artifacts                                                              | `sha2`                                         | **Not validated** (approved algorithm).                                                             |

### Users and external protocol compatibility

| ID     | Where                                                | Primitive                                                                           | Provider                                               | Status                                                                                                            |
| ------ | ---------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| PWD-1  | `password-hashing/src/bcrypt.rs`, `bcrypt_sha256.rs` | bcrypt and bcrypt-sha256 password hashes                                            | `bcrypt`, `hmac`, `sha2`                               | **Compat-fixed** (existing Python Keystone hashes) and **Not validated**; bcrypt is not an approved password KDF. |
| PWD-2  | `password-hashing/src/scrypt.rs`                     | scrypt                                                                              | `scrypt`                                               | **Compat-fixed**, **Not validated**.                                                                              |
| PWD-3  | `password-hashing/src/pbkdf2.rs`                     | PBKDF2-HMAC-SHA512                                                                  | `hmac`, `sha2`                                         | **Compat-fixed**. The algorithm is approved (SP 800-132); the implementation is **Not validated**.                |
| PWD-4  | `password-hashing/src/plaintext.rs`, `lib.rs`        | Constant-time compare, random 16-byte salt                                          | `subtle`, `rand`                                       | **Not validated** (OS RNG).                                                                                       |
| EC2-1  | `core/src/credential/ec2_signature.rs`               | AWS Signature v2 (HMAC-SHA1, HMAC-SHA256) and v4 (HMAC-SHA256) verification         | `hmac`, `sha1`, `sha2`                                 | **Compat-fixed** (AWS protocol). HMAC-SHA1 is allowed for MAC use, not for signatures. **Not validated.**         |
| TOTP-1 | `core/src/credential/totp.rs`                        | HMAC-SHA1 TOTP (RFC 6238)                                                           | `hmac`, `sha1`                                         | **Compat-fixed**, **Not validated**.                                                                              |
| WEB-1  | `webauthn` crate, `api-types/src/webauthn/*`         | WebAuthn registration and assertion verification (ES256, RS256, attestation chains) | `webauthn-rs` (links system OpenSSL through `openssl`) | **Not validated** by this build; validity follows the system OpenSSL.                                             |

### Transport and databases

| ID    | Where                                                                                  | Primitive                   | Provider                                                 | Status                                                                                         |
| ----- | -------------------------------------------------------------------------------------- | --------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| NET-1 | `keystone` (reqwest), `cli-manage`, `assignment-driver-openfga`, `oslo-config` (Vault) | HTTPS clients               | `rustls` through `openstack-keystone-tls-provider`       | **Validated** with the service `fips` feature.                                                 |
| NET-2 | `identity-driver-ldap`                                                                 | LDAPS / StartTLS            | `ldap3`; the `rustls-aws-lc` feature selects `aws-lc-rs` | **Validated** with the service `fips` feature. The `rand` use there only shuffles server URLs. |
| NET-3 | `sea-orm` / `sqlx` in all `*-sql` drivers and `cli-manage`                             | TLS to MySQL and PostgreSQL | `runtime-tokio-native-tls` (system OpenSSL)              | **Delegated** to the system OpenSSL. FIPS validity follows the host's OpenSSL provider.        |

### Tests and tools (no production impact)

`tests/*` and `tools/*` use `sha2`, `hmac`, `sha1`, `jsonwebtoken` and `rcgen`
to build fixtures and cross-check against Python Keystone
(`tools/cross_verify.py`, `tools/generate_kats.py`, `tools/audit_vectors.py`).
`tools/verify_and_pin_opa_bundle.sh` and the Dockerfiles use `sha256sum` to pin
downloaded artifacts. None of it ships in a service binary.

## TLS and transport gaps

TLS follows `openstack-keystone-tls-provider`. With the service `fips` feature,
rustls runs on the validated module through its own `fips` feature. This is the
design of the provider crate; this inventory did not re-verify it with a
handshake test.

Remaining gaps:

- SPIFFE mTLS (`spiffe-rustls`) hardwires `ring` and stays on it in every build,
  so Raft peers authenticated by SPIFFE identities are not on the validated
  module.
- Database TLS (`sea-orm`/`sqlx` with `native-tls`) and WebAuthn use the system
  OpenSSL.
- An `aws-lc` or `fips` TLS build links `aws-lc-sys` or `aws-lc-fips-sys` next
  to the `fips` build of `storage-crypto` and `cadf`; the libraries use distinct
  symbol prefixes and coexist in one binary.

## Caveats

- The validated module only treats AES-GCM encryption as an approved service
  when it generates the IV. The `fips` build therefore never supplies an IV for
  encryption; decryption with an external IV is approved.
- HKDF is only used as Extract-then-Expand with a non-empty salt and info in the
  `fips` build, which is the flow the `aws-lc-rs` documentation lists as an
  approved service. Expand-only HKDF remains in default-build nonce derivation
  and is never executed in `fips`.
- Both `assert_fips()` functions check that the validated module is the one
  linked and running in FIPS mode. They do not prove that every call a binary
  makes into any library is an approved service; TOK-_, PWD-_, EC2-_, TOTP-_,
  WEB-* and NET-* are outside the module.
- Hashes and MACs called "approved algorithm" above are NIST-approved
  algorithms, not validated implementations.
- The statements here come from the `aws-lc-rs` documentation and source and
  from tests of this repository, not from the CMVP security policy of the
  module. Check the policy for the exact module version before an audit.

## Maintenance checklist

When a change adds or alters cryptography:

1. Add or update the row in this file with provider and status.
2. Add `// Crypto inventory: <ID>` below the license header of each file that
   calls the primitive.
3. If the primitive can run on the validated module, route it through the
   crate's backend seam rather than calling the library directly, and add a
   known-answer test that runs in both builds.
4. Run the unit tests with and without the `fips` feature for `storage-crypto`
   and `cadf`.
5. Re-run
   `grep -rnE "\b(use|extern crate) (sha2|sha1|hmac|hkdf|argon2|bcrypt|scrypt|fernet|jsonwebtoken|rsa|p256|rand|getrandom|ring|aws_lc_rs|rustls|webauthn_rs|cryptoki|tss_esapi)\b" crates --include=*.rs`
   and check that every file it lists is covered by a row. Fully qualified uses
   without a `use` line (`sha2::Sha256::new()`) need a second grep for
   `\b(sha2|sha1|hmac|hkdf)::`.
