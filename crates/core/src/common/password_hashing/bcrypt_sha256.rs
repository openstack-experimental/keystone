// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Bcrypt-SHA256 hasher - mirrors `bcrypt.py::Bcrypt_sha256`.
//!
//! Bcrypt silently truncates inputs at 72 bytes, so this variant first reduces
//! the password to a fixed-size HMAC-SHA256 digest (keyed by the salt) and
//! feeds that digest to bcrypt. The full password therefore always
//! contributes, regardless of length.

use base64::{Engine as _, engine::general_purpose::STANDARD};
// KeyInit provides new_from_slice; Mac provides update/finalize.
use hmac::{Hmac, KeyInit, Mac};
use openstack_keystone_config::Config;
use tokio::task;
use tracing::debug;

use super::{PasswordHashError, PasswordHasher, generate_salt};

type HmacSha256 = Hmac<sha2::Sha256>;

/// Length in characters of a bcrypt-encoded (Radix64) salt string.
const BCRYPT_SALT_LEN: usize = 22;

/// Length in bytes of the bcrypt checksum/digest segment of a formatted
/// bcrypt hash string (the trailing portion after the salt).
const BCRYPT_CHECKSUM_LEN: usize = 31;

/// Length of the bcrypt prefix `$2b$NN$` (ident + 2-digit cost factor,
/// each `$`-delimited).
const BCRYPT_PREFIX_LEN: usize = 7;

/// Total length of a complete `$2b$`-format bcrypt hash string:
/// prefix + salt + checksum. (This is where a bare `60` would otherwise
/// show up unexplained.)
const BCRYPT_FULL_HASH_LEN: usize = BCRYPT_PREFIX_LEN + BCRYPT_SALT_LEN + BCRYPT_CHECKSUM_LEN;

/// Cost factor used solely to derive the canonical Radix64 encoding of a
/// freshly generated random salt (see [`BcryptSha256Hasher::hash`]).
/// This is bcrypt's minimum permitted cost factor, so the extra bcrypt call
/// it requires is negligible compared to the real hash computed afterwards
/// at the configured `rounds`.
const BCRYPT_SALT_ENCODING_COST: u32 = 4;

pub(super) struct BcryptSha256Hasher;

impl PasswordHasher for BcryptSha256Hasher {
    async fn hash(&self, conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        // mirrors keystone/common/password_hashers/bcrypt.py::Bcrypt_sha256.hash():
        //   salt_with_opts = bcrypt.gensalt(rounds)
        //   salt = salt_with_opts[-22:]
        //   hmac_digest = base64.b64encode(hmac.digest(salt, password, "sha256"))
        //   hashed = bcrypt.hashpw(hmac_digest, salt_with_opts)
        //   digest = hashed[-31:]
        //   return f"$bcrypt-sha256$v=2,t=2b,r={rounds}${salt}${digest}"
        let password_bytes = password.to_vec();
        let rounds = conf.identity.password_hash_rounds.unwrap_or(12);

        let hash = task::spawn_blocking(move || {
            // Two values are derived from the same 16 random salt bytes:
            //   (a) the raw bytes themselves, used directly as the salt for
            //       the real bcrypt hash computed below; and
            //   (b) their canonical 22-char Radix64 encoding, used both as
            //       the HMAC-SHA256 key and embedded in the output record.
            //
            // (b) must be exactly the encoding bcrypt itself would use, so it
            // is taken from the bcrypt crate's own salt-formatting logic via a
            // throwaway hash at the algorithm's minimum cost factor
            // (BCRYPT_SALT_ENCODING_COST). Only the salt string from that call
            // is kept; its hash output is discarded.
            //
            // Hand-rolling the encoding (picking 22 random alphabet chars) is
            // a trap: a bcrypt salt carries 128 bits across 22 chars, so the
            // last char has only 4 meaningful bits - just 4 of the 64 alphabet
            // chars are canonical there. A non-canonical salt gets silently
            // re-canonicalized by bcrypt when the hash is computed, so the salt
            // string embedded in the record would stop matching the salt used
            // as the HMAC key. Letting the bcrypt crate produce it sidesteps
            // this entirely.
            let raw_salt = generate_salt();
            let salt_encoder =
                ::bcrypt::hash_with_salt(b"unused", BCRYPT_SALT_ENCODING_COST, raw_salt)?;
            let salt_str = salt_encoder.get_salt();

            // HMAC-SHA256 keyed by the salt bytes, over the password, encoded
            // with standard PADDED base64 (Python's `base64.b64encode`, not a
            // padding-stripped variant). This must match verify()'s encoding
            // byte-for-byte or no hash either path produces is verifiable by
            // the other.
            let hmac_res = compute_hmac_sha256(salt_str.as_bytes(), &password_bytes)?;
            let hmac_digest_b64 = STANDARD.encode(hmac_res);

            // Hash using the real raw salt and the HMAC-derived intermediate password.
            let final_bcrypt =
                ::bcrypt::hash_with_salt(hmac_digest_b64.as_bytes(), rounds as u32, raw_salt)?;
            let full_bcrypt_str = final_bcrypt.format_for_version(::bcrypt::Version::TwoB);
            debug_assert_eq!(
                full_bcrypt_str.len(),
                BCRYPT_FULL_HASH_LEN,
                "bcrypt crate's 2b format string length changed unexpectedly"
            );

            // Extract the exact trailing bcrypt signature digest.
            let digest_str = &full_bcrypt_str[full_bcrypt_str.len() - BCRYPT_CHECKSUM_LEN..];

            Ok::<String, PasswordHashError>(format!(
                "$bcrypt-sha256$v=2,t=2b,r={}${}${}",
                rounds, salt_str, digest_str
            ))
        })
        .await??;
        Ok(hash)
    }

    async fn verify(
        &self,
        _conf: &Config,
        password: &[u8],
        hash: &str,
    ) -> Result<bool, PasswordHashError> {
        // mirrors keystone/common/password_hashers/bcrypt.py::Bcrypt_sha256.verify()
        // exactly: there is no "version" concept in the real implementation.
        // It always HMACs (never falls back to a plain digest), and it does not
        // even look at `v=`, it just scans every comma-delimited param for `t=`
        // and `r=` and ignores anything else. An earlier revision of this module
        // had a second, version-gated code path that computed a plain SHA-256
        // digest (no HMAC) for records without `v=2`. That path was based on a
        // Passlib-only format Keystone's own implementation never produces or
        // reads, and has been removed.
        let password_bytes = password.to_vec();
        let hash_str = hash.to_string();

        // Split on '$': ["", "bcrypt-sha256", "v=2,t=2b,r=12", salt, digest]
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() != 5 {
            debug!("Malformed BcryptSha256 record encountered");
            return Ok(false);
        }

        let options = parts[2].to_string();
        let salt = parts[3].to_string();
        let checksum_part = parts[4].to_string();

        if salt.len() != BCRYPT_SALT_LEN || checksum_part.len() != BCRYPT_CHECKSUM_LEN {
            return Ok(false);
        }

        // Parse t= (bcrypt ident) and r= (cost rounds) from the options field.
        let mut bcrypt_type = "2b".to_string();
        let mut rounds = None;
        for opt in options.split(',') {
            if let Some(val) = opt.strip_prefix("t=") {
                bcrypt_type = val.to_string();
            } else if let Some(val) = opt.strip_prefix("r=") {
                rounds = Some(val.parse::<u32>().map_err(|_| {
                    PasswordHashError::CryptoHash("Invalid BcryptSha256 cost factor".into())
                })?);
            }
        }

        let rounds = rounds.ok_or_else(|| {
            PasswordHashError::CryptoHash("Missing rounds parameter in BcryptSha256 record".into())
        })?;

        match task::spawn_blocking(move || {
            // Reconstruct the bcrypt hash string for checkpw.
            // Python does: new_salt = f"${opts['t']}${opts['r']}${salt}"
            // then bcrypt.checkpw(hmac_digest, f"{new_salt}{digest}".encode("ascii")).
            //
            // The {:02} zero-pad is deliberate and must NOT be dropped to
            // literally mirror Python's f-string: the Rust `bcrypt` crate's
            // parser requires the cost field to be exactly two digits, whereas
            // Python's `int`-formatted `r=` lets the underlying libbcrypt accept
            // a single digit. The stored digest was originally computed against
            // a salt from `bcrypt.gensalt(rounds)`, which always embeds a
            // 2-digit zero-padded cost (e.g. "05"), so "05", not "5", is the
            // cost the digest actually corresponds to. For realistic round
            // counts (>= 10) the two forms are identical anyway.
            let reconstructed_hash =
                format!("${}${:02}${}{}", bcrypt_type, rounds, salt, checksum_part);

            // Re-derive the HMAC digest using the embedded salt.
            let hmac_res = compute_hmac_sha256(salt.as_bytes(), &password_bytes)?;
            let intermediate_b64 = STANDARD.encode(hmac_res);

            ::bcrypt::verify(intermediate_b64, &reconstructed_hash).map_err(PasswordHashError::from)
        })
        .await?
        {
            Ok(res) => Ok(res),
            Err(e) => Err(e),
        }
    }
}

/// HMAC-SHA256 keyed by `salt`, over `password`. Returns raw 32-byte digest.
///
/// Both `hash` and `verify` must use this function so the intermediate digest
/// is identical on both paths.
fn compute_hmac_sha256(salt: &[u8], password: &[u8]) -> Result<[u8; 32], PasswordHashError> {
    let mut mac = HmacSha256::new_from_slice(salt).map_err(|e| {
        PasswordHashError::CryptoHash(format!("HMAC key initialization error: {e}"))
    })?;
    mac.update(password);
    let result = mac.finalize().into_bytes();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::mock_config;
    use super::super::{hash_password, verify_password};
    use openstack_keystone_config::PasswordHashingAlgo;

    #[tokio::test]
    async fn test_bcrypt_sha256_matches_keystone_python_ascii_password() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let python_hash =
            "$bcrypt-sha256$v=2,t=2b,r=12$dWWyn1sALNWeny6KjQhSUu$iOmfSpzioo6ThZbSXwWYSZAQcGlba/q";

        assert!(
            verify_password(&conf, "password123", python_hash)
                .await
                .unwrap(),
            "Rust BcryptSha256 verification rejected a real Keystone Python BcryptSha256 hash"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_sha256_matches_keystone_python_does_not_truncate_at_72_bytes() {
        // Unlike plain Bcrypt, BcryptSha256 is *not* capped at 72 bytes by
        // password_hashing.py - it HMACs the full password to a fixed-size
        // digest before bcrypt ever sees it. This hash was generated from
        // the full, untruncated 73-byte password.
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let python_hash =
            "$bcrypt-sha256$v=2,t=2b,r=12$BL2N.GYa/h9LYksj.qtsb.$oUw7Xg.rbmPt8aXB2z544HOIQMrQbZ6";
        let full_73_byte_password = "A".repeat(73);

        assert!(
            verify_password(&conf, &full_73_byte_password, python_hash)
                .await
                .unwrap(),
            "Rust BcryptSha256 must not truncate at 72 bytes - that would diverge from Keystone Python"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_sha256_matches_keystone_python_utf8_password() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let python_hash =
            "$bcrypt-sha256$v=2,t=2b,r=12$eP5KRHawhX/K86TK3IOLoO$fpoVOwh9QvOLy1Y9GKxMkf.RnkfO60.";

        assert!(
            verify_password(&conf, "🚀-rocket-password", python_hash)
                .await
                .unwrap(),
            "Rust BcryptSha256 verification rejected a real Keystone Python hash of a UTF-8 password"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_sha256_rejects_wrong_password() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let hash = hash_password(&conf, "correct_password").await.unwrap();

        let result = verify_password(&conf, "wrong_password", &hash)
            .await
            .unwrap();
        assert!(
            !result,
            "BcryptSha256 incorrectly accepted a wrong password"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_sha256_malformed_hash_returns_false_or_err() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);

        for malformed in [
            "$bcrypt-sha256$v=2,t=2b,r=12$shortsalt", // too few '$'-delimited segments
            "$bcrypt-sha256$",                        // nearly empty
            "not-even-a-hash-string",                 // no '$' at all
        ] {
            let result = verify_password(&conf, "anything", malformed).await;
            assert!(
                matches!(result, Ok(false)) || result.is_err(),
                "Malformed hash `{malformed}` should fail safely, not panic"
            );
        }
    }

    #[tokio::test]
    async fn test_verify_bcrypt_sha256_roundtrip() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let password = b"password123";
        let generated_hash = hash_password(&conf, password).await.unwrap();

        let is_valid = verify_password(&conf, password, &generated_hash)
            .await
            .expect("Verification function failed");
        assert!(
            is_valid,
            "BcryptSha256 dynamically generated hash failed to verify against itself"
        );
    }
}
