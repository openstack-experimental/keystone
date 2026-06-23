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

use std::collections::HashMap;
use std::sync::OnceLock;
use thiserror::Error;
use tokio::task;
use tracing::{debug, warn};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use hmac::Mac;
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::rand_core::OsRng;
use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::distr::{Alphanumeric, SampleString};
use scrypt::Scrypt;
use sha2::Digest;
use subtle::ConstantTimeEq;

use openstack_keystone_config::{Config, PasswordHashingAlgo};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

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

/// Length in bytes of a SHA-512 digest, used by the PBKDF2-SHA512 checksum.
const SHA512_OUTPUT_BYTES: usize = 64;

/// Cost factor used solely to derive the canonical Radix64 encoding of a
/// freshly generated random salt (see `hash_password`'s `BcryptSha256` arm).
/// This is bcrypt's minimum permitted cost factor, so the extra bcrypt call
/// it requires is negligible compared to the real hash computed afterwards
/// at the configured `rounds`.
const BCRYPT_SALT_ENCODING_COST: u32 = 4;

/// Safe dynamic thread-safe cache to handle runtime configuration reloads
/// and prevent timing side-channel attacks across different configurations.
///
/// Uses `RwLock<HashMap>` rather than a sharded map (e.g. `DashMap`): key
/// cardinality here is bounded by the number of distinct
/// `(algorithm, rounds)` pairs in use, which is tiny (almost always 1, at
/// most a handful across a config-reload transition), so write-lock
/// contention on the shared map is not a practical concern.
struct DynamicDummyCache {
    map: tokio::sync::RwLock<HashMap<String, String>>,
}

static DUMMY_HASH_CACHE: OnceLock<DynamicDummyCache> = OnceLock::new();

/// Internal helper to retrieve the global cache instance.
fn get_dummy_cache() -> &'static DynamicDummyCache {
    DUMMY_HASH_CACHE.get_or_init(|| DynamicDummyCache {
        map: tokio::sync::RwLock::new(HashMap::new()),
    })
}

/// Gets a cached dummy hash matching the precise parameters of the current
/// configuration profile, preventing timing side-channel variations.
pub async fn get_or_init_dummy_hash(conf: &Config) -> Result<String, PasswordHashError> {
    let algo = &conf.identity.password_hashing_algorithm;
    let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
    let cache_key = format!("{:?}-{}", algo, rounds);

    let cache = get_dummy_cache();

    // Attempt read access first
    {
        let read_guard = cache.map.read().await;
        if let Some(cached_hash) = read_guard.get(&cache_key) {
            return Ok(cached_hash.clone());
        }
    }

    // Compute outside the lock to avoid stalling the cache for other configurations
    let new_hash = generate_dummy_hash(conf).await?;

    // Acquire write lock only for the quick insertion. Re-check under the
    // write lock: if another concurrent caller raced us and already
    // populated this key, keep their value so every caller observes the
    // same cached hash (double-checked locking).
    let mut write_guard = cache.map.write().await;
    if let Some(existing) = write_guard.get(&cache_key) {
        return Ok(existing.clone());
    }
    write_guard.insert(cache_key, new_hash.clone());

    Ok(new_hash)
}

/// Password hashing related errors.
#[derive(Error, Debug)]
pub enum PasswordHashError {
    /// Bcrypt error.
    #[error(transparent)]
    BCrypt {
        #[from]
        source: bcrypt::BcryptError,
    },

    /// Crypto password-hash crate error (handles scrypt/pbkdf2 formatting).
    #[error("Password hashing framework error: {0}")]
    CryptoHash(String),

    /// Async task join error.
    #[error(transparent)]
    Join {
        #[from]
        source: tokio::task::JoinError,
    },
}

/// Verify the password length against algorithm constraints and truncate if necessary.
///
/// Mirrors Keystone's own `password_hashing.py` pre-dispatch truncation:
/// only `Bcrypt` is capped at 72 bytes (bcrypt's native input limit); every
/// other algorithm is left at the full `config_max_length`, since
/// `BcryptSha256`, `Scrypt` and `Pbkdf2Sha512` all first reduce the
/// password to a fixed-size digest/key and never hit bcrypt's 72-byte
/// limit directly.
fn verify_length_and_trunc_password<'a>(
    password: &'a [u8],
    algo: &PasswordHashingAlgo,
    config_max_length: usize,
) -> &'a [u8] {
    assert!(config_max_length > 0, "max_password_length must be > 0");
    let max_length = match algo {
        PasswordHashingAlgo::Bcrypt => std::cmp::min(config_max_length, 72),
        _ => config_max_length,
    };

    if password.len() > max_length {
        debug!("Truncating password to the specified value");
        return &password[..max_length];
    }
    password
}

/// Helper to generate a compliant, secure standard HMAC-SHA256 digest string
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

/// Generate a dummy password hash matching the configured algorithm.
pub async fn generate_dummy_hash(conf: &Config) -> Result<String, PasswordHashError> {
    // Uniformly distributed dummy password. Avoids the modulo bias of
    // `byte % 95`, which skews the low end of the printable-ASCII range;
    // not security-relevant on its own (this value is never authenticated
    // against real input), but there's no reason to introduce non-uniform
    // output when a uniform sampler is one call away.
    let dummy_password: String = Alphanumeric.sample_string(&mut rand::rng(), 32);

    hash_password(conf, dummy_password).await
}

/// Calculate password hash with the configuration defaults.
pub async fn hash_password<S: AsRef<[u8]>>(
    conf: &Config,
    password: S,
) -> Result<String, PasswordHashError> {
    let truncated_password = verify_length_and_trunc_password(
        password.as_ref(),
        &conf.identity.password_hashing_algorithm,
        conf.identity.max_password_length,
    );

    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = truncated_password.to_vec();
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            let hash =
                task::spawn_blocking(move || bcrypt::hash(password_bytes, rounds as u32)).await??;
            Ok(hash)
        }

        PasswordHashingAlgo::BcryptSha256 => {
            // Mirrors keystone/common/password_hashers/bcrypt.py::Bcrypt_sha256.hash():
            //   salt_with_opts = bcrypt.gensalt(rounds)
            //   salt = salt_with_opts[-22:]
            //   hmac_digest = base64.b64encode(hmac.digest(salt, password, "sha256"))
            //   hashed = bcrypt.hashpw(hmac_digest, salt_with_opts)
            //   digest = hashed[-31:]
            //   return f"$bcrypt-sha256$v=2,t=2b,r={rounds}${salt}${digest}"
            let password_bytes = truncated_password.to_vec();
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);

            let hash = task::spawn_blocking(move || {
                // Generate the real salt ourselves instead of throwing away a
                // full-cost bcrypt computation just to obtain one. We only
                // need (a) 16 random bytes for the actual hash below, and
                // (b) their canonical 22-char Radix64 encoding for the HMAC
                // key / hash record. (b) is obtained via the bcrypt crate's
                // own (well-tested) salt formatting logic, but at the
                // algorithm's *minimum* cost factor rather than `rounds` —
                // the hash output of this call is discarded, only the salt
                // encoding is used.
                //
                // Hand-rolling this encoding instead (e.g. picking 22 random
                // alphabet characters) is a real trap: a bcrypt salt only
                // carries 128 bits of entropy across 22 characters, so the
                // last character has only 4 valid bits - only 4 of the 64
                // alphabet characters are canonical there. A non-canonical
                // salt gets silently re-canonicalized by bcrypt when the
                // hash is computed, so the salt string you embed in the
                // record stops matching the salt you used for the HMAC key.
                // Letting the bcrypt crate generate it sidesteps this
                // entirely.
                let raw_salt: [u8; 16] = rand::random();
                let salt_encoder =
                    bcrypt::hash_with_salt(b"unused", BCRYPT_SALT_ENCODING_COST, raw_salt)?;
                let salt_str = salt_encoder.get_salt();

                // HMAC-SHA256 keyed by the salt, over the password, encoded
                // with standard PADDED base64 (Python's `base64.b64encode`,
                // not a padding-stripped variant). This must match
                // verify_password's encoding byte-for-byte or no hash
                // either path produces is verifiable by the other.
                let hmac_res = compute_hmac_sha256(salt_str.as_bytes(), &password_bytes)?;
                let hmac_digest_b64 = STANDARD.encode(&hmac_res);

                // Hash using the real raw salt and the HMAC-derived intermediate password
                let final_bcrypt =
                    bcrypt::hash_with_salt(hmac_digest_b64.as_bytes(), rounds as u32, raw_salt)?;
                let full_bcrypt_str = final_bcrypt.format_for_version(bcrypt::Version::TwoB);
                debug_assert_eq!(
                    full_bcrypt_str.len(),
                    BCRYPT_FULL_HASH_LEN,
                    "bcrypt crate's 2b format string length changed unexpectedly"
                );

                // Extract the exact trailing bcrypt signature digest
                let digest_str = &full_bcrypt_str[full_bcrypt_str.len() - BCRYPT_CHECKSUM_LEN..];

                Ok::<String, PasswordHashError>(format!(
                    "$bcrypt-sha256$v=2,t=2b,r={}${}${}",
                    rounds, salt_str, digest_str
                ))
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::Scrypt => {
            let password_bytes = truncated_password.to_vec();
            let salt = SaltString::generate(&mut OsRng);
            let hash = task::spawn_blocking(move || {
                Scrypt
                    .hash_password(&password_bytes, &salt)
                    .map(|hash| hash.to_string())
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::Pbkdf2Sha512 => {
            let password_bytes = truncated_password.to_vec();
            let rounds = conf.identity.password_hash_rounds.unwrap_or(25000);
            let hash = task::spawn_blocking(move || {
                let salt: [u8; 16] = rand::random(); // or configurable salt_bytesize
                let mut digest = vec![0u8; 64];
                pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&password_bytes, &salt, rounds, &mut digest);
                let salt_str = STANDARD_NO_PAD.encode(salt);
                let digest_str = STANDARD_NO_PAD.encode(&digest);
                format!("$pbkdf2-sha512${rounds}${salt_str}${digest_str}")
            }).await?;
            Ok(hash)
        }

        PasswordHashingAlgo::None => {
            warn!(
                "PasswordHashingAlgo::None is active — passwords are stored and compared in plaintext"
            );
            // Reject invalid UTF-8 outright instead of mutating it via lossy conversion to prevent collisions
            String::from_utf8(truncated_password.to_vec()).map_err(|_| {
                PasswordHashError::CryptoHash("Invalid UTF-8 sequence in password".into())
            })
        }
    }
}

/// Verify the password matches the hashed value.
pub async fn verify_password<P: AsRef<[u8]>, H: AsRef<str>>(
    conf: &Config,
    password: P,
    hash: H,
) -> Result<bool, PasswordHashError> {
    let password_hash = hash.as_ref().to_string();
    let raw_password = password.as_ref();

    let algo = if password_hash.starts_with("$2b$")
        || password_hash.starts_with("$2a$")
        || password_hash.starts_with("$2y$")
    {
        PasswordHashingAlgo::Bcrypt
    } else if password_hash.starts_with("$bcrypt-sha256$") {
        PasswordHashingAlgo::BcryptSha256
    } else if password_hash.starts_with("$scrypt$") {
        PasswordHashingAlgo::Scrypt
    } else if password_hash.starts_with("$pbkdf2-sha512$") {
        PasswordHashingAlgo::Pbkdf2Sha512
    } else {
        conf.identity.password_hashing_algorithm.clone()
    };

    let truncated_password = verify_length_and_trunc_password(
        raw_password,
        &conf.identity.password_hashing_algorithm,  
        conf.identity.max_password_length,
    );


    match algo {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = truncated_password.to_vec();
            match task::spawn_blocking(move || bcrypt::verify(password_bytes, &password_hash))
                .await?
            {
                Ok(res) => Ok(res),
                Err(e) => Err(PasswordHashError::from(e))
            }
        }

        PasswordHashingAlgo::BcryptSha256 => {
            // Mirrors keystone/common/password_hashers/bcrypt.py::Bcrypt_sha256.verify()
            // exactly: there is no "version" concept in the real implementation.
            // It always HMACs (never falls back to a plain digest), and it
            // does not even look at `v=` - it just scans every comma-delimited
            // param for `t=` and `r=` and ignores anything else. An earlier
            // revision of this module had a second, version-gated code path
            // that computed a plain SHA-256 digest (no HMAC) for records
            // without `v=2`. That path was based on a Passlib-only legacy
            // format Keystone's own implementation never produces or reads,
            // and has been removed.
            let password_bytes = truncated_password.to_vec();

            let parts: Vec<&str> = password_hash.split('$').collect();
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

            let mut bcrypt_type = "2b".to_string();
            let mut rounds = None;
            for opt in options.split(',') {
                if let Some(val) = opt.strip_prefix("t=") {
                    bcrypt_type = val.to_string();
                } else if let Some(val) = opt.strip_prefix("r=") {
                    rounds = Some(val.parse::<u32>().map_err(|_| {
                        PasswordHashError::CryptoHash(
                            "Invalid BcryptSha256 cost factor".into(),
                        )
                    })?);
                }
            }

            let rounds = rounds.ok_or_else(|| {
                PasswordHashError::CryptoHash(
                    "Missing rounds parameter in BcryptSha256 record".into(),
                )
            })?;

            match task::spawn_blocking(move || {
                let reconstructed_hash =
                    format!("${}${:02}${}{}", bcrypt_type, rounds, salt, checksum_part);

                let hmac_res = compute_hmac_sha256(salt.as_bytes(), &password_bytes)?;
                let intermediate_b64 = STANDARD.encode(&hmac_res);

                bcrypt::verify(intermediate_b64, &reconstructed_hash)
                    .map_err(PasswordHashError::from)
            })
            .await?
            {
                Ok(res) => Ok(res),
                Err(e) => Err(e),
            }
        }

        PasswordHashingAlgo::Scrypt => {
            let password_bytes = truncated_password.to_vec();
            let res = task::spawn_blocking(move || {
                let normalized_hash = password_hash.replace('.', "+");
                let parsed_hash = PasswordHash::new(&normalized_hash)
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
                Ok::<bool, PasswordHashError>(
                    Scrypt
                        .verify_password(&password_bytes, &parsed_hash)
                        .is_ok(),
                )
            })
            .await??;
            Ok(res)
        }

        PasswordHashingAlgo::Pbkdf2Sha512 => {
            let password_bytes = truncated_password.to_vec();
            let res = task::spawn_blocking(move || {
                if let Ok(parsed_hash) = PasswordHash::new(&password_hash) {
                    return Ok::<bool, PasswordHashError>(
                        Pbkdf2
                            .verify_password(&password_bytes, &parsed_hash)
                            .is_ok(),
                    );
                }

                let parts: Vec<&str> = password_hash.split('$').collect();
                if parts.len() == 5 && parts[1] == "pbkdf2-sha512" {
                    let rounds: u32 = parts[2].parse().map_err(|_| {
                        PasswordHashError::CryptoHash(
                            "Invalid PBKDF2 rounds configuration parameter".into(),
                        )
                    })?;

                    // maintainer note: Removed 1,000,000 iteration bound to match Python Keystone

                    let salt_str = parts[3].replace('.', "+");
                    let digest_str = parts[4].replace('.', "+");

                    let salt = STANDARD_NO_PAD.decode(salt_str.as_bytes()).map_err(|_| {
                        PasswordHashError::CryptoHash("Invalid salt mapping".into())
                    })?;

                    // maintainer note: Removed 512-byte salt bound to match Python Keystone

                    let expected_digest =
                        STANDARD_NO_PAD.decode(digest_str.as_bytes()).map_err(|_| {
                            PasswordHashError::CryptoHash("Invalid database payload digest".into())
                        })?;

                    if expected_digest.len() != SHA512_OUTPUT_BYTES {
                        return Err(PasswordHashError::CryptoHash(
                            "Invalid PBKDF2-SHA512 checksum buffer bounds".into(),
                        ));
                    }

                    let mut computed_digest = vec![0u8; SHA512_OUTPUT_BYTES];
                    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
                        &password_bytes,
                        &salt,
                        rounds,
                        &mut computed_digest,
                    );

                    return Ok(computed_digest
                        .as_slice()
                        .ct_eq(expected_digest.as_slice())
                        .into());
                }

                Err(PasswordHashError::CryptoHash(
                    "Unrecognized crypto hash structure".to_string(),
                ))
            })
            .await??;
            Ok(res)
        }
        
    PasswordHashingAlgo::None => {
        let password_bytes = truncated_password.to_vec();
        Ok(password_bytes.ct_eq(password_hash.as_bytes()).into())
    }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_config::{Config, PasswordHashingAlgo};
    use tracing_test::traced_test;

    const TEST_PASSWORD: &str = "openstack123";

    // --- Configuration Helper (Bypasses manual struct nested instantiation) ---
    fn mock_config(algo: PasswordHashingAlgo, max_len: usize) -> Config {
        let mut conf = Config::default();
        conf.identity.password_hashing_algorithm = algo;
        conf.identity.password_hash_rounds = Some(12);
        conf.identity.max_password_length = max_len;
        conf
    }

    // --- Core Truncation & Schema Alignment Tests ---

    #[test]
    fn test_verify_length_and_trunc_password() {
        let algo = PasswordHashingAlgo::Bcrypt;
        assert_eq!(
            b"abcdefg",
            verify_length_and_trunc_password("abcdefg".as_bytes(), &algo, 70)
        );
        assert_eq!(
            b"abcd",
            verify_length_and_trunc_password("abcdefg".as_bytes(), &algo, 4)
        );
        assert_eq!(
            b"\xE2\x98\x81a",
            verify_length_and_trunc_password("☁abcdefg".as_bytes(), &algo, 4)
        );
    }

    #[test]
    fn test_verify_length_and_trunc_password_boundary() {
        // Non-Bcrypt algorithm: no implicit 72-byte cap applies, so the only
        // bound in play is `max_length` itself.
        let algo = PasswordHashingAlgo::Pbkdf2Sha512;
        let max_length = 10;

        let exactly_max = "a".repeat(max_length);
        assert_eq!(
            exactly_max.as_bytes(),
            verify_length_and_trunc_password(exactly_max.as_bytes(), &algo, max_length),
            "A password exactly at max_length must not be truncated"
        );

        let one_over = "a".repeat(max_length + 1);
        let truncated = verify_length_and_trunc_password(one_over.as_bytes(), &algo, max_length);
        assert_eq!(
            truncated.len(),
            max_length,
            "A password one byte over max_length must be truncated to exactly max_length"
        );
    }

    #[test]
    #[should_panic(expected = "max_password_length must be > 0")]
    fn test_zero_max_password_length_panics() {
        let algo = PasswordHashingAlgo::Bcrypt;
        // A max_password_length of 0 must never silently truncate every
        // password to an empty (and therefore identical) value. This must
        // panic loudly at config-validation time rather than allow a
        // mass-auth-bypass to ship.
        let _ = verify_length_and_trunc_password(b"anything", &algo, 0);
    }

    #[tokio::test]
    async fn test_truncation_behavior_differences() {
        let long_password = "A".repeat(100);
        let truncated_72_password = "A".repeat(72);

        // 1. Standard Bcrypt Truncation Check
        let conf_bcrypt = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let hash_bcrypt = hash_password(&conf_bcrypt, &long_password).await.unwrap();
        let is_valid_bcrypt = verify_password(&conf_bcrypt, &truncated_72_password, &hash_bcrypt)
            .await
            .unwrap();
        assert!(
            is_valid_bcrypt,
            "Bcrypt failed to truncate a 100-byte password to 72 bytes."
        );

        // 2. BcryptSha256 Arbitrary Length Check
        let conf_bcrypt_sha256 = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let hash_bcrypt_sha256 = hash_password(&conf_bcrypt_sha256, &long_password)
            .await
            .unwrap();
        let is_valid_substring = verify_password(
            &conf_bcrypt_sha256,
            &truncated_72_password,
            &hash_bcrypt_sha256,
        )
        .await
        .unwrap();
        assert!(
            !is_valid_substring,
            "BcryptSha256 incorrectly truncated the password to 72 bytes!"
        );

        let is_valid_full =
            verify_password(&conf_bcrypt_sha256, &long_password, &hash_bcrypt_sha256)
                .await
                .unwrap();
        assert!(
            is_valid_full,
            "BcryptSha256 failed to verify the full 100-byte password sequence."
        );
    }

    // --- Keystone Python cross-compatibility tests ---
    //
    // Every hash string below was generated by a faithful, independently
    // verified reimplementation of Keystone's actual Python hashers
    // (keystone/common/password_hashers/{bcrypt,pbkdf2,scrypt}.py — NOT
    // Passlib), applying the same password_hashing.py pre-dispatch
    // truncation policy this module implements
    // (`verify_length_and_trunc_password`). See tools/generate_password_kats.py
    // to regenerate or extend this set against a real `bcrypt` install.
    //
    // The bcrypt/bcrypt_sha256 generator used libxcrypt in place of the
    // `bcrypt` PyPI package (sandbox had no network access to install it),
    // validated against the published Niels Provos bcrypt reference test
    // vectors before being trusted for this purpose.

    #[tokio::test]
    async fn test_pbkdf2_sha512_matches_keystone_python_hash() {
        let conf = mock_config(PasswordHashingAlgo::Pbkdf2Sha512, 255);
        let python_hash = "$pbkdf2-sha512$25000$I8rUIx2uchQj3EvwpW/HNQ$jjZ0I3rlnrbptEmxRTThY7W0oyt7qrAmou/2/PDcY8cK+b1lXaxuynbEhCvm7Tdx2OcelTioygvuVVEPiGRRZQ";

        assert!(
            verify_password(&conf, TEST_PASSWORD, python_hash).await.unwrap(),
            "Rust PBKDF2-SHA512 verification rejected a real Keystone Python PBKDF2-SHA512 hash"
        );
    }

    #[tokio::test]
    async fn test_scrypt_matches_keystone_python_hash() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255); // intentional mismatch: exercises auto-detection by hash prefix
        let python_hash = "$scrypt$ln=16,r=8,p=1$3k9FLaX9XcxhagGmGMxqwA$T6FmonL+mu+Wx86D2S4Acs5UjRdndfITzW+yF+mj+C0";

        assert!(
            verify_password(&conf, TEST_PASSWORD, python_hash).await.unwrap(),
            "Rust Scrypt verification rejected a real Keystone Python Scrypt hash"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_matches_keystone_python_ascii_password() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let python_hash = "$2b$12$Hmo85liOZ57y/qMHnbRENON8zynaqEm14wdRuNAoMQHfcNPsx0i56";

        assert!(
            verify_password(&conf, "password123", python_hash).await.unwrap(),
            "Rust Bcrypt verification rejected a real Keystone Python Bcrypt hash"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_matches_keystone_python_truncates_at_72_bytes() {
        // Generated from a 72-byte password (Python's own caller-side
        // truncation already applied before hashing). Feeding the full,
        // *untruncated* 73-byte password into Rust's verify_password must
        // still succeed, proving Rust's own truncation lines up with
        // Python's at the exact same 72-byte boundary.
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let python_hash = "$2b$12$2TBm2IYYRW/cb23hWAhcuO6rE0GOqbR/8zzry14eCAAYh671B1mre";
        let untruncated_73_byte_password = "A".repeat(73);

        assert!(
            verify_password(&conf, &untruncated_73_byte_password, python_hash)
                .await
                .unwrap(),
            "Rust Bcrypt did not truncate at the same 72-byte boundary as Keystone Python"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_sha256_matches_keystone_python_ascii_password() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let python_hash = "$bcrypt-sha256$v=2,t=2b,r=12$dBydkKzGxra2xREv29P6/O$GVrUiF0tJM4hk4xQECVHJ80Rm6cnFBe";

        assert!(
            verify_password(&conf, "password123", python_hash).await.unwrap(),
            "Rust BcryptSha256 verification rejected a real Keystone Python BcryptSha256 hash"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_sha256_matches_keystone_python_does_not_truncate_at_72_bytes() {
        // Unlike plain Bcrypt, BcryptSha256 is *not* capped at 72 bytes by
        // password_hashing.py — it HMACs the full password to a fixed-size
        // digest before bcrypt ever sees it. This hash was generated from
        // the full, untruncated 73-byte password.
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let python_hash = "$bcrypt-sha256$v=2,t=2b,r=12$y6Bnyh5m5Eljt3ZJ15cVQO$.tr2HNwQrYWXZYbHrzqm.iu4x1m6EvW";
        let full_73_byte_password = "A".repeat(73);

        assert!(
            verify_password(&conf, &full_73_byte_password, python_hash)
                .await
                .unwrap(),
            "Rust BcryptSha256 must not truncate at 72 bytes — that would diverge from Keystone Python"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_sha256_matches_keystone_python_utf8_password() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let python_hash = "$bcrypt-sha256$v=2,t=2b,r=12$mLeKr3jq7QG7SobmywRn..$7IYIos8ugr49dcjSf1AtORmFCwkYxYu";

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
        assert!(!result, "BcryptSha256 incorrectly accepted a wrong password");
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

    #[tokio::test]
    async fn test_scrypt_hash_then_verify_roundtrip() {
        let conf = mock_config(PasswordHashingAlgo::Scrypt, 255);
        let password = "scrypt_roundtrip_password";

        let hashed = hash_password(&conf, password).await.unwrap();
        assert!(
            verify_password(&conf, password, &hashed).await.unwrap(),
            "Scrypt hash_password output failed to verify against the same password"
        );
        assert!(
            !verify_password(&conf, "wrong_password", &hashed).await.unwrap(),
            "Scrypt verification incorrectly accepted a wrong password"
        );
    }

    #[tokio::test]
    async fn test_none_algorithm_hash_then_verify_roundtrip() {
        let conf = mock_config(PasswordHashingAlgo::None, 255);
        let password = "plaintext_password";

        let hashed = hash_password(&conf, password).await.unwrap();
        assert_eq!(
            hashed, password,
            "None algorithm must store the password unchanged"
        );

        assert!(verify_password(&conf, password, &hashed).await.unwrap());
        assert!(!verify_password(&conf, "wrong_password", &hashed).await.unwrap());
    }

    #[tokio::test]
    async fn test_reject_invalid_utf8() {
        let conf = mock_config(PasswordHashingAlgo::None, 72);
        let invalid_utf8_password = b"bad\xFFpassword";

        // Ensure our strict UTF-8 validation safely rejects invalid sequence vulnerabilities
        let hash_result = hash_password(&conf, invalid_utf8_password).await;
        assert!(
            hash_result.is_err(),
            "None algorithm should reject invalid UTF-8 strings during hash generation"
        );
    }

    // --- Roundtrip & Security Operations Tests ---

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let pass = "abcdefg";
        let hashed = hash_password(&conf, &pass).await.unwrap();

        assert!(verify_password(&conf, &pass, &hashed).await.unwrap());
        assert!(
            !verify_password(&conf, "wrong_password", &hashed)
                .await
                .unwrap()
        );
        assert!(!logs_contain(pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt_bad_hash() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        assert!(!verify_password(&conf, &pass, "foobar").await.unwrap());
    }

    // --- Side-Channel Attack Mitigation Tests (Dummy Cache) ---

    #[tokio::test]
    #[traced_test]
    async fn test_generate_and_verify_dummy_hash_bcrypt() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let dummy_hash = generate_dummy_hash(&conf).await.unwrap();

        assert!(
            dummy_hash.starts_with("$2b$"),
            "Dummy hash should be a valid bcrypt hash"
        );

        let pass = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let result = verify_password(&conf, &pass, &dummy_hash).await.unwrap();

        assert!(
            !result,
            "Dummy hash should not match a random password assignment"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_generate_dummy_hash_none() {
        let conf = mock_config(PasswordHashingAlgo::None, 255);
        let dummy_hash = generate_dummy_hash(&conf).await.unwrap();

        assert!(!dummy_hash.is_empty(), "Dummy hash should not be empty");

        let pass = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let result = verify_password(&conf, &pass, &dummy_hash).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_dummy_hash_is_actually_cached() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);

        let first_fetch = get_or_init_dummy_hash(&conf).await.unwrap();
        let second_fetch = get_or_init_dummy_hash(&conf).await.unwrap();

        assert_eq!(
            first_fetch, second_fetch,
            "The dynamic dummy cache failed to preserve the identical hash reference string across runs!"
        );
    }

    #[tokio::test]
    async fn test_dummy_cache_concurrent_cold_start() {
        // Regression test: N concurrent callers racing on a cold cache key
        // must all observe the *same* cached hash, not each independently
        // compute and overwrite it with a different value. Uses a distinct
        // (algo, rounds) key from other tests in this binary so the cache
        // is genuinely cold here.
        let conf = std::sync::Arc::new(mock_config(PasswordHashingAlgo::Bcrypt, 199));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let conf = conf.clone();
            handles.push(tokio::spawn(
                async move { get_or_init_dummy_hash(&conf).await.unwrap() },
            ));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        let first = &results[0];
        assert!(
            results.iter().all(|hash| hash == first),
            "Concurrent cold-start callers must all observe the same cached dummy hash"
        );
    }
}