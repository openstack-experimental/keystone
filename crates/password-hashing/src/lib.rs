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

//! Password hashing with cross-compatibility to Python Keystone.
//!
//! Split out of `openstack-keystone-core` so that the crypto dependencies the
//! hashers pull in (`bcrypt`, `scrypt`, ...) are compiled only by the crates
//! that actually hash passwords, not by every crate that depends on core.
//!
//! Each algorithm lives in its own submodule mirroring the class layout in
//! `keystone/common/password_hashers/`, so the implementation and its unit
//! tests stay small and focused:
//!
//! - [`bcrypt`] - `bcrypt.py::Bcrypt`
//! - [`bcrypt_sha256`] - `bcrypt.py::Bcrypt_sha256`
//! - [`scrypt`] - `scrypt.py::Scrypt`
//! - [`pbkdf2`] - `pbkdf2.py::Sha512`
//! - [`plaintext`] - Rust-only extension, no Python counterpart
//!
//! This module holds the shared infrastructure: the [`PasswordHasher`] trait
//! every hasher implements, the dispatch in [`hash_password`] /
//! [`verify_password`], the dummy-hash cache, and the salt generator.

use std::collections::HashMap;
use std::sync::OnceLock;
use thiserror::Error;
use tracing::debug;

use rand::distr::{Alphanumeric, SampleString};
use secrecy::{ExposeSecret, SecretString};

use openstack_keystone_config::{Config, PasswordHashingAlgo};

mod bcrypt;
mod bcrypt_sha256;
mod pbkdf2;
mod plaintext;
mod scrypt;

use bcrypt::BcryptHasher;
use bcrypt_sha256::BcryptSha256Hasher;
use pbkdf2::Pbkdf2Sha512Hasher;
use plaintext::PlaintextHasher;
use scrypt::ScryptHasher;

/// Number of random bytes used for a password salt.
///
/// Keystone hardcodes a 16-byte salt for scrypt/pbkdf2 and bcrypt's salt is
/// likewise 16 bytes, so a single constant covers every hasher here.
const SALT_BYTES: usize = 16;

/// Generate cryptographically random salt bytes.
///
/// Centralized so the random source is a single-point change: some
/// deployments require a specific CSPRNG, and keeping salt generation in one
/// place means that requirement can be satisfied without touching every
/// individual hasher.
fn generate_salt() -> [u8; SALT_BYTES] {
    rand::random()
}

/// Password hashing related errors.
#[derive(Error, Debug)]
pub enum PasswordHashError {
    /// Bcrypt error.
    #[error(transparent)]
    BCrypt {
        // Absolute path: `bcrypt` alone would resolve to the sibling
        // submodule of the same name, not the extern crate.
        #[from]
        source: ::bcrypt::BcryptError,
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

// ---------------------------------------------------------------------------
// PasswordHasher trait - mirrors the hash()/verify() static-method pair
// every Python hasher class in keystone.common.password_hashers implements.
// Dispatch is always static (no dyn), so async fn in traits is safe here.
// ---------------------------------------------------------------------------

trait PasswordHasher {
    async fn hash(&self, conf: &Config, password: &[u8]) -> Result<String, PasswordHashError>;
    async fn verify(
        &self,
        conf: &Config,
        password: &[u8],
        hash: &str,
    ) -> Result<bool, PasswordHashError>;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Verify the password length against algorithm constraints and truncate if
/// necessary.
///
/// Mirrors Keystone's own
/// `password_hashing.py::verify_length_and_trunc_password`: only `Bcrypt` is
/// capped at 72 bytes (bcrypt's native input limit); every other algorithm is
/// left at the full `config_max_length`, since `BcryptSha256`, `Scrypt` and
/// `Pbkdf2Sha512` all first reduce the password to a fixed-size digest/key and
/// never hit bcrypt's 72-byte limit directly.
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

/// Determine which algorithm produced `hash` by inspecting its prefix.
///
/// Falls back to `configured` for unrecognized prefixes (e.g. plaintext
/// stored by `PlaintextHasher`, or truly unknown formats).
fn detect_algo(hash: &str, configured: &PasswordHashingAlgo) -> PasswordHashingAlgo {
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        PasswordHashingAlgo::Bcrypt
    } else if hash.starts_with("$bcrypt-sha256$") {
        PasswordHashingAlgo::BcryptSha256
    } else if hash.starts_with("$scrypt$") {
        PasswordHashingAlgo::Scrypt
    } else if hash.starts_with("$pbkdf2-sha512$") {
        PasswordHashingAlgo::Pbkdf2Sha512
    } else {
        configured.clone()
    }
}

// ---------------------------------------------------------------------------
// Dummy-hash cache
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Public API - signatures unchanged; callers outside this module are
// unaffected.
// ---------------------------------------------------------------------------

/// Gets a cached dummy hash matching the precise parameters of the current
/// configuration profile, preventing timing side-channel variations.
pub async fn get_or_init_dummy_hash(conf: &Config) -> Result<String, PasswordHashError> {
    let algo = &conf.identity.password_hashing_algorithm;
    let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
    let cache_key = format!("{:?}-{}", algo, rounds);

    let cache = get_dummy_cache();

    // Fast path: read lock only.
    {
        let read_guard = cache.map.read().await;
        if let Some(cached_hash) = read_guard.get(&cache_key) {
            return Ok(cached_hash.clone());
        }
    }

    // Compute outside the lock to avoid stalling other callers.
    let new_hash = generate_dummy_hash(conf).await?;

    // Double-checked locking: re-check under write lock. If another concurrent
    // caller already populated this key, keep their value.
    let mut write_guard = cache.map.write().await;
    if let Some(existing) = write_guard.get(&cache_key) {
        return Ok(existing.clone());
    }
    write_guard.insert(cache_key, new_hash.clone());

    Ok(new_hash)
}

/// Clear all cached dummy hashes.
///
/// Call this whenever the Keystone configuration reloads (e.g. via
/// `ConfigManager::notify_tx`) so that stale `(algorithm, rounds)` entries
/// are not served after a config change. See
/// `crates/keystone/src/bin/keystone.rs` for the wiring.
pub async fn reset_dummy_hash_cache() {
    get_dummy_cache().map.write().await.clear();
}

/// Generate a dummy password hash matching the configured algorithm.
pub async fn generate_dummy_hash(conf: &Config) -> Result<String, PasswordHashError> {
    // Uniformly distributed dummy password. Avoids the modulo bias of
    // `byte % 95`, which skews the low end of the printable-ASCII range;
    // not security-relevant on its own (this value is never authenticated
    // against real input), but there's no reason to introduce non-uniform
    // output when a uniform sampler is one call away.
    let dummy_password: String = Alphanumeric.sample_string(&mut rand::rng(), 32);

    hash_password(conf, &SecretString::from(dummy_password)).await
}

/// Calculate password hash with the configuration defaults.
pub async fn hash_password(
    conf: &Config,
    password: &SecretString,
) -> Result<String, PasswordHashError> {
    // Truncation uses the *configured* algorithm, not any algorithm detected
    // from an existing hash string. This is the correct behaviour during
    // algorithm migrations: a user whose hash is in the old format and whose
    // password is longer than the new algorithm's limit must be truncated
    // consistently with what Python Keystone would do.
    let exposed = password.expose_secret();
    let truncated = verify_length_and_trunc_password(
        exposed.as_bytes(),
        &conf.identity.password_hashing_algorithm,
        conf.identity.max_password_length,
    );

    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => BcryptHasher.hash(conf, truncated).await,
        PasswordHashingAlgo::BcryptSha256 => BcryptSha256Hasher.hash(conf, truncated).await,
        PasswordHashingAlgo::Pbkdf2Sha512 => Pbkdf2Sha512Hasher.hash(conf, truncated).await,
        PasswordHashingAlgo::Scrypt => ScryptHasher.hash(conf, truncated).await,
        PasswordHashingAlgo::None => PlaintextHasher.hash(conf, truncated).await,
    }
}

/// Verify the password matches the hashed value.
pub async fn verify_password<H: AsRef<str>>(
    conf: &Config,
    password: &SecretString,
    hash: H,
) -> Result<bool, PasswordHashError> {
    let hash_str = hash.as_ref();

    // Detect algorithm from the hash prefix for dispatch, but truncate using
    // the *configured* algorithm. These two may differ during an algorithm
    // migration (e.g. config changed to bcrypt_sha256, but user has an old
    // bcrypt hash). Truncating by detected algo instead of configured algo
    // would produce wrong results: a user with a >72-byte password whose
    // old bcrypt hash was computed from the first 72 bytes would fail
    // verification once the config switches to a non-truncating algorithm.
    let detected = detect_algo(hash_str, &conf.identity.password_hashing_algorithm);

    let exposed = password.expose_secret();
    let truncated = verify_length_and_trunc_password(
        exposed.as_bytes(),
        &conf.identity.password_hashing_algorithm,
        conf.identity.max_password_length,
    );

    match detected {
        PasswordHashingAlgo::Bcrypt => BcryptHasher.verify(conf, truncated, hash_str).await,
        PasswordHashingAlgo::BcryptSha256 => {
            BcryptSha256Hasher.verify(conf, truncated, hash_str).await
        }
        PasswordHashingAlgo::Pbkdf2Sha512 => {
            Pbkdf2Sha512Hasher.verify(conf, truncated, hash_str).await
        }
        PasswordHashingAlgo::Scrypt => ScryptHasher.verify(conf, truncated, hash_str).await,
        PasswordHashingAlgo::None => PlaintextHasher.verify(conf, truncated, hash_str).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_config::PasswordHashingAlgo;
    use rand::distr::{Alphanumeric, SampleString};
    use tracing_test::traced_test;

    pub(super) const TEST_PASSWORD: &str = "openstack123";

    pub(super) fn mock_config(
        algo: openstack_keystone_config::PasswordHashingAlgo,
        max_len: usize,
    ) -> Config {
        let mut conf = Config::default();
        conf.identity.password_hashing_algorithm = algo;
        conf.identity.password_hash_rounds = Some(12);
        conf.identity.max_password_length = max_len;
        conf
    }

    // --- Core truncation & schema alignment tests ---

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
        let long_secret = SecretString::from(long_password);
        let truncated_secret = SecretString::from(truncated_72_password);

        // 1. Standard Bcrypt Truncation Check
        let conf_bcrypt = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let hash_bcrypt = hash_password(&conf_bcrypt, &long_secret).await.unwrap();
        let is_valid_bcrypt = verify_password(&conf_bcrypt, &truncated_secret, &hash_bcrypt)
            .await
            .unwrap();
        assert!(
            is_valid_bcrypt,
            "Bcrypt failed to truncate a 100-byte password to 72 bytes."
        );

        // 2. BcryptSha256 Arbitrary Length Check
        let conf_bcrypt_sha256 = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let hash_bcrypt_sha256 = hash_password(&conf_bcrypt_sha256, &long_secret)
            .await
            .unwrap();
        let is_valid_substring =
            verify_password(&conf_bcrypt_sha256, &truncated_secret, &hash_bcrypt_sha256)
                .await
                .unwrap();
        assert!(
            !is_valid_substring,
            "BcryptSha256 incorrectly truncated the password to 72 bytes!"
        );

        let is_valid_full = verify_password(&conf_bcrypt_sha256, &long_secret, &hash_bcrypt_sha256)
            .await
            .unwrap();
        assert!(
            is_valid_full,
            "BcryptSha256 failed to verify the full 100-byte password sequence."
        );
    }

    // --- Side-channel attack mitigation tests (dummy cache) ---

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
        let result = verify_password(&conf, &SecretString::from(pass), &dummy_hash)
            .await
            .unwrap();

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
        let result = verify_password(&conf, &SecretString::from(pass), &dummy_hash)
            .await
            .unwrap();
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
        // compute and overwrite it with a different value.
        //
        // Uses password_hash_rounds=4 (bcrypt minimum) to build a cache key
        // ("Bcrypt-4") that no other test in this module uses, ensuring the
        // cache is genuinely cold regardless of test execution order.
        let mut conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        conf.identity.password_hash_rounds = Some(4); // unique key: "Bcrypt-4"
        let conf = std::sync::Arc::new(conf);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let conf = conf.clone();
            handles.push(tokio::spawn(async move {
                get_or_init_dummy_hash(&conf).await.unwrap()
            }));
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

    #[tokio::test]
    async fn test_reset_dummy_hash_cache() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);

        // Populate the cache first.
        let before = get_or_init_dummy_hash(&conf).await.unwrap();

        // Reset should clear the cache so the next call recomputes.
        reset_dummy_hash_cache().await;

        // After reset, cache is cold; the new hash may differ (bcrypt is randomized).
        // We just need to confirm the call succeeds and the cache is re-populated.
        let after = get_or_init_dummy_hash(&conf).await.unwrap();
        assert!(
            after.starts_with("$2b$"),
            "After cache reset, dummy hash should still be a valid bcrypt hash"
        );
        // The two hashes are likely different (random salt), but we can't assert
        // inequality deterministically. Just verify both are structurally valid.
        let _ = before;
    }

    // --- Bidirectional cross-verification against the real Python hashers ---
    //
    // These tests close the loop the per-algorithm KAT vectors only check one
    // way: the KATs prove Rust can *verify* a Python-produced hash; the tests
    // below prove Python can *verify* a Rust-produced hash. They shell out to
    // tools/cross_verify.py and require `pip install keystone`. They skip
    // silently when `import keystone` is unavailable (the common case in local
    // dev without a Python install). To run locally:
    //
    //   pip install keystone
    //   cargo test -p openstack-keystone-core -- cross_verify

    /// Run a Rust-produced hash through tools/cross_verify.py against the
    /// Python hashers. Returns the script's exit code (0 = verified, 1 =
    /// rejected, 2 = error). Returns `None` when the `keystone` Python
    /// package is not installed, so the caller can skip.
    async fn python_cross_verify(algo_name: &str, password: &str, hash: &str) -> Option<i32> {
        // Skip if `import keystone` fails — no Python Keystone installed.
        let importable = tokio::process::Command::new("python")
            .args(["-c", "import keystone"])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if !importable {
            return None;
        }

        // cross_verify.py lives in <repo>/tools; this crate is
        // <repo>/crates/password-hashing.
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/cross_verify.py");

        let status = tokio::process::Command::new("python")
            .arg(script)
            .arg(algo_name)
            .arg(password)
            .arg(hash)
            .status()
            .await
            .expect("failed to spawn python cross_verify.py");

        Some(status.code().unwrap_or(2))
    }

    #[tokio::test]
    async fn test_cross_verify_bcrypt() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let password = "openstack123";
        let hash = hash_password(&conf, &SecretString::from(password))
            .await
            .unwrap();

        match python_cross_verify("bcrypt", password, &hash).await {
            None => return, // no Python checkout configured - skip
            Some(0) => {}
            Some(code) => panic!("Python rejected Rust bcrypt hash (exit {code}): {hash}"),
        }
    }

    #[tokio::test]
    async fn test_cross_verify_bcrypt_sha256() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let password = "openstack123";
        let hash = hash_password(&conf, &SecretString::from(password))
            .await
            .unwrap();

        match python_cross_verify("bcrypt_sha256", password, &hash).await {
            None => return,
            Some(0) => {}
            Some(code) => panic!("Python rejected Rust bcrypt_sha256 hash (exit {code}): {hash}"),
        }
    }

    #[tokio::test]
    async fn test_cross_verify_scrypt() {
        let conf = mock_config(PasswordHashingAlgo::Scrypt, 255);
        let password = "openstack123";
        let hash = hash_password(&conf, &SecretString::from(password))
            .await
            .unwrap();

        match python_cross_verify("scrypt", password, &hash).await {
            None => return,
            Some(0) => {}
            Some(code) => panic!("Python rejected Rust scrypt hash (exit {code}): {hash}"),
        }
    }

    #[tokio::test]
    async fn test_cross_verify_pbkdf2_sha512() {
        let conf = mock_config(PasswordHashingAlgo::Pbkdf2Sha512, 255);
        let password = "openstack123";
        let hash = hash_password(&conf, &SecretString::from(password))
            .await
            .unwrap();

        match python_cross_verify("pbkdf2_sha512", password, &hash).await {
            None => return,
            Some(0) => {}
            Some(code) => panic!("Python rejected Rust pbkdf2_sha512 hash (exit {code}): {hash}"),
        }
    }
}
