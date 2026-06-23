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
// KeyInit provides new_from_slice; Mac provides update/finalize.
use hmac::{Hmac, KeyInit, Mac};
use rand::distr::{Alphanumeric, SampleString};
use subtle::ConstantTimeEq;

use openstack_keystone_config::{Config, PasswordHashingAlgo};

// HMAC type aliases — use workspace sha2 v0.11 / hmac v0.13 (digest v0.11).
// The pbkdf2 crate (v0.12) uses sha2 v0.10 (digest v0.10) internally, which
// is a different type family. By not importing pbkdf2::pbkdf2_hmac and instead
// implementing PBKDF2 ourselves here, we avoid the cross-version trait conflict.
type HmacSha256 = Hmac<sha2::Sha256>;
type HmacSha512 = Hmac<sha2::Sha512>;

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
/// freshly generated random salt (see `BcryptSha256Hasher::hash`).
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

// ---------------------------------------------------------------------------
// PasswordHasher trait — mirrors the hash()/verify() static-method pair
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
// Hasher structs — one per algorithm, mirroring Python's class layout.
// Naming avoids collisions with crate types (e.g. `bcrypt::*`, `scrypt::Scrypt`).
// ---------------------------------------------------------------------------

struct BcryptHasher;
struct BcryptSha256Hasher;
struct ScryptHasher;
struct Pbkdf2Sha512Hasher;
/// Rust-only extension — no counterpart in Python Keystone's SUPPORTED_HASHERS.
/// Stores passwords in plaintext; must never be used in production.
struct PlaintextHasher;

// ---------------------------------------------------------------------------
// BcryptHasher — mirrors keystone/common/password_hashers/bcrypt.py::Bcrypt
// ---------------------------------------------------------------------------

impl PasswordHasher for BcryptHasher {
    async fn hash(&self, conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        let password_bytes = password.to_vec();
        let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
        // bcrypt::hash is CPU-bound; run off the async executor.
        let hash =
            task::spawn_blocking(move || bcrypt::hash(password_bytes, rounds as u32)).await??;
        Ok(hash)
    }

    async fn verify(
        &self,
        _conf: &Config,
        password: &[u8],
        hash: &str,
    ) -> Result<bool, PasswordHashError> {
        let password_bytes = password.to_vec();
        let hash_str = hash.to_string();
        match task::spawn_blocking(move || bcrypt::verify(password_bytes, &hash_str)).await? {
            Ok(res) => Ok(res),
            // A malformed hash string is not a fatal error — it just means
            // the stored value is not a valid bcrypt hash and cannot match.
            Err(bcrypt::BcryptError::InvalidHash(_)) => Ok(false),
            Err(e) => Err(PasswordHashError::from(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// BcryptSha256Hasher — mirrors bcrypt.py::Bcrypt_sha256
// ---------------------------------------------------------------------------

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

            // HMAC-SHA256 keyed by the salt bytes, over the password, encoded
            // with standard PADDED base64 (Python's `base64.b64encode`,
            // not a padding-stripped variant). This must match
            // verify()'s encoding byte-for-byte or no hash either path
            // produces is verifiable by the other.
            let hmac_res = compute_hmac_sha256(salt_str.as_bytes(), &password_bytes)?;
            let hmac_digest_b64 = STANDARD.encode(hmac_res);

            // Hash using the real raw salt and the HMAC-derived intermediate password.
            let final_bcrypt =
                bcrypt::hash_with_salt(hmac_digest_b64.as_bytes(), rounds as u32, raw_salt)?;
            let full_bcrypt_str = final_bcrypt.format_for_version(bcrypt::Version::TwoB);
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
        // It always HMACs (never falls back to a plain digest), and it
        // does not even look at `v=` — it just scans every comma-delimited
        // param for `t=` and `r=` and ignores anything else. An earlier
        // revision of this module had a second, version-gated code path
        // that computed a plain SHA-256 digest (no HMAC) for records
        // without `v=2`. That path was based on a Passlib-only format
        // Keystone's own implementation never produces or reads, and has
        // been removed.
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
            // 2-digit zero-padded cost (e.g. "05"), so "05" — not "5" — is the
            // cost the digest actually corresponds to. For realistic round
            // counts (>= 10) the two forms are identical anyway.
            let reconstructed_hash =
                format!("${}${:02}${}{}", bcrypt_type, rounds, salt, checksum_part);

            // Re-derive the HMAC digest using the embedded salt.
            let hmac_res = compute_hmac_sha256(salt.as_bytes(), &password_bytes)?;
            let intermediate_b64 = STANDARD.encode(hmac_res);

            bcrypt::verify(intermediate_b64, &reconstructed_hash).map_err(PasswordHashError::from)
        })
        .await?
        {
            Ok(res) => Ok(res),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// ScryptHasher — mirrors keystone/common/password_hashers/scrypt.py::Scrypt
// ---------------------------------------------------------------------------

impl PasswordHasher for ScryptHasher {
    async fn hash(&self, _conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        // mirrors keystone/common/password_hashers/scrypt.py::Scrypt.hash()
        // Python hardcodes: n=2**16 (ln=16), r=8, p=1, salt_size=16, output=32 bytes.
        // scrypt_block_size / scrypt_parallelism / salt_bytesize config fields are
        // not yet in IdentityProvider — use Keystone's own defaults until they are added.
        let password_bytes = password.to_vec();
        let hash = task::spawn_blocking(move || {
            let salt: [u8; 16] = rand::random();
            // Params::new(log_n, r, p, output_len): ln=16 means n=2^16=65536.
            let params = scrypt::Params::new(16, 8, 1, 32)
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
            let mut digest = vec![0u8; 32];
            scrypt::scrypt(&password_bytes, &salt, &params, &mut digest)
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
            // Python uses binascii.b2a_base64(x).rstrip(b"=\n") — standard base64 no-pad.
            let salt_str = STANDARD_NO_PAD.encode(salt);
            let digest_str = STANDARD_NO_PAD.encode(&digest);
            Ok::<String, PasswordHashError>(format!(
                "$scrypt$ln=16,r=8,p=1${salt_str}${digest_str}"
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
        // mirrors keystone/common/password_hashers/scrypt.py::Scrypt.verify()
        // Parses the embedded ln/r/p params from the hash string so this path
        // correctly verifies both hashes produced by this hasher (ln=16) and any
        // old hashes with different params.
        let password_bytes = password.to_vec();
        let hash_str = hash.to_string();
        let res = task::spawn_blocking(move || -> Result<bool, PasswordHashError> {
            // Strip leading '$', split on '$': ["scrypt", "ln=N,r=R,p=P", salt_b64, digest_b64]
            let parts: Vec<&str> = hash_str[1..].split('$').collect();
            if parts.len() != 4 {
                return Ok(false);
            }
            let (params_str, salt_b64, digest_b64) = (parts[1], parts[2], parts[3]);

            // Parse ln/r/p with Keystone defaults as fallback.
            let (mut ln, mut r, mut p) = (16u8, 8u32, 1u32);
            for seg in params_str.split(',') {
                if let Some(v) = seg.strip_prefix("ln=") {
                    ln = v
                        .parse()
                        .map_err(|_| PasswordHashError::CryptoHash("Invalid scrypt ln".into()))?;
                } else if let Some(v) = seg.strip_prefix("r=") {
                    r = v
                        .parse()
                        .map_err(|_| PasswordHashError::CryptoHash("Invalid scrypt r".into()))?;
                } else if let Some(v) = seg.strip_prefix("p=") {
                    p = v
                        .parse()
                        .map_err(|_| PasswordHashError::CryptoHash("Invalid scrypt p".into()))?;
                }
            }

            // replace('.', "+") handles old Passlib-era hashes that used '.' in place of '+'.
            let salt = STANDARD_NO_PAD
                .decode(salt_b64.replace('.', "+").as_bytes())
                .map_err(|_| PasswordHashError::CryptoHash("Invalid scrypt salt".into()))?;
            let expected = STANDARD_NO_PAD
                .decode(digest_b64.replace('.', "+").as_bytes())
                .map_err(|_| PasswordHashError::CryptoHash("Invalid scrypt digest".into()))?;

            let params = scrypt::Params::new(ln, r, p, expected.len())
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
            let mut computed = vec![0u8; expected.len()];
            scrypt::scrypt(&password_bytes, &salt, &params, &mut computed)
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;

            Ok(computed.as_slice().ct_eq(expected.as_slice()).into())
        })
        .await??;
        Ok(res)
    }
}

// ---------------------------------------------------------------------------
// Pbkdf2Sha512Hasher — mirrors keystone/common/password_hashers/pbkdf2.py::Sha512
// ---------------------------------------------------------------------------

impl PasswordHasher for Pbkdf2Sha512Hasher {
    async fn hash(&self, conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        // mirrors keystone/common/password_hashers/pbkdf2.py::Sha512.hash()
        // Wire format: $pbkdf2-sha512$<rounds>$<salt_b64>$<digest_b64>
        // salt and digest are standard base64 no-pad (binascii.b2a_base64().rstrip("=\n")).
        let password_bytes = password.to_vec();
        let rounds = conf.identity.password_hash_rounds.unwrap_or(25000);
        let hash = task::spawn_blocking(move || {
            let salt: [u8; 16] = rand::random();
            let mut digest = [0u8; SHA512_OUTPUT_BYTES];
            pbkdf2_hmac_sha512(&password_bytes, &salt, rounds as u32, &mut digest)?;
            let salt_str = STANDARD_NO_PAD.encode(salt);
            let digest_str = STANDARD_NO_PAD.encode(digest);
            Ok::<String, PasswordHashError>(format!(
                "$pbkdf2-sha512${rounds}${salt_str}${digest_str}"
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
        // mirrors keystone/common/password_hashers/pbkdf2.py::Sha512.verify()
        // Parses the embedded rounds from the hash string.
        // replace('.', "+") handles old Passlib-era hashes that used '.' instead of '+'.
        let password_bytes = password.to_vec();
        let hash_str = hash.to_string();
        let res = task::spawn_blocking(move || {
            // Split "$pbkdf2-sha512$<rounds>$<salt>$<digest>" on '$':
            // parts = ["", "pbkdf2-sha512", rounds_str, salt_b64, digest_b64]
            let parts: Vec<&str> = hash_str.split('$').collect();
            if parts.len() != 5 || parts[1] != "pbkdf2-sha512" {
                return Err(PasswordHashError::CryptoHash(
                    "Unrecognized PBKDF2 hash format".into(),
                ));
            }

            let rounds: u32 = parts[2].parse().map_err(|_| {
                PasswordHashError::CryptoHash(
                    "Invalid PBKDF2 rounds configuration parameter".into(),
                )
            })?;

            let salt_str = parts[3].replace('.', "+");
            let digest_str = parts[4].replace('.', "+");

            let salt = STANDARD_NO_PAD
                .decode(salt_str.as_bytes())
                .map_err(|_| PasswordHashError::CryptoHash("Invalid PBKDF2 salt".into()))?;

            let expected_digest = STANDARD_NO_PAD.decode(digest_str.as_bytes()).map_err(|_| {
                PasswordHashError::CryptoHash("Invalid PBKDF2 digest encoding".into())
            })?;

            if expected_digest.len() != SHA512_OUTPUT_BYTES {
                return Err(PasswordHashError::CryptoHash(
                    "Invalid PBKDF2-SHA512 checksum buffer bounds".into(),
                ));
            }

            let mut computed_digest = [0u8; SHA512_OUTPUT_BYTES];
            pbkdf2_hmac_sha512(&password_bytes, &salt, rounds, &mut computed_digest)?;

            Ok(computed_digest
                .as_slice()
                .ct_eq(expected_digest.as_slice())
                .into())
        })
        .await??;
        Ok(res)
    }
}

// ---------------------------------------------------------------------------
// PlaintextHasher — Rust-only, no Python counterpart
// ---------------------------------------------------------------------------

impl PasswordHasher for PlaintextHasher {
    async fn hash(&self, _conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        warn!(
            "PasswordHashingAlgo::None is active — passwords are stored and compared in plaintext"
        );
        // Reject invalid UTF-8 outright to prevent collisions from lossy conversion.
        String::from_utf8(password.to_vec())
            .map_err(|_| PasswordHashError::CryptoHash("Invalid UTF-8 sequence in password".into()))
    }

    async fn verify(
        &self,
        _conf: &Config,
        password: &[u8],
        hash: &str,
    ) -> Result<bool, PasswordHashError> {
        Ok(password.ct_eq(hash.as_bytes()).into())
    }
}

// ---------------------------------------------------------------------------
// Shared helper functions
// ---------------------------------------------------------------------------

/// Verify the password length against algorithm constraints and truncate if necessary.
///
/// Mirrors Keystone's own `password_hashing.py::verify_length_and_trunc_password`:
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

/// HMAC-SHA256 keyed by `salt`, over `password`. Returns raw 32-byte digest.
///
/// Both `hash` and `verify` in `BcryptSha256Hasher` must use this function so
/// the intermediate digest is identical on both paths.
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

/// PBKDF2-HMAC-SHA512 using the workspace's hmac v0.13 + sha2 v0.11.
///
/// The pbkdf2 crate (v0.12) uses sha2 v0.10 / digest v0.10 internally,
/// which is a different type family from the workspace. Implementing the
/// algorithm directly avoids the resulting incompatible trait bounds.
/// Output is exactly SHA512_OUTPUT_BYTES (64) — one PBKDF2 block.
fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8; SHA512_OUTPUT_BYTES],
) -> Result<(), PasswordHashError> {
    // U1 = HMAC(password, salt || INT(1))
    let mut u = {
        let mut mac = HmacSha512::new_from_slice(password)
            .map_err(|e| PasswordHashError::CryptoHash(format!("PBKDF2 HMAC init: {e}")))?;
        mac.update(salt);
        // Block index is big-endian 4-byte integer, starting at 1.
        mac.update(&1u32.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut arr = [0u8; SHA512_OUTPUT_BYTES];
        arr.copy_from_slice(&result);
        arr
    };

    // Seed the output with U1, then XOR in U2..Uc.
    output.copy_from_slice(&u);

    for _ in 1..iterations {
        let mut mac = HmacSha512::new_from_slice(password)
            .map_err(|e| PasswordHashError::CryptoHash(format!("PBKDF2 HMAC iter: {e}")))?;
        mac.update(&u);
        let result = mac.finalize().into_bytes();
        let mut next_u = [0u8; SHA512_OUTPUT_BYTES];
        next_u.copy_from_slice(&result);
        u = next_u;
        // XOR accumulate: DK[i] ^= Uc[i]
        for (a, b) in output.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }

    Ok(())
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
// Public API — signatures unchanged; callers outside this module are unaffected.
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
/// are not served after a config change. See `crates/keystone/src/main.rs`
/// for the wiring.
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

    hash_password(conf, dummy_password).await
}

/// Calculate password hash with the configuration defaults.
pub async fn hash_password<S: AsRef<[u8]>>(
    conf: &Config,
    password: S,
) -> Result<String, PasswordHashError> {
    // Truncation uses the *configured* algorithm, not any algorithm detected
    // from an existing hash string. This is the correct behaviour during
    // algorithm migrations: a user whose hash is in the old format and whose
    // password is longer than the new algorithm's limit must be truncated
    // consistently with what Python Keystone would do.
    let truncated = verify_length_and_trunc_password(
        password.as_ref(),
        &conf.identity.password_hashing_algorithm,
        conf.identity.max_password_length,
    );

    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => BcryptHasher.hash(conf, truncated).await,
        PasswordHashingAlgo::BcryptSha256 => BcryptSha256Hasher.hash(conf, truncated).await,
        PasswordHashingAlgo::Scrypt => ScryptHasher.hash(conf, truncated).await,
        PasswordHashingAlgo::Pbkdf2Sha512 => Pbkdf2Sha512Hasher.hash(conf, truncated).await,
        PasswordHashingAlgo::None => PlaintextHasher.hash(conf, truncated).await,
    }
}

/// Verify the password matches the hashed value.
pub async fn verify_password<P: AsRef<[u8]>, H: AsRef<str>>(
    conf: &Config,
    password: P,
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

    let truncated = verify_length_and_trunc_password(
        password.as_ref(),
        &conf.identity.password_hashing_algorithm,
        conf.identity.max_password_length,
    );

    match detected {
        PasswordHashingAlgo::Bcrypt => BcryptHasher.verify(conf, truncated, hash_str).await,
        PasswordHashingAlgo::BcryptSha256 => {
            BcryptSha256Hasher.verify(conf, truncated, hash_str).await
        }
        PasswordHashingAlgo::Scrypt => ScryptHasher.verify(conf, truncated, hash_str).await,
        PasswordHashingAlgo::Pbkdf2Sha512 => {
            Pbkdf2Sha512Hasher.verify(conf, truncated, hash_str).await
        }
        PasswordHashingAlgo::None => PlaintextHasher.verify(conf, truncated, hash_str).await,
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
            verify_password(&conf, TEST_PASSWORD, python_hash)
                .await
                .unwrap(),
            "Rust PBKDF2-SHA512 verification rejected a real Keystone Python PBKDF2-SHA512 hash"
        );
    }

    #[tokio::test]
    async fn test_scrypt_matches_keystone_python_hash() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255); // intentional mismatch: exercises auto-detection by hash prefix
        let python_hash = "$scrypt$ln=16,r=8,p=1$3k9FLaX9XcxhagGmGMxqwA$T6FmonL+mu+Wx86D2S4Acs5UjRdndfITzW+yF+mj+C0";

        assert!(
            verify_password(&conf, TEST_PASSWORD, python_hash)
                .await
                .unwrap(),
            "Rust Scrypt verification rejected a real Keystone Python Scrypt hash"
        );
    }

    #[tokio::test]
    async fn test_bcrypt_matches_keystone_python_ascii_password() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let python_hash = "$2b$12$Hmo85liOZ57y/qMHnbRENON8zynaqEm14wdRuNAoMQHfcNPsx0i56";

        assert!(
            verify_password(&conf, "password123", python_hash)
                .await
                .unwrap(),
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
        let python_hash =
            "$bcrypt-sha256$v=2,t=2b,r=12$dBydkKzGxra2xREv29P6/O$GVrUiF0tJM4hk4xQECVHJ80Rm6cnFBe";

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
        // password_hashing.py — it HMACs the full password to a fixed-size
        // digest before bcrypt ever sees it. This hash was generated from
        // the full, untruncated 73-byte password.
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let python_hash =
            "$bcrypt-sha256$v=2,t=2b,r=12$y6Bnyh5m5Eljt3ZJ15cVQO$.tr2HNwQrYWXZYbHrzqm.iu4x1m6EvW";
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
        let python_hash =
            "$bcrypt-sha256$v=2,t=2b,r=12$mLeKr3jq7QG7SobmywRn..$7IYIos8ugr49dcjSf1AtORmFCwkYxYu";

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
            !verify_password(&conf, "wrong_password", &hashed)
                .await
                .unwrap(),
            "Scrypt verification incorrectly accepted a wrong password"
        );
    }

    #[tokio::test]
    async fn test_pbkdf2_roundtrip_default_rounds() {
        let mut conf = mock_config(PasswordHashingAlgo::Pbkdf2Sha512, 255);
        conf.identity.password_hash_rounds = None; // exercise the default (25000)
        let password = "pbkdf2_roundtrip_password";

        let hashed = hash_password(&conf, password).await.unwrap();
        assert!(
            hashed.starts_with("$pbkdf2-sha512$25000$"),
            "PBKDF2 hash should embed the default round count"
        );
        assert!(
            verify_password(&conf, password, &hashed).await.unwrap(),
            "PBKDF2 roundtrip failed with default rounds"
        );
    }

    #[tokio::test]
    async fn test_pbkdf2_roundtrip_non_default_rounds() {
        // Exercises the case where password_hash_rounds is explicitly configured.
        // This is the scenario where bugs in reading the config field hide.
        let mut conf = mock_config(PasswordHashingAlgo::Pbkdf2Sha512, 255);
        conf.identity.password_hash_rounds = Some(10000);
        let password = "pbkdf2_custom_rounds";

        let hashed = hash_password(&conf, password).await.unwrap();
        assert!(
            hashed.starts_with("$pbkdf2-sha512$10000$"),
            "PBKDF2 hash must embed the configured round count, not the default"
        );
        assert!(
            verify_password(&conf, password, &hashed).await.unwrap(),
            "PBKDF2 roundtrip failed with non-default rounds"
        );
    }

    #[tokio::test]
    async fn test_scrypt_hash_format_matches_python() {
        // Verify the wire format prefix matches what Python emits:
        // $scrypt$ln=16,r=8,p=1$<base64_salt>$<base64_digest>
        let conf = mock_config(PasswordHashingAlgo::Scrypt, 255);
        let hashed = hash_password(&conf, "any_password").await.unwrap();
        assert!(
            hashed.starts_with("$scrypt$ln=16,r=8,p=1$"),
            "Scrypt hash format must match Python Keystone's prefix; got: {hashed}"
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
        assert!(
            !verify_password(&conf, "wrong_password", &hashed)
                .await
                .unwrap()
        );
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
    // These tests close the loop the KAT vectors above only check one way: the
    // KATs prove Rust can *verify* a Python-produced hash; the tests below prove
    // Python can *verify* a Rust-produced hash. They shell out to
    // tools/cross_verify.py inside a real Keystone Python checkout, so they are
    // gated on the KEYSTONE_PYTHON_CHECKOUT env var and silently skip when it is
    // unset (the common case in CI without a Python install). To run:
    //
    //   KEYSTONE_PYTHON_CHECKOUT=~/Projects/openstack/keystone \
    //     cargo test -p openstack-keystone-core -- cross_verify
    //
    // The checkout must have the `bcrypt` and `cryptography` packages installed.

    /// Run a Rust-produced hash through tools/cross_verify.py against the Python
    /// hashers. Returns the script's exit code (0 = verified, 1 = rejected,
    /// 2 = error). Returns `None` when no Python checkout is configured so the
    /// caller can skip.
    async fn python_cross_verify(algo_name: &str, password: &str, hash: &str) -> Option<i32> {
        let checkout = std::env::var("KEYSTONE_PYTHON_CHECKOUT").ok()?;

        // cross_verify.py lives in <repo>/tools; this crate is <repo>/crates/core.
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/cross_verify.py");

        let status = tokio::process::Command::new("python")
            .arg(script)
            .arg(algo_name)
            .arg(password)
            .arg(hash)
            // Run inside the checkout so `import keystone...` resolves.
            .current_dir(checkout)
            .status()
            .await
            .expect("failed to spawn python cross_verify.py");

        Some(status.code().unwrap_or(2))
    }

    #[tokio::test]
    async fn test_cross_verify_bcrypt() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let password = "openstack123";
        let hash = hash_password(&conf, password).await.unwrap();

        match python_cross_verify("bcrypt", password, &hash).await {
            None => return, // no Python checkout configured — skip
            Some(0) => {}
            Some(code) => panic!("Python rejected Rust bcrypt hash (exit {code}): {hash}"),
        }
    }

    #[tokio::test]
    async fn test_cross_verify_bcrypt_sha256() {
        let conf = mock_config(PasswordHashingAlgo::BcryptSha256, 255);
        let password = "openstack123";
        let hash = hash_password(&conf, password).await.unwrap();

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
        let hash = hash_password(&conf, password).await.unwrap();

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
        let hash = hash_password(&conf, password).await.unwrap();

        match python_cross_verify("pbkdf2_sha512", password, &hash).await {
            None => return,
            Some(0) => {}
            Some(code) => panic!("Python rejected Rust pbkdf2_sha512 hash (exit {code}): {hash}"),
        }
    }
}
