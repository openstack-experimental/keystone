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

use std::cmp::max;
use std::str;
use thiserror::Error;
use tokio::task;
use tracing::warn;

use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::rand_core::OsRng;
use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use scrypt::Scrypt;
use sha2::Digest;

use openstack_keystone_config::{Config, PasswordHashingAlgo};

/// Password hashing related errors.
#[derive(Error, Debug)]
pub enum PasswordHashError {
    /// Bcrypt error.
    #[error(transparent)]
    BCrypt {
        /// The source of the error.
        #[from]
        source: bcrypt::BcryptError,
    },

    /// Crypto password-hash crate error (handles scrypt/pbkdf2 formatting).
    #[error("Password hashing framework error: {0}")]
    CryptoHash(String),

    /// Async task join error.
    #[error(transparent)]
    Join {
        /// The source of the error.
        #[from]
        source: tokio::task::JoinError,
    },

    /// Non UTF8 data.
    #[error(transparent)]
    Utf8 {
        /// The source of the error.
        #[from]
        source: str::Utf8Error,
    },
}

/// Verify the password length and truncate if necessary.
///
/// # Parameters
/// - `password`: The password bytes.
/// - `max_length`: The maximum allowed length.
///
/// # Returns
/// - `&[u8]` - The password bytes, truncated if they exceeded `max_length`.
fn verify_length_and_trunc_password(password: &[u8], max_length: usize) -> &[u8] {
    if password.len() > max_length {
        let mut end = max_length;
        // Step backward while the byte is a UTF-8 continuation byte.
        // A continuation byte falls in the range 128..192.
        while end > 0 && password[end] >= 128 && password[end] < 192 {
            end -= 1;
        }
        warn!("Truncating password to the specified value");
        return &password[..end];
    }
    password
}

/// Generate a dummy password hash matching the configured algorithm.
///
/// Used for timing attack prevention: when a user is not found, a dummy hash
/// is generated and verified against the provided password, so the response
/// time is approximately the same as when the user exists but the password is
/// wrong.
///
/// # Parameters
/// - `conf`: The service configuration.
///
/// # Returns
/// - `Ok(String)` - A dummy hash string matching the configured algorithm.
/// - `Err(PasswordHashError)` - If hash generation failed.
pub async fn generate_dummy_hash(conf: &Config) -> Result<String, PasswordHashError> {
    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => {
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            // bcrypt dummy hash: "$2b$XX$" + 53 random base64 chars
            // Generate a dummy hash with a random salt by hashing a random string
            // with matching rounds, so verify_password takes the same time
            let dummy_password = rand::random::<[u8; 16]>();
            let hash =
                task::spawn_blocking(move || bcrypt::hash(dummy_password, rounds as u32)).await??;
            Ok(hash)
        }

        PasswordHashingAlgo::BcryptSha256 => {
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            let dummy_password = rand::random::<[u8; 16]>();
            let hash = task::spawn_blocking(move || {
                let digest = sha2::Sha256::digest(dummy_password);
                let hex_digest = digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                bcrypt::hash(hex_digest, rounds as u32)
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::Scrypt => {
            let dummy_password = rand::random::<[u8; 16]>();
            let salt = SaltString::generate(&mut OsRng);
            let hash = task::spawn_blocking(move || {
                Scrypt
                    .hash_password(&dummy_password, &salt)
                    .map(|hash| hash.to_string())
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::Pbkdf2Sha512 => {
            let dummy_password = rand::random::<[u8; 16]>();
            let salt = SaltString::generate(&mut OsRng);
            let hash = task::spawn_blocking(move || {
                Pbkdf2
                    .hash_password_customized(
                        &dummy_password,
                        Some(pbkdf2::Algorithm::Pbkdf2Sha512.ident()),
                        None,
                        pbkdf2::Params::default(),
                        &salt,
                    )
                    .map(|h| h.to_string())
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::None => {
            let dummy: [u8; 32] = rand::random();
            Ok(dummy
                .map(|b| b % 95 + 32_u8)
                .into_iter()
                .map(|b| b as char)
                .collect())
        }
    }
}

/// Calculate password hash with the configuration defaults.
///
/// # Parameters
/// - `conf`: The service configuration.
/// - `password`: The password to hash.
///
/// # Returns
/// - `Ok(String)` - The hashed password.
/// - `Err(PasswordHashError)` - If hashing failed.
pub async fn hash_password<S: AsRef<[u8]>>(
    conf: &Config,
    password: S,
) -> Result<String, PasswordHashError> {
    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            let hash =
                task::spawn_blocking(move || bcrypt::hash(password_bytes, rounds as u32)).await??;
            Ok(hash)
        }

        PasswordHashingAlgo::BcryptSha256 => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            let hash = task::spawn_blocking(move || {
                let digest = sha2::Sha256::digest(password_bytes);
                let hex_digest = digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                bcrypt::hash(hex_digest, rounds as u32)
            })
            .await??;
            Ok(hash)
        }

        PasswordHashingAlgo::Scrypt => {
            let password_bytes = password.as_ref().to_owned();
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
            let password_bytes = password.as_ref().to_owned();
            let salt = SaltString::generate(&mut OsRng);
            let hash = task::spawn_blocking(move || {
                Pbkdf2
                    .hash_password_customized(
                        &password_bytes,
                        Some(pbkdf2::Algorithm::Pbkdf2Sha512.ident()),
                        None,
                        pbkdf2::Params::default(),
                        &salt,
                    )
                    .map(|h| h.to_string())
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))
            })
            .await??;
            Ok(hash)
        }

        //#[cfg(test)]
        PasswordHashingAlgo::None => Ok(str::from_utf8(password.as_ref())?.to_string()),
    }
}

/// Verify the password matches the hashed value.
///
/// # Parameters
/// - `conf`: The service configuration.
/// - `password`: The password to verify.
/// - `hash`: The hash to compare against.
///
/// # Returns
/// - `Ok(bool)` - True if the password matches the hash, false otherwise.
/// - `Err(PasswordHashError)` - If verification failed.
pub async fn verify_password<P: AsRef<[u8]>, H: AsRef<str>>(
    conf: &Config,
    password: P,
    hash: H,
) -> Result<bool, PasswordHashError> {
    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            let password_hash = hash.as_ref().to_string();
            // Do not block the main thread with a definitely long running call.
            match task::spawn_blocking(move || bcrypt::verify(password_bytes, &password_hash))
                .await?
            {
                Ok(res) => Ok(res),
                Err(bcrypt::BcryptError::InvalidHash(..)) => {
                    // InvalidHash error contain the hash itself. We do not want to log it.
                    warn!("Bcrypt hash verification error: bad hash");
                    Ok(false)
                }
                other => {
                    warn!("Bcrypt hash verification error: {other:?}");
                    Ok(false)
                }
            }
        }

        PasswordHashingAlgo::BcryptSha256 => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            let password_hash = hash.as_ref().to_string();
            // Do not block the main thread with a definitely long running call.
            match task::spawn_blocking(move || {
                let digest = sha2::Sha256::digest(password_bytes);
                let hex_digest = digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                bcrypt::verify(hex_digest, &password_hash)
            })
            .await?
            {
                Ok(res) => Ok(res),
                Err(bcrypt::BcryptError::InvalidHash(..)) => {
                    warn!("BcryptSha256 hash verification error: bad hash");
                    Ok(false)
                }
                other => {
                    warn!("BcryptSha256 hash verification error: {other:?}");
                    Ok(false)
                }
            }
        }

        PasswordHashingAlgo::Scrypt => {
            let password_bytes = password.as_ref().to_owned();
            let password_hash = hash.as_ref().to_string();
            // Do not block the main thread with a definitely long running call.
            let res = task::spawn_blocking(move || {
                let parsed_hash = PasswordHash::new(&password_hash)
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
            let password_bytes = password.as_ref().to_owned();
            let password_hash = hash.as_ref().to_string();
            // Do not block the main thread with a definitely long running call.
            let res = task::spawn_blocking(move || {
                let parsed_hash = PasswordHash::new(&password_hash)
                    .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
                Ok::<bool, PasswordHashError>(
                    Pbkdf2
                        .verify_password(&password_bytes, &parsed_hash)
                        .is_ok(),
                )
            })
            .await??;
            Ok(res)
        }

        //#[cfg(test)]
        PasswordHashingAlgo::None => Ok(str::from_utf8(password.as_ref())?.eq(hash.as_ref())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::{Alphanumeric, SampleString};
    use tracing_test::traced_test;

    #[test]
    fn test_verify_length_and_trunc_password() {
        assert_eq!(
            b"abcdefg",
            verify_length_and_trunc_password("abcdefg".as_bytes(), 70)
        );
        assert_eq!(
            b"abcd",
            verify_length_and_trunc_password("abcdefg".as_bytes(), 4)
        );
        // In UTF8 bytes a single unicode is taking 3 bytes already
        assert_eq!(
            b"\xE2\x98\x81a",
            verify_length_and_trunc_password("☁abcdefg".as_bytes(), 4)
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_hash_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = "abcdefg";
        let hashed = hash_password(&conf, &pass).await.unwrap();
        assert!(!logs_contain(pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = "abcdefg";
        let hashed = hash_password(&conf, &pass).await.unwrap();
        assert!(verify_password(&conf, &pass, &hashed).await.unwrap());
        assert!(!logs_contain(pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt_longer_than_72() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        let hashed = hash_password(&conf, &pass).await.unwrap();
        assert!(verify_password(&conf, &pass, &hashed).await.unwrap());
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt_mismatch() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        let hashed = hash_password(&conf, "other password").await.unwrap();
        assert!(!verify_password(&conf, &pass, &hashed).await.unwrap());
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&hashed));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_roundtrip_bcrypt_bad_hash() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        assert!(!verify_password(&conf, &pass, "foobar").await.unwrap());
        assert!(!logs_contain("foobar"));
        assert!(!logs_contain(&pass));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_generate_and_verify_dummy_hash_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let dummy_hash = generate_dummy_hash(&conf).await.unwrap();
        // Dummy hash should be a valid bcrypt hash (starts with $2b$)
        assert!(
            dummy_hash.starts_with("$2b$"),
            "Dummy hash should be a valid bcrypt hash"
        );
        // Verify should return false for any random password
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let result = verify_password(&conf, &pass, &dummy_hash).await.unwrap();
        // Result should be false (password doesn't match dummy hash)
        assert!(!result, "Dummy hash should not match random password");
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&dummy_hash));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_generate_dummy_hash_none() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap()
            .set_override("identity.password_hashing_algorithm", "None")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let dummy_hash = generate_dummy_hash(&conf).await.unwrap();
        // Dummy hash should be a non-empty string
        assert!(!dummy_hash.is_empty(), "Dummy hash should not be empty");
        // Verify should return false for any random password
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let result = verify_password(&conf, &pass, &dummy_hash).await.unwrap();
        // Result should almost certainly be false (random password unlikely to match)
        assert!(!result, "Dummy hash should not match random password");
        assert!(!logs_contain(&pass));
        assert!(!logs_contain(&dummy_hash));
    }
}
#[cfg(test)]
mod passlib_migration_tests {
    use super::*; // Imports your hash_password / verify_password functions
    use pbkdf2::Pbkdf2;
    use pbkdf2::password_hash::{PasswordHash, PasswordVerifier};
    use scrypt::Scrypt;

    const TEST_PASSWORD: &str = "openstack123";

    /// Custom verifier required for OpenStack database migrations.
    /// Replicates Passlib's legacy quirk of base64-decoding the salt
    /// (whereas the modern PHC standard uses the raw salt string directly).
    pub fn verify_legacy_passlib_pbkdf2(password: &str, raw_python_hash: &str) -> bool {
        let parts: Vec<&str> = raw_python_hash.split('$').collect();
        if parts.len() != 5 || parts[1] != "pbkdf2-sha512" {
            return false;
        }

        let rounds = parts[2];
        let passlib_salt_ascii = parts[3];
        let checksum_b64 = parts[4].replace('.', "+");

        // Parse using Rust's standard crate just to easily decode the base64 checksum
        let dummy_salt = passlib_salt_ascii.replace('.', "+");
        let norm_str = format!(
            "$pbkdf2-sha512$i={}${}${}",
            rounds, dummy_salt, checksum_b64
        );
        let parsed = match pbkdf2::password_hash::PasswordHash::new(&norm_str) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let iterations = parsed
            .params
            .get("i")
            .and_then(|p| p.as_str().parse::<u32>().ok())
            .unwrap_or(25000);

        // Extract the target checksum bytes that Python generated
        let hash_output = parsed.hash.unwrap();
        let expected_bytes = hash_output.as_bytes();

        // DECODE THE SALT (Passlib decodes the salt; standard Rust does not)
        // This handles Passlib's adapted unpadded base64 (which uses '.' instead of '+')
        let mut decoded_salt = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for &c in passlib_salt_ascii.as_bytes() {
            let val = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' | b'.' => 62,
                b'/' => 63,
                _ => continue, // Ignore padding or invalid chars
            };
            buf = (buf << 6) | (val as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                decoded_salt.push((buf >> bits) as u8);
            }
        }

        // Compute hash manually using the DECODED salt bytes
        let mut computed_hash = vec![0u8; expected_bytes.len()];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            password.as_bytes(),
            &decoded_salt, // <-- The actual fix
            iterations,
            &mut computed_hash,
        );

        computed_hash == expected_bytes
    }

    /// Normalizes Python Passlib Scrypt hashes (which DO follow standards!)
    fn normalize_scrypt_hash(passlib_hash: &str) -> String {
        let parts: Vec<&str> = passlib_hash.split('$').collect();
        if parts.len() != 5 || parts[1] != "scrypt" {
            return passlib_hash.to_string();
        }
        let salt = parts[3].replace('.', "+");
        let checksum = parts[4].replace('.', "+");
        format!("$scrypt${}${}${}", parts[2], salt, checksum)
    }

    #[test]
    fn test_roundtrip_pbkdf2() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Pbkdf2,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(
            Pbkdf2
                .verify_password(TEST_PASSWORD.as_bytes(), &parsed_hash)
                .is_ok()
        );
    }

    #[test]
    fn test_roundtrip_scrypt() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Scrypt,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(
            Scrypt
                .verify_password(TEST_PASSWORD.as_bytes(), &parsed_hash)
                .is_ok()
        );
    }

    #[test]
    fn test_rejection_wrong_password() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Pbkdf2,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(
            Pbkdf2
                .verify_password(b"wrongpassword", &parsed_hash)
                .is_err()
        );
    }

    #[test]
    fn test_rejection_empty_password() {
        let salt =
            pbkdf2::password_hash::SaltString::generate(pbkdf2::password_hash::rand_core::OsRng);
        let hash = pbkdf2::password_hash::PasswordHasher::hash_password(
            &Pbkdf2,
            TEST_PASSWORD.as_bytes(),
            &salt,
        )
        .unwrap();
        let hash_string = hash.to_string();
        let parsed_hash = PasswordHash::new(&hash_string).unwrap();
        assert!(Pbkdf2.verify_password(b"", &parsed_hash).is_err());
    }

    #[test]
    fn test_python_passlib_compatibility() {
        let python_pbkdf2_hash = "$pbkdf2-sha512$25000$bo2REsLY.z9HCCFESEmJkQ$qX0JhkudwUVXpDKfMkDrWRgiP2AcYLbocxVkQrOmX4i0SGANHAB8KQUd1vbwVYJEBpbi4RvyvP5QJWZfIhnWTQ";
        let python_scrypt_hash = "$scrypt$ln=16,r=8,p=1$FoLwnnPuvVdKqbWWEuK8lw$zaI+PjacJwDMwu4NoXmY9spmyrB4qnc8kGAJ4I6oABo";

        // 1. Verify PBKDF2 using our OpenStack legacy manual verifier
        assert!(
            verify_legacy_passlib_pbkdf2(TEST_PASSWORD, python_pbkdf2_hash),
            "Custom verifier rejected Python's legacy PBKDF2 hash!"
        );

        // 2. Verify SCRYPT using standard tools (Passlib Scrypt is fully standard compliant)
        let norm_scrypt_str = normalize_scrypt_hash(python_scrypt_hash);
        let parsed_scrypt = PasswordHash::new(&norm_scrypt_str).unwrap();
        assert!(
            Scrypt
                .verify_password(TEST_PASSWORD.as_bytes(), &parsed_scrypt)
                .is_ok(),
            "Rust rejected Python's valid SCRYPT hash!"
        );
    }
}
