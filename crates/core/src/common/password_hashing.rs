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
        warn!("Truncating password to the specified value");
        return &password[..max_length];
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
        PasswordHashingAlgo::None => {
            let dummy: [u8; 32] = rand::random();
            Ok(dummy
                .map(|b| b % 95 + 32 as u8)
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
