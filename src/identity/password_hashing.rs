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
use tokio::task;
use tracing::warn;

use crate::config::{Config, PasswordHashingAlgo};
use crate::identity::error::IdentityProviderPasswordHashError;

fn verify_length_and_trunc_password(password: &[u8], max_length: usize) -> &[u8] {
    if password.len() > max_length {
        warn!("Truncating password to the specified value");
        return &password[..max_length];
    }
    password
}

/// Calculate password hash with the configuration defaults.
pub async fn hash_password<S: AsRef<[u8]>>(
    conf: &Config,
    password: S,
) -> Result<String, IdentityProviderPasswordHashError> {
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
    }
}

/// Verify the password matches the hashed value.
pub async fn verify_password<P: AsRef<[u8]>, H: AsRef<str>>(
    conf: &Config,
    password: P,
    hash: H,
) -> Result<bool, IdentityProviderPasswordHashError> {
    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            )
            .to_owned();
            let password_hash = hash.as_ref().to_string();
            // Do not block the main thread with a definitely long running call.
            let verify =
                task::spawn_blocking(move || bcrypt::verify(password_bytes, &password_hash))
                    .await??;
            Ok(verify)
            //Ok(bcrypt::verify(password_bytes, hash.as_ref())?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::{Alphanumeric, SampleString};

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
    async fn test_hash_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        assert!(hash_password(&conf, "abcdefg").await.is_ok());
    }

    #[tokio::test]
    async fn test_roundtrip_bcrypt() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let hashed = hash_password(&conf, "abcdefg").await.unwrap();
        assert!(verify_password(&conf, "abcdefg", hashed).await.unwrap());
    }

    #[tokio::test]
    async fn test_roundtrip_bcrypt_longer_than_72() {
        let builder = config::Config::builder()
            .set_override("auth.methods", "")
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let conf: Config = Config::try_from(builder).expect("can build a valid config");
        let pass = Alphanumeric.sample_string(&mut rand::rng(), 80);
        let hashed = hash_password(&conf, pass.clone()).await.unwrap();
        assert!(verify_password(&conf, pass, hashed).await.unwrap());
    }
}
