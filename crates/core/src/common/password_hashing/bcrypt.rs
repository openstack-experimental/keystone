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

//! Bcrypt hasher - mirrors
//! `keystone/common/password_hashers/bcrypt.py::Bcrypt`.

use openstack_keystone_config::Config;
use tokio::task;

use super::{PasswordHashError, PasswordHasher};

/// Plain bcrypt. The `bcrypt` crate path is referenced absolutely (`::bcrypt`)
/// throughout this module so it is never confused with the module's own name.
pub(super) struct BcryptHasher;

impl PasswordHasher for BcryptHasher {
    async fn hash(&self, conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        let password_bytes = password.to_vec();
        let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
        // bcrypt::hash is CPU-bound; run off the async executor.
        let hash =
            task::spawn_blocking(move || ::bcrypt::hash(password_bytes, rounds as u32)).await??;
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
        match task::spawn_blocking(move || ::bcrypt::verify(password_bytes, &hash_str)).await? {
            Ok(res) => Ok(res),
            // A malformed hash string is not a fatal error - it just means
            // the stored value is not a valid bcrypt hash and cannot match.
            Err(::bcrypt::BcryptError::InvalidHash(_)) => Ok(false),
            Err(e) => Err(PasswordHashError::from(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::mock_config;
    use super::super::{hash_password, verify_password};
    use openstack_keystone_config::PasswordHashingAlgo;
    use rand::distr::{Alphanumeric, SampleString};
    use tracing_test::traced_test;

    #[tokio::test]
    async fn test_bcrypt_matches_keystone_python_ascii_password() {
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let python_hash = "$2b$12$0DJQbRXGHzPsBrwGt/DebuerSmDAslUjtPYtph84hMimE3XiK9K4e";

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
        let python_hash = "$2b$12$WzlPV/xopC8EI12Uz6kak.Edrg/n6QqM71MXoxegUUPxr.F52Hpsi";
        let untruncated_73_byte_password = "A".repeat(73);

        assert!(
            verify_password(&conf, &untruncated_73_byte_password, python_hash)
                .await
                .unwrap(),
            "Rust Bcrypt did not truncate at the same 72-byte boundary as Keystone Python"
        );
    }

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
}
