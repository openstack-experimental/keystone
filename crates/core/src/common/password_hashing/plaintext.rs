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

//! Plaintext "hasher" - a Rust-only extension with no Python counterpart in
//! Keystone's `SUPPORTED_HASHERS`. Stores passwords in plaintext; must never
//! be used in production. Selected via `PasswordHashingAlgo::None`.

use openstack_keystone_config::Config;
use subtle::ConstantTimeEq;
use tracing::warn;

use super::{PasswordHashError, PasswordHasher};

pub(super) struct PlaintextHasher;

impl PasswordHasher for PlaintextHasher {
    async fn hash(&self, _conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        warn!(
            "PasswordHashingAlgo::None is active - passwords are stored and compared in plaintext"
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

#[cfg(test)]
mod tests {
    use super::super::tests::mock_config;
    use super::super::{hash_password, verify_password};
    use openstack_keystone_config::PasswordHashingAlgo;

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
}
