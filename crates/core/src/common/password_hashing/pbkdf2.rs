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

//! PBKDF2-HMAC-SHA512 hasher - mirrors `pbkdf2.py::Sha512`.
//!
//! The pbkdf2 crate (v0.12) uses sha2 v0.10 / digest v0.10 internally, which is
//! a different type family from the workspace's sha2 v0.11 / hmac v0.13. To
//! avoid the resulting incompatible trait bounds, the algorithm is implemented
//! directly here on top of the workspace HMAC.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
// KeyInit provides new_from_slice; Mac provides update/finalize.
use hmac::{Hmac, KeyInit, Mac};
use openstack_keystone_config::Config;
use subtle::ConstantTimeEq;
use tokio::task;

use super::{PasswordHashError, PasswordHasher, generate_salt};

type HmacSha512 = Hmac<sha2::Sha512>;

/// Length in bytes of a SHA-512 digest, used by the PBKDF2-SHA512 checksum.
const SHA512_OUTPUT_BYTES: usize = 64;

pub(super) struct Pbkdf2Sha512Hasher;

impl PasswordHasher for Pbkdf2Sha512Hasher {
    async fn hash(&self, conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        // mirrors keystone/common/password_hashers/pbkdf2.py::Sha512.hash()
        // Wire format: $pbkdf2-sha512$<rounds>$<salt_b64>$<digest_b64>
        // salt and digest are standard base64 no-pad
        // (binascii.b2a_base64().rstrip("=\n")).
        let password_bytes = password.to_vec();
        let rounds = conf.identity.password_hash_rounds.unwrap_or(25000);
        let hash = task::spawn_blocking(move || {
            let salt = generate_salt();
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
        // replace('.', "+") handles old Passlib-era hashes that used '.' instead of
        // '+'.
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

/// PBKDF2-HMAC-SHA512 using the workspace's hmac v0.13 + sha2 v0.11.
///
/// Output is exactly SHA512_OUTPUT_BYTES (64), i.e. one PBKDF2 block. Follows
/// RFC 2898 section 5.2 directly.
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

#[cfg(test)]
mod tests {
    use super::super::tests::{TEST_PASSWORD, mock_config};
    use super::super::{hash_password, verify_password};
    use openstack_keystone_config::PasswordHashingAlgo;
    use secrecy::SecretString;

    #[tokio::test]
    async fn test_pbkdf2_sha512_matches_keystone_python_hash() {
        let conf = mock_config(PasswordHashingAlgo::Pbkdf2Sha512, 255);
        let python_hash = "$pbkdf2-sha512$25000$z1PryJDTkFQEQN/E5K0nLQ$CzQ9XdgqUzdTOTjUSRGMN9r9O7WQmiyUl4fVA2jwJpB6zSXEonqw9Jfg4WImljlZ7fRPPFXmZZVdVhnCTJZymg";

        assert!(
            verify_password(&conf, &SecretString::from(TEST_PASSWORD), python_hash)
                .await
                .unwrap(),
            "Rust PBKDF2-SHA512 verification rejected a real Keystone Python PBKDF2-SHA512 hash"
        );
    }

    #[tokio::test]
    async fn test_pbkdf2_roundtrip_default_rounds() {
        let mut conf = mock_config(PasswordHashingAlgo::Pbkdf2Sha512, 255);
        conf.identity.password_hash_rounds = None; // exercise the default (25000)
        let password = "pbkdf2_roundtrip_password";
        let secret = SecretString::from(password);

        let hashed = hash_password(&conf, &secret).await.unwrap();
        assert!(
            hashed.starts_with("$pbkdf2-sha512$25000$"),
            "PBKDF2 hash should embed the default round count"
        );
        assert!(
            verify_password(&conf, &secret, &hashed).await.unwrap(),
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
        let secret = SecretString::from(password);

        let hashed = hash_password(&conf, &secret).await.unwrap();
        assert!(
            hashed.starts_with("$pbkdf2-sha512$10000$"),
            "PBKDF2 hash must embed the configured round count, not the default"
        );
        assert!(
            verify_password(&conf, &secret, &hashed).await.unwrap(),
            "PBKDF2 roundtrip failed with non-default rounds"
        );
    }
}
