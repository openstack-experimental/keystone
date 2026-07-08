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

//! Scrypt hasher - mirrors
//! `keystone/common/password_hashers/scrypt.py::Scrypt`.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use openstack_keystone_config::Config;
use subtle::ConstantTimeEq;
use tokio::task;

use super::{PasswordHashError, PasswordHasher, generate_salt};

pub(super) struct ScryptHasher;

impl PasswordHasher for ScryptHasher {
    async fn hash(&self, _conf: &Config, password: &[u8]) -> Result<String, PasswordHashError> {
        // mirrors keystone/common/password_hashers/scrypt.py::Scrypt.hash()
        // Python hardcodes: n=2**16 (ln=16), r=8, p=1, salt_size=16, output=32 bytes.
        // scrypt_block_size / scrypt_parallelism / salt_bytesize config fields are
        // not yet in IdentityProvider - use Keystone's own defaults until they are
        // added.
        let password_bytes = password.to_vec();
        let hash = task::spawn_blocking(move || {
            let salt = generate_salt();
            // Params::new(log_n, r, p): ln=16 means n=2^16=65536.
            let params = ::scrypt::Params::new(16, 8, 1)
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
            let mut digest = vec![0u8; 32];
            ::scrypt::scrypt(&password_bytes, &salt, &params, &mut digest)
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
            // Python uses binascii.b2a_base64(x).rstrip(b"=\n") - standard base64 no-pad.
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
            // Strip leading '$', split on '$': ["scrypt", "ln=N,r=R,p=P", salt_b64,
            // digest_b64]
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

            // replace('.', "+") handles old Passlib-era hashes that used '.' in place of
            // '+'.
            let salt = STANDARD_NO_PAD
                .decode(salt_b64.replace('.', "+").as_bytes())
                .map_err(|_| PasswordHashError::CryptoHash("Invalid scrypt salt".into()))?;
            let expected = STANDARD_NO_PAD
                .decode(digest_b64.replace('.', "+").as_bytes())
                .map_err(|_| PasswordHashError::CryptoHash("Invalid scrypt digest".into()))?;

            let params = ::scrypt::Params::new(ln, r, p)
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;
            let mut computed = vec![0u8; expected.len()];
            ::scrypt::scrypt(&password_bytes, &salt, &params, &mut computed)
                .map_err(|e| PasswordHashError::CryptoHash(e.to_string()))?;

            Ok(computed.as_slice().ct_eq(expected.as_slice()).into())
        })
        .await??;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{TEST_PASSWORD, mock_config};
    use super::super::{hash_password, verify_password};
    use openstack_keystone_config::PasswordHashingAlgo;
    use secrecy::SecretString;

    #[tokio::test]
    async fn test_scrypt_matches_keystone_python_hash() {
        // Intentional algorithm mismatch in config: exercises auto-detection by
        // hash prefix in verify_password.
        let conf = mock_config(PasswordHashingAlgo::Bcrypt, 255);
        let python_hash = "$scrypt$ln=16,r=8,p=1$Gx7wZNue5sPNsfTOmI4YNg$umTMUw1tH3HhQBqHUG9tEr7x6RxfyVgNty/COb+m1IM";

        assert!(
            verify_password(&conf, &SecretString::from(TEST_PASSWORD), python_hash)
                .await
                .unwrap(),
            "Rust Scrypt verification rejected a real Keystone Python Scrypt hash"
        );
    }

    #[tokio::test]
    async fn test_scrypt_hash_then_verify_roundtrip() {
        let conf = mock_config(PasswordHashingAlgo::Scrypt, 255);
        let password = "scrypt_roundtrip_password";
        let secret = SecretString::from(password);

        let hashed = hash_password(&conf, &secret).await.unwrap();
        assert!(
            verify_password(&conf, &secret, &hashed).await.unwrap(),
            "Scrypt hash_password output failed to verify against the same password"
        );
        assert!(
            !verify_password(&conf, &SecretString::from("wrong_password"), &hashed)
                .await
                .unwrap(),
            "Scrypt verification incorrectly accepted a wrong password"
        );
    }

    #[tokio::test]
    async fn test_scrypt_hash_format_matches_python() {
        // Verify the wire format prefix matches what Python emits:
        // $scrypt$ln=16,r=8,p=1$<base64_salt>$<base64_digest>
        let conf = mock_config(PasswordHashingAlgo::Scrypt, 255);
        let hashed = hash_password(&conf, &SecretString::from("any_password"))
            .await
            .unwrap();
        assert!(
            hashed.starts_with("$scrypt$ln=16,r=8,p=1$"),
            "Scrypt hash format must match Python Keystone's prefix; got: {hashed}"
        );
    }
}
