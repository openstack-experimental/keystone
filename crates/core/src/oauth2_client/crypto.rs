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
//! # OAuth2 client secret generation & Argon2id hashing (ADR 0026 §5)
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use rand::RngExt;
use rand::distr::{Alphanumeric, SampleString};
use secrecy::SecretString;

use openstack_keystone_config::Oauth2Provider;

use crate::oauth2_client::Oauth2ClientProviderError;

const SECRET_PREFIX: &str = "kosc";
/// ~256 bits of entropy over the 62-character alphanumeric alphabet.
const ENTROPY_LEN: usize = 43;

fn generate_salt() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    STANDARD_NO_PAD.encode(bytes)
}

fn build_params(config: &Oauth2Provider) -> Result<Params, Oauth2ClientProviderError> {
    Params::new(
        config.argon2_memory_kib,
        config.argon2_time_cost,
        config.argon2_parallelism,
        None,
    )
    .map_err(Oauth2ClientProviderError::crypto)
}

/// Generate a fresh plaintext client secret (`kosc_<entropy>`), shown to the
/// caller exactly once on `create`/`rotate_secret`.
pub fn generate_secret() -> SecretString {
    let entropy = Alphanumeric.sample_string(&mut rand::rng(), ENTROPY_LEN);
    SecretString::from(format!("{SECRET_PREFIX}_{entropy}"))
}

/// Hash a plaintext client secret into a PHC-formatted Argon2id string using
/// the configured parameters.
pub async fn hash_secret(
    secret: &SecretString,
    config: &Oauth2Provider,
) -> Result<String, Oauth2ClientProviderError> {
    use secrecy::ExposeSecret;
    let secret_plain = secret.expose_secret().to_string();
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let params = build_params(&config)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::from_b64(generate_salt().as_str())
            .map_err(Oauth2ClientProviderError::crypto)?;
        argon2
            .hash_password(secret_plain.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(Oauth2ClientProviderError::crypto)
    })
    .await
    .map_err(Oauth2ClientProviderError::crypto)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use secrecy::ExposeSecret;

    fn test_config() -> Oauth2Provider {
        Oauth2Provider {
            argon2_memory_kib: 8,
            argon2_time_cost: 1,
            argon2_parallelism: 1,
            ..Default::default()
        }
    }

    #[test]
    fn test_generate_secret_has_expected_prefix() {
        let secret = generate_secret();
        assert!(secret.expose_secret().starts_with("kosc_"));
    }

    #[tokio::test]
    async fn test_hash_secret_roundtrips() {
        let config = test_config();
        let secret = generate_secret();
        let phc = hash_secret(&secret, &config).await.unwrap();
        let parsed = PasswordHash::new(&phc).unwrap();
        assert!(
            Argon2::default()
                .verify_password(secret.expose_secret().as_bytes(), &parsed)
                .is_ok()
        );
        let wrong = generate_secret();
        assert!(
            Argon2::default()
                .verify_password(wrong.expose_secret().as_bytes(), &parsed)
                .is_err()
        );
    }
}
