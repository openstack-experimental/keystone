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
//! # API Key Argon2id hashing & verification (ADR 0021 §3 Step 3, §6.B).
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use openstack_keystone_config::ApiKeyProvider;

use crate::api_key::ApiKeyProviderError;

/// Fixed non-secret input used only to burn CPU time equivalent to a real
/// verification, never compared against a stored hash (ADR 0021 Invariant
/// 7). Deliberately not derived from any request data.
const DUMMY_ENTROPY: &str = "keystone-api-key-dummy-entropy-constant-time-padding";

fn build_params(config: &ApiKeyProvider) -> Result<Params, ApiKeyProviderError> {
    Params::new(
        config.argon2_memory_kib,
        config.argon2_time_cost,
        config.argon2_parallelism,
        None,
    )
    .map_err(ApiKeyProviderError::crypto)
}

/// Hash token entropy into a PHC-formatted Argon2id string using the
/// configured (current) parameters.
pub async fn hash_secret(
    entropy: &str,
    config: &ApiKeyProvider,
) -> Result<String, ApiKeyProviderError> {
    let entropy = entropy.to_string();
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let params = build_params(&config)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        argon2
            .hash_password(entropy.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(ApiKeyProviderError::crypto)
    })
    .await
    .map_err(ApiKeyProviderError::crypto)?
}

/// Verify token entropy against a stored PHC-formatted Argon2id hash.
///
/// Verification uses the algorithm/version/parameters embedded in `phc`
/// itself (not the caller's current configuration), so a key hashed with
/// older parameters still verifies correctly before the lazy re-hash
/// (Invariant 8) brings it up to the current floor. Comparison against the
/// stored hash is constant-time, performed internally by the `argon2` crate.
pub async fn verify_secret(entropy: &str, phc: &str) -> Result<bool, ApiKeyProviderError> {
    let entropy = entropy.to_string();
    let phc = phc.to_string();
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&phc).map_err(ApiKeyProviderError::crypto)?;
        Ok(Argon2::default()
            .verify_password(entropy.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(ApiKeyProviderError::crypto)?
}

/// Whether the parameters embedded in a stored PHC string meet the
/// configured minimums (Invariant 8).
pub fn params_meet_minimums(
    phc: &str,
    config: &ApiKeyProvider,
) -> Result<bool, ApiKeyProviderError> {
    let parsed = PasswordHash::new(phc).map_err(ApiKeyProviderError::crypto)?;
    let params = Params::try_from(&parsed).map_err(ApiKeyProviderError::crypto)?;
    Ok(params.m_cost() >= config.argon2_memory_kib
        && params.t_cost() >= config.argon2_time_cost
        && params.p_cost() >= config.argon2_parallelism)
}

/// Re-hash `entropy` with the current configured parameters if the stored
/// `phc` falls below the configured floor. Returns `None` when no re-hash is
/// necessary.
pub async fn rehash_if_needed(
    entropy: &str,
    phc: &str,
    config: &ApiKeyProvider,
) -> Result<Option<String>, ApiKeyProviderError> {
    if params_meet_minimums(phc, config)? {
        return Ok(None);
    }
    Ok(Some(hash_secret(entropy, config).await?))
}

/// Generate a dummy Argon2id hash using the current configured parameters,
/// for the caller to verify the presented (non-existent-key) token against.
/// Ensures the "no such `lookup_hash`" response path costs the same wall
/// time as a real "found but wrong secret" verification, preventing
/// timing-based enumeration of valid lookup hashes (ADR 0021 Invariant 7).
pub async fn generate_dummy_hash(config: &ApiKeyProvider) -> Result<String, ApiKeyProviderError> {
    hash_secret(DUMMY_ENTROPY, config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ApiKeyProvider {
        ApiKeyProvider {
            argon2_memory_kib: 8,
            argon2_time_cost: 1,
            argon2_parallelism: 1,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_hash_and_verify_roundtrip() {
        let config = test_config();
        let phc = hash_secret("correct-entropy", &config).await.unwrap();
        assert!(verify_secret("correct-entropy", &phc).await.unwrap());
        assert!(!verify_secret("wrong-entropy", &phc).await.unwrap());
    }

    #[tokio::test]
    async fn test_params_meet_minimums() {
        let low_config = test_config();
        let phc = hash_secret("entropy", &low_config).await.unwrap();
        assert!(params_meet_minimums(&phc, &low_config).unwrap());

        let higher_config = ApiKeyProvider {
            argon2_memory_kib: 65536,
            ..low_config
        };
        assert!(!params_meet_minimums(&phc, &higher_config).unwrap());
    }

    #[tokio::test]
    async fn test_rehash_if_needed() {
        let low_config = test_config();
        let phc = hash_secret("entropy", &low_config).await.unwrap();

        // No re-hash needed against the same (low) parameters.
        assert!(
            rehash_if_needed("entropy", &phc, &low_config)
                .await
                .unwrap()
                .is_none()
        );

        // Re-hash required against stricter parameters, and the new hash
        // still verifies.
        let higher_config = ApiKeyProvider {
            argon2_time_cost: 2,
            ..low_config
        };
        let rehashed = rehash_if_needed("entropy", &phc, &higher_config)
            .await
            .unwrap()
            .expect("rehash expected");
        assert!(verify_secret("entropy", &rehashed).await.unwrap());
        assert!(params_meet_minimums(&rehashed, &higher_config).unwrap());
    }

    #[tokio::test]
    async fn test_generate_dummy_hash_is_valid_phc() {
        let config = test_config();
        let phc = generate_dummy_hash(&config).await.unwrap();
        assert!(verify_secret(DUMMY_ENTROPY, &phc).await.unwrap());
        assert!(!verify_secret("attacker-guess", &phc).await.unwrap());
    }
}
