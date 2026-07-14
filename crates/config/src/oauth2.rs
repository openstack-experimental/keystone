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
//! # OAuth2/OIDC provider configuration (ADR 0026)
//!
//! Phase 1 scope only: the per-domain signing-key algorithm and rotation
//! cadence for the `GET /v4/oauth2/{domain_id}/jwks` cryptographic engine.
//! Later phases (client registration, scopes, grants) get their own config
//! sections when implemented.
use serde::Deserialize;
use validator::Validate;

/// OAuth2 signing algorithm (ADR 0026 §3).
///
/// This same value governs both outbound signing and inbound verification;
/// the two must always match to prevent cross-algorithm signature exploits.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// ECDSA over P-256, SHA-256. Default per ADR 0026 §3.
    #[default]
    #[serde(rename = "ES256")]
    Es256,
    /// RSA-2048, SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Es256 => write!(f, "ES256"),
            Self::Rs256 => write!(f, "RS256"),
        }
    }
}

/// OAuth2/OIDC provider configuration.
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct Oauth2Provider {
    /// Signing algorithm for per-domain OAuth2 signing keypairs.
    #[serde(default)]
    pub signing_algorithm: SigningAlgorithm,

    /// Days between automatic signing-key rotations. Manual rotation via
    /// `keystone-manage oauth2 rotate-signing-key` is always available
    /// regardless of this value.
    #[serde(default = "default_signing_key_rotation_days")]
    #[validate(range(min = 1))]
    pub signing_key_rotation_days: u32,

    /// Argon2id memory cost, in KiB, for `OAuth2Client` confidential-client
    /// secret hashing (ADR 0026 §5). A separate knob set from `[api_key]`
    /// so the two credential classes can be tuned independently.
    #[serde(default = "default_argon2_memory_kib")]
    #[validate(range(min = 1))]
    pub argon2_memory_kib: u32,

    /// Argon2id time cost (iterations) for client secret hashing.
    #[serde(default = "default_argon2_time_cost")]
    #[validate(range(min = 1))]
    pub argon2_time_cost: u32,

    /// Argon2id parallelism (lanes) for client secret hashing.
    #[serde(default = "default_argon2_parallelism")]
    #[validate(range(min = 1))]
    pub argon2_parallelism: u32,
}

fn default_signing_key_rotation_days() -> u32 {
    90
}

fn default_argon2_memory_kib() -> u32 {
    65536
}

fn default_argon2_time_cost() -> u32 {
    3
}

fn default_argon2_parallelism() -> u32 {
    4
}

impl Default for Oauth2Provider {
    fn default() -> Self {
        Self {
            signing_algorithm: SigningAlgorithm::default(),
            signing_key_rotation_days: default_signing_key_rotation_days(),
            argon2_memory_kib: default_argon2_memory_kib(),
            argon2_time_cost: default_argon2_time_cost(),
            argon2_parallelism: default_argon2_parallelism(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let cfg = Oauth2Provider::default();
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::Es256);
        assert_eq!(cfg.signing_key_rotation_days, 90);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_deserialize_defaults_when_empty() {
        let cfg: Oauth2Provider = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::Es256);
        assert_eq!(cfg.signing_key_rotation_days, 90);
    }

    #[test]
    fn test_deserialize_rs256_override() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"signing_algorithm": "RS256"}"#).unwrap();
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::Rs256);
        assert_eq!(cfg.signing_algorithm.to_string(), "RS256");
    }

    #[test]
    fn test_validate_rejects_zero_rotation_days() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"signing_key_rotation_days": 0}"#).unwrap();
        assert!(cfg.validate().is_err());
    }
}
