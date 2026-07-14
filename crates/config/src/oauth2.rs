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

    /// Lifetime, in minutes, of an `access_token` minted at `/token` (ADR
    /// 0026 §4).
    #[serde(default = "default_access_token_lifetime_minutes")]
    #[validate(range(min = 1))]
    pub access_token_lifetime_minutes: u32,

    /// Maximum burst of `/token` requests accepted instantaneously, per
    /// rate-limit key (the presented, unverified `client_id`), before
    /// throttling kicks in (ADR 0026 §7.A). A separate pool from
    /// `[api_key] rate_limit_burst_size` so SCIM ingress and OAuth2 ingress
    /// have independently tunable blast radii.
    #[serde(default = "default_token_rate_limit_burst_size")]
    #[validate(range(min = 1))]
    pub token_rate_limit_burst_size: u32,

    /// Sustained `/token` requests allowed per minute, per rate-limit key,
    /// once the burst allowance is exhausted.
    #[serde(default = "default_token_rate_limit_replenish_per_minute")]
    #[validate(range(min = 1))]
    pub token_rate_limit_replenish_per_minute: u32,

    /// Lifetime, in minutes, of an `id_token` minted at `/token` for the
    /// `authorization_code` grant (ADR 0026 §4). Mirrors
    /// `access_token_lifetime_minutes` per the ADR's default, but kept as
    /// an independent knob since the two tokens serve different consumers.
    #[serde(default = "default_id_token_lifetime_minutes")]
    #[validate(range(min = 1))]
    pub id_token_lifetime_minutes: u32,

    /// Lifetime, in seconds, of an authorization code minted at
    /// `/authorize` before it must be redeemed at `/token` (ADR 0026 §10
    /// Phase 4). Single-use regardless of this TTL.
    #[serde(default = "default_authorization_code_lifetime_seconds")]
    #[validate(range(min = 1))]
    pub authorization_code_lifetime_seconds: u32,

    /// Idle lifetime, in days, of a `refresh_token` family before it must
    /// be re-established via a fresh `authorization_code` grant (ADR 0026
    /// §2). Reset on each successful rotation.
    #[serde(default = "default_refresh_token_lifetime_days")]
    #[validate(range(min = 1))]
    pub refresh_token_lifetime_days: u32,

    /// Grace period, in minutes, during which a `refresh_token` presented
    /// a second time is tolerated as a benign multi-device race rather
    /// than treated as a breach (ADR 0026 §9). `0` disables the grace
    /// period entirely (tightest breach detection).
    #[serde(default = "default_refresh_token_reuse_grace_minutes")]
    #[validate(range(max = 30))]
    pub refresh_token_reuse_grace_minutes: u32,

    /// Lifetime, in minutes, of the pre-authentication browser session
    /// created at `GET /authorize` -- bounds how long a user has to
    /// complete the login + consent sequence before it expires (ADR 0026
    /// §10 Phase 4, §8).
    #[serde(default = "default_pre_auth_session_lifetime_minutes")]
    #[validate(range(min = 1))]
    pub pre_auth_session_lifetime_minutes: u32,
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

fn default_access_token_lifetime_minutes() -> u32 {
    15
}

fn default_token_rate_limit_burst_size() -> u32 {
    10
}

fn default_token_rate_limit_replenish_per_minute() -> u32 {
    60
}

fn default_id_token_lifetime_minutes() -> u32 {
    15
}

fn default_authorization_code_lifetime_seconds() -> u32 {
    60
}

fn default_refresh_token_lifetime_days() -> u32 {
    30
}

fn default_refresh_token_reuse_grace_minutes() -> u32 {
    10
}

fn default_pre_auth_session_lifetime_minutes() -> u32 {
    10
}

impl Default for Oauth2Provider {
    fn default() -> Self {
        Self {
            signing_algorithm: SigningAlgorithm::default(),
            signing_key_rotation_days: default_signing_key_rotation_days(),
            argon2_memory_kib: default_argon2_memory_kib(),
            argon2_time_cost: default_argon2_time_cost(),
            argon2_parallelism: default_argon2_parallelism(),
            access_token_lifetime_minutes: default_access_token_lifetime_minutes(),
            token_rate_limit_burst_size: default_token_rate_limit_burst_size(),
            token_rate_limit_replenish_per_minute: default_token_rate_limit_replenish_per_minute(),
            id_token_lifetime_minutes: default_id_token_lifetime_minutes(),
            authorization_code_lifetime_seconds: default_authorization_code_lifetime_seconds(),
            refresh_token_lifetime_days: default_refresh_token_lifetime_days(),
            refresh_token_reuse_grace_minutes: default_refresh_token_reuse_grace_minutes(),
            pre_auth_session_lifetime_minutes: default_pre_auth_session_lifetime_minutes(),
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
        assert_eq!(cfg.access_token_lifetime_minutes, 15);
        assert_eq!(cfg.token_rate_limit_burst_size, 10);
        assert_eq!(cfg.token_rate_limit_replenish_per_minute, 60);
        assert_eq!(cfg.id_token_lifetime_minutes, 15);
        assert_eq!(cfg.authorization_code_lifetime_seconds, 60);
        assert_eq!(cfg.refresh_token_lifetime_days, 30);
        assert_eq!(cfg.refresh_token_reuse_grace_minutes, 10);
        assert_eq!(cfg.pre_auth_session_lifetime_minutes, 10);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_refresh_token_reuse_grace_minutes_over_30() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"refresh_token_reuse_grace_minutes": 31}"#).unwrap();
        assert!(cfg.validate().is_err());
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
