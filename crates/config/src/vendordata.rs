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
//! # Vendor data JWT provider configuration (SPIRE integration plan, Phase 2)
//!
//! `POST /v4/vendordata` signs a short-lived attestation JWT for a booting
//! VM instance, using a signing key wholly independent from `[oauth2]`'s
//! (see `doc/src/adr/0032-vendor-data-jwt.md`, "Attestation key isolation").
use std::path::PathBuf;

use secrecy::SecretString;
use serde::Deserialize;

use crate::SigningAlgorithm;

/// Vendor data JWT provider.
#[derive(Debug, Deserialize, Clone)]
pub struct VendordataProvider {
    /// Cross-check the calling compute host and the request's
    /// `project_id`/`instance_id` against Nova before signing (Fix 1,
    /// "Ownership verification"). Disabling this trusts the compute host's
    /// claims unverified -- a materially weaker trust posture, documented
    /// as an explicit opt-out, not the default.
    #[serde(default = "default_verify_placement")]
    pub verify_placement: bool,

    /// Path to the attestation signing keypair repository. One
    /// subdirectory per domain, in the same on-disk shape as
    /// `[jws_tokens] key_repository`, but a wholly separate directory tree
    /// -- this key must never be shared with any OAuth2/JWS signing key.
    #[serde(default = "default_key_repository")]
    pub key_repository: PathBuf,

    /// Signing algorithm for the attestation key. Independent from
    /// `[oauth2] signing_algorithm` by design (separate key, separate
    /// rotation cadence).
    #[serde(default)]
    pub signing_algorithm: SigningAlgorithm,

    /// Default `ttl_seconds` for an issued attestation JWT when the request
    /// does not specify one. Accepted range is 60-600 seconds regardless of
    /// what the request asks for.
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: u32,

    /// Base URL of the Nova API used for the ownership cross-check (e.g.
    /// `http://nova-api:8774/v2.1`). Required when `verify_placement` is
    /// `true`; if unset, the ownership check fails closed with `503`.
    #[serde(default)]
    pub nova_api_base_url: Option<String>,

    /// Admin/system-scoped token used to authenticate to Nova for the
    /// ownership cross-check (`server.hypervisor_hostname` is gated behind
    /// `os-extended-server-attributes`, normally admin-only).
    ///
    /// This is a known simplification for Phase 2: a static, operator
    /// provisioned token rather than a dynamically minted, auto-refreshed
    /// system-scoped service credential. Treat it with the same operational
    /// rigor as a signing key (see the plan's Security Considerations
    /// table) and rotate it manually until a follow-up phase automates
    /// credential issuance.
    #[serde(default)]
    pub nova_admin_token: Option<SecretString>,

    /// Timeout for the Nova ownership-check HTTP call, in seconds. Kept
    /// tight (ADR default 2s) to bound the keystone-rs <-> nova-api request
    /// cycle and reduce the auth-deadlock risk documented in the plan
    /// ("Auth deadlock prevention").
    #[serde(default = "default_nova_request_timeout_seconds")]
    pub nova_request_timeout_seconds: u64,
}

fn default_verify_placement() -> bool {
    true
}

fn default_key_repository() -> PathBuf {
    PathBuf::from("/etc/keystone/spiffe-attestation-keys/")
}

fn default_ttl_seconds() -> u32 {
    300
}

fn default_nova_request_timeout_seconds() -> u64 {
    2
}

impl Default for VendordataProvider {
    fn default() -> Self {
        Self {
            verify_placement: default_verify_placement(),
            key_repository: default_key_repository(),
            signing_algorithm: SigningAlgorithm::default(),
            default_ttl_seconds: default_ttl_seconds(),
            nova_api_base_url: None,
            nova_admin_token: None,
            nova_request_timeout_seconds: default_nova_request_timeout_seconds(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let cfg = VendordataProvider::default();
        assert!(cfg.verify_placement);
        assert_eq!(
            cfg.key_repository,
            PathBuf::from("/etc/keystone/spiffe-attestation-keys/")
        );
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::Es256);
        assert_eq!(cfg.default_ttl_seconds, 300);
        assert_eq!(cfg.nova_request_timeout_seconds, 2);
        assert!(cfg.nova_api_base_url.is_none());
    }

    #[test]
    fn test_deserialize_defaults_when_empty() {
        let cfg: VendordataProvider = serde_json::from_str("{}").unwrap();
        assert!(cfg.verify_placement);
        assert_eq!(cfg.default_ttl_seconds, 300);
    }

    #[test]
    fn test_deserialize_disables_verify_placement() {
        let cfg: VendordataProvider =
            serde_json::from_str(r#"{"verify_placement": false}"#).unwrap();
        assert!(!cfg.verify_placement);
    }
}
