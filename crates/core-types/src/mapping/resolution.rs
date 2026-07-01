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
//! Domain resolution and identity source types.

use serde::{Deserialize, Serialize};

/// Domain resolution mode for the mapping ruleset.
///
/// Controls how `user_domain_id` templates are resolved at evaluation time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainResolutionMode {
    /// Locked to `mapping.domain_id`; claims templates in `user_domain_id` are
    /// rejected.
    Fixed,
    /// System-Admin Only: rules may override `mapping.domain_id` via claims
    /// templates.
    ClaimsOrMapping {
        /// Whitelist of domain IDs that claims-based interpolation may resolve
        /// to.
        allowed_domains: Vec<String>,
    },
    /// System-Admin Only: neither mapping nor provider is bound to a domain.
    ClaimsOnly {
        /// Whitelist of domain IDs that claims-based interpolation may resolve
        /// to.
        allowed_domains: Vec<String>,
    },
}

/// Identity source type.
///
/// Identifies which ingress provider instance the claims originated from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IdentitySource {
    /// OIDC/JWT federation identity provider.
    Federation {
        /// The federation IdP identifier.
        idp_id: String,
    },
    /// Kubernetes TokenReview authentication.
    K8s {
        /// The K8s cluster identifier.
        cluster_id: String,
    },
    /// SPIFFE SVID authentication.
    Spiffe {
        /// The SPIFFE trust domain.
        trust_domain: String,
    },
    /// API Key (SCIM ingress) machine identity authentication (ADR 0021).
    ApiClient {
        /// The API Key `provider_id` this ruleset is bound to.
        provider_id: String,
    },
}

impl IdentitySource {
    /// Returns a stable string representation for keyspace indexing.
    ///
    /// Format: `"<variant>:<id>"`, e.g. `"federation:okta-enterprise-idp"`,
    /// `"k8s:eks-prod-cluster-01"`, `"spiffe:prod.keystone.internal"`.
    pub fn to_string_key(&self) -> String {
        match self {
            Self::Federation { idp_id } => format!("federation:{idp_id}"),
            Self::K8s { cluster_id } => format!("k8s:{cluster_id}"),
            Self::Spiffe { trust_domain } => format!("spiffe:{trust_domain}"),
            Self::ApiClient { provider_id } => format!("api_client:{provider_id}"),
        }
    }
}
