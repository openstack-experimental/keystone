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
//! Mapping engine authentication types.
//!
//! Request and context types for `authenticate_by_mapping`.

use std::collections::HashMap;

use super::resolution::IdentitySource;

/// Request from an ingress adapter to authenticate via the mapping engine.
///
/// The ingress adapter validates cryptographic claims (signature, CRL,
/// TokenReview, etc.) and produces the flattened claims map and canonical
/// workload identifier. The mapping engine consumes this request, evaluates
/// rulesets, persists the shadow registry record, and emits the
/// [`AuthenticationResult`](crate::auth::AuthenticationResult).
#[derive(Debug, Clone)]
pub struct MappingAuthRequest {
    /// Owning domain boundary. `None` for global system mappings.
    pub domain_id: Option<String>,

    /// Identifies the ingress provider instance.
    pub source: IdentitySource,

    /// Canonical workload identifier derived by the ingress adapter per ADR
    /// §11.2 (e.g., `sub` for OIDC, `<sa>:<ns>` for K8s).
    pub unique_workload_id: String,

    /// Flattened claims map from the ingress adapter.
    pub claims: HashMap<String, Vec<String>>,
}

/// Authentication context for a mapped virtual user.
///
/// Carries the mapping-specific metadata required for shadow registry lookup
/// during token verification (TOCTOU ruleset-version check, rule existence
/// validation).
#[derive(Debug, Clone, PartialEq)]
pub struct MappingContext {
    /// The mapping ruleset that produced the match.
    pub mapping_id: String,

    /// The rule that matched.
    pub matched_rule_name: String,

    /// Virtual user shadow record ID.
    pub virtual_user_id: String,
}
