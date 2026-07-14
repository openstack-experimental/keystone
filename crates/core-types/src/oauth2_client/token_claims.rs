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
//! # OAuth2 outbound access token claims (ADR 0026 §4)
//!
//! Phase 3 (`client_credentials`) scope only: [`OpenStackAccessTokenClaims`]
//! is the authorization claim set consumed by downstream OpenStack services,
//! issued unconditionally on the `client_credentials` grant (the client
//! itself is always the OpenStack-facing subject there). `IdTokenClaims` and
//! `OidcAccessTokenClaims` (the RP-facing identity tracks) are Phase 4's
//! `authorization_code` deliverable, not defined here.
use crate::role::RoleRef;
use serde::{Deserialize, Serialize};

/// Authorization claims consumed by downstream OpenStack services (ADR 0026
/// §4). Issued as the `access_token` on `client_credentials` grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStackAccessTokenClaims {
    /// Issuer URL bound to the domain: `/v4/oauth2/{domain_id}`.
    pub iss: String,
    /// Keystone user_id (the ephemeral shadow `user_id` for
    /// `client_credentials`).
    pub sub: String,
    /// Domain-bound audience: `"openstack-apis:{domain_id}"` (ADR 0026 §5,
    /// "Domain Key Isolation and `aud` Binding").
    pub aud: String,
    /// The registered `OAuth2Client.client_id` that initiated the grant.
    pub client_id: String,
    /// Expiration, Unix seconds.
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Not-before, always equal to `iat` (defense-in-depth per the Token
    /// Replay Model, ADR 0026 §4).
    pub nbf: i64,
    /// Unique token UUID for revocation mapping / audit trail.
    pub jti: String,
    /// Policy rule state anchor: the matched `MappingRuleSet.ruleset_version`.
    pub keystone_ruleset_version: u128,
    /// Authentication methods references (mirrors `id_token` for
    /// downstream). Always `["client_credentials"]` for this grant.
    pub amr: Vec<String>,
    /// Fixed `"access"` (OIDC Core §3.1.3.4 analogue); downstream middleware
    /// checks this alongside `openstack_context` presence.
    pub token_use: String,

    /// Delegated auth context. `client_credentials` only ever produces
    /// `Plain` in v1 — the three delegated variants are forward-declared so
    /// the type already matches what a future Token Exchange grant (ADR
    /// 0026 §12) will populate.
    pub delegation_context: DelegationContext,

    #[serde(flatten)]
    pub openstack_context: OpenStackContext,
}

/// Delegated auth context: structurally enforces that a plain auth method
/// cannot carry a `delegated_project_id` (security.md I2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "auth_method", rename_all = "snake_case")]
pub enum DelegationContext {
    /// No delegation: the authenticated principal is the token subject
    /// directly. The only variant `client_credentials` produces in v1.
    Plain,
    /// Delegated via a trust.
    Trust {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
    /// Delegated via an application credential.
    AppCred {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
    /// Delegated via an EC2 credential.
    Ec2 {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
}

/// OpenStack identity/authorization context embedded in an
/// [`OpenStackAccessTokenClaims`] via `#[serde(flatten)]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStackContext {
    /// Core user UUID or virtual (shadow) identity string.
    pub user_id: String,
    /// Normalized, case-folded alphanumeric principal name.
    pub user_name: String,
    /// Home domain UUID of the identity itself, distinct from the scope
    /// below.
    pub user_domain_id: Option<String>,
    #[serde(flatten)]
    pub scope: OpenStackScope,
    /// Effective role names evaluated at token issuance.
    pub roles: Vec<String>,
}

/// The token's authorization scope. Mirrors
/// [`crate::mapping::authorization::Authorization`]'s shape (`Project`/
/// `Domain`/`System` variants, same `system_id` field name) but is a
/// distinct, outbound wire type: it additionally carries `Unscoped`, and is
/// tagged `scope_type` (the ADR 0026 §4 outbound claim name) rather than the
/// internal mapping type's `type` tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope_type", rename_all = "snake_case")]
pub enum OpenStackScope {
    /// Project-scoped authorization.
    Project {
        /// Project UUID.
        project_id: String,
        /// Domain UUID the project belongs to.
        project_domain_id: String,
        /// Roles granted on this scope.
        roles: Vec<RoleRef>,
    },
    /// Domain-scoped authorization.
    Domain {
        /// Domain UUID.
        domain_id: String,
        /// Roles granted on this scope.
        roles: Vec<RoleRef>,
    },
    /// System-scoped authorization.
    System {
        /// System scope identifier (e.g. `"all"`).
        system_id: String,
        /// Roles granted on this scope.
        roles: Vec<RoleRef>,
    },
    /// No authorization scope.
    Unscoped,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_delegation_context_serializes_without_project_id() {
        let value = serde_json::to_value(DelegationContext::Plain).unwrap();
        assert_eq!(value, serde_json::json!({"auth_method": "plain"}));
    }

    #[test]
    fn test_openstack_scope_project_tag_is_scope_type() {
        let scope = OpenStackScope::Project {
            project_id: "p1".to_string(),
            project_domain_id: "d1".to_string(),
            roles: vec![],
        };
        let value = serde_json::to_value(&scope).unwrap();
        assert_eq!(value["scope_type"], "project");
        assert_eq!(value["project_id"], "p1");
    }

    #[test]
    fn test_openstack_access_token_claims_flattens_context() {
        let claims = OpenStackAccessTokenClaims {
            iss: "https://ks.example/v4/oauth2/d1".to_string(),
            sub: "shadow-user".to_string(),
            aud: "openstack-apis:d1".to_string(),
            client_id: "client-1".to_string(),
            exp: 1000,
            iat: 900,
            nbf: 900,
            jti: "jti-1".to_string(),
            keystone_ruleset_version: 42,
            amr: vec!["client_credentials".to_string()],
            token_use: "access".to_string(),
            delegation_context: DelegationContext::Plain,
            openstack_context: OpenStackContext {
                user_id: "shadow-user".to_string(),
                user_name: "client-1".to_string(),
                user_domain_id: None,
                scope: OpenStackScope::Domain {
                    domain_id: "d1".to_string(),
                    roles: vec![],
                },
                roles: vec!["member".to_string()],
            },
        };
        let value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["scope_type"], "domain");
        assert_eq!(value["domain_id"], "d1");
        assert_eq!(value["user_id"], "shadow-user");
        assert!(value.get("openstack_context").is_none());
    }
}
