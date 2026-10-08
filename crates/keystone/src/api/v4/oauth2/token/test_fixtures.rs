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
//! Shared fixtures for the per-grant unit tests.

use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use serde_json::Value;

use openstack_keystone_core_types::auth::AuthenticationResultBuilder;
use openstack_keystone_core_types::auth::{
    AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalIdentityInfoBuilder,
    PrincipalInfo, ScopeInfo,
};
use openstack_keystone_core_types::mapping::auth::MappingContext;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::resolution::DomainResolutionMode;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::rule::{IdentityBinding, MappingRule, MatchCriteria};
use openstack_keystone_core_types::mapping::ruleset::MappingRuleSet;
use openstack_keystone_core_types::oauth2_client as provider_types;
use openstack_keystone_core_types::role::RoleRef;
use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};

use crate::identity::MockIdentityProvider;
use crate::oauth2_key::MockOauth2KeyProvider;
use crate::resource::MockResourceProvider;

pub(in crate::api::v4::oauth2) async fn confidential_client() -> provider_types::OAuth2ClientResource
{
    let cfg = openstack_keystone_config::Oauth2Provider {
        argon2_memory_kib: 8,
        argon2_time_cost: 1,
        argon2_parallelism: 1,
        ..Default::default()
    };
    let hash = openstack_keystone_core::oauth2_client::crypto::hash_secret(
        &secrecy::SecretString::from("s3cr3t".to_string()),
        &cfg,
    )
    .await
    .unwrap();
    provider_types::OAuth2ClientResource {
        client_id: "client-1".into(),
        provider_id: "provider-1".into(),
        domain_id: "domain-1".into(),
        client_secret_hash: Some(hash),
        redirect_uris: vec![],
        token_endpoint_auth_method: "client_secret_basic".into(),
        grant_types: vec![provider_types::GrantType::ClientCredentials],
        require_pkce: false,
        allowed_scopes: vec!["openstack:api".into()],
        pre_authorized: false,
        enabled: true,
        claims_template: Default::default(),
        created_at: 0,
        updated_at: 0,
        deleted_at: None,
        name: String::new(),
        description: None,
        logo_uri: None,
        policy_uri: None,
        tos_uri: None,
        contacts: vec![],
    }
}

pub(super) fn matching_ruleset() -> MappingRuleSet {
    MappingRuleSet {
        mapping_id: "m1".to_string(),
        domain_id: Some("domain-1".to_string()),
        source: IdentitySource::OAuth2Client {
            provider_id: "provider-1".to_string(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![MappingRule {
            name: "always".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "client-1".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![Authorization::Domain {
                domain_id: "domain-1".to_string(),
                roles: vec![RoleRef {
                    id: "role-1".to_string(),
                    name: Some("member".to_string()),
                    domain_id: None,
                }],
            }],
            groups: vec![],
        }],
        ruleset_version: 7,
    }
}

pub(super) fn successful_auth_result() -> openstack_keystone_core_types::auth::AuthenticationResult
{
    AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Mapping(MappingContext {
            mapping_id: "m1".to_string(),
            matched_rule_name: "always".to_string(),
            virtual_user_id: "shadow-1".to_string(),
            is_system: false,
        }))
        .principal(PrincipalInfo {
            identity: IdentityInfo::Principal(
                PrincipalIdentityInfoBuilder::default()
                    .id("shadow-1")
                    .resolved_user_name("client-1")
                    .issuer("oauth2_client:provider-1")
                    .build()
                    .unwrap(),
            ),
        })
        .authorization(
            AuthzInfoBuilder::default()
                .scope(ScopeInfo::Domain(
                    openstack_keystone_core_types::resource::Domain {
                        id: "domain-1".to_string(),
                        name: String::new(),
                        description: None,
                        enabled: true,
                        extra: Default::default(),
                        options: Default::default(),
                    },
                ))
                .roles(vec![RoleRef {
                    id: "role-1".to_string(),
                    name: Some("member".to_string()),
                    domain_id: None,
                }])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

pub(super) fn ok_key_mock() -> MockOauth2KeyProvider {
    let mut mock = MockOauth2KeyProvider::default();
    mock.expect_active_signing_key()
        .returning(|_, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
    mock
}

pub(super) fn request(body: &str) -> Request<Body> {
    Request::builder()
        .uri("/domain-1/token")
        .method("POST")
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub(in crate::api::v4::oauth2) async fn json_body(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

pub(in crate::api::v4::oauth2) fn refresh_user(
    enabled: bool,
    domain_id: &str,
) -> openstack_keystone_core_types::identity::UserResponse {
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    UserResponseBuilder::default()
        .id("user-1")
        .domain_id(domain_id)
        .enabled(enabled)
        .name("user-1")
        .build()
        .unwrap()
}

pub(in crate::api::v4::oauth2) fn refresh_identity_mock(
    user: Option<openstack_keystone_core_types::identity::UserResponse>,
) -> MockIdentityProvider {
    let mut mock = MockIdentityProvider::default();
    mock.expect_get_user()
        .returning(move |_, _| Ok(user.clone()));
    mock
}

/// `enabled`: `Some(flag)` = domain exists, `None` = domain deleted.
pub(super) fn refresh_resource_mock(enabled: Option<bool>) -> MockResourceProvider {
    let mut mock = MockResourceProvider::default();
    mock.expect_get_domain().returning(move |_, _| {
        Ok(
            enabled.map(|enabled| openstack_keystone_core_types::resource::Domain {
                id: "domain-1".to_string(),
                name: "domain-1".to_string(),
                description: None,
                enabled,
                extra: Default::default(),
                options: Default::default(),
            }),
        )
    });
    mock
}

pub(in crate::api::v4::oauth2) async fn public_authz_code_client()
-> provider_types::OAuth2ClientResource {
    provider_types::OAuth2ClientResource {
        client_id: "client-1".into(),
        provider_id: "provider-1".into(),
        domain_id: "domain-1".into(),
        client_secret_hash: None,
        redirect_uris: vec!["https://rp.example.com/callback".into()],
        token_endpoint_auth_method: "none".into(),
        grant_types: vec![provider_types::GrantType::AuthorizationCode],
        require_pkce: true,
        allowed_scopes: vec!["openid".into()],
        pre_authorized: false,
        enabled: true,
        claims_template: Default::default(),
        created_at: 0,
        updated_at: 0,
        deleted_at: None,
        name: String::new(),
        description: None,
        logo_uri: None,
        policy_uri: None,
        tos_uri: None,
        contacts: vec![],
    }
}

/// Decode (without verifying) the claims of a compact JWS.
pub(in crate::api::v4::oauth2) fn jwt_claims(token: &str) -> Value {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}
