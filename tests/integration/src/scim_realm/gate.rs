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
//! End-to-end Realm Activation Gate tests (ADR 0024 §2.B), driven over real
//! HTTP through the [`ScimRealmAuth`] extractor, complementing
//! `scim_realm::show`'s pure provider-level `get_realm` coverage.
//!
//! [`ScimRealmAuth`] is only ever mounted on policy-checked handlers
//! (`scim::user`/`scim::group`) in the real router, but this test suite's
//! shared `common::get_state()` wires a fixed, unconfigurable
//! `MockPolicy::default()` with no expectations set -- calling into any of
//! those handlers here would panic on the first `policy_enforcer.enforce`
//! call. So this test mounts the extractor on a bespoke, policy-free probe
//! route instead: everything upstream of the handler body (rate limiting,
//! Argon2id verification, mapping-engine hydration, the domain-scope check,
//! and the Realm Activation Gate itself) is the real, unmodified extractor
//! code: only the terminal handler body is a stand-in.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router, body::Body};
use eyre::Result;
use http_body_util::BodyExt;
use secrecy::ExposeSecret;
use serde_json::json;
use tower::ServiceExt;
use tracing_test::traced_test;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::api_key::{crypto, token};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::api_key::ApiClientResource;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::*;
use openstack_keystone_core_types::resource::Domain;
use openstack_keystone_core_types::role::RoleRefBuilder;

use super::{create_realm, sample_realm_create};

use crate::common::{AsyncResourceGuard, get_state};
use crate::{create_domain, create_role};

/// Mirrors `api_key::ingress::provision_working_api_key` (bearer token +
/// domain-scoped mapping ruleset), duplicated locally rather than made
/// `pub` from that module since the two suites otherwise have no shared
/// dependency.
async fn provision_domain_scoped_api_key(
    state: &ServiceState,
    domain: &Domain,
    provider_id: &str,
) -> Result<(String, AsyncResourceGuard<ApiClientResource, ServiceState>)> {
    let generated = token::generate();
    let entropy = generated.entropy.expose_secret().to_string();
    let cfg = state.config_manager.config.read().await.api_key.clone();
    let secret_hash = crypto::hash_secret(&entropy, &cfg).await?;

    let mut create = crate::api_key::sample_api_key_create(&domain.id, provider_id);
    create.lookup_hash = generated.lookup_hash;
    create.secret_hash = secret_hash;
    let guard = crate::api_key::create_api_key(state, create).await?;

    let member_role = create_role!(state, "member")?;
    let ruleset = MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::ApiClient {
            provider_id: provider_id.to_string(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![MappingRule {
            name: "gate-e2e-rule".into(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "${claims.api_client.client_id}".into(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![Authorization::Domain {
                domain_id: domain.id.clone(),
                roles: vec![
                    RoleRefBuilder::default()
                        .id(member_role.id.clone())
                        .name(member_role.name.clone())
                        .build()
                        .unwrap(),
                ],
            }],
            groups: Vec::new(),
        }],
    };
    state
        .provider
        .get_mapping_provider()
        .create_ruleset(&ExecutionContext::internal(state), ruleset)
        .await?;

    Ok((generated.token.expose_secret().to_string(), guard))
}

/// A trivial handler mounted exclusively behind [`ScimRealmAuth`]: reaching
/// this body at all proves the gate upstream of it passed.
async fn probe(ScimRealmAuth { realm, .. }: ScimRealmAuth) -> Json<serde_json::Value> {
    Json(json!({ "provider_id": realm.provider_id }))
}

fn probe_router() -> Router<ServiceState> {
    Router::new().route("/{domain_id}/probe", get(probe))
}

fn probe_request(domain_id: &str, token: &str, peer: SocketAddr) -> Request<Body> {
    Request::builder()
        .uri(format!("/{domain_id}/probe"))
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .extension(ConnectInfo(peer))
        .body(Body::empty())
        .unwrap()
}

#[traced_test]
#[tokio::test]
async fn test_gate_rejects_when_no_realm_registered() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let (token, _guard) = provision_domain_scoped_api_key(&state, &domain, "provider-1").await?;

    // No `create_realm` call -- the coordinate has never been registered.
    let router = probe_router().with_state(state.clone());
    let peer: SocketAddr = "203.0.113.9:54321".parse()?;

    let response = router
        .oneshot(probe_request(&domain.id, &token, peer))
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_gate_rejects_when_realm_disabled() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let (token, _guard) = provision_domain_scoped_api_key(&state, &domain, "provider-1").await?;

    let realm = create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;
    state
        .provider
        .get_scim_realm_provider()
        .update_realm(
            &ExecutionContext::internal(&state),
            &realm.domain_id,
            &realm.provider_id,
            openstack_keystone_core_types::scim::ScimRealmResourceUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    let router = probe_router().with_state(state.clone());
    let peer: SocketAddr = "203.0.113.9:54321".parse()?;

    let response = router
        .oneshot(probe_request(&domain.id, &token, peer))
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_gate_admits_when_realm_enabled() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let (token, _guard) = provision_domain_scoped_api_key(&state, &domain, "provider-1").await?;
    create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;

    let router = probe_router().with_state(state.clone());
    let peer: SocketAddr = "203.0.113.9:54321".parse()?;

    let response = router
        .oneshot(probe_request(&domain.id, &token, peer))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(json["provider_id"], "provider-1");
    Ok(())
}
