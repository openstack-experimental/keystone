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
//! Real-HTTP SCIM `Users` cross-realm IDOR test (ADR 0024 §3.C Ownership
//! Fencing), repeating `scim::user::show::test_show_not_owned_returns_404`'s
//! assertion against the real [`ScimRealmAuth`] extractor and real
//! `scim-driver-raft` backend instead of a mock -- the single highest-value
//! security property this ADR introduces was previously only proven at the
//! mocked-handler level.
//!
//! Unlike `scim_realm::gate`, this drives the real `scim::user` handlers
//! (which call `policy_enforcer.enforce`), so it cannot use the
//! policy-free probe route pattern: `common::get_state()`'s
//! `MockPolicy::default()` has no expectations set and panics on the first
//! `enforce()` call. [`get_state_allow_all`] swaps in a permissive mock
//! instead. Live OPA policy evaluation is exercised separately by the
//! `tests/api` `--profile api` suite (real OPA, not this crate's concern).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use eyre::Result;
use http_body_util::BodyExt;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_test::traced_test;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::api_key::{crypto, token};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::{MockPolicy, PolicyEvaluationResult};
use openstack_keystone_core_types::api_key::ApiClientResource;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::*;
use openstack_keystone_core_types::resource::Domain;
use openstack_keystone_core_types::role::RoleRefBuilder;

use super::{create_realm, sample_realm_create};

use crate::common::{AsyncResourceGuard, get_state};
use crate::{create_domain, create_role};

/// `common::get_state()` with the policy enforcer swapped for a permissive
/// mock. Safe to mutate via `Arc::get_mut` because nothing has cloned the
/// `Arc` yet at this point.
async fn get_state_allow_all() -> Result<(ServiceState, TempDir)> {
    let (mut state, tmp) = get_state().await?;

    let mut policy = MockPolicy::default();
    policy
        .expect_enforce()
        .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
    policy.expect_health_check().returning(|| Ok(()));

    Arc::get_mut(&mut state)
        .expect("sole owner of the Arc immediately after get_state() returns")
        .policy_enforcer = Arc::new(policy);

    Ok((state, tmp))
}

/// Mirrors `scim_realm::gate::provision_domain_scoped_api_key`, duplicated
/// locally per that module's own precedent (the two suites share no
/// dependency otherwise).
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
            name: "scim-ingress-e2e-rule".into(),
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

fn scim_request(
    method: &str,
    domain_id: &str,
    path: &str,
    token: &str,
    peer: SocketAddr,
    body: Option<Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .uri(format!("/{domain_id}{path}"))
        .method(method)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(peer));
    match body {
        Some(body) => builder.body(Body::from(body.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// A user provisioned under realm A must be invisible (`404`, not `403` or
/// `200`) to a request authenticated under realm B's own token, even though
/// both realms share the same domain and the same underlying identity
/// backend -- the Ownership Fencing Algorithm (§3.C) keys visibility on
/// `(domain_id, provider_id)`, not on the identity backend's own view of
/// the user.
#[traced_test]
#[tokio::test]
async fn test_cross_realm_show_returns_404() -> Result<()> {
    let (state, _tmp) = get_state_allow_all().await?;
    let domain = create_domain!(state)?;
    let peer: SocketAddr = "203.0.113.10:54321".parse()?;

    let (token_a, _guard_a) = provision_domain_scoped_api_key(&state, &domain, "realm-a").await?;
    let (token_b, _guard_b) = provision_domain_scoped_api_key(&state, &domain, "realm-b").await?;
    create_realm(&state, sample_realm_create(&domain.id, "realm-a")).await?;
    create_realm(&state, sample_realm_create(&domain.id, "realm-b")).await?;

    let router = openstack_keystone::scim::router().with_state(state.clone());

    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "externalId": "alice-ext",
        "active": true
    });
    let response = router
        .clone()
        .oneshot(scim_request(
            "POST",
            &domain.id,
            "/Users",
            &token_a,
            peer,
            Some(create_body),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await?.to_bytes();
    let created: Value = serde_json::from_slice(&body)?;
    let user_id = created["id"].as_str().expect("created user has an id");

    // Realm B, a distinct realm in the same domain, must not be able to
    // see realm A's user by guessing/reusing its id.
    let response = router
        .clone()
        .oneshot(scim_request(
            "GET",
            &domain.id,
            &format!("/Users/{user_id}"),
            &token_b,
            peer,
            None,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Sanity check: realm A can still see its own user -- rules out a
    // trivial "everything 404s" false positive above.
    let response = router
        .oneshot(scim_request(
            "GET",
            &domain.id,
            &format!("/Users/{user_id}"),
            &token_a,
            peer,
            None,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    Ok(())
}

/// The same fencing must hold for mutation, not just read: realm B must not
/// be able to deprovision (or otherwise touch) realm A's user via `DELETE`.
#[traced_test]
#[tokio::test]
async fn test_cross_realm_delete_returns_404_and_does_not_deprovision() -> Result<()> {
    let (state, _tmp) = get_state_allow_all().await?;
    let domain = create_domain!(state)?;
    let peer: SocketAddr = "203.0.113.11:54321".parse()?;

    let (token_a, _guard_a) = provision_domain_scoped_api_key(&state, &domain, "realm-a").await?;
    let (token_b, _guard_b) = provision_domain_scoped_api_key(&state, &domain, "realm-b").await?;
    create_realm(&state, sample_realm_create(&domain.id, "realm-a")).await?;
    create_realm(&state, sample_realm_create(&domain.id, "realm-b")).await?;

    let router = openstack_keystone::scim::router().with_state(state.clone());

    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bob",
        "externalId": "bob-ext",
        "active": true
    });
    let response = router
        .clone()
        .oneshot(scim_request(
            "POST",
            &domain.id,
            "/Users",
            &token_a,
            peer,
            Some(create_body),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await?.to_bytes();
    let created: Value = serde_json::from_slice(&body)?;
    let user_id = created["id"].as_str().expect("created user has an id");

    let response = router
        .clone()
        .oneshot(scim_request(
            "DELETE",
            &domain.id,
            &format!("/Users/{user_id}"),
            &token_b,
            peer,
            None,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The user must still be intact and visible under its real owning
    // realm -- realm B's rejected delete attempt must not have deprovisioned
    // it.
    let response = router
        .oneshot(scim_request(
            "GET",
            &domain.id,
            &format!("/Users/{user_id}"),
            &token_a,
            peer,
            None,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    let shown: Value = serde_json::from_slice(&body)?;
    assert_eq!(shown["active"], true);

    Ok(())
}
