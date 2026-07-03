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
//! End-to-end SCIM ingress pipeline tests (ADR 0021 §3) driven over real
//! HTTP through `openstack_keystone::scim::router()`, complementing the
//! pure-function unit tests in `crates/core/src/api/api_key_auth.rs`
//! (which cover `resolve_client_ip`/`ip_allowed` in isolation but never
//! exercise the full extractor -- rate limiting, storage lookup, Argon2id
//! verification and mapping-engine hydration -- together over a real
//! request).
use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use eyre::Result;
use http_body_util::BodyExt;
use secrecy::ExposeSecret;
use tower::ServiceExt;
use tracing_test::traced_test;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::api_key::{crypto, token};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::api_key::ApiClientResource;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::*;
use openstack_keystone_core_types::resource::Domain;
use openstack_keystone_core_types::role::RoleRefBuilder;

use super::{create_api_key, sample_api_key_create};

use crate::common::{AsyncResourceGuard, get_state};
use crate::create_domain;

/// Generate a real `kscim_...` bearer token, persist its `ApiClientResource`
/// (with a genuine Argon2id `secret_hash`, unlike `sample_api_key_create`'s
/// placeholder), and wire a matching ADR 0020 mapping ruleset granting
/// `Authorization::Domain` on the key's own domain. Returns the plaintext
/// bearer token to present over HTTP, plus the resource guard -- which the
/// caller MUST keep bound to a variable for the HTTP calls' duration: an
/// unbound guard is dropped (and the key revoked by its cleanup `Drop` impl)
/// at the end of the creating statement.
async fn provision_working_api_key(
    state: &ServiceState,
    domain: &Domain,
    provider_id: &str,
    allowed_ips: Option<Vec<String>>,
) -> Result<(String, AsyncResourceGuard<ApiClientResource, ServiceState>)> {
    let generated = token::generate();
    let entropy = generated.entropy.expose_secret().to_string();
    let cfg = state.config_manager.config.read().await.api_key.clone();
    let secret_hash = crypto::hash_secret(&entropy, &cfg).await?;

    let mut create = sample_api_key_create(&domain.id, provider_id);
    create.lookup_hash = generated.lookup_hash;
    create.secret_hash = secret_hash;
    create.allowed_ips = allowed_ips;
    let guard = create_api_key(state, create).await?;

    let ruleset = MappingRuleSetCreate {
        mapping_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        domain_id: Some(domain.id.clone()),
        source: IdentitySource::ApiClient {
            provider_id: provider_id.to_string(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![MappingRule {
            name: "ingress-e2e-rule".into(),
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
                        .id("member")
                        .name("member")
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

fn whoami_request(
    domain_id: &str,
    token: &str,
    peer: SocketAddr,
    xff: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .uri(format!("/{domain_id}/whoami"))
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .extension(ConnectInfo(peer));
    if let Some(xff) = xff {
        builder = builder.header("x-forwarded-for", xff);
    }
    builder.body(Body::empty()).unwrap()
}

#[traced_test]
#[tokio::test]
async fn test_valid_key_authenticates_end_to_end() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let (token, _guard) = provision_working_api_key(&state, &domain, "provider-1", None).await?;

    let router = openstack_keystone::scim::router().with_state(state.clone());
    let peer: SocketAddr = "203.0.113.9:54321".parse()?;

    let response = router
        .oneshot(whoami_request(&domain.id, &token, peer, None))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body)?;
    assert!(json["scope"].as_str().unwrap().contains(&domain.id));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_wrong_secret_is_rejected() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let (_token, _guard) = provision_working_api_key(&state, &domain, "provider-1", None).await?;

    // Well-formed token, but never persisted -- lookup_hash won't match.
    let forged = token::generate();
    let forged_token = forged.token.expose_secret().to_string();

    let router = openstack_keystone::scim::router().with_state(state.clone());
    let peer: SocketAddr = "203.0.113.9:54321".parse()?;

    let response = router
        .oneshot(whoami_request(&domain.id, &forged_token, peer, None))
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_xff_spoof_through_trusted_proxy_is_rejected() -> Result<()> {
    // ADR 0021 §3 Step 2 / §6.E / Invariant 4: the rightmost-non-trusted
    // algorithm must resolve to the hop adjacent to the trusted proxy, not
    // whatever an attacker prepends as the leftmost XFF entry. The key only
    // allows 198.51.100.0/24; an attacker prepends that allowed range as the
    // leftmost entry hoping it gets picked, while their real (disallowed)
    // origin is the rightmost, proxy-adjacent hop.
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    {
        let mut cfg = state.config_manager.config.write().await;
        cfg.api_key.trusted_proxies = vec!["10.0.0.0/8".to_string()];
    }
    let (token, _guard) = provision_working_api_key(
        &state,
        &domain,
        "provider-1",
        Some(vec!["198.51.100.0/24".to_string()]),
    )
    .await?;

    let router = openstack_keystone::scim::router().with_state(state.clone());
    let trusted_peer: SocketAddr = "10.0.0.1:54321".parse()?;

    // Legitimate path: rightmost-non-trusted hop is the allowed range.
    let ok_response = router
        .clone()
        .oneshot(whoami_request(
            &domain.id,
            &token,
            trusted_peer,
            Some("198.51.100.9"),
        ))
        .await?;
    assert_eq!(ok_response.status(), StatusCode::OK);

    // Spoof attempt: attacker prepends the allowed range as bait, but their
    // real origin (rightmost, adjacent to the trusted proxy) is outside it.
    let spoofed_response = router
        .oneshot(whoami_request(
            &domain.id,
            &token,
            trusted_peer,
            Some("198.51.100.9, 9.9.9.9"),
        ))
        .await?;
    assert_eq!(spoofed_response.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_rate_limit_trips_after_burst_from_same_peer() -> Result<()> {
    // ADR 0021 §6.A: malformed tokens (no valid entropy) key the limiter on
    // source IP so brute-force garbage traffic can't dodge rate limiting.
    // Default quota is burst=10 / 60 per minute (crates/config/src/api_key.rs).
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let router = openstack_keystone::scim::router().with_state(state.clone());
    let peer: SocketAddr = "203.0.113.77:54321".parse()?;

    let mut saw_rate_limited = false;
    for _ in 0..15 {
        let response = router
            .clone()
            .oneshot(whoami_request(&domain.id, "not-a-real-token", peer, None))
            .await?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_rate_limited = true;
            break;
        }
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // Keep well within the 60/minute replenish window.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert!(
        saw_rate_limited,
        "expected TOO_MANY_REQUESTS within the burst window"
    );

    Ok(())
}
