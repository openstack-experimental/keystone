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
//! `client_credentials` grant (RFC 6749 §4.4, ADR 0026 §5, §7.A).

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cadf::Outcome;
use cadf::OutcomeReason;
use governor::clock::Clock as _;

use openstack_keystone_core::oauth2_client::hydrate_client_credentials_context;
use openstack_keystone_core::oauth2_client::{build_access_token_claims, crypto};
use openstack_keystone_core_types::oauth2_client::GrantType;
use openstack_keystone_key_repository::asymmetric::{jwt_algorithm, to_encoding_key};

use crate::audit::{
    build_initiator_from_vsc, build_initiator_unknown, emit_perimeter_authenticate_event,
};
use crate::keystone::ServiceState;

use super::common::*;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// `client_credentials` machine-to-machine grant (ADR 0026 §5, §7.A).
pub(super) async fn handle_client_credentials_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, client_secret)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };

    // Step 1 (ADR 0026 §7.A "Pre-Hash Enforcement"): rate limit on the raw,
    // unverified client_id string, before any storage lookup or Argon2id
    // verification.
    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let exec = openstack_keystone_core::auth::ExecutionContext::internal(state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            Oauth2TokenError::internal("client lookup failed")
        })?;

    let Some(client) = client.filter(|c| c.domain_id == domain_id) else {
        // Enumeration defense (ADR 0026 §7.A / mirrors ADR 0021 Invariant
        // 7): burn the same Argon2id cost a real "found but wrong secret"
        // verification would, so a missing client_id can't be distinguished
        // from a wrong secret by response latency alone. This does NOT mask
        // the DB lookup's own variable timing (unknown client_id: fast
        // reject; known client_id: lookup + Argon2id) -- that gap is
        // accepted as defense-in-depth residual, bounded by the pre-hash
        // rate limiter above (keyed on raw client_id, checked before this
        // DB query), mirroring ADR 0021's API key posture.
        let _ = crypto::generate_dummy_hash(oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };

    if !client.enabled || client.deleted_at.is_some() {
        let _ = crypto::generate_dummy_hash(oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    // RFC 6749 §4.4 requires a confidential client for client_credentials --
    // a public client has no secret to verify at all.
    let Some(secret_hash) = client.client_secret_hash.as_deref() else {
        let _ = crypto::generate_dummy_hash(oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };
    let Some(presented_secret) = client_secret else {
        let _ = crypto::generate_dummy_hash(oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };

    let verified = crypto::verify_secret(&presented_secret, secret_hash)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client secret argon2 verification errored");
            Oauth2TokenError::internal("client authentication failed")
        })?;
    if !verified {
        emit_perimeter_authenticate_event(
            &state.audit_dispatcher,
            correlation_id,
            build_initiator_unknown(),
            Outcome::Failure,
            Some(OutcomeReason::literal("ClientAuthenticationFailed")),
        );
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    // Enumeration defense (V8a): checked only after a verified secret, so an
    // existing-but-unauthorized client can't be distinguished from an
    // unknown/wrong-secret one by response shape alone -- both require
    // proving possession of a valid secret first.
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the client_credentials grant",
        ));
    }

    // Scope Validation (ADR 0026 §4): requested scope must be a subset of
    // `allowed_scopes`, reject-outright, never silently narrowed. Omitted
    // scope defaults to the client's full `allowed_scopes`.
    let granted_scope: Vec<String> = match &form.scope {
        Some(requested) => {
            let requested: Vec<String> = requested.split_whitespace().map(str::to_string).collect();
            if requested
                .iter()
                .any(|s| !client.allowed_scopes.iter().any(|allowed| allowed == s))
            {
                return Err(Oauth2TokenError::invalid_scope(
                    "requested scope exceeds the client's allowed_scopes",
                ));
            }
            requested
        }
        None => client.allowed_scopes.clone(),
    };

    let (vsc, ruleset_version) = hydrate_client_credentials_context(state, &client)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client_credentials mapping ingress failed");
            Oauth2TokenError::invalid_client("client is not authorized for any scope")
        })?;

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{}", client.domain_id);
    let now = chrono::Utc::now().timestamp();
    let lifetime_seconds = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let exp = now + lifetime_seconds;
    let jti = uuid::Uuid::new_v4().to_string();

    let claims = build_access_token_claims(&client, &vsc, &issuer, jti, ruleset_version, now, exp)
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 access token claim construction failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let signing_key = state
        .provider
        .get_oauth2_key_provider()
        .active_signing_key(state, &client.domain_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 signing key lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let encoding_key = to_encoding_key(&signing_key).map_err(|e| {
        tracing::warn!(error = %e, "oauth2 signing key conversion failed");
        Oauth2TokenError::internal("token issuance failed")
    })?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(signing_key.algorithm));
    header.kid = Some(openstack_keystone_key_repository::asymmetric::derive_kid(
        &signing_key.public_key_der,
    ));
    let access_token = jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|e| {
        tracing::warn!(error = %e, "oauth2 access token signing failed");
        Oauth2TokenError::internal("token issuance failed")
    })?;

    emit_perimeter_authenticate_event(
        &state.audit_dispatcher,
        correlation_id,
        build_initiator_from_vsc(&vsc),
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: lifetime_seconds,
        scope: granted_scope.join(" "),
        // `client_credentials` never issues an `id_token` (no RP identity
        // display surface) or a `refresh_token` (the client re-authenticates
        // with its own credentials on every mint instead of rotating one).
        id_token: None,
        refresh_token: None,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use cadf::Outcome;

    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{extract::ConnectInfo, http::StatusCode};

    use sea_orm::DatabaseConnection;

    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;

    use openstack_keystone_core_types::oauth2_client as provider_types;

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        confidential_client, json_body, matching_ruleset, ok_key_mock, request,
        successful_auth_result,
    };

    use crate::mapping::MockMappingProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;

    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    async fn test_unknown_client_id_is_invalid_client() {
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=unknown&client_secret=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_client_without_client_credentials_grant_is_unauthorized_client() {
        let mut client = confidential_client().await;
        client.grant_types = vec![provider_types::GrantType::AuthorizationCode];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "unauthorized_client");
    }

    #[tokio::test]
    async fn test_wrong_secret_is_invalid_client() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let (state, mut receivers) =
            openstack_keystone_core::api::tests::get_mocked_state_with_audit(provider, true, {
                let mut config = Config::default();
                config.oauth2.allow_host_header_issuer = true;
                config
            })
            .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=wrong",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");

        let event = receivers
            .perimeter
            .try_recv()
            .expect("a wrong secret must leave a perimeter audit record");
        assert_eq!(event.payload().action(), "authenticate");
        assert_eq!(event.payload().outcome(), Outcome::Failure);
        assert_eq!(event.payload().initiator().id(), "unknown");
    }

    #[tokio::test]
    async fn test_public_client_cannot_use_client_credentials() {
        let mut client = confidential_client().await;
        client.client_secret_hash = None;
        client.require_pkce = true;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_scope_outside_allowed_scopes_is_invalid_scope() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t&scope=not-allowed",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn test_successful_client_credentials_issues_signed_jwt() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock
            .expect_get_ruleset_by_source()
            .returning(|_, _, _| Ok(Some(matching_ruleset())));
        mapping_mock
            .expect_authenticate_by_mapping()
            .returning(|_, _| Ok(successful_auth_result()));

        let mut resource_mock = MockResourceProvider::default();
        resource_mock.expect_get_domain().returning(|_, _| {
            Ok(Some(openstack_keystone_core_types::resource::Domain {
                id: "domain-1".to_string(),
                name: "domain-1".to_string(),
                description: None,
                enabled: true,
                extra: Default::default(),
                options: Default::default(),
            }))
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_mapping(mapping_mock)
            .mock_resource(resource_mock)
            .mock_oauth2_key(ok_key_mock());
        let (state, mut receivers) =
            openstack_keystone_core::api::tests::get_mocked_state_with_audit(provider, true, {
                let mut config = Config::default();
                config.oauth2.allow_host_header_issuer = true;
                config
            })
            .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "Bearer");
        let access_token = body["access_token"].as_str().unwrap();
        // Three dot-separated JWT segments, no signature validation here
        // (that belongs to the downstream middleware's own test suite).
        assert_eq!(access_token.split('.').count(), 3);

        let event = receivers
            .perimeter
            .try_recv()
            .expect("a minted token must leave a perimeter audit record");
        assert_eq!(event.payload().action(), "authenticate");
        assert_eq!(event.payload().outcome(), Outcome::Success);
    }

    #[tokio::test]
    async fn test_rate_limit_returns_429_before_client_lookup() {
        let config = Config {
            oauth2: openstack_keystone_config::Oauth2Provider {
                token_rate_limit_burst_size: 1,
                token_rate_limit_replenish_per_minute: 1,
                allow_host_header_issuer: true,
                ..Default::default()
            },
            ..Config::default()
        };

        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::default(),
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut req1 = request("grant_type=client_credentials&client_id=client-1&client_secret=x");
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        // First request consumes the single burst token and reaches the
        // (mocked) client lookup, which reports "not found".
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let mut req2 = request("grant_type=client_credentials&client_id=client-1&client_secret=x");
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        // Second request for the same client_id, burst exhausted: rejected
        // by the rate limiter before any further client lookup or Argon2id
        // work (ADR 0026 §7.A).
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
