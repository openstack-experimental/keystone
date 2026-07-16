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
//! `POST /v4/oauth2/{domain_id}/device_authorization` (RFC 8628 §3.1/§3.2,
//! ADR 0026 §7.C).
//!
//! Unauthenticated at the `Auth`-extractor level like `/authorize`: device
//! flow clients are overwhelmingly public/native applications, so -- like
//! `/authorize` -- this endpoint validates the client is registered,
//! enabled, and holds the `device_code` grant type, but does not require a
//! `client_secret`.

use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::StartDeviceAuthorizationRequest;
use openstack_keystone_core_types::oauth2_client::GrantType;

use super::token::Oauth2TokenError;
use super::well_known::base_url;
use crate::api::common::PeerAddr;
use crate::keystone::ServiceState;

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(super) struct DeviceAuthorizationForm {
    client_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(super) struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: u32,
}

#[utoipa::path(
    post,
    path = "/{domain_id}/device_authorization",
    operation_id = "/oauth2:device_authorization",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Device authorization grant issued"),
        (status = BAD_REQUEST, description = "Malformed request, unknown client, or invalid scope"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::device_authorization",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn device_authorization(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    Form(form): Form<DeviceAuthorizationForm>,
) -> Result<Response, Oauth2TokenError> {
    // Mirrors `/token`'s and `/authorize`'s pre-lookup per-IP throttle: this
    // endpoint does a client lookup and mints session state on every call,
    // and -- like `/authorize` -- is reachable with no client_secret.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Err(Oauth2TokenError::too_many_requests(
            retry_after.as_secs().max(1),
        ));
    }

    let Some(client_id) = form.client_id.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };

    let exec = ExecutionContext::internal(&state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            Oauth2TokenError::internal("client lookup failed")
        })?;
    let Some(client) =
        client.filter(|c| c.domain_id == domain_id && c.enabled && c.deleted_at.is_none())
    else {
        return Err(Oauth2TokenError::invalid_client(
            "unknown or disabled client",
        ));
    };
    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the device_code grant",
        ));
    }

    let requested_scope: Vec<String> = form
        .scope
        .clone()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    const DISPLAY_SCOPES: &[&str] = &["openid", "profile", "email"];
    for s in &requested_scope {
        // Mirrors `/authorize`'s guard: full `OpenStackAccessTokenClaims`
        // issuance requires resolving a project/domain authorization scope,
        // which this phase's verification page does not collect.
        if s == "openstack:api" {
            return Err(Oauth2TokenError::invalid_scope(
                "openstack:api is not yet supported on the device_code grant",
            ));
        }
        if !DISPLAY_SCOPES.contains(&s.as_str()) || !client.allowed_scopes.iter().any(|a| a == s) {
            return Err(Oauth2TokenError::invalid_scope(
                "requested scope exceeds the client's allowed_scopes",
            ));
        }
    }

    let start = state
        .provider
        .get_oauth2_session_provider()
        .start_device_authorization(
            &state,
            StartDeviceAuthorizationRequest {
                domain_id: domain_id.clone(),
                client_id: client.client_id.clone(),
                scope: requested_scope,
            },
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 device authorization grant creation failed");
            Oauth2TokenError::internal("device authorization failed")
        })?;

    let base = base_url(&state, &headers).await;
    let verification_uri = format!("{base}/v4/oauth2/{domain_id}/device");
    let verification_uri_complete = {
        let mut url = url::Url::parse(&verification_uri).map_err(|e| {
            tracing::warn!(error = %e, "oauth2 device verification_uri build failed");
            Oauth2TokenError::internal("device authorization failed")
        })?;
        url.query_pairs_mut()
            .append_pair("user_code", &start.user_code);
        url.to_string()
    };
    let now = chrono::Utc::now().timestamp();

    let response = DeviceAuthorizationResponse {
        device_code: start.device_code,
        user_code: start.user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: (start.expires_at - now).max(0),
        interval: start.interval,
    };
    Ok((StatusCode::OK, axum::Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::oauth2_session::DeviceAuthorizationStart;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core_types::oauth2_client as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn device_client() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![provider_types::GrantType::DeviceCode],
            require_pkce: false,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    fn request(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/domain-1/device_authorization")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_missing_client_id_is_invalid_request() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("scope=openid"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_client_without_device_code_grant_is_unauthorized() {
        let mut client = device_client();
        client.grant_types = vec![provider_types::GrantType::ClientCredentials];
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
            .oneshot(request("client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_openstack_api_scope_is_invalid_scope() {
        let client = device_client();
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
            .oneshot(request("client_id=client-1&scope=openstack:api"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_success_returns_device_and_user_codes() {
        let client = device_client();
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_start_device_authorization()
            .returning(|_, _| {
                Ok(DeviceAuthorizationStart {
                    device_code: "device-code-1".to_string(),
                    user_code: "ABCD-EFGH".to_string(),
                    expires_at: chrono::Utc::now().timestamp() + 600,
                    interval: 5,
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("client_id=client-1&scope=openid"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["device_code"], "device-code-1");
        assert_eq!(json["user_code"], "ABCD-EFGH");
        assert!(
            json["verification_uri_complete"]
                .as_str()
                .unwrap()
                .contains("ABCD-EFGH")
        );
        assert_eq!(json["interval"], 5);
    }

    #[tokio::test]
    async fn test_rate_limit_returns_429_before_client_lookup() {
        let config = Config {
            rate_limit_global_ip: openstack_keystone_config::RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
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
                DatabaseConnection::Disconnected,
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

        let mut req1 = request("client_id=client-1");
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        // First request consumes the single burst token and reaches the
        // (mocked) client lookup, which reports "not found".
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let mut req2 = request("client_id=client-1");
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
