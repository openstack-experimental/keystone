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
//! `GET /v4/oauth2/{domain_id}/jwks/revocation` (ADR 0026 §3, §11).
//!
//! Published alongside JWKS: the JTI revocation list populated by
//! emergency signing-key rotation. Unauthenticated by design, same posture
//! as `jwks` -- the downstream middleware must be able to fetch it without
//! a Keystone token, and must fail closed if it can't be reached (ADR §6,
//! §11).

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Response body for `jwks/revocation`.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct JwksRevocationResponse {
    /// JTIs revoked by an emergency signing-key rotation, not yet expired.
    revoked_jtis: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/{domain_id}/jwks/revocation",
    operation_id = "/oauth2:jwks_revocation",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "JTI revocation list", body = JwksRevocationResponse),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::jwks_revocation",
    level = "debug",
    skip(state),
    err(Debug)
)]
pub(super) async fn jwks_revocation(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
) -> Result<impl IntoResponse, KeystoneApiError> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    let revoked_jtis = state
        .provider
        .get_oauth2_key_provider()
        .revoked_jtis(&state, &domain_id)
        .await?
        .into_iter()
        .collect();

    // 60s cache, matching the reference middleware's own revocation-list
    // client-side TTL (ADR 0026 §6) -- shorter than JWKS's 300s since a
    // fresh emergency revocation must propagate quickly.
    Ok((
        [(header::CACHE_CONTROL, "public, max-age=60")],
        Json(JwksRevocationResponse { revoked_jtis }),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_returns_revoked_jtis() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_revoked_jtis()
            .returning(|_, _| Ok(HashSet::from(["jti-1".to_string()])));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/jwks/revocation")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "public, max-age=60"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["revoked_jtis"], serde_json::json!(["jti-1"]));
    }

    #[tokio::test]
    async fn test_request_without_auth_header_still_succeeds() {
        // Unauthenticated by design, mirroring `jwks`.
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_revoked_jtis()
            .returning(|_, _| Ok(HashSet::new()));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/jwks/revocation")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
