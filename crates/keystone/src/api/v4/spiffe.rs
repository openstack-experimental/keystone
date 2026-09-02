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
//! `GET /v4/spiffe/{domain_id}/jwks`: dedicated SPIFFE attestation-key
//! JSON Web Key Set (SPIRE integration plan, Phase 2, "Attestation key
//! isolation").
//!
//! Deliberately a separate endpoint from `/v4/oauth2/{domain_id}/jwks`,
//! backed by a wholly independent signing key
//! ([`openstack_keystone_core::spiffe_key`]) -- see
//! `doc/src/adr/0032-vendor-data-jwt.md`. The Phase 5 SPIRE server plugin
//! only ever fetches this endpoint, so it can never be tricked into
//! trusting the OAuth2 access-token signing key.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// OpenApi specification for the SPIFFE attestation key API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "spiffe", description = "SPIFFE attestation signing key API (SPIRE integration plan, Phase 2). Unauthenticated by design."),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(jwks))
}

/// Publish a domain's active SPIFFE attestation signing keys as a JWKS.
///
/// Unauthenticated by design, same rationale as
/// `GET /v4/oauth2/{domain_id}/jwks`: the (external, Phase 5) SPIRE server
/// plugin must be able to fetch and cache this without a Keystone token.
#[utoipa::path(
    get,
    path = "/{domain_id}/jwks",
    operation_id = "/spiffe:jwks",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "JSON Web Key Set"),
        (status = NOT_FOUND, description = "No attestation signing keys provisioned for this domain"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "spiffe"
)]
#[tracing::instrument(
    name = "api::v4::spiffe::jwks",
    level = "debug",
    skip(state),
    err(Debug)
)]
async fn jwks(
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

    let jwk_set = state
        .provider
        .get_spiffe_key_provider()
        .jwks(&state, &domain_id)
        .await?;

    Ok((
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(jwk_set),
    ))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_key_repository::asymmetric::{
        ActiveKeys, SigningAlgorithm, generate_keypair,
    };

    use super::openapi_router;
    use crate::api::tests::get_mocked_state as default_get_mocked_state;
    use crate::provider::Provider;
    use crate::spiffe_key::MockSpiffeKeyProvider;

    #[tokio::test]
    async fn test_jwks_returns_single_key_and_cache_control_header() {
        let mut mock = MockSpiffeKeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: None,
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });
        let provider = Provider::mocked_builder().mock_spiffe_key(mock);
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/jwks")
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
            "public, max-age=300"
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&body).unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn test_jwks_returns_not_found_for_unprovisioned_domain() {
        let mut mock = MockSpiffeKeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            Err(
                openstack_keystone_core_types::spiffe_key::SpiffeKeyProviderError::NotFound(
                    "domain-unknown".into(),
                ),
            )
        });
        let provider = Provider::mocked_builder().mock_spiffe_key(mock);
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-unknown/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_jwks_request_without_auth_header_still_succeeds() {
        let mut mock = MockSpiffeKeyProvider::default();
        mock.expect_jwks().returning(|_, _| {
            let active = ActiveKeys {
                primary: generate_keypair(SigningAlgorithm::Es256).unwrap(),
                previous: None,
            };
            Ok(openstack_keystone_core::oauth2_key::jwks::active_keys_to_jwk_set(&active).unwrap())
        });
        let provider = Provider::mocked_builder().mock_spiffe_key(mock);
        let state = default_get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain-1/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
