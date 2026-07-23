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
//! # Create trust API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{TrustCreateRequest, TrustResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new trust.
///
/// Trust authorization is decided by `policy/trust/create.rego` off the
/// caller's identity (`credentials.user_id` must match the requested
/// `trustor_user_id`) rather than the resource's own role list -- the
/// trustor-holds-the-role invariant is enforced provider-side
/// (`TrustService::create_trust`), not by policy.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Trust created", body = TrustResponse),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal error")
    ),
    tag="OS-TRUST"
)]
#[tracing::instrument(name = "api::v3::trust_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<TrustCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/trust/create",
            &user_auth,
            json!({"trust": payload.trust}),
            None,
        )
        .await?;

    let created = state
        .provider
        .get_trust_provider()
        .create_trust(
            &ExecutionContext::from_auth(&state, &user_auth),
            payload.into(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(TrustResponse {
            trust: created.into(),
        }),
    )
        .into_response())
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

    use openstack_keystone_core_types::trust::TrustBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::os_trust::trust::types::{
        Trust as ApiTrust, TrustCreate, TrustCreateRequest, TrustResponse,
    };
    use crate::provider::Provider;
    use crate::trust::MockTrustProvider;

    fn create_request() -> TrustCreateRequest {
        TrustCreateRequest {
            trust: TrustCreate {
                id: None,
                trustor_user_id: "trustor".into(),
                trustee_user_id: "trustee".into(),
                project_id: None,
                impersonation: false,
                expires_at: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles: Vec::new(),
                extra: None,
            },
        }
    }

    #[tokio::test]
    async fn test_create() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock.expect_create_trust().returning(|_, t| {
            Ok(TrustBuilder::default()
                .id("new_trust_id")
                .trustor_user_id(t.trustor_user_id)
                .trustee_user_id(t.trustee_user_id)
                .impersonation(t.impersonation)
                .build()
                .unwrap())
        });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_trust(trust_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        serde_json::to_string(&create_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TrustResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiTrust {
                id: "new_trust_id".into(),
                trustor_user_id: "trustor".into(),
                trustee_user_id: "trustee".into(),
                project_id: None,
                impersonation: false,
                expires_at: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles: Vec::new(),
                extra: None,
            },
            res.trust,
        );
    }

    #[tokio::test]
    async fn test_create_forbidden() {
        let trust_mock = MockTrustProvider::default();

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_trust(trust_mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        serde_json::to_string(&create_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        serde_json::to_string(&create_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
