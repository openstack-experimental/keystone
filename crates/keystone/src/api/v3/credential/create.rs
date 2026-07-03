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
//! # Create credential API

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use super::types::{CredentialCreateRequest, CredentialResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new credential.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Credential created", body = CredentialResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="credentials"
)]
#[tracing::instrument(name = "api::v3::credential_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<CredentialCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/credential/create",
            &user_auth,
            super::credential_policy_input(&payload.credential),
            None,
        )
        .await?;

    let created = state
        .provider
        .get_credential_provider()
        .create_credential(
            &ExecutionContext::from_auth(&state, &user_auth),
            payload.into(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CredentialResponse {
            credential: created.into(),
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

    use openstack_keystone_core_types::credential::{CredentialBuilder, CredentialCreate};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::credential::types::{CredentialCreateBuilder, CredentialResponse};
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_create() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_create_credential()
            .withf(|_, rec: &CredentialCreate| {
                rec.r#type == "totp" && rec.blob == r#"{"seed":"AAAA"}"#
            })
            .returning(|_, _| {
                Ok(CredentialBuilder::default()
                    .id("new_id")
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("uid")
                    .build()
                    .unwrap())
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::credential::types::CredentialCreateRequest {
            credential: CredentialCreateBuilder::default()
                .blob(r#"{"seed":"AAAA"}"#)
                .r#type("totp")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: CredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credential.id, "new_id");
    }
}
