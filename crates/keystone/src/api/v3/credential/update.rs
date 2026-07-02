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

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{Credential, CredentialResponse, CredentialUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update an existing credential.
///
/// Immutable fields (`user_id`, and — within `blob` — `access`, `trust_id`,
/// `app_cred_id`, `access_token_id`) are enforced by the provider layer
/// (CVE-2020-12691); this handler only wires the request through.
#[utoipa::path(
    patch,
    path = "/{credential_id}",
    description = "Update credential by ID",
    params(),
    responses(
        (status = OK, description = "Updated credential", body = CredentialResponse),
        (status = 404, description = "Credential not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="credentials"
)]
#[tracing::instrument(name = "api::credential_update", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(credential_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<CredentialUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let current = state
        .provider
        .get_credential_provider()
        .get_credential(
            &ExecutionContext::from_auth(&state, &user_auth),
            &credential_id,
        )
        .await?;

    let existing = current.as_ref().map(|c| json!({"credential": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/credential/update",
            &user_auth,
            json!({"credential": req.credential}),
            existing,
        )
        .await?;

    match current {
        Some(_) => {
            let updated = state
                .provider
                .get_credential_provider()
                .update_credential(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &credential_id,
                    req.into(),
                )
                .await?;
            Ok((
                StatusCode::OK,
                Json(CredentialResponse {
                    credential: Credential::from(updated),
                }),
            )
                .into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "credential".into(),
            identifier: credential_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::credential::CredentialBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::credential::types::{
        CredentialResponse as ApiCredentialResponse, CredentialUpdateBuilder,
        CredentialUpdateRequest,
    };
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_update() {
        let mut credential_mock = MockCredentialProvider::default();

        credential_mock
            .expect_get_credential()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    CredentialBuilder::default()
                        .id("bar")
                        .blob(r#"{"seed":"OLD"}"#)
                        .r#type("totp")
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ))
            });

        credential_mock
            .expect_update_credential()
            .withf(
                |_,
                 id: &'_ str,
                 _: &openstack_keystone_core_types::credential::CredentialUpdate| {
                    id == "bar"
                },
            )
            .returning(|_, _, _| {
                Ok(CredentialBuilder::default()
                    .id("bar")
                    .blob(r#"{"seed":"NEW"}"#)
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

        let update_req = CredentialUpdateRequest {
            credential: CredentialUpdateBuilder::default()
                .blob(r#"{"seed":"NEW"}"#)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/bar")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&update_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let updated: ApiCredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated.credential.blob, r#"{"seed":"NEW"}"#);
        assert_eq!(updated.credential.id, "bar");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential()
            .withf(|_, id: &'_ str| id == "missing")
            .returning(|_, _| Ok(None));

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

        let update_req = CredentialUpdateRequest {
            credential: CredentialUpdateBuilder::default()
                .blob(r#"{"seed":"NEW"}"#)
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/missing")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&update_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
