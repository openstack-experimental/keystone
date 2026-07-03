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

use openstack_keystone_api_types::v3::credential::{Credential, CredentialResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Get single credential.
#[utoipa::path(
    get,
    path = "/{credential_id}",
    description = "Get credential by ID",
    params(),
    responses(
        (status = OK, description = "Credential object", body = CredentialResponse),
        (status = 404, description = "Credential not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="credentials"
)]
#[tracing::instrument(name = "api::credential_get", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(credential_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_credential_provider()
        .get_credential(
            &ExecutionContext::from_auth(&state, &user_auth),
            &credential_id,
        )
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/credential/show",
            &user_auth,
            serde_json::Value::Null,
            Some(super::credential_policy_input(&current)),
        )
        .await?;

    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(CredentialResponse {
                credential: Credential::from(current),
            }),
        )
            .into_response()),
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
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_get_not_found_not_allowed() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
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
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
