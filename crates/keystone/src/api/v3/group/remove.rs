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
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;

/// Delete group by ID.
#[utoipa::path(
    delete,
    path = "/{group_id}",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "group not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_delete", level = "debug", skip(state))]
pub async fn remove(
    Auth(user_auth): Auth,
    Path(group_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_identity_provider()
        .delete_group(&state, &group_id)
        .await?;
    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::identity::{MockIdentityProvider, error::IdentityProviderError};
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_delete() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_delete_group()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Err(IdentityProviderError::GroupNotFound("foo".into())));

        identity_mock
            .expect_delete_group()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
