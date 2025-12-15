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

//! Token restriction: delete.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::token::TokenApi;

/// Delete Token restriction.
///
/// Deletes the existing token restriction by the ID.
#[utoipa::path(
    delete,
    path = "/{id}",
    operation_id = "/token_restriction:delete",
    params(
      ("id" = String, Path, description = "The ID of the token restriction.")
    ),
    responses(
        (status = 204, description = "Deleted."),
        (status = 404, description = "Token restriction not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="token_restriction"
)]
#[tracing::instrument(
    name = "api::token_restriction::delete",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn remove(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_token_provider()
        .get_token_restriction(&state, &id, false)
        .await?;

    policy
        .enforce(
            "identity/token_restriction/delete",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;

    if current.is_some() {
        state
            .provider
            .get_token_provider()
            .delete_token_restriction(&state, &id)
            .await
            .map_err(KeystoneApiError::token)?;
    } else {
        return Err(KeystoneApiError::NotFound {
            resource: "token_restriction".to_string(),
            identifier: id.clone(),
        });
    }
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
    use tracing_test::traced_test;

    use super::super::{openapi_router, tests::get_mocked_state};

    use crate::assignment::types::Role as ProviderRole;
    use crate::token::{MockTokenProvider, TokenProviderError, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_delete() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "foo" && !expand)
            .returning(|_, _, _| Ok(None));
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "bar" && !expand)
            .returning(|_, _, _| {
                Ok(Some(provider_types::TokenRestriction {
                    user_id: Some("uid".into()),
                    allow_renew: true,
                    allow_rescope: true,
                    id: "bar".into(),
                    domain_id: "did".into(),
                    project_id: Some("pid".into()),
                    role_ids: vec!["r1".into(), "r2".into()],
                    roles: Some(vec![
                        ProviderRole {
                            id: "r1".into(),
                            ..Default::default()
                        },
                        ProviderRole {
                            id: "r2".into(),
                            ..Default::default()
                        },
                    ]),
                }))
            });
        token_mock
            .expect_delete_token_restriction()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Err(TokenProviderError::TokenRestrictionNotFound("foo".into())));

        token_mock
            .expect_delete_token_restriction()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(token_mock, true, None);

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
