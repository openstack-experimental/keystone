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

//! Token restriction: update
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::token::types::*;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::token::TokenApi;

/// Update existing token restriction by the ID.
///
/// Updates the existing token restriction.
///
/// It is expected that only admin user is able to update token restriction in
/// other domain.
#[utoipa::path(
    put,
    path = "/{id}",
    operation_id = "/token_restriction:update",
    params(
      ("id" = String, Path, description = "The ID of the token restriction")
    ),
    responses(
        (status = OK, description = "Token restriction object", body = TokenRestrictionResponse),
        (status = 404, description = "Token restriction not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="token_restriction"
)]
#[tracing::instrument(
    name = "api::token_restriction::update",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<TokenRestrictionUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Fetch the current resource to pass current object into the policy evaluation
    let current = state
        .provider
        .get_token_provider()
        .get_token_restriction(&state, &id, false)
        .await?;

    policy
        .enforce(
            "identity/token_restriction/update",
            &user_auth,
            serde_json::to_value(&current)?,
            Some(serde_json::to_value(&req.restriction)?),
        )
        .await?;

    let res = state
        .provider
        .get_token_provider()
        .update_token_restriction(&state, &id, req.into())
        .await
        .map_err(KeystoneApiError::token)?;
    Ok(res.into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`

    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::{
        super::{openapi_router, tests::get_mocked_state},
        *,
    };

    use crate::token::{MockTokenProvider, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_update() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "1" && !expand)
            .returning(|_, _, _| {
                Ok(Some(provider_types::TokenRestriction {
                    id: "1".into(),
                    domain_id: "did".into(),
                    user_id: Some("uid".into()),
                    project_id: Some("pid".into()),
                    allow_renew: true,
                    allow_rescope: true,
                    role_ids: vec!["r1".into()],
                    roles: None,
                }))
            });
        token_mock
            .expect_update_token_restriction()
            .withf(
                |_, id: &'_ str, req: &provider_types::TokenRestrictionUpdate| {
                    id == "1"
                        && provider_types::TokenRestrictionUpdate {
                            project_id: Some(Some("new_pid".into())),
                            ..Default::default()
                        } == *req
                },
            )
            .returning(|_, _, _| {
                Ok(provider_types::TokenRestriction {
                    id: "1".into(),
                    domain_id: "did".into(),
                    user_id: Some("uid".into()),
                    project_id: Some("new_pid".into()),
                    allow_renew: true,
                    allow_rescope: true,
                    role_ids: vec!["r1".into()],
                    roles: None,
                })
            });

        let state = get_mocked_state(token_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = TokenRestrictionUpdateRequest {
            restriction: TokenRestrictionUpdate {
                project_id: Some(Some("new_pid".into())),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/1")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: TokenRestrictionResponse = serde_json::from_slice(&body).unwrap();
    }
}
