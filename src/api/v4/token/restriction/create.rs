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
//! Token restriction: create

use axum::{Json, debug_handler, extract::State, http::StatusCode, response::IntoResponse};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::token::types::*;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::token::TokenApi;

/// Create the token restriction.
///
/// Create the token restriction with the specified properties.
///
/// It is expected that only admin user is able to create token restriction in
/// other domain.
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/token_restriction:create",
    responses(
        (status = CREATED, description = "token restriction object", body = TokenRestrictionResponse),
    ),
    security(("x-auth" = [])),
    tag="token_restriction"
)]
#[tracing::instrument(
    name = "api::token_restriction::create",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
#[debug_handler]
pub(super) async fn create(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Json(req): Json<TokenRestrictionCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce(
            "identity/token_restriction/create",
            &user_auth,
            serde_json::to_value(&req.restriction)?,
            None,
        )
        .await?;

    let res = state
        .provider
        .get_token_provider()
        .create_token_restriction(&state, req.into())
        .await
        .map_err(KeystoneApiError::token)?;
    Ok((StatusCode::CREATED, res).into_response())
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

    use crate::assignment::types::Role as ProviderRole;
    use crate::token::{MockTokenProvider, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_create() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_create_token_restriction()
            .withf(|_, req: &provider_types::TokenRestrictionCreate| {
                provider_types::TokenRestrictionCreate {
                    id: String::new(),
                    domain_id: "did".into(),
                    user_id: Some("uid".into()),
                    project_id: Some("pid".into()),
                    allow_renew: true,
                    allow_rescope: true,
                    role_ids: vec!["r1".into()],
                } == *req
            })
            .returning(|_, _| {
                Ok(provider_types::TokenRestriction {
                    user_id: Some("uid".into()),
                    allow_renew: true,
                    allow_rescope: true,
                    id: "bar".into(),
                    domain_id: "did".into(),
                    project_id: Some("pid".into()),
                    role_ids: vec!["r1".into(), "r2".into()],
                    roles: Some(vec![ProviderRole {
                        id: "r1".into(),
                        name: "r1n".into(),
                        ..Default::default()
                    }]),
                })
            });

        let state = get_mocked_state(token_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = TokenRestrictionCreateRequest {
            restriction: TokenRestrictionCreate {
                domain_id: "did".into(),
                user_id: Some("uid".into()),
                project_id: Some("pid".into()),
                allow_renew: true,
                allow_rescope: true,
                roles: vec![
                    ProviderRole {
                        id: "r1".into(),
                        name: "r1n".into(),
                        ..Default::default()
                    }
                    .into(),
                ],
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenRestrictionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.restriction.domain_id, req.restriction.domain_id);
        //assert_eq!(
        //    res.identity_provider.domain_id,
        //    req.identity_provider.domain_id
        //);
    }
}
