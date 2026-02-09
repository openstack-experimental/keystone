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

//! Show token restriction.
use axum::{
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

/// Get single token restriction.
///
/// Shows details of the existing token restriction.
#[utoipa::path(
    get,
    path = "/{id}",
    operation_id = "/token_restriction:show",
    params(
      ("id" = String, Path, description = "The ID of the token restriction")
    ),
    responses(
        (status = OK, description = "Token restriction object", body = TokenRestrictionResponse),
        (status = 404, description = "Resource not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="token_restriction"
)]
#[tracing::instrument(
    name = "api::token_restriction::get",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_token_provider()
        .get_token_restriction(&state, &id, true)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "token_restriction".into(),
                identifier: id,
            })
        })??;

    policy
        .enforce(
            "identity/token_restriction/show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`

    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::{
        super::{openapi_router, tests::get_mocked_state},
        *,
    };

    use crate::api::v3::role_assignment::types::Role;
    use crate::assignment::types::Role as ProviderRole;
    use crate::token::{MockTokenProvider, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_get() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "foo" && *expand)
            .returning(|_, _, _| Ok(None));
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "bar" && *expand)
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
                            name: "r1n".into(),
                            ..Default::default()
                        },
                        ProviderRole {
                            id: "r2".into(),
                            name: "r2n".into(),
                            ..Default::default()
                        },
                    ]),
                }))
            });

        let state = get_mocked_state(token_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
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
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenRestrictionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            TokenRestriction {
                id: "bar".into(),
                domain_id: "did".into(),
                allow_rescope: true,
                allow_renew: true,
                user_id: Some("uid".into()),
                project_id: Some("pid".into()),
                roles: vec![
                    Role {
                        id: "r1".into(),
                        name: Some("r1n".into())
                    },
                    Role {
                        id: "r2".into(),
                        name: Some("r2n".into())
                    }
                ]
            },
            res.restriction,
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_get_forbidden() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "bar" && *expand)
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
                            name: "r1n".into(),
                            ..Default::default()
                        },
                        ProviderRole {
                            id: "r2".into(),
                            name: "r2n".into(),
                            ..Default::default()
                        },
                    ]),
                }))
            });
        let state = get_mocked_state(token_mock, false, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
