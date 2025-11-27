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
//! Token Restriction: list

use axum::{
    extract::{Query, State},
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::to_value;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::token::types::*;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::token::{
    TokenApi, types::TokenRestrictionListParameters as ProviderTokenRestrictionListParameters,
};

/// List token restrictions.
///
/// List existing token restrictions. By default only admin user is allowed to
/// leave `domain_id` query parameter empty, what means that token restrictions
/// for all domains should be listed.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/token_restriction:list",
    params(TokenRestrictionListParameters),
    responses(
        (status = OK, description = "List of token restrictions.", body = TokenRestrictionList),
        (status = 500, description = "Internal error.", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="token_restrictions"
)]
#[tracing::instrument(
    name = "api::token_restriction::list",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Query(query): Query<TokenRestrictionListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce(
            "identity/token_restriction/list",
            &user_auth,
            to_value(&query)?,
            None,
        )
        .await?;

    let provider_list_params: ProviderTokenRestrictionListParameters = query.into();

    let token_restrictions: Vec<TokenRestriction> = state
        .provider
        .get_token_provider()
        .list_token_restrictions(&state, &provider_list_params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(TokenRestrictionList {
        restrictions: token_restrictions,
    })
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
    async fn test_list() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_list_token_restrictions()
            .withf(|_, _: &provider_types::TokenRestrictionListParameters| true)
            .returning(|_, _| {
                Ok(vec![provider_types::TokenRestriction {
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
                }])
            });
        let state = get_mocked_state(token_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenRestrictionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![TokenRestriction {
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
            }],
            res.restrictions
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_qp() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_list_token_restrictions()
            .withf(|_, qp: &provider_types::TokenRestrictionListParameters| {
                provider_types::TokenRestrictionListParameters {
                    domain_id: Some("did".into()),
                    user_id: Some("uid".into()),
                    project_id: Some("pid".into()),
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::TokenRestriction {
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
                }])
            });
        let state = get_mocked_state(token_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=did&user_id=uid&project_id=pid")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: TokenRestrictionList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_forbidden() {
        let token_mock = MockTokenProvider::default();
        let state = get_mocked_state(token_mock, false, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
