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
//! Token Restriction: list.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::to_value;

use openstack_keystone_core_types::token::TokenRestrictionListParameters as ProviderTokenRestrictionListParameters;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::token::types::*;
use crate::keystone::ServiceState;
use crate::token::TokenApi;

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
    tag="token_restriction"
)]
#[tracing::instrument(
    name = "api::token_restriction::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<TokenRestrictionListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
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
    Ok((
        StatusCode::OK,
        Json(TokenRestrictionList {
            restrictions: token_restrictions,
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
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::role::RoleRef as ProviderRoleRef;
    use openstack_keystone_core_types::token as provider_types;

    use super::{
        super::{openapi_router, tests::get_token_provider_mock_with_mocks},
        *,
    };
    use crate::api::tests::get_mocked_state;
    use crate::api::v3::role::types::RoleRef;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_list() {
        let mut token_mock = get_token_provider_mock_with_mocks();
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
                        ProviderRoleRef {
                            id: "r1".into(),
                            name: Some("r1n".into()),
                            domain_id: None,
                        },
                        ProviderRoleRef {
                            id: "r2".into(),
                            name: Some("r2n".into()),
                            domain_id: None,
                        },
                    ]),
                }])
            });
        let state = get_mocked_state(
            Provider::mocked_builder().mock_token(token_mock),
            true,
            None,
            Some(true),
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
                    RoleRef {
                        id: "r1".into(),
                        name: "r1n".into(),
                        domain_id: None
                    },
                    RoleRef {
                        id: "r2".into(),
                        name: "r2n".into(),
                        domain_id: None
                    }
                ]
            }],
            res.restrictions
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut token_mock = get_token_provider_mock_with_mocks();
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
                        ProviderRoleRef {
                            id: "r1".into(),
                            name: Some("r1n".into()),
                            domain_id: None,
                        },
                        ProviderRoleRef {
                            id: "r2".into(),
                            name: Some("r2n".into()),
                            domain_id: None,
                        },
                    ]),
                }])
            });
        let state = get_mocked_state(
            Provider::mocked_builder().mock_token(token_mock),
            true,
            None,
            Some(true),
        )
        .await;

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
    async fn test_list_forbidden() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None, None).await;

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
