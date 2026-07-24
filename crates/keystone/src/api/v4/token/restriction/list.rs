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
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;
use openstack_keystone_core_types::token::TokenRestrictionListParameters as ProviderTokenRestrictionListParameters;

use crate::api::auth::Auth;
use crate::api::common::paginate_bidirectional;
use crate::api::error::KeystoneApiError;
use crate::api::v4::token::types::*;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

impl crate::api::common::ResourceIdentifier for TokenRestriction {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}

/// List token restrictions.
///
/// List existing token restrictions. By default only admin user is allowed to
/// leave `domain_id` query parameter empty, what means that token restrictions
/// for all domains should be listed.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/token_restriction:list",
    params(TokenRestrictionListParameters, PaginationQuery),
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
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<TokenRestrictionListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/token/token_restriction/list",
            &user_auth,
            json!({"restriction": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut provider_list_params: ProviderTokenRestrictionListParameters = query.into();
    provider_list_params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.token_restriction.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: pagination.page_reverse,
    };

    let token_restrictions: Vec<TokenRestriction> = state
        .provider
        .get_token_provider()
        .list_token_restrictions(
            &ExecutionContext::from_auth(&state, &user_auth),
            &provider_list_params,
        )
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let (restrictions, links) = paginate_bidirectional(
        &config,
        token_restrictions,
        &pagination,
        original_url.path(),
    )?;

    Ok((
        StatusCode::OK,
        Json(TokenRestrictionList {
            restrictions,
            links,
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
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::role::types::RoleRef;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_list() {
        let vsc = test_fixture_scoped();
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
                    .extension(vsc)
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
        let vsc = test_fixture_scoped();
        let mut token_mock = get_token_provider_mock_with_mocks();
        token_mock
            .expect_list_token_restrictions()
            .withf(|_, qp: &provider_types::TokenRestrictionListParameters| {
                qp.domain_id == Some("did".into())
                    && qp.user_id == Some("uid".into())
                    && qp.project_id == Some("pid".into())
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
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: TokenRestrictionList = serde_json::from_slice(&body).unwrap();
    }

    /// Backend over-fetched (returned `limit + 1 == 2` rows), not the first
    /// page (`marker` set): both `next` and `previous` links are produced,
    /// and the extra row is trimmed from the response body.
    #[tokio::test]
    async fn test_list_pagination_bidirectional_links() {
        let vsc = test_fixture_scoped();
        let mut token_mock = get_token_provider_mock_with_mocks();
        token_mock
            .expect_list_token_restrictions()
            .withf(|_, qp: &provider_types::TokenRestrictionListParameters| {
                qp.pagination.limit == Some(1) && qp.pagination.marker == Some("m".into())
            })
            .returning(|_, _| {
                Ok(vec![
                    provider_types::TokenRestriction {
                        user_id: None,
                        allow_renew: true,
                        allow_rescope: true,
                        id: "1".into(),
                        domain_id: "did".into(),
                        project_id: None,
                        role_ids: vec![],
                        roles: None,
                    },
                    provider_types::TokenRestriction {
                        user_id: None,
                        allow_renew: true,
                        allow_rescope: true,
                        id: "2".into(),
                        domain_id: "did".into(),
                        project_id: None,
                        role_ids: vec![],
                        roles: None,
                    },
                ])
            });
        let state = get_mocked_state(
            Provider::mocked_builder().mock_token(token_mock),
            true,
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
                    .uri("/?limit=1&marker=m")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenRestrictionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.restrictions.len(), 1);
        assert_eq!(res.restrictions[0].id, "1");
        let links = res.links.expect("expected next+previous links");
        assert!(links.iter().any(|l| l.rel == "next"));
        assert!(links.iter().any(|l| l.rel == "previous"));
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let vsc = test_fixture_scoped();
        let mut token_mock = get_token_provider_mock_with_mocks();
        token_mock
            .expect_list_token_restrictions()
            .withf(|_, qp: &provider_types::TokenRestrictionListParameters| {
                qp.pagination.limit == Some(1)
            })
            .returning(|_, _| {
                Ok(vec![provider_types::TokenRestriction {
                    user_id: None,
                    allow_renew: true,
                    allow_rescope: true,
                    id: "1".into(),
                    domain_id: "did".into(),
                    project_id: None,
                    role_ids: vec![],
                    roles: None,
                }])
            });
        let state = get_mocked_state(
            Provider::mocked_builder().mock_token(token_mock),
            true,
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
                    .uri("/?limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenRestrictionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.restrictions.len(), 1);
        assert_eq!(res.links, None);
    }

    #[tokio::test]
    async fn test_list_forbidden() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
