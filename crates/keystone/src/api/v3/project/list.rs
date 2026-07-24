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
//! # List projects API

use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;

use super::types::{ProjectListParameters, ProjectShortList};
use crate::api::auth::Auth;
use crate::api::common::paginate_forward;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List projects
#[utoipa::path(
    get,
    path = "/",
    params(ProjectListParameters, PaginationQuery),
    description = "List projects",
    responses(
        (status = OK, description = "List of projects", body = ProjectShortList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<ProjectListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;
    state
        .policy_enforcer
        .enforce(
            "identity/resource/project/list",
            &user_auth,
            json!({"project": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut provider_params =
        openstack_keystone_core_types::resource::ProjectListParameters::from(query);
    provider_params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.resource.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: false,
    };

    let projects: Vec<super::types::ProjectShort> = state
        .provider
        .get_resource_provider()
        .list_projects(
            &ExecutionContext::from_auth(&state, &user_auth),
            &provider_params,
        )
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let (projects, links) = paginate_forward(&config, projects, &pagination, original_url.path())?;

    Ok((StatusCode::OK, Json(ProjectShortList { projects, links })).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::resource::{
        Project as ProviderProject, ProjectListParameters,
    };

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::project::types::{ProjectShort, ProjectShortList};
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    async fn test_list() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_list_projects()
            .withf(|_, _: &ProjectListParameters| true)
            .returning(|_, _| {
                Ok(vec![ProviderProject {
                    description: None,
                    domain_id: "did".into(),
                    enabled: true,
                    extra: std::collections::HashMap::new(),
                    id: "p1".into(),
                    name: "p1_name".into(),
                    parent_id: None,
                    is_domain: false,
                }])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
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
        let res: ProjectShortList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ProjectShort {
                domain_id: "did".into(),
                enabled: true,
                id: "p1".into(),
                name: "p1_name".into(),
            }],
            res.projects
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_list_projects()
            .withf(|_, qp: &ProjectListParameters| qp.name == Some("project_name".into()))
            .returning(|_, _| Ok(Vec::new()));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
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
                    .uri("/?name=project_name")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: ProjectShortList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_not_allowed() {
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

    /// Backend over-fetched (returned `limit + 1 == 2` rows): a `next` link
    /// is produced and the extra row trimmed from the response body.
    #[tokio::test]
    async fn test_list_pagination_link() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_list_projects()
            .withf(|_, qp: &ProjectListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![
                    ProviderProject {
                        domain_id: "did".into(),
                        enabled: true,
                        extra: std::collections::HashMap::new(),
                        id: "p1".into(),
                        name: "p1_name".into(),
                        parent_id: None,
                        is_domain: false,
                        description: None,
                    },
                    ProviderProject {
                        domain_id: "did".into(),
                        enabled: true,
                        extra: std::collections::HashMap::new(),
                        id: "p2".into(),
                        name: "p2_name".into(),
                        parent_id: None,
                        is_domain: false,
                        description: None,
                    },
                ])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
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
        let res: ProjectShortList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.projects.len(), 1);
        assert_eq!(res.projects[0].id, "p1");
        assert!(res.links.is_some());
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_list_projects()
            .withf(|_, qp: &ProjectListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![ProviderProject {
                    domain_id: "did".into(),
                    enabled: true,
                    extra: std::collections::HashMap::new(),
                    id: "p1".into(),
                    name: "p1_name".into(),
                    parent_id: None,
                    is_domain: false,
                    description: None,
                }])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
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
        let res: ProjectShortList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.projects.len(), 1);
        assert_eq!(res.links, None);
    }
}
