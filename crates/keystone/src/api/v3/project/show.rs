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
//! # Show project API

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::{Project, ProjectResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::resource::ResourceApi;

/// Get single project
#[utoipa::path(
    get,
    path = "/{project_id}",
    params(),
    responses(
        (status = OK, description = "Single project", body = ProjectResponse),
        (status = 404, description = "Project not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project_show", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(project_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_resource_provider()
        .get_project(&state, &project_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/resource/project/show",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"project": current})),
        )
        .await?;
    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(ProjectResponse {
                project: Project::from(current),
            }),
        )),
        _ => Err(KeystoneApiError::NotFound {
            resource: "project".to_string(),
            identifier: project_id.clone(),
        }),
    }
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

    use openstack_keystone_core_types::resource::Project as ProviderProject;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::project::types::{
        Project as ApiProject, ProjectResponse as ApiProjectResponse,
    };
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    async fn test_get() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(ProviderProject {
                    id: "bar".into(),
                    domain_id: "did".into(),
                    enabled: true,
                    name: "project_name".into(),
                    ..Default::default()
                }))
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
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .extension(vsc.clone())
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
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiProjectResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiProject {
                description: None,
                domain_id: "did".into(),
                enabled: true,
                extra: std::collections::HashMap::new(),
                id: "bar".into(),
                is_domain: false,
                name: "project_name".into(),
                parent_id: None,
            },
            res.project,
        );
    }

    #[tokio::test]
    async fn test_get_not_allowed() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(ProviderProject {
                    id: "foo".into(),
                    domain_id: "did".into(),
                    enabled: true,
                    name: "project_name".into(),
                    ..Default::default()
                }))
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
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
