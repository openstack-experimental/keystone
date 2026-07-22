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
//! # Update project API

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{Project, ProjectResponse, ProjectUpdateRequest};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update existing project
#[utoipa::path(
    patch,
    path = "/{project_id}",
    description = "Update project by ID",
    params(),
    responses(
        (status = OK, description = "Updated project", body = ProjectResponse),
        (status = 404, description = "Project not found", example = json!(KeystoneApiError::NotFound{resource: "project".into(), identifier: "id = 1".into()}))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project_update", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(project_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<ProjectUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    // Fetch the current project to pass it as existing object into the
    // policy evaluation
    let current = state
        .provider
        .get_resource_provider()
        .get_project(
            &ExecutionContext::from_auth(&state, &user_auth),
            &project_id,
        )
        .await?;

    let existing_project = current.as_ref().map(|c| json!({"project": c}));

    state
        .policy_enforcer
        .enforce(
            "identity/resource/project/update",
            &user_auth,
            json!({"project": req.project}),
            existing_project,
        )
        .await?;

    match current {
        Some(_) => {
            let project = state
                .provider
                .get_resource_provider()
                .update_project(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &project_id,
                    req.into(),
                )
                .await?;
            Ok((
                StatusCode::OK,
                Json(ProjectResponse {
                    project: Project::from(project),
                }),
            )
                .into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "project".into(),
            identifier: project_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::resource::Project as ProviderProject;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::project::types::*;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    async fn test_update_success() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(ProviderProject {
                    id: "foo".into(),
                    name: "old_name".into(),
                    domain_id: "did".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_update_project()
            .withf(|_, id: &'_ str, _| id == "foo")
            .returning(|_, _, _| {
                Ok(ProviderProject {
                    id: "foo".into(),
                    name: "new_name".into(),
                    domain_id: "did".into(),
                    enabled: true,
                    ..Default::default()
                })
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

        let req = ProjectUpdateRequest {
            project: ProjectUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ProjectResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.project.name, "new_name");
        assert_eq!(res.project.id, "foo");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

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

        let req = ProjectUpdateRequest {
            project: ProjectUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_forbidden() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(ProviderProject {
                    id: "foo".into(),
                    name: "old_name".into(),
                    domain_id: "did".into(),
                    enabled: true,
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

        let req = ProjectUpdateRequest {
            project: ProjectUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = ProjectUpdateRequest {
            project: ProjectUpdateBuilder::default()
                .name("new_name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/foo")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_update_rejects_put() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/foo")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"project":{"name":"updated"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
