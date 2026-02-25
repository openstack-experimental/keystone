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
//! # Create project API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;
use validator::Validate;

use super::types::{ProjectCreateRequest, ProjectResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::resource::ResourceApi;

/// Create project.
///
/// Creates a project, where the project may act as a domain.
#[utoipa::path(
    post,
    path = "/",
    request_body = ProjectCreateRequest,
    responses(
        (status = CREATED, description = "Project created", body = ProjectResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project_create", level = "debug", skip(state, policy))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Json(payload): Json<ProjectCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Validate the request
    payload.validate()?;

    policy
        .enforce(
            "identity/project/user/role/check",
            &user_auth,
            serde_json::to_value(&payload.project)?,
            None,
        )
        .await?;

    // Create the project
    let created_project = state
        .provider
        .get_resource_provider()
        .create_project(&state, payload.project.into())
        .await?;

    // Return response with 201 CREATED status
    Ok((
        StatusCode::CREATED,
        Json(ProjectResponse {
            project: created_project.into(),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`
    use serde_json::json;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::api::v3::project::types::*;
    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types::Project as ProviderProject};

    #[traced_test]
    #[tokio::test]
    async fn test_allowed() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock.expect_create_project().returning(|_, _| {
            Ok(ProviderProject {
                description: Some("A new project".into()),
                domain_id: "did".into(),
                enabled: true,
                extra: None,
                id: "pid".into(),
                is_domain: false,
                name: "project_name".into(),
                parent_id: Some("ppid".into()),
            })
        });

        let provider_builder = Provider::mocked_builder().resource(resource_mock);
        let state = get_mocked_state(provider_builder, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = ProjectCreateRequest {
            project: ProjectCreate {
                name: "name".into(),
                domain_id: "did".into(),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .header(header::CONTENT_TYPE, "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let res: ProjectResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            Project {
                description: Some("A new project".into()),
                domain_id: "did".into(),
                enabled: true,
                extra: Some(json!({})),
                id: "pid".into(),
                is_domain: false,
                name: "project_name".into(),
                parent_id: Some("ppid".into()),
            },
            res.project,
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_not_allowed() {
        let provider_builder = Provider::mocked_builder();
        let state = get_mocked_state(provider_builder, false, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = ProjectCreateRequest {
            project: ProjectCreate {
                name: "name".into(),
                domain_id: "did".into(),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .header(header::CONTENT_TYPE, "application/json")
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
