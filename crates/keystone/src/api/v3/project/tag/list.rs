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
//! # List project tags API
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::super::types::ProjectTags;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List project tags.
#[utoipa::path(
    get,
    path = "/{project_id}/tags",
    params(),
    responses(
        (status = OK, description = "Project tags", body = ProjectTags),
        (status = 404, description = "Project not found", example = json!(KeystoneApiError::NotFound{resource: "project".into(), identifier: "id = 1".into()}))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project::tag::list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(project_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let ctx = ExecutionContext::from_auth(&state, &user_auth);
    let current = state
        .provider
        .get_resource_provider()
        .get_project(&ctx, &project_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/resource/project/tag/list",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"project": current})),
        )
        .await?;
    if current.is_none() {
        return Err(KeystoneApiError::NotFound {
            resource: "project".to_string(),
            identifier: project_id,
        });
    }
    let tags = state
        .provider
        .get_resource_provider()
        .list_project_tags(&ctx, &project_id)
        .await?;
    Ok((StatusCode::OK, Json(ProjectTags { tags })))
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
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn existing_project() -> ProviderProject {
        ProviderProject {
            id: "foo".into(),
            domain_id: "did".into(),
            enabled: true,
            ..Default::default()
        }
    }

    fn request(with_auth: bool) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/foo/tags")
            .header(header::CONTENT_TYPE, "application/json");
        if with_auth {
            builder = builder.extension(test_fixture_scoped());
        }
        builder.body(Body::from("")).unwrap()
    }

    #[tokio::test]
    async fn test_list() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(Some(existing_project())));
        resource_mock
            .expect_list_project_tags()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(vec!["a".to_string(), "b".to_string()]));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: crate::api::v3::project::types::ProjectTags =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(res.tags, vec!["a".to_string(), "b".to_string()]);
    }

    #[tokio::test]
    async fn test_list_project_not_found() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_forbidden() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(Some(existing_project())));
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            false,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(false)).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_policy_input() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(Some(existing_project())));
        resource_mock
            .expect_list_project_tags()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(vec!["a".to_string(), "b".to_string()]));

        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_resource(resource_mock)).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert!(response.status().is_success());

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.policy_name, "identity/resource/project/tag/list");
        assert_eq!(call.target, serde_json::Value::Null);
        policy_contract::assert_existing_presence(&call.existing, true);
        let existing = call.existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["project"]);
        policy_contract::assert_no_secrets(existing);
    }
}
