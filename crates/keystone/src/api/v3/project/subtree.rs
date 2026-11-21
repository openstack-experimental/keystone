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
//! # List project subtree API

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::show::{filter_visible, flag, subtree_to_ids, to_list};
use super::types::{ProjectRelativesParameters, ProjectSubtreeResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List project subtree
///
/// Lists all descendants of the project, breadth first. Only the projects the caller is allowed to see are returned. The
/// `as_ids` query parameter returns a nested object of the project IDs
/// instead of the list.
#[utoipa::path(
    get,
    path = "/{project_id}/subtree",
    params(ProjectRelativesParameters),
    responses(
        (status = OK, description = "Project subtree", body = ProjectSubtreeResponse),
        (status = 404, description = "Project not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project_subtree", level = "debug", skip(state))]
pub(super) async fn subtree(
    Auth(user_auth): Auth,
    Path(project_id): Path<String>,
    Query(query): Query<ProjectRelativesParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let ctx = ExecutionContext::from_auth(&state, &user_auth);
    let current = state
        .provider
        .get_resource_provider()
        .get_project(&ctx, &project_id)
        .await?;

    // The target project itself must be visible to the caller.
    state
        .policy_enforcer
        .enforce(
            "identity/resource/project/show",
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

    let found = state
        .provider
        .get_resource_provider()
        .get_project_subtree(&ctx, &project_id)
        .await?
        .unwrap_or_default();
    let visible = filter_visible(&state, &user_auth, found.clone()).await?;
    let subtree = if flag(&query.as_ids) {
        subtree_to_ids(&project_id, &found, &visible)
    } else {
        to_list(visible)
    };
    Ok((StatusCode::OK, Json(ProjectSubtreeResponse { subtree })))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::resource::Project as ProviderProject;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn proj(id: &str, parent: Option<&str>) -> ProviderProject {
        ProviderProject {
            id: id.into(),
            domain_id: "did".into(),
            enabled: true,
            name: format!("{id}_name"),
            parent_id: parent.map(Into::into),
            ..Default::default()
        }
    }

    fn mock() -> MockResourceProvider {
        let mut m = MockResourceProvider::default();
        m.expect_get_project()
            .withf(|_, id: &'_ str| id == "p2")
            .returning(|_, _| Ok(Some(proj("p2", Some("p1")))));
        m.expect_get_project()
            .withf(|_, id: &'_ str| id == "missing")
            .returning(|_, _| Ok(None));
        m.expect_get_project_subtree()
            .withf(|_, id: &'_ str| id == "p2")
            .returning(|_, _| Ok(Some(vec![proj("p1", Some("did")), proj("p3", Some("p2"))])));
        m
    }

    async fn call(uri: &str, allow: bool, authed: bool) -> (StatusCode, Value) {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(mock()),
            allow,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut req = Request::builder().uri(uri);
        if authed {
            req = req.extension(test_fixture_scoped());
        }
        let response = api
            .as_service()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn test_list() {
        let (status, body) = call("/p2/subtree", true, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["subtree"].as_array().map(Vec::len), Some(2));
        assert_eq!(body["subtree"][0]["project"]["id"], json!("p1"));
    }

    #[tokio::test]
    async fn test_list_as_ids() {
        let (status, body) = call("/p2/subtree?as_ids", true, true).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["subtree"].is_object());
    }

    #[tokio::test]
    async fn test_list_not_found() {
        let (status, _) = call("/missing/subtree", true, true).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_not_allowed() {
        let (status, _) = call("/p2/subtree", false, true).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthenticated() {
        let (status, _) = call("/p2/subtree", true, false).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
