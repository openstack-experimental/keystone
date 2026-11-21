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

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v3::project::show::{
    filter_visible, flag, get_visible_project, subtree_to_ids, to_list,
};
use crate::api::v3::project::types::{ProjectRelativesParameters, ProjectSubtreeResponse};
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List project subtree
///
/// Lists all descendants of the project, breadth first.
/// Only the projects the caller is allowed to see are
/// returned. The `as_ids` query parameter returns a nested object of the
/// project IDs instead of the list.
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
#[tracing::instrument(name = "api::v4::project_subtree", level = "debug", skip(state))]
pub(super) async fn subtree(
    Auth(user_auth): Auth,
    Path(project_id): Path<String>,
    Query(query): Query<ProjectRelativesParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let ctx = ExecutionContext::from_auth(&state, &user_auth);
    // The target project itself must be visible to the caller.
    get_visible_project(&state, &ctx, &user_auth, &project_id).await?;

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
    use axum::http::StatusCode;
    use serde_json::json;

    use super::super::test_support::{call, proj};
    use crate::resource::MockResourceProvider;

    fn mock() -> MockResourceProvider {
        let mut m = MockResourceProvider::default();
        m.expect_get_project()
            .withf(|_, id: &'_ str| id == "p1")
            .returning(|_, _| Ok(Some(proj("p1", Some("did")))));
        m.expect_get_project()
            .withf(|_, id: &'_ str| id == "missing")
            .returning(|_, _| Ok(None));
        m.expect_get_project_subtree()
            .withf(|_, id: &'_ str| id == "p1")
            .returning(|_, _| {
                Ok(Some(vec![
                    proj("p2", Some("p1")),
                    proj("p3", Some("p2")),
                    proj("p4", Some("p3")),
                ]))
            });
        m
    }

    #[tokio::test]
    async fn test_list() {
        let (status, body) = call("/p1/subtree", mock(), true, None, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["subtree"].as_array().map(Vec::len), Some(3));
        assert_eq!(body["subtree"][0]["project"]["id"], json!("p2"));
    }

    #[tokio::test]
    async fn test_list_as_ids() {
        let (status, body) = call("/p1/subtree?as_ids", mock(), true, None, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["subtree"], json!({"p2": {"p3": {"p4": null}}}));
    }

    #[tokio::test]
    async fn test_list_hides_denied_project() {
        let (status, body) = call("/p1/subtree", mock(), true, Some("p2"), true).await;
        assert_eq!(status, StatusCode::OK);
        let ids: Vec<&str> = body["subtree"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x["project"]["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["p3", "p4"]);
    }

    #[tokio::test]
    async fn test_list_as_ids_reattaches_to_visible_ancestor() {
        let (status, body) = call("/p1/subtree?as_ids", mock(), true, Some("p2"), true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["subtree"], json!({"p3": {"p4": null}}));
    }

    #[tokio::test]
    async fn test_list_not_found() {
        let (status, _) = call("/missing/subtree", mock(), true, None, true).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_not_allowed() {
        let (status, _) = call("/p1/subtree", mock(), false, None, true).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthenticated() {
        let (status, _) = call("/p1/subtree", mock(), true, None, false).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
