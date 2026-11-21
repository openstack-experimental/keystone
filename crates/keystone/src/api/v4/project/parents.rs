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
//! # List project parents API

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v3::project::show::{
    filter_visible, flag, get_visible_project, parents_to_ids, to_list,
};
use crate::api::v3::project::types::{ProjectParentsResponse, ProjectRelativesParameters};
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List project parents
///
/// Lists the parents of the project, the closest first.
/// Only the projects the caller is allowed to see are
/// returned. The `as_ids` query parameter returns a nested object of the
/// project IDs instead of the list.
#[utoipa::path(
    get,
    path = "/{project_id}/parents",
    params(ProjectRelativesParameters),
    responses(
        (status = OK, description = "Project parents", body = ProjectParentsResponse),
        (status = 404, description = "Project not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v4::project_parents", level = "debug", skip(state))]
pub(super) async fn parents(
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
        .get_project_parents(&ctx, &project_id)
        .await?
        .unwrap_or_default();
    let visible = filter_visible(&state, &user_auth, found).await?;
    let parents = if flag(&query.as_ids) {
        parents_to_ids(&visible)
    } else {
        to_list(visible)
    };
    Ok((StatusCode::OK, Json(ProjectParentsResponse { parents })))
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
            .withf(|_, id: &'_ str| id == "p3")
            .returning(|_, _| Ok(Some(proj("p3", Some("p2")))));
        m.expect_get_project()
            .withf(|_, id: &'_ str| id == "missing")
            .returning(|_, _| Ok(None));
        m.expect_get_project_parents()
            .withf(|_, id: &'_ str| id == "p3")
            .returning(|_, _| Ok(Some(vec![proj("p2", Some("p1")), proj("p1", Some("did"))])));
        m
    }

    #[tokio::test]
    async fn test_list() {
        let (status, body) = call("/p3/parents", mock(), true, None, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["parents"].as_array().map(Vec::len), Some(2));
        assert_eq!(body["parents"][0]["project"]["id"], json!("p2"));
        assert_eq!(body["parents"][1]["project"]["id"], json!("p1"));
    }

    #[tokio::test]
    async fn test_list_as_ids() {
        let (status, body) = call("/p3/parents?as_ids", mock(), true, None, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["parents"], json!({"p2": {"p1": null}}));
    }

    #[tokio::test]
    async fn test_list_hides_denied_project() {
        let (status, body) = call("/p3/parents", mock(), true, Some("p2"), true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["parents"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["parents"][0]["project"]["id"], json!("p1"));
    }

    #[tokio::test]
    async fn test_list_not_found() {
        let (status, _) = call("/missing/parents", mock(), true, None, true).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_not_allowed() {
        let (status, _) = call("/p3/parents", mock(), false, None, true).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthenticated() {
        let (status, _) = call("/p3/parents", mock(), true, None, false).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
