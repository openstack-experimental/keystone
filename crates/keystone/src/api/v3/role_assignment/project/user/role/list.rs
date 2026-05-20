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

//! Project user role: list.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use serde_json::json;
use tracing::info;


use openstack_keystone_api_types::v3::role_assignment::{Role, RoleAssignmentRoleList};
use openstack_keystone_core_types::assignment::RoleAssignmentListParameters;

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::{
    api::auth::Auth, assignment::AssignmentApi, identity::IdentityApi, resource::ResourceApi};

/// List the roles that a user has on a project.
///
/// List the roles that a user has on a project.
#[utoipa::path(
    head,
    path = "/projects/{project_id}/users/{user_id}/roles",
    operation_id = "/project/user/role:list",
    params(
      ("project_id" = String, Path, description = "The project ID."),
      ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = OK, description = "List of roles", example = json!([])),
        (status = 404, description = "User or project not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::project_user_role_list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]

pub(super) async fn list(
    Auth(user_auth): Auth,
    Path((project_id, user_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let query_params = RoleAssignmentListParameters {
        user_id: Some(user_id.clone()),
        project_id: Some(project_id.clone()),
        effective: Some(true),
        include_names: Some(false),
        ..Default::default()
    };
    // Use join instead of try_join to have more constant latency preventing timing
    // attacks.
    let (user, project, assignments) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id),
        state
            .provider
            .get_resource_provider()
            .get_project(&state, &project_id),
        state
            .provider
            .get_assignment_provider()
            .list_role_assignments(&state, &query_params)
    );
    let user = user?.ok_or_else(|| {
        info!("User {} was not found", user_id);
        KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        }
    })?;
    let project = project?.ok_or_else(|| {
        info!("Project {} was not found", project_id);
        KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        }
    })?;
    // let role = role?.ok_or_else(|| {
    //     info!("Role {} was not found", role_id);
    //     KeystoneApiError::NotFound {
    //         resource: "grant".into(),
    //         identifier: "".into(),
    //     }
    // })?;

    state
        .policy_enforcer
        .enforce(
            "identity/project/user/role/list",
            &user_auth,
            json!({"user": user,  "project": project}),
            None,
        )
        .await?;

    // let grants: Vec<Assignment> = assignments?.into_iter().collect();

    let roles: Vec<Role> = assignments?
        .into_iter()
        .map(|a| a.try_into())
        .collect::<Result<Vec<_>, _>>()?;

    Ok((StatusCode::OK, Json(RoleAssignmentRoleList { roles })).into_response())
}
