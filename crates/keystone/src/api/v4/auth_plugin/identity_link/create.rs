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
//! Dynamic plugin identity link: create (ADR 0025 §4).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::auth_plugin::{
    IdentityLink, IdentityLinkCreateRequest, IdentityLinkResponse,
};
use openstack_keystone_core::auth::ExecutionContext;
use validator::Validate;

use super::{domain_allowed, require_full_auth_plugin, target_holds_system_role};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Create an admin-authorized `(plugin_name, external_id) -> user_id` link.
#[utoipa::path(
    post,
    path = "/{plugin_name}/identity_links",
    operation_id = "/auth_plugin/identity_link:create",
    params(("plugin_name" = String, Path, description = "Dynamic plugin name")),
    request_body = IdentityLinkCreateRequest,
    responses(
        (status = CREATED, description = "Identity link", body = IdentityLinkResponse),
        (status = CONFLICT, description = "external_id already linked"),
    ),
    security(("x-auth" = [])),
    tag = "auth_plugin"
)]
#[tracing::instrument(
    name = "api::v4::auth_plugin::identity_link::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(crate) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Path(plugin_name): Path<String>,
    Json(req): Json<IdentityLinkCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let external_id = req.identity_link.external_id;
    let user_id = req.identity_link.user_id;

    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let config = require_full_auth_plugin(&state, &plugin_name).await?;

    // Resolve the target user and its live domain.
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: user_id.clone(),
        })?;
    let domain_id = user.domain_id.clone();

    // The link can never place a user outside the plugin's configured
    // provisioning domain(s) (ADR §4) - checked here at link time and again
    // in `find_user` at every resolve time.
    if !domain_allowed(&config, &domain_id) {
        return Err(KeystoneApiError::BadRequest(format!(
            "user {user_id}'s domain {domain_id} is outside plugin {plugin_name}'s provisioning domain(s)"
        )));
    }

    // RBAC tiering (ADR §4): system-admin required to link a principal that
    // holds any system-scope role; domain-admin scoped to the target's own
    // domain suffices otherwise. The decision itself is the policy's - the
    // handler only supplies the facts it keys on.
    let is_system = target_holds_system_role(&state, &exec, &user_id).await?;
    state
        .policy_enforcer
        .enforce(
            "identity/auth_plugin/identity_link/create",
            &user_auth,
            serde_json::json!({
                "identity_link": {
                    "plugin_name": plugin_name,
                    "user_id": user_id,
                    "domain_id": domain_id,
                    "is_system": is_system,
                }
            }),
            None,
        )
        .await?;

    // No silent overwrite (ADR §4): re-linking an external_id that already
    // has an entry is a conflict; an admin must DELETE it first.
    let dpi = state.provider.get_auth_plugin_identity_provider();
    if dpi.find(&exec, &plugin_name, &external_id).await?.is_some() {
        return Err(KeystoneApiError::Conflict(format!(
            "external_id {external_id} is already linked for plugin {plugin_name}"
        )));
    }
    // `create_or_resolve` is atomic on `(plugin_name, external_id)`: if a
    // concurrent admin link won the race, it returns that winner's user_id,
    // which we surface as the same conflict rather than a silent success.
    let canonical = dpi
        .create_or_resolve(&exec, &plugin_name, &external_id, &user_id)
        .await?;
    if canonical != user_id {
        return Err(KeystoneApiError::Conflict(format!(
            "external_id {external_id} is already linked for plugin {plugin_name}"
        )));
    }

    Ok((
        StatusCode::CREATED,
        Json(IdentityLinkResponse {
            identity_link: IdentityLink {
                plugin_name,
                external_id,
                user_id,
            },
        }),
    )
        .into_response())
}
