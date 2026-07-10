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
//! Dynamic plugin identity link: delete (ADR 0025 §4). Removing a link also
//! revokes the unlinked user's live tokens, so an identity can't keep using
//! tokens issued while the link was active.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::revoke::RevocationEventCreate;

use super::{require_full_auth_plugin, target_holds_system_role};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Delete an admin-authorized identity link and revoke the user's tokens.
#[utoipa::path(
    delete,
    path = "/{plugin_name}/identity_links/{external_id}",
    operation_id = "/auth_plugin/identity_link:delete",
    params(
        ("plugin_name" = String, Path, description = "Dynamic plugin name"),
        ("external_id" = String, Path, description = "External identity id"),
    ),
    responses(
        (status = NO_CONTENT, description = "Identity link deleted"),
        (status = NOT_FOUND, description = "No such identity link"),
    ),
    security(("x-auth" = [])),
    tag = "auth_plugin"
)]
#[tracing::instrument(
    name = "api::v4::auth_plugin::identity_link::delete",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(crate) async fn delete(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Path((plugin_name, external_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let exec = ExecutionContext::from_auth(&state, &user_auth);
    require_full_auth_plugin(&state, &plugin_name).await?;

    let dpi = state.provider.get_auth_plugin_identity_provider();
    let user_id = dpi
        .find(&exec, &plugin_name, &external_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "identity_link".to_string(),
            identifier: external_id.clone(),
        })?;

    // Resolve target facts for RBAC tiering. A link to a since-deleted user
    // is still deletable (stale-entry cleanup); we just pass the facts we can
    // establish and let policy decide.
    let (domain_id, is_system) = match state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user_id)
        .await?
    {
        Some(user) => {
            let is_system = target_holds_system_role(&state, &exec, &user_id).await?;
            (Some(user.domain_id), is_system)
        }
        None => (None, false),
    };

    state
        .policy_enforcer
        .enforce(
            "identity/auth_plugin/identity_link/delete",
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

    dpi.purge(&exec, &plugin_name, &external_id).await?;

    // Revoke live sessions for the unlinked user (ADR §4, same mechanism a
    // disabled virtual user uses - ADR 0020 §9.F).
    state
        .provider
        .get_revoke_provider()
        .create_revocation_event(
            &exec,
            RevocationEventCreate {
                domain_id,
                project_id: None,
                user_id: Some(user_id),
                role_id: None,
                trust_id: None,
                consumer_id: None,
                access_token_id: None,
                issued_before: Utc::now(),
                expires_at: None,
                audit_id: None,
                audit_chain_id: None,
                revoked_at: Utc::now(),
            },
        )
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
