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
//! Bulk revocation of a compromised `full_auth` plugin's persistent state
//! (ADR 0025 §4 "Bulk Revocation on Plugin Compromise"). One system-admin
//! call, scoped to a single `plugin_name`, disables every user the plugin
//! provisioned or that an admin linked to it, deletes those identity links,
//! and revokes the affected users' live tokens.
//!
//! It deliberately does **not** revoke the role assignments the plugin
//! granted: tracking per-assignment origin is bookkeeping this ADR rejects
//! elsewhere (see "Why plugin-name-scoped, not version-scoped"). Disabling the
//! account already denies all access; the operator reviews the disabled users'
//! remaining roles against the CADF audit trail (§6.E records `plugin_name` on
//! every `assign_role`) and revokes any they deem compromised out of band.

use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use openstack_keystone_api_types::v4::auth_plugin::{RevokeAllResponse, RevokeAllSummary};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::identity::UserUpdate;
use openstack_keystone_core_types::revoke::RevocationEventCreate;

use super::identity_link::require_full_auth_plugin;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Revoke all persistent state a `full_auth` plugin wrote.
#[utoipa::path(
    post,
    path = "/{plugin_name}/revoke_all",
    operation_id = "/auth_plugin/revoke_all",
    params(("plugin_name" = String, Path, description = "Dynamic plugin name")),
    responses(
        (status = OK, description = "Revocation summary", body = RevokeAllResponse),
        (status = NOT_FOUND, description = "No such dynamic plugin"),
    ),
    security(("x-auth" = [])),
    tag = "auth_plugin"
)]
#[tracing::instrument(
    name = "api::v4::auth_plugin::revoke_all",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(crate) async fn revoke_all(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Path(plugin_name): Path<String>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let exec = ExecutionContext::from_auth(&state, &user_auth);
    require_full_auth_plugin(&state, &plugin_name).await?;

    // System-admin only (rego): a cross-domain action by construction, since a
    // plugin's provisioning domains and role grants can span any domain, so no
    // narrower RBAC tier is meaningful (ADR §4).
    state
        .policy_enforcer
        .enforce(
            "identity/auth_plugin/revoke_all",
            &user_auth,
            serde_json::json!({ "plugin_name": plugin_name }),
            None,
        )
        .await?;

    let dpi = state.provider.get_auth_plugin_identity_provider();
    let links = dpi.list_by_plugin(&exec, &plugin_name).await?;
    let links_deleted = links.len();

    let identity = state.provider.get_identity_provider();
    let revoke = state.provider.get_revoke_provider();

    // Disable + revoke each distinct affected user once (an admin link and a
    // self-provision can point at the same user_id).
    let mut seen = HashSet::new();
    let mut users_disabled = 0usize;
    for (_external_id, user_id) in &links {
        if !seen.insert(user_id.as_str()) {
            continue;
        }
        // Disable (not delete) the account, reusing the same disable path a
        // disabled virtual user uses (ADR 0020 §9.F). A link pointing at a
        // since-deleted user still gets a (harmless) revocation event so any
        // token minted while it existed cannot outlive this call.
        let domain_id = match identity.get_user(&exec, user_id).await? {
            Some(user) => {
                identity
                    .update_user(
                        &exec,
                        user_id,
                        UserUpdate {
                            enabled: Some(false),
                            ..Default::default()
                        },
                    )
                    .await?;
                users_disabled += 1;
                Some(user.domain_id)
            }
            None => None,
        };

        revoke
            .create_revocation_event(
                &exec,
                RevocationEventCreate {
                    domain_id,
                    project_id: None,
                    user_id: Some(user_id.clone()),
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
    }

    // Delete every remaining identity-link entry for the plugin - the batched
    // equivalent of the per-external_id DELETE.
    for (external_id, _user_id) in &links {
        dpi.purge(&exec, &plugin_name, external_id).await?;
    }

    Ok((
        StatusCode::OK,
        Json(RevokeAllResponse {
            revoke_all: RevokeAllSummary {
                users_disabled,
                links_deleted,
            },
        }),
    )
        .into_response())
}
