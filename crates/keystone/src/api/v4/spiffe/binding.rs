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
//! SPIFFE binding API.
//!
//! OPA input structure for all spiffe/binding operations:
//! ```text
//! {
//!   "credentials": { ... },
//!   "target": { "binding": <object-or-null> },
//!   "existing": { "binding": <object-or-null> }
//! }
//! ```
//!
//! | Operation | `input.target.binding`       | `input.existing.binding`    |
//! |-----------|-----------------------------|----------------------------|
//! | Create    | Enriched new binding         | null                       |
//! | Update    | Enriched patch (authorizations) | Raw current binding   |
//! | Show      | null                         | Raw current binding        |
//! | Delete    | null                         | Raw current binding        |
//! | List      | Query parameters             | null                       |

use serde::Serialize;
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use openstack_keystone_api_types::v4::spiffe::*;
use openstack_keystone_core_types::resource::{Domain, Project};
use openstack_keystone_core_types::role::RoleRef;

mod create;
mod delete;
mod list;
mod show;
mod update;

use crate::keystone::ServiceState;
use crate::resource::ResourceApi;
use crate::role::RoleApi;

/// OpenApi specification for the SPIFFE binding api.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="spiffe_binding", description=r#"SPIFFE binding API.

SPIFFE bindings map SVIDs to OpenStack authorization (Actor/Scope/Roles).
        "#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(show::show, delete::remove, update::update))
        .routes(routes!(list::list, create::create))
}

/// SPIFFE binding enriched with resolved authorization objects for policy
/// evaluation.
///
/// Used by the create handler. Resolved objects are `None` when lookup
/// fails, preventing resource-existence information leakage.
///
/// Serialized under `input.target.binding` for create operations.
#[derive(Serialize)]
pub(super) struct EnrichedSpiffeBinding<'a> {
    pub domain_id: &'a str,
    pub is_system: bool,
    pub svid: &'a str,
    pub user_id: Option<&'a str>,
    pub authorizations: Option<Vec<EnrichedSpiffeAuthorization>>,
}

/// Enriched patch for update operations.
///
/// Only contains the `authorizations` field from the user's update request,
/// enriched with resolved Domain/Project/Role objects. Serialized under
/// `input.target.binding` for update policy evaluation.
#[derive(Serialize)]
pub(super) struct EnrichedSpiffeBindingUpdate {
    pub authorizations: Option<Vec<EnrichedSpiffeAuthorization>>,
}

/// SPIFFE authorization enriched with resolved objects for policy evaluation.
///
/// Used by the create/update handlers to serialize the binding's authorizations
/// together with the resolved Domain, Project, and Role objects for OPA policy
/// evaluation. Resolved objects are `None` when the lookup fails or the
/// resource does not exist, preventing information leakage about resource
/// existence.
///
/// The OPA policy receives both the raw string IDs and the optional resolved
/// objects, allowing it to make nuanced authorization decisions without the
/// handler leaking which resources were or were not found.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum EnrichedSpiffeAuthorization {
    Domain {
        domain_id: String,
        /// Resolved domain object. `None` if the domain does not exist or the
        /// provider returned an error.
        domain: Option<Domain>,
        role_ids: Option<Vec<String>>,
        /// Resolved role references. `None` if no role IDs were provided.
        /// Contains only the roles that were successfully resolved.
        roles: Option<Vec<RoleRef>>,
    },
    Project {
        project_id: String,
        /// Resolved project object. `None` if the project does not exist or the
        /// provider returned an error.
        project: Option<Project>,
        role_ids: Option<Vec<String>>,
        /// Resolved role references. `None` if no role IDs were provided.
        /// Contains only the roles that were successfully resolved.
        roles: Option<Vec<RoleRef>>,
    },
    System {
        system_id: String,
        role_ids: Option<Vec<String>>,
        /// Resolved role references. `None` if no role IDs were provided.
        /// Contains only the roles that were successfully resolved.
        roles: Option<Vec<RoleRef>>,
    },
}

/// Resolve `SpiffeAuthorization` entries to `EnrichedSpiffeAuthorization` with
/// resolved Domain, Project, and Role objects.
///
/// Always succeeds and never returns an error. Unresolvable resources silently
/// produce `None` for the corresponding resolved object (domain, project,
/// role). This prevents information leakage: a missing resource and a provider
/// error produce the same enrichment outcome.
async fn enrich_authorizations_list(
    state: &ServiceState,
    authorizations: Option<Vec<SpiffeAuthorization>>,
) -> Option<Vec<EnrichedSpiffeAuthorization>> {
    let Some(auths) = authorizations else {
        return None;
    };

    let mut enriched = Vec::with_capacity(auths.len());

    for auth in auths {
        match auth {
            SpiffeAuthorization::Domain {
                domain_id,
                role_ids,
            } => {
                let domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(state, &domain_id)
                    .await
                    .ok()
                    .flatten();
                let roles = resolve_roles(state, role_ids.as_ref()).await;
                enriched.push(EnrichedSpiffeAuthorization::Domain {
                    domain_id,
                    domain,
                    role_ids,
                    roles,
                });
            }
            SpiffeAuthorization::Project {
                project_id,
                role_ids,
            } => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(state, &project_id)
                    .await
                    .ok()
                    .flatten();
                let roles = resolve_roles(state, role_ids.as_ref()).await;
                enriched.push(EnrichedSpiffeAuthorization::Project {
                    project_id,
                    project,
                    role_ids,
                    roles,
                });
            }
            SpiffeAuthorization::System {
                system_id,
                role_ids,
            } => {
                let roles = resolve_roles(state, role_ids.as_ref()).await;
                enriched.push(EnrichedSpiffeAuthorization::System {
                    system_id,
                    role_ids,
                    roles,
                });
            }
        }
    }

    Some(enriched)
}

/// Resolve a list of role IDs to `RoleRef` objects.
///
/// Silently skips roles that are not found or cause a provider error. The
/// returned `Option<Vec<RoleRef>>` contains only the roles that were
/// successfully resolved. It returns `None` when the input role IDs list is
/// empty. This is not a security concern, as OPA policy uses the credential's
/// role list for authorization decisions; the resolved roles here are only for
/// binding-level metadata.
async fn resolve_roles(
    state: &ServiceState,
    role_ids: Option<&Vec<String>>,
) -> Option<Vec<RoleRef>> {
    let ids = role_ids?;
    let mut r = Vec::new();
    for id in ids {
        if let Ok(Some(role)) = state.provider.get_role_provider().get_role(state, id).await {
            r.push(role.into());
        }
    }
    Some(r)
}
