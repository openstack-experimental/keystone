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

//! # K8s auth API: authenticate
use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_api_types::k8s_auth::K8sAuthRequest;
use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::auth::{AuthenticationContext, ScopeInfo, SecurityContext};
use openstack_keystone_core_types::mapping::MappingContext;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::resource::{Domain, Project};
use tracing::{debug, warn};

use crate::api::types::{Catalog, CatalogService};
use crate::api::v4::auth::token::types::TokenResponse;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(post))
}

/// Authenticate using the JWT token of the Kubernetes service account.
///
/// Validates the JWT via TokenReview, flattens claims, and delegates to the
/// unified mapping engine for identity resolution and authorization.
#[utoipa::path(
    post,
    path = "/instances/{instance_id}/auth",
    operation_id = "/k8s_auth/auth:post",
    request_body = K8sAuthRequest,
    responses(
        (
            status = OK,
            description = "Authentication Token object",
            body = TokenResponse,
            headers(
                ("x-subject-token" = String, description = "Keystone token"),
            ),
        ),
    ),
    tag="k8s_auth_instance"
)]
#[tracing::instrument(
    name = "api::identity_provider_auth",
    level = "debug",
    skip(state),
    err(Debug)
)]
#[debug_handler]
pub async fn post(
    State(state): State<ServiceState>,
    Path(instance_id): Path<String>,
    Json(req): Json<K8sAuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let (ctx, scope) = mapping_auth(&state, &req.to_provider_with_instance_id(instance_id)).await?;

    let exec = ExecutionContext::internal(&state);
    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(exec.state(), &ctx, &scope)
        .await?;

    let mut api_token = TokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    api_token.validate()?;

    let catalog: Catalog = Catalog(
        state
            .provider
            .get_catalog_provider()
            .get_catalog(&exec, true)
            .await?
            .into_iter()
            .map(|(s, es)| CatalogService {
                id: s.id.clone(),
                name: s.name(),
                r#type: s.r#type,
                endpoints: es.into_iter().map(Into::into).collect(),
            })
            .collect::<Vec<_>>(),
    );
    api_token.token.catalog = Some(catalog);

    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state
                .provider
                .get_token_provider()
                .encode_token(vsc.token()?)?,
        )],
        Json(api_token),
    )
        .into_response())
}

/// Mapping-engine authentication path: delegates to the unified mapping engine
/// for identity resolution and authorization.
///
/// Validates the JWT via TokenReview, flattens claims, and delegates to the
/// mapping engine. The first authorization from the matched rule is used as the
/// token scope.
async fn mapping_auth(
    state: &ServiceState,
    req: &openstack_keystone_core_types::k8s_auth::K8sAuthRequest,
) -> Result<(SecurityContext, ScopeInfo), KeystoneApiError> {
    let auth_result = state
        .provider
        .get_k8s_auth_provider()
        .authenticate_by_k8s_mapping(&ExecutionContext::internal(state), req)
        .await?;

    let ctx = SecurityContext::try_from(auth_result)?;

    // Resolve scope from the first authorization in the matched rule.
    // Mapping-engine authorizations are stored on the virtual user and carried
    // in the authentication result's authorization field. If present, use that;
    // otherwise fall back to unscoped.
    let scope = if let Some(authz) = ctx.authorization() {
        authz.scope.clone()
    } else {
        debug!("mapping_auth: ctx.authorization() is None, falling back to scope derivation");
        let mapping_ctx: MappingContext = match ctx.authentication_context() {
            AuthenticationContext::Mapping(mc) => mc.clone(),
            _ => unreachable!("mapping auth always produces Mapping context"),
        };

        // If is_system and no authorization in context, the ruleset likely
        // provides no explicit roles. Fall through to storage fallback.
        if mapping_ctx.is_system {
            ScopeInfo::Unscoped
        } else {
            // Slow path: read virtual user to derive scope from authorizations.
            // On a follower this read can race with Raft replication (ForwardToLeader
            // always fails locally), so handle the None gracefully to avoid aborting
            // the HTTP connection with a panic.
            match state
                .provider
                .get_mapping_provider()
                .get_virtual_user(
                    &ExecutionContext::internal(state),
                    &mapping_ctx.virtual_user_id,
                )
                .await
            {
                Ok(Some(vu)) => derive_scope_from_authorizations(&vu.authorizations)?,
                Ok(None) => {
                    // Virtual user not found locally (Raft replication lag).
                    // The ruleset match is trustworthy; fall back to unscoped
                    // to avoid aborting the connection. This returns a 401 instead
                    // of a server-panic connection drop.
                    warn!(
                        virtual_user_id = mapping_ctx.virtual_user_id,
                        "virtual user not found locally, falling back to unscoped scope"
                    );
                    ScopeInfo::Unscoped
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    scope.validate()?;

    Ok((ctx, scope))
}

/// Derive a [`ScopeInfo`] from the first authorization in the virtual user's
/// authorization list.
///
/// If no authorizations are present, returns [`ScopeInfo::Unscoped`].
fn derive_scope_from_authorizations(
    authorizations: &[Authorization],
) -> Result<ScopeInfo, KeystoneApiError> {
    if let Some(first) = authorizations.first() {
        match first {
            Authorization::Project {
                project_id,
                project_domain_id,
                ..
            } => {
                let domain = Domain {
                    id: project_domain_id.clone(),
                    name: String::new(),
                    description: None,
                    enabled: true,
                    extra: Default::default(),
                };
                let project = Project {
                    id: project_id.clone(),
                    domain_id: project_domain_id.clone(),
                    name: String::new(),
                    description: None,
                    enabled: true,
                    is_domain: false,
                    parent_id: None,
                    extra: Default::default(),
                };
                Ok(ScopeInfo::Project {
                    project,
                    project_domain: domain,
                })
            }
            Authorization::Domain { domain_id, .. } => {
                let domain = Domain {
                    id: domain_id.clone(),
                    name: String::new(),
                    description: None,
                    enabled: true,
                    extra: Default::default(),
                };
                Ok(ScopeInfo::Domain(domain))
            }
            Authorization::System { system_id, .. } => Ok(ScopeInfo::System(system_id.clone())),
        }
    } else {
        Ok(ScopeInfo::Unscoped)
    }
}

#[cfg(test)]
mod tests {

    use openstack_keystone_core_types::auth::ScopeInfo;
    use openstack_keystone_core_types::mapping::authorization::Authorization;

    use openstack_keystone_core_types::role::RoleRef;

    use super::*;

    fn member_role() -> RoleRef {
        RoleRef {
            id: "member".into(),
            name: Some("member".into()),
            domain_id: None,
        }
    }

    #[test]
    fn test_derive_scope_project() {
        let authz = Authorization::Project {
            project_id: "proj-123".into(),
            project_domain_id: "domain-1".into(),
            roles: vec![member_role()],
        };
        let scope = derive_scope_from_authorizations(&[authz]).unwrap();
        match scope {
            ScopeInfo::Project {
                project,
                project_domain,
            } => {
                assert_eq!(project.id, "proj-123");
                assert_eq!(project.domain_id, "domain-1");
                assert_eq!(project_domain.id, "domain-1");
            }
            _ => panic!("expected Project scope"),
        }
    }

    #[test]
    fn test_derive_scope_domain() {
        let authz = Authorization::Domain {
            domain_id: "domain-1".into(),
            roles: vec![member_role()],
        };
        let scope = derive_scope_from_authorizations(&[authz]).unwrap();
        assert!(matches!(scope, ScopeInfo::Domain(_)));
    }

    #[test]
    fn test_derive_scope_system() {
        let authz = Authorization::System {
            system_id: "all".into(),
            roles: vec![member_role()],
        };
        let scope = derive_scope_from_authorizations(&[authz]).unwrap();
        assert!(matches!(scope, ScopeInfo::System(_)));
    }

    #[test]
    fn test_derive_scope_unscoped() {
        let scope = derive_scope_from_authorizations(&[]).unwrap();
        assert!(matches!(scope, ScopeInfo::Unscoped));
    }
}
