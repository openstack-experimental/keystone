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
use std::collections::HashSet;
use std::ops::Deref;

use chrono::Utc;
use tracing::debug;

use openstack_keystone_core_types::assignment::{
    AssignmentProviderError, RoleAssignmentListParametersBuilder,
};
use openstack_keystone_core_types::identity::IdentityProviderError;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::role::*;
use openstack_keystone_core_types::spiffe::*;
use openstack_keystone_core_types::token::FernetToken;

use crate::assignment::AssignmentApi;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::mapping::MappingApi;
use crate::resource::ResourceApi;
use crate::role::RoleApi;
use crate::trust::TrustApi;

pub use openstack_keystone_core_types::auth::*;

/// Conversion trait that forces the caller to provide context information when
/// converting a provider error into [`AuthenticationError::Provider`]. Similar
/// to [`crate::error::DbContextExt`] but for authentication validation errors.
pub trait IntoAuthContext<T> {
    /// Converts the result error into `AuthenticationError::Provider` with the
    /// given context label.
    ///
    /// # Parameters
    /// - `ctx`: The context message to add to the error.
    ///
    /// # Returns
    /// - `Result<T, AuthenticationError>` - The original result or a wrapped
    ///   `AuthenticationError::Provider`.
    fn auth_context(self, ctx: impl Into<String>) -> Result<T, AuthenticationError>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> IntoAuthContext<T> for Result<T, E> {
    fn auth_context(self, ctx: impl Into<String>) -> Result<T, AuthenticationError> {
        self.map_err(|e| AuthenticationError::Provider {
            source: Box::new(e),
            context: Some(ctx.into()),
        })
    }
}

// Validated security context.
//
// Prevent use of unvalidated context
#[derive(Clone, Debug)]
pub struct ValidatedSecurityContext(SecurityContext);

impl ValidatedSecurityContext {
    /// The validated security context.
    #[must_use]
    pub fn inner(&self) -> &SecurityContext {
        &self.0
    }

    /// Validate the SecurityContext for the given scope, resolving effective
    /// roles and returning a locked context.
    ///
    /// When a scope is requested that differs from any scope already set on the
    /// context, [`SecurityContext::validate_scope_boundaries`] is enforced to
    /// guard the override. Scope-setting, validation, and role resolution
    /// happen as a single atomic step.
    #[tracing::instrument(skip(state), err(Debug))]
    pub async fn new_for_scope(
        mut ctx: SecurityContext,
        scope: ScopeInfo,
        state: &ServiceState,
    ) -> Result<Self, AuthenticationError> {
        // Scope conflict check: if scope already set and differs, enforce
        // boundary validation to prevent accidental scope override.
        if let Some(existing_authz) = ctx.authorization() {
            if existing_authz.scope != scope {
                ctx.validate_scope_boundaries(&scope)?;
            }
        } else {
            ctx.set_authorization_scope(scope.clone())?;
        }
        let scope_clone = scope;

        // Populate user_domain before validation, since validate() requires it
        if let IdentityInfo::User(user_info) = &ctx.principal().identity
            && user_info.user_domain.is_none()
            && let Some(domain) = &user_info.user
        {
            let domain_id = &domain.domain_id;
            let user_domain = state
                .provider
                .get_resource_provider()
                .get_domain(state, domain_id)
                .await
                .auth_context("fetching user domain")?
                .ok_or(ResourceProviderError::DomainNotFound(domain_id.clone()))
                .auth_context("fetching user domain")?;
            ctx.populate_user_domain(user_domain);
        }
        ctx.validate()?;
        let now = Utc::now();
        if ctx.expires_at().is_some_and(|expiry| expiry < now) {
            return Err(AuthenticationError::AuthTokenExpired);
        }
        // Not all of the checks can be done synchronously inside the SecurityContext.
        // Do whatever else is required.
        match &ctx.authentication_context() {
            AuthenticationContext::ApplicationCredential {
                application_credential,
                ..
            } => {
                if application_credential.user_id != ctx.principal().get_user_id() {
                    return Err(AuthenticationError::AuthzPrincipalMismatch);
                }

                if application_credential
                    .expires_at
                    .is_some_and(|expiry| expiry < Utc::now())
                {
                    return Err(AuthenticationError::AuthApplicationCredentialExpired);
                }
            }
            AuthenticationContext::Oidc { .. } => {}
            AuthenticationContext::K8s(..) => {}
            AuthenticationContext::Password => {}
            AuthenticationContext::Spiffe(..) => {}
            AuthenticationContext::Trust { trust, .. } => {
                // Validate the trust chain
                state
                    .provider
                    .get_trust_provider()
                    .validate_trust_delegation_chain(state, trust)
                    .await
                    .auth_context("validating trust delegation chain")?;

                if trust.trustee_user_id != ctx.principal().get_user_id() {
                    return Err(AuthenticationError::AuthzPrincipalMismatch);
                }

                // Resolve and verify trustor user is enabled and resolves to a
                // domain that is also enabled
                let trustor = state
                    .provider
                    .get_identity_provider()
                    .get_user(state, &trust.trustor_user_id)
                    .await
                    .auth_context("fetching trustor user")?
                    .ok_or(IdentityProviderError::UserNotFound(
                        trust.trustor_user_id.clone(),
                    ))
                    .auth_context("fetching trustor user")?;
                if !trustor.enabled {
                    return Err(AuthenticationError::TrustorUserDisabled(
                        trust.trustor_user_id.clone(),
                    ));
                }

                // TODO: this hints to eventual necessity to include trustor information in the
                // Context statically.
                if let IdentityInfo::User(user) = &ctx.principal().identity {
                    if let Some(user) = &user.user
                        && user.domain_id != trustor.domain_id
                    {
                        let trustor_domain_enabled = state
                            .provider
                            .get_resource_provider()
                            .get_domain_enabled(state, &trustor.domain_id)
                            .await
                            .auth_context("get_trustor_domain_enabled")?;
                        if !trustor_domain_enabled {
                            return Err(AuthenticationError::TrustorDomainDisabled);
                        }
                    }
                } else {
                    return Err(AuthenticationError::TrustorPrincipalUseNotSupported);
                }
            }
            AuthenticationContext::Token(..) => {}
            AuthenticationContext::WebauthN => {}
            AuthenticationContext::Mapping(mc) => {
                // Read virtual user shadow record to get allowed authorizations
                let vu = state
                    .provider
                    .get_mapping_provider()
                    .get_virtual_user(state, &mc.virtual_user_id)
                    .await
                    .auth_context("fetching virtual user for scope resolution")?
                    .ok_or(AuthenticationError::ActorHasNoRolesOnTarget)
                    .auth_context("virtual user not found")?;

                if vu.authorizations.is_empty() {
                    // No authorizations - fall through with no scope
                } else {
                    // Find authorization matching the requested scope (by type + specific ID)
                    let roles = match &scope_clone {
                        ScopeInfo::Domain(domain) => vu.authorizations.iter().find_map(|a| {
                            if let Authorization::Domain { domain_id, roles } = a
                                && *domain_id == domain.id
                            {
                                Some(roles.clone())
                            } else {
                                None
                            }
                        }),
                        ScopeInfo::Project {
                            project,
                            project_domain,
                        } => vu.authorizations.iter().find_map(|a| {
                            if let Authorization::Project {
                                project_id,
                                project_domain_id,
                                roles,
                            } = a
                                && *project_id == project.id
                                && *project_domain_id == project_domain.id
                            {
                                Some(roles.clone())
                            } else {
                                None
                            }
                        }),
                        ScopeInfo::System(system_id) => vu.authorizations.iter().find_map(|a| {
                            if let Authorization::System {
                                system_id: s,
                                roles,
                            } = a
                                && s.as_str() == system_id.as_str()
                            {
                                Some(roles.clone())
                            } else {
                                None
                            }
                        }),
                        ScopeInfo::Unscoped | ScopeInfo::TrustProject(_) => None,
                    };

                    if let Some(roles) = roles {
                        let authz =
                            openstack_keystone_core_types::auth::AuthzInfoBuilder::default()
                                .scope(scope_clone)
                                .roles(roles)
                                .build()
                                .map_err(
                                    openstack_keystone_core_types::auth::AuthenticationError::from,
                                )?;
                        ctx.set_authorization(authz);
                    }
                }
            }
        }
        // TODO: Evaluate whether token revocation check should be done here - it is a
        // part of the authentication validation
        // Populate roles before locking
        if let Some(authz) = ctx.authorization() {
            let role_vec = calculate_effective_roles(state, &ctx, &authz.scope).await?;
            ctx.set_effective_roles(role_vec);
        }

        if let Some(authz) = ctx.authorization()
            && !matches!(authz.scope, ScopeInfo::Unscoped)
            && authz.effective_roles().is_none_or(|r| r.is_empty())
        {
            return Err(AuthenticationError::ActorHasNoRolesOnTarget);
        }
        Ok(ValidatedSecurityContext(ctx))
    }

    /// Returns the token associated with the security context.
    ///
    /// The token is guaranteed to be present for any validated context that
    /// was produced by token-based authentication flows (`issue_token_context`
    /// or `authorize_by_token`). If `None`, it indicates a programming error
    /// where a token was expected but a password-auth or similar context was
    /// passed to a token handler.
    #[must_use = "FernetToken must be read from the context"]
    pub fn token(&self) -> Result<&FernetToken, AuthenticationError> {
        self.0.token().ok_or(AuthenticationError::TokenNotInContext)
    }

    /// Construct without validation. ONLY for tests and mocks.
    #[cfg(any(test, feature = "mock"))]
    pub fn test_new(ctx: SecurityContext) -> Self {
        ValidatedSecurityContext(ctx)
    }
}

impl Deref for ValidatedSecurityContext {
    type Target = SecurityContext;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Expand scope role information.
//
// Compute the effective roles that the principal has on the scope taking into
// consideration the authentication method.
//
// * For application_credential this returns roles frozen on the application
//   credential removing the ones the principal is not having access to anymore.
// * For trusts it returns all roles the trustor has or the ones explicitly
//   declared on the [`Trust`].
// * For project scope and token restrictions present in the context with the
//   roles attached - such roles are returned without verifying whether they are
//   directly assigned to the user. Otherwise a regular user roles on the
//   project resolving is applied.
// * For the domain scope a roles that the user is having on the domain are
//   evaluated.
// * For unscoped context an empty list is returned.
// * For system scope a lookup of all roles the user has access to on the system
//   are returned.
async fn calculate_effective_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    scope: &ScopeInfo,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    scope.validate()?;

    // Mapping engine pre-populates roles from the matched authorization.
    // Skip assignment lookup since virtual users have no role assignments.
    if matches!(
        ctx.authentication_context(),
        AuthenticationContext::Mapping(_)
    ) && let Some(authz) = ctx.authorization()
        && let Some(roles) = authz.effective_roles()
    {
        return Ok(roles.to_vec());
    }

    let roles = match scope {
        ScopeInfo::Domain(domain) => resolve_domain_roles(state, ctx, &domain.id).await?,
        ScopeInfo::Project { project, .. } => {
            resolve_project_roles(state, ctx, &project.id).await?
        }
        ScopeInfo::System(system_id) => resolve_system_roles(state, ctx, system_id).await?,
        ScopeInfo::TrustProject(tpi) => resolve_trust_roles(state, tpi).await?,
        ScopeInfo::Unscoped => Vec::new(),
    };

    if !matches!(scope, ScopeInfo::Unscoped) && roles.is_empty() {
        return Err(AuthenticationError::ActorHasNoRolesOnTarget);
    }

    Ok(roles)
}

// Resolve effective roles for a domain scope.
async fn resolve_domain_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    domain_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    let user_id = ctx.principal().get_user_id();
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(&user_id)
                .domain_id(domain_id)
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving role assignments")?;
    assignments_to_roles(assignments)
}

// Resolve effective roles for a project scope.
async fn resolve_project_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    project_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    if let Some(restriction) = ctx.token_restriction()
        && !restriction.role_ids.is_empty()
    {
        return resolve_project_token_restriction_roles(state, restriction).await;
    }

    if let Some(mut roles) = resolve_project_spiffe_roles(ctx, project_id) {
        state
            .provider
            .get_role_provider()
            .expand_implied_roles(state, &mut roles)
            .await
            .auth_context("expanding scope roles")?;
        return Ok(roles);
    }

    resolve_project_default_roles(state, ctx, project_id).await
}

// Resolve roles from a token restriction on a project scope.
async fn resolve_project_token_restriction_roles(
    state: &ServiceState,
    restriction: &openstack_keystone_core_types::token::TokenRestriction,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    if let Some(roles) = &restriction.roles {
        return Ok(roles.clone());
    }

    let mut roles = restriction
        .role_ids
        .iter()
        .map(|rid| RoleRef {
            id: rid.clone(),
            name: None,
            domain_id: None,
        })
        .collect();
    state
        .provider
        .get_role_provider()
        .expand_implied_roles(state, &mut roles)
        .await
        .auth_context("expanding token restriction roles")?;
    Ok(roles)
}

// Resolve roles from a SPIFFE binding for a given project scope.
//
// Returns `Some(Vec<RoleRef>)` if the binding contains a matching project
// authorization with role IDs, `None` otherwise.  When `Some` is returned the
// caller is responsible for expanding implied roles.
fn resolve_project_spiffe_roles(ctx: &SecurityContext, project_id: &str) -> Option<Vec<RoleRef>> {
    let binding = match ctx.authentication_context() {
        AuthenticationContext::Spiffe(binding) => binding,
        _ => return None,
    };

    let authz = binding.authorizations.as_ref()?.iter().find(|scope| {
        matches!(scope, SpiffeAuthorization::Project { project_id: pid, .. } if *pid == project_id)
    })?;

    authz.role_refs()
}

// Resolve project-scoped roles using the default assignment-based logic.
async fn resolve_project_default_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    project_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    let user_id = ctx.principal().get_user_id();
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(&user_id)
                .project_id(project_id)
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving role assignments")?;

    match ctx.authentication_context() {
        AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        } => {
            let user_role_ids: HashSet<String> =
                assignments.iter().map(|a| a.role_id.clone()).collect();
            let restricted = application_credential
                .roles
                .iter()
                .filter(|role| user_role_ids.contains(&role.id))
                .cloned()
                .collect();
            Ok(restricted)
        }
        _ => assignments_to_roles(assignments),
    }
}

// Resolve effective roles for a system scope.
async fn resolve_system_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    system_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    if let AuthenticationContext::Spiffe(binding) = ctx.authentication_context() {
        if binding.is_system {
            let roles = state
                .provider
                .get_role_provider()
                .list_roles(
                    state,
                    &RoleListParameters {
                        name: Some("reader".into()),
                        ..Default::default()
                    },
                )
                .await
                .auth_context("searching reader role")?
                .into_iter()
                .map(|role| role.into())
                .collect();
            return Ok(roles);
        } else {
            return Ok(Vec::new());
        }
    }

    let user_id = ctx.principal().get_user_id();
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(&user_id)
                .system_id(system_id)
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving role assignments")?;
    assignments_to_roles(assignments)
}

// Resolve effective roles for a trust scope.
async fn resolve_trust_roles(
    state: &ServiceState,
    tpi: &TrustProjectInfo,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    let trustor_assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(tpi.trust.trustor_user_id.clone())
                .project_id(tpi.project.id.clone())
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving trust role assignments")?;

    if let Some(trust_roles) = &tpi.trust.roles {
        let trustor_role_ids: HashSet<String> = trustor_assignments
            .iter()
            .map(|a| a.role_id.clone())
            .collect();
        let mut trust_roles = trust_roles.clone();
        state
            .provider
            .get_role_provider()
            .expand_implied_roles(state, &mut trust_roles)
            .await
            .auth_context("expanding implied roles for trust")?;

        if !trust_roles
            .iter()
            .all(|role| trustor_role_ids.contains(&role.id))
        {
            debug!(
                "Trust roles {:?} are missing for the trustor {:?}",
                trust_roles, trustor_role_ids
            );
            return Err(AuthenticationError::ActorHasNoRolesOnTarget);
        }
        trust_roles.retain_mut(|role| role.domain_id.is_none());
        Ok(trust_roles)
    } else {
        assignments_to_roles(trustor_assignments)
    }
}

// Convert a list of role assignments into [`RoleRef`] values.
fn assignments_to_roles(
    assignments: Vec<openstack_keystone_core_types::assignment::Assignment>,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    assignments
        .into_iter()
        .map(|a| {
            a.try_into()
                .map_err(|_| AuthenticationError::RoleConversionFailed)
        })
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::assignment::{
        Assignment, AssignmentProviderError, AssignmentType, RoleAssignmentListParameters,
    };
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalIdentityInfo,
        PrincipalInfo, ScopeInfo, SecurityContextTestingBuilder, TrustProjectInfo,
        UserIdentityInfo,
    };
    use openstack_keystone_core_types::identity::{UserOptions, UserResponse};
    use openstack_keystone_core_types::mapping::authorization::Authorization;
    use openstack_keystone_core_types::mapping::{MappingContext, VirtualUser};
    use openstack_keystone_core_types::resource::Project;
    use openstack_keystone_core_types::role::{Role, RoleRef, RoleRefBuilder};
    use openstack_keystone_core_types::token::TokenRestriction;
    use openstack_keystone_core_types::trust::Trust;
    use std::collections::HashMap;

    use crate::assignment::MockAssignmentProvider;
    use crate::mapping::mock::MockMappingProvider;
    use crate::provider::Provider;
    use crate::role::{MockRoleProvider, RoleProviderError};
    use crate::tests::get_mocked_state;

    use super::*;

    fn make_user_identity(user_id: impl Into<String>) -> PrincipalInfo {
        let uid = user_id.into();
        let u = UserResponse {
            id: uid.clone(),
            domain_id: "d1".to_string(),
            enabled: true,
            name: "u".to_string(),
            extra: HashMap::new(),
            default_project_id: None,
            federated: None,
            options: UserOptions::default(),
            password_expires_at: None,
        };
        let ui = UserIdentityInfo {
            user_id: uid.clone(),
            user: Some(u),
            user_domain: Some(openstack_keystone_core_types::resource::Domain {
                id: "d1".to_string(),
                description: None,
                enabled: true,
                name: "default".to_string(),
                extra: HashMap::new(),
            }),
            user_groups: Vec::new(),
        };
        PrincipalInfo {
            identity: IdentityInfo::User(ui),
        }
    }

    fn make_project(pid: impl Into<String>) -> Project {
        let pid = pid.into();
        Project {
            id: pid.clone(),
            domain_id: "d1".to_string(),
            enabled: true,
            name: "p".to_string(),
            description: None,
            is_domain: false,
            parent_id: None,
            extra: HashMap::new(),
        }
    }

    fn make_project_scope(pid: impl Into<String>) -> ScopeInfo {
        ScopeInfo::Project {
            project: make_project(pid),
            project_domain: openstack_keystone_core_types::resource::Domain {
                id: "d1".to_string(),
                description: None,
                enabled: true,
                name: "default".to_string(),
                extra: HashMap::new(),
            },
        }
    }

    fn make_domain_scope(did: impl Into<String>) -> ScopeInfo {
        ScopeInfo::Domain(openstack_keystone_core_types::resource::Domain {
            id: did.into(),
            description: None,
            enabled: true,
            name: "default".to_string(),
            extra: HashMap::new(),
        })
    }

    fn make_trust_scope(
        trustor: impl Into<String>,
        trustee: impl Into<String>,
        project: &str,
        roles: Option<Vec<RoleRef>>,
    ) -> ScopeInfo {
        ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
            trust: Trust {
                id: "t1".to_string(),
                trustor_user_id: trustor.into(),
                trustee_user_id: trustee.into(),
                impersonation: false,
                project_id: None,
                expires_at: None,
                deleted_at: None,
                extra: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles,
            },
            project: make_project(project),
            project_domain: openstack_keystone_core_types::resource::Domain {
                id: "d1".to_string(),
                description: None,
                enabled: true,
                name: "default".to_string(),
                extra: HashMap::new(),
            },
        }))
    }

    fn assignment_with_role(rid: impl Into<String>) -> Assignment {
        assignment_with_role_actor(rid, "uid")
    }

    fn assignment_with_role_actor(rid: impl Into<String>, actor: impl Into<String>) -> Assignment {
        Assignment {
            actor_id: actor.into(),
            role_id: rid.into(),
            role_name: Some("admin".to_string()),
            target_id: "target".to_string(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }
    }

    fn role_ref(id: impl Into<String>, name: impl Into<String>) -> RoleRef {
        RoleRefBuilder::default().id(id).name(name).build().unwrap()
    }

    fn role_ref_with_domain(
        id: impl Into<String>,
        name: impl Into<String>,
        domain_id: Option<String>,
    ) -> RoleRef {
        let mut r = RoleRefBuilder::default().id(id).name(name).build().unwrap();
        r.domain_id = domain_id;
        r
    }

    fn make_spiffe_binding(
        svid: impl Into<String>,
        is_system: bool,
        authorizations: Option<Vec<SpiffeAuthorization>>,
    ) -> SpiffeBinding {
        SpiffeBinding {
            authorizations,
            domain_id: "d1".to_string(),
            svid: svid.into(),
            is_system,
            user_id: None,
        }
    }

    fn make_spiffe_principal(svid: impl Into<String>, issuer: impl Into<String>) -> PrincipalInfo {
        PrincipalInfo {
            identity: IdentityInfo::Principal(PrincipalIdentityInfo {
                id: svid.into(),
                issuer: issuer.into(),
                attributes: HashMap::new(),
                domain: Some(openstack_keystone_core_types::resource::Domain {
                    id: "d1".to_string(),
                    description: None,
                    enabled: true,
                    name: "default".to_string(),
                    extra: HashMap::new(),
                }),
            }),
        }
    }

    fn make_role(id: impl Into<String>, name: impl Into<String>) -> Role {
        Role {
            id: id.into(),
            name: name.into(),
            description: None,
            domain_id: None,
            extra: HashMap::new(),
        }
    }

    fn disabled_domain_scope(did: impl Into<String>) -> ScopeInfo {
        ScopeInfo::Domain(openstack_keystone_core_types::resource::Domain {
            id: did.into(),
            description: None,
            enabled: false,
            name: "disabled".to_string(),
            extra: HashMap::new(),
        })
    }

    fn disabled_project_scope(pid: impl Into<String>) -> ScopeInfo {
        ScopeInfo::Project {
            project: Project {
                id: pid.into(),
                domain_id: "d1".to_string(),
                enabled: false,
                name: "p".to_string(),
                description: None,
                is_domain: false,
                parent_id: None,
                extra: HashMap::new(),
            },
            project_domain: openstack_keystone_core_types::resource::Domain {
                id: "d1".to_string(),
                description: None,
                enabled: true,
                name: "default".to_string(),
                extra: HashMap::new(),
            },
        }
    }

    fn disabled_project_domain_scope(pid: impl Into<String>) -> ScopeInfo {
        ScopeInfo::Project {
            project: Project {
                id: pid.into(),
                domain_id: "d1".to_string(),
                enabled: true,
                name: "p".to_string(),
                description: None,
                is_domain: false,
                parent_id: None,
                extra: HashMap::new(),
            },
            project_domain: openstack_keystone_core_types::resource::Domain {
                id: "d1".to_string(),
                description: None,
                enabled: false,
                name: "disabled".to_string(),
                extra: HashMap::new(),
            },
        }
    }

    fn disabled_trust_scope(
        trustor: impl Into<String>,
        trustee: impl Into<String>,
        project: &str,
        roles: Option<Vec<RoleRef>>,
    ) -> ScopeInfo {
        ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
            trust: Trust {
                id: "t1".to_string(),
                trustor_user_id: trustor.into(),
                trustee_user_id: trustee.into(),
                impersonation: false,
                project_id: None,
                expires_at: None,
                deleted_at: None,
                extra: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles,
            },
            project: Project {
                id: project.to_string(),
                domain_id: "d1".to_string(),
                enabled: false,
                name: "p".to_string(),
                description: None,
                is_domain: false,
                parent_id: None,
                extra: HashMap::new(),
            },
            project_domain: openstack_keystone_core_types::resource::Domain {
                id: "d1".to_string(),
                description: None,
                enabled: true,
                name: "default".to_string(),
                extra: HashMap::new(),
            },
        }))
    }

    fn disabled_trust_project_domain_scope(
        trustor: impl Into<String>,
        trustee: impl Into<String>,
        project: &str,
        roles: Option<Vec<RoleRef>>,
    ) -> ScopeInfo {
        ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
            trust: Trust {
                id: "t1".to_string(),
                trustor_user_id: trustor.into(),
                trustee_user_id: trustee.into(),
                impersonation: false,
                project_id: None,
                expires_at: None,
                deleted_at: None,
                extra: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles,
            },
            project: Project {
                id: project.to_string(),
                domain_id: "d1".to_string(),
                enabled: true,
                name: "p".to_string(),
                description: None,
                is_domain: false,
                parent_id: None,
                extra: HashMap::new(),
            },
            project_domain: openstack_keystone_core_types::resource::Domain {
                id: "d1".to_string(),
                description: None,
                enabled: false,
                name: "disabled".to_string(),
                extra: HashMap::new(),
            },
        }))
    }

    #[tokio::test]
    async fn test_unscoped_returns_empty() {
        let state = get_mocked_state(None, None).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .build();
        let scope = ScopeInfo::Unscoped;
        let roles = calculate_effective_roles(&state, &ctx, &scope).await;
        assert_eq!(roles.unwrap(), Vec::<RoleRef>::new());
    }

    #[tokio::test]
    async fn test_project_scope_returns_assignment_roles() {
        let uid = "uid";
        let pid = "pid";
        let rid1 = "rid1";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
                    && q.domain_id.is_none()
                    && q.system_id.is_none()
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(rid1)]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = make_project_scope(pid);
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid1);
    }

    #[tokio::test]
    async fn test_domain_scope_returns_assignment_roles() {
        let uid = "uid";
        let did = "did";
        let rid1 = "rid1";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.domain_id.as_deref() == Some(did)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
                    && q.project_id.is_none()
                    && q.system_id.is_none()
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(rid1)]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = make_domain_scope(did);
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid1);
    }

    #[tokio::test]
    async fn test_system_scope_returns_assignment_roles() {
        let uid = "uid";
        let system = "all";
        let rid1 = "rid1";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.system_id.as_deref() == Some(system)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
                    && q.domain_id.is_none()
                    && q.project_id.is_none()
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(rid1)]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = ScopeInfo::System(system.to_string());
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid1);
    }

    #[tokio::test]
    async fn test_trust_scope_with_roles() {
        let trustor = "trustor";
        let pid = "pid";
        let rid1 = "rid1";
        let trust_roles = vec![role_ref(rid1, "admin")];
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(rid1)]));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(|_state, _roles| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_role(role_mock),
            ),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid1);
    }

    #[tokio::test]
    async fn test_trust_scope_without_roles() {
        let trustor = "trustor";
        let pid = "pid";
        let rid1 = "rid1";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role("rid1")]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, None);
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid1);
    }

    #[tokio::test]
    async fn test_project_scope_with_token_restriction() {
        let rid1 = "rid1";
        let restriction_roles = vec![role_ref(rid1, "admin")];
        let tr = TokenRestriction {
            id: "tr1".to_string(),
            domain_id: "d1".to_string(),
            allow_rescope: true,
            allow_renew: false,
            role_ids: vec![rid1.to_string()],
            roles: Some(restriction_roles.clone()),
            project_id: Some("pid".to_string()),
            user_id: Some("uid".to_string()),
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .token_restriction(tr)
            .build();
        let state = get_mocked_state(None, None).await;
        let scope = make_project_scope("pid");
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles, restriction_roles);
    }

    #[tokio::test]
    async fn test_project_scope_appcred_filters_missing_role() {
        let uid = "uid";
        let pid = "pid";
        let admin_rid = "admin";
        let viewer_rid = "viewer";
        let appcred_roles = vec![role_ref(admin_rid, "admin"), role_ref(viewer_rid, "viewer")];
        // User only has admin assigned
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(admin_rid)]));
        let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
            id: "ac1".to_string(),
            user_id: uid.to_string(),
            project_id: pid.to_string(),
            name: "cred".to_string(),
            description: None,
            roles: appcred_roles,
            unrestricted: false,
            expires_at: None,
            access_rules: None,
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: ac,
                token: None,
            })
            .principal(make_user_identity(uid))
            .build();
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let scope = make_project_scope(pid);
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, admin_rid);
    }

    #[tokio::test]
    async fn test_project_scope_spiffe_matching_authz() {
        let pid = "pid";
        let rid1 = "spiffe_role";
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/workload",
            false,
            Some(vec![SpiffeAuthorization::Project {
                project_id: pid.to_string(),
                role_ids: Some(vec![rid1.to_string()]),
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(|_state, _roles| Ok(()));
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = make_project_scope(pid);
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid1);
    }

    #[tokio::test]
    async fn test_project_scope_token_restriction_expand_role_ids() {
        let rid1 = "rid1";
        let rid2 = "rid2";
        let tr = TokenRestriction {
            id: "tr1".to_string(),
            domain_id: "d1".to_string(),
            allow_rescope: true,
            allow_renew: false,
            role_ids: vec![rid1.to_string(), rid2.to_string()],
            roles: None,
            project_id: Some("pid".to_string()),
            user_id: Some("uid".to_string()),
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .token_restriction(tr)
            .build();
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .withf(move |_state, roles| roles.len() == 2 && roles.iter().any(|r| r.id == rid1))
            .returning(move |_state, roles| {
                for role in roles.iter_mut() {
                    if role.id == rid1 {
                        role.name = Some("admin".to_string());
                    }
                }
                Ok(())
            });
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let scope = make_project_scope("pid");
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 2);
        assert!(roles.iter().any(|r| r.id == rid1));
        assert!(roles.iter().any(|r| r.id == rid2));
    }

    #[tokio::test]
    async fn test_trust_scope_missing_role_error() {
        let trustor = "trustor";
        let pid = "pid";
        let trust_rid = "trust_role";
        let trustor_rid = "other_role";
        let trust_roles = vec![role_ref(trust_rid, "trustadmin")];
        // Trustor has a different role, not the one on the trust
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(trustor_rid)]));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(|_state, _roles| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_role(role_mock),
            ),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    #[tokio::test]
    async fn test_trust_scope_filters_domain_roles() {
        let trustor = "trustor";
        let pid = "pid";
        let rid1 = "rid1";
        let rid2 = "rid2";
        let trust_roles = vec![
            role_ref_with_domain(rid1, "admin", None),
            role_ref_with_domain(rid2, "domain_admin", Some("d1".to_string())),
        ];
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| {
                Ok(vec![assignment_with_role(rid1), assignment_with_role(rid2)])
            });
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(|_state, _roles| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_role(role_mock),
            ),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid1);
    }

    #[tokio::test]
    async fn test_domain_scope_empty_assignments_error() {
        let uid = "uid";
        let did = "did";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.domain_id.as_deref() == Some(did)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = make_domain_scope(did);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    #[tokio::test]
    async fn test_domain_scope_disabled_error() {
        let did = "did";
        let state = get_mocked_state(None, None).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .build();
        let scope = disabled_domain_scope(did);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        match result.unwrap_err() {
            //result,
            //Err(AuthenticationError::DomainDisabled(id))
            AuthenticationError::DomainDisabled(id) if id == did => {}
            e => panic!("unexpected error: {:?}", e),
        };
    }

    #[tokio::test]
    async fn test_project_scope_disabled_error() {
        let pid = "pid";
        let state = get_mocked_state(None, None).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .build();
        let scope = disabled_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        match result.unwrap_err() {
            //result,
            //Err(AuthenticationError::ProjectDisabled(id))
            AuthenticationError::ProjectDisabled(id) if id == pid => {}
            e => panic!("unexpected error: {:?}", e),
        };
    }

    #[tokio::test]
    async fn test_project_scope_disabled_domain_error() {
        let pid = "pid";
        let state = get_mocked_state(None, None).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .build();
        let scope = disabled_project_domain_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        match result.unwrap_err() {
            //result,
            //Err(AuthenticationError::DomainDisabled(id))
            AuthenticationError::DomainDisabled(id) if id == "d1" => {}
            e => panic!("unexpected error: {:?}", e),
        };
    }

    #[tokio::test]
    async fn test_trust_scope_disabled_project_error() {
        let state = get_mocked_state(None, None).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("trustor"))
            .build();
        let scope = disabled_trust_scope("trustor", "trustee", "pid", None);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        match result.unwrap_err() {
            //result,
            //Err(AuthenticationError::ProjectDisabled(id))
            AuthenticationError::ProjectDisabled(id) if id == "pid" => {}
            e => panic!("unexpected error: {:?}", e),
        };
    }

    #[tokio::test]
    async fn test_trust_scope_disabled_domain_error() {
        let state = get_mocked_state(None, None).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("trustor"))
            .build();
        let scope = disabled_trust_project_domain_scope("trustor", "trustee", "pid", None);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        match result.unwrap_err() {
            // result,
            //Err(AuthenticationError::DomainDisabled(id))
            AuthenticationError::DomainDisabled(id) if id == "d1" => {}
            e => panic!("unexpected error: {:?}", e),
        };
    }

    // --- Project scope empty assignments error ---
    #[tokio::test]
    async fn test_project_scope_empty_assignments_error() {
        let uid = "uid";
        let pid = "pid";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- System scope empty assignments error ---
    #[tokio::test]
    async fn test_system_scope_empty_assignments_error() {
        let uid = "uid";
        let system = "all";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.system_id.as_deref() == Some(system)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = ScopeInfo::System(system.to_string());
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- SPIFFE system: is_system = true, returns reader role ---
    #[tokio::test]
    async fn test_system_scope_spiffe_system_true() {
        let reader_rid = "reader";
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/system-workload",
            true,
            Some(vec![SpiffeAuthorization::System {
                system_id: "all".to_string(),
                role_ids: None,
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/system-workload", "spire-agent");
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .returning(move |_state, _params| Ok(vec![make_role(reader_rid, "reader")]));
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = ScopeInfo::System("all".to_string());
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, reader_rid);
    }

    // --- SPIFFE system: is_system = false, returns empty → error ---
    #[tokio::test]
    async fn test_system_scope_spiffe_system_false() {
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/workload",
            false,
            Some(vec![SpiffeAuthorization::System {
                system_id: "all".to_string(),
                role_ids: None,
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let state = get_mocked_state(None, None).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = ScopeInfo::System("all".to_string());
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- SPIFFE project: authorizations_none, falls through to default
    //     (which with no assignments returns empty → error) ---
    #[tokio::test]
    async fn test_project_scope_spiffe_authorizations_none() {
        let pid = "pid";
        let binding = make_spiffe_binding("spiffe://domain/ns/workload", false, None);
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- SPIFFE project: no matching project_id, falls through to default ---
    #[tokio::test]
    async fn test_project_scope_spiffe_no_matching_project() {
        let target_pid = "pid";
        let other_pid = "other_pid";
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/workload",
            false,
            Some(vec![SpiffeAuthorization::Project {
                project_id: other_pid.to_string(),
                role_ids: Some(vec!["spiffe_role".to_string()]),
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.project_id.as_deref() == Some(target_pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = make_project_scope(target_pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- SPIFFE project: role_ids_none, falls through to default ---
    #[tokio::test]
    async fn test_project_scope_spiffe_role_ids_none() {
        let pid = "pid";
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/workload",
            false,
            Some(vec![SpiffeAuthorization::Project {
                project_id: pid.to_string(),
                role_ids: None,
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- AppCred: all roles pass filter ---
    #[tokio::test]
    async fn test_project_scope_appcred_all_roles_pass() {
        let uid = "uid";
        let pid = "pid";
        let admin_rid = "admin";
        let viewer_rid = "viewer";
        let appcred_roles = vec![role_ref(admin_rid, "admin"), role_ref(viewer_rid, "viewer")];
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| {
                Ok(vec![
                    assignment_with_role(admin_rid),
                    assignment_with_role(viewer_rid),
                ])
            });
        let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
            id: "ac1".to_string(),
            user_id: uid.to_string(),
            project_id: pid.to_string(),
            name: "cred".to_string(),
            description: None,
            roles: appcred_roles,
            unrestricted: false,
            expires_at: None,
            access_rules: None,
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: ac,
                token: None,
            })
            .principal(make_user_identity(uid))
            .build();
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let scope = make_project_scope(pid);
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 2);
        assert!(roles.iter().any(|r| r.id == admin_rid));
        assert!(roles.iter().any(|r| r.id == viewer_rid));
    }

    // --- Token restriction: roles: Some(empty) returns empty ---
    #[tokio::test]
    async fn test_project_scope_token_restriction_empty_roles() {
        let tr = TokenRestriction {
            id: "tr1".to_string(),
            domain_id: "d1".to_string(),
            allow_rescope: true,
            allow_renew: false,
            role_ids: vec!["rid1".to_string()],
            roles: Some(Vec::new()),
            project_id: Some("pid".to_string()),
            user_id: Some("uid".to_string()),
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .token_restriction(tr)
            .build();
        let state = get_mocked_state(None, None).await;
        let scope = make_project_scope("pid");
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    #[tokio::test]
    async fn test_new_for_scope_explicit_empty_roles_error() {
        let uid = "uid";
        let pid = "pid";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let authz = AuthzInfoBuilder::default()
            .scope(make_project_scope(pid))
            .roles(Vec::new())
            .build()
            .unwrap();
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .authorization(authz)
            .build();
        let result =
            ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- Trust scope: expand_implied_roles adds an implied role, trustor has it
    // ---
    #[tokio::test]
    async fn test_trust_scope_implied_role_expansion() {
        let trustor = "trustor";
        let pid = "pid";
        let base_rid = "base_role";
        let implied_rid = "implied_role";
        let trust_roles = vec![role_ref(base_rid, "base")];
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| {
                Ok(vec![
                    assignment_with_role_actor(base_rid, trustor),
                    assignment_with_role_actor(implied_rid, trustor),
                ])
            });
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(move |_state, roles| {
                roles.push(role_ref(implied_rid, "implied"));
                Ok(())
            });
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_role(role_mock),
            ),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 2);
        assert!(roles.iter().any(|r| r.id == base_rid));
        assert!(roles.iter().any(|r| r.id == implied_rid));
    }

    // --- Project scope: expand_implied_roles adds an implied role for SPIFFE ---
    #[tokio::test]
    async fn test_project_scope_spiffe_implied_role_expansion() {
        let pid = "pid";
        let base_rid = "spiffe_role";
        let implied_rid = "implied_role";
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/workload",
            false,
            Some(vec![SpiffeAuthorization::Project {
                project_id: pid.to_string(),
                role_ids: Some(vec![base_rid.to_string()]),
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(move |_state, roles| {
                roles.push(role_ref(implied_rid, "implied"));
                Ok(())
            });
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = make_project_scope(pid);
        let roles = calculate_effective_roles(&state, &ctx, &scope)
            .await
            .unwrap();
        assert_eq!(roles.len(), 2);
        assert!(roles.iter().any(|r| r.id == base_rid));
        assert!(roles.iter().any(|r| r.id == implied_rid));
    }

    // --- SPIFFE non-system with principal identity on system scope, no assignments
    // ---
    #[tokio::test]
    async fn test_system_scope_spiffe_non_system_no_assignments() {
        let binding = make_spiffe_binding("spiffe://domain/ns/workload", false, None);
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let state = get_mocked_state(None, None).await;
        let scope = ScopeInfo::System("all".to_string());
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- Provider error: domain scope list_role_assignments ---
    #[tokio::test]
    async fn test_domain_scope_provider_error() {
        let uid = "uid";
        let did = "did";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.domain_id.as_deref() == Some(did)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Err(AssignmentProviderError::Driver("db down".into())));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = make_domain_scope(did);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Provider error: project scope list_role_assignments ---
    #[tokio::test]
    async fn test_project_scope_provider_error() {
        let uid = "uid";
        let pid = "pid";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Err(AssignmentProviderError::Driver("db down".into())));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Provider error: system scope list_role_assignments ---
    #[tokio::test]
    async fn test_system_scope_provider_error() {
        let uid = "uid";
        let system = "all";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.system_id.as_deref() == Some(system)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Err(AssignmentProviderError::Driver("db down".into())));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .build();
        let scope = ScopeInfo::System(system.to_string());
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Provider error: trust scope list_role_assignments ---
    #[tokio::test]
    async fn test_trust_scope_provider_error() {
        let trustor = "trustor";
        let pid = "pid";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Err(AssignmentProviderError::Driver("db down".into())));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, None);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Provider error: SPIFFE expand_implied_roles ---
    #[tokio::test]
    async fn test_project_scope_spiffe_expand_implied_error() {
        let pid = "pid";
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/workload",
            false,
            Some(vec![SpiffeAuthorization::Project {
                project_id: pid.to_string(),
                role_ids: Some(vec!["spiffe_role".to_string()]),
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/workload", "spire-agent");
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(move |_state, _roles| Err(RoleProviderError::Driver("db down".into())));
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Provider error: trust expand_implied_roles ---
    #[tokio::test]
    async fn test_trust_scope_expand_implied_error() {
        let trustor = "trustor";
        let pid = "pid";
        let trust_rid = "trust_role";
        let trust_roles = vec![role_ref(trust_rid, "trustadmin")];
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(trust_rid)]));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(move |_state, _roles| Err(RoleProviderError::Driver("db down".into())));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_role(role_mock),
            ),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Provider error: token restriction expand_implied_roles ---
    #[tokio::test]
    async fn test_project_scope_token_restriction_expand_error() {
        let rid1 = "rid1";
        let tr = TokenRestriction {
            id: "tr1".to_string(),
            domain_id: "d1".to_string(),
            allow_rescope: true,
            allow_renew: false,
            role_ids: vec![rid1.to_string()],
            roles: None,
            project_id: Some("pid".to_string()),
            user_id: Some("uid".to_string()),
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .token_restriction(tr)
            .build();
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(move |_state, _roles| Err(RoleProviderError::Driver("db".into())));
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let scope = make_project_scope("pid");
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Provider error: SPIFFE system list_roles ---
    #[tokio::test]
    async fn test_system_scope_spiffe_list_roles_error() {
        let binding = make_spiffe_binding(
            "spiffe://domain/ns/system-workload",
            true,
            Some(vec![SpiffeAuthorization::System {
                system_id: "all".to_string(),
                role_ids: None,
            }]),
        );
        let principal = make_spiffe_principal("spiffe://domain/ns/system-workload", "spire-agent");
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .returning(move |_state, _params| Err(RoleProviderError::Driver("db".into())));
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Spiffe(binding))
            .principal(principal)
            .build();
        let scope = ScopeInfo::System("all".to_string());
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- AppCred: empty roles list returns empty after filter ---
    #[tokio::test]
    async fn test_project_scope_appcred_empty_roles() {
        let uid = "uid";
        let pid = "pid";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role("admin")]));
        let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
            id: "ac1".to_string(),
            user_id: uid.to_string(),
            project_id: pid.to_string(),
            name: "cred".to_string(),
            description: None,
            roles: Vec::new(),
            unrestricted: false,
            expires_at: None,
            access_rules: None,
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: ac,
                token: None,
            })
            .principal(make_user_identity(uid))
            .build();
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- AppCred: all credential roles missing after filter ---
    #[tokio::test]
    async fn test_project_scope_appcred_all_roles_missing() {
        let uid = "uid";
        let pid = "pid";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role("admin")]));
        let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
            id: "ac1".to_string(),
            user_id: uid.to_string(),
            project_id: pid.to_string(),
            name: "cred".to_string(),
            description: None,
            roles: vec![role_ref("other", "other")],
            unrestricted: false,
            expires_at: None,
            access_rules: None,
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: ac,
                token: None,
            })
            .principal(make_user_identity(uid))
            .build();
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- Trust: expand adds role trustor does not have, .all() fails ---
    #[tokio::test]
    async fn test_trust_scope_expand_adds_missing_role() {
        let trustor = "trustor";
        let pid = "pid";
        let base_rid = "base_role";
        let extra_rid = "extra_role";
        let trust_roles = vec![role_ref(base_rid, "base")];
        // Trustor only has base_role, not extra_role
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role_actor(base_rid, trustor)]));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(move |_state, roles| {
                roles.push(role_ref(extra_rid, "extra"));
                Ok(())
            });
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_role(role_mock),
            ),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        // After expand, trust_roles includes extra_role, but trustor does not have it
        // .all() check fails -> ActorHasNoRolesOnTarget
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- Trust: no roles, trustor has no assignments ---
    #[tokio::test]
    async fn test_trust_scope_no_roles_no_assignments() {
        let trustor = "trustor";
        let pid = "pid";
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(trustor)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(trustor))
            .build();
        let scope = make_trust_scope(trustor, "trustee", pid, None);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- Token restriction: role_ids empty, roles Some(roles) falls through ---
    #[tokio::test]
    async fn test_project_scope_token_restriction_no_role_ids_fallthrough() {
        let uid = "uid";
        let pid = "pid";
        let restriction_roles = vec![role_ref("restricted", "restricted")];
        let tr = TokenRestriction {
            id: "tr1".to_string(),
            domain_id: "d1".to_string(),
            allow_rescope: true,
            allow_renew: false,
            role_ids: Vec::new(),
            roles: Some(restriction_roles.clone()),
            project_id: Some(pid.to_string()),
            user_id: Some(uid.to_string()),
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .token_restriction(tr)
            .build();
        // role_ids is empty so !restriction.role_ids.is_empty() is false
        // Falls through to assignment lookup which returns empty
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
            })
            .returning(move |_state, _q| Ok(Vec::<Assignment>::new()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;
        let scope = make_project_scope(pid);
        let result = calculate_effective_roles(&state, &ctx, &scope).await;
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // Unscoped scope must succeed with zero effective roles.  The assignment
    // provider must never be called (no mock needed).
    #[tokio::test]
    async fn test_new_for_scope_unscoped_success() {
        let state = get_mocked_state(None, None).await;
        // Build a context that already carries an Unscoped authorization so the
        // scope-boundary check is skipped entirely (scopes are equal).
        let authz = AuthzInfoBuilder::default()
            .scope(ScopeInfo::Unscoped)
            .roles(Vec::new())
            .build()
            .unwrap();
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity("uid"))
            .authorization(authz)
            .build();

        let result =
            ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

        // Must succeed and carry zero effective roles — the Unscoped path in
        // calculate_effective_roles returns Vec::new() and skips the
        // ActorHasNoRolesOnTarget guard.
        let validated = result.unwrap();

        // Access the roles via the authorization state getter
        let roles = validated.0.authorization().unwrap().effective_roles();
        assert!(roles.is_none() || roles.unwrap().is_empty());
    }

    // Project-scoped context with a live assignment must succeed and surface
    // exactly that one role as an effective role.
    #[tokio::test]
    async fn test_new_for_scope_project_scoped_success() {
        let uid = "uid";
        let pid = "pid";
        let rid = "admin_role";

        // Strict predicate: must be called once for this user+project combination
        // with the exact flags used by resolve_project_default_roles.
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
                    && q.domain_id.is_none()
                    && q.system_id.is_none()
            })
            .returning(move |_state, _q| Ok(vec![assignment_with_role(rid)]));

        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;

        // Pre-set the same project scope so the boundary check is skipped.
        let authz = AuthzInfoBuilder::default()
            .scope(make_project_scope(pid))
            .roles(Vec::new())
            .build()
            .unwrap();
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .authorization(authz)
            .build();

        let result =
            ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

        // Must succeed; effective roles must contain exactly the one role the
        // assignment provider returned.
        let validated = result.unwrap();

        // Access the roles via the authorization state getter
        let roles = validated
            .0
            .authorization()
            .unwrap()
            .effective_roles()
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, rid);
    }

    // Project-scoped context where the assignment provider returns nothing must
    // fail with ActorHasNoRolesOnTarget.
    #[tokio::test]
    async fn test_new_for_scope_project_scoped_no_roles_fails() {
        let uid = "uid";
        let pid = "pid";

        // Same strict predicate as Test 2 — the provider IS called but returns
        // an empty list, triggering the ActorHasNoRolesOnTarget guard.
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some(uid)
                    && q.project_id.as_deref() == Some(pid)
                    && q.effective == Some(true)
                    && q.include_names == Some(true)
                    && q.domain_id.is_none()
                    && q.system_id.is_none()
            })
            .returning(|_, _| Ok(Vec::<Assignment>::new()));

        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
        )
        .await;

        let authz = AuthzInfoBuilder::default()
            .scope(make_project_scope(pid))
            .roles(Vec::new())
            .build()
            .unwrap();
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(make_user_identity(uid))
            .authorization(authz)
            .build();

        let result =
            ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

        // calculate_effective_roles sees an empty, non-Unscoped result and must
        // return ActorHasNoRolesOnTarget.
        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- Mapping: domain scope match returns pre-populated roles ---
    #[tokio::test]
    async fn test_new_for_scope_mapping_domain_scope_match() {
        let did = "domain-1";
        let vir_id = "vu-1234567890abcdef1234567890abcdef";
        let rid = "admin";
        let roles = vec![role_ref(rid, "admin")];

        let vu = VirtualUser {
            user_id: vir_id.to_string(),
            unique_workload_id: "workload-1".to_string(),
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            domain_id: Some(did.to_string()),
            resolved_user_name: "mapped_user".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![Authorization::Domain {
                domain_id: did.to_string(),
                roles: roles.clone(),
            }],
            ruleset_version: 1,
            enabled: true,
            created_at: 0,
            last_authenticated_at: 0,
        };

        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_get_virtual_user()
            .returning(move |_state, id: &str| {
                if id == vir_id {
                    Ok(Some(vu.clone()))
                } else {
                    Ok(None)
                }
            });

        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
        )
        .await;

        let mc = MappingContext {
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            virtual_user_id: vir_id.to_string(),
        };

        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Mapping(mc))
            .principal(make_user_identity(vir_id))
            .build();

        let result =
            ValidatedSecurityContext::new_for_scope(ctx, make_domain_scope(did), &state).await;

        let validated = result.unwrap();
        let eff = validated
            .0
            .authorization()
            .unwrap()
            .effective_roles()
            .unwrap();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].id, rid);
    }

    // --- Mapping: project scope match returns pre-populated roles ---
    #[tokio::test]
    async fn test_new_for_scope_mapping_project_scope_match() {
        let pid = "project-1";
        let vir_id = "vu-abcdef1234567890abcdef1234567890";
        let rid = "reader";
        let roles = vec![role_ref(rid, "reader")];

        let vu = VirtualUser {
            user_id: vir_id.to_string(),
            unique_workload_id: "workload-2".to_string(),
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            domain_id: Some("d1".to_string()),
            resolved_user_name: "mapped_user".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![Authorization::Project {
                project_id: pid.to_string(),
                project_domain_id: "d1".to_string(),
                roles: roles.clone(),
            }],
            ruleset_version: 1,
            enabled: true,
            created_at: 0,
            last_authenticated_at: 0,
        };

        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_get_virtual_user()
            .returning(move |_state, id: &str| {
                if id == vir_id {
                    Ok(Some(vu.clone()))
                } else {
                    Ok(None)
                }
            });

        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
        )
        .await;

        let mc = MappingContext {
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            virtual_user_id: vir_id.to_string(),
        };

        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Mapping(mc))
            .principal(make_user_identity(vir_id))
            .build();

        let result =
            ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

        let validated = result.unwrap();
        let eff = validated
            .0
            .authorization()
            .unwrap()
            .effective_roles()
            .unwrap();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].id, rid);
    }

    // --- Mapping: system scope match returns pre-populated roles ---
    #[tokio::test]
    async fn test_new_for_scope_mapping_system_scope_match() {
        let sys = "all";
        let vir_id = "vu-11111111111111111111111111111111";
        let rid = "admin";
        let roles = vec![role_ref(rid, "admin")];

        let vu = VirtualUser {
            user_id: vir_id.to_string(),
            unique_workload_id: "workload-3".to_string(),
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            domain_id: None,
            resolved_user_name: "mapped_user".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![Authorization::System {
                system_id: sys.to_string(),
                roles: roles.clone(),
            }],
            ruleset_version: 1,
            enabled: true,
            created_at: 0,
            last_authenticated_at: 0,
        };

        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_get_virtual_user()
            .returning(move |_state, id: &str| {
                if id == vir_id {
                    Ok(Some(vu.clone()))
                } else {
                    Ok(None)
                }
            });

        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
        )
        .await;

        let mc = MappingContext {
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            virtual_user_id: vir_id.to_string(),
        };

        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Mapping(mc))
            .principal(make_user_identity(vir_id))
            .build();

        let result = ValidatedSecurityContext::new_for_scope(
            ctx,
            ScopeInfo::System(sys.to_string()),
            &state,
        )
        .await;

        let validated = result.unwrap();
        let eff = validated
            .0
            .authorization()
            .unwrap()
            .effective_roles()
            .unwrap();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].id, rid);
    }

    // --- Mapping: scope mismatch (no matching authorization) fails ---
    #[tokio::test]
    async fn test_new_for_scope_mapping_scope_mismatch() {
        let vir_id = "vu-aabbccdd11223344aabbccdd11223344";

        let vu = VirtualUser {
            user_id: vir_id.to_string(),
            unique_workload_id: "workload-4".to_string(),
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            domain_id: Some("d1".to_string()),
            resolved_user_name: "mapped_user".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            // Authorization for a different project, so requested scope won't match
            authorizations: vec![Authorization::Project {
                project_id: "other-project".to_string(),
                project_domain_id: "d1".to_string(),
                roles: vec![role_ref("reader", "reader")],
            }],
            ruleset_version: 1,
            enabled: true,
            created_at: 0,
            last_authenticated_at: 0,
        };

        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_get_virtual_user()
            .returning(move |_state, id: &str| {
                if id == vir_id {
                    Ok(Some(vu.clone()))
                } else {
                    Ok(None)
                }
            });

        // Assignment fallback is triggered since no matching authorization
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::<Assignment>::new()));

        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_mapping(mapping_mock)
                    .mock_assignment(assignment_mock),
            ),
        )
        .await;

        let mc = MappingContext {
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            virtual_user_id: vir_id.to_string(),
        };

        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Mapping(mc))
            .principal(make_user_identity(vir_id))
            .build();

        let result = ValidatedSecurityContext::new_for_scope(
            ctx,
            make_project_scope("requested-project"),
            &state,
        )
        .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }

    // --- Mapping: virtual user not found fails ---
    #[tokio::test]
    async fn test_new_for_scope_mapping_virtual_user_not_found() {
        let vir_id = "vu-nonexistent0000000000000000000000";

        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_get_virtual_user()
            .returning(move |_state, _| Ok(None::<VirtualUser>));

        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
        )
        .await;

        let mc = MappingContext {
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            virtual_user_id: vir_id.to_string(),
        };

        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Mapping(mc))
            .principal(make_user_identity(vir_id))
            .build();

        let result =
            ValidatedSecurityContext::new_for_scope(ctx, make_project_scope("pid"), &state).await;

        assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
    }

    // --- Mapping: empty authorizations list fails ---
    #[tokio::test]
    async fn test_new_for_scope_mapping_empty_authorizations() {
        let vir_id = "vu-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        let vu = VirtualUser {
            user_id: vir_id.to_string(),
            unique_workload_id: "workload-5".to_string(),
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            domain_id: Some("d1".to_string()),
            resolved_user_name: "mapped_user".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![],
            ruleset_version: 1,
            enabled: true,
            created_at: 0,
            last_authenticated_at: 0,
        };

        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_get_virtual_user()
            .returning(move |_state, id: &str| {
                if id == vir_id {
                    Ok(Some(vu.clone()))
                } else {
                    Ok(None)
                }
            });

        // Assignment fallback is triggered since no matching authorization
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::<Assignment>::new()));

        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_mapping(mapping_mock)
                    .mock_assignment(assignment_mock),
            ),
        )
        .await;

        let mc = MappingContext {
            mapping_id: "map-1".to_string(),
            matched_rule_name: "rule-1".to_string(),
            virtual_user_id: vir_id.to_string(),
        };

        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Mapping(mc))
            .principal(make_user_identity(vir_id))
            .build();

        let result =
            ValidatedSecurityContext::new_for_scope(ctx, make_project_scope("pid"), &state).await;

        assert!(matches!(
            result,
            Err(AuthenticationError::ActorHasNoRolesOnTarget)
        ));
    }
}
