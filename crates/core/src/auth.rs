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
    AssignmentProviderError, RoleAssignmentListParameters, RoleAssignmentListParametersBuilder,
};
use openstack_keystone_core_types::identity::IdentityProviderError;
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::role::*;
use openstack_keystone_core_types::token::FernetToken;

use crate::assignment::AssignmentApi;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
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
            ctx.set_authorization_scope(scope)?;
        }

        // Populate user_domain before validation, since xvalidate() requires it
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
        }
        // TODO: Evaluate whether token revocation check should be done here - it is a
        // part of the authentication validation
        // Populate roles before locking
        if let Some(authz) = ctx.authorization() {
            let role_vec = calculate_effective_roles(state, &ctx, &authz.scope).await?;
            ctx.set_effective_roles(role_vec);
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
// * For project scope and token restrictions present in the context with the roles attached - such
//   roles are returned without verifying whether they are directly assigned to the user. Otherwise a
//   regular user roles on the project resolving is applied.
// * For the domain scope a roles that the user is having on the domain are evaluated.
// * For unscoped context an empty list is returned.
// * For system scope a lookup of all roles the user has access to on the system are returned.
async fn calculate_effective_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    scope: &ScopeInfo,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    scope.validate()?;
    let user_id = ctx.principal().get_user_id();
    let roles = match &scope {
        ScopeInfo::Domain(domain) => state
            .provider
            .get_assignment_provider()
            .list_role_assignments(
                state,
                &RoleAssignmentListParametersBuilder::default()
                    .user_id(&user_id)
                    .domain_id(&domain.id)
                    .include_names(true)
                    .effective(true)
                    .build()
                    .map_err(AssignmentProviderError::from)?,
            )
            .await
            .auth_context("resolving role assignments")?
            .into_iter()
            .map(|a| {
                a.try_into()
                    .map_err(|_| AuthenticationError::RoleConversionFailed)
            })
            .collect::<Result<Vec<_>, _>>()?,
        ScopeInfo::Project { project, .. } => {
            if let Some(token_restriction) = &ctx.token_restriction()
                && let Some(roles) = &token_restriction.roles
            {
                // When the context has a token restriction bound use the roles tied to the token
                // restriction otherwise use the normal role resolution
                roles.clone()
            } else {
                let user_assignments = state
                    .provider
                    .get_assignment_provider()
                    .list_role_assignments(
                        state,
                        &RoleAssignmentListParametersBuilder::default()
                            .user_id(&user_id)
                            .project_id(&project.id)
                            .include_names(false)
                            .effective(true)
                            .build()
                            .map_err(AssignmentProviderError::from)?,
                    )
                    .await
                    .auth_context("resolving role assignments")?;
                match &ctx.authentication_context() {
                    AuthenticationContext::ApplicationCredential {
                        application_credential,
                        ..
                    } => {
                        let user_role_ids: HashSet<String> = user_assignments
                            .into_iter()
                            .map(|x| x.role_id.clone())
                            .collect();
                        application_credential
                            .roles
                            .iter()
                            .filter(|role| user_role_ids.contains(&role.id))
                            .cloned()
                            .collect()
                    }
                    _ => user_assignments
                        .into_iter()
                        .map(|a| {
                            a.try_into()
                                .map_err(|_| AuthenticationError::RoleConversionFailed)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                }
            }
        }
        ScopeInfo::System(system_id) => state
            .provider
            .get_assignment_provider()
            .list_role_assignments(
                state,
                &RoleAssignmentListParametersBuilder::default()
                    .user_id(&user_id)
                    .system_id(system_id)
                    .include_names(true)
                    .effective(true)
                    .build()
                    .map_err(AssignmentProviderError::from)?,
            )
            .await
            .auth_context("resolving role assignments")?
            .into_iter()
            .map(|a| {
                a.try_into()
                    .map_err(|_| AuthenticationError::RoleConversionFailed)
            })
            .collect::<Result<Vec<_>, _>>()?,
        ScopeInfo::TrustProject(tpi) => {
            // Get all trustor roles
            let trustor_assignments = state
                .provider
                .get_assignment_provider()
                .list_role_assignments(
                    state,
                    &RoleAssignmentListParameters {
                        user_id: Some(tpi.trust.trustor_user_id.clone()),
                        project_id: Some(tpi.project.id.clone()),
                        effective: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .auth_context("resolving trust role assignments")?;
            if let Some(trust_roles) = &tpi.trust.roles {
                // Capture unique role_id of the trustor on the project
                let trustor_role_ids: HashSet<String> = trustor_assignments
                    .into_iter()
                    .map(|x| x.role_id.clone())
                    .collect();
                let mut trust_roles = trust_roles.clone();
                // expand implied roles of the trust
                state
                    .provider
                    .get_role_provider()
                    .expand_implied_roles(state, &mut trust_roles)
                    .await
                    .auth_context("expanding implied roles for trust")?;
                // Filter out roles frozen in the trust that the trustor does not possess anymore.
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
                trust_roles
            } else {
                // No roles were tied to the trust. Return all trustor roles.
                trustor_assignments
                    .into_iter()
                    .map(|a| {
                        a.try_into()
                            .map_err(|_| AuthenticationError::RoleConversionFailed)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
        }
        ScopeInfo::Unscoped => Vec::new(),
    };

    if !matches!(scope, ScopeInfo::Unscoped) && roles.is_empty() {
        return Err(AuthenticationError::ActorHasNoRolesOnTarget);
    }

    Ok(roles)
}
#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::assignment::{
        Assignment, AssignmentType, RoleAssignmentListParameters,
    };
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContextTestingBuilder, TrustProjectInfo, UserIdentityInfo,
    };
    use openstack_keystone_core_types::identity::{UserOptions, UserResponse};
    use openstack_keystone_core_types::resource::Project;
    use openstack_keystone_core_types::role::{RoleRef, RoleRefBuilder};
    use openstack_keystone_core_types::token::TokenRestriction;
    use openstack_keystone_core_types::trust::Trust;
    use std::collections::HashMap;

    use crate::assignment::MockAssignmentProvider;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;
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
            domain_id: Some("d1".to_string()),
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
        Assignment {
            actor_id: "uid".to_string(),
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
                    && q.include_names == Some(false)
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
            .returning(move |_state, _q| Ok(vec![assignment_with_role(rid1)]));
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
                    && q.include_names == Some(false)
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
}
