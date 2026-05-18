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

use tracing::debug;

use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::error::KeystoneError;
use openstack_keystone_core_types::role::*;

use crate::assignment::AssignmentApi;
use crate::keystone::ServiceState;
use crate::role::RoleApi;

pub use openstack_keystone_core_types::auth::*;

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

    /// The only way to create an instance in production — validates and locks
    /// the context.
    pub async fn new_with_roles(
        mut ctx: SecurityContext,
        state: &ServiceState,
    ) -> Result<Self, KeystoneError> {
        ctx.validate()?;
        // Populate roles before locking
        if ctx.authorization.is_some() {
            calculate_effective_roles_in_security_context(state, &mut ctx).await?;
        }
        Ok(ValidatedSecurityContext(ctx))
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

// Expand scope role information in the SecurityContext.
//
// Set the effective roles into the (`SecurityContext::authorization::roles`)
// that the principal has on the scope taking into consideration the
// authentication method.
//
// * For application_credential this sets roles frozen on the application
//   credential removing the
// ones the principal is not having access to anymore.
// * For trusts it returns all roles the trustor has or the ones explicitly
//   declared on the [`Trust`].
//
pub async fn calculate_effective_roles_in_security_context(
    state: &ServiceState,
    security_context: &mut SecurityContext,
) -> Result<(), KeystoneError> {
    if let Some(ref mut authorization) = security_context.authorization {
        match &authorization.scope {
            ScopeInfo::Domain(domain) => {
                authorization.try_set_roles(
                    state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&security_context.principal.get_user_id())
                                .domain_id(&domain.id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter(),
                )?;
            }
            ScopeInfo::Project(project) => {
                let user_roles = state
                    .provider
                    .get_assignment_provider()
                    .list_role_assignments(
                        state,
                        &RoleAssignmentListParametersBuilder::default()
                            .user_id(&security_context.principal.get_user_id())
                            .project_id(&project.id)
                            .include_names(false)
                            .effective(true)
                            .build()
                            .map_err(AssignmentProviderError::from)?,
                    )
                    .await?;
                match &security_context.authentication_context {
                    AuthenticationContext::ApplicationCredential(application_credential) => {
                        // For application credential we must take the roles frozen on the app_cred
                        // itself and filter out roles that the actor does
                        // not have access to (anymore).
                        let user_role_ids: HashSet<String> =
                            user_roles.into_iter().map(|x| x.role_id.clone()).collect();

                        // Gather all effective roles that the user have remaining should some of
                        // the AppCred assigned roles be revoked in the
                        // meanwhile.
                        let mut effective_roles: Vec<RoleRef> = Vec::new();
                        for role in application_credential.roles.iter() {
                            if user_role_ids.contains(&role.id) {
                                effective_roles.push(role.clone());
                            }
                        }

                        // Set roles on the authorization
                        authorization.roles = Some(effective_roles.clone());
                    }
                    _ => {
                        // for everything else just set all roles the principal has on the project.
                        authorization.try_set_roles(user_roles.into_iter())?;
                    }
                }
            }
            ScopeInfo::System(system_id) => {
                authorization.try_set_roles(
                    state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&security_context.principal.get_user_id())
                                .system_id(system_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter(),
                )?;
            }
            ScopeInfo::Trust(trust) => {
                // Resolve role assignments of the trust verifying that the trustor still has
                // those roles on the scope.
                let trustor_roles = state
                    .provider
                    .get_assignment_provider()
                    .list_role_assignments(
                        state,
                        &RoleAssignmentListParameters {
                            user_id: Some(trust.trustor_user_id.clone()),
                            project_id: trust.project_id.clone(),
                            effective: Some(true),
                            ..Default::default()
                        },
                    )
                    .await?;
                if let Some(trust_roles) = &trust.roles {
                    // `token_model._get_trust_roles`: Verify that the trustor still has all
                    // roles mentioned in the trust. Return error when at least one role is not
                    // available anymore.

                    let trustor_role_ids: HashSet<String> = trustor_roles
                        .into_iter()
                        .map(|x| x.role_id.clone())
                        .collect();
                    // Expand the implied roles
                    let mut trust_roles = trust_roles.clone();
                    state
                        .provider
                        .get_role_provider()
                        .expand_implied_roles(state, &mut trust_roles)
                        .await?;
                    if !trust_roles
                        .iter()
                        .all(|role| trustor_role_ids.contains(&role.id))
                    {
                        debug!(
                            "Trust roles {:?} are missing for the trustor {:?}",
                            trust_roles, trustor_role_ids
                        );
                        return Err(AuthenticationError::ActorHasNoRolesOnTarget)?;
                    }
                    trust_roles.retain_mut(|role| role.domain_id.is_none());
                    authorization.roles = Some(trust_roles);
                } else {
                    authorization.try_set_roles(trustor_roles.into_iter())?;
                }
            }
            ScopeInfo::Unscoped => {
                // Unscoped tokens by design have no roles. Token restrictions
                // cannot narrow an unscoped scope, so apply restrictions and
                // return early — skipping the empty-roles gate below.
                if let Some(token_restriction) = &security_context.token_restriction {
                    if let Some(roles) = &token_restriction.roles {
                        authorization.roles = Some(roles.clone());
                    }
                }
                return Ok(());
            }
        }

        if authorization
            .roles
            .as_ref()
            .is_none_or(|roles| roles.is_empty())
        {
            return Err(AuthenticationError::ActorHasNoRolesOnTarget)?;
        }
        // Checking token restrictions take place at the end to ensure it is not
        // overwritten by other logic.
        if let Some(token_restriction) = &security_context.token_restriction {
            if let Some(roles) = &token_restriction.roles {
                authorization.roles = Some(roles.clone());
            }
        }
    }

    Ok(())
}
