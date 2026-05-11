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
//! # Token provider.
//!
//! A Keystone token is an alpha-numeric text string that enables access to
//! OpenStack APIs and resources. A token may be revoked at any time and is
//! valid for a finite duration. OpenStack Identity is an integration service
//! that does not aspire to be a full-fledged identity store and management
//! solution.

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, trace};
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::assignment::{
    RoleAssignmentListParameters, RoleAssignmentListParametersBuilder,
};
use openstack_keystone_core_types::role::RoleRef;
use openstack_keystone_core_types::token::*;

use crate::auth::*;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::resource::ResourceApi;
use crate::revoke::RevokeApi;
use crate::token::validate::{validate_token_scope, validate_token_subject};
use crate::token::{
    TokenApi, TokenProviderError,
    backend::{TokenBackend, TokenRestrictionBackend},
};
use crate::{
    application_credential::ApplicationCredentialApi,
    assignment::{AssignmentApi, error::AssignmentProviderError},
    role::RoleApi,
    trust::TrustApi,
};

pub struct TokenService {
    config: Config,
    backend_driver: Arc<dyn TokenBackend>,
    tr_backend_driver: Arc<dyn TokenRestrictionBackend>,
}

impl TokenService {
    /// Creates a new `TokenService` instance.
    ///
    /// # Parameters
    /// - `config`: The system configuration.
    /// - `plugin_manager`: The plugin manager to resolve backends.
    ///
    /// # Returns
    /// - `Result<Self, TokenProviderError>` - The new `TokenService` instance
    ///   or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, TokenProviderError> {
        let backend_driver = plugin_manager
            .get_token_backend(config.token.provider.to_string())?
            .clone();
        let tr_backend_driver = plugin_manager
            .get_token_restriction_backend(&config.token_restriction.driver)?
            .clone();
        Ok(Self {
            config: config.clone(),
            backend_driver,
            tr_backend_driver,
        })
    }

    /// Calculates the expiration time for a new token.
    ///
    /// # Parameters
    /// - `auth_expiration`: Optional expiration time from authentication.
    ///
    /// # Returns
    /// - `Result<DateTime<Utc>, TokenProviderError>` - The calculated
    ///   expiration time or an error.
    fn get_new_token_expiry(
        &self,
        auth_expiration: &Option<DateTime<Utc>>,
    ) -> Result<DateTime<Utc>, TokenProviderError> {
        let default_expiry = Utc::now()
            .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
            .ok_or(TokenProviderError::ExpiryCalculation)?;
        Ok(auth_expiration
            .map(|x| std::cmp::min(x, default_expiry))
            .unwrap_or(default_expiry))
    }

    /// Expand user information in the token.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `token`: The token to expand.
    ///
    /// # Returns
    /// - `Result<(), TokenProviderError>` - Ok on success, or an error.
    async fn expand_user_information(
        &self,
        state: &ServiceState,
        token: &mut Token,
    ) -> Result<(), TokenProviderError> {
        if token.user().is_none() {
            let user = state
                .provider
                .get_identity_provider()
                .get_user(state, token.user_id())
                .await?;
            match token {
                Token::ApplicationCredential(data) => {
                    data.user = user;
                }
                Token::Unscoped(data) => {
                    data.user = user;
                }
                Token::ProjectScope(data) => {
                    data.user = user;
                }
                Token::DomainScope(data) => {
                    data.user = user;
                }
                Token::FederationUnscoped(data) => {
                    data.user = user;
                }
                Token::FederationProjectScope(data) => {
                    data.user = user;
                }
                Token::FederationDomainScope(data) => {
                    data.user = user;
                }
                Token::Restricted(data) => {
                    data.user = user;
                }
                Token::SystemScope(data) => {
                    data.user = user;
                }
                Token::Trust(data) => {
                    data.user = if let Some(trust) = &data.trust
                        && trust.impersonation
                    {
                        state
                            .provider
                            .get_identity_provider()
                            .get_user(state, &trust.trustor_user_id)
                            .await?
                    } else {
                        user
                    };
                }
            }
        }
        Ok(())
    }

    /// Expand the target scope information in the token.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `token`: The token to expand.
    ///
    /// # Returns
    /// - `Result<(), TokenProviderError>` - Ok on success, or an error.
    async fn expand_scope_information(
        &self,
        state: &ServiceState,
        token: &mut Token,
    ) -> Result<(), TokenProviderError> {
        match token {
            Token::ProjectScope(data) if data.project.is_none() => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(state, &data.project_id)
                    .await?;

                data.project = project;
            }
            Token::ApplicationCredential(data) => {
                if data.application_credential.is_none() {
                    data.application_credential = Some(
                        state
                            .provider
                            .get_application_credential_provider()
                            .get_application_credential(state, &data.application_credential_id)
                            .await?
                            .ok_or_else(|| {
                                TokenProviderError::ApplicationCredentialNotFound(
                                    data.application_credential_id.clone(),
                                )
                            })?,
                    );
                }
                if data.project.is_none() {
                    let project = state
                        .provider
                        .get_resource_provider()
                        .get_project(state, &data.project_id)
                        .await?;

                    data.project = project;
                }
            }
            Token::FederationProjectScope(data) if data.project.is_none() => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(state, &data.project_id)
                    .await?;

                data.project = project;
            }
            Token::DomainScope(data) if data.domain.is_none() => {
                let domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(state, &data.domain_id)
                    .await?;

                data.domain = domain;
            }
            Token::FederationDomainScope(data) if data.domain.is_none() => {
                let domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(state, &data.domain_id)
                    .await?;

                data.domain = domain;
            }
            Token::Restricted(data) if data.project.is_none() => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(state, &data.project_id)
                    .await?;

                data.project = project;
            }
            Token::SystemScope(_data) => {}
            Token::Trust(data) => {
                if data.trust.is_none() {
                    data.trust = state
                        .provider
                        .get_trust_provider()
                        .get_trust(state, &data.trust_id)
                        .await?;
                }
                if data.project.is_none() {
                    data.project = state
                        .provider
                        .get_resource_provider()
                        .get_project(state, &data.project_id)
                        .await?;
                }
            }

            _ => {}
        };
        Ok(())
    }

    /// Populate role assignments in the token that support that information.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `token`: The token to populate.
    ///
    /// # Returns
    /// - `Result<(), TokenProviderError>` - Ok on success, or an error.
    async fn _populate_role_assignments(
        &self,
        state: &ServiceState,
        token: &mut Token,
    ) -> Result<(), TokenProviderError> {
        match token {
            Token::ApplicationCredential(data) => {
                if data.application_credential.is_none() {
                    data.application_credential = Some(
                        state
                            .provider
                            .get_application_credential_provider()
                            .get_application_credential(state, &data.application_credential_id)
                            .await?
                            .ok_or_else(|| {
                                TokenProviderError::ApplicationCredentialNotFound(
                                    data.application_credential_id.clone(),
                                )
                            })?,
                    );
                }
                if let Some(ref mut ac) = data.application_credential {
                    let user_role_ids: HashSet<String> = state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .project_id(&ac.project_id)
                                .include_names(false)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| x.role_id.clone())
                        .collect();

                    // Gather all effective roles that the user have remaining should some of the
                    // AppCred assigned roles be revoked in the meanwhile.
                    let mut final_roles: Vec<RoleRef> = Vec::new();
                    for role in ac.roles.iter() {
                        if user_role_ids.contains(&role.id) {
                            final_roles.push(role.clone());
                        }
                    }
                    if final_roles.is_empty() {
                        return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                    }
                    data.roles = Some(final_roles);
                };
            }
            Token::DomainScope(data) => {
                data.roles = Some(
                    state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .domain_id(&data.domain_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| RoleRef {
                            id: x.role_id.clone(),
                            name: x.role_name.clone(),
                            domain_id: None,
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::FederationProjectScope(data) => {
                data.roles = Some(
                    state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .project_id(&data.project_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| RoleRef {
                            id: x.role_id.clone(),
                            name: x.role_name.clone(),
                            domain_id: None,
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::FederationDomainScope(data) => {
                data.roles = Some(
                    state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .domain_id(&data.domain_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| RoleRef {
                            id: x.role_id.clone(),
                            name: x.role_name.clone(),
                            domain_id: None,
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::ProjectScope(data) => {
                data.roles = Some(
                    state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .project_id(&data.project_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| RoleRef {
                            id: x.role_id.clone(),
                            name: x.role_name.clone(),
                            domain_id: None,
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::Restricted(data) if data.roles.is_none() => {
                self.get_token_restriction(state, &data.token_restriction_id, true)
                    .await?
                    .inspect(|restrictions| data.roles = restrictions.roles.clone())
                    .ok_or(TokenProviderError::TokenRestrictionNotFound(
                        data.token_restriction_id.clone(),
                    ))?;
            }
            Token::SystemScope(data) => {
                data.roles = Some(
                    state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .system_id(&data.system_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| RoleRef {
                            id: x.role_id.clone(),
                            name: x.role_name.clone(),
                            domain_id: None,
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::Trust(data) => {
                // Resolve role assignments of the trust verifying that the trustor still has
                // those roles on the scope.
                if let Some(ref mut trust) = data.trust {
                    let trustor_roles: HashSet<String> = state
                        .provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            state,
                            &RoleAssignmentListParameters {
                                user_id: Some(trust.trustor_user_id.clone()),
                                project_id: Some(data.project_id.clone()),
                                effective: Some(true),
                                ..Default::default()
                            },
                        )
                        .await?
                        .into_iter()
                        .map(|x| x.role_id.clone())
                        .collect();
                    if let Some(ref mut trust_roles) = trust.roles {
                        // `token_model._get_trust_roles`: Verify that the trustor still has all
                        // roles mentioned in the trust. Return error when at least one role is not
                        // available anymore.

                        // Expand the implied roles
                        state
                            .provider
                            .get_role_provider()
                            .expand_implied_roles(state, trust_roles)
                            .await?;
                        if !trust_roles
                            .iter()
                            .all(|role| trustor_roles.contains(&role.id))
                        {
                            debug!(
                                "Trust roles {:?} are missing for the trustor {:?}",
                                trust_roles, trustor_roles
                            );
                            return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                        }
                        trust_roles.retain_mut(|role| role.domain_id.is_none());
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[async_trait]
impl TokenApi for TokenService {
    /// Authenticate by token.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `credential`: The token credential string.
    /// - `allow_expired`: Whether to allow expired tokens.
    /// - `window_seconds`: Expiration buffer in seconds.
    ///
    /// # Returns
    /// - `Result<AuthenticatedInfo, TokenProviderError>` - Authenticated
    ///   information or an error.
    async fn authenticate_by_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<AuthenticationResult, TokenProviderError> {
        // TODO: is the expand really false?
        let token = self
            .validate_token(state, credential, allow_expired, window_seconds)
            .await?;
        let user = token
            .user()
            .as_ref()
            .ok_or(TokenProviderError::UserNotFound(token.user_id().clone()))?;
        let mut ctx = AuthenticationResultBuilder::default();

        ctx.context(AuthenticationContext::Token(
            TokenContextBuilder::default()
                .audit_ids(token.audit_ids().clone())
                .methods(token.methods().clone())
                .expires_at(*token.expires_at())
                .build()?,
        ))
        .principal(PrincipalInfo {
            domain_id: Some(user.domain_id.clone()),
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(token.user_id())
                    .user(user.clone())
                    .build()?,
            ),
        });
        if let Token::Restricted(restriction) = &token {
            if !restriction.allow_renew {
                return Err(AuthenticationError::TokenRenewalForbidden)?;
            }
            let token_restriction = &state
                .provider
                .get_token_provider()
                .get_token_restriction(state, &restriction.token_restriction_id, false)
                .await?
                .ok_or(TokenProviderError::TokenRestrictionNotFound(
                    restriction.token_restriction_id.clone(),
                ))?;
            ctx.token_restriction(token_restriction.to_owned());
        }
        Ok(ctx.build().map_err(AuthenticationError::from)?)
    }

    /// Validate token.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `credential`: The token credential string.
    /// - `allow_expired`: Whether to allow expired tokens.
    /// - `window_seconds`: Expiration buffer in seconds.
    ///
    /// # Returns
    /// - `Result<Token, TokenProviderError>` - The decoded token or an error.
    async fn validate_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError> {
        let mut token = self.backend_driver.decode(credential)?;
        let latest_expiration_cutof = Utc::now()
            .checked_add_signed(TimeDelta::seconds(window_seconds.unwrap_or(0)))
            .unwrap_or(Utc::now());
        if !allow_expired.unwrap_or_default() && *token.expires_at() < latest_expiration_cutof {
            trace!(
                "Token has expired at {:?} with cutof: {:?}",
                token.expires_at(),
                latest_expiration_cutof
            );
            return Err(TokenProviderError::Expired);
        }

        // Expand the token unless `expand = Some(false)`
        token = self.expand_token_information(state, &token).await?;

        if state
            .provider
            .get_revoke_provider()
            .is_token_revoked(state, &token)
            .await?
        {
            return Err(TokenProviderError::TokenRevoked);
        }

        validate_token_subject(&token, state).await?;
        validate_token_scope(&token, state).await?;

        Ok(token)
    }

    /// Issue the Keystone token.
    ///
    /// # Security Note
    /// A series of checks is performed to verify whether a token for the
    /// requested scope can be issued with the given [`SecurityContext`].
    ///
    /// * `token_restriction` - When set in the context only a restricted token
    ///   bound to the project scope can be issued.
    /// * `trust` - For Trust scope only Password/Token auth can be used. Trust
    ///   from Trust is
    /// forbidden.
    /// * `system` - Only Password/Token auth can be used to grant system scope.
    /// * `application_credentials` - Token can be granted only when auth is
    ///   scoped to AppCreds and
    /// the project_id matches the scope. No other token can be issued with
    /// [`ApplicationCredential`] in the context.
    ///
    ///
    /// # Parameters
    /// - `authentication_info`: Information about the authenticated user.
    /// - `authz_info`: Authorization scope.
    /// - `token_restrictions`: Optional restrictions for the token.
    ///
    /// # Returns
    /// - `Result<Token, TokenProviderError>` - The issued token or an error.
    fn issue_token(
        &self,
        ctx: &SecurityContext,
        authz_info: &AuthzInfo,
    ) -> Result<Token, TokenProviderError> {
        // This should be executed already, but let's better repeat it as last line of
        // defense. It is also necessary to call this before to stop before we
        // start to resolve authz info.
        ctx.validate()?;

        // Check whether it is allowed to change the scope of the token if
        // AuthenticatedInfo already contains scope it was issued for.
        ctx.validate_scope_boundaries(authz_info)?;
        let token = Token::from_security_context_with_scope(
            ctx,
            authz_info,
            self.get_new_token_expiry(&ctx.expires_at)?,
        )?;
        Ok(token)
    }

    /// Encode the token into a `String` representation.
    ///
    /// # Parameters
    /// - `token`: The token to encode.
    ///
    /// # Returns
    /// - `Result<String, TokenProviderError>` - The encoded string or an error.
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError> {
        self.backend_driver.encode(token)
    }

    /// Populate role assignments in the token that support that information.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `token`: The token to populate.
    ///
    /// # Returns
    /// - `Result<(), TokenProviderError>` - Ok on success, or an error.
    async fn populate_role_assignments(
        &self,
        state: &ServiceState,
        token: &mut Token,
    ) -> Result<(), TokenProviderError> {
        self._populate_role_assignments(state, token).await
    }

    /// Expand the token information.
    ///
    /// Query and expand information about the user, scope and the role
    /// assignments into the token.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `token`: The token to expand.
    ///
    /// # Returns
    /// - `Result<Token, TokenProviderError>` - The expanded token or an error.
    async fn expand_token_information(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<Token, TokenProviderError> {
        let mut new_token = token.clone();
        self.expand_user_information(state, &mut new_token).await?;
        self.expand_scope_information(state, &mut new_token).await?;
        self.populate_role_assignments(state, &mut new_token)
            .await?;
        Ok(new_token)
    }

    /// Get the token restriction by the ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The restriction ID.
    /// - `_expand_roles`: Whether to expand roles.
    ///
    /// # Returns
    /// - `Result<Option<TokenRestriction>, TokenProviderError>` - A `Result`
    ///   containing an `Option` with the token restriction if found, or an
    ///   `Error`.
    async fn get_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        _expand_roles: bool,
    ) -> Result<Option<TokenRestriction>, TokenProviderError> {
        let res = self
            .tr_backend_driver
            .get_token_restriction(state, id)
            .await?;

        Ok(res)
    }

    /// Create new token restriction.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `restriction`: The restriction data to create.
    ///
    /// # Returns
    /// - `Result<TokenRestriction, TokenProviderError>` - The created token
    ///   restriction or an error.
    async fn create_token_restriction<'a>(
        &self,
        state: &ServiceState,
        restriction: TokenRestrictionCreate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        let mut restriction = restriction;
        if restriction.id.is_empty() {
            restriction.id = Uuid::new_v4().simple().to_string();
        }
        self.tr_backend_driver
            .create_token_restriction(state, restriction)
            .await
    }

    /// List token restrictions.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for listing restrictions.
    ///
    /// # Returns
    /// - `Result<Vec<TokenRestriction>, TokenProviderError>` - A list of token
    ///   restrictions or an error.
    async fn list_token_restrictions<'a>(
        &self,
        state: &ServiceState,
        params: &TokenRestrictionListParameters,
    ) -> Result<Vec<TokenRestriction>, TokenProviderError> {
        self.tr_backend_driver
            .list_token_restrictions(state, params)
            .await
    }

    /// Update existing token restriction.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The restriction ID.
    /// - `restriction`: The update data.
    ///
    /// # Returns
    /// - `Result<TokenRestriction, TokenProviderError>` - The updated token
    ///   restriction or an error.
    async fn update_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        restriction: TokenRestrictionUpdate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        self.tr_backend_driver
            .update_token_restriction(state, id, restriction)
            .await
    }

    /// Delete token restriction by the ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The restriction ID.
    ///
    /// # Returns
    /// - `Result<(), TokenProviderError>` - Ok on success, or an error.
    async fn delete_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), TokenProviderError> {
        self.tr_backend_driver
            .delete_token_restriction(state, id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use eyre::{Result, eyre};
    use std::sync::Arc;
    use uuid::Uuid;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::application_credential::*;
    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::*;

    use super::super::tests::setup_config;
    use super::*;
    use crate::application_credential::MockApplicationCredentialProvider;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::revoke::MockRevokeProvider;
    use crate::tests::get_mocked_state;
    use crate::token::backend::{MockTokenBackend, MockTokenRestrictionBackend};

    /// Generate test token to use for validation testing.
    fn generate_token(validity: Option<TimeDelta>) -> Result<Token> {
        Ok(Token::ProjectScope(ProjectScopePayload {
            methods: vec!["password".into()],
            user_id: Uuid::new_v4().simple().to_string(),
            project_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Utc::now()
                .checked_add_signed(validity.unwrap_or_default())
                .ok_or(eyre!("timedelta apply failed"))?,
            ..Default::default()
        }))
    }

    fn get_provider(config: &Config, token_mock: Option<MockTokenBackend>) -> TokenService {
        TokenService {
            config: config.clone(),
            backend_driver: Arc::new(token_mock.unwrap_or_default()),
            tr_backend_driver: Arc::new(MockTokenRestrictionBackend::default()),
        }
    }

    #[tokio::test]
    async fn test_populate_role_assignments() {
        let token_provider = get_provider(&Config::default(), None);
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.project_id == Some("project_id".to_string())
            })
            .returning(|_, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "rid".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.project_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.domain_id == Some("domain_id".to_string())
            })
            .returning(|_, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "rid".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.domain_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        let provider = Provider::mocked_builder().mock_assignment(assignment_mock);

        let state = get_mocked_state(None, Some(provider)).await;

        let mut ptoken = Token::ProjectScope(ProjectScopePayload {
            user_id: "bar".into(),
            project_id: "project_id".into(),
            ..Default::default()
        });
        token_provider
            .populate_role_assignments(&state, &mut ptoken)
            .await
            .unwrap();

        if let Token::ProjectScope(data) = ptoken {
            assert_eq!(
                data.roles.unwrap(),
                vec![RoleRef {
                    id: "rid".into(),
                    name: Some("role_name".into()),
                    domain_id: None
                }]
            );
        } else {
            panic!("Not project scope");
        }

        let mut dtoken = Token::DomainScope(DomainScopePayload {
            user_id: "bar".into(),
            domain_id: "domain_id".into(),
            ..Default::default()
        });
        token_provider
            .populate_role_assignments(&state, &mut dtoken)
            .await
            .unwrap();

        if let Token::DomainScope(data) = dtoken {
            assert_eq!(
                data.roles.unwrap(),
                vec![RoleRef {
                    id: "rid".into(),
                    name: Some("role_name".into()),
                    domain_id: None
                }]
            );
        } else {
            panic!("Not domain scope");
        }

        let mut utoken = Token::Unscoped(UnscopedPayload {
            user_id: "bar".into(),
            ..Default::default()
        });
        assert!(
            token_provider
                .populate_role_assignments(&state, &mut utoken)
                .await
                .is_ok()
        );
    }

    /// Test that a valid token with revocation events fails validation.
    #[tokio::test]
    async fn test_validate_token_revoked() {
        let token = generate_token(Some(TimeDelta::hours(1))).unwrap();
        let token_clone_expect = token.clone();

        let mut backend_driver_mock = MockTokenBackend::default();
        backend_driver_mock
            .expect_encode()
            .returning(|_| Ok("token".to_string()));
        backend_driver_mock
            .expect_decode()
            .returning(move |_| Ok(token_clone_expect.clone()));

        let config = setup_config();
        let token_provider = get_provider(&config, Some(backend_driver_mock));
        let mut revoke_mock = MockRevokeProvider::default();
        //let token_clone = token.clone();
        revoke_mock
            .expect_is_token_revoked()
            // TODO: in roundtrip the precision of expiry is reduced and issued_at is different
            //.withf(move |_, t: &Token| {
            //    *t == token_clone
            //})
            .returning(|_, _| Ok(true));

        let mut identity_mock = MockIdentityProvider::default();
        let token_clone = token.clone();
        identity_mock
            .expect_get_user()
            .withf(move |_, id: &'_ str| id == token_clone.user_id())
            .returning(|_, id: &'_ str| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .id(id)
                        .build()
                        .unwrap(),
                ))
            });
        let mut resource_mock = MockResourceProvider::default();
        let token_clone2 = token.clone();
        resource_mock
            .expect_get_project()
            .withf(move |_, id: &'_ str| id == token_clone2.project_id().unwrap())
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    name: "project".to_string(),
                    ..Default::default()
                }))
            });

        let mut assignment_mock = MockAssignmentProvider::default();
        let token_clone3 = token.clone();
        assignment_mock
            .expect_list_role_assignments()
            .withf(move |_, q: &RoleAssignmentListParameters| {
                q.project_id == token_clone3.project_id().cloned()
            })
            .returning(|_, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "rid".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.project_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        let provider = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_revoke(revoke_mock)
            .mock_resource(resource_mock);

        let state = get_mocked_state(Some(config), Some(provider)).await;

        let credential = token_provider.encode_token(&token).unwrap();
        match token_provider
            .validate_token(&state, &credential, Some(false), None)
            .await
        {
            Err(TokenProviderError::TokenRevoked) => {}
            _ => {
                panic!("token must be revoked")
            }
        }
    }

    #[tokio::test]
    async fn test_populate_role_assignments_application_credential() {
        let token_provider = get_provider(&Config::default(), None);
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.project_id == Some("project_id".to_string())
                    && q.user_id == Some("bar".to_string())
            })
            .returning(|_, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "role_1".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.project_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.domain_id == Some("domain_id".to_string())
            })
            .returning(|_, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "rid".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.domain_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        let mut ac_mock = MockApplicationCredentialProvider::default();
        ac_mock
            .expect_get_application_credential()
            .withf(|_, id: &'_ str| id == "app_cred_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(ApplicationCredential {
                    access_rules: None,
                    description: None,
                    expires_at: None,
                    id: id.into(),
                    name: "foo".into(),
                    project_id: "project_id".into(),
                    roles: vec![
                        RoleRef {
                            id: "role_1".into(),
                            name: Some("role_name_1".into()),
                            domain_id: None,
                        },
                        RoleRef {
                            id: "role_2".into(),
                            name: Some("role_name_2".into()),
                            domain_id: None,
                        },
                    ],
                    unrestricted: false,
                    user_id: "bar".into(),
                }))
            });
        ac_mock
            .expect_get_application_credential()
            .withf(|_, id: &'_ str| id == "app_cred_bad_roles")
            .returning(|_, id: &'_ str| {
                Ok(Some(ApplicationCredential {
                    access_rules: None,
                    description: None,
                    expires_at: None,
                    id: id.into(),
                    name: "foo".into(),
                    project_id: "project_id".into(),
                    roles: vec![
                        RoleRef {
                            id: "-role_1".into(),
                            name: Some("-role_name_1".into()),
                            domain_id: None,
                        },
                        RoleRef {
                            id: "-role_2".into(),
                            name: Some("-role_name_2".into()),
                            domain_id: None,
                        },
                    ],
                    unrestricted: false,
                    user_id: "bar".into(),
                }))
            });
        ac_mock
            .expect_get_application_credential()
            .withf(|_, id: &'_ str| id == "missing")
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder()
            .mock_application_credential(ac_mock)
            .mock_assignment(assignment_mock);

        let state = get_mocked_state(None, Some(provider)).await;

        let mut token = Token::ApplicationCredential(ApplicationCredentialPayload {
            user_id: "bar".into(),
            project_id: "project_id".into(),
            application_credential_id: "app_cred_id".into(),
            ..Default::default()
        });
        token_provider
            .populate_role_assignments(&state, &mut token)
            .await
            .unwrap();

        if let Token::ApplicationCredential(..) = &token {
            assert_eq!(
                token.effective_roles().unwrap(),
                &vec![RoleRef {
                    id: "role_1".into(),
                    name: Some("role_name_1".into()),
                    domain_id: None,
                }],
                "only still active role assignment is returned"
            );
        } else {
            panic!("Not application credential scope");
        }

        // Try populating role assignments for not existing appcred
        if let Err(TokenProviderError::ApplicationCredentialNotFound(id)) = token_provider
            .populate_role_assignments(
                &state,
                &mut Token::ApplicationCredential(ApplicationCredentialPayload {
                    user_id: "bar".into(),
                    project_id: "project_id".into(),
                    application_credential_id: "missing".into(),
                    ..Default::default()
                }),
            )
            .await
        {
            assert_eq!(id, "missing");
        } else {
            panic!("role expansion for missing application credential should fail");
        }

        // No roles remain after subtracting current user roles
        if let Err(TokenProviderError::ActorHasNoRolesOnTarget) = token_provider
            .populate_role_assignments(
                &state,
                &mut Token::ApplicationCredential(ApplicationCredentialPayload {
                    user_id: "bar".into(),
                    project_id: "project_id".into(),
                    application_credential_id: "app_cred_bad_roles".into(),
                    ..Default::default()
                }),
            )
            .await
        {
        } else {
            panic!(
                "role expansion for application credential with roles the user does not have anymore should fail"
            );
        }
    }
}
