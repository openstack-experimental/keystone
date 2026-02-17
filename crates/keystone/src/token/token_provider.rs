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

use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;

use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::config::{Config, TokenProviderDriver};
use crate::keystone::ServiceState;
use crate::token::{
    FernetTokenProvider, TokenProvider, TokenProviderError, types::*,
};
use crate::{
    application_credential::ApplicationCredentialApi,
    assignment::{
        AssignmentApi,
        error::AssignmentProviderError,
        types::{Role, RoleAssignmentListParameters, RoleAssignmentListParametersBuilder},
    },
    identity::IdentityApi,
    resource::{
        ResourceApi,
        types::{Domain, Project},
    },
    trust::{TrustApi, types::Trust},
};

//pub struct TokenProvider {
//    config: Config,
//    backend_driver: Arc<dyn TokenBackend>,
//}

impl TokenProvider {
    pub fn new(config: &Config) -> Result<Self, TokenProviderError> {
        let backend_driver = match config.token.provider {
            TokenProviderDriver::Fernet => FernetTokenProvider::new(config.clone()),
        };
        Ok(Self {
            config: config.clone(),
            backend_driver: Arc::new(backend_driver),
        })
    }

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

    /// Create unscoped token.
    fn create_unscoped_token(
        &self,
        authentication_info: &AuthenticatedInfo,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::Unscoped(
            UnscopedPayloadBuilder::default()
                .user_id(authentication_info.user_id.clone())
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                .build()?,
        ))
    }

    /// Create project scoped token.
    pub fn create_project_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        project: &Project,
    ) -> Result<Token, TokenProviderError> {
        let token_expiry = self.get_new_token_expiry(&authentication_info.expires_at)?;
        if let Some(application_credential) = &authentication_info.application_credential {
            // Token for the application credential authentication
            Ok(Token::ApplicationCredential(
                ApplicationCredentialPayloadBuilder::default()
                    .application_credential_id(application_credential.id.clone())
                    .application_credential(application_credential.clone())
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(
                        application_credential
                            .expires_at
                            .map(|ac_expiry| std::cmp::min(token_expiry, ac_expiry))
                            .unwrap_or(token_expiry),
                    )
                    .project_id(project.id.clone())
                    .project(project.clone())
                    .build()?,
            ))
        } else {
            // General project scoped token
            Ok(Token::ProjectScope(
                ProjectScopePayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(token_expiry)
                    .project_id(project.id.clone())
                    .project(project.clone())
                    .build()?,
            ))
        }
    }

    /// Create domain scoped token.
    pub fn create_domain_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        domain: &Domain,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::DomainScope(
            DomainScopePayloadBuilder::default()
                .user_id(authentication_info.user_id.clone())
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                .domain_id(domain.id.clone())
                .domain(domain.clone())
                .build()?,
        ))
    }

    /// Create unscoped token with the identity provider bind.
    pub fn create_federated_unscoped_token(
        &self,
        authentication_info: &AuthenticatedInfo,
    ) -> Result<Token, TokenProviderError> {
        if let (Some(idp_id), Some(protocol_id)) = (
            authentication_info.idp_id.clone(),
            authentication_info.protocol_id.clone(),
        ) {
            Ok(Token::FederationUnscoped(
                FederationUnscopedPayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                    .idp_id(idp_id)
                    .protocol_id(protocol_id)
                    .group_ids(vec![])
                    .build()?,
            ))
        } else {
            Err(TokenProviderError::FederatedPayloadMissingData)
        }
    }

    /// Create project scoped token with the identity provider bind.
    pub fn create_federated_project_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        project: &Project,
    ) -> Result<Token, TokenProviderError> {
        if let (Some(idp_id), Some(protocol_id)) = (
            authentication_info.idp_id.clone(),
            authentication_info.protocol_id.clone(),
        ) {
            Ok(Token::FederationProjectScope(
                FederationProjectScopePayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                    .idp_id(idp_id)
                    .protocol_id(protocol_id)
                    .group_ids(
                        authentication_info
                            .user_groups
                            .clone()
                            .iter()
                            .map(|grp| grp.id.clone())
                            .collect::<Vec<_>>(),
                    )
                    .project_id(project.id.clone())
                    .project(project.clone())
                    .build()?,
            ))
        } else {
            Err(TokenProviderError::FederatedPayloadMissingData)
        }
    }

    /// Create domain scoped token with the identity provider bind.
    pub fn create_federated_domain_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        domain: &Domain,
    ) -> Result<Token, TokenProviderError> {
        if let (Some(idp_id), Some(protocol_id)) = (
            authentication_info.idp_id.clone(),
            authentication_info.protocol_id.clone(),
        ) {
            Ok(Token::FederationDomainScope(
                FederationDomainScopePayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                    .idp_id(idp_id)
                    .protocol_id(protocol_id)
                    .group_ids(
                        authentication_info
                            .user_groups
                            .clone()
                            .iter()
                            .map(|grp| grp.id.clone())
                            .collect::<Vec<_>>(),
                    )
                    .domain_id(domain.id.clone())
                    .domain(domain.clone())
                    .build()?,
            ))
        } else {
            Err(TokenProviderError::FederatedPayloadMissingData)
        }
    }

    /// Create token with the specified restrictions.
    pub fn create_restricted_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        authz_info: &AuthzInfo,
        restriction: &TokenRestriction,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::Restricted(
            RestrictedPayloadBuilder::default()
                .user_id(
                    restriction
                        .user_id
                        .as_ref()
                        .unwrap_or(&authentication_info.user_id.clone()),
                )
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                .token_restriction_id(restriction.id.clone())
                .project_id(
                    restriction
                        .project_id
                        .as_ref()
                        .or(match authz_info {
                            AuthzInfo::Project(project) => Some(&project.id),
                            _ => None,
                        })
                        .ok_or_else(|| TokenProviderError::RestrictedTokenNotProjectScoped)?,
                )
                .allow_renew(restriction.allow_renew)
                .allow_rescope(restriction.allow_rescope)
                .roles(restriction.roles.clone())
                .build()?,
        ))
    }

    /// Create system scoped token.
    pub fn create_system_scoped_token(
        &self,
        authentication_info: &AuthenticatedInfo,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::SystemScope(
            SystemScopePayloadBuilder::default()
                .user_id(authentication_info.user_id.clone())
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .system_id("system")
                .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                .build()?,
        ))
    }

    /// Create token based on the trust.
    pub fn create_trust_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        trust: &Trust,
    ) -> Result<Token, TokenProviderError> {
        if let Some(project_id) = &trust.project_id {
            Ok(Token::Trust(
                TrustPayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                    .trust_id(trust.id.clone())
                    .project_id(project_id.clone())
                    .build()?,
            ))
        } else {
            // Trust without project_id is unscoped
            Ok(Token::Unscoped(
                UnscopedPayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(self.get_new_token_expiry(&authentication_info.expires_at)?)
                    .build()?,
            ))
        }
    }

    /// Expand user information in the token.
    pub async fn expand_user_information(
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
    pub async fn expand_scope_information(
        &self,
        state: &ServiceState,
        token: &mut Token,
    ) -> Result<(), TokenProviderError> {
        match token {
            Token::ProjectScope(data) => {
                if data.project.is_none() {
                    let project = state
                        .provider
                        .get_resource_provider()
                        .get_project(state, &data.project_id)
                        .await?;

                    data.project = project;
                }
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
            Token::FederationProjectScope(data) => {
                if data.project.is_none() {
                    let project = state
                        .provider
                        .get_resource_provider()
                        .get_project(state, &data.project_id)
                        .await?;

                    data.project = project;
                }
            }
            Token::DomainScope(data) => {
                if data.domain.is_none() {
                    let domain = state
                        .provider
                        .get_resource_provider()
                        .get_domain(state, &data.domain_id)
                        .await?;

                    data.domain = domain;
                }
            }
            Token::FederationDomainScope(data) => {
                if data.domain.is_none() {
                    let domain = state
                        .provider
                        .get_resource_provider()
                        .get_domain(state, &data.domain_id)
                        .await?;

                    data.domain = domain;
                }
            }
            Token::Restricted(data) => {
                if data.project.is_none() {
                    let project = state
                        .provider
                        .get_resource_provider()
                        .get_project(state, &data.project_id)
                        .await?;

                    data.project = project;
                }
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
    pub async fn _populate_role_assignments(
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
                    // Filter out roles referred in the AC that the user does not have anymore.
                    ac.roles.retain(|role| user_role_ids.contains(&role.id));
                    if ac.roles.is_empty() {
                        return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                    }
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
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
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
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
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
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
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
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::Restricted(data) => {
                if data.roles.is_none() {
                    self.get_token_restriction(state, &data.token_restriction_id, true)
                        .await?
                        .inspect(|restrictions| data.roles = restrictions.roles.clone())
                        .ok_or(TokenProviderError::TokenRestrictionNotFound(
                            data.token_restriction_id.clone(),
                        ))?;
                }
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
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
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
                            .get_assignment_provider()
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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::auth::AuthenticatedInfoBuilder;
    use crate::config::Config;
    use crate::resource::types::*;

    #[tokio::test]
    async fn test_create_unscoped_token() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
        let now = Utc::now();
        let token = token_provider
            .create_unscoped_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .expires_at(now)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(*token.expires_at(), now);
        assert_eq!(*token.user_id(), "uid");
        let token = token_provider
            .create_unscoped_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(now < *token.expires_at());
        assert_eq!(*token.user_id(), "uid");
        assert!(token.project_id().is_none());
    }

    #[tokio::test]
    async fn test_create_project_scope_token() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
        let now = Utc::now();
        let token = token_provider
            .create_project_scope_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .expires_at(now)
                    .build()
                    .unwrap(),
                &ProjectBuilder::default()
                    .id("pid")
                    .domain_id("did")
                    .name("pname")
                    .enabled(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(*token.expires_at(), now);
        assert_eq!(*token.user_id(), "uid");
        let token = token_provider
            .create_project_scope_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
                &ProjectBuilder::default()
                    .id("pid")
                    .domain_id("did")
                    .name("pname")
                    .enabled(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(now < *token.expires_at());
        assert_eq!(*token.user_id(), "uid");
        assert_eq!(*token.project_id().unwrap(), "pid");
    }

    #[tokio::test]
    async fn test_create_domain_scope_token() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
        let now = Utc::now();
        let token = token_provider
            .create_domain_scope_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .expires_at(now)
                    .build()
                    .unwrap(),
                &DomainBuilder::default()
                    .id("did")
                    .name("pname")
                    .enabled(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(*token.expires_at(), now);
        assert_eq!(*token.user_id(), "uid");
        let token = token_provider
            .create_domain_scope_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
                &DomainBuilder::default()
                    .id("did")
                    .name("pname")
                    .enabled(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(now < *token.expires_at());
        assert_eq!(*token.user_id(), "uid");
        assert_eq!(token.domain().unwrap().id, "did");
    }

    #[tokio::test]
    async fn test_create_system_token() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
        let now = Utc::now();
        let token = token_provider
            .create_system_scoped_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .expires_at(now)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(*token.expires_at(), now);
        assert_eq!(*token.user_id(), "uid");
        let token = token_provider
            .create_system_scoped_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(now < *token.expires_at());
        assert_eq!(*token.user_id(), "uid");
        if let Token::SystemScope(data) = token {
            assert_eq!(data.system_id, "system");
        } else {
            panic!("wrong token type");
        }
    }

    #[tokio::test]
    async fn test_create_trust_token() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
        let now = Utc::now();
        let token = token_provider
            .create_trust_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .expires_at(now)
                    .build()
                    .unwrap(),
                &TrustBuilder::default()
                    .id("tid")
                    .impersonation(false)
                    .trustor_user_id("trustor_uid")
                    .trustee_user_id("trustor_uid")
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(*token.expires_at(), now);
        assert_eq!(*token.user_id(), "uid");
        let token = token_provider
            .create_trust_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
                &TrustBuilder::default()
                    .id("tid")
                    .impersonation(false)
                    .trustor_user_id("trustor_uid")
                    .trustee_user_id("trustor_uid")
                    .project_id("pid")
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(now < *token.expires_at());
        assert_eq!(*token.user_id(), "uid");
        if let Token::Trust(data) = token {
            assert_eq!(data.trust_id, "tid");
        } else {
            panic!("wrong token type");
        }

        // unscoped
        let token = token_provider
            .create_trust_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
                &TrustBuilder::default()
                    .id("tid")
                    .impersonation(false)
                    .trustor_user_id("trustor_uid")
                    .trustee_user_id("trustor_uid")
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(now < *token.expires_at());
        assert_eq!(*token.user_id(), "uid");
        if let Token::Unscoped(_data) = token {
        } else {
            panic!("wrong token type");
        }
    }

    #[tokio::test]
    async fn test_create_restricted_token() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
        let now = Utc::now();
        let token = token_provider
            .create_restricted_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .expires_at(now)
                    .build()
                    .unwrap(),
                &AuthzInfo::System,
                &TokenRestrictionBuilder::default()
                    .id("rid")
                    .domain_id("did")
                    .project_id("pid")
                    .allow_renew(true)
                    .allow_rescope(true)
                    .role_ids([])
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(*token.expires_at(), now);
        assert_eq!(*token.user_id(), "uid");
        let token = token_provider
            .create_restricted_token(
                &AuthenticatedInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
                &AuthzInfo::System,
                &TokenRestrictionBuilder::default()
                    .id("rid")
                    .domain_id("did")
                    .project_id("pid")
                    .allow_renew(true)
                    .allow_rescope(true)
                    .role_ids([])
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(now < *token.expires_at());
        assert_eq!(*token.user_id(), "uid");
        if let Token::Restricted(data) = token {
            assert_eq!(data.token_restriction_id, "rid");
        } else {
            panic!("wrong token type");
        }
    }
}
