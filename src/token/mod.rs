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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Local, TimeDelta};
use uuid::Uuid;

pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
mod token_restriction;
pub mod types;

use crate::assignment::{
    AssignmentApi,
    error::AssignmentProviderError,
    types::{Role, RoleAssignmentListParametersBuilder},
};
use crate::auth::{AuthenticatedInfo, AuthenticationError, AuthzInfo};
use crate::config::{Config, TokenProviderDriver};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::resource::{
    ResourceApi,
    types::{Domain, Project},
};
use crate::revoke::RevokeApi;
use backend::{TokenBackend, fernet::FernetTokenProvider};
pub use error::TokenProviderError;

pub use crate::token::types::*;
#[cfg(test)]
pub use mock::MockTokenProvider;

#[derive(Clone, Debug)]
pub struct TokenProvider {
    config: Config,
    backend_driver: Box<dyn TokenBackend>,
}

impl TokenProvider {
    pub fn new(config: &Config) -> Result<Self, TokenProviderError> {
        let backend_driver = match config.token.provider {
            TokenProviderDriver::Fernet => FernetTokenProvider::new(config.clone()),
        };
        Ok(Self {
            config: config.clone(),
            backend_driver: Box::new(backend_driver),
        })
    }

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
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
                .build()?,
        ))
    }

    fn create_project_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        project: &Project,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::ProjectScope(
            ProjectScopePayloadBuilder::default()
                .user_id(authentication_info.user_id.clone())
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
                .project_id(project.id.clone())
                .project(project.clone())
                .build()?,
        ))
    }

    fn create_domain_scope_token(
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
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
                .domain_id(domain.id.clone())
                .domain(domain.clone())
                .build()?,
        ))
    }

    fn create_federated_unscoped_token(
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
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
                    .idp_id(idp_id)
                    .protocol_id(protocol_id)
                    .group_ids(vec![])
                    .build()?,
            ))
        } else {
            Err(TokenProviderError::FederatedPayloadMissingData)
        }
    }

    fn create_federated_project_scope_token(
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
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
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

    fn create_federated_domain_scope_token(
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
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
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
    fn create_restricted_token(
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
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
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

    /// Expand user information in the token.
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
            }
        }
        Ok(())
    }

    /// Expand the target scope information in the token.
    async fn expand_scope_information(
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

            _ => {}
        };
        Ok(())
    }

    /// Populate role assignments in the token that support that information.
    async fn _populate_role_assignments(
        &self,
        state: &ServiceState,
        token: &mut Token,
    ) -> Result<(), TokenProviderError> {
        match token {
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
            Token::ApplicationCredential(data) => {
                data.roles = state
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
                    .collect();
                if data.roles.is_empty() {
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
            _ => {}
        }

        Ok(())
    }
}

#[async_trait]
impl TokenApi for TokenProvider {
    /// Authenticate by token.
    #[tracing::instrument(level = "info", skip(self, state, credential))]
    async fn authenticate_by_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<AuthenticatedInfo, TokenProviderError> {
        // TODO: is the expand really false?
        let token = self
            .validate_token(
                state,
                credential,
                allow_expired,
                window_seconds,
                Some(false),
            )
            .await?;
        if let Token::Restricted(restriction) = &token
            && !restriction.allow_renew
        {
            return Err(AuthenticationError::TokenRenewalForbidden)?;
        }
        let mut auth_info_builder = AuthenticatedInfo::builder();
        auth_info_builder.user_id(token.user_id());
        auth_info_builder.methods(token.methods().clone());
        auth_info_builder.audit_ids(token.audit_ids().clone());
        if let Token::Restricted(restriction) = &token {
            auth_info_builder.token_restriction_id(restriction.token_restriction_id.clone());
        }
        Ok(auth_info_builder
            .build()
            .map_err(AuthenticationError::from)?)
    }

    /// Validate token.
    #[tracing::instrument(level = "info", skip(self, state, credential))]
    async fn validate_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
        expand: Option<bool>,
    ) -> Result<Token, TokenProviderError> {
        let mut token = self.backend_driver.decode(credential)?;
        if Local::now().to_utc()
            > token
                .expires_at()
                .checked_add_signed(TimeDelta::seconds(window_seconds.unwrap_or(0)))
                .unwrap_or_else(|| *token.expires_at())
            && !allow_expired.unwrap_or(false)
        {
            return Err(TokenProviderError::Expired);
        }

        // Expand the token unless `expand = Some(false)`
        if expand.is_none_or(|v| v) {
            token = self.expand_token_information(state, &token).await?;
        }

        if state
            .provider
            .get_revoke_provider()
            .is_token_revoked(state, &token)
            .await?
        {
            return Err(TokenProviderError::TokenRevoked);
        }

        Ok(token)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn issue_token(
        &self,
        authentication_info: AuthenticatedInfo,
        authz_info: AuthzInfo,
        token_restrictions: Option<&TokenRestriction>,
    ) -> Result<Token, TokenProviderError> {
        // This should be executed already, but let's better repeat it as last line of
        // defence. It is also necessary to call this before to stop before we
        // start to resolve authz info.
        authentication_info.validate()?;

        // TODO: Check whether it is allowed to change the scope of the token if
        // AuthenticatedInfo already contains scope it was issued for.
        let mut authentication_info = authentication_info;
        authentication_info
            .audit_ids
            .push(URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()));
        if let Some(token_restrictions) = &token_restrictions {
            self.create_restricted_token(&authentication_info, &authz_info, token_restrictions)
        } else if authentication_info.idp_id.is_some() && authentication_info.protocol_id.is_some()
        {
            match &authz_info {
                AuthzInfo::Project(project) => {
                    self.create_federated_project_scope_token(&authentication_info, project)
                }
                AuthzInfo::Domain(domain) => {
                    self.create_federated_domain_scope_token(&authentication_info, domain)
                }
                AuthzInfo::Unscoped => self.create_federated_unscoped_token(&authentication_info),
            }
        } else {
            match &authz_info {
                AuthzInfo::Project(project) => {
                    self.create_project_scope_token(&authentication_info, project)
                }
                AuthzInfo::Domain(domain) => {
                    self.create_domain_scope_token(&authentication_info, domain)
                }
                AuthzInfo::Unscoped => self.create_unscoped_token(&authentication_info),
            }
        }
    }

    /// Encode the token into a `String` representation.
    ///
    /// Encode the [`Token`] into the `String` to be used as a http header.
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError> {
        self.backend_driver.encode(token)
    }

    /// Populate role assignments in the token that support that information.
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
    async fn get_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        expand_roles: bool,
    ) -> Result<Option<TokenRestriction>, TokenProviderError> {
        token_restriction::get(&state.db, id, expand_roles).await
    }

    /// Create new token restriction.
    async fn create_token_restriction<'a>(
        &self,
        state: &ServiceState,
        restriction: TokenRestrictionCreate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        let mut restriction = restriction;
        if restriction.id.is_empty() {
            restriction.id = Uuid::new_v4().simple().to_string();
        }
        token_restriction::create(&state.db, restriction).await
    }

    /// List token restrictions.
    async fn list_token_restrictions<'a>(
        &self,
        state: &ServiceState,
        params: &TokenRestrictionListParameters,
    ) -> Result<Vec<TokenRestriction>, TokenProviderError> {
        token_restriction::list(&state.db, params).await
    }

    /// Update existing token restriction.
    async fn update_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        restriction: TokenRestrictionUpdate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        token_restriction::update(&state.db, id, restriction).await
    }

    /// Delete token restriction by the ID.
    async fn delete_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), TokenProviderError> {
        token_restriction::delete(&state.db, id).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use eyre::{Result, eyre};
    use sea_orm::DatabaseConnection;
    use std::fs::File;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tracing_test::traced_test;
    use uuid::Uuid;

    use super::*;
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Assignment, AssignmentType, Role, RoleAssignmentListParameters},
    };
    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::UserResponse};
    use crate::keystone::Service;
    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types::Project};
    use crate::revoke::MockRevokeProvider;
    use crate::token::{DomainScopePayload, ProjectScopePayload, Token, UnscopedPayload};

    pub(super) fn setup_config() -> Config {
        let keys_dir = tempdir().unwrap();
        // write fernet key used to generate tokens in python
        let file_path = keys_dir.path().join("0");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

        let builder = config::Config::builder()
            .set_override(
                "auth.methods",
                "password,token,openid,application_credential",
            )
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let mut config: Config = Config::try_from(builder).expect("can build a valid config");
        config.fernet_tokens.key_repository = keys_dir.keep();
        config
    }

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

    #[tokio::test]
    async fn test_populate_role_assignments() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
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
                }])
            });
        let provider = Provider::mocked_builder()
            .assignment(assignment_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                crate::policy::MockPolicyFactory::new(),
            )
            .unwrap(),
        );

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
                vec![Role {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
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
                vec![Role {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
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
    #[traced_test]
    async fn test_validate_token_revoked() {
        let token = generate_token(Some(TimeDelta::hours(1))).unwrap();

        let config = setup_config();
        let token_provider = TokenProvider::new(&config).unwrap();
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
                Ok(Some(UserResponse {
                    id: id.to_string(),
                    domain_id: "user_domain_id".into(),
                    ..Default::default()
                }))
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
                }])
            });
        let provider = Provider::mocked_builder()
            .assignment(assignment_mock)
            .identity(identity_mock)
            .revoke(revoke_mock)
            .resource(resource_mock)
            .build()
            .unwrap();
        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                crate::policy::MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let credential = token_provider.encode_token(&token).unwrap();
        match token_provider
            .validate_token(&state, &credential, Some(false), None, None)
            .await
        {
            Err(TokenProviderError::TokenRevoked) => {}
            _ => {
                panic!("token must be revoked")
            }
        }
    }
}
