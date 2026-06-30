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

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use tracing::trace;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core_types::auth::{
    AuthzInfo, AuthzInfoBuilder, ScopeInfo, SecurityContext, TrustProjectInfo,
};
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::role::{Role, RoleListParameters, RoleRef};
use openstack_keystone_core_types::token::{
    FernetToken, TokenRestriction, TokenRestrictionCreate, TokenRestrictionListParameters,
    TokenRestrictionUpdate,
};
use openstack_keystone_core_types::trust::TrustProviderError;

use crate::auth::ExecutionContext;
use crate::auth::*;
use crate::events::AuditDispatchError;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::token::{
    TokenApi, TokenProviderError,
    backend::{TokenBackend, TokenRestrictionBackend},
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

    /// Build [`AuthzInfo`] from a token by fetching scope objects
    /// from DB.
    async fn build_authz_info_from_fernet_token(
        &self,
        state: &ServiceState,
        token: &FernetToken,
    ) -> Result<AuthzInfo, TokenProviderError> {
        let ctx = ExecutionContext::internal(state);
        let scope = match token {
            FernetToken::ApplicationCredential(data) => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(&ctx, &data.project_id)
                    .await?
                    .ok_or(ResourceProviderError::ProjectNotFound(
                        data.project_id.clone(),
                    ))?;
                let project_domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(&ctx, &project.domain_id)
                    .await?
                    .ok_or(ResourceProviderError::DomainNotFound(
                        project.domain_id.clone(),
                    ))?;
                ScopeInfo::Project {
                    project,
                    project_domain,
                }
            }
            FernetToken::DomainScope(data) => ScopeInfo::Domain(
                state
                    .provider
                    .get_resource_provider()
                    .get_domain(&ctx, &data.domain_id)
                    .await?
                    .ok_or(ResourceProviderError::DomainNotFound(
                        data.domain_id.clone(),
                    ))?,
            ),
            FernetToken::ProjectScope(data) => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(&ctx, &data.project_id)
                    .await?
                    .ok_or(ResourceProviderError::ProjectNotFound(
                        data.project_id.clone(),
                    ))?;
                let project_domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(&ctx, &project.domain_id)
                    .await?
                    .ok_or(ResourceProviderError::DomainNotFound(
                        project.domain_id.clone(),
                    ))?;
                ScopeInfo::Project {
                    project,
                    project_domain,
                }
            }
            FernetToken::FederationDomainScope(data) => ScopeInfo::Domain(
                state
                    .provider
                    .get_resource_provider()
                    .get_domain(&ctx, &data.domain_id)
                    .await?
                    .ok_or(ResourceProviderError::DomainNotFound(
                        data.domain_id.clone(),
                    ))?,
            ),
            FernetToken::FederationProjectScope(data) => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(&ctx, &data.project_id)
                    .await?
                    .ok_or(ResourceProviderError::ProjectNotFound(
                        data.project_id.clone(),
                    ))?;
                let project_domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(&ctx, &project.domain_id)
                    .await?
                    .ok_or(ResourceProviderError::DomainNotFound(
                        project.domain_id.clone(),
                    ))?;
                ScopeInfo::Project {
                    project,
                    project_domain,
                }
            }
            FernetToken::SystemScope(data) => ScopeInfo::System(data.system_id.clone()),
            FernetToken::Trust(data) => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(&ctx, &data.project_id)
                    .await?
                    .ok_or(ResourceProviderError::ProjectNotFound(
                        data.project_id.clone(),
                    ))?;
                let project_domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(&ctx, &project.domain_id)
                    .await?
                    .ok_or(ResourceProviderError::DomainNotFound(
                        project.domain_id.clone(),
                    ))?;
                let trust = state
                    .provider
                    .get_trust_provider()
                    .get_trust(&ctx, &data.trust_id)
                    .await?
                    .ok_or(TrustProviderError::TrustNotFound(data.trust_id.clone()))?;
                ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                    trust,
                    project,
                    project_domain,
                }))
            }
            FernetToken::Restricted(data) => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(&ctx, &data.project_id)
                    .await?
                    .ok_or(ResourceProviderError::ProjectNotFound(
                        data.project_id.clone(),
                    ))?;
                let project_domain = state
                    .provider
                    .get_resource_provider()
                    .get_domain(&ctx, &project.domain_id)
                    .await?
                    .ok_or(ResourceProviderError::DomainNotFound(
                        project.domain_id.clone(),
                    ))?;
                ScopeInfo::Project {
                    project,
                    project_domain,
                }
            }
            FernetToken::Unscoped(_) | FernetToken::FederationUnscoped(_) => ScopeInfo::Unscoped,
        };
        Ok(AuthzInfoBuilder::default().scope(scope).build()?)
    }

    /// Validate the token and produce a [`ValidatedSecurityContext`].
    ///
    /// Decodes the fernet token, checks expiration, expands the resource data ,
    /// checks for revocation, builds a [`SecurityContext`] from the token
    /// data, validates the context, resolves effective roles, and
    /// returns the locked context.
    async fn validate_to_context_impl(
        &self,
        ctx: &ExecutionContext<'_>,
        credential: &str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<ValidatedSecurityContext, TokenProviderError> {
        let token = self.backend_driver.decode(credential)?;
        let state = ctx.state();

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

        // For special token types restore the original resource (ApplicationCredential,
        // Trust, etc) to use it for the corresponding AuthenticationContext.
        // Otherwise the AuthenticationContext remains just Token
        let auth_context = match &token {
            FernetToken::ApplicationCredential(data) => {
                AuthenticationContext::ApplicationCredential {
                    application_credential: state
                        .provider
                        .get_application_credential_provider()
                        .get_application_credential(ctx, &data.application_credential_id)
                        .await?
                        .ok_or_else(|| {
                            ApplicationCredentialProviderError::ApplicationCredentialNotFound(
                                data.application_credential_id.clone(),
                            )
                        })?,
                    token: Some(token.clone()),
                }
            }
            FernetToken::Trust(data) => AuthenticationContext::Trust {
                trust: state
                    .provider
                    .get_trust_provider()
                    .get_trust(ctx, &data.trust_id)
                    .await?
                    .ok_or_else(|| TrustProviderError::TrustNotFound(data.trust_id.clone()))?,
                token: Some(token.clone()),
            },
            // No other payload types require to substitute the AuthenticationContext
            _ => AuthenticationContext::Token(token.clone()),
        };
        let user = state
            .provider
            .get_identity_provider()
            .get_user(ctx, token.user_id())
            .await?
            .ok_or(TokenProviderError::UserNotFound(token.user_id().clone()))?;
        let user_domain = state
            .provider
            .get_resource_provider()
            .get_domain(ctx, &user.domain_id)
            .await?
            .ok_or(ResourceProviderError::DomainNotFound(
                user.domain_id.clone(),
            ))?;
        let mut auth_result_builder = AuthenticationResultBuilder::default();

        auth_result_builder
            .context(auth_context)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id(token.user_id())
                        .user(user.clone())
                        .user_domain(user_domain)
                        .build()?,
                ),
            })
            .expires_at(*token.expires_at())
            .authorization(
                // populate scope info
                self.build_authz_info_from_fernet_token(state, &token)
                    .await?,
            );
        if let FernetToken::Restricted(restriction) = &token {
            if !restriction.allow_renew {
                return Err(AuthenticationError::TokenRenewalForbidden.into());
            }
            let token_restriction = &state
                .provider
                .get_token_provider()
                .get_token_restriction(ctx, &restriction.token_restriction_id, false)
                .await?
                .ok_or(TokenProviderError::TokenRestrictionNotFound(
                    restriction.token_restriction_id.clone(),
                ))?;
            auth_result_builder.token_restriction(token_restriction.to_owned());
        }

        let auth_result = auth_result_builder.build()?;

        let mut sc = SecurityContext::try_from(auth_result)?;
        sc.set_token(token.clone());
        let scope = sc
            .authorization()
            .ok_or(TokenProviderError::ScopeMissing)?
            .scope
            .clone();
        let vsc = ValidatedSecurityContext::new_for_scope(sc, scope, state).await?;

        if state
            .provider
            .get_revoke_provider()
            .is_token_revoked(ctx, &vsc)
            .await?
        {
            return Err(TokenProviderError::TokenRevoked);
        }

        Ok(vsc)
    }
}

#[async_trait]
impl TokenApi for TokenService {
    /// Authenticate by token.
    ///
    /// Token based authentication in reality is an authorization since the
    /// token represent an authentication and authorization and the token
    /// revocation can be only verified once the all necessary information
    /// about scope and roles on the scope is frozen.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `credential`: The token credential string.
    /// - `allow_expired`: Whether to allow expired tokens.
    /// - `window_seconds`: Expiration buffer in seconds.
    ///
    /// # Returns
    /// - `Result<ValidatedSecurityContext, TokenProviderError>` - Authenticated
    ///   information or an error.
    async fn authorize_by_token<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<ValidatedSecurityContext, TokenProviderError> {
        let vsc = self
            .validate_to_context_impl(ctx, credential, allow_expired, window_seconds)
            .await?;

        if let FernetToken::Restricted(restriction) = vsc.token()?
            && !restriction.allow_renew
        {
            return Err(AuthenticationError::TokenRenewalForbidden.into());
        }
        Ok(vsc)
    }

    /// Validate the token and produce a [`ValidatedSecurityContext`].
    async fn validate_to_context<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<ValidatedSecurityContext, TokenProviderError> {
        self.validate_to_context_impl(ctx, credential, allow_expired, window_seconds)
            .await
    }

    /// Issue a token and produce a [`ValidatedSecurityContext`].
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
    /// - `scope`: Scope for the token.
    /// - `token_restrictions`: Optional restrictions for the token.
    ///
    /// # Returns
    /// - `Result<ValidatedSecurityContext, TokenProviderError>` - The validated
    ///   context with Token
    /// and expanded information or an error.
    async fn issue_token_context(
        &self,
        state: &ServiceState,
        ctx: &SecurityContext,
        scope: &ScopeInfo,
    ) -> Result<ValidatedSecurityContext, TokenProviderError> {
        let mut sc = ctx.clone();
        sc.set_authorization_scope(scope.clone())?;

        let token =
            FernetToken::from_security_context(&sc, self.get_new_token_expiry(&ctx.expires_at())?)?;
        sc.set_token(token);
        let vsc = ValidatedSecurityContext::new_for_scope(sc, scope.clone(), state).await?;
        Ok(vsc)
    }

    /// Encode the token into a `String` representation.
    ///
    /// # Parameters
    /// - `token`: The token to encode.
    ///
    /// # Returns
    /// - `Result<String, TokenProviderError>` - The encoded string or an error.
    fn encode_token(&self, token: &FernetToken) -> Result<String, TokenProviderError> {
        self.backend_driver.encode(token)
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
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        expand_roles: bool,
    ) -> Result<Option<TokenRestriction>, TokenProviderError> {
        let mut res = self
            .tr_backend_driver
            .get_token_restriction(ctx.state(), id)
            .await?;
        if let Some(ref mut tr) = res
            && expand_roles
        {
            let roles: HashMap<String, Role> = ctx
                .state()
                .provider
                .get_role_provider()
                .list_roles(ctx, &RoleListParameters::default())
                .await?
                .into_iter()
                .map(|role| (role.id.clone(), role))
                .collect();

            let mut filtered_roles: Vec<RoleRef> = tr
                .role_ids
                .iter()
                .filter_map(|rid| roles.get(rid).map(|role| role.into()))
                .collect();
            ctx.state()
                .provider
                .get_role_provider()
                .expand_implied_roles(ctx, &mut filtered_roles)
                .await?;
            tr.roles.get_or_insert_default().extend(filtered_roles);
        }

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
        ctx: &ExecutionContext<'a>,
        restriction: TokenRestrictionCreate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        let mut restriction = restriction;
        if restriction.id.is_empty() {
            restriction.id = Uuid::new_v4().simple().to_string();
        }
        let restriction_id = restriction.id.clone();
        let result = if let Some(vsc) = ctx.ctx() {
            let tr_backend_driver = &self.tr_backend_driver;
            let restriction_clone = restriction.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::TokenRestriction { id: restriction_id },
                ),
                operation: async {
                    tr_backend_driver.create_token_restriction(ctx.state(), restriction_clone).await
                },
                on_audit_error: |_: AuditDispatchError| TokenProviderError::Driver { source: "audit dispatch failed".into() },
            }?
        } else {
            let result = self
                .tr_backend_driver
                .create_token_restriction(ctx.state(), restriction)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::TokenRestriction { id: restriction_id },
                ))
                .await;
            result
        };
        Ok(result)
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
        ctx: &ExecutionContext<'a>,
        params: &TokenRestrictionListParameters,
    ) -> Result<Vec<TokenRestriction>, TokenProviderError> {
        self.tr_backend_driver
            .list_token_restrictions(ctx.state(), params)
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
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        restriction: TokenRestrictionUpdate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        let updated = if let Some(vsc) = ctx.ctx() {
            let tr_backend_driver = &self.tr_backend_driver;
            let restriction_clone = restriction.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::TokenRestriction { id: id.to_string() },
                ),
                operation: async {
                    tr_backend_driver.update_token_restriction(ctx.state(), id, restriction_clone).await
                },
                on_audit_error: |_: AuditDispatchError| TokenProviderError::Driver { source: "audit dispatch failed".into() },
            }?
        } else {
            let updated = self
                .tr_backend_driver
                .update_token_restriction(ctx.state(), id, restriction)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::TokenRestriction { id: id.to_string() },
                ))
                .await;
            updated
        };
        Ok(updated)
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
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), TokenProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::TokenRestriction { id: id.to_string() },
                ),
                operation: async {
                    self.tr_backend_driver.delete_token_restriction(ctx.state(), id).await?;
                    Ok::<(), TokenProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| TokenProviderError::Driver { source: "audit dispatch failed".into() },
            }?;
        } else {
            self.tr_backend_driver
                .delete_token_restriction(ctx.state(), id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::TokenRestriction { id: id.to_string() },
                ))
                .await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use eyre::{Result, eyre};
    use std::sync::Arc;
    use uuid::Uuid;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::*;
    use openstack_keystone_core_types::token::ProjectScopePayload;

    use super::super::tests::setup_config;
    use super::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::revoke::MockRevokeProvider;
    use crate::tests::get_mocked_state;
    use crate::token::backend::{MockTokenBackend, MockTokenRestrictionBackend};

    /// Generate test token to use for validation testing.
    fn generate_token(validity: Option<TimeDelta>) -> Result<FernetToken> {
        Ok(FernetToken::ProjectScope(ProjectScopePayload {
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
            //.withf(move |_, t: &FernetToken| {
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
        resource_mock
            .expect_get_domain_enabled()
            .returning(|_, _| Ok(true));
        resource_mock.expect_get_domain().returning(|_, id| {
            Ok(Some(Domain {
                id: id.to_string(),
                name: "domain".to_string(),
                enabled: true,
                ..Default::default()
            }))
        });
        let token_clone2 = token.clone();
        resource_mock
            .expect_get_project()
            .withf(move |_, id: &'_ str| id == token_clone2.project_id().unwrap())
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    name: "project".to_string(),
                    enabled: true,
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
        let ctx = ExecutionContext::internal(&state);
        match token_provider
            .validate_to_context(&ctx, &credential, Some(false), None)
            .await
        {
            Err(TokenProviderError::TokenRevoked) => {}
            other => {
                panic!("token must be revoked: {:?}", other)
            }
        }
    }
}
