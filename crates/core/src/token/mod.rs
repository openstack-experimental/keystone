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

use openstack_keystone_config::Config;
use openstack_keystone_core_types::auth::{AuthenticationResult, AuthzInfo, SecurityContext};
pub use openstack_keystone_core_types::token::*;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;
mod validate;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::token::service::TokenService;
pub use error::TokenProviderError;
pub use provider_api::TokenApi;

#[cfg(any(test, feature = "mock"))]
pub use mock::MockTokenProvider;

pub enum TokenProvider {
    Service(TokenService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockTokenProvider),
}

impl TokenProvider {
    /// Creates a new `TokenProvider` instance.
    ///
    /// # Parameters
    /// - `config`: The system configuration.
    /// - `plugin_manager`: The plugin manager to resolve backends.
    ///
    /// # Returns
    /// - `Result<Self, TokenProviderError>` - The new provider instance or an
    ///   error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, TokenProviderError> {
        Ok(Self::Service(TokenService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl TokenApi for TokenProvider {
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
    #[tracing::instrument(level = "info", skip(self, state, credential))]
    async fn authenticate_by_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<AuthenticationResult, TokenProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .authenticate_by_token(state, credential, allow_expired, window_seconds)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .authenticate_by_token(state, credential, allow_expired, window_seconds)
                    .await
            }
        }
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
    #[tracing::instrument(level = "info", skip(self, state, credential))]
    async fn validate_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .validate_token(state, credential, allow_expired, window_seconds)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .validate_token(state, credential, allow_expired, window_seconds)
                    .await
            }
        }
    }

    /// Issue the Keystone token.
    ///
    /// # Parameters
    /// - `security_context`: Information about the authenticated user.
    /// - `authz_info`: Authorization scope.
    /// - `token_restrictions`: Optional restrictions for the token.
    ///
    /// # Returns
    /// - `Result<Token, TokenProviderError>` - The issued token or an error.
    #[tracing::instrument(level = "debug", skip(self))]
    fn issue_token(
        &self,
        security_context: &SecurityContext,
        authz_info: &AuthzInfo,
    ) -> Result<Token, TokenProviderError> {
        match self {
            Self::Service(provider) => provider.issue_token(security_context, authz_info),
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.issue_token(security_context, authz_info),
        }
    }

    /// Encode the token into a `String` representation.
    ///
    /// # Parameters
    /// - `token`: The token to encode.
    ///
    /// # Returns
    /// - `Result<String, TokenProviderError>` - The encoded string or an error.
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError> {
        match self {
            Self::Service(provider) => provider.encode_token(token),
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.encode_token(token),
        }
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
        match self {
            Self::Service(provider) => provider.populate_role_assignments(state, token).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.populate_role_assignments(state, token).await,
        }
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
        match self {
            Self::Service(provider) => provider.expand_token_information(state, token).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.expand_token_information(state, token).await,
        }
    }

    /// Get the token restriction by the ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The restriction ID.
    /// - `expand_roles`: Whether to expand roles.
    ///
    /// # Returns
    /// - `Result<Option<TokenRestriction>, TokenProviderError>` - A `Result`
    ///   containing an `Option` with the token restriction if found, or an
    ///   `Error`.
    async fn get_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        expand_roles: bool,
    ) -> Result<Option<TokenRestriction>, TokenProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .get_token_restriction(state, id, expand_roles)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .get_token_restriction(state, id, expand_roles)
                    .await
            }
        }
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
        match self {
            Self::Service(provider) => provider.create_token_restriction(state, restriction).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_token_restriction(state, restriction).await,
        }
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
        match self {
            Self::Service(provider) => provider.list_token_restrictions(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_token_restrictions(state, params).await,
        }
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
        match self {
            Self::Service(provider) => {
                provider
                    .update_token_restriction(state, id, restriction)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .update_token_restriction(state, id, restriction)
                    .await
            }
        }
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
        match self {
            Self::Service(provider) => provider.delete_token_restriction(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_token_restriction(state, id).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use openstack_keystone_config::Config;

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
}
