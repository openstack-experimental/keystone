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

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
pub mod service;
//mod token_restriction;
pub mod types;

use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::token::service::TokenService;
pub use error::TokenProviderError;

pub use crate::token::types::*;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockTokenProvider;

pub enum TokenProvider {
    Service(TokenService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockTokenProvider),
}

impl TokenProvider {
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
    async fn authenticate_by_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<AuthenticatedInfo, TokenProviderError> {
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
    fn issue_token(
        &self,
        authentication_info: AuthenticatedInfo,
        authz_info: AuthzInfo,
        token_restrictions: Option<&TokenRestriction>,
    ) -> Result<Token, TokenProviderError> {
        match self {
            Self::Service(provider) => {
                provider.issue_token(authentication_info, authz_info, token_restrictions)
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider.issue_token(authentication_info, authz_info, token_restrictions)
            }
        }
    }

    /// Encode the token into a `String` representation.
    ///
    /// Encode the [`Token`] into the `String` to be used as a http header.
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError> {
        match self {
            Self::Service(provider) => provider.encode_token(token),
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.encode_token(token),
        }
    }

    /// Populate role assignments in the token that support that information.
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

    use crate::config::Config;

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
