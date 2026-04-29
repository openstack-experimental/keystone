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
//! Token provider backends.

use openstack_keystone_config::Config;

use openstack_keystone_core_types::token::*;

use crate::keystone::ServiceState;
use crate::token::TokenProviderError;

/// Token Provider backend interface.
#[cfg_attr(test, mockall::automock)]
pub trait TokenBackend: Send + Sync {
    /// Set config.
    ///
    /// # Parameters
    /// - `g`: The configuration to set.
    fn set_config(&mut self, g: Config);

    /// Extract the token from string.
    ///
    /// # Parameters
    /// - `credential`: The credential string.
    ///
    /// # Returns
    /// - `Result<Token, TokenProviderError>` - The decoded token or an error.
    fn decode(&self, credential: &str) -> Result<Token, TokenProviderError>;

    /// Encode the token into a string.
    ///
    /// # Parameters
    /// - `token`: The token to encode.
    ///
    /// # Returns
    /// - `Result<String, TokenProviderError>` - The encoded string or an error.
    fn encode(&self, token: &Token) -> Result<String, TokenProviderError>;
}

/// Token restrictions backend interface.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait TokenRestrictionBackend: Send + Sync {
    /// Get the token restriction by the ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The restriction ID.
    ///
    /// # Returns
    /// - `Result<Option<TokenRestriction>, TokenProviderError>` - A `Result`
    ///   containing an `Option` with the token restriction if found, or an
    ///   `Error`.
    async fn get_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<TokenRestriction>, TokenProviderError>;

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
    ) -> Result<TokenRestriction, TokenProviderError>;

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
    ) -> Result<Vec<TokenRestriction>, TokenProviderError>;

    /// Update token restriction by the ID.
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
    ) -> Result<TokenRestriction, TokenProviderError>;

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
    ) -> Result<(), TokenProviderError>;
}
