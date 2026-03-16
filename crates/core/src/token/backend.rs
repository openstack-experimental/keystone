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

use crate::config::Config;
use crate::token::{TokenProviderError, types::*};

use crate::keystone::ServiceState;

/// Token Provider backend interface.
#[cfg_attr(test, mockall::automock)]
pub trait TokenBackend: Send + Sync {
    /// Set config.
    fn set_config(&mut self, g: Config);

    /// Extract the token from string.
    fn decode(&self, credential: &str) -> Result<Token, TokenProviderError>;

    /// Extract the token from string.
    fn encode(&self, token: &Token) -> Result<String, TokenProviderError>;
}

/// Token restrictions backend interface.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait TokenRestrictionBackend: Send + Sync {
    /// Get the token restriction by the ID.
    async fn get_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        expand_roles: bool,
    ) -> Result<Option<TokenRestriction>, TokenProviderError>;

    /// Create new token restriction.
    async fn create_token_restriction<'a>(
        &self,
        state: &ServiceState,
        restriction: TokenRestrictionCreate,
    ) -> Result<TokenRestriction, TokenProviderError>;

    /// List token restrictions.
    async fn list_token_restrictions<'a>(
        &self,
        state: &ServiceState,
        params: &TokenRestrictionListParameters,
    ) -> Result<Vec<TokenRestriction>, TokenProviderError>;

    /// Update token restriction by the ID.
    async fn update_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        restriction: TokenRestrictionUpdate,
    ) -> Result<TokenRestriction, TokenProviderError>;

    /// Delete token restriction by the ID.
    async fn delete_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), TokenProviderError>;
}
