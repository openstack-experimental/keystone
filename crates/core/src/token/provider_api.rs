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
//! Token provider types.

use async_trait::async_trait;

use openstack_keystone_core_types::token::*;

use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::keystone::ServiceState;
use crate::token::TokenProviderError;

/// Token Provider interface.
#[async_trait]
pub trait TokenApi: Send + Sync {
    /// Authenticate using the existing token.
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
    ) -> Result<AuthenticatedInfo, TokenProviderError>;

    /// Validate the token.
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
    ) -> Result<Token, TokenProviderError>;

    /// Issue a token for given parameters.
    ///
    /// # Parameters
    /// - `authentication_info`: Authentication information for the token.
    /// - `authz_info`: Authorization information (scope) for the token.
    /// - `token_restriction`: Optional restrictions for the token.
    ///
    /// # Returns
    /// - `Result<Token, TokenProviderError>` - The issued token or an error.
    fn issue_token(
        &self,
        authentication_info: AuthenticatedInfo,
        authz_info: AuthzInfo,
        token_restriction: Option<&TokenRestriction>,
    ) -> Result<Token, TokenProviderError>;

    /// Encode the token into the X-Subject-Token String.
    ///
    /// # Parameters
    /// - `token`: The token to encode.
    ///
    /// # Returns
    /// - `Result<String, TokenProviderError>` - The encoded string or an error.
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError>;

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
    ) -> Result<(), TokenProviderError>;

    /// Populate additional information (project, domain, roles, etc) in the
    /// token that support that information.
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
    ) -> Result<Token, TokenProviderError>;

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
