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

use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::keystone::ServiceState;
use crate::token::TokenProviderError;

use super::*;

/// Token Provider interface.
#[async_trait]
pub trait TokenApi: Send + Sync + Clone {
    /// Authenticate using the existing token.
    async fn authenticate_by_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<AuthenticatedInfo, TokenProviderError>;

    /// Validate the token.
    ///
    /// # Arguments
    ///
    /// * `state` - An application state.
    /// * `credential` - A token as a string.
    /// * `allow_expired` - Indicates whether for the expired token the an error
    ///   should be raised
    /// or not.
    /// * `window_seconds` - An additional token expiration buffer that is added
    ///   to the
    /// `token.expires_at() during the expiration calculation.
    /// * `expand` - Indicates whether the token information should be expanded
    ///   or not. Defaults to
    /// true.
    async fn validate_token<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
        expand: Option<bool>,
    ) -> Result<Token, TokenProviderError>;

    /// Issue a token for given parameters.
    ///
    /// # Arguments
    ///
    /// * `authentication_info` - Authentication information for the token.
    /// * `authz_info` - Authorization information (scope) for the token.
    fn issue_token(
        &self,
        authentication_info: AuthenticatedInfo,
        authz_info: AuthzInfo,
        token_restriction: Option<&TokenRestriction>,
    ) -> Result<Token, TokenProviderError>;

    /// Encode the token into the X-SubjectToken String
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError>;

    /// Populate role assignments in the token that support that information
    async fn populate_role_assignments(
        &self,
        state: &ServiceState,
        token: &mut Token,
    ) -> Result<(), TokenProviderError>;

    /// Populate additional information (project, domain, roles, etc) in the
    /// token that support that information
    async fn expand_token_information(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<Token, TokenProviderError>;

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
