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

use crate::auth::{ExecutionContext, ScopeInfo, SecurityContext, ValidatedSecurityContext};
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
    /// - `Result<ValidatedSecurityContext, TokenProviderError>` - Authenticated
    ///   information or an error.
    async fn authorize_by_token<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<ValidatedSecurityContext, TokenProviderError>;

    /// Validate the token and produce a [`ValidatedSecurityContext`].
    ///
    /// Decodes the fernet token, checks expiration and revocation, builds
    /// the security context from the token data, validates, resolves effective
    /// roles, and returns the locked context.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    /// - `credential`: The token credential string.
    /// - `allow_expired`: Whether to allow expired tokens.
    /// - `window_seconds`: Expiration buffer in seconds.
    ///
    /// # Returns
    /// - `Result<ValidatedSecurityContext, TokenProviderError>` - The validated
    ///   and expanded security context or an error.
    async fn validate_to_context<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<ValidatedSecurityContext, TokenProviderError>;

    /// Issue a token and produce a [`ValidatedSecurityContext`] without
    /// performing validation.
    ///
    /// Creates a token from the provided [`SecurityContext`] and scope,
    /// builds authorization info from the token scope, resolves effective
    /// roles, and returns the validated security context with the issued
    /// token embedded. Skips revocation, expiration, and subject
    /// validation since the token was just issued.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `ctx`: The security context from which the token is issued.
    /// - `scope`: Scope for the token.
    ///
    /// # Returns
    /// - `Result<ValidatedSecurityContext, TokenProviderError>` - The validated
    ///   security context with the issued token embedded or an error.
    async fn issue_token_context(
        &self,
        state: &ServiceState,
        ctx: &SecurityContext,
        scope: &ScopeInfo,
    ) -> Result<ValidatedSecurityContext, TokenProviderError>;

    /// Encode the token into the X-Subject-Token String.
    ///
    /// # Parameters
    /// - `token`: The token to encode.
    ///
    /// # Returns
    /// - `Result<String, TokenProviderError>` - The encoded string or an error.
    fn encode_token(&self, token: &FernetToken) -> Result<String, TokenProviderError>;

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
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
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
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), TokenProviderError>;
}
