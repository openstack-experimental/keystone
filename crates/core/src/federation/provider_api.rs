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
//! # Federation provider
//!
//! Federation provider implements the functionality necessary for the user
//! federation.
use async_trait::async_trait;

use openstack_keystone_core_types::federation::*;

use crate::auth::ExecutionContext;
use crate::federation::error::FederationProviderError;

/// Federation provider interface.
#[async_trait]
pub trait FederationApi: Send + Sync {
    /// Cleanup expired resources
    ///
    /// # Parameters
    /// - `state`: The service state.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or a
    ///   federation provider error.
    async fn cleanup<'a>(&self, ctx: &ExecutionContext<'a>) -> Result<(), FederationProviderError>;

    /// Create identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `idp`: The identity provider details to create.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The created
    ///   `IdentityProvider` or an error.
    async fn create_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError>;

    /// Create authentication state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `state`: The authentication state to create.
    ///
    /// # Returns
    /// - `Result<AuthState, FederationProviderError>` - The created `AuthState`
    ///   or an error.
    async fn create_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        state: AuthState,
    ) -> Result<AuthState, FederationProviderError>;

    /// Delete authentication state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the authentication state to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    /// Delete identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    /// Get authentication state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the authentication state to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<AuthState>, FederationProviderError>` - A `Result`
    ///   containing an `Option` with the AuthState if found, or an `Error`.
    async fn get_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError>;

    /// Get identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<IdentityProvider>, FederationProviderError>` - A
    ///   `Result` containing an `Option` with the IdentityProvider if found, or
    ///   an `Error`.
    async fn get_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError>;

    /// List identity providers.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters for identity providers.
    ///
    /// # Returns
    /// - `Result<Vec<IdentityProvider>, FederationProviderError>` - A list of
    ///   identity providers or an error.
    async fn list_identity_providers<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

    /// Update identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to update.
    /// - `idp`: The update details for the identity provider.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The updated
    ///   `IdentityProvider` or an error.
    async fn update_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError>;
}
