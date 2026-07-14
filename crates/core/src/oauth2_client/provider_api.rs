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
//! # OAuth2 client (relying party registration) provider API.

use async_trait::async_trait;

use openstack_keystone_core_types::oauth2_client::*;

use crate::auth::ExecutionContext;
use crate::oauth2_client::Oauth2ClientProviderError;

/// The trait for managing OAuth2 client (relying party) registrations (ADR
/// 0026 §5).
#[async_trait]
pub trait Oauth2ClientApi: Send + Sync {
    /// Register a new OAuth2 client. Generates `client_id`, and -- for
    /// confidential clients -- a fresh plaintext secret, returning it
    /// alongside the created resource (shown to the caller exactly once).
    ///
    /// # Returns
    /// * Success with the created [`OAuth2ClientResource`] and, for
    ///   confidential clients, the one-time plaintext secret.
    /// * Error if validation fails or the client could not be created.
    async fn create<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: OAuth2ClientResourceCreate,
        confidential: bool,
    ) -> Result<(OAuth2ClientResource, Option<String>), Oauth2ClientProviderError>;

    /// Soft-delete a client (disables and stamps the tombstone).
    async fn delete<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError>;

    /// Fetch a client by its `(domain_id, provider_id)` coordinate.
    async fn get<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError>;

    /// Fetch a client by its globally unique `client_id`.
    async fn get_by_client_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        client_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError>;

    /// List OAuth2 clients for a domain.
    async fn list<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError>;

    /// Generate and persist a fresh client secret, returning the updated
    /// resource alongside the one-time plaintext secret.
    async fn rotate_secret<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<(OAuth2ClientResource, String), Oauth2ClientProviderError>;

    /// Update an OAuth2 client's configuration.
    async fn update<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError>;
}
