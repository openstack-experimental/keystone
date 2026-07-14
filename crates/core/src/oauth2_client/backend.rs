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
//! # OAuth2 client provider: Backends.
use async_trait::async_trait;

use openstack_keystone_core_types::oauth2_client::*;

use crate::keystone::ServiceState;
use crate::oauth2_client::Oauth2ClientProviderError;

/// OAuth2 client Backend trait.
///
/// Backend driver interface expected by the OAuth2 client provider (ADR 0026
/// §5).
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Oauth2ClientBackend: Send + Sync {
    /// Register a new OAuth2 client.
    async fn create(
        &self,
        state: &ServiceState,
        data: OAuth2ClientResourceCreate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError>;

    /// Soft-delete: disables the client and stamps the tombstone without
    /// deleting the record.
    async fn delete<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError>;

    /// Fetch a client by its `(domain_id, provider_id)` coordinate.
    async fn get<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError>;

    /// Fetch a client by its globally unique `client_id`.
    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        client_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError>;

    /// List OAuth2 clients for a domain.
    async fn list(
        &self,
        state: &ServiceState,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError>;

    /// Replace the stored `client_secret_hash` for a client.
    async fn rotate_secret<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        client_secret_hash: String,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError>;

    /// Update an OAuth2 client's configuration.
    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        provider_id: &'a str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError>;
}
