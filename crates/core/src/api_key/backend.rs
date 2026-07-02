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
//! # API Key provider: Backends.
use async_trait::async_trait;

use openstack_keystone_core_types::api_key::*;

use crate::api_key::ApiKeyProviderError;
use crate::keystone::ServiceState;

/// API Key Backend trait.
///
/// Backend driver interface expected by the API Key provider.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ApiKeyBackend: Send + Sync {
    /// Create a new API Key.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `data` - [`ApiClientResourceCreate`] data for the new key.
    ///
    /// # Returns
    /// * Success with the created [`ApiClientResource`].
    /// * Error if the instance could not be created.
    async fn create(
        &self,
        state: &ServiceState,
        data: ApiClientResourceCreate,
    ) -> Result<ApiClientResource, ApiKeyProviderError>;

    /// Fetch an API Key by its public `client_id`.
    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError>;

    /// Fetch an API Key by its `lookup_hash`.
    async fn get_by_lookup_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError>;

    /// List API Keys.
    async fn list(
        &self,
        state: &ServiceState,
        params: &ApiClientResourceListParameters,
    ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError>;

    /// Update an API Key's configuration.
    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        data: ApiClientResourceUpdate,
    ) -> Result<ApiClientResource, ApiKeyProviderError>;

    /// Emergency revocation path.
    async fn revoke<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        revoked_by: &'a str,
    ) -> Result<ApiClientResource, ApiKeyProviderError>;

    /// Update the `last_used_at` timestamp for a key.
    async fn update_last_used<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        last_used_at: i64,
    ) -> Result<(), ApiKeyProviderError>;

    /// Replace the stored `secret_hash` for a key (lazy re-hash).
    async fn update_secret_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        secret_hash: String,
    ) -> Result<(), ApiKeyProviderError>;

    /// Cross-domain listing of every `ApiClientResource`, for the janitor
    /// sweep (ADR 0021 §6.F). Not part of the public admin API -- the
    /// domain-scoped `list` above serves `GET /v4/api-keys`.
    async fn list_all(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError>;

    /// Hard-delete a tombstoned record (ADR 0021 §6.F physical
    /// reclamation). A no-op if the record is already gone.
    async fn purge<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<(), ApiKeyProviderError>;
}
