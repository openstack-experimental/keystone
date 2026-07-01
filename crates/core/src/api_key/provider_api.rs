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
//! # API Key (SCIM ingress) provider API.

use async_trait::async_trait;

use openstack_keystone_core_types::api_key::*;

use crate::api_key::ApiKeyProviderError;
use crate::keystone::ServiceState;

/// The trait for managing API Key (SCIM ingress) machine identities (ADR
/// 0021).
#[async_trait]
pub trait ApiKeyApi: Send + Sync {
    /// Create a new API Key.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `data` - [`ApiClientResourceCreate`] data for the new key.
    ///
    /// # Returns
    /// * Success with the created [`ApiClientResource`].
    /// * Error if the key could not be created.
    async fn create(
        &self,
        state: &ServiceState,
        data: ApiClientResourceCreate,
    ) -> Result<ApiClientResource, ApiKeyProviderError>;

    /// Fetch an API Key by its public `client_id`.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain the key belongs to.
    /// * `client_id` - The public UUID of the key.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`ApiClientResource`] if
    /// found, or an `Error`.
    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError>;

    /// Fetch an API Key by its `lookup_hash` (the SCIM ingress hot path,
    /// ADR 0021 §3 Step 2).
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain the key belongs to.
    /// * `lookup_hash` - `SHA-256(entropy)` of the presented token.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`ApiClientResource`] if
    /// found, or an `Error`.
    async fn get_by_lookup_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError>;

    /// List API Keys.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`ApiClientResourceListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`ApiClientResource`].
    /// * Error if the listing failed.
    async fn list(
        &self,
        state: &ServiceState,
        params: &ApiClientResourceListParameters,
    ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError>;

    /// Update an API Key's configuration.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain the key belongs to.
    /// * `client_id` - The public UUID of the key to update.
    /// * `data` - [`ApiClientResourceUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`ApiClientResource`].
    /// * Error if the update failed.
    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        data: ApiClientResourceUpdate,
    ) -> Result<ApiClientResource, ApiKeyProviderError>;

    /// Emergency revocation path (ADR 0021 §5.C): disables the key and
    /// stamps the tombstone without deleting the record.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain the key belongs to.
    /// * `client_id` - The public UUID of the key to revoke.
    /// * `revoked_by` - User ID of the revoking operator.
    ///
    /// # Returns
    /// * Success with the revoked [`ApiClientResource`].
    /// * Error if the revocation failed.
    async fn revoke<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        revoked_by: &'a str,
    ) -> Result<ApiClientResource, ApiKeyProviderError>;

    /// Update the `last_used_at` timestamp for a key (ADR 0021 §3 Step 3).
    /// Callers on the authentication hot path are expected to invoke this
    /// asynchronously (fire-and-forget) rather than await it inline.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain the key belongs to.
    /// * `lookup_hash` - `SHA-256(entropy)` of the presented token.
    /// * `last_used_at` - UTC epoch seconds of the authentication event.
    async fn update_last_used<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        last_used_at: i64,
    ) -> Result<(), ApiKeyProviderError>;

    /// Replace the stored `secret_hash` for a key (ADR 0021 §6.B Invariant
    /// 8, lazy re-hash). Internal maintenance operation, not part of the
    /// public admin update surface — callers on the authentication hot path
    /// are expected to invoke this asynchronously (fire-and-forget).
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain the key belongs to.
    /// * `lookup_hash` - `SHA-256(entropy)` of the presented token.
    /// * `secret_hash` - The freshly computed PHC-formatted Argon2id hash.
    async fn update_secret_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        secret_hash: String,
    ) -> Result<(), ApiKeyProviderError>;
}
