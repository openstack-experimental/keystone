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
//! # Spiffe provider API.

use async_trait::async_trait;

use openstack_keystone_core_types::spiffe::*;

use crate::keystone::ServiceState;
use crate::spiffe::SpiffeProviderError;

/// The trait for managing the SPIFFE functionality.
#[async_trait]
pub trait SpiffeApi: Send + Sync {
    /// Register new binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `binding` - [`SpiffeBindingCreate`] data for the new binding.
    ///
    /// # Returns
    /// * Success with the created [`SpiffeBinding`].
    /// * Error if the instance could not be created.
    async fn create_binding(
        &self,
        state: &ServiceState,
        binding: SpiffeBindingCreate,
    ) -> Result<SpiffeBinding, SpiffeProviderError>;

    /// Delete SPIFFE binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID of a binding to delete.
    ///
    /// # Returns
    /// * Success if the binding was deleted.
    /// * Error if the deletion failed.
    async fn delete_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
    ) -> Result<(), SpiffeProviderError>;

    /// Fetch binding for the SVID.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID identifier to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`SpiffeBinding`] if found,
    /// or an `Error`.
    async fn get_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
    ) -> Result<Option<SpiffeBinding>, SpiffeProviderError>;

    /// List SpiffeBindings.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`SpiffeBindingListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`SpiffeBinding`].
    /// * Error if the listing failed.
    async fn list_bindings(
        &self,
        state: &ServiceState,
        params: &SpiffeBindingListParameters,
    ) -> Result<Vec<SpiffeBinding>, SpiffeProviderError>;

    /// Update binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `svid` - The SVID for the binding to update.
    /// * `data` - [`SpiffeBindingUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`SpiffeBinding`].
    /// * Error if the update failed.
    async fn update_binding<'a>(
        &self,
        state: &ServiceState,
        svid: &'a str,
        data: SpiffeBindingUpdate,
    ) -> Result<SpiffeBinding, SpiffeProviderError>;
}
