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
//! # OpenStack Keystone Raft driver for the SPIFFE workload identity mapping
use std::collections::BTreeSet;

use async_trait::async_trait;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::spiffe::backend::SpiffeBackend;
use openstack_keystone_core::spiffe::error::SpiffeProviderError;
use openstack_keystone_core_types::spiffe::*;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreDataEnvelope, store_command::Mutation,
};

/// Raft Database SPIFFE identity backend.
#[derive(Default)]
pub struct RaftBackend {}

impl RaftBackend {
    /// Get the storage key for binding - direct entry.
    ///
    /// # Parameters
    /// - `svid`: The auth instance ID.
    ///
    /// # Returns
    /// The storage key.
    fn get_binding_id_key_name<I: AsRef<str>>(&self, svid: I) -> String {
        format!("spiffe:binding:svid:{}", svid.as_ref())
    }

    /// Get the storage key for binding - domain based index.
    ///
    /// # Parameters
    /// - `svid`: The identity binding.
    /// - `domain_id`: The domain ID.
    ///
    /// # Returns
    /// The storage key.
    fn get_binding_domain_id_idx_key_name<I: AsRef<str>, D: AsRef<str>>(
        &self,
        svid: I,
        domain_id: D,
    ) -> String {
        format!(
            "spiffe:binding:domain:{}:{}",
            domain_id.as_ref(),
            svid.as_ref()
        )
    }

    /// Get the prefix key for listing all bindings.
    ///
    /// # Returns
    /// The prefix key.
    fn get_binding_prefix(&self) -> String {
        format!("spiffe:binding:svid:")
    }

    /// Get the prefix for listing bindings by the domain_id.
    ///
    /// # Parameters
    /// - `domain_id`: The domain ID.
    ///
    /// # Returns
    /// The prefix key.
    fn get_binding_by_domain_id_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("spiffe:binding:domain:{}:", domain_id.as_ref(),)
    }
}

#[async_trait]
impl SpiffeBackend for RaftBackend {
    /// Register new binding.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `binding` - [`SpiffeBindingCreate`] data for the new binding.
    ///
    /// # Returns
    /// * Error if the instance could not be created.
    async fn create_binding(
        &self,
        state: &ServiceState,
        binding: SpiffeBindingCreate,
    ) -> Result<SpiffeBinding, SpiffeProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(SpiffeProviderError::RaftNotAvailable)?;
        let obj = SpiffeBinding::from(binding);
        let mutations = vec![
            Mutation::set(
                self.get_binding_id_key_name(&obj.svid),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(SpiffeProviderError::raft)?,
            Mutation::set_index(self.get_binding_domain_id_idx_key_name(&obj.svid, &obj.domain_id))
                .map_err(SpiffeProviderError::raft)?,
        ];
        raft.transaction(mutations)
            .await
            .map_err(SpiffeProviderError::raft)?;
        Ok(obj)
    }

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
    ) -> Result<(), SpiffeProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(SpiffeProviderError::RaftNotAvailable)?;
        // Find the current object to be able to cleanup indexes as well
        let curr: Option<SpiffeBinding> = raft
            .get_by_key(self.get_binding_id_key_name(svid), None::<&str>)
            .await
            .map_err(SpiffeProviderError::raft)?
            .map(|x| x.data);
        if let Some(obj) = curr {
            let mutations = vec![
                Mutation::remove(self.get_binding_id_key_name(&svid), None::<&str>)
                    .map_err(SpiffeProviderError::raft)?,
                Mutation::remove_index(
                    self.get_binding_domain_id_idx_key_name(&svid, &obj.domain_id),
                )
                .map_err(SpiffeProviderError::raft)?,
            ];
            raft.transaction(mutations)
                .await
                .map_err(SpiffeProviderError::raft)?;
        }
        Ok(())
    }

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
    ) -> Result<Option<SpiffeBinding>, SpiffeProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(SpiffeProviderError::RaftNotAvailable)?;
        Ok(raft
            .get_by_key(self.get_binding_id_key_name(svid), None::<&str>)
            .await
            .map_err(SpiffeProviderError::raft)?
            .map(|x| x.data))
    }

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
    ) -> Result<Vec<SpiffeBinding>, SpiffeProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(SpiffeProviderError::RaftNotAvailable)?;
        let mut res: Vec<SpiffeBinding> = Vec::new();
        let mut post_filters: Vec<SpiffeBindingFilter> = Vec::new();
        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();
        if let Some(did) = &params.domain_id {
            post_filters.push(SpiffeBindingFilter::Domain(did.clone()));
            // pre-calculate the ID candidates by the DOMAIN_ID filter
            let prefix = self.get_binding_by_domain_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                raft.prefix_index(self.get_binding_by_domain_id_prefix(did))
                    .await
                    .map_err(SpiffeProviderError::raft)?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }

        if !pre_filter_ids.is_empty() {
            for id in pre_filter_ids {
                if let Some(candidate) = raft
                    .get_by_key::<SpiffeBinding, String, &str>(
                        self.get_binding_id_key_name(id),
                        None::<&str>,
                    )
                    .await
                    .map_err(SpiffeProviderError::raft)?
                    .map(|x| x.data)
                {
                    if post_filters.iter().all(|f| f.matches(&candidate)) {
                        res.push(candidate);
                    }
                }
            }
        } else {
            for candidate in raft
                .prefix::<SpiffeBinding, String, &str>(self.get_binding_prefix(), None::<&str>)
                .await
                .map_err(SpiffeProviderError::raft)?
                .into_iter()
                .map(|(_, v)| v.data)
            {
                if post_filters.iter().all(|f| f.matches(&candidate)) {
                    res.push(candidate);
                }
            }
        }
        Ok(res)
    }

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
    ) -> Result<SpiffeBinding, SpiffeProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(SpiffeProviderError::RaftNotAvailable)?;
        let curr: StoreDataEnvelope<SpiffeBinding> = raft
            .get_by_key(self.get_binding_id_key_name(svid), None::<&str>)
            .await
            .map_err(SpiffeProviderError::raft)?
            .ok_or(SpiffeProviderError::BindingNotFound(svid.to_string()))?;
        let new = curr.data.with_update(data);
        let new_meta = curr.metadata.new_revision();
        raft.set_value(
            self.get_binding_id_key_name(svid),
            StoreDataEnvelope {
                data: new.clone(),
                metadata: new_meta,
            },
            None::<&str>,
            Some(curr.metadata.revision),
        )
        .await
        .map_err(SpiffeProviderError::raft)?;
        Ok(new)
    }
}
