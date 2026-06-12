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
    Metadata, StorageApi, StoreDataEnvelope, StoreError, store_command::Mutation,
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
        "spiffe:binding:svid:".to_string()
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

    #[cfg_attr(not(test), allow(dead_code))]
    async fn create_binding_impl(
        &self,
        storage: &impl StorageApi,
        binding: SpiffeBindingCreate,
    ) -> Result<SpiffeBinding, StoreError> {
        let obj = SpiffeBinding::from(binding);
        let mutations = vec![
            Mutation::set(
                self.get_binding_id_key_name(&obj.svid),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )?,
            Mutation::set_index(
                self.get_binding_domain_id_idx_key_name(&obj.svid, &obj.domain_id),
            )?,
        ];
        storage.transaction(mutations).await?;
        Ok(obj)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn delete_binding_impl(
        &self,
        storage: &impl StorageApi,
        svid: &str,
    ) -> Result<(), StoreError> {
        let curr: Option<SpiffeBinding> = storage
            .get_by_key(self.get_binding_id_key_name(svid), None::<&str>)
            .await?
            .map(|x| x.data);
        if let Some(obj) = curr {
            let mutations = vec![
                Mutation::remove(self.get_binding_id_key_name(svid), None::<&str>)?,
                Mutation::remove_index(
                    self.get_binding_domain_id_idx_key_name(svid, &obj.domain_id),
                )?,
            ];
            storage.transaction(mutations).await?;
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn get_binding_impl(
        &self,
        storage: &impl StorageApi,
        svid: &str,
    ) -> Result<Option<SpiffeBinding>, StoreError> {
        Ok(storage
            .get_by_key(self.get_binding_id_key_name(svid), None::<&str>)
            .await?
            .map(|x| x.data))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_bindings_impl(
        &self,
        storage: &impl StorageApi,
        params: &SpiffeBindingListParameters,
    ) -> Result<Vec<SpiffeBinding>, StoreError> {
        let mut res: Vec<SpiffeBinding> = Vec::new();
        let mut post_filters: Vec<SpiffeBindingFilter> = Vec::new();
        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();
        if let Some(did) = &params.domain_id {
            post_filters.push(SpiffeBindingFilter::Domain(did.clone()));
            let prefix = self.get_binding_by_domain_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                storage
                    .prefix_index(self.get_binding_by_domain_id_prefix(did))
                    .await?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }

        if !pre_filter_ids.is_empty() {
            for id in pre_filter_ids {
                if let Some(candidate) = storage
                    .get_by_key::<SpiffeBinding, String, &str>(
                        self.get_binding_id_key_name(id),
                        None::<&str>,
                    )
                    .await?
                    .map(|x| x.data)
                    && post_filters.iter().all(|f| f.matches(&candidate))
                {
                    res.push(candidate);
                }
            }
        } else {
            for candidate in storage
                .prefix::<SpiffeBinding, String, &str>(self.get_binding_prefix(), None::<&str>)
                .await?
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

    #[cfg_attr(not(test), allow(dead_code))]
    async fn update_binding_impl(
        &self,
        storage: &impl StorageApi,
        svid: &str,
        data: SpiffeBindingUpdate,
    ) -> Result<SpiffeBinding, StoreError> {
        let curr: StoreDataEnvelope<SpiffeBinding> = storage
            .get_by_key(self.get_binding_id_key_name(svid), None::<&str>)
            .await?
            .ok_or_else(|| StoreError::IO {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            })?;
        let new = curr.data.with_update(data);
        let new_meta = curr.metadata.new_revision();
        storage
            .set_value(
                self.get_binding_id_key_name(svid),
                StoreDataEnvelope {
                    data: new.clone(),
                    metadata: new_meta,
                },
                None::<&str>,
                Some(curr.metadata.revision),
            )
            .await?;
        Ok(new)
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
        self.create_binding_impl(raft, binding)
            .await
            .map_err(SpiffeProviderError::raft)
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
        self.delete_binding_impl(raft, svid)
            .await
            .map_err(SpiffeProviderError::raft)
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
        self.get_binding_impl(raft, svid)
            .await
            .map_err(SpiffeProviderError::raft)
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
        self.list_bindings_impl(raft, params)
            .await
            .map_err(SpiffeProviderError::raft)
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
        match self.update_binding_impl(raft, svid, data).await {
            Ok(b) => Ok(b),
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    Err(SpiffeProviderError::BindingNotFound(svid.to_string()))
                } else {
                    Err(SpiffeProviderError::raft(e))
                }
            }
        }
    }
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;

    fn make_binding(svid: &str, domain_id: &str) -> SpiffeBindingCreate {
        SpiffeBindingCreate {
            svid: svid.to_string(),
            domain_id: domain_id.to_string(),
            is_system: false,
            user_id: None,
            authorizations: None,
        }
    }

    #[tokio::test]
    async fn test_create_binding() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let binding = make_binding("spiffe://example/test", "domain-1");
        let result = backend.create_binding_impl(&storage, binding.clone()).await;
        assert!(result.is_ok());
        let created = result.unwrap();
        assert_eq!(created.svid, "spiffe://example/test");
        assert_eq!(created.domain_id, "domain-1");
    }

    #[tokio::test]
    async fn test_get_binding_exists() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/test", "domain-1"))
            .await
            .unwrap();

        let result = backend
            .get_binding_impl(&storage, "spiffe://example/test")
            .await;
        assert!(result.is_ok());
        let binding = result.unwrap();
        assert!(binding.is_some());
        assert_eq!(binding.unwrap().svid, "spiffe://example/test");
    }

    #[tokio::test]
    async fn test_get_binding_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let result = backend
            .get_binding_impl(&storage, "spiffe://example/nonexistent")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_binding() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/test", "domain-1"))
            .await
            .unwrap();

        let result = backend
            .delete_binding_impl(&storage, "spiffe://example/test")
            .await;
        assert!(result.is_ok());

        let found = backend
            .get_binding_impl(&storage, "spiffe://example/test")
            .await;
        assert!(found.is_ok());
        assert!(found.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_binding_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let result = backend
            .delete_binding_impl(&storage, "spiffe://example/nonexistent")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_bindings_all() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/a", "domain-1"))
            .await
            .unwrap();
        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/b", "domain-2"))
            .await
            .unwrap();
        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/c", "domain-1"))
            .await
            .unwrap();

        let params = SpiffeBindingListParameters {
            domain_id: None,
            user_id: None,
        };
        let result = backend.list_bindings_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_list_bindings_by_domain() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/a", "domain-1"))
            .await
            .unwrap();
        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/b", "domain-2"))
            .await
            .unwrap();
        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/c", "domain-1"))
            .await
            .unwrap();

        let params = SpiffeBindingListParameters {
            domain_id: Some("domain-1".to_string()),
            user_id: None,
        };
        let result = backend.list_bindings_impl(&storage, &params).await;
        assert!(result.is_ok());
        let bindings = result.unwrap();
        assert_eq!(bindings.len(), 2);
        for b in &bindings {
            assert_eq!(b.domain_id, "domain-1");
        }
    }

    #[tokio::test]
    async fn test_list_bindings_empty() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let params = SpiffeBindingListParameters {
            domain_id: None,
            user_id: None,
        };
        let result = backend.list_bindings_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_update_binding() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/test", "domain-1"))
            .await
            .unwrap();

        let update = SpiffeBindingUpdate {
            authorizations: Some(vec![SpiffeAuthorization::Domain {
                domain_id: "domain-1".to_string(),
                role_ids: Some(vec!["admin".to_string()]),
            }]),
        };

        let result = backend
            .update_binding_impl(&storage, "spiffe://example/test", update)
            .await;
        assert!(result.is_ok());
        let binding = result.unwrap();
        assert!(binding.authorizations.is_some());
        assert_eq!(binding.authorizations.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_update_binding_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let update = SpiffeBindingUpdate {
            authorizations: None,
        };

        let result = backend
            .update_binding_impl(&storage, "spiffe://example/nonexistent", update)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_index_is_created_and_cleaned() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_binding_impl(&storage, make_binding("spiffe://example/test", "domain-1"))
            .await
            .unwrap();

        // Check index exists
        let idx = storage
            .prefix_index("spiffe:binding:domain:domain-1:")
            .await
            .unwrap();
        assert_eq!(idx.len(), 1);

        backend
            .delete_binding_impl(&storage, "spiffe://example/test")
            .await
            .unwrap();

        // Check index is removed
        let idx = storage
            .prefix_index("spiffe:binding:domain:domain-1:")
            .await
            .unwrap();
        assert_eq!(idx.len(), 0);
    }
}
