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
//! # OpenStack Keystone Raft driver for the K8s auth provider
use std::collections::BTreeSet;

use async_trait::async_trait;

use openstack_keystone_core::k8s_auth::backend::K8sAuthBackend;
use openstack_keystone_core::k8s_auth::error::K8sAuthProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::k8s_auth::*;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreDataEnvelope, StoreError, store_command::Mutation,
};

/// Raft Database K8s auth backend.
#[derive(Default)]
pub struct RaftBackend {}

impl RaftBackend {
    /// Get the storage key for auth instance - direct entry.
    ///
    /// # Parameters
    /// - `id`: The auth instance ID.
    ///
    /// # Returns
    /// The storage key.
    fn get_auth_instance_id_key_name<I: AsRef<str>>(&self, id: I) -> String {
        format!("k8s_auth:instance:id:{}", id.as_ref())
    }

    /// Get the prefix key for listing all auth instances.
    ///
    /// # Returns
    /// The prefix key.
    fn get_auth_instance_prefix(&self) -> String {
        "k8s_auth:instance:id:".to_string()
    }

    /// Get the storage key for auth instance - domain based index.
    ///
    /// # Parameters
    /// - `id`: The auth instance ID.
    /// - `domain_id`: The domain ID.
    ///
    /// # Returns
    /// The storage key.
    fn get_auth_instance_domain_id_idx_key_name<I: AsRef<str>, D: AsRef<str>>(
        &self,
        id: I,
        domain_id: D,
    ) -> String {
        format!(
            "k8s_auth:instance:domain:{}:{}",
            domain_id.as_ref(),
            id.as_ref()
        )
    }

    /// Get the prefix for listing auth instances by the domain_id.
    ///
    /// # Parameters
    /// - `domain_id`: The domain ID.
    ///
    /// # Returns
    /// The prefix key.
    fn get_auth_instance_by_domain_id_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("k8s_auth:instance:domain:{}:", domain_id.as_ref(),)
    }

    /// Get the storage key for auth role - direct entry.
    ///
    /// # Parameters
    /// - `id`: The auth role ID.
    ///
    /// # Returns
    /// The storage key.
    fn get_auth_role_id_key_name<I: AsRef<str>>(&self, id: I) -> String {
        format!("k8s_auth:role:id:{}", id.as_ref())
    }

    /// Get the prefix key for listing all auth roles.
    ///
    /// # Returns
    /// The prefix key.
    fn get_auth_role_prefix(&self) -> String {
        "k8s_auth:role:id:".to_string()
    }

    /// Get the storage key for auth role - domain based index.
    ///
    /// # Parameters
    /// - `id`: The auth role ID.
    /// - `domain_id`: The domain ID.
    ///
    /// # Returns
    /// The storage key.
    fn get_auth_role_domain_id_idx_key_name<I: AsRef<str>, D: AsRef<str>>(
        &self,
        id: I,
        domain_id: D,
    ) -> String {
        format!(
            "k8s_auth:role:domain:{}:{}",
            domain_id.as_ref(),
            id.as_ref()
        )
    }

    /// Get the prefix for listing auth roles by the domain_id.
    ///
    /// # Parameters
    /// - `domain_id`: The domain ID.
    ///
    /// # Returns
    /// The prefix key.
    fn get_auth_role_by_domain_id_prefix<D: AsRef<str>>(&self, domain_id: D) -> String {
        format!("k8s_auth:role:domain:{}:", domain_id.as_ref(),)
    }

    /// Get the storage key for auth role - domain based index.
    ///
    /// # Parameters
    /// - `id`: The auth role ID.
    /// - `instance_id`: The auth instance ID.
    ///
    /// # Returns
    /// The storage key.
    fn get_auth_role_instance_id_idx_key_name<I: AsRef<str>, D: AsRef<str>>(
        &self,
        id: I,
        instance_id: D,
    ) -> String {
        format!(
            "k8s_auth:role:instance:{}:{}",
            instance_id.as_ref(),
            id.as_ref()
        )
    }

    /// Get the prefix for listing auth roles by the auth_instance_id.
    ///
    /// # Parameters
    /// - `instance_id`: The auth instance ID.
    ///
    /// # Returns
    /// The prefix key.
    fn get_auth_role_by_instance_id_prefix<D: AsRef<str>>(&self, instance_id: D) -> String {
        format!("k8s_auth:role:instance:{}:", instance_id.as_ref(),)
    }

    async fn create_auth_instance_impl(
        &self,
        storage: &impl StorageApi,
        instance: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, StoreError> {
        let obj = K8sAuthInstance::from(instance);
        let mutations = vec![
            Mutation::set(
                self.get_auth_instance_id_key_name(&obj.id),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )?,
            Mutation::set_index(
                self.get_auth_instance_domain_id_idx_key_name(&obj.id, &obj.domain_id),
            )?,
        ];
        storage.transaction(mutations).await?;
        Ok(obj)
    }

    async fn create_auth_role_impl(
        &self,
        storage: &impl StorageApi,
        role: K8sAuthRoleCreate,
    ) -> Result<K8sAuthRole, StoreError> {
        let obj = K8sAuthRole::from(role);
        let mutations = vec![
            Mutation::set(
                self.get_auth_role_id_key_name(&obj.id),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )?,
            Mutation::set_index(
                self.get_auth_role_domain_id_idx_key_name(&obj.id, &obj.domain_id),
            )?,
            Mutation::set_index(
                self.get_auth_role_instance_id_idx_key_name(&obj.id, &obj.auth_instance_id),
            )?,
        ];
        storage.transaction(mutations).await?;
        Ok(obj)
    }

    async fn delete_auth_instance_impl(
        &self,
        storage: &impl StorageApi,
        id: &str,
    ) -> Result<(), StoreError> {
        let curr: Option<K8sAuthInstance> = storage
            .get_by_key(self.get_auth_instance_id_key_name(id), None::<&str>)
            .await?
            .map(|x| x.data);
        if let Some(obj) = curr {
            let mutations = vec![
                Mutation::remove(self.get_auth_instance_id_key_name(id), None::<&str>)?,
                Mutation::remove_index(
                    self.get_auth_instance_domain_id_idx_key_name(id, &obj.domain_id),
                )?,
            ];
            storage.transaction(mutations).await?;
        }
        Ok(())
    }

    async fn delete_auth_role_impl(
        &self,
        storage: &impl StorageApi,
        id: &str,
    ) -> Result<(), StoreError> {
        let curr: Option<K8sAuthRole> = storage
            .get_by_key(self.get_auth_role_id_key_name(id), None::<&str>)
            .await?
            .map(|x| x.data);
        if let Some(obj) = curr {
            let mutations = vec![
                Mutation::remove(self.get_auth_role_id_key_name(&obj.id), None::<&str>)?,
                Mutation::remove_index(
                    self.get_auth_role_domain_id_idx_key_name(&obj.id, &obj.domain_id),
                )?,
                Mutation::remove_index(
                    self.get_auth_role_instance_id_idx_key_name(&obj.id, &obj.auth_instance_id),
                )?,
            ];
            storage.transaction(mutations).await?;
        }
        Ok(())
    }

    async fn get_auth_instance_impl(
        &self,
        storage: &impl StorageApi,
        id: &str,
    ) -> Result<Option<K8sAuthInstance>, StoreError> {
        Ok(storage
            .get_by_key(self.get_auth_instance_id_key_name(id), None::<&str>)
            .await?
            .map(|x| x.data))
    }

    async fn get_auth_role_impl(
        &self,
        storage: &impl StorageApi,
        id: &str,
    ) -> Result<Option<K8sAuthRole>, StoreError> {
        Ok(storage
            .get_by_key(self.get_auth_role_id_key_name(id), None::<&str>)
            .await?
            .map(|x| x.data))
    }

    async fn list_auth_instances_impl(
        &self,
        storage: &impl StorageApi,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, StoreError> {
        let mut res: Vec<K8sAuthInstance> = Vec::new();
        let mut post_filters: Vec<K8sAuthInstanceFilter> = Vec::new();
        if let Some(val) = &params.name {
            post_filters.push(K8sAuthInstanceFilter::Name(val.clone()));
        }

        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();
        if let Some(did) = &params.domain_id {
            post_filters.push(K8sAuthInstanceFilter::Domain(did.clone()));
            let prefix = self.get_auth_instance_by_domain_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                storage
                    .prefix_index(self.get_auth_instance_by_domain_id_prefix(did))
                    .await?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }

        if !pre_filter_ids.is_empty() {
            for id in pre_filter_ids {
                if let Some(candidate) = storage
                    .get_by_key::<K8sAuthInstance, String, &str>(
                        self.get_auth_instance_id_key_name(id),
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
                .prefix::<K8sAuthInstance, String, &str>(
                    self.get_auth_instance_prefix(),
                    None::<&str>,
                )
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

    async fn list_auth_roles_impl(
        &self,
        storage: &impl StorageApi,
        params: &K8sAuthRoleListParameters,
    ) -> Result<Vec<K8sAuthRole>, StoreError> {
        let mut res: Vec<K8sAuthRole> = Vec::new();
        let mut post_filters: Vec<K8sAuthRoleFilter> = Vec::new();
        if let Some(val) = &params.name {
            post_filters.push(K8sAuthRoleFilter::Name(val.clone()));
        }
        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();

        if let Some(did) = &params.domain_id {
            post_filters.push(K8sAuthRoleFilter::Domain(did.clone()));
            let prefix = self.get_auth_role_by_domain_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                storage
                    .prefix_index(self.get_auth_role_by_domain_id_prefix(did))
                    .await?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }
        if let Some(did) = &params.auth_instance_id {
            post_filters.push(K8sAuthRoleFilter::Instance(did.clone()));
            let prefix = self.get_auth_role_by_instance_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            let by_instance_ids: BTreeSet<String> = storage
                .prefix_index(self.get_auth_role_by_instance_id_prefix(did))
                .await?
                .into_iter()
                .map(|entry| entry[id_offset..].into())
                .collect();
            if pre_filter_ids.is_empty() {
                pre_filter_ids = by_instance_ids;
            } else {
                pre_filter_ids.retain(|x| by_instance_ids.contains(x));
            }
        }

        if !pre_filter_ids.is_empty() {
            for id in pre_filter_ids {
                if let Some(candidate) = storage
                    .get_by_key::<K8sAuthRole, String, &str>(
                        self.get_auth_role_id_key_name(id),
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
                .prefix::<K8sAuthRole, String, &str>(self.get_auth_role_prefix(), None::<&str>)
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

    async fn update_auth_instance_impl(
        &self,
        storage: &impl StorageApi,
        id: &str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<Option<K8sAuthInstance>, StoreError> {
        let curr: Option<StoreDataEnvelope<K8sAuthInstance>> = storage
            .get_by_key(self.get_auth_instance_id_key_name(id), None::<&str>)
            .await?;
        if let Some(curr) = curr {
            let new = curr.data.with_update(data);
            let new_meta = curr.metadata.new_revision();
            storage
                .set_value(
                    self.get_auth_instance_id_key_name(id),
                    StoreDataEnvelope {
                        data: new.clone(),
                        metadata: new_meta,
                    },
                    None::<&str>,
                    Some(curr.metadata.revision),
                )
                .await?;
            Ok(Some(new))
        } else {
            Ok(None)
        }
    }

    async fn update_auth_role_impl(
        &self,
        storage: &impl StorageApi,
        id: &str,
        data: K8sAuthRoleUpdate,
    ) -> Result<Option<K8sAuthRole>, StoreError> {
        let curr: Option<StoreDataEnvelope<K8sAuthRole>> = storage
            .get_by_key(self.get_auth_role_id_key_name(id), None::<&str>)
            .await?;
        if let Some(curr) = curr {
            let new = curr.data.with_update(data);
            let new_meta = curr.metadata.new_revision();
            storage
                .set_value(
                    self.get_auth_role_id_key_name(id),
                    StoreDataEnvelope {
                        data: new.clone(),
                        metadata: new_meta,
                    },
                    None::<&str>,
                    Some(curr.metadata.revision),
                )
                .await?;
            Ok(Some(new))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl K8sAuthBackend for RaftBackend {
    /// Register new K8s auth.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `instance`: The K8s auth instance to create.
    ///
    /// # Returns
    /// The created K8s auth instance.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_instance(
        &self,
        state: &ServiceState,
        instance: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.create_auth_instance_impl(raft, instance)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// Register new K8s auth role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `role`: The K8s auth role to create.
    ///
    /// # Returns
    /// The created K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_role(
        &self,
        state: &ServiceState,
        role: K8sAuthRoleCreate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.create_auth_role_impl(raft, role)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// Delete K8s auth.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The auth instance ID.
    ///
    /// # Returns
    /// An empty result on success.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.delete_auth_instance_impl(raft, id)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// Delete K8s auth role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The auth role ID.
    ///
    /// # Returns
    /// An empty result on success.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.delete_auth_role_impl(raft, id)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// Get K8s auth instance.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The auth instance ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the K8sAuthInstance if found, or
    /// an `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.get_auth_instance_impl(raft, id)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// Get K8s auth role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The auth role ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the K8sAuthRole if found, or an
    /// `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthRole>, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.get_auth_role_impl(raft, id)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// List K8s auth auth_instances.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters.
    ///
    /// # Returns
    /// A list of K8s auth instances.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_auth_instances(
        &self,
        state: &ServiceState,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.list_auth_instances_impl(raft, params)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// List K8s auth roles.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters.
    ///
    /// # Returns
    /// A list of K8s auth roles.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_auth_roles(
        &self,
        state: &ServiceState,
        params: &K8sAuthRoleListParameters,
    ) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.list_auth_roles_impl(raft, params)
            .await
            .map_err(K8sAuthProviderError::raft)
    }

    /// Update K8s auth.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The auth instance ID.
    /// - `data`: The update data.
    ///
    /// # Returns
    /// The updated K8s auth instance.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.update_auth_instance_impl(raft, id, data)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .ok_or_else(|| K8sAuthProviderError::AuthInstanceNotFound(id.to_string()))
    }

    /// Update K8s auth role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The auth role ID.
    /// - `data`: The update data.
    ///
    /// # Returns
    /// The updated K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthRoleUpdate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        let raft = state
            .storage
            .as_ref()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        self.update_auth_role_impl(raft, id, data)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .ok_or_else(|| K8sAuthProviderError::RoleNotFound(id.to_string()))
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

    fn make_instance(id: &str, domain_id: &str) -> K8sAuthInstanceCreate {
        K8sAuthInstanceCreate {
            id: Some(id.to_string()),
            domain_id: domain_id.to_string(),
            enabled: true,
            host: "https://k8s.example.com".to_string(),
            ca_cert: None,
            disable_local_ca_jwt: None,
            name: None,
        }
    }

    fn make_role(id: &str, domain_id: &str, instance_id: &str) -> K8sAuthRoleCreate {
        K8sAuthRoleCreate {
            id: Some(id.to_string()),
            domain_id: domain_id.to_string(),
            auth_instance_id: instance_id.to_string(),
            enabled: true,
            name: "test-role".to_string(),
            token_restriction_id: "tr-1".to_string(),
            bound_audience: None,
            bound_service_account_names: vec!["default".to_string()],
            bound_service_account_namespaces: vec!["default".to_string()],
        }
    }

    #[tokio::test]
    async fn test_create_and_get_auth_instance() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let inst = make_instance("inst-1", "domain-1");
        let result = backend
            .create_auth_instance_impl(&storage, inst.clone())
            .await;
        assert!(result.is_ok());
        let created = result.unwrap();
        assert_eq!(created.id, "inst-1");
        assert_eq!(created.domain_id, "domain-1");

        let found = backend.get_auth_instance_impl(&storage, "inst-1").await;
        assert!(found.is_ok());
        assert!(found.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_get_auth_instance_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let result = backend
            .get_auth_instance_impl(&storage, "nonexistent")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_auth_instance() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_instance_impl(&storage, make_instance("inst-1", "domain-1"))
            .await
            .unwrap();

        backend
            .delete_auth_instance_impl(&storage, "inst-1")
            .await
            .unwrap();

        let found = backend.get_auth_instance_impl(&storage, "inst-1").await;
        assert!(found.is_ok());
        assert!(found.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_create_and_get_auth_role() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let role = make_role("role-1", "domain-1", "inst-1");
        let result = backend.create_auth_role_impl(&storage, role.clone()).await;
        assert!(result.is_ok());
        let created = result.unwrap();
        assert_eq!(created.id, "role-1");
        assert_eq!(created.auth_instance_id, "inst-1");

        let found = backend.get_auth_role_impl(&storage, "role-1").await;
        assert!(found.is_ok());
        assert!(found.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_delete_auth_role() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_role_impl(&storage, make_role("role-1", "domain-1", "inst-1"))
            .await
            .unwrap();

        backend
            .delete_auth_role_impl(&storage, "role-1")
            .await
            .unwrap();

        let found = backend.get_auth_role_impl(&storage, "role-1").await;
        assert!(found.is_ok());
        assert!(found.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_auth_instances_all() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_instance_impl(&storage, make_instance("inst-1", "domain-1"))
            .await
            .unwrap();
        backend
            .create_auth_instance_impl(&storage, make_instance("inst-2", "domain-2"))
            .await
            .unwrap();

        let params = K8sAuthInstanceListParameters {
            domain_id: None,
            name: None,
        };
        let result = backend.list_auth_instances_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_auth_instances_by_domain() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_instance_impl(&storage, make_instance("inst-1", "domain-1"))
            .await
            .unwrap();
        backend
            .create_auth_instance_impl(&storage, make_instance("inst-2", "domain-2"))
            .await
            .unwrap();

        let params = K8sAuthInstanceListParameters {
            domain_id: Some("domain-1".to_string()),
            name: None,
        };
        let result = backend.list_auth_instances_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_auth_roles_by_domain_and_instance() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_role_impl(&storage, make_role("role-1", "domain-1", "inst-1"))
            .await
            .unwrap();
        backend
            .create_auth_role_impl(&storage, make_role("role-2", "domain-1", "inst-2"))
            .await
            .unwrap();
        backend
            .create_auth_role_impl(&storage, make_role("role-3", "domain-2", "inst-1"))
            .await
            .unwrap();

        let params = K8sAuthRoleListParameters {
            domain_id: Some("domain-1".to_string()),
            auth_instance_id: Some("inst-1".to_string()),
            name: None,
        };
        let result = backend.list_auth_roles_impl(&storage, &params).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_update_auth_instance() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_instance_impl(&storage, make_instance("inst-1", "domain-1"))
            .await
            .unwrap();

        let update = K8sAuthInstanceUpdate {
            enabled: Some(false),
            ..K8sAuthInstanceUpdate::default()
        };
        let result = backend
            .update_auth_instance_impl(&storage, "inst-1", update)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap().unwrap().enabled);
    }

    #[tokio::test]
    async fn test_update_auth_instance_not_found() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        let update = K8sAuthInstanceUpdate::default();
        let result = backend
            .update_auth_instance_impl(&storage, "nonexistent", update)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_update_auth_role() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_role_impl(&storage, make_role("role-1", "domain-1", "inst-1"))
            .await
            .unwrap();

        let update = K8sAuthRoleUpdate {
            enabled: Some(false),
            ..K8sAuthRoleUpdate::default()
        };
        let result = backend
            .update_auth_role_impl(&storage, "role-1", update)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap().unwrap().enabled);
    }

    #[tokio::test]
    async fn test_instance_indexes_created_and_cleaned() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_instance_impl(&storage, make_instance("inst-1", "domain-1"))
            .await
            .unwrap();

        let idx = storage
            .prefix_index("k8s_auth:instance:domain:domain-1:")
            .await
            .unwrap();
        assert_eq!(idx.len(), 1);

        backend
            .delete_auth_instance_impl(&storage, "inst-1")
            .await
            .unwrap();

        let idx = storage
            .prefix_index("k8s_auth:instance:domain:domain-1:")
            .await
            .unwrap();
        assert_eq!(idx.len(), 0);
    }

    #[tokio::test]
    async fn test_role_indexes_created_and_cleaned() {
        let backend = RaftBackend::default();
        let storage = MockStorage::default();

        backend
            .create_auth_role_impl(&storage, make_role("role-1", "domain-1", "inst-1"))
            .await
            .unwrap();

        let idx_domain = storage
            .prefix_index("k8s_auth:role:domain:domain-1:")
            .await
            .unwrap();
        assert_eq!(idx_domain.len(), 1);

        let idx_instance = storage
            .prefix_index("k8s_auth:role:instance:inst-1:")
            .await
            .unwrap();
        assert_eq!(idx_instance.len(), 1);

        backend
            .delete_auth_role_impl(&storage, "role-1")
            .await
            .unwrap();

        let idx_domain = storage
            .prefix_index("k8s_auth:role:domain:domain-1:")
            .await
            .unwrap();
        assert_eq!(idx_domain.len(), 0);

        let idx_instance = storage
            .prefix_index("k8s_auth:role:instance:inst-1:")
            .await
            .unwrap();
        assert_eq!(idx_instance.len(), 0);
    }
}
