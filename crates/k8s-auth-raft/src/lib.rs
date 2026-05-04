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
//! # OpenStack Keystone SQL driver for the K8s auth provider
use std::collections::BTreeSet;

use async_trait::async_trait;

use openstack_keystone_core::k8s_auth::backend::K8sAuthBackend;
use openstack_keystone_core::k8s_auth::error::K8sAuthProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::k8s_auth::*;
use openstack_keystone_distributed_storage::{
    Metadata, StorageApi, StoreDataEnvelope, store_command::Mutation,
};

/// Raft  Database K8s auth backend.
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
        format!("k8s_auth:instance:id:")
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
        format!("k8s_auth:role:id:")
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
            .get_storage()
            .ok_or(K8sAuthProviderError::RaftNotAvailable)?;
        let obj = K8sAuthInstance::from(instance);
        let mutations = vec![
            Mutation::set(
                self.get_auth_instance_id_key_name(&obj.id),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(K8sAuthProviderError::raft)?,
            Mutation::set_index(
                self.get_auth_instance_domain_id_idx_key_name(&obj.id, &obj.domain_id),
            )
            .map_err(K8sAuthProviderError::raft)?,
        ];
        raft.transaction(mutations)
            .await
            .map_err(K8sAuthProviderError::raft)?;
        Ok(obj)
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
        let obj = K8sAuthRole::from(role);
        let mutations = vec![
            Mutation::set(
                self.get_auth_role_id_key_name(&obj.id),
                obj.clone(),
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(K8sAuthProviderError::raft)?,
            Mutation::set_index(self.get_auth_role_domain_id_idx_key_name(&obj.id, &obj.domain_id))
                .map_err(K8sAuthProviderError::raft)?,
            Mutation::set_index(
                self.get_auth_role_instance_id_idx_key_name(&obj.id, &obj.auth_instance_id),
            )
            .map_err(K8sAuthProviderError::raft)?,
        ];
        raft.transaction(mutations)
            .await
            .map_err(K8sAuthProviderError::raft)?;
        Ok(obj)
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
        // Find the current object to be able to cleanup indexes as well
        let curr: Option<K8sAuthInstance> = raft
            .get_by_key(self.get_auth_instance_id_key_name(id), None::<&str>)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .map(|x| x.data);
        if let Some(obj) = curr {
            let mutations = vec![
                Mutation::remove(self.get_auth_instance_id_key_name(&obj.id), None::<&str>)
                    .map_err(K8sAuthProviderError::raft)?,
                Mutation::remove_index(
                    self.get_auth_instance_domain_id_idx_key_name(&obj.id, &obj.domain_id),
                )
                .map_err(K8sAuthProviderError::raft)?,
            ];
            raft.transaction(mutations)
                .await
                .map_err(K8sAuthProviderError::raft)?;
        }
        Ok(())
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
        // Find the current object to be able to cleanup indexes as well
        let curr: Option<K8sAuthRole> = raft
            .get_by_key(self.get_auth_role_id_key_name(id), None::<&str>)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .map(|x| x.data);
        if let Some(obj) = curr {
            let mutations = vec![
                Mutation::remove(self.get_auth_role_id_key_name(&obj.id), None::<&str>)
                    .map_err(K8sAuthProviderError::raft)?,
                Mutation::remove_index(
                    self.get_auth_role_domain_id_idx_key_name(&obj.id, &obj.domain_id),
                )
                .map_err(K8sAuthProviderError::raft)?,
                Mutation::remove_index(
                    self.get_auth_role_instance_id_idx_key_name(&obj.id, &obj.auth_instance_id),
                )
                .map_err(K8sAuthProviderError::raft)?,
            ];
            raft.transaction(mutations)
                .await
                .map_err(K8sAuthProviderError::raft)?;
        }
        Ok(())
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
        Ok(raft
            .get_by_key(self.get_auth_instance_id_key_name(id), None::<&str>)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .map(|x| x.data))
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
        Ok(raft
            .get_by_key(self.get_auth_role_id_key_name(id), None::<&str>)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .map(|x| x.data))
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
        let mut res: Vec<K8sAuthInstance> = Vec::new();
        let mut post_filters: Vec<K8sAuthInstanceFilter> = Vec::new();
        if let Some(val) = &params.name {
            post_filters.push(K8sAuthInstanceFilter::Name(val.clone()));
        }

        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();
        if let Some(did) = &params.domain_id {
            post_filters.push(K8sAuthInstanceFilter::Domain(did.clone()));
            // pre-calculate the ID candidates by the DOMAIN_ID filter
            let prefix = self.get_auth_instance_by_domain_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                raft.prefix_index(self.get_auth_instance_by_domain_id_prefix(did))
                    .await
                    .map_err(K8sAuthProviderError::raft)?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }

        if !pre_filter_ids.is_empty() {
            for id in pre_filter_ids {
                if let Some(candidate) = raft
                    .get_by_key::<K8sAuthInstance, String, &str>(
                        self.get_auth_instance_id_key_name(id),
                        None::<&str>,
                    )
                    .await
                    .map_err(K8sAuthProviderError::raft)?
                    .map(|x| x.data)
                {
                    if post_filters.iter().all(|f| f.matches(&candidate)) {
                        res.push(candidate);
                    }
                }
            }
        } else {
            for candidate in raft
                .prefix::<K8sAuthInstance, String, &str>(
                    self.get_auth_instance_prefix(),
                    None::<&str>,
                )
                .await
                .map_err(K8sAuthProviderError::raft)?
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
        let mut res: Vec<K8sAuthRole> = Vec::new();
        let mut post_filters: Vec<K8sAuthRoleFilter> = Vec::new();
        if let Some(val) = &params.name {
            post_filters.push(K8sAuthRoleFilter::Name(val.clone()));
        }
        let mut pre_filter_ids: BTreeSet<String> = BTreeSet::new();

        if let Some(did) = &params.domain_id {
            post_filters.push(K8sAuthRoleFilter::Domain(did.clone()));
            // pre-calculate the ID candidates by the DOMAIN_ID filter
            let prefix = self.get_auth_role_by_domain_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            pre_filter_ids.extend(
                raft.prefix_index(self.get_auth_role_by_domain_id_prefix(did))
                    .await
                    .map_err(K8sAuthProviderError::raft)?
                    .into_iter()
                    .map(|entry| entry[id_offset..].into()),
            );
        }
        if let Some(did) = &params.auth_instance_id {
            post_filters.push(K8sAuthRoleFilter::Instance(did.clone()));
            // pre-calculate the ID candidates by the DOMAIN_ID filter
            let prefix = self.get_auth_role_by_instance_id_prefix(did);
            let id_offset = if prefix.ends_with(':') {
                prefix.len()
            } else {
                prefix.len() + 1
            };
            let by_instance_ids: BTreeSet<String> = raft
                .prefix_index(self.get_auth_role_by_instance_id_prefix(did))
                .await
                .map_err(K8sAuthProviderError::raft)?
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
                if let Some(candidate) = raft
                    .get_by_key::<K8sAuthRole, String, &str>(
                        self.get_auth_role_id_key_name(id),
                        None::<&str>,
                    )
                    .await
                    .map_err(K8sAuthProviderError::raft)?
                    .map(|x| x.data)
                {
                    if post_filters.iter().all(|f| f.matches(&candidate)) {
                        res.push(candidate);
                    }
                }
            }
        } else {
            for candidate in raft
                .prefix::<K8sAuthRole, String, &str>(self.get_auth_role_prefix(), None::<&str>)
                .await
                .map_err(K8sAuthProviderError::raft)?
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
        let curr: StoreDataEnvelope<K8sAuthInstance> = raft
            .get_by_key(self.get_auth_instance_id_key_name(id), None::<&str>)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .ok_or(K8sAuthProviderError::AuthInstanceNotFound(id.to_string()))?;
        let new = curr.data.with_update(data);
        let new_meta = curr.metadata.new_revision();
        raft.set_value(
            self.get_auth_instance_id_key_name(id),
            StoreDataEnvelope {
                data: new.clone(),
                metadata: new_meta,
            },
            None::<&str>,
            Some(curr.metadata.revision),
        )
        .await
        .map_err(K8sAuthProviderError::raft)?;
        Ok(new)
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
        let curr: StoreDataEnvelope<K8sAuthRole> = raft
            .get_by_key(self.get_auth_role_id_key_name(id), None::<&str>)
            .await
            .map_err(K8sAuthProviderError::raft)?
            .ok_or(K8sAuthProviderError::RoleNotFound(id.to_string()))?;
        let new = curr.data.with_update(data);
        let new_meta = curr.metadata.new_revision();
        raft.set_value(
            self.get_auth_role_id_key_name(id),
            StoreDataEnvelope {
                data: new.clone(),
                metadata: new_meta,
            },
            None::<&str>,
            Some(curr.metadata.revision),
        )
        .await
        .map_err(K8sAuthProviderError::raft)?;
        Ok(new)
    }
}

#[cfg(test)]
mod tests {}
