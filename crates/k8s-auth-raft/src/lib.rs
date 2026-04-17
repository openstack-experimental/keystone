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
use std::borrow::Cow;

use async_trait::async_trait;
use uuid::Uuid;

use openstack_keystone_core::k8s_auth::backend::K8sAuthBackend;
use openstack_keystone_core::k8s_auth::error::K8sAuthProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::k8s_auth::*;

/// Raft  Database K8s auth backend.
#[derive(Default)]
pub struct RaftBackend {}

impl RaftBackend {
    /// Get the storage key for auth instance - direct entry.
    fn get_auth_instance_id_key_name<I: AsRef<str>>(&self, id: I) -> String {
        format!("k8s_auth:instance:id:{}", id.as_ref())
    }

    /// Get the storage key for auth instance - domain based.
    fn get_auth_instance_domain_id_key_name<I: AsRef<str>, D: AsRef<str>>(
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
}

#[async_trait]
impl K8sAuthBackend for RaftBackend {
    /// Register new K8s auth.
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
        let id = instance
            .id
            .as_deref()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(Uuid::new_v4().simple().to_string()));
        raft.set_value(
            self.get_auth_instance_id_key_name(&id),
            &instance,
            None::<&str>,
        )
        raft.set_value(
            self.get_auth_instance_domain_id_key_name(&id, &instance.domain_id),
            &instance,
            None::<&str>,
        )
        .await
        .map_err(K8sAuthProviderError::raft)?;
        todo!();
    }

    /// Register new K8s auth role.
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
        todo!();
    }

    /// Delete K8s auth.
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
        todo!();
    }

    /// Delete K8s auth role.
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
        todo!();
    }

    /// Register new K8s auth.
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
        todo!();
    }

    /// Register new K8s auth role.
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
        todo!();
    }

    /// List K8s auth auth_instances.
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
        todo!();
    }

    /// List K8s auth roles.
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
        todo!();
    }

    /// Update K8s auth.
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
        todo!();
    }

    /// Update K8s auth role.
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
        todo!();
    }
}
