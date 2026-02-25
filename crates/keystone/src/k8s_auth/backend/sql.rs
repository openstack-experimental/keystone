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
//! K8s auth: database backend.

use async_trait::async_trait;

use super::K8sAuthBackend;
use crate::k8s_auth::error::K8sAuthProviderError;
use crate::k8s_auth::types::*;
use crate::keystone::ServiceState;

mod instance;
mod role;

/// Sql Database K8s auth backend.
#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl K8sAuthBackend for SqlBackend {
    /// Register new K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_instance(
        &self,
        state: &ServiceState,
        config: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        Ok(instance::create(&state.db, config).await?)
    }

    /// Register new K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_role(
        &self,
        state: &ServiceState,
        role: K8sAuthRoleCreate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        Ok(role::create(&state.db, role).await?)
    }

    /// Delete K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        Ok(instance::delete(&state.db, id).await?)
    }

    /// Delete K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        Ok(role::delete(&state.db, id).await?)
    }

    /// Register new K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError> {
        Ok(instance::get(&state.db, id).await?)
    }

    /// Register new K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthRole>, K8sAuthProviderError> {
        Ok(role::get(&state.db, id).await?)
    }

    /// List K8s auth auth_instances.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_auth_instances(
        &self,
        state: &ServiceState,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError> {
        Ok(instance::list(&state.db, params).await?)
    }

    /// List K8s auth roles.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_auth_roles(
        &self,
        state: &ServiceState,
        params: &K8sAuthRoleListParameters,
    ) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError> {
        Ok(role::list(&state.db, params).await?)
    }

    /// Update K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        Ok(instance::update(&state.db, id, data).await?)
    }

    /// Update K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthRoleUpdate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        Ok(role::update(&state.db, id, data).await?)
    }
}

impl From<crate::error::DatabaseError> for K8sAuthProviderError {
    fn from(source: crate::error::DatabaseError) -> Self {
        match source {
            cfl @ crate::error::DatabaseError::Conflict { .. } => Self::Conflict(cfl.to_string()),
            other => Self::Driver {
                source: other.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {}
