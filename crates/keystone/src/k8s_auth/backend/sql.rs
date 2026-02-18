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
//! Revoke provider: database backend.

use async_trait::async_trait;

use super::K8sAuthBackend;
use crate::k8s_auth::error::K8sAuthProviderError;
use crate::k8s_auth::types::*;
use crate::keystone::ServiceState;

mod k8s_auth;
mod k8s_auth_role;

/// Sql Database K8s auth backend.
#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl K8sAuthBackend for SqlBackend {
    /// Register new K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_k8s_auth_configuration(
        &self,
        state: &ServiceState,
        config: K8sAuthConfigurationCreate,
    ) -> Result<K8sAuthConfiguration, K8sAuthProviderError> {
        Ok(k8s_auth::create(&state.db, config).await?)
    }

    /// Register new K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_k8s_auth_role(
        &self,
        state: &ServiceState,
        role: K8sAuthRoleCreate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        Ok(k8s_auth_role::create(&state.db, role).await?)
    }

    /// Delete K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_k8s_auth_configuration<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        Ok(k8s_auth::delete(&state.db, id).await?)
    }

    /// Delete K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_k8s_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        Ok(k8s_auth_role::delete(&state.db, id).await?)
    }

    /// Register new K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_k8s_auth_configuration<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthConfiguration>, K8sAuthProviderError> {
        Ok(k8s_auth::get(&state.db, id).await?)
    }

    /// Register new K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_k8s_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthRole>, K8sAuthProviderError> {
        Ok(k8s_auth_role::get(&state.db, id).await?)
    }

    /// List K8s auth configurations.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_k8s_auth_configurations(
        &self,
        state: &ServiceState,
        params: &K8sAuthConfigurationListParameters,
    ) -> Result<Vec<K8sAuthConfiguration>, K8sAuthProviderError> {
        Ok(k8s_auth::list(&state.db, params).await?)
    }

    /// List K8s auth roles.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_k8s_auth_roles(
        &self,
        state: &ServiceState,
        params: &K8sAuthRoleListParameters,
    ) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError> {
        Ok(k8s_auth_role::list(&state.db, params).await?)
    }

    /// Update K8s auth.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_k8s_auth_configuration<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthConfigurationUpdate,
    ) -> Result<K8sAuthConfiguration, K8sAuthProviderError> {
        Ok(k8s_auth::update(&state.db, id, data).await?)
    }

    /// Update K8s auth role.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_k8s_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthRoleUpdate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        Ok(k8s_auth_role::update(&state.db, id, data).await?)
    }
}

#[cfg(test)]
mod tests {
    //    use crate::db::entity::revocation_event as db_revocation_event;
    //    use chrono::NaiveDateTime;
    //
    //    pub(super) fn get_mock() -> db_revocation_event::Model {
    //        db_revocation_event::Model {
    //            id: 1i32,
    //            domain_id: Some("did".into()),
    //            project_id: Some("pid".into()),
    //            user_id: Some("uid".into()),
    //            role_id: Some("rid".into()),
    //            trust_id: Some("trust_id".into()),
    //            consumer_id: Some("consumer_id".into()),
    //            access_token_id: Some("access_token_id".into()),
    //            issued_before: NaiveDateTime::default(),
    //            expires_at: Some(NaiveDateTime::default()),
    //            revoked_at: NaiveDateTime::default(),
    //            audit_id: Some("audit_id".into()),
    //            audit_chain_id: Some("audit_chain_id".into()),
    //        }
    //    }
}
